from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

pytest.importorskip("pydantic_ai", reason="the pydantic-ai extra is not installed")

from pydantic import BaseModel
from pydantic_ai import Agent, ModelRequest, ModelResponse, TextPart, ToolCallPart, ToolOutput, ToolReturnPart
from pydantic_ai.capabilities import NativeTool
from pydantic_ai.exceptions import UserError
from pydantic_ai.messages import ModelMessage
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.native_tools import WebSearchTool
from pydantic_ai.tools import DeferredToolRequests, ToolDefinition
from pydantic_ai.toolsets import ExternalToolset

from launchsafe_firewall import AsyncClient, AsyncGuard, Client, Guard
from launchsafe_firewall.integrations.pydantic_ai import LaunchSafeFirewall, check_output_functions, output_functions

from .fake_sidecar import Failure, Served

TOOLS: dict[str, dict[str, Any]] = {
    "lookup": {"kind": "read", "results": "trusted", "privateData": False},
    "send_email": {"kind": "send"},
}


class Script:
    """A scripted model: first it asks for the given calls, then it answers. It records what it was told."""

    def __init__(self, calls: list[tuple[str, dict[str, Any], str]]) -> None:
        self.calls = calls
        self.returned: dict[str, Any] = {}

    def __call__(self, messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        for m in messages:
            if isinstance(m, ModelRequest):
                for part in m.parts:
                    if isinstance(part, ToolReturnPart):
                        self.returned[part.tool_call_id] = part.content
        if self.returned:
            return ModelResponse(parts=[TextPart("done")])
        return ModelResponse(parts=[ToolCallPart(n, a, tool_call_id=i) for n, a, i in self.calls])


class Stubs:
    """Harmless stub tools that only record that they ran."""

    def __init__(self) -> None:
        self.ran: list[tuple[str, dict[str, Any]]] = []

    def agent(self, script: Script, guard: Guard | AsyncGuard, **kw: Any) -> Agent[None, str]:
        agent: Agent[None, str] = Agent(FunctionModel(script), capabilities=[LaunchSafeFirewall(guard)], **kw)

        @agent.tool_plain
        def send_email(to: str, body: str) -> str:
            """Send an email (stub)."""
            self.ran.append(("send_email", {"to": to, "body": body}))
            return f"sent to {to}"

        @agent.tool_plain
        def lookup(key: str) -> str:
            """Look up a value (stub)."""
            self.ran.append(("lookup", {"key": key}))
            return f"value for {key}: SECRET"

        @agent.tool_plain
        def explode(x: str) -> str:
            """Raise (stub)."""
            self.ran.append(("explode", {"x": x}))
            raise ValueError("boom")

        return agent


@pytest.fixture
async def aguard(served: Served) -> AsyncIterator[AsyncGuard]:
    async with AsyncGuard(AsyncClient(**served.client_kwargs()), session="pai-1", tools=TOOLS) as g:
        yield g
        await g.client.aclose()


async def test_allowed_call_runs_and_its_result_is_recorded(served: Served, aguard: AsyncGuard) -> None:
    stubs, script = Stubs(), Script([("send_email", {"to": "a@b.c", "body": "hi"}, "c1")])
    result = await stubs.agent(script, aguard).run("go")
    assert result.output == "done"
    assert stubs.ran == [("send_email", {"to": "a@b.c", "body": "hi"})]
    decide = served.fake.calls("/v1/decide")[0].body
    assert decide["action"] == {
        "format": "native",
        "tool": "send_email",
        "input": {"to": "a@b.c", "body": "hi"},
        "callId": "c1",
    }
    assert served.fake.calls("/v1/sessions/pai-1/results")[0].body == {"decisionId": "dec_1", "output": "sent to a@b.c"}
    assert script.returned == {"c1": "sent to a@b.c"}


@pytest.mark.parametrize("verdict", ["deny", "hold", "ask"])
async def test_a_call_not_allowed_never_runs_and_the_model_reads_why(
    served: Served, aguard: AsyncGuard, verdict: str
) -> None:
    served.fake.verdicts["send_email"] = verdict
    stubs, script = Stubs(), Script([("send_email", {"to": "x@evil.test", "body": "b"}, "c1")])
    result = await stubs.agent(script, aguard).run("go")
    assert result.output == "done"
    assert stubs.ran == []
    assert script.returned == {"c1": f"LaunchSafe Firewall: {verdict} send_email"}
    assert served.fake.calls("/v1/sessions/") == []


async def test_redacted_output_replaces_what_the_model_sees(served: Served, aguard: AsyncGuard) -> None:
    stubs, script = Stubs(), Script([("lookup", {"key": "k"}, "c1")])
    await stubs.agent(script, aguard).run("go")
    assert stubs.ran == [("lookup", {"key": "k"})]
    assert script.returned == {"c1": "value for k: [redacted]"}


async def test_sidecar_down_fails_closed_but_reads_run(tcp: Served) -> None:
    tcp.fake.fail("/v1/decide", Failure(status=503))
    stubs = Stubs()
    script = Script([("send_email", {"to": "a", "body": "b"}, "c1"), ("lookup", {"key": "k"}, "c2")])
    async with AsyncGuard(AsyncClient(**tcp.client_kwargs()), tools=TOOLS) as g:
        await stubs.agent(script, g).run("go")
        await g.client.aclose()
    assert stubs.ran == [("lookup", {"key": "k"})]
    assert "FW-UNAVAILABLE" in str(script.returned["c1"])
    assert script.returned["c2"] == "value for k: SECRET"  # the fail-open read has no decision to record against
    assert tcp.fake.calls("/v1/sessions/") == []


async def test_a_blocking_guard_works_too(tcp: Served) -> None:
    tcp.fake.verdicts["send_email"] = "deny"
    stubs, script = Stubs(), Script([("send_email", {"to": "a", "body": "b"}, "c1")])
    with Guard(Client(**tcp.client_kwargs()), tools=TOOLS) as g:
        await stubs.agent(script, g).run("go")
        g.client.close()
    assert stubs.ran == []


async def test_an_approval_given_in_the_firewall_is_waited_for(tcp: Served) -> None:
    tcp.fake.verdicts["send_email"] = "hold"
    tcp.fake.approval_script["*"] = ["pending", "approved"]
    stubs, script = Stubs(), Script([("send_email", {"to": "a", "body": "b"}, "c1")])
    async with AsyncGuard(AsyncClient(**tcp.client_kwargs()), approval_timeout=5.0) as g:
        await stubs.agent(script, g).run("go")
        await g.client.aclose()
    assert stubs.ran == [("send_email", {"to": "a", "body": "b"})]


async def test_a_failing_tool_is_recorded_as_failed(served: Served, aguard: AsyncGuard) -> None:
    stubs, script = Stubs(), Script([("explode", {"x": "a"}, "c1")])
    with pytest.raises(ValueError, match="boom"):
        await stubs.agent(script, aguard).run("go")
    assert stubs.ran == [("explode", {"x": "a"})]
    rec = served.fake.calls("/v1/sessions/pai-1/results")
    assert len(rec) == 1 and rec[0].body["failed"] is True and "ValueError: boom" in rec[0].body["output"]


async def test_deferred_tools_are_refused_not_passed_through(aguard: AsyncGuard) -> None:
    ext = ExternalToolset([ToolDefinition(name="remote", parameters_json_schema={"type": "object", "properties": {}})])
    agent: Agent[None, str | DeferredToolRequests] = Agent(
        FunctionModel(Script([])),
        toolsets=[ext],
        output_type=[str, DeferredToolRequests],
        capabilities=[LaunchSafeFirewall(aguard)],
    )
    with pytest.raises(UserError, match="cannot gate it"):
        await agent.run("go")


async def test_provider_side_native_tools_are_refused(aguard: AsyncGuard) -> None:
    agent: Agent[None, str] = Agent(
        FunctionModel(Script([])), capabilities=[LaunchSafeFirewall(aguard), NativeTool(WebSearchTool())]
    )
    with pytest.raises(UserError, match="cannot be gated"):
        await agent.run("go")


def _to_upper(text: str) -> str:
    """An output function (stub)."""
    return text.upper()


class Answer(BaseModel):
    text: str


def test_output_functions_are_found_and_refused(aguard: AsyncGuard) -> None:
    assert output_functions(str) == []
    assert output_functions([Answer, str]) == []
    assert output_functions(_to_upper) == ["_to_upper"]
    assert output_functions([Answer, ToolOutput(_to_upper)]) == ["_to_upper"]
    agent: Agent[None, str] = Agent(FunctionModel(Script([])), output_type=_to_upper)
    with pytest.raises(UserError, match="output functions"):
        check_output_functions(agent)
    with pytest.warns(UserWarning, match="output functions"):
        check_output_functions(agent, allow=True)
    check_output_functions(Agent(FunctionModel(Script([])), output_type=Answer))


def test_the_capability_is_not_spec_serializable(aguard: AsyncGuard) -> None:
    assert LaunchSafeFirewall.get_serialization_name() is None
