from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from typing import Any

import pytest

pytest.importorskip("agents", reason="the openai-agents extra is not installed")

from agents import (
    Agent,
    AgentOutputSchemaBase,
    FunctionTool,
    Handoff,
    Model,
    ModelResponse,
    ModelSettings,
    ModelTracing,
    Runner,
    Tool,
    TResponseInputItem,
    Usage,
    WebSearchTool,
    function_tool,
    handoff,
)
from agents.items import TResponseOutputItem, TResponseStreamEvent
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputRefusal,
    ResponseOutputText,
)
from openai.types.responses.response_prompt_param import ResponsePromptParam

from launchsafe_firewall import AsyncClient, AsyncGuard, Client, Guard
from launchsafe_firewall.integrations.openai_agents import (
    firewall_agent,
    firewall_tool,
    firewall_tools,
    parse_arguments,
)

from .fake_sidecar import Failure, Served

TOOLS: dict[str, dict[str, Any]] = {
    "lookup": {"kind": "read", "results": "trusted", "privateData": False},
    "send_email": {"kind": "send"},
}


def function_call(name: str, arguments: Mapping[str, Any], *, call_id: str) -> TResponseOutputItem:
    return ResponseFunctionToolCall(
        type="function_call", name=name, arguments=json.dumps(arguments), call_id=call_id, status="completed"
    )


def assistant_message(text: str) -> TResponseOutputItem:
    content: list[ResponseOutputText | ResponseOutputRefusal] = [
        ResponseOutputText(type="output_text", text=text, annotations=[])
    ]
    return ResponseOutputMessage(id="msg", type="message", role="assistant", status="completed", content=content)


class ScriptedModel(Model):
    """A model that answers each turn with the next scripted list of output items, and keeps what it was given.

    Built on the SDK's `Model` interface (the same from openai-agents 0.4 to 0.23), not on `agents.testing`,
    which only 0.21 and later have: an install with the crewai extra (openai<3) resolves openai-agents 0.20.
    """

    def __init__(self, turns: list[list[TResponseOutputItem]]) -> None:
        self.turns = list(turns)
        self.inputs: list[str | list[TResponseInputItem]] = []

    async def get_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: ResponsePromptParam | None,
    ) -> ModelResponse:
        self.inputs.append(input)
        assert self.turns, "the model was called more often than scripted"
        return ModelResponse(output=self.turns.pop(0), usage=Usage(), response_id=None)

    def stream_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: ResponsePromptParam | None,
    ) -> AsyncIterator[TResponseStreamEvent]:
        raise NotImplementedError("the tests run the model without streaming")


class Stubs:
    """Harmless stub tools that only record that they ran."""

    def __init__(self) -> None:
        self.ran: list[tuple[str, dict[str, Any]]] = []

        @function_tool
        def send_email(to: str, body: str) -> str:
            """Send an email (stub)."""
            self.ran.append(("send_email", {"to": to, "body": body}))
            return f"sent to {to}"

        @function_tool
        def lookup(key: str) -> str:
            """Look up a value (stub)."""
            self.ran.append(("lookup", {"key": key}))
            return f"value for {key}: SECRET"

        self.send_email = send_email
        self.lookup = lookup


@pytest.fixture
async def aguard(served: Served) -> AsyncIterator[AsyncGuard]:
    async with AsyncGuard(AsyncClient(**served.client_kwargs()), session="agents-1", tools=TOOLS) as g:
        yield g
        await g.client.aclose()


def _outputs(model: ScriptedModel) -> list[str]:
    """The tool outputs the model was given on its last call."""
    assert model.inputs, "the model was never called"
    last = model.inputs[-1]
    items = last if isinstance(last, list) else []
    out = []
    for item in items:
        d = item if isinstance(item, dict) else getattr(item, "model_dump", lambda: {})()
        if d.get("type") == "function_call_output":
            o = d.get("output")
            out.append(o if isinstance(o, str) else json.dumps(o))
    return out


def _agent(model: ScriptedModel, tools: list[Any]) -> Agent[Any]:
    return Agent(name="test", instructions="test", model=model, tools=tools)


async def test_allowed_call_runs_and_its_result_is_recorded(served: Served, aguard: AsyncGuard) -> None:
    stubs = Stubs()
    model = ScriptedModel(
        [[function_call("send_email", {"to": "a@b.c", "body": "hi"}, call_id="c1")], [assistant_message("done")]]
    )
    result = await Runner.run(_agent(model, firewall_tools(aguard, [stubs.send_email])), "go")
    assert result.final_output == "done"
    assert stubs.ran == [("send_email", {"to": "a@b.c", "body": "hi"})]
    decide = served.fake.calls("/v1/decide")[0].body
    assert decide["action"] == {
        "format": "native",
        "tool": "send_email",
        "input": {"to": "a@b.c", "body": "hi"},
        "callId": "c1",
    }
    rec = served.fake.calls("/v1/sessions/agents-1/results")[0].body
    assert rec == {"decisionId": "dec_1", "output": "sent to a@b.c"}
    assert _outputs(model) == ["sent to a@b.c"]


@pytest.mark.parametrize("verdict", ["deny", "hold", "ask"])
async def test_a_call_not_allowed_never_runs_and_the_model_reads_why(
    served: Served, aguard: AsyncGuard, verdict: str
) -> None:
    served.fake.verdicts["send_email"] = verdict
    stubs = Stubs()
    model = ScriptedModel(
        [[function_call("send_email", {"to": "x@evil.test", "body": "b"}, call_id="c1")], [assistant_message("ok")]]
    )
    await Runner.run(_agent(model, firewall_tools(aguard, [stubs.send_email])), "go")
    assert stubs.ran == []
    assert _outputs(model) == [f"LaunchSafe Firewall: {verdict} send_email"]
    assert served.fake.calls("/v1/sessions/") == []


async def test_redacted_output_replaces_what_the_model_sees(served: Served, aguard: AsyncGuard) -> None:
    stubs = Stubs()
    model = ScriptedModel([[function_call("lookup", {"key": "k"}, call_id="c1")], [assistant_message("ok")]])
    await Runner.run(_agent(model, firewall_tools(aguard, [stubs.lookup])), "go")
    assert stubs.ran == [("lookup", {"key": "k"})]
    assert _outputs(model) == ["value for k: [redacted]"]


async def test_sidecar_down_fails_closed_but_reads_run(tcp: Served) -> None:
    tcp.fake.fail("/v1/decide", Failure(status=503))
    stubs = Stubs()
    model = ScriptedModel(
        [
            [
                function_call("send_email", {"to": "a", "body": "b"}, call_id="c1"),
                function_call("lookup", {"key": "k"}, call_id="c2"),
            ],
            [assistant_message("ok")],
        ]
    )
    async with AsyncGuard(AsyncClient(**tcp.client_kwargs()), tools=TOOLS) as g:
        await Runner.run(_agent(model, firewall_tools(g, [stubs.send_email, stubs.lookup])), "go")
        await g.client.aclose()
    assert stubs.ran == [("lookup", {"key": "k"})]
    outs = _outputs(model)
    assert any("FW-UNAVAILABLE" in o for o in outs)
    # The fail-open read has no decision to record against.
    assert tcp.fake.calls("/v1/sessions/") == []


async def test_a_blocking_guard_works_too(tcp: Served) -> None:
    tcp.fake.verdicts["send_email"] = "deny"
    stubs = Stubs()
    model = ScriptedModel(
        [[function_call("send_email", {"to": "a", "body": "b"}, call_id="c1")], [assistant_message("ok")]]
    )
    with Guard(Client(**tcp.client_kwargs()), tools=TOOLS) as g:
        await Runner.run(_agent(model, [firewall_tool(g, stubs.send_email)]), "go")
        g.client.close()
    assert stubs.ran == []


def test_own_guardrails_are_kept_and_the_original_is_untouched(aguard: AsyncGuard) -> None:
    stubs = Stubs()
    wrapped = firewall_tool(aguard, stubs.send_email)
    assert isinstance(wrapped, FunctionTool)
    assert wrapped is not stubs.send_email
    assert stubs.send_email.tool_input_guardrails in (None, [])
    assert [g.get_name() for g in wrapped.tool_input_guardrails or []] == ["launchsafe-firewall"]
    again = firewall_tool(aguard, wrapped)
    assert [g.get_name() for g in again.tool_output_guardrails or []] == [
        "launchsafe-firewall-result",
        "launchsafe-firewall-result",
    ]


def test_tools_that_cannot_be_gated_are_refused(aguard: AsyncGuard) -> None:
    with pytest.raises(TypeError, match="cannot be gated"):
        firewall_tools(aguard, [WebSearchTool()])
    with pytest.raises(TypeError, match="not a FunctionTool"):
        firewall_tool(aguard, WebSearchTool())  # type: ignore[arg-type]


def _guarded(t: Any) -> bool:
    return any(g.get_name() == "launchsafe-firewall" for g in getattr(t, "tool_input_guardrails", None) or [])


def test_firewall_agent_gates_every_reachable_agent_in_place(aguard: AsyncGuard) -> None:
    stubs = Stubs()
    model = ScriptedModel([])
    deep = Agent(name="deep", instructions="d", model=model, tools=[stubs.lookup])
    helper = Agent(name="helper", instructions="h", model=model, tools=[stubs.send_email], handoffs=[deep])
    via_handoff = Agent(name="billing", instructions="b", model=model, tools=[stubs.lookup])
    as_tool_inner = Agent(name="researcher", instructions="r", model=model, tools=[stubs.send_email])
    root = Agent(
        name="root",
        instructions="t",
        model=model,
        tools=[stubs.lookup, as_tool_inner.as_tool(tool_name="research", tool_description="r")],
        handoffs=[helper, handoff(via_handoff)],
    )
    assert firewall_agent(aguard, root) is root
    for a in (root, helper, deep, via_handoff, as_tool_inner):  # before: only what was passed in by hand
        assert a.tools and all(_guarded(t) for t in a.tools), a.name
    # Twice is harmless: no tool is wrapped again.
    firewall_agent(aguard, root)
    first = root.tools[0]
    assert isinstance(first, FunctionTool)
    assert [g.get_name() for g in first.tool_input_guardrails or []] == ["launchsafe-firewall"]


class _StubMcpServer:
    name = "files"


def test_firewall_agent_refuses_what_it_cannot_gate(aguard: AsyncGuard) -> None:
    model = ScriptedModel([])
    with_mcp = Agent(name="m", instructions="m", model=model, mcp_servers=[_StubMcpServer()])  # type: ignore[list-item]
    with pytest.raises(TypeError, match="MCP servers"):
        firewall_agent(aguard, Agent(name="root", instructions="r", model=model, handoffs=[with_mcp]))
    assert firewall_agent(aguard, with_mcp, allow_mcp_servers=True) is with_mcp
    hosted = Agent(name="h", instructions="h", model=model, tools=[WebSearchTool()])
    stubs = Stubs()
    root = Agent(name="root", instructions="r", model=model, tools=[stubs.lookup, hosted.as_tool("x", "x")])
    with pytest.raises(TypeError, match="cannot be gated"):
        firewall_agent(aguard, root)
    assert not any(_guarded(t) for t in root.tools)  # checked before anything was changed


async def test_a_failing_tool_is_recorded_as_failed(served: Served, aguard: AsyncGuard) -> None:
    @function_tool
    def explode(x: str) -> str:
        """Raise (stub)."""
        raise ValueError("boom")

    model = ScriptedModel([[function_call("explode", {"x": "a"}, call_id="c1")], [assistant_message("ok")]])
    await Runner.run(_agent(model, firewall_tools(aguard, [explode])), "go")
    rec = served.fake.calls("/v1/sessions/agents-1/results")
    assert len(rec) == 1 and rec[0].body["failed"] is True  # before: recorded as an ordinary result


def test_parse_arguments() -> None:
    assert parse_arguments('{"a": 1}') == {"a": 1}
    assert parse_arguments("") == {}
    assert parse_arguments("[1]") == {"value": [1]}
    assert parse_arguments("not json") == {"arguments": "not json"}
