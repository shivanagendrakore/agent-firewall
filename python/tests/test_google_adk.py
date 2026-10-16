from __future__ import annotations

import warnings
from collections.abc import AsyncGenerator, AsyncIterator
from typing import Any

import pytest

pytest.importorskip("google.adk", reason="the google-adk extra is not installed")

with warnings.catch_warnings():
    # google-genai's import-time use of a typing alias that Python 3.14 deprecates; not ours to fix.
    warnings.simplefilter("ignore", DeprecationWarning)
    from google.adk.agents import LlmAgent
    from google.adk.apps import App
    from google.adk.code_executors.unsafe_local_code_executor import UnsafeLocalCodeExecutor
    from google.adk.models.base_llm import BaseLlm
    from google.adk.models.llm_request import LlmRequest
    from google.adk.models.llm_response import LlmResponse
    from google.adk.runners import InMemoryRunner
    from google.adk.tools.agent_tool import AgentTool
    from google.adk.tools.google_search_tool import google_search
    from google.genai import types
    from pydantic import Field

from launchsafe_firewall import AsyncClient, AsyncGuard, Client, Guard
from launchsafe_firewall.integrations.google_adk import FirewallPlugin, firewall_callbacks, unsupported_tools

from .fake_sidecar import Failure, Served

# ADK warns once per experimental feature it switches on by default.
pytestmark = pytest.mark.filterwarnings("ignore:\\[EXPERIMENTAL\\]:UserWarning")

TOOLS: dict[str, dict[str, Any]] = {
    "lookup": {"kind": "read", "results": "trusted", "privateData": False},
    "send_email": {"kind": "send"},
}

RAN: list[str] = []


def send_email(to: str, body: str) -> str:
    """Send an email (stub)."""
    RAN.append(f"send_email:{to}")
    return f"sent to {to}"


def lookup(key: str) -> str:
    """Look up a value (stub)."""
    RAN.append(f"lookup:{key}")
    return f"value for {key}: SECRET"


class ScriptedLlm(BaseLlm):
    """Calls the given tools in one turn, then says what the tools answered. No network."""

    calls: list[tuple[str, dict[str, Any]]]
    seen: list[list[types.FunctionResponse]] = Field(default_factory=list)

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        last = llm_request.contents[-1] if llm_request.contents else None
        answers = [p.function_response for p in (last.parts or []) if p.function_response] if last else []
        if answers:
            self.seen.append(answers)
            yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text="done")]))
            return
        parts = [
            types.Part(function_call=types.FunctionCall(name=n, args=a, id=f"call-{i}"))
            for i, (n, a) in enumerate(self.calls)
        ]
        yield LlmResponse(content=types.Content(role="model", parts=parts))


@pytest.fixture(autouse=True)
def _reset() -> None:
    RAN.clear()


@pytest.fixture
async def aguard(served: Served) -> AsyncIterator[AsyncGuard]:
    g = AsyncGuard(AsyncClient(**served.client_kwargs()), session="adk-1", tools=TOOLS)
    yield g
    await g.client.aclose()


def make_agent(*calls: tuple[str, dict[str, Any]], **kwargs: Any) -> tuple[LlmAgent, ScriptedLlm]:
    llm = ScriptedLlm(model="scripted", calls=list(calls), seen=[])
    return LlmAgent(name="a", model=llm, tools=[send_email, lookup], **kwargs), llm


async def run(agent: LlmAgent, plugins: list[Any] | None = None) -> list[types.Content]:
    runner = InMemoryRunner(app=App(name="adk_test", root_agent=agent, plugins=plugins or []))
    session = await runner.session_service.create_session(app_name=runner.app_name, user_id="u")
    out: list[types.Content] = []
    async for ev in runner.run_async(
        user_id="u", session_id=session.id, new_message=types.Content(role="user", parts=[types.Part(text="go")])
    ):
        if ev.content:
            out.append(ev.content)
    return out


def responses(llm: ScriptedLlm) -> dict[str, Any]:
    return {r.id or "": r.response for batch in llm.seen for r in batch}


async def test_plugin_allowed_runs_denied_does_not(served: Served, aguard: AsyncGuard) -> None:
    served.fake.verdicts["send_email"] = "deny"
    agent, llm = make_agent(("lookup", {"key": "k"}), ("send_email", {"to": "x", "body": "b"}))
    await run(agent, [FirewallPlugin(aguard)])
    assert RAN == ["lookup:k"]
    got = responses(llm)
    assert got["call-0"] == {"result": "value for k: [redacted]"}  # the sidecar's redacted copy
    assert got["call-1"] == {"error": "LaunchSafe Firewall: deny send_email"}
    rec = served.fake.calls("/v1/sessions/adk-1/results")
    assert [r.body["output"] for r in rec] == ["value for k: SECRET"]  # only the call that ran
    actions = [r.body["action"] for r in served.fake.calls("/v1/decide")]
    assert {"format": "native", "tool": "send_email", "input": {"to": "x", "body": "b"}, "callId": "call-1"} in actions


@pytest.mark.parametrize("verdict", ["ask", "hold"])
async def test_ask_and_hold_are_not_run(served: Served, aguard: AsyncGuard, verdict: str) -> None:
    served.fake.verdicts["send_email"] = verdict
    agent, llm = make_agent(("send_email", {"to": "x", "body": "b"}))
    await run(agent, [FirewallPlugin(aguard)])
    assert RAN == []
    assert verdict in responses(llm)["call-0"]["error"]
    assert served.fake.calls("/v1/sessions/adk-1/results") == []


async def test_hold_approved_in_the_firewall_runs(served: Served) -> None:
    served.fake.verdicts["send_email"] = "hold"
    served.fake.approval_script["*"] = ["approved"]
    async with AsyncGuard(AsyncClient(**served.client_kwargs()), tools=TOOLS, approval_timeout=5) as g:
        agent, llm = make_agent(("send_email", {"to": "x", "body": "b"}))
        await run(agent, [FirewallPlugin(g)])
        await g.client.aclose()
    assert RAN == ["send_email:x"]
    assert responses(llm)["call-0"] == {"result": "sent to x"}


async def test_sidecar_down_fails_closed(tcp: Served) -> None:
    tcp.fake.fail("/v1/decide", Failure(status=503))
    async with AsyncGuard(AsyncClient(**tcp.client_kwargs()), tools=TOOLS) as g:
        agent, llm = make_agent(("send_email", {"to": "x", "body": "b"}), ("lookup", {"key": "k"}))
        await run(agent, [FirewallPlugin(g)])
        await g.client.aclose()
    assert RAN == ["lookup:k"]  # a trusted read follows fail_open_reads; the send is denied
    assert "FW-UNAVAILABLE" in responses(llm)["call-0"]["error"]


async def test_agent_callbacks_without_a_plugin(served: Served, aguard: AsyncGuard) -> None:
    served.fake.verdicts["send_email"] = "deny"
    cb = firewall_callbacks(aguard)
    agent, llm = make_agent(
        ("lookup", {"key": "k"}),
        ("send_email", {"to": "x", "body": "b"}),
        before_tool_callback=cb.before,
        after_tool_callback=cb.after,
    )
    await run(agent)
    assert RAN == ["lookup:k"]
    got = responses(llm)
    assert got["call-0"] == {"result": "value for k: [redacted]"}
    assert "error" in got["call-1"]


async def test_a_blocking_guard_decides_in_a_thread(served: Served) -> None:
    served.fake.verdicts["send_email"] = "deny"
    guard = Guard(Client(**served.client_kwargs()), session="adk-1", tools=TOOLS)
    agent, llm = make_agent(("send_email", {"to": "x", "body": "b"}), ("lookup", {"key": "k"}))
    await run(agent, [FirewallPlugin(guard)])
    guard.client.close()
    assert RAN == ["lookup:k"]
    assert "error" in responses(llm)["call-0"]


async def test_provider_side_tools_are_refused(served: Served, aguard: AsyncGuard) -> None:
    # A Gemini model name: some ADK releases refuse google_search for any other model while they build the
    # request, before a plugin is asked, which would hide whether the plugin refuses it.
    llm = ScriptedLlm(model="gemini-2.5-flash", calls=[("lookup", {"key": "k"})], seen=[])
    agent = LlmAgent(name="a", model=llm, tools=[google_search])
    assert unsupported_tools(agent) == ["google_search"]
    out = await run(agent, [FirewallPlugin(aguard)])
    assert llm.seen == [] and RAN == []
    assert served.fake.requests == []
    assert "cannot be checked" in (out[0].parts or [])[0].text  # type: ignore[operator]


def test_function_tools_are_supported() -> None:
    agent, _ = make_agent()
    assert unsupported_tools(agent) == []


def test_any_code_executor_is_refused_unless_allowed() -> None:
    agent, _ = make_agent(code_executor=UnsafeLocalCodeExecutor())
    # Before: only BuiltInCodeExecutor counted; a local executor runs model-written code with no tool callback.
    assert unsupported_tools(agent) == ["UnsafeLocalCodeExecutor"]
    assert unsupported_tools(agent, allow_code_executor=True) == []


def test_agents_behind_agent_tools_are_checked() -> None:
    llm = ScriptedLlm(model="gemini-2.5-flash", calls=[], seen=[])
    inner = LlmAgent(name="searcher", model=llm, tools=[google_search])
    outer, _ = make_agent()
    outer.tools.append(AgentTool(agent=inner))
    assert unsupported_tools(outer) == ["google_search"]  # before: the AgentTool's agent was not looked into


async def test_callbacks_run_the_startup_check_too(served: Served, aguard: AsyncGuard) -> None:
    cb = firewall_callbacks(aguard)
    agent, llm = make_agent(
        ("lookup", {"key": "k"}),
        code_executor=UnsafeLocalCodeExecutor(),
        before_agent_callback=cb.before_agent,
        before_tool_callback=cb.before,
        after_tool_callback=cb.after,
    )
    out = await run(agent)
    assert RAN == [] and llm.seen == [] and served.fake.requests == []
    assert "cannot be checked" in (out[0].parts or [])[0].text  # type: ignore[operator]


async def test_callbacks_without_before_agent_still_refuse_each_tool(served: Served, aguard: AsyncGuard) -> None:
    cb = firewall_callbacks(aguard)
    agent, llm = make_agent(
        ("lookup", {"key": "k"}),
        code_executor=UnsafeLocalCodeExecutor(),
        before_tool_callback=cb.before,
        after_tool_callback=cb.after,
    )
    await run(agent)
    assert RAN == [] and served.fake.requests == []
    assert "cannot be checked" in responses(llm)["call-0"]["error"]


def explode(x: str) -> str:
    """Raise (stub)."""
    RAN.append(f"explode:{x}")
    raise ValueError("boom")


async def test_a_failing_tool_is_recorded_as_failed(served: Served, aguard: AsyncGuard) -> None:
    llm = ScriptedLlm(model="scripted", calls=[("explode", {"x": "a"})], seen=[])
    agent = LlmAgent(name="a", model=llm, tools=[explode])
    with pytest.raises(ValueError, match="boom"):
        await run(agent, [FirewallPlugin(aguard)])
    assert RAN == ["explode:a"]
    rec = served.fake.calls("/v1/sessions/adk-1/results")
    assert len(rec) == 1 and rec[0].body["failed"] is True and "boom" in rec[0].body["output"]
