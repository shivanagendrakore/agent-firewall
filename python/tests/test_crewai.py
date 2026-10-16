from __future__ import annotations

import threading
import warnings
from collections.abc import Iterator
from typing import Any

import pytest

pytest.importorskip("crewai", reason="the crewai extra is not installed")

with warnings.catch_warnings():
    # Third-party import-time deprecations under newer Pythons; not ours to fix.
    warnings.simplefilter("ignore")
    from crewai import Agent, Crew, Task
    from crewai.hooks import (
        ToolCallHookContext,
        clear_all_global_hooks,
        get_after_tool_call_hooks,
        get_before_tool_call_hooks,
    )
    from crewai.llms.base_llm import BaseLLM
    from crewai.tools import tool
    from pydantic import Field

from launchsafe_firewall import AsyncClient, AsyncGuard, Client, Guard
from launchsafe_firewall.integrations.crewai import firewall_hooks, install_firewall

from .fake_sidecar import Failure, Served

pytestmark = pytest.mark.filterwarnings("ignore")

TOOLS: dict[str, dict[str, Any]] = {
    "lookup": {"kind": "read", "results": "trusted", "privateData": False},
    "send_email": {"kind": "send"},
}

RAN: list[str] = []


@tool("send_email")
def send_email(to: str, body: str) -> str:
    """Send an email (stub)."""
    RAN.append(f"send_email:{to}")
    return f"sent to {to}"


@tool("lookup")
def lookup(key: str) -> str:
    """Look up a value (stub)."""
    RAN.append(f"lookup:{key}")
    return f"value for {key}: SECRET"


class ScriptedLLM(BaseLLM):
    """Reasons in CrewAI's ReAct format: calls each tool in turn, then answers. No network."""

    script: list[tuple[str, str]] = Field(default_factory=list)
    seen: list[str] = Field(default_factory=list)

    def call(self, messages: Any, *args: Any, **kwargs: Any) -> str:
        self.seen = (
            [str(m.get("content")) if isinstance(m, dict) else str(m) for m in messages]
            if isinstance(messages, list)
            else [str(messages)]
        )
        step = sum(1 for m in messages if isinstance(m, dict) and m.get("role") == "assistant")
        if step < len(self.script):
            name, arguments = self.script[step]
            return f"Thought: I need a tool.\nAction: {name}\nAction Input: {arguments}"
        return "Thought: I now know the final answer\nFinal Answer: done"

    def supports_function_calling(self) -> bool:
        return False


@pytest.fixture(autouse=True)
def _reset() -> Iterator[None]:
    RAN.clear()
    clear_all_global_hooks()
    yield
    clear_all_global_hooks()


@pytest.fixture
def guard(served: Served) -> Iterator[Guard]:
    g = Guard(Client(**served.client_kwargs()), session="crew-1", tools=TOOLS)
    yield g
    g.client.close()


def crew(*script: tuple[str, str]) -> tuple[Crew, ScriptedLLM]:
    llm = ScriptedLLM(model="scripted", script=list(script), seen=[])
    agent = Agent(role="r", goal="g", backstory="b", llm=llm, tools=[send_email, lookup], allow_delegation=False)
    task = Task(description="do it", expected_output="done", agent=agent)
    return Crew(agents=[agent], tasks=[task], verbose=False), llm


def observations(llm: ScriptedLLM) -> str:
    return "\n".join(llm.seen)


def test_allowed_runs_and_is_recorded(served: Served, guard: Guard) -> None:
    install_firewall(guard)
    c, llm = crew(("lookup", '{"key": "k"}'))
    c.kickoff()
    assert RAN == ["lookup:k"]
    assert "value for k: [redacted]" in observations(llm)  # the sidecar's redacted copy
    assert "SECRET" not in observations(llm)
    rec = served.fake.calls("/v1/sessions/crew-1/results")
    assert [r.body["output"] for r in rec] == ["value for k: SECRET"]
    action = served.fake.calls("/v1/decide")[0].body["action"]
    call_id = action.pop("callId")
    assert action == {"format": "native", "tool": "lookup", "input": {"key": "k"}}
    assert call_id.startswith("crewai-") and len(call_id) == 39


@tool("explode")
def explode(x: str) -> str:
    """Raise (stub)."""
    RAN.append(f"explode:{x}")
    raise ValueError("boom")


def test_a_failing_tool_is_recorded_as_failed(served: Served, guard: Guard) -> None:
    install_firewall(guard)
    llm = ScriptedLLM(model="scripted", script=[("explode", '{"x": "a"}')], seen=[])
    agent = Agent(role="r", goal="g", backstory="b", llm=llm, tools=[explode], allow_delegation=False)
    Crew(agents=[agent], tasks=[Task(description="do it", expected_output="done", agent=agent)]).kickoff()
    assert RAN[:1] == ["explode:a"]
    rec = served.fake.calls("/v1/sessions/crew-1/results")
    assert rec and rec[0].body.get("failed") is True, [r.body for r in rec]


def test_failure_detection() -> None:
    from launchsafe_firewall.integrations.crewai import _failed

    assert _failed("Error executing tool: boom")
    assert _failed("\nI encountered an error while trying to use the tool. This was the error: boom.")
    assert not _failed("ok") and not _failed(None)


def test_parallel_calls_of_one_tool_keep_their_own_decisions(served: Served, guard: Guard) -> None:
    hooks = firewall_hooks(guard)
    first_input, second_input = {"to": "a", "body": "1"}, {"to": "b", "body": "2"}

    def ctx(tool_input: dict[str, Any], result: str | None = None) -> ToolCallHookContext:
        # CrewAI makes a new context for the after hook, with the same tool_input dict.
        return ToolCallHookContext(
            tool_name="send_email",
            tool_input=tool_input,
            tool=send_email,  # type: ignore[arg-type]
            tool_result=result,
        )

    hooks.before(ctx(first_input))
    hooks.before(ctx(second_input))  # before: this replaced the first call's decision
    hooks.after(ctx(second_input, "sent 2"))
    hooks.after(ctx(first_input, "sent 1"))
    rec = {r.body["output"]: r.body["decisionId"] for r in served.fake.calls("/v1/sessions/crew-1/results")}
    assert rec == {"sent 2": "dec_2", "sent 1": "dec_1"}
    ids = [r.body["action"]["callId"] for r in served.fake.calls("/v1/decide")]
    assert len(set(ids)) == 2


def test_the_after_hook_sees_the_decision_from_another_context_or_thread(served: Served, guard: Guard) -> None:
    hooks = firewall_hooks(guard)
    tool_input = {"to": "a", "body": "1"}

    def ctx(result: str | None = None) -> ToolCallHookContext:
        return ToolCallHookContext(
            tool_name="send_email",
            tool_input=tool_input,
            tool=send_email,  # type: ignore[arg-type]
            tool_result=result,
        )

    t = threading.Thread(target=hooks.before, args=(ctx(),))
    t.start()
    t.join()
    hooks.after(ctx("sent"))  # a different thread and context from the before hook
    rec = served.fake.calls("/v1/sessions/crew-1/results")
    assert [r.body["output"] for r in rec] == ["sent"]


def test_the_decision_table_is_bounded(guard: Guard, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("launchsafe_firewall.integrations.crewai.MAX_DECIDED", 3)
    hooks = firewall_hooks(guard)
    kept = [{"key": str(i)} for i in range(6)]
    for tool_input in kept:
        ctx = ToolCallHookContext(tool_name="lookup", tool_input=tool_input, tool=lookup)  # type: ignore[arg-type]
        hooks.before(ctx)
    assert len(hooks._decided) == 3


def test_denied_message_reaches_the_model_and_the_tool_never_runs(served: Served, guard: Guard) -> None:
    served.fake.verdicts["send_email"] = "deny"
    install_firewall(guard)
    c, llm = crew(("send_email", '{"to": "x", "body": "b"}'))
    c.kickoff()
    assert RAN == []
    assert "LaunchSafe Firewall: deny send_email" in observations(llm)
    assert "blocked by hook" not in observations(llm)
    assert served.fake.calls("/v1/sessions/crew-1/results") == []  # nothing ran, nothing to record


@pytest.mark.parametrize("verdict", ["ask", "hold"])
def test_ask_and_hold_are_not_run(served: Served, guard: Guard, verdict: str) -> None:
    served.fake.verdicts["send_email"] = verdict
    install_firewall(guard)
    c, llm = crew(("send_email", '{"to": "x", "body": "b"}'))
    c.kickoff()
    assert RAN == []
    assert verdict in observations(llm)


def test_hold_approved_in_the_firewall_runs(served: Served) -> None:
    served.fake.verdicts["send_email"] = "hold"
    served.fake.approval_script["*"] = ["approved"]
    with Guard(Client(**served.client_kwargs()), tools=TOOLS, approval_timeout=5) as g:
        install_firewall(g)
        c, _ = crew(("send_email", '{"to": "x", "body": "b"}'))
        c.kickoff()
        g.client.close()
    assert RAN == ["send_email:x"]


def test_sidecar_down_fails_closed(tcp: Served) -> None:
    tcp.fake.fail("/v1/decide", Failure(status=503))
    with Guard(Client(**tcp.client_kwargs()), tools=TOOLS) as g:
        install_firewall(g)
        c, llm = crew(("send_email", '{"to": "x", "body": "b"}'))
        c.kickoff()
        g.client.close()
    assert RAN == []
    assert "FW-UNAVAILABLE" in observations(llm)


def test_sidecar_down_still_lets_a_trusted_read_run(tcp: Served) -> None:
    tcp.fake.fail("/v1/decide", Failure(status=503))
    with Guard(Client(**tcp.client_kwargs()), tools=TOOLS) as g:
        install_firewall(g)
        c, _ = crew(("lookup", '{"key": "k"}'))
        c.kickoff()
        g.client.close()
    assert RAN == ["lookup:k"]


async def test_async_crew_is_gated(served: Served, guard: Guard) -> None:
    served.fake.verdicts["send_email"] = "deny"
    install_firewall(guard)
    c, llm = crew(("send_email", '{"to": "x", "body": "b"}'))
    await c.kickoff_async()
    assert RAN == []
    assert "LaunchSafe Firewall: deny send_email" in observations(llm)


def test_a_hook_error_blocks_instead_of_failing_open(guard: Guard, monkeypatch: pytest.MonkeyPatch) -> None:
    hooks = firewall_hooks(guard)

    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(guard, "authorize", boom)
    ctx = ToolCallHookContext(tool_name="send_email", tool_input={"to": "x"}, tool=send_email)  # type: ignore[arg-type]
    from crewai.hooks import HookAborted

    with pytest.raises(HookAborted):
        hooks.before(ctx)


def test_install_and_uninstall(guard: Guard) -> None:
    uninstall = install_firewall(guard)
    assert len(get_before_tool_call_hooks()) == 1 and len(get_after_tool_call_hooks()) == 1
    uninstall()
    assert get_before_tool_call_hooks() == [] and get_after_tool_call_hooks() == []


async def test_an_async_guard_is_refused(served: Served) -> None:
    g = AsyncGuard(AsyncClient(**served.client_kwargs()), tools=TOOLS)
    with pytest.raises(TypeError, match="synchronous"):
        install_firewall(g)  # type: ignore[arg-type]
    await g.client.aclose()
