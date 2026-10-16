from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest

pytest.importorskip("langgraph", reason="the langgraph extra is not installed")

from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.types import Command

from launchsafe_firewall import AsyncClient, AsyncGuard, Client, Guard
from launchsafe_firewall.integrations.langgraph import firewall_tool_node

from .fake_sidecar import Failure, Served

TOOLS: dict[str, dict[str, Any]] = {
    "lookup": {"kind": "read", "results": "trusted", "privateData": False},
    "send_email": {"kind": "send"},
}

RAN: list[str] = []


@tool
def send_email(to: str, body: str) -> str:
    """Send an email (stub)."""
    RAN.append(f"send_email:{to}")
    return f"sent to {to}"


@tool
def lookup(key: str) -> str:
    """Look up a value (stub)."""
    RAN.append(f"lookup:{key}")
    return f"value for {key}: SECRET"


@tool
def remember(note: str, tool_call_id: str = "") -> Command[Any]:
    """Return a Command (stub)."""
    RAN.append(f"remember:{note}")
    return Command(update={"messages": [ToolMessage(content=f"noted {note}", tool_call_id="c9")]})


@tool
def remember_secret(note: str) -> Command[Any]:
    """Return a Command whose ToolMessage holds a secret (stub)."""
    RAN.append(f"remember_secret:{note}")
    return Command(update={"messages": [ToolMessage(content=f"noted {note}: SECRET", tool_call_id="c9")]})


@tool
def remember_more(note: str) -> Command[Any]:
    """Return a Command with two messages, one holding a secret (stub)."""
    RAN.append(f"remember_more:{note}")
    return Command(
        update={
            "messages": [
                ToolMessage(content=f"noted {note}", tool_call_id="c9"),
                ToolMessage(content="other SECRET", tool_call_id="c10"),
            ]
        }
    )


@tool
def remember_failure(note: str) -> Command[Any]:
    """Return a Command whose ToolMessage reports an error (stub)."""
    RAN.append(f"remember_failure:{note}")
    return Command(update={"messages": [ToolMessage(content="disk full", tool_call_id="c9", status="error")]})


@tool
def explode(x: str) -> str:
    """Raise (stub)."""
    RAN.append(f"explode:{x}")
    raise ValueError("boom")


@pytest.fixture(autouse=True)
def _reset() -> None:
    RAN.clear()


@pytest.fixture
def guard(served: Served) -> Iterator[Guard]:
    g = Guard(Client(**served.client_kwargs()), session="lg-1", tools=TOOLS)
    yield g
    g.client.close()


@pytest.fixture
async def aguard(served: Served) -> AsyncIterator[AsyncGuard]:
    g = AsyncGuard(AsyncClient(**served.client_kwargs()), session="lg-1", tools=TOOLS)
    yield g
    await g.client.aclose()


def turn(*calls: tuple[str, dict[str, Any], str]) -> dict[str, list[BaseMessage]]:
    ai = AIMessage(content="", tool_calls=[{"name": n, "args": a, "id": i, "type": "tool_call"} for n, a, i in calls])
    return {"messages": [ai]}


def graph(node: Any, *calls: tuple[str, dict[str, Any], str]) -> Any:
    """A model step that emits one turn of tool calls, then the guarded tool node."""

    def model(state: MessagesState) -> dict[str, list[BaseMessage]]:
        return turn(*calls)

    g = StateGraph(MessagesState)
    g.add_node("model", model)
    g.add_node("tools", node)
    g.add_edge(START, "model")
    g.add_edge("model", "tools")
    g.add_edge("tools", END)
    return g.compile()


def _msgs(final: Any) -> list[ToolMessage]:
    return [m for m in final["messages"] if isinstance(m, ToolMessage)]


def run(node: Any, *calls: tuple[str, dict[str, Any], str]) -> list[ToolMessage]:
    return _msgs(graph(node, *calls).invoke({"messages": []}))


async def arun(node: Any, *calls: tuple[str, dict[str, Any], str]) -> list[ToolMessage]:
    return _msgs(await graph(node, *calls).ainvoke({"messages": []}))


def test_allowed_runs_denied_does_not(served: Served, guard: Guard) -> None:
    served.fake.verdicts["send_email"] = "deny"
    node = firewall_tool_node(guard, [send_email, lookup])
    out = run(node, ("lookup", {"key": "k"}, "c1"), ("send_email", {"to": "x", "body": "b"}, "c2"))
    assert RAN == ["lookup:k"]
    by_id = {m.tool_call_id: m for m in out}
    assert by_id["c1"].content == "value for k: [redacted]"  # the sidecar's redacted copy
    assert by_id["c2"].status == "error"
    assert by_id["c2"].content == "LaunchSafe Firewall: deny send_email"
    rec = served.fake.calls("/v1/sessions/lg-1/results")
    # Tool calls run in parallel, so the decision ids come in either order.
    assert [r.body["output"] for r in rec] == ["value for k: SECRET"]
    lookup_decision = next(r for r in served.fake.calls("/v1/decide") if r.body["action"]["tool"] == "lookup")
    assert rec[0].body["decisionId"] == served.fake.idempotent[lookup_decision.headers["idempotency-key"]]["decisionId"]
    actions = [r.body["action"] for r in served.fake.calls("/v1/decide")]
    assert {"format": "native", "tool": "send_email", "input": {"to": "x", "body": "b"}, "callId": "c2"} in actions


@pytest.mark.parametrize("verdict", ["ask", "hold"])
def test_ask_and_hold_are_not_run(served: Served, guard: Guard, verdict: str) -> None:
    served.fake.verdicts["send_email"] = verdict
    out = run(firewall_tool_node(guard, [send_email]), ("send_email", {"to": "x", "body": "b"}, "c1"))
    assert RAN == []
    assert out[0].status == "error" and verdict in str(out[0].content)


def test_ask_approved_in_the_firewall_runs(served: Served) -> None:
    served.fake.verdicts["send_email"] = "hold"
    served.fake.approval_script["*"] = ["approved"]
    with Guard(Client(**served.client_kwargs()), tools=TOOLS, approval_timeout=5) as g:
        out = run(firewall_tool_node(g, [send_email]), ("send_email", {"to": "x", "body": "b"}, "c1"))
        g.client.close()
    assert RAN == ["send_email:x"]
    assert out[0].content == "sent to x"


def test_ask_runs_after_the_queue_approves_with_wait_for_approval(served: Served) -> None:
    served.fake.verdicts["send_email"] = "ask"
    served.fake.approval_script["*"] = ["approved"]
    with Guard(Client(**served.client_kwargs()), tools=TOOLS, wait_for_approval=True, approval_timeout=5) as g:
        out = run(firewall_tool_node(g, [send_email]), ("send_email", {"to": "x", "body": "b"}, "c1"))
        g.client.close()
    assert RAN == ["send_email:x"] and out[0].content == "sent to x"


def test_sidecar_down_fails_closed(tcp: Served) -> None:
    tcp.fake.fail("/v1/decide", Failure(status=503))
    with Guard(Client(**tcp.client_kwargs()), tools=TOOLS) as g:
        node = firewall_tool_node(g, [send_email, lookup])
        out = run(node, ("send_email", {"to": "x", "body": "b"}, "c1"), ("lookup", {"key": "k"}, "c2"))
        g.client.close()
    assert RAN == ["lookup:k"]
    assert "FW-UNAVAILABLE" in str(next(m for m in out if m.tool_call_id == "c1").content)


def test_a_command_result_is_recorded(served: Served, guard: Guard) -> None:
    out = run(firewall_tool_node(guard, [remember]), ("remember", {"note": "n"}, "c9"))
    assert RAN == ["remember:n"]
    assert [m.content for m in out] == ["noted n"]
    assert served.fake.calls("/v1/sessions/lg-1/results")[0].body["output"] == "noted n"


def test_a_command_result_is_redacted_inside_the_command(served: Served, guard: Guard) -> None:
    out = run(firewall_tool_node(guard, [remember_secret]), ("remember_secret", {"note": "n"}, "c9"))
    assert RAN == ["remember_secret:n"]
    assert [m.content for m in out] == ["noted n: [redacted]"]  # before: the secret reached the model
    assert served.fake.calls("/v1/sessions/lg-1/results")[0].body["output"] == "noted n: SECRET"


def test_a_structured_command_that_needs_masking_is_not_delivered(served: Served, guard: Guard) -> None:
    out = run(firewall_tool_node(guard, [remember_more]), ("remember_more", {"note": "n"}, "c9"))
    assert RAN == ["remember_more:n"]
    assert len(out) == 1 and out[0].status == "error" and "SECRET" not in str(out[0].content)
    assert "cannot mask" in str(out[0].content)
    # Recorded as structure: every message's content, not a repr.
    rec = served.fake.calls("/v1/sessions/lg-1/results")[0].body["output"]
    assert rec == {"messages": ["noted n", "other SECRET"]}


def test_a_command_reporting_an_error_is_recorded_as_failed(served: Served, guard: Guard) -> None:
    out = run(firewall_tool_node(guard, [remember_failure]), ("remember_failure", {"note": "n"}, "c9"))
    assert out[0].status == "error"
    assert served.fake.calls("/v1/sessions/lg-1/results")[0].body == {
        "decisionId": "dec_1",
        "output": "disk full",
        "failed": True,
    }


def test_a_failing_tool_is_recorded_as_failed(served: Served, guard: Guard) -> None:
    node = firewall_tool_node(guard, [explode], handle_tool_errors=True)
    out = run(node, ("explode", {"x": "a"}, "c1"))
    assert RAN == ["explode:a"] and out[0].status == "error"
    rec = served.fake.calls("/v1/sessions/lg-1/results")
    assert len(rec) == 1 and rec[0].body["failed"] is True and "boom" in str(rec[0].body["output"])


async def test_a_failing_tool_is_recorded_as_failed_async(served: Served, aguard: AsyncGuard) -> None:
    node = firewall_tool_node(aguard, [explode], handle_tool_errors=True)
    out = await arun(node, ("explode", {"x": "a"}, "c1"))
    assert out[0].status == "error"
    rec = served.fake.calls("/v1/sessions/lg-1/results")
    assert len(rec) == 1 and rec[0].body["failed"] is True


async def test_a_raising_tool_is_recorded_as_failed_and_raised_on(served: Served, guard: Guard) -> None:
    node = firewall_tool_node(guard, [explode], handle_tool_errors=False)
    with pytest.raises(ValueError, match="boom"):
        await arun(node, ("explode", {"x": "a"}, "c1"))
    rec = served.fake.calls("/v1/sessions/lg-1/results")
    assert len(rec) == 1 and rec[0].body["failed"] is True and "ValueError" in rec[0].body["output"]


async def test_async_guard_in_a_graph(served: Served, aguard: AsyncGuard) -> None:
    served.fake.verdicts["send_email"] = "deny"
    node = firewall_tool_node(aguard, [send_email, lookup])
    out = await arun(node, ("lookup", {"key": "k"}, "c1"), ("send_email", {"to": "x", "body": "b"}, "c2"))
    assert RAN == ["lookup:k"]
    tm = {m.tool_call_id: m for m in out}
    assert tm["c2"].status == "error"
    assert tm["c1"].content == "value for k: [redacted]"


def test_an_async_guard_refuses_blocking_invoke(served: Served, aguard: AsyncGuard) -> None:
    out = run(firewall_tool_node(aguard, [send_email]), ("send_email", {"to": "x", "body": "b"}, "c1"))
    assert RAN == []
    assert "ainvoke" in str(out[0].content)
    assert served.fake.requests == []


async def test_a_blocking_guard_on_ainvoke(served: Served, guard: Guard) -> None:
    served.fake.verdicts["send_email"] = "deny"
    node = firewall_tool_node(guard, [send_email, lookup])
    out = await arun(node, ("send_email", {"to": "x", "body": "b"}, "c1"), ("lookup", {"key": "k"}, "c2"))
    assert RAN == ["lookup:k"]
    assert {m.tool_call_id: m.status for m in out} == {"c1": "error", "c2": "success"}


def test_own_wrappers_are_refused(guard: Guard) -> None:
    with pytest.raises(ValueError, match="wrap_tool_call"):
        firewall_tool_node(guard, [lookup], wrap_tool_call=lambda r, e: e(r))
