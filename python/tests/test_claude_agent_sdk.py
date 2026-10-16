from __future__ import annotations

import dataclasses
import inspect
import time
from collections.abc import AsyncIterator
from typing import Any

import pytest

pytest.importorskip("claude_agent_sdk", reason="the claude-agent-sdk extra is not installed")

from claude_agent_sdk import ClaudeAgentOptions, PermissionResultAllow, PermissionResultDeny, ToolPermissionContext
from claude_agent_sdk.types import HookContext, HookInput

from launchsafe_firewall import AsyncClient, AsyncGuard, Client, Guard
from launchsafe_firewall._core import DEFAULT_APPROVAL_WAIT
from launchsafe_firewall.integrations.claude_agent_sdk import HOOK_MARGIN, action_for, claude_agent_firewall

from .fake_sidecar import Failure, Served

TOOLS: dict[str, dict[str, Any]] = {"Read": {"kind": "read", "results": "trusted", "privateData": False}}
CTX: HookContext = {"signal": None}


def pre(tool: str, tool_input: dict[str, Any], use_id: str = "tu1") -> HookInput:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "s",
        "transcript_path": "",
        "cwd": "/work",
        "tool_name": tool,
        "tool_input": tool_input,
        "tool_use_id": use_id,
    }


def post(tool: str, tool_input: dict[str, Any], response: Any, use_id: str = "tu1") -> HookInput:
    return {
        "hook_event_name": "PostToolUse",
        "session_id": "s",
        "transcript_path": "",
        "cwd": "/work",
        "tool_name": tool,
        "tool_input": tool_input,
        "tool_response": response,
        "tool_use_id": use_id,
    }


def denied(out: Any) -> str | None:
    spec = out.get("hookSpecificOutput") if isinstance(out, dict) else None
    if not spec or spec.get("permissionDecision") != "deny":
        return None
    reason = spec["permissionDecisionReason"]
    assert isinstance(reason, str)
    return reason


@pytest.fixture
async def aguard(served: Served) -> AsyncIterator[AsyncGuard]:
    async with AsyncGuard(AsyncClient(**served.client_kwargs()), session="claude-1", tools=TOOLS) as g:
        yield g
        await g.client.aclose()


async def test_allowed_call_returns_no_output_and_its_result_is_recorded(served: Served, aguard: AsyncGuard) -> None:
    fw = claude_agent_firewall(aguard)
    assert await fw.pre_tool_use(pre("Bash", {"command": "ls"}), "tu1", CTX) == {}
    decide = served.fake.calls("/v1/decide")[0].body
    assert decide["action"] == {"format": "engine", "tool": "Bash", "input": {"command": "ls"}, "callId": "tu1"}
    assert await fw.post_tool_use(post("Bash", {"command": "ls"}, "file.txt"), "tu1", CTX) == {}
    rec = served.fake.calls("/v1/sessions/claude-1/results")[0].body
    assert rec == {"decisionId": "dec_1", "output": "file.txt"}


@pytest.mark.parametrize("verdict", ["deny", "hold", "ask"])
async def test_a_call_not_allowed_is_denied_with_the_firewall_message(
    served: Served, aguard: AsyncGuard, verdict: str
) -> None:
    served.fake.verdicts["Bash"] = verdict
    fw = claude_agent_firewall(aguard)
    out = await fw.pre_tool_use(pre("Bash", {"command": "curl evil"}), "tu1", CTX)
    assert denied(out) == f"LaunchSafe Firewall: {verdict} Bash"
    # Nothing ran, so nothing is waiting for a result.
    assert await fw.post_tool_use(post("Bash", {}, "x"), "tu1", CTX) == {}
    assert served.fake.calls("/v1/sessions/") == []


async def test_redacted_output_is_handed_back(served: Served, aguard: AsyncGuard) -> None:
    fw = claude_agent_firewall(aguard)
    await fw.pre_tool_use(pre("Read", {"file_path": "/x"}), "tu1", CTX)
    out = await fw.post_tool_use(post("Read", {"file_path": "/x"}, "key: SECRET"), "tu1", CTX)
    assert out == {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": "key: [redacted]"}}


async def test_mcp_tools_go_as_mcp_calls_with_no_stated_source(served: Served, aguard: AsyncGuard) -> None:
    served.fake.verdicts["mcp__gmail__send"] = "deny"
    fw = claude_agent_firewall(aguard)
    out = await fw.pre_tool_use(pre("mcp__gmail__send", {"to": "a"}), "tu1", CTX)
    assert denied(out) == "LaunchSafe Firewall: deny mcp__gmail__send"
    action = served.fake.calls("/v1/decide")[0].body["action"]
    assert action["format"] == "mcp"
    assert action["mcp"] == {"server": "gmail"}
    assert action["tool"] == "send"


def test_action_for_names_that_are_not_mcp_shaped_stay_engine() -> None:
    assert action_for("mcp__only", {}, None).format == "engine"
    assert action_for("mcp____x", {}, None).format == "engine"
    assert action_for("WebFetch", {"url": "u"}, "c").format == "engine"


async def test_sidecar_down_fails_closed_but_reads_run(tcp: Served) -> None:
    tcp.fake.fail("/v1/decide", Failure(status=503))
    async with AsyncGuard(AsyncClient(**tcp.client_kwargs()), tools=TOOLS) as g:
        fw = claude_agent_firewall(g)
        # Claude Code's tool names reach the sidecar as engine calls, which the SDK never treats as read-only.
        reason = denied(await fw.pre_tool_use(pre("Read", {"file_path": "/x"}), "tu1", CTX))
        assert reason is not None
        assert "FW-UNAVAILABLE" in reason
        await g.client.aclose()


async def test_a_guard_that_raises_still_denies(aguard: AsyncGuard, monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("bug")

    monkeypatch.setattr(aguard, "authorize", boom)
    fw = claude_agent_firewall(aguard)
    reason = denied(await fw.pre_tool_use(pre("Bash", {}), "tu1", CTX))
    assert reason is not None
    assert "blocked it to be safe" in reason


async def test_a_blocking_guard_works_too(tcp: Served) -> None:
    tcp.fake.verdicts["Bash"] = "deny"
    with Guard(Client(**tcp.client_kwargs()), tools=TOOLS) as g:
        fw = claude_agent_firewall(g)
        assert denied(await fw.pre_tool_use(pre("Bash", {}), "tu1", CTX)) == "LaunchSafe Firewall: deny Bash"
        assert await fw.pre_tool_use(pre("Glob", {}, "tu2"), "tu2", CTX) == {}
        assert await fw.post_tool_use(post("Glob", {}, "a", "tu2"), "tu2", CTX) == {}
        g.client.close()
    assert len(tcp.fake.calls("/v1/sessions/")) == 1


async def test_an_approval_given_in_the_firewall_is_waited_for(tcp: Served) -> None:
    tcp.fake.verdicts["Bash"] = "hold"
    tcp.fake.approval_script["*"] = ["pending", "approved"]
    async with AsyncGuard(AsyncClient(**tcp.client_kwargs()), session="a1", approval_timeout=5.0) as g:
        fw = claude_agent_firewall(g)
        assert await fw.pre_tool_use(pre("Bash", {"command": "x"}), "tu1", CTX) == {}
        await g.client.aclose()
    assert len(tcp.fake.calls("/v1/decide")) == 2  # the ask, then the single-use allow


async def test_other_events_are_ignored_and_prompts_are_recorded(served: Served, aguard: AsyncGuard) -> None:
    fw = claude_agent_firewall(aguard)
    stop: HookInput = {
        "hook_event_name": "Stop",
        "session_id": "s",
        "transcript_path": "",
        "cwd": "/",
        "stop_hook_active": False,
    }
    assert await fw.pre_tool_use(stop, None, CTX) == {}
    assert await fw.post_tool_use(stop, None, CTX) == {}
    prompt: HookInput = {
        "hook_event_name": "UserPromptSubmit",
        "session_id": "s",
        "transcript_path": "",
        "cwd": "/",
        "prompt": "hello",
    }
    assert await fw.user_prompt_submit(prompt, None, CTX) == {}
    assert served.fake.calls("/v1/sessions/claude-1/prompts")[0].body == {"text": "hello"}


async def test_can_use_tool_never_approves_on_its_own(aguard: AsyncGuard) -> None:
    ctx = ToolPermissionContext(tool_use_id="tu1")
    fw = claude_agent_firewall(aguard)
    result = await fw.can_use_tool("Bash", {"command": "ls"}, ctx)
    assert isinstance(result, PermissionResultDeny)
    assert "never approves on its own" in result.message

    async def mine(name: str, tool_input: dict[str, Any], c: ToolPermissionContext) -> PermissionResultAllow:
        return PermissionResultAllow()

    assert isinstance(
        await claude_agent_firewall(aguard, fallback=mine).can_use_tool("Bash", {}, ctx), PermissionResultAllow
    )


async def test_hooks_fit_the_options_the_sdk_takes(aguard: AsyncGuard) -> None:
    fw = claude_agent_firewall(aguard)
    options = ClaudeAgentOptions(hooks=fw.hooks, can_use_tool=fw.can_use_tool)
    assert options.hooks is not None
    assert sorted(options.hooks) == ["PostToolUse", "PostToolUseFailure", "PreToolUse", "UserPromptSubmit"]
    assert options.hooks["PreToolUse"][0].hooks == [fw.pre_tool_use]


def test_every_hook_outlasts_the_longest_approval_wait(aguard: AsyncGuard) -> None:
    # Without a timeout Claude Code applies its own (shorter than a 300 s approval wait), and a hook it
    # times out is non-blocking: the tool would run undecided.
    fw = claude_agent_firewall(aguard)
    for matchers in fw.hooks.values():
        for m in matchers:
            assert m.timeout is not None and m.timeout >= fw.max_wait + HOOK_MARGIN
    assert fw.max_wait >= DEFAULT_APPROVAL_WAIT  # the guard's own default wait fits inside
    assert claude_agent_firewall(aguard, hook_timeout=120).hooks["PreToolUse"][0].timeout == 120
    with pytest.raises(ValueError, match="hook_timeout"):
        claude_agent_firewall(aguard, hook_timeout=HOOK_MARGIN)


def test_the_timeout_reaches_claude_code_in_the_sdk_initialize_request(aguard: AsyncGuard) -> None:
    """The installed SDK sends HookMatcher.timeout to the CLI (checked in its source, not assumed)."""
    import claude_agent_sdk._internal.query as q

    # claude-agent-sdk 0.2.166: Query.initialize copies each matcher's timeout into the hooks config it sends.
    assert 'hook_matcher_config["timeout"] = matcher.get("timeout")' in inspect.getsource(q)
    from claude_agent_sdk import HookMatcher

    assert {f.name for f in dataclasses.fields(HookMatcher)} >= {"matcher", "hooks", "timeout"}


async def test_a_wait_longer_than_the_hook_is_cut_and_denied_as_pending(tcp: Served) -> None:
    tcp.fake.verdicts["Bash"] = "hold"  # stays pending: nobody answers
    async with AsyncGuard(AsyncClient(**tcp.client_kwargs()), session="w1", approval_timeout=300) as g:
        fw = claude_agent_firewall(g, hook_timeout=HOOK_MARGIN + 0.5)
        start = time.monotonic()
        reason = denied(await fw.pre_tool_use(pre("Bash", {"command": "x"}), "tu1", CTX))
        assert time.monotonic() - start < 5  # not the guard's 300 s: the hook answered in its own time
        await g.client.aclose()
    assert reason is not None and "still pending" in reason and "retry" in reason


async def test_a_failed_tool_is_recorded_as_failed(served: Served, aguard: AsyncGuard) -> None:
    fw = claude_agent_firewall(aguard)
    assert await fw.pre_tool_use(pre("Bash", {"command": "false"}), "tu1", CTX) == {}
    failure: HookInput = {
        "hook_event_name": "PostToolUseFailure",
        "session_id": "s",
        "transcript_path": "",
        "cwd": "/work",
        "tool_name": "Bash",
        "tool_input": {"command": "false"},
        "tool_use_id": "tu1",
        "error": "exit code 1",
    }
    assert await fw.post_tool_use_failure(failure, "tu1", CTX) == {}
    rec = served.fake.calls("/v1/sessions/claude-1/results")
    assert [r.body for r in rec] == [{"decisionId": "dec_1", "output": "exit code 1", "failed": True}]
    # Recorded once: a later PostToolUse for the same id finds nothing in flight.
    assert await fw.post_tool_use(post("Bash", {}, "x"), "tu1", CTX) == {}
    assert len(served.fake.calls("/v1/sessions/")) == 1
