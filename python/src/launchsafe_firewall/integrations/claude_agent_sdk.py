"""Claude Agent SDK (`claude-agent-sdk`, Python) integration.

`claude_agent_firewall(guard)` returns the hooks (and a `can_use_tool` callback) to pass in
`ClaudeAgentOptions`. They use the SDK's own interception points:

- `PreToolUse` hook: authorizes every tool call Claude Code is about to make (built-in tools, MCP
  tools, sub-agents' tools). An allowed call produces no output, so Claude Code's own permission rules
  still apply after the firewall. An ask, hold or deny is answered with `permissionDecision: "deny"`
  and the firewall's message as the reason: the tool never runs and the model reads why. A guard with
  `approval_timeout` waits for a person in the firewall's queue (terminal, phone) first; approvals are
  given there, never by this process. Hooks also run under `permission_mode="bypassPermissions"`,
  where `can_use_tool` is never consulted, which is why the gate is a hook.
- `PostToolUse` hook: records what the tool returned (`guard.record_result`). When the sidecar sends
  a redacted copy it is returned as `updatedToolOutput`. Claude Code accepts a replacement for a
  built-in tool only if it matches that tool's output shape, and otherwise keeps the original: for
  tools with structured output, rely on the PreToolUse decision rather than on redaction.
- `PostToolUseFailure` hook: records a tool that failed, with `failed=True`.
- `UserPromptSubmit` hook: records the person's prompt (`guard.record_prompt`).

Every `HookMatcher` carries `timeout=hook_timeout` (600 s by default): without one Claude Code gives a
hook 60 s (claude-agent-sdk 0.2.166's `HookMatcher.timeout` docs), and a hook it times out is
non-blocking, so the tool would run undecided. An approval wait is cut to `hook_timeout - HOOK_MARGIN`
and an approval still pending then is denied, asking the model to retry later.
- `can_use_tool`: Claude Code calls it for permission prompts its own rules raise. The firewall never
  approves on its own: it hands the prompt to your `fallback`, and without one refuses it.

Calls in Claude Code's own tool vocabulary (`Bash`, `Read`, `WebFetch`, ...) go to the sidecar in the
`engine` format; `mcp__<server>__<tool>` names as MCP calls with an unstated (so untrusted) source. A
hook that cannot decide denies: Claude Code treats a hook that raises as non-blocking, so every
failure is caught here and turned into a deny.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from claude_agent_sdk import (
    CanUseTool,
    HookContext,
    HookInput,
    HookJSONOutput,
    HookMatcher,
    PermissionResult,
    PermissionResultDeny,
    ToolPermissionContext,
)
from claude_agent_sdk.types import HookEvent

from .._core import Authorization, ReportOutcome
from ..formats import engine, from_mcp_call
from ..guard import AsyncGuard, Guard
from ..types import Action

# Allowed calls waiting for their result to be recorded; ones whose tool never finished are dropped oldest first.
_MAX_IN_FLIGHT = 1000

DEFAULT_HOOK_TIMEOUT = 600.0
"""Seconds Claude Code gives each firewall hook: past the guard's default 300 s approval wait."""
HOOK_MARGIN = 30.0
"""Seconds of a hook's time kept for the decides and report flushes around a wait for a person."""

_PENDING = (
    "The approval is still pending in the LaunchSafe Agent Firewall's queue; "
    "retry the call after a person has answered it there."
)

_NO_FALLBACK = (
    "LaunchSafe Agent Firewall: no approval handler for this permission prompt, "
    "and the firewall never approves on its own."
)


def action_for(tool_name: str, tool_input: dict[str, Any], call_id: str | None) -> Action:
    """The sidecar's view of a Claude Code tool call."""
    if tool_name.startswith("mcp__"):
        _, _, rest = tool_name.partition("mcp__")
        server, sep, tool = rest.partition("__")
        if sep and server and tool:
            return from_mcp_call(server, name=tool, arguments=tool_input, call_id=call_id)
    return engine(tool_name, tool_input, call_id=call_id)


async def _authorize(guard: Guard | AsyncGuard, action: Action, max_wait: float) -> Authorization:
    if isinstance(guard, AsyncGuard):
        return await guard.authorize(action, max_wait=max_wait)
    return await asyncio.to_thread(guard.authorize, action, max_wait=max_wait)


async def _record(guard: Guard | AsyncGuard, auth: Authorization, output: Any, failed: bool | None) -> ReportOutcome:
    if isinstance(guard, AsyncGuard):
        return await guard.record_result(auth, output, failed=failed)
    return await asyncio.to_thread(guard.record_result, auth, output, failed=failed)


async def _record_prompt(guard: Guard | AsyncGuard, text: str) -> ReportOutcome:
    if isinstance(guard, AsyncGuard):
        return await guard.record_prompt(text)
    return await asyncio.to_thread(guard.record_prompt, text)


def _deny(reason: str) -> HookJSONOutput:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


@dataclass
class ClaudeAgentFirewall:
    """What to give `ClaudeAgentOptions`: `hooks=fw.hooks, can_use_tool=fw.can_use_tool`."""

    guard: Guard | AsyncGuard
    fallback: CanUseTool | None = None
    hook_timeout: float = DEFAULT_HOOK_TIMEOUT
    """Seconds Claude Code gives each firewall hook (`HookMatcher.timeout`). A wait for a person in the
    firewall's queue is cut to `hook_timeout - HOOK_MARGIN` and then denied as still pending, so the
    hook always answers before Claude Code would give up on it."""
    _in_flight: OrderedDict[str, Authorization] = field(
        default_factory=OrderedDict[str, Authorization], init=False, repr=False
    )

    def __post_init__(self) -> None:
        if not self.hook_timeout > HOOK_MARGIN:
            raise ValueError(f"hook_timeout must be more than {HOOK_MARGIN:g} seconds")

    @property
    def max_wait(self) -> float:
        """The longest a hook waits for a person before it denies the call as still pending."""
        return self.hook_timeout - HOOK_MARGIN

    @property
    def hooks(self) -> dict[HookEvent, list[HookMatcher]]:
        """Pass as `ClaudeAgentOptions(hooks=...)`; merge with your own hooks if you have any.

        Every matcher carries `timeout`: without one Claude Code applies its own default (60 s), shorter
        than an approval wait, and a hook it times out is non-blocking, so the tool would run undecided.
        """
        t = self.hook_timeout
        return {
            "PreToolUse": [HookMatcher(hooks=[self.pre_tool_use], timeout=t)],
            "PostToolUse": [HookMatcher(hooks=[self.post_tool_use], timeout=t)],
            "PostToolUseFailure": [HookMatcher(hooks=[self.post_tool_use_failure], timeout=t)],
            "UserPromptSubmit": [HookMatcher(hooks=[self.user_prompt_submit], timeout=t)],
        }

    async def pre_tool_use(self, input: HookInput, tool_use_id: str | None, context: HookContext) -> HookJSONOutput:
        if input.get("hook_event_name") != "PreToolUse":
            return {}
        name = str(input.get("tool_name", ""))
        try:
            raw_input = input.get("tool_input")
            tool_args: dict[str, Any] = dict(raw_input) if isinstance(raw_input, dict) else {}
            call_id = str(input.get("tool_use_id") or tool_use_id or "") or None
            auth = await _authorize(self.guard, action_for(name, tool_args, call_id), self.max_wait)
        except Exception as e:  # never let an error out: Claude Code would treat a raising hook as non-blocking
            return _deny(
                f"LaunchSafe Agent Firewall could not check this action ({type(e).__name__}) and blocked it to be safe."
            )
        if auth.allowed:
            if call_id is not None:
                self._in_flight[call_id] = auth
                while len(self._in_flight) > _MAX_IN_FLIGHT:
                    self._in_flight.popitem(last=False)
            return {}
        message = auth.message or f"LaunchSafe Agent Firewall did not allow {name}."
        cut_short = self.guard.longest_wait() > self.max_wait
        if cut_short and auth.approval is not None and auth.approval.status == "pending":
            message += f"\n{_PENDING}"  # the guard would have waited longer than the hook may
        return _deny(message)

    async def _record_after(
        self, input: HookInput, tool_use_id: str | None, output: Any, failed: bool | None
    ) -> ReportOutcome | None:
        call_id = str(input.get("tool_use_id") or tool_use_id or "")
        auth = self._in_flight.pop(call_id, None)
        if auth is None:
            return None
        try:
            return await _record(self.guard, auth, output, failed)
        except Exception:
            return None

    async def post_tool_use(self, input: HookInput, tool_use_id: str | None, context: HookContext) -> HookJSONOutput:
        if input.get("hook_event_name") != "PostToolUse":
            return {}
        out = await self._record_after(input, tool_use_id, input.get("tool_response"), None)
        if out is None or out.output is None:
            return {}
        # The sidecar masked something (redactSecretsInOutput): the model gets the masked copy.
        return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": out.output}}

    async def post_tool_use_failure(
        self, input: HookInput, tool_use_id: str | None, context: HookContext
    ) -> HookJSONOutput:
        """A tool that ran and failed: its error is recorded with `failed=True` (the identical-failures limit)."""
        if input.get("hook_event_name") != "PostToolUseFailure":
            return {}
        await self._record_after(input, tool_use_id, input.get("error"), True)
        return {}

    async def user_prompt_submit(
        self, input: HookInput, tool_use_id: str | None, context: HookContext
    ) -> HookJSONOutput:
        if input.get("hook_event_name") == "UserPromptSubmit":
            try:
                await _record_prompt(self.guard, str(input.get("prompt", "")))
            except Exception:  # a lost prompt only makes decisions stricter
                return {}
        return {}

    async def can_use_tool(
        self, tool_name: str, tool_input: dict[str, Any], context: ToolPermissionContext
    ) -> PermissionResult:
        """For permission prompts Claude Code's own rules raise: your `fallback`, else a refusal."""
        if self.fallback is not None:
            return await self.fallback(tool_name, tool_input, context)
        return PermissionResultDeny(message=_NO_FALLBACK)


def claude_agent_firewall(
    guard: Guard | AsyncGuard,
    *,
    fallback: Callable[[str, dict[str, Any], ToolPermissionContext], Awaitable[PermissionResult]] | None = None,
    hook_timeout: float = DEFAULT_HOOK_TIMEOUT,
) -> ClaudeAgentFirewall:
    """Hooks and `can_use_tool` that put every Claude Code tool call through the firewall.

    `fallback` is your own `can_use_tool`, for permission prompts the firewall did not raise.
    `hook_timeout`: seconds Claude Code gives each hook; approval waits are cut to fit inside it.
    """
    return ClaudeAgentFirewall(guard, fallback, hook_timeout)


__all__ = ["DEFAULT_HOOK_TIMEOUT", "HOOK_MARGIN", "ClaudeAgentFirewall", "action_for", "claude_agent_firewall"]
