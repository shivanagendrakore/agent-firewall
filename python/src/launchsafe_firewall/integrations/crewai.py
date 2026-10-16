"""CrewAI (`crewai`, Python) integration.

CrewAI's own interception points for tool calls are the tool-call hooks (`crewai.hooks`):
`before_tool_call` runs before every tool call of every agent and crew, and `after_tool_call` after it.
`install_firewall(guard)` registers one of each:

- the before hook authorizes the call (`guard.authorize`). An allowed call runs. An ask, hold or deny
  aborts it (`HookAborted`), so the tool never runs. A guard with `approval_timeout` waits for a
  person in the firewall's queue first (terminal, phone); `context.request_human_input` is not a
  firewall approval and is not used.
- the after hook gives the model the firewall's message in place of CrewAI's own generic "Tool execution
  blocked by hook" text (CrewAI runs after hooks for blocked calls too), and, for a call that ran,
  records what the tool returned (`guard.record_result`); when the sidecar returns a redacted copy, the
  model is given that instead.

Things to know:

- CrewAI swallows any exception a hook raises other than `HookAborted` and lets the call through
  (fail-open). These hooks therefore turn every unexpected error into an abort: a hook that fails
  never lets a tool run.
- Hooks are global to the process (every crew, every agent), and `crewai.hooks` runs them in
  registration order. Install the firewall after your own hooks, so a hook that edits `tool_input`
  runs before the firewall authorizes what will really run.
- Hooks are synchronous, also when the crew runs under `kickoff_async` / `akickoff`, so they take a
  blocking `Guard` (an `AsyncGuard` is refused: it cannot be awaited from a hook). A decision takes
  a few milliseconds, and as long as the approval wait if you set `approval_timeout`; a crew running
  on an event loop is paused for that time.
- The registry name of a tool is the name CrewAI gives the model: lowercase letters, digits and
  underscores (`"Send Email"` is `send_email`).
- The hooks see tool calls made through the agent executors, MCP tools and platform tools included.
  Tools the model provider runs on its own side (provider built-in search or code tools) do not
  reach them and cannot be gated; report their results with `guard.report_input`.
"""

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from crewai.hooks import (
    HookAborted,
    ToolCallHookContext,
    register_after_tool_call_hook,
    register_before_tool_call_hook,
    unregister_after_tool_call_hook,
    unregister_before_tool_call_hook,
)

from .._core import Authorization
from ..formats import native
from ..guard import AsyncGuard, Guard

# What each call was decided as, between its before and after hook. CrewAI builds a new hook context for
# the after hook, but hands both the same `tool_input` dict (crewai 1.15: `args_dict` / `tool_input` in
# the tool-execution paths), so a call is keyed by its tool name and that dict's identity, which is kept
# alive in the entry: two parallel calls of the same tool never share a decision. The table is plain
# instance state under a lock, not a ContextVar: the before and after hooks may run in different contexts
# (a worker thread, a copied context), where a ContextVar set by one is invisible to the other.
_Key = tuple[str, int]
MAX_DECIDED = 1000  # calls whose after hook never ran (a crashed tool) are forgotten, oldest first


_ToolFailure: type | None
try:  # crewai 1.15.28 and later: a tool's own failure report
    from crewai.tools.tool_failure import ToolFailure

    _ToolFailure = ToolFailure
except ImportError:  # pragma: no cover - older crewai
    _ToolFailure = None

# What CrewAI hands the after hook when the tool raised (crewai 1.15.28, English texts): the native
# tool-call executor's "Error executing tool: {e}", and the ReAct path's tool-usage error text.
_RAISED = ("Error executing tool: ", "I encountered an error while trying to use the tool.")


def _failed(raw: Any) -> bool:
    """The tool failed: it raised (CrewAI hands the hook its error text), or returned a ToolFailure."""
    if _ToolFailure is not None and isinstance(raw, _ToolFailure):
        return True
    return isinstance(raw, str) and raw.lstrip().startswith(_RAISED)


def _message(auth: Authorization, tool: str) -> str:
    return auth.message or f"LaunchSafe Agent Firewall did not allow {tool}."


class FirewallHooks:
    """The before and after tool-call hooks for one guard."""

    def __init__(self, guard: Guard) -> None:
        if isinstance(guard, AsyncGuard):
            raise TypeError(
                "CrewAI tool-call hooks are synchronous and cannot await an AsyncGuard; use a blocking Guard"
            )
        self.guard = guard
        self._decided: OrderedDict[_Key, tuple[object, Authorization]] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _key(context: ToolCallHookContext) -> _Key:
        return (context.tool_name, id(context.tool_input))

    def _set(self, context: ToolCallHookContext, auth: Authorization | None) -> None:
        key = self._key(context)
        with self._lock:
            if auth is None:
                self._decided.pop(key, None)
                return
            self._decided[key] = (context.tool_input, auth)
            self._decided.move_to_end(key)
            while len(self._decided) > MAX_DECIDED:
                self._decided.popitem(last=False)

    def _get(self, context: ToolCallHookContext) -> Authorization | None:
        with self._lock:
            entry = self._decided.get(self._key(context))
        # The same dict object, not only the same id (an id can be reused once its object is gone).
        return entry[1] if entry is not None and entry[0] is context.tool_input else None

    def before(self, context: ToolCallHookContext) -> None:
        """`before_tool_call` hook: returns if the call may run, else raises `HookAborted`."""
        name = context.tool_name
        try:
            # CrewAI gives a hook no call id: one per call, as the TypeScript integrations send.
            call_id = f"crewai-{uuid.uuid4().hex}"
            auth = self.guard.authorize(native(name, dict(context.tool_input), call_id=call_id))
        except Exception as e:
            # Not reachable through authorize(), which never raises; but CrewAI would let the call through.
            raise HookAborted(f"LaunchSafe Agent Firewall could not decide {name}: {type(e).__name__}") from e
        self._set(context, auth)
        if not auth.allowed:
            raise HookAborted(_message(auth, name), source=self.before)

    def after(self, context: ToolCallHookContext) -> str | None:
        """`after_tool_call` hook: the firewall's message for a blocked call, the redacted copy if any."""
        name = context.tool_name
        auth = self._get(context)
        if auth is None:
            # The firewall never decided this call (an earlier hook blocked it first, or it is a stray
            # result): CrewAI's own text stands, and nothing is recorded.
            return None
        self._set(context, None)
        if not auth.allowed:
            return _message(auth, name)
        result = context.tool_result if context.tool_result is not None else context.raw_tool_result
        try:
            out = self.guard.record_result(auth, result, failed=True if _failed(context.raw_tool_result) else None)
        except Exception:
            return None  # the call has run; recording is best effort and a failure cannot undo it
        return out.output  # the sidecar masked something (redactSecretsInOutput): the model gets that


def firewall_hooks(guard: Guard) -> FirewallHooks:
    """The hooks without registering them, for `@CrewBase` classes or scoped registration."""
    return FirewallHooks(guard)


def install_firewall(guard: Guard) -> Callable[[], None]:
    """Register the firewall's hooks globally. Returns a function that removes them again."""
    hooks = FirewallHooks(guard)
    register_before_tool_call_hook(hooks.before)
    register_after_tool_call_hook(hooks.after)

    def uninstall() -> None:
        unregister_before_tool_call_hook(hooks.before)
        unregister_after_tool_call_hook(hooks.after)

    return uninstall


__all__ = ["FirewallHooks", "firewall_hooks", "install_firewall"]
