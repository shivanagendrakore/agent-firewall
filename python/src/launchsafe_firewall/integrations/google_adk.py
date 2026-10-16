"""Google Agent Development Kit (`google-adk`, Python) integration.

ADK's own interception points for tool calls are the tool callbacks. This module offers both forms:

- `FirewallPlugin(guard)`: a `BasePlugin` for `Runner(plugins=[...])`. A plugin runs for every agent
  under the runner, sub-agents and `AgentTool` runs included (ADK hands the parent's plugins down).
  Prefer this one.
- `firewall_callbacks(guard)`: the same two callbacks for a single `LlmAgent`
  (`before_tool_callback=cb.before`, `after_tool_callback=cb.after`), for code that builds agents
  but not the runner.

`before_tool_callback` authorizes the call (`guard.authorize`). An allowed call runs. An ask, hold or
deny returns `{"error": <the firewall's message>}`, which ADK uses as the tool's response, so the model
reads why and the tool never runs. A guard with `approval_timeout` waits for a person in the
firewall's queue first (terminal, phone); ADK's own tool confirmation is not a firewall approval.
`after_tool_callback` records what the tool returned (`guard.record_result`), and when the sidecar
returns a redacted copy the model is given that, as `{"result": <redacted text>}`. ADK also runs the
after callbacks for a call a before callback answered; those are never recorded.

Tools that run at the model provider (`google_search`, grounding, ...) and code executors (any
`code_executor`: ADK runs the model's code without a tool callback) cannot be gated. The plugin, and
the callbacks' `before_agent`, refuse to start a run whose agents (sub-agents and `AgentTool` agents
included) have one (the run ends with a message, nothing executes), and the tool callback refuses each
call of such an agent; `unsupported_tools(agent)` lists them so you can check at build time.
`allow_code_executor=True` accepts an executor you trust to be contained. A tool that raises is
recorded with `failed=True` (`on_tool_error_callback`).

An `AsyncGuard` is the natural fit (ADK is async); a blocking `Guard` decides in a worker thread.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from typing import Any

from google.adk.agents.callback_context import CallbackContext
from google.adk.agents.invocation_context import InvocationContext
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools.agent_tool import AgentTool
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext
from google.genai import types

from .._core import Authorization
from ..formats import native
from ..guard import AsyncGuard, Guard

# Allowed calls waiting for their result to be recorded; ones whose tool never returned are dropped oldest first.
_MAX_IN_FLIGHT = 1000


def _call_key(tool_args: dict[str, Any], tool_context: ToolContext) -> str:
    call_id = tool_context.function_call_id
    return call_id if call_id else f"args-{id(tool_args)}"


def unsupported_tools(agent: object, *, allow_code_executor: bool = False) -> list[str]:
    """Names of the tools and code executors in `agent`, its sub-agents and the agents its `AgentTool`s
    run, that never pass through a tool callback, so the firewall cannot gate them.

    That is a tool that declares no function to the model (the provider runs it: `google_search`,
    grounding, ...) and any `code_executor`: ADK runs the code the model writes (at the provider, or in
    this process for `UnsafeLocalCodeExecutor`, a container, ...) without a tool callback.
    `allow_code_executor=True` leaves executors out, for an executor you trust to be contained.

    Toolsets are resolved by ADK at run time and are not inspected; their tools are ordinary
    callbacks-gated tools unless they declare nothing to the model.
    """
    found: list[str] = []
    seen: set[int] = set()
    pending: list[Any] = [agent]
    while pending:
        a = pending.pop()
        if id(a) in seen:
            continue
        seen.add(id(a))
        pending.extend(getattr(a, "sub_agents", None) or [])
        for t in getattr(a, "tools", None) or []:
            if isinstance(t, AgentTool):
                pending.append(t.agent)  # its agent runs under its own runner: its tools count too
            # A BaseTool that declares no function to the model is one the provider runs itself.
            if isinstance(t, BaseTool) and t._get_declaration() is None:
                found.append(t.name)
        executor = getattr(a, "code_executor", None)
        if executor is not None and not allow_code_executor:
            found.append(type(executor).__name__)
    return sorted(found)


def _refusal(bad: list[str]) -> str:
    return (
        "LaunchSafe Agent Firewall: this agent uses tools or code executors that do not pass through the "
        f"firewall and cannot be checked ({', '.join(bad)}). Nothing was run."
    )


class FirewallCallbacks:
    """The agent and tool callbacks, sharing the record of calls awaiting their result."""

    def __init__(self, guard: Guard | AsyncGuard, *, allow_code_executor: bool = False) -> None:
        self.guard = guard
        self.allow_code_executor = allow_code_executor
        self._in_flight: OrderedDict[str, Authorization] = OrderedDict()

    def check(self, agent: object) -> str | None:
        """The refusal for an agent with tools or executors the firewall cannot gate; None when it has none."""
        bad = unsupported_tools(agent, allow_code_executor=self.allow_code_executor)
        return _refusal(bad) if bad else None

    async def _authorize(self, name: str, args: dict[str, Any], call_id: str | None) -> Authorization:
        action = native(name, args, call_id=call_id)
        if isinstance(self.guard, AsyncGuard):
            return await self.guard.authorize(action)
        return await asyncio.to_thread(self.guard.authorize, action)

    async def _record(self, auth: Authorization, output: Any, failed: bool | None) -> Any:
        if isinstance(self.guard, AsyncGuard):
            return await self.guard.record_result(auth, output, failed=failed)
        return await asyncio.to_thread(self.guard.record_result, auth, output, failed=failed)

    async def before_agent(self, callback_context: CallbackContext) -> types.Content | None:
        """`before_agent_callback`: the startup check. An agent the firewall cannot fully gate does not run."""
        text = self.check(callback_context._invocation_context.agent)
        return types.Content(role="model", parts=[types.Part(text=text)]) if text else None

    async def before(
        self, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext
    ) -> dict[str, Any] | None:
        """`before_tool_callback`: None lets the tool run; a dict is the tool's answer instead."""
        # The startup check again, for callbacks given to an agent without `before_agent`.
        refusal = self.check(tool_context._invocation_context.agent)
        if refusal is not None:
            return {"error": refusal}
        auth = await self._authorize(tool.name, dict(tool_args), tool_context.function_call_id)
        if not auth.allowed:
            return {"error": auth.message or f"LaunchSafe Agent Firewall did not allow {tool.name}."}
        self._in_flight[_call_key(tool_args, tool_context)] = auth
        while len(self._in_flight) > _MAX_IN_FLIGHT:
            self._in_flight.popitem(last=False)
        return None

    async def after(
        self, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext, tool_response: dict[str, Any]
    ) -> dict[str, Any] | None:
        """`after_tool_callback`: records the result; a dict replaces it (the sidecar's redacted copy)."""
        auth = self._in_flight.pop(_call_key(tool_args, tool_context), None)
        if auth is None:
            return None  # a call that was not allowed, or that the firewall never saw: nothing ran
        out = await self._record(auth, tool_response, None)
        if out.output is not None:
            # The sidecar masked something (redactSecretsInOutput): the model gets the masked copy.
            return {"result": out.output}
        return None

    async def on_error(
        self, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext, error: Exception
    ) -> dict[str, Any] | None:
        """`on_tool_error_callback`: records the failure (`failed=True`); ADK then handles the error as usual."""
        auth = self._in_flight.pop(_call_key(tool_args, tool_context), None)
        if auth is not None:
            await self._record(auth, f"the tool raised {type(error).__name__}: {error}"[:2000], True)
        return None


def firewall_callbacks(guard: Guard | AsyncGuard, *, allow_code_executor: bool = False) -> FirewallCallbacks:
    """Callbacks for one `LlmAgent`: `before_agent_callback=cb.before_agent, before_tool_callback=cb.before,
    after_tool_callback=cb.after, on_tool_error_callback=cb.on_error`."""
    return FirewallCallbacks(guard, allow_code_executor=allow_code_executor)


class FirewallPlugin(BasePlugin):
    """An ADK plugin that sends every tool call of every agent under the runner through the firewall."""

    def __init__(
        self, guard: Guard | AsyncGuard, *, name: str = "launchsafe_firewall", allow_code_executor: bool = False
    ) -> None:
        super().__init__(name=name)
        self.callbacks = FirewallCallbacks(guard, allow_code_executor=allow_code_executor)

    async def before_run_callback(self, *, invocation_context: InvocationContext) -> types.Content | None:
        text = self.callbacks.check(invocation_context.agent)
        return types.Content(role="model", parts=[types.Part(text=text)]) if text else None

    async def before_tool_callback(
        self, *, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext
    ) -> dict[str, Any] | None:
        return await self.callbacks.before(tool, tool_args, tool_context)

    async def after_tool_callback(
        self, *, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext, result: dict[str, Any]
    ) -> dict[str, Any] | None:
        return await self.callbacks.after(tool, tool_args, tool_context, result)

    async def on_tool_error_callback(
        self, *, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext, error: Exception
    ) -> dict[str, Any] | None:
        return await self.callbacks.on_error(tool, tool_args, tool_context, error)


__all__ = ["FirewallCallbacks", "FirewallPlugin", "firewall_callbacks", "unsupported_tools"]
