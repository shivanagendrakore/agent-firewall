"""OpenAI Agents SDK (`openai-agents`, Python) integration.

`firewall_tool(guard, tool)` returns a copy of a `FunctionTool` with two tool guardrails, the SDK's
own interception points for function tools:

- an input guardrail, run before the tool: it authorizes the call (`guard.authorize`). An allowed
  call runs; an ask, hold or deny is rejected with the firewall's message (`reject_content`), so the
  model reads why and the tool never runs. A guard with `approval_timeout` waits for a person in the
  firewall's queue first. Approvals happen there (terminal, phone): the SDK's own `needs_approval`
  is not a firewall approval and is left as you set it.
- an output guardrail: it records what the tool returned (`guard.record_result`), and when the
  sidecar returns a redacted copy, the model is given that instead.

Guardrails run when the Runner executes the tool. Hosted tools (web search, file search, code
interpreter) run at OpenAI and cannot be gated: `firewall_tools` refuses them, and their results
should be reported with `guard.report_input`.

`firewall_agent(guard, agent)` does this for a whole agent graph: the agent's tools, its handoff
agents, the agents behind its `as_tool()` tools, recursively (in place). It refuses agents with
`mcp_servers` (their tools are listed at run time, outside these guardrails) unless told otherwise.

A tool that raised is recorded with `failed=True`: the copy's failure formatter notes the call, then
formats the error as the tool's own (default or custom) one does. A tool with
`failure_error_function=None` ends the run (nothing is recorded).

With `RunConfig(tool_execution=...pre_approval_tool_input_guardrails=True)` the input guardrail also
runs before the SDK's own approval prompt, so a call is decided twice; both decisions are logged.
"""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
import json
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from typing import Any, cast

from agents import Agent, FunctionTool, Handoff, RunContextWrapper, Tool
from agents.tool import default_tool_error_function
from agents.tool_guardrails import (
    ToolGuardrailFunctionOutput,
    ToolInputGuardrail,
    ToolInputGuardrailData,
    ToolOutputGuardrail,
    ToolOutputGuardrailData,
)

from .._core import Authorization, ReportOutcome
from ..formats import native
from ..guard import AsyncGuard, Guard

# Allowed calls waiting for their result to be recorded; ones whose tool never returned are dropped oldest first.
_MAX_IN_FLIGHT = 1000

_INPUT_GUARDRAIL = "launchsafe-firewall"


def parse_arguments(arguments: str) -> dict[str, Any]:
    """The model's JSON arguments as an object; anything else is judged as given."""
    try:
        v = json.loads(arguments) if arguments else {}
    except ValueError:
        return {"arguments": arguments}
    if isinstance(v, Mapping):
        return dict(v)
    return {"value": v}


async def _authorize(guard: Guard | AsyncGuard, name: str, args: dict[str, Any], call_id: str) -> Authorization:
    action = native(name, args, call_id=call_id)
    if isinstance(guard, AsyncGuard):
        return await guard.authorize(action)
    return await asyncio.to_thread(guard.authorize, action)


async def _record(guard: Guard | AsyncGuard, auth: Authorization, output: Any, failed: bool | None) -> ReportOutcome:
    if isinstance(guard, AsyncGuard):
        return await guard.record_result(auth, output, failed=failed)
    return await asyncio.to_thread(guard.record_result, auth, output, failed=failed)


def _info(auth: Authorization) -> dict[str, Any]:
    info: dict[str, Any] = {"verdict": auth.verdict, "rules": list(auth.rule_ids)}
    if auth.decision_id is not None:
        info["decisionId"] = auth.decision_id
    if auth.approval is not None:
        info["approval"] = {"id": auth.approval.id, "status": auth.approval.status}
    if auth.error is not None:
        info["error"] = auth.error
    return info


def _marking_failures(tool: FunctionTool, failed_calls: set[str]) -> dict[str, Any]:
    """Fields for the copy whose failure formatter also notes the call as failed, then formats as before.

    The SDK turns a tool's exception into its output with the tool's `failure_error_function` (or its
    default one), read off the tool that runs (openai-agents 0.23: `_failure_error_function` and
    `_use_default_failure_error_function`, which `dataclasses.replace` carries into the copy, whose own
    invoker reads them). A tool with `failure_error_function=None` raises instead: left as it is.
    """
    use_default = getattr(tool, "_use_default_failure_error_function", None)
    if use_default is None:  # an SDK without these fields: failures are recorded as results
        return {}
    base: Any = default_tool_error_function if use_default else tool._failure_error_function
    if base is None:
        return {}

    async def formatter(ctx: RunContextWrapper[Any], error: Exception) -> str:
        call_id = getattr(ctx, "tool_call_id", None)
        if isinstance(call_id, str):
            failed_calls.add(call_id)
            while len(failed_calls) > _MAX_IN_FLIGHT:
                failed_calls.pop()
        text = base(ctx, error)
        return str(await text) if inspect.isawaitable(text) else str(text)

    return {"_failure_error_function": formatter, "_use_default_failure_error_function": False}


def firewall_tool(guard: Guard | AsyncGuard, tool: FunctionTool) -> FunctionTool:
    """A copy of `tool` whose every call goes through the firewall. Your own guardrails still run."""
    if not isinstance(tool, FunctionTool):
        raise TypeError(f"{type(tool).__name__} is not a FunctionTool: only function tools can be gated")
    name = tool.name
    in_flight: OrderedDict[str, Authorization] = OrderedDict()
    failed_calls: set[str] = set()

    async def check_call(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
        ctx = data.context
        auth = await _authorize(guard, name, parse_arguments(ctx.tool_arguments), ctx.tool_call_id)
        if auth.allowed:
            in_flight[ctx.tool_call_id] = auth
            while len(in_flight) > _MAX_IN_FLIGHT:
                in_flight.popitem(last=False)
            return ToolGuardrailFunctionOutput.allow(_info(auth))
        message = auth.message or f"LaunchSafe Agent Firewall did not allow {name}."
        return ToolGuardrailFunctionOutput.reject_content(message, _info(auth))

    async def record_output(data: ToolOutputGuardrailData) -> ToolGuardrailFunctionOutput:
        auth = in_flight.pop(data.context.tool_call_id, None)
        if auth is None:
            return ToolGuardrailFunctionOutput.allow()
        failed = True if data.context.tool_call_id in failed_calls else None
        failed_calls.discard(data.context.tool_call_id)
        out = await _record(guard, auth, data.output, failed)
        info = {"recorded": out.recorded, "queued": out.queued}
        if out.output is not None:
            # The sidecar masked something (redactSecretsInOutput): the model gets the masked copy.
            return ToolGuardrailFunctionOutput.reject_content(out.output, {**info, "redacted": True})
        return ToolGuardrailFunctionOutput.allow(info)

    before = ToolInputGuardrail[Any](guardrail_function=check_call, name=_INPUT_GUARDRAIL)
    after = ToolOutputGuardrail[Any](guardrail_function=record_output, name="launchsafe-firewall-result")
    return dataclasses.replace(
        tool,
        **_marking_failures(tool, failed_calls),
        tool_input_guardrails=[before, *(tool.tool_input_guardrails or [])],
        # First, so a later guardrail's rejection cannot skip recording what the tool returned.
        tool_output_guardrails=[after, *(tool.tool_output_guardrails or [])],
    )


def firewall_tools(guard: Guard | AsyncGuard, tools: Iterable[Tool]) -> list[Tool]:
    """`firewall_tool` for each tool. A tool the firewall cannot gate is refused, never passed through."""
    out: list[Tool] = []
    for t in tools:
        if not isinstance(t, FunctionTool):
            raise TypeError(
                f"{type(t).__name__} runs outside this process and cannot be gated by the firewall; "
                "leave it out, or add it yourself and report its results with guard.report_input"
            )
        out.append(firewall_tool(guard, t))
    return out


def _gated(tool: Tool) -> bool:
    return any(g.get_name() == _INPUT_GUARDRAIL for g in getattr(tool, "tool_input_guardrails", None) or [])


def firewall_agent(guard: Guard | AsyncGuard, agent: Agent[Any], *, allow_mcp_servers: bool = False) -> Agent[Any]:
    """Puts every tool of `agent`, and of every agent it can reach, through the firewall. Returns `agent`.

    Reached are the agents in `handoffs` (an `Agent`, or a `Handoff` made by `handoff()`), and the agent
    behind each `Agent.as_tool()` tool; and theirs in turn. The agents are changed **in place**: a handoff
    and an `as_tool()` tool hold on to their agent object, so a gated copy would leave the agent that
    really runs ungated. A tool already gated is left as it is, so calling this twice is harmless.

    Refused (`TypeError`), never passed through: a tool that is not a `FunctionTool` (hosted tools run at
    OpenAI), a `Handoff` whose agent the SDK does not expose (one not made by `handoff()`), an
    `as_tool()` tool whose agent is not exposed, and, unless `allow_mcp_servers=True`, an agent with
    `mcp_servers`: the SDK lists MCP tools at run time, outside these guardrails, so they would run
    unchecked. With `allow_mcp_servers=True` they still are: gate those servers some other way.

    Tools added to an agent after this call are not gated.
    """
    agents = _reachable(agent, allow_mcp_servers)  # everything is checked before anything is changed
    for a in agents:
        a.tools = [t if _gated(t) else firewall_tool(guard, cast(FunctionTool, t)) for t in a.tools]
    return agent


def _reachable(agent: Agent[Any], allow_mcp_servers: bool) -> list[Agent[Any]]:
    """Every agent `agent` can hand off to or run as a tool, itself included; raises for what cannot be gated."""
    found: list[Agent[Any]] = []
    seen: set[int] = set()
    pending: list[Any] = [agent]
    while pending:
        a = pending.pop()
        if id(a) in seen:
            continue
        seen.add(id(a))
        if not isinstance(a, Agent):
            raise TypeError(f"{type(a).__name__} is not an Agent: the firewall cannot see its tools")
        found.append(a)
        if a.mcp_servers and not allow_mcp_servers:
            names = ", ".join(str(getattr(s, "name", type(s).__name__)) for s in a.mcp_servers)
            raise TypeError(
                f"agent {a.name!r} has MCP servers ({names}) whose tools the SDK lists at run time, outside the "
                "firewall's guardrails; leave them out, or pass allow_mcp_servers=True and gate them yourself"
            )
        for t in a.tools:
            if not isinstance(t, FunctionTool):
                raise TypeError(
                    f"{type(t).__name__} on agent {a.name!r} runs outside this process and cannot be gated by "
                    "the firewall; leave it out, or add it yourself and report its results with guard.report_input"
                )
            if getattr(t, "_is_agent_tool", False):
                inner = getattr(t, "_agent_instance", None)
                if inner is None:
                    raise TypeError(f"the agent behind tool {t.name!r} is not visible, so its tools cannot be gated")
                pending.append(inner)
        for h in a.handoffs:
            if isinstance(h, Handoff):
                ref = h._agent_ref
                target = ref() if ref is not None else None
                if target is None:
                    raise TypeError(
                        f"handoff {h.tool_name!r} does not expose its agent (make it with agents.handoff()), "
                        "so that agent's tools cannot be gated"
                    )
                pending.append(target)
            else:
                pending.append(h)
    return found


__all__ = ["firewall_agent", "firewall_tool", "firewall_tools", "parse_arguments"]
