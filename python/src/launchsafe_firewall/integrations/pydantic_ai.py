"""Pydantic AI (`pydantic-ai-slim`, Python) integration.

`LaunchSafeFirewall(guard)` is a Pydantic AI capability. Capabilities are the framework's own home
for cross-cutting tool behaviour; this one uses three of their hooks:

- `wrap_tool_execute`: runs after the model's arguments are validated and before the tool function,
  around every function, toolset and MCP tool the agent has. It authorizes the call
  (`guard.authorize`). An allowed call runs and what it returned is recorded (`guard.record_result`);
  the model is given the sidecar's redacted copy when it sends one. An ask, hold or deny is not run:
  the firewall's message is the tool's result, so the model reads why. A guard with `approval_timeout`
  waits for a person in the firewall's queue (terminal, phone) first. Approvals happen there: Pydantic
  AI's own `ApprovalRequired` / deferred tools are not a firewall approval and are left as you set them.
- `prepare_tools`: refuses `external` (deferred) tools, which run outside this process and cannot be
  gated, rather than passing them through.
- `before_model_request`: refuses provider-side native tools (web search, code execution, ...), which
  run at the model provider and cannot be gated. Report their results with `guard.report_input`.

    agent = Agent(model, tools=[...], capabilities=[LaunchSafeFirewall(guard)])

List it first among your capabilities so no other capability's `wrap_tool_execute` runs outside it.

Not gated: output tools and output functions. Output tools are the framework's own and fire no tool
hooks; an output function (a function given as `output_type`) runs with the model's arguments in
output processing, outside any tool hook. `check_output_functions(agent)` refuses an agent that has
one (`allow=True` only warns); prefer output types, or make the function a tool.

A tool that raises (`ModelRetry` included) is recorded with `failed=True`, then the error goes on to
the framework as before.
"""

from __future__ import annotations

import asyncio
import inspect
import warnings
from dataclasses import dataclass, replace
from typing import Any

from pydantic_ai import RunContext
from pydantic_ai.capabilities import AbstractCapability
from pydantic_ai.exceptions import ApprovalRequired, CallDeferred, UserError
from pydantic_ai.messages import ToolCallPart
from pydantic_ai.models import ModelRequestContext
from pydantic_ai.tools import ToolDefinition

from .._core import Authorization, ReportOutcome
from ..formats import native
from ..guard import AsyncGuard, Guard


async def _authorize(guard: Guard | AsyncGuard, name: str, args: dict[str, Any], call_id: str | None) -> Authorization:
    action = native(name, args, call_id=call_id)
    if isinstance(guard, AsyncGuard):
        return await guard.authorize(action)
    return await asyncio.to_thread(guard.authorize, action)


async def _record(
    guard: Guard | AsyncGuard, auth: Authorization, output: Any, failed: bool | None = None
) -> ReportOutcome:
    if isinstance(guard, AsyncGuard):
        return await guard.record_result(auth, output, failed=failed)
    return await asyncio.to_thread(guard.record_result, auth, output, failed=failed)


@dataclass
class LaunchSafeFirewall(AbstractCapability[Any]):
    """Puts every tool call of an agent through the LaunchSafe Agent Firewall."""

    guard: Guard | AsyncGuard

    @classmethod
    def get_serialization_name(cls) -> str | None:
        return None  # holds a live guard: not spec-serializable

    async def wrap_tool_execute(
        self,
        ctx: RunContext[Any],
        *,
        call: ToolCallPart,
        tool_def: ToolDefinition,
        args: dict[str, Any],
        handler: Any,
    ) -> Any:
        name = call.tool_name
        # authorize() never raises: a failure is a decision, and a read-only tool alone may fail open.
        auth = await _authorize(self.guard, name, args, call.tool_call_id)
        if not auth.allowed:
            return auth.message or f"LaunchSafe Agent Firewall did not allow {name}."
        try:
            result = await handler(args)
        except (CallDeferred, ApprovalRequired):  # the tool deferred itself; it did not fail
            raise
        except BaseException as e:  # the tool ran and failed (ModelRetry included): recorded, then raised on
            await _record(self.guard, auth, f"the tool raised {type(e).__name__}: {e}"[:2000], failed=True)
            raise
        out = await _record(self.guard, auth, result)
        # The sidecar masked something (redactSecretsInOutput): the model gets the masked copy.
        return out.output if out.output is not None else result

    async def prepare_tools(self, ctx: RunContext[Any], tool_defs: list[ToolDefinition]) -> list[ToolDefinition]:
        for td in tool_defs:
            if td.kind == "external":
                raise UserError(
                    f"tool {td.name!r} is deferred and runs outside this process, so the firewall cannot gate it; "
                    "leave it out, or run it yourself and report its result with guard.report_input"
                )
        return tool_defs

    async def before_model_request(
        self, ctx: RunContext[Any], request_context: ModelRequestContext
    ) -> ModelRequestContext:
        native_tools = request_context.model_request_parameters.native_tools
        if native_tools:
            names = ", ".join(type(t).__name__ for t in native_tools)
            raise UserError(
                f"provider-side tools ({names}) run at the model provider and cannot be gated by the firewall; "
                "leave them out, or report what they return with guard.report_input"
            )
        return replace(request_context)


def output_functions(output_type: Any) -> list[str]:
    """Names of the output functions in a Pydantic AI output spec (`output_type`).

    An output function (a plain function or method as `output_type`, alone, in a list, or inside
    `ToolOutput` / `NativeOutput` / `PromptedOutput` / `TextOutput`) is run by the framework's output
    processing with the model's arguments. That is not a tool call: no tool hook sees it, so the
    firewall does not gate it. A type (a class, `str`, a pydantic model) only validates and is fine.
    """
    found: list[str] = []
    pending: list[Any] = [output_type]
    while pending:
        o = pending.pop()
        if isinstance(o, list | tuple | set | frozenset):
            pending.extend(o)
        elif isinstance(o, type) or o is None:
            continue
        elif inspect.isfunction(o) or inspect.ismethod(o) or inspect.isbuiltin(o):
            found.append(str(getattr(o, "__qualname__", None) or getattr(o, "__name__", repr(o))))
        elif hasattr(o, "outputs") or hasattr(o, "output") or hasattr(o, "output_function"):
            # The output markers wrap their spec in one of these (pydantic-ai 2.x).
            for attr in ("outputs", "output", "output_function"):
                if hasattr(o, attr):
                    pending.append(getattr(o, attr))
        elif callable(o) and not hasattr(o, "__origin__"):
            found.append(type(o).__name__)  # a callable object; a typing form (Literal[...], list[int]) is not one
    return sorted(found)


def check_output_functions(agent: Any, *, allow: bool = False) -> None:
    """Raises `UserError` when `agent` has output functions the firewall cannot gate (see `output_functions`).

    Call it where you build the agent; `allow=True` (you accept that they run unchecked) only warns.
    It reads the agent's output spec, which Pydantic AI keeps on the agent (`_output_type`, 2.x); for an
    agent where it cannot be read it does nothing, so prefer output types to output functions.
    """
    spec = getattr(agent, "_output_type", None)
    names = output_functions(spec) if spec is not None else []
    if not names:
        return
    text = (
        f"output functions ({', '.join(names)}) run with the model's arguments outside any tool hook, so the "
        "LaunchSafe Agent Firewall cannot gate them"
    )
    if allow:
        warnings.warn(text, stacklevel=2)
        return
    raise UserError(f"{text}; use an output type, or make the function a tool")


__all__ = ["LaunchSafeFirewall", "check_output_functions", "output_functions"]
