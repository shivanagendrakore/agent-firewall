"""LangGraph (`langgraph`, Python) integration.

`firewall_tool_node(guard, tools)` is a drop-in for `ToolNode`, built on ToolNode's own interception
points (`wrap_tool_call` / `awrap_tool_call`):

- each tool call is authorized first (`guard.authorize`); an allowed call runs and what it returned is
  recorded (`guard.record_result`), and the model is given the sidecar's redacted copy when it sends one;
- an ask, hold or deny is not run: its `ToolMessage` (status "error") carries the firewall's message, so
  the model reads why. A guard with `approval_timeout` waits for a person in the firewall's queue
  (terminal, phone) first. LangGraph's `interrupt()` is not used: in v0 an approval is given in the
  firewall, not by the host, and an agent credential can never approve.
- a tool that fails is recorded with `failed=True`: one that raises (recorded, then raised on, so
  ToolNode's `handle_tool_errors` applies as usual) or one whose ToolMessage has status "error".
- a tool that returns a `Command`: when it carries only this call's ToolMessage, that content is
  recorded and the sidecar's masked copy replaces it. Anything else in the Command (other messages,
  state keys, a goto) is recorded as a structured record, and if the sidecar masks something there
  the Command is not delivered (the model gets an error ToolMessage): it cannot be masked in place.

Both the blocking and the async path are gated whichever guard you pass: with an `AsyncGuard`, a
blocking `invoke()` is refused (never run unchecked); with a `Guard`, `ainvoke()` decides in a worker
thread.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from langchain_core.messages import ToolMessage
from langchain_core.tools import BaseTool
from langgraph.errors import GraphBubbleUp
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.tool_node import ToolCallRequest
from langgraph.types import Command

from .._core import Authorization, ReportOutcome
from ..formats import native
from ..guard import AsyncGuard, Guard

Result = ToolMessage | Command[Any]


def _blocked(request: ToolCallRequest, message: str) -> ToolMessage:
    call = request.tool_call
    return ToolMessage(content=message, name=call["name"], tool_call_id=call["id"] or "", status="error")


def _not_allowed(request: ToolCallRequest, auth: Authorization) -> ToolMessage:
    return _blocked(request, auth.message or f"LaunchSafe Agent Firewall did not allow {request.tool_call['name']}.")


def _action(request: ToolCallRequest) -> Any:
    call = request.tool_call
    return native(call["name"], dict(call.get("args") or {}), call_id=call.get("id"))


def _plain(v: Any) -> Any:
    """`v` if it is JSON, else its repr (so the record still carries it to the scanner)."""
    try:
        json.dumps(v, allow_nan=False)
    except (TypeError, ValueError):
        return repr(v)
    return v


def _messages(command: Command[Any]) -> list[Any]:
    update = command.update
    messages = update.get("messages", []) if isinstance(update, dict) else []
    return list(messages) if isinstance(messages, list | tuple) else [messages]


def _matching(command: Command[Any], call_id: str | None) -> ToolMessage | None:
    for m in _messages(command):
        if isinstance(m, ToolMessage) and m.tool_call_id == call_id:
            return m
    return None


def _only_message(command: Command[Any], call_id: str | None) -> ToolMessage | None:
    """The Command's ToolMessage for this call when that is all it carries (nothing else reaches the model)."""
    update = command.update
    m = _matching(command, call_id)
    if m is None or not isinstance(update, dict) or set(update) != {"messages"} or len(_messages(command)) != 1:
        return None
    if command.goto or command.graph is not None or command.resume is not None:
        return None
    return m


def _output(result: Result, call_id: str | None) -> Any:
    """What the tool returned, for the record.

    A ToolMessage: its content. A Command that only carries this call's ToolMessage: that content. Any
    other Command: all of it as a structured record (every message's content, the other state keys, a
    goto), since all of it reaches the graph and, through state, the model.
    """
    if isinstance(result, ToolMessage):
        return result.content
    only = _only_message(result, call_id)
    if only is not None:
        return only.content
    record: dict[str, Any] = {"messages": [_plain(getattr(m, "content", m)) for m in _messages(result)]}
    update = result.update
    if isinstance(update, dict):
        rest = {str(k): _plain(v) for k, v in update.items() if k != "messages"}
        if rest:
            record["update"] = rest
    elif update is not None:
        record["update"] = _plain(update)
    if result.goto:
        record["goto"] = _plain(result.goto)
    return record


def _failed(result: Result, call_id: str | None) -> bool:
    """The tool failed: ToolNode turned an error into a ToolMessage with status "error"."""
    m = result if isinstance(result, ToolMessage) else _matching(result, call_id)
    return m is not None and m.status == "error"


def _error_text(e: BaseException) -> str:
    return f"the tool raised {type(e).__name__}: {e}"[:2000]


def _redacted(request: ToolCallRequest, result: Result, out: ReportOutcome) -> Result:
    """The result with the sidecar's masked copy in place; a Command that cannot be masked is not delivered."""
    if out.output is None:
        return result
    if isinstance(result, ToolMessage):
        return result.model_copy(update={"content": out.output})
    call_id = request.tool_call.get("id")
    only = _only_message(result, call_id)
    if only is None or not isinstance(result.update, dict):
        return _blocked(
            request,
            "LaunchSafe Agent Firewall: the tool's result held something that had to be masked, and it came as a "
            "structured Command the firewall cannot mask, so it was not delivered.",
        )
    masked = only.model_copy(update={"content": out.output})
    return dataclasses.replace(result, update={**result.update, "messages": [masked]})


def firewall_tool_node(
    guard: Guard | AsyncGuard,
    tools: Sequence[BaseTool | Callable[..., Any]],
    **tool_node_kwargs: Any,
) -> ToolNode:
    """A `ToolNode` over `tools` whose every call goes through the firewall."""
    if "wrap_tool_call" in tool_node_kwargs or "awrap_tool_call" in tool_node_kwargs:
        raise ValueError("firewall_tool_node sets wrap_tool_call and awrap_tool_call itself")

    if isinstance(guard, AsyncGuard):
        async_guard = guard

        def refuse_sync(request: ToolCallRequest, execute: Callable[[ToolCallRequest], Result]) -> Result:
            return _blocked(
                request,
                "LaunchSafe Agent Firewall: this graph is guarded by an AsyncGuard; run it with ainvoke(). "
                "Nothing was run.",
            )

        async def awrap(request: ToolCallRequest, execute: Callable[[ToolCallRequest], Awaitable[Result]]) -> Result:
            auth = await async_guard.authorize(_action(request))
            if not auth.allowed:
                return _not_allowed(request, auth)
            try:
                result = await execute(request)
            except GraphBubbleUp:  # interrupt() and the like pause the graph; not a failure
                raise
            except BaseException as e:  # the tool ran and failed: recorded as a failure, then raised on
                await async_guard.record_result(auth, _error_text(e), failed=True)
                raise
            call_id = request.tool_call.get("id")
            out = await async_guard.record_result(
                auth, _output(result, call_id), failed=True if _failed(result, call_id) else None
            )
            return _redacted(request, result, out)

        return ToolNode(tools, wrap_tool_call=refuse_sync, awrap_tool_call=awrap, **tool_node_kwargs)

    sync_guard = guard

    def wrap(request: ToolCallRequest, execute: Callable[[ToolCallRequest], Result]) -> Result:
        auth = sync_guard.authorize(_action(request))
        if not auth.allowed:
            return _not_allowed(request, auth)
        try:
            result = execute(request)
        except GraphBubbleUp:
            raise
        except BaseException as e:
            sync_guard.record_result(auth, _error_text(e), failed=True)
            raise
        call_id = request.tool_call.get("id")
        failed = True if _failed(result, call_id) else None
        return _redacted(request, result, sync_guard.record_result(auth, _output(result, call_id), failed=failed))

    async def awrap_sync_guard(
        request: ToolCallRequest, execute: Callable[[ToolCallRequest], Awaitable[Result]]
    ) -> Result:
        auth = await asyncio.to_thread(sync_guard.authorize, _action(request))
        if not auth.allowed:
            return _not_allowed(request, auth)
        try:
            result = await execute(request)
        except GraphBubbleUp:
            raise
        except BaseException as e:
            await asyncio.to_thread(sync_guard.record_result, auth, _error_text(e), failed=True)
            raise
        call_id = request.tool_call.get("id")
        output, failed = _output(result, call_id), True if _failed(result, call_id) else None
        out = await asyncio.to_thread(sync_guard.record_result, auth, output, failed=failed)
        return _redacted(request, result, out)

    return ToolNode(tools, wrap_tool_call=wrap, awrap_tool_call=awrap_sync_guard, **tool_node_kwargs)


__all__ = ["firewall_tool_node"]
