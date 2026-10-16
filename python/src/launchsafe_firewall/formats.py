"""Build an `Action` from the tool-call shapes agent frameworks produce (docs/api-v0.md, "Decide request").

The native block is sent untouched (`raw`) where the contract has a format for it, so the sidecar
maps it and an approval binds to the native call. Objects from the OpenAI and Anthropic SDKs are
accepted as well as plain dicts (anything with `model_dump()`).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from .types import Action, McpInfo


def _as_dict(v: Any, what: str) -> dict[str, Any]:
    if isinstance(v, Mapping):
        return dict(v)
    dump = getattr(v, "model_dump", None)
    if callable(dump):
        d = dump()
        if isinstance(d, Mapping):
            return dict(cast(Mapping[str, Any], d))
    raise TypeError(f"{what} must be a mapping or an SDK object with model_dump()")


def native(tool: str, input: Mapping[str, Any] | None = None, *, call_id: str | None = None) -> Action:
    """A call to one of the host's own tools, looked up in the agent's tool registry."""
    return Action(format="native", tool=tool, input=dict(input or {}), call_id=call_id)


def engine(tool: str, input: Mapping[str, Any] | None = None, *, call_id: str | None = None) -> Action:
    """A call already in the engine's vocabulary (`Bash`, `Read`, `WebFetch`, ...)."""
    return Action(format="engine", tool=tool, input=dict(input or {}), call_id=call_id)


def from_openai_tool_call(tool_call: Any) -> Action:
    """One entry of an OpenAI chat completion's `message.tool_calls`.

    `arguments` stays the JSON string the model wrote; the sidecar parses it (unparseable JSON is
    FW-UNCLASSIFIABLE there, never an allow).
    """
    d = _as_dict(tool_call, "tool_call")
    fn = _as_dict(d.get("function"), "tool_call.function")
    name = fn.get("name")
    if not isinstance(name, str) or name == "":
        raise ValueError("tool_call.function.name must be a non-empty string")
    arguments = fn.get("arguments", "")
    if not isinstance(arguments, str):
        raise ValueError("tool_call.function.arguments must be a JSON string")
    call_id = d.get("id")
    raw: dict[str, Any] = {"type": "function", "function": {"name": name, "arguments": arguments}}
    if isinstance(call_id, str):
        raw = {"id": call_id, **raw}
    return Action(format="openai.chat", raw=raw, call_id=call_id if isinstance(call_id, str) else None)


def from_anthropic_tool_use(block: Any) -> Action:
    """One `tool_use` content block of an Anthropic Messages response."""
    d = _as_dict(block, "tool_use block")
    if d.get("type") != "tool_use":
        raise ValueError("block.type must be 'tool_use' (server tools are not gateable: report results as inputs)")
    name = d.get("name")
    if not isinstance(name, str) or name == "":
        raise ValueError("block.name must be a non-empty string")
    block_id = d.get("id")
    if not isinstance(block_id, str):
        raise ValueError("block.id must be a string")
    tool_input = d.get("input", {})
    if not isinstance(tool_input, Mapping):
        raise ValueError("block.input must be an object")
    raw = {"type": "tool_use", "id": block_id, "name": name, "input": dict(cast(Mapping[str, Any], tool_input))}
    return Action(format="anthropic", raw=raw, call_id=block_id)


def from_mcp_call(
    server: str,
    call: Mapping[str, Any] | None = None,
    *,
    name: str | None = None,
    arguments: Mapping[str, Any] | None = None,
    source: str | None = None,
    call_id: str | None = None,
) -> Action:
    """An MCP `tools/call` on `server`: pass its params (`{"name", "arguments"}`) or `name=` and `arguments=`.

    `source` is where the server was configured ("user", "project", "sdk"...); unstated means untrusted.
    """
    if call is not None:
        if name is not None or arguments is not None:
            raise ValueError("pass either the tools/call params or name= and arguments=, not both")
        n = call.get("name")
        a = call.get("arguments", {})
        if not isinstance(n, str):
            raise ValueError("tools/call params need a string 'name'")
        if a is None:
            a = {}
        if not isinstance(a, Mapping):
            raise ValueError("tools/call 'arguments' must be an object")
        name, arguments = n, cast(Mapping[str, Any], a)
    if not name:
        raise ValueError("an MCP call needs a tool name")
    if not server:
        raise ValueError("an MCP call needs a server name")
    return Action(
        format="mcp",
        tool=name,
        input=dict(arguments or {}),
        call_id=call_id,
        mcp=McpInfo(server=server, source=source),
    )
