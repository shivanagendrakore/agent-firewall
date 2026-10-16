from __future__ import annotations

from typing import Any

import pytest

from launchsafe_firewall import (
    Action,
    DecideContext,
    DecideRequest,
    engine,
    from_anthropic_tool_use,
    from_mcp_call,
    from_openai_tool_call,
    native,
)


class SDKObject:
    """Stands in for an OpenAI or Anthropic SDK model (anything with model_dump())."""

    def __init__(self, d: dict[str, Any]) -> None:
        self._d = d

    def model_dump(self) -> dict[str, Any]:
        return self._d


def test_native_and_engine() -> None:
    assert native("send_email", {"to": "a"}, call_id="c").to_json() == {
        "format": "native",
        "tool": "send_email",
        "input": {"to": "a"},
        "callId": "c",
    }
    assert engine("Read").to_json() == {"format": "engine", "tool": "Read", "input": {}}


def test_openai_tool_call_keeps_the_arguments_string() -> None:
    a = from_openai_tool_call(
        SDKObject({"id": "call_1", "type": "function", "function": {"name": "f", "arguments": "{bad json"}})
    )
    assert a.to_json() == {
        "format": "openai.chat",
        "callId": "call_1",
        "raw": {"id": "call_1", "type": "function", "function": {"name": "f", "arguments": "{bad json"}},
    }
    assert a.tool_name == "f"


@pytest.mark.parametrize(
    "bad",
    [
        {"id": "c", "function": {"arguments": "{}"}},
        {"id": "c", "function": {"name": "f", "arguments": {"a": 1}}},
        {"id": "c"},
    ],
)
def test_openai_tool_call_refuses_bad_shapes(bad: dict[str, Any]) -> None:
    with pytest.raises((ValueError, TypeError)):
        from_openai_tool_call(bad)


def test_anthropic_tool_use_keeps_only_the_contract_keys() -> None:
    a = from_anthropic_tool_use(
        SDKObject({"type": "tool_use", "id": "toolu_1", "name": "f", "input": {"x": 1}, "caller": {"type": "direct"}})
    )
    assert a.raw == {"type": "tool_use", "id": "toolu_1", "name": "f", "input": {"x": 1}}
    assert a.call_id == "toolu_1" and a.tool_name == "f"


@pytest.mark.parametrize(
    "bad",
    [
        {"type": "server_tool_use", "id": "s", "name": "web_search", "input": {}},
        {"type": "tool_use", "id": "t", "name": "", "input": {}},
        {"type": "tool_use", "name": "f", "input": {}},
        {"type": "tool_use", "id": "t", "name": "f", "input": "x"},
    ],
)
def test_anthropic_refuses_bad_shapes(bad: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="block"):
        from_anthropic_tool_use(bad)


def test_mcp_call_both_ways() -> None:
    a = from_mcp_call("gmail", {"name": "send", "arguments": None})
    b = from_mcp_call("gmail", name="send", source="project", call_id="r1")
    assert a.to_json() == {"format": "mcp", "tool": "send", "input": {}, "mcp": {"server": "gmail"}}
    assert b.to_json()["mcp"] == {"server": "gmail", "source": "project"}
    assert b.tool_name == "send"
    with pytest.raises(ValueError, match="not both"):
        from_mcp_call("gmail", {"name": "send"}, name="send")
    with pytest.raises(ValueError, match="server"):
        from_mcp_call("", name="send")
    with pytest.raises(ValueError, match="tool name"):
        from_mcp_call("gmail")
    with pytest.raises(ValueError, match="object"):
        from_mcp_call("gmail", {"name": "send", "arguments": [1]})


def test_unknown_shapes_are_refused() -> None:
    with pytest.raises(TypeError, match="mapping"):
        from_openai_tool_call(42)


def test_decide_request_leaves_unset_fields_out() -> None:
    assert DecideRequest("s", Action(format="engine", tool="Read")).to_json() == {
        "session": "s",
        "action": {"format": "engine", "tool": "Read"},
    }
    assert DecideRequest("s", native("x"), DecideContext()).to_json() == {
        "session": "s",
        "action": {"format": "native", "tool": "x", "input": {}},
    }
