"""LangGraph with the LaunchSafe Agent Firewall.

Runs offline: a scripted "model" node asks for two tool calls, and both tools are harmless stubs.
Start the sidecar first (`launchsafe-firewall serve --api`, register this agent's tools) and set
LAUNCHSAFE_FIREWALL_TOKEN. Without a sidecar you see the fail-closed path: the read-only lookup runs
and the email is blocked with FW-UNAVAILABLE.

In a real graph the model node calls your chat model bound to the same tools
(`llm.bind_tools(tools)`); `firewall_tool_node` replaces `ToolNode` and nothing else changes.

    pip install 'launchsafe-firewall[langgraph]'
    python examples/langgraph_example.py
"""

from __future__ import annotations

from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph

from launchsafe_firewall import Guard
from launchsafe_firewall.integrations.langgraph import firewall_tool_node

TOOLS = {
    "lookup_order": {"kind": "read", "results": "trusted", "privateData": False},
    "send_email": {"kind": "send"},
}


@tool
def lookup_order(order_id: str) -> str:
    """Look up an order's status (stub)."""
    return f"order {order_id}: shipped"


@tool
def send_email(to: str, body: str) -> str:
    """Send an email (stub: nothing is sent)."""
    return f"(stub) would send {len(body)} characters to {to}"


def model(state: MessagesState) -> dict[str, list[BaseMessage]]:
    """Stands in for a chat model that chose two tool calls."""
    calls = [
        {"name": "lookup_order", "args": {"order_id": "A-17"}, "id": "call_1", "type": "tool_call"},
        {
            "name": "send_email",
            "args": {"to": "someone@example.com", "body": "order shipped"},
            "id": "call_2",
            "type": "tool_call",
        },
    ]
    return {"messages": [AIMessage(content="", tool_calls=calls)]}


def main() -> None:
    with Guard(session="example-run", tools=TOOLS) as guard:
        graph = StateGraph(MessagesState)
        graph.add_node("model", model)
        graph.add_node("tools", firewall_tool_node(guard, [lookup_order, send_email]))
        graph.add_edge(START, "model")
        graph.add_edge("model", "tools")
        graph.add_edge("tools", END)
        final = graph.compile().invoke({"messages": []})
    for m in final["messages"]:
        if isinstance(m, ToolMessage):
            print(f"{m.tool_call_id} [{m.status}]: {m.content}")


if __name__ == "__main__":
    main()
