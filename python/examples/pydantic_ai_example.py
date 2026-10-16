"""Pydantic AI with the LaunchSafe Agent Firewall.

Runs offline: a scripted `FunctionModel` asks for two tool calls, and both tools are harmless stubs that
only return text. Start the sidecar first (`launchsafe-firewall serve --api`, and register this agent's
tools with `launchsafe-firewall api tools set <agentId> tools.json`), and set
LAUNCHSAFE_FIREWALL_TOKEN. Without a sidecar you see the fail-closed path: the read-only lookup
runs and the email is blocked with FW-UNAVAILABLE.

To use a real model, replace `FunctionModel(...)` with a model name such as "anthropic:claude-sonnet-5-5".

    pip install 'launchsafe-firewall[pydantic-ai]'
    python examples/pydantic_ai_example.py
"""

from __future__ import annotations

import asyncio
import os

from pydantic_ai import Agent, ModelRequest, ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.messages import ModelMessage
from pydantic_ai.models.function import AgentInfo, FunctionModel

from launchsafe_firewall import AsyncGuard
from launchsafe_firewall.integrations.pydantic_ai import LaunchSafeFirewall

# The same specs the person registered with the sidecar; the guard uses them only to know which tools
# are read-only when the sidecar cannot answer.
TOOLS = {
    "lookup_order": {"kind": "read", "results": "trusted", "privateData": False},
    "send_email": {"kind": "send"},
}

returned: dict[str, object] = {}


def scripted(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
    for m in messages:
        if isinstance(m, ModelRequest):
            for part in m.parts:
                if isinstance(part, ToolReturnPart):
                    returned[part.tool_call_id] = part.content
    if returned:
        return ModelResponse(parts=[TextPart("Done.")])
    return ModelResponse(
        parts=[
            ToolCallPart("lookup_order", {"order_id": "A-17"}, tool_call_id="call_1"),
            ToolCallPart("send_email", {"to": "someone@example.com", "body": "order shipped"}, tool_call_id="call_2"),
        ]
    )


async def main() -> None:
    async with AsyncGuard(session=os.environ.get("RUN_ID", "example-run"), tools=TOOLS) as guard:
        agent: Agent[None, str] = Agent(
            FunctionModel(scripted),
            instructions="Help with orders.",
            capabilities=[LaunchSafeFirewall(guard)],
        )

        @agent.tool_plain
        def lookup_order(order_id: str) -> str:
            """Look up an order's status (stub)."""
            return f"order {order_id}: shipped"

        @agent.tool_plain
        def send_email(to: str, body: str) -> str:
            """Send an email (stub: nothing is sent)."""
            return f"(stub) would send {len(body)} characters to {to}"

        result = await agent.run("Where is order A-17? Email the customer.")
    for call_id, output in returned.items():
        print(f"{call_id}: {output}")
    print("final:", result.output)


if __name__ == "__main__":
    asyncio.run(main())
