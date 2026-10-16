"""OpenAI Agents SDK with the LaunchSafe Agent Firewall.

Runs offline: a scripted model (the small `Model` below) asks for two tool calls, and both tools are
harmless stubs that only return text. Start the sidecar first (`launchsafe-firewall serve --api`, and
register this agent's tools with `launchsafe-firewall api tools set <agentId> tools.json`), and set
LAUNCHSAFE_FIREWALL_TOKEN. Without a sidecar you see the fail-closed path: the read-only lookup
runs and the email is blocked with FW-UNAVAILABLE.

To use a real model, drop `model=` (the SDK then uses OpenAI with OPENAI_API_KEY).

    pip install 'launchsafe-firewall[openai-agents]'
    python examples/openai_agents_example.py
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator

from agents import (
    Agent,
    AgentOutputSchemaBase,
    Handoff,
    Model,
    ModelResponse,
    ModelSettings,
    ModelTracing,
    Runner,
    Tool,
    TResponseInputItem,
    Usage,
    function_tool,
    set_tracing_disabled,
)
from agents.items import TResponseOutputItem, TResponseStreamEvent
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputRefusal,
    ResponseOutputText,
)
from openai.types.responses.response_prompt_param import ResponsePromptParam

from launchsafe_firewall import AsyncGuard
from launchsafe_firewall.integrations.openai_agents import firewall_tools

# The same specs the person registered with the sidecar; the guard uses them only to know which tools
# are read-only when the sidecar cannot answer.
TOOLS = {
    "lookup_order": {"kind": "read", "results": "trusted", "privateData": False},
    "send_email": {"kind": "send"},
}


class ScriptedModel(Model):
    """Stands in for the model: each turn returns the next scripted output items. Keeps the inputs it was given."""

    def __init__(self, turns: list[list[TResponseOutputItem]]) -> None:
        self.turns = turns
        self.inputs: list[str | list[TResponseInputItem]] = []

    async def get_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: ResponsePromptParam | None,
    ) -> ModelResponse:
        self.inputs.append(input)
        return ModelResponse(output=self.turns.pop(0), usage=Usage(), response_id=None)

    def stream_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: ResponsePromptParam | None,
    ) -> AsyncIterator[TResponseStreamEvent]:
        raise NotImplementedError("this example does not stream")


def function_call(name: str, arguments: dict[str, str], *, call_id: str) -> TResponseOutputItem:
    return ResponseFunctionToolCall(
        type="function_call", name=name, arguments=json.dumps(arguments), call_id=call_id, status="completed"
    )


def assistant_message(text: str) -> TResponseOutputItem:
    content: list[ResponseOutputText | ResponseOutputRefusal] = [
        ResponseOutputText(type="output_text", text=text, annotations=[])
    ]
    return ResponseOutputMessage(id="msg", type="message", role="assistant", status="completed", content=content)


@function_tool
def lookup_order(order_id: str) -> str:
    """Look up an order's status (stub)."""
    return f"order {order_id}: shipped"


@function_tool
def send_email(to: str, body: str) -> str:
    """Send an email (stub: nothing is sent)."""
    return f"(stub) would send {len(body)} characters to {to}"


async def main() -> None:
    set_tracing_disabled(True)
    model = ScriptedModel(
        [
            [
                function_call("lookup_order", {"order_id": "A-17"}, call_id="call_1"),
                function_call("send_email", {"to": "someone@example.com", "body": "order shipped"}, call_id="call_2"),
            ],
            [assistant_message("Done.")],
        ]
    )
    async with AsyncGuard(session=os.environ.get("RUN_ID", "example-run"), tools=TOOLS) as guard:
        agent = Agent(
            name="support",
            instructions="Help with orders.",
            model=model,
            tools=firewall_tools(guard, [lookup_order, send_email]),
        )
        result = await Runner.run(agent, "Where is order A-17? Email the customer.")
    last = model.inputs[-1] if model.inputs else []
    for item in last if isinstance(last, list) else []:
        if isinstance(item, dict) and item.get("type") == "function_call_output":
            print(f"{item.get('call_id')}: {item.get('output')}")
    print("final:", result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
