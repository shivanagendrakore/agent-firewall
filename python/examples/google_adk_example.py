"""Google ADK with the LaunchSafe Agent Firewall, using stub tools and a scripted model (no API key).

Needs the sidecar running (`launchsafe-firewall serve --api`).

    pip install 'launchsafe-firewall[google-adk]'
    python examples/google_adk_example.py
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

from google.adk.agents import LlmAgent
from google.adk.apps import App
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types

from launchsafe_firewall import AsyncGuard
from launchsafe_firewall.integrations.google_adk import FirewallPlugin

TOOLS = {
    "lookup_order": {"kind": "read", "results": "trusted", "privateData": False},
    "send_email": {"kind": "send"},
}


def lookup_order(order_id: str) -> str:
    """Look up an order's status (stub)."""
    return f"order {order_id}: shipped"


def send_email(to: str, body: str) -> str:
    """Send an email (stub: nothing is sent)."""
    return f"(stub) would send {len(body)} characters to {to}"


class ScriptedModel(BaseLlm):
    """Stands in for a model that chose two tool calls, then summarises what came back."""

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        last = llm_request.contents[-1] if llm_request.contents else None
        answers = [p.function_response for p in (last.parts or []) if p.function_response] if last else []
        if answers:
            text = "; ".join(str(a.response) for a in answers)
            yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text=text)]))
            return
        calls = [
            types.FunctionCall(name="lookup_order", args={"order_id": "A-17"}, id="call_1"),
            types.FunctionCall(name="send_email", args={"to": "someone@example.com", "body": "shipped"}, id="call_2"),
        ]
        yield LlmResponse(content=types.Content(role="model", parts=[types.Part(function_call=c) for c in calls]))


async def main() -> None:
    async with AsyncGuard(session="example-run", tools=TOOLS) as guard:
        agent = LlmAgent(name="support", model=ScriptedModel(model="scripted"), tools=[lookup_order, send_email])
        runner = InMemoryRunner(app=App(name="example", root_agent=agent, plugins=[FirewallPlugin(guard)]))
        session = await runner.session_service.create_session(app_name=runner.app_name, user_id="u")
        message = types.Content(role="user", parts=[types.Part(text="Check order A-17 and email the customer.")])
        async for event in runner.run_async(user_id="u", session_id=session.id, new_message=message):
            for part in (event.content.parts or []) if event.content else []:
                if part.function_response:
                    print(f"{part.function_response.id}: {part.function_response.response}")


if __name__ == "__main__":
    asyncio.run(main())
