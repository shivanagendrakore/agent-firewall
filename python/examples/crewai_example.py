"""CrewAI with the LaunchSafe Agent Firewall, using stub tools and a scripted model (no API key).

Needs the sidecar running (`launchsafe-firewall serve --api`). Register the tools under the names
CrewAI gives the model (lowercase, underscores): `lookup_order`, `send_email`.

    pip install 'launchsafe-firewall[crewai]'
    python examples/crewai_example.py
"""

from __future__ import annotations

from typing import Any

from crewai import Agent, Crew, Task
from crewai.llms.base_llm import BaseLLM
from crewai.tools import tool

from launchsafe_firewall import Guard
from launchsafe_firewall.integrations.crewai import install_firewall

TOOLS = {
    "lookup_order": {"kind": "read", "results": "trusted", "privateData": False},
    "send_email": {"kind": "send"},
}


@tool("lookup_order")
def lookup_order(order_id: str) -> str:
    """Look up an order's status (stub)."""
    return f"order {order_id}: shipped"


@tool("send_email")
def send_email(to: str, body: str) -> str:
    """Send an email (stub: nothing is sent)."""
    return f"(stub) would send {len(body)} characters to {to}"


class ScriptedLLM(BaseLLM):
    """Stands in for a model that chooses two tool calls, then gives its answer."""

    def call(self, messages: Any, *args: Any, **kwargs: Any) -> str:
        step = sum(1 for m in messages if isinstance(m, dict) and m.get("role") == "assistant")
        script = [
            ("lookup_order", '{"order_id": "A-17"}'),
            ("send_email", '{"to": "someone@example.com", "body": "shipped"}'),
        ]
        if step < len(script):
            name, arguments = script[step]
            return f"Thought: I need a tool.\nAction: {name}\nAction Input: {arguments}"
        return "Thought: I now know the final answer\nFinal Answer: done"

    def supports_function_calling(self) -> bool:
        return False


def main() -> None:
    with Guard(session="example-run", tools=TOOLS) as guard:
        uninstall = install_firewall(guard)  # after any hooks of your own
        try:
            agent = Agent(
                role="support",
                goal="Answer order questions",
                backstory="A support agent.",
                llm=ScriptedLLM(model="scripted"),
                tools=[lookup_order, send_email],
                allow_delegation=False,
            )
            task = Task(
                description="Check order A-17 and email the customer.", expected_output="A summary", agent=agent
            )
            print(Crew(agents=[agent], tasks=[task]).kickoff())
        finally:
            uninstall()


if __name__ == "__main__":
    main()
