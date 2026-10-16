"""Claude Agent SDK with the LaunchSafe Agent Firewall.

This example makes no model call and starts no Claude Code process: it builds the options you would
pass to `query()` and shows what the PreToolUse hook answers for two tool calls Claude Code is about to
make. Start the sidecar first (`launchsafe-firewall serve --api`, and register this agent with
`launchsafe-firewall api tools set <agentId> tools.json`), and set LAUNCHSAFE_FIREWALL_TOKEN. Without a
sidecar you see the fail-closed answer: both calls are denied with FW-UNAVAILABLE.

To use it for real:

    options = ClaudeAgentOptions(hooks=firewall.hooks, can_use_tool=firewall.can_use_tool)
    async for message in query(prompt="...", options=options):
        ...

    pip install 'launchsafe-firewall[claude-agent-sdk]'
    python examples/claude_agent_sdk_example.py
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from claude_agent_sdk import ClaudeAgentOptions
from claude_agent_sdk.types import HookInput

from launchsafe_firewall import AsyncGuard
from launchsafe_firewall.integrations.claude_agent_sdk import claude_agent_firewall


def tool_call(name: str, tool_input: dict[str, Any], use_id: str) -> HookInput:
    """What Claude Code sends a PreToolUse hook (built here by hand: nothing runs)."""
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "example",
        "transcript_path": "",
        "cwd": os.getcwd(),
        "tool_name": name,
        "tool_input": tool_input,
        "tool_use_id": use_id,
    }


async def main() -> None:
    async with AsyncGuard(session=os.environ.get("RUN_ID", "example-run")) as guard:
        firewall = claude_agent_firewall(guard)
        options = ClaudeAgentOptions(hooks=firewall.hooks, can_use_tool=firewall.can_use_tool)
        print("hooks:", sorted(options.hooks or {}))
        for name, tool_input in [("Read", {"file_path": "README.md"}), ("WebFetch", {"url": "https://example.com"})]:
            answer = await firewall.pre_tool_use(tool_call(name, tool_input, f"toolu_{name}"), None, {"signal": None})
            print(name, "->", answer or "allowed (Claude Code's own permission rules still apply)")


if __name__ == "__main__":
    asyncio.run(main())
