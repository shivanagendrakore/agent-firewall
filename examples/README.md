# Examples

Runnable examples of the firewall's library (`@launchsafe/agent-firewall/sdk`)
with the agent frameworks it supports. They use stub tools and a scripted or
mock model, so they need no API key unless a file says otherwise. Python
examples are in [python/examples/](../python/examples/).

In `sdk/`:

- `claude-agent-sdk.ts`: the hooks and `canUseTool` in the Claude Agent SDK's
  `query()` options. With `RUN_CLAUDE=1` it runs a real query; otherwise it shows
  what the hooks answer for two calls.
- `langgraph.ts`: `firewallToolNode()` in place of `ToolNode`; an ask interrupts
  the graph.
- `openai-agents.ts`: `firewallTool()` adds approval and tool guardrails to a
  function tool.
- `plain-loop.ts`: the library in a hand-written agent loop, with your own tools
  and approval prompt.
- `vercel-ai.ts`: the firewall as `toolApproval`, plus wrapped tools.

Run `npm run build` from the repository root first, then run a file from the
root, for example `node examples/sdk/plain-loop.ts`. The package's `engines`
field asks for Node 22 or newer; running a `.ts` file directly needs Node 22.18
or newer, which runs TypeScript without a flag. On an older Node 22, build
the file first or use a TypeScript runner.
