/**
 * Claude Agent SDK: the firewall's hooks and canUseTool in query()'s options.
 * Run: npm run build && node examples/sdk/claude-agent-sdk.ts
 * With RUN_CLAUDE=1 (and Claude Code's credentials set up) it runs a real query(); otherwise it shows
 * what the hooks answer for two calls, without starting Claude Code.
 */

import { query, type PreToolUseHookInput } from "@anthropic-ai/claude-agent-sdk";
import { createNodeGuard } from "@launchsafe/agent-firewall/sdk/node";
import { claudeAgentFirewall } from "@launchsafe/agent-firewall/sdk/claude-agent-sdk";

const guard = createNodeGuard({
  workspace: process.cwd(),
  // Your person. Here: no (a real host shows req.message and waits for the answer).
  onApproval: (req) => {
    console.log(`asked: ${req.message.split("\n")[0]}`);
    return false;
  },
});
const fw = claudeAgentFirewall(guard);

if (process.env.RUN_CLAUDE === "1") {
  for await (const message of query({ prompt: "Summarize README.md", options: { hooks: fw.hooks, canUseTool: fw.canUseTool } })) {
    if (message.type === "result") console.log(message);
  }
} else {
  const pre = (tool_name: string, tool_input: Record<string, unknown>): PreToolUseHookInput => ({ session_id: "demo", transcript_path: "/dev/null", cwd: process.cwd(), hook_event_name: "PreToolUse", tool_name, tool_input, tool_use_id: `toolu_${tool_name}` });
  const hook = fw.hooks.PreToolUse?.[0]?.hooks[0];
  const signal = new AbortController().signal;
  for (const [tool, input] of [["Read", { file_path: `${process.cwd()}/README.md` }], ["Bash", { command: "cat ~/.ssh/id_rsa" }]] as const) {
    const out = await hook?.(pre(tool, input), `toolu_${tool}`, { signal });
    const spec = out !== undefined && "hookSpecificOutput" in out ? (out.hookSpecificOutput as { permissionDecision?: string } | undefined) : undefined;
    console.log(`${tool}: ${spec?.permissionDecision ?? "allow (no output: Claude Code's own rules apply)"}`);
  }
}
