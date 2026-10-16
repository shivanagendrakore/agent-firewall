/**
 * The host's own tools in the engine's vocabulary (docs/library.md, "Your
 * tools in the engine's vocabulary"). A tool is either one the engine models
 * (`as`) or judged like an MCP tool (`kind`), so no rule is written twice.
 */

import type { FirewallConfig, McpServerPolicy, NormalizedAction } from "../types.js";
import type { KindToolSpec, ToolCall, ToolSpec } from "./types.js";
import { own, setOwn } from "../own.js";

/** An MCP server name can hold anything but "__" (the separator in mcp__server__tool). */
function serverName(s: string): string {
  const n = s.replace(/_{2,}/g, "_").replace(/^_+|_+$/g, "");
  return n === "" ? "tool" : n;
}

function isKind(s: ToolSpec): s is KindToolSpec {
  return "kind" in s;
}

/** The server policies the specs declare, merged into the config (exact entries, so presets do not apply). */
export function toolServers(specs: Record<string, ToolSpec>): Record<string, McpServerPolicy> {
  const out: Record<string, McpServerPolicy> = {};
  const lists: Record<KindToolSpec["kind"], "readTools" | "sendTools" | "destructiveTools" | "blockedTools"> = { read: "readTools", send: "sendTools", destroy: "destructiveTools", blocked: "blockedTools" };
  for (const [tool, spec] of Object.entries(specs)) {
    if (!isKind(spec)) continue;
    if (!(spec.kind in lists)) throw new Error(`tool ${tool}: kind must be read, send, destroy or blocked`);
    // The policy's tool lists are globs: a name with glob characters would match other tools too.
    if (/[*?{},]/.test(tool)) throw new Error(`tool ${tool}: a tool name with *, ?, {, } or , cannot be declared`);
    const server = serverName(spec.server ?? tool);
    const results = spec.results ?? "untrusted";
    const privateData = spec.privateData ?? true;
    const p = own(out, server) ?? { results, privateData };
    if (p.results !== results || p.privateData !== privateData) throw new Error(`tools of server ${server} disagree on results/privateData (${tool}); give them separate servers`);
    const key = lists[spec.kind];
    p[key] = [...(p[key] ?? []), tool];
    setOwn(out, server, p);
  }
  return out;
}

/** The config with the specs' servers added (the host's specs win over a policy entry of the same name). */
export function withToolServers(cfg: FirewallConfig, specs: Record<string, ToolSpec>): FirewallConfig {
  const servers = toolServers(specs);
  if (Object.keys(servers).length === 0) return cfg;
  return { ...cfg, mcpServers: { ...cfg.mcpServers, ...servers } };
}

/** The action the engine judges for a host call, and the MCP source to judge it with. */
export function toAction(call: ToolCall, specs: Record<string, ToolSpec>): { action: NormalizedAction; mcpSource?: string } {
  const spec = own(specs, call.tool);
  const input = call.input;
  if (spec === undefined) {
    // Not declared: the engine's own vocabulary. An mcp__ tool whose configuration source is not stated is
    // "unknown" (a repository-defined server is never trusted on its name), as the hook derives it.
    if (call.tool.startsWith("mcp__")) return { action: { tool: call.tool, input }, mcpSource: call.mcpSource ?? "unknown" };
    return { action: { tool: call.tool, input } };
  }
  if (isKind(spec)) {
    const server = serverName(spec.server ?? call.tool);
    // The declared server is the host's own: its exact policy entry decides, whatever the source.
    return { action: { tool: `mcp__${server}__${call.tool}`, input } };
  }
  return { action: { tool: spec.as, input: spec.input !== undefined ? spec.input(input) : input } };
}
