/**
 * Doctor's checks for the agent-configuration scan: the last agent-configuration scan of this
 * project (what made sessions start untrusted, what was only logged, whether
 * it was complete) and the MCP pins (changes waiting for review, a corrupt
 * pins file moved aside).
 */

import { readdirSync } from "node:fs";
import { dirname } from "node:path";
import { readLastScan, scanWorkspace } from "./agentscan.js";
import { readText } from "./fsutil.js";
import type { Layout } from "./layout.js";
import { parsePins, pinsPath } from "./pins.js";

export interface AgentCheck {
  name: string;
  status: "ok" | "warn" | "fail";
  detail: string;
}

export function agentChecks(l: Layout, projectDir: string, home: string): AgentCheck[] {
  const out: AgentCheck[] = [];
  const last = readLastScan(l, scanWorkspace(projectDir, home));
  if (last === null) out.push({ name: "agent scan", status: "ok", detail: "no session has started in this project yet (the scan runs when one does)" });
  else {
    const when = last.at.slice(0, 16).replace("T", " ");
    if (last.tainted.length > 0) out.push({ name: "agent scan", status: "warn", detail: `the last session here (${when}) started untrusted: ${last.tainted.slice(0, 3).join("; ")}` });
    else out.push({ name: "agent scan", status: "ok", detail: `last session here (${when}) started trusted${last.logged.length > 0 ? `; logged: ${last.logged.slice(0, 3).join("; ")}` : ""}` });
    if (last.incomplete.length > 0) out.push({ name: "agent scan coverage", status: "warn", detail: `the last scan here was incomplete (${last.incomplete.join("; ")}); files beyond the limit were not checked` });
  }
  const text = readText(pinsPath(l));
  const pins = text === null ? null : parsePins(text);
  if (text !== null && pins === null) out.push({ name: "MCP pins", status: "fail", detail: `${pinsPath(l)} is unreadable; the next session moves it aside, taints once and pins every server again` });
  else if (pins !== null && pins.pending.length > 0) {
    const names = [...new Set(pins.pending.map((c) => c.name))];
    out.push({ name: "MCP pins", status: "warn", detail: `${pins.pending.length} change(s) waiting for review on ${names.join(", ")}: sessions that use them are untrusted. Run "launchsafe-firewall pins", then "launchsafe-firewall pins accept <server>" in your own terminal` });
  } else out.push({ name: "MCP pins", status: "ok", detail: `${pins === null ? 0 : Object.keys(pins.servers).length} server(s) pinned, nothing waiting for review` });
  // Review of FZ15: a server name that ends in "_" (or in a character agents turn into "_") runs into the "__" in
  // mcp__<server>__<tool>; the firewall then cannot tell it from a server without the "_" and asks every call.
  const names = new Set<string>(pins === null ? [] : Object.values(pins.servers).map((p) => p.name));
  const runInto = [...names].filter((n) => n.replace(/[^A-Za-z0-9_-]/g, "_").endsWith("_"));
  if (runInto.length > 0) out.push({ name: "MCP server names", status: "warn", detail: `${runInto.slice(0, 5).join(", ")}: a server name ending in "_" runs into the "__" separator of its tools' names (mcp__<server>__<tool>), so every call to it is asked; rename the server` });
  try {
    const aside = readdirSync(dirname(pinsPath(l))).filter((n) => n.startsWith("mcp.json.corrupt-"));
    if (aside.length > 0) out.push({ name: "MCP pins history", status: "warn", detail: `an unreadable pins file was moved aside (${aside.join(", ")}); inspect and delete it` });
  } catch {
    // No pins directory yet.
  }
  return out;
}
