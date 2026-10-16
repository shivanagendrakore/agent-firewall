/**
 * tools/list pinning and hiding (the gateway's
 * pinning of each tool definition). A hook never sees a server's tool list; the gateway sees every
 * one, so each tool's definition is pinned in the same pins/mcp.json the hooks
 * use, hashed twice:
 *
 * - v1 = descriptionHash({description, inputSchema}), the hooks' own hash, so
 *   a pin made through Claude Code's ToolSearch and one made here agree;
 * - v2 = sha256 of the canonical {name, title, description, inputSchema,
 *   outputSchema, annotations}, which also catches a changed annotation.
 *
 * First sight of a server pins everything, except a tool whose description
 * carries hidden text or an instruction to the agent: that one is hidden at
 * once. Afterwards a changed definition, or a new tool after the grace window,
 * is a pending change, and under `gateway.toolChanges: "hide"` (the
 * default) the tool is removed from what the client sees until a
 * person runs `pins accept <server>`. Under "taint" it stays visible and the
 * session is tainted, as v0.2 does. A changed server version alone is pending
 * and reported, but hides nothing: the definitions the model sees are the
 * same. The order of the list never matters (each tool is hashed by itself).
 */

import { createHash } from "node:crypto";
import type { FirewallConfig } from "../types.js";
import { canonicalJson, type JsonValue } from "../vendor/agent-safety/index.js";
import { day, descriptionFindings, descriptionHash, dropPending, inGrace, MCP_CHANGED, updatePins, upsertPending, type McpPin, type PendingChange, type PinFile, type PinOutcome } from "../runtime/pins.js";
import type { Layout } from "../runtime/layout.js";
import { own, setOwn } from "../own.js";

type Json = Record<string, unknown>;

export interface GatewayPinKey {
  /** The pin key (`gw-<client>:<server>` in full mode, the agent's own key in hook mode). */
  key: string;
  /** The server's name as the client knows it (the middle of mcp__<server>__<tool>). */
  server: string;
  source: string;
}

export interface ListOutcome extends PinOutcome {
  /** The tools the client may see, in the server's order. */
  visible: Json[];
  hidden: { tool: string; why: string }[];
}

const HIDING_KINDS = new Set(["description", "new_tool", "annotations"]);

const strOf = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

function canon(v: unknown): string {
  try {
    return canonicalJson((v ?? null) as JsonValue);
  } catch {
    return JSON.stringify(v ?? null);
  }
}

export function v1Hash(t: Json): string {
  return descriptionHash({ server: "", tool: strOf(t.name) ?? "", description: strOf(t.description) ?? "", schema: t.inputSchema ?? null });
}

export function v2Hash(t: Json): string {
  return createHash("sha256").update(canon({ name: t.name ?? null, title: t.title ?? null, description: t.description ?? null, inputSchema: t.inputSchema ?? null, outputSchema: t.outputSchema ?? null, annotations: t.annotations ?? null })).digest("hex");
}

/**
 * A new tool recorded the way the hooks record one (no definition hash): in hook mode the client's own hook
 * decides calls to it (R9: taint, results untrusted), so the gateway does not hide it as well (V22), as long
 * as the gateway saw the server list it (`listed`; see hiddenTool).
 */
const hookNewTool = (p: PendingChange): boolean => p.kind === "new_tool" && p.toV2 === undefined;

/**
 * Whether a tool is hidden: a pending change to it that hides, or a tool the gateway-seen server never
 * listed. `hookMode`: the gateway runs in hook mode, where a new tool recorded by the hooks' rule is the
 * hook's to decide, but only one the server listed: a hook's record (from a call the agent made) never
 * makes a tool the server did not list callable (GW6), and a listed definition with a finding is recorded
 * over the hook's record (upsertPending keeps the stricter state, GW7).
 *
 * "Listed" is what the gateway saw in a tools/list: a definition it pinned (gatewayDefs), or a hook-style
 * new tool it saw listed. The hooks' own name list (pin.tools) does not count: it also holds tools seen
 * only in calls.
 */
export function hiddenTool(pins: PinFile, key: string, tool: string, hookMode = false): string | null {
  const mine = pins.pending.filter((p) => p.key === key && p.tool === tool && HIDING_KINDS.has(p.kind));
  const pend = mine.find((p) => !(hookMode && hookNewTool(p)));
  if (pend !== undefined) return pend.detail;
  const pin = own(pins.servers, key);
  if (pin === undefined || !(pin.seenBy ?? []).includes("gateway")) return null;
  const listed = Object.prototype.hasOwnProperty.call(pin.gatewayDefs ?? {}, tool) || mine.some((p) => p.listed === true);
  if (!listed) return `MCP server "${pin.name}" did not list a tool called ${tool} when the firewall last saw its tool list`;
  return null;
}

/**
 * V12: every text of a tool definition the model reads, not only its description: the title, the
 * annotations' title, and every string and property name in its input and output schemas (property
 * descriptions are the usual tool-poisoning place).
 */
export function toolTexts(t: Json): { texts: string[]; truncated: boolean } {
  const out: string[] = [];
  // V12 (GW8): the name is shown to the model too (and tag characters in it are as hidden as anywhere).
  for (const k of ["name", "description", "title"]) if (typeof own(t, k) === "string") out.push(own(t, k) as string);
  if (isObj(t.annotations) && typeof t.annotations.title === "string") out.push(t.annotations.title);
  let budget = TOOL_WALK_NODES;
  let truncated = false;
  const walk = (v: unknown, depth: number): void => {
    if (truncated) return;
    // GW1/GW2: a walk that runs out of depth or nodes reports it, so the caller fails closed.
    if (budget-- <= 0 || depth > TOOL_WALK_DEPTH) {
      truncated = true;
      return;
    }
    if (typeof v === "string") out.push(v);
    else if (Array.isArray(v)) for (const x of v) walk(x, depth + 1);
    else if (isObj(v)) {
      for (const [k, x] of Object.entries(v)) {
        out.push(k);
        walk(x, depth + 1);
      }
    }
  };
  walk(t.inputSchema, 0);
  walk(t.outputSchema, 0);
  return { texts: out, truncated };
}

/** The walk limits for a tool's schemas: past either, the definition is not fully checked and the tool is hidden. */
export const TOOL_WALK_DEPTH = 64;
export const TOOL_WALK_NODES = 20_000;
export const TOO_LARGE_FINDING = `a definition too deep or too large to check (past ${TOOL_WALK_DEPTH} levels or ${TOOL_WALK_NODES.toLocaleString("en-US")} values)`;

/**
 * What the hidden-text and instruction detectors find anywhere in a tool's definition. A definition the walk
 * could not finish is a finding of its own (fail closed): what lies past the limit was never checked.
 */
export function toolFindings(t: Json): string[] {
  const { texts, truncated } = toolTexts(t);
  const found = descriptionFindings(texts.join("\n"));
  if (truncated) found.push(TOO_LARGE_FINDING);
  return found;
}

/**
 * One tools/list result. `serverVersion` is the server's self-reported version (from discovery or
 * initialize), when known. `hide`: gateway.toolChanges is "hide".
 */
export function observeToolList(l: Layout, cfg: FirewallConfig, k: GatewayPinKey, tools: readonly Json[], serverVersion: string | undefined, hide: boolean, now: Date, hookMode = false): ListOutcome {
  const out: ListOutcome = { events: [], alerts: [], log: [], visible: [], hidden: [] };
  if (!cfg.mcpPinning.enabled) {
    out.visible = [...tools];
    return out;
  }
  const ts = now.toISOString();
  const valid = tools.filter((t) => typeof t.name === "string" && t.name !== "");
  return updatePins(l, now, (pins, corrupt) => {
    let changed = false;
    if (corrupt !== null) {
      out.events.push({ type: "taint", source: `${MCP_CHANGED}: the MCP pins file was unreadable` });
      out.log.push({ type: "mcp_pin", change: "corrupt", moved: corrupt });
    }
    let pin: McpPin | undefined = own(pins.servers, k.key);
    const first = pin === undefined;
    if (pin === undefined) {
      pin = { key: k.key, name: k.server, source: k.source, configHash: null, launch: { pin: "unknown" }, tools: [], descriptions: {}, pinnedAt: ts, pinnedBy: "first-use", gatewayDefs: {}, seenBy: ["gateway"], ...(serverVersion !== undefined ? { serverVersion } : {}) };
      setOwn(pins.servers, k.key, pin);
      out.log.push({ type: "mcp_pin", change: "pinned", server: k.key, by: "first-use", via: "gateway" });
      changed = true;
    }
    // V22: the gateway's first look at a server a hook pinned (from tool calls, never a tool list). In hook
    // mode the hook keeps deciding its calls, so a listed tool it never saw follows the hook's own first-use
    // rule (R9) rather than being hidden as a new tool.
    const hookFirstSight = hookMode && !first && !(pin.seenBy ?? []).includes("gateway");
    if (!(pin.seenBy ?? []).includes("gateway")) {
      pin.seenBy = [...(pin.seenBy ?? ["hook"]), "gateway"];
      changed = true;
    }
    const defs = pin.gatewayDefs ?? {};
    pin.gatewayDefs = defs;
    const hideNow = new Map<string, string>();
    const taintFor = (tool: string, why: string): void => {
      if (!hide && cfg.mcpPinning.taintOnChange) out.events.push({ type: "taint", source: `${MCP_CHANGED}: ${why} (tool ${tool} on MCP server ${k.server})`.slice(0, 300) });
    };
    for (const t of valid) {
      const name = t.name as string;
      const v1 = v1Hash(t);
      const v2 = v2Hash(t);
      const findings = toolFindings(t);
      const known = pin.tools.includes(name);
      if (!known) {
        if (first || inGrace(pin, cfg, now)) {
          pin.tools.push(name);
          changed = true;
          if (findings.length > 0) {
            const detail = `The description of ${name} on MCP server "${k.server}" carries ${findings.join(" and ")}`;
            upsertPending(pins, { key: k.key, name: k.server, kind: "description", tool: name, to: v1, toV2: v2, detail, ...(findings.length > 0 ? { finding: true } : {}) }, ts);
            hideNow.set(name, detail);
            out.alerts.push(`${detail}. The tool is hidden from the agent until you have read it and run in your own terminal: launchsafe-firewall pins accept ${k.server}`);
            out.log.push({ type: "mcp_pin", change: "hidden", server: k.key, tool: name, findings });
          } else {
            setOwn(pin.descriptions, name, v1);
            setOwn(defs, name, v2);
          }
          continue;
        }
        const p0 = pin;
        if (findings.length === 0 && (hookFirstSight || (hookMode && pins.pending.some((p) => p.key === p0.key && p.tool === name && hookNewTool(p))))) {
          hookFirstUse(pins, pin, cfg, k, name, v1, v2, ts, out);
          changed = true;
          continue;
        }
        const detail = `MCP server "${k.server}" lists a new tool, ${name}, that it did not have when it was pinned on ${day(pin.pinnedAt)}${findings.length > 0 ? `, and its definition carries ${findings.join(" and ")}` : ""}`;
        upsertPending(pins, { key: k.key, name: k.server, kind: "new_tool", tool: name, to: v1, toV2: v2, detail, ...(findings.length > 0 ? { finding: true } : {}) }, ts);
        changed = true;
        out.log.push({ type: "mcp_pin", change: "new_tool", server: k.key, tool: name, via: "gateway" });
        if (hide || findings.length > 0) {
          hideNow.set(name, detail);
          out.alerts.push(`${detail}. It is hidden from the agent until you review it; if you expected it, run in your own terminal: launchsafe-firewall pins accept ${k.server}`);
          out.log.push({ type: "mcp_pin", change: "hidden", server: k.key, tool: name });
        } else {
          out.alerts.push(`${detail}. A new tool counts as unknown until you review it: launchsafe-firewall pins accept ${k.server}`);
          taintFor(name, "a new tool");
        }
        continue;
      }
      const pinned1 = own(pin.descriptions, name);
      const pinned2 = own(defs, name);
      if (pinned1 === undefined) {
        // Known by name only (a hook saw it called): its definition is pinned now, unless it carries a finding.
        if (findings.length > 0) {
          const detail = `The description of ${name} on MCP server "${k.server}" carries ${findings.join(" and ")}`;
          upsertPending(pins, { key: k.key, name: k.server, kind: "description", tool: name, to: v1, toV2: v2, detail, ...(findings.length > 0 ? { finding: true } : {}) }, ts);
          hideNow.set(name, detail);
          out.alerts.push(`${detail}. The tool is hidden from the agent until you have read it: launchsafe-firewall pins accept ${k.server}`);
          out.log.push({ type: "mcp_pin", change: "hidden", server: k.key, tool: name, findings });
        } else {
          setOwn(pin.descriptions, name, v1);
          setOwn(defs, name, v2);
        }
        changed = true;
        continue;
      }
      if (pinned1 !== v1) {
        const detail = `The description of ${name} on MCP server "${k.server}" changed since it was pinned on ${day(pin.pinnedAt)}${findings.length > 0 ? `, and the new text carries ${findings.join(" and ")}` : ""}`;
        upsertPending(pins, { key: k.key, name: k.server, kind: "description", tool: name, to: v1, toV2: v2, detail, ...(findings.length > 0 ? { finding: true } : {}) }, ts);
        changed = true;
        out.log.push({ type: "mcp_pin", change: "description", server: k.key, tool: name, via: "gateway" });
        if (hide || findings.length > 0) {
          hideNow.set(name, detail);
          out.log.push({ type: "mcp_pin", change: "hidden", server: k.key, tool: name });
          out.alerts.push(`${detail}. A changed description can carry new instructions for the agent (a "rug pull"), so the tool is hidden until you review it: launchsafe-firewall pins accept ${k.server}`);
        } else {
          out.alerts.push(`${detail}. Review it, then run in your own terminal: launchsafe-firewall pins accept ${k.server}`);
          taintFor(name, "a changed description");
        }
        continue;
      }
      if (pinned2 === undefined || pinned2 !== v2) {
        // The description and input schema are the pinned ones; what changed is the title, the annotations or
        // the output schema (or, for a tool only a hook pinned, they were never recorded). Those are read by
        // the model too, so they are checked like a description (VG2, VG3): a finding hides the tool under
        // every toolChanges policy, and a definition carrying one is never pinned.
        const changedFindings = toolFindings({ name: t.name, title: t.title, annotations: t.annotations, outputSchema: t.outputSchema });
        if (pinned2 === undefined && changedFindings.length === 0) {
          setOwn(defs, name, v2);
          changed = true;
        } else {
          const what = pinned2 === undefined ? "title, annotations or output schema" : "annotations, title or output schema";
          const detail = `The ${what} of ${name} on MCP server "${k.server}" ${pinned2 === undefined ? "were not recorded when it was pinned" : `changed since it was pinned on ${day(pin.pinnedAt)}`}${changedFindings.length > 0 ? `, and the new text carries ${changedFindings.join(" and ")}` : ""}`;
          upsertPending(pins, { key: k.key, name: k.server, kind: "annotations", tool: name, toV2: v2, detail, ...(changedFindings.length > 0 ? { finding: true } : {}) }, ts);
          changed = true;
          out.log.push({ type: "mcp_pin", change: "annotations", server: k.key, tool: name, ...(changedFindings.length > 0 ? { findings: changedFindings } : {}) });
          if (hide || changedFindings.length > 0) {
            hideNow.set(name, detail);
            out.log.push({ type: "mcp_pin", change: "hidden", server: k.key, tool: name });
            out.alerts.push(`${detail}. It is hidden from the agent until you review it: launchsafe-firewall pins accept ${k.server}`);
          } else {
            out.alerts.push(`${detail}. Review it, then run in your own terminal: launchsafe-firewall pins accept ${k.server}`);
            taintFor(name, "changed annotations");
          }
          continue;
        }
      }
      // The definition is the pinned one again: a pending change for it no longer applies.
      for (const kind of ["description", "annotations"] as const) if (dropPending(pins, k.key, kind, name)) changed = true;
    }
    if (serverVersion !== undefined) {
      if (pin.serverVersion === undefined) {
        pin.serverVersion = serverVersion;
        changed = true;
      } else if (pin.serverVersion !== serverVersion) {
        const detail = `MCP server "${k.server}" reports version ${serverVersion.slice(0, 40)}, not the ${pin.serverVersion.slice(0, 40)} pinned on ${day(pin.pinnedAt)}`;
        upsertPending(pins, { key: k.key, name: k.server, kind: "server_version", to: serverVersion, detail }, ts);
        changed = true;
        out.log.push({ type: "mcp_pin", change: "server_version", server: k.key });
        out.alerts.push(`${detail}. Its tool definitions are compared one by one; to record the new version, run in your own terminal: launchsafe-firewall pins accept ${k.server}`);
      } else if (dropPending(pins, k.key, "server_version")) changed = true;
    }
    for (const t of valid) {
      const name = t.name as string;
      const why = hideNow.get(name) ?? (hide ? hiddenTool(pins, k.key, name, hookMode) : pendingFinding(pins, k.key, name));
      if (why !== null) out.hidden.push({ tool: name, why });
      else out.visible.push(t);
    }
    return { changed, result: out };
  });
}

/** Under "taint", a tool stays visible unless its pending change carries a description finding. */
function pendingFinding(pins: PinFile, key: string, tool: string): string | null {
  const p = pins.pending.find((x) => x.key === key && x.tool === tool && HIDING_KINDS.has(x.kind) && x.finding === true);
  return p?.detail ?? null;
}

/** The call-time check: under "hide", any hiding change; under "taint", only a description finding. */
export function callHidden(pins: PinFile, key: string, tool: string, hide: boolean, hookMode = false): string | null {
  return hide ? hiddenTool(pins, key, tool, hookMode) : pendingFinding(pins, key, tool);
}

/**
 * V22, hook mode: a listed tool the hook never saw called, on a server the hook pinned, judged as the hook
 * judges a first call (src/runtime/pins.ts toolCallPins, R9). Inside the grace window, or when its
 * definition was seen before or the server's launch is pinned to an exact version with an unchanged
 * configuration, it is a first use: pinned and logged. Otherwise it is a new tool recorded the hook's way
 * (taint, an alert, `pins accept` to review), still visible: calls to it go through the client's hook, which
 * taints the session and treats the results as outside content, as without the gateway.
 */
function hookFirstUse(pins: PinFile, pin: McpPin, cfg: FirewallConfig, k: GatewayPinKey, name: string, v1: string, v2: string, ts: string, out: ListOutcome): void {
  const pendingConfig = pins.pending.some((c) => c.key === pin.key && c.kind === "config");
  const existed = Object.prototype.hasOwnProperty.call(pin.descriptions, name) || (pin.launch.pin === "stable" && pin.configHash !== null && !pendingConfig);
  if (inGrace(pin, cfg, new Date(ts)) || existed) {
    pin.tools.push(name);
    if (!Object.prototype.hasOwnProperty.call(pin.descriptions, name)) setOwn(pin.descriptions, name, v1);
    setOwn((pin.gatewayDefs ??= {}), name, v2);
    out.log.push({ type: "mcp_pin", change: "first_use", server: k.key, tool: name, via: "gateway" });
    return;
  }
  const why = pendingConfig ? "its configuration changed and is not reviewed" : pin.launch.pin === "stable" ? "it was never seen to expose it" : "its launch is not pinned to a version, so its tools can change without a configuration change";
  const detail = `MCP server "${k.server}" exposes a new tool, ${name}, not seen since it was pinned on ${day(pin.pinnedAt)} (${why})`;
  const had = pins.pending.some((p) => p.key === pin.key && p.kind === "new_tool" && p.tool === name);
  upsertPending(pins, { key: pin.key, name: k.server, kind: "new_tool", tool: name, detail, listed: true }, ts);
  if (had) return;
  out.log.push({ type: "mcp_pin", change: "new_tool", server: k.key, tool: name, via: "gateway", rule: "hook" });
  out.alerts.push(`${detail}. A new tool counts as unknown until you review it. If you expected it, run in your own terminal: launchsafe-firewall pins accept ${k.server}`);
  if (cfg.mcpPinning.taintOnChange) out.events.push({ type: "taint", source: `${MCP_CHANGED}: new tool ${name} on MCP server ${k.server}`.slice(0, 300) });
}
