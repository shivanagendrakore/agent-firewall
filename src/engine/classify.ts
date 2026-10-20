/**
 * From a tool call to effects: Claude Code's built-in tools, MCP tools, and
 * unknown tools (judged by the paths and URLs in their arguments).
 */

import type { Context, FirewallConfig, NormalizedAction, SessionState } from "../types.js";
import { addEffect, addFinding, createdByTrustedSession, egress, externalSend, newCollector, readPath, writePath, type Collector } from "./effects.js";
import { isFilesystemServerName, isMessageTool, mcpDestination, resolveMcpTool, rootsInWorkspace, serverPolicy, toolKind, type FsRoots } from "./mcp.js";
import { parseUrlLike } from "./network.js";
import { classifyAsSpelled, resolvePath } from "./paths.js";
import { analyzeShell } from "./shell/analyze.js";
import { classifySql } from "./sql.js";
import { judgeMcpTool, judgeSql } from "./catastrophic.js";
import { invisibleCharacters } from "./unicode.js";
import { agentOfSettings, applyEdits, isClaudeSettingsFile, isHookSettingsIn, looseEditResults, settingsViolations } from "./settings.js";
import { gatewayConfigChanges, gatewayConfigFor } from "./gateway-config.js";
import { layersInteract, mergeSettingsLayers, profileFromPolicy, sandboxPolicy, sandboxViolations, settingsRank, type SandboxGuard } from "./sandbox.js";
import { isEditorSettingsFile, newAutoApproveSwitches } from "./autoapprove.js";
import { checkAutorun } from "./autorun.js";
import { normalizeAbs } from "./paths.js";
import { hostTool, type HostTool } from "./hosttools.js";
import { own } from "../own.js";
import { MAX_INPUT_DEPTH } from "./input-depth.js";

/** Tools that only talk to the agent itself or the person (todo lists, plans, questions, background shell output). */
export const SAFE_TOOLS = new Set([
  "TodoWrite",
  "TodoRead",
  "ExitPlanMode",
  "EnterPlanMode",
  "AskUserQuestion",
  "BashOutput",
  "KillShell",
  "KillBash",
  "TaskOutput",
  "TaskStop",
  "TaskCreate",
  "TaskUpdate",
  "TaskList",
  "TaskGet",
  "ToolSearch",
  "Task",
  "Agent",
  "Skill",
  "SlashCommand",
  "SendMessage",
  "Sleep",
]);

/**
 * The name an adapter gives a native call it cannot read (a Codex patch that does not parse).
 * The firewall cannot tell what it would change, so it is a parse failure: a person decides.
 */
export const UNPARSEABLE_TOOL = "launchsafe:unparseable";

/**
 * A network request a sandbox middleware refused before asking the engine (a Host or pseudo-header naming
 * another target than the one the connection goes to, a loopback or other non-public address target): recorded as a decision so the
 * refusal is in the signed log with its rule and reason. Always denied (FW-NET-REFUSED).
 */
export const NETWORK_REFUSED_TOOL = "launchsafe:network-refused";

/** Tools that read but never change anything: they fail open if the firewall itself fails. */
export const READ_ONLY_TOOLS = new Set(["Read", "Glob", "Grep", "LS", "NotebookRead", "ListMcpResourcesTool", ...SAFE_TOOLS]);

/** M5: the directory a glob pattern starts from when the pattern is absolute ("/etc/**", "~/.ssh/*"), else null. */
function globBase(pattern: string): string | null {
  if (!pattern.startsWith("/") && !pattern.startsWith("~/") && pattern !== "~") return null;
  const segs = pattern.split("/");
  const i = segs.findIndex((s) => /[*?[\]{}]/.test(s));
  const base = (i === -1 ? segs.slice(0, -1) : segs.slice(0, i)).join("/");
  return base === "" ? "/" : base;
}

export interface Classified {
  collector: Collector;
}

function str(input: Record<string, unknown>, ...keys: string[]): string | undefined {
  for (const k of keys) {
    const v = own(input, k);
    if (typeof v === "string") return v;
  }
  return undefined;
}

function listing(c: Collector, raw: string, via: string): void {
  const r = resolvePath(raw, c.ctx);
  if (r === null) return;
  // I1: a listing only ever grants trust by a match (the agent's own settings, a credential store's names), so the
  // lists are matched by the platform's case rule: on a case-sensitive disk another spelling is another directory.
  const info = classifyAsSpelled(r, c.ctx, c.cfg);
  if (info.zone === "outside" && !info.trustedRead && !info.credentialStore && !info.protected && !info.firewall && !createdByTrustedSession(c, info.abs)) addEffect(c, { cls: "read_external", target: info.abs, detail: `list files outside the workspace: ${info.abs} (${via})`, taints: true });
  else addEffect(c, { cls: "read_local_workspace", target: info.abs, detail: `list ${info.abs} (${via})` });
}

export function classifyAction(action: NormalizedAction, ctx: Context, cfg: FirewallConfig, state: SessionState): Collector {
  const c = newCollector(ctx, cfg, state);
  const input = action.input;
  const tool = action.tool;
  switch (tool) {
    case "Read":
    case "NotebookRead": {
      const p = str(input, "file_path", "notebook_path", "path");
      if (p !== undefined) { checkPathText(c, p); readPath(c, p, { via: tool }); }
      return c;
    }
    case "Write": {
      const p = str(input, "file_path", "path");
      if (p !== undefined) {
        checkPathText(c, p);
        writePath(c, p, { via: "Write", proposal: str(input, "content") ?? "", contentChecked: true });
        checkSettingsResult(c, p, () => str(input, "content") ?? "");
        checkGatewayConfig(c, p, () => str(input, "content") ?? "");
        checkEditorAutoApprove(c, p, () => str(input, "content") ?? "");
        checkAutorun(c, p, () => str(input, "content") ?? "", true);
      }
      return c;
    }
    case "Edit":
    case "MultiEdit": {
      const p = str(input, "file_path", "path");
      const edits = Array.isArray(input.edits) ? (input.edits as Record<string, unknown>[]) : [input];
      const proposal = edits.map((e) => `--- replace\n${String(e.old_string ?? "")}\n+++ with\n${String(e.new_string ?? "")}`).join("\n");
      if (p !== undefined) {
        checkPathText(c, p);
        writePath(c, p, { via: tool, proposal, contentChecked: true });
        const list = edits.map((e) => ({ old: String(e.old_string ?? ""), new: String(e.new_string ?? ""), all: e.replace_all === true }));
        const news = list.map((e) => e.new).join("\n");
        // An adapter whose edit tool matches loosely (Codex apply_patch, Gemini CLI replace, `patch`) marks
        // the edit; each plausible result is judged and the most severe wins. No plausible match: unknown.
        const loose = input.match === "loose" ? looseCandidates(c, p, list) : null;
        const results: ((before: string | null) => string)[] = loose === null || loose === "unknown" ? [(before) => (before === null ? news : applyEdits(before, list))] : loose.map((r) => () => r);
        if (loose === "unknown") results.splice(0, 1, (before) => `${before ?? ""}\n${news}`);
        // Without the current content, an edit's result is unknown: judge what it adds.
        for (const result of results) {
          checkEditorAutoApprove(c, p, result);
          checkSettingsResult(c, p, (before) => (before === null && loose === null ? (/\.toml$/i.test(p) ? news : list[0]?.old === "" ? applyEdits("", list) : list.some((e) => /disableAllHooks|allowManagedHooksOnly|hooksConfig|LAUNCHSAFE_FIREWALL_/.test(e.new)) ? "{\"disableAllHooks\": true}" : "{}") : result(before)), loose === "unknown");
          checkAutorun(c, p, result, false);
          checkGatewayConfig(c, p, (before) => (before === null ? null : result(before)));
        }
      }
      return c;
    }
    case "NotebookEdit": {
      const p = str(input, "notebook_path", "file_path");
      if (p !== undefined) { checkPathText(c, p); writePath(c, p, { via: "NotebookEdit", proposal: str(input, "new_source") ?? "" }); }
      return c;
    }
    case "Glob":
    case "LS": {
      listing(c, str(input, "path") ?? ctx.cwd, tool);
      // M5: an absolute pattern lists where it points, whatever directory the call names.
      const base = tool === "Glob" ? globBase(str(input, "pattern") ?? "") : null;
      if (base !== null) listing(c, base, tool);
      return c;
    }
    case "ListMcpResourcesTool": {
      // M6: the listing carries names and descriptions the servers wrote: outside content from an untrusted server
      // (and from every server, when the call names none).
      const server = str(input, "server");
      const pol = server !== undefined ? serverPolicy(server, cfg, ctx.mcpSource, fsRootsOf(ctx)) : null;
      if (pol === null || pol.results === "untrusted") addEffect(c, { cls: "read_external", target: server ?? "every MCP server", detail: `list the MCP resources of ${server ?? "every MCP server"}`, taints: true });
      else addEffect(c, { cls: "read_local_workspace", target: server ?? "", detail: `list the MCP resources of ${server ?? ""}` });
      return c;
    }
    case "Grep": {
      const p = str(input, "path") ?? ctx.cwd;
      checkPathText(c, p);
      readPath(c, p, { via: "Grep", recursive: true });
      return c;
    }
    case "Bash":
    case "Monitor":
    case "PowerShell": {
      const cmd = str(input, "command", "cmd");
      if (cmd === undefined) {
        if (tool === "Monitor") return c;
        addFinding(c, "parse_failure", `${tool} call without a command`);
        return c;
      }
      if (tool === "PowerShell") {
        addFinding(c, "parse_failure", "PowerShell commands are not analyzed by this version");
        addEffect(c, { cls: "execute_opaque", target: "PowerShell", detail: "run a PowerShell command the firewall cannot analyze" });
        return c;
      }
      analyzeShell(cmd, c);
      return c;
    }
    case "WebFetch": {
      const url = str(input, "url") ?? "";
      checkPathText(c, url);
      if (!egress(c, url, "fetch", { via: "WebFetch", scheme: "https" })) {
        addFinding(c, "parse_failure", `WebFetch with an address that cannot be read: ${url.slice(0, 200)}`);
        addEffect(c, { cls: "egress_fetch", target: url, detail: "fetch an unreadable address", payload: url });
      }
      addEffect(c, { cls: "read_external", target: url, detail: `read the web page ${url.slice(0, 200)}`, taints: true });
      return c;
    }
    case "HttpRequest": {
      // One HTTP request an outer sandbox's supervisor saw leave (docs/sandboxes.md: the OpenShell middleware).
      // A request that can carry data (a body, or a method other than GET, HEAD or OPTIONS) is a send, with
      // the URL and the body as its payload; the response it gets back is outside content, as WebFetch's is.
      const url = str(input, "url") ?? "";
      const method = (str(input, "method") ?? "GET").toUpperCase();
      const body = str(input, "body") ?? "";
      const send = body !== "" || !["GET", "HEAD", "OPTIONS"].includes(method);
      checkPathText(c, url);
      const via = `HttpRequest ${method.slice(0, 16)}`;
      if (!egress(c, url, send ? "send" : "fetch", { via, scheme: "https", ...(send ? { payload: body === "" ? url : `${url}\n${body}` } : {}) })) {
        addFinding(c, "parse_failure", `HttpRequest with an address that cannot be read: ${url.slice(0, 200)}`);
        addEffect(c, { cls: send ? "egress_send" : "egress_fetch", target: url, detail: "contact an unreadable address", payload: body === "" ? url : `${url}\n${body}` });
      }
      addEffect(c, { cls: "read_external", target: url, detail: `read the response from ${url.slice(0, 200)}`, taints: true });
      return c;
    }
    case "WebSearch": {
      const q = str(input, "query") ?? "";
      addEffect(c, { cls: "egress_fetch", target: "web search", destination: "web-search", detail: "search the web", payload: q, tags: ["search"] });
      addEffect(c, { cls: "read_external", target: "web search results", detail: "read web search results", taints: true });
      return c;
    }
    case NETWORK_REFUSED_TOOL: {
      const code = (str(input, "code") ?? "refused").slice(0, 80);
      const target = (str(input, "url") ?? "an address").slice(0, 300);
      addFinding(c, "network_refused", `${(str(input, "method") ?? "a").slice(0, 16)} request to ${target} refused by the sandbox middleware (${code}): ${(str(input, "reason") ?? "no reason given").slice(0, 300)}`);
      return c;
    }
    case UNPARSEABLE_TOOL: {
      const what = str(input, "tool") ?? "a tool";
      addFinding(c, "parse_failure", `${what} call the firewall cannot read: ${(str(input, "reason") ?? "unknown format").slice(0, 200)}`);
      addEffect(c, { cls: "unknown", target: what, detail: `use ${what} with input the firewall cannot read` });
      return c;
    }
    case "ReadMcpResourceTool":
    case "ReadMcpResource": {
      const server = str(input, "server") ?? "unknown";
      const pol = serverPolicy(server, cfg, ctx.mcpSource, fsRootsOf(ctx));
      const uri = str(input, "uri") ?? "";
      if (pol.results === "untrusted") addEffect(c, { cls: "read_external", target: `${server}:${uri}`, detail: `read the MCP resource ${uri} from ${server}`, taints: true, private: pol.privateData });
      else addEffect(c, { cls: "read_local_workspace", target: `${server}:${uri}`, detail: `read the MCP resource ${uri} from ${server}`, private: pol.privateData });
      if (/^file:/.test(uri)) readPath(c, uri, { via: `MCP resource from ${server}` });
      return c;
    }
    default:
      break;
  }
  if (SAFE_TOOLS.has(tool)) return c;
  // F-d: the host application's own tools (sending a file to the person, a chapter marker, a proposed
  // session, publishing a page), recognised from captured events; MCP-shaped ones only from the host.
  const host = hostTool(tool, ctx.mcpSource, cfg, input);
  if (host !== null) {
    classifyHostTool(c, host, input);
    return c;
  }
  const mcp = resolveMcpTool(tool, cfg.mcpServers, ctx.mcpTool);
  if (mcp !== null) {
    const before = c.effects.length;
    if (mcp.ambiguous) addFinding(c, "parse_failure", `the MCP tool name ${tool.slice(0, 200)} can be read as more than one server (a server name ending in "_" runs into the "__" separator)`);
    classifyMcp(c, mcp.server, mcp.tool, input);
    // Which MCP server and tool data leaves through, for per-secret bindings (separate tags so
    // nothing that reads mcp-server: changes).
    for (const e of c.effects.slice(before)) if (e.cls === "egress_send" || e.cls === "egress_fetch") e.tags = [...(e.tags ?? []), `mcp-call:${mcp.server}`, `mcp-tool:${mcp.tool}`];
    return c;
  }
  // A tool this version does not know: judge its arguments, and say it is unknown. R2: whatever it
  // returns is treated as outside content (the README: anything it cannot fully understand is treated as
  // the most dangerous thing it could be), and a person is asked before it runs (decide: FW-UNKNOWN-TOOL).
  addEffect(c, { cls: "unknown", target: tool, detail: `use the tool ${tool}, which the firewall does not know`, taints: true });
  scanArguments(c, input, "send", tool);
  return c;
}

/**
 * A Write/Edit/MultiEdit of a Claude Code settings file is judged by the content the file would have
 * afterwards: removing or altering the firewall's hooks, switching hooks off, or setting the
 * firewall's own variables is tampering, in any session.
 */
/** The results a loosely matched edit may leave (null: not a loose edit or the file is unreadable; "unknown": no plausible match). */
function looseCandidates(c: Collector, rawPath: string, list: readonly { old: string; new: string; all: boolean }[]): string[] | "unknown" | null {
  const r = resolvePath(rawPath, c.ctx);
  if (r === null) return null;
  let before: string | null = null;
  try {
    before = c.ctx.readFile?.(r.abs) ?? null;
  } catch {
    before = null;
  }
  if (before === null) return null;
  return looseEditResults(before, list) ?? "unknown";
}

function checkSettingsResult(c: Collector, rawPath: string, compute: (before: string | null) => string | null, unknown = false): void {
  const r = resolvePath(rawPath, c.ctx);
  if (r === null) return;
  const targets = [r.abs];
  try {
    if (c.ctx.realpath !== undefined) targets.push(normalizeAbs(c.ctx.realpath(r.abs)));
  } catch {
    // Judge the path as written.
  }
  for (const abs of new Set(targets)) {
    // F13: a registered (or agent-located) hooks file is a settings file whatever it is called.
    if (!isHookSettingsIn(c.ctx, abs)) continue;
    // I1: a registered settings file is the same file whatever the case of its name (PROTECTION_FOLDS_CASE, canonical.ts).
    const lc = (x: string): string => x.toLowerCase();
    const registered = (c.ctx.registeredSettings ?? []).some((p) => lc(p) === lc(abs));
    let before: string | null = null;
    let known = c.ctx.readFile !== undefined;
    try {
      before = c.ctx.readFile?.(abs) ?? null;
    } catch {
      known = false;
    }
    if (unknown) {
      // The agent's edit tool matches loosely and the old text is not in the file: the result is unknown.
      addEffect(c, { cls: "firewall_tamper", target: abs, detail: `change ${agentOfSettings(abs)} settings at ${abs} with an edit whose text is not in the file exactly; the agent's edit tool matches loosely, so the result cannot be checked (this could remove the firewall's hooks or switch hooks off)` });
      continue;
    }
    const after = known || !registered ? compute(before) : null;
    for (const problem of settingsViolations(before, after, registered, abs, sandboxGuard(c, abs, lc))) {
      addFinding(c, "hook_disable", `changing ${abs}: ${problem}`);
      addEffect(c, { cls: "firewall_tamper", target: abs, detail: `change ${agentOfSettings(abs)} settings so that ${problem}` });
    }
    for (const problem of layeredSandboxViolations(c, abs, before, after)) {
      addFinding(c, "hook_disable", `changing ${abs}: ${problem}`);
      addEffect(c, { cls: "firewall_tamper", target: abs, detail: `change Claude Code settings so that ${problem}` });
    }
  }
}

/**
 * An MCP client configuration file the gateway wrapped (gateway/install.json) is judged by
 * its result: a wrapped entry removed or changed is tampering; an unwrapped server added is a settings
 * change (src/engine/gateway-config.ts).
 */
function checkGatewayConfig(c: Collector, rawPath: string, compute: (before: string | null) => string | null): void {
  if ((c.ctx.gatewayConfigs ?? []).length === 0) return;
  const r = resolvePath(rawPath, c.ctx);
  if (r === null) return;
  const targets = [r.abs];
  try {
    if (c.ctx.realpath !== undefined) targets.push(normalizeAbs(c.ctx.realpath(r.abs)));
  } catch {
    // Judge the path as written.
  }
  for (const abs of new Set(targets)) {
    const g = gatewayConfigFor(c.ctx, abs);
    if (g === null) continue;
    let before: string | null = null;
    try {
      before = c.ctx.readFile?.(abs) ?? null;
    } catch {
      before = null;
    }
    const ch = gatewayConfigChanges(before, compute(before), g.wrapped, abs);
    for (const problem of ch.tamper) addEffect(c, { cls: "firewall_tamper", target: abs, detail: `change the MCP client configuration ${abs} so that ${problem}` });
    if (ch.added.length > 0) addEffect(c, { cls: "write_protected", target: abs, detail: `add MCP server ${ch.added.map((n) => `"${n}"`).join(", ")} to ${abs} without the firewall's gateway (its calls would not be checked)`, tags: ["settings"] });
    return;
  }
}

function parseJson(text: string | null): Record<string, unknown> | null {
  if (text === null) return {};
  try {
    const v: unknown = JSON.parse(text);
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/**
 * Claude Code takes the sandbox's scalars from the highest settings layer that sets them (local >
 * project > user) and merges its lists across layers, so another layer can weaken the recorded profile
 * without touching its file. The change is judged on the effective settings, before and after.
 */
function layeredSandboxViolations(c: Collector, abs: string, beforeText: string | null, afterText: string | null): string[] {
  if (!isClaudeSettingsFile(abs) || /managed-settings/i.test(abs)) return [];
  const pol = sandboxPolicy(c.cfg);
  if (!pol.protectInstalledProfile) return [];
  const out: string[] = [];
  const home = c.ctx.home;
  for (const rec of c.ctx.sandboxProfiles ?? []) {
    if (!layersInteract(rec.path, abs, home)) continue;
    let recText: string | null = null;
    try {
      recText = c.ctx.readFile?.(rec.path) ?? null;
    } catch {
      recText = null;
    }
    const recDoc = parseJson(recText) ?? { sandbox: rec.installed };
    const b = parseJson(beforeText);
    const a = afterText === null ? null : parseJson(afterText);
    if (a === null) {
      out.push("the result cannot be read as settings, and this settings layer can override the sandbox profile the firewall installed");
      continue;
    }
    const strict = settingsRank(rec.path, home) === 1 && (rec.installed.network as Record<string, unknown> | undefined)?.strictAllowlist === true;
    const higher = settingsRank(abs, home) > settingsRank(rec.path, home);
    const layered = (doc: Record<string, unknown> | null): Record<string, unknown> => {
      const mine = { doc, repo: settingsRank(abs, home) >= 2 };
      const theirs = { doc: recDoc, repo: settingsRank(rec.path, home) >= 2 };
      return mergeSettingsLayers(higher ? [mine, theirs] : [theirs, mine], strict);
    };
    const guard = { installed: rec.installed, policyDomains: profileFromPolicy(c.cfg).profile.network.allowedDomains, safeExcluded: pol.safeExcludedCommands };
    for (const p of sandboxViolations(layered(b), layered(a), guard)) out.push(`${p} (this layer overrides the sandbox profile the firewall installed in ${rec.path})`);
  }
  return [...new Set(out)];
}

/** The sandbox profile `doctor --fix` installed in this settings file, when it is protected. */
function sandboxGuard(c: Collector, abs: string, lc: (x: string) => string): SandboxGuard | undefined {
  const rec = (c.ctx.sandboxProfiles ?? []).find((p) => lc(p.path) === lc(abs));
  const pol = sandboxPolicy(c.cfg);
  if (rec === undefined || !pol.protectInstalledProfile) return undefined;
  return { installed: rec.installed, policyDomains: profileFromPolicy(c.cfg).profile.network.allowedDomains, safeExcluded: pol.safeExcludedCommands };
}

/**
 * G4: a change to an editor's settings that switches on an agent's own auto-approval is a change to
 * the agent's settings (every later tool call would run unasked): the same rules as .mcp.json and
 * hooks apply (approve when trusted, held as a proposal when not).
 */
function checkEditorAutoApprove(c: Collector, rawPath: string, result: (before: string | null) => string): void {
  const r = resolvePath(rawPath, c.ctx);
  if (r === null || !isEditorSettingsFile(r.abs)) return;
  let before: string | null = null;
  try {
    before = c.ctx.readFile?.(r.abs) ?? null;
  } catch {
    before = null;
  }
  const on = newAutoApproveSwitches(before, result(before));
  if (on.length === 0) return;
  addEffect(c, { cls: "write_protected", target: r.abs, detail: `switch on agent auto-approval in the editor settings ${r.abs} (${on.slice(0, 3).join(", ")})`, tags: ["settings"], proposal: result(before) });
}

function checkPathText(c: Collector, p: string): void {
  const hidden = invisibleCharacters(p);
  if (hidden.length > 0) addFinding(c, "invisible_unicode", `the path or address contains hidden characters (${hidden.join(", ")})`);
}

/** How many strings of one call's arguments the engine reads (FZ17: past this, the call is FW-UNCLASSIFIABLE). */
export const MAX_ARGUMENT_STRINGS = 20000;

/**
 * Strings in a tool's arguments, with their keys, depth-first and bounded, and whether the walk reached every one.
 * FZ17: the walk used to stop silently at depth 12 and at 2,000 strings, so a credential path or a credential put
 * past either bound was never seen (an MCP read of ~/.ssh/id_rsa allowed; a key in a "read" tool's arguments sent
 * to a third party with no data rule applied). It now follows the engine's own depth bound (MAX_INPUT_DEPTH; deeper
 * arguments are refused before this runs), and a caller that judges by the strings reports an incomplete walk.
 */
export interface ArgumentWalk {
  /** Each string with its nearest key and the top-level key it lies under ("" for the input itself). */
  strings: { key: string; value: string; top: string }[];
  complete: boolean;
}

export function argumentWalk(input: unknown, limit = MAX_ARGUMENT_STRINGS): ArgumentWalk {
  const out: { key: string; value: string; top: string }[] = [];
  let complete = true;
  const walk = (v: unknown, key: string, top: string, depth: number): void => {
    if (out.length >= limit || depth > MAX_INPUT_DEPTH) {
      if (typeof v === "string" || (typeof v === "object" && v !== null)) complete = false;
      return;
    }
    if (typeof v === "string") out.push({ key, value: v, top });
    else if (Array.isArray(v)) for (const x of v) walk(x, key, top, depth + 1);
    else if (typeof v === "object" && v !== null) for (const [k, x] of Object.entries(v)) walk(x, k, depth === 0 ? k : top, depth + 1);
  };
  walk(input, "", "", 0);
  return { strings: out, complete };
}

/** Strings in a tool's arguments, with their keys, depth-first and bounded (argumentWalk without the flag). */
export function argumentStrings(input: unknown, limit = MAX_ARGUMENT_STRINGS): { key: string; value: string }[] {
  return argumentWalk(input, limit).strings;
}

/** FZ17: arguments the walk could not read to the end are judged as the riskiest thing they could be. */
function incompleteArguments(c: Collector, via: string): void {
  addFinding(c, "too_large", `the arguments of ${via} hold more than ${MAX_ARGUMENT_STRINGS} strings or deeper nesting than the firewall reads`);
}

const PATH_KEYS = /^(?:path|paths|file|files|file_?path|filename|dir|directory|cwd|root|target|source|destination|dest|output|out|notebook_path|local_path|uri)$/i;

/**
 * Judges the strings of a call's arguments: URLs as destinations, path-like values as reads (and writes for a
 * sending tool). Review of FZ17: the caller passes the one walk and the one payload it made for the call, so a
 * large input is walked and serialised once per decision; `skipTop` leaves out a top-level key's strings.
 */
function scanArguments(c: Collector, input: Record<string, unknown>, kind: "read" | "send", via: string, args: ArgumentWalk = argumentWalk(input), payload: string = safeJson(input), skipTop?: string): void {
  if (!args.complete) incompleteArguments(c, via);
  for (const { key, value, top } of args.strings) {
    if (skipTop !== undefined && top === skipTop) continue;
    const v = value.trim();
    if (/^(?:https?|wss?|ftp):\/\/\S+$/i.test(v)) {
      checkPathText(c, v);
      egress(c, v, kind === "read" ? "fetch" : "send", { payload, via });
      continue;
    }
    if (PATH_KEYS.test(key) || /^(?:~\/|\/(?:Users|home|etc|root|var|tmp|private|Library|opt)\/|file:\/\/)/.test(v)) {
      if (v.length > 4096 || /\n/.test(v)) continue;
      checkPathText(c, v);
      if (kind === "read") readPath(c, v, { via });
      else {
        // A sending or writing tool given a path may read it (to upload) or write it.
        readPath(c, v, { via });
        writePath(c, v, { via });
      }
    }
  }
}

function safeJson(v: unknown): string {
  try {
    return JSON.stringify(v) ?? "";
  } catch {
    return String(v);
  }
}

function fsRootsOf(ctx: Context): FsRoots | undefined {
  return ctx.mcpRoots === undefined ? undefined : { roots: ctx.mcpRoots, workspace: ctx.workspaceRoots, caseInsensitive: ctx.caseInsensitive };
}

/** G6/R21: a filesystem server whose launch roots all lie in the workspace, and that the policy does not class otherwise. */
function confinedFilesystem(c: Collector, server: string): boolean {
  const fs = fsRootsOf(c.ctx);
  if (!isFilesystemServerName(server) || !rootsInWorkspace(fs)) return false;
  const pol = serverPolicy(server, c.cfg, c.ctx.mcpSource, fs);
  return pol.results === "trusted";
}

function classifyMcp(c: Collector, server: string, tool: string, input: Record<string, unknown>): void {
  const pol = serverPolicy(server, c.cfg, c.ctx.mcpSource, fsRootsOf(c.ctx), tool);
  const kind = toolKind(tool, pol);
  const dest = mcpDestination(server, input);
  const payload = safeJson(input);
  const label = `${server}.${tool}`;
  if (kind === "blocked") {
    addFinding(c, "blocked_tool", `${label} is blocked by the policy`);
    return;
  }
  // A tool whose name says it deletes a whole project, repository, database or namespace (or drops one).
  const named = judgeMcpTool(tool);
  if (named !== null) addFinding(c, "catastrophic", `${label}: ${named}`);
  // Whatever the verb, the call's arguments travel to the server. Record them as an egress payload
  // so the always-on data rules see them, and so an untrusted session holding private data cannot
  // hand that data to a third-party service through a "read" tool (search, docs, query).
  // FZ17: arguments the walk could not read to the end travel too.
  const walked = argumentWalk(input);
  if (!walked.complete || walked.strings.some((x) => x.value.trim() !== "")) {
    addEffect(c, { cls: "egress_fetch", target: dest, destination: dest, detail: `send the arguments of ${label} to the ${server} server`, payload, tags: ["mcp-args", `mcp-server:${server}`, ...(pol.privateData ? [] : ["third-party"])] });
  }
  // SQL arguments are judged by what the SQL does, not by the tool's name.
  const sqlText = walked.strings.filter((a) => /^(?:query|queries|sql|sql_?statements?|statements?|command|script)$/i.test(a.key)).map((a) => a.value).join(";\n");
  if (sqlText.trim() !== "" && /sql|postgres|supabase|mysql|database|db|neon|query|sqlite|planetscale|turso|d1|bigquery|snowflake|clickhouse/i.test(`${server} ${tool}`)) {
    const s = classifySql(sqlText);
    if (s.destroys) addEffect(c, { cls: "destructive", target: dest, detail: `run destructive SQL through ${label}` });
    // DROP DATABASE/SCHEMA is denied (a scratch name from the person's allowlist is asked); TRUNCATE through
    // an MCP tool stays the ordinary destructive ask above.
    const whole = judgeSql(sqlText, false, c.ctx.scratchTargets !== undefined ? { scratch: c.ctx.scratchTargets } : {});
    if (whole?.level === "deny") addFinding(c, "catastrophic", `${label}: ${whole.reason}`);
    else if (whole !== null) addEffect(c, { cls: "destructive", target: dest, detail: `${label}: ${whole.reason}` });
    if (s.external || s.opaque) {
      addEffect(c, { cls: "execute_opaque", target: dest, detail: `run SQL through ${label} that reaches outside the database or is built at run time` });
      externalSend(c, dest, `SQL through ${label} that can send data out of the database`, payload);
    }
    if (s.writes && !s.destroys) externalSend(c, dest, `change data through ${label}`, payload);
    addEffect(c, { cls: "read_external", target: dest, detail: `read data from ${label}`, taints: pol.results === "untrusted", private: pol.privateData });
    scanArguments(c, input, s.writes || s.destroys ? "send" : "read", label, walked, payload);
    return;
  }
  if (/memory|mem0|knowledge|remember|zep|letta/i.test(server) && kind !== "read") {
    addEffect(c, { cls: "write_protected", target: `${server}`, detail: `change the agent's long-term memory through ${label}`, tags: ["memory"], proposal: payload });
    return;
  }
  if (kind === "read") {
    if (pol.results === "untrusted") addEffect(c, { cls: "read_external", target: dest, detail: `read from ${label}${pol.privateData ? "" : " (public content)"}`, taints: true, private: pol.privateData });
    else addEffect(c, { cls: "read_local_workspace", target: dest, detail: `read from ${label}`, private: pol.privateData });
    scanArguments(c, input, "read", label, walked, payload);
    return;
  }
  // R21: a filesystem server confined to the workspace (G6) writes local files, it does not send data
  // anywhere: its writes are judged like the Write tool's (protected paths, outside-workspace writes,
  // tainted-write records), not as egress.
  if ((kind === "send" || kind === "destroy") && confinedFilesystem(c, server)) {
    if (!walked.complete) incompleteArguments(c, label);
    const content = typeof input.content === "string" ? input.content : Array.isArray(input.edits) ? safeJson(input.edits) : undefined;
    // The key each path value first appears under (one pass, not one search per path).
    const keyOf = new Map<string, string>();
    for (const a of walked.strings) if (!keyOf.has(a.value.trim())) keyOf.set(a.value.trim(), a.key);
    const paths = walked.strings.filter((a) => PATH_KEYS.test(a.key) || /^(?:source|destination)$/i.test(a.key)).map((a) => a.value.trim()).filter((v) => v !== "" && v.length <= 4096 && !/\n/.test(v));
    for (const v of paths) {
      checkPathText(c, v);
      writePath(c, v, { via: label, ...(content !== undefined ? { proposal: content } : {}), ...(kind === "destroy" || (/move|rename/i.test(tool) && /^(?:source|from)$/i.test(keyOf.get(v) ?? "")) ? { remove: true } : {}) });
    }
    if (paths.length === 0) externalSend(c, dest, `${label} on ${dest}`, payload);
    return;
  }
  if (kind === "destroy") {
    addEffect(c, { cls: "destructive", target: dest, detail: `${label}: delete or revoke in ${dest}` });
    scanArguments(c, input, "send", label, walked, payload);
    return;
  }
  externalSend(c, dest, `${label} on ${dest}`, payload, isMessageTool(server, tool) ? { tags: ["message"] } : {});
  // Browser and fetch tools that open a URL contact that host.
  for (const { value } of walked.strings) {
    const v = value.trim();
    if (/^(?:https?|wss?):\/\//i.test(v) && parseUrlLike(v) !== null) egress(c, v, "send", { payload, via: label });
  }
  // What a sending tool returns (a page, a thread, a created issue) is outside content too.
  if (pol.results === "untrusted") addEffect(c, { cls: "read_external", target: dest, detail: `read the result of ${label}`, taints: true, private: pol.privateData });
  // The url argument was judged above as the page the tool opens; the rest of the arguments as data.
  scanArguments(c, input, "send", label, walked, payload, "url");
}

/** The path values a host tool's path arguments hold (a string or a list of strings). */
function hostPaths(host: HostTool, input: Record<string, unknown>): string[] {
  const out: string[] = [];
  if (host.pathArgs.includes("*")) {
    for (const { key, value } of argumentStrings(input)) {
      const v = value.trim();
      if ((PATH_KEYS.test(key) || /^(?:~\/|\/|file:\/\/)/.test(v)) && v.length <= 4096 && !/\n/.test(v) && !/^(?:https?|wss?|ftp):\/\//i.test(v)) out.push(v);
    }
    return out;
  }
  const add = (x: unknown): void => {
    if (typeof x === "string" && x.trim() !== "" && x.length <= 4096) out.push(x.trim());
  };
  for (const k of host.pathArgs) {
    const v = own(input, k);
    for (const x of Array.isArray(v) ? v : [v]) {
      // A map of published path to local source ({"page.html": "~/.ssh/id_rsa"}) or a list of {path, from}
      // objects (Artifact's files): the sources are local paths too.
      if (typeof x === "object" && x !== null) {
        const o = x as Record<string, unknown>;
        if (Array.isArray(v)) {
          add(o.path);
          add(o.from);
        } else {
          for (const val of Object.values(o)) {
            if (typeof val === "object" && val !== null) add((val as Record<string, unknown>).from);
            else add(val);
          }
        }
      } else add(x);
    }
  }
  return out;
}

/**
 * Reading a file to show it to the person: the credential rules still apply (an agent reaching into a
 * credential store is the event that matters, whoever sees the result), and a secret file still makes
 * the session sensitive; everything else is a local read with no taint. No write probe: these tools
 * do not write the paths they are given.
 */
function hostReads(c: Collector, host: HostTool, paths: readonly string[], verb: string): void {
  for (const p of paths) {
    checkPathText(c, p);
    const probe: Collector = { ...c, effects: [], findings: [] };
    readPath(probe, p, { via: host.name });
    for (const f of probe.findings) if (f.id === "credential_store_read" || f.id === "recursive_home_sweep") addFinding(c, f.id, f.detail);
    for (const e of probe.effects) {
      if (e.cls === "read_secret") addEffect(c, e);
      else addEffect(c, { cls: "read_local_workspace", target: e.target, detail: `${verb} ${e.target} (${host.name})`, tags: ["to-user"] });
    }
  }
}

function classifyHostTool(c: Collector, host: HostTool, input: Record<string, unknown>): void {
  switch (host.kind) {
    case "ui_state":
      // No effect: the app's UI only.
      return;
    case "spawn_session": {
      // A proposed session the person has to start themselves. In a trusted session the chip is the
      // approval. R4: from an untrusted session the prompt may be someone else's words, and the chip shows
      // only the title and summary the agent wrote, so a person reads the full prompt first (FW-AGENT-SPAWN).
      // The hook records the prompt's hash either way, so the new session is not treated as the
      // person's own choice of destinations (spawned.ts).
      if (!c.state.tainted) return;
      const prompt = typeof input.prompt === "string" ? input.prompt : safeJson(input);
      addEffect(c, { cls: "agent_spawn", target: host.name, detail: `propose a new session (${host.name}) with a prompt written in this session`, tags: ["spawn-session"], proposal: prompt });
      return;
    }
    case "to_user":
      hostReads(c, host, hostPaths(host, input), "show the person");
      return;
    case "read_outside": {
      // R2: the result is text other people wrote. The request itself (a URL, a collection name, a query)
      // goes to the host's service, so the data rules see it as a fetch's payload.
      const dest = host.destination ?? "host";
      const what = typeof input.url === "string" ? input.url.slice(0, 200) : dest;
      addEffect(c, { cls: "egress_fetch", target: `https://${dest}/`, host: dest, destination: dest, detail: `ask ${dest} for ${host.name} content`, payload: safeJson(input), tags: ["mcp-args", "host-read"] });
      addEffect(c, { cls: "read_external", target: what, detail: `read content other people wrote through ${host.name} (${what})`, taints: true });
      // ArtifactData can save what it read as files under out_dir: a write like any other.
      if (typeof input.out_dir === "string" && input.out_dir.trim() !== "" && input.out_dir.length <= 4096) {
        checkPathText(c, input.out_dir);
        writePath(c, input.out_dir.trim(), { via: host.name });
      }
      return;
    }
    case "publish": {
      const paths = hostPaths(host, input);
      hostReads(c, host, paths, "publish");
      // The published text leaves the machine: the data rules see the arguments and the files' content.
      const parts = [safeJson(input)];
      for (const p of paths) {
        const r = resolvePath(p, c.ctx);
        if (r === null) continue;
        try {
          const text = c.ctx.readFile?.(r.abs) ?? null;
          if (text !== null) parts.push(text.slice(0, 2 * 1024 * 1024));
        } catch {
          // Unreadable: the arguments alone are judged.
        }
      }
      const dest = host.destination ?? "host";
      addEffect(c, { cls: "egress_send", target: `https://${dest}/`, host: dest, destination: dest, detail: `publish ${paths.length > 0 ? paths.join(", ") : "content"} as a page on ${dest} (${host.name})`, payload: parts.join("\n") });
      return;
    }
  }
}
