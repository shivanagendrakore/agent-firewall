/**
 * The hook pipeline, shared by every agent. It reads one event as
 * JSON on stdin and answers on stdout. The adapter for the agent (`hook
 * --agent claude|codex|gemini|cursor`, src/adapters/) parses the event and renders the
 * answer; everything in between is the same for every agent: pre-tool events
 * are normalized and decided (one native call can be several actions, and the
 * most severe verdict wins), post-tool events record what the tool brought in,
 * prompt events record the destinations the person named and the task's scope
 * (the task scope), and Claude Code's
 * ConfigChange protects the firewall's own hook registration. Session state,
 * queue, log, policy and identity are shared across agents; session ids are
 * namespaced per agent (`codex:<id>`), Claude Code's stay as they were.
 *
 * Every review fix that lives in the hook lives here or in pipeline.ts, so
 * it holds for every agent: R1 (tripwire events and alerts whatever the
 * verdict, also when an ask becomes a held action), R4 (spawned prompts), R6
 * (agent- and repository-written text escaped in everything rendered), R12
 * (MCP pins compared on every session start), R13 (notifications for every
 * block that stops data leaving), R14 (pin taint applied before deciding), R19
 * (held edits keep replace_all).
 *
 * Failure policy: every path catches its own errors. If deciding fails,
 * read-only tools proceed and everything else is blocked (fail closed). The
 * installed command adds `|| exit 2`, so a crash of node itself also blocks.
 */


import { destinationsFromPrompt } from "../engine/post.js";
import type { SessionState, StateEvent } from "../types.js";
import { loadPolicy } from "../runtime/config.js";
import { buildContext } from "../runtime/context.js";
import { recordStart, resumePins, SESSION_START_BUDGET_MS } from "./agent-checks.js";
import { layout, type Layout } from "../runtime/layout.js";
import { appendEvents, loadState, pruneQueue, pruneSessions, sessionFile } from "../runtime/store.js";
import { existsSync } from "node:fs";
import { checkHookRegistration } from "../runtime/install.js";
import { maintainLedger } from "../runtime/ledger.js";
import { matchSpawned } from "../runtime/spawned.js";
import { safeText } from "../engine/terminal.js";
import { recordPromptScope } from "../runtime/scope.js";
import { adapterFor } from "../adapters/index.js";
import { isCursorEvent } from "../adapters/cursor.js";
import { pruneQuarantine } from "../runtime/quarantine.js";
import { appendBounded as appendLog } from "../runtime/logbound.js";
import { seatbeltRefusal } from "../runtime/gemini-seatbelt.js";
import { AdapterParseError, type AdapterEvent, type AgentAdapter, type HookIO, type HookOutcome } from "../adapters/types.js";
import { basics, envOverrides, isUnattended, notifyKind, notifyStart, projectDirOf, runPostTool, runPreTool, stateSessionId, trustedKeys, type HookEnv, type Json } from "./pipeline.js";

export type { HookIO };
// I1: the CLI's hook handler takes the home from here, inside the hook bundle.
export { trustedHome } from "../runtime/home-trust.js";
// The pipeline's public names, kept importable from here as before the v0.3 split.
export { decideNative, message, pinSource, stateSessionId, stopsDataLeaving, trustedApproverKey, trustedKeys, type HookEnv } from "./pipeline.js";

/**
 * R6: every text the firewall hands an agent to show (the permission reason, system messages, added
 * context, diagnostics) carries paths, URLs, commands and findings the agent or a repository wrote:
 * control, bidi and zero-width characters are escaped for every agent. A redacted tool output is the
 * tool's own text with secrets masked and is passed through as it was.
 */
function say(a: AgentAdapter, ev: AdapterEvent, out: HookOutcome): HookIO {
  const o: HookOutcome = { ...out, message: safeText(out.message) };
  if (out.systemMessage !== undefined) o.systemMessage = safeText(out.systemMessage);
  if (out.additionalContext !== undefined) o.additionalContext = safeText(out.additionalContext);
  if (out.stderr !== undefined) o.stderr = safeText(out.stderr);
  return a.render(ev, o);
}

/** The decision for a pre-tool event (src/hook/pipeline.ts), in the agent's format. */
function preToolUse(ev: AdapterEvent, a: AgentAdapter, h: HookEnv, l: Layout): HookIO {
  return say(a, ev, runPreTool(ev, a, h, l).outcome);
}

/** What a post-tool event recorded (src/hook/pipeline.ts), in the agent's format. */
function postToolUse(ev: AdapterEvent, a: AgentAdapter, h: HookEnv, l: Layout): HookIO {
  return say(a, ev, runPostTool(ev, a, h, l).outcome);
}

function userPromptSubmit(ev: AdapterEvent, a: AgentAdapter, h: HookEnv, l: Layout): HookIO {
  try {
    const b = basics(ev);
    const prompt = ev.prompt ?? "";
    // R4: a prompt an agent proposed (spawn_task) names no destination for the person and records no task
    // scope (it is not the person's task), and one proposed by an untrusted session starts this session untrusted.
    const spawned = matchSpawned(l, prompt);
    if (spawned !== null) {
      if (spawned.tainted) appendEvents(l, b.sessionId, [{ type: "taint", source: "this session's prompt was proposed (spawn_task) by a session that had read outside content" }]);
      return say(a, ev, { verdict: "allow", message: "" });
    }
    const dest = destinationsFromPrompt(prompt);
    if (dest.length > 0) appendEvents(l, b.sessionId, [{ type: "user_destinations", destinations: dest }]);
    // The task's scope. A failure here records nothing, so the previous scope (or none: today's rules) stays.
    let warn = "";
    try {
      const policy = loadPolicy(l, [projectDirOf(ev, a, h)]);
      if (policy.config.taskScope.mode !== "off") {
        const { ctx } = buildContext({ l, cfg: policy.config, basics: b, env: h.env, ...envOverrides(h), ...(a.id !== "claude" ? { projectDir: projectDirOf(ev, a, h) } : {}), detectNonInteractive: () => false });
        recordPromptScope(l, b.sessionId, prompt, policy.config, ctx, loadState(l, b.sessionId, trustedKeys(l, h.env, policy.config, h.now)), h.now ?? new Date());
      }
    } catch (e) {
      warn = seatbeltRefusal(e, h.env) ?? `LaunchSafe Firewall could not record the task scope: ${(e as Error).message}`;
    }
    return say(a, ev, { verdict: "allow", message: "", ...(warn !== "" ? { stderr: warn } : {}) });
  } catch (e) {
    return say(a, ev, { verdict: "allow", message: "", stderr: seatbeltRefusal(e, h.env) ?? `LaunchSafe Firewall UserPromptSubmit error: ${(e as Error).message}` });
  }
}

function sessionStart(ev: AdapterEvent, a: AgentAdapter, h: HookEnv, l: Layout): HookIO {
  try {
    if (ev.source === "startup" || ev.source === undefined) {
      pruneSessions(l);
      pruneQueue(l);
      pruneQuarantine(l);
      maintainLedger(l);
    }
    // Check what the agent is armed with, once per session (a compacted or cleared session keeps its result).
    const b = basics(ev);
    const projectDir = projectDirOf(ev, a, h);
    // I9: a resumed or compacted session carries what it read before; with no record of it here (pruned, another
    // machine, a firewall installed mid-session) that is unknown, so it starts untrusted.
    if ((ev.source === "resume" || ev.source === "compact") && !existsSync(sessionFile(l, b.sessionId))) {
      appendEvents(l, b.sessionId, [{ type: "taint", source: `this session was continued (${ev.source}) but the firewall has no record of it, so what it read before is unknown` }]);
    }
    if (loadState(l, b.sessionId, trustedKeys(l, h.env, undefined, h.now)).agentScanned) {
      // R12: the agent-safety scan runs once per session, but the MCP comparison runs on every source
      // (resume, clear, compact): the servers start again from their current configuration.
      const policy = loadPolicy(l, [projectDir]);
      const pins = resumePins(l, policy.config, projectDir, b.sessionId, { env: h.env, home: h.home, now: h.now, agent: a.id });
      const changes = Math.max(pins.alerts.length, pins.events.filter((e) => e.type === "taint").length);
      if (changes > 0) notifyKind(l, h, "mcp_changed", changes, policy.config, isUnattended(l, h, policy.config, b, ev, a));
      if (pins.alerts.length === 0) return say(a, ev, { verdict: "allow", message: "" });
      const msg = `LaunchSafe Firewall: ${pins.alerts.join(" ")}`;
      return say(a, ev, { verdict: "allow", message: "", additionalContext: msg, systemMessage: msg, stderr: msg });
    }
    const policy = loadPolicy(l, [projectDir]);
    const start = recordStart(l, policy.config, projectDir, b.sessionId, { env: h.env, home: h.home, now: h.now, agent: a.id }, SESSION_START_BUDGET_MS, false);
    if (start.scan.untrustedBecause.length > 0 || start.pins.alerts.length > 0 || start.pins.events.length > 0) notifyStart(l, h, start, policy.config, isUnattended(l, h, policy.config, b, ev, a));
    return say(a, ev, { verdict: "allow", message: "", ...(start.context !== null ? { additionalContext: start.context } : {}), ...(start.message !== null ? { systemMessage: start.message } : {}), stderr: start.message ?? "" });
  } catch (e) {
    return say(a, ev, { verdict: "allow", message: "", stderr: seatbeltRefusal(e, h.env) ?? `LaunchSafe Firewall SessionStart error: ${(e as Error).message}` });
  }
}

function configChange(ev: AdapterEvent, a: AgentAdapter, l: Layout, home?: string): HookIO {
  try {
    const problems = checkHookRegistration(l, typeof ev.raw.cwd === "string" ? ev.raw.cwd : process.cwd(), home, (id) => adapterFor(id).settings);
    if (problems.length > 0) {
      return say(a, ev, { verdict: "deny", message: `LaunchSafe Firewall blocked this settings change: ${problems.join("; ")}. Use "launchsafe-firewall uninstall" outside the agent to remove the firewall.` });
    }
    return say(a, ev, { verdict: "allow", message: "" });
  } catch (e) {
    return say(a, ev, { verdict: "deny", message: `LaunchSafe Firewall could not check the settings change and blocked it: ${(e as Error).message}` });
  }
}

/** The state a subagent inherits from its parent (subagent linkage), as events. */
function inherited(s: SessionState, parent: string): StateEvent[] {
  const out: StateEvent[] = [{ type: "linked", parent }];
  if (s.tainted) for (const src of s.taintSources.length > 0 ? s.taintSources : ["the parent session read outside content"]) out.push({ type: "taint", source: `parent session: ${src}`.slice(0, 200) });
  if (s.sensitive) for (const src of s.sensitiveSources.length > 0 ? s.sensitiveSources : ["the parent session holds private data"]) out.push({ type: "sensitive", source: `parent session: ${src}`.slice(0, 200) });
  for (const hash of s.fingerprints) out.push({ type: "fingerprint", hash });
  if (s.userDestinations.size > 0) out.push({ type: "user_destinations", destinations: [...s.userDestinations] });
  for (const path of s.downloaded) out.push({ type: "downloaded", path });
  for (const path of s.taintedWrites) out.push({ type: "tainted_write", path });
  for (const path of s.secretPaths) out.push({ type: "secret_path", path });
  for (const source of s.credentialReads ?? []) out.push({ type: "credential_read", source: source.startsWith("parent session: ") ? source : `parent session: ${source}`.slice(0, 200) });
  if (s.scope !== null) out.push({ type: "scope", scope: s.scope });
  return out;
}

/** What a finished subagent hands back to its parent: its output enters the parent's context. */
function handedBack(s: SessionState): StateEvent[] {
  const out: StateEvent[] = [];
  if (s.tainted) for (const src of s.taintSources.length > 0 ? s.taintSources : ["the subagent read outside content"]) out.push({ type: "taint", source: src.startsWith("parent session: ") ? src : `subagent: ${src}`.slice(0, 200) });
  if (s.sensitive) for (const src of s.sensitiveSources.length > 0 ? s.sensitiveSources : ["the subagent read private data"]) out.push({ type: "sensitive", source: src.startsWith("parent session: ") ? src : `subagent: ${src}`.slice(0, 200) });
  for (const hash of s.fingerprints) out.push({ type: "fingerprint", hash });
  for (const path of s.downloaded) out.push({ type: "downloaded", path });
  for (const path of s.taintedWrites) out.push({ type: "tainted_write", path });
  for (const path of s.secretPaths) out.push({ type: "secret_path", path });
  for (const source of s.credentialReads ?? []) out.push({ type: "credential_read", source: source.startsWith("parent session: ") || source.startsWith("subagent: ") ? source : `subagent: ${source}`.slice(0, 200) });
  return out;
}

/**
 * Subagent linkage: a subagent with its own session id starts with its parent's state, and when
 * it stops its taint, private data and secret fingerprints are added to the parent. Never blocks.
 */
function subagent(ev: AdapterEvent, a: AgentAdapter, h: HookEnv, l: Layout): HookIO {
  try {
    const child = stateSessionId(ev.agent, ev.sessionId);
    const key = trustedKeys(l, h.env, undefined, h.now);
    if (ev.kind === "subagent_start") {
      if (ev.parentSessionId !== undefined && ev.parentSessionId !== ev.sessionId) {
        const parent = stateSessionId(ev.agent, ev.parentSessionId);
        appendEvents(l, child, inherited(loadState(l, parent, key), parent));
      }
      return say(a, ev, { verdict: "allow", message: "" });
    }
    const s = loadState(l, child, key);
    const parents = new Set(s.linkedParents);
    if (ev.parentSessionId !== undefined && ev.parentSessionId !== ev.sessionId) parents.add(stateSessionId(ev.agent, ev.parentSessionId));
    for (const p of parents) appendEvents(l, p, handedBack(s));
    return say(a, ev, { verdict: "allow", message: "" });
  } catch (e) {
    return say(a, ev, { verdict: "allow", message: "", stderr: `LaunchSafe Firewall subagent linkage error: ${(e as Error).message}` });
  }
}

/** Runs one hook invocation. Pure with respect to process: the CLI writes the result out. */
export function runHook(raw: string, h: HookEnv): HookIO {
  const l = h.layout ?? layout();
  const requested = h.agent ?? "claude";
  let a = adapterFor(requested);
  let input: Json;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("hook input is not a JSON object");
    input = parsed as Json;
  } catch (e) {
    // Without the input we cannot tell what the action is: block (every supported agent honors exit 2 for a pre-tool event).
    return { stdout: "", stderr: `LaunchSafe Firewall could not read the hook input and blocked the action: ${(e as Error).message}`, exitCode: 2 };
  }
  // Cursor runs the hooks in Claude Code's settings too (third-party import), with its own payload.
  if (requested === "claude" && isCursorEvent(input)) a = adapterFor("cursor");
  let ev: AdapterEvent;
  try {
    ev = a.parse(input);
    if (a.id !== requested) ev.via = requested;
  } catch (e) {
    const blocking = !(e instanceof AdapterParseError) || e.blocking;
    if (blocking) return { stdout: "", stderr: `LaunchSafe Firewall could not read this ${a.settings.label} hook event and blocked the action: ${(e as Error).message}`, exitCode: 2 };
    return { stdout: "", stderr: `LaunchSafe Firewall ignored a ${a.settings.label} hook event it could not read: ${(e as Error).message}`, exitCode: 0 };
  }
  // I1: the environment that chose the firewall's state and settings cannot be trusted: nothing runs, nothing changes settings.
  if (h.homeTamper !== undefined && (ev.kind === "pre_tool" || ev.kind === "config_change")) {
    try {
      appendLog(l, { type: "decision", session: stateSessionId(ev.agent, ev.sessionId).slice(0, 200), tool: (ev.tool ?? ev.kind).slice(0, 300), verdict: "deny", rules: ["FW-TAMPER"], what: h.homeTamper.slice(0, 300) });
    } catch {
      // The deny stands either way.
    }
    return say(a, ev, { verdict: "deny", message: `LaunchSafe Firewall blocked this: ${h.homeTamper}. Run "launchsafe-firewall install" again in your own terminal, then "launchsafe-firewall doctor". (rule FW-TAMPER)` });
  }
  // An event another of the firewall's hooks decides (see AgentAdapter.shortCircuit).
  const early = a.shortCircuit?.(ev, { ...(h.home !== undefined ? { home: h.home } : {}) }) ?? null;
  if (early !== null) return say(a, ev, early);
  switch (ev.kind) {
    case "pre_tool":
      return preToolUse(ev, a, h, l);
    case "post_tool":
      return postToolUse(ev, a, h, l);
    case "prompt":
      return userPromptSubmit(ev, a, h, l);
    case "session_start":
      return sessionStart(ev, a, h, l);
    case "config_change":
      return configChange(ev, a, l, h.home);
    case "subagent_start":
    case "subagent_stop":
      return subagent(ev, a, h, l);
    default:
      return say(a, ev, { verdict: "allow", message: "" });
  }
}
