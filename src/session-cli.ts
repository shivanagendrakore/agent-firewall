/**
 * The kill switch's commands (docs/usage.md "Stopping an agent").
 *
 * - `session stop <session>` / `agent stop <agentId>`: a person stops a session,
 *   or every session of an agent; every later action of it is denied
 *   (FW-STOPPED) until a person resumes it. A stop only tightens, so it needs
 *   no passphrase and no terminal (a script may stop an agent), but a process
 *   started by an agent is refused, and the engine refuses the command from an
 *   agent's tool call (changesState: FW-TAMPER).
 * - `session resume <session>` / `agent resume <agentId>`: loosening, so a
 *   person at the keyboard and the approval passphrase, which signs the resume.
 * - `session list`: read-only, the stops in force and why.
 *
 * Each stop and resume is a signed entry in the decision log. Terminal and
 * environment come in through SessionCliDeps, so tests run the real handlers
 * with scripted input.
 */

import { existsSync } from "node:fs";
import type { Parsed } from "./cliargs.js";
import { AGENT_IDS } from "./adapters/types.js";
import { isAgentId } from "./api/files.js";
import { signalSentence } from "./engine/budgets.js";
import type { StopState } from "./engine/stop.js";
import { safeLine } from "./engine/terminal.js";
import type { Layout } from "./runtime/layout.js";
import { appendLog } from "./runtime/log.js";
import { sessionFile } from "./runtime/store.js";
import { listStops, readStops, resumeTarget, stopTarget, type StopScope } from "./runtime/stops.js";
import { own } from "./own.js";

type Ok = Extract<Parsed, { kind: "ok" }>;

export interface SessionCliDeps {
  out: (s: string) => void;
  err: (s: string) => void;
  /**
   * False when an agent started this process, or a process it was started from cannot be read (stop is refused).
   * It prints why: `refusal` for an agent.
   */
  notAgent: (refusal: string) => Promise<boolean>;
  /** A person at the keyboard: an interactive terminal not started by an agent (resume). */
  humanAtKeyboard: () => Promise<boolean>;
  /** Reads a line with echo off (the passphrase). */
  readSecret: (prompt: string) => Promise<string>;
  env: NodeJS.ProcessEnv;
}

type Handler = (p: Ok, l: Layout, d: SessionCliDeps) => Promise<number>;

const USAGE = 64;

const opt = (p: Ok, name: string): string | undefined => {
  const v = p.flags.get(name);
  return typeof v === "string" ? v : undefined;
};

/** A session id as the firewall stores it (as `status` and `session list` show it): any id the hook can record. */
function validSession(s: string): boolean {
  return s.length > 0;
}

/** A hook agent (claude, codex, gemini, cursor), the MCP gateway, or a local API agent id. */
function validAgent(s: string): boolean {
  return (AGENT_IDS as readonly string[]).includes(s) || s === "gateway" || isAgentId(s);
}

function describe(s: StopState): string {
  const who = s.by === "person" ? "by a person" : s.by === "monitor" ? "by the behaviour monitor" : "(record unreadable)";
  const why = s.by === "monitor" && s.signal !== undefined ? signalSentence(s.signal) : s.reason;
  return `${s.scope} ${safeLine(s.target)}  stopped ${who}${s.at !== "" ? ` at ${s.at}` : ""}${why !== "" ? `: ${safeLine(why)}` : ""}`;
}

async function stop(scope: StopScope, p: Ok, l: Layout, d: SessionCliDeps): Promise<number> {
  const target = p.positionals[0] as string;
  if (!(scope === "session" ? validSession(target) : validAgent(target))) {
    d.err(`launchsafe-firewall ${scope} stop: "${safeLine(target).slice(0, 80)}" is not a valid ${scope === "session" ? "session id" : "agent id (claude, codex, gemini, cursor, gateway, or a local API agent id)"}`);
    return USAGE;
  }
  if (!(await d.notAgent(`launchsafe-firewall ${scope} stop was started from inside an agent session. Run it from your own terminal or script.`))) return 1;
  const reason = (opt(p, "--reason") ?? "").slice(0, 300);
  const { trustedApproverKey } = await import("./hook/pipeline.js");
  const r = stopTarget(l, scope, target, { by: "person", reason, approverKey: trustedApproverKey(l, d.env) });
  if (!r.created) {
    d.out(`Already stopped: ${describe(r.stop)}`);
    return 0;
  }
  appendLog(l, { type: "stop", scope, target, by: "person", ...(reason !== "" ? { reason } : {}), id: r.stop.id });
  if (scope === "session") {
    d.out(`Session ${target} is stopped (${r.stop.id}). Every later tool call it makes through the firewall is blocked (a command already running keeps running) until you run: launchsafe-firewall session resume ${target}`);
    if (!existsSync(sessionFile(l, target))) d.out(`No session named ${target} has been seen yet; it is stopped from its first action. Session ids are shown by: launchsafe-firewall status`);
  } else d.out(`Agent ${target} is stopped (${r.stop.id}): every session of it is blocked until you run: launchsafe-firewall agent resume ${target}`);
  return 0;
}

async function resume(scope: StopScope, p: Ok, l: Layout, d: SessionCliDeps): Promise<number> {
  const target = p.positionals[0] as string;
  if (!(scope === "session" ? validSession(target) : validAgent(target))) {
    d.err(`launchsafe-firewall ${scope} resume: "${safeLine(target).slice(0, 80)}" is not a valid ${scope === "session" ? "session id" : "agent id"}`);
    return USAGE;
  }
  if (!(await d.humanAtKeyboard())) return 1;
  const { approverPublicKey, publicKeyOf, signStateChange, unlockApprover } = await import("./runtime/approver.js");
  if (approverPublicKey(l) === null) {
    d.err('Resuming needs the approval passphrase, and none is set. In your own terminal run "launchsafe-firewall approver init", then "launchsafe-firewall install" again to pin it, then resume.');
    return 1;
  }
  // Nothing to resume: say so before asking for the passphrase.
  if (readStops(l, scope, target, approverPublicKey(l)).active.length === 0) {
    d.out(`${scope === "session" ? "Session" : "Agent"} ${target} is not stopped.`);
    return 0;
  }
  const priv = unlockApprover(l, await d.readSecret("Approval passphrase: "));
  const mine = publicKeyOf(priv);
  // The hook honours a resume only if it verifies against the key pinned in its command: refuse before writing
  // when that is another key (rotated without reinstalling), instead of printing a success the hook ignores.
  const { pinnedApproverKeys } = await import("./runtime/install.js");
  const pins = pinnedApproverKeys(l, d.env);
  const other = pins.filter((k) => k !== mine);
  if (other.length > 0) {
    d.err('The hooks pin a different approval key than the one your passphrase unlocks (rotated without reinstalling?), so they would ignore this resume. Run "launchsafe-firewall install" again, then resume. Nothing was changed.');
    return 1;
  }
  const r = resumeTarget(l, scope, target, { sign: (fields) => signStateChange(priv, "resume", target, fields), approverKey: mine });
  // Check it as the hook will, with the pinned key (the key on disk when none is pinned).
  const still = readStops(l, scope, target, pins[0] ?? mine).active;
  if (still.length > 0) {
    d.err(`The resume was written, but ${scope} ${target} is still stopped as the hook reads it (${still.map((x) => x.id).join(", ")}). Run "launchsafe-firewall doctor".`);
    return 1;
  }
  appendLog(l, { type: "resume", scope, target, by: "person", stops: r.ended.map((s) => s.id), ...(r.movedAside !== null ? { movedAside: r.movedAside } : {}) });
  if (r.movedAside !== null) d.out(`The stop record of ${scope} ${target} could not be read; it was moved aside to ${r.movedAside}.`);
  d.out(`${scope === "session" ? "Session" : "Agent"} ${target} is resumed: its actions are checked as usual again. The behaviour monitor counts from now.`);
  return 0;
}

async function list(p: Ok, l: Layout, d: SessionCliDeps): Promise<number> {
  const { trustedApproverKey } = await import("./hook/pipeline.js");
  const { pinnedApproverKey } = await import("./runtime/install.js");
  const { stops, ignored } = listStops(l, pinnedApproverKey(l, d.env) ?? trustedApproverKey(l, d.env));
  if (p.flags.get("--json") === true) {
    d.out(JSON.stringify({ stopped: stops.map((s) => ({ scope: s.scope, target: s.target, by: s.by, at: s.at, reason: s.reason, ...(s.signal !== undefined ? { signal: s.signal } : {}), id: s.id })), ignoredResumes: ignored }, null, 2));
    return 0;
  }
  for (const x of ignored) d.out(`Warning: ${x.count} resume record(s) for ${x.scope} ${safeLine(x.target)} were ignored: not signed by your approval key, so something other than you wrote them.`);
  if (stops.length === 0) {
    d.out("No session or agent is stopped.");
    return 0;
  }
  for (const s of stops) d.out(describe(s));
  d.out("Resume with: launchsafe-firewall session resume <session>, or agent resume <agentId> (needs the approval passphrase).");
  return 0;
}

export const SESSION_HANDLERS: Record<string, Handler> = {
  session: (p, l, d) => list(p, l, d),
  "session list": (p, l, d) => list(p, l, d),
  "session stop": (p, l, d) => stop("session", p, l, d),
  "session resume": (p, l, d) => resume("session", p, l, d),
  "agent stop": (p, l, d) => stop("agent", p, l, d),
  "agent resume": (p, l, d) => resume("agent", p, l, d),
};

export function sessionHandler(key: string): Handler {
  const h = own(SESSION_HANDLERS, key);
  if (h === undefined) throw new Error(`no session handler for ${key}`);
  return h;
}
