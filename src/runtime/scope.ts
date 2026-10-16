/**
 * Task scope at run time: recording the scope a prompt sets (UserPromptSubmit),
 * a person's signed widening (`scope widen`, `queue approve`), and what
 * `scope show` and `status` print. The engine part is src/engine/scope.ts.
 */

import { createHash, randomBytes } from "node:crypto";
import { statSync } from "node:fs";
import { nextScope, normalizeWiden, scopeFromPrompt, taskScopePolicy, type PathKind, type ScopeWiden, type TaskScope } from "../engine/scope.js";
import type { Context, FirewallConfig, SessionState } from "../types.js";
import type { Layout } from "./layout.js";
import { tailLog } from "./log.js";
import { appendEvents } from "./store.js";

export function statKind(abs: string): PathKind {
  const st = statSync(abs, { throwIfNoEntry: false });
  return st === undefined ? null : st.isDirectory() ? "dir" : "file";
}

/**
 * The scope a prompt sets, appended as a `scope` event. Nothing when the mode is off or the prompt is
 * a continuation (the previous scope stays). The prompt text is hashed, never stored.
 */
export function recordPromptScope(l: Layout, sessionId: string, prompt: string, cfg: FirewallConfig, ctx: Context, previous: SessionState, now: Date = new Date()): TaskScope | null {
  if (taskScopePolicy(cfg).mode === "off") return null;
  const hash = createHash("sha256").update(prompt).digest("hex");
  const scope = nextScope(previous.scope, prompt, () => scopeFromPrompt(prompt, hash, ctx, { stat: statKind }, now));
  if (scope !== null) appendEvents(l, sessionId, [{ type: "scope", scope }]);
  return scope;
}

/**
 * A person widens the scope of one session. `sign` holds the unlocked approver key and signs
 * (session, "scope-widen", kind, value, id); an unsigned or forged line makes the session untrusted.
 */
export function widenScope(l: Layout, sessionId: string, widen: ScopeWiden, sign: (fields: readonly string[]) => string): string {
  const w = normalizeWiden(widen.kind, widen.value);
  if (w === null) throw new Error(`not a valid ${widen.kind} to widen the task scope with: ${widen.value}`);
  const id = `w${randomBytes(5).toString("hex")}`;
  appendEvents(l, sessionId, [{ type: "scope_widen", kind: w.kind, value: w.value, id, sig: sign([w.kind, w.value, id]) }]);
  return id;
}

/** `scope show`: the current scope of a session, in plain words. */
export function formatScope(sessionId: string, state: SessionState, cfg: FirewallConfig): string {
  const mode = taskScopePolicy(cfg).mode;
  const L = [`Task scope of session ${sessionId} (taskScope.mode: ${mode}${mode === "log" ? ", logged only: no decision changes" : ""})`];
  const s = state.scope;
  if (s === null) L.push("  No prompt has set a scope in this session: the firewall's other rules apply as they are.");
  else {
    L.push(`  Set ${s.at} by a prompt (sha256 ${s.prompt.slice(0, 12)}...).`);
    if (!s.narrowed) L.push("  The prompt named no path in the workspace and no publish-type verb: the whole workspace, no limits.");
    L.push(`  Paths: ${s.paths.length > 0 ? s.paths.join(", ") : "the whole workspace"}`);
    L.push(`  Repositories: ${s.repos.length > 0 ? s.repos.join(", ") : "none named"}`);
    L.push(`  Hosts: ${s.hosts.length > 0 ? s.hosts.join(", ") : "none named"}`);
    L.push(`  Asked to: ${s.intents.length > 0 ? s.intents.join(", ") : "nothing that publishes, deploys, installs or deletes"}`);
  }
  if (state.scopeWidenings.length > 0) {
    L.push("  Widened by you:");
    for (const w of state.scopeWidenings) L.push(`    ${w.kind} ${w.value} (${w.id})`);
  }
  return L.join("\n");
}

/** How many recent decisions the task scope asked for (enforce) or would have asked for (log). */
export function scopeCounts(l: Layout, n = 1000): { wouldAsk: number; asked: number } {
  let wouldAsk = 0;
  let asked = 0;
  for (const e of tailLog(l, n)) {
    const sc = e.event.scope as { mode?: string; changes?: boolean } | undefined;
    if (e.event.type !== "decision" || sc === undefined || sc.changes !== true) continue;
    if (sc.mode === "enforce") asked++;
    else wouldAsk++;
  }
  return { wouldAsk, asked };
}
