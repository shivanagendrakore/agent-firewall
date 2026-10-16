/**
 * Optional: hold the agent's call open while the phone answers
 * (`phone.holdSeconds`, off by default). When an
 * approval item is queued and a phone is paired, the hook watches the
 * session file (local reads every 250 ms, no network: the relay daemon
 * appends the verified phone_approval) and, if the approval arrives in
 * time, decides the call again, which now allows it once (FW-APPROVED).
 *
 * The wait is capped at the agent's hook timeout minus 10 seconds: Codex and
 * Gemini CLI fail open on a hook timeout, so waiting near their limit would
 * turn a hold into an allow. `doctor` warns when the policy asks for more.
 */

import { adapterFor } from "../../adapters/index.js";
import type { AgentId } from "../../adapters/types.js";
import { phonePolicy } from "../../policy-phone.js";
import type { FirewallConfig } from "../../types.js";
import type { Layout } from "../layout.js";
import { getQueueItem, loadState, type QueueItem, type TrustKeys } from "../store.js";

export interface HoldDeps {
  /** Blocks for `ms` (the hook is synchronous). */
  sleep: (ms: number) => void;
  now: () => number;
}

const sleeper = new Int32Array(new SharedArrayBuffer(4));
export const REAL_HOLD: HoldDeps = { sleep: (ms) => void Atomics.wait(sleeper, 0, 0, ms), now: () => Date.now() };

/** The agent's hook timeout in seconds, as install writes it. */
export function hookTimeoutSeconds(agent: AgentId): number {
  const t = adapterFor(agent).settings.timeout;
  // Gemini CLI's hook timeouts are in milliseconds.
  return agent === "gemini" ? Math.floor(t / 1000) : t;
}

/** The longest a hold may last for this agent: its hook timeout minus 10 seconds. */
export function holdCapSeconds(agent: AgentId): number {
  return Math.max(0, hookTimeoutSeconds(agent) - 10);
}

/** How long this call may be held: 0 unless a phone is pinned, the policy asks, and the item may go to the phone. */
export function holdSecondsFor(item: QueueItem, cfg: Pick<FirewallConfig, "phone">, agent: AgentId, env: NodeJS.ProcessEnv): number {
  const p = phonePolicy(cfg);
  if (p.holdSeconds <= 0 || !p.enabled || item.kind !== "approval" || !p.approvable.includes("approval")) return 0;
  if (item.rules.some((r) => p.excludeRules.includes(r))) return 0;
  if (env.LAUNCHSAFE_FIREWALL_PHONES === undefined || env.LAUNCHSAFE_FIREWALL_PHONES === "") return 0;
  return Math.min(p.holdSeconds, holdCapSeconds(agent));
}

/** Waits up to `seconds` for a verified phone approval of `actionHash`. False on timeout or a rejection. */
export function waitForPhoneApproval(l: Layout, item: QueueItem, keys: () => TrustKeys, seconds: number, d: HoldDeps = REAL_HOLD): boolean {
  const deadline = d.now() + seconds * 1000;
  for (;;) {
    if (loadState(l, item.sessionId, keys()).approvals.has(item.actionHash)) return true;
    const cur = getQueueItem(l, item.id);
    if (cur === null || cur.status === "rejected") return false;
    if (d.now() >= deadline) return false;
    d.sleep(Math.min(250, Math.max(1, deadline - d.now())));
  }
}
