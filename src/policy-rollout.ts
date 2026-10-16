/**
 * The rollout policy key, kept apart from policy.ts so it stays one module: `rollout`. In watch mode the
 * firewall decides every action as usual and logs the verdict, but lets the action run, so a team can see
 * what enforcing would ask, hold or block before switching it on. Only a reviewed list of rules relaxes
 * (WATCH_RELAXABLE_RULES); every other rule stays enforced (WATCH_ENFORCED_RULES).
 *
 * Watch mode loosens the firewall, so a project file may never turn it on (it may set "enforce", which
 * tightens), and a user file's "watch" counts only with a grant signed by the approval key
 * (`launchsafe-firewall rollout watch`, src/runtime/rollout.ts). A managed file may set either.
 */

import type { FirewallConfig, RolloutMode, RolloutPolicy } from "./types.js";
import { RULES } from "./rules.js";

export const ROLLOUT_POLICY_KEYS = ["rollout"] as const;
export const ROLLOUT_MODES: readonly RolloutMode[] = ["enforce", "watch"];

export interface RolloutDoc {
  rollout?: Partial<RolloutPolicy>;
}

/**
 * The rules watch mode may relax, reviewed one by one: the rules that ask about ordinary work after outside
 * content, or about things that are friction rather than damage (an unknown tool, a raw IP, a misspelt
 * package name, budgets and loops, the task scope). None of them is a rule a person could not approve.
 * Every other rule in the catalogue stays enforced in watch mode (WATCH_ENFORCED_RULES), including every rule
 * that can never be approved and any rule added later until it is reviewed and listed here.
 */
export const WATCH_RELAXABLE_RULES: ReadonlySet<string> = new Set([
  "FW-SEND",
  "FW-MESSAGE",
  "FW-SEND-ARGS",
  "FW-FETCH",
  "FW-FETCH-DATA",
  "FW-OUTSIDE-WRITE",
  "FW-INSTALL",
  "FW-OPAQUE-CODE",
  "FW-AGENT-SPAWN",
  "FW-SCOPE",
  "FW-RAW-IP",
  "FW-UNKNOWN-TOOL",
  "FW-TYPOSQUAT",
  "FW-BUDGET-BYTES",
  "FW-BUDGET-REQUESTS",
  "FW-BUDGET-MCP",
  "FW-LOOP",
  "FW-POLICY-ERROR",
]);

/** The rules watch mode never relaxes: every catalogued rule not reviewed as relaxable (never one a person cannot approve). */
export const WATCH_ENFORCED_RULES: ReadonlySet<string> = new Set(Object.values(RULES).filter((r) => !r.approvable || !WATCH_RELAXABLE_RULES.has(r.id)).map((r) => r.id));

/**
 * Whether a rule keeps its outcome in watch mode. A rule id the catalogue does not know (none should exist)
 * is enforced: only reviewed rules relax.
 */
export function enforcedInWatch(rule: string): boolean {
  return WATCH_ENFORCED_RULES.has(rule) || !WATCH_RELAXABLE_RULES.has(rule);
}

/** The always-enforced rules, grouped for status, doctor and docs/policy.md. */
export const WATCH_ENFORCED_GROUPS: readonly { group: string; rules: readonly string[] }[] = (() => {
  const groups: { group: string; test: (id: string) => boolean }[] = [
    { group: "data leaving (credentials, personal data, capture hosts, DNS exfiltration, metadata, the vault)", test: (id) => /^FW-(DLP-|SECRET-|METADATA|CAPTURE-HOST|DNS-EXFIL|VAULT-|CREDENTIAL-READ|CREDENTIAL-FLOW|NEW-HOST)/.test(id) },
    { group: "decoys", test: (id) => id.startsWith("FW-CANARY-") },
    { group: "self-protection and the agent's own configuration", test: (id) => /^FW-(TAMPER|AGENT-BYPASS|AGENT-SETTINGS|INSTRUCTIONS|PERSISTENCE|AUTORUN|SYMLINK|HIDDEN-TEXT|LOG-UNRECORDED|RESULT-UNRECORDED)/.test(id) },
    { group: "outside content (commands it suggested, hidden text in results)", test: (id) => /^FW-(OUTSIDE-COMMAND|HIDDEN-OUTPUT)$/.test(id) },
    { group: "destructive and code-running actions", test: (id) => /^FW-(CATASTROPHIC|DESTROY-ROOT|DESTRUCTIVE|MALICIOUS-PACKAGE|REMOTE-CODE|OBFUSCATED|UNTRUSTED-CODE|TAINTED-MANIFEST|UNCLASSIFIABLE|PRIVILEGE|BLOCKED-TOOL|INPUT-SHAPE)/.test(id) },
    { group: "stops and limits (the kill switch, spending limits, a person's never)", test: (id) => /^FW-(STOPPED|CAP|CAP-WARN|LEARNED-DENY)$/.test(id) },
  ];
  const all = [...WATCH_ENFORCED_RULES].sort();
  const out = groups.map((g) => ({ group: g.group, rules: all.filter(g.test) }));
  const rest = all.filter((id) => !groups.some((g) => g.test(id)));
  return [...out, { group: "everything else (the gateway, the local API, approvals)", rules: rest }];
})();

/** The mode a configuration asks for (before the grant check). */
export function rolloutMode(cfg: Pick<FirewallConfig, "rollout">): RolloutMode {
  return cfg.rollout?.mode === "watch" ? "watch" : "enforce";
}

type Raw = Record<string, unknown>;

/** Validates `rollout` of a (migrated) policy document into `out`. Unknown sub-keys and bad values are errors. */
export function validateRolloutKeys(raw: Raw, problems: string[], out: RolloutDoc): void {
  if (raw.rollout === undefined) return;
  const r = raw.rollout;
  if (typeof r !== "object" || r === null || Array.isArray(r)) {
    problems.push('"rollout" must be an object');
    return;
  }
  const res: Partial<RolloutPolicy> = {};
  for (const [k, v] of Object.entries(r as Raw)) {
    if (k === "mode") {
      if (typeof v !== "string" || !(ROLLOUT_MODES as readonly string[]).includes(v)) problems.push(`"rollout.mode" must be one of ${ROLLOUT_MODES.map((m) => `"${m}"`).join(", ")}`);
      else res.mode = v as RolloutMode;
    } else problems.push(`"rollout.${k}" is not a known setting (expected mode)`);
  }
  out.rollout = res;
}

/** Applies a project file's `rollout`: "enforce" only; "watch" is a loosening and is listed in `ignored`. */
export function tightenRolloutKeys(over: RolloutDoc, cfg: FirewallConfig, ignored: string[]): void {
  const mode = over.rollout?.mode;
  if (mode === undefined) return;
  if (mode === "enforce") cfg.rollout = { mode: "enforce" };
  else ignored.push('rollout.mode "watch" (a project may not turn watch mode on; only a person can, with "launchsafe-firewall rollout watch")');
}
