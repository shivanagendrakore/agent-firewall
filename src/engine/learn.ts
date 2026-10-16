/**
 * Learned project allows ("Fewer prompts", docs/usage.md). Pure: which actions a person may tell the
 * firewall to stop asking about in one project, the key an action is remembered by, and why an action
 * is not eligible. The runtime (src/runtime/learned.ts) stores the person's signed choices in the
 * firewall's own home; decide() applies them.
 *
 * The guarantees, each enforced here at decision time (the stored choice never decides on its own):
 * - Only rules whose risk class is "low" can be covered. Every other class (catastrophic, credential,
 *   exfiltration, tamper, instructions, supply chain, ...) is never covered, whatever a file says.
 * - Never in a session that has read outside content or holds private data: taint always wins.
 * - Never when any part of the action is outside a short list of harmless effects, or the analyzer
 *   recorded any finding about it, or the policy file is broken.
 * - Exact: the key is the tool and its whole input (a cosmetic field such as a shell command's
 *   description aside), so a learned allow never covers a different command.
 */

import { sha256Hex } from "./bytes.js";
import { canonicalJson } from "./decide.js";
import { memoByInput } from "./payload-memo.js";
import type { ActionClass, Effect, Finding, NormalizedAction, SessionState } from "../types.js";
import { own } from "../own.js";

/** How risky a rule's subject is, for learned allows. Only "low" can ever be learned. */
export type RiskClass = "low" | "catastrophic" | "credential" | "exfiltration" | "tamper" | "instructions" | "supply-chain" | "unverifiable" | "limit" | "scope" | "policy" | "state";

/**
 * Every rule id in the catalogue (src/rules.ts), by risk class. A test keeps this complete; a rule that
 * is missing here is treated as "unverifiable", so a new rule is never learnable by accident.
 */
export const RULE_RISK: Readonly<Record<string, RiskClass>> = {
  "FW-SEND": "exfiltration",
  "FW-MESSAGE": "exfiltration",
  "FW-SEND-ARGS": "exfiltration",
  "FW-FETCH": "exfiltration",
  "FW-FETCH-DATA": "exfiltration",
  "FW-CAPTURE-HOST": "exfiltration",
  "FW-DNS-EXFIL": "exfiltration",
  "FW-RAW-IP": "exfiltration",
  "FW-NEW-HOST": "exfiltration",
  "FW-DLP-CREDENTIAL": "credential",
  "FW-DLP-SEEN-SECRET": "credential",
  "FW-DLP-PERSONAL": "credential",
  "FW-CREDENTIAL-READ": "credential",
  "FW-SECRET-FLOW": "credential",
  "FW-SECRET-VARIABLE": "credential",
  "FW-METADATA": "credential",
  "FW-SECRET-FILE-PUBLISH": "credential",
  "FW-CREDENTIAL-FLOW": "credential",
  "FW-CANARY-READ": "credential",
  "FW-CANARY-EGRESS": "credential",
  "FW-VAULT-EGRESS": "credential",
  "FW-VAULT-UNBOUND": "credential",
  "FW-VAULT-INDEX": "credential",
  "FW-VAULT-UNSUPPORTED": "credential",
  "FW-VAULT-OPTION": "credential",
  "FW-VAULT-APPROVE": "credential",
  "FW-MCP-AUTH": "credential",
  "FW-INSTRUCTIONS-HELD": "instructions",
  "FW-INSTRUCTIONS": "instructions",
  "FW-AGENT-SETTINGS": "instructions",
  "FW-AGENT-SPAWN": "instructions",
  "FW-HIDDEN-TEXT": "instructions",
  "FW-HIDDEN-OUTPUT": "instructions",
  "FW-OUTSIDE-COMMAND": "instructions",
  "FW-MCP-CHANGED": "instructions",
  "FW-MCP-TOOL-HELD": "instructions",
  "FW-MCP-WITHHELD": "instructions",
  "FW-MCP-SAMPLING": "instructions",
  "FW-MAIL-WITHHELD": "instructions",
  "FW-TAMPER": "tamper",
  "FW-AGENT-BYPASS": "tamper",
  "FW-PERSISTENCE": "tamper",
  "FW-PERSISTENCE-HELD": "tamper",
  "FW-AUTORUN": "tamper",
  "FW-SYMLINK": "tamper",
  "FW-OUTSIDE-WRITE": "tamper",
  "FW-LOG-UNRECORDED": "tamper",
  "FW-RESULT-UNRECORDED": "tamper",
  "FW-DESTRUCTIVE": "catastrophic",
  "FW-DESTROY-ROOT": "catastrophic",
  "FW-CATASTROPHIC": "catastrophic",
  "FW-PRIVILEGE": "catastrophic",
  "FW-REMOTE-CODE": "catastrophic",
  "FW-OBFUSCATED": "catastrophic",
  "FW-UNTRUSTED-CODE": "catastrophic",
  "FW-TAINTED-MANIFEST": "catastrophic",
  "FW-INSTALL": "supply-chain",
  "FW-MALICIOUS-PACKAGE": "supply-chain",
  "FW-TYPOSQUAT": "supply-chain",
  "FW-OPAQUE-CODE": "unverifiable",
  "FW-UNCLASSIFIABLE": "unverifiable",
  "FW-POLICY-ERROR": "unverifiable",
  "FW-UNAVAILABLE": "unverifiable",
  "FW-RATE-LIMITED": "unverifiable",
  "FW-API-ERROR": "unverifiable",
  "FW-MCP-METHOD": "unverifiable",
  "FW-INPUT-SHAPE": "unverifiable",
  "FW-BUDGET-BYTES": "limit",
  "FW-BUDGET-REQUESTS": "limit",
  "FW-BUDGET-MCP": "limit",
  "FW-LOOP": "limit",
  "FW-CAP": "limit",
  "FW-CAP-WARN": "limit",
  "FW-STOPPED": "limit",
  "FW-SCOPE": "scope",
  "FW-BLOCKED-TOOL": "policy",
  "FW-NET-REFUSED": "exfiltration",
  "FW-LEARNED-DENY": "policy",
  "FW-APPROVED": "state",
  "FW-LEARNED-ALLOW": "state",
  "FW-UNKNOWN-TOOL": "low",
};

/** Why a class is never learnable, in words a person reads after "not offered: ". */
const CLASS_WHY: Record<Exclude<RiskClass, "low">, string> = {
  catastrophic: "it could destroy data or run code no one has checked",
  credential: "it involves credentials or private data",
  exfiltration: "it could send data off this machine",
  tamper: "it changes the firewall, the agent's settings or files that run code later",
  instructions: "it changes or carries the agent's instructions",
  "supply-chain": "it installs or runs packages",
  unverifiable: "part of it cannot be checked before it runs",
  limit: "it is a budget or loop limit, and approving it already raises that limit for the session",
  scope: "it is outside the task you gave, which is decided for each task",
  policy: "your policy decides it",
  state: "it is not a question for you",
};

export function riskOf(rule: string): RiskClass {
  return own(RULE_RISK, rule) ?? "unverifiable";
}

/** The rules a learned allow may cover (the "low" class). */
export const LEARNABLE_RULES: readonly string[] = Object.entries(RULE_RISK)
  .filter(([, c]) => c === "low")
  .map(([r]) => r);

/** The only effects an action covered by a learned allow may have. */
const HARMLESS_EFFECTS: ReadonlySet<ActionClass> = new Set<ActionClass>(["read_local_workspace", "write_workspace", "execute", "unknown"]);

/** Fields of a tool's input that do not change what it does (shown to the person, not run). */
const COSMETIC: Readonly<Record<string, readonly string[]>> = { Bash: ["description"] };

/** The key a learned allow or "never" is stored under: the tool and its whole input, canonical JSON. */
export function learnKey(action: NormalizedAction): string {
  return typeof action.input === "object" && action.input !== null ? learnKeyOf(action.tool, action.input) : learnKeyOf(action.tool, {});
}

/** learnKey, remembered per input object within one decision (src/engine/payload-memo.ts). */
const learnKeyOf = memoByInput((tool, raw) => {
  const drop = own(COSMETIC, tool) ?? [];
  const input = Object.fromEntries(Object.entries(raw).filter(([k]) => !drop.includes(k)));
  return sha256Hex(`launchsafe-firewall/learn/v1\n${tool}\n${canonicalJson(input)}`);
});

/**
 * The key the loop and failure counters count an action under (FW-LOOP's same-action count, the behaviour
 * monitor's failures, the identical-failures spending limit): the learnKey, so a cosmetic field (a Bash
 * description) that changes from call to call cannot make the same command look new and reset the count.
 * Approvals and budget raises stay bound to the exact actionHash.
 */
export function counterKey(action: NormalizedAction): string {
  return learnKey(action);
}

/**
 * What a tool is, beyond its name: for an MCP tool the hash of its server's current pin (configuration,
 * the tool's observed description, version), for any other tool the agent that offers it. An "always"
 * choice holds only for the identity it was made under; null (an MCP server with no current, reviewed
 * pin) means no "always" choice can apply.
 */
export function allowKey(key: string, identity: string): string {
  return sha256Hex(`launchsafe-firewall/learn-allow/v1\n${key}\n${identity}`);
}

/**
 * The person's choices for one project, as the hook hands them to decide(). `allows` is keyed by
 * allowKey(learnKey(action), identity); `nevers` by learnKey(action) alone, so a "never" holds whatever
 * the tool's identity becomes. `identity` is the current call's tool identity.
 */
export interface LearnedView {
  allows: ReadonlyMap<string, string>;
  nevers: ReadonlyMap<string, string>;
  identity?: string | null;
}

export type Eligibility = { eligible: true } | { eligible: false; why: string; cls?: RiskClass };

/** Whether these rules could ever be learned (the static part: the CLI re-checks a candidate with it). */
export function rulesEligibility(rules: readonly string[]): Eligibility {
  if (rules.length === 0) return { eligible: false, why: "nothing about it needs you" };
  for (const r of rules) {
    const cls = riskOf(r);
    if (cls !== "low") return { eligible: false, why: CLASS_WHY[cls], cls };
  }
  return { eligible: true };
}

/** The action's part: only learnable rules fired, nothing else about it is risky, and the analyzer saw all of it. */
export function actionEligibility(x: { rules: readonly string[]; effects: readonly Effect[]; findings: readonly Finding[] }): Eligibility {
  const byRule = rulesEligibility(x.rules);
  if (!byRule.eligible) return byRule;
  if (x.findings.length > 0) return { eligible: false, why: "part of it cannot be checked before it runs", cls: "unverifiable" };
  for (const e of x.effects) {
    // A fixed reason: the effect's own text is agent-chosen and is not repeated in "Your choices".
    if (!HARMLESS_EFFECTS.has(e.cls) || e.private === true || e.download !== undefined) return { eligible: false, why: "it does more than the action the rule is about" };
  }
  return { eligible: true };
}

/** The session's part: taint and private data always win, and a broken policy file allows nothing extra. */
export function sessionEligibility(state: SessionState, policyError?: string, interactive = true): Eligibility {
  if (policyError !== undefined) return { eligible: false, why: "the policy file is invalid" };
  // A person must be there: an unattended session (claude -p, CI, dontAsk, unattended hours) gets no learned allow.
  if (!interactive) return { eligible: false, why: "no one is here to see it (an unattended session)" };
  if (state.tainted) return { eligible: false, why: "this session has read outside content, and that always wins" };
  if (state.sensitive || state.fingerprints.size > 0 || state.secretPaths.size > 0) return { eligible: false, why: "this session holds private data, and that always wins" };
  if (state.canaryTripped.size > 0 || state.canarySeen.size > 0) return { eligible: false, why: "this session touched a decoy file you planted" };
  return { eligible: true };
}

/**
 * Whether a learned allow may cover this decision now. `rules` are all the rules that fired (any
 * outcome); `state` is the session's. Every check must pass; the first that fails is the reason.
 */
export function learnEligibility(x: { rules: readonly string[]; effects: readonly Effect[]; findings: readonly Finding[]; state: SessionState; policyError?: string | undefined; interactive: boolean }): Eligibility {
  const session = sessionEligibility(x.state, x.policyError, x.interactive);
  return session.eligible ? actionEligibility(x) : session;
}
