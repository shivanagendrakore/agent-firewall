/**
 * The rules. Pure: an action, the session's state, the policy and the
 * context go in; a verdict with reasons and the state changes to record come
 * out. Rules are evaluated independently and the most severe outcome wins.
 *
 *   deny     never allowed, not even with approval (always-on protections)
 *   hold     kept as a proposal for a person to review; never done by the agent now
 *   approve  needs a person: ask when someone is there, queue when unattended
 *   allow    proceeds (and Claude Code's own permission rules still apply)
 */

import { sha256Hex } from "./bytes.js";
import type { Context, Decision, Effect, FirewallConfig, Finding, NormalizedAction, Outcome, SessionState, StateEvent, Verdict } from "../types.js";
import { canaryIdsIn, carriesCanary } from "./canary.js";
import { catastropheReason } from "./catastrophic.js";
import { classifyAction, READ_ONLY_TOOLS } from "./classify.js";
import { hostInList, hostMatches, urlCarriesData, parseUrlLike } from "./network.js";
import { isUnder } from "./paths.js";
import { downloadsOf } from "./effects.js";
import { packageRules } from "./packages.js";
import { outsideCommandRules } from "./outsider.js";
import { safeText } from "./terminal.js";
import { budgetRules, measureUsage, monitorCheck, type BudgetOutcome, type BudgetView } from "./budgets.js";
import { stoppedReason, type StopView } from "./stop.js";
import { capPolicy, capRules, monitorCountedVerdict, type CapOutcome, type CapRecord, type CapView, type ModelUsage } from "./caps.js";
import { isHookBody } from "./autorun.js";
import { defaultPersistence } from "../policy-persistence.js";
import { enforcedInWatch } from "../policy-rollout.js";
import { scopeHits, taskScopePolicy, type ScopeHit } from "./scope.js";
import { findPersonalData, isKnownTestValue } from "./pii.js";
import { allGoingToIssuer, containsFingerprint, findSecrets, isTestSecret } from "./secrets.js";
import { egressBound, entriesIn, formatRef, vaultFingerprints } from "./vault-ref.js";
import { vaultRules } from "./vault-checks.js";
import { matchServerEntry, parseMcpTool } from "./mcp.js";
import { knownHostRules } from "./knownhosts.js";
import { own } from "../own.js";
import { InputTooDeep, MAX_INPUT_DEPTH, nestedDeeperThan } from "./input-depth.js";
import { inDecision, memoByInput, memoLast, newDecisionMemo } from "./payload-memo.js";

// One scan per payload per decision, however many effects carry it (src/engine/payload-memo.ts).
const carriesCanaryM = memoLast(carriesCanary);
const canaryIdsInM = memoLast(canaryIdsIn);
const entriesInM = memoLast(entriesIn);
const findSecretsM = memoLast(findSecrets);
const containsFingerprintM = memoLast(containsFingerprint);
const findPersonalDataM = memoLast(findPersonalData);
import { allowKey, counterKey, learnEligibility, learnKey, type LearnedView } from "./learn.js";
import { approvalRefusal, type ApprovalPlace } from "./state.js";

export interface RuleHit {
  rule: string;
  outcome: Outcome;
  reason: string;
}

const RANK: Record<Outcome, number> = { allow: 0, approve: 1, hold: 2, deny: 3 };

export interface DecideInput {
  action: NormalizedAction;
  state: SessionState;
  config: FirewallConfig;
  ctx: Context;
  /** Set when the policy file could not be read: every risky action then needs a person. */
  policyError?: string;
  /**
   * I9: what a person's approval of this action is also bound to besides the action itself (the local API sets
   * the call's cwd and workspace roots, which the caller states). An approval given under one scope is never
   * used under another: the same relative path or command means another file in another directory. Absent:
   * approvals bind to the action alone (the hook and the gateway check the place an approval was signed for
   * instead, approvalWhere).
   */
  approvalScope?: string;
  /**
   * I9: the working directory and project directory this route decides in, for an approval signed with its own
   * (the hook and the gateway state them; the local API and the library bind through approvalScope instead).
   * An approval given for another place is not used. Absent: no place is checked.
   */
  approvalWhere?: ApprovalPlace;
  /** The session's budget counters so far (read by the runtime). Absent: budgets are not checked. */
  budgets?: BudgetView;
  /**
   * Watch mode is in effect (src/policy-rollout.ts). Set by the hook pipeline only after it verified that a
   * person turned it on (src/runtime/rollout.ts); never derived from the configuration here.
   */
  watch?: boolean;
  /** The kill switch: a stop in force for this session or its agent, and when it was last resumed. Absent: none. */
  stop?: StopView;
  /** The session id, for the resume command in FW-STOPPED's reason. */
  sessionId?: string;
  /** The session's and today's spending-limit counters (read by the runtime). Absent: caps are not checked. */
  caps?: CapView;
  /** Model usage the agent reported with this call (local API, SDKs), counted toward the token and cost caps. */
  usage?: ModelUsage;
  /** False: the call is network traffic a middleware asks about, not a tool call; it is not counted toward toolCalls. */
  countCall?: false;
  /**
   * The person's learned choices for this project (src/runtime/learned.ts): "never" entries deny the exact
   * action; "always" entries let it run only when learnEligibility() says so now. Absent: none apply.
   */
  learned?: LearnedView;
}

/** Canonical JSON (sorted keys) so the same action always hashes the same. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .filter((k) => own(o, k) !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(own(o, k))}`)
    .join(",")}}`;
}

const hashOf = memoByInput((tool, input) => sha256Hex(`${tool}\n${canonicalJson(input)}`));

/** I9: the key a person's approval is stored and looked up under: the action's hash, bound to its scope when there is one. */
export function approvalKey(hash: string, scope: string | undefined): string {
  return scope === undefined ? hash : sha256Hex(`approval-scope\n${hash}\n${scope}`);
}

/** The hash approvals, budgets and the log name an action by. Remembered per input object within one decision. */
export function actionHash(action: NormalizedAction): string {
  return typeof action.input === "object" && action.input !== null ? hashOf(action.tool, action.input) : sha256Hex(`${action.tool}\n${canonicalJson(action.input)}`);
}

function egressEffects(effects: readonly Effect[]): Effect[] {
  return effects.filter((e) => e.cls === "egress_send" || e.cls === "egress_fetch");
}

/** The always-on data rules: credentials and personal data never leave unless the destination is allowed for that kind. */
function dataRules(effects: readonly Effect[], state: SessionState, cfg: FirewallConfig, ctx: Context, hits: RuleHit[]): void {
  let damagedAsked = false;
  for (const e of egressEffects(effects)) {
    const payload = e.payload ?? "";
    // FB5: the vault is on but its index is unreadable or unsigned: a stored value could leave unrecognised
    // (or under a forged binding), so a send, or a fetch carrying data, needs a person.
    const damaged = ctx.vault?.damaged;
    if (damaged !== undefined && !damagedAsked && (e.cls === "egress_send" || payload !== "")) {
      damagedAsked = true;
      hits.push({ rule: "FW-VAULT-INDEX", outcome: "approve", reason: `${e.detail}: the vault index cannot be trusted (${damaged}), so a stored value in it could not be recognised; repair it (launchsafe-firewall doctor)` });
    }
    if (payload === "") continue;
    // A decoy's value goes nowhere: no allowlist applies, and this holds in sessions that never read the decoy
    // (the value may have reached the agent another way).
    if (carriesCanaryM(payload, ctx.canaries)) {
      hits.push({ rule: "FW-CANARY-EGRESS", outcome: "deny", reason: `${e.detail} would carry a decoy value you planted (canary files are valid nowhere); no destination may receive one` });
    }
    // A vaulted value is always a credential. To a destination not bound for that secret it is
    // denied, whatever dataAllowHosts and sendAllowHosts say (the per-secret binding is the narrower statement).
    const view = ctx.vault;
    if (view !== undefined) {
      const leaked = entriesInM(payload, view).filter((entry) => !egressBound(entry, e, view));
      if (leaked.length > 0) {
        const names = leaked.slice(0, 3).map((x) => formatRef(x.name)).join(", ");
        hits.push({ rule: "FW-VAULT-EGRESS", outcome: "deny", reason: `${e.detail} would carry the value of ${names}, which you stored in the vault, to a destination that secret is not bound to (also checked in base64, hex and URL encoding)${view.signed ? "" : "; the vault index is not signed by your approval key, so no destination is bound"}` });
      }
    }
    const servers = (e.tags ?? []).filter((t) => t.startsWith("mcp-server:")).map((t) => t.slice(11));
    const allowedFor = (kind: keyof FirewallConfig["dataAllowHosts"]): boolean =>
      (e.host !== undefined && hostInList(e.host, cfg.dataAllowHosts[kind])) || cfg.dataAllowHosts[kind].some((d) => d.startsWith("mcp:") && servers.includes(d.slice(4)));
    const secrets = findSecretsM(payload).filter((h) => !(cfg.allowTestValues && isTestSecret(h.value)));
    if (secrets.length > 0 && !allGoingToIssuer(secrets, e.host) && !allowedFor("credential")) {
      hits.push({ rule: "FW-DLP-CREDENTIAL", outcome: "deny", reason: `${e.detail} would carry a credential (${[...new Set(secrets.map((s) => s.name))].join(", ")}) to a destination that did not issue it` });
    }
    if (state.fingerprints.size > 0 && !allowedFor("credential") && containsFingerprintM(payload, state.fingerprints)) {
      hits.push({ rule: "FW-DLP-SEEN-SECRET", outcome: "deny", reason: `${e.detail} would carry a secret this session read earlier (also checked in base64, hex and URL encoding)` });
    }
    for (const d of findPersonalDataM(payload)) {
      if (cfg.allowTestValues && isKnownTestValue(d)) continue;
      if (!allowedFor(d.kind)) {
        hits.push({ rule: "FW-DLP-PERSONAL", outcome: "deny", reason: `${e.detail} would carry a ${d.name}; no destination is allowed to receive that kind of data (set dataAllowHosts.${d.kind})` });
        break;
      }
    }
  }
}

function findingRules(findings: readonly Finding[], trusted: boolean, effects: readonly Effect[], cfg: FirewallConfig, hits: RuleHit[]): void {
  for (const f of findings) {
    switch (f.id) {
      case "capture_host":
        hits.push({ rule: "FW-CAPTURE-HOST", outcome: "deny", reason: f.detail });
        break;
      case "dns_exfil_shape":
        hits.push({ rule: "FW-DNS-EXFIL", outcome: "deny", reason: f.detail });
        break;
      case "metadata_endpoint":
        hits.push({ rule: "FW-METADATA", outcome: "deny", reason: f.detail });
        break;
      case "secret_flow_in_command":
        hits.push({ rule: "FW-SECRET-FLOW", outcome: "deny", reason: `${f.detail}: a credential read and network traffic in one command is a data flow out` });
        break;
      case "canary_read":
        // Allowed on purpose (the content is fake, and blocking would show which file is the decoy); the state
        // events and the alert are what this rule is for.
        hits.push({ rule: "FW-CANARY-READ", outcome: "allow", reason: `${f.detail}: a tripwire alert is raised and this session is now untrusted` });
        break;
      case "invisible_unicode":
        hits.push({ rule: "FW-HIDDEN-TEXT", outcome: "deny", reason: f.detail });
        break;
      case "destroy_root":
        hits.push({ rule: "FW-DESTROY-ROOT", outcome: "deny", reason: catastropheReason(f.detail, /\bmay\b/.test(f.detail) ? "diskTool" : /\/dev\/|disk|partition/.test(f.detail) ? "disk" : "root") });
        break;
      case "catastrophic":
        // Denied in every session, mode and policy, approval or not: the reason says why and what to do instead.
        hits.push({ rule: "FW-CATASTROPHIC", outcome: "deny", reason: f.detail });
        break;
      case "bypass_flags":
        hits.push({ rule: "FW-AGENT-BYPASS", outcome: "deny", reason: f.detail });
        break;
      case "hook_disable":
        hits.push({ rule: "FW-TAMPER", outcome: "deny", reason: f.detail });
        break;
      case "blocked_tool":
        hits.push({ rule: "FW-BLOCKED-TOOL", outcome: "deny", reason: f.detail });
        break;
      case "network_refused":
        hits.push({ rule: "FW-NET-REFUSED", outcome: "deny", reason: f.detail });
        break;
      case "remote_code_pipe":
        hits.push({ rule: "FW-REMOTE-CODE", outcome: trusted ? "approve" : "deny", reason: f.detail });
        break;
      case "obfuscated_exec":
        hits.push({ rule: "FW-OBFUSCATED", outcome: trusted ? "approve" : "deny", reason: f.detail });
        break;
      case "credential_store_read":
      case "recursive_home_sweep":
        hits.push({ rule: "FW-CREDENTIAL-READ", outcome: "approve", reason: `${f.detail}; no ordinary coding task needs this` });
        break;
      case "secret_env_in_egress": {
        const hosts = egressEffects(effects).map((e) => e.host).filter((h): h is string => h !== undefined);
        const allowed = hosts.length > 0 && hosts.every((h) => hostInList(h, cfg.dataAllowHosts.credential) || hostInList(h, cfg.sendAllowHosts));
        if (!allowed) hits.push({ rule: "FW-SECRET-VARIABLE", outcome: "approve", reason: `${f.detail}, which is not a service this variable is known to belong to` });
        break;
      }
      case "raw_ip":
        hits.push({ rule: "FW-RAW-IP", outcome: "approve", reason: `${f.detail}, not a named service` });
        break;
      case "symlink_to_protected":
        hits.push({ rule: "FW-SYMLINK", outcome: "approve", reason: f.detail });
        break;
      case "unresolvable_command":
      case "unresolvable_write_target":
      case "parse_failure":
      case "too_large":
      case "env_injection":
        // The analyzer could not see the whole action: treat it as the riskiest thing it could be.
        hits.push({ rule: "FW-UNCLASSIFIABLE", outcome: trusted ? "approve" : "approve", reason: f.detail });
        break;
      case "pii_in_payload":
      case "secret_in_payload":
      case "secret_fingerprint_in_payload":
      case "url_data_capacity":
      case "insecure_scheme":
      case "policy_error":
        break;
    }
  }
}

const stringSizeM = memoLast((payload: string): { longest: number; total: number } => stringSize(payload));

/**
 * The longest string value and the total length of all string values in a JSON payload (the payload itself
 * if it is not JSON). The total matters: many short fields carry as much as one long one.
 */
function stringSize(payload: string): { longest: number; total: number } {
  try {
    let max = 0;
    let total = 0;
    const walk = (v: unknown): void => {
      if (typeof v === "string") {
        max = Math.max(max, v.length);
        total += v.length;
      } else if (Array.isArray(v)) v.forEach(walk);
      else if (typeof v === "object" && v !== null) Object.values(v).forEach(walk);
    };
    walk(JSON.parse(payload));
    return { longest: max, total };
  } catch {
    return { longest: payload.length, total: payload.length };
  }
}

function inWorkspace(target: string, ctx: Context): boolean {
  return ctx.workspaceRoots.some((r) => isUnder(target, r, ctx.caseInsensitive));
}

/**
 * A write to a file that makes code run later. Outside the workspace it needs a person in any
 * session. Inside it, a trusted session may write it unless the change adds a code-running capability
 * (FW-AUTORUN, from the content checks in autorun.ts); an untrusted session needs a person, and git
 * hooks, editor auto-run forms and dev-container lifecycle commands are held as proposals.
 */
function persistenceRules(e: Effect, trusted: boolean, why: string, cfg: FirewallConfig, ctx: Context, hits: RuleHit[]): void {
  const tags = e.tags ?? [];
  const tag = tags.find((t) => t.startsWith("persist:"))?.slice(8);
  const checked = tags.includes("autorun-checked");
  const removed = tags.includes("removed");
  const adds = tags.filter((t) => t.startsWith("autorun:")).map((t) => t.slice(8));
  const pol = cfg.persistence ?? defaultPersistence();
  // A shell write (echo >> .git/hooks/x, cp x .vscode/tasks.json): the result cannot be seen.
  const body = tag !== "git-hook" || isHookBody(e.target);
  const unknown = !checked && !removed && ((tag === "git-hook" && body) || tag === "editor-task");
  const addsWhat = adds.length > 0 ? `: the change adds ${adds.slice(0, 3).join("; ")}` : "";
  if (!trusted) {
    const holdTag = tag !== undefined && (pol.holdWhenUntrusted as string[]).includes(tag) && !removed;
    const autoRunForm = tags.includes("autorun-form") || (tag === "editor-task" && unknown);
    // Hook bodies are held whatever they contain; editor tasks, dev containers and git's own config only in their auto-run forms.
    const held = holdTag && ((tag !== "editor-task" && tag !== "devcontainer" && body) || autoRunForm);
    if (held) hits.push({ rule: "FW-PERSISTENCE-HELD", outcome: "hold", reason: `${e.detail}${addsWhat}.${why} The change is kept as a proposal for you to review, like a change to the agent's instructions.` });
    else hits.push({ rule: "FW-PERSISTENCE", outcome: "approve", reason: `${e.detail}${addsWhat}.${why}` });
    if (adds.length > 0) hits.push({ rule: "FW-AUTORUN", outcome: "approve", reason: `${e.detail}${addsWhat}` });
    return;
  }
  if (!inWorkspace(e.target, ctx)) {
    hits.push({ rule: "FW-PERSISTENCE", outcome: "approve", reason: `${e.detail}, outside the workspace${addsWhat}` });
    if (adds.length > 0) hits.push({ rule: "FW-AUTORUN", outcome: "approve", reason: `${e.detail}${addsWhat}` });
    return;
  }
  if (!pol.trustedContentChecks) return;
  if (adds.length > 0) hits.push({ rule: "FW-AUTORUN", outcome: "approve", reason: `${e.detail}${addsWhat}, which ordinary edits rarely do` });
  else if (unknown) hits.push({ rule: "FW-AUTORUN", outcome: "approve", reason: `${e.detail}, and the firewall cannot see the content this leaves (a shell write), so it assumes the change makes code run; use the Write or Edit tool to have the change checked` });
}

/** Destinations whose sends FW-SECRET-FILE-PUBLISH judges instead (a push or a publish carries files, not the session's memory). */
/**
 * Explicit destination ids only (a named git remote, a GitHub repository, a tool's package registry), never a
 * URL: https://x.example/upload/registry is an ordinary send.
 */
const PUBLISH_DESTINATION = /^git-remote:[^/:]+$|^github:[a-z0-9-]+\/[a-z0-9._-]+$|^[a-z0-9][a-z0-9_-]*:registry$/;

/**
 * FW-CREDENTIAL-FLOW: the session read a credential earlier, and this sends data to a host the person has not
 * allowed. The exact value leaving is denied by FW-DLP-SEEN-SECRET; this covers the forms the firewall cannot
 * recognise (encrypted, split, rewritten), in any session.
 */
function credentialFlow(e: Effect, state: SessionState, cfg: FirewallConfig, hits: RuleHit[], mcpServer?: string): void {
  const reads = state.credentialReads ?? [];
  if (reads.length === 0) return;
  if (PUBLISH_DESTINATION.test(e.destination ?? e.target)) return;
  if (e.host !== undefined && (hostInList(e.host, cfg.sendAllowHosts) || hostInList(e.host, cfg.dataAllowHosts.credential))) return;
  // An MCP server the person trusts in their policy (results "trusted", which a project file cannot set), or
  // one allowed to receive credentials (dataAllowHosts.credential "mcp:<server>").
  const servers = [...new Set([...(e.tags ?? []).filter((t) => t.startsWith("mcp-server:")).map((t) => t.slice(11)), ...(mcpServer !== undefined ? [mcpServer] : [])])];
  if (servers.length > 0 && servers.every((s) => matchServerEntry(cfg.mcpServers, s)?.results === "trusted" || cfg.dataAllowHosts.credential.includes(`mcp:${s}`) || cfg.sendAllowHosts.includes(`mcp:${s}`))) return;
  hits.push({ rule: "FW-CREDENTIAL-FLOW", outcome: "approve", reason: `${e.detail}: earlier in this session the agent read credentials (${reads.slice(-2).join("; ")}), and this sends data off this machine, so check it does not carry them` });
}

function effectRules(effects: readonly Effect[], state: SessionState, cfg: FirewallConfig, ctx: Context, hits: RuleHit[], mcpServer?: string): void {
  const trusted = !state.tainted;
  const why = trusted ? "" : ` This session has read outside content (${state.taintSources.slice(-3).join("; ")}), so it may be acting on someone else's instructions.`;
  for (const e of effects) {
    const tags = e.tags ?? [];
    switch (e.cls) {
      case "firewall_tamper":
        hits.push({ rule: "FW-TAMPER", outcome: "deny", reason: `${e.detail}: the agent may never change the firewall` });
        break;
      case "write_protected":
        if (!trusted) hits.push({ rule: "FW-INSTRUCTIONS-HELD", outcome: "hold", reason: `${e.detail}.${why} The change is kept as a proposal for you to review.` });
        else if (tags.includes("settings")) hits.push({ rule: "FW-AGENT-SETTINGS", outcome: "approve", reason: `${e.detail}: these files can make code run in every future session` });
        else if (!cfg.allowInstructionWritesWhenTrusted) hits.push({ rule: "FW-INSTRUCTIONS", outcome: "approve", reason: e.detail });
        break;
      case "write_persistence":
        persistenceRules(e, trusted, why, cfg, ctx, hits);
        break;
      case "write_outside_workspace":
        if (!trusted) hits.push({ rule: "FW-OUTSIDE-WRITE", outcome: "approve", reason: `${e.detail}.${why}` });
        break;
      case "destructive":
        hits.push({ rule: "FW-DESTRUCTIVE", outcome: "approve", reason: `${e.detail}: this destroys data or infrastructure.${why}` });
        break;
      case "privilege":
        hits.push({ rule: "FW-PRIVILEGE", outcome: "approve", reason: `${e.detail}.${why}` });
        break;
      case "agent_spawn":
        if (!trusted && tags.includes("spawn-session")) {
          // R4: the person sees every word of the prompt here; the task chip shows only what the agent chose.
          hits.push({ rule: "FW-AGENT-SPAWN", outcome: "approve", reason: `${e.detail}. The new session would start trusted with this prompt, which the task chip does not show:\n----- prompt (${(e.proposal ?? "").length} characters) -----\n${safeText(e.proposal ?? "")}\n----- end of prompt -----\n${why.trim()}` });
        } else if (!trusted) hits.push({ rule: "FW-AGENT-SPAWN", outcome: "approve", reason: `${e.detail}.${why}` });
        break;
      case "execute_untrusted":
        if (tags.includes("manifest")) hits.push({ rule: "FW-TAINTED-MANIFEST", outcome: "approve", reason: `${e.detail}. Check the change before it runs.${why}` });
        else hits.push({ rule: "FW-UNTRUSTED-CODE", outcome: trusted ? "approve" : "deny", reason: `${e.detail}.${why}` });
        break;
      case "execute_opaque":
        if (!trusted) hits.push({ rule: tags.includes("install") ? "FW-INSTALL" : "FW-OPAQUE-CODE", outcome: "approve", reason: `${e.detail}: the firewall cannot see what this code will do.${why}` });
        break;
      case "execute":
        if (!trusted && tags.includes("install")) hits.push({ rule: "FW-INSTALL", outcome: "approve", reason: `${e.detail}.${why}` });
        break;
      case "egress_send": {
        if (state.canaryTripped.size > 0 || state.canarySeen.size > 0) {
          hits.push({ rule: "FW-CANARY-READ", outcome: "approve", reason: `${e.detail}: this session touched a decoy file you planted, so something other than the task may be steering it; every send needs a person (even to an allowed host)` });
        }
        if (state.secretPaths.size > 0 && /^git-remote:|^github:|^gh:|registry$/.test(e.destination ?? e.target)) {
          hits.push({ rule: "FW-SECRET-FILE-PUBLISH", outcome: "approve", reason: `${e.detail}: earlier in this session credentials were copied into ${[...state.secretPaths].slice(0, 3).join(", ")}, which this could publish` });
        }
        if (!trusted) {
          const allowed = e.host !== undefined && hostInList(e.host, cfg.sendAllowHosts);
          if (!allowed) hits.push({ rule: tags.includes("message") ? "FW-MESSAGE" : "FW-SEND", outcome: "approve", reason: `${e.detail}: data leaves this machine.${why}` });
        }
        credentialFlow(e, state, cfg, hits, mcpServer);
        break;
      }
      case "egress_fetch": {
        if (tags.includes("search") || tags.includes("mcp-args")) {
          // The arguments of a search or an MCP call leave the machine. Once the session is untrusted and
          // holds private data, handing text to a third-party service (or a long payload to any server)
          // is a send and needs a person, exactly like any other egress.
          const thirdParty = tags.includes("third-party") || tags.includes("search");
          const size = stringSizeM(e.payload ?? "");
          const carries = size.longest >= 80 || size.total >= 200;
          // R15: after a decoy was touched, every send needs a person, and these arguments are sent.
          if (state.canaryTripped.size > 0 || state.canarySeen.size > 0) {
            hits.push({ rule: "FW-CANARY-READ", outcome: "approve", reason: `${e.detail}: this session touched a decoy file you planted, so something other than the task may be steering it; every send needs a person, including the arguments of a search or an MCP call` });
          }
          if (!trusted && state.sensitive && (thirdParty || carries)) {
            hits.push({ rule: "FW-SEND-ARGS", outcome: "approve", reason: `${e.detail}: this session has read private data (${state.sensitiveSources.slice(-2).join("; ")}) and outside content, and the arguments leave the machine.${why}` });
          }
          break;
        }
        if (!trusted) {
          const host = e.host;
          const allowListed = host !== undefined && hostInList(host, cfg.fetchAllowHosts);
          const named = (host !== undefined && [...state.userDestinations].some((d) => hostMatches(host, d))) || (e.destination !== undefined && state.userDestinations.has(e.destination.toLowerCase()));
          const parsed = parseUrlLike(e.target);
          const carries = parsed !== null && urlCarriesData(parsed);
          if (carries && !allowListed) hits.push({ rule: "FW-FETCH-DATA", outcome: "approve", reason: `${e.detail}: the address itself could carry data out.${why}` });
          else if (!allowListed && !named) hits.push({ rule: "FW-FETCH", outcome: "approve", reason: `${e.detail}, a destination you have not named and that is not on the allowlist.${why}` });
        }
        // An address that can carry data is a send too, once the session holds credentials.
        if (!(e.host !== undefined && hostInList(e.host, cfg.fetchAllowHosts))) {
          const parsed = parseUrlLike(e.target);
          if (parsed !== null && urlCarriesData(parsed)) credentialFlow(e, state, cfg, hits, mcpServer);
        }
        break;
      }
      case "unknown":
        // R2: in any session (the README: a brand-new tool is sent to a person). Its result taints (classify).
        hits.push({ rule: "FW-UNKNOWN-TOOL", outcome: "approve", reason: trusted ? `${e.detail}: it could do anything, and what it returns is treated as outside content` : `${e.detail}.${why}` });
        break;
      case "read_secret":
      case "read_external":
      case "read_local_workspace":
      case "write_workspace":
        break;
    }
  }
}

/** Path segments of test data and examples: secrets there are fake, so reading them is not a credential read. */
/**
 * File names that say the secret in them is not real (id_rsa.fixture, fake.pem, dummy-credentials.json,
 * .env.mock). Directory names do not count: tests/.env and examples/app/.env often hold real keys.
 */
const FIXTURE_NAME = /(?:^|[._-])(?:examples?|samples?|templates?|dist|fixtures?|fakes?|dummy|mocks?|stubs?)(?:$|[._-])/i;

/**
 * Whether an effect reads a credential, for FW-CREDENTIAL-FLOW, and how to name it. Not counted: secret
 * environment variables (used to authenticate, or listed by env: FW-SECRET-VARIABLE and the output's
 * fingerprints cover those), decoys (FW-CANARY-READ), and secret files in the workspace whose own name says
 * they are fixtures. The name is checked on the path as given and on its real path, and a credential store is
 * never exempt, so a fixture-named link to ~/.aws/credentials still counts.
 */
function credentialReadSource(e: Effect, ctx: Context): string | null {
  if (e.cls !== "read_secret") return null;
  const tags = e.tags ?? [];
  if (tags.includes("env-var") || tags.includes("bulk-env") || tags.includes("canary") || e.target.startsWith("$")) return null;
  if (e.target.startsWith("/") && e.detail.startsWith("read the secret file ") && fixtureFile(e.target, ctx)) return null;
  return e.detail.slice(0, 200);
}

function fixtureFile(path: string, ctx: Context): boolean {
  let real = path;
  if (ctx.realpath !== undefined) {
    try {
      real = ctx.realpath(path);
    } catch {
      return false;
    }
  }
  const named = (p: string): boolean => FIXTURE_NAME.test(p.slice(p.lastIndexOf("/") + 1));
  const inside = (p: string): boolean => ctx.workspaceRoots.some((r) => isUnder(p, r, ctx.caseInsensitive));
  return named(path) && named(real) && inside(path) && inside(real);
}

/**
 * State events in the order they were added, each once (equal as JSON). A set of the serialized events, so an add
 * costs one lookup: scanning the list for every add was quadratic in a command with thousands of distinct effects
 * (`cat` of 8,000 files outside the workspace took 22 s).
 */
function eventList(): { ev: StateEvent[]; add: (e: StateEvent) => void } {
  const ev: StateEvent[] = [];
  const seen = new Set<string>();
  return {
    ev,
    add: (e) => {
      const key = JSON.stringify(e);
      if (seen.has(key)) return;
      seen.add(key);
      ev.push(e);
    },
  };
}

/** The state changes an allowed (or asked) action records: they only ever make the session stricter. (The tripwire's are recorded for every verdict: tripwireEvents.) */
function eventsFor(effects: readonly Effect[], state: SessionState, ctx: Context): StateEvent[] {
  const { ev, add } = eventList();
  for (const e of effects) {
    if (e.taints === true) add({ type: "taint", source: e.detail.slice(0, 200) });
    if (e.private === true || e.cls === "read_secret") add({ type: "sensitive", source: e.detail.slice(0, 200) });
    for (const t of e.tags ?? []) if (t.startsWith("canary:")) add({ type: "canary_tripped", id: t.slice(7) });
    for (const path of downloadsOf(e)) add({ type: "downloaded", path });
    // A file written after outside content, an instruction or settings file included (write_protected, which gets
    // here once a person approved the held proposal): I1 made more names protected (agents.md outside the workspace
    // on Linux), and a write there must keep the record an ordinary write would have left.
    if (state.tainted && (e.cls === "write_workspace" || e.cls === "write_outside_workspace" || e.cls === "write_persistence" || e.cls === "write_protected") && e.target.startsWith("/")) add({ type: "tainted_write", path: e.target });
  }
  for (const e of effects) {
    const source = credentialReadSource(e, ctx);
    if (source !== null) add({ type: "credential_read", source });
  }
  // Credentials written to a file in the same command (printenv > out.txt, cat ~/.aws/credentials > x): the file is now a secret.
  // A secret variable used to authenticate a request (curl -H "Bearer $TOKEN" ... > out.json) does not put the secret in the output.
  const hasEgress = effects.some((e) => e.cls === "egress_send" || e.cls === "egress_fetch");
  const readsSecret = effects.some((e) => e.cls === "read_secret" && !(hasEgress && (e.tags ?? []).includes("env-var")));
  // A file written with a secret this session saw (Read .env, then Write it elsewhere) is a secret too, and
  // so is one written with a value stored in the vault (see the vault). An instruction or settings file too
  // (write_protected): I1 made more names protected (agents.md outside the workspace on Linux), and a write
  // there must keep the record an ordinary write would have left.
  const vaultPrints = vaultFingerprints(ctx.vault);
  for (const e of effects) {
    if ((e.cls === "write_workspace" || e.cls === "write_outside_workspace" || e.cls === "write_protected") && e.proposal !== undefined && e.target.startsWith("/")) {
      if (findSecrets(e.proposal).length > 0 || (state.fingerprints.size > 0 && containsFingerprint(e.proposal, state.fingerprints)) || (vaultPrints.length > 0 && containsFingerprint(e.proposal, vaultPrints))) add({ type: "secret_path", path: e.target });
    }
  }
  if (readsSecret) {
    for (const e of effects) {
      if ((e.cls === "write_workspace" || e.cls === "write_outside_workspace" || e.cls === "write_persistence" || e.cls === "write_protected") && e.target.startsWith("/") && e.download === undefined) add({ type: "secret_path", path: e.target });
    }
  }
  return ev;
}

/**
 * R1: the tripwire's state changes, recorded whatever the verdict. A decoy touched by an action that is
 * held, queued or denied is as much a signal as one that ran (more: a credential sweep with no one
 * watching, an exfiltration attempt), so the session turns untrusted and sensitive and the decoy is
 * marked tripped. A decoy's value in outbound data means the agent holds it: the decoy is marked seen.
 */
export function tripwireEvents(effects: readonly Effect[], ctx: Context): StateEvent[] {
  const { ev, add } = eventList();
  for (const e of effects) {
    const ids = (e.tags ?? []).filter((t) => t.startsWith("canary:")).map((t) => t.slice(7));
    if (ids.length === 0) continue;
    add({ type: "taint", source: e.detail.slice(0, 200) });
    add({ type: "sensitive", source: e.detail.slice(0, 200) });
    for (const id of ids) add({ type: "canary_tripped", id });
  }
  const idx = ctx.canaries;
  if (idx !== undefined) {
    for (const e of egressEffects(effects)) {
      const payload = e.payload ?? "";
      if (!carriesCanaryM(payload, idx)) continue;
      const source = `tried to send the value of a decoy file you planted (${e.detail})`.slice(0, 200);
      add({ type: "taint", source });
      add({ type: "sensitive", source });
      for (const id of canaryIdsInM(payload, idx)) add({ type: "canary_seen", id });
    }
  }
  return ev;
}

function primary(effects: readonly Effect[], hits: readonly RuleHit[]): Decision["primaryClass"] {
  const order: Effect["cls"][] = ["firewall_tamper", "write_protected", "destructive", "egress_send", "read_secret", "execute_untrusted", "write_persistence", "privilege", "agent_spawn", "execute_opaque", "egress_fetch", "write_outside_workspace", "unknown", "execute", "read_external", "write_workspace", "read_local_workspace"];
  void hits;
  for (const cls of order) if (effects.some((e) => e.cls === cls)) return cls;
  return "none";
}

export function evaluate(input: DecideInput): { hits: RuleHit[]; effects: Effect[]; findings: Finding[]; scope: ScopeHit[]; budget?: BudgetOutcome; caps?: CapOutcome; vault?: Decision["vault"] } {
  const { action, state, config, ctx } = input;
  const c = classifyAction(action, ctx, config, state);
  const hits: RuleHit[] = [];
  const trusted = !state.tainted;
  dataRules(c.effects, state, config, ctx, hits);
  findingRules(c.findings, trusted, c.effects, config, hits);
  effectRules(c.effects, state, config, ctx, hits, parseMcpTool(action.tool)?.server);
  knownHostRules(action, c.effects, state, config, ctx, hits);
  hits.push(...packageRules(c));
  hits.push(...outsideCommandRules(action, c, state, config));
  // References in positions that leave the machine (no reference: nothing changes).
  const vault = vaultRules(action, c.effects, state, config, ctx, hits);
  if (input.policyError !== undefined && !READ_ONLY_TOOLS.has(action.tool)) {
    hits.push({ rule: "FW-POLICY-ERROR", outcome: "approve", reason: `the firewall's policy file is invalid (${input.policyError}), so it is not applied and every action other than a read needs a person` });
  }
  // The task scope's hits are part of the verdict only in enforce mode; in log mode decide() only reports them.
  const scope = scopeHits(c.effects, state, config, ctx);
  if (taskScopePolicy(config).mode === "enforce") hits.push(...scope);
  const v = vault !== undefined ? { vault } : {};
  const budget = input.budgets === undefined ? undefined : budgetRules({ action, actionHash: counterKey(action), effects: c.effects, state, config, view: input.budgets, readOnlyTool: READ_ONLY_TOOLS.has(action.tool) });
  if (budget !== undefined) hits.push(...budget.hits);
  const caps = input.caps === undefined ? undefined : actionCaps(input, c.effects);
  if (caps !== undefined) hits.push(...caps.hits);
  return { hits, effects: c.effects, findings: c.findings, scope, ...(budget !== undefined ? { budget } : {}), ...(caps !== undefined ? { caps } : {}), ...v };
}

/** The spending limits for one action (its bytes measured as the byte budgets measure them). */
export function actionCaps(input: DecideInput, effects: readonly Effect[], hash = counterKey(input.action)): CapOutcome | undefined {
  if (input.caps === undefined) return undefined;
  const bytes = measureUsage(input.action, effects, input.config).usage.find((u) => u.key === "bytes:*")?.amount ?? 0;
  return capRules({ policy: capPolicy(input.config), view: input.caps, actionHash: hash, bytes, ...(input.usage !== undefined ? { usage: input.usage } : {}), interactive: input.ctx.interactive, ...(input.countCall === false ? { countCall: false } : {}) });
}

/**
 * V37: whether a stored approval is the kind that lets this outcome run. Any approval covers "approve"; a "hold"
 * (kept as a proposal) is covered only by an approval given on a proposal, after the person saw its diff. An
 * approval given while the session was trusted (an approval item, in the terminal or on a phone) never
 * lets through the same change once it is held as a proposal.
 */
function approvalKind(outcome: Outcome, state: DecideInput["state"], hash: string): boolean {
  if (!state.approvals.has(hash)) return false;
  if (outcome === "approve") return true;
  return outcome === "hold" && state.proposalApprovals?.has(hash) === true;
}

/**
 * I2/I9: why a stored approval of the right kind still does not apply to these hits here, or null when it does:
 * a rule asking now (the hits that give the outcome, as a held item lists them) that the person was not shown
 * when they approved, or another working directory or project than it was signed for (see approvalRefusal).
 */
function approvalRefused(input: DecideInput, hash: string, outcome: Outcome, hits: readonly RuleHit[]): string | null {
  const asking = collapseRules(hits.filter((h) => h.outcome === outcome).map((h) => ({ rule: h.rule, reason: h.reason }))).rules;
  return approvalRefusal(input.state, hash, asking, input.approvalWhere);
}

/** Whether a stored approval lets this outcome run: the right kind, and still applicable to `judged` (approvalRefused). */
function approvalCovers(outcome: Outcome, input: DecideInput, hash: string, judged: readonly RuleHit[]): boolean {
  return approvalKind(outcome, input.state, hash) && approvalRefused(input, hash, outcome, judged) === null;
}

/**
 * The verdict a set of hits gives (the same steps as decide(), without recording anything). `judged`: the hits a
 * stored approval is checked against, all of them unless said otherwise.
 */
function verdictOf(hits: readonly RuleHit[], input: DecideInput, hash: string, judged: readonly RuleHit[] = hits): Verdict {
  let outcome: Outcome = hits.reduce<Outcome>((m, h) => (RANK[h.outcome] > RANK[m] ? h.outcome : m), "allow");
  if (approvalCovers(outcome, input, hash, judged)) outcome = "allow";
  return outcome === "deny" ? "deny" : outcome === "hold" ? "queue" : outcome === "approve" ? (input.ctx.interactive ? "ask" : "queue") : "allow";
}

/** What the scope did, or in log mode would have done, to this decision. */
function scopeEffect(scope: readonly ScopeHit[], hits: readonly RuleHit[], input: DecideInput, hash: string): Decision["scope"] {
  if (scope.length === 0) return undefined;
  const enforce = taskScopePolicy(input.config).mode === "enforce";
  const base = enforce ? hits.filter((h) => !scope.includes(h as ScopeHit)) : hits;
  const baseVerdict = verdictOf(base, input, hash);
  // I2: in log mode the scope's rules were never listed, so no approval signed them; enforced, the held item would
  // have listed them and its approval signed them. What enforcing would do checks the approval against the rest.
  const verdict = verdictOf([...base, ...scope], input, hash, enforce ? undefined : base);
  return { mode: enforce ? "enforce" : "log", applied: enforce, verdict, baseVerdict, changes: verdict !== baseVerdict, reasons: scope.map((h) => h.reason), widen: scope.flatMap((h) => (h.widen !== undefined ? [h.widen] : [])) };
}

/** The most entries a decision's rules (and reasons) list holds, and the most for one rule id. */
export const MAX_RULE_ENTRIES = 16;
export const MAX_ENTRIES_PER_RULE = 3;

/**
 * SELF-016 (log bloat): a decision named FW-TAINTED-MANIFEST 265 times when one npm run read many
 * downloaded files. Identical (rule, reason) pairs are dropped; one rule id keeps its first few distinct
 * reasons (two fetched hosts both show) and its last kept reason counts the rest ("and 262 more like
 * it"); the list is capped. Rules and reasons stay parallel. The effects keep every target.
 */
export function collapseRules(pairs: readonly { rule: string; reason: string }[]): { rules: string[]; reasons: string[] } {
  const rules: string[] = [];
  const reasons: string[] = [];
  const seen = new Set<string>();
  const kept = new Map<string, number[]>();
  const extra = new Map<number, number>();
  const droppedRules: string[] = [];
  for (const { rule, reason } of pairs) {
    const key = `${rule}\u0000${reason}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const at = kept.get(rule) ?? [];
    if (at.length >= MAX_ENTRIES_PER_RULE || (at.length > 0 && rules.length >= MAX_RULE_ENTRIES)) {
      const last = at[at.length - 1] as number;
      extra.set(last, (extra.get(last) ?? 0) + 1);
      continue;
    }
    if (rules.length >= MAX_RULE_ENTRIES) {
      if (!droppedRules.includes(rule)) droppedRules.push(rule);
      continue;
    }
    at.push(rules.length);
    kept.set(rule, at);
    rules.push(rule);
    reasons.push(reason);
  }
  for (const [i, n] of extra) reasons[i] = `${reasons[i] as string} (and ${n} more like it)`;
  if (droppedRules.length > 0 && reasons.length > 0) {
    const i = reasons.length - 1;
    reasons[i] = `${reasons[i] as string} (and more rules: ${droppedRules.slice(0, 5).join(", ")}${droppedRules.length > 5 ? ", ..." : ""})`;
  }
  return { rules, reasons };
}

/** The decision for an action. `interactive` comes from the context; unattended sessions queue instead of asking. */
export function decide(input: DecideInput): Decision {
  // memoByInput remembers only inside a decision (src/engine/payload-memo.ts).
  return inDecision(() => decideOnce(input));
}

function decideOnce(input: DecideInput): Decision {
  // FZ14: arguments nested past what any tool takes are not judged (recursive walks would overflow); the
  // callers' failure policies treat this as the input's doing and never let the call through.
  if (nestedDeeperThan(input.action.input, MAX_INPUT_DEPTH)) throw new InputTooDeep();
  newDecisionMemo();
  // The kill switch comes before every other rule (and after the depth bound, as stopped() classifies the action).
  const active = input.stop?.active ?? null;
  if (active !== null) return stopped(input, stoppedReason(active, input.sessionId ?? "<session>"));
  const { hits, effects, findings, scope, budget, caps, vault } = evaluate(input);
  const hash = actionHash(input.action);
  // I9: approvals are stored under the action bound to its scope (the same as `hash` when there is none).
  const akey = approvalKey(hash, input.approvalScope);
  // The person's "never" for this exact action in this project only tightens: it applies in every session.
  const key = input.learned !== undefined ? learnKey(input.action) : undefined;
  const never = key !== undefined ? input.learned?.nevers.get(key) : undefined;
  if (never !== undefined) hits.push({ rule: "FW-LEARNED-DENY", outcome: "deny", reason: `you chose "never" for this exact action in this project (entry ${never})` });
  const scoped = scopeEffect(scope, hits, input, akey);
  hits.sort((a, b) => RANK[b.outcome] - RANK[a.outcome]);
  let outcome: Outcome = hits[0]?.outcome ?? "allow";
  const events: StateEvent[] = [];
  // A person approved this exact action once (through the queue): it may run now, while no rule they were not
  // shown asks about it and it is the same place (I2, I9). Otherwise the approval stays unused and the action asks again.
  const kindOk = approvalKind(outcome, input.state, akey);
  const refused = kindOk ? approvalRefused(input, akey, outcome, hits) : null;
  if (kindOk && refused === null) {
    events.push({ type: "approval_used", actionHash: akey });
    hits.unshift({ rule: "FW-APPROVED", outcome: "allow", reason: `approved once by a person (queue item ${input.state.approvals.get(akey) ?? ""})` });
    outcome = "allow";
  } else if (outcome === "approve" && key !== undefined) {
    // A learned project allow: the stored choice never decides alone; every guarantee is checked again now
    // (low-risk rules only, nothing else the action does, a session with no outside content or private data).
    const identity = input.learned?.identity;
    const id = identity !== undefined && identity !== null ? input.learned?.allows.get(allowKey(key, identity)) : undefined;
    if (id !== undefined && learnEligibility({ rules: hits.map((h) => h.rule), effects, findings, state: input.state, policyError: input.policyError, interactive: input.ctx.interactive }).eligible) {
      hits.unshift({ rule: "FW-LEARNED-ALLOW", outcome: "allow", reason: `you chose to always allow this exact action in this project (entry ${id})` });
      outcome = "allow";
    }
  }
  const toVerdict = (o: Outcome): Verdict => (o === "deny" ? "deny" : o === "hold" ? "queue" : o === "approve" ? (input.ctx.interactive ? "ask" : "queue") : "allow");
  // Watch mode: only the always-enforced core keeps its outcome; what the other rules would have done is
  // recorded (Decision.watch) and the action goes ahead, with the state events of an allowed action.
  let watch: Decision["watch"];
  if (input.watch === true && outcome !== "allow" && !hits.some((h) => h.rule === "FW-APPROVED")) {
    const enforced = hits.filter((h) => enforcedInWatch(h.rule)).reduce<Outcome>((m, h) => (RANK[h.outcome] > RANK[m] ? h.outcome : m), "allow");
    if (RANK[enforced] < RANK[outcome]) {
      const would = collapseRules(hits.filter((h) => h.outcome === outcome));
      watch = { verdict: toVerdict(outcome), rules: would.rules, reasons: would.reasons };
      outcome = enforced;
    }
  }
  const verdict: Verdict = toVerdict(outcome);
  // The behaviour monitor (FW-LOOP's stop limits): this action crosses one, so it is denied and the session stops.
  // It counts the verdict the action really got (in watch mode, after relaxing), and its stop (FW-STOPPED) is
  // never relaxed by watch mode: it returns here, after the watch step.
  // A spending limit (FW-CAP, FW-CAP-WARN) is not the agent misbehaving: a decision refused only by one (every rule
  // that gives the verdict is a cap rule) counts as allowed, as the counters count it (monitorCountedVerdict), so a
  // cap stop never also trips a kill-switch stop (which needs the passphrase to end).
  const monitorVerdict: Verdict = monitorCountedVerdict({ verdict, rules: hits.filter((h) => h.outcome === outcome).map((h) => h.rule) });
  const ck = counterKey(input.action);
  const watched = input.budgets !== undefined && budget !== undefined ? monitorCheck({ config: input.config, view: input.budgets, budget, actionHash: ck, verdict: monitorVerdict, ...(input.stop?.resumedAt !== undefined ? { sinceMs: input.stop.resumedAt } : {}) }) : null;
  if (watched !== null) {
    const base: Decision = { verdict, primaryClass: primary(effects, hits), reasons: [], rules: [], effects, findings, events: [], actionHash: hash, counterKey: ck, ...(caps !== undefined ? { caps: caps.record } : {}), ...(budget?.watch !== undefined ? { budget: { usage: [], raises: [], loopEligible: false, writes: false, watch: budget.watch } } : {}) };
    return monitorStopDecision(base, input.ctx, watched, "session", input.sessionId ?? "<session>");
  }
  if (verdict === "allow" || verdict === "ask") events.push(...eventsFor(effects, input.state, input.ctx));
  const tripped = tripwireEvents(effects, input.ctx);
  if (tripped.length > 0) {
    const have = new Set(events.map((x) => JSON.stringify(x)));
    for (const e of tripped) if (!have.has(JSON.stringify(e))) events.push(e);
  }
  const shown = collapseRules(hits.filter((h) => h.outcome === outcome || (outcome === "allow" && (h.rule === "FW-APPROVED" || h.rule === "FW-LEARNED-ALLOW"))));
  return {
    verdict,
    primaryClass: primary(effects, hits),
    reasons: shown.reasons,
    rules: shown.rules,
    effects,
    findings,
    events,
    actionHash: hash,
    counterKey: ck,
    ...(budget !== undefined ? { budget: { usage: budget.usage, raises: budget.raises, loopEligible: budget.loopEligible, writes: budget.writes, ...(budget.watch !== undefined ? { watch: budget.watch } : {}) } } : {}),
    ...(caps !== undefined ? { caps: caps.record } : {}),
    ...(scoped !== undefined ? { scope: scoped } : {}),
    ...(vault !== undefined ? { vault } : {}),
    ...(watch !== undefined ? { watch } : {}),
    ...(refused !== null && verdict !== "allow" ? { approvalIgnored: refused } : {}),
  };
}

/**
 * The action that crossed one of the behaviour monitor's limits: denied (FW-STOPPED), counted as what it was
 * (its hosts, its configuration change, a denial), with the stop for the runtime to record. `scope` "agent":
 * the agent's own counters crossed it (the library and the local API count per agent too).
 */
export function monitorStopDecision(d: Decision, ctx: Context, watched: { signal: NonNullable<Decision["stop"]>["signal"]; reason: string }, scope: "session" | "agent", target: string): Decision {
  const who = scope === "agent" ? `every session of agent ${target}` : "this session";
  const resume = scope === "agent" ? `launchsafe-firewall agent resume ${target}` : `launchsafe-firewall session resume ${target}`;
  return {
    verdict: "deny",
    primaryClass: d.primaryClass,
    reasons: [`the behaviour monitor stopped ${who}: ${watched.reason}; every later action is blocked until a person resumes it in their own terminal (${resume}, with the approval passphrase)`],
    rules: ["FW-STOPPED"],
    effects: d.effects,
    findings: d.findings,
    events: tripwireEvents(d.effects, ctx),
    actionHash: d.actionHash,
    ...(d.counterKey !== undefined ? { counterKey: d.counterKey } : {}),
    ...(d.budget?.watch !== undefined ? { budget: { usage: [], raises: [], loopEligible: false, writes: false, watch: d.budget.watch } } : {}),
    // The model was used to make the call: its tokens and cost count whatever the verdict (CapRecord.always).
    ...(d.caps !== undefined && d.caps.always.length > 0 ? { caps: usageOnly(d.caps) } : {}),
    stop: { signal: watched.signal, reason: watched.reason, scope },
  };
}

/**
 * A denial by the kill switch (FW-STOPPED): never approvable, no budget use. The action is still classified,
 * so a decoy it touches raises its alert and the log shows what was attempted.
 */
function stopped(input: DecideInput, reason: string): Decision {
  const k = classifyAction(input.action, input.ctx, input.config, input.state);
  const c = { effects: k.effects, findings: k.findings, hash: actionHash(input.action) };
  const used = stoppedUsage(input);
  return {
    verdict: "deny",
    primaryClass: primary(c.effects, []),
    reasons: [reason],
    rules: ["FW-STOPPED"],
    effects: c.effects,
    findings: c.findings,
    events: tripwireEvents(c.effects, input.ctx),
    actionHash: c.hash,
    counterKey: counterKey(input.action),
    ...(used !== undefined ? { caps: used } : {}),
  };
}

/** A cap record with only what counts whatever the verdict: the model usage reported with the call. */
export function usageOnly(r: CapRecord): CapRecord {
  return { always: [...r.always], ifRuns: [], warned: [], stopped: [] };
}

/**
 * The model usage a call the kill switch denies still reported: the model was used to make it, so its tokens
 * and cost count toward the spending limits (nothing else does: the call does not run). Undefined when there
 * is nothing to count, the caps are not checked, or the report is not valid (that call is denied anyway).
 */
export function stoppedUsage(input: Pick<DecideInput, "caps" | "usage" | "config" | "ctx">): CapRecord | undefined {
  if (input.caps === undefined || input.usage === undefined) return undefined;
  const r = capRules({ policy: capPolicy(input.config), view: input.caps, actionHash: "", bytes: 0, usage: input.usage, interactive: input.ctx.interactive }).record;
  return r.always.length > 0 ? usageOnly(r) : undefined;
}

/**
 * The spending limits of one native call that became several actions (a multi-file patch, a fetch of
 * many URLs), applied to the combined decision: the call counts once, its parts' bytes together. A stop
 * denies the whole call; a warning asks (or is noted) only when nothing more severe already applies.
 */
export function mergeCapOutcome(d: Decision, out: CapOutcome, ctx: DecideInput["ctx"]): void {
  d.caps = out.record;
  const stops = out.hits.filter((h) => h.outcome === "deny");
  if (stops.length > 0) {
    const kept = d.verdict === "deny" ? d.rules.map((rule, i) => ({ rule, reason: d.reasons[i] ?? "" })) : [];
    const shown = collapseRules([...stops.map((h) => ({ rule: h.rule, reason: h.reason })), ...kept]);
    d.verdict = "deny";
    d.rules = shown.rules;
    d.reasons = shown.reasons;
    d.events = tripwireEvents(d.effects, ctx);
    return;
  }
  for (const h of out.hits) {
    if (h.outcome === "approve" && (d.verdict === "allow" || d.verdict === "ask")) {
      if (d.verdict === "allow") {
        d.verdict = ctx.interactive ? "ask" : "queue";
        d.rules = [];
        d.reasons = [];
      }
      d.rules.push(h.rule);
      d.reasons.push(h.reason);
    } else if (h.outcome === "allow" && d.verdict === "allow") {
      d.rules.push(h.rule);
      d.reasons.push(h.reason);
    }
  }
}

