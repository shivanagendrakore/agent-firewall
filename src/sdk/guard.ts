/**
 * createGuard(): the hook pipeline (src/hook/claude.ts) for an agent the host
 * runs itself. A tool call is mapped to the engine's vocabulary and decided by
 * the same decide(), with the same state, counters and log; the host's person
 * answers an "ask" through its own callback, and a held action runs only after
 * the host approves it. The library never approves on its own
 * (docs/library.md, principle 2). Browser-safe.
 *
 * Failure policy, as the hook's: if deciding fails, read-only tools proceed
 * and everything else is denied. LG1/LR11: no decision is carried out without
 * a log entry. Events are bounded and fall back to a short entry, as the hook
 * writes them (src/engine/log-bound.ts); when the store refuses even that, an
 * allow becomes ask (a person can answer) or deny (FW-LOG-UNRECORDED), and a
 * yes whose approval entry is refused does not run. Log failures are reported
 * (GuardDecision.problems and onLogError), never swallowed.
 */

import { sha256Hex } from "../engine/bytes.js";
import { classifyAction, READ_ONLY_TOOLS } from "../engine/classify.js";
import { actionHash, approvalKey, canonicalJson, decide as engineDecide, monitorStopDecision, tripwireEvents } from "../engine/decide.js";
import { budgetPolicy, monitorCheck, type BudgetView } from "../engine/budgets.js";
import { monitorStopId, type StopState, type StopView } from "../engine/stop.js";
import { appendBoundedWith, isLogUnrecorded } from "../engine/log-bound.js";
import { InputTooDeep, isInputShapeError, MAX_INPUT_DEPTH, nestedDeeperThan, RULE_INPUT_SHAPE } from "../engine/input-depth.js";
import { afterTool, destinationsFromPrompt, programOutputOnly } from "../engine/post.js";
import { counterKey } from "../engine/learn.js";
import { SATURATED } from "../engine/outsider.js";
import { nextScope, scopeFromPrompt, taskScopePolicy } from "../engine/scope.js";
import { ruleSentence, summarizeAction } from "../engine/summary.js";
import { safeText } from "../engine/terminal.js";
import { redactSecrets } from "../engine/secrets.js";
import { defaultConfig, inUnattendedHours, mergeTrusted, POLICY_VERSION, validatePolicy } from "../policy.js";
import { vaultPolicy } from "../policy-vault.js";
import { emptyState, usedApproval } from "../engine/state.js";
import type { VaultView } from "../engine/vault-ref.js";
import type { Context, Decision, Effect, FirewallConfig, NormalizedAction, StateEvent } from "../types.js";
import { BoundedMap } from "./bounded.js";
import { memoryStore } from "./store.js";
import { toAction, withToolServers } from "./tools.js";
import type { ApprovalAnswer, Authorization, GuardDecision, GuardOptions, GuardVerdict, HeldAction, LogEntry, LogVerifyResult, ModelUsage, ResultNote, ResultOptions, SessionSnapshot, StateStore, ToolCall, UntrustedInput } from "./types.js";
import { capFailure, capFailureKeys, capPolicy, monitorCountedVerdict, usageProblem } from "../engine/caps.js";

/** Asks and last verdicts a guard remembers, at most (the oldest go first; a forgotten ask is refused as unknown). */
const MAX_ASKED = 10_000;
const MAX_VERDICTS = 100_000;

/** A tool call whose reported model usage is not valid: denied, read-only or not (it cannot be counted). */
class InvalidUsage extends Error {}

/** Spending limits on with a store that cannot count them: every call is denied, read-only or not. */
class CapsUnavailable extends Error {}

export interface Guard {
  /** This guard's session id. */
  readonly session: string;
  /** The store behind it (shared stores serve several guards). */
  readonly store: StateStore;
  /** The effective policy (defaults, the host's policy, the tools' server entries). */
  readonly config: FirewallConfig;
  /** What decide() would say now. Records nothing. */
  check(call: ToolCall): GuardDecision;
  /** Decides a call and records it (the hook's PreToolUse). */
  decide(call: ToolCall): GuardDecision;
  /** decide(), then for an "ask" the host's approval callback. Only an explicit yes allows. */
  authorize(call: ToolCall): Promise<Authorization>;
  /** Puts an "ask" this guard decided to the host's approval callback, and records the answer. */
  requestApproval(decision: GuardDecision): Promise<{ approved: boolean; by?: string; note?: string }>;
  /** Records a person's answer to an "ask" that a framework put to them (its own approval UI). */
  approveAsked(decision: GuardDecision, answer: ApprovalAnswer): { approved: boolean; by?: string; note?: string };
  /** Records what a tool that ran returned (the hook's PostToolUse); `failed` counts it toward the identical-failures spending limit. */
  recordResult(call: ToolCall, output: unknown, options?: ResultOptions): ResultNote;
  /** Untrusted content that reached the agent outside a tool call. */
  reportInput(input: UntrustedInput): void;
  /**
   * What the person typed (never model or tool text): the destinations they named and the task's scope.
   * `apply: false` records only the prompt's log entry (its hash, `applied: false`): for a prompt from a source
   * that cannot vouch it was the person's (the local API, a token without the prompt role).
   */
  recordPrompt(text: string, o?: { apply?: boolean }): void;
  /** A person approved a held action: the same call may run once. */
  approve(id: string, by?: { by?: string }): HeldAction;
  /** A person rejected a held action. */
  reject(id: string, by?: { by?: string }): HeldAction;
  /** This session's held actions waiting for review. */
  pending(): HeldAction[];
  state(): SessionSnapshot;
  /** The decision log (the store's, oldest first). */
  log(limit?: number): LogEntry[];
  verifyLog(): LogVerifyResult;
}

const VERDICT: Record<Decision["verdict"], GuardVerdict> = { allow: "allow", ask: "ask", queue: "hold", deny: "deny" };

function randomSession(): string {
  const b = new Uint8Array(12);
  globalThis.crypto.getRandomValues(b);
  return `sdk-${[...b].map((x) => x.toString(16).padStart(2, "0")).join("")}`;
}

function isFullConfig(p: unknown): p is FirewallConfig {
  return typeof p === "object" && p !== null && ((p as { version?: unknown }).version === POLICY_VERSION || (p as { version?: unknown }).version === 2) && "mcpDefault" in p && "budgets" in p && "taskScope" in p && "provenance" in p;
}

/** The policy as the user's own policy file would give it (loosening allowed: the host is the user). */
export function resolvePolicy(p: GuardOptions["policy"]): FirewallConfig {
  if (p === undefined) return defaultConfig();
  // FB4: a whole FirewallConfig is validated as strictly as a partial one (an unknown or misspelt key at
  // any depth is an error), then applied over the defaults. One built under schema 2 (v0.2) means the
  // same under 3: only the number moves.
  if (isFullConfig(p)) return mergeTrusted(defaultConfig(), validatePolicy({ ...p, version: POLICY_VERSION }, "the guard's policy"));
  return mergeTrusted(defaultConfig(), validatePolicy({ version: POLICY_VERSION, ...p }, "the guard's policy"));
}

function primaryEffect(d: Decision): Effect | undefined {
  return d.effects.find((e) => e.cls === d.primaryClass);
}

/** The text a person (and the model) reads. */
export function guardMessage(d: Decision, verdict: GuardVerdict, held: HeldAction | undefined): string {
  if (verdict === "allow") return "";
  const what = primaryEffect(d)?.detail ?? d.reasons[0] ?? "this action";
  const why = d.reasons.map((r) => `- ${r}`).join("\n");
  const rules = `(rule ${d.rules.join(", ")})`;
  // One plain sentence (the rule's own, as in the hook's messages and `explain`), then what can be done.
  const plain = `Why: ${ruleSentence(d.rules, d.reasons)}`;
  if (verdict === "deny" && d.rules[0] === "FW-STOPPED") return safeText(`LaunchSafe Agent Firewall: this session is stopped, so this was not done: ${what}.\n${why}\n${plain}\nStop and tell the person; do not try other ways to do it. ${rules}`);
  if (verdict === "deny" && d.rules.length > 0 && d.rules.every((r) => r === "FW-CAP")) return safeText(`LaunchSafe Agent Firewall stopped the agent: ${what}.\n${why}\n${plain}\nThis is a spending limit. The agent cannot raise it; tell the person, and stop. ${rules}`);
  if (verdict === "deny") return safeText(`LaunchSafe Agent Firewall blocked this: ${what}.\n${why}\n${plain}\nThis protection is always on and cannot be approved. ${rules}`);
  // I2: a person who already approved this exact action is told why it asks again.
  const earlier = d.approvalIgnored !== undefined ? `An earlier approval of this exact action was not used: ${d.approvalIgnored}.\n` : "";
  if (verdict === "hold") return safeText(`LaunchSafe Agent Firewall held this for review${held !== undefined ? ` (held action ${held.id})` : ""}: ${what}.\n${why}\n${plain}\n${earlier}It was not done. A person can approve this exact action once; then it can be tried again. ${rules}`);
  return safeText(`LaunchSafe Agent Firewall: ${what}.\n${why}\n${plain}\n${earlier}Allow it only if you asked for this. ${rules}`);
}

/**
 * Text for the decision log: credentials masked, and every URL query value replaced (tokens, signed links and
 * personal data travel in query strings), so the log never keeps what the call carried.
 */
export function logSafe(s: string): string {
  return redactSecrets(s).text.replace(/([?&][^=\s&#?]{1,100}=)[^&\s#]+/g, "$1…");
}

/** Only `true` or `{ approved: true }` is a yes. */
export function normalizeAnswer(a: unknown): { approved: boolean; by?: string; note?: string } {
  if (a === true) return { approved: true };
  if (typeof a === "object" && a !== null && (a as { approved?: unknown }).approved === true) {
    const o = a as { by?: unknown; note?: unknown };
    return { approved: true, ...(typeof o.by === "string" ? { by: o.by.slice(0, 200) } : {}), ...(typeof o.note === "string" ? { note: o.note.slice(0, 500) } : {}) };
  }
  const o = typeof a === "object" && a !== null ? (a as { by?: unknown; note?: unknown }) : {};
  return { approved: false, ...(typeof o.by === "string" ? { by: o.by.slice(0, 200) } : {}), ...(typeof o.note === "string" ? { note: o.note.slice(0, 500) } : {}) };
}

export function createGuard(options: GuardOptions = {}): Guard {
  const specs = options.tools ?? {};
  const config = withToolServers(resolvePolicy(options.policy), specs);
  const store = options.store ?? memoryStore({ ...(options.signer !== undefined ? { signer: options.signer } : {}) });
  const session = options.session ?? randomSession();
  const now = options.now ?? (() => new Date());
  const roots = options.workspace === undefined ? [] : Array.isArray(options.workspace) ? options.workspace : [options.workspace];
  const caseInsensitive = options.caseInsensitive ?? false;
  const realpath = options.fs?.realpath;
  const canaries = config.canaries.enabled ? store.canaries?.(caseInsensitive, realpath) : undefined;
  // F-e: the provenance ledger carries what an untrusted session wrote into later sessions. It hashes real files, so it
  // is used only by a guard that has file access, as the hook has; the memory store has none (nothing outlives the process).
  const ledger = options.fs !== undefined ? store.ledger : undefined;
  // The behaviour monitor also counts per agent (counters under "agent:<id>"), so a new session id does not escape it.
  const agent = options.agent ?? (session.indexOf("/") > 0 ? session.slice(0, session.indexOf("/")) : null);
  // Network traffic a middleware asks about is not the agent's tool calls: it is not counted per agent (traffic).
  const network = options.traffic === "network";
  const agentKey = agent !== null && !network ? `agent:${agent}` : null;
  /** Monitor stops this guard made that the store could not keep (no stop(), or it failed): they hold in this guard. */
  const localStops = new Map<string, StopState>();
  /** Decision ids handed out, so approveAsked can tell one of this guard's asks from a made-up object. */
  const asked = new BoundedMap<{ actionHash: string; answered: boolean }>(MAX_ASKED);
  /**
   * The last verdict this guard gave each action: a call it denied or held that a host ran anyway is not written
   * into the provenance ledger as trusted. An ask may have been answered yes in the host's own dialog, so it counts.
   */
  const lastVerdict = new BoundedMap<GuardVerdict>(MAX_VERDICTS);
  let seq = 0;
  /** I3: a policy that failed to load, as the hook passes it (FW-POLICY-ERROR), and the problem each decision carries. */
  const policyError = options.policyError !== undefined && options.policyError !== "" ? String(options.policyError).slice(0, 500) : undefined;
  const policyIn = policyError !== undefined ? { policyError } : {};
  const policyProblems = (): string[] => (policyError !== undefined ? [`LaunchSafe Firewall policy problem: ${policyError} (running with strict defaults: every risky action needs a person, FW-POLICY-ERROR)`] : []);
  /** I9: the scope an approval is bound to (cwd and workspace roots), when the host asked for it. */
  const scopeOf = (ctx: Context): string | undefined => (options.bindApprovalsToContext === true ? canonicalJson({ cwd: ctx.cwd, workspace: [...ctx.workspaceRoots] }) : undefined);
  const approvalIn = (ctx: Context): { approvalScope?: string } => {
    const s = scopeOf(ctx);
    return s !== undefined ? { approvalScope: s } : {};
  };

  /** The vault as the hook reads it for each call: the host's view, else the store's; none when the policy turns it off. */
  function vault(): VaultView | undefined {
    if (!vaultPolicy(config).enabled) return undefined;
    return options.vault ?? store.vault?.();
  }

  function context(mcpSource: string | undefined, permissionMode?: string): { ctx: Context; unattended: string | null } {
    const t = now();
    const unattended =
      options.attended === false
        ? "the host says no one is there to answer (attended: false)"
        : config.unattended
          ? "the policy sets unattended mode"
          : permissionMode !== undefined && config.unattendedPermissionModes.includes(permissionMode)
            ? `permission mode ${permissionMode}`
            : inUnattendedHours(config.unattendedHours, t)
              ? "inside the configured unattended hours"
              : null;
    const ctx: Context = {
      cwd: options.cwd ?? roots[0] ?? "/",
      workspaceRoots: roots,
      home: options.home ?? "/home/agent",
      scratchRoots: options.scratch ?? [],
      firewallHome: store.firewallHome,
      firewallInstallDir: options.installDir ?? "/__launchsafe_firewall_install__",
      interactive: unattended === null,
      caseInsensitive,
    };
    if (realpath !== undefined) ctx.realpath = realpath;
    if (options.fs?.readFile !== undefined) ctx.readFile = options.fs.readFile;
    if (options.fs?.size !== undefined) ctx.fileSize = options.fs.size;
    if (options.settingsFiles?.registered !== undefined) ctx.registeredSettings = options.settingsFiles.registered;
    if (options.settingsFiles?.agents !== undefined) ctx.agentSettings = options.settingsFiles.agents;
    if (options.settingsFiles?.sandboxProfiles !== undefined) ctx.sandboxProfiles = options.settingsFiles.sandboxProfiles;
    if (options.settingsFiles?.gatewayConfigs !== undefined) ctx.gatewayConfigs = options.settingsFiles.gatewayConfigs;
    if (mcpSource !== undefined) ctx.mcpSource = mcpSource;
    if (canaries !== undefined) ctx.canaries = canaries;
    // F-e: the hook's lookups (attachProvenance): a file's current content, if still what a session wrote, and who wrote it.
    if (ledger !== undefined) {
      const max = config.provenance.maxHashBytes;
      ctx.provenance = (abs: string) => ledger.file(abs, max, caseInsensitive);
      ctx.dirProvenance = (abs: string) => ledger.dir(abs, caseInsensitive);
    }
    if (options.packageIntel !== undefined) ctx.packageIntel = options.packageIntel;
    // Known hosts (FW-NEW-HOST): the hosts a person approved for the project, as the hook reads them.
    const known = knownHostsNow();
    if (known !== undefined) ctx.knownHosts = { approved: [...known] };
    if (options.lockfiles !== undefined) ctx.lockfiles = options.lockfiles;
    // The guard does not rewrite arguments, so ctx.vaultPaths stays unset (a reference that would
    // need substituting is refused, as on an agent the hook cannot rewrite).
    const v = vault();
    if (v !== undefined) ctx.vault = v;
    return { ctx, unattended };
  }

  function nextId(): string {
    seq += 1;
    return `${session}:${seq}`;
  }

  /** Tells the host about a log failure (default: console.warn). Never throws. */
  function reportLogError(message: string): void {
    try {
      if (options.onLogError !== undefined) options.onLogError(message);
      else globalThis.console?.warn(message);
    } catch {
      // The failure is also in the decision's problems where there is a decision.
    }
  }

  // A store without capView cannot hold the spending limits: while they are on, every call is denied (capsUnavailable).
  const capsUnavailable = capPolicy(config).enabled && typeof store.capView !== "function";
  if (capsUnavailable) reportLogError(`LaunchSafe Agent Firewall: spending limits (policy caps) are on, but the ${store.kind} store has no capView, so they cannot be counted and every call is denied; give the store capView, recordCaps and recordFailure, or set caps.enabled to false`);

  /**
   * LG1/LR11: the event bounded, or its fallback entry when the store refuses it (src/engine/log-bound.ts).
   * "unrecorded": the store refused both (or reported LogUnrecorded), so the caller fails closed. "failed":
   * any other error (I/O); the decision stands, as on the hook path (docs/limitations.md). Both are reported.
   */
  function log(event: Record<string, unknown>, err: string[]): "ok" | "failed" | "unrecorded" {
    try {
      // Network traffic (GuardOptions.traffic) is in the signed entry, so the log says which calls skipped the agent-wide counts.
      appendBoundedWith((e) => store.appendLog(e), { session, sdk: true, ...(network ? { traffic: "network" } : {}), ...event });
      return "ok";
    } catch (e) {
      const unrecorded = isLogUnrecorded(e);
      const message = `LaunchSafe Agent Firewall could not write its decision log${unrecorded ? " (neither the entry nor the short fallback entry was recorded)" : ""}: ${e instanceof Error ? e.message : String(e)}`;
      err.push(message);
      reportLogError(message);
      return unrecorded ? "unrecorded" : "failed";
    }
  }

  /**
   * LR11: a decision the store refused to record (entry and fallback) is not carried out unrecorded, as on the
   * hook path: an allow becomes ask when a person can answer, else deny; an ask carries the rule too, and its
   * yes counts only if the approval entry is recorded (approveAsked). Deny and hold already do not run.
   */
  function failClosedUnrecorded(d: Decision, attended: boolean): void {
    if (d.verdict !== "allow" && d.verdict !== "ask") return;
    const approved = d.rules.includes("FW-APPROVED");
    if (d.verdict === "allow") d.verdict = attended ? "ask" : "deny";
    d.rules = ["FW-LOG-UNRECORDED", ...d.rules.filter((r) => r !== "FW-APPROVED" && r !== "FW-LOG-UNRECORDED")];
    d.reasons = ["the decision log refused to record this decision (its entry and the short fallback entry), so it would run with no record; check the store's log (launchsafe-firewall log verify for a file store)", ...(approved ? [] : d.reasons)];
  }

  function wrap(call: ToolCall, action: NormalizedAction, d: Decision, held?: HeldAction, id = nextId()): GuardDecision {
    const verdict = VERDICT[d.verdict];
    return { id, verdict, call, action, rules: [...d.rules], reasons: [...d.reasons], message: guardMessage(d, verdict, held), actionHash: d.actionHash, primaryClass: d.primaryClass, ...(held !== undefined ? { held } : {}), engine: d };
  }

  /**
   * The person's "never" choices: the host's (GuardOptions.nevers), else the store's for the first workspace root.
   * A failure to read them throws, so the call fails closed.
   */
  const learnedNow = (): { learned?: { allows: ReadonlyMap<string, string>; nevers: ReadonlyMap<string, string>; identity: null } } => {
    const nv = options.nevers !== undefined ? options.nevers() : roots[0] !== undefined && typeof store.nevers === "function" ? store.nevers(roots[0]) : undefined;
    return nv !== undefined && nv.size > 0 ? { learned: { allows: new Map(), nevers: nv, identity: null } } : {};
  };

  /** The project's approved hosts: the host's, else the store's for the first workspace root; none when unreadable. */
  function knownHostsNow(): readonly string[] | undefined {
    try {
      if (options.knownHosts !== undefined) return options.knownHosts();
      return roots[0] !== undefined ? store.knownHosts?.(roots[0]) : undefined;
    } catch {
      return [];
    }
  }

  /** The engine's decision for a call, and what it was judged as. Throws only on a programming error. */
  function evaluate(call: ToolCall, consume = false): { action: NormalizedAction; d: Decision; ctx: Context; unattended: string | null } {
    // FZ14: checked here too, before the call's own mapper (a registry `input` function) walks the arguments.
    if (nestedDeeperThan(call.input, MAX_INPUT_DEPTH)) throw new InputTooDeep();
    const { action, mcpSource } = toAction(call, specs);
    const bad = call.usage !== undefined ? usageProblem(call.usage) : null;
    if (bad !== null) throw new InvalidUsage(`the reported model usage is not valid (${bad}), so the spending limits cannot count it`);
    const { ctx, unattended } = context(mcpSource, call.permissionMode);
    const state = store.load(session);
    const view = store.budgetView(session, state, now());
    const agentView = agentKey !== null ? store.budgetView(agentKey, state, now()) : null;
    // The kill switch: read once per call, like the hook.
    const stop = stopFor(view, agentView);
    const extra = { sessionId: session, ...(stop !== undefined ? { stop } : {}) };
    if (capsUnavailable) throw new CapsUnavailable(`the ${store.kind} store has no capView, so the spending limits cannot be counted`);
    const capsFor = (): { caps?: ReturnType<StateStore["capView"]>; usage?: ModelUsage; countCall?: false } => ({ ...(capPolicy(config).enabled ? { caps: store.capView(session, state, now()) } : {}), ...(call.usage !== undefined ? { usage: call.usage } : {}), ...(network ? { countCall: false as const } : {}) });
    let d = engineDecide({ action, state, config, ctx, budgets: view, ...extra, ...capsFor(), ...learnedNow(), ...policyIn, ...approvalIn(ctx) });
    const used = consume && store.consumeApproval !== undefined ? usedApproval(d.events) : undefined;
    if (used !== undefined) {
      // A held approval is used once, atomically: if another guard or process used it since this one loaded
      // the session, decide again without it. Either way "approval_used" is already recorded.
      const id = state.approvals.get(used);
      // I2: the engine already left the approval unused when a rule the person was not shown asks now (decide.ts
      // approvalRefused), so an "approval_used" here means it covers this decision.
      if (id === undefined || store.consumeApproval?.(session, used, id) !== true) {
        state.approvals.delete(used);
        state.proposalApprovals?.delete(used);
        d = engineDecide({ action, state, config, ctx, budgets: store.budgetView(session, state, now()), ...extra, ...capsFor(), ...learnedNow(), ...policyIn, ...approvalIn(ctx) });
      }
      d.events = d.events.filter((e) => e.type !== "approval_used");
    }
    // The agent's own counters (its sessions together): crossing a limit there stops every session of the agent.
    if (agentView !== null && agent !== null && d.stop === undefined && d.rules[0] !== "FW-STOPPED" && d.budget !== undefined) {
      const w = monitorCheck({ config, view: agentView, budget: d.budget, actionHash: d.counterKey ?? d.actionHash, verdict: monitorCountedVerdict(d), ...(stop?.resumedAt !== undefined ? { sinceMs: stop.resumedAt } : {}) });
      if (w !== null) d = monitorStopDecision(d, ctx, w, "agent", agent);
    }
    return { action, d, ctx, unattended };
  }

  /**
   * Review of FZ14: a read-only call goes ahead through an internal error only if the engine alone (an empty
   * session, this guard's policy and context, no store) allows it: a read the engine would stop stays stopped.
   */
  function judgedAllowed(call: ToolCall): boolean {
    // The kill switch blocks reads too: a session or agent known to be stopped never gets this exception.
    if (localStops.has(`session\n${session}`) || (agent !== null && localStops.has(`agent\n${agent}`))) return false;
    // Spending limits that cannot be counted deny every call, reads too.
    if (capsUnavailable) return false;
    try {
      if (typeof store.stops === "function") {
        if (store.stops(session, agent)?.active != null) return false;
      } else {
        // A store without stop records: the monitor's sentinel in the counters still stops the session (or agent).
        const s = store.budgetView(session, emptyState(), now()).stops?.() ?? [];
        if (s.some((x) => (x.scope === "session" && x.target === session) || (x.scope === "agent" && x.target === agent))) return false;
      }
    } catch {
      // The store's stop records could not be read: nothing says the session is not stopped.
      return false;
    }
    try {
      const { action, mcpSource } = toAction(call, specs);
      // A person's "never" still applies here (an exact action they refused stays refused).
      return engineDecide({ action, state: emptyState(), config, ctx: context(mcpSource, call.permissionMode).ctx, ...learnedNow(), ...policyIn }).verdict === "allow";
    } catch {
      return false;
    }
  }

  /** The stop in force: the store's records, else one this guard had to keep itself, else the counters' sentinels. */
  function stopFor(view: BudgetView, agentView: BudgetView | null): StopView | undefined {
    const fromStore = store.stops?.(session, agent);
    if (fromStore?.active !== null && fromStore?.active !== undefined) return fromStore;
    const local = localStops.get(`session\n${session}`) ?? (agent !== null ? localStops.get(`agent\n${agent}`) : undefined);
    if (local !== undefined) return { active: local, ...(fromStore?.resumedAt !== undefined ? { resumedAt: fromStore.resumedAt } : {}) };
    // A store that keeps no stop records: the sentinel the counters carry still stops the session (or agent).
    if (store.stops === undefined) {
      const s = view.stops?.().find((x) => x.scope === "session" && x.target === session) ?? agentView?.stops?.().find((x) => x.scope === "agent" && x.target === agent);
      if (s !== undefined) return { active: { id: s.id, at: s.at, by: "monitor", scope: s.scope, target: s.target, reason: s.reason, signal: s.signal } };
    }
    return fromStore;
  }

  /** Deciding failed: read-only tools proceed, everything else is denied (the hook's failure policy). */
  function failure(call: ToolCall, e: unknown, prior: readonly string[] = []): GuardDecision {
    let action: NormalizedAction = { tool: call.tool, input: call.input };
    try {
      action = toAction(call, specs).action;
    } catch {
      // Keep the call as given.
    }
    // LG1: a read-only tool is let through an internal error, but never one that left the decision unrecorded,
    // never one the input's own shape caused (FZ14: arguments nested too deep to judge), and never invalid usage.
    const shape = isInputShapeError(e);
    const readOnly = READ_ONLY_TOOLS.has(action.tool) && !isLogUnrecorded(e) && !shape && !(e instanceof InvalidUsage) && !(e instanceof CapsUnavailable) && judgedAllowed(call);
    const reason = `LaunchSafe Agent Firewall could not check this action (${e instanceof Error ? e.message : String(e)})${readOnly ? "; it only reads, so it may go ahead" : " and blocked it to be safe"}`;
    const rules = shape ? [RULE_INPUT_SHAPE] : [];
    const d: Decision = { verdict: readOnly ? "allow" : "deny", primaryClass: "none", reasons: [reason], rules, effects: [], findings: [], events: [], actionHash: "" };
    const err = [...prior];
    const logged = log({ type: "decision", tool: call.tool, verdict: d.verdict, rules, error: reason.slice(0, 300), ...(call.callId !== undefined ? { callId: call.callId } : {}) }, err);
    // LR11: the read-only allow is not carried out when even its fallback entry was refused.
    if (logged === "unrecorded") failClosedUnrecorded(d, false);
    const g = wrap(call, action, d);
    if (g.verdict !== "allow") g.message = safeText(d.reasons.join("; "));
    if (err.length > 0) g.problems = err;
    return g;
  }

  /** The engine stopped the call (deny, hold or ask), then recording it failed: it is denied, with the engine's rules. */
  function recordingFailedAfter(call: ToolCall, action: NormalizedAction, decided: Decision, e: unknown, prior: readonly string[]): GuardDecision {
    const why = `LaunchSafe Agent Firewall decided ${VERDICT[decided.verdict]} but could not record it (${e instanceof Error ? e.message : String(e)}), so it is blocked`;
    const d: Decision = { ...decided, verdict: "deny", reasons: [...decided.reasons, why], events: [] };
    const err = [...prior];
    log({ type: "decision", tool: call.tool, verdict: "deny", rules: d.rules, action: d.actionHash, error: why.slice(0, 300), ...(call.callId !== undefined ? { callId: call.callId } : {}) }, err);
    const g = wrap(call, action, d);
    g.message = safeText(`${guardMessage(decided, VERDICT[decided.verdict], undefined)}\n${why}`);
    if (err.length > 0) g.problems = err;
    return g;
  }

  function check(call: ToolCall): GuardDecision {
    try {
      const { action, d } = evaluate(call);
      const g = wrap(call, action, d);
      if (policyError !== undefined) g.problems = policyProblems();
      return g;
    } catch (e) {
      // As decide()'s failure policy (FZ14: never for an error the input's shape caused).
      const shape = isInputShapeError(e);
      const readOnly = READ_ONLY_TOOLS.has(call.tool) && !shape && !(e instanceof InvalidUsage) && !(e instanceof CapsUnavailable) && judgedAllowed(call);
      const d: Decision = { verdict: readOnly ? "allow" : "deny", primaryClass: "none", reasons: [`could not check this action: ${(e as Error).message}`], rules: shape ? [RULE_INPUT_SHAPE] : [], effects: [], findings: [], events: [], actionHash: "" };
      return wrap(call, { tool: call.tool, input: call.input }, d);
    }
  }

  function decide(call: ToolCall): GuardDecision {
    const err: string[] = policyProblems();
    let r: ReturnType<typeof evaluate>;
    try {
      r = evaluate(call, true);
    } catch (e) {
      const g = failure(call, e, err);
      // F-e: a call this guard could not check is stopped unless it only reads, so one a host runs anyway vouches for
      // nothing it left, as after the engine's own deny. Arguments refused as nested too deep are not hashed here
      // (FZ14): recordResult refuses to vouch for them on its own. Any other failure, one the input's shape caused
      // included (a stack overflow while deciding), is remembered.
      if (!(e instanceof InputTooDeep)) {
        try {
          lastVerdict.set(actionHash(g.action), g.verdict);
        } catch {
          // Not hashable: recordResult cannot look it up either, and fails closed on it.
        }
      }
      return g;
    }
    const { action, ctx, unattended } = r;
    let d = r.d;
    // budgets.stopScope "agent": a stop of the session's own counters covers every session of the agent, as on
    // the hook route (an agent the guard knows; network traffic keeps its stops to its session).
    if (d.stop !== undefined && (d.stop.scope ?? "session") === "session" && agent !== null && !network && budgetPolicy(config).stopScope === "agent") d = monitorStopDecision(d, ctx, { signal: d.stop.signal, reason: d.stop.reason }, "agent", agent);
    try {
      store.append(session, d.events);
      // F-e: what a partial write outside the workspace is about to keep (the hook's PreToolUse note). A failure only
      // loses the note: the result is then recorded as untrusted.
      if (ledger !== undefined && (d.verdict === "allow" || d.verdict === "ask")) {
        try {
          ledger.note({ session, tool: action.tool, effects: d.effects, maxHashBytes: config.provenance.maxHashBytes, caseInsensitive });
        } catch (e) {
          err.push(`LaunchSafe Agent Firewall could not note a write in its provenance ledger: ${(e as Error).message}`);
        }
      }
      let held: HeldAction | undefined;
      if (d.verdict === "queue") {
        // A held change to the agent's instructions or memory, or to a file that runs code later, is a proposal.
        const prop = d.effects.find((e) => (e.cls === "write_protected" && d.rules.includes("FW-INSTRUCTIONS-HELD")) || (e.cls === "write_persistence" && d.rules.includes("FW-PERSISTENCE-HELD")));
        const state = store.load(session);
        held = store.hold({
          session,
          tool: call.tool,
          input: call.input,
          // I9: the key the approval is stored and used under (the action's hash, bound to cwd and roots when asked).
          actionHash: approvalKey(d.actionHash, scopeOf(ctx)),
          rules: d.rules,
          reasons: d.reasons,
          kind: prop !== undefined ? "proposal" : "approval",
          ...(prop !== undefined ? { proposal: { target: prop.target, change: prop.proposal ?? JSON.stringify(action.input) } } : {}),
          cwd: ctx.cwd,
          summary: summarizeAction(action.tool, action.input, ctx.cwd, primaryEffect(d)?.detail),
          trustSources: state.taintSources.slice(-3),
          unattended: unattended !== null,
        });
        try {
          options.onHold?.(held);
        } catch (e) {
          err.push(`onHold failed: ${(e as Error).message}`);
        }
      }
      const at = now();
      const st = d.stop;
      if (st !== undefined) {
        // Named before the counters are written: their sentinel and the stop record carry the same id.
        const scope = st.scope ?? "session";
        Object.assign(st, { scope, id: monitorStopId(at, d.actionHash), target: scope === "agent" ? (agent ?? session) : session });
      }
      store.recordBudget(session, d, at);
      if (agentKey !== null) store.recordBudget(agentKey, d, at);
      if (st?.id !== undefined && st.target !== undefined) {
        // The behaviour monitor stopped this session (or agent): kept by the store (fileStore: until a person resumes
        // it); when the store cannot keep it, this guard keeps it.
        const scope = st.scope ?? "session";
        const keep = (): void => void localStops.set(`${scope}\n${st.target}`, { id: st.id as string, at: at.toISOString(), by: "monitor", scope, target: st.target as string, reason: st.reason, signal: st.signal });
        let created = true;
        if (store.stop === undefined) keep();
        else {
          try {
            created = store.stop(st.target, { signal: st.signal, reason: st.reason, scope, id: st.id }, at).created;
          } catch (e) {
            keep();
            err.push(`the stop could not be recorded (it holds in this guard and in the counters): ${(e as Error).message}`);
          }
        }
        if (created) log({ type: "stop", scope, target: st.target, by: "monitor", signal: st.signal, reason: st.reason, id: st.id }, err);
      }
      try {
        store.recordCaps?.(session, d, at);
      } catch (e) {
        // Fail closed: a call the day's counters could not count does not go ahead uncounted.
        err.push(`the spending-limit counters could not be updated: ${(e as Error).message}`);
        if (d.verdict === "allow" || d.verdict === "ask") {
          d.verdict = "deny";
          d.rules = ["FW-CAP"];
          d.reasons = [`today's spending-limit counters could not be updated (${(e as Error).message}), so this call cannot be counted and was stopped`];
        }
      }
      store.capStopped?.(session, d);
      const id = nextId();
      const logged = log(
        {
          type: "decision",
          id,
          tool: call.tool,
          ...(action.tool !== call.tool ? { judgedAs: action.tool } : {}),
          verdict: VERDICT[d.verdict],
          rules: d.rules,
          class: d.primaryClass,
          action: d.actionHash,
          ...(held !== undefined ? { held: held.id } : {}),
          ...(d.approvalIgnored !== undefined ? { approvalIgnored: d.approvalIgnored } : {}),
          ...(call.callId !== undefined ? { callId: call.callId } : {}),
          what: logSafe(primaryEffect(d)?.detail ?? "").slice(0, 300),
          ...(d.scope !== undefined ? { scope: { mode: d.scope.mode, verdict: d.scope.verdict, changes: d.scope.changes } } : {}),
        },
        err,
      );
      if (logged === "unrecorded") failClosedUnrecorded(d, unattended === null);
      const g = wrap(call, action, d, held, id);
      if (g.verdict === "ask") asked.set(g.id, { actionHash: d.actionHash, answered: false });
      lastVerdict.set(d.actionHash, g.verdict);
      if (err.length > 0) g.problems = err;
      return g;
    } catch (e) {
      // Recording failed after deciding: an allowed read-only call still proceeds; anything else does not.
      // R1: a call that does not run still keeps its tripwire events where they can be kept.
      try {
        store.append(session, tripwireEvents(d.effects, ctx));
      } catch {
        // Nothing more to do; the failure decision says why.
      }
      // Review of FZ14: a verdict that exists is never lowered. The read-only exception of failure() is for an
      // evaluation that could not run; a call the engine already denied, held or asked about stays stopped.
      const g = d.verdict !== "allow" ? recordingFailedAfter(call, action, d, e, err) : failure(call, e, err);
      lastVerdict.set(d.actionHash, g.verdict);
      return g;
    }
  }

  function approveAsked(decision: GuardDecision, answer: ApprovalAnswer): { approved: boolean; by?: string; note?: string } {
    const a = normalizeAnswer(answer);
    const known = asked.get(decision.id);
    // Only an "ask" this guard handed out, answered once, for the action it was about.
    const valid = known !== undefined && !known.answered && decision.verdict === "ask" && known.actionHash === decision.actionHash;
    let result = valid ? a : { ...a, approved: false };
    // A real answer (yes or no) uses the ask up; a mismatched one leaves it for the real answer.
    if (valid) {
      known.answered = true;
      // Answered: an ask is never answered twice, so the record can go (an unknown id is refused just the same).
      asked.delete(decision.id);
    }
    const err: string[] = [];
    const logged = log({ type: "approval", of: "ask", decision: decision.id, tool: decision.call.tool, action: decision.actionHash, approved: result.approved, ...(result.by !== undefined ? { by: result.by } : {}), ...(result.note !== undefined ? { note: result.note } : {}), ...(!valid ? { refused: "not an unanswered ask from this guard" } : {}) }, err);
    // LR11: a yes the store refused to record (entry and fallback) does not let the action run unrecorded.
    if (result.approved && logged === "unrecorded") {
      result = { ...result, approved: false, note: "LaunchSafe Agent Firewall: the decision log refused to record this approval (its entry and the short fallback entry), so the action was not let through (rule FW-LOG-UNRECORDED)" };
    }
    if (result.approved) {
      try {
        // The asked action runs: raise the budgets it exceeded (the hook does this when PostToolUse arrives).
        store.confirmBudget(session, decision.actionHash, now());
      } catch (e) {
        err.push((e as Error).message);
      }
    }
    return result;
  }

  async function askHost(g: GuardDecision): Promise<ApprovalAnswer> {
    if (options.onApproval === undefined) return false;
    const pending = Promise.resolve().then(() => options.onApproval?.({ session, decision: g, message: g.message }));
    if (options.approvalTimeoutMs === undefined) return pending;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<ApprovalAnswer>((resolve) => {
      timer = setTimeout(() => resolve(false), options.approvalTimeoutMs);
    });
    try {
      return await Promise.race([pending, timeout]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  async function requestApproval(g: GuardDecision): Promise<{ approved: boolean; by?: string; note?: string }> {
    // Deny and hold never reach the person; neither does a decision this guard did not hand out.
    if (g.verdict !== "ask" || asked.get(g.id)?.answered !== false) return approveAsked(g, false);
    let answer: ApprovalAnswer = false;
    try {
      answer = await askHost(g);
    } catch {
      answer = false;
    }
    return approveAsked(g, answer);
  }

  async function authorize(call: ToolCall): Promise<Authorization> {
    const g = decide(call);
    if (g.verdict === "allow") return { allowed: true, decision: g };
    if (g.verdict !== "ask") return { allowed: false, decision: g };
    const approval = await requestApproval(g);
    return { allowed: approval.approved, decision: g, approval };
  }

  function recordResult(call: ToolCall, output: unknown, options: ResultOptions = {}): ResultNote {
    const err: string[] = [];
    try {
      const { action, mcpSource } = toAction(call, specs);
      const { ctx } = context(mcpSource);
      const before = store.load(session);
      // Re-derive the taint from what the tool was (also covers a call that was never decided).
      const c = classifyAction(action, ctx, config, before);
      const events: StateEvent[] = [];
      for (const e of c.effects) {
        if (e.taints === true) events.push({ type: "taint", source: e.detail.slice(0, 200) });
        if (e.private === true || e.cls === "read_secret") events.push({ type: "sensitive", source: e.detail.slice(0, 200) });
      }
      const outside = events.some((e) => e.type === "taint");
      // The host decides what its model receives, so hidden characters taint here (FW-HIDDEN-OUTPUT) rather than being
      // rewritten. Which output counts as only programs' own (colours, progress lines) is the hook's rule.
      const programOutput = programOutputOnly([c.effects], [action], before.tainted || outside);
      const post = afterTool(output, { redact: config.redactSecretsInOutput, source: call.tool, outside, programOutput, ...(before.outsideCommands !== undefined ? { known: before.outsideCommands } : {}), ...(ctx.canaries !== undefined ? { canaries: ctx.canaries } : {}), ...(ctx.vault !== undefined ? { vault: ctx.vault } : {}) });
      events.push(...post.events);
      store.append(session, events);
      // Spending limits: a failure (the host says so, or the output carries an explicit marker) counts toward
      // the identical-failures cap of this exact call.
      const failure = capFailure(output, options.failed === true);
      // F-e: remember what the tool left on disk, so a later session knows who wrote it (the hook's PostToolUse). Only a
      // call that succeeded and that this guard did not deny or hold vouches for what is on disk; otherwise what it left
      // is recorded only when the session was untrusted (as untrusted: a command that exits non-zero may still have left
      // its file). A failure here only loses the entry, as on the hook path; it is told to the host. Arguments nested
      // too deep to judge are denied whenever this guard sees them (FZ14; decide() keeps no verdict for them), so a
      // result for such a call vouches for nothing, decided here or not.
      const deep = nestedDeeperThan(call.input, MAX_INPUT_DEPTH) || nestedDeeperThan(action.input, MAX_INPUT_DEPTH);
      const last = deep ? undefined : lastVerdict.get(actionHash(action));
      const vouches = !deep && failure === null && last !== "deny" && last !== "hold";
      if (ledger !== undefined && (vouches || before.tainted || outside)) {
        try {
          ledger.record({ session, tool: action.tool, effects: c.effects, findings: c.findings, taintedBefore: before.tainted || !vouches, maxHashBytes: config.provenance.maxHashBytes, caseInsensitive });
        } catch (e) {
          reportLogError(`LaunchSafe Agent Firewall could not record a write in its provenance ledger: ${(e as Error).message}`);
        }
      }
      store.confirmBudget(session, actionHash(action), now());
      if (failure !== null) store.recordFailure?.(session, counterKey(action), capFailureKeys(failure), now());
      log({ type: "result", tool: call.tool, ...(call.callId !== undefined ? { callId: call.callId } : {}), taints: outside, secrets: post.secretsSeen, ...(post.canariesSeen.length > 0 ? { canariesSeen: post.canariesSeen } : {}), ...(failure !== null ? { failed: true } : {}) }, err);
      const became = !before.tainted && (outside || post.hidden !== undefined);
      const notes = [...(became ? ["LaunchSafe Agent Firewall: this session has now read outside content. From here on, sending data out, sending messages, changing the agent's instructions or memory, and reading credentials need a person's approval. If an action is blocked, tell the user; do not try to work around the block."] : []), ...(post.hidden !== undefined ? [post.hidden.warning] : [])];
      return {
        becameUntrusted: became,
        secretsSeen: post.secretsSeen,
        ...(post.redacted !== undefined ? { redacted: post.redacted } : {}),
        ...(notes.length > 0 ? { note: notes.join("\n") } : {}),
      };
    } catch (e) {
      // The tool already ran: make the session untrusted rather than lose what it brought in. A session that already
      // remembers commands from outside content may have lost more of them here, so every risky command asks.
      try {
        const lost: StateEvent[] = [{ type: "corrupt", detail: `recording a result failed: ${(e as Error).message}`.slice(0, 200) }];
        let holds = true;
        try {
          holds = (store.load(session).outsideCommands?.size ?? 0) > 0;
        } catch {
          // Unknown: assume it does.
        }
        if (holds) lost.push({ type: "outside_command", hash: SATURATED, source: `a tool result that could not be checked (${call.tool})`.slice(0, 200) });
        store.append(session, lost);
      } catch {
        // Nothing more to do.
      }
      return { becameUntrusted: true, secretsSeen: 0 };
    }
  }

  function reportInput(input: UntrustedInput): void {
    const source = String(input.source).slice(0, 200) || "untrusted input";
    const before = store.load(session);
    // The taint (and private data) is recorded before the content is scanned: a scan that fails or throws on
    // hostile content must not leave the session looking as if nothing came in.
    store.append(session, [{ type: "taint", source }, ...(input.private === true ? [{ type: "sensitive" as const, source }] : [])]);
    const v = vault();
    const post = afterTool(input.content, { redact: false, source, outside: true, ...(before.outsideCommands !== undefined ? { known: before.outsideCommands } : {}), ...(canaries !== undefined ? { canaries } : {}), ...(v !== undefined ? { vault: v } : {}) });
    const events: StateEvent[] = [...post.events];
    if (events.length > 0) store.append(session, events);
    log({ type: "input", source, private: input.private === true, secrets: post.secretsSeen, wasUntrusted: before.tainted }, []);
  }

  function recordPrompt(text: string, o: { apply?: boolean } = {}): void {
    const prompt = String(text);
    if (o.apply === false) {
      // Nothing it names is applied: no destinations, no task scope. The prompt is hashed, never stored.
      log({ type: "prompt", hash: sha256Hex(prompt), length: prompt.length, applied: false }, []);
      return;
    }
    const dest = destinationsFromPrompt(prompt);
    const events: StateEvent[] = [];
    if (dest.length > 0) events.push({ type: "user_destinations", destinations: dest });
    const hash = sha256Hex(prompt);
    if (taskScopePolicy(config).mode !== "off") {
      const { ctx } = context(undefined);
      const stat = options.fs?.stat ?? (() => null);
      const scope = nextScope(store.load(session).scope, prompt, () => scopeFromPrompt(prompt, hash, ctx, { stat }, now()));
      if (scope !== null) events.push({ type: "scope", scope });
    }
    store.append(session, events);
    // The prompt is hashed, never stored.
    log({ type: "prompt", hash, length: prompt.length, destinations: dest.length }, []);
  }

  function settle(id: string, status: "approved" | "rejected", by: { by?: string } | undefined): HeldAction {
    const h = store.held(id);
    if (h === null || h.session !== session) throw new Error(`no held action ${id} in this session`);
    const who = typeof by?.by === "string" && by.by !== "" ? by.by.slice(0, 200) : "the host application";
    const out = store.settle(id, status, who);
    log({ type: "approval", of: "hold", held: id, tool: h.tool, action: h.actionHash, approved: status === "approved", by: who }, []);
    return out;
  }

  function state(): SessionSnapshot {
    const s = store.load(session);
    return { session, untrusted: s.tainted, untrustedBecause: [...s.taintSources], holdsPrivateData: s.sensitive, privateBecause: [...s.sensitiveSources], namedDestinations: [...s.userDestinations] };
  }

  return {
    session,
    store,
    config,
    check,
    decide,
    authorize,
    requestApproval,
    approveAsked,
    recordResult,
    reportInput,
    recordPrompt,
    approve: (id, by) => settle(id, "approved", by),
    reject: (id, by) => settle(id, "rejected", by),
    pending: () => store.listHeld(session).filter((h) => h.status === "pending"),
    state,
    log: (limit) => store.entries(limit),
    verifyLog: () => store.verifyLog(),
  };
}
