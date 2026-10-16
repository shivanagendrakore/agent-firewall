/**
 * The local API's endpoints (docs/api.md), independent of the transport (server.ts). Every call is the
 * library's guard (src/sdk/guard.ts) over the firewall's own files, so a decision here is the decision the
 * library and the hooks make for the same action: the same engine, the same session state, the same signed
 * log, and the same queue, where `queue list`, terminal approvals and phone approvals see what this holds.
 *
 * What the API adds to the library:
 * - sessions are `<agentId>/<session>`: one agent can never read or taint another's;
 * - a "hold" is a queue item (as in the library), approved by a person in the terminal or on a phone, and the
 *   identical retry is then allowed once; an "ask" is answered by the host's own person and creates no item;
 * - session state that cannot be read makes the session untrusted and sensitive (a "corrupt" event), never
 *   an error the caller could treat as "no state";
 * - Idempotency-Key: a retry with the same key and body returns the first answer and writes nothing.
 */

import { loadNevers, projectId } from "../runtime/learned.js";
import { createHash, randomBytes } from "node:crypto";
import { closeSync, existsSync, openSync } from "node:fs";
import { homedir } from "node:os";
import { foldEvents } from "../engine/state.js";
import { trustedKeys } from "../hook/pipeline.js";
import { agentOfSession, stopView } from "../runtime/stops.js";
import { loadPolicy } from "../runtime/config.js";
import { ensureDir } from "../runtime/fsutil.js";
import type { Layout } from "../runtime/layout.js";
import type { LogEntry } from "../runtime/log.js";
import { realpathStrict } from "../runtime/realpath.js";
import { enqueue, getQueueItem, loadState, sessionFile, type QueueItem } from "../runtime/store.js";
import { ruleDoc } from "../rules.js";
import { createGuard, type Guard } from "../sdk/guard.js";
import { fileStore, nodeEnvironment } from "../sdk/node.js";
import type { GuardDecision, GuardVerdict, HeldAction, StateStore, ToolCall } from "../sdk/types.js";
import type { FirewallConfig } from "../types.js";
import { VERSION } from "../version.js";
import { sessionOf } from "./files.js";
import { posix } from "node:path";
import { own } from "../own.js";
import { readRegistry, toolSpecs, trustedSource, type Registry } from "./registry.js";
import { BadRequest, parseDecide, parseInput, parsePrompt, parseResult, sessionId, type DecideRequest } from "./request.js";
import { bearer, readTokens, recordOfToken, rolesOf, type TokenRecord, type TokenRole } from "./tokens.js";

export interface Reply {
  status: number;
  body: Record<string, unknown>;
  /** Seconds, for a 429 or 503 (the Retry-After header). */
  retryAfter?: number;
}

export interface Problem {
  slug: string;
  title: string;
  status: number;
  detail: string;
}

export const PROBLEM_BASE = "https://github.com/shivanagendrakore/agent-firewall/blob/main/docs/api.md#";

export function problem(status: number, slug: string, title: string, detail: string): Reply {
  return { status, body: { type: `${PROBLEM_BASE}${slug}`, title, status, detail } };
}

export interface ApiCoreOptions {
  l: Layout;
  /** The server's environment: the approval key and phone pins it trusts, as the hook's are. */
  env: NodeJS.ProcessEnv;
  /** The home directory paths are judged against (~/.ssh...). Default os.homedir(). */
  home?: string;
  /** Scratch directories (default the OS temp directories, as the library's nodeEnvironment). */
  scratch?: string[];
  now?: () => Date;
  /**
   * Whether the engine may look at the file system (symlinks, file contents and sizes, lockfiles, the
   * protected settings files, the package-intel snapshot), as the hook does. Default true. False judges paths
   * as text only: the conformance vectors' reference environment.
   */
  fileAccess?: boolean;
  /** How many decisions are remembered for results and idempotent retries (default 10000). */
  remember?: number;
  /** How many bytes of remembered arguments and replies are kept, in total, at most (default REMEMBER_MAX_BYTES). */
  rememberBytes?: number;
  /** Diagnostics (the server's stderr): what an error's reply leaves out. */
  diag?: (s: string) => void;
  /** New sessions one agent may open while the server runs (default MAX_NEW_SESSIONS). */
  maxNewSessions?: number;
}

/** New sessions per agent per server run (ApiCore touch). */
export const MAX_NEW_SESSIONS = 100_000;

/** Whether `p` is `root` or inside it (both absolute; "." and ".." segments resolved first). */
function within(p: string, root: string): boolean {
  const a = posix.resolve(p);
  const r = posix.resolve(root);
  return a === r || r === "/" || a.startsWith(`${r}/`);
}

/** Whether `p` is `root` or inside it after resolving symlinks (realpathStrict) and "." / ".." segments. */
function realWithin(p: string, root: string): boolean {
  try {
    const rr = realpathStrict(root);
    return within(realpathStrict(p), rr) && within(realpathStrict(posix.resolve(p)), rr);
  } catch {
    return false;
  }
}

/** The registry workspaceRoots matched by the request's workspace/cwd (in order), or the request's own roots. */
function matchedRoots(pinned: readonly string[] | undefined, roots: readonly string[], cwd: string | undefined): string[] {
  if (pinned === undefined) return [...roots];
  const out: string[] = [];
  for (const p of [...roots, ...(cwd !== undefined ? [cwd] : [])]) {
    for (const r of pinned) {
      if (realWithin(p, r) && !out.includes(r)) out.push(r);
    }
  }
  return out.length > 0 ? out : [...pinned];
}

/**
 * I2: a decide request's context is the agent's own word. The registry a person set pins what it may claim:
 * - an MCP server listed in `mcpServers` is judged with the person's source; a request claiming a source the
 *   engine trusts (user, sdk...) for a server the person registered as untrusted (project...) is refused (403);
 * - a server not listed there is never judged as a trusted source's on the agent's word: a claimed "user" (or any
 *   source the engine trusts) is judged as "unknown", and the decision's problems say so;
 * - with `workspaceRoots`, every context.workspace root and context.cwd must be one of them or inside one (403).
 */
export function pinContext(registry: Registry | null, req: DecideRequest): { req: DecideRequest; problems: string[] } | Reply {
  const problems: string[] = [];
  let call = req.call;
  if (call.tool.startsWith("mcp__")) {
    const server = call.tool.slice("mcp__".length).split("__")[0] ?? "";
    const claimed = call.mcpSource;
    const registered = registry?.mcpServers !== undefined ? own(registry.mcpServers, server)?.source : undefined;
    if (registered !== undefined) {
      if (claimed !== undefined && trustedSource(claimed) && !trustedSource(registered)) return problem(403, "forbidden-context", "Forbidden", `action.mcp.source "${claimed.slice(0, 40)}" is refused: the agent's registry lists MCP server ${server} as "${registered}" (launchsafe-firewall api tools set)`);
      if (claimed === undefined || (trustedSource(claimed) && claimed !== registered)) call = { ...call, mcpSource: registered };
    } else if (claimed !== undefined && trustedSource(claimed)) {
      call = { ...call, mcpSource: "unknown" };
      problems.push(`action.mcp.source "${claimed.slice(0, 40)}" was judged as "unknown": MCP server ${server} is not in the agent's registry with that source (add it under "mcpServers" with launchsafe-firewall api tools set)`);
    }
  }
  const roots = registry?.workspaceRoots;
  let workspace = req.workspace;
  if (roots !== undefined) {
    const outside = [...(req.workspace ?? []), ...(req.cwd !== undefined ? [req.cwd] : [])].find((p) => !roots.some((r) => realWithin(p, r)));
    if (outside !== undefined) return problem(403, "forbidden-context", "Forbidden", `${outside.slice(0, 200)} is outside the workspace roots the agent's registry allows (${roots.join(", ").slice(0, 300)})`);
    if ((workspace === undefined || workspace.length === 0) && roots.length > 0) {
      const byCwd = req.cwd !== undefined ? roots.filter((r) => realWithin(req.cwd as string, r)) : [];
      workspace = byCwd.length > 0 ? [...byCwd, ...roots.filter((r) => !byCwd.includes(r))] : [...roots];
    }
  }
  return { req: call === req.call && workspace === req.workspace ? req : { ...req, call, ...(workspace !== undefined ? { workspace } : {}) }, problems };
}

/** Who a request's token says is calling. */
export interface Caller {
  agent: string;
  /** The token was made with --traffic network: it may send context.traffic "network" (TokenRecord.traffic). */
  networkTraffic: boolean;
  /** What the token may do (TokenRecord.roles; the default for a token made without --role: decide and report). */
  roles: readonly TokenRole[];
}

/** The role each endpoint needs (src/api/tokens.ts TOKEN_ROLES). /prompts takes "prompt" or "report" (see prompt()). */
export function roleRefused(c: Caller, need: TokenRole): Reply | null {
  if (c.roles.includes(need)) return null;
  return problem(403, "forbidden", "Forbidden", `this token does not have the "${need}" role (launchsafe-firewall api token add <agentId> --role ${need}); it has ${c.roles.join(", ")}`);
}

interface DecisionRecord {
  agent: string;
  session: string;
  call: ToolCall;
  mode: "registry" | "engine";
  workspace?: string[];
  cwd?: string;
  attended: boolean;
  /** "network": a network middleware's request (not a tool call; GuardOptions.traffic). */
  traffic?: "network";
  /**
   * What the engine said. A call that was denied or held did not run, so a result reported for it records no file in the
   * provenance ledger (a report may only make things stricter; it cannot vouch for a file's content).
   */
  verdict?: GuardVerdict;
}

interface Remembered {
  bodyHash: string;
  reply: Reply;
  /** When the first answer was given (ms), for the in-flight window of an allow or ask. */
  at: number;
  /** What the call was, to check the kill switch and the spending limits again before an allow is replayed. */
  record: DecisionRecord;
  verdict: string;
  /**
   * How many times an allow or an ask was given again (at most once: a key is a retry, not a way to run uncounted).
   * An answer given when the key was decided again starts at 1: the key has had its replay, so it is never given again.
   */
  replays: number;
  /** A dry run: never given again (it decided nothing), but the key stays bound to its body. */
  dry: boolean;
}

/**
 * An idempotent retry gets the first answer again when it was a deny or a hold (replaying it changes nothing),
 * or, for an allow or an ask, once, only within this window, and only while a dry check of the same call still gives
 * the same verdict for the same action: a retry of a request whose answer was lost in flight. Otherwise the call is
 * decided again (and counted), so a remembered allow never outlives a stop, a spending limit, a new "never" or a
 * change in the session's trust. A key has one replay in all: once it has been decided again (after its replay, or
 * because the replay was refused), every later request with it is decided and counted afresh, so one key cannot run
 * an action again and again uncounted.
 */
export const IDEMPOTENT_ALLOW_MS = 30_000;

/**
 * A bounded map: the oldest entries go first, past `max` entries or past `maxWeight` in total. FZ18: the decisions
 * kept for `results` hold each call's arguments, and 10,000 of them at up to 1 MiB each let one agent's token grow
 * the server's memory until the process was killed (every agent then lost the firewall). So entries are also
 * weighed (about their size in bytes) and the oldest go when the total is over the limit.
 */
class Bounded<V> {
  private readonly m = new Map<string, { v: V; w: number }>();
  private total = 0;
  constructor(
    private readonly max: number,
    private readonly maxWeight = Number.POSITIVE_INFINITY,
    private readonly onEvict?: (k: string, v: V) => void,
  ) {}
  get(k: string): V | undefined {
    return this.m.get(k)?.v;
  }
  set(k: string, v: V, weight = 0): void {
    this.delete(k);
    this.m.set(k, { v, w: weight });
    this.total += weight;
    while (this.m.size > this.max || (this.total > this.maxWeight && this.m.size > 1)) {
      const first = this.m.keys().next().value;
      if (first === undefined) break;
      const gone = this.m.get(first);
      this.delete(first);
      if (gone !== undefined) this.onEvict?.(first, gone.v);
    }
  }
  private delete(k: string): void {
    const e = this.m.get(k);
    if (e === undefined) return;
    this.total -= e.w;
    this.m.delete(k);
  }
}

/** Remembered decisions' arguments, in total (bytes, roughly): the oldest are forgotten past it. */
export const REMEMBER_MAX_BYTES = 64 * 1024 * 1024;

/** About how many bytes a JSON value holds (strings by length, 16 per other node). Iterative. */
export function approxBytes(v: unknown): number {
  let n = 0;
  const stack: unknown[] = [v];
  while (stack.length > 0) {
    const x = stack.pop();
    if (typeof x === "string") n += x.length * 2;
    else if (Array.isArray(x)) {
      n += 16;
      for (const y of x) stack.push(y);
    } else if (typeof x === "object" && x !== null) {
      n += 16;
      for (const [k, y] of Object.entries(x)) {
        n += k.length * 2;
        stack.push(y);
      }
    } else n += 16;
  }
  return n;
}

const VERDICT_OUTCOME = { allow: "allow", ask: "approve", deny: "deny" } as const;

/** The engine outcome a shown rule had: a hold is "hold" for a rule that holds, else an ask nobody could answer. */
export function ruleOutcome(verdict: GuardDecision["verdict"], id: string): string {
  if (verdict !== "hold") return VERDICT_OUTCOME[verdict];
  const doc = ruleDoc(id);
  return doc !== null && (doc.outcome.trusted === "hold" || doc.outcome.untrusted === "hold") ? "hold" : "approve";
}

function heldOf(it: QueueItem): HeldAction {
  return { id: it.id, session: it.sessionId, createdAt: it.createdAt, tool: it.tool, input: it.input, actionHash: it.actionHash, rules: it.rules, reasons: it.reasons, kind: it.kind, ...(it.proposal !== undefined ? { proposal: { target: it.proposal.target, change: it.proposal.change } } : {}), status: it.status, ...(it.decidedAt !== undefined ? { decidedAt: it.decidedAt } : {}) };
}

function newDecisionId(): string {
  return `dec_${randomBytes(16).toString("base64url")}`;
}

/** The rule an accepted result carries when its decision had been forgotten: recorded as untrusted, private input. */
export const RULE_RESULT_UNRECORDED = "FW-RESULT-UNRECORDED";

/** Ids of forgotten decisions remembered per agent (ids only, so a later result for one is not a plain 404). */
const FORGOTTEN_IDS = 100_000;

export class ApiCore {
  /**
   * Review of FZ18: decisions and idempotent replies are remembered per agent, each agent with its own count and
   * size bounds, so one agent's traffic never makes the server forget another agent's decisions.
   */
  private readonly decisionsBy = new Map<string, Bounded<DecisionRecord>>();
  private readonly idemBy = new Map<string, Bounded<Remembered>>();
  private readonly forgottenBy = new Map<string, Bounded<true>>();

  constructor(private readonly o: ApiCoreOptions) {}

  private forgotten(agent: string): Bounded<true> {
    let b = this.forgottenBy.get(agent);
    if (b === undefined) {
      b = new Bounded<true>(FORGOTTEN_IDS);
      this.forgottenBy.set(agent, b);
    }
    return b;
  }

  private decisions(agent: string): Bounded<DecisionRecord> {
    let b = this.decisionsBy.get(agent);
    if (b === undefined) {
      b = new Bounded<DecisionRecord>(this.o.remember ?? 10000, this.o.rememberBytes ?? REMEMBER_MAX_BYTES, (id) => this.forgotten(agent).set(id, true));
      this.decisionsBy.set(agent, b);
    }
    return b;
  }

  private idem(agent: string): Bounded<Remembered> {
    let b = this.idemBy.get(agent);
    if (b === undefined) {
      b = new Bounded<Remembered>(this.o.remember ?? 10000, this.o.rememberBytes ?? REMEMBER_MAX_BYTES);
      this.idemBy.set(agent, b);
    }
    return b;
  }

  private now(): Date {
    return this.o.now?.() ?? new Date();
  }

  health(): Reply {
    return { status: 200, body: { ok: true, engine: { version: VERSION } } };
  }

  /** The agent an Authorization header names, or the 401 to send. The token file is read per request, so a revoke takes effect at once. */
  authenticate(header: string | undefined): Caller | Reply {
    const token = bearer(header);
    if (token === null) return problem(401, "unauthorized", "Unauthorized", "send Authorization: Bearer <token> (launchsafe-firewall api token add <agentId>)");
    let rec: TokenRecord | null;
    try {
      rec = recordOfToken(readTokens(this.o.l), token);
    } catch (e) {
      // Not yet authenticated: the reply says what failed, never where or why (a path, a parse error).
      this.o.diag?.(`LaunchSafe Firewall API: the token store cannot be read: ${(e as Error).message}`);
      return problem(500, "internal", "Internal error", "the token store cannot be read (the server's diagnostics say why)");
    }
    if (rec === null) return problem(401, "unauthorized", "Unauthorized", "this token is not valid (unknown or revoked)");
    return { agent: rec.agent, networkTraffic: rec.traffic === "network", roles: rolesOf(rec) };
  }

  /**
   * The policy the hook would use for these roots (user and managed files, and the workspace's project file), and
   * I3: its load error, which the guard turns into FW-POLICY-ERROR and a problem on every decision, as the hook does.
   */
  private policy(roots: readonly string[]): { config: FirewallConfig; error?: string } {
    const p = loadPolicy(this.o.l, roots);
    return { config: p.config, ...(p.error !== undefined ? { error: p.error } : {}) };
  }

  /**
   * The file store, with: the trust keys the hook uses (approval key and phone pins, so phone approvals count),
   * unreadable state read as corrupt (untrusted and sensitive), queue items that carry the project directory
   * (phones decide only items that do), and log entries tagged with the agent and decision id.
   */
  private store(cfg: FirewallConfig, projectDir: string, tag: Record<string, unknown>, onEntry: (e: LogEntry) => void, ledger: boolean): StateStore {
    const l = this.o.l;
    const base = fileStore({ home: l.home });
    return {
      ...base,
      // F-e: fileStore's provenance ledger is the hook's, in the same home (used when the server has file access).
      ledger: ledger ? base.ledger : undefined,
      load: (session) => {
        try {
          return loadState(l, session, trustedKeys(l, this.o.env, cfg, this.now()));
        } catch (e) {
          return foldEvents([{ type: "corrupt", detail: `the session state cannot be read (${(e as Error).message})`.slice(0, 200) }]);
        }
      },
      // The kill switch with the key the hook trusts (a pinned approver key wins over the one on disk).
      stops: (session) => stopView(l, session, agentOfSession(session), trustedKeys(l, this.o.env, cfg, this.now()).approver),
      hold: (item) =>
        heldOf(
          enqueue(l, {
            sessionId: item.session,
            cwd: item.cwd,
            projectDir,
            tool: item.tool,
            input: item.input,
            actionHash: item.actionHash,
            rules: item.rules,
            reasons: item.reasons,
            kind: item.kind,
            ...(item.proposal !== undefined ? { proposal: item.proposal } : {}),
            ...(item.summary !== undefined ? { summary: item.summary } : {}),
            ...(item.trustSources !== undefined ? { trustSources: item.trustSources } : {}),
            unattended: item.unattended,
          }),
        ),
      appendLog: (event) => {
        const entry = base.appendLog({ ...event, ...tag }) as LogEntry;
        onEntry(entry);
        return entry;
      },
    };
  }

  /** A guard for one request: built fresh, so policy and registry changes apply at once (the hook reads them per call too). */
  private guard(agent: string, r: Pick<DecisionRecord, "session" | "mode" | "workspace" | "cwd" | "attended" | "traffic">, tag: Record<string, unknown>, onEntry: (e: LogEntry) => void = () => undefined, ledger = true): Guard {
    const registry = readRegistry(this.o.l, agent);
    const specs = registry !== null ? toolSpecs(registry) : {};
    const pinned = registry?.workspaceRoots;
    const roots = r.workspace !== undefined && r.workspace.length > 0 ? r.workspace : pinned !== undefined && pinned.length > 0 ? [...pinned] : [];
    const projectRoots = matchedRoots(pinned, roots, r.cwd);
    const policyRoots = [...new Set([...projectRoots, ...roots])];
    const loaded = this.policy(policyRoots);
    const cfg = loaded.config;
    const home = this.o.home ?? homedir();
    const env =
      this.o.fileAccess === false
        ? { workspace: [...roots], home, scratch: this.o.scratch ?? [], ...(roots[0] !== undefined ? { cwd: roots[0] } : {}) }
        : nodeEnvironment({ workspace: roots, home, ...(this.o.scratch !== undefined ? { scratch: this.o.scratch } : {}), firewallHome: this.o.l.home, policy: cfg });
    const cwd = r.cwd ?? env.cwd ?? roots[0] ?? "/";
    const projectRoot = projectRoots[0];
    const store = this.store(cfg, projectRoot ?? cwd, tag, onEntry, ledger);
    return createGuard({
      ...env,
      session: r.session,
      cwd,
      policy: cfg,
      ...(loaded.error !== undefined ? { policyError: loaded.error } : {}),
      // I9: the caller states cwd and workspace, so an approval holds only in the context it was given for.
      bindApprovalsToContext: true,
      tools: r.mode === "registry" ? specs : Object.fromEntries(Object.entries(specs).filter(([, s]) => "kind" in s)),
      store,
      attended: r.attended,
      ...(r.traffic === "network" ? { traffic: "network" as const } : {}),
      // The person's "never" choices and approved hosts for the request's project, from the firewall's home.
      ...(this.o.fileAccess !== false && projectRoot !== undefined
        ? {
            nevers: () => {
              const out = new Map<string, string>();
              for (const d of policyRoots) {
                for (const [k, v] of loadNevers(this.o.l, projectId(d))) out.set(k, v);
              }
              return out;
            },
            ...(store.knownHosts !== undefined ? { knownHosts: () => store.knownHosts?.(projectRoot) ?? [] } : {}),
          }
        : {}),
      now: () => this.now(),
      // Log failures are in the decision's problems and in the verdict (FW-LOG-UNRECORDED), not on a console.
      onLogError: () => undefined,
    });
  }

  /**
   * The session file exists from the first call that names the session, so GET can tell a known session from an
   * unknown one. A new session starts clean, so an agent that could open sessions without end could also leave
   * every tainted one behind and fill the disk: each agent may open at most MAX_NEW_SESSIONS while the server runs
   * (429 past it). Returns the refusal, or null.
   */
  private touch(agent: string, session: string, force = false): Reply | null {
    const f = sessionFile(this.o.l, session);
    if (existsSync(f)) return null;
    const n = this.newSessions.get(agent) ?? 0;
    if (!force && n >= (this.o.maxNewSessions ?? MAX_NEW_SESSIONS)) return { ...problem(429, "too-many-sessions", "Too many requests", `agent ${agent} opened ${n} sessions since the server started, the most it may; reuse a session, or restart the server (a person's command)`), retryAfter: 60 };
    this.newSessions.set(agent, n + 1);
    ensureDir(this.o.l.sessions);
    closeSync(openSync(f, "a", 0o600));
    return null;
  }

  private readonly newSessions = new Map<string, number>();

  /** `networkTraffic`: the token may send context.traffic "network" (Caller). */
  decide(agent: string, body: unknown, rawBody: string, idempotencyKey: string | undefined, networkTraffic = false): Reply {
    const key = idempotencyKey !== undefined ? `${agent}\u0000${idempotencyKey}` : undefined;
    const bodyHash = createHash("sha256").update(rawBody).digest("hex");
    // The request is read (and the token's right to send network traffic checked) before any remembered answer is
    // looked up: an ordinary token never receives the answer a network middleware's token was given for the same
    // key and body, it gets the 400 its own request earns.
    let registry: Registry | null;
    try {
      registry = readRegistry(this.o.l, agent);
    } catch (e) {
      this.o.diag?.(`LaunchSafe Firewall API: the tool registry of agent ${agent} cannot be read: ${(e as Error).message}`);
      return problem(500, "internal", "Internal error", "the agent's tool registry cannot be read (the server's diagnostics say why)");
    }
    const parsed = parseDecide(body, Object.keys(registry?.tools ?? {}), { networkTraffic });
    // I2: the person's registry, not the request, says which MCP sources and workspace roots this agent may claim.
    const pinned = pinContext(registry, parsed);
    if ("status" in pinned) return pinned;
    const req = pinned.req;
    let seen: Remembered | undefined;
    if (key !== undefined) {
      seen = this.idem(agent).get(key);
      if (seen !== undefined) {
        if (seen.bodyHash !== bodyHash) return problem(400, "idempotency-key-reused", "Bad request", "this Idempotency-Key was used with a different body");
        if (this.replayable(agent, seen)) {
          if (seen.verdict !== "deny" && seen.verdict !== "hold") seen.replays += 1;
          return this.withApprovalNow(seen.reply);
        }
        // Too old to replay, already replayed once, or the session was stopped or a spending limit reached since:
        // decided again below.
      }
    }
    const reply = this.decideParsed(agent, req, pinned.problems);
    // Every answered key is remembered with its body, a dry run too, so the key can never be reused with another body.
    if (key !== undefined && reply.status === 200) {
      const record = this.recordOf(agent, req);
      // A key decided again has had its turn: its new answer is never replayed (replays: 1), so a loop of one key is
      // decided and counted on every request after its one replay, never decide, replay, decide, replay.
      const replays = seen !== undefined ? 1 : 0;
      this.idem(agent).set(key, { bodyHash, reply, at: this.now().getTime(), record, verdict: String(reply.body.verdict), replays, dry: req.dryRun === true }, approxBytes(reply.body) + approxBytes(record.call.input));
    }
    return reply;
  }

  /**
   * A replayed hold says where its queue item is now (approved, denied), not "pending" as when it was first
   * answered: the caller polling by retry learns it was approved and retries with a new key. The verdict stays the
   * hold it was (a replay decides nothing).
   */
  private withApprovalNow(reply: Reply): Reply {
    const a = reply.body.approval as { id?: unknown } | undefined;
    if (reply.body.verdict !== "hold" || typeof a?.id !== "string") return reply;
    let status: string = "pending";
    try {
      const it = getQueueItem(this.o.l, a.id);
      status = it === null ? "pending" : it.status === "pending" ? "pending" : it.status === "approved" ? "approved" : "denied";
    } catch {
      return reply;
    }
    return { ...reply, body: { ...reply.body, approval: { id: a.id, status } } };
  }

  private recordOf(agent: string, req: DecideRequest): DecisionRecord {
    return { agent, session: sessionOf(agent, req.session), call: req.call, mode: req.mode, attended: req.attended, ...(req.workspace !== undefined ? { workspace: req.workspace } : {}), ...(req.cwd !== undefined ? { cwd: req.cwd } : {}), ...(req.traffic === "network" ? { traffic: "network" as const } : {}) };
  }

  /**
   * Whether a remembered answer may be given again: a deny or a hold always; an allow or an ask once, within
   * IDEMPOTENT_ALLOW_MS, and only while a dry check of the same call (nothing recorded) gives the same verdict
   * for the same action, with no stop and no spending limit in the way. A tainted session, a new "never" or a
   * changed policy changes the dry check's answer, so the stale one is not given. Any error: no (decided again).
   */
  private replayable(agent: string, seen: Remembered): boolean {
    if (seen.dry) return false;
    if (seen.verdict === "deny" || seen.verdict === "hold") return true;
    if (seen.replays >= 1) return false;
    if (this.now().getTime() - seen.at > IDEMPOTENT_ALLOW_MS) return false;
    try {
      const d = this.guard(agent, seen.record, { api: agent }).check(seen.record.call);
      if (d.verdict !== seen.verdict || `sha256:${d.actionHash}` !== seen.reply.body.actionHash) return false;
      return !d.rules.includes("FW-STOPPED") && !d.rules.includes("FW-CAP");
    } catch {
      return false;
    }
  }

  private decideParsed(agent: string, req: DecideRequest, notes: readonly string[] = []): Reply {
    const session = sessionOf(agent, req.session);
    const decisionId = newDecisionId();
    const record = this.recordOf(agent, req);
    let entry: LogEntry | undefined;
    const g = this.guard(agent, record, { api: agent, decisionId }, (e) => {
      entry = e;
    });
    if (req.dryRun) {
      const d = g.check(req.call);
      return { status: 200, body: this.decisionBody(decisionId, d, g, undefined, undefined, notes) };
    }
    const capped = this.touch(agent, session);
    if (capped !== null) return capped;
    const d = g.decide(req.call);
    // Only a hold is queued for a person (as in the library); an ask is the host's person's to answer.
    const approval = d.verdict === "hold" && d.held !== undefined ? { id: d.held.id, status: "pending" as const } : undefined;
    this.decisions(agent).set(decisionId, { ...record, verdict: d.verdict }, approxBytes(record.call.input) + approxBytes(record.workspace ?? []));
    return { status: 200, body: this.decisionBody(decisionId, d, g, approval, entry, notes) };
  }

  private decisionBody(decisionId: string, d: GuardDecision, g: Guard, approval: { id: string; status: string } | undefined, entry: LogEntry | undefined, notes: readonly string[] = []): Record<string, unknown> {
    const problems = [...notes, ...(d.problems ?? [])];
    const s = g.state();
    return {
      decisionId,
      verdict: d.verdict,
      rules: d.rules.map((id, i) => ({ id, outcome: ruleOutcome(d.verdict, id), reason: d.reasons[i] ?? "" })),
      message: d.message,
      actionHash: `sha256:${d.actionHash}`,
      session: { untrusted: s.untrusted, untrustedBecause: s.untrustedBecause, holdsPrivateData: s.holdsPrivateData, privateBecause: s.privateBecause },
      ...(approval !== undefined ? { approval } : {}),
      engine: { version: VERSION },
      ...(entry !== undefined ? { log: { seq: entry.seq, hash: `sha256:${entry.hash}` } } : {}),
      ...(problems.length > 0 ? { problems } : {}),
    };
  }

  /** The session a path names, for this agent. */
  private sessionArg(agent: string, raw: string): string {
    return sessionOf(agent, sessionId(raw));
  }

  result(agent: string, rawSession: string, body: unknown): Reply {
    const session = this.sessionArg(agent, rawSession);
    const r = parseResult(body);
    const rec = this.decisions(agent).get(r.decisionId);
    if (rec === undefined && this.forgotten(agent).get(r.decisionId) === true) {
      // The decision was forgotten (memory bounds): what the tool was is lost, so its output is recorded as untrusted,
      // private input of this session (taint, private data, credential fingerprints), the strictest reading.
      // A tool already ran: what it brought in is recorded whatever the session count.
      this.touch(agent, session, true);
      this.guard(agent, { session, mode: "engine", attended: true }, { api: agent, decisionId: r.decisionId }).reportInput({ source: `the result of a forgotten decision (${RULE_RESULT_UNRECORDED})`, content: r.output, private: true });
      return { status: 200, body: { recorded: true, rule: RULE_RESULT_UNRECORDED, detail: "the decision was no longer remembered, so the output was recorded as untrusted input holding private data" } };
    }
    if (rec === undefined || rec.agent !== agent || rec.session !== session) return problem(404, "not-found", "Not found", "no decision with this id in this session (decisions are remembered while the server runs)");
    // A call that was denied or held did not run: whatever is on disk is not its doing, so no file is recorded for it.
    const ran = rec.verdict === "allow" || rec.verdict === "ask";
    const note = this.guard(agent, rec, { api: agent, decisionId: r.decisionId }, undefined, ran).recordResult(rec.call, r.output, { failed: r.failed });
    return { status: 200, body: { recorded: true, ...(note.redacted !== undefined ? { output: note.redacted } : {}) } };
  }

  input(agent: string, rawSession: string, body: unknown): Reply {
    const session = this.sessionArg(agent, rawSession);
    const r = parseInput(body);
    const capped = this.touch(agent, session);
    if (capped !== null) return capped;
    this.guard(agent, { session, mode: "engine", attended: true }, { api: agent }).reportInput({ source: r.source, content: r.content, private: r.private });
    return { status: 200, body: { recorded: true } };
  }

  /**
   * I1: a prompt names the destinations an untrusted session may still send to and sets the task scope, so it is
   * applied only from a token with the "prompt" role (the component that reads what the person typed). From any
   * other token (an agent's own, decide and report) it is only logged, by its hash: an agent cannot widen its own
   * session by saying the person asked for it.
   */
  prompt(agent: string, rawSession: string, body: unknown, apply = true): Reply {
    const session = this.sessionArg(agent, rawSession);
    const r = parsePrompt(body);
    const capped = this.touch(agent, session);
    if (capped !== null) return capped;
    this.guard(agent, { session, mode: "engine", attended: true }, { api: agent }).recordPrompt(r.text, { apply });
    if (apply) return { status: 200, body: { recorded: true } };
    return { status: 200, body: { recorded: true, applied: false, detail: 'logged only: this token does not have the "prompt" role, so the destinations and task scope the prompt names were not applied (launchsafe-firewall api token add <agentId> --role prompt)' } };
  }

  session(agent: string, rawSession: string): Reply {
    const session = this.sessionArg(agent, rawSession);
    if (!existsSync(sessionFile(this.o.l, session))) return problem(404, "not-found", "Not found", "no such session for this agent");
    const s = this.guard(agent, { session, mode: "engine", attended: true }, { api: agent }).state();
    return { status: 200, body: { untrusted: s.untrusted, untrustedBecause: s.untrustedBecause, holdsPrivateData: s.holdsPrivateData, privateBecause: s.privateBecause } };
  }

  approval(agent: string, id: string): Reply {
    const it = /^[a-z0-9]{1,32}$/.test(id) ? getQueueItem(this.o.l, id) : null;
    if (it === null || !it.sessionId.startsWith(`${agent}/`)) return problem(404, "not-found", "Not found", "no such approval for this agent");
    const status = it.status === "pending" ? "pending" : it.status === "approved" ? "approved" : "denied";
    return { status: 200, body: { id: it.id, status } };
  }
}

export { BadRequest };
