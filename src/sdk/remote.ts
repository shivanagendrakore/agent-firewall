/**
 * createRemoteGuard(): the library's guard surface, decided by the local API sidecar
 * (`launchsafe-firewall serve --api`, docs/api-v0.md) instead of in-process, so an agent shares the
 * coding-agent hooks' state, queue and log. Node only (unix socket or loopback TCP, node:http).
 *
 * Fail closed (the contract's table, as code): authorize(), decide() and check() never throw. When the
 * sidecar cannot be reached, times out or answers 503 or 429, a read-only tool (kind "read", results
 * "trusted", privateData false in `tools`) goes ahead unless failOpenReads is false (any other 5xx denies
 * reads too), and everything else
 * is denied (FW-UNAVAILABLE, FW-RATE-LIMITED). A 4xx answer, or one that is not the contract's shape,
 * denies everything (FW-API-ERROR).
 *
 * Approvals: an agent credential can never approve. An ask or hold is an item in the firewall's queue
 * (terminal, phone, dashboard); after a person approves it there, the identical call is decided again
 * and allowed once. A framework's own approval UI saying yes is necessary but not sufficient.
 *
 * Untrusted input and prompts that could not be sent are kept and sent before the next decision; while
 * they cannot be, decisions fail closed, so a lost report never leaves the sidecar's session looser.
 */

import { join } from "node:path";
import { capFailure } from "../engine/caps.js";
import { safeText } from "../engine/terminal.js";
import { firewallHome } from "../runtime/layout.js";
import { own } from "../own.js";
import { BoundedMap } from "./bounded.js";
import { normalizeAnswer } from "./guard.js";
import type { ApprovalOutcome, GuardPort } from "./port.js";
import { loopbackTarget, newIdempotencyKey, RemoteHttpError, requestJson, type Target } from "./remote-http.js";
import type { ApprovalWait, RemoteApprovalStatus, RemoteAuthorization, RemoteDecision, RemoteFailure, RemoteFormat, RemoteGuardOptions, RemoteHealth, RemoteRecorded, RemoteResultNote, RemoteRule, RemoteSessionSnapshot, RemoteSessionState } from "./remote-types.js";
import type { ApprovalAnswer, GuardVerdict, ResultOptions, ToolCall, ToolSpec, UntrustedInput } from "./types.js";

export interface RemoteGuard extends GuardPort<RemoteDecision> {
  readonly session: string;
  /** A preview (`dryRun`): records nothing. Never throws. */
  check(call: ToolCall): Promise<RemoteDecision>;
  /** Decides and records a call (one log entry; ask and hold make a queue item). Never throws. */
  decide(call: ToolCall): Promise<RemoteDecision>;
  /** decide(); for an ask, waits for a person's approval in the firewall's queue and decides again. Never throws. */
  authorize(call: ToolCall): Promise<RemoteAuthorization>;
  /** For one of this guard's unanswered asks: waits for the queue's approval, then decides the call again. */
  requestApproval(decision: RemoteDecision): Promise<ApprovalOutcome>;
  /** A framework's person answered an ask: a no is a no; a yes still needs the queue's approval (requestApproval). */
  approveAsked(decision: RemoteDecision, answer: ApprovalAnswer): Promise<ApprovalOutcome>;
  /** Waits until a queue item is decided, the wait times out, or the sidecar refuses. Never throws. */
  waitForApproval(approval: string | RemoteDecision, opts?: { timeoutMs?: number; signal?: AbortSignal }): Promise<ApprovalWait>;
  /** What a tool that ran returned (with the decision it ran under, when the caller has it). Never throws. */
  recordResult(call: ToolCall, output: unknown, decision?: RemoteDecision | ResultOptions, options?: ResultOptions): Promise<RemoteResultNote>;
  /** Untrusted content that reached the agent outside a tool call. Never throws; kept and resent if it fails. */
  reportInput(input: UntrustedInput): Promise<RemoteRecorded>;
  /** What the person typed. Never throws; kept and resent if it fails. */
  recordPrompt(text: string): Promise<void>;
  /** The session as the sidecar has it. Rejects with a RemoteHttpError when the sidecar cannot say. */
  state(): Promise<RemoteSessionSnapshot>;
  /** GET /v1/health (no token). Rejects with a RemoteHttpError on failure. */
  health(): Promise<RemoteHealth>;
}

const VERDICTS = new Set<GuardVerdict>(["allow", "ask", "hold", "deny"]);
const APPROVAL_STATUSES = new Set<RemoteApprovalStatus>(["pending", "approved", "denied", "expired"]);
/** Reports kept for resending, at most; past that the guard stays failed closed. */
const MAX_PENDING_REPORTS = 100;
/** Allowed decisions remembered for recordResult. */
const MAX_REMEMBERED = 1000;
const UNTRUSTED_NOTE = "LaunchSafe Agent Firewall: this session has now read outside content. From here on, sending data out, sending messages, changing the agent's instructions or memory, and reading credentials need a person's approval. If an action is blocked, tell the user; do not try to work around the block.";
const TRUNCATED = "\n[LaunchSafe Agent Firewall: cut here; the whole text is larger than the API's 1 MiB limit]";
/** Room left for the rest of a report's body under the 1 MiB cap. */
const MAX_TEXT_BYTES = 1024 * 1024 - 16 * 1024;

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function strings(v: unknown): string[] | null {
  return Array.isArray(v) && v.every((x) => typeof x === "string") ? (v as string[]) : null;
}

function randomSession(): string {
  const b = new Uint8Array(12);
  globalThis.crypto.getRandomValues(b);
  return `sdk-${[...b].map((x) => x.toString(16).padStart(2, "0")).join("")}`;
}

/** A string cut to fit the request cap (by bytes, never splitting a character). */
function fitText(s: string): { text: string; cut: boolean } {
  if (Buffer.byteLength(s, "utf8") <= MAX_TEXT_BYTES) return { text: s, cut: false };
  const buf = Buffer.from(s, "utf8").subarray(0, MAX_TEXT_BYTES);
  return { text: buf.toString("utf8").replace(/�$/, "") + TRUNCATED, cut: true };
}

/** Output or content as sent: JSON values as they are when they fit, else their text cut to fit. */
function fitValue(v: unknown): { value: unknown; cut: boolean } {
  if (typeof v === "string") {
    const f = fitText(v);
    return { value: f.text, cut: f.cut };
  }
  let json: string | undefined;
  try {
    json = JSON.stringify(v);
  } catch {
    json = undefined;
  }
  if (json === undefined) return { value: String(v), cut: false };
  if (Buffer.byteLength(json, "utf8") <= MAX_TEXT_BYTES) return { value: v, cut: false };
  const f = fitText(json);
  return { value: f.text, cut: true };
}

/** A stable key for a call without an id: tool and input with sorted keys. */
function callKey(call: ToolCall): string {
  if (call.callId !== undefined) return `id:${call.callId}`;
  const sort = (v: unknown): unknown => (Array.isArray(v) ? v.map(sort) : isObj(v) ? Object.fromEntries(Object.entries(v).sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)).map(([k, x]) => [k, sort(x)])) : v);
  try {
    return `call:${JSON.stringify(sort({ tool: call.tool, input: call.input }))}`;
  } catch {
    return `call:${call.tool}`;
  }
}

function sessionState(v: unknown): RemoteSessionState | null {
  if (!isObj(v)) return null;
  const ub = strings(v.untrustedBecause);
  const pb = strings(v.privateBecause);
  if (typeof v.untrusted !== "boolean" || typeof v.holdsPrivateData !== "boolean" || ub === null || pb === null) return null;
  const nd = strings(v.namedDestinations);
  return { untrusted: v.untrusted, untrustedBecause: ub, holdsPrivateData: v.holdsPrivateData, privateBecause: pb, ...(nd !== null ? { namedDestinations: nd } : {}) };
}

/** Whether the specs make a tool read-only for the fail-closed table: kind read, results trusted, no private data. */
export function readOnlyBySpec(tool: string, specs: Record<string, ToolSpec>): boolean {
  const s = own(specs, tool);
  return s !== undefined && "kind" in s && s.kind === "read" && s.results === "trusted" && s.privateData === false;
}

export function createRemoteGuard(options: RemoteGuardOptions = {}): RemoteGuard {
  if (options.socketPath !== undefined && options.baseUrl !== undefined) throw new Error("createRemoteGuard: give socketPath or baseUrl, not both");
  const target: Target = options.baseUrl !== undefined ? loopbackTarget(options.baseUrl) : { socketPath: options.socketPath ?? join(firewallHome(), "api.sock") };
  // I7: on TCP nothing proves the answer is the firewall's (another local process may hold the port, and it would
  // be sent the token), so it is a choice the host makes explicitly; the socket's owner and mode are checked.
  if (options.baseUrl !== undefined && options.allowTcp !== true) throw new Error("createRemoteGuard: baseUrl (loopback TCP) needs allowTcp: true; prefer the unix socket (socketPath), whose owner and mode the guard checks before sending the token");
  // A token goes into a header: a line break could add headers of its own.
  if (options.token !== undefined && !/^[\x21-\x7e]+$/.test(options.token)) throw new Error("createRemoteGuard: token must be printable ASCII without spaces");
  if (options.promptToken !== undefined && !/^[\x21-\x7e]+$/.test(options.promptToken)) throw new Error("createRemoteGuard: promptToken must be printable ASCII without spaces");
  const session = options.session ?? randomSession();
  if (session === "" || session.length > 200) throw new Error("createRemoteGuard: session must be 1 to 200 characters");
  const specs = options.tools ?? {};
  const timeoutMs = options.timeoutMs ?? 250;
  const failOpenReads = options.failOpenReads ?? true;
  const approvalTimeoutMs = options.approvalTimeoutMs ?? 300_000;
  const approvalPollMs = Math.max(10, options.approvalPollMs ?? 1000);
  const maxResponseBytes = options.maxResponseBytes ?? 2 * 1024 * 1024;
  const unattendedModes = options.unattendedPermissionModes ?? ["dontAsk", "bypassPermissions", "auto"];
  const roots = options.workspace === undefined ? undefined : Array.isArray(options.workspace) ? options.workspace : [options.workspace];
  const sessionPath = `/v1/sessions/${encodeURIComponent(session)}`;

  /** Reports that could not be sent, in order; each keeps its idempotency key (and its token) for the resend. */
  const unsent: { path: string; body: unknown; key: string; what: string; token?: string }[] = [];
  /** More reports failed than are kept: decisions stay failed closed for this guard. */
  let lostReports = false;
  /** No request before this time (a 429's Retry-After): no tight retry loop. */
  let quietUntil = 0;
  /** The session's untrusted flag as last seen (for ResultNote.becameUntrusted). */
  let lastUntrusted: boolean | undefined;
  /** Allowed decisions by call, for recordResult's decisionId. */
  const allowed = new Map<string, string>();
  /** This guard's asks, by decision id, until answered. */
  const asked = new BoundedMap<{ actionHash: string; answered: boolean }>(MAX_REMEMBERED);
  let localSeq = 0;

  function reportError(message: string): void {
    try {
      if (options.onError !== undefined) options.onError(message);
      else globalThis.console?.warn(message);
    } catch {
      // The failure is in the result's problems too.
    }
  }

  async function call(method: "GET" | "POST", path: string, body?: unknown, key?: string, auth = true, token = options.token): Promise<unknown> {
    const wait = quietUntil - Date.now();
    if (wait > 0) throw new RemoteHttpError("rate-limited", `rate limited; the sidecar asked for no request for another ${Math.ceil(wait / 1000)} s`, 429, wait);
    try {
      return await requestJson(target, {
        method,
        path,
        ...(auth && token !== undefined ? { token } : {}),
        ...(body !== undefined ? { body } : {}),
        ...(method === "POST" ? { idempotencyKey: key ?? newIdempotencyKey() } : {}),
        timeoutMs,
        maxResponseBytes,
      });
    } catch (e) {
      const err = e instanceof RemoteHttpError ? e : new RemoteHttpError("unavailable", String(e));
      if (err.kind === "rate-limited") quietUntil = Date.now() + Math.max(err.retryAfterMs ?? 1000, 1000);
      throw err;
    }
  }

  function remember(map: Map<string, string>, k: string, v: string): void {
    map.delete(k);
    map.set(k, v);
    if (map.size > MAX_REMEMBERED) map.delete(map.keys().next().value as string);
  }

  function formatOf(c: ToolCall): RemoteFormat {
    if (own(specs, c.tool) !== undefined) return "native";
    if (c.tool.startsWith("mcp__")) return "mcp";
    return options.format ?? "native";
  }

  function actionOf(c: ToolCall, format: RemoteFormat): Record<string, unknown> {
    if (format === "mcp") {
      // mcp__<server>__<tool>: a server name never holds "__"; the tool name may.
      const rest = c.tool.slice("mcp__".length);
      const at = rest.indexOf("__");
      const server = at > 0 ? rest.slice(0, at) : rest;
      const tool = at > 0 ? rest.slice(at + 2) : "";
      return { format, tool, input: c.input, ...(c.callId !== undefined ? { callId: c.callId } : {}), mcp: { server, source: c.mcpSource ?? "unknown" } };
    }
    return { format, tool: c.tool, input: c.input, ...(c.callId !== undefined ? { callId: c.callId } : {}) };
  }

  function contextOf(c: ToolCall, unattended = false): Record<string, unknown> {
    const attended = !unattended && options.attended !== false && !(c.permissionMode !== undefined && unattendedModes.includes(c.permissionMode));
    return { attended, ...(roots !== undefined ? { workspace: roots } : {}), ...(options.cwd !== undefined ? { cwd: options.cwd } : {}) };
  }

  /** The fail-closed table: the guard's own decision when the sidecar gave none. */
  function failed(c: ToolCall, format: RemoteFormat, err: RemoteHttpError, problems: string[] = []): RemoteDecision {
    const outage = err.kind === "unavailable" || err.kind === "timeout" || err.kind === "server" || err.kind === "rate-limited";
    // I6: only a sidecar that cannot answer (unreachable, timed out, 429, 503 overloaded) lets a read through. A 500
    // means it took the request and failed on it, which a crafted request can cause: that fails closed, reads too.
    const unanswered = outage && !(err.kind === "server" && err.status !== 503);
    const readOnly = unanswered && failOpenReads && readOnlyBySpec(c.tool, specs) && !lostReports && unsent.length === 0;
    const rule = !outage ? "FW-API-ERROR" : err.kind === "rate-limited" ? "FW-RATE-LIMITED" : "FW-UNAVAILABLE";
    const failure: RemoteFailure = { kind: err.kind, ...(err.status !== undefined ? { status: err.status } : {}), detail: err.message };
    const reason = readOnly
      ? `LaunchSafe Agent Firewall could not check this action (${err.message}); it only reads trusted, non-private data, so it may go ahead`
      : `LaunchSafe Agent Firewall could not check this action (${err.message}) and blocked it to be safe`;
    localSeq += 1;
    const verdict: GuardVerdict = readOnly ? "allow" : "deny";
    const rules = readOnly ? [] : [rule];
    const message = readOnly ? "" : safeText(`${reason}. (rule ${rule})`);
    reportError(`LaunchSafe Agent Firewall: ${c.tool}: ${err.message} (${verdict}${readOnly ? "" : `, ${rule}`})`);
    return { id: `${session}:local:${localSeq}`, decisionId: null, verdict, call: c, rules, reasons: [safeText(reason)], message, actionHash: "", format, ruleDetails: rules.map((id) => ({ id, outcome: "deny", reason })), failure, ...(problems.length > 0 ? { problems } : {}) };
  }

  function parseDecision(raw: unknown, c: ToolCall, format: RemoteFormat, dryRun: boolean): RemoteDecision {
    const bad = (why: string): never => {
      throw new RemoteHttpError("protocol", `the decision is not the contract's shape (${why})`, 200);
    };
    if (!isObj(raw)) return bad("not an object");
    const { decisionId, verdict, rules, message, actionHash } = raw;
    if (typeof decisionId !== "string" || decisionId === "") return bad("decisionId");
    if (typeof verdict !== "string" || !VERDICTS.has(verdict as GuardVerdict)) return bad("verdict");
    if (!Array.isArray(rules)) return bad("rules");
    const ruleDetails: RemoteRule[] = [];
    for (const r of rules) {
      if (!isObj(r) || typeof r.id !== "string") return bad("a rule");
      ruleDetails.push({ id: r.id, outcome: typeof r.outcome === "string" ? r.outcome : "", reason: typeof r.reason === "string" ? r.reason : "" });
    }
    if (typeof message !== "string") return bad("message");
    if (typeof actionHash !== "string") return bad("actionHash");
    let approval: RemoteDecision["approval"];
    if (raw.approval !== undefined && raw.approval !== null) {
      const a = raw.approval;
      if (!isObj(a) || typeof a.id !== "string" || a.id === "" || typeof a.status !== "string" || !APPROVAL_STATUSES.has(a.status as RemoteApprovalStatus)) return bad("approval");
      approval = { id: a.id, status: a.status as RemoteApprovalStatus };
    }
    // A recorded hold is a queue item; without one it could never be approved. An ask has none (api-v0.md:
    // the host's person answers it); approvedByQueue() puts it in the queue when someone says yes.
    if (!dryRun && verdict === "hold" && approval === undefined) return bad("a hold without an approval");
    const s = raw.session === undefined ? undefined : sessionState(raw.session);
    if (s === null) return bad("session");
    const engine = isObj(raw.engine) && typeof raw.engine.version === "string" ? { version: raw.engine.version } : undefined;
    const log = isObj(raw.log) && typeof raw.log.seq === "number" && typeof raw.log.hash === "string" ? { seq: raw.log.seq, hash: raw.log.hash } : undefined;
    const v = verdict as GuardVerdict;
    return {
      id: decisionId,
      decisionId,
      verdict: v,
      call: c,
      rules: ruleDetails.map((r) => r.id),
      reasons: ruleDetails.map((r) => safeText(r.reason)),
      // The sidecar escapes it; escaped again here because it crossed a socket.
      message: v === "allow" ? safeText(message) : safeText(message !== "" ? message : `LaunchSafe Agent Firewall: ${v} (rule ${ruleDetails.map((r) => r.id).join(", ")})`),
      actionHash,
      format,
      ruleDetails,
      ...(s !== undefined ? { session: s } : {}),
      ...(approval !== undefined ? { approval } : {}),
      ...(v === "hold" && approval !== undefined ? { held: { id: approval.id } } : {}),
      ...(engine !== undefined ? { engine } : {}),
      ...(log !== undefined ? { log } : {}),
    };
  }

  /** Sends the reports kept from earlier failures, in order. False: some are still unsent. */
  async function flush(problems: string[]): Promise<boolean> {
    while (unsent.length > 0) {
      const r = unsent[0] as (typeof unsent)[number];
      try {
        const raw = await call("POST", r.path, r.body, r.key, true, r.token ?? options.token);
        if (!isObj(raw) || raw.recorded !== true) throw new RemoteHttpError("protocol", "the answer is not { recorded: true }", 200);
        unsent.shift();
      } catch (e) {
        const err = e as RemoteHttpError;
        if (err.kind === "api-error" || err.kind === "protocol") {
          // The sidecar refuses it for good (bad request, unknown session): resending cannot help.
          unsent.shift();
          lostReports = true;
          problems.push(`${r.what} was refused by the sidecar (${err.message}); this guard now fails closed`);
          reportError(`LaunchSafe Agent Firewall: ${r.what} was refused (${err.message}); decisions now fail closed`);
          continue;
        }
        problems.push(`${r.what} could not be sent yet (${err.message})`);
        return false;
      }
    }
    return !lostReports;
  }

  async function decideOnce(c: ToolCall, dryRun: boolean, unattended = false): Promise<RemoteDecision> {
    const format = formatOf(c);
    const problems: string[] = [];
    try {
      if (!(await flush(problems))) {
        const why = lostReports ? "an untrusted input, prompt or result report was refused, so the sidecar's session may be looser than this agent's" : "an untrusted input, prompt or result report is still unsent";
        return failed(c, format, new RemoteHttpError(lostReports ? "api-error" : "unavailable", why), problems);
      }
      const raw = await call("POST", "/v1/decide", { session, action: actionOf(c, format), context: contextOf(c, unattended), dryRun, ...(c.usage !== undefined ? { usage: c.usage } : {}) });
      const d = parseDecision(raw, c, format, dryRun);
      if (problems.length > 0) d.problems = problems;
      if (d.session !== undefined && !dryRun) lastUntrusted = d.session.untrusted;
      return d;
    } catch (e) {
      return failed(c, format, e instanceof RemoteHttpError ? e : new RemoteHttpError("protocol", String(e)), problems);
    }
  }

  async function check(c: ToolCall): Promise<RemoteDecision> {
    return decideOnce(c, true);
  }

  async function decide(c: ToolCall): Promise<RemoteDecision> {
    const d = await decideOnce(c, false);
    if (d.verdict === "allow" && d.decisionId !== null) remember(allowed, callKey(c), d.decisionId);
    if (d.verdict === "ask" && d.decisionId !== null) asked.set(d.id, { actionHash: d.actionHash, answered: false });
    if ((d.verdict === "ask" || d.verdict === "hold") && options.onPending !== undefined) {
      try {
        options.onPending(d);
      } catch (e) {
        d.problems = [...(d.problems ?? []), `onPending failed: ${(e as Error).message}`];
      }
    }
    return d;
  }

  async function sleep(ms: number, signal?: AbortSignal): Promise<void> {
    await new Promise<void>((resolve) => {
      const t = setTimeout(done, ms);
      function done(): void {
        clearTimeout(t);
        signal?.removeEventListener("abort", done);
        resolve();
      }
      signal?.addEventListener("abort", done, { once: true });
    });
  }

  async function waitForApproval(a: string | RemoteDecision, opts: { timeoutMs?: number; signal?: AbortSignal } = {}): Promise<ApprovalWait> {
    const id = typeof a === "string" ? a : (a.approval?.id ?? "");
    if (id === "") return { id, status: "pending", error: "no approval id (only an ask or hold from the sidecar has one)" };
    const deadline = Date.now() + (opts.timeoutMs ?? approvalTimeoutMs);
    let last = "";
    for (;;) {
      if (opts.signal?.aborted === true) return { id, status: "pending", error: "the wait was aborted" };
      let pause = approvalPollMs;
      try {
        const raw = await call("GET", `/v1/approvals/${encodeURIComponent(id)}`);
        if (!isObj(raw) || typeof raw.status !== "string" || !APPROVAL_STATUSES.has(raw.status as RemoteApprovalStatus) || (raw.id !== undefined && raw.id !== id)) {
          return { id, status: "pending", error: "the approval is not the contract's shape" };
        }
        const status = raw.status as RemoteApprovalStatus;
        if (status !== "pending") return { id, status };
      } catch (e) {
        const err = e as RemoteHttpError;
        // A refusal (unknown approval, bad token) will not change by waiting; an outage might.
        if (err.kind === "api-error" || err.kind === "protocol") return { id, status: "pending", error: err.message };
        last = err.message;
        if (err.kind === "rate-limited") pause = Math.max(pause, err.retryAfterMs ?? pause);
      }
      const left = deadline - Date.now();
      if (left <= 0) return { id, status: "pending", ...(last !== "" ? { error: last } : {}) };
      await sleep(Math.min(pause, left), opts.signal);
    }
  }

  /**
   * An ask has no queue item (api-v0.md: the host's person answers it), but only the queue's approval lets a
   * call run here. So the identical call is decided again with `attended: false`, which the sidecar turns
   * into a hold: a queue item for the same action, shown by `queue list` and on a paired phone.
   */
  async function queued(d: RemoteDecision): Promise<{ hold?: RemoteDecision; note?: string }> {
    if (d.approval !== undefined) return { hold: d };
    const h = await decideOnce(d.call, false, true);
    if (h.verdict !== "hold" || h.approval === undefined || h.actionHash !== d.actionHash) {
      return { note: `LaunchSafe Agent Firewall: the ask could not be put in the firewall's approval queue (deciding it again gave ${h.verdict}${h.failure !== undefined ? `: ${h.failure.detail}` : ""}); the action was not let through` };
    }
    if (options.onPending !== undefined) {
      try {
        options.onPending(h);
      } catch {
        // Informs only; the wait goes on.
      }
    }
    return { hold: h };
  }

  /** Waits for the queue's approval of one of this guard's asks, then decides the identical call again. */
  async function approvedByQueue(d: RemoteDecision): Promise<{ outcome: ApprovalOutcome; retry?: RemoteDecision }> {
    const q = await queued(d);
    if (q.hold === undefined) return { outcome: { approved: false, note: q.note ?? "LaunchSafe Agent Firewall: no approval queue item" } };
    const w = await waitForApproval(q.hold);
    if (w.status !== "approved") {
      return { outcome: { approved: false, note: `LaunchSafe Agent Firewall: approval ${w.id} is ${w.status}${w.error !== undefined ? ` (${w.error})` : ""}; the action was not let through` } };
    }
    const retry = await decide(d.call);
    // The approval binds to the exact action: the retry must be allowed for the same hash.
    if (retry.verdict !== "allow" || retry.decisionId === null || retry.actionHash !== d.actionHash) {
      return { outcome: { approved: false, note: `LaunchSafe Agent Firewall: approval ${w.id} was given, but deciding the call again gave ${retry.verdict}${retry.failure !== undefined ? ` (${retry.failure.detail})` : ""}; the action was not let through` }, retry };
    }
    return { outcome: { approved: true, by: `the firewall's approval queue (${w.id})` }, retry };
  }

  /** Only an unanswered ask this guard handed out, for the action it was about. Marks it answered. */
  function claimAsk(d: RemoteDecision): boolean {
    const known = asked.get(d.id);
    if (known === undefined || known.answered || d.verdict !== "ask" || known.actionHash !== d.actionHash) return false;
    known.answered = true;
    asked.delete(d.id);
    return true;
  }

  async function requestApproval(d: RemoteDecision): Promise<ApprovalOutcome> {
    if (!claimAsk(d)) return { approved: false, note: "LaunchSafe Agent Firewall: not an unanswered ask from this guard" };
    return (await approvedByQueue(d)).outcome;
  }

  async function approveAsked(d: RemoteDecision, answer: ApprovalAnswer): Promise<ApprovalOutcome> {
    const a = normalizeAnswer(answer);
    if (!claimAsk(d)) return { ...a, approved: false, note: "LaunchSafe Agent Firewall: not an unanswered ask from this guard" };
    // A no stays a no (the queue item expires unanswered); a yes still needs the queue's approval.
    if (!a.approved) return a;
    const r = await approvedByQueue(d);
    return r.outcome.approved ? { ...r.outcome, ...(a.by !== undefined ? { by: `${a.by}; ${r.outcome.by ?? ""}` } : {}) } : r.outcome;
  }

  async function authorize(c: ToolCall): Promise<RemoteAuthorization> {
    try {
      const d = await decide(c);
      if (d.verdict === "allow") return { allowed: true, decision: d };
      if (d.verdict !== "ask") return { allowed: false, decision: d };
      claimAsk(d);
      const r = await approvedByQueue(d);
      return { allowed: r.outcome.approved, decision: d, approval: r.outcome, ...(r.retry !== undefined ? { retry: r.retry } : {}) };
    } catch (e) {
      // Nothing above throws by design; this is the last line of the table.
      return { allowed: false, decision: failed(c, formatOf(c), new RemoteHttpError("protocol", `internal error: ${(e as Error).message}`)) };
    }
  }

  /** Sends a report; on an outage keeps it for resending. */
  async function report(path: string, body: unknown, what: string, token?: string, verb = "sent"): Promise<RemoteRecorded & { redacted?: string }> {
    const problems: string[] = [];
    const key = newIdempotencyKey();
    const tok = token !== undefined ? { token } : {};
    const ok = await flush(problems);
    if (!ok && !lostReports) {
      // Keep order: this one waits behind the earlier ones.
      if (unsent.length >= MAX_PENDING_REPORTS) {
        lostReports = true;
        unsent.length = 0;
        problems.push(`${what} could not be ${verb} (more than ${MAX_PENDING_REPORTS} reports could not be sent; this guard now fails closed)`);
      } else {
        unsent.push({ path, body, key, what, ...tok });
        problems.push(`${what} could not be ${verb} (earlier reports are still unsent); it is sent before the next decision, which fails closed until it is`);
      }
      return { recorded: false, problems };
    }
    try {
      const raw = await call("POST", path, body, key, true, token ?? options.token);
      if (!isObj(raw) || raw.recorded !== true) throw new RemoteHttpError("protocol", "the answer is not { recorded: true }", 200);
      const redacted = typeof raw.output === "string" ? raw.output : undefined;
      return { recorded: true, ...(redacted !== undefined ? { redacted } : {}), ...(problems.length > 0 ? { problems } : {}) };
    } catch (e) {
      const err = e as RemoteHttpError;
      if (err.kind === "api-error" || err.kind === "protocol") {
        lostReports = true;
        problems.push(`${what} could not be ${verb} and was refused (${err.message}); this guard now fails closed`);
      } else if (unsent.length >= MAX_PENDING_REPORTS) {
        lostReports = true;
        unsent.length = 0;
        problems.push(`${what} could not be ${verb} (${err.message}); more than ${MAX_PENDING_REPORTS} reports could not be sent, so this guard now fails closed`);
      } else {
        unsent.push({ path, body, key, what, ...tok });
        problems.push(`${what} could not be ${verb} (${err.message}); it is sent before the next decision, which fails closed until it is`);
      }
      reportError(`LaunchSafe Agent Firewall: ${problems[problems.length - 1] ?? what}`);
      return { recorded: false, problems };
    }
  }

  async function reportInput(input: UntrustedInput): Promise<RemoteRecorded> {
    const source = String(input.source).slice(0, 200) || "untrusted input";
    const f = fitValue(input.content);
    const r = await report(`${sessionPath}/inputs`, { source, content: f.value, ...(input.private === true || f.cut ? { private: true } : {}) }, `untrusted input (${source})`);
    if (r.recorded) lastUntrusted = true;
    return f.cut ? { ...r, problems: [...(r.problems ?? []), "the content is larger than the API's 1 MiB limit: only its first part was scanned"] } : r;
  }

  async function recordPrompt(text: string): Promise<void> {
    // I1: with promptToken, the prompt goes with the token made for what the person typed, so the sidecar applies it.
    await report(`${sessionPath}/prompts`, { text: fitText(String(text)).text }, "the person's prompt", options.promptToken);
  }

  async function state(): Promise<RemoteSessionSnapshot> {
    const raw = await call("GET", sessionPath);
    const s = sessionState(raw);
    if (s === null) throw new RemoteHttpError("protocol", "the session is not the contract's shape", 200);
    lastUntrusted = s.untrusted;
    return { session, ...s };
  }

  async function recordResult(c: ToolCall, output: unknown, decisionOrOptions?: RemoteDecision | ResultOptions, more: ResultOptions = {}): Promise<RemoteResultNote> {
    // GuardPort passes the options third; a caller that has the decision passes it third and the options fourth.
    let decision: RemoteDecision | undefined;
    let options: ResultOptions = more;
    if (decisionOrOptions !== undefined) {
      if ("verdict" in decisionOrOptions) decision = decisionOrOptions;
      else options = decisionOrOptions;
    }
    const problems: string[] = [];
    const k = callKey(c);
    const decisionId = decision?.decisionId ?? allowed.get(k) ?? null;
    allowed.delete(k);
    const before = lastUntrusted;
    const f = fitValue(output);
    const failed = options.failed === true || (f.cut && capFailure(output, false) !== null);
    if (f.cut) problems.push("the output is larger than the API's 1 MiB limit: only its first part was scanned");
    if (decisionId === null) {
      // No sidecar decision to attach it to (decided while the sidecar was down, or never decided):
      // reported as untrusted input, which can only make the session stricter.
      const r = await reportInput({ source: `result of ${c.tool} (no decision from the sidecar)`, content: output, ...(f.cut ? { private: true } : {}) });
      const became = r.recorded && before !== true;
      return { becameUntrusted: became, secretsSeen: 0, recorded: r.recorded, ...(r.problems !== undefined || problems.length > 0 ? { problems: [...problems, ...(r.problems ?? [])] } : {}), ...(became ? { note: UNTRUSTED_NOTE } : {}) };
    }
    const r = await report(`${sessionPath}/results`, { decisionId, output: f.value, ...(failed ? { failed: true } : {}) }, `the result of ${c.tool}`, undefined, "recorded");
    const cutSource = `scan_incomplete: the output of ${c.tool} was larger than the API's 1 MiB limit`.slice(0, 200);
    if (!r.recorded) {
      if (f.cut && !lostReports) {
        if (unsent.length >= MAX_PENDING_REPORTS) {
          lostReports = true;
          unsent.length = 0;
        } else {
          unsent.push({ path: `${sessionPath}/inputs`, body: { source: cutSource, content: "", private: true }, key: newIdempotencyKey(), what: `the truncated result of ${c.tool}` });
        }
      }
      return { becameUntrusted: false, secretsSeen: 0, recorded: false, problems: [...(r.problems ?? []), ...problems] };
    }
    if (f.cut) {
      const cut = await report(`${sessionPath}/inputs`, { source: cutSource, content: "", private: true }, `the truncated result of ${c.tool}`, undefined, "recorded");
      if (!cut.recorded) {
        return { becameUntrusted: false, secretsSeen: 0, recorded: false, problems: [...(cut.problems ?? []), ...(r.problems ?? []), ...problems] };
      }
      lastUntrusted = true;
    }
    let became = f.cut && before === false;
    try {
      const s = await state();
      became = before === false && s.untrusted;
    } catch (e) {
      problems.push(`the session could not be read after recording (${(e as Error).message})`);
    }
    const allProblems = [...(r.problems ?? []), ...problems];
    return { becameUntrusted: became, secretsSeen: 0, recorded: true, ...(r.redacted !== undefined ? { redacted: r.redacted } : {}), ...(became ? { note: UNTRUSTED_NOTE } : {}), ...(allProblems.length > 0 ? { problems: allProblems } : {}) };
  }

  async function health(): Promise<RemoteHealth> {
    const raw = await call("GET", "/v1/health", undefined, undefined, false);
    if (!isObj(raw) || typeof raw.ok !== "boolean" || !isObj(raw.engine) || typeof raw.engine.version !== "string") throw new RemoteHttpError("protocol", "the health answer is not the contract's shape", 200);
    return { ok: raw.ok, engine: { version: raw.engine.version } };
  }

  return { session, check, decide, authorize, requestApproval, approveAsked, waitForApproval, recordResult, reportInput, recordPrompt, state, health };
}
