/**
 * The gateway's per-message pipeline (requests, results
 * and other server output, tools/list pinning and hiding). Transport-free:
 * stdio.ts and http.ts feed it parsed JSON-RPC messages and send what it
 * emits. One instance serves one wrapped server for one client.
 *
 * - Client requests: `tools/call`, `resources/read`, `prompts/get` and
 *   `completion/complete` are decided by the hook pipeline in full mode
 *   (src/hook/pipeline.ts runPreTool: same rules, ids, queue, log and budgets
 *   as the hooks); in hook mode the client's own hook decides and the gateway
 *   adds only what a hook cannot do. A call to a hidden tool is denied
 *   (FW-MCP-TOOL-HELD) in both modes. Unknown methods are refused
 *   (FW-MCP-METHOD, -32601) in both directions.
 * - Results: tools/list is pinned and filtered; results are scanned, and
 *   stripped, flagged or withheld (FW-MCP-WITHHELD); runPostTool records the
 *   taint and secrets in full mode.
 * - Input requests from the server (MRTR results, or legacy server requests):
 *   sampling from an untrusted server is refused (FW-MCP-SAMPLING),
 *   elicitation passes labelled with the server's name (a URL from an
 *   untrusted server is shown as text, never opened), roots pass and are
 *   logged. Input requests are not translated between eras.
 * - Eras: see era.ts. The upstream's era is probed once per process.
 *
 * Fail closed throughout: a call the engine could not check is not
 * forwarded; a result the scanner could not scan is withheld.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { actionHash } from "../engine/decide.js";
import { serverPolicy } from "../engine/mcp.js";
import { safeText } from "../engine/terminal.js";
import type { ScanOptions, ScanResult } from "../engine/content-scan.js";
import type { AdapterEvent } from "../adapters/types.js";
import { recordGatewayHookEvents, runPostTool, runPreTool, runTripwire, stateSessionId, trustedApproverKey, type HookEnv, type PipelineAdapter } from "../hook/pipeline.js";
import { guardMailResult } from "../runtime/mail/guard.js";
import { loadPolicy } from "../runtime/config.js";
import { atomicWrite, ensureDir, readText } from "../runtime/fsutil.js";
import type { Layout } from "../runtime/layout.js";
import { appendBounded, LogUnrecorded } from "../runtime/logbound.js";
import { notify, type NotifyDeps } from "../runtime/notify.js";
import { loadPins } from "../runtime/pins.js";
import { addQuarantine } from "../runtime/quarantine.js";
import { appendEvents } from "../runtime/store.js";
import { gatewayPolicy, type GatewayPolicy } from "../policy-gateway.js";
import type { FirewallConfig, NormalizedAction, StateEvent } from "../types.js";
import { VERSION } from "../version.js";
import { declaredVersion, discoverFromInitialize, initializeFromDiscover, isModernError, LEGACY_VERSIONS, META_CAPS, META_CLIENT, META_RELATED_TASK, META_VERSION, metaOf, MODERN_VERSION, serverVersionOf, withModernMeta, withoutModernMeta, type ClientIdentity, type Era } from "./era.js";
import { errorResponse, INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, isNotification, isRequest, isResponse, METHOD_NOT_FOUND, parseMessage, Pending, resultResponse, type Id, type Json, type Message, type Request, type Response } from "./jsonrpc.js";
import { callHidden, observeToolList } from "./pins.js";
import { scanResult, TOO_DEEP, withheldResult } from "./scan.js";
import { validMcpHeaderSchema } from "./headers.js";
import { serverNameProblem } from "./names.js";
import { logSafe } from "../sdk/guard.js";
import { statSync } from "node:fs";
import { refPaths, type VaultView } from "../engine/vault-ref.js";
import { scrubJson, type KnownValue } from "../engine/vault-scrub.js";
import { vaultPolicy } from "../policy-vault.js";
import type { VaultSubstitution } from "../types.js";
import { indexPath, loadIndex, vaultView } from "../runtime/vault/index.js";
import { defaultBackendFor, logDenied, readValues, substituteAtPaths, type BackendFor } from "../runtime/vault/substitute.js";
import { consumeGrant } from "../runtime/vault/tickets.js";
import { rotatingPrintsPath, withRotatingPrints } from "./oauth-vault.js";
import { own, setOwn } from "../own.js";

export const RULE_TOOL_HELD = "FW-MCP-TOOL-HELD";
export const RULE_WITHHELD = "FW-MCP-WITHHELD";
export const RULE_SAMPLING = "FW-MCP-SAMPLING";
export const RULE_METHOD = "FW-MCP-METHOD";
export const RULE_LOG_UNRECORDED = "FW-LOG-UNRECORDED";

/** Client to server requests the gateway knows (both eras). Anything else is refused. */
const CLIENT_METHODS = new Set(["initialize", "server/discover", "ping", "tools/list", "tools/call", "resources/list", "resources/templates/list", "resources/read", "resources/subscribe", "resources/unsubscribe", "prompts/list", "prompts/get", "completion/complete", "logging/setLevel", "subscriptions/listen"]);
const CLIENT_NOTIFICATIONS = new Set(["notifications/initialized", "notifications/cancelled", "notifications/progress", "notifications/roots/list_changed"]);
const SERVER_NOTIFICATIONS = new Set(["notifications/tools/list_changed", "notifications/resources/list_changed", "notifications/prompts/list_changed", "notifications/resources/updated", "notifications/progress", "notifications/message", "notifications/cancelled", "notifications/subscriptions/acknowledged"]);
const SERVER_REQUESTS = new Set(["ping", "sampling/createMessage", "elicitation/create", "roots/list"]);
const INPUT_METHODS = new Set(["sampling/createMessage", "elicitation/create", "roots/list"]);
const DECIDED = new Set(["tools/call", "resources/read", "prompts/get", "completion/complete"]);
const SCANNED = new Set(["tools/call", "resources/read", "prompts/get"]);
/** V31: list results whose entries the model can read (names, titles, descriptions), each entry scanned by itself. */
const LISTS: Record<string, string> = { "prompts/list": "prompts", "resources/list": "resources", "resources/templates/list": "resourceTemplates" };

/** The most tools of one tools/list result the gateway checks, pins and passes on. */
export const MAX_LISTED_TOOLS = 1000;

/** How long an approval question asked through the client stays answerable (the signed request state and a legacy ask). */
export const ASK_TTL_MS = 120_000;

/** Clients whose elicitation forms the model cannot answer, each verified by a captured fixture. None yet. */
export const VERIFIED_ELICITATION_CLIENTS: readonly string[] = [];

const INTERNAL = "lsfw-";
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

export interface CoreOptions {
  l: Layout;
  env: NodeJS.ProcessEnv;
  client: string;
  server: string;
  mode: "full" | "hook";
  /** Where the wrapped entry was configured: "user" (a person's own file) or "project" (repository content, never trusted). */
  source: string;
  /** The pin key's source: `gw-<client>` in full mode, the agent's own source in hook mode. */
  pinSource: string;
  /** The raw session id (the pipeline adds `gateway:`), asked for on every message (resets, idle gaps). */
  session: () => string;
  cwd: string;
  workspaceRoots: string[];
  mcpRoots?: string[];
  transport: "stdio" | "http";
  home?: string;
  now?: () => Date;
  detectNonInteractive?: (sessionId: string) => boolean;
  notifyDeps?: NotifyDeps;
  scratchRoots?: string[];
  /** How long the upstream may take to answer the era probe before it counts as legacy. */
  probeTimeoutMs?: number;
  setTimer?: (fn: () => void, ms: number) => () => void;
  /** Diagnostics (stderr). */
  diag?: (line: string) => void;
  /** Ten protocol violations by the upstream in a minute: the caller closes it. */
  onUpstreamAbuse?: () => void;
  /** The vault's stores (tests pass an in-memory one; the real ones never run under a test marker). */
  vaultBackend?: BackendFor;
  /** Tests: a failing engine or scanner, and the verified elicitation clients. */
  preTool?: typeof runPreTool;
  scan?: (text: string, o: ScanOptions) => ScanResult;
  verifiedElicitationClients?: readonly string[];
}

export interface Sink {
  client(m: Message): void;
  upstream(m: Message): void;
}

interface PendingCall {
  method: string;
  params: Json | undefined;
  /** The forwarded (era-translated) request, for a legacy client whose initialize was answered locally. */
  action?: NormalizedAction;
  approvedVia?: string;
}

/** Every string (and property name) in a JSON value made safe to show: terminal escapes, bidi and tag characters become visible escapes. */
function safeJson(v: unknown, depth = 0): unknown {
  if (typeof v === "string") return safeText(v);
  if (depth > 32) return null;
  if (Array.isArray(v)) return v.map((x) => safeJson(x, depth + 1));
  if (isObj(v)) {
    const out: Json = {};
    for (const [k, x] of Object.entries(v)) setOwn<unknown>(out, safeText(k, { keepNewlines: false }), safeJson(x, depth + 1));
    return out;
  }
  return v;
}

const NO_VAULT_ANSWER = "LaunchSafe Firewall withheld this answer from MCP server";

/** Why something was withheld, in words that match its signals (a check that could not finish is not a finding). */
function withheldWhy(signals: readonly string[]): string {
  const list = signals.join(", ");
  if (signals.includes(TOO_DEEP)) return `it is nested too deeply or holds too many values to be checked in full, so it was not passed on unchecked (${list})`;
  if (signals.includes("scan_failed")) return `it could not be checked (${list})`;
  return `it carries text hidden from people that is aimed at the AI assistant (${list})`;
}

export class GatewayCore {
  private upstreamEra: Era | "unknown" | "probing" | "failed" = "unknown";
  private clientEra: Era | "unknown" = "unknown";
  private identity: ClientIdentity = { capabilities: {}, info: { name: "unknown", version: "unknown" } };
  private queue: Message[] = [];
  private readonly pending = new Pending<PendingCall>();
  /** Upstream (legacy) requests forwarded to the client, by id. */
  private readonly serverRequests = new Pending<string>();
  private discover: Json | undefined;
  private initResult: Json | undefined;
  private serverVersion: string | undefined;
  private forwardedInitialize = false;
  private readonly schemas = new Map<string, unknown>();
  private violations: number[] = [];
  private internalSeq = 0;
  private readonly usedStates = new Set<string>();
  /** Per decided call (its action hash), the input requests and requestState passed on to the client. */
  private readonly inputKeys = new Map<string, { keys: Map<string, string>; requestState?: string }>();
  /** Legacy elicitation asks: our request id to the original client request, and the rules the question named (I2). */
  private readonly asks = new Map<string, { req: Request; action: NormalizedAction; at: number; params: Json | undefined; rules: readonly string[] }>();
  /** Values substituted into calls still in flight, by request id; dropped when the answer is scrubbed. */
  private readonly inflight = new Map<string, KnownValue[]>();
  private viewCache: { key: string; view: VaultView | undefined } | null = null;

  constructor(
    private readonly o: CoreOptions,
    private readonly out: Sink,
  ) {}

  // --- entry points -------------------------------------------------------------------------------

  /** A raw line or body from the client. Malformed JSON gets a parse error back and is logged. */
  clientText(text: string): void {
    this.guarded("client", null, () => {
      const p = parseMessage(text);
      if (!p.ok) {
        this.logEvent({ type: "gateway_protocol", from: "client", problem: p.reason });
        this.out.client(errorResponse(p.id, p.code, `LaunchSafe Firewall gateway: ${p.reason}`));
        return;
      }
      this.fromClient(p.msg);
    });
  }

  upstreamText(text: string): void {
    this.guarded("server", null, () => this.upstreamTextInner(text));
  }

  private upstreamTextInner(text: string): void {
    const p = parseMessage(text);
    if (!p.ok) {
      this.violation(`invalid message from the server: ${p.reason}`);
      if (p.id !== null && this.pending.has(p.id)) {
        this.pending.take(p.id);
        this.out.client(errorResponse(p.id, INVALID_REQUEST, "LaunchSafe Firewall gateway: the server sent an invalid message"));
      }
      return;
    }
    this.fromUpstream(p.msg);
  }

  /** The upstream sent more than 16 MiB in one message. */
  upstreamOversize(): void {
    this.violation("a message from the server was larger than 16 MiB");
  }

  /** The tool's input schema from the last tools/list (HTTP: Mcp-Param headers). */
  toolSchema(name: string): unknown {
    return this.schemas.get(name);
  }

  /** Whether a request the gateway forwarded upstream is still waiting for its answer (the HTTP transport fails it closed otherwise). */
  awaiting(id: Id): boolean {
    return this.pending.has(id);
  }

  /**
   * The HTTP transport got no real answer to one of the gateway's own era requests (the probe or the gateway's
   * initialize): the connection failed, timed out, was refused (401, 403, 429), redirected or broke with a server
   * error. That says nothing about the server's protocol version, so the era is left undecided (never "legacy",
   * never "failed"): the requests waiting for it get the error, and the next request probes again.
   * Returns whether `id` was one of those requests (otherwise the caller answers it as before).
   */
  upstreamUnavailable(id: Id, message: string): boolean {
    const call = this.pending.peek(id);
    if (call === undefined || (call.method !== "lsfw/probe" && call.method !== "lsfw/init")) return false;
    this.guarded("server", null, () => this.resetEra(id, message));
    return true;
  }

  private resetEra(id: Id, message: string): void {
    this.pending.take(id);
    this.probeDone = null;
    this.upstreamEra = "unknown";
    this.discover = undefined;
    this.initResult = undefined;
    this.diag(`LaunchSafe Firewall gateway: ${safeText(message, { keepNewlines: false }).slice(0, 300)}; the protocol version is not decided, the next request tries again.`);
    this.logEvent({ type: "gateway_protocol", from: "server", problem: `era probe unanswered: ${safeText(message, { keepNewlines: false })}`.slice(0, 300) });
    const q = this.queue;
    this.queue = [];
    for (const m of q) {
      if (!isRequest(m)) continue;
      if (m.method === "tools/call") this.out.client(resultResponse(m.id, { content: [{ type: "text", text: message }], isError: true }));
      else this.out.client(errorResponse(m.id, -32000, message));
    }
  }

  get era(): { client: string; upstream: string } {
    return { client: this.clientEra, upstream: this.upstreamEra };
  }

  /**
   * FZ3: every way into the core is guarded. An exception while handling one message must not end the
   * gateway (the stdio wrapper's data handler would throw it out of the process, the HTTP server would lose
   * every route's session); it fails closed instead: the request gets an error, nothing more is forwarded.
   */
  fromClient(m: Message): void {
    this.guarded("client", m, () => this.fromClientInner(m));
  }

  fromUpstream(m: Message): void {
    this.guarded("server", m, () => this.fromUpstreamInner(m));
  }

  private guarded(from: "client" | "server", m: Message | null, fn: () => void): void {
    try {
      fn();
    } catch (e) {
      this.internalError(from, m, e);
    }
  }

  private internalError(from: "client" | "server", m: Message | null, e: unknown): void {
    try {
      const why = safeText(e instanceof Error ? e.message : String(e), { keepNewlines: false }).slice(0, 200);
      this.diag(`LaunchSafe Firewall gateway: an internal error was caught while handling a message from the ${from} (${why}); nothing was forwarded.`);
      this.logEvent({ type: "gateway_protocol", from, problem: `internal error: ${why}`.slice(0, 300) });
      if (m === null) return;
      if (from === "client" && isRequest(m)) {
        // A request that reached the server before the failure gets no answer through: the client has its error.
        if (this.pending.has(m.id)) this.pending.take(m.id);
        this.out.client(errorResponse(m.id, INTERNAL_ERROR, "LaunchSafe Firewall gateway: an internal error stopped this request; it was not completed"));
      } else if (from === "server" && isResponse(m) && m.id !== null && this.pending.has(m.id)) {
        this.pending.take(m.id);
        this.out.client(errorResponse(m.id, INTERNAL_ERROR, "LaunchSafe Firewall gateway: an internal error stopped the server's answer; it was withheld"));
      } else if (from === "server" && isRequest(m)) {
        this.out.upstream(errorResponse(m.id, INTERNAL_ERROR, "LaunchSafe Firewall gateway: an internal error stopped this request"));
      }
    } catch {
      // Reporting the failure failed too (a closed stream): there is nothing left to do but not crash.
    }
  }

  private fromClientInner(m: Message): void {
    if (isResponse(m)) return this.clientResponse(m);
    if (isRequest(m) && typeof m.id === "string" && m.id.startsWith(INTERNAL)) {
      this.out.client(errorResponse(m.id, INVALID_REQUEST, `LaunchSafe Firewall gateway: request ids starting with "${INTERNAL}" are reserved`));
      return;
    }
    if (this.clientEra === "unknown" && "method" in m) {
      if (m.method === "initialize") {
        this.clientEra = "legacy";
        const p = m.params ?? {};
        this.identity = { capabilities: isObj(p.capabilities) ? p.capabilities : {}, info: isObj(p.clientInfo) ? p.clientInfo : this.identity.info };
      } else if (declaredVersion(m.params) !== null) {
        this.clientEra = "modern";
        const meta = metaOf(m.params);
        this.identity = { capabilities: isObj(meta[META_CAPS]) ? meta[META_CAPS] : {}, info: isObj(meta[META_CLIENT]) ? meta[META_CLIENT] : this.identity.info };
      }
    }
    if (this.upstreamEra === "failed") {
      if (isRequest(m)) this.out.client(errorResponse(m.id, INVALID_REQUEST, "LaunchSafe Firewall gateway: the server's protocol version could not be agreed, so the gateway refuses the connection"));
      return;
    }
    if (this.upstreamEra !== "modern" && this.upstreamEra !== "legacy") {
      this.queue.push(m);
      if (this.upstreamEra === "unknown") this.probe();
      return;
    }
    this.handleClient(m);
  }

  private fromUpstreamInner(m: Message): void {
    if (isResponse(m)) return this.upstreamResponse(m);
    if (isRequest(m)) return this.upstreamRequest(m);
    if (isNotification(m)) return this.upstreamNotification(m);
  }

  // --- era negotiation ----------------------------------------------------------------------------

  private internalId(kind: string): string {
    return `${INTERNAL}${kind}-${++this.internalSeq}`;
  }

  private probe(): void {
    this.upstreamEra = "probing";
    const id = this.internalId("probe");
    this.pending.add(id, { method: "lsfw/probe", params: undefined });
    let done = false;
    const cancel = (this.o.setTimer ?? defaultTimer)(() => {
      if (done || !this.pending.has(id)) return;
      done = true;
      // Over HTTP a slow or silent server is not a legacy one (stdio: no answer means legacy, as documented).
      if (this.o.transport === "http") return this.guarded("server", null, () => this.resetEra(id, `MCP server ${this.o.server} did not answer the protocol version check in time`));
      this.pending.take(id);
      this.guarded("server", null, () => this.decided("legacy"));
    }, this.o.probeTimeoutMs ?? 3000);
    this.probeDone = (r: Response) => {
      done = true;
      cancel();
      if (r.result !== undefined) {
        const versions = Array.isArray(r.result.supportedVersions) ? r.result.supportedVersions : [];
        if (!versions.includes(MODERN_VERSION)) return this.decided("failed", `the server supports ${versions.map(String).join(", ") || "no version"}, not ${MODERN_VERSION}`);
        try {
          this.discover = this.checkedInstructions(r.result);
        } catch (e) {
          return this.decided("failed", `the server's instructions could not be checked (${(e as Error).message})`);
        }
        this.serverVersion = serverVersionOf(r.result);
        return this.decided("modern");
      }
      const code = r.error?.code ?? 0;
      if (isModernError(code)) {
        const supported = isObj(r.error?.data) && Array.isArray(r.error.data.supported) ? r.error.data.supported : [];
        return this.decided("failed", `the server speaks a modern MCP version the gateway does not know (${supported.map(String).join(", ")})`);
      }
      this.decided("legacy");
    };
    this.out.upstream({ jsonrpc: "2.0", id, method: "server/discover", params: { _meta: { "io.modelcontextprotocol/protocolVersion": MODERN_VERSION, [META_CAPS]: this.identity.capabilities, [META_CLIENT]: { name: "launchsafe-firewall-gateway", version: VERSION } } } });
  }

  private probeDone: ((r: Response) => void) | null = null;

  private decided(era: Era | "failed", why?: string): void {
    if (era === "failed") {
      this.upstreamEra = "failed";
      this.diag(`LaunchSafe Firewall gateway: ${why ?? "era negotiation failed"}; refusing the connection.`);
      this.logEvent({ type: "gateway_protocol", from: "server", problem: `era negotiation failed: ${why ?? ""}`.slice(0, 300) });
      const q = this.queue;
      this.queue = [];
      for (const m of q) if (isRequest(m)) this.out.client(errorResponse(m.id, INVALID_REQUEST, `LaunchSafe Firewall gateway: ${why ?? "the server's protocol version could not be agreed"}`));
      return;
    }
    this.upstreamEra = era;
    const first = this.queue.find((m) => "method" in m);
    if (era === "legacy" && !(first !== undefined && first.method === "initialize")) {
      // A modern client (or one that skipped the handshake) to a legacy server: the gateway initializes it.
      const id = this.internalId("init");
      this.pending.add(id, { method: "lsfw/init", params: undefined });
      this.out.upstream({ jsonrpc: "2.0", id, method: "initialize", params: { protocolVersion: LEGACY_VERSIONS[0], capabilities: this.identity.capabilities, clientInfo: this.identity.info } });
      return;
    }
    this.flush();
  }

  private flush(): void {
    const q = this.queue;
    this.queue = [];
    for (const m of q) this.guarded("client", m, () => this.handleClient(m));
  }

  // --- client to server ---------------------------------------------------------------------------

  private handleClient(m: Message): void {
    if (isNotification(m)) {
      if (!CLIENT_NOTIFICATIONS.has(m.method)) {
        this.logEvent({ type: "gateway_protocol", from: "client", problem: `unknown notification ${m.method.slice(0, 100)}`, rule: RULE_METHOD });
        return;
      }
      if (m.method === "notifications/initialized" && !this.forwardedInitialize) return;
      if (this.upstreamEra === "modern" && m.method !== "notifications/cancelled" && m.method !== "notifications/progress") return;
      this.out.upstream({ ...m, ...(m.params !== undefined ? { params: this.translateParams(m.params) } : {}) });
      return;
    }
    if (!isRequest(m)) return;
    if (this.inFlight(m.id)) {
      // V32: a second request with the id of one still in flight would take over its pending entry, so its
      // answer would be read as this one's (a tools/call result delivered as a list result, unscanned).
      this.logEvent({ type: "gateway_protocol", from: "client", problem: "a request reused the id of a request still in flight" });
      this.out.client(errorResponse(m.id, INVALID_REQUEST, "LaunchSafe Firewall gateway: a request with this id is still in flight; each request needs its own id, so this one was not passed on"));
      return;
    }
    if (!CLIENT_METHODS.has(m.method) && gatewayPolicy(this.config()).unknownMethods === "deny") {
      this.logEvent({ type: "decision", session: this.sessionId(), tool: `mcp__${this.o.server}__${m.method}`.slice(0, 200), verdict: "deny", rules: [RULE_METHOD], agent: "gateway", client: this.o.client, server: this.o.server, what: `unknown MCP method ${m.method}`.slice(0, 300) });
      this.out.client(errorResponse(m.id, METHOD_NOT_FOUND, `LaunchSafe Firewall gateway: the method ${safeText(m.method.slice(0, 100))} is not one the gateway knows, so it was not passed on. (rule ${RULE_METHOD})`));
      return;
    }
    switch (m.method) {
      case "initialize":
        return this.clientInitialize(m);
      case "server/discover":
        if (this.upstreamEra === "legacy") return this.out.client(resultResponse(m.id, discoverFromInitialize(this.initResult ?? {})));
        if (this.discover !== undefined) return this.out.client(resultResponse(m.id, this.discover));
        return this.forward(m);
      case "ping":
        if (this.upstreamEra === "modern") return this.out.client(resultResponse(m.id, {}));
        return this.forward(m);
      case "subscriptions/listen":
        if (this.upstreamEra === "legacy") return this.out.client(errorResponse(m.id, METHOD_NOT_FOUND, "LaunchSafe Firewall gateway: this server speaks an MCP version before 2026-07-28, which has no subscriptions/listen; the gateway does not translate it"));
        return this.forward(m);
      default:
        if (DECIDED.has(m.method)) return this.decideCall(m);
        return this.forward(m);
    }
  }

  private clientInitialize(m: Request): void {
    if (this.upstreamEra === "modern") {
      this.out.client(resultResponse(m.id, initializeFromDiscover(this.discover ?? {}, m.params?.protocolVersion)));
      return;
    }
    if (this.initResult !== undefined) {
      // The gateway already initialized this legacy server for an earlier request.
      this.out.client(resultResponse(m.id, this.initResult));
      return;
    }
    this.forwardedInitialize = true;
    this.forward(m);
  }

  /** Params as the upstream's era expects them. */
  private translateParams(params: Json | undefined): Json | undefined {
    if (this.upstreamEra === "modern" && this.clientEra !== "modern") return withModernMeta(params, this.identity);
    if (this.upstreamEra === "legacy" && this.clientEra === "modern") return withoutModernMeta(params);
    return params;
  }

  /** A client request id that is still waiting for its answer (forwarded, or asked about in the client). */
  private inFlight(id: Id): boolean {
    if (this.pending.has(id)) return true;
    for (const a of this.asks.values()) if (typeof a.req.id === typeof id && a.req.id === id) return true;
    return false;
  }

  private forward(m: Request, extra: Partial<PendingCall> = {}, params: Json | undefined = m.params, upstreamParams: Json | undefined = params): void {
    if (this.pending.has(m.id)) {
      this.out.client(errorResponse(m.id, INVALID_REQUEST, "LaunchSafe Firewall gateway: a request with this id is still in flight; each request needs its own id, so this one was not passed on"));
      return;
    }
    if (!this.pending.add(m.id, { method: m.method, params, ...extra })) {
      this.out.client(errorResponse(m.id, INVALID_REQUEST, "LaunchSafe Firewall gateway: too many requests in flight (1,000)"));
      return;
    }
    const p = this.translateParams(upstreamParams);
    this.out.upstream({ jsonrpc: "2.0", id: m.id, method: m.method, ...(p !== undefined ? { params: p } : {}) });
  }

  private config(): FirewallConfig {
    return loadPolicy(this.o.l, [this.o.cwd]).config;
  }

  private sessionId(): string {
    return stateSessionId("gateway", this.o.session());
  }

  private gp(): GatewayPolicy {
    return gatewayPolicy(this.config());
  }

  /** The action a decided request stands for (the request's method and params). */
  private actionOf(m: Request, inputResponses?: Json): NormalizedAction | { error: string } {
    const p = m.params ?? {};
    const s = this.o.server;
    const ir = inputResponses !== undefined ? { inputResponses } : {};
    if (m.method === "tools/call") {
      if (typeof p.name !== "string" || p.name === "") return { error: "tools/call needs params.name" };
      if (p.arguments !== undefined && !isObj(p.arguments)) return { error: "tools/call params.arguments must be an object" };
      const args = isObj(p.arguments) ? p.arguments : {};
      return {
        tool: `mcp__${s}__${p.name}`,
        input: inputResponses !== undefined && Object.hasOwn(args, "inputResponses") ? { ...args, inputResponses: [own(args, "inputResponses"), inputResponses] } : { ...args, ...ir },
      };
    }
    if (m.method === "resources/read") {
      if (typeof p.uri !== "string") return { error: "resources/read needs params.uri" };
      return { tool: `mcp__${s}__read_resource`, input: { uri: p.uri, ...ir } };
    }
    if (m.method === "prompts/get") {
      if (typeof p.name !== "string") return { error: "prompts/get needs params.name" };
      return { tool: `mcp__${s}__get_prompt`, input: { name: p.name, arguments: isObj(p.arguments) ? p.arguments : {}, ...ir } };
    }
    // The context's arguments are forwarded, so they are part of what is decided.
    return { tool: `mcp__${s}__get_completion`, input: { ref: p.ref ?? null, argument: p.argument ?? null, ...(p.context !== undefined ? { context: p.context } : {}) } };
  }

  /** A refusal in the shape the method's caller reads: a tool error for tools/call, a JSON-RPC error otherwise. */
  private refuse(m: Request, text: string): void {
    const t = safeText(text);
    if (m.method === "tools/call") this.out.client(resultResponse(m.id, { resultType: "complete", content: [{ type: "text", text: t }], isError: true }));
    else this.out.client(errorResponse(m.id, INVALID_REQUEST, t));
  }

  private decideCall(m: Request): void {
    // A server name the engine would read back as another server's (mcp__crm___x is server "crm") is never decided.
    const badName = serverNameProblem(this.o.server);
    if (badName !== null) {
      this.refuse(m, `LaunchSafe Firewall did not pass this on: the MCP server's name ${badName}. Rename the server in the client's configuration and wrap it again.`);
      return;
    }
    const base = this.actionOf(m);
    if ("error" in base) {
      this.out.client(errorResponse(m.id, INVALID_PARAMS, `LaunchSafe Firewall gateway: ${base.error}`));
      return;
    }
    let gp: GatewayPolicy;
    try {
      gp = this.gp();
      if (m.method === "tools/call") {
        const name = (m.params as Json).name as string;
        const why = callHidden(loadPins(this.o.l).pins, this.pinKey(), name, gp.toolChanges === "hide", this.o.mode === "hook");
        if (why !== null) {
          // R1 (V23): the call is refused unseen by the engine, but a decoy value in its arguments is still the
          // signal. In hook mode the client's own hook already ran its tripwire on this call.
          if (this.o.mode === "full") {
            const rawAction = this.actionOf(m, isObj(m.params?.inputResponses) ? m.params.inputResponses : undefined) as NormalizedAction;
            const t = runTripwire(this.event("pre_tool", rawAction), this.adapter(m.method), this.hookEnv(), this.o.l);
            if (t !== "") this.diag(t);
          }
          this.logEvent({ type: "decision", session: this.sessionId(), tool: base.tool, verdict: "deny", rules: [RULE_TOOL_HELD], agent: "gateway", client: this.o.client, server: this.o.server, what: why.slice(0, 300) });
          this.refuse(m, `LaunchSafe Firewall blocked this: ${why}.\nThe tool is hidden until a person reviews it. If you expected the change, run in your own terminal: launchsafe-firewall pins accept ${this.o.server}\n(rule ${RULE_TOOL_HELD})`);
          return;
        }
      }
    } catch (e) {
      this.refuse(m, `LaunchSafe Firewall could not check this call and did not pass it on (${(e as Error).message}). Run "launchsafe-firewall doctor" to find the problem.`);
      return;
    }
    // Elicitation approval retry (opt-in for verified clients): our own requestState.
    const params = m.params ?? {};
    // Only the parameters the method defines go on: anything else was never part of the decision (a value
    // under an unknown key is not an argument the engine read), so it is dropped, not forwarded unread.
    let forwardParams: Json | undefined = knownParams(m.method, m.params);
    const dropped = Object.keys(params).filter((k) => forwardParams === undefined || !Object.hasOwn(forwardParams, k));
    // Inside `_meta`, `task`, `requestState` and `inputResponses` too, only what the protocol defines goes on.
    if (forwardParams !== undefined) {
      const tidy = this.tidyForwarded(forwardParams, actionHash(base));
      forwardParams = tidy.params;
      dropped.push(...tidy.dropped);
    }
    // LG5: every dropped field is named in the log (`fields`, bounded by logbound), not only the first 300 characters.
    if (dropped.length > 0) this.logEvent({ type: "gateway_protocol", from: "client", problem: `dropped parameters ${m.method} does not define: ${dropped.join(", ")}`.slice(0, 300), fields: dropped, count: dropped.length, client: this.o.client, server: this.o.server });
    if (typeof params.requestState === "string" && params.requestState.startsWith("lsfw1.")) {
      const asked = this.verifyApprovalState(params.requestState, actionHash(base));
      const ok = isObj(params.inputResponses) && isObj(params.inputResponses.launchsafe_approval) && params.inputResponses.launchsafe_approval.action === "accept";
      if (asked === null || !ok) {
        this.refuse(m, "LaunchSafe Firewall did not pass this on: the approval it carries is not valid (expired, used, or for another action). Ask again, or approve it in your terminal with launchsafe-firewall queue approve.");
        return;
      }
      forwardParams = Object.fromEntries(Object.entries(forwardParams ?? {}).filter(([k]) => k !== "requestState" && k !== "inputResponses"));
      this.approvedForward(m, base, "elicitation", forwardParams, asked);
      return;
    }
    const a = this.actionOf(m, isObj(forwardParams?.inputResponses) ? forwardParams.inputResponses : undefined) as NormalizedAction;
    if (this.o.mode === "hook") {
      // The client's own hook decided; the gateway puts values in only for what that decision allowed.
      if (m.method === "tools/call" && refPaths(a.input).length > 0) {
        const name = (m.params as Json).name as string;
        const grant = (() => {
          try {
            return consumeGrant(this.o.l, this.o.server, name, a.input, this.o.now?.() ?? new Date());
          } catch {
            return null;
          }
        })();
        if (grant === null) {
          this.vaultRefused(m, a, "it carries vault references, and no decision of the firewall's hook allowed putting their values in (the hook is not installed for this client, the call changed, or its approval expired)");
          return;
        }
        this.substituteAndForward(m, a, grant.substitute, forwardParams);
        return;
      }
      this.forward(m, { action: a }, forwardParams);
      return;
    }
    let res: ReturnType<typeof runPreTool>;
    try {
      res = (this.o.preTool ?? runPreTool)(this.event("pre_tool", a), this.adapter(m.method), this.hookEnv(), this.o.l);
    } catch (e) {
      this.refuse(m, `LaunchSafe Firewall could not check this call and did not pass it on (${(e as Error).message}). Run "launchsafe-firewall doctor" to find the problem.`);
      return;
    }
    if (res.outcome.stderr !== undefined && res.outcome.stderr !== "") this.diag(res.outcome.stderr);
    if (res.outcome.verdict === "allow") {
      const subs = (res.decision?.vault?.substitute ?? []).filter((x) => x.via === "gateway");
      if (subs.length > 0 && m.method === "tools/call") this.substituteAndForward(m, a, subs, forwardParams);
      else this.forward(m, { action: a }, forwardParams);
      return;
    }
    const d = res.decision;
    const approvable = d !== null && (d.verdict === "queue" || d.verdict === "ask") && res.item !== null && res.item.kind === "approval";
    if (approvable && gp.askVia === "elicitation" && this.elicitationVerified()) {
      this.askToApprove(m, a, res.outcome.message, forwardParams, d.rules);
      return;
    }
    this.refuse(m, res.outcome.message);
  }

  private pinKey(): string {
    return `${this.o.pinSource}:${this.o.server}`;
  }

  private adapter(method: string): PipelineAdapter {
    const source = this.o.source;
    return {
      id: "gateway",
      normalize: (ev) => [{ tool: ev.tool ?? "", input: ev.input ?? {} }],
      provenance: () => source,
      nonInteractive: () => "the MCP gateway cannot put a question to a person, so approvals are queued",
      supportsAsk: false,
      supportsUpdatedOutput: true,
      gateway: { pinSource: this.o.pinSource, workspaceRoots: this.o.workspaceRoots, ...(this.o.mcpRoots !== undefined ? { mcpRoots: this.o.mcpRoots } : {}), pinCheck: method === "tools/call", ...(this.o.mode === "hook" ? { hookMode: true } : {}) },
    };
  }

  private recordEvents(events: readonly StateEvent[]): void {
    if (events.length === 0) return;
    appendEvents(this.o.l, this.sessionId(), events);
    if (this.o.mode === "hook") recordGatewayHookEvents(this.o.l, this.o.client, this.o.session(), events, this.o.now?.() ?? new Date());
  }

  private event(kind: "pre_tool" | "post_tool", a: NormalizedAction, output?: unknown): AdapterEvent {
    const parts = a.tool.split("__");
    return { kind, agent: "gateway", sessionId: this.o.session(), cwd: this.o.cwd, projectDir: this.o.cwd, tool: a.tool, input: a.input, ...(output !== undefined ? { output } : {}), mcp: { server: this.o.server, tool: parts.slice(2).join("__"), source: this.o.source }, raw: {} };
  }

  private hookEnv(): HookEnv {
    return {
      env: this.o.env,
      layout: this.o.l,
      ...(this.o.home !== undefined ? { home: this.o.home } : {}),
      ...(this.o.now !== undefined ? { now: this.o.now() } : {}),
      ...(this.o.detectNonInteractive !== undefined ? { detectNonInteractive: this.o.detectNonInteractive } : {}),
      ...(this.o.notifyDeps !== undefined ? { notifyDeps: this.o.notifyDeps } : {}),
      ...(this.o.scratchRoots !== undefined ? { scratchRoots: this.o.scratchRoots } : {}),
      logExtra: { client: this.o.client, server: this.o.server },
    };
  }

  // --- vault substitution ----------------------------------------------------------------

  /** The vault's view (names, bindings, fingerprints; never a value), re-read when the index file changes. */
  private vault(): VaultView | undefined {
    try {
      if (!vaultPolicy(this.config()).enabled) return undefined;
      let key = "absent";
      try {
        const st = statSync(indexPath(this.o.l));
        key = `${st.mtimeMs}:${st.size}`;
        const r = statSync(rotatingPrintsPath(this.o.l), { throwIfNoEntry: false });
        if (r !== undefined) key += `:${r.mtimeMs}:${r.size}`;
      } catch {
        key = "absent";
      }
      if (this.viewCache?.key !== key) this.viewCache = { key, view: key === "absent" ? undefined : withRotatingPrints(this.o.l, vaultView(loadIndex(this.o.l, trustedApproverKey(this.o.l, this.o.env)))) };
      return this.viewCache.view;
    } catch {
      return undefined;
    }
  }

  private vaultRefused(m: Request, a: NormalizedAction, why: string): void {
    const refs = [...new Set(refPaths(a.input).map((r) => r.ref.text))];
    this.logEvent({ type: "vault_denied", session: this.sessionId(), refs: refs.slice(0, 10), problem: why.slice(0, 300), destination: `mcp:${this.o.server}:${a.tool.split("__").slice(2).join("__")}`, client: this.o.client, server: this.o.server });
    this.refuse(m, `LaunchSafe Firewall did not pass this on: ${why}. The values were not read.`);
  }

  /**
   * After the verdict is allow: reads each value, puts it in place of its reference in the arguments sent
   * upstream (the HTTP transport regenerates the Mcp-Name and Mcp-Param headers from them), and remembers
   * the values only until the answer is scrubbed. The client never sees them; the pending call keeps the
   * client's own arguments, with the references.
   */
  private substituteAndForward(m: Request, a: NormalizedAction, subs: readonly VaultSubstitution[], params: Json | undefined): void {
    const session = this.sessionId();
    if (subs.some((x) => x.path === undefined)) {
      // A substitution says where its value goes (V17); one that does not (an older grant) puts nothing in.
      this.vaultRefused(m, a, "the decision that allowed its vault references does not say which argument each value goes into");
      return;
    }
    let read: ReturnType<typeof readValues>;
    try {
      read = readValues(this.o.l, subs, trustedApproverKey(this.o.l, this.o.env), this.o.vaultBackend ?? defaultBackendFor(this.o.l));
    } catch (e) {
      read = { ok: false, ref: subs[0]?.ref ?? "vault://", why: (e as Error).message };
    }
    if (!read.ok) {
      try {
        logDenied(this.o.l, { session, refs: subs.map((x) => x.ref), problem: `${read.ref}: ${read.why}`, destination: subs[0]?.destination ?? "", extra: { client: this.o.client, server: this.o.server } });
      } catch {
        // The refusal below still stands.
      }
      this.refuse(m, `LaunchSafe Firewall did not pass this on: could not use ${read.ref} (${read.why}). The call was not sent with the reference in place of the value.`);
      return;
    }
    const base = params ?? {};
    const upstream: Json = { ...base, arguments: substituteAtPaths(isObj(base.arguments) ? base.arguments : {}, subs, read.values) };
    const hash = actionHash(a);
    for (const sub of subs) this.logEvent({ type: "vault_use", session, ref: sub.ref, kind: sub.kind, via: "gateway", destination: sub.destination, binding: sub.binding, action: hash, verdict: "allow", client: this.o.client, server: this.o.server });
    this.inflight.set(`${typeof m.id}:${String(m.id)}`, read.values);
    this.forward(m, { action: a }, params, upstream);
  }

  /** Every value in flight, for scrubbing what comes back. */
  private inflightValues(): KnownValue[] {
    return [...this.inflight.values()].flat();
  }

  /** Replaces vaulted values in something from the server with their references; leftover = withhold it. */
  private scrubIn<T>(x: T): { value: T; leftover: boolean } {
    const known = this.inflightValues();
    const view = this.vault();
    if (known.length === 0 && (view === undefined || view.entries.every((e) => Object.keys(e.fingerprints).length === 0))) return { value: x, leftover: false };
    const r = scrubJson(x, known, view);
    if (r.leftover) this.logEvent({ type: "vault_scrub", session: this.sessionId(), client: this.o.client, server: this.o.server, replaced: r.count, withheld: true });
    return { value: r.value, leftover: r.leftover };
  }

  /** The wrapped server's stderr with vaulted values replaced (it may log the arguments it received). */
  scrubDiagnostic(text: string): string {
    const r = this.scrubIn(text);
    return r.leftover ? "[LaunchSafe Firewall withheld a line of the server's output: it carried a vaulted value]\n" : r.value;
  }

  // --- elicitation asks (opt-in, verified clients only) --------------------------------------

  private elicitationVerified(): boolean {
    const list = this.o.verifiedElicitationClients ?? VERIFIED_ELICITATION_CLIENTS;
    const name = typeof this.identity.info.name === "string" ? this.identity.info.name : "";
    return list.includes(name) && isObj(this.identity.capabilities.elicitation);
  }

  private stateKey(): Buffer {
    const p = join(this.o.l.keys, "gateway-elicitation.key");
    const t = readText(p);
    if (t !== null && /^[0-9a-f]{64}$/.test(t.trim())) return Buffer.from(t.trim(), "hex");
    ensureDir(this.o.l.keys);
    const k = randomBytes(32);
    atomicWrite(p, k.toString("hex"));
    return k;
  }

  private nowMs(): number {
    return (this.o.now?.() ?? new Date()).getTime();
  }

  /** Asks nobody answered in time are forgotten (refused), so the map never grows and a late yes approves nothing. */
  private expireAsks(): void {
    const now = this.nowMs();
    for (const [id, ask] of this.asks) {
      if (now - ask.at <= ASK_TTL_MS) continue;
      this.asks.delete(id);
      this.refuse(ask.req, "LaunchSafe Firewall: nobody answered the approval question in time, so the action was not passed on. Ask again.");
    }
  }

  /** The request state the client hands back with its answer: the session, the action, an expiry and the rules the question named (I2). */
  private signState(hash: string, rules: readonly string[]): string {
    const payload = Buffer.from(JSON.stringify({ s: this.sessionId(), h: hash, e: (this.o.now?.() ?? new Date()).getTime() + ASK_TTL_MS, n: randomBytes(8).toString("hex"), r: rules })).toString("base64url");
    return `lsfw1.${payload}.${createHmac("sha256", this.stateKey()).update(payload).digest("base64url")}`;
  }

  /** The rules the question named when the state is ours, unexpired, unused and for this action; null otherwise (a state without them is refused). */
  private verifyApprovalState(state: string, hash: string): string[] | null {
    const [, payload, mac] = state.split(".");
    if (payload === undefined || mac === undefined || this.usedStates.has(state)) return null;
    const want = createHmac("sha256", this.stateKey()).update(payload).digest();
    const got = Buffer.from(mac, "base64url");
    if (got.length !== want.length || !timingSafeEqual(got, want)) return null;
    try {
      const v = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { s: string; h: string; e: number; r?: unknown };
      if (v.s !== this.sessionId() || v.h !== hash || (this.o.now?.() ?? new Date()).getTime() > v.e) return null;
      if (!Array.isArray(v.r) || !v.r.every((x) => typeof x === "string")) return null;
      this.usedStates.add(state);
      return v.r as string[];
    } catch {
      return null;
    }
  }

  private askToApprove(m: Request, a: NormalizedAction, why: string, params: Json | undefined, rules: readonly string[]): void {
    const message = `LaunchSafe Firewall: allow this exact action once?\n${safeText(why)}`;
    const ask = { mode: "form", message, requestedSchema: { type: "object", properties: {} } };
    if (this.clientEra === "modern") {
      this.out.client(resultResponse(m.id, { resultType: "input_required", inputRequests: { launchsafe_approval: { method: "elicitation/create", params: ask } }, requestState: this.signState(actionHash(a), rules) }));
      return;
    }
    const id = this.internalId("ask");
    this.expireAsks();
    this.asks.set(id, { req: m, action: a, at: this.nowMs(), params, rules: [...rules] });
    this.out.client({ jsonrpc: "2.0", id, method: "elicitation/create", params: { message, requestedSchema: ask.requestedSchema } });
  }

  /** `rules`: the ones the question named; the call is decided again, and a rule asking now that it did not name is not covered (I2). */
  private approvedForward(m: Request, a: NormalizedAction, via: string, params: Json | undefined, rules: readonly string[]): void {
    if (refPaths(a.input).length > 0) {
      this.vaultRefused(m, a, "an approval given in the client does not cover vault references; approve it in your own terminal (launchsafe-firewall queue approve) and ask the agent to try again");
      return;
    }
    // The approval stands in for a queue approval of this exact action, and the call is decided again with it:
    // a stop, a spending limit or the monitor that applies now still denies it, and the decision is counted
    // (spending limits, budgets) and logged (LG1: not forwarded without its log entry) like any other.
    let res: ReturnType<typeof runPreTool>;
    try {
      const env = this.hookEnv();
      res = (this.o.preTool ?? runPreTool)(this.event("pre_tool", a), this.adapter(m.method), { ...env, logExtra: { ...(env.logExtra ?? {}), via }, approvedOnce: { actionHash: actionHash(a), via, rules } }, this.o.l);
    } catch (e) {
      this.refuse(m, `LaunchSafe Firewall could not check this approved call again and did not pass it on (${(e as Error).message}). Run "launchsafe-firewall doctor" to find the problem.`);
      return;
    }
    if (res.outcome.stderr !== undefined && res.outcome.stderr !== "") this.diag(res.outcome.stderr);
    if (res.outcome.verdict !== "allow") {
      this.refuse(m, res.outcome.message !== "" ? res.outcome.message : "LaunchSafe Firewall did not pass this on: decided again after the approval, it was not allowed.");
      return;
    }
    this.forward(m, { action: a, approvedVia: via }, params);
  }

  private clientResponse(r: Response): void {
    // I8: an answer is the ask's only for an id the gateway made (lsfw-ask-...); a server's request can never hold
    // one (upstreamRequest refuses the prefix), so the two tables never share an id.
    if (typeof r.id === "string" && r.id.startsWith(`${INTERNAL}ask-`) && this.asks.has(r.id)) {
      const ask = this.asks.get(r.id) as { req: Request; action: NormalizedAction; at: number; params: Json | undefined; rules: readonly string[] };
      this.asks.delete(r.id);
      // An answer after the ask expired (as the signed request state does) does not approve anything.
      const expired = this.nowMs() - ask.at > ASK_TTL_MS;
      if (!expired && r.result !== undefined && r.result.action === "accept") this.approvedForward(ask.req, ask.action, "elicitation", ask.params, ask.rules);
      else this.refuse(ask.req, expired ? "LaunchSafe Firewall: the approval came after the question expired, so the action was not passed on. Ask again." : "LaunchSafe Firewall: the person did not allow this action, so it was not passed on.");
      return;
    }
    if (r.id !== null && this.serverRequests.take(r.id) !== undefined) {
      this.out.upstream(r);
      return;
    }
    this.logEvent({ type: "gateway_protocol", from: "client", problem: "a response to no request the gateway forwarded" });
  }

  // --- server to client ---------------------------------------------------------------------------

  private violation(problem: string): void {
    this.logEvent({ type: "gateway_protocol", from: "server", problem: problem.slice(0, 300) });
    const now = Date.now();
    this.violations = [...this.violations.filter((t) => now - t < 60_000), now];
    if (this.violations.length >= 10) this.o.onUpstreamAbuse?.();
  }

  private upstreamResponse(r: Response): void {
    if (r.id === null) return this.violation("a response without an id");
    const call = this.pending.take(r.id);
    if (call === undefined) return this.violation("a response to no request");
    // Values substituted into this call, and any vaulted value, go back as references before
    // anything else reads the answer (the scanner, the quarantine store, the post-tool step, the client).
    const inflightKey = `${typeof r.id}:${String(r.id)}`;
    if (call.method !== "lsfw/probe" && call.method !== "lsfw/init") {
      const sc = this.scrubIn({ result: r.result, error: r.error });
      this.inflight.delete(inflightKey);
      if (sc.leftover) {
        this.out.client(call.method === "tools/call" ? resultResponse(r.id, withheldResult(call.method, `${NO_VAULT_ANSWER} ${this.o.server}: it carried a value stored in the vault in a form that could not be replaced by its reference.`)) : errorResponse(r.id, INVALID_REQUEST, `${NO_VAULT_ANSWER} ${this.o.server}: it carried a value stored in the vault.`));
        return;
      }
      // The parsed message is the gateway's own object: the scrubbed answer replaces the server's from here on.
      if (sc.value.result !== undefined) r.result = sc.value.result;
      if (sc.value.error !== undefined) r.error = sc.value.error;
    }
    if (call.method === "lsfw/probe") {
      const f = this.probeDone;
      this.probeDone = null;
      f?.(r);
      return;
    }
    if (call.method === "lsfw/init") {
      if (r.result === undefined) return this.decided("failed", `the server refused initialize (${r.error?.message.slice(0, 120) ?? ""})`);
      try {
        this.initResult = this.checkedInstructions(r.result);
      } catch (e) {
        return this.decided("failed", `the server's instructions could not be checked (${(e as Error).message})`);
      }
      this.serverVersion = serverVersionOf(r.result);
      this.out.upstream({ jsonrpc: "2.0", method: "notifications/initialized" });
      this.flush();
      return;
    }
    if (r.error !== undefined || r.result === undefined) {
      this.out.client(this.checkedError(r.id, call, r));
      return;
    }
    let result = r.result;
    try {
      // V5: an input request (sampling, elicitation, roots) is checked whatever method it answers.
      if (result.resultType === "input_required") return this.inputRequired(r.id, call, result);
      if (call.method === "initialize") {
        result = this.checkedInstructions(result);
        this.initResult = result;
        this.serverVersion = serverVersionOf(result);
      } else if (call.method === "server/discover") {
        result = this.checkedInstructions(result);
        this.serverVersion = serverVersionOf(result) ?? this.serverVersion;
      } else if (call.method === "tools/list") {
        result = this.filterTools(result);
      } else if (SCANNED.has(call.method)) {
        result = this.scanAndRecord(call, result);
      } else if (own(LISTS, call.method) !== undefined) {
        result = this.scanList(call.method, own(LISTS, call.method) as string, result);
      } else if (call.method === "completion/complete") {
        result = this.scanCompletion(result);
      }
    } catch (e) {
      // Fail closed: a result the gateway could not check is not delivered.
      this.diag(`LaunchSafe Firewall gateway: could not check a ${call.method} result: ${(e as Error).message}`);
      result = withheldResult(call.method, `LaunchSafe Firewall could not check this result from ${this.o.server} and withheld it (${safeText((e as Error).message)}). Run "launchsafe-firewall doctor".`);
    }
    this.out.client(resultResponse(r.id, result));
  }

  private filterTools(result: Json): Json {
    const cfg = this.config();
    const gp = gatewayPolicy(cfg);
    let tools = Array.isArray(result.tools) ? (result.tools as unknown[]).filter(isObj) : [];
    if (this.o.transport === "http") {
      // Streamable HTTP clients MUST exclude tools whose x-mcp-header annotations are invalid.
      tools = tools.filter((t) => {
        const why = validMcpHeaderSchema(t.inputSchema);
        if (why !== null) this.logEvent({ type: "gateway_protocol", from: "server", problem: `tool ${String(t.name).slice(0, 80)} excluded: ${why}` });
        return why === null;
      });
    }
    // Every listed tool is pinned in the shared pins file: a server listing without end would grow it (and every
    // hook's read of it) without end. Past MAX_LISTED_TOOLS the rest are not passed on, and the log says so.
    if (tools.length > MAX_LISTED_TOOLS) {
      this.logEvent({ type: "gateway_protocol", from: "server", problem: `tools/list had ${tools.length} tools; only the first ${MAX_LISTED_TOOLS} were checked and passed on`, client: this.o.client, server: this.o.server });
      tools = tools.slice(0, MAX_LISTED_TOOLS);
    }
    const o = observeToolList(this.o.l, cfg, { key: this.pinKey(), server: this.o.server, source: this.o.pinSource }, tools, this.serverVersion, gp.toolChanges === "hide", this.o.now?.() ?? new Date(), this.o.mode === "hook");
    for (const entry of o.log) this.logEvent({ ...entry, session: this.sessionId() });
    if (o.events.length > 0) this.recordEvents(o.events);
    if (o.alerts.length > 0) {
      // V41: alerts carry server-chosen names; control and bidi characters are escaped before stderr.
      for (const a of o.alerts) this.diag(`LaunchSafe Firewall: ${safeText(a, { keepNewlines: false })}`);
      notify(this.o.l, "mcp_changed", o.alerts.length, cfg, this.o.env, this.o.notifyDeps !== undefined ? { deps: this.o.notifyDeps } : {});
    }
    for (const t of o.visible) if (typeof t.name === "string") this.schemas.set(t.name, t.inputSchema);
    return { ...this.scanRest("tools/list", result, "tools"), tools: o.visible };
  }

  /**
   * GW10: the fields of a list or completion result beside the part checked entry by entry (a description,
   * nextCursor, anything a server adds) reach the model too. They are scanned together; withheld, they are
   * dropped (the list itself is still delivered). `_meta` is left as it is, as everywhere.
   */
  private scanRest(method: string, result: Json, checked: string, keep = true): Json {
    const rest = Object.fromEntries(Object.entries(result).filter(([k]) => k !== checked && k !== "_meta"));
    const meta = result._meta !== undefined ? { _meta: result._meta } : {};
    // `keep`: the member the caller has checked entry by entry goes back as it is. A caller whose member was
    // not the shape it expected (not an array, not an object) passes false and scans the member itself.
    const kept = keep && own(result, checked) !== undefined ? { [checked]: own(result, checked) } : {};
    if (Object.keys(rest).length === 0) return keep ? result : { ...meta };
    const s = this.scanFields(`${method} result`, rest);
    if (s.withheld) return { ...(typeof result.resultType === "string" ? { resultType: "complete" } : {}), ...meta, ...kept };
    return { ...s.value, ...meta, ...kept };
  }

  private scanAndRecord(call: PendingCall, result: Json): Json {
    const cfg = this.config();
    const gp = gatewayPolicy(cfg);
    const tool = call.action?.tool ?? `mcp__${this.o.server}__${call.method}`;
    const raw = result;
    // A mail server's result goes through the email guard first, message by message (withheld
    // messages become stubs, hidden parts are stripped from the rest); the general scan then sees what remains.
    if (call.method === "tools/call") result = this.mailGuard(cfg, tool, result);
    const s = scanResult(call.method, result, { policy: gp.responses, server: this.o.server, redact: cfg.redactSecretsInOutput, ...(this.o.scan !== undefined ? { scan: this.o.scan } : {}) });
    const session = this.sessionId();
    const events: StateEvent[] = s.taintSources.map((source) => ({ type: "taint" as const, source: source.slice(0, 300) }));
    let delivered = s.result;
    let record: string | undefined;
    if (s.verdict === "withhold") {
      const rec = addQuarantine(this.o.l, { session, client: this.o.client, server: this.o.server, tool, signals: s.signals, text: s.text });
      record = rec.id;
      const uri = isObj(call.params) && typeof call.params.uri === "string" ? call.params.uri : undefined;
      delivered = withheldResult(call.method, `LaunchSafe Firewall withheld this result from MCP server ${this.o.server} (${tool}): ${withheldWhy(s.signals)}. Record ${rec.id}. A person can review it in their own terminal: launchsafe-firewall gateway quarantine show ${rec.id} (rule ${RULE_WITHHELD})`, uri);
      notify(this.o.l, "mcp_withheld", 1, cfg, this.o.env, this.o.notifyDeps !== undefined ? { deps: this.o.notifyDeps } : {});
      this.logEvent({ type: "decision", session, tool, verdict: "deny", rules: [RULE_WITHHELD], agent: "gateway", client: this.o.client, server: this.o.server, what: `result withheld: ${s.signals.join(", ")}`.slice(0, 300), quarantine: rec.id });
    }
    if (s.verdict !== "deliver" || s.signals.length > 0) this.logEvent({ type: "mcp_result_scan", session, tool, client: this.o.client, server: this.o.server, verdict: s.verdict, signals: s.signals, ...(record !== undefined ? { record } : {}), ...(s.strippedChars > 0 ? { stripped: s.strippedChars } : {}) });
    if (call.action !== undefined) {
      // The hook pipeline's post-tool step: taint per the server's policy, secrets' fingerprints, decoys. It reads
      // what the server returned (vault values already scrubbed), not what is delivered: a decoy's value inside a
      // withheld or stripped result is still the signal (R1, V39).
      // FW-OUTSIDE-COMMAND remembers the commands in what the agent is shown (hidden text marked or stripped),
      // and the scan's own finding (hidden text, instructions) makes the result outside content for that too.
      const ad = this.adapter(call.method);
      const gw = ad.gateway !== undefined ? { ...ad.gateway, shown: delivered, scanTainted: s.taintSources.length > 0 } : undefined;
      const post = runPostTool(this.event("post_tool", call.action, raw), { ...ad, ...(gw !== undefined ? { gateway: gw } : {}) }, this.hookEnv(), this.o.l);
      if (post.outcome.stderr !== undefined && post.outcome.stderr !== "") this.diag(post.outcome.stderr);
      if (this.o.mode === "hook" && post.events.length > 0) {
        for (const ev of post.events) {
          if (ev.type === "canary_seen") this.logEvent({ type: "canary_alert", kind: "seen", id: ev.id, session, tool, client: this.o.client, server: this.o.server });
        }
        recordGatewayHookEvents(this.o.l, this.o.client, this.o.session(), post.events, this.o.now?.() ?? new Date());
      }
    } else if (this.o.mode === "full") {
      events.push({ type: "taint", source: `MCP result from ${this.o.server} (${call.method})` });
    }
    if (events.length > 0) this.recordEvents(events);
    return delivered;
  }

  /**
   * Scans text fields the model can read outside a result's content (an error, server instructions, list
   * entries, completions) with the same scanner and policy. Withheld: a quarantine record, a log entry, a
   * notification. The taint the scan finds is added to the session.
   */
  private scanFields(what: string, fields: Json): { withheld: false; value: Json } | { withheld: true; record: string; signals: string[] } {
    const cfg = this.config();
    const gp = gatewayPolicy(cfg);
    const s = scanResult("notification", fields, { policy: gp.responses, server: this.o.server, redact: cfg.redactSecretsInOutput, ...(this.o.scan !== undefined ? { scan: this.o.scan } : {}) });
    const session = this.sessionId();
    const tool = `mcp__${this.o.server}__${what}`.slice(0, 200);
    if (s.taintSources.length > 0) this.recordEvents(s.taintSources.map((source) => ({ type: "taint" as const, source: source.slice(0, 300) })));
    if (s.verdict === "withhold") {
      const rec = addQuarantine(this.o.l, { session, client: this.o.client, server: this.o.server, tool, signals: s.signals, text: s.text });
      notify(this.o.l, "mcp_withheld", 1, cfg, this.o.env, this.o.notifyDeps !== undefined ? { deps: this.o.notifyDeps } : {});
      this.logEvent({ type: "decision", session, tool, verdict: "deny", rules: [RULE_WITHHELD], agent: "gateway", client: this.o.client, server: this.o.server, what: `${what} withheld: ${s.signals.join(", ")}`.slice(0, 300), quarantine: rec.id });
      this.logEvent({ type: "mcp_result_scan", session, tool, client: this.o.client, server: this.o.server, verdict: s.verdict, signals: s.signals, record: rec.id });
      return { withheld: true, record: rec.id, signals: s.signals };
    }
    if (s.verdict !== "deliver" || s.signals.length > 0) this.logEvent({ type: "mcp_result_scan", session, tool, client: this.o.client, server: this.o.server, verdict: s.verdict, signals: s.signals, ...(s.strippedChars > 0 ? { stripped: s.strippedChars } : {}) });
    return { withheld: false, value: s.result };
  }

  private withheldNote(what: string, record: string, signals: readonly string[]): string {
    return `LaunchSafe Firewall withheld ${what} from MCP server ${this.o.server}: ${withheldWhy(signals)}. Record ${record}. A person can review it in their own terminal: launchsafe-firewall gateway quarantine show ${record} (rule ${RULE_WITHHELD})`;
  }

  /**
   * V10: a JSON-RPC error's message and data reach the model like a result. They are scanned (withheld: the
   * error keeps its code and carries the notice), and in full mode the post-tool step reads the error as it
   * read a result (taint per the server's policy, decoys). A check that fails withholds the error.
   */
  private checkedError(id: Id, call: PendingCall, r: Response): Response {
    if (r.error === undefined) {
      this.violation("a response with neither a result nor an error");
      return errorResponse(id, INVALID_REQUEST, `LaunchSafe Firewall gateway: MCP server ${this.o.server} sent an answer with neither a result nor an error`);
    }
    const code = typeof r.error.code === "number" ? r.error.code : INVALID_REQUEST;
    try {
      const fields: Json = { message: r.error.message, ...(r.error.data !== undefined ? { data: r.error.data } : {}) };
      const s = this.scanFields(`${call.method} error`, fields);
      if (call.action !== undefined) {
        const post = runPostTool(this.event("post_tool", call.action, fields), this.adapter(call.method), this.hookEnv(), this.o.l);
        if (post.outcome.stderr !== undefined && post.outcome.stderr !== "") this.diag(post.outcome.stderr);
        if (this.o.mode === "hook" && post.events.length > 0) {
          for (const ev of post.events) {
            if (ev.type === "canary_seen") this.logEvent({ type: "canary_alert", kind: "seen", id: ev.id, session: this.sessionId(), tool: call.action.tool, client: this.o.client, server: this.o.server });
          }
          recordGatewayHookEvents(this.o.l, this.o.client, this.o.session(), post.events, this.o.now?.() ?? new Date());
        }
      }
      if (s.withheld) return errorResponse(id, code, this.withheldNote("the error message of this request", s.record, s.signals));
      const message = typeof s.value.message === "string" ? s.value.message : "the server reported an error";
      return { jsonrpc: "2.0", id, error: { code, message, ...(s.value.data !== undefined ? { data: s.value.data } : {}) } } as Response;
    } catch (e) {
      this.diag(`LaunchSafe Firewall gateway: could not check a ${call.method} error: ${(e as Error).message}`);
      return errorResponse(id, code, `LaunchSafe Firewall could not check the error message from ${this.o.server} and withheld it (${safeText((e as Error).message)}).`);
    }
  }

  /** V11: a server's instructions (initialize, server/discover) usually go into the system prompt. Throws when the check fails. */
  private checkedInstructions(result: Json): Json {
    if (typeof result.instructions !== "string") return result;
    const s = this.scanFields("instructions", { instructions: result.instructions });
    if (s.withheld) return { ...result, instructions: this.withheldNote("this server's instructions", s.record, s.signals) };
    return { ...result, instructions: typeof s.value.instructions === "string" ? s.value.instructions : "" };
  }

  /** V31: each entry of a prompts, resources or templates list scanned by itself; a withheld entry is left out. */
  private scanList(method: string, key: string, result: Json): Json {
    if (!Array.isArray(own(result, key))) {
      // Not the list the method promises: whatever the member holds is scanned as a whole (withheld: left out).
      const rest = this.scanRest(method, result, key, false);
      const member = own(result, key);
      if (member === undefined) return rest;
      const s = this.scanFields(`${method} ${key}`, { [key]: member });
      return s.withheld ? rest : { ...rest, [key]: own(s.value, key) };
    }
    const kept: Json[] = [];
    for (const item of own(result, key) as unknown[]) {
      if (!isObj(item)) continue;
      const s = this.scanFields(`${method} entry`, item);
      if (!s.withheld) kept.push(s.value);
    }
    return { ...this.scanRest(method, result, key), [key]: kept };
  }

  /** V31: completion values a server suggests; withheld: no suggestions. */
  private scanCompletion(result: Json): Json {
    const rest = this.scanRest("completion/complete", result, "completion", false);
    if (result.completion === undefined) return rest;
    // Whatever shape it has (an object is the promised one), the member is scanned whole.
    const s = this.scanFields("completion/complete", { completion: result.completion });
    if (s.withheld) return { ...rest, completion: { values: [], hasMore: false } };
    return { ...rest, completion: s.value.completion };
  }

  /**
   * The email guard on the gateway's read path (the gateway calls filterMailResult). The
   * gateway owns the pipe, so it can replace the result for every client, including those whose hooks cannot.
   */
  private mailGuard(cfg: FirewallConfig, tool: string, result: Json): Json {
    const session = this.sessionId();
    const name = tool.startsWith(`mcp__${this.o.server}__`) ? tool.slice(`mcp__${this.o.server}__`.length) : tool;
    const m = guardMailResult(this.o.l, cfg, { session, agent: this.o.client, server: this.o.server, tool: name, output: result, canReplace: true, approverKey: trustedApproverKey(this.o.l, this.o.env), ...(this.o.now !== undefined ? { now: this.o.now() } : {}) });
    if (m === null) return result;
    for (const line of m.stderr) this.diag(line);
    if (m.events.length > 0) this.recordEvents(m.events);
    if (m.newRecords > 0) notify(this.o.l, "mail_quarantined", m.newRecords, cfg, this.o.env, this.o.notifyDeps !== undefined ? { deps: this.o.notifyDeps } : {});
    if (m.systemMessage !== undefined) this.diag(m.systemMessage);
    let out = result;
    if (m.updatedOutput !== undefined) {
      const o = m.result.output;
      // The filter rewrote the result in its own shape; text, or anything without content blocks, becomes one text block.
      // Nothing of the original result rides along: its other members (structured content, a server's own fields) may
      // carry what was withheld, and the filter's text replaces all of them; only isError (a boolean) is kept.
      if (isObj(o) && Array.isArray(o.content)) out = o;
      else out = { content: [{ type: "text", text: m.updatedOutput }], ...(typeof result.isError === "boolean" ? { isError: result.isError } : {}) };
    }
    if (m.additionalContext !== undefined && Array.isArray(out.content)) out = { ...out, content: [...(out.content as unknown[]), { type: "text", text: m.additionalContext }] };
    return out;
  }

  /**
   * The parts of a decided request the engine does not read, reduced to what the protocol defines.
   * `_meta`: the progress token (a short string or a number) and the modern protocol keys. `task`: its ttl.
   * `inputResponses`: only answers to input requests the gateway passed on for this same call (`inputRequired`
   * remembers their keys and methods by the call's action hash), each with only the fields its method's
   * result defines. Everything else is dropped (and logged by the caller), never forwarded unread.
   */
  private tidyForwarded(params: Json, hash: string): { params: Json; dropped: string[] } {
    const out: Json = { ...params };
    const dropped: string[] = [];
    if (Object.hasOwn(params, "_meta")) {
      const meta = params._meta;
      const kept: Json = {};
      if (isObj(meta)) {
        for (const [k, v] of Object.entries(meta)) {
          // LG5: the related task (RequestMetaSchema: `{ taskId: string }`) goes on, with only its taskId.
          if (k === META_RELATED_TASK) {
            if (isObj(v) && typeof v.taskId === "string" && v.taskId !== "" && v.taskId.length <= 256) {
              setOwn<unknown>(kept, k, { taskId: v.taskId });
              for (const f of Object.keys(v)) if (f !== "taskId") dropped.push(`_meta.${k}.${f}`);
            } else dropped.push(`_meta.${k}`);
            continue;
          }
          const ok = k === "progressToken" ? (typeof v === "string" && v.length <= 256) || (typeof v === "number" && Number.isFinite(v)) : k === META_VERSION ? typeof v === "string" : (k === META_CAPS || k === META_CLIENT) && isObj(v);
          if (ok) setOwn<unknown>(kept, k, v);
          else dropped.push(`_meta.${k}`);
        }
      } else dropped.push("_meta");
      if (Object.keys(kept).length > 0) out._meta = kept;
      else delete out._meta;
    }
    if (Object.hasOwn(params, "task")) {
      // LG5: TaskMetadata is `{ ttl?: number }`: `task: {}` asks for a task with the server's default ttl, so an
      // object always goes on (with its ttl when that is a finite number); anything else in it is dropped and logged.
      const t = params.task;
      const ttl = isObj(t) ? t.ttl : undefined;
      const ttlOk = typeof ttl === "number" && Number.isFinite(ttl) && ttl >= 0;
      if (isObj(t)) out.task = ttlOk ? { ttl } : {};
      else delete out.task;
      if (!isObj(t)) dropped.push("task");
      else for (const k of Object.keys(t)) if (k !== "ttl" || !ttlOk) dropped.push(`task.${k}`);
    }
    const asked = this.inputKeys.get(hash);
    if (Object.hasOwn(params, "requestState")) {
      const s = params.requestState;
      const isOurs = typeof s === "string" && s.startsWith("lsfw1.");
      if (!isOurs && (typeof s !== "string" || s !== asked?.requestState)) {
        delete out.requestState;
        dropped.push("requestState");
      }
    }
    if (Object.hasOwn(params, "inputResponses")) {
      const given = params.inputResponses;
      const kept: Json = {};
      if (isObj(given)) {
        for (const [k, v] of Object.entries(given)) {
          // The gateway's own approval answer is checked and removed by the caller.
          if (k === "launchsafe_approval" && typeof params.requestState === "string" && params.requestState.startsWith("lsfw1.")) continue;
          const method = asked?.keys.get(k);
          const fields = method !== undefined ? own(RESPONSE_FIELDS, method) : undefined;
          if (fields === undefined || !isObj(v)) {
            dropped.push(`inputResponses.${k}`);
            continue;
          }
          const r: Json = {};
          for (const [f, x] of Object.entries(v)) {
            if (fields.includes(f)) setOwn<unknown>(r, f, x);
            else dropped.push(`inputResponses.${k}.${f}`);
          }
          setOwn<unknown>(kept, k, r);
        }
      } else dropped.push("inputResponses");
      if (Object.keys(kept).length > 0) out.inputResponses = kept;
      else delete out.inputResponses;
    }
    return { params: out, dropped };
  }

  /** An InputRequiredResult (MRTR): the input requests it carries are checked before the client sees them. */
  private inputRequired(id: Id, call: PendingCall, result: Json): void {
    const req: Request = { jsonrpc: "2.0", id, method: call.method, ...(call.params !== undefined ? { params: call.params } : {}) };
    if (this.clientEra === "legacy") {
      this.logEvent({ type: "gateway_input_request", session: this.sessionId(), client: this.o.client, server: this.o.server, refused: "cross-era" });
      this.refuse(req, `LaunchSafe Firewall: MCP server ${this.o.server} asked for input in the 2026-07-28 form (sampling, elicitation or roots), and this client speaks an older version; the gateway does not translate input requests between versions, so the request was refused.`);
      return;
    }
    const inputs = isObj(result.inputRequests) ? result.inputRequests : {};
    const next: Json = {};
    for (const [key, v] of Object.entries(inputs)) {
      const checked = isObj(v) ? this.checkInput(String(v.method ?? ""), isObj(v.params) ? v.params : {}) : { refused: RULE_METHOD, why: "a malformed input request" };
      if ("refused" in checked) {
        this.refuse(req, `LaunchSafe Firewall refused a request from MCP server ${this.o.server}: ${checked.why}. (rule ${checked.refused})`);
        return;
      }
      setOwn<unknown>(next, key, { method: (v as Json).method, params: checked.params });
    }
    const requestState = typeof result.requestState === "string" ? result.requestState : undefined;
    // The retry may answer exactly these (tidyForwarded), keyed by the call's action.
    if (DECIDED.has(call.method)) {
      const a = this.actionOf(req);
      if (!("error" in a)) {
        const keys = new Map<string, string>();
        for (const [key, v] of Object.entries(next)) keys.set(key, String((v as Json).method));
        const hash = actionHash(a);
        this.inputKeys.delete(hash);
        this.inputKeys.set(hash, { keys, ...(requestState !== undefined ? { requestState } : {}) });
        while (this.inputKeys.size > 256) this.inputKeys.delete(this.inputKeys.keys().next().value as string);
      }
    }
    // Only the input-required fields go on: content, tools or other fields beside them would skip the result checks.
    this.out.client(resultResponse(id, { resultType: "input_required", inputRequests: next, ...(requestState !== undefined ? { requestState } : {}), ...(result._meta !== undefined ? { _meta: result._meta } : {}) }));
  }

  /**
   * One input request from the server: refused, or the params to pass on (labelled). LR12: a request is
   * passed on only once its entry is in the log; when the log refuses it (entry and fallback), it is refused
   * (FW-LOG-UNRECORDED) and why goes to stderr.
   */
  private checkInput(method: string, params: Json): { params: Json } | { refused: string; why: string } {
    const cfg = this.config();
    const gp = gatewayPolicy(cfg);
    const untrusted = serverPolicy(this.o.server, cfg, this.o.source).results === "untrusted";
    const log = (extra: Json): boolean => this.logEvent({ type: "gateway_input_request", session: this.sessionId(), client: this.o.client, server: this.o.server, method, ...extra });
    const pass = (extra: Json, out: Json): { params: Json } | { refused: string; why: string } => {
      if (log({ passed: true, ...extra })) return { params: out };
      const why = `its log entry could not be recorded (the decision log refused the entry and the short fallback entry), so it was not passed on unrecorded; run "launchsafe-firewall log verify" to find the problem`;
      this.diag(`LaunchSafe Firewall gateway: refused the ${method.slice(0, 80)} request from MCP server ${this.o.server}: ${why}. (rule ${RULE_LOG_UNRECORDED})`);
      return { refused: RULE_LOG_UNRECORDED, why };
    };
    if (!INPUT_METHODS.has(method)) {
      log({ refused: RULE_METHOD });
      return { refused: RULE_METHOD, why: `the input request ${method.slice(0, 80)} is not one the gateway knows` };
    }
    if (method === "sampling/createMessage") {
      if (gp.sampling === "deny" || (gp.sampling === "deny_untrusted" && untrusted)) {
        log({ refused: RULE_SAMPLING });
        this.logEvent({ type: "decision", session: this.sessionId(), tool: `mcp__${this.o.server}__sampling`, verdict: "deny", rules: [RULE_SAMPLING], agent: "gateway", client: this.o.client, server: this.o.server, what: "the server asked to run the client's model on its own text" });
        return { refused: RULE_SAMPLING, why: "it asked to run your AI model on text it wrote and read the answer (sampling), and its results count as outside content" };
      }
      return pass({}, params);
    }
    if (method === "roots/list") return pass({ note: "reveals local paths to the server" }, params);
    // elicitation/create: labelled with the server's name; a URL from an untrusted server is shown as text.
    // Its message, schema (titles, descriptions, names) and url are shown to the person and read by the model like
    // a result: scanned first (hidden instructions are refused), then every string is made safe to show.
    const scanned = this.scanFields("elicitation/create", params);
    if (scanned.withheld) {
      log({ refused: RULE_WITHHELD });
      return { refused: RULE_WITHHELD, why: `its text could not be passed on: ${withheldWhy(scanned.signals)}` };
    }
    const shown = safeJson(scanned.value);
    const text = isObj(shown) ? shown : {};
    const label = `[MCP server ${this.o.server}] `;
    if (text.mode === "url" && untrusted) {
      const url = typeof text.url === "string" ? text.url : "";
      return pass({ urlAsText: true }, { mode: "form", message: `${label}${typeof text.message === "string" ? text.message : ""}\nIt asks you to open this address. LaunchSafe Firewall did not open it; copy it into your browser yourself only if you trust it: ${url}`, requestedSchema: { type: "object", properties: {} } });
    }
    return pass({}, { ...text, message: `${label}${typeof text.message === "string" ? text.message : ""}` });
  }

  /** Legacy server-to-client requests (2025-11-25 and earlier). */
  private upstreamRequest(m: Request): void {
    // I8: ids starting "lsfw-" are the gateway's own (its approval questions to the client among them). A server
    // request with one would share the client's answer space with them: the person's answer to the server's
    // elicitation could be read as the approval of a held call. Refused, never passed on.
    if (typeof m.id === "string" && m.id.startsWith(INTERNAL)) {
      this.violation(`a request with the reserved id prefix ${INTERNAL}`);
      this.out.upstream(errorResponse(m.id, INVALID_REQUEST, `LaunchSafe Firewall gateway: request ids starting with "${INTERNAL}" are reserved`));
      return;
    }
    if (!SERVER_REQUESTS.has(m.method)) {
      this.violation(`unknown request ${m.method.slice(0, 80)}`);
      this.logEvent({ type: "decision", session: this.sessionId(), tool: `mcp__${this.o.server}__${m.method}`.slice(0, 200), verdict: "deny", rules: [RULE_METHOD], agent: "gateway", client: this.o.client, server: this.o.server, what: `unknown MCP method from the server: ${m.method}`.slice(0, 300) });
      this.out.upstream(errorResponse(m.id, METHOD_NOT_FOUND, `LaunchSafe Firewall gateway: the method ${m.method.slice(0, 100)} is not passed on (rule ${RULE_METHOD})`));
      return;
    }
    if (m.method === "ping") {
      this.out.upstream(resultResponse(m.id, {}));
      return;
    }
    if (this.clientEra === "modern") {
      this.logEvent({ type: "gateway_input_request", session: this.sessionId(), client: this.o.client, server: this.o.server, method: m.method, refused: "cross-era" });
      this.out.upstream(errorResponse(m.id, METHOD_NOT_FOUND, "LaunchSafe Firewall gateway: this client speaks MCP 2026-07-28; server requests are not translated between versions"));
      return;
    }
    const sc = this.scrubIn(m.params ?? {});
    if (sc.leftover) {
      this.out.upstream(errorResponse(m.id, INVALID_REQUEST, "LaunchSafe Firewall refused this request: it carried a value stored in the vault"));
      return;
    }
    const checked = this.checkInput(m.method, sc.value);
    if ("refused" in checked) {
      this.out.upstream(errorResponse(m.id, INVALID_REQUEST, `LaunchSafe Firewall refused this request: ${checked.why} (rule ${checked.refused})`));
      return;
    }
    if (!this.serverRequests.add(m.id, m.method)) {
      this.out.upstream(errorResponse(m.id, INVALID_REQUEST, "LaunchSafe Firewall gateway: too many requests in flight"));
      return;
    }
    this.out.client({ ...m, params: checked.params });
  }

  private upstreamNotification(n: Message & { method: string; params?: Json }): void {
    if (!SERVER_NOTIFICATIONS.has(n.method)) {
      this.violation(`unknown notification ${n.method.slice(0, 80)}`);
      return;
    }
    let m = n;
    if (n.params !== undefined) {
      const sc = this.scrubIn(n.params);
      if (sc.leftover) return;
      m = { ...n, params: sc.value };
    }
    if ((m.method === "notifications/message" || m.method === "notifications/progress") && m.params !== undefined) {
      let s: ReturnType<typeof scanResult>;
      try {
        s = scanResult("notification", m.params, { policy: this.gp().responses, server: this.o.server, redact: false, ...(this.o.scan !== undefined ? { scan: this.o.scan } : {}) });
      } catch {
        return;
      }
      if (s.verdict === "withhold") {
        this.logEvent({ type: "mcp_result_scan", session: this.sessionId(), tool: m.method, client: this.o.client, server: this.o.server, verdict: "withhold", signals: s.signals });
        return;
      }
      this.out.client({ jsonrpc: "2.0", method: m.method, params: s.result });
      return;
    }
    this.out.client(m);
  }

  /** Diagnostics for stderr; V41: whatever a server chose (names, versions, messages) is escaped first. */
  private diag(line: string): void {
    this.o.diag?.(safeText(line));
  }

  /**
   * LG1: every event is bounded, or replaced by its fallback entry (src/runtime/logbound.ts). Returns false
   * only when the log refused both, so the caller of a decision that would forward fails closed; an I/O
   * failure (a full disk) is reported and the decision stands, as before (docs/limitations.md).
   */
  private logEvent(e: Record<string, unknown>): boolean {
    try {
      // Free text a server or a call chose (what, problem) is logged with credentials and URL query values masked.
      const safe: Record<string, unknown> = { ...e };
      for (const k of ["what", "problem", "tool"]) {
        const v = own(safe, k);
        if (typeof v === "string") setOwn<unknown>(safe, k, logSafe(v));
      }
      appendBounded(this.o.l, safe);
      return true;
    } catch (err) {
      this.diag(`LaunchSafe Firewall gateway could not write its log: ${(err as Error).message}`);
      return !(err instanceof LogUnrecorded);
    }
  }
}

/**
 * The parameters each decided method defines (MCP 2026-07-28: the method's own fields, `_meta`, and the
 * multi round-trip `inputResponses`/`requestState`; `task` on tools/call). What `actionOf` reads is among
 * them; everything else is dropped before forwarding.
 */
const KNOWN_PARAMS: Record<string, readonly string[]> = {
  "tools/call": ["name", "arguments", "_meta", "inputResponses", "requestState", "task"],
  "resources/read": ["uri", "_meta", "inputResponses", "requestState"],
  "prompts/get": ["name", "arguments", "_meta", "inputResponses", "requestState"],
  "completion/complete": ["ref", "argument", "context", "_meta"],
};

/** The fields each input request's result defines (MCP 2026-07-28), the only ones an answer forwards. */
const RESPONSE_FIELDS: Record<string, readonly string[]> = {
  "sampling/createMessage": ["role", "content", "model", "stopReason"],
  "elicitation/create": ["action", "content"],
  "roots/list": ["roots"],
};

function knownParams(method: string, params: Json | undefined): Json | undefined {
  const keys = own(KNOWN_PARAMS, method);
  if (params === undefined || keys === undefined) return params;
  const out: Json = {};
  for (const k of keys) if (Object.hasOwn(params, k)) setOwn(out, k, own(params, k));
  return out;
}

function defaultTimer(fn: () => void, ms: number): () => void {
  const t = setTimeout(fn, ms);
  t.unref?.();
  return () => clearTimeout(t);
}
