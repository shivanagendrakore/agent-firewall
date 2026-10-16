/**
 * `launchsafe-firewall native-host`: the browser link's host process (docs/browser-link.md). The browser
 * starts it (through the launcher install wrote) when the LaunchSafe extension connects, with the
 * extension's origin as its argument, and talks to it over stdin and stdout in Chrome's native messaging
 * frames (protocol.ts).
 *
 * - The origin must be one an install allowed (Chrome checks allowed_origins too), and the first message
 *   must be a hello with this protocol version.
 * - log.append: the browser's decision goes into the firewall's signed, hash-chained log, so `log verify`
 *   covers it. Never page text: the schema has no field for it.
 * - state.taint: the browser's agent session read outside content; every linked agent session is tainted
 *   (link.ts). The other way, a tainted linked agent session is reported to the browser.
 * - approval.request: the action goes into the firewall's queue, where only a person with the approval
 *   passphrase can approve it (`queue approve`). The result goes back with the approval's signature; the
 *   extension accepts it only for the pending action with that binding.
 *
 * Fails closed: an oversized frame, a message that does not fit the schema, or messages out of order get an
 * error and the host exits, which drops the link; the extension then keeps deciding on its own.
 */

import { createHash, randomBytes } from "node:crypto";
import type { Readable } from "node:stream";
import { approverPublicKey } from "../approver.js";
import { appendLog } from "../log.js";
import type { Layout } from "../layout.js";
import { decideQueueItem, enqueue, getQueueItem, loadState, readEvents } from "../store.js";
import { allowedOrigins } from "./browsers.js";
import { recordBrowserTaint, taintedLinkedSessions } from "./link.js";
import { encodeFrame, extensionIdOf, FrameDecoder, parseBrowserMessage, PROTOCOL_VERSION, ProtocolError, type BrowserMessage, type HostCapability, type HostMessage } from "./protocol.js";

/** The most approval requests one browser link may have waiting in the queue at once. */
const MAX_PENDING_APPROVALS = 16;

/** How often the host looks for decided approvals and newly tainted linked sessions. */
export const POLL_MS = 1000;

export interface HostDeps {
  layout: Layout;
  env: NodeJS.ProcessEnv;
  /** The extension origin the browser passed as the first argument. */
  origin: string | undefined;
  write: (frame: Buffer) => void;
  version: string;
  now?: () => Date;
}

interface PendingApproval {
  id: string;
  sessionId: string;
  actionHash: string;
}

function nonce(): string {
  return randomBytes(12).toString("base64url");
}

/** The approval key approvals must be signed with: pinned in the launcher, else the one on disk. */
function approverKey(l: Layout, env: NodeJS.ProcessEnv): string | null {
  const pinned = env.LAUNCHSAFE_FIREWALL_APPROVER;
  if (pinned !== undefined && pinned !== "") return pinned;
  try {
    return approverPublicKey(l);
  } catch {
    return null;
  }
}

/** One connection. `handle` throws ProtocolError for anything that must end it. */
export class HostSession {
  private greeted = false;
  private readonly pending = new Map<string, PendingApproval>();
  private readonly reported = new Set<string>();
  private readonly extensionId: string;
  private readonly approver: string | null;

  constructor(private readonly d: HostDeps) {
    this.extensionId = extensionIdOf(d.origin ?? "") ?? "unknown";
    this.approver = approverKey(d.layout, d.env);
  }

  private send(m: HostMessage): void {
    this.d.write(encodeFrame(m));
  }

  private now(): Date {
    return this.d.now?.() ?? new Date();
  }

  get capabilities(): HostCapability[] {
    return this.approver !== null ? ["log", "taint", "approval"] : ["log", "taint"];
  }

  /** The browser session id an approval's queue item is filed under. */
  private get queueSession(): string {
    return `browser-${this.extensionId.slice(0, 12)}`;
  }

  handle(raw: unknown): void {
    const msg: BrowserMessage = parseBrowserMessage(raw);
    if (!this.greeted && msg.type !== "hello") throw new ProtocolError("order", "the first message must be hello");
    switch (msg.type) {
      case "hello":
        if (this.greeted) throw new ProtocolError("order", "hello was already sent");
        if (msg.version !== PROTOCOL_VERSION) throw new ProtocolError("version", `this firewall speaks protocol version ${PROTOCOL_VERSION}; the extension sent ${msg.version}. Update the one that is older`);
        this.greeted = true;
        this.send({ type: "hello", re: msg.nonce, version: PROTOCOL_VERSION, capabilities: this.capabilities, firewall: this.d.version });
        this.tryLog({ type: "browser_link", event: "connected", extension: this.extensionId, extension_version: msg.extension, enforces: msg.capabilities });
        this.tick();
        return;
      case "log.append": {
        const e = msg.entry;
        try {
          const entry = appendLog(this.d.layout, {
            type: "browser_decision",
            extension: this.extensionId,
            site: e.site,
            action_class: e.actionClass,
            verdict: e.verdict,
            rules: e.rules,
            ...(e.approval !== undefined ? { approval: e.approval } : {}),
            ...(e.binding !== undefined ? { binding: e.binding } : {}),
            ...(e.event !== undefined ? { event: e.event } : {}),
            ...(e.detail !== undefined ? { detail: e.detail } : {}),
            at: new Date(e.at).toISOString(),
            browser_seq: e.seq,
            browser_hash: e.hash,
            browser_prev: e.prevHash,
          });
          this.send({ type: "log.ack", re: msg.nonce, seq: entry.seq });
        } catch (err) {
          // Not fatal: the extension keeps the entry in its own log and offers it again on the next connection.
          this.send({ type: "error", re: msg.nonce, code: "log_failed", message: (err as Error).message.slice(0, 300) });
        }
        return;
      }
      case "state.taint": {
        const n = recordBrowserTaint(this.d.layout, `${this.extensionId.slice(0, 12)}-${msg.session}`, msg.reason, this.now());
        this.tryLog({ type: "browser_taint", extension: this.extensionId, session: msg.session, reason: msg.reason, agent_sessions: n });
        this.send({ type: "ack", re: msg.nonce });
        return;
      }
      case "approval.request": {
        if (this.approver === null) {
          this.send({ type: "error", re: msg.nonce, code: "unavailable", message: 'no approval passphrase is set, so the firewall cannot take approvals: run "launchsafe-firewall approver init"' });
          return;
        }
        // A page cannot flood the person's queue: past the cap a new request is refused (one already waiting may be asked again).
        if (this.pending.size >= MAX_PENDING_APPROVALS && !this.pending.has(msg.binding)) {
          this.send({ type: "error", re: msg.nonce, code: "too_many", message: `at most ${MAX_PENDING_APPROVALS} approvals can wait at once; decide or cancel one first` });
          return;
        }
        const actionHash = createHash("sha256").update(`launchsafe-browser/approval/v1\n${this.extensionId}\n${msg.binding}`).digest("hex");
        const a = msg.action;
        const item = enqueue(this.d.layout, {
          sessionId: this.queueSession,
          cwd: "",
          tool: "browser",
          input: { kind: a.kind, site: a.site, actionClass: a.actionClass, binding: msg.binding },
          actionHash,
          rules: [],
          reasons: [`the LaunchSafe browser extension holds this action for a person: ${a.label}`],
          kind: "approval",
          summary: `browser: ${a.label}${a.site !== "" ? ` on ${a.site}` : ""}`,
        });
        this.pending.set(msg.binding, { id: item.id, sessionId: item.sessionId, actionHash });
        this.tryLog({ type: "browser_approval", event: "queued", extension: this.extensionId, queue: item.id, binding: msg.binding, site: a.site });
        this.send({ type: "approval.queued", re: msg.nonce, id: item.id });
        return;
      }
      case "approval.cancel": {
        const p = this.pending.get(msg.binding);
        if (p !== undefined) {
          this.pending.delete(msg.binding);
          this.reject(p);
        }
        this.send({ type: "ack", re: msg.nonce });
        return;
      }
    }
  }

  /** Decided approvals go back to the browser; newly tainted linked agent sessions are reported. */
  tick(): void {
    if (!this.greeted) return;
    for (const [binding, p] of [...this.pending]) {
      const verdict = this.outcome(p);
      if (verdict === null) continue;
      this.pending.delete(binding);
      this.send({ type: "approval.result", nonce: nonce(), binding, verdict: verdict.verdict, ...(verdict.sig !== undefined ? { sig: verdict.sig } : {}) });
    }
    let tainted: string[] = [];
    try {
      tainted = taintedLinkedSessions(this.d.layout, this.now());
    } catch {
      tainted = [];
    }
    for (const s of tainted) {
      if (this.reported.has(s)) continue;
      this.reported.add(s);
      // The agent session's id stays on this machine's disk; the browser gets a stable short name for it.
      this.send({ type: "state.taint", nonce: nonce(), session: `agent-${createHash("sha256").update(s).digest("hex").slice(0, 16)}`, reason: "agent_session_untrusted" });
    }
  }

  /**
   * A decided queue item, as the browser should take it. "approve" only when the session holds an approval
   * for this action signed by the approval key; an approved item without one is tampering and reads as deny.
   */
  private outcome(p: PendingApproval): { verdict: "approve" | "deny"; sig?: string } | null {
    const it = getQueueItem(this.d.layout, p.id);
    if (it === null) return { verdict: "deny" };
    if (it.status === "pending") return null;
    if (it.status === "rejected") return { verdict: "deny" };
    const st = loadState(this.d.layout, p.sessionId, this.approver);
    if (this.approver === null || st.approvals.get(p.actionHash) !== p.id) {
      this.tryLog({ type: "browser_approval", event: "unverified", extension: this.extensionId, queue: p.id });
      return { verdict: "deny" };
    }
    const ev = readEvents(this.d.layout, p.sessionId).find((e) => e.type === "approval" && e.actionHash === p.actionHash && e.id === p.id);
    const sig = ev?.type === "approval" ? ev.sig : undefined;
    return sig !== undefined ? { verdict: "approve", sig } : { verdict: "approve" };
  }

  private reject(p: PendingApproval): void {
    try {
      const it = getQueueItem(this.d.layout, p.id);
      if (it !== null && it.status === "pending") decideQueueItem(this.d.layout, p.id, "rejected");
    } catch {
      // Already decided by a person, or unreadable: nothing to close.
    }
  }

  /** The browser closed the link: approvals it was waiting for are closed in the queue too. */
  close(): void {
    for (const p of this.pending.values()) this.reject(p);
    this.pending.clear();
    if (this.greeted) this.tryLog({ type: "browser_link", event: "disconnected", extension: this.extensionId });
  }

  private tryLog(event: Record<string, unknown>): void {
    try {
      appendLog(this.d.layout, event);
    } catch {
      // A record of the link itself, not a decision: the link keeps working.
    }
  }
}

/**
 * Runs the host until the browser closes stdin. Returns the exit code: 0 when the browser closed the link,
 * 1 when the host refused it (an origin not allowed, a protocol error).
 */
export function runNativeHost(input: Readable, d: HostDeps & { pollMs?: number }): Promise<number> {
  return new Promise((resolve) => {
    const fail = (code: string, message: string, re?: string): void => {
      try {
        d.write(encodeFrame({ type: "error", ...(re !== undefined ? { re } : {}), code, message }));
      } catch {
        // The browser is gone.
      }
    };
    let origins: string[] = [];
    try {
      origins = allowedOrigins(d.layout);
    } catch (e) {
      fail("refused", `the browser link's install record cannot be read: ${(e as Error).message}`);
      resolve(1);
      return;
    }
    if (d.origin === undefined || !origins.includes(d.origin)) {
      fail("refused", "this extension is not allowed to use the firewall's browser link (run launchsafe-firewall install --browser with its id)");
      resolve(1);
      return;
    }
    const session = new HostSession(d);
    const decoder = new FrameDecoder();
    let done = false;
    const timer = setInterval(() => {
      try {
        session.tick();
      } catch {
        // A poll that fails is tried again on the next one.
      }
    }, d.pollMs ?? POLL_MS);
    const finish = (code: number): void => {
      if (done) return;
      done = true;
      clearInterval(timer);
      input.removeAllListeners("data");
      session.close();
      input.pause();
      resolve(code);
    };
    input.on("data", (chunk: Buffer) => {
      if (done) return;
      try {
        for (const m of decoder.push(chunk)) session.handle(m);
      } catch (e) {
        fail(e instanceof ProtocolError ? e.code : "internal", (e as Error).message.slice(0, 300));
        finish(1);
      }
    });
    input.on("end", () => finish(decoder.pending > 0 ? 1 : 0));
    input.on("error", () => finish(1));
  });
}
