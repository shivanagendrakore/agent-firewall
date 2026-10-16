/**
 * The native link to the local LaunchSafe firewall (design 10). Optional and off by default: the person
 * turns it on in the side panel, which first asks for the optional `nativeMessaging` permission (design 11).
 *
 * While connected:
 * - every decision-log entry is mirrored to the firewall's signed log (`log.append`); entries made while
 *   the link was down are sent on the next connection (from the last one the firewall acknowledged);
 *   deleting the browser's log sends its "log deleted" marker and restarts the count from the new chain;
 * - taint is shared both ways (`state.taint`): this browser's agent session reading outside content is
 *   sent once per session, and a linked coding-agent session the firewall reports as untrusted makes the
 *   agent session here untrusted (the worker applies it, engine/session.ts linkedAgentTainted);
 * - when the firewall can take approvals, each pending approval is also filed in its queue; its answer is
 *   handed to the worker only for the pending approval with that binding (its fingerprint salted per worker,
 *   index.ts linkBinding; the unsalted fingerprint never leaves the browser).
 *
 * Degrades cleanly: no host installed, a host that exits, or a message that does not fit the protocol all
 * end in a disconnected link with a status line, and the extension keeps deciding exactly as without it.
 * Nothing the host sends can make anything less strict: taint only adds, and an approval from the
 * firewall is the same as the person approving in our own UI.
 */
import type { ChainedEntry, LinkState, LinkStatus } from "../shared/messages.js";

export type { LinkState, LinkStatus } from "../shared/messages.js";
import type { KeyValueArea } from "./state.js";
import { EXTENSION_CAPABILITIES, HOST_NAME, isBinding, isReason, isSessionId, MAX_MESSAGE_BYTES, messageBytes, newNonce, parseHostMessage, PROTOCOL_VERSION, wireCode, wireEntry, wireLabel, wireSite, type ExtensionMessage, type HostCapability } from "./link-protocol.js";

export const LINK_KEY = "ls.link";
/** At most this many log entries are sent when a connection opens; older ones stay in the browser's log only. */
export const BACKLOG_LIMIT = 500;
/** How long to wait before trying a dropped link again (on the next decision after this). */
export const RETRY_MS = 30_000;

/** The part of chrome.runtime.Port the link uses (a fake in tests). */
export interface NativePort {
  postMessage(m: unknown): void;
  disconnect(): void;
  onMessage: { addListener(fn: (m: unknown) => void): void };
  onDisconnect: { addListener(fn: () => void): void };
}

export interface LinkDeps {
  area: KeyValueArea;
  /** chrome.runtime.connectNative; throws when the permission is missing. */
  connect: (name: string) => NativePort;
  /** chrome.runtime.lastError's message at disconnect, if any. */
  lastError: () => string | undefined;
  hasPermission: () => Promise<boolean>;
  /** Log entries after `seq` (exclusive), oldest first. */
  entriesAfter: (seq: number) => Promise<ChainedEntry[]>;
  /** The newest sequence number in the browser's log (-1 when empty). */
  headSeq: () => Promise<number>;
  /** The agent session's taint to send on connect, or null. */
  currentTaint: () => Promise<{ session: string; reason: string } | null>;
  onAgentTaint: (agentSession: string, reason: string) => Promise<void>;
  onApprovalResult: (binding: string, verdict: "approve" | "deny") => Promise<void>;
  /** Pending approvals to file when a connection opens. */
  pendingApprovals: () => Promise<ApprovalOffer[]>;
  onChange: () => void;
  version: string;
  now?: () => number;
}

export interface ApprovalOffer {
  binding: string;
  kind: string;
  actionClass: string | null;
  site: string;
  label: string;
}

interface Stored {
  enabled: boolean;
  /** The last browser sequence number the firewall acknowledged. */
  ackedSeq: number;
}

export interface NativeLink {
  /** Reads the setting and connects when it is on and permitted. */
  start(): Promise<void>;
  setEnabled(on: boolean): Promise<{ ok: boolean; reason?: string }>;
  status(): Promise<LinkStatus>;
  /** A new log entry: mirrored now when connected, else on the next connection (which this may start). */
  forward(entry: ChainedEntry): void;
  /**
   * The browser's log was deleted and its new chain starts with this "log deleted" marker (RR14): the
   * firewall is sent the marker, and acknowledgements now count from the new chain's start.
   */
  logCleared(marker: ChainedEntry): void;
  /** The agent session is untrusted; sent once per session. */
  taint(session: string, reason: string): void;
  requestApproval(offer: ApprovalOffer): void;
  /** Decided here first: the firewall's queue item is closed. */
  cancelApproval(binding: string): void;
  /** The permission was removed: disconnect and turn off. */
  permissionRemoved(): Promise<void>;
  /** Whether the firewall takes approvals right now. */
  offersApprovals(): boolean;
}

function parseStored(v: unknown): Stored {
  const o = typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};
  return { enabled: o.enabled === true, ackedSeq: typeof o.ackedSeq === "number" && Number.isInteger(o.ackedSeq) && o.ackedSeq >= -1 ? o.ackedSeq : -1 };
}

/** Chrome's errors for a host that is not installed or not allowed, as the person should read them. */
function explain(err: string | undefined): string {
  if (err === undefined || err === "") return "The local firewall closed the link.";
  if (/not found/i.test(err)) return 'The local firewall is not installed for this browser. In a terminal run "launchsafe-firewall install --browser chrome --extension-id <this extension\'s id>".';
  if (/forbidden/i.test(err)) return "The local firewall's install does not allow this extension (its id differs). Run install --browser again with this extension's id.";
  if (/exited/i.test(err)) return "The local firewall's host stopped. Run \"launchsafe-firewall doctor\".";
  return `The link to the local firewall failed: ${err.slice(0, 200)}`;
}

export function createLink(d: LinkDeps): NativeLink {
  const now = d.now ?? Date.now;
  let port: NativePort | null = null;
  let state: LinkState = "off";
  let detail = "Off. Turn it on to send decisions to the local firewall's signed log and share taint with coding agents.";
  let caps: HostCapability[] = [];
  let firewall: string | undefined;
  let mirrored = 0;
  let lastAttempt = Number.NEGATIVE_INFINITY;
  let helloNonce: string | null = null;
  /** Nonce of a log.append -> the browser sequence number it carried. */
  const sentSeq = new Map<string, number>();
  /** Sessions whose taint was sent on this connection. */
  const taintSent = new Set<string>();
  /** Bindings filed with the firewall on this connection. */
  const filed = new Set<string>();
  let storedCache: Stored | null = null;

  const load = async (): Promise<Stored> => (storedCache ??= parseStored((await d.area.get(LINK_KEY))[LINK_KEY]));
  const save = async (s: Stored): Promise<void> => {
    storedCache = s;
    await d.area.set({ [LINK_KEY]: s });
  };

  const send = (m: ExtensionMessage): boolean => {
    if (port === null) return false;
    // Ours are small; one that is not would be refused by the host and end the link.
    if (messageBytes(m) > MAX_MESSAGE_BYTES) return false;
    try {
      port.postMessage(m);
      return true;
    } catch {
      drop("error", "The link to the local firewall failed while sending.");
      return false;
    }
  };

  function drop(next: LinkState, why: string): void {
    const p = port;
    port = null;
    helloNonce = null;
    caps = [];
    sentSeq.clear();
    taintSent.clear();
    filed.clear();
    state = next;
    detail = why;
    if (p !== null) {
      try {
        p.disconnect();
      } catch {
        // Already closed.
      }
    }
    d.onChange();
  }

  async function connect(): Promise<void> {
    if (port !== null) return;
    lastAttempt = now();
    if (!(await d.hasPermission())) {
      state = "off";
      detail = "Off: the browser has not granted the permission to talk to the local firewall.";
      d.onChange();
      return;
    }
    let p: NativePort;
    try {
      p = d.connect(HOST_NAME);
    } catch (e) {
      drop("unavailable", explain((e as Error).message));
      return;
    }
    port = p;
    state = "connecting";
    detail = "Connecting to the local firewall…";
    p.onMessage.addListener((m) => {
      if (port !== p) return;
      void onHost(m);
    });
    p.onDisconnect.addListener(() => {
      if (port !== p) return;
      drop("unavailable", explain(d.lastError()));
    });
    helloNonce = newNonce();
    send({ type: "hello", nonce: helloNonce, version: PROTOCOL_VERSION, capabilities: [...EXTENSION_CAPABILITIES], extension: d.version });
    d.onChange();
  }

  async function flush(): Promise<void> {
    const st = await load();
    const head = await d.headSeq();
    // The browser's log was cleared or replaced: start again from its first entry.
    const from = head < st.ackedSeq ? -1 : st.ackedSeq;
    if (from !== st.ackedSeq) await save({ ...st, ackedSeq: from });
    const entries = (await d.entriesAfter(from)).slice(-BACKLOG_LIMIT);
    for (const e of entries) forwardNow(e);
    const t = await d.currentTaint();
    if (t !== null) sendTaint(t.session, t.reason);
    if (caps.includes("approval")) for (const a of await d.pendingApprovals()) fileApproval(a);
  }

  function forwardNow(e: ChainedEntry): void {
    if (state !== "connected") return;
    const nonce = newNonce();
    if (send({ type: "log.append", nonce, entry: wireEntry(e) })) sentSeq.set(nonce, e.seq);
  }

  function sendTaint(session: string, reason: string): void {
    if (state !== "connected" || taintSent.has(session) || !isSessionId(session) || !isReason(reason)) return;
    if (send({ type: "state.taint", nonce: newNonce(), session, reason })) taintSent.add(session);
  }

  function fileApproval(a: ApprovalOffer): void {
    if (state !== "connected" || !caps.includes("approval") || filed.has(a.binding) || !isBinding(a.binding)) return;
    const ok = send({ type: "approval.request", nonce: newNonce(), binding: a.binding, action: { kind: wireCode(a.kind) ?? "action", actionClass: wireCode(a.actionClass), site: wireSite(a.site), label: wireLabel(a.label) }, surface: "firewall" });
    if (ok) filed.add(a.binding);
  }

  function forward(entry: ChainedEntry): void {
    if (state === "connected") return forwardNow(entry);
    // A dropped link is tried again on a later decision, not on every one.
    if (port === null && storedCache?.enabled === true && now() - lastAttempt >= RETRY_MS) void connect();
  }

  async function onHost(raw: unknown): Promise<void> {
    const m = parseHostMessage(raw);
    if (m === null) {
      drop("error", "The local firewall sent a message this extension does not understand, so the link was closed. Update the firewall and the extension.");
      return;
    }
    switch (m.type) {
      case "hello":
        if (state !== "connecting" || m.re !== helloNonce) return drop("error", "The local firewall answered out of order; the link was closed.");
        if (m.version !== PROTOCOL_VERSION) return drop("error", `The local firewall speaks link version ${m.version}; this extension speaks ${PROTOCOL_VERSION}. Update the older one.`);
        state = "connected";
        caps = m.capabilities;
        firewall = m.firewall;
        detail = caps.includes("approval") ? "Connected. Decisions go to the firewall's signed log; held actions can also be approved with the firewall's passphrase." : "Connected. Decisions go to the firewall's signed log. (Set an approval passphrase in the firewall to approve from there too.)";
        d.onChange();
        await flush();
        return;
      case "log.ack": {
        const seq = sentSeq.get(m.re);
        if (seq === undefined) return;
        sentSeq.delete(m.re);
        mirrored++;
        const st = await load();
        if (seq > st.ackedSeq) await save({ ...st, ackedSeq: seq });
        return;
      }
      case "state.taint":
        await d.onAgentTaint(m.session, m.reason);
        return;
      case "approval.result":
        // Only for an approval this connection filed; the worker checks it is still pending with that binding.
        if (!filed.has(m.binding)) return;
        filed.delete(m.binding);
        await d.onApprovalResult(m.binding, m.verdict);
        return;
      case "error":
        // A refused log entry or approval: the browser keeps its own record. Shown, not fatal.
        detail = `Connected, with a problem: ${m.message}`;
        d.onChange();
        return;
      case "ack":
      case "approval.queued":
        return;
    }
  }

  return {
    async start() {
      const st = await load();
      if (!st.enabled) {
        state = "off";
        return;
      }
      await connect();
    },
    async setEnabled(on) {
      const st = await load();
      if (on) {
        if (!(await d.hasPermission())) return { ok: false, reason: "permission" };
        await save({ ...st, enabled: true });
        await connect();
        return { ok: true };
      }
      await save({ ...st, enabled: false });
      drop("off", "Off. Turn it on to send decisions to the local firewall's signed log and share taint with coding agents.");
      return { ok: true };
    },
    async status() {
      const st = await load();
      return { enabled: st.enabled, state, detail, capabilities: [...caps], ...(firewall !== undefined ? { firewall } : {}), mirrored };
    },
    forward,
    logCleared(marker) {
      // Acks still in flight are for the old chain's sequence numbers; they must not move the new one forward.
      sentSeq.clear();
      void load()
        .then((st) => save({ ...st, ackedSeq: -1 }))
        .catch(() => undefined)
        .then(() => forward(marker));
    },
    taint(session, reason) {
      sendTaint(session, reason);
    },
    requestApproval(offer) {
      fileApproval(offer);
    },
    cancelApproval(binding) {
      if (state !== "connected" || !filed.has(binding)) return;
      filed.delete(binding);
      send({ type: "approval.cancel", nonce: newNonce(), binding });
    },
    async permissionRemoved() {
      const st = await load();
      await save({ ...st, enabled: false });
      drop("off", "Off: the permission to talk to the local firewall was removed.");
    },
    offersApprovals() {
      return state === "connected" && caps.includes("approval");
    },
  };
}
