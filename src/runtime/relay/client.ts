/**
 * The relay client, behind an interface so the pairing flow and the daemon
 * never depend on HTTP: tests run them against a stub relay on 127.0.0.1
 * (test/phone/stub-relay.ts) through the same HTTP client, and anything else
 * can implement RelayClient. Every request is signed with the device key
 * (protocol.ts); relay operations also carry the device token.
 *
 * Only https, or plain http to this machine, is ever contacted, with a
 * timeout and a response size cap. No request is made during a hook
 * decision: only `phone pair`, `relay run` and doctor's read of local state.
 */

import { API, HEADER_SIG, HEADER_TS, parseConfirm, parseDecisions, parsePairingStart, parsePairingStatus, parseUpload, RelayHttpError, RelayProtocolError, requestSigningString, type ConfirmResponse, type DecisionsResponse, type PairingStartRequest, type PairingStartResponse, type PairingStatus, type UploadItem, type UploadResponse, type WithdrawReason } from "./protocol.js";
import { deviceSign, type DeviceFile } from "./keys.js";

export interface RelayClient {
  startPairing(req: PairingStartRequest): Promise<PairingStartResponse>;
  pairingStatus(pairingId: string): Promise<PairingStatus>;
  confirmPairing(pairingId: string): Promise<ConfirmResponse>;
  uploadItems(items: UploadItem[]): Promise<UploadResponse>;
  withdraw(itemRef: string, reason: WithdrawReason): Promise<void>;
  /** Long-polls for decisions after `after` (null: from the start), waiting up to `waitSeconds`. */
  decisions(after: string | null, waitSeconds: number): Promise<DecisionsResponse>;
  /** Counts only: how many held changes wait in the terminal (proposals are never sent). */
  summary(s: { waitingInTerminal: number }): Promise<void>;
}

const MAX_RESPONSE = 1024 * 1024;

/** Whether a base URL may be contacted: https anywhere, http only to this machine. */
export function allowedBase(base: string): boolean {
  try {
    const u = new URL(base);
    if (u.protocol === "https:") return true;
    return u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost" || u.hostname === "[::1]");
  } catch {
    return false;
  }
}

export interface HttpClientOptions {
  /** The relay's API base (the policy's phone.relayOrigin). */
  base: string;
  /** Reads the device file fresh for each request (the token arrives at confirm). */
  device: () => DeviceFile;
  /** Tests: a fixed clock for the signature timestamp. */
  now?: () => number;
  fetch?: typeof fetch;
}

export class HttpRelayClient implements RelayClient {
  private readonly base: string;
  constructor(private readonly o: HttpClientOptions) {
    if (!allowedBase(o.base)) throw new Error(`refusing relay address ${o.base}: https only (or http to this machine)`);
    this.base = o.base.replace(/\/+$/, "");
  }

  private async call(method: "GET" | "POST" | "PUT", path: string, body: unknown, o: { auth: boolean; timeoutMs?: number }): Promise<unknown> {
    const d = this.o.device();
    const text = body === undefined ? "" : JSON.stringify(body);
    const ts = (this.o.now ?? Date.now)();
    const headers: Record<string, string> = { accept: "application/json, application/problem+json", [HEADER_TS]: String(ts), [HEADER_SIG]: deviceSign(d, requestSigningString(method, path, ts, text)) };
    if (text !== "") headers["content-type"] = "application/json";
    if (o.auth && d.token !== undefined) headers.authorization = `Bearer ${d.token}`;
    const res = await (this.o.fetch ?? fetch)(`${this.base}${path}`, { method, headers, ...(text !== "" ? { body: text } : {}), redirect: "error", signal: AbortSignal.timeout(o.timeoutMs ?? 20000) });
    const raw = await readCapped(res);
    let json: unknown = null;
    if (raw !== "") {
      try {
        json = JSON.parse(raw);
      } catch {
        if (res.ok) throw new RelayProtocolError(`the relay answered ${method} ${path.split("?")[0] ?? ""} with something that is not JSON`);
      }
    }
    if (!res.ok) {
      // The relay answers refusals as RFC 9457 problem+json with a top-level error { code, message } for this
      // client (docs/firewall-relay.md in the app); the problem's own `reason` and `detail` are the fallback.
      const p = typeof json === "object" && json !== null ? (json as { error?: { code?: unknown; message?: unknown }; reason?: unknown; detail?: unknown; title?: unknown }) : {};
      const e = p.error;
      const code = typeof e?.code === "string" ? e.code.slice(0, 64) : typeof p.reason === "string" ? p.reason.slice(0, 64) : `http_${res.status}`;
      const message = typeof e?.message === "string" ? e.message.slice(0, 300) : typeof p.detail === "string" ? p.detail.slice(0, 300) : typeof p.title === "string" ? p.title.slice(0, 300) : `HTTP ${res.status}`;
      throw new RelayHttpError(res.status, code, message);
    }
    return json;
  }

  async startPairing(req: PairingStartRequest): Promise<PairingStartResponse> {
    return parsePairingStart(await this.call("POST", API.pairings, req, { auth: true }));
  }
  async pairingStatus(pairingId: string): Promise<PairingStatus> {
    return parsePairingStatus(await this.call("GET", API.pairing(pairingId), undefined, { auth: false }));
  }
  async confirmPairing(pairingId: string): Promise<ConfirmResponse> {
    return parseConfirm(await this.call("POST", API.confirm(pairingId), {}, { auth: true }));
  }
  async uploadItems(items: UploadItem[]): Promise<UploadResponse> {
    return parseUpload(await this.call("POST", API.items, { items }, { auth: true }));
  }
  async withdraw(itemRef: string, reason: WithdrawReason): Promise<void> {
    await this.call("POST", API.withdraw(itemRef), { reason }, { auth: true });
  }
  async decisions(after: string | null, waitSeconds: number): Promise<DecisionsResponse> {
    return parseDecisions(await this.call("GET", API.decisions(after, waitSeconds), undefined, { auth: true, timeoutMs: (waitSeconds + 15) * 1000 }));
  }
  async summary(s: { waitingInTerminal: number }): Promise<void> {
    await this.call("PUT", API.summary, s, { auth: true });
  }
}

async function readCapped(res: Response): Promise<string> {
  const len = Number(res.headers.get("content-length") ?? "0");
  if (len > MAX_RESPONSE) throw new RelayProtocolError("the relay's answer is too large");
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > MAX_RESPONSE) throw new RelayProtocolError("the relay's answer is too large");
  return buf.toString("utf8");
}
