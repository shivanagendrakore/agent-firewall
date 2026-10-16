/**
 * Test only: a stub of the LaunchSafe relay on 127.0.0.1, speaking the
 * contract in src/runtime/relay/protocol.ts. It checks device signatures and
 * tokens like the real relay would, stores sealed items it cannot read, and
 * lets a test play the phone (claim a pairing, post a decision) or the
 * attacker (swap a key, rewrite a reference, replay, go down, revoke).
 */
import { createPublicKey, randomUUID, verify } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { HEADER_SIG, HEADER_TS, requestSigningString, type PairingAnswer, type RelayDecision, type UploadItem } from "../../src/runtime/relay/protocol.js";

interface Pairing {
  id: string;
  devicePub: string;
  secretHash: string;
  label: string;
  status: "waiting" | "claimed" | "expired";
  answer?: PairingAnswer;
  mac?: string;
  deviceId?: string;
}

interface Device {
  id: string;
  token: string;
  pub: string;
  revoked: boolean;
}

export interface StubRelay {
  url: string;
  pairings: Map<string, Pairing>;
  devices: Device[];
  items: (UploadItem & { deviceId: string })[];
  withdraws: { itemRef: string; reason: string }[];
  summaries: number[];
  decisions: RelayDecision[];
  requests: { method: string; path: string }[];
  /** Answer every request with 503. */
  down: boolean;
  /** Refuse uploads beyond this many items per device (the fair-use limit). */
  maxItems: number;
  /** Every upload request's item count and body size (the app relay caps them at 50 items and 768 KB). */
  uploadRequests: { items: number; bytes: number }[];
  /** Refuses one uploaded item with this code (null: accept), like the app relay's per-item refusals. */
  refuseItem?: (it: UploadItem) => string | null;
  /** Mutates a claimed answer before the device reads it (the relay attacking the pairing). */
  tamperAnswer?: (a: PairingAnswer) => PairingAnswer;
  claim(pairingId: string, answer: PairingAnswer, mac: string): void;
  addDecision(d: Omit<RelayDecision, "id">): RelayDecision;
  revokeAll(): void;
  close(): Promise<void>;
}

function body(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let s = "";
    req.on("data", (c: Buffer) => (s += c.toString("utf8")));
    req.on("end", () => resolve(s));
  });
}

function send(res: ServerResponse, status: number, v: unknown): void {
  // Refusals as the app relay sends them: RFC 9457 problem+json with `reason`, plus error { code, message }.
  const err = typeof v === "object" && v !== null ? (v as { error?: { code: string; message: string } }).error : undefined;
  if (status >= 400 && err !== undefined) {
    res.writeHead(status, { "content-type": "application/problem+json", connection: "close" });
    res.end(JSON.stringify({ type: "about:blank", title: err.message, status, reason: err.code, error: err }));
    return;
  }
  // No keep-alive: a reused socket the server times out at the same moment resets the next request (ECONNRESET).
  res.writeHead(status, { "content-type": "application/json", connection: "close" });
  res.end(JSON.stringify(v));
}

function sigOk(req: IncomingMessage, path: string, text: string, pubB64u: string): boolean {
  const ts = Number(req.headers[HEADER_TS]);
  const sig = req.headers[HEADER_SIG];
  if (!Number.isFinite(ts) || typeof sig !== "string") return false;
  try {
    const key = createPublicKey({ key: Buffer.from(pubB64u, "base64url"), format: "der", type: "spki" });
    return verify("sha256", requestSigningString(req.method ?? "GET", path, ts, text), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(sig, "base64url"));
  } catch {
    return false;
  }
}

export async function startStubRelay(o: { maxWaitMs?: number } = {}): Promise<StubRelay> {
  const waiters: (() => void)[] = [];
  let seq = 0;
  const relay: StubRelay = {
    url: "",
    pairings: new Map(),
    devices: [],
    items: [],
    withdraws: [],
    summaries: [],
    decisions: [],
    requests: [],
    down: false,
    maxItems: 500,
    uploadRequests: [],
    claim(pairingId, answer, mac) {
      const p = relay.pairings.get(pairingId);
      if (p === undefined) throw new Error(`no pairing ${pairingId}`);
      p.status = "claimed";
      p.answer = answer;
      p.mac = mac;
    },
    addDecision(d) {
      const full = { ...d, id: String(++seq) };
      relay.decisions.push(full);
      for (const w of waiters.splice(0)) w();
      return full;
    },
    revokeAll() {
      for (const d of relay.devices) d.revoked = true;
    },
    close: () => new Promise((r) => server.close(() => r())),
  };
  const auth = (req: IncomingMessage): Device | null => {
    const h = req.headers.authorization;
    const t = typeof h === "string" && h.startsWith("Bearer ") ? h.slice(7) : null;
    return relay.devices.find((d) => d.token === t) ?? null;
  };
  const server: Server = createServer((req, res) => {
    void (async () => {
      const text = await body(req);
      const path = req.url ?? "/";
      relay.requests.push({ method: req.method ?? "", path });
      if (relay.down) return send(res, 503, { error: { code: "unavailable", message: "relay down" } });
      const u = new URL(path, "http://x");
      const parts = u.pathname.split("/").filter((x) => x !== "");
      const json = text === "" ? {} : (JSON.parse(text) as Record<string, unknown>);
      // POST /v1/firewall/pairings
      if (req.method === "POST" && u.pathname === "/v1/firewall/pairings") {
        const pub = String(json.deviceSignPub);
        if (!sigOk(req, path, text, pub)) return send(res, 401, { error: { code: "bad_signature", message: "bad device signature" } });
        const p: Pairing = { id: randomUUID(), devicePub: pub, secretHash: String(json.secretHash), label: String(json.label), status: "waiting" };
        const existing = auth(req);
        if (existing !== null) p.deviceId = existing.id;
        relay.pairings.set(p.id, p);
        return send(res, 200, { pairingId: p.id, expiresAt: new Date(Date.now() + 600000).toISOString() });
      }
      if (parts[0] === "v1" && parts[1] === "firewall" && parts[2] === "pairings" && parts[3] !== undefined) {
        const p = relay.pairings.get(decodeURIComponent(parts[3]));
        if (p === undefined) return send(res, 404, { error: { code: "not_found", message: "no such pairing" } });
        if (!sigOk(req, path, text, p.devicePub)) return send(res, 401, { error: { code: "bad_signature", message: "bad device signature" } });
        if (req.method === "GET" && parts.length === 4) {
          if (p.status !== "claimed") return send(res, 200, { status: p.status });
          const answer = relay.tamperAnswer !== undefined ? relay.tamperAnswer(p.answer as PairingAnswer) : p.answer;
          return send(res, 200, { status: "claimed", answer, mac: p.mac });
        }
        if (req.method === "POST" && parts[4] === "confirm") {
          if (p.status !== "claimed") return send(res, 409, { error: { code: "not_claimed", message: "not claimed" } });
          // A device unpaired in the app and paired again gets a new id and token (the app relay does the same).
          const existing = p.deviceId !== undefined ? relay.devices.find((d) => d.id === p.deviceId && !d.revoked) : undefined;
          if (existing !== undefined) return send(res, 200, { deviceId: existing.id });
          const d: Device = { id: randomUUID(), token: `tok_${randomUUID()}`, pub: p.devicePub, revoked: false };
          relay.devices.push(d);
          return send(res, 200, { deviceId: d.id, deviceToken: d.token });
        }
      }
      // Device operations: token and signature.
      const dev = auth(req);
      if (dev === null || dev.revoked) return send(res, 401, { error: { code: "device_revoked", message: "unknown or revoked device" } });
      if (!sigOk(req, path, text, dev.pub)) return send(res, 401, { error: { code: "bad_signature", message: "bad device signature" } });
      if (req.method === "POST" && u.pathname === "/v1/firewall/relay/items") {
        const list = json.items as UploadItem[];
        relay.uploadRequests.push({ items: list.length, bytes: Buffer.byteLength(text, "utf8") });
        if (list.length > 50) return send(res, 400, { error: { code: "too_many_items", message: "at most 50 items a request" } });
        if (Buffer.byteLength(text, "utf8") > 768 * 1024) return send(res, 413, { error: { code: "payload_too_large", message: "at most 768 KB a request" } });
        const accepted: string[] = [];
        const refused: { itemRef: string; code: string; message: string }[] = [];
        for (const it of json.items as UploadItem[]) {
          const mine = relay.items.filter((x) => x.deviceId === dev.id);
          if (mine.some((x) => x.itemRef === it.itemRef)) {
            accepted.push(it.itemRef);
            continue;
          }
          const custom = relay.refuseItem?.(it) ?? null;
          if (it.kind !== undefined && it.kind !== "approval") refused.push({ itemRef: it.itemRef, code: "not_phone_approvable", message: "only approval items can be decided on a phone" });
          else if (custom !== null) refused.push({ itemRef: it.itemRef, code: custom, message: `refused: ${custom}` });
          else if (mine.length >= relay.maxItems) refused.push({ itemRef: it.itemRef, code: "fair_use", message: `more than ${relay.maxItems} items today from this device` });
          else if (Buffer.from(it.sealed, "base64url").length > 16384) refused.push({ itemRef: it.itemRef, code: "too_large", message: "sealed payload too large" });
          else {
            relay.items.push({ ...it, deviceId: dev.id });
            accepted.push(it.itemRef);
          }
        }
        return send(res, 200, { accepted, refused });
      }
      if (req.method === "POST" && parts[2] === "relay" && parts[3] === "items" && parts[5] === "withdraw") {
        relay.withdraws.push({ itemRef: decodeURIComponent(parts[4] as string), reason: String(json.reason) });
        return send(res, 200, {});
      }
      if (req.method === "PUT" && u.pathname === "/v1/firewall/relay/summary") {
        relay.summaries.push(Number(json.waitingInTerminal));
        return send(res, 200, {});
      }
      if (req.method === "GET" && u.pathname === "/v1/firewall/relay/decisions") {
        const after = Number(u.searchParams.get("after") ?? "0");
        const wait = Number(u.searchParams.get("wait") ?? "0");
        const pick = (): RelayDecision[] => relay.decisions.filter((d) => Number(d.id) > after).slice(0, 100);
        if (pick().length === 0 && wait > 0) await new Promise<void>((r) => {
          const t = setTimeout(r, Math.min(wait * 1000, o.maxWaitMs ?? 200));
          waiters.push(() => {
            clearTimeout(t);
            r();
          });
        });
        const ds = pick();
        return send(res, 200, { decisions: ds, cursor: ds.length > 0 ? (ds[ds.length - 1] as RelayDecision).id : u.searchParams.get("after") });
      }
      return send(res, 404, { error: { code: "not_found", message: `no route ${req.method ?? ""} ${u.pathname}` } });
    })().catch((e: unknown) => send(res, 500, { error: { code: "stub_error", message: (e as Error).message } }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  relay.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return relay;
}
