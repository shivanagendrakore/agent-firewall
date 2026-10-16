/**
 * v0.3 `run`: the allowlist proxy the sandboxed command must use. Node's
 * `http` server, outside the sandbox, on 127.0.0.1 (macOS) or a Unix socket
 * in a private directory (Linux, bridged into the sandbox's own network
 * namespace). HTTPS arrives as CONNECT, plain HTTP in absolute form; TLS is
 * never decrypted. Every decision goes to `onEvent` (run.ts writes the signed
 * log). docs/run.md lists the checks in order.
 */

import { lookup } from "node:dns/promises";
import { createServer, request, type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from "node:http";
import { connect, type Socket } from "node:net";
import type { Duplex } from "node:stream";
import { internalAddress, judgeHost, NO_LOCAL_ANSWERS, type LocalAnswers, type RunBudgetHit, type RunBudgets, type RunJudgement, type RunNetPolicy, type RunWhy } from "../../engine/netgate.js";
import { normalizeHost } from "../../engine/network.js";
import { parseClientHello } from "../../engine/tls-sni.js";
import { setOwn } from "../../own.js";

export type ProxyEvent =
  | { type: "net"; method: "CONNECT" | "HTTP"; host: string; port: number; verdict: "allow" | "deny"; why?: RunWhy; rule?: string; kind?: RunJudgement["kind"]; known?: boolean; uploadCapable?: boolean; reason: string }
  | { type: "budget"; host: string; hit: RunBudgetHit };

export interface ProxyHostStats {
  host: string;
  /** Connections or requests let through. */
  conns: number;
  /** Bytes from the client to the server (what the budgets count). */
  up: number;
  down: number;
  refused: number;
}

export interface ProxyOptions {
  policy: RunNetPolicy;
  budgets: RunBudgets;
  listen: { host: "127.0.0.1" } | { path: string };
  /**
   * Told about every decision (run.ts writes the signed log). Returning `false` (exactly) for an allow means
   * its entry could not be recorded (FW-LOG-UNRECORDED): the connection is refused instead of made
   * unrecorded. Any other return value is ignored.
   */
  onEvent: (e: ProxyEvent) => unknown;
  /**
   * Tests only (not reachable from the CLI): open the upstream connection for an admitted host
   * instead of the real DNS lookup and address checks.
   */
  dial?: (host: string, port: number) => Promise<Socket>;
  /**
   * The hosts a person approved for the workspace (knownHosts), asked for when a connection opens (read
   * fresh, so an approval given during the run counts). Used only when the policy's `knownHosts` is set.
   */
  knownHosts?: () => readonly string[];
  /** Names whose DNS answers may be loopback or private (--allow-localhost, run.privateHosts). Default: none. */
  localAnswers?: LocalAnswers;
  /** Tests only: the DNS lookup of the real dial (default: node:dns, every answer). */
  resolve?: Resolver;
  /** Tests only: opens the TCP connection to the address the real dial checked. */
  connectTo?: (address: string, family: number, port: number) => Socket;
  now?: () => number;
  /** How long to wait for the client's TLS ClientHello after the tunnel opens. */
  helloTimeoutMs?: number;
}

export interface RunningProxy {
  /** The TCP port (macOS), or null on a Unix socket. */
  port: number | null;
  path: string | null;
  stats(): ProxyHostStats[];
  close(): Promise<void>;
}

/** A DNS answer the proxy refuses to connect to. */
export class DialRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DialRefused";
  }
}

export type Resolver = (host: string) => Promise<{ address: string; family: number }[]>;

const systemResolve: Resolver = (host) => lookup(host, { all: true, verbatim: true });

/**
 * The real dial: one lookup, every answer checked (one bad answer refuses the name, so a rebinding
 * resolver cannot win by ordering), then a connection to the first checked address. The address is
 * passed to connect() as an IP, so there is no second lookup between the check and the connection.
 */
export async function checkedDial(
  host: string,
  port: number,
  o: { local?: LocalAnswers; resolve?: Resolver; connectTo?: (address: string, family: number, port: number) => Socket } = {},
): Promise<Socket> {
  const answers = await (o.resolve ?? systemResolve)(host);
  if (answers.length === 0) throw new Error(`${host} has no address`);
  for (const a of answers) {
    const why = internalAddress(a.address, host, o.local ?? NO_LOCAL_ANSWERS);
    if (why !== null) throw new DialRefused(`${host} resolves to ${a.address}, ${why}; the proxy does not connect there (DNS rebinding)`);
  }
  const first = answers[0] as { address: string; family: number };
  return new Promise<Socket>((resolveSocket, reject) => {
    const s = o.connectTo !== undefined ? o.connectTo(first.address, first.family, port) : connect({ host: first.address, port, family: first.family });
    const fail = (e: Error): void => {
      s.destroy();
      reject(e);
    };
    s.setTimeout(15000, () => fail(new Error(`connecting to ${host} timed out`)));
    s.once("error", fail);
    s.once("connect", () => {
      s.setTimeout(0);
      s.removeListener("error", fail);
      resolveSocket(s);
    });
  });
}

/** "host:port" or "[v6]:port" from a CONNECT line. */
export function parseAuthority(a: string): { host: string; port: number } | null {
  const m = /^\[([^\]]+)\]:(\d{1,5})$/.exec(a) ?? /^([^:[\]]+):(\d{1,5})$/.exec(a);
  if (m === null) return null;
  return { host: normalizeHost(m[1] as string), port: Number(m[2]) };
}

const HOP = new Set(["connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate", "te", "trailer", "upgrade"]);

function forwardHeaders(h: IncomingHttpHeaders): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(h)) if (v !== undefined && !HOP.has(k.toLowerCase())) setOwn(out, k, v);
  return out;
}

/** Whether a Host header value ("name" or "name:port", default port 80) names this host and port. */
function hostNames(value: string, host: string, port: number): boolean {
  const m = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(value) ?? /^([^:[\]]+)(?::(\d{1,5}))?$/.exec(value);
  if (m === null) return false;
  return normalizeHost(m[1] as string) === host && (m[2] === undefined ? 80 : Number(m[2])) === port;
}

/** Most bytes the proxy holds for an upgrade before the server's answer (the client's bytes queued behind the request, or the answer's head). */
const UPGRADE_HOLD_MAX = 64 * 1024;

/** Most distinct hosts the proxy keeps statistics for; the rest are counted together under OTHER_HOSTS. */
export const MAX_STAT_HOSTS = 512;
export const OTHER_HOSTS = "*other*";

const UNRECORDED = 'the decision log refused to record this connection (its entry and the short fallback entry), so it was not made unrecorded; run "launchsafe-firewall log verify" to find the problem';

function refusalBody(host: string, port: number, reason: string): string {
  return `LaunchSafe Agent Firewall (run) refused ${host}:${port}: ${reason}\n`;
}

export async function startProxy(o: ProxyOptions): Promise<RunningProxy> {
  const now = o.now ?? Date.now;
  const dial =
    o.dial ??
    ((host: string, port: number): Promise<Socket> =>
      checkedDial(host, port, { ...(o.localAnswers !== undefined ? { local: o.localAnswers } : {}), ...(o.resolve !== undefined ? { resolve: o.resolve } : {}), ...(o.connectTo !== undefined ? { connectTo: o.connectTo } : {}) }));
  const stats = new Map<string, ProxyHostStats>();
  const sockets = new Set<Duplex>();
  const statOther = (): ProxyHostStats => {
    let s = stats.get(OTHER_HOSTS);
    if (s === undefined) {
      s = { host: OTHER_HOSTS, conns: 0, up: 0, down: 0, refused: 0 };
      stats.set(OTHER_HOSTS, s);
    }
    return s;
  };
  const stat = (host: string): ProxyHostStats => {
    let s = stats.get(host);
    if (s === undefined) {
      // A program that tries thousands of names must not grow this map without bound: past the cap, the rest share one entry.
      if (stats.size >= MAX_STAT_HOSTS) return statOther();
      s = { host, conns: 0, up: 0, down: 0, refused: 0 };
      stats.set(host, s);
    }
    return s;
  };
  const deny = (method: "CONNECT" | "HTTP", host: string, port: number, why: RunWhy, reason: string, rule?: string): void => {
    stat(host).refused++;
    o.onEvent({ type: "net", method, host, port, verdict: "deny", why, reason, ...(rule !== undefined ? { rule } : {}) });
  };

  /** The checks before dialing: the host list, then the request budget. Null when allowed. */
  const gate = (method: "CONNECT" | "HTTP", host: string, port: number): { reason: string } | null => {
    const j = judgeHost(o.policy, host, port, o.policy.knownHosts && o.knownHosts !== undefined ? o.knownHosts() : []);
    if (j.verdict === "deny") {
      deny(method, host, port, j.why ?? "not-listed", j.reason, j.rule);
      return { reason: j.reason };
    }
    const hit = o.budgets.admitRequest(host, now());
    if (hit !== null) {
      o.onEvent({ type: "budget", host, hit });
      deny(method, host, port, "budget", hit.reason, hit.rule);
      return { reason: `${hit.reason}. Raise it in your user policy's budgets key, or add the host to sendAllowHosts, if this agent should send more` };
    }
    // LG1: a connection is made only once its decision is recorded.
    if (o.onEvent({ type: "net", method, host, port, verdict: "allow", reason: j.reason, ...(j.kind !== undefined ? { kind: j.kind } : {}), ...(j.known === true ? { known: true } : {}), ...(j.uploadCapable === true ? { uploadCapable: true } : {}) }) === false) {
      stat(host).refused++;
      return { reason: `${UNRECORDED} (rule FW-LOG-UNRECORDED)` };
    }
    stat(host).conns++;
    return null;
  };

  const dialOrRefuse = async (method: "CONNECT" | "HTTP", host: string, port: number): Promise<{ socket: Socket } | { status: number; reason: string }> => {
    try {
      return { socket: await dial(host, port) };
    } catch (e) {
      if (e instanceof DialRefused) {
        deny(method, host, port, "resolves-internal", e.message);
        return { status: 403, reason: e.message };
      }
      return { status: 502, reason: `could not connect: ${(e as Error).message}` };
    }
  };

  /** Pipes one direction, counting bytes; client-to-server bytes go through the budgets. */
  const pump = (from: Duplex, to: Duplex, host: string, port: number, upward: boolean, kill: () => void): void => {
    from.on("data", (chunk: Buffer) => {
      const s = stat(host);
      if (upward) {
        s.up += chunk.length;
        const hit = o.budgets.addBytes(host, chunk.length);
        if (hit !== null) {
          o.onEvent({ type: "budget", host, hit });
          deny("CONNECT", host, port, "budget", hit.reason, hit.rule);
          kill();
          return;
        }
      } else s.down += chunk.length;
      if (!to.write(chunk)) from.pause();
    });
    to.on("drain", () => from.resume());
    from.on("end", () => to.end());
  };

  /** CONNECT tunnels to port 80 that carry HTTP: every request inside is read and checked like an absolute-form one. */
  const tunnels = new WeakMap<object, { host: string; port: number }>();
  const server = createServer();
  server.on("connection", (s: Socket) => {
    sockets.add(s);
    s.on("close", () => sockets.delete(s));
  });
  server.on("clientError", (_e, s: Duplex) => s.destroy());

  server.on("connect", (req: IncomingMessage, client: Duplex, head: Buffer) => {
    client.on("error", () => client.destroy());
    const t = parseAuthority(req.url ?? "");
    const refuse = (status: number, host: string, port: number, reason: string): void => {
      const body = refusalBody(host, port, reason);
      client.end(`HTTP/1.1 ${status} ${status === 403 ? "Forbidden" : "Bad Gateway"}\r\nContent-Type: text/plain; charset=utf-8\r\nX-LaunchSafe-Firewall: refused\r\nConnection: close\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
    };
    if (t === null) {
      deny("CONNECT", String(req.url ?? "").slice(0, 80), 0, "bad-host", "not a host:port CONNECT target");
      refuse(403, String(req.url ?? "").slice(0, 80), 0, "not a host:port CONNECT target");
      return;
    }
    const g = gate("CONNECT", t.host, t.port);
    if (g !== null) {
      refuse(403, t.host, t.port, g.reason);
      return;
    }
    void dialOrRefuse("CONNECT", t.host, t.port).then((d) => {
      if ("status" in d) {
        refuse(d.status, t.host, t.port, d.reason);
        return;
      }
      const upstream = d.socket;
      sockets.add(upstream);
      upstream.on("close", () => sockets.delete(upstream));
      const kill = (): void => {
        upstream.destroy();
        client.destroy();
      };
      upstream.on("error", kill);
      client.on("close", () => upstream.destroy());
      let handedOff = false;
      upstream.on("close", () => {
        if (!handedOff) client.destroy();
      });
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      // Read the client's first bytes: the TLS ClientHello must name the host of the CONNECT line.
      let buf = head.length > 0 ? Buffer.from(head) : Buffer.alloc(0);
      let decided = false;
      const timer = setTimeout(() => finish({ state: "not-tls", why: "no ClientHello within the time limit" }), o.helloTimeoutMs ?? 10000);
      const onData = (chunk: Buffer): void => {
        buf = Buffer.concat([buf, chunk]);
        check();
      };
      const finish = (r: ReturnType<typeof parseClientHello>): void => {
        if (decided) return;
        decided = true;
        clearTimeout(timer);
        client.removeListener("data", onData);
        client.pause();
        let problem: { why: RunWhy; reason: string } | null = null;
        if (r.state === "refused") problem = { why: "sni-mismatch", reason: `the TLS handshake for ${t.host} cannot be checked: ${r.why}` };
        else if (r.state === "tls" && r.sni !== t.host) problem = { why: "sni-mismatch", reason: r.sni === null ? `the TLS handshake for ${t.host} names no server; run requires the name of the CONNECT line` : `the tunnel was opened for ${t.host} but TLS asks for ${r.sni} (a different server behind the same address)` };
        else if (r.state === "not-tls" && t.port === 443) problem = { why: "not-tls", reason: `port 443 of ${t.host} must carry TLS (${r.why})` };
        if (problem !== null) {
          deny("CONNECT", t.host, t.port, problem.why, problem.reason);
          kill();
          return;
        }
        if (r.state === "not-tls" && t.port !== 443) {
          // Plain HTTP inside the tunnel: the proxy reads each request (Host header, budgets) instead of
          // relaying bytes it cannot see. The upstream dialed above is dropped; each request dials its own.
          handedOff = true;
          upstream.destroy();
          tunnels.set(client, { host: t.host, port: t.port });
          client.unshift(buf);
          server.emit("connection", client);
          client.resume();
          return;
        }
        const s = stat(t.host);
        s.up += buf.length;
        const hit = o.budgets.addBytes(t.host, buf.length);
        if (hit !== null) {
          o.onEvent({ type: "budget", host: t.host, hit });
          deny("CONNECT", t.host, t.port, "budget", hit.reason, hit.rule);
          kill();
          return;
        }
        if (buf.length > 0) upstream.write(buf);
        pump(client, upstream, t.host, t.port, true, kill);
        pump(upstream, client, t.host, t.port, false, kill);
        client.resume();
      };
      const check = (): void => {
        const r = parseClientHello(buf);
        if (r.state !== "need-more") finish(r);
      };
      client.on("data", onData);
      client.on("end", () => finish({ state: "not-tls", why: "the client closed the tunnel before sending anything" }));
      if (buf.length > 0) check();
    });
  });

  /**
   * The checks for a plain-HTTP request (absolute form, or origin form inside a CONNECT-to-port-80 tunnel)
   * before anything is dialed: the URL, the tunnel's own target, the host list and budgets, the Host header.
   * Shared by ordinary requests and upgrades (WebSocket), so both are admitted the same way.
   */
  const admit = (req: IncomingMessage): { ok: true; host: string; port: number; url: URL } | { ok: false; status: number; host: string; port: number; reason: string } => {
    const forced = tunnels.get(req.socket);
    let url: URL;
    try {
      // Inside a CONNECT-to-port-80 tunnel a request is usually origin-form: the tunnel names the server.
      url = new URL(forced !== undefined && (req.url ?? "").startsWith("/") ? `http://${forced.host.includes(":") ? `[${forced.host}]` : forced.host}:${forced.port}${req.url}` : (req.url ?? ""));
    } catch {
      return { ok: false, status: 400, host: "-", port: 0, reason: "send requests in absolute form (http://host/path) or use CONNECT for HTTPS" };
    }
    if (url.protocol !== "http:" && url.protocol !== "ws:") return { ok: false, status: 400, host: url.hostname, port: 0, reason: "only http:// URLs are proxied in absolute form; HTTPS goes through CONNECT" };
    const host = normalizeHost(url.hostname);
    const port = url.port === "" ? 80 : Number(url.port);
    if (forced !== undefined && (host !== forced.host || port !== forced.port)) {
      // A tunnel opened for one server does not carry requests for another.
      const reason = `the tunnel was opened for ${forced.host}:${forced.port} but the request is for ${host}:${port}`;
      deny("HTTP", host, port, "bad-host", reason);
      return { ok: false, status: 403, host, port, reason };
    }
    const g = gate("HTTP", host, port);
    if (g !== null) return { ok: false, status: 403, host, port, reason: g.reason };
    // The Host header must name the admitted server: the list was checked against the URL, and a shared
    // front end routes on Host. A request that names another server is refused; the rest carry the
    // admitted host (a missing Host is filled in).
    const named = req.headers.host;
    if (named !== undefined && !hostNames(named, host, port)) {
      const reason = `the request is for ${host}:${port} but its Host header names ${named.slice(0, 80)} (a different server behind the same address)`;
      deny("HTTP", host, port, "bad-host", reason);
      return { ok: false, status: 403, host, port, reason };
    }
    return { ok: true, host, port, url };
  };

  const hostHeader = (host: string, port: number): string => (port === 80 ? (host.includes(":") ? `[${host}]` : host) : `${host.includes(":") ? `[${host}]` : host}:${port}`);

  server.on("request", (req: IncomingMessage, res: ServerResponse) => {
    const refuse = (status: number, host: string, port: number, reason: string): void => {
      const body = refusalBody(host, port, reason);
      res.writeHead(status, { "content-type": "text/plain; charset=utf-8", "x-launchsafe-firewall": "refused", connection: "close", "content-length": Buffer.byteLength(body) });
      res.end(body);
    };
    const a = admit(req);
    if (!a.ok) {
      req.resume();
      refuse(a.status, a.host, a.port, a.reason);
      return;
    }
    const { host, port, url } = a;
    void dialOrRefuse("HTTP", host, port).then((d) => {
      if ("status" in d) {
        req.resume();
        refuse(d.status, host, port, d.reason);
        return;
      }
      const socket = d.socket;
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
      const headers = forwardHeaders(req.headers);
      for (const k of Object.keys(headers)) if (k.toLowerCase() === "host") delete headers[k];
      headers.host = hostHeader(host, port);
      const path = `${url.pathname}${url.search}`;
      // What the request line and headers put on the wire, counted like the body.
      const headBytes = req.method !== undefined ? req.method.length + path.length + 12 + Object.entries(headers).reduce((n, [k, v]) => n + k.length + 4 + (Array.isArray(v) ? v.join(", ") : v).length, 0) : 0;
      const s = stat(host);
      s.up += headBytes;
      const first = o.budgets.addBytes(host, headBytes);
      if (first !== null) {
        o.onEvent({ type: "budget", host, hit: first });
        deny("HTTP", host, port, "budget", first.reason, first.rule);
        socket.destroy();
        req.resume();
        refuse(403, host, port, first.reason);
        return;
      }
      const up = request({ method: req.method ?? "GET", path, headers, createConnection: () => socket });
      up.on("error", (e) => {
        if (!res.headersSent) refuse(502, host, port, `upstream error: ${e.message || String((e as NodeJS.ErrnoException).code ?? e.name)}`);
        else res.destroy();
      });
      up.on("response", (r) => {
        res.writeHead(r.statusCode ?? 502, forwardHeaders(r.headers));
        r.on("data", (c: Buffer) => {
          s.down += c.length;
        });
        r.pipe(res);
      });
      req.on("data", (c: Buffer) => {
        s.up += c.length;
        const hit = o.budgets.addBytes(host, c.length);
        if (hit !== null) {
          o.onEvent({ type: "budget", host, hit });
          deny("HTTP", host, port, "budget", hit.reason, hit.rule);
          up.destroy();
          req.destroy();
          return;
        }
        if (!up.write(c)) req.pause();
      });
      up.on("drain", () => req.resume());
      req.on("end", () => up.end());
    });
  });

  // An upgrade (a WebSocket, ws://) is admitted like a request (admit: tunnel target, host list, budgets,
  // Host header), then relayed both ways with the bytes the client sends counted against the budgets (RN9).
  server.on("upgrade", (req: IncomingMessage, client: Duplex, head: Buffer) => {
    client.on("error", () => client.destroy());
    const refuse = (status: number, host: string, port: number, reason: string): void => {
      const body = refusalBody(host, port, reason);
      client.end(`HTTP/1.1 ${status} ${status === 403 ? "Forbidden" : status === 400 ? "Bad Request" : "Bad Gateway"}\r\nContent-Type: text/plain; charset=utf-8\r\nX-LaunchSafe-Firewall: refused\r\nConnection: close\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
    };
    const a = admit(req);
    if (!a.ok) {
      refuse(a.status, a.host, a.port, a.reason);
      return;
    }
    const { host, port, url } = a;
    void dialOrRefuse("HTTP", host, port).then((d) => {
      if ("status" in d) {
        refuse(d.status, host, port, d.reason);
        return;
      }
      const upstream = d.socket;
      sockets.add(upstream);
      upstream.on("close", () => sockets.delete(upstream));
      const kill = (): void => {
        upstream.destroy();
        client.destroy();
      };
      upstream.on("error", kill);
      upstream.on("close", () => client.destroy());
      client.on("close", () => upstream.destroy());
      const headers = forwardHeaders(req.headers);
      for (const k of Object.keys(headers)) if (k.toLowerCase() === "host") delete headers[k];
      const lines = [`${req.method ?? "GET"} ${url.pathname}${url.search} HTTP/1.1`, `host: ${hostHeader(host, port)}`, "connection: Upgrade", `upgrade: ${String(req.headers.upgrade ?? "")}`];
      for (const [k, v] of Object.entries(headers)) for (const x of Array.isArray(v) ? v : [v]) lines.push(`${k}: ${x}`);
      // Only the first request's head goes upstream now. Anything the client sends behind it (a pipelined
      // second request with another Host header, which admit() never saw) is held, and is relayed only if the
      // server answers 101: from then on the connection is not HTTP any more. Any other answer ends it.
      const lead = Buffer.from(`${lines.join("\r\n")}\r\n\r\n`, "latin1");
      const s = stat(host);
      s.up += lead.length;
      const hit = o.budgets.addBytes(host, lead.length);
      if (hit !== null) {
        o.onEvent({ type: "budget", host, hit });
        deny("HTTP", host, port, "budget", hit.reason, hit.rule);
        kill();
        return;
      }
      upstream.write(lead);
      const held: Buffer[] = head.length > 0 ? [Buffer.from(head)] : [];
      let heldBytes = head.length;
      const hold = (c: Buffer): void => {
        held.push(c);
        heldBytes += c.length;
        if (heldBytes > UPGRADE_HOLD_MAX) kill();
      };
      client.on("data", hold);
      let answer: Buffer = Buffer.alloc(0);
      const onAnswer = (c: Buffer): void => {
        answer = Buffer.concat([answer, c]);
        const end = answer.indexOf("\r\n\r\n");
        if (end < 0) {
          if (answer.length > UPGRADE_HOLD_MAX) kill();
          return;
        }
        upstream.removeListener("data", onAnswer);
        client.removeListener("data", hold);
        s.down += answer.length;
        if (!/^HTTP\/1\.[01] 101[ \r]/.test(answer.subarray(0, 24).toString("latin1"))) {
          // Not switching protocols: pass the answer on, drop what the client queued behind the request.
          upstream.destroy();
          client.end(answer);
          return;
        }
        client.write(answer);
        const queued = Buffer.concat(held);
        held.length = 0;
        if (queued.length > 0) {
          s.up += queued.length;
          const more = o.budgets.addBytes(host, queued.length);
          if (more !== null) {
            o.onEvent({ type: "budget", host, hit: more });
            deny("HTTP", host, port, "budget", more.reason, more.rule);
            kill();
            return;
          }
          upstream.write(queued);
        }
        pump(client, upstream, host, port, true, kill);
        pump(upstream, client, host, port, false, kill);
      };
      upstream.on("data", onAnswer);
    });
  });

  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    if ("path" in o.listen) server.listen(o.listen.path, () => resolveListen());
    else server.listen(0, o.listen.host, () => resolveListen());
  });
  const addr = server.address();
  return {
    port: typeof addr === "object" && addr !== null ? addr.port : null,
    path: "path" in o.listen ? o.listen.path : null,
    stats: () => [...stats.values()].map((x) => ({ ...x })).sort((a, b) => (a.host < b.host ? -1 : 1)),
    close: () =>
      new Promise<void>((done) => {
        for (const s of sockets) s.destroy();
        server.close(() => done());
      }),
  };
}
