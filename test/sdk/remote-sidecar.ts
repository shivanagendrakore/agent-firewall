/**
 * A fake API sidecar for the remote guard's tests: an in-test node:http server on a temporary unix
 * socket or 127.0.0.1, answering the shapes of docs/api-v0.md. It judges by a table the test sets (tool
 * to verdict), keeps sessions, queue items and idempotency keys, and records every request. It runs no
 * engine, no shell and touches nothing outside its temporary directory.
 */

import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";

export interface Seen {
  method: string;
  path: string;
  headers: http.IncomingHttpHeaders;
  body: unknown;
}

/** Overrides the next answers (one per request, in order). */
export interface Override {
  status?: number;
  /** Raw body text (sent as is). */
  raw?: string;
  /** Answer only after this long (ms). */
  delayMs?: number;
  headers?: Record<string, string>;
}

type Verdict = "allow" | "ask" | "hold" | "deny";

interface Approval {
  id: string;
  status: "pending" | "approved" | "denied" | "expired";
  session: string;
  hash: string;
  used: boolean;
}

export interface FakeSidecar {
  socketPath?: string;
  baseUrl?: string;
  token: string;
  seen: Seen[];
  /** Tool name (as sent in action.tool) to verdict; default allow. */
  verdicts: Map<string, Verdict>;
  /** Tools whose decision taints the session (as an untrusted read does at decision time). */
  tainting: Set<string>;
  overrides: Override[];
  approvals: Map<string, Approval>;
  settle(id: string, status: Approval["status"]): void;
  sessions: Map<string, { untrusted: boolean; untrustedBecause: string[]; holdsPrivateData: boolean; privateBecause: string[] }>;
  close(): Promise<void>;
}

const DECIDE_KEYS = new Set(["session", "action", "context", "dryRun"]);
const ACTION_KEYS = new Set(["format", "tool", "input", "callId", "mcp", "raw"]);
const CONTEXT_KEYS = new Set(["attended", "workspace", "cwd"]);

function problem(res: http.ServerResponse, status: number, detail: string): void {
  res.writeHead(status, { "content-type": "application/problem+json" });
  res.end(JSON.stringify({ type: "about:blank", title: http.STATUS_CODES[status] ?? "error", status, detail }));
}

function json(res: http.ServerResponse, value: unknown): void {
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify(value));
}

export async function startSidecar(kind: "socket" | "tcp"): Promise<FakeSidecar> {
  const dir = mkdtempSync(join(tmpdir(), "lsfw-api-"));
  const seen: Seen[] = [];
  const verdicts = new Map<string, Verdict>();
  const tainting = new Set<string>();
  const overrides: Override[] = [];
  const approvals = new Map<string, Approval>();
  const sessions: FakeSidecar["sessions"] = new Map();
  const idem = new Map<string, string>();
  let seq = 0;
  const token = "test-token-not-a-secret";

  const sessionOf = (s: string) => {
    let v = sessions.get(s);
    if (v === undefined) {
      v = { untrusted: false, untrustedBecause: [], holdsPrivateData: false, privateBecause: [] };
      sessions.set(s, v);
    }
    return v;
  };

  function decide(body: Record<string, unknown>): { status: number; value: unknown } {
    for (const k of Object.keys(body)) if (!DECIDE_KEYS.has(k)) return { status: 400, value: `unknown field ${k}` };
    const action = body.action as Record<string, unknown>;
    const context = body.context as Record<string, unknown>;
    if (typeof body.session !== "string" || typeof action !== "object" || action === null) return { status: 400, value: "bad request" };
    for (const k of Object.keys(action)) if (!ACTION_KEYS.has(k)) return { status: 400, value: `unknown action field ${k}` };
    for (const k of Object.keys(context ?? {})) if (!CONTEXT_KEYS.has(k)) return { status: 400, value: `unknown context field ${k}` };
    if (!["native", "engine", "mcp", "openai.chat", "anthropic"].includes(String(action.format))) return { status: 400, value: "unknown format" };
    const session = `agent-1/${body.session}`;
    const tool = String(action.tool);
    const hash = `sha256:${Buffer.from(JSON.stringify([action.format, tool, action.input, action.mcp ?? null])).toString("base64url").slice(0, 40)}`;
    let verdict: Verdict = verdicts.get(tool) ?? "allow";
    if (verdict === "ask" && context?.attended === false) verdict = "hold";
    const dry = body.dryRun === true;
    // An approved, unused queue item for this exact action: allow once.
    const granted = [...approvals.values()].find((a) => a.session === session && a.hash === hash && a.status === "approved" && !a.used);
    if (granted !== undefined && (verdict === "ask" || verdict === "hold")) {
      if (!dry) granted.used = true;
      verdict = "allow";
    }
    const s = sessionOf(session);
    if (!dry && verdict === "allow" && tainting.has(tool)) {
      s.untrusted = true;
      s.untrustedBecause.push(`${tool} result`);
    }
    seq += 1;
    let approval: { id: string; status: string } | undefined;
    // As the real sidecar (api-v0.md): only a hold is a queue item; an ask is the host's person's.
    if (!dry && verdict === "hold") {
      const id = `apr_${seq}`;
      approvals.set(id, { id, status: "pending", session, hash, used: false });
      approval = { id, status: "pending" };
    }
    const rule = verdict === "allow" ? [] : [{ id: verdict === "deny" ? "FW-SECRET-EGRESS" : "FW-SEND", outcome: verdict === "deny" ? "deny" : "approve", reason: `${tool} needs a look` }];
    return {
      status: 200,
      value: {
        decisionId: `dec_${seq}`,
        verdict,
        rules: rule,
        message: verdict === "allow" ? "" : `LaunchSafe Firewall: ${tool} (${verdict})`,
        actionHash: hash,
        session: { ...s },
        ...(approval !== undefined ? { approval } : {}),
        engine: { version: "0.3.0-test" },
        log: { seq, hash: `sha256:log${seq}` },
      },
    };
  }

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      let body: unknown;
      try {
        body = text === "" ? undefined : JSON.parse(text);
      } catch {
        body = text;
      }
      const path = req.url ?? "";
      seen.push({ method: req.method ?? "", path, headers: req.headers, body });
      const o = overrides.shift();
      const answer = (): void => {
        if (o !== undefined && (o.status !== undefined || o.raw !== undefined)) {
          res.writeHead(o.status ?? 200, { "content-type": "application/json", ...(o.headers ?? {}) });
          res.end(o.raw ?? "");
          return;
        }
        if (req.method === "GET" && path === "/v1/health") return json(res, { ok: true, engine: { version: "0.3.0-test" } });
        if (req.headers.authorization !== `Bearer ${token}`) return problem(res, 401, "no or bad token");
        if (chunks.reduce((n, c) => n + c.length, 0) > 1024 * 1024) return problem(res, 413, "too large");
        if (req.method === "POST" && path === "/v1/decide") {
          const key = req.headers["idempotency-key"];
          const prior = typeof key === "string" ? idem.get(key) : undefined;
          if (prior !== undefined) return json(res, JSON.parse(prior));
          const r = decide(body as Record<string, unknown>);
          if (r.status !== 200) return problem(res, r.status, String(r.value));
          if (typeof key === "string") idem.set(key, JSON.stringify(r.value));
          return json(res, r.value);
        }
        const m = /^\/v1\/sessions\/([^/]+)(?:\/(results|inputs|prompts))?$/.exec(path);
        if (m !== null) {
          const session = `agent-1/${decodeURIComponent(m[1] as string)}`;
          const what = m[2];
          const b = (body ?? {}) as Record<string, unknown>;
          if (req.method === "GET" && what === undefined) return sessions.has(session) ? json(res, sessionOf(session)) : problem(res, 404, "unknown session");
          if (req.method === "POST" && what === "results") {
            if (typeof b.decisionId !== "string" || (b.failed !== undefined && typeof b.failed !== "boolean") || Object.keys(b).some((k) => k !== "decisionId" && k !== "output" && k !== "failed")) return problem(res, 400, "bad result");
            const out = typeof b.output === "string" ? b.output : JSON.stringify(b.output);
            if (out.includes("SECRETVALUE")) {
              sessionOf(session).holdsPrivateData = true;
              return json(res, { recorded: true, output: out.replaceAll("SECRETVALUE", "[masked]") });
            }
            if (out.includes("outside")) {
              sessionOf(session).untrusted = true;
              sessionOf(session).untrustedBecause.push("result");
            }
            return json(res, { recorded: true });
          }
          if (req.method === "POST" && what === "inputs") {
            if (typeof b.source !== "string" || Object.keys(b).some((k) => !["source", "content", "private"].includes(k))) return problem(res, 400, "bad input");
            const s = sessionOf(session);
            s.untrusted = true;
            s.untrustedBecause.push(b.source);
            if (b.private === true) {
              s.holdsPrivateData = true;
              s.privateBecause.push(b.source);
            }
            return json(res, { recorded: true });
          }
          if (req.method === "POST" && what === "prompts") {
            if (typeof b.text !== "string" || Object.keys(b).length !== 1) return problem(res, 400, "bad prompt");
            sessionOf(session);
            return json(res, { recorded: true });
          }
        }
        const a = /^\/v1\/approvals\/([^/]+)$/.exec(path);
        if (req.method === "GET" && a !== null) {
          const ap = approvals.get(decodeURIComponent(a[1] as string));
          return ap === undefined ? problem(res, 404, "unknown approval") : json(res, { id: ap.id, status: ap.status });
        }
        return problem(res, 404, "no such endpoint");
      };
      if (o?.delayMs !== undefined) setTimeout(answer, o.delayMs);
      else answer();
    });
  });

  const socketPath = join(dir, "api.sock");
  await new Promise<void>((resolve) => (kind === "socket" ? server.listen(socketPath, resolve) : server.listen(0, "127.0.0.1", resolve)));
  // The guard uses only a socket owned by this user with mode 0600 (I7), as the real server makes it.
  if (kind === "socket") chmodSync(socketPath, 0o600);
  const port = kind === "tcp" ? (server.address() as AddressInfo).port : 0;
  return {
    ...(kind === "socket" ? { socketPath } : { baseUrl: `http://127.0.0.1:${port}` }),
    token,
    seen,
    verdicts,
    tainting,
    overrides,
    approvals,
    sessions,
    settle(id, status) {
      const ap = approvals.get(id);
      if (ap === undefined) throw new Error(`no approval ${id}`);
      ap.status = status;
    },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** A temporary path where nothing listens (connection refused / no such socket). */
export function deadSocket(): { path: string; done: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "lsfw-api-dead-"));
  return { path: join(dir, "api.sock"), done: () => rmSync(dir, { recursive: true, force: true }) };
}

/** A loopback port that was just closed. */
export async function closedPort(): Promise<number> {
  const s = http.createServer();
  await new Promise<void>((resolve) => s.listen(0, "127.0.0.1", resolve));
  const port = (s.address() as AddressInfo).port;
  await new Promise<void>((resolve) => s.close(() => resolve()));
  return port;
}
