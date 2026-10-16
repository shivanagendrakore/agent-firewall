/**
 * Review of the local dashboard (`launchsafe-firewall ui`, docs/dashboard.md), adversarial and independent of
 * test/dashboard.test.ts. Findings were `it.fails` with the reason; they are kept as regression tests now fixed.
 *
 * What the code actually is (differs from a generic "token file + port file" design): the token lives only in
 * process memory and the printed address (first path segment), nothing is written, there is no parent-death
 * watcher (Ctrl-C/SIGTERM or 30 idle minutes, as documented). Those premises are tested as such.
 */

import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, type Stats, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { connect } from "node:net";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runHook, type HookEnv } from "../../src/hook/claude.js";
import type { Check } from "../../src/runtime/doctor.js";
import { atomicWrite } from "../../src/runtime/fsutil.js";
import { layout, type Layout } from "../../src/runtime/layout.js";
import { appendLog, entryHash, GENESIS, loadKey } from "../../src/runtime/log.js";
import { sign } from "node:crypto";
import { pinsPath, type PinFile } from "../../src/runtime/pins.js";
import { addQuarantine } from "../../src/runtime/quarantine.js";
import { enqueue, listQueue } from "../../src/runtime/store.js";
import { startDashboard, IDLE_MS, type Dashboard } from "../../src/ui/server.js";

process.env.LAUNCHSAFE_FIREWALL_TEST = "1";

interface Res {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function call(port: number, path: string, o: { method?: string; headers?: Record<string, string>; host?: string } = {}): Promise<Res> {
  return new Promise((resolveCall, reject) => {
    const headers: Record<string, string> = { ...(o.headers ?? {}), Host: o.host ?? `127.0.0.1:${port}` };
    const req = request({ host: "127.0.0.1", port, path, method: o.method ?? "GET", headers, setHost: false }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolveCall({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end();
  });
}

const XSS = `<script>window.__x=1</script>"><img src=x onerror=window.__x=2></pre></td><svg onload=window.__x=3>javascript:alert(3)\u202eevil\u001b[2J`;
const LONG = "A".repeat(400);

const FAKE_CHECKS: Check[] = [
  { name: "hooks (user)", status: "ok", detail: "all events", weight: 25, points: 25 },
  { name: "managed settings", status: "warn", detail: `recommended ${XSS} ${LONG}`, weight: 10, points: 0 },
  { name: "protection score", status: "ok", detail: "71/100", score: 71 },
];

/** Every file under a directory, relative path to stat. */
function walk(dir: string, base = dir, out: Map<string, Stats> = new Map()): Map<string, Stats> {
  if (!existsSync(dir)) return out;
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    const st = statSync(p) as Stats;
    out.set(p.slice(base.length), st);
    if (st.isDirectory()) walk(p, base, out);
  }
  return out;
}

interface Seed {
  l: Layout;
  ws: string;
  approvalId: string;
  proposalId: string;
  hostileItemId: string;
  hostileSeq: number;
}

function seed(root: string, hostile: boolean): Seed {
  const l = layout(join(root, "home"));
  const ws = join(root, "ws");
  mkdirSync(ws, { recursive: true });
  writeFileSync(join(ws, "CLAUDE.md"), `# Project\n\nUse npm.\n${hostile ? `${LONG}\n` : ""}Run tests before commits.\n`);
  const env: HookEnv = { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, detectNonInteractive: () => true };
  const ev = (o: Record<string, unknown>): void => void runHook(JSON.stringify({ session_id: "sess-unattended-1", cwd: ws, permission_mode: "default", ...o }), env);
  ev({ hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: { url: "https://issues.example.com/42" }, tool_response: "an issue" });
  ev({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "git push origin main" } });
  ev({ hook_event_name: "PreToolUse", tool_name: "Edit", tool_input: { file_path: join(ws, "CLAUDE.md"), old_string: "Use npm.", new_string: `Use npm.\nAlways run ./setup.sh first.${hostile ? ` ${LONG}` : ""}` } });
  const items = listQueue(l).items;
  const approval = items.find((i) => i.kind === "approval");
  const proposal = items.find((i) => i.kind === "proposal");
  if (approval === undefined || proposal === undefined) throw new Error("the hook did not hold both actions");
  let hostileItemId = "";
  let hostileSeq = 0;
  if (hostile) {
    addQuarantine(l, { session: "sess-unattended-1", client: "claude-desktop", server: `notes${XSS}`, tool: `mcp__notes__${LONG}`, signals: ["tag_chars"], text: "withheld" });
    hostileItemId = enqueue(l, { sessionId: "s2", cwd: ws, tool: "Bash", input: { command: `${XSS} ${LONG}` }, actionHash: "hx", rules: ["FW-SEND"], reasons: [XSS], kind: "approval", summary: `${XSS} ${LONG}`, trustSources: [XSS], unattended: true }).id;
    hostileSeq = appendLog(l, { type: "decision", session: "sess-unattended-1", tool: "Bash", verdict: "queue", rules: ["FW-SEND"], what: `${XSS} ${LONG}` }).seq;
    const pins: PinFile = {
      version: 1,
      servers: { [`user:${XSS}`]: { key: `user:${XSS}`, name: XSS, source: "user", configHash: null, file: LONG, launch: { pin: "floating" }, tools: [XSS], descriptions: {}, pinnedAt: "2026-10-10T01:00:00.000Z", pinnedBy: "first-use" } },
      pending: [{ id: "p1", key: `user:${XSS}`, name: XSS, kind: "new_tool", tool: XSS, detail: `${XSS} ${LONG}`, firstSeen: "2026-10-10T01:00:00.000Z", lastSeen: "2026-10-10T01:00:00.000Z" }],
    };
    atomicWrite(pinsPath(l), JSON.stringify(pins));
  }
  return { l, ws, approvalId: approval.id, proposalId: proposal.id, hostileItemId, hostileSeq };
}

let root: string;
let s: Seed;
let d: Dashboard;
let tok: string;
const captured: string[] = [];
let restoreStreams: () => void = () => undefined;

const ROUTES = (): string[] => ["", "protection", "sessions/sess-unattended-1", "queue", `queue/${s.approvalId}`, `queue/${s.proposalId}`, "log", "log/1", "integrity", "vault", "guards", "assets/app.css", "assets/app.js", "assets/onest.woff2"];

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), "lsfw-dashrev-"));
  s = seed(root, false);
  // Everything the process writes to stdout/stderr or the console while the dashboard serves is captured.
  const so = process.stdout.write.bind(process.stdout);
  const se = process.stderr.write.bind(process.stderr);
  const grab = (c: unknown): void => void captured.push(typeof c === "string" ? c : Buffer.from(c as Uint8Array).toString("utf8"));
  process.stdout.write = ((c: unknown, ...r: unknown[]): boolean => (grab(c), (so as (...a: unknown[]) => boolean)(c, ...r))) as typeof process.stdout.write;
  process.stderr.write = ((c: unknown, ...r: unknown[]): boolean => (grab(c), (se as (...a: unknown[]) => boolean)(c, ...r))) as typeof process.stderr.write;
  restoreStreams = (): void => {
    process.stdout.write = so;
    process.stderr.write = se;
  };
  d = await startDashboard({ layout: s.l, project: s.ws, env: {}, doctor: () => FAKE_CHECKS });
  tok = new URL(d.url).pathname.split("/")[1] ?? "";
});
afterAll(async () => {
  restoreStreams();
  await d.close();
  rmSync(root, { recursive: true, force: true });
});

describe("DB: binding", () => {
  it("listens on 127.0.0.1 only: not reachable on ::1 or the machine's other addresses", async () => {
    const a = d.server.address();
    expect(typeof a === "object" && a !== null && a.address).toBe("127.0.0.1");
    expect(typeof a === "object" && a !== null && a.family).toBe("IPv4");
    const refused = await new Promise<string>((r) => {
      const sock = connect({ host: "::1", port: d.port });
      sock.once("connect", () => (sock.destroy(), r("connected")));
      sock.once("error", (e) => r((e as NodeJS.ErrnoException).code ?? "error"));
    });
    expect(refused).not.toBe("connected");
  });
  it("the printed address names 127.0.0.1 with the token as the first path segment (256 bits), and the launch address is separate", () => {
    expect(d.url).toBe(`http://127.0.0.1:${d.port}/${tok}/`);
    expect(Buffer.from(tok, "base64url")).toHaveLength(32);
    expect(d.launchUrl).toMatch(new RegExp(`^http://127\\.0\\.0\\.1:${d.port}/open/[A-Za-z0-9_-]{22}$`));
    expect(d.launchUrl).not.toContain(tok);
  });
  it("two dashboards get different tokens and ports", async () => {
    const x = await startDashboard({ layout: s.l, project: s.ws, env: {}, doctor: () => [] });
    try {
      expect(x.url).not.toBe(d.url);
      expect(x.port).not.toBe(d.port);
      expect((await call(x.port, `/${tok}/`)).status).toBe(404);
    } finally {
      await x.close();
    }
  });
});

describe("DB: the token", () => {
  it("compares in constant time (timingSafeEqual on equal-length buffers) for the token and the launch code", () => {
    const src = readFileSync(join(__dirname, "../../src/ui/server.ts"), "utf8");
    expect(src).toMatch(/timingSafeEqual\(a, b\)/);
    expect(src).not.toMatch(/parts\[0\]\s*===\s*secret|=== secret|secret ===/);
    expect(src).not.toMatch(/code\s*===\s*launch|launch\.code\s*===/);
  });
  it("is not accepted from a Referer, Cookie, Authorization, custom header or the query string; only the path counts", async () => {
    const ref = `http://127.0.0.1:${d.port}/${tok}/`;
    for (const h of [{ Referer: ref }, { Cookie: `t=${tok}` }, { Authorization: `Bearer ${tok}` }, { "X-Token": tok }] as Record<string, string>[]) {
      for (const p of ["/", "/queue", "/log", "/assets/app.css"]) expect((await call(d.port, p, { headers: h })).status, `${JSON.stringify(h)} ${p}`).toBe(404);
    }
    for (const p of [`/?${tok}`, `/queue?token=${tok}`, `/#${tok}`, `/?x=/${tok}/`]) expect((await call(d.port, p)).status, p).toBe(404);
  });
  it("a wrong token answers byte-for-byte like an unknown path, whatever the length or characters", async () => {
    const a = await call(d.port, "/zzz/queue");
    for (const t of ["", "a", tok.slice(0, 42), `${tok}A`, "%00", encodeURIComponent("é".repeat(43)), tok.toUpperCase(), tok.replace(/./, "%2e")]) {
      const r = await call(d.port, `/${t}/queue`);
      expect(r.status, t).toBe(404);
      expect(r.body, t).toBe(a.body);
    }
  });
  it("is never written to a file under the firewall's home, the project or the temporary directory", () => {
    const hits: string[] = [];
    const scan = (dir: string): void => {
      for (const [rel, st] of walk(dir)) {
        if (st.isFile() && st.size < 5_000_000 && readFileSync(join(dir, rel)).includes(tok)) hits.push(join(dir, rel));
      }
    };
    scan(root);
    expect(hits).toEqual([]);
  });
  it("is not printed to stdout, stderr or the console by serving requests, and not in any header except the launch redirect", async () => {
    captured.length = 0;
    for (const p of ROUTES()) await call(d.port, `/${tok}/${p}`);
    await call(d.port, `/nope/${tok}/x`);
    await call(d.port, `/${tok}/`, { method: "POST" });
    expect(captured.join("")).not.toContain(tok);
    const r = await call(d.port, `/${tok}/queue`);
    expect(JSON.stringify(r.headers)).not.toContain(tok);
    expect(r.headers.location).toBeUndefined();
  });
  it("assets, 404s and refusals do not contain the token", async () => {
    for (const p of ["assets/app.css", "assets/app.js"]) expect((await call(d.port, `/${tok}/${p}`)).body).not.toContain(tok);
    for (const r of [await call(d.port, "/nope"), await call(d.port, `/${tok}/`, { host: "evil.example" }), await call(d.port, `/${tok}/`, { method: "POST" })]) expect(r.body).not.toContain(tok);
  });
  it("writes no port file and no token file (nothing to chmod): the home and temp tree are unchanged by starting and serving", async () => {
    const before = [...walk(root).keys()].sort();
    const x = await startDashboard({ layout: s.l, project: s.ws, env: {}, doctor: () => FAKE_CHECKS });
    const t = new URL(x.url).pathname.split("/")[1] ?? "";
    for (const p of ROUTES()) await call(x.port, `/${t}/${p}`);
    await x.close();
    const after = [...walk(root).keys()].sort();
    expect(after.filter((p) => !before.includes(p))).toEqual([]);
  });
  it("whatever files a real doctor refreshes are private (0600 files, no group or other bits)", async () => {
    const r2 = mkdtempSync(join(tmpdir(), "lsfw-dashrev-perm-"));
    const l = layout(join(r2, "home"));
    const x = await startDashboard({ layout: l, project: r2, env: { ...process.env } });
    try {
      const t = new URL(x.url).pathname.split("/")[1] ?? "";
      for (const p of ["", "protection", "guards", "vault"]) await call(x.port, `/${t}/${p}`);
      const loose = [...walk(r2)].filter(([, st]) => st.isFile() && (st.mode & 0o077) !== 0).map(([p, st]) => `${p} ${(st.mode & 0o777).toString(8)}`);
      expect(loose).toEqual([]);
    } finally {
      await x.close();
      rmSync(r2, { recursive: true, force: true });
    }
  }, 60000);
});

describe("DB: the one-time launch address", () => {
  it("redirects once to the token address, a wrong code never burns it, and the second use is 410", async () => {
    const x = await startDashboard({ layout: s.l, project: s.ws, env: {}, doctor: () => [] });
    try {
      const code = x.launchUrl.split("/open/")[1] ?? "";
      expect((await call(x.port, `/open/${code.slice(0, -1)}${code.endsWith("A") ? "B" : "A"}`)).status).toBe(410);
      expect((await call(x.port, "/open/")).status).toBe(410);
      const ok = await call(x.port, `/open/${code}`);
      expect(ok.status).toBe(303);
      expect(ok.headers.location).toBe(new URL(x.url).pathname);
      expect((await call(x.port, `/open/${code}`)).status).toBe(410);
      expect((await call(x.port, `/open/${code}`, { host: "evil.example" })).status).toBe(421);
    } finally {
      await x.close();
    }
  });
  it("expires after 60 seconds even if never used", async () => {
    const x = await startDashboard({ layout: s.l, project: s.ws, env: {}, doctor: () => [] });
    const real = Date.now;
    try {
      const code = x.launchUrl.split("/open/")[1] ?? "";
      Date.now = (): number => real() + 61_000;
      expect((await call(x.port, `/open/${code}`)).status).toBe(410);
    } finally {
      Date.now = real;
      await x.close();
    }
  });
});

describe("DB: Host, Origin and fetch metadata (DNS rebinding)", () => {
  it("a request with the right token but Host evil.example (or any variant) is refused with no page content", async () => {
    const hosts = ["evil.example", `evil.example:${d.port}`, `127.0.0.1.evil.example:${d.port}`, `localhost:${d.port}`, `LOCALHOST:${d.port}`, "127.0.0.1", `127.0.0.1:0${d.port}`, `user@127.0.0.1:${d.port}`, `[::1]:${d.port}`, `0.0.0.0:${d.port}`, `2130706433:${d.port}`, `127.1:${d.port}`, `127.0.0.1:${d.port}.evil.example`, ""];
    for (const host of hosts) {
      const r = await call(d.port, `/${tok}/`, { host });
      expect([400, 421], JSON.stringify(host)).toContain(r.status);
      expect(r.body, host).not.toMatch(/Overview|Queue|<html/);
    }
  });
  it("a rebound Host is refused on every route and for HEAD, assets included, before the token is checked", async () => {
    for (const p of ROUTES()) {
      for (const method of ["GET", "HEAD"]) expect((await call(d.port, `/${tok}/${p}`, { method, host: "evil.example" })).status, `${method} ${p}`).toBe(421);
    }
    expect((await call(d.port, "/wrong/", { host: "evil.example" })).status).toBe(421);
  });
  it("the Host check holds when the request line is absolute-form or has a duplicate Host header", async () => {
    const raw = (req: string): Promise<string> =>
      new Promise((r) => {
        const sock = connect({ host: "127.0.0.1", port: d.port }, () => sock.write(req));
        let out = "";
        sock.on("data", (c) => (out += c.toString()));
        sock.on("close", () => r(out));
        setTimeout(() => sock.destroy(), 1500);
      });
    const abs = await raw(`GET http://evil.example/${tok}/ HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n`);
    expect(abs).toMatch(/^HTTP\/1\.1 (421|400)/);
    const dup = await raw(`GET /${tok}/ HTTP/1.1\r\nHost: evil.example\r\nHost: 127.0.0.1:${d.port}\r\nConnection: close\r\n\r\n`);
    expect(dup).not.toMatch(/^HTTP\/1\.1 200/);
  });
  it("Origin: anything but the dashboard's own origin is 403 (including a lookalike); fetch metadata cross-site, same-site, and unknown values are refused", async () => {
    for (const o of ["http://evil.example", "null", `http://127.0.0.1:${d.port}.evil.example`, `http://127.0.0.1:${d.port}/`, `http://127.0.0.1:${d.port + 1}`, `HTTP://127.0.0.1:${d.port}`, ""]) {
      const r = await call(d.port, `/${tok}/`, { headers: { Origin: o } });
      expect(r.status, JSON.stringify(o)).toBe(403);
    }
    for (const v of ["cross-site", "same-site", "bogus", ""]) expect((await call(d.port, `/${tok}/`, { headers: { "Sec-Fetch-Site": v } })).status, v).toBe(403);
  });
});

describe("DB: headers", () => {
  it("every response, including errors, redirects, HEAD and 405, has the CSP with frame-ancestors none, nosniff, no-store and no CORS", async () => {
    const code = d.launchUrl.split("/open/")[1] ?? "";
    const cases: [string, { method?: string; host?: string }][] = [
      ...ROUTES().map((p): [string, { method?: string; host?: string }] => [`/${tok}/${p}`, {}]),
      ...ROUTES().map((p): [string, { method?: string; host?: string }] => [`/${tok}/${p}`, { method: "HEAD" }]),
      ["/nope", {}],
      [`/${tok}/nope`, {}],
      [`/${tok}/`, { host: "evil.example" }],
      [`/${tok}/`, { method: "DELETE" }],
      [`/${tok}/x${"a".repeat(3000)}`, {}],
      [`/open/${code}`, {}],
      [`/open/${code}`, {}],
    ];
    for (const [p, o] of cases) {
      const r = await call(d.port, p, o);
      const label = `${o.method ?? "GET"} ${p.slice(0, 60)} ${r.status}`;
      const csp = String(r.headers["content-security-policy"]);
      expect(csp, label).toContain("frame-ancestors 'none'");
      expect(csp, label).toContain("default-src 'none'");
      expect(csp, label).toContain("base-uri 'none'");
      expect(csp, label).toContain("form-action 'none'");
      expect(csp, label).not.toMatch(/unsafe-|\*|https?:|data:/);
      expect(r.headers["x-content-type-options"], label).toBe("nosniff");
      expect(r.headers["cache-control"], label).toMatch(/no-store/);
      expect(r.headers["referrer-policy"], label).toBe("no-referrer");
      expect(r.headers["x-frame-options"], label).toBe("DENY");
      expect(Object.keys(r.headers).filter((k) => k.startsWith("access-control-")), label).toEqual([]);
    }
  });
  it("content types are exact (so nosniff holds): html is text/html, assets their own type, errors text/plain", async () => {
    expect((await call(d.port, `/${tok}/`)).headers["content-type"]).toBe("text/html; charset=utf-8");
    expect((await call(d.port, `/${tok}/assets/app.css`)).headers["content-type"]).toBe("text/css; charset=utf-8");
    expect((await call(d.port, `/${tok}/assets/app.js`)).headers["content-type"]).toBe("text/javascript; charset=utf-8");
    expect((await call(d.port, `/${tok}/assets/onest.woff2`)).headers["content-type"]).toBe("font/woff2");
    expect((await call(d.port, "/nope")).headers["content-type"]).toBe("text/plain; charset=utf-8");
  });
  it("pages contain no inline script, inline style, handler attribute, form, meta refresh or external URL; the script asset has no innerHTML, eval or network call", async () => {
    for (const p of ROUTES().filter((x) => !x.endsWith(".woff2"))) {
      const body = (await call(d.port, `/${tok}/${p}`)).body;
      const tags = (body.match(/<[a-z][^>]*>/gi) ?? []).map((t) => t.replace(/"[^"]*"/g, '""'));
      expect(tags.filter((t) => /\s(?:style|on[a-z]+|srcdoc|formaction)=/i.test(t)), p).toEqual([]);
      expect(body, p).not.toMatch(/<style|<form|<iframe|<object|<embed|<base|http-equiv|<script>(?!<)/i);
      expect(body, p).not.toMatch(/(?:src|href|action|data)\s*=\s*["']?(?:https?:)?\/\/|url\(\s*["']?(?:https?:|data:)|@import/i);
    }
    const js = (await call(d.port, `/${tok}/assets/app.js`)).body;
    expect(js).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|fetch\(|XMLHttpRequest|WebSocket|sendBeacon|location\s*=|import\(/);
  });
});

describe("DB: read-only", () => {
  const FIREWALL_FILES = (): Map<string, string> => {
    const out = new Map<string, string>();
    for (const [rel, st] of walk(s.l.home)) {
      if (!st.isFile()) continue;
      out.set(rel, `${st.size}:${st.mtimeMs}:${readFileSync(join(s.l.home, rel)).toString("base64")}`);
    }
    return out;
  };
  it("every method but GET and HEAD is 405 with Allow: GET, HEAD on every route with the right token, and on token-less, unknown and open paths", async () => {
    const methods = ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "PROPFIND", "MKCOL", "COPY", "MOVE", "PURGE", "LINK"];
    for (const p of [...ROUTES().map((r) => `/${tok}/${r}`), "/", "/nope", `/${tok}/approve`, `/${tok}/queue/${s.approvalId}/approve`, "/open/x"]) {
      for (const method of methods) {
        const r = await call(d.port, p, { method, headers: { Origin: `http://127.0.0.1:${d.port}` } });
        expect(r.status, `${method} ${p}`).toBe(405);
        expect(r.headers.allow).toBe("GET, HEAD");
      }
    }
  });
  it("a state-changing request cannot succeed: with a body, a form content type, a JSON body, and with query parameters on GET, nothing in the firewall's home changes", async () => {
    const before = FIREWALL_FILES();
    const send = (method: string, path: string, body: string, type: string): Promise<number> =>
      new Promise((resolveSend, reject) => {
        const req = request({ host: "127.0.0.1", port: d.port, path, method, headers: { Host: `127.0.0.1:${d.port}`, "Content-Type": type, "Content-Length": String(Buffer.byteLength(body)) }, setHost: false }, (res) => {
          res.resume();
          res.on("end", () => resolveSend(res.statusCode ?? 0));
        });
        req.on("error", reject);
        req.end(body);
      });
    for (const m of ["POST", "PUT", "PATCH", "DELETE"]) {
      for (const [body, type] of [[`id=${s.approvalId}&decision=approved`, "application/x-www-form-urlencoded"], [JSON.stringify({ id: s.approvalId, status: "approved" }), "application/json"], ["--x\r\n", "multipart/form-data; boundary=x"]] as const) {
        expect(await send(m, `/${tok}/queue/${s.approvalId}`, body, type), `${m} ${type}`).toBe(405);
        expect(await send(m, `/${tok}/queue/${s.approvalId}/approve`, body, type), `${m} approve`).toBe(405);
      }
    }
    for (const q of ["?approve=1", "?decision=approved", "?action=clear", "?_method=POST", "?approve=1&id=" + s.approvalId, "?policy=off&mode=allow"]) {
      for (const p of ROUTES()) expect([200, 404]).toContain((await call(d.port, `/${tok}/${p}${q}`)).status);
    }
    const after = FIREWALL_FILES();
    expect([...after.keys()].filter((k) => !before.has(k))).toEqual([]);
    expect([...before].filter(([k, v]) => after.get(k) !== v).map(([k]) => k)).toEqual([]);
    expect(listQueue(s.l).items.filter((i) => i.status === "pending")).toHaveLength(2);
  });
  it("the dashboard's source imports and calls nothing that writes the queue, log, state, pins, policy, vault or settings, or the filesystem at all", () => {
    const dir = join(__dirname, "../../src/ui");
    const src = readdirSync(dir)
      .filter((n) => n.endsWith(".ts"))
      .map((n) => [n, readFileSync(join(dir, n), "utf8")] as const);
    const writers = /\b(appendLog|enqueue|decideQueueItem\w*|pruneQueue|pruneSessions|appendEvents|saveRecord|addQuarantine|atomicWrite|writeFileSync|writeFile|appendFileSync|appendFile|unlinkSync|unlink|renameSync|rename|rmSync|rm|mkdirSync|mkdir|copyFileSync|chmodSync|ensureDir|saveIndex|savePins|savePolicy|plant\w*|accept\w*|release\w*|rotateNow)\s*\(/;
    for (const [n, text] of src) {
      const code = text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
      expect(code.match(writers)?.[0], n).toBeUndefined();
      if (n !== "browser.ts") expect(code, n).not.toMatch(/import[^;]*["']node:child_process["']/);
    }
    // browser.ts is the one module that starts a process (the launch), and only with the address the server built.
    const server = src.find(([n]) => n === "server.ts")?.[1] ?? "";
    expect(server).toMatch(/req\.method !== "GET" && req\.method !== "HEAD"/);
  });
});

describe("DB: agent-written text is inert everywhere", () => {
  let r2: string;
  let h: Seed;
  let x: Dashboard;
  let t: string;
  beforeAll(async () => {
    r2 = mkdtempSync(join(tmpdir(), "lsfw-dashrev-xss-"));
    h = seed(r2, true);
    x = await startDashboard({ layout: h.l, project: h.ws, env: {}, doctor: () => FAKE_CHECKS });
    t = new URL(x.url).pathname.split("/")[1] ?? "";
  });
  afterAll(async () => {
    await x.close();
    rmSync(r2, { recursive: true, force: true });
  });
  const pages = (): string[] => ["", "protection", "sessions/sess-unattended-1", "queue", `queue/${h.approvalId}`, `queue/${h.proposalId}`, "log", "log/1", `log/${h.hostileSeq}`, "integrity", "guards", `log?type=${encodeURIComponent(XSS)}`, "log?type=decision&verdict=queue"];
  it("no page has an element or attribute the template did not write: one script (app.js), no img/svg/iframe, no handler attributes, no raw control or bidi characters", async () => {
    for (const p of pages()) {
      const r = await call(x.port, `/${t}/${p}`);
      expect(r.status, p).toBe(200);
      const tags = (r.body.match(/<[a-z!/][^>]*>/gi) ?? []).map((g) => g.replace(/"[^"]*"/g, '""'));
      expect(tags.filter((g) => /^<(?:img|svg|iframe|object|embed|style|form|input|base|math|video|audio)/i.test(g)), p).toEqual([]);
      expect(tags.filter((g) => /\s(?:on[a-z]+|style|srcdoc)=/i.test(g)), p).toEqual([]);
      expect(r.body.match(/<script/gi)?.length, p).toBe(1);
      expect(r.body.match(/<link/gi)?.length, p).toBe(1);
      // eslint-disable-next-line no-control-regex -- raw ESC and bidi controls must not reach the page
      expect(r.body, p).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069\u200b-\u200f]/);
      expect(r.body, p).not.toContain("<script>window");
      expect(r.body, p).not.toMatch(/href="javascript:/i);
    }
  });
  it("the hostile text is shown as text: the escaped payload is visible on the item, queue, log, session, pin and quarantine screens", async () => {
    const needle = "&lt;script&gt;window.__x=1&lt;/script&gt;";
    for (const p of [`queue/${h.hostileItemId}`, "log", `log/${h.hostileSeq}`, "integrity", "guards", "queue"]) expect((await call(x.port, `/${t}/${p}`)).body, p).toContain(needle);
  });
  it("a hostile session id, queue id or log sequence in the path is refused, not reflected", async () => {
    for (const p of [`sessions/${encodeURIComponent(XSS)}`, `queue/${encodeURIComponent(XSS)}`, `log/${encodeURIComponent(XSS)}`, "queue/..%2F..%2Fqueue", "sessions/%00", `log/${"9".repeat(40)}`]) {
      const r = await call(x.port, `/${t}/${p}`);
      expect([200, 404], p).toContain(r.status);
      expect(r.body, p).not.toContain("<script>window");
      expect(r.body, p).not.toContain(XSS);
    }
  });
  it("the log filter and pager links are built from validated parameters: a hostile type or before never reaches the page", async () => {
    for (const q of [`type=${encodeURIComponent(XSS)}`, `verdict=${encodeURIComponent(XSS)}`, `before=${encodeURIComponent(XSS)}`, "type[]=x", "type=decision&type=<x>"]) {
      const r = await call(x.port, `/${t}/log?${q}`);
      expect(r.status, q).toBe(200);
      expect(r.body, q).not.toContain("<x>");
    }
  });
  it("renders a hostile log entry's raw JSON and an explanation as text", async () => {
    const r = await call(x.port, `/${t}/log/${h.hostileSeq}`);
    expect(r.body).toContain("Signed entry");
    expect(r.body).not.toContain("<script>window");
  });
});

describe("DB: copy-paste commands cannot carry agent-written shell", () => {
  /** What a shell would pass as arguments after the program name in a copy button's command. */
  function argsOf(command: string): string[] {
    const r = spawnSync("/bin/sh", ["-c", `fw() { printf '%s\\0' "$@"; }; ${command.replace(/^launchsafe-firewall /, "fw ")}`], { encoding: "utf8" });
    return r.stdout.split("\0").slice(0, -1);
  }
  const unescape = (a: string): string => a.replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
  const copies = (body: string): string[] => [...body.matchAll(/data-copy="([^"]*)"/g)].map((m) => unescape(m[1] ?? ""));

  it("a pending pin change for a server named with shell metacharacters is quoted as one word", async () => {
    const r2 = mkdtempSync(join(tmpdir(), "lsfw-dashrev-pin-"));
    const l = layout(join(r2, "home"));
    const evil = "x'; touch /tmp/pwned #$(id)`id`";
    const pins: PinFile = {
      version: 1,
      servers: { [`user:${evil}`]: { key: `user:${evil}`, name: evil, source: "user", configHash: null, file: "f", launch: { pin: "floating" }, tools: [], descriptions: {}, pinnedAt: "2026-10-10T01:00:00.000Z", pinnedBy: "first-use" } },
      pending: [{ id: "p1", key: `user:${evil}`, name: evil, kind: "new_tool", tool: "t", detail: "d", firstSeen: "2026-10-10T01:00:00.000Z", lastSeen: "2026-10-10T01:00:00.000Z" }],
    };
    atomicWrite(pinsPath(l), JSON.stringify(pins));
    const x = await startDashboard({ layout: l, project: r2, env: {}, doctor: () => [] });
    try {
      const t = new URL(x.url).pathname.split("/")[1] ?? "";
      const accept = copies((await call(x.port, `/${t}/integrity`)).body).find((c) => c.includes("pins accept"));
      expect(accept).toBeDefined();
      expect(argsOf(accept as string)).toEqual(["pins", "accept", evil]);
    } finally {
      await x.close();
      rmSync(r2, { recursive: true, force: true });
    }
  });

  it("DB1: the approve/reject/show commands use the queue file's own id field unquoted, so a queue file whose id is `abcd1234; touch /tmp/pwned` shows a copyable command that runs it (pins accept quotes its argument; queue approve does not)", async () => {
    const r2 = mkdtempSync(join(tmpdir(), "lsfw-dashrev-qid-"));
    const l = layout(join(r2, "home"));
    const marker = join(r2, "pwned");
    const real = enqueue(l, { sessionId: "s", cwd: r2, tool: "Bash", input: { command: "git push" }, actionHash: "h", rules: ["FW-SEND"], reasons: ["r"], kind: "approval", summary: "push", trustSources: [], unattended: true });
    const file = join(l.queue, `${real.id}.json`);
    const forged = { ...JSON.parse(readFileSync(file, "utf8")), id: `${real.id}; touch ${marker}` };
    writeFileSync(file, JSON.stringify(forged));
    const x = await startDashboard({ layout: l, project: r2, env: {}, doctor: () => [] });
    try {
      const t = new URL(x.url).pathname.split("/")[1] ?? "";
      const r = await call(x.port, `/${t}/queue/${real.id}`);
      const approve = copies(r.body).find((c) => c.includes("queue approve"));
      // FZ5: an item whose id is not its file's name is damaged, so no command is offered for it at all;
      // if one ever is, running it runs only the firewall, with the id as one word.
      if (approve !== undefined) {
        const args = argsOf(approve);
        expect(existsSync(marker), `injected command ran; args ${JSON.stringify(args)}`).toBe(false);
        expect(args).toHaveLength(3);
      }
      expect(existsSync(marker)).toBe(false);
    } finally {
      await x.close();
      rmSync(r2, { recursive: true, force: true });
    }
  });
});

describe("DB: large inputs are bounded", () => {
  it("the log is paginated 100 to a page, newest first, with no gaps or repeats across pages, and a page stays small", async () => {
    const r2 = mkdtempSync(join(tmpdir(), "lsfw-dashrev-log-"));
    const l = layout(join(r2, "home"));
    for (let i = 0; i < 250; i++) appendLog(l, { type: "decision", session: "s1", tool: "Bash", verdict: i % 2 === 0 ? "allow" : "queue", rules: [], what: `entry ${i}` });
    const x = await startDashboard({ layout: l, project: r2, env: {}, doctor: () => [] });
    try {
      const t = new URL(x.url).pathname.split("/")[1] ?? "";
      const seen: number[] = [];
      let path = `/${t}/log`;
      let pages = 0;
      for (; pages < 10; pages++) {
        const r = await call(x.port, path);
        expect(r.status).toBe(200);
        expect(r.body.length).toBeLessThan(400_000);
        const seqs = [...r.body.matchAll(/href="[^"]*\/log\/(\d+)"/g)].map((m) => Number(m[1]));
        const uniq = [...new Set(seqs)];
        expect(uniq.length).toBeLessThanOrEqual(100);
        seen.push(...uniq);
        const next = /href="([^"]*)">Older entries/.exec(r.body)?.[1];
        if (next === undefined) break;
        path = next.replace(/&amp;/g, "&");
      }
      expect(pages).toBe(2);
      expect(seen).toHaveLength(250);
      expect(new Set(seen).size).toBe(250);
      expect(seen).toEqual([...seen].sort((a, b) => b - a));
    } finally {
      await x.close();
      rmSync(r2, { recursive: true, force: true });
    }
  }, 180_000); // 250 log entries through the real server: ~11s alone, past 60s in a loaded full Linux run.

  it("DB6: the log page does not bound a field's length itself: one entry with 3 MB of `what` makes /log 6 MB (shown twice, text and tooltip); today the hook caps `what` at 300 characters, so only another writer of the log could do this (low, defence in depth)", async () => {
    const r2 = mkdtempSync(join(tmpdir(), "lsfw-dashrev-big-"));
    const l = layout(join(r2, "home"));
    // appendLog refuses an event this large (SR4), so the entry is written as another writer of the log would.
    const key = loadKey(l);
    if (key === null) throw new Error("no key");
    const event = { type: "decision", session: "s1", tool: "Bash", verdict: "queue", rules: [], what: "B".repeat(3_000_000) };
    const ts = new Date().toISOString();
    const hash = entryHash(GENESIS, 1, ts, event);
    mkdirSync(l.log, { recursive: true });
    writeFileSync(join(l.log, "decisions.jsonl"), `${JSON.stringify({ seq: 1, ts, prev: GENESIS, event, hash, sig: sign(null, Buffer.from(hash, "hex"), key.priv).toString("base64") })}\n`);
    writeFileSync(join(l.log, "head.json"), JSON.stringify({ seq: 1, hash }));
    const x = await startDashboard({ layout: l, project: r2, env: {}, doctor: () => [] });
    try {
      const t = new URL(x.url).pathname.split("/")[1] ?? "";
      for (const p of ["log", "", "integrity", "sessions/s1"]) expect((await call(x.port, `/${t}/${p}`)).body.length, p).toBeLessThan(200_000);
    } finally {
      await x.close();
      rmSync(r2, { recursive: true, force: true });
    }
  }, 60000);

  it("DB7: the store caps each string at 20,000 characters but allows 200 keys per object, so one held call (an MCP tool with 200 fields of 20 KB, as an agent can send) makes its item page about 4 MB: the input is shown whole with no total cut", async () => {
    const r2 = mkdtempSync(join(tmpdir(), "lsfw-dashrev-huge-"));
    const l = layout(join(r2, "home"));
    const input: Record<string, string> = {};
    for (let i = 0; i < 200; i++) input[`k${i}`] = `${i}`.padEnd(30000, "Z");
    const it1 = enqueue(l, { sessionId: "s", cwd: r2, tool: "mcp__x__y", input, actionHash: "h", rules: ["FW-SEND"], reasons: ["r"], kind: "approval", summary: "call", trustSources: [], unattended: true });
    const x = await startDashboard({ layout: l, project: r2, env: {}, doctor: () => [] });
    try {
      const t = new URL(x.url).pathname.split("/")[1] ?? "";
      expect((await call(x.port, `/${t}/queue/${it1.id}`)).body.length).toBeLessThan(500_000);
    } finally {
      await x.close();
      rmSync(r2, { recursive: true, force: true });
    }
  }, 60000);

  it("DB2: the queue list is unbounded: 400 held items render 400 rows in one page (the log, sessions, quarantine and decisions are capped; the queue and its 'review all' have no page size)", async () => {
    const r2 = mkdtempSync(join(tmpdir(), "lsfw-dashrev-q-"));
    const l = layout(join(r2, "home"));
    const first = enqueue(l, { sessionId: "s", cwd: r2, tool: "Bash", input: { command: "c" }, actionHash: "h", rules: ["FW-SEND"], reasons: ["r"], kind: "approval", summary: "push 0", trustSources: [], unattended: true });
    // enqueue() lists the queue under a lock each time (quadratic), so the other 399 are copies of its file.
    for (let i = 1; i < 400; i++) writeFileSync(join(l.queue, `q${String(i).padStart(5, "0")}.json`), JSON.stringify({ ...first, id: `q${String(i).padStart(5, "0")}`, actionHash: `h${i}`, summary: `push ${i}` }));
    const x = await startDashboard({ layout: l, project: r2, env: {}, doctor: () => [] });
    try {
      const t = new URL(x.url).pathname.split("/")[1] ?? "";
      const r = await call(x.port, `/${t}/queue`);
      expect(r.body.match(/<li class="row item">/g)?.length ?? 0).toBeLessThanOrEqual(200);
    } finally {
      await x.close();
      rmSync(r2, { recursive: true, force: true });
    }
  }, 60000);

  it("DB3: every /log, /log/<seq> request reads and JSON-parses the whole decision log (tailLog(MAX_SAFE_INTEGER), up to 21 files of 5 MB) and then verifies it again; the page cost is not bounded by the page size", () => {
    const src = readFileSync(join(__dirname, "../../src/ui/data.ts"), "utf8");
    expect(src).not.toMatch(/tailLog\(l, Number\.MAX_SAFE_INTEGER\)/);
  });

  it("the log index follows appends (cache keyed by file sizes and mtimes) and the queue's second page holds the rest", async () => {
    const r2 = mkdtempSync(join(tmpdir(), "lsfw-dashrev-cache-"));
    const l = layout(join(r2, "home"));
    appendLog(l, { type: "decision", session: "s1", tool: "Bash", verdict: "allow", rules: [], what: "first" });
    const first = enqueue(l, { sessionId: "s", cwd: r2, tool: "Bash", input: { command: "c" }, actionHash: "h", rules: ["FW-SEND"], reasons: ["r"], kind: "approval", summary: "push 0", trustSources: [], unattended: true });
    for (let i = 1; i < 130; i++) writeFileSync(join(l.queue, `q${String(i).padStart(5, "0")}.json`), JSON.stringify({ ...first, id: `q${String(i).padStart(5, "0")}`, actionHash: `h${i}`, summary: `push ${i}` }));
    const x = await startDashboard({ layout: l, project: r2, env: {}, doctor: () => [] });
    try {
      const t = new URL(x.url).pathname.split("/")[1] ?? "";
      expect((await call(x.port, `/${t}/log`)).body).toContain("first");
      appendLog(l, { type: "decision", session: "s1", tool: "Bash", verdict: "deny", rules: [], what: "second-entry" });
      expect((await call(x.port, `/${t}/log`)).body).toContain("second-entry");
      expect((await call(x.port, `/${t}/log/2`)).body).toContain("second-entry");
      expect((await call(x.port, `/${t}/queue?page=2`)).body.match(/<li class="row item">/g)?.length).toBe(30);
    } finally {
      await x.close();
      rmSync(r2, { recursive: true, force: true });
    }
  }, 60000);

  it("a long request line is 414 and a request with a huge header block is refused by Node before routing", async () => {
    expect((await call(d.port, `/${tok}/${"a".repeat(3000)}`)).status).toBe(414);
    const r = await call(d.port, `/${tok}/`, { headers: { "X-Big": "a".repeat(100_000) } }).catch(() => ({ status: 431 }));
    expect([431, 0]).toContain(r.status);
  });
});

describe("DB: lifetime", () => {
  it("stops by itself after the idle time, calls onIdle once and frees the port; requests keep it alive", async () => {
    let idled = 0;
    const x = await startDashboard({ layout: s.l, project: s.ws, env: {}, doctor: () => [], idleMs: 400, onIdle: () => void idled++ });
    const t = new URL(x.url).pathname.split("/")[1] ?? "";
    for (let i = 0; i < 4; i++) {
      await new Promise((r) => setTimeout(r, 200));
      expect((await call(x.port, `/${t}/`)).status).toBe(200);
    }
    expect(idled).toBe(0);
    await new Promise((r) => setTimeout(r, 1000));
    expect(idled).toBe(1);
    await expect(call(x.port, `/${t}/`)).rejects.toThrow();
    expect(x.server.listening).toBe(false);
  }, 20000);

  it("the documented idle time is 30 minutes and the `ui` command stops on SIGINT, SIGTERM and idle (as docs/dashboard.md says)", () => {
    expect(IDLE_MS).toBe(30 * 60 * 1000);
    const cli = readFileSync(join(__dirname, "../../src/climain.ts"), "utf8");
    expect(cli).toMatch(/process\.once\("SIGINT", onSignal\)/);
    expect(cli).toMatch(/process\.once\("SIGTERM", onSignal\)/);
  });

  it("DB4: a refused or token-less request (a wrong token, a rebound Host, a 405) restarts the idle clock, so any local process can keep the dashboard, and the address in the person's history, alive forever; only a valid request should count", async () => {
    let idled = 0;
    const x = await startDashboard({ layout: s.l, project: s.ws, env: {}, doctor: () => [], idleMs: 400, onIdle: () => void idled++ });
    try {
      for (let i = 0; i < 5; i++) {
        await new Promise((r) => setTimeout(r, 200));
        await call(x.port, "/wrong-token/").catch(() => undefined);
      }
      expect(idled).toBe(1);
    } finally {
      await x.close();
    }
  }, 20000);

  it("DB5: nothing ties the dashboard to the terminal that started it: `ui` has no parent-death watch (no `ppid` poll, stdin end or SIGHUP handler), so if the shell is killed with SIGKILL the server and its address live on to the 30-minute idle limit, and a detached copy can be started by a person's script", () => {
    const cli = readFileSync(join(__dirname, "../../src/climain.ts"), "utf8");
    const ui = cli.slice(cli.indexOf("async ui(p, l)"), cli.indexOf("async run(p, l)"));
    expect(ui).toMatch(/ppid|SIGHUP|stdin\.on\("(?:end|close)"/);
  });
});

// --- the page at 375 px and 1440 px, in headless Chromium (skipped when none is installed) -------------

function findChrome(): string | null {
  const env = process.env.CHROME_HEADLESS;
  if (env !== undefined && existsSync(env)) return env;
  const home = userInfo().homedir; // not $HOME: the suite moves it into a temporary directory
  const base = join(home, "Library/Caches/ms-playwright");
  const linux = join(home, ".cache/ms-playwright");
  for (const b of [base, linux]) {
    if (!existsSync(b)) continue;
    for (const n of readdirSync(b).filter((x) => x.startsWith("chromium_headless_shell")).sort().reverse()) {
      for (const sub of readdirSync(join(b, n))) {
        const p = join(b, n, sub, "chrome-headless-shell");
        if (existsSync(p)) return p;
      }
    }
  }
  return null;
}

const CHROME = findChrome();

describe.skipIf(CHROME === null)("DB: layout in a real browser", () => {
  let proc: ChildProcess;
  let ws: WebSocket;
  let id = 0;
  const pending = new Map<number, (v: { result?: unknown; error?: { message: string } }) => void>();
  const events: { method: string; params: Record<string, unknown>; sessionId?: string }[] = [];
  let r3: string;
  let h: Seed;
  let x: Dashboard;
  let t: string;
  let profile: string;

  const send = (method: string, params: Record<string, unknown> = {}, sessionId?: string): Promise<Record<string, any>> =>
    new Promise((resolveSend, reject) => {
      const n = ++id;
      pending.set(n, (v) => (v.error !== undefined ? reject(new Error(`${method}: ${v.error.message}`)) : resolveSend((v.result ?? {}) as Record<string, any>)));
      ws.send(JSON.stringify({ id: n, method, params, ...(sessionId !== undefined ? { sessionId } : {}) }));
    });

  beforeAll(async () => {
    r3 = mkdtempSync(join(tmpdir(), "lsfw-dashrev-ui-"));
    profile = mkdtempSync(join(tmpdir(), "lsfw-dashrev-chrome-"));
    h = seed(r3, true);
    // A queue item whose proposal has a very long line and many lines, to stress the diff.
    x = await startDashboard({ layout: h.l, project: h.ws, env: {}, doctor: () => FAKE_CHECKS });
    t = new URL(x.url).pathname.split("/")[1] ?? "";
    proc = spawn(CHROME as string, ["--no-sandbox", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "--disable-gpu", "about:blank"], { stdio: ["ignore", "ignore", "pipe"] });
    const url = await new Promise<string>((res, rej) => {
      let buf = "";
      proc.stderr?.on("data", (c: Buffer) => {
        buf += c.toString();
        const m = /DevTools listening on (ws:\/\/\S+)/.exec(buf);
        if (m !== null) res(m[1] as string);
      });
      setTimeout(() => rej(new Error("no DevTools endpoint")), 15000);
    });
    ws = new WebSocket(url);
    await new Promise<void>((res, rej) => {
      ws.onopen = (): void => res();
      ws.onerror = (): void => rej(new Error("websocket"));
    });
    ws.onmessage = (m): void => {
      const msg = JSON.parse(String(m.data)) as { id?: number; result?: unknown; error?: { message: string }; method?: string; params?: Record<string, unknown>; sessionId?: string };
      if (msg.id !== undefined) pending.get(msg.id)?.(msg);
      else if (msg.method !== undefined) events.push({ method: msg.method, params: msg.params ?? {}, ...(msg.sessionId !== undefined ? { sessionId: msg.sessionId } : {}) });
    };
  }, 30000);
  afterAll(async () => {
    try {
      ws?.close();
    } catch {
      // closing a socket that never opened
    }
    proc?.kill();
    await x?.close();
    rmSync(r3, { recursive: true, force: true });
    rmSync(profile, { recursive: true, force: true });
  });

  async function measure(path: string, width: number, height: number, mobile: boolean): Promise<{ scrollW: number; innerW: number; bodyW: number; csp: string[]; scripts: number; injected: number; x: number | null; wide: string[] }> {
    const { targetId } = await send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
    const sid = sessionId as string;
    await send("Page.enable", {}, sid);
    await send("Log.enable", {}, sid);
    await send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile }, sid);
    const start = events.length;
    await send("Page.navigate", { url: `http://127.0.0.1:${x.port}/${t}/${path}` }, sid);
    for (let i = 0; i < 100 && !events.slice(start).some((e) => e.method === "Page.loadEventFired" && e.sessionId === sid); i++) await new Promise((r) => setTimeout(r, 100));
    await new Promise((r) => setTimeout(r, 300));
    const ev = await send("Runtime.evaluate", { expression: `JSON.stringify({ scrollW: document.documentElement.scrollWidth, innerW: window.innerWidth, bodyW: document.body.scrollWidth, scripts: document.querySelectorAll('script').length, injected: document.querySelectorAll('img,iframe,svg,object,embed,form,input,style,[onerror],[onload]').length, x: window.__x === undefined ? null : window.__x, wide: (function(){ var o=[]; document.querySelectorAll('body *').forEach(function(e){ var r=e.getBoundingClientRect(); if (r.right > window.innerWidth + 1 && o.length < 3) o.push(e.tagName + '.' + e.className + ' right=' + Math.round(r.right) + ' ' + (e.textContent||'').slice(0,40)); }); return o; })() })`, returnByValue: true }, sid);
    const csp = events
      .slice(start)
      .filter((e) => e.sessionId === sid && e.method === "Log.entryAdded")
      .map((e) => String((e.params.entry as { text?: string }).text ?? ""))
      .filter((m) => /Content Security Policy|Refused to/i.test(m));
    await send("Target.closeTarget", { targetId });
    return { ...JSON.parse(String((ev.result as { value: string }).value)), csp };
  }

  const SCREENS = (): string[] => ["", "protection", "queue", `queue/${h.approvalId}`, `queue/${h.proposalId}`, "log", `log/${h.hostileSeq}`, "integrity", "vault", "guards", "sessions/sess-unattended-1"];

  it("DB8: /integrity scrolls the whole page sideways on a 1440 px desktop when a pending pin change names a long tool (150 characters here): the row's tool tag and detail are not truncated like the rest of the row (it holds at 375 px)", async () => {
    const m = await measure("integrity", 1440, 900, false);
    expect(m.scrollW, m.wide.join(" | ")).toBeLessThanOrEqual(m.innerW + 1);
  }, 60000);

  it("no screen scrolls horizontally at 375 px (phone) or 1440 px (desktop), with hostile 400-character unbreakable text in every field", async () => {
    const bad: string[] = [];
    for (const [w, hgt, mobile] of [[375, 812, true], [1440, 900, false]] as const) {
      for (const p of SCREENS()) {
        const m = await measure(p, w, hgt, mobile);
        if (m.scrollW > m.innerW + 1 || m.bodyW > m.innerW + 1) bad.push(`${w}px /${p || "(overview)"}: scrollWidth ${m.scrollW} > ${m.innerW}; wide: ${m.wide.join(' | ')}`);
      }
    }
    expect(bad).toEqual([]);
  }, 120000);

  it("in a real browser the page runs exactly one script, injects no element or handler from agent text, and the CSP blocks nothing the page itself needs", async () => {
    for (const p of SCREENS()) {
      const m = await measure(p, 1440, 900, false);
      expect(m.scripts, p).toBe(1);
      expect(m.injected, p).toBe(0);
      expect(m.x, p).toBeNull();
      expect(m.csp, p).toEqual([]);
    }
  }, 120000);
});
