/**
 * `launchsafe-firewall ui`: the read-only local dashboard (docs/dashboard.md).
 *
 * The server listens on 127.0.0.1 only, on a port the system picks, and answers GET and HEAD only.
 * Every request must carry the per-launch token as the first path segment (compared in constant time;
 * anything else is the same 404 as an unknown path), a Host of exactly 127.0.0.1:<port> (DNS
 * rebinding), no foreign Origin and no cross-site or same-site fetch metadata. Every response carries a
 * strict CSP and no CORS header. No route writes the queue, session state, pins, decoys, policy,
 * settings or the log: approving stays in the person's terminal, behind the approval passphrase.
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { doctor as runDoctor, type Check } from "../runtime/doctor.js";
import { explainId } from "../runtime/explain.js";
import type { Layout } from "../runtime/layout.js";
import { listQueue } from "../runtime/store.js";
import { CSS, JS } from "./assets.js";
import { guardsView, integrityView, itemView, logEntry, logVerify, logView, overview, queueView, sessionView, vaultMask, vaultSummary, type Result } from "./data.js";
import { ONEST_WOFF2_BASE64 } from "./font.js";
import { guardsPage, integrityPage, itemPage, logEntryPage, logPage, overviewPage, plainPage, protectionPage, queuePage, sessionPage, vaultPage, type PageContext } from "./pages.js";
import { withVault } from "./html.js";
import type { PathContext } from "./paths.js";

export const CSP = "default-src 'none'; style-src 'self'; script-src 'self'; font-src 'self'; img-src 'self'; connect-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": CSP,
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
  "X-Frame-Options": "DENY",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), clipboard-read=(), usb=(), serial=(), payment=()",
};

/** How long the server waits without a request before it stops by itself. */
export const IDLE_MS = 30 * 60 * 1000;
/** How long the one-time launch address stays valid. */
export const LAUNCH_MS = 60 * 1000;
/** How long doctor's checks are reused (they start agent CLIs to read their versions). */
export const DOCTOR_CACHE_MS = 60 * 1000;

export interface DashboardOptions {
  layout: Layout;
  /** The project doctor checks (default: the current directory). */
  project?: string;
  env?: NodeJS.ProcessEnv;
  /** The home directory paths are shown relative to (default: os.homedir()). */
  home?: string;
  /** Tests inject a fixed doctor; by default the real one runs, cached for a minute. */
  doctor?: () => Check[];
  now?: () => Date;
  idleMs?: number;
  /** Called when the server stops because it was idle. */
  onIdle?: () => void;
  /** Where a page's failure is reported (the terminal that started `ui`; default: standard error). Never the browser. */
  log?: (message: string) => void;
}

export interface Dashboard {
  /** The address with the token: printed once to the person's terminal, nowhere else. */
  url: string;
  /** A one-time address that redirects to `url` (what the browser is opened with). */
  launchUrl: string;
  port: number;
  server: Server;
  close: () => Promise<void>;
}

function token(bytes: number): string {
  return randomBytes(bytes).toString("base64url");
}

function sameToken(given: string, expected: string): boolean {
  const a = Buffer.from(given, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function send(res: ServerResponse, head: boolean, status: number, type: string, body: string | Buffer, extra: Record<string, string> = {}): void {
  const buf = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  res.writeHead(status, { ...SECURITY_HEADERS, "Content-Type": type, "Content-Length": String(buf.length), ...extra });
  res.end(head ? undefined : buf);
}

const HTML = "text/html; charset=utf-8";
const TEXT = "text/plain; charset=utf-8";

/** Why a request is refused before routing, or null when it may proceed. Exported for tests. */
export function refuse(req: { method?: string | undefined; headers: Record<string, string | string[] | undefined> }, port: number): { status: number; message: string } | null {
  const host = req.headers.host;
  if (host !== `127.0.0.1:${port}`) return { status: 421, message: "This dashboard answers only at the address it printed (http://127.0.0.1)." };
  const origin = req.headers.origin;
  if (origin !== undefined && origin !== `http://127.0.0.1:${port}`) return { status: 403, message: "Requests from other origins are refused." };
  const site = req.headers["sec-fetch-site"];
  if (site !== undefined && site !== "none" && site !== "same-origin") return { status: 403, message: "Requests from other sites are refused." };
  if (req.method !== "GET" && req.method !== "HEAD") return { status: 405, message: "The dashboard is read-only: it answers GET and HEAD only. Approvals happen in your terminal." };
  return null;
}

export async function startDashboard(o: DashboardOptions): Promise<Dashboard> {
  const l = o.layout;
  const project = o.project ?? process.cwd();
  const env = o.env ?? process.env;
  const now = o.now ?? ((): Date => new Date());
  const secret = token(32);
  const both = (p: string): string[] => {
    try {
      return [...new Set([p, realpathSync(p)])];
    } catch {
      return [p];
    }
  };
  const paths: PathContext = { projects: both(project), homes: both(o.home ?? homedir()) };
  let launch: { code: string; expires: number } | null = { code: token(16), expires: Date.now() + LAUNCH_MS };
  const font = Buffer.from(ONEST_WOFF2_BASE64, "base64");

  let doctorCache: { at: Date; value: Result<Check[]> } | null = null;
  const checks = (): { value: Result<Check[]>; at: Date | null } => {
    const t = now();
    if (doctorCache === null || t.getTime() - doctorCache.at.getTime() > DOCTOR_CACHE_MS) {
      let value: Result<Check[]>;
      try {
        value = { ok: true, value: o.doctor !== undefined ? o.doctor() : runDoctor(l, project) };
      } catch (e) {
        value = { ok: false, error: (e as Error).message };
      }
      doctorCache = { at: t, value };
    }
    return { value: doctorCache.value, at: doctorCache.at };
  };

  let port = 0;
  let idle: NodeJS.Timeout | null = null;
  const idleMs = o.idleMs ?? IDLE_MS;

  /** Why a page failed goes to the person's terminal only; the browser gets a generic message. */
  const report = o.log ?? ((m: string): void => void process.stderr.write(`${m}\n`));
  const failPage = (res: ServerResponse, head: boolean, e: unknown): void => {
    try {
      report(`launchsafe-firewall ui: a page could not be rendered: ${(e instanceof Error ? e.message : String(e)).replace(/[^\x20-\x7e]/g, "?")}`);
    } catch {
      // Reporting is best effort; the response still goes out.
    }
    if (!res.headersSent) send(res, head, 500, TEXT, "The dashboard could not render this page. The reason is printed in the terminal that started it.\n");
    else res.destroy();
  };

  const handle = (req: IncomingMessage, res: ServerResponse): void => {
    const head = req.method === "HEAD";
    const raw = req.url ?? "/";
    if (raw.length > 2048) {
      send(res, head, 414, TEXT, "Address too long.\n");
      return;
    }
    // The address is parsed before anything else looks at the request, and never throws out of here. A path
    // is always read as a path on this server (`//queue` is the path "//queue", a 404 like any wrong token,
    // never the host "queue"); anything else (an absolute-form address for another origin, one that does
    // not parse) is a 400.
    let url: URL;
    try {
      url = new URL(raw.startsWith("/") ? `http://127.0.0.1:${port}${raw}` : raw);
      if (url.origin !== `http://127.0.0.1:${port}`) throw new Error("another origin");
    } catch {
      send(res, head, 400, TEXT, "Bad request.\n");
      return;
    }
    const no = refuse(req, port);
    if (no !== null) {
      send(res, head, no.status, TEXT, `${no.message}\n`, no.status === 405 ? { Allow: "GET, HEAD" } : {});
      return;
    }
    const parts = url.pathname.split("/").slice(1);
    // The one-time launch address: valid once, for a minute, then gone.
    if (parts[0] === "open" && parts.length === 2) {
      const code = parts[1] ?? "";
      const ok = launch !== null && Date.now() <= launch.expires && sameToken(code, launch.code);
      if (launch !== null && sameToken(code, launch.code)) launch = null;
      if (ok) idle?.refresh();
      if (ok) send(res, head, 303, TEXT, "See the dashboard.\n", { Location: `/${secret}/` });
      else send(res, head, 410, HTML, plainPage("This launch address was already used", "Each launch address works once. If you did not just open it yourself, stop the dashboard (Ctrl-C in its terminal) and start it again. Otherwise use the full address printed in your terminal."));
      return;
    }
    if (!sameToken(parts[0] ?? "", secret)) {
      send(res, head, 404, TEXT, "Not found.\n");
      return;
    }
    // Only a request that passed the Host, Origin, method and token checks keeps the dashboard alive (DB4):
    // a wrong token, a rebound Host or a 405 from another local process cannot hold it open.
    idle?.refresh();
    const rest = parts.slice(1);
    const route = rest.join("/");
    const str = (k: string): string | undefined => url.searchParams.get(k) ?? undefined;
    try {
      let held: number | null = null;
      try {
        held = listQueue(l).items.filter((i) => i.status === "pending").length;
      } catch {
        held = null;
      }
      // A stored value never reaches a page (html.ts): every page renders with the vault's fingerprints. When
      // they cannot be read, every page says so (masking unavailable) instead of looking as safe as usual.
      const mask = vaultMask(l, env);
      const c: PageContext = { base: `/${secret}/`, now: now(), held, paths, ...(mask.unavailable !== null ? { maskingUnavailable: mask.unavailable } : {}) };
      const page = (body: () => string): void => send(res, head, 200, HTML, withVault(mask.view, body));
      if (route === "") return page(() => overviewPage(c, overview(l, project, env, c.now, checks())));
      if (route === "assets/app.css") return send(res, head, 200, "text/css; charset=utf-8", CSS);
      if (route === "assets/app.js") return send(res, head, 200, "text/javascript; charset=utf-8", JS);
      if (route === "assets/onest.woff2") return send(res, head, 200, "font/woff2", font);
      if (route === "protection") return page(() => protectionPage(c, overview(l, project, env, c.now, checks())));
      if (rest[0] === "sessions" && rest.length === 2 && /^[A-Za-z0-9_-]{1,100}$/.test(rest[1] ?? "")) return page(() => sessionPage(c, sessionView(l, rest[1] as string, c.now), rest[1] as string));
      if (route === "queue") {
        const pg = str("page");
        return page(() => queuePage(c, queueView(l, pg !== undefined && /^\d{1,6}$/.test(pg) ? Number(pg) : 1)));
      }
      if (rest[0] === "queue" && rest.length === 2 && /^[a-z0-9]{4,32}$/.test(rest[1] ?? "")) {
        // The item's own cwd is agent-written: it is neither a root paths are shortened against nor a place
        // the dashboard reads from. Only the project and the home directory are.
        const v = itemView(l, rest[1] as string, { roots: [...paths.projects, ...paths.homes], homes: paths.homes });
        return page(() => itemPage(c, v, rest[1] as string));
      }
      if (route === "log") {
        const before = str("before");
        const type = str("type");
        const verdict = str("verdict");
        const f = {
          ...(before !== undefined && /^\d{1,15}$/.test(before) ? { before: Number(before) } : {}),
          ...(type !== undefined && /^[a-z_]{1,40}$/.test(type) ? { type } : {}),
          ...(verdict !== undefined && /^(?:allow|ask|queue|deny)$/.test(verdict) ? { verdict } : {}),
        };
        return page(() => logPage(c, logView(l, f), logVerify(l), f));
      }
      if (rest[0] === "log" && rest.length === 2 && /^\d{1,15}$/.test(rest[1] ?? "")) {
        const seq = Number(rest[1]);
        const entry = logEntry(l, seq);
        let explained: string | null = null;
        try {
          explained = entry.ok && entry.value !== null ? explainId(l, String(seq), { json: false, width: 100, entry: entry.value }) : null;
        } catch {
          explained = null;
        }
        return page(() => logEntryPage(c, entry, explained, seq));
      }
      if (route === "integrity") return page(() => integrityPage(c, integrityView(l, c.now)));
      if (route === "vault") return page(() => vaultPage(c, vaultSummary(l, env)));
      if (route === "guards") return page(() => guardsPage(c, guardsView(l), checks().value));
      send(res, head, 404, TEXT, "Not found.\n");
    } catch (e) {
      failPage(res, head, e);
    }
  };

  const server = createServer((req, res) => {
    try {
      handle(req, res);
    } catch (e) {
      failPage(res, req.method === "HEAD", e);
    }
  });
  // No keep-alive surprises after close: requests are small and local.
  server.keepAliveTimeout = 1000;
  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0, exclusive: true }, () => resolveListen());
  });
  port = (server.address() as AddressInfo).port;
  const close = (): Promise<void> =>
    new Promise((r) => {
      if (idle !== null) clearTimeout(idle);
      server.closeAllConnections();
      server.close(() => r());
    });
  idle = setTimeout(() => {
    void close().then(() => o.onIdle?.());
  }, idleMs);
  idle.unref();
  return { url: `http://127.0.0.1:${port}/${secret}/`, launchUrl: `http://127.0.0.1:${port}/open/${launch?.code ?? ""}`, port, server, close };
}
