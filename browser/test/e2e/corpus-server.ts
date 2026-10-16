/**
 * A static server for test/corpus/ on 127.0.0.1 only, on a random port. The
 * browser reaches it as shop.test, mail.test, attacker.test and accounts.test
 * through --host-resolver-rules, so pages can pose as different sites without
 * DNS or network. Every request is recorded (host, method, path, body), so a
 * test can assert that an action did or did not reach the "server".
 *
 * HTML files may say __PORT__; it is replaced with the server's port so pages
 * can link and frame across the .test hosts.
 */
import { createServer, type IncomingMessage, type Server } from "node:http";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const CORPUS_DIR = resolve(fileURLToPath(new URL("../corpus/", import.meta.url)));
/**
 * The real-page corpus: saved copies of third-party public pages, which are not in this repository (they are other
 * people's copyrighted pages). Rebuild it with `npm run capture:corpus`, or point LAUNCHSAFE_BROWSER_CORPUS_DIR at an
 * existing copy. Served under /real/. Tests that need it skip, with that reason, when the directory has no manifest.
 */
export const REAL_CORPUS_DIR = resolve(process.env.LAUNCHSAFE_BROWSER_CORPUS_DIR ?? join(homedir(), ".launchsafe", "browser-corpus", "real"));
export const TEST_HOSTS = ["shop.test", "mail.test", "attacker.test", "accounts.test"] as const;
export type TestHost = (typeof TEST_HOSTS)[number];

export interface RecordedRequest {
  host: string;
  method: string;
  path: string;
  body: string;
  at: number;
}

export interface CorpusServer {
  port: number;
  /** http://<host>:<port><path> */
  url(host: TestHost, path?: string): string;
  requests: RecordedRequest[];
  close(): Promise<void>;
}

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".png": "image/png",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".exe": "application/x-msdownload",
  ".pdf": "application/pdf",
};

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((ok) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size <= 1024 * 1024) chunks.push(c);
    });
    req.on("end", () => ok(Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => ok(""));
  });
}

export async function startCorpusServer(): Promise<CorpusServer> {
  const requests: RecordedRequest[] = [];
  let port = 0;
  const server: Server = createServer(async (req, res) => {
    const host = (req.headers.host ?? "").replace(/:\d+$/, "").toLowerCase();
    const url = new URL(req.url ?? "/", "http://corpus.invalid");
    requests.push({ host, method: req.method ?? "GET", path: url.pathname + url.search, body: await readBody(req), at: Date.now() });
    // Only the mapped test hosts and loopback are served.
    if (!(TEST_HOSTS as readonly string[]).includes(host) && host !== "127.0.0.1") {
      res.writeHead(421).end();
      return;
    }
    let path = decodeURIComponent(url.pathname);
    if (path.endsWith("/")) path += "index.html";
    const real = path.startsWith("/real/");
    const root = real ? REAL_CORPUS_DIR : CORPUS_DIR;
    const file = normalize(join(root, real ? path.slice("/real/".length) : path));
    if (!file.startsWith(root + sep)) {
      res.writeHead(403).end();
      return;
    }
    try {
      let data: Buffer | string = await readFile(file);
      const type = TYPES[extname(file)] ?? "application/octet-stream";
      if (type.startsWith("text/html")) data = data.toString("utf8").replaceAll("__PORT__", String(port));
      res.writeHead(200, { "content-type": type, "cache-control": "no-store" }).end(data);
    } catch {
      res.writeHead(404, { "content-type": "text/plain" }).end("not found");
    }
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("corpus server has no port");
  port = addr.port;
  return {
    port,
    url: (host, path = "/") => `http://${host}:${port}${path}`,
    requests,
    close: () => new Promise<void>((ok) => server.close(() => ok())),
  };
}
