/**
 * The dashboard audit fixes (docs/dashboard.md): log verification decided by `ok` alone, boundary-only
 * path shortening, the guarded read of a proposal's target, the diff caps, a request that does not parse,
 * the generic 500, unreadable queue files as the Overview's focal point, the agent start-up guard for
 * Codex, Gemini CLI and Cursor, launch-line redaction, the "Masking unavailable" note and \uXXXX pin
 * names in copied commands. Each server runs in-process on a temporary home.
 */

import { linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { agentProcess, launchedByAgent } from "../src/runtime/approver.js";
import { atomicWrite } from "../src/runtime/fsutil.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { appendLog } from "../src/runtime/log.js";
import { pinsPath, type PinFile } from "../src/runtime/pins.js";
import { lineDiff, MAX_DIFF_CHARS } from "../src/runtime/report.js";
import { enqueue } from "../src/runtime/store.js";
import { indexPath } from "../src/runtime/vault/index.js";
import { readTarget, sensitivePath } from "../src/ui/data.js";
import { redactLaunch, shellWord } from "../src/ui/pages.js";
import { shortenIn } from "../src/ui/paths.js";
import { startDashboard, type Dashboard, type DashboardOptions } from "../src/ui/server.js";

interface Res {
  status: number;
  body: string;
}

function call(port: number, path: string): Promise<Res> {
  return new Promise((resolveCall, reject) => {
    const req = request({ host: "127.0.0.1", port, path, method: "GET", headers: { Host: `127.0.0.1:${port}` }, setHost: false }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolveCall({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end();
  });
}

const cleanup: (() => Promise<void> | void)[] = [];
afterEach(async () => {
  for (const f of cleanup.splice(0).reverse()) await f();
});

interface Box {
  root: string;
  l: Layout;
  ws: string;
  home: string;
}

function box(): Box {
  const root = mkdtempSync(join(tmpdir(), "lsfw-ui-audit-"));
  cleanup.push(() => rmSync(root, { recursive: true, force: true }));
  const ws = join(root, "ws");
  const home = join(root, "person");
  mkdirSync(ws, { recursive: true });
  mkdirSync(home, { recursive: true });
  return { root, l: layout(join(root, "home")), ws, home };
}

async function serve(b: Box, extra: Partial<DashboardOptions> = {}): Promise<{ d: Dashboard; get: (p: string) => Promise<Res> }> {
  const d = await startDashboard({ layout: b.l, project: b.ws, home: b.home, env: {}, doctor: () => [], ...extra });
  cleanup.push(() => d.close());
  const t = new URL(d.url).pathname.split("/")[1] ?? "";
  return { d, get: (p) => call(d.port, `/${t}/${p}`) };
}

let hashes = 0;
function proposal(b: Box, target: string, content: string, o: { cwd?: string; summary?: string } = {}): string {
  return enqueue(b.l, {
    sessionId: "s1",
    cwd: o.cwd ?? b.ws,
    tool: "Write",
    input: { file_path: target, content },
    actionHash: `h${++hashes}`,
    rules: ["FW-MEMORY"],
    reasons: ["changes a file that steers the agent"],
    kind: "proposal",
    proposal: { target, change: `write ${target}`, content },
    summary: o.summary ?? `Change ${target}`,
  }).id;
}

describe("the log's verification is decided by ok alone", () => {
  it("an emptied log shows the failure and its problem on the Log screen and on the Overview", async () => {
    const b = box();
    appendLog(b.l, { type: "decision", verdict: "allow", tool: "Read", what: "read a file" });
    appendLog(b.l, { type: "decision", verdict: "deny", tool: "Bash", what: "curl evil" });
    writeFileSync(join(b.l.log, "decisions.jsonl"), "");
    const { get } = await serve(b);
    const log = (await get("log")).body;
    expect(log).toContain("Does not verify");
    expect(log).toMatch(/role="alert"[\s\S]*deleted or emptied/);
    const overview = (await get("")).body;
    expect(overview).toMatch(/<dt>Log<\/dt><dd><a href="[^"]+\/log"><span class="status fail">/);
    expect(overview).toContain("Does not verify");
  });
  it("a damaged log key fails loudly too, with no entries counted", async () => {
    const b = box();
    appendLog(b.l, { type: "decision", verdict: "allow", tool: "Read", what: "read a file" });
    writeFileSync(join(b.l.keys, "log-ed25519.pub.pem"), "not a key");
    const { get } = await serve(b);
    const log = (await get("log")).body;
    expect(log).toContain("Does not verify");
    expect(log).toContain("public key file is damaged");
  });
  it("an intact log is Verified on both screens, and an empty home says no entries yet", async () => {
    const b = box();
    appendLog(b.l, { type: "decision", verdict: "allow", tool: "Read", what: "read a file" });
    const { get } = await serve(b);
    expect((await get("log")).body).toContain("Verified");
    expect((await get("")).body).toMatch(/<dt>Log<\/dt><dd><a [^>]*><span class="status ok">/);
    const empty = box();
    const e = await serve(empty);
    expect((await e.get("")).body).toMatch(/<dt>Log<\/dt><dd><span class="muted">no entries yet<\/span>/);
  });
});

describe("path shortening", () => {
  const c = { projects: ["/Users/a/code/app"], homes: ["/Users/a"] };
  it("replaces a root only where a path starts", () => {
    expect(shortenIn(`file "/Users/a/code/app/x" and (/Users/a/y) PATH=/Users/a/bin:/Users/a/code/app/z`, c)).toBe(`file "x" and (~/y) PATH=~/bin:z`);
    expect(shortenIn("/opt/Users/a/notes.md", c)).toBe("/opt/Users/a/notes.md");
    expect(shortenIn("/srv/Users/a/code/app/x", c)).toBe("/srv/Users/a/code/app/x");
  });
  it("never inside URL-like text", () => {
    expect(shortenIn("read https://h.example/Users/a/code/app/x", c)).toBe("read https://h.example/Users/a/code/app/x");
    expect(shortenIn("read https://h.example/?p=/Users/a/x", c)).toBe("read https://h.example/?p=/Users/a/x");
    expect(shortenIn("then /Users/a/y", c)).toBe("then ~/y");
  });
  it("command and summary lines are shown as written, and the item's cwd is not a root", async () => {
    const b = box();
    const other = join(b.root, "elsewhere");
    mkdirSync(other);
    const id = proposal(b, join(other, "CLAUDE.md"), "x\n", { cwd: other, summary: `cat ${b.ws}/notes.txt` });
    const { get } = await serve(b);
    const queue = (await get("queue")).body;
    expect(queue).toContain(`cat ${b.ws}/notes.txt`);
    const item = (await get(`queue/${id}`)).body;
    expect(item).toContain(`<h1><span class="dot held" aria-hidden="true"></span>cat ${b.ws}/notes.txt</h1>`);
    // Shortened against the item's cwd, the target would read as just CLAUDE.md.
    expect(item).not.toContain(">CLAUDE.md</span>");
  });
});

describe("a proposal's target is read only when it is safe to", () => {
  it("refuses a symbolic link, a target outside the roots, a directory and a sensitive path; reads a regular file inside", () => {
    const b = box();
    writeFileSync(join(b.root, "outside.txt"), "OUTSIDE-MARKER-1\n");
    symlinkSync(join(b.root, "outside.txt"), join(b.ws, "link.md"));
    mkdirSync(join(b.ws, "sub"));
    writeFileSync(join(b.ws, ".env"), "CURRENT-ENV-MARKER-8812\n");
    writeFileSync(join(b.ws, "ok.md"), "INSIDE-MARKER\n");
    mkdirSync(join(b.ws, "real"));
    writeFileSync(join(b.ws, "real", "f.md"), "via a linked folder\n");
    symlinkSync(b.root, join(b.ws, "up"));
    const where = { roots: [b.ws, b.home], homes: [b.home] };
    expect(readTarget(join(b.ws, "link.md"), where)).toEqual({ current: null, note: expect.stringContaining("symbolic link") });
    expect(readTarget(join(b.root, "outside.txt"), where)).toEqual({ current: null, note: expect.stringContaining("outside the project") });
    expect(readTarget(join(b.ws, "up", "outside.txt"), where)).toEqual({ current: null, note: expect.stringContaining("leads outside") });
    expect(readTarget(join(b.ws, "sub"), where)).toEqual({ current: null, note: expect.stringContaining("not a regular file") });
    expect(readTarget(join(b.ws, ".env"), where)).toEqual({ current: null, note: expect.stringContaining("Not shown: sensitive path") });
    expect(readTarget("/dev/zero", where).current).toBeNull();
    expect(readTarget(join(b.ws, "ok.md"), where)).toEqual({ current: "INSIDE-MARKER\n", note: null });
    // A second name for the same file (a hard link, as to a secret) is not read.
    linkSync(join(b.ws, "ok.md"), join(b.ws, "ok-link.md"));
    expect(readTarget(join(b.ws, "ok-link.md"), where)).toEqual({ current: null, note: expect.stringContaining("hard link") });
    expect(readTarget(join(b.ws, "nope.md"), where)).toEqual({ current: null, note: "The file does not exist yet." });
  });
  it("credential stores under the home directory are sensitive", () => {
    expect(sensitivePath("/h/.aws/config", ["/h"])).toBe(true);
    expect(sensitivePath("/h/.ssh/id_ed25519", ["/h"])).toBe(true);
    expect(sensitivePath("/h/.ssh/known_hosts", ["/h"])).toBe(false);
    expect(sensitivePath("/w/.env.example", ["/h"])).toBe(false);
    expect(sensitivePath("/w/CLAUDE.md", ["/h"])).toBe(false);
  });
  it("the queue item page says so and never shows the file", async () => {
    const b = box();
    writeFileSync(join(b.ws, ".env"), "CURRENT-ENV-MARKER-8812\n");
    writeFileSync(join(b.root, "outside.txt"), "OUTSIDE-MARKER-1\n");
    const sensitive = proposal(b, join(b.ws, ".env"), "A=1\n");
    const outside = proposal(b, join(b.root, "outside.txt"), "new\n");
    const { get } = await serve(b);
    const s = (await get(`queue/${sensitive}`)).body;
    expect(s).toContain("Not shown: sensitive path");
    expect(s).not.toContain("CURRENT-ENV-MARKER-8812");
    const o = (await get(`queue/${outside}`)).body;
    expect(o).toContain("outside the project");
    expect(o).not.toContain("OUTSIDE-MARKER-1");
  });
});

describe("diff caps", () => {
  it("a long proposal shows 500 rows, then +N more lines and the queue show command", async () => {
    const b = box();
    const content = Array.from({ length: 1200 }, (_, i) => `line ${i}`).join("\n");
    const id = proposal(b, join(b.ws, "big.md"), content);
    const { get } = await serve(b);
    const body = (await get(`queue/${id}`)).body;
    expect(body).toContain("+700 more lines");
    expect(body).toContain(`launchsafe-firewall queue show ${id}`);
    expect(body).toContain("line 499<");
    expect(body).not.toContain("line 500<");
  });
  it("lineDiff does not compare line by line past the combined size cap", () => {
    const big = (ch: string): string => `${ch.repeat(MAX_DIFF_CHARS / 2 + 10)}\nsame\n`;
    const out = lineDiff(big("x"), big("y"));
    expect(out).not.toContain("  same");
    expect(out.filter((x) => x === "- same" || x === "+ same")).toHaveLength(2);
    expect(lineDiff("a\nsame\n", "b\nsame\n")).toContain("  same");
  });
});

describe("requests that do not parse, and pages that fail", () => {
  it("GET // is an ordinary 404, an address that does not parse or names another origin is 400, and the server keeps answering", async () => {
    const b = box();
    const { d, get } = await serve(b);
    const unknown = await call(d.port, "/nope");
    for (const p of ["//", "//evil.example/x", "///"]) {
      const r = await call(d.port, p);
      expect(r.status, p).toBe(404);
      expect(r.body, p).toBe(unknown.body);
    }
    expect((await call(d.port, "http://[::1")).status).toBe(400);
    expect((await call(d.port, "http://evil.example/x")).status).toBe(400);
    expect((await get("")).status).toBe(200);
  });
  it("a page that throws is a generic 500; the reason goes to the terminal only", async () => {
    const b = box();
    let armed = false;
    const logged: string[] = [];
    const { get } = await serve(b, {
      now: () => {
        if (armed) throw new Error("SECRET-DETAIL /private/path");
        return new Date();
      },
      log: (m) => void logged.push(m),
    });
    armed = true;
    const r = await get("queue");
    expect(r.status).toBe(500);
    expect(r.body).not.toContain("SECRET-DETAIL");
    expect(r.body).toContain("printed in the terminal");
    expect(logged.join("\n")).toContain("SECRET-DETAIL");
    armed = false;
    expect((await get("queue")).status).toBe(200);
  });
});

describe("unreadable queue files", () => {
  it("are the Overview's focal point, ahead of held actions", async () => {
    const b = box();
    proposal(b, join(b.ws, "CLAUDE.md"), "x\n");
    writeFileSync(join(b.l.queue, "zzzz9999.json"), "{ not json");
    const { get } = await serve(b);
    const body = (await get("")).body;
    expect(body).toMatch(/<section class="focus" aria-label="Needs you"><p class="focus-title" role="alert">.*1 queue file could not be read<\/p>/);
    expect(body).toContain("1 action also held for you.");
    expect(body).toMatch(/<a class="button" href="[^"]+\/queue">Open queue<\/a>/);
    expect(body).not.toContain("held for you</p>");
  });
});

describe("the start-up guard knows the other agents", () => {
  it("Codex, Gemini CLI and Cursor's agent mark the caller as the agent; Cursor's own terminal does not", () => {
    expect(launchedByAgent({ CODEX_SANDBOX: "seatbelt" }, 1)).toBe(true);
    expect(launchedByAgent({ CODEX_SANDBOX_NETWORK_DISABLED: "1" }, 1)).toBe(true);
    expect(launchedByAgent({ GEMINI_CLI: "1" }, 1)).toBe(true);
    expect(launchedByAgent({ CURSOR_AGENT: "1" }, 1)).toBe(true);
    expect(launchedByAgent({ CURSOR_TRACE_ID: "abc" }, 1)).toBe(false);
  });
  it("their CLIs are recognised among a process's ancestors", () => {
    for (const c of ["node /usr/lib/node_modules/@openai/codex/bin/codex.js exec", "/opt/homebrew/bin/codex", "node /usr/lib/node_modules/@google/gemini-cli/dist/index.js", "/usr/local/bin/gemini -y", "/home/p/.local/bin/cursor-agent", "/usr/local/bin/claude", "/usr/lib/node_modules/@openai/codex/vendor/codex-x86_64-unknown-linux-musl exec", "/opt/codex/codex-aarch64-apple-darwin", "node /home/p/.cursor/cursor-agent/index.js"]) expect(agentProcess(c), c).toBe(true);
    for (const c of ["/bin/zsh -l", "vim codex.md", "/usr/bin/python3 gemini_notes.py", "/Applications/Cursor.app/Contents/MacOS/Cursor"]) expect(agentProcess(c), c).toBe(false);
  });
});

describe("what the integrity page shows of agent-configured text", () => {
  it("redacts credential arguments and URL query strings in a launch line", () => {
    expect(redactLaunch("npx srv --api-key sk-live-ABC123 --token=QQQ --verbose")).toBe("npx srv --api-key [redacted] --token=[redacted] --verbose");
    expect(redactLaunch("https://user:pw@h.example/mcp?token=QQQ&x=1")).toBe("https://[redacted]@h.example/mcp?[redacted]");
    expect(redactLaunch("node server.js --port 3000")).toBe("node server.js --port 3000");
  });
  it("a pin change's launch line is redacted on the page, and a non-ASCII name is escaped in the copy command", async () => {
    const b = box();
    const name = "nоtes";
    const pins: PinFile = {
      version: 1,
      servers: {},
      pending: [{ id: "p1", key: `user:${name}`, name, kind: "config", detail: `MCP server "${name}" changed: it now runs npx srv --api-key sk-live-ABC123 https://h.example/mcp?token=QQQSECRET`, firstSeen: "2026-10-10T01:00:00.000Z", lastSeen: "2026-10-10T01:00:00.000Z" }],
    };
    atomicWrite(pinsPath(b.l), JSON.stringify(pins));
    const { get } = await serve(b);
    const body = (await get("integrity")).body;
    expect(body).not.toContain("sk-live-ABC123");
    expect(body).not.toContain("QQQSECRET");
    expect(body).toContain("[redacted]");
    expect(body).toContain("pins accept $&#39;n\\u043etes&#39;");
    expect(shellWord(name)).toBe("$'n\\u043etes'");
    expect(shellWord("it's")).toBe("'it'\\''s'");
    expect(shellWord("docs")).toBe("docs");
  });
});

describe("masking unavailable", () => {
  it("a vault index that cannot be parsed puts a visible note on every page", async () => {
    const b = box();
    mkdirSync(join(indexPath(b.l), ".."), { recursive: true });
    writeFileSync(indexPath(b.l), "{ damaged");
    const { get } = await serve(b);
    for (const p of ["", "queue", "log", "vault"]) expect((await get(p)).body, p).toContain("Masking unavailable");
    const clean = box();
    const c = await serve(clean);
    expect((await c.get("")).body).not.toContain("Masking unavailable");
  });
});
