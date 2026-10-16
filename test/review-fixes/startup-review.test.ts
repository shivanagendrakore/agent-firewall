/**
 * Independent enforcement review (11 Oct 2026) of the hook start-up changes (f0ac7db, 95540e9, bab935f):
 *
 * - the bundled hook (dist/hook/bundle.js): which code the hook command loads, and whether self-protection
 *   still covers it (install directory computed from the bundle, writes and mtime tricks, symlinked CLI);
 * - V8's compile cache in <firewall home>/cache/compile: who can write it, symlinks and loose modes, the
 *   test-marker rule, the environment;
 * - the decision log with one fsync per decision: head.json via the lock-file rename, recovery from the
 *   log's last entry, `log verify` accepting a head behind the log;
 * - lock-free session appends: approval_used and the counters still under the lock, torn lines.
 *
 * Each test states correct behaviour. Where the code does not hold, the test is `it.fails` with a one-line
 * reason (SR-numbered), so it turns red when the gap is fixed.
 * Temporary homes only (LAUNCHSAFE_FIREWALL_TEST=1); no network.
 */

import fs, { appendFileSync, chmodSync, cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import module from "node:module";
import { userInfo } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { entryHash, appendLog, loadKey, MAX_EVENT_BYTES, MAX_TAIL_SEARCH, rotateNow, verifyLog, type LogEntry } from "../../src/runtime/log.js";
import { layout, type Layout } from "../../src/runtime/layout.js";
import { appendEvents, consumeApproval, loadState, readEvents, sessionFile } from "../../src/runtime/store.js";
import { seatbeltBlock } from "../../src/runtime/gemini-seatbelt.js";
import { protectedPaths } from "../../src/runtime/run/run.js";
import { hookCommand } from "../../src/runtime/install.js";
import { parseHookCommand } from "../../src/runtime/identity.js";
import { bash, run, explain, SLOW, UNDER_COVERAGE } from "../helpers.js";
import { REPO, spawnCli, tempHome, testEnv } from "../helpers.js";

// --- helpers ------------------------------------------------------------------------------------------

function copyPackage(): string {
  const pkg = join(tempHome("pkg-"), "agent-firewall");
  mkdirSync(pkg, { recursive: true });
  cpSync(join(REPO, "dist"), join(pkg, "dist"), { recursive: true, preserveTimestamps: true });
  cpSync(join(REPO, "package.json"), join(pkg, "package.json"));
  return pkg;
}

function tracer(): string {
  const f = join(tempHome("trace-"), "trace.mjs");
  writeFileSync(f, `import module from "node:module";\nconst seen = [];\nmodule.registerHooks({ load(url, ctx, next) { seen.push(url); return next(url, ctx); } });\nprocess.on("exit", () => process.stderr.write("LOADED " + seen.join(" ") + "\\n"));\n`);
  return f;
}

function hookCall(cli: string, home: string, tool: string, input: Record<string, unknown>, o: { nodeArgs?: string[]; env?: Record<string, string | undefined> } = {}) {
  const ws = join(home, "proj");
  mkdirSync(ws, { recursive: true });
  const event = JSON.stringify({ hook_event_name: "PreToolUse", session_id: "sr1", cwd: ws, permission_mode: "default", tool_name: tool, tool_input: input });
  const r = spawnCli(["hook"], { home, cli, input: event, cwd: ws, env: { CLAUDE_PROJECT_DIR: ws, ...(o.env ?? {}) }, ...(o.nodeArgs !== undefined ? { nodeArgs: o.nodeArgs } : {}) });
  const loaded = /LOADED (.*)/.exec(r.stderr)?.[1]?.split(" ") ?? [];
  let decision: string | undefined;
  try {
    decision = (JSON.parse(r.stdout) as { hookSpecificOutput?: { permissionDecision?: string } }).hookSpecificOutput?.permissionDecision;
  } catch {
    decision = undefined;
  }
  return { r, loaded, decision };
}

const files = (dir: string): string[] => {
  try {
    return readdirSync(dir, { recursive: true }).map(String);
  } catch {
    return [];
  }
};

function freshLog(): Layout {
  const l = layout(join(tempHome("log-"), "fw"));
  loadKey(l);
  return l;
}
const headPath = (l: Layout): string => join(l.log, "head.json");
const current = (l: Layout): string => join(l.log, "decisions.jsonl");
const entries = (l: Layout): LogEntry[] =>
  readFileSync(current(l), "utf8")
    .split("\n")
    .filter((x) => x.trim() !== "")
    .flatMap((x) => {
      try {
        return [JSON.parse(x) as LogEntry];
      } catch {
        return [];
      }
    });

// --- 1. the bundle ------------------------------------------------------------------------------------

describe("bundle loading", () => {
  it("the bundle computes the install directory as the modules do: package.json and node_modules of the copy are protected through the bundle", () => {
    const pkg = copyPackage();
    const home = tempHome();
    for (const target of [join(pkg, "package.json"), join(pkg, "node_modules", "x", "index.js"), join(pkg, "dist", "hook", "claude.js"), join(pkg, "dist", "hook", "bundle.js")]) {
      const { r, loaded, decision } = hookCall(join(pkg, "dist", "cli.js"), home, "Write", { file_path: target, content: "export {}" }, { nodeArgs: ["--import", tracer()] });
      expect(loaded.some((u) => u.endsWith("/dist/hook/bundle.js")), r.stderr).toBe(true);
      expect(decision, `${target}: ${r.stdout}`).toBe("deny");
    }
  });

  it("the engine refuses the mtime trick and replacing either entry file (touch, utimes, ln -sf, cp) under the install directory", () => {
    const d = "/opt/launchsafe-firewall/dist/hook";
    for (const cmd of [`touch ${d}/claude.js`, `touch -d 2099-01-01 ${d}/claude.js`, `ln -sf /tmp/evil.js ${d}/bundle.js`, `cp /tmp/evil.js ${d}/bundle.js`, `node -e "require('fs').utimesSync('${d}/claude.js', new Date(), new Date(4102444800000))"`, `rm ${d}/bundle.js`]) {
      const dec = bash(cmd);
      expect(dec.verdict, `${cmd}: ${explain(dec)}`).not.toBe("allow");
    }
    expect(run("Write", { file_path: `${d}/bundle.js`, content: "x" }).verdict).toBe("deny");
  });

  it("a CLI reached through a symlink in a directory the agent controls loads the real package's bundle, not one next to the link", () => {
    const pkg = copyPackage();
    const evil = tempHome("evil-");
    mkdirSync(join(evil, "hook"), { recursive: true });
    writeFileSync(join(evil, "hook", "bundle.js"), "process.stderr.write('EVIL BUNDLE\\n'); export async function runHook() { process.stdout.write('{}'); return 0; }\n");
    writeFileSync(join(evil, "hook", "claude.js"), "process.stderr.write('EVIL MODULES\\n'); export async function runHook() { process.stdout.write('{}'); return 0; }\n");
    writeFileSync(join(evil, "package.json"), JSON.stringify({ type: "module" }));
    symlinkSync(join(pkg, "dist", "cli.js"), join(evil, "cli.js"));
    const { r, decision } = hookCall(join(evil, "cli.js"), tempHome(), "Write", { file_path: join(pkg, "dist", "cli.js"), content: "x" });
    expect(r.stderr).not.toContain("EVIL");
    expect(decision).toBe("deny");
  });

  it("the bundle has no import left that resolves outside itself (no bare packages, no relative dynamic imports)", () => {
    const text = readFileSync(join(REPO, "dist", "hook", "bundle.js"), "utf8");
    const specifiers = [...text.matchAll(/^import\b[^;\n]*?from\s*"([^"]+)"|\bimport\(\s*"([^"]+)"\s*\)/gm)].map((m) => (m[1] ?? m[2]) as string);
    expect(specifiers.length).toBeGreaterThan(0);
    expect(specifiers.filter((s) => !s.startsWith("node:"))).toEqual([]);
    expect(text).not.toMatch(/\brequire\s*\(/);
  });
});

// --- 2. the compile cache ----------------------------------------------------------------------------

describe("compile cache", () => {
  it("no other process the firewall sets up can write it: the gemini -s profile and the run sandbox leave <home>/cache read-only", () => {
    const block = seatbeltBlock({ fwHome: "/Users/u/.launchsafe-firewall" });
    const write = block.slice(block.indexOf("(allow file-write*"));
    expect(write).not.toContain("/cache");
    expect(write).not.toMatch(/\(subpath "\/Users\/u\/\.launchsafe-firewall"\)/);
    const l = layout(join(tempHome(), "fw"));
    const ws = tempHome("ws-");
    const p = protectedPaths(l, ws, tempHome(), process.platform);
    expect(p.readOnly.some((x) => x === l.home || l.home.startsWith(`${x}/`))).toBe(true);
  });

  it("is not enabled in a default home while a test marker is set (no LAUNCHSAFE_FIREWALL_HOME)", () => {
    const pkg = copyPackage();
    const home = tempHome();
    const fw = join(home, ".launchsafe-firewall");
    mkdirSync(fw, { recursive: true, mode: 0o700 });
    hookCall(join(pkg, "dist", "cli.js"), home, "Bash", { command: "git status" }, { env: { LAUNCHSAFE_FIREWALL_HOME: undefined } });
    hookCall(join(pkg, "dist", "cli.js"), home, "Bash", { command: "git status" }, { env: { LAUNCHSAFE_FIREWALL_HOME: undefined } });
    expect(existsSync(join(fw, "cache"))).toBe(false);
  });

  /**
   * Runs dist/cli.js with module.enableCompileCache replaced by a recorder, and stops before climain.js
   * loads, so nothing at all is written wherever the firewall home points.
   */
  function cacheDirChosen(env: Record<string, string | undefined>): string | null {
    const f = join(tempHome("stub-"), "stub.mjs");
    writeFileSync(
      f,
      `import module from "node:module";\nmodule.enableCompileCache = (d) => { process.stderr.write("CC " + d + "\\n"); };\nmodule.registerHooks({ load(url, ctx, next) { if (url.endsWith("/climain.js")) { process.stderr.write("STOP\\n"); process.exit(0); } return next(url, ctx); } });\n`,
    );
    const r = spawnCli(["--version"], { env, nodeArgs: ["--import", f] });
    expect(r.stderr).toContain("STOP");
    return /CC (.*)/.exec(r.stderr)?.[1] ?? null;
  }

  // SR1 (fixed): under a test marker the resolved home decides, so an explicit LAUNCHSAFE_FIREWALL_HOME in the real home is not used.
  it("SR1: never enabled in the real home under a test marker, even when LAUNCHSAFE_FIREWALL_HOME names it", () => {
    expect(cacheDirChosen({ LAUNCHSAFE_FIREWALL_HOME: userInfo().homedir })).toBeNull();
    // A path that reaches the real home only through a symlink is resolved first.
    const link = join(tempHome("link-"), "via");
    symlinkSync(userInfo().homedir, link);
    expect(cacheDirChosen({ LAUNCHSAFE_FIREWALL_HOME: join(link, "no-such-firewall-home") })).toBeNull();
    // A temporary home outside it still gets the cache.
    const fw = join(tempHome(), ".launchsafe-firewall");
    mkdirSync(fw, { recursive: true, mode: 0o700 });
    expect(cacheDirChosen({ LAUNCHSAFE_FIREWALL_HOME: fw })).toBe(join(fw, "cache", "compile"));
  });

  // SR2 (fixed): every component is lstat-ed (a real directory, owned by this user, not group/other-writable).
  it("SR2: a <home>/cache that is a symlink is not used", () => {
    const pkg = copyPackage();
    const home = tempHome();
    const fw = join(home, ".launchsafe-firewall");
    mkdirSync(fw, { recursive: true, mode: 0o700 });
    const elsewhere = tempHome("elsewhere-");
    symlinkSync(elsewhere, join(fw, "cache"));
    hookCall(join(pkg, "dist", "cli.js"), home, "Bash", { command: "git status" });
    hookCall(join(pkg, "dist", "cli.js"), home, "Bash", { command: "git status" });
    expect(files(elsewhere)).toEqual([]);
  });

  it("SR2: a cache directory others can write (mode 777) is not used", () => {
    const pkg = copyPackage();
    const home = tempHome();
    const fw = join(home, ".launchsafe-firewall");
    const cache = join(fw, "cache", "compile");
    mkdirSync(cache, { recursive: true });
    chmodSync(fw, 0o700);
    chmodSync(join(fw, "cache"), 0o777);
    chmodSync(cache, 0o777);
    hookCall(join(pkg, "dist", "cli.js"), home, "Bash", { command: "git status" });
    hookCall(join(pkg, "dist", "cli.js"), home, "Bash", { command: "git status" });
    expect(files(cache)).toEqual([]);
    // Group-writable, and a symlinked compile directory, are refused the same way; a firewall home that is itself a symlink too.
    chmodSync(join(fw, "cache"), 0o770);
    chmodSync(cache, 0o700);
    expect(cacheDirChosen({ LAUNCHSAFE_FIREWALL_HOME: fw })).toBeNull();
    chmodSync(join(fw, "cache"), 0o700);
    expect(cacheDirChosen({ LAUNCHSAFE_FIREWALL_HOME: fw })).toBe(cache);
    rmSync(cache, { recursive: true });
    const other = tempHome("other-");
    symlinkSync(other, cache);
    expect(cacheDirChosen({ LAUNCHSAFE_FIREWALL_HOME: fw })).toBeNull();
    const fwLink = join(tempHome("fwlink-"), "fw");
    symlinkSync(fw, fwLink);
    expect(cacheDirChosen({ LAUNCHSAFE_FIREWALL_HOME: fwLink })).toBeNull();
  });

  it("SR2: a missing cache directory is created private (700) inside an existing firewall home", () => {
    const fw = join(tempHome(), ".launchsafe-firewall");
    mkdirSync(fw, { recursive: true, mode: 0o700 });
    expect(cacheDirChosen({ LAUNCHSAFE_FIREWALL_HOME: fw })).toBe(join(fw, "cache", "compile"));
    for (const d of [join(fw, "cache"), join(fw, "cache", "compile")]) expect(fs.lstatSync(d).mode & 0o777).toBe(0o700);
  });

  // SR3 (fixed): node enables NODE_COMPILE_CACHE at start-up, before cli.ts runs, so the installed hook command sets it empty.
  // Node keeps no compile cache while NODE_V8_COVERAGE is set (npm run coverage sets it), so the children run without it.
  it.skipIf(UNDER_COVERAGE)("SR3: NODE_COMPILE_CACHE in the agent's environment does not move the cache: the installed hook command clears it", () => {
    const pkg = copyPackage();
    const home = tempHome();
    const fw = join(home, ".launchsafe-firewall");
    mkdirSync(fw, { recursive: true, mode: 0o700 });
    const cmd = hookCommand(layout(fw), process.execPath, join(pkg, "dist", "cli.js"));
    expect(cmd).toContain(" NODE_COMPILE_CACHE= ");
    expect(parseHookCommand(cmd)?.clearsCompileCache).toBe(true);
    const tmpCache = tempHome("node-cc-");
    const ws = join(home, "proj");
    mkdirSync(ws, { recursive: true });
    const event = JSON.stringify({ hook_event_name: "PreToolUse", session_id: "sr3", cwd: ws, permission_mode: "default", tool_name: "Bash", tool_input: { command: "git status" } });
    for (let i = 0; i < 2; i++) {
      const r = spawnSync("/bin/sh", ["-c", cmd], { encoding: "utf8", input: event, cwd: ws, env: testEnv(home, { NODE_COMPILE_CACHE: tmpCache, CLAUDE_PROJECT_DIR: ws, NODE_V8_COVERAGE: undefined }), timeout: 60000 });
      expect(r.status, r.stderr).toBe(0);
    }
    expect(files(tmpCache)).toEqual([]);
    // Without the assignment (an install from before 0.3.0) the environment's directory is used.
    spawnSync("/bin/sh", ["-c", cmd.replace(" NODE_COMPILE_CACHE= ", " ")], { encoding: "utf8", input: event, cwd: ws, env: testEnv(home, { NODE_COMPILE_CACHE: tmpCache, CLAUDE_PROJECT_DIR: ws, NODE_V8_COVERAGE: undefined }), timeout: 60000 });
    expect(files(tmpCache).length).toBeGreaterThan(0);
  });
});

// --- 3. the decision log ------------------------------------------------------------------------------

describe("decision log", () => {
  it("a forged entry with a valid hash but no signature, appended by someone who can write log/, is reported; the next entry chains past it but verify stays red", () => {
    const l = freshLog();
    for (let i = 0; i < 3; i++) appendLog(l, { type: "decision", n: i });
    const last = entries(l).at(-1) as LogEntry;
    const seq = last.seq + 1000;
    const ts = new Date().toISOString();
    const event = { type: "decision", verdict: "allow", forged: true };
    appendFileSync(current(l), `${JSON.stringify({ seq, ts, prev: last.hash, event, hash: entryHash(last.hash, seq, ts, event), sig: "" })}\n`);
    appendLog(l, { type: "decision", n: 3 });
    const v = verifyLog(l);
    expect(v.ok).toBe(false);
    expect(v.problems.join("\n")).toMatch(/bad signature/);
  });

  it("a crash-cut line plus a head behind: the next entry chains from the last complete entry, on its own line, and verify reports only the fragment", () => {
    const l = freshLog();
    for (let i = 0; i < 3; i++) appendLog(l, { type: "decision", n: i });
    const old = readFileSync(headPath(l), "utf8");
    appendLog(l, { type: "decision", n: 3 });
    const before = entries(l).at(-1) as LogEntry;
    writeFileSync(headPath(l), old);
    appendFileSync(current(l), '{"seq":99,"ts":"2026-10-11T00:00:00.000Z","prev":"ab');
    appendLog(l, { type: "decision", n: 4 });
    const after = entries(l);
    const rec = after.find((e) => e.event.type === "log_head_recovered") as LogEntry;
    expect(rec.prev).toBe(before.hash);
    expect(after.at(-1)?.event).toEqual({ type: "decision", n: 4 });
    const v = verifyLog(l);
    expect(v.problems.length, v.problems.join("; ")).toBe(1);
  });

  it("a head ahead of the log, or behind it naming an entry that is not in the chain, is still reported", () => {
    const l = freshLog();
    for (let i = 0; i < 4; i++) appendLog(l, { type: "decision", n: i });
    const es = entries(l);
    writeFileSync(headPath(l), JSON.stringify({ seq: (es.at(-1) as LogEntry).seq + 1, hash: "f".repeat(64) }));
    expect(verifyLog(l).ok).toBe(false);
    writeFileSync(headPath(l), JSON.stringify({ seq: (es[1] as LogEntry).seq, hash: "e".repeat(64) }));
    expect(verifyLog(l).ok).toBe(false);
    // Removing the tail and leaving the head as it was is caught.
    writeFileSync(headPath(l), JSON.stringify({ seq: (es.at(-1) as LogEntry).seq, hash: (es.at(-1) as LogEntry).hash }));
    writeFileSync(current(l), es.slice(0, 2).map((e) => JSON.stringify(e)).join("\n") + "\n");
    expect(verifyLog(l).ok).toBe(false);
  });

  // SR4 (fixed): readTail reads backwards in growing windows until a complete entry parses.
  it("SR4: after a power cut that loses head.json, the chain continues from the last entry even when that entry is longer than 64 KiB", () => {
    const l = freshLog();
    appendLog(l, { type: "decision", n: 0 });
    appendLog(l, { type: "sdk_event", blob: "x".repeat(70 * 1024) });
    const last = entries(l).at(-1) as LogEntry;
    rmSync(headPath(l));
    const next = appendLog(l, { type: "decision", n: 2 });
    expect(next.seq).toBeGreaterThan(last.seq);
    expect(verifyLog(l).problems.filter((p) => !/head/.test(p))).toEqual([]);
  });

  // SR5 (fixed): creating decisions.jsonl, and the rotation rename, fsync the log directory.
  it("SR5: the first entry of a new decisions.jsonl (after a rotation) also fsyncs the log directory, so the new file's name is durable", () => {
    const l = freshLog();
    appendLog(l, { type: "decision", n: 0 });
    rotateNow(l);
    const origFsync = fs.fsyncSync;
    const origOpen = fs.openSync;
    const synced: string[] = [];
    const fdPath = new Map<number, string>();
    fs.openSync = ((p: fs.PathLike, ...rest: unknown[]) => {
      const fd = (origOpen as (...a: unknown[]) => number)(p, ...rest);
      fdPath.set(fd, String(p));
      return fd;
    }) as typeof fs.openSync;
    fs.fsyncSync = ((fd: number) => {
      synced.push(fdPath.get(fd) ?? "?");
      origFsync(fd);
    }) as typeof fs.fsyncSync;
    module.syncBuiltinESMExports();
    try {
      appendLog(l, { type: "decision", n: 1 });
    } finally {
      fs.fsyncSync = origFsync;
      fs.openSync = origOpen;
      module.syncBuiltinESMExports();
    }
    expect(synced).toContain(current(l));
    expect(synced.some((p) => p === l.log || p === `${l.log}/`)).toBe(true);
  });
});

describe("decision log: SR4 bounds", () => {
  it("SR4: the last entry is found behind a 200 KB entry and a damaged line, so a lost head is rebuilt from it", () => {
    const l = freshLog();
    appendLog(l, { type: "decision", n: 0 });
    appendLog(l, { type: "sdk_event", blob: "x".repeat(200 * 1024) });
    const last = entries(l).at(-1) as LogEntry;
    appendFileSync(current(l), `${"y".repeat(100 * 1024)}\n`);
    rmSync(headPath(l));
    const next = appendLog(l, { type: "decision", n: 2 });
    expect(next.seq).toBe(last.seq + 2);
    expect(entries(l).at(-2)?.event).toMatchObject({ type: "log_head_recovered", why: "missing", last: { seq: last.seq } });
  });

  it("SR4: an event larger than MAX_EVENT_BYTES is refused with a clear error and nothing is written", () => {
    const l = freshLog();
    appendLog(l, { type: "decision", n: 0 });
    const before = readFileSync(current(l), "utf8");
    expect(() => appendLog(l, { type: "sdk_event", blob: "x".repeat(MAX_EVENT_BYTES) })).toThrow(/must be at most 262144 bytes as JSON; this one is \d+/);
    expect(readFileSync(current(l), "utf8")).toBe(before);
    expect(() => appendLog(l, { type: "sdk_event", blob: "x".repeat(MAX_EVENT_BYTES - 100) })).not.toThrow();
  });

  it("SR4: past the search bound appendLog fails closed (refuses, never forks) and log verify says why", () => {
    const l = freshLog();
    for (let i = 0; i < 3; i++) appendLog(l, { type: "decision", n: i });
    appendFileSync(current(l), `${"z".repeat(MAX_TAIL_SEARCH + 10)}\n`);
    rmSync(headPath(l));
    const before = readFileSync(current(l), "utf8");
    expect(() => appendLog(l, { type: "decision", n: 3 })).toThrow(/last entry is not within the last 1048576 bytes.*Nothing was appended/);
    expect(readFileSync(current(l), "utf8")).toBe(before);
    expect(existsSync(join(l.log, "log.lock"))).toBe(false);
    expect(verifyLog(l).problems.join("\n")).toMatch(/New entries are refused until the end of decisions.jsonl is repaired/);
  });

  it("SR5: the first entry of a brand-new log also fsyncs the directory; an ordinary append does not", () => {
    const l = freshLog();
    const synced = (fn: () => void): string[] => {
      const origFsync = fs.fsyncSync;
      const origOpen = fs.openSync;
      const out: string[] = [];
      const fdPath = new Map<number, string>();
      fs.openSync = ((p: fs.PathLike, ...rest: unknown[]) => {
        const fd = (origOpen as (...a: unknown[]) => number)(p, ...rest);
        fdPath.set(fd, String(p));
        return fd;
      }) as typeof fs.openSync;
      fs.fsyncSync = ((fd: number) => {
        out.push(fdPath.get(fd) ?? "?");
        origFsync(fd);
      }) as typeof fs.fsyncSync;
      module.syncBuiltinESMExports();
      try {
        fn();
      } finally {
        fs.fsyncSync = origFsync;
        fs.openSync = origOpen;
        module.syncBuiltinESMExports();
      }
      return out;
    };
    expect(synced(() => appendLog(l, { type: "decision", n: 0 }))).toEqual([current(l), l.log]);
    expect(synced(() => appendLog(l, { type: "decision", n: 1 }))).toEqual([current(l)]);
    expect(synced(() => rotateNow(l))).toEqual([l.log]);
  });
});

// --- 4. lock-free session appends --------------------------------------------------------------------

describe("session appends without the lock", () => {
  it("many processes appending large events at once: every line parses, none is lost", async () => {
    const l = layout(join(tempHome(), "fw"));
    const storeUrl = pathToFileURL(join(REPO, "dist", "runtime", "store.js")).href;
    const layoutUrl = pathToFileURL(join(REPO, "dist", "runtime", "layout.js")).href;
    const N = 8;
    const PER = 40;
    const script = `const { appendEvents } = await import(${JSON.stringify(storeUrl)}); const { layout } = await import(${JSON.stringify(layoutUrl)}); const l = layout(${JSON.stringify(l.home)}); for (let i = 0; i < ${PER}; i++) appendEvents(l, "race", [{ type: "taint", source: "p" + process.argv[1] + "-" + i + "-" + "y".repeat(6000) }, { type: "secret_path", path: "/x/" + i }]);`;
    await Promise.all(
      Array.from({ length: N }, (_, k) =>
        new Promise<void>((res, rej) => {
          const c = spawn(process.execPath, ["--input-type=module", "-e", script, String(k)], { stdio: "ignore", env: testEnv(tempHome()) });
          c.on("exit", (code) => (code === 0 ? res() : rej(new Error(`child ${k} exited ${code}`))));
        }),
      ),
    );
    const evs = readEvents(l, "race");
    expect(evs.filter((e) => e.type === "corrupt")).toEqual([]);
    expect(evs.filter((e) => e.type === "taint").length).toBe(N * PER);
    expect(evs.filter((e) => e.type === "secret_path").length).toBe(N * PER);
  });

  it("a session line cut off by a crash, followed by a lock-free taint append, leaves the session untrusted (never silently trusted)", () => {
    const l = layout(join(tempHome(), "fw"));
    appendEvents(l, "torn", [{ type: "secret_path", path: "/x" }]);
    expect(loadState(l, "torn").tainted).toBe(false);
    appendFileSync(sessionFile(l, "torn"), '{"type":"sensitive","detail":"cut');
    appendEvents(l, "torn", [{ type: "taint", source: "read https://example.com" }]);
    const st = loadState(l, "torn");
    expect(st.tainted).toBe(true);
  });

  it("approval_used goes through the session lock (appendEvents and consumeApproval wait for a held lock); a plain taint does not", () => {
    const l = layout(join(tempHome(), "fw"));
    appendEvents(l, "lk", [{ type: "taint", source: "x" }]);
    const lock = `${sessionFile(l, "lk")}.lock`;
    const timed = (fn: () => void): number => {
      // A live holder (a dead one's lock is broken at once, fsutil holderDead).
      writeFileSync(lock, `${process.pid} ${Date.now()}`);
      spawn("sh", ["-c", `sleep 0.6; rm -f '${lock}'`], { stdio: "ignore" });
      const t = Date.now();
      fn();
      const ms = Date.now() - t;
      rmSync(lock, { force: true });
      return ms;
    };
    expect(timed(() => appendEvents(l, "lk", [{ type: "approval_used", actionHash: "h1" }]))).toBeGreaterThanOrEqual(400);
    expect(timed(() => consumeApproval(l, "lk", "h2", "nope"))).toBeGreaterThanOrEqual(400);
    expect(timed(() => appendEvents(l, "lk", [{ type: "taint", source: "y" }]))).toBeLessThan(300 * SLOW);
  });
});
