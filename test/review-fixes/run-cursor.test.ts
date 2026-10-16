/**
 * Review of the v0.3 fixes, lane "run sandbox + proxy + Cursor" (V3, V4, V7, V18, V19, V20, V36). Each
 * it.fails (kept as a regression test now the gap is fixed) asserts the PROMISED behaviour (docs/run.md); a
 * plain `it` is a finding that is fixed (or, where marked, asserts the documented behaviour instead).
 * Every path is inside the suite's temporary root; no network (127.0.0.1 only). Live sandbox tests run
 * only where sandbox-exec is available.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { connect, type Socket } from "node:net";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bwrapMissing, type RunPlan } from "../../src/engine/run-profile.js";
import { RunBudgets, runNetPolicy } from "../../src/engine/netgate.js";
import { defaultConfig } from "../../src/policy.js";
import { layout } from "../../src/runtime/layout.js";
import { startProxy } from "../../src/runtime/run/proxy.js";
import { GIT_CONFIG_NOTICE, GIT_INIT_NOTICE, protectedPaths, runSandboxed, type RunOptions } from "../../src/runtime/run/run.js";
import { detectRunPlatform } from "../../src/runtime/run/platform.js";
import { tempHome, testRoot } from "../helpers.js";

const sb = detectRunPlatform();

/** The commit identity setup() puts in the environment, for runs whose command commits. */
const GIT_IDENTITY = ["GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "GIT_CONFIG_NOSYSTEM"];

function setup(o: { git: boolean }): { ws: string; env: NodeJS.ProcessEnv; opts: (command: string[]) => RunOptions } {
  const home = tempHome("rn-");
  const l = layout(join(home, ".launchsafe-firewall"));
  mkdirSync(l.home, { recursive: true, mode: 0o700 });
  writeFileSync(l.policy, JSON.stringify({ version: 2 }));
  const ws = mkdtempSync(join(testRoot(), "rn-ws-"));
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid" };
  if (o.git) execFileSync("git", ["init", "-q", ws], { env });
  const opts = (command: string[]): RunOptions => ({ layout: l, command, workspace: ws, allowWrite: [], sendHosts: [], allowLocalhost: false, allowKeychain: false, dryRun: false, verbose: false, env, home, cwd: ws, say: () => undefined, warn: () => undefined, capture: true, dial: () => Promise.reject(new Error("no network in this test")) });
  return { ws, env, opts };
}

/** Runs a shell script inside the sandbox; each `echo NAME=$?` line becomes one entry. */
async function codes(opts: (c: string[]) => RunOptions, script: string): Promise<Record<string, string>> {
  const r = await runSandboxed(opts(["/bin/sh", "-c", script]));
  const out: Record<string, string> = {};
  for (const m of r.stdout.matchAll(/^(\w+)=(\d+)$/gm)) out[m[1] as string] = m[2] as string;
  return out;
}

// Written for macOS; they hold under bubblewrap too (messages differ where noted), so they run under both.
describe.skipIf(sb.kind === "none")(`review fixes: run under the OS sandbox (${sb.kind})`, () => {
  it("RN1 (V4, macOS): .git/commondir cannot point git at a directory the agent wrote, whose hooks git runs outside the sandbox", async () => {
    // docs/run.md: everything in the workspace that starts a program later, outside the sandbox, is read-only.
    // git reads $GIT_DIR/commondir in any git directory and then takes hooks/ and config from the directory it
    // names. Inside run: copy .git's objects, refs and config to evil/, add evil/hooks/pre-commit, write
    // `../evil` to .git/commondir. The person's next `git commit` (outside run) runs the planted hook.
    const { ws, env, opts } = setup({ git: true });
    writeFileSync(join(ws, "a.txt"), "a");
    execFileSync("git", ["-C", ws, "add", "a.txt"], { env });
    execFileSync("git", ["-C", ws, "commit", "-qm", "a"], { env });
    const marker = join(ws, "MARKER");
    await runSandboxed(opts(["/bin/sh", "-c", `mkdir evil && cp -R .git/objects .git/refs .git/config evil/ && mkdir evil/hooks && printf '#!/bin/sh\\ntouch ${marker}\\n' > evil/hooks/pre-commit && chmod +x evil/hooks/pre-commit && echo ../evil > .git/commondir`]));
    try {
      execFileSync("git", ["-C", ws, "commit", "--allow-empty", "-qm", "b"], { env, stdio: "ignore" });
    } catch {
      // A refused redirect may leave git unable to commit; only the marker matters.
    }
    expect(existsSync(marker)).toBe(false);
  });

  it("RN2 (V4, macOS), documented instead: git commands that rewrite .git/config fail inside run with git's own message, run says so at the start, and .git/config is unchanged", async () => {
    // .git/config stays protected (V4: core.fsmonitor, core.hooksPath, filters and aliases run programs).
    // git writes .git/config.lock and renames it over .git/config, which the read-only rule refuses; run's
    // start-up notice and docs/run.md (Limits) name the commands and the message, and say to run them outside.
    const { ws, opts } = setup({ git: true });
    const warns: string[] = [];
    const before = readFileSync(join(ws, ".git", "config"), "utf8");
    const res = await runSandboxed({ ...opts(["/bin/sh", "-c", "git config user.email t@example.invalid; echo cfg=$?; git remote add origin https://example.invalid/x.git; echo remote=$?"]), warn: (w) => warns.push(w) });
    expect(res.stdout).toMatch(/^cfg=[1-9]\d*$/m);
    expect(res.stdout).toMatch(/^remote=[1-9]\d*$/m);
    expect(res.stderr).toMatch(sb.kind === "seatbelt" ? /could not write config file \S*\.git\/config: Operation not permitted/ : /could not write config file \S*\.git\/config: Device or resource busy/);
    expect(warns).toContain(GIT_CONFIG_NOTICE);
    expect(readFileSync(join(ws, ".git", "config"), "utf8")).toBe(before);
  });

  it("RN3 (V3/V7, macOS), documented instead: `git init` fails inside run (.git stays protected) and run says so; with --git-init the repository is created before the run starts", async () => {
    // .git is a guarded ancestor of .git/hooks and .git/config even when it does not exist. Allowing it to be
    // created inside the run would let the agent prepare the git directory (hooks, config) itself.
    const { ws, opts } = setup({ git: false });
    const warns: string[] = [];
    const res = await runSandboxed({ ...opts(["/bin/sh", "-c", "git init -q; echo init=$?"]), warn: (w) => warns.push(w) });
    expect(res.stdout).toMatch(/^init=[1-9]\d*$/m);
    expect(res.stderr).toMatch(sb.kind === "seatbelt" ? /\.git: Operation not permitted/ : /Read-only file system/);
    expect(warns).toContain(GIT_INIT_NOTICE);
    expect(existsSync(join(ws, ".git"))).toBe(false);
    // run passes only the base list of variables (I2), so setup's GIT_AUTHOR_*/GIT_COMMITTER_* stay outside
    // and the temporary HOME has no .gitconfig. Without them git falls back to the account's full name, which
    // a CI runner's account does not have ("empty ident name", exit 128). --pass-env is how a person hands
    // them in.
    const withFlag = await runSandboxed({ ...opts(["/bin/sh", "-c", "echo a > a.txt && git add a.txt && git commit -qm first && git log --oneline"]), gitInit: true, passEnv: GIT_IDENTITY });
    expect(withFlag.exitCode, withFlag.stderr).toBe(0);
    expect(withFlag.stdout).toContain("first");
    expect(existsSync(join(ws, ".git", "HEAD"))).toBe(true);
  });

  it("RN4 (V18, macOS): a script that a protected hook names stays read-only even when it does not exist yet", async () => {
    // code-paths.ts scriptsNamed keeps only existing files, so with `sh scripts/guard.sh` in
    // .claude/settings.json and no scripts/guard.sh at the start (gitignored, generated), the agent creates it
    // and Claude Code runs it as a hook in the person's next session, outside the sandbox.
    const { ws, opts } = setup({ git: true });
    mkdirSync(join(ws, ".claude"));
    writeFileSync(join(ws, ".claude", "settings.json"), JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "sh scripts/guard.sh" }] }] } }));
    const r = await codes(opts, "mkdir -p scripts; printf 'echo placeholder\\n' > scripts/guard.sh; echo script=$?");
    expect(r.script).toMatch(/^[1-9]/); // refused (macOS sh exits 1, Linux dash 2)
    expect(existsSync(join(ws, "scripts", "guard.sh"))).toBe(false);
  });

  it("RN5 (V4, macOS): core.hooksPath set in an [include]d config file is protected like one set in .git/config", async () => {
    // gitConfigPaths protects the included file but does not read it, so its core.hooksPath (.githooks) stays
    // writable: the agent writes .githooks/pre-commit and git runs it outside the sandbox.
    const { ws, env, opts } = setup({ git: true });
    writeFileSync(join(ws, ".gitconfig-shared"), "[core]\n\thooksPath = .githooks\n");
    execFileSync("git", ["-C", ws, "config", "include.path", "../.gitconfig-shared"], { env });
    const r = await codes(opts, "mkdir -p .githooks; printf '#!/bin/sh\\n' > .githooks/pre-commit; echo hook=$?");
    expect(r.hook).toMatch(/^[1-9]/); // refused (macOS sh exits 1, Linux dash 2)
    expect(existsSync(join(ws, ".githooks", "pre-commit"))).toBe(false);
  });

  it("RN6 (V18, macOS), as decided: build output an MCP server runs stays read-only by default, run's notice names why and the key, and run.allowWritePaths in the user policy exempts it", async () => {
    // .mcp.json naming `node dist/index.js` makes dist/index.js read-only and dist/ unremovable: the agent could
    // otherwise replace the server the person's next session starts. Protected by default; the person exempts it.
    const { ws, opts } = setup({ git: true });
    writeFileSync(join(ws, ".mcp.json"), JSON.stringify({ mcpServers: { dev: { command: "node", args: ["dist/index.js"] } } }));
    mkdirSync(join(ws, "dist"));
    writeFileSync(join(ws, "dist", "index.js"), "1");
    const script = "echo 2 > dist/index.js; echo build=$?; rm -rf dist; echo clean=$?";
    const warns: string[] = [];
    const res = await runSandboxed({ ...opts(["/bin/sh", "-c", script]), warn: (w) => warns.push(w) });
    expect(res.stdout).toMatch(/^build=[1-9]/m);
    expect(res.stdout).toMatch(/^clean=[1-9]/m);
    const note = warns.find((w) => w.includes("dist/index.js (.mcp.json runs it)")) ?? "";
    expect(note).toContain("allowWritePaths");
    expect(note).toContain("Operation not permitted");
    // The person's user policy exempts dist; a project policy saying the same is ignored.
    const policy = opts([]).layout.policy;
    writeFileSync(join(ws, ".launchsafe-firewall.json"), JSON.stringify({ version: 2, run: { allowWritePaths: ["dist"] } }));
    expect((await codes(opts, script)).build).toMatch(/^[1-9]/);
    writeFileSync(policy, JSON.stringify({ version: 2, run: { allowWritePaths: ["dist"] } }));
    expect(await codes(opts, script)).toEqual({ build: "0", clean: "0" });
  });

  it("RN7 (V3/V18, macOS): .claude/skills and .claude/agents (whose frontmatter can declare hooks) stay read-only", async () => {
    // Claude Code skills and subagents can declare hooks in their frontmatter (unconfirmed for every Claude Code
    // version); the run protects only .claude/settings*.json, so the agent writes a skill with a hook.
    const { ws, opts } = setup({ git: true });
    mkdirSync(join(ws, ".claude"));
    writeFileSync(join(ws, ".claude", "settings.json"), "{}");
    const r = await codes(opts, "mkdir -p .claude/skills/x && printf -- '---\\nname: x\\n---\\n' > .claude/skills/x/SKILL.md; echo skill=$?; mkdir -p .claude/agents && printf -- '---\\nname: a\\n---\\n' > .claude/agents/a.md; echo agent=$?");
    expect(r.skill).toMatch(/^[1-9]/);
    expect(r.agent).toMatch(/^[1-9]/);
    expect(existsSync(join(ws, ".claude", "skills", "x"))).toBe(false);
  });
});

describe("review fixes: run plans (both platforms)", () => {
  // Names that exist nowhere: on macOS /home is an automount point, and looking up a path under it can stall for tens of seconds.
  const home = "/lsfw-no-such-root/dev";
  const ws = "/lsfw-no-such-root/dev/proj";
  const l = layout(join(home, ".launchsafe-firewall"));

  it("RN1 (V4, Linux and macOS plans): .git/commondir is in the read-only list", () => {
    for (const platform of ["linux", "darwin"] as const) expect(protectedPaths(l, ws, home, platform).readOnly).toContain(join(ws, ".git", "commondir"));
  });

  it("RN3 (V7, Linux), documented instead: a workspace without .git gets a read-only tmpfs on .git (git init runs outside run, or with --git-init)", () => {
    const plan: RunPlan = { platform: "linux", workspace: ws, runTmp: "/tmp/r", writable: [ws, "/tmp/r"], readOnly: [".git/hooks", ".git/config", ".git/modules"].map((p) => join(ws, p)), unreadable: [], socketDirs: [ws], proxyPort: 3128, allowLocalhost: false, allowKeychain: false };
    const { args } = bwrapMissing(plan, (p) => (p === ws || p === "/tmp/r" ? "dir" : null));
    expect(args.join(" ")).toContain(`--tmpfs ${join(ws, ".git")} --remount-ro ${join(ws, ".git")}`);
  });

  it("RN8 (V18): .devcontainer (devcontainer.json's initializeCommand runs on the host) is read-only whole, and .vscode/settings.json on both platforms", () => {
    // The whole directory is listed (it covers devcontainer.json and the scripts next to it).
    for (const platform of ["linux", "darwin"] as const) {
      const ro = protectedPaths(l, ws, home, platform).readOnly;
      expect(ro).toContain(join(ws, ".devcontainer"));
      expect(ro).toContain(join(ws, ".vscode", "settings.json"));
    }
  });
});

describe("review fixes: run proxy", () => {
  let web: HttpServer;
  let webPort = 0;
  beforeAll(async () => {
    web = createHttpServer((_q, r) => r.end("web"));
    web.on("upgrade", (_q, s: Socket) => s.end("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"));
    await new Promise<void>((r) => web.listen(0, "127.0.0.1", () => r()));
    webPort = (web.address() as { port: number }).port;
  });
  afterAll(() => web.close());

  it("RN9 (V19): a WebSocket upgrade (ws://) inside a CONNECT to port 80 reaches the admitted server, as before the fix", async () => {
    // Before V19 a port-80 tunnel was relayed; now its requests go to the proxy's HTTP server, whose upgrade
    // handler answers 501 to every upgrade.
    const { policy } = runNetPolicy({ ...defaultConfig(), fetchAllowHosts: ["allowed.test"] }, { sendHosts: [] });
    const p = await startProxy({ policy, budgets: new RunBudgets(policy), listen: { host: "127.0.0.1" }, onEvent: () => undefined, helloTimeoutMs: 300, dial: () => new Promise((res, rej) => { const s = connect(webPort, "127.0.0.1", () => res(s)); s.on("error", rej); }) });
    const s = connect(p.port as number, "127.0.0.1", () => s.write("CONNECT allowed.test:80 HTTP/1.1\r\nHost: allowed.test:80\r\n\r\n"));
    const got = await new Promise<string>((r) => {
      let b = "";
      let sent = false;
      s.on("data", (c: Buffer) => {
        b += c.toString("latin1");
        if (!sent && b.includes("\r\n\r\n")) {
          sent = true;
          b = "";
          s.write("GET /ws HTTP/1.1\r\nHost: allowed.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
        } else if (sent && b.includes("\r\n\r\n")) r(b);
      });
      s.on("close", () => r(b));
    });
    s.destroy();
    await p.close();
    expect(got).toMatch(/^HTTP\/1.1 101/);
  });
});
