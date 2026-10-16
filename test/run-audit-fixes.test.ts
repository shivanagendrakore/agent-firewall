/**
 * The run sandbox audit's fixes (B1, I1-I5, I7, I10 and the minor items), checked on what the firewall
 * builds: the terminal decision, the Seatbelt profile text (macOS behaviour itself is to be verified on a
 * Mac; this suite runs on Linux), the unreadable paths, the child's environment, the plan's refusals, the
 * ClientHello parser, the address classes and the doctor's run check. Temporary directories only.
 */
import { lstatSync, mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { classifyAnswer, internalAddress } from "../src/engine/netgate.js";
import { bwrapArgs, bwrapMissing, guardedAncestors, HOME_UNREADABLE_OPTIONAL, writePathProblem, LINUX_DOCKER_SOCKET_DIRS, MACH_DNS_DENY, MACH_PREFS_DENY, SEATBELT_HARDLINK_DENY, SEATBELT_PROCESS_RULES, SEATBELT_TIOCSTI_DENY, seatbeltProfile, WORKSPACE_PROTECTED, WORKSPACE_PROTECTED_DIRS, type RunPlan } from "../src/engine/run-profile.js";
import { buildClientHello, parseClientHello } from "../src/engine/tls-sni.js";
import { agentSandboxChecks, looksInsideRun } from "../src/runtime/agent-sandbox-doctor.js";
import { installDir, layout } from "../src/runtime/layout.js";
import { runnerCommands } from "../src/runtime/run/code-paths.js";
import { agentAncestor, agentEnvMarker, allowedEnv, passEnvProblem, printable, socketsIn, ttyWrapNeeded } from "../src/runtime/run/guards.js";
import { detectRunPlatform } from "../src/runtime/run/platform.js";
import { buildPlan, childEnv, killGroup, protectedPaths, runnerNotice, runSandboxed } from "../src/runtime/run/run.js";
import { tempHome, testRoot } from "./helpers.js";

const plan = (over: Partial<RunPlan> = {}): RunPlan => ({
  platform: "darwin",
  workspace: "/Users/dev/proj",
  runTmp: "/private/var/folders/x/T/lsfw-run-1",
  writable: ["/Users/dev/proj", "/private/var/folders/x/T/lsfw-run-1"],
  readOnly: ["/Users/dev/.launchsafe-firewall", "/Users/dev/proj/.git/hooks"],
  unreadable: ["/Users/dev/.launchsafe-firewall/keys", "/Users/dev/.ssh"],
  socketDirs: ["/Users/dev/proj", "/private/var/folders/x/T/lsfw-run-1"],
  proxyPort: 51234,
  allowLocalhost: false,
  allowKeychain: false,
  ...over,
});

describe("B1: a pseudo-terminal whenever the run can reach a terminal", () => {
  it("any of 0, 1, 2 being a terminal is enough, not only standard input", () => {
    expect(ttyWrapNeeded({ fds: [true, false, false], controlling: true })).toBe(true);
    expect(ttyWrapNeeded({ fds: [false, true, false], controlling: false })).toBe(true);
    expect(ttyWrapNeeded({ fds: [false, false, true], controlling: false })).toBe(true);
  });
  it("a controlling terminal with every descriptor redirected still counts (/dev/tty opens)", () => {
    expect(ttyWrapNeeded({ fds: [false, false, false], controlling: true })).toBe(true);
  });
  it("no terminal anywhere (CI, a pipe): no wrap", () => {
    expect(ttyWrapNeeded({ fds: [false, false, false], controlling: false })).toBe(false);
  });
  it("the profile denies the TIOCSTI ioctl (rule text; syntax to verify on a Mac)", () => {
    expect(SEATBELT_TIOCSTI_DENY).toMatch(/^\(deny file-ioctl \(ioctl-command #x80017472\)\)$/);
    expect(seatbeltProfile(plan()).text).toContain(SEATBELT_TIOCSTI_DENY);
  });
});

describe("I1 and I3: the Seatbelt profile's other rules (text; behaviour to verify on a Mac)", () => {
  const { text } = seatbeltProfile(plan());
  it("no launchd jobs; other processes' information and task ports only within the sandbox", () => {
    expect(text).toContain("(deny job-creation)");
    for (const r of SEATBELT_PROCESS_RULES) expect(text).toContain(r);
    expect(text.indexOf("(allow process-info* (target same-sandbox))")).toBeGreaterThan(text.indexOf("(deny process-info*)"));
    expect(text.indexOf("(allow mach-priv-task-port (target same-sandbox))")).toBeGreaterThan(text.indexOf("(deny mach-priv-task-port)"));
  });
  it("name resolution (mDNSResponder) and preference writes (cfprefsd) are denied services", () => {
    for (const n of [...MACH_DNS_DENY, ...MACH_PREFS_DENY]) expect(text).toContain(`(global-name "${n}")`);
    expect(MACH_DNS_DENY).toContain("com.apple.mDNSResponder");
  });
  it("I3: hard links are refused (macOS: a file-link deny; Linux: each protected path is its own mount)", () => {
    expect(text).toContain(SEATBELT_HARDLINK_DENY);
    expect(SEATBELT_HARDLINK_DENY).toBe("(deny file-link)");
    const lp = plan({ platform: "linux", workspace: "/w", runTmp: "/tmp/r", writable: ["/w", "/tmp/r"], readOnly: ["/w/.git/config"], unreadable: [] });
    const args = bwrapArgs(lp, { socketDir: "/s", insideSocketDir: "/run/lsfw", socketName: "p.sock", nodePath: "/usr/bin/node", bridgeSource: "x", exists: (p) => (p === "/w/.git/config" ? "file" : p.startsWith("/w") || p === "/tmp/r" ? "dir" : null), cwd: "/w" }, ["sh"]).join(" ");
    expect(args).toContain("--ro-bind /w/.git/config /w/.git/config");
  });
});

describe("I2: credential stores and the environment", () => {
  const l = layout("/h/.launchsafe-firewall");
  it("the token stores are unreadable by default; --allow-home-read frees one; ~/.ssh never", () => {
    const p = protectedPaths(l, "/w", "/h", "darwin");
    for (const n of HOME_UNREADABLE_OPTIONAL) expect(p.unreadable).toContain(join("/h", n));
    expect(p.unreadable).toContain("/h/.ssh");
    const freed = protectedPaths(l, "/w", "/h", "darwin", [], [".npmrc"]);
    expect(freed.unreadable).not.toContain("/h/.npmrc");
    expect(freed.unreadable).toContain("/h/.docker");
  });
  it("Linux: Docker Desktop's sockets stay hidden even with .docker readable", () => {
    const p = protectedPaths(l, "/w", "/h", "linux", [], [".docker"]);
    expect(p.unreadable).not.toContain("/h/.docker");
    for (const d of LINUX_DOCKER_SOCKET_DIRS) expect(p.unreadable).toContain(join("/h", d));
    expect(protectedPaths(l, "/w", "/h", "darwin").unreadable).not.toContain("/h/.docker/run");
  });
  it("buildPlan refuses --allow-home-read for anything off the list (~/.ssh among them)", () => {
    const home = realpathSync(tempHome("audit-"));
    const ws = realpathSync(mkdtempSync(join(testRoot(), "audit-ws-")));
    const r = buildPlan({ l: layout(join(home, ".launchsafe-firewall")), workspace: ws, runTmp: "/tmp/x", allowWrite: [], home, cwd: ws, platform: "linux", proxyPort: 3128, allowLocalhost: false, allowKeychain: false, allowHomeRead: [".ssh"] });
    expect("problem" in r && r.problem).toMatch(/--allow-home-read \.ssh: not one of/);
  });
  it("the child gets the base list and --pass-env only: a token in the person's shell stays out", () => {
    const base = { PATH: "/usr/bin", HOME: "/h", LANG: "C", LC_ALL: "C", GITHUB_TOKEN: "ghp_x", AWS_SECRET_ACCESS_KEY: "k", NPM_CONFIG_REGISTRY: "r", NPM_CONFIG__AUTH: "a", SSH_AUTH_SOCK: "/s" };
    const e = childEnv(base, { proxyUrl: "http://127.0.0.1:1", runTmp: "/t", runId: "run-1" });
    expect(e.PATH).toBe("/usr/bin");
    expect(e.LC_ALL).toBe("C");
    expect(e.GITHUB_TOKEN).toBeUndefined();
    expect(e.AWS_SECRET_ACCESS_KEY).toBeUndefined();
    const p = childEnv(base, { proxyUrl: "http://127.0.0.1:1", runTmp: "/t", runId: "run-1", pass: ["GITHUB_TOKEN", "NPM_CONFIG_*", "SSH_AUTH_SOCK"], extra: { DEPLOY_KEY: "v" } });
    expect(p.GITHUB_TOKEN).toBe("ghp_x");
    expect(p.NPM_CONFIG_REGISTRY).toBe("r");
    expect(p.DEPLOY_KEY).toBe("v");
    expect(p.SSH_AUTH_SOCK).toBeUndefined();
    expect(p.HTTPS_PROXY).toBe("http://127.0.0.1:1");
    expect(allowedEnv({ FOO: "1" }, ["*"])).toEqual({});
  });
  it("--pass-env takes names and NAME_* prefixes only", () => {
    expect(passEnvProblem("GITHUB_TOKEN")).toBeNull();
    expect(passEnvProblem("NPM_CONFIG_*")).toBeNull();
    for (const bad of ["*", "A=B", "1X", "a b", "X**"]) expect(passEnvProblem(bad), bad).not.toBeNull();
  });
});

describe("I5: --allow-write and other programs' sockets", () => {
  const setup = (): { home: string; ws: string; dir: string; l: ReturnType<typeof layout> } => {
    const home = realpathSync(tempHome("audit-"));
    const ws = realpathSync(mkdtempSync(join(testRoot(), "audit-ws-")));
    const dir = realpathSync(mkdtempSync(join(testRoot(), "audit-aw-")));
    return { home, ws, dir, l: layout(join(home, ".launchsafe-firewall")) };
  };
  it("Linux refuses a directory that holds a socket; macOS notes it", () => {
    const s = setup();
    const sockets = (d: string): string[] => (d === s.dir ? [join(s.dir, "tmux-1000/default")] : []);
    const base = { l: s.l, workspace: s.ws, runTmp: "/tmp/x", allowWrite: [s.dir], home: s.home, cwd: s.ws, proxyPort: 3128, allowLocalhost: false, allowKeychain: false, sockets };
    const linux = buildPlan({ ...base, platform: "linux" });
    expect("problem" in linux && linux.problem).toMatch(/holds Unix sockets .*tmux-1000\/default/);
    const mac = buildPlan({ ...base, platform: "darwin" });
    expect("plan" in mac && mac.notes.join("\n")).toMatch(/holds Unix sockets of other programs/);
    const clean = buildPlan({ ...base, platform: "linux", sockets: () => [] });
    expect("plan" in clean).toBe(true);
  });
  it("socketsIn finds a listening socket a few levels down", async () => {
    const dir = realpathSync(mkdtempSync(join(testRoot(), "audit-sock-")));
    mkdirSync(join(dir, "a"));
    const path = join(dir, "a", "s.sock");
    const srv = createServer();
    await new Promise<void>((ok) => srv.listen(path, ok));
    try {
      expect(socketsIn(dir)).toEqual([path]);
    } finally {
      await new Promise<void>((ok) => srv.close(() => ok()));
    }
  });
});

describe("I4: ClientHellos whose server name cannot be trusted", () => {
  it("ECH (0xfe0d) and encrypted SNI (0xffce) are refused", () => {
    expect(parseClientHello(buildClientHello("github.com", [{ type: 0xfe0d, body: [0, 1, 2] }]))).toMatchObject({ state: "refused", why: expect.stringMatching(/Encrypted Client Hello/) });
    expect(parseClientHello(buildClientHello("github.com", [{ type: 0xffce, body: [1] }]))).toMatchObject({ state: "refused", why: expect.stringMatching(/encrypted SNI/) });
  });
  it("a second server_name extension, or a second name in one, is refused (not the first name taken)", () => {
    const name = [...Buffer.from("evil.example", "ascii")];
    const entry = [0, name.length >> 8, name.length & 255, ...name];
    const list = [entry.length >> 8, entry.length & 255, ...entry];
    expect(parseClientHello(buildClientHello("github.com", [{ type: 0, body: list }]))).toMatchObject({ state: "refused", why: expect.stringMatching(/two server_name/) });
    // One extension, two host_name entries.
    const first = [...Buffer.from("github.com", "ascii")];
    const e1 = [0, first.length >> 8, first.length & 255, ...first];
    const two = [...e1, ...entry];
    expect(parseClientHello(buildClientHello(null, [{ type: 0, body: [two.length >> 8, two.length & 255, ...two] }]))).toMatchObject({ state: "refused", why: expect.stringMatching(/names two servers/) });
  });
  it("an ordinary ClientHello with other extensions after the name still parses", () => {
    expect(parseClientHello(buildClientHello("github.com", [{ type: 0x0010, body: [0, 3, 2, 0x68, 0x32] }]))).toEqual({ state: "tls", sni: "github.com" });
  });
});

describe("I7: agents other than Claude Code start run only through a person", () => {
  it("the agents' shell variables and the firewall's hook marker are recognised", () => {
    for (const k of ["LAUNCHSAFE_FIREWALL_HOOK", "CODEX_SANDBOX", "GEMINI_CLI", "CURSOR_AGENT", "CLAUDECODE"]) expect(agentEnvMarker({ [k]: "1" }), k).toBe(k);
    expect(agentEnvMarker({ PATH: "/usr/bin", TERM: "xterm" })).toBeNull();
  });
  it("a Codex, Gemini CLI or Cursor agent among the parent processes is found", () => {
    const table: Record<number, string> = { 50: "40 /bin/zsh", 40: "30 node /opt/homebrew/lib/node_modules/@openai/codex/bin/codex.js", 30: "1 -zsh" };
    expect(agentAncestor(50, (pid) => table[pid] ?? null)).toMatch(/@openai\/codex/);
    const gem: Record<number, string> = { 50: "40 sh -c x", 40: "1 node /usr/local/bin/gemini --yolo" };
    expect(agentAncestor(50, (pid) => gem[pid] ?? null)).toMatch(/gemini/);
    const none: Record<number, string> = { 50: "40 /bin/zsh", 40: "1 /usr/bin/login" };
    expect(agentAncestor(50, (pid) => none[pid] ?? null)).toBeNull();
  });
});

describe("I10: agent configuration that runs later, and runners", () => {
  it(".codex, .gemini/extensions, .gemini/commands and .envrc are protected", () => {
    for (const p of [".codex", ".gemini/extensions", ".gemini/commands", ".envrc"]) expect(WORKSPACE_PROTECTED).toContain(p);
    for (const d of [".codex", ".gemini/extensions", ".gemini/commands"]) expect(WORKSPACE_PROTECTED_DIRS).toContain(d);
  });
  it("hooks and MCP servers started through npm run, npx, make, python -m or node_modules/.bin are named", () => {
    const ws = realpathSync(mkdtempSync(join(testRoot(), "audit-run-")));
    mkdirSync(join(ws, ".claude"));
    writeFileSync(join(ws, ".claude", "settings.json"), JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "npm run lint-hook" }] }] } }));
    writeFileSync(join(ws, ".mcp.json"), JSON.stringify({ mcpServers: { a: { command: "npx", args: ["-y", "some-server"] }, b: { command: "python", args: ["-m", "srv"] } } }));
    const found = runnerCommands(ws);
    expect(found.map((f) => `${f.source}: ${f.runner}`)).toEqual(expect.arrayContaining([".claude/settings.json: npm run (package.json scripts)", ".mcp.json: npx", ".mcp.json: python -m"]));
    expect(runnerNotice(ws)).toMatch(/through a runner/);
    const plain = realpathSync(mkdtempSync(join(testRoot(), "audit-run-")));
    writeFileSync(join(plain, ".mcp.json"), JSON.stringify({ mcpServers: { a: { command: "./bin/server.sh" } } }));
    expect(runnerNotice(plain)).toBeNull();
  });
});

describe("minor items", () => {
  it("text the command controls loses its control characters before reaching the terminal", () => {
    expect(printable("evil\u001b]0;pwned\u0007.example: \u009b2J refused\n")).toBe("evil?]0;pwned?.example: ?2J refused\n");
  });
  it("special-purpose address blocks are not public", () => {
    for (const ip of ["192.0.0.8", "192.0.2.1", "198.51.100.7", "203.0.113.9", "198.18.0.1", "198.19.255.255", "2001:db8::1"]) expect(classifyAnswer(ip).kind, ip).toBe("never");
    expect(classifyAnswer("fec0::1").kind).toBe("private");
    expect(classifyAnswer("64:ff9b::a00:1").kind).toBe("private"); // NAT64 of 10.0.0.1
    expect(internalAddress("198.18.0.1")).not.toBeNull();
    expect(classifyAnswer("198.20.0.1").kind).toBe("public");
    expect(classifyAnswer("192.0.1.1").kind).toBe("public");
  });
  it("6to4, Teredo and local-use NAT64 answers are judged by the IPv4 address they carry", () => {
    expect(classifyAnswer("2002:a00:1::1").kind).toBe("private"); // 6to4 of 10.0.0.1
    expect(classifyAnswer("2002:7f00:1::1").kind).toBe("loopback"); // 6to4 of 127.0.0.1
    expect(classifyAnswer("2002:a9fe:a9fe::1").kind).toBe("never"); // 6to4 of 169.254.169.254
    expect(classifyAnswer("2002:808:808::1").kind).toBe("public"); // 6to4 of 8.8.8.8
    expect(classifyAnswer("2001:0:4136:e378:8000:63bf:f5ff:fffe").kind).toBe("private"); // Teredo client 10.0.0.1, bit-inverted
    expect(classifyAnswer("2001:0:4136:e378:8000:63bf:80ff:fffe").kind).toBe("loopback"); // Teredo client 127.0.0.1
    expect(classifyAnswer("2001:0:4136:e378:8000:63bf:f7f7:f7f7").kind).toBe("public"); // Teredo client 8.8.8.8
    expect(classifyAnswer("64:ff9b:1::1").kind).toBe("private");
    expect(classifyAnswer("64:ff9b:1:ffff::8.8.8.8").kind).toBe("private");
    expect(internalAddress("2002:a00:1::1")).not.toBeNull();
  });
  it("killGroup kills the whole process group, never pid 1 or below", () => {
    const calls: [number, string][] = [];
    killGroup(4242, (pid, sig) => void calls.push([pid, sig]));
    killGroup(1, (pid, sig) => void calls.push([pid, sig]));
    killGroup(0, (pid, sig) => void calls.push([pid, sig]));
    expect(calls).toEqual([[-4242, "SIGKILL"]]);
  });
  it("doctor does not take LAUNCHSAFE_FIREWALL_RUN alone as proof of being inside run", () => {
    const input = { home: "/h", projectDir: "/w", hooked: new Set<string>(), claudeSandboxOn: true, findBinary: (n: string) => (n === "codex" ? "/usr/bin/codex" : null) };
    const forged = agentSandboxChecks({ ...input, env: { LAUNCHSAFE_FIREWALL_RUN: "x" } });
    expect(forged[0]?.status).toBe("warn");
    expect(forged[0]?.detail).toMatch(/LAUNCHSAFE_FIREWALL_RUN is set, but the rest of run's environment is not/);
    const proxy = "http://127.0.0.1:50123";
    const real = { LAUNCHSAFE_FIREWALL_RUN: "run-20261014120000-0a1b2c3d", TMPDIR: "/private/var/folders/x/T/lsfw-run-AbCd", HTTPS_PROXY: proxy, HTTP_PROXY: proxy, ALL_PROXY: proxy, https_proxy: proxy, http_proxy: proxy, NODE_USE_ENV_PROXY: "1" };
    expect(looksInsideRun(real)).toBe(true);
    expect(agentSandboxChecks({ ...input, env: real })[0]?.status).toBe("ok");
    expect(looksInsideRun({ ...real, HTTPS_PROXY: "http://corp:8080" })).toBe(false);
  });
  it("buildPlan refuses --allow-write inside read-only protected paths, and protectedPaths expands intermediate symlinks", async () => {
    const home = realpathSync(tempHome("audit-f10-"));
    const ws = realpathSync(mkdtempSync(join(testRoot(), "audit-f10-ws-")));
    const l = layout(join(home, ".launchsafe-firewall"));
    mkdirSync(l.home, { recursive: true, mode: 0o700 });
    mkdirSync(join(ws, ".git", "hooks"), { recursive: true });
    mkdirSync(join(ws, ".claude", "skills"), { recursive: true });
    for (const target of [join(ws, ".git", "hooks"), join(ws, ".claude", "skills"), join(installDir(), "dist")]) {
      const res = buildPlan({ l, workspace: ws, runTmp: "/tmp/x", allowWrite: [target], home, cwd: ws, platform: "darwin", proxyPort: 3128, allowLocalhost: false, allowKeychain: false });
      expect("problem" in res && res.problem, target).toMatch(/--allow-write .* refused: .*read-only or unreadable/);
    }
    const ws2 = realpathSync(mkdtempSync(join(testRoot(), "audit-f10-links-")));
    mkdirSync(join(ws2, "real_claude"), { recursive: true });
    symlinkSync("real_claude", join(ws2, "link1"));
    symlinkSync("link1", join(ws2, ".claude"));
    const prot = protectedPaths(l, ws2, home, "darwin");
    expect(prot.readOnly).toContain(join(ws2, "link1", "settings.json"));
    expect(guardedAncestors([...prot.readOnly, ...prot.unreadable], [ws2], true)).toContain(join(ws2, "link1"));

    if (detectRunPlatform().kind === "seatbelt") {
      const unlinkRes = await runSandboxed({
        layout: l,
        command: [process.execPath, "-e", `const fs = require("node:fs"); try { fs.unlinkSync(${JSON.stringify(join(ws2, "link1"))}); console.log("UNLINKED"); } catch (e) { console.log(e.code); }`],
        workspace: ws2,
        allowWrite: [],
        sendHosts: [],
        allowLocalhost: false,
        allowKeychain: false,
        dryRun: false,
        verbose: false,
        env: { ...process.env, HOME: home, LAUNCHSAFE_FIREWALL_RUN: undefined },
        home,
        cwd: ws2,
        say: () => undefined,
        warn: () => undefined,
        capture: true,
      });
      expect(unlinkRes.stdout.trim()).toBe("EPERM");
      expect(lstatSync(join(ws2, "link1")).isSymbolicLink()).toBe(true);

      for (const ttyWrap of [false, true]) {
        const bgRes = await runSandboxed({
          layout: l,
          command: [
            process.execPath,
            "-e",
            'const { spawn } = require("node:child_process"); process.on("SIGHUP", () => {}); const c = spawn(process.execPath, ["-e", "process.on(\\"SIGHUP\\", () => {}); setInterval(() => {}, 1000)"], { detached: true, stdio: "ignore" }); c.unref(); console.log("BG=" + c.pid);',
          ],
          workspace: ws,
          allowWrite: [],
          sendHosts: [],
          allowLocalhost: false,
          allowKeychain: false,
          dryRun: false,
          verbose: false,
          env: { ...process.env, HOME: home, LAUNCHSAFE_FIREWALL_RUN: undefined },
          home,
          cwd: ws,
          say: () => undefined,
          warn: () => undefined,
          capture: true,
          ttyWrap,
        });
        const m = /BG=(\d+)/.exec(bgRes.stdout);
        const bgPid = Number(m?.[1] ?? 0);
        expect(bgPid).toBeGreaterThan(1);
        let alive = false;
        try {
          process.kill(bgPid, 0);
          alive = true;
        } catch {
          alive = false;
        }
        expect(alive, `ttyWrap=${String(ttyWrap)}`).toBe(false);
      }
    }
  });
});

describe("protected paths for every writable root, and the longer lists", () => {
  it("an --allow-write directory gets the workspace's protected paths (git hooks and config, .envrc, MCP list, editor tasks)", () => {
    const home = realpathSync(tempHome("audit-roots-"));
    const ws = realpathSync(mkdtempSync(join(testRoot(), "audit-roots-ws-")));
    const extra = realpathSync(mkdtempSync(join(testRoot(), "audit-roots-aw-")));
    const l = layout(join(home, ".launchsafe-firewall"));
    mkdirSync(join(extra, ".git", "hooks"), { recursive: true });
    writeFileSync(join(extra, "team.code-workspace"), "{}");
    const r = buildPlan({ l, workspace: ws, runTmp: "/tmp/x", allowWrite: [extra], home, cwd: ws, platform: "darwin", proxyPort: 3128, allowLocalhost: false, allowKeychain: false, sockets: () => [] });
    if (!("plan" in r)) throw new Error(r.problem);
    for (const p of [".git/hooks", ".git/config", ".envrc", ".mcp.json", ".vscode/tasks.json", ".claude/settings.json", "team.code-workspace"]) expect(r.plan.readOnly, p).toContain(join(extra, p));
    for (const p of [".git/hooks", ".envrc"]) expect(r.plan.readOnly, p).toContain(join(ws, p));
    // The directories on the way are guarded for the extra root as well.
    expect(guardedAncestors(r.plan.readOnly, r.plan.writable, true)).toContain(join(extra, ".git"));
  });
  it("Linux: a missing protected path under an extra root is masked relative to that root", () => {
    const ws = "/w/proj";
    const extra = "/w/extra";
    const kinds = new Map<string, "dir" | "file">([[ws, "dir"], [extra, "dir"], ["/tmp/r", "dir"], [`${extra}/.vscode`, "dir"]]);
    const p = plan({ platform: "linux", workspace: ws, runTmp: "/tmp/r", writable: [ws, "/tmp/r", extra], readOnly: [`${extra}/.git/hooks`, `${extra}/.vscode/tasks.json`, `${extra}/.envrc`], unreadable: [] });
    const m = bwrapMissing(p, (q) => kinds.get(q) ?? null);
    expect(m.args).toContain(`${extra}/.vscode`); // an existing agent configuration directory is bound read-only whole
    expect(m.args.join(" ")).toContain(`--tmpfs ${extra}/.git --remount-ro ${extra}/.git`);
    expect(m.args.join(" ")).toContain(`--tmpfs ${extra}/.envrc --remount-ro ${extra}/.envrc`);
  });
  it("hook managers, mise and editor project files are protected", () => {
    for (const p of [".pre-commit-config.yaml", "lefthook.yml", "lefthook.yaml", ".lefthook.yml", ".lefthook.yaml", "mise.toml", ".mise.toml", ".vscode/launch.json", ".idea"]) expect(WORKSPACE_PROTECTED, p).toContain(p);
    expect(WORKSPACE_PROTECTED_DIRS).toContain(".idea");
    const ws = realpathSync(mkdtempSync(join(testRoot(), "audit-glob-")));
    writeFileSync(join(ws, "a.code-workspace"), "{}");
    const home = realpathSync(tempHome("audit-glob-"));
    const prot = protectedPaths(layout(join(home, ".launchsafe-firewall")), ws, home, "linux");
    expect(prot.readOnly).toContain(join(ws, "a.code-workspace"));
    expect(prot.readOnly).toContain(join(ws, "lefthook.yml"));
  });
  it("more of the home directory is refused for --allow-write", () => {
    const H = "/Users/dev";
    for (const p of [".config/nvim", ".config/zsh/x", ".vim", ".emacs.d", ".tmux", ".config/environment.d", ".local/share/applications", ".cargo/bin", "go/bin", ".npm-global/bin", "Library/Application Support/Code/User"]) expect(writePathProblem(`${H}/${p}`, H, [], true), p).not.toBeNull();
    expect(writePathProblem(`${H}/go/src/x`, H, [], true)).toBeNull();
  });
});
