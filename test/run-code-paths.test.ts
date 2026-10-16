/**
 * v0.3 `run`: what the workspace itself names as code that runs later outside the sandbox (V4, V18), and
 * the Linux mount-point registry (V7). Everything is under the suite's temporary root.
 */
import { chmodSync, existsSync, linkSync, mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { commandStrings, gitConfigPaths, nestedRepoPaths, scriptsNamed, stripJsonc, workspaceCodePaths } from "../src/runtime/run/code-paths.js";
import { defaultRegistryRoot, isFirewallRun, mountRegistry, placeholderFile, processIdentity, readOnlyMountPoint, runMountPoint } from "../src/runtime/run/mountpoints.js";
import { createHash } from "node:crypto";
import { readText } from "../src/runtime/fsutil.js";
import { readSmallFile } from "../src/runtime/context.js";
import { linkedProtectedPath, protectedPaths } from "../src/runtime/run/run.js";
import { layout } from "../src/runtime/layout.js";
import { fakeRunProcess, testRoot } from "./helpers.js";

function ws(): string {
  const w = mkdtempSync(join(testRoot(), "cp-"));
  mkdirSync(join(w, ".git", "hooks"), { recursive: true });
  return w;
}
const put = (p: string, text = "x"): void => {
  mkdirSync(join(p, ".."), { recursive: true });
  writeFileSync(p, text);
};

describe("code paths named by the workspace (V4, V18)", () => {
  it("core.hooksPath (even when missing), an included config and a file the git config names", () => {
    const w = ws();
    put(join(w, "tools", "fsmon.sh"));
    const cfg = '[core]\n\thooksPath = tools/h\n\tfsmonitor = tools/fsmon.sh\n[include]\n\tpath = ../cfg/extra\n[remote "origin"]\n\turl = ../elsewhere.git\n';
    expect(gitConfigPaths(cfg, w, "/home/x").sort()).toEqual([join(w, "cfg", "extra"), join(w, "tools", "fsmon.sh"), join(w, "tools", "h")].sort());
    expect(gitConfigPaths("[core]\n  hooksPath = /etc/hooks\n", w, "/home/x")).toEqual([]);
  });
  it("RN5: core.hooksPath and fsmonitor from an included file (transitively, [includeIf] too), from .git/config.worktree and from the global config", () => {
    const w = ws();
    const home = mkdtempSync(join(testRoot(), "cp-home-"));
    put(join(w, ".git", "config"), "[include]\n\tpath = ../shared.gitconfig\n");
    put(join(w, "shared.gitconfig"), '[includeIf "gitdir:~/x/"]\n\tpath = more/second.gitconfig\n[core]\n\thooksPath = .githooks\n');
    put(join(w, "more", "second.gitconfig"), "[core]\n\tfsmonitor = tools/fsmon.sh\n");
    put(join(w, ".git", "config.worktree"), "[core]\n\thooksPath = wt-hooks\n");
    put(join(home, ".gitconfig"), "[core]\n\thooksPath = .husky-global\n");
    const got = workspaceCodePaths(w, home);
    for (const p of ["shared.gitconfig", "more/second.gitconfig", ".githooks", "tools/fsmon.sh", "wt-hooks", ".husky-global"]) expect(got, p).toContain(join(w, p));
    // An include loop ends.
    put(join(w, "more", "second.gitconfig"), "[include]\n\tpath = ../shared.gitconfig\n");
    expect(workspaceCodePaths(w, home)).toContain(join(w, ".githooks"));
  });
  it("hook, MCP server and task commands: scripts inside the workspace, with the project variables expanded", () => {
    const w = ws();
    put(join(w, ".claude", "hooks", "check.sh"));
    put(join(w, "scripts", "server.js"));
    put(join(w, "scripts", "build.sh"));
    put(join(w, ".claude", "settings.json"), JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: '"$CLAUDE_PROJECT_DIR"/.claude/hooks/check.sh --fast' }] }] } }));
    put(join(w, ".mcp.json"), JSON.stringify({ mcpServers: { s: { command: "node", args: ["scripts/server.js"] } } }));
    put(join(w, ".vscode", "tasks.json"), '{\n // a comment\n "tasks": [{ "label": "b", "command": "./scripts/build.sh", "args": ["src/main.ts"], }],\n}');
    put(join(w, "src", "main.ts"));
    const got = workspaceCodePaths(w, "/home/x");
    expect(got).toContain(join(w, ".claude", "hooks", "check.sh"));
    expect(got).toContain(join(w, "scripts", "server.js"));
    expect(got).toContain(join(w, "scripts", "build.sh"));
    // A task's arguments can name a script (e.g. bash scripts/setup.sh), so script args are protected too.
    expect(got).toContain(join(w, "src", "main.ts"));
  });
  it("tasks.json args, .vscode/settings.json, .claude/{skills,agents,commands} frontmatter, multi-line TOML, commented git config and nested repo git config", () => {
    const w = ws();
    put(join(w, ".vscode", "tasks.json"), JSON.stringify({ tasks: [{ label: "setup", command: "bash", args: ["scripts/setup.sh"] }] }));
    put(join(w, ".vscode", "settings.json"), JSON.stringify({ "python.defaultInterpreterPath": "./bin/venv-py", mcp: { servers: { s: { command: "node", args: ["scripts/vscode-mcp.js"] } } } }));
    put(join(w, ".claude", "skills", "deploy", "SKILL.md"), "---\nname: deploy\nhooks:\n  PreToolUse:\n    - matcher: Bash\n      hooks:\n        - type: command\n          command: scripts/skill-hook.sh\n---\n# Deploy\n");
    put(join(w, ".claude", "agents", "rev.md"), "---\nname: rev\nhooks:\n  Stop:\n    - hooks:\n        - type: command\n          command: ./scripts/agent-hook\n          args:\n            - scripts/agent-arg.sh\n---\n");
    put(join(w, ".claude", "commands", "cmd.md"), '---\ncommand: "$CLAUDE_PROJECT_DIR"/scripts/cmd-hook\n---\n');
    put(join(w, ".codex", "config.toml"), 'notify = [\n  "python3",\n  "scripts/codex-notify.py"\n]\n[mcp_servers.m]\ncommand = "node"\nargs = [\n  "scripts/codex-mcp.js"\n]\n');
    put(join(w, ".git", "config"), '[core] hooksPath = .githooks # custom\n[core]\n\tfsmonitor = tools/fsmon ; inline comment\n[include]\n\tpath = ../extra.gitconfig # comment\n');
    put(join(w, "extra.gitconfig"), '[core]\n\thooksPath = ".quoted#hooks" # keep hash in quotes\n');
    put(join(w, "sub", ".git", "config"), "[core]\n\thooksPath = .subhooks # nested repo hooks\n\tfsmonitor = tools/sub-fsmon\n");
    const got = workspaceCodePaths(w, "/home/x");
    for (const rel of [
      "scripts/setup.sh",
      "bin/venv-py",
      "scripts/vscode-mcp.js",
      "scripts/skill-hook.sh",
      "scripts/agent-hook",
      "scripts/agent-arg.sh",
      "scripts/cmd-hook",
      "scripts/codex-notify.py",
      "scripts/codex-mcp.js",
      ".githooks",
      "tools/fsmon",
      "extra.gitconfig",
      ".quoted#hooks",
      "sub/.subhooks",
      "sub/tools/sub-fsmon",
    ]) {
      expect(got, rel).toContain(join(w, rel));
    }
  });
  it("nested repositories: their hooks and config, or their .git file; installed packages are not walked", () => {
    const w = ws();
    mkdirSync(join(w, "vendor", "lib", ".git"), { recursive: true });
    put(join(w, "sub", ".git"), "gitdir: ../.git/modules/sub\n");
    mkdirSync(join(w, "node_modules", "p", ".git"), { recursive: true });
    const got = nestedRepoPaths(w);
    expect(got).toContain(join(w, "vendor", "lib", ".git", "hooks"));
    expect(got).toContain(join(w, "vendor", "lib", ".git", "config"));
    expect(got).toContain(join(w, "vendor", "lib", ".git", "commondir"));
    expect(got).toContain(join(w, "sub", ".git"));
    expect(got.some((p) => p.includes("node_modules"))).toBe(false);
    expect(got.some((p) => p === join(w, ".git", "hooks"))).toBe(false);
  });
  it("the workspace's own .git as a file is protected", () => {
    const w = mkdtempSync(join(testRoot(), "cp-"));
    put(join(w, ".git"), "gitdir: /elsewhere/.git/worktrees/w\n");
    expect(workspaceCodePaths(w, "/home/x")).toContain(join(w, ".git"));
  });
  it("RN6: allowWritePaths exempts scripts the agent settings run, and only those (never the fixed list or git's files)", () => {
    const w = realpathSync(ws());
    put(join(w, "dist", "index.js"));
    put(join(w, ".mcp.json"), JSON.stringify({ mcpServers: { s: { command: "node", args: ["dist/index.js"] } } }));
    const l = layout(join(testRoot(), "fw-home-rn6"));
    const def = protectedPaths(l, w, "/home/x", "linux");
    expect(def.readOnly).toContain(join(w, "dist", "index.js"));
    expect(def.scripts.map((e) => [e.path, e.source])).toEqual([[join(w, "dist", "index.js"), ".mcp.json"]]);
    const ex = protectedPaths(l, w, "/home/x", "linux", ["dist", ".git", ".mcp.json", "/"]);
    expect(ex.readOnly).not.toContain(join(w, "dist", "index.js"));
    expect(ex.exempted).toEqual([join(w, "dist", "index.js")]);
    for (const p of [".git/hooks", ".git/config", ".mcp.json", ".launchsafe-firewall.json"]) expect(ex.readOnly, p).toContain(join(w, p));
  });
  it("parsers: JSONC, TOML command lines, and tokens that are not files", () => {
    expect(JSON.parse(stripJsonc('{"a": "http://x//y", /* c */ "b": [1,],}'))).toEqual({ a: "http://x//y", b: [1] });
    expect(commandStrings('notify = ["python3", "hooks/n.py"]\n[mcp_servers.x]\ncommand = "node"\nargs = [\'srv.js\']\n', ["command", "args", "notify"], "toml")).toEqual(["python3", "hooks/n.py", "node", "srv.js"]);
    const w = ws();
    expect(scriptsNamed("node --flag $HOME/x https://a/b", w)).toEqual([]);
    // RN4: a missing script is protected before it exists (the agent could create it); bare words and data files are not.
    expect(scriptsNamed("sh scripts/guard.sh && ./bin/check --x && node missing.js data/config.json sh", w)).toEqual([join(w, "scripts", "guard.sh"), join(w, "bin", "check"), join(w, "missing.js")]);
    // FA2: in agent settings a missing path in program position is protected without an extension or ./; a data argument with a / is not, nor a bare word.
    expect(scriptsNamed('"$CLAUDE_PROJECT_DIR"/.claude/hooks/guard && FOO=1 tools/lint --out dist/out; guard', w, { programs: true })).toEqual([join(w, ".claude", "hooks", "guard"), join(w, "tools", "lint")]);
    // Git config values are not programs by position (refs/heads/main is not a file to protect).
    expect(scriptsNamed("refs/heads/main", w)).toEqual([]);
  });
  it("protectedPaths lists each workspace path as written and resolved; Linux refuses a symlink on the way (V3)", () => {
    const w = ws();
    const real = join(w, "shared-claude");
    mkdirSync(real);
    symlinkSync(real, join(w, ".claude"));
    const l = layout(join(testRoot(), "fw-home-cp"));
    const ro = protectedPaths(l, w, "/home/x", "darwin").readOnly;
    expect(ro).toContain(join(w, ".claude", "settings.json"));
    expect(ro.some((p) => p.endsWith("/shared-claude/settings.json"))).toBe(true);
    expect(linkedProtectedPath(ro, w)).toBe(join(w, ".claude"));
    expect(linkedProtectedPath([join(w, ".git", "hooks")], w)).toBeNull();
  });
});

describe("mount-point registry (V7, Linux)", () => {
  it("the last live run removes an empty mount point; never while another run uses it; never a non-empty one", () => {
    const root = mkdtempSync(join(testRoot(), "mr-"));
    const w = mkdtempSync(join(testRoot(), "mw-"));
    const mp = join(w, ".mcp.json");
    const full = join(w, ".cursor");
    mkdirSync(mp);
    mkdirSync(full);
    const a = mountRegistry(join(root, "reg"), process.pid);
    // Another live process (the parent of this one) also uses the mount point.
    const b = mountRegistry(join(root, "reg"), process.ppid);
    a.claim([mp, full]);
    expect(b.inUse([mp, full, join(w, "nothing")])).toEqual([mp, full]);
    b.claim([mp]);
    writeFileSync(join(full, "kept"), "agent wrote this");
    expect(a.release()).toEqual([]);
    expect(existsSync(mp)).toBe(true);
    expect(existsSync(full)).toBe(true);
    expect(b.release()).toEqual([mp]);
    expect(existsSync(mp)).toBe(false);
  });
  it("file stand-ins (.git/commondir): shared like directories, removed by the last run only while unchanged", () => {
    const root = mkdtempSync(join(testRoot(), "mr-"));
    const w = mkdtempSync(join(testRoot(), "mw-"));
    mkdirSync(join(w, ".git"));
    const cd = join(w, ".git", "commondir");
    const cw = join(w, ".git", "config.worktree");
    writeFileSync(cd, ".\n");
    writeFileSync(cw, "");
    expect(placeholderFile(cd)).toBe(true);
    expect(placeholderFile(cw)).toBe(true);
    expect(placeholderFile(join(w, ".git"))).toBe(false);
    const a = mountRegistry(join(root, "reg"), process.pid);
    const b = mountRegistry(join(root, "reg"), process.ppid);
    a.claim([cd, cw]);
    expect(b.inUse([cd, cw])).toEqual([cd, cw]);
    b.claim([cd]);
    expect(a.release()).toEqual([cw]); // cd is still in use by b
    expect(existsSync(cd)).toBe(true);
    expect(existsSync(cw)).toBe(false);
    expect(b.release()).toEqual([cd]);
    expect(existsSync(cd)).toBe(false);
    // Changed since (real content written outside the run, or a hard link to it): left alone.
    writeFileSync(cd, "../other\n");
    writeFileSync(cw, "");
    linkSync(cw, join(w, "hl"));
    const c = mountRegistry(join(root, "reg"), process.pid);
    c.claim([cd, cw]);
    expect(c.release()).toEqual([]);
    expect(existsSync(cd)).toBe(true);
    expect(existsSync(cw)).toBe(true);
  });
  it("runMountPoint: an empty directory a live run claims; not one a dead run claimed, not a non-empty one, not an unclaimed one, not on the word of the environment alone", () => {
    const root = join(mkdtempSync(join(testRoot(), "mr-")), "reg");
    const w = realpathSync(mkdtempSync(join(testRoot(), "mw-")));
    const mp = join(w, ".mcp.json");
    const other = join(w, ".launchsafe-firewall.json");
    mkdirSync(mp);
    mkdirSync(other);
    expect(runMountPoint(mp, root, {})).toBe(false);
    mountRegistry(root, 2 ** 22 + 12345).claim([mp]);
    expect(runMountPoint(mp, root, {})).toBe(false);
    // FA3: a live process that is not this firewall's run is no proof either.
    mountRegistry(root, process.ppid).claim([mp]);
    expect(runMountPoint(mp, root, {})).toBe(false);
    const fake = fakeRunProcess();
    try {
      mountRegistry(root, fake.pid).claim([mp]);
      expect(runMountPoint(mp, root, {})).toBe(true);
      // A registry others can write, or reach through a link, is not trusted.
      chmodSync(root, 0o770);
      expect(runMountPoint(mp, root, {})).toBe(false);
      chmodSync(root, 0o700);
      const link = join(dirname(root), "reg-link");
      symlinkSync(root, link);
      expect(runMountPoint(mp, link, {})).toBe(false);
      expect(runMountPoint(mp, root, {})).toBe(true);
      // A claim file naming the run's pid but another start time (a forged or stale claim of a reused pid) is not proof.
      const other2 = join(w, ".cursor");
      mkdirSync(other2);
      const key = join(root, createHash("sha256").update(other2).digest("hex").slice(0, 32));
      mkdirSync(key, { mode: 0o700 });
      const id = processIdentity(fake.pid);
      writeFileSync(join(key, String(fake.pid)), JSON.stringify({ path: other2, pid: fake.pid, start: "Thu Jan  1 00:00:00 1970", cmd: id?.cmd }));
      expect(runMountPoint(other2, root, {})).toBe(false);
    } finally {
      fake.stop();
    }
    expect(runMountPoint(mp, root, {})).toBe(false);
    // The command line must name this firewall's cli.js followed by run (a path with spaces included).
    expect(isFirewallRun("node /opt/My Tools/fw/dist/cli.js run -- claude", undefined, "/opt/My Tools/fw/dist/cli.js")).toBe(true);
    expect(isFirewallRun("node /opt/My Tools/fw/dist/cli.js log tail run", undefined, "/opt/My Tools/fw/dist/cli.js")).toBe(false);
    expect(isFirewallRun("node /elsewhere/cli.js run", undefined, "/opt/fw/dist/cli.js")).toBe(false);
    expect(runMountPoint(other, root, {})).toBe(false);
    // Inside a run the variable alone is no proof: an ordinary directory with it set is not a mount point,
    // whatever filesystem it is on (the test root is on a tmpfs in a Linux container with a tmpfs /tmp).
    expect(runMountPoint(other, root, { LAUNCHSAFE_FIREWALL_RUN: "run-x" })).toBe(false);
    writeFileSync(join(mp, "f"), "x");
    expect(runMountPoint(mp, root, {})).toBe(false);
  });
  it("runMountPoint inside a run (Linux): only a path this run claimed that is a read-only mount point here; never an empty directory on a tmpfs alone", () => {
    const root = join(mkdtempSync(join(testRoot(), "mr-")), "reg");
    const w = realpathSync(mkdtempSync(join(testRoot(), "mw-")));
    const mp = join(w, ".mcp.json");
    const made = join(w, ".launchsafe-firewall.json");
    mkdirSync(mp);
    mkdirSync(made);
    const inRun = { LAUNCHSAFE_FIREWALL_RUN: "run-20261013-a1b2c3d4" };
    // What the run's mount namespace shows: a read-only tmpfs on the mount point, on a workspace that is
    // itself on a writable tmpfs (a Linux host with a tmpfs /tmp).
    const table = [`22 1 0:21 / ${dirname(w)} rw,nosuid,nodev - tmpfs tmpfs rw`, `40 22 0:35 / ${mp} ro,relatime - tmpfs tmpfs ro`].join("\n");
    const mounts = (): string => table;
    // Not claimed: a read-only mount point is no proof by itself, nor is an empty directory on a tmpfs.
    expect(runMountPoint(mp, root, inRun, mounts)).toBe(false);
    expect(runMountPoint(made, root, inRun, mounts)).toBe(false);
    // The run claims it before the sandbox starts (with its own pid, which is in another pid namespace from inside:
    // a pid nothing here can prove, like this dead one).
    mountRegistry(root, 2 ** 22 + 23456, inRun.LAUNCHSAFE_FIREWALL_RUN).claim([mp]);
    expect(runMountPoint(mp, root, inRun, mounts)).toBe(true);
    // Another run's id, no run id, or the claim outside the run: no proof.
    expect(runMountPoint(mp, root, { LAUNCHSAFE_FIREWALL_RUN: "run-20261013-ffffffff" }, mounts)).toBe(false);
    expect(runMountPoint(mp, root, {}, mounts)).toBe(false);
    // Claimed, but not a mount point in this namespace (a stale claim seen outside the run, where the directory
    // lies on the tmpfs / filesystem only), a writable mount, or no mount table: no proof.
    expect(runMountPoint(mp, root, inRun, () => table.split("\n")[0] as string)).toBe(false);
    expect(runMountPoint(mp, root, inRun, () => `40 22 0:35 / ${mp} rw,relatime - tmpfs tmpfs rw`)).toBe(false);
    expect(runMountPoint(mp, root, inRun, () => null)).toBe(false);
    // The real mount table: the directory is not a mount point here, whatever filesystem the test root is on.
    expect(runMountPoint(mp, root, inRun)).toBe(false);
    // A directory the agent made is never claimed by the run, even when the mount table would pass it.
    expect(runMountPoint(made, root, inRun, () => `${table}\n41 22 0:36 / ${made} ro - tmpfs tmpfs ro`)).toBe(false);
    // A registry others can write is not trusted inside the run either.
    chmodSync(root, 0o770);
    expect(runMountPoint(mp, root, inRun, mounts)).toBe(false);
    chmodSync(root, 0o700);
    // Not empty: not a mount point the run keeps.
    writeFileSync(join(mp, "f"), "x");
    expect(runMountPoint(mp, root, inRun, mounts)).toBe(false);
  });
  it("readOnlyMountPoint: the topmost mount on exactly that path, read-only; escaped paths", () => {
    const t = ["30 1 0:20 / / rw - ext4 /dev/sda1 rw", "31 30 0:21 / /tmp rw,nosuid - tmpfs tmpfs rw", "32 31 0:22 / /tmp/w/.mcp.json ro,relatime - tmpfs tmpfs ro", "33 31 0:23 / /tmp/my\\040ws/.git/hooks ro - tmpfs tmpfs ro"].join("\n");
    expect(readOnlyMountPoint("/tmp/w/.mcp.json", t)).toBe(true);
    expect(readOnlyMountPoint("/tmp/my ws/.git/hooks", t)).toBe(true);
    expect(readOnlyMountPoint("/tmp/my\\040ws/.git/hooks", t)).toBe(false);
    // On a tmpfs, but not a mount point; a writable mount; a prefix of a mount point.
    expect(readOnlyMountPoint("/tmp/w/.cursor", t)).toBe(false);
    expect(readOnlyMountPoint("/tmp", t)).toBe(false);
    expect(readOnlyMountPoint("/tmp/w", t)).toBe(false);
    // A writable mount stacked on top of the read-only one is what the path is now.
    expect(readOnlyMountPoint("/tmp/w/.mcp.json", `${t}\n34 32 0:24 / /tmp/w/.mcp.json rw - tmpfs tmpfs rw`)).toBe(false);
    expect(readOnlyMountPoint("/tmp/w/.mcp.json", "")).toBe(false);
  });
  it("readText and readSmallFile (the hooks' readers): a live run's mount point reads as absent; any other directory still throws EISDIR", () => {
    const w = realpathSync(mkdtempSync(join(testRoot(), "mw-")));
    const mp = join(w, ".mcp.json");
    mkdirSync(mp);
    expect(() => readText(mp)).toThrow(/EISDIR/);
    expect(() => readSmallFile(mp)).toThrow(/EISDIR/);
    const fake = fakeRunProcess();
    const reg = mountRegistry(defaultRegistryRoot(), fake.pid);
    reg.claim([mp]);
    try {
      expect(readText(mp)).toBeNull();
      expect(readSmallFile(mp)).toBeNull();
    } finally {
      reg.release();
      fake.stop();
    }
  });
  it("claims of dead runs do not keep a mount point", () => {
    const root = mkdtempSync(join(testRoot(), "mr-"));
    const w = mkdtempSync(join(testRoot(), "mw-"));
    const mp = join(w, ".husky");
    mkdirSync(mp);
    mountRegistry(join(root, "reg"), 2 ** 22 + 12345).claim([mp]);
    const a = mountRegistry(join(root, "reg"), process.pid);
    expect(a.inUse([mp])).toEqual([]);
    a.claim([mp]);
    expect(a.release()).toEqual([mp]);
  });
});
