/**
 * Final enforcement review, lane A: the `run` sandbox fixes (RN1-RN9, commondir, Linux stand-ins, concurrent
 * runs, run.allowWritePaths, --git-init) and the install-lifecycle fixes (LC1-LC9: modes, symlink write-through,
 * --restore-backup, doctor --repair-state, unwrap-config). Each test asserts the CORRECT behaviour; an `it.fails`
 * was a finding (FA*), kept as a regression test now fixed. Temporary homes only
 * (LAUNCHSAFE_FIREWALL_TEST=1), no network (the proxy's dial is refused), nothing in src/ changed.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { isReadOnlyInvocation } from "../../src/cliargs.js";
import { mergeTighten, validatePolicy, defaultConfig } from "../../src/policy.js";
import { runAllowWritePaths } from "../../src/policy-run.js";
import { loadPolicy } from "../../src/runtime/config.js";
import { readText } from "../../src/runtime/fsutil.js";
import { layout } from "../../src/runtime/layout.js";
import { mountRegistry, placeholderFile, runMountPoint } from "../../src/runtime/run/mountpoints.js";
import { detectRunPlatform } from "../../src/runtime/run/platform.js";
import { protectedPaths, runSandboxed, type RunOptions } from "../../src/runtime/run/run.js";
import { bash, explain, run as decideTool, tempHome, testRoot } from "../helpers.js";
import { lab, person, run as cli, write, type Lab } from "../lifecycle/lab.js";

const sb = detectRunPlatform();

function wsSetup(o: { git: boolean; userPolicy?: Record<string, unknown> }): { home: string; ws: string; l: ReturnType<typeof layout>; env: NodeJS.ProcessEnv; opts: (command: string[], extra?: Partial<RunOptions>) => RunOptions } {
  const home = realpathSync(tempHome("fa-"));
  const l = layout(join(home, ".launchsafe-firewall"));
  mkdirSync(l.home, { recursive: true, mode: 0o700 });
  writeFileSync(l.policy, JSON.stringify({ version: 3, ...(o.userPolicy ?? {}) }));
  const ws = realpathSync(mkdtempSync(join(testRoot(), "fa-ws-")));
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid" };
  if (o.git) execFileSync("git", ["init", "-q", ws], { env });
  const opts = (command: string[], extra: Partial<RunOptions> = {}): RunOptions => ({ layout: l, command, workspace: ws, allowWrite: [], sendHosts: [], allowLocalhost: false, allowKeychain: false, dryRun: false, verbose: false, env, home, cwd: ws, say: () => undefined, warn: () => undefined, capture: true, dial: () => Promise.reject(new Error("no network in this test")), ...extra });
  return { home, ws, l, env, opts };
}

/** Runs a shell script inside the sandbox; each `echo NAME=$?` line becomes one entry. */
async function codes(opts: RunOptions): Promise<Record<string, string>> {
  const r = await runSandboxed(opts);
  const out: Record<string, string> = {};
  for (const m of r.stdout.matchAll(/^(\w+)=(\d+)$/gm)) out[m[1] as string] = m[2] as string;
  return out;
}

// ---------------------------------------------------------------------------------------------------------
// run.allowWritePaths: person-only, and never an exemption for git's files, the fixed list or the firewall's.
// ---------------------------------------------------------------------------------------------------------
describe("run.allowWritePaths is person-only", () => {
  it("a project policy's run.allowWritePaths is ignored (reported), and the merged config has no exemption", () => {
    const base = defaultConfig();
    const doc = validatePolicy({ version: 3, run: { allowWritePaths: ["dist", "."] } }, "/w/.launchsafe-firewall.json");
    const { config, ignored } = mergeTighten(base, doc);
    expect(runAllowWritePaths(config)).toEqual([]);
    expect(ignored.join("\n")).toMatch(/run\.allowWritePaths/);
  });

  it("loadPolicy: a project file cannot add to (or replace) the user's exemptions", () => {
    const { ws, l } = wsSetup({ git: false, userPolicy: { run: { allowWritePaths: ["build"] } } });
    writeFileSync(join(ws, ".launchsafe-firewall.json"), JSON.stringify({ version: 3, run: { allowWritePaths: ["dist"] } }));
    const pol = loadPolicy(l, [ws], process.platform, join(ws, "no-managed.json"));
    expect(runAllowWritePaths(pol.config)).toEqual(["build"]);
    expect(pol.ignored.join("\n")).toMatch(/run\.allowWritePaths/);
  });

  it("an agent cannot write the user policy (Write tool, shell redirect, policy init/migrate): FW-TAMPER", () => {
    const pol = "/Users/dev/.launchsafe-firewall/policy.json";
    const w = decideTool("Write", { file_path: pol, content: JSON.stringify({ version: 3, run: { allowWritePaths: ["."] } }) });
    expect(w.verdict, explain(w)).toBe("deny");
    for (const cmd of [`echo '{"version":3,"run":{"allowWritePaths":["."]}}' > ~/.launchsafe-firewall/policy.json`, "launchsafe-firewall policy init", "launchsafe-firewall policy migrate", "python3 -c \"open('/Users/dev/.launchsafe-firewall/policy.json','w').write('{}')\""]) {
      const d = bash(cmd);
      expect(d.verdict, `${cmd}: ${explain(d)}`).not.toBe("allow");
    }
  });

  it("an agent cannot start run (so cannot pick --allow-write or --git-init either)", () => {
    expect(isReadOnlyInvocation(["run", "--", "sh"])).toBe(false);
    expect(isReadOnlyInvocation(["run", "--git-init", "--", "sh"])).toBe(false);
    const d = bash("launchsafe-firewall run --git-init -- sh -c true");
    expect(d.verdict, explain(d)).toBe("deny");
  });

  it("even '.', '~' and '/' never exempt the fixed list, .git's files or the firewall's directory", () => {
    const { home, ws, l } = wsSetup({ git: true });
    mkdirSync(join(ws, "scripts"));
    writeFileSync(join(ws, "scripts", "srv.js"), "");
    writeFileSync(join(ws, ".mcp.json"), JSON.stringify({ mcpServers: { s: { command: "node", args: ["scripts/srv.js", ".git/config", ".claude/settings.json"] } } }));
    mkdirSync(join(ws, ".claude"));
    writeFileSync(join(ws, ".claude", "settings.json"), "{}");
    const p = protectedPaths(l, ws, home, process.platform, [".", "~", "/"]);
    for (const must of [join(ws, ".git", "config"), join(ws, ".git", "hooks"), join(ws, ".git", "commondir"), join(ws, ".claude", "settings.json"), join(ws, ".mcp.json"), join(ws, ".launchsafe-firewall.json"), l.home]) expect(p.readOnly, must).toContain(must);
    expect(p.unreadable).toContain(l.keys);
    // The one thing the exemption is for: the script itself.
    expect(p.exempted).toContain(join(ws, "scripts", "srv.js"));
  });

  // FA1: workspaceCodeEntries keeps the FIRST entry per path, and agent-settings scripts are collected before nested
  // repositories, so a nested repository's `.git` pointer (or its .git/config) that `.mcp.json` happens to name in
  // its args is tagged "script", and an allowWritePaths entry covering that directory exempts it, contrary to
  // "never git's files" (docs/policy.md). A repository's .mcp.json is outside content.
  it("FA1: a nested repository's .git file stays read-only even when .mcp.json names it and allowWritePaths covers its directory", () => {
    const { home, ws, l } = wsSetup({ git: true });
    mkdirSync(join(ws, "vendor", "lib"), { recursive: true });
    writeFileSync(join(ws, "vendor", "lib", ".git"), "gitdir: ../../.git/modules/lib\n");
    writeFileSync(join(ws, ".mcp.json"), JSON.stringify({ mcpServers: { s: { command: "node", args: ["vendor/lib/server.js", "--repo", "vendor/lib/.git"] } } }));
    const p = protectedPaths(l, ws, home, process.platform, ["vendor"]);
    expect(p.readOnly).toContain(join(ws, "vendor", "lib", ".git"));
  });

  it("control for FA1: without the .mcp.json mention the nested .git file is read-only despite the exemption", () => {
    const { home, ws, l } = wsSetup({ git: true });
    mkdirSync(join(ws, "vendor", "lib"), { recursive: true });
    writeFileSync(join(ws, "vendor", "lib", ".git"), "gitdir: ../../.git/modules/lib\n");
    const p = protectedPaths(l, ws, home, process.platform, ["vendor"]);
    expect(p.readOnly).toContain(join(ws, "vendor", "lib", ".git"));
  });
});

// ---------------------------------------------------------------------------------------------------------
// RN4 residue: scripts the agent settings run, before they exist.
// ---------------------------------------------------------------------------------------------------------
describe("scripts named by agent settings (RN4)", () => {
  it("a missing ./script or *.sh hook is protected before it exists", () => {
    const { home, ws, l } = wsSetup({ git: true });
    mkdirSync(join(ws, ".claude"));
    writeFileSync(join(ws, ".claude", "settings.json"), JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "./tools/guard" }, { type: "command", command: '"$CLAUDE_PROJECT_DIR"/.claude/hooks/check.sh' }] }] } }));
    const p = protectedPaths(l, ws, home, process.platform);
    expect(p.readOnly).toContain(join(ws, "tools", "guard"));
    expect(p.readOnly).toContain(join(ws, ".claude", "hooks", "check.sh"));
  });

  // FA2: the canonical Claude Code hook form is `"$CLAUDE_PROJECT_DIR"/.claude/hooks/<name>`. Its first word is the
  // program by definition, yet a missing one without a script extension is not protected (only *.sh-like names or
  // a leading ./ are), and `.claude/hooks/` is not on the fixed list: the agent creates it inside run and the next
  // session runs it outside the sandbox (the RN4 scenario with an extensionless name).
  it("FA2: a missing extensionless hook named as \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/guard is protected before it exists", () => {
    const { home, ws, l } = wsSetup({ git: true });
    mkdirSync(join(ws, ".claude"));
    writeFileSync(join(ws, ".claude", "settings.json"), JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: '"$CLAUDE_PROJECT_DIR"/.claude/hooks/guard' }] }] } }));
    const p = protectedPaths(l, ws, home, process.platform);
    expect(p.readOnly).toContain(join(ws, ".claude", "hooks", "guard"));
  });
});

// ---------------------------------------------------------------------------------------------------------
// Live sandbox (sandbox-exec here; bubblewrap where available).
// ---------------------------------------------------------------------------------------------------------
describe.skipIf(sb.kind === "none")(`run, live (${sb.kind})`, () => {
  it("a project policy cannot exempt build output an MCP server runs; the person's user policy can", async () => {
    const mk = (userPolicy?: Record<string, unknown>) => {
      const s = wsSetup({ git: true, ...(userPolicy !== undefined ? { userPolicy } : {}) });
      mkdirSync(join(s.ws, "dist"));
      writeFileSync(join(s.ws, "dist", "index.js"), "// built\n");
      writeFileSync(join(s.ws, ".mcp.json"), JSON.stringify({ mcpServers: { dev: { command: "node", args: ["dist/index.js"] } } }));
      return s;
    };
    const a = mk();
    writeFileSync(join(a.ws, ".launchsafe-firewall.json"), JSON.stringify({ version: 3, run: { allowWritePaths: ["dist"] } }));
    const ra = await codes(a.opts(["/bin/sh", "-c", "echo pwned > dist/index.js 2>/dev/null; echo W=$?"]));
    expect(ra.W).not.toBe("0");
    expect(readFileSync(join(a.ws, "dist", "index.js"), "utf8")).toBe("// built\n");
    const b = mk({ run: { allowWritePaths: ["dist"] } });
    const rb = await codes(b.opts(["/bin/sh", "-c", "echo rebuilt > dist/index.js; echo W=$?; echo x > .mcp.json 2>/dev/null; echo M=$?"]));
    expect(rb.W).toBe("0");
    expect(rb.M).not.toBe("0");
  });

  it("--git-init: git init runs before the sandbox, and the new .git's hooks, config and commondir are read-only inside", async () => {
    const { ws, opts } = wsSetup({ git: false });
    const r = await codes(opts(["/bin/sh", "-c", "mkdir -p .git/hooks 2>/dev/null; printf '#!/bin/sh\\n' > .git/hooks/pre-commit 2>/dev/null; echo H=$?; echo '[core]' >> .git/config 2>/dev/null; echo C=$?; echo ../evil > .git/commondir 2>/dev/null; echo D=$?; mv .git .git2 2>/dev/null; echo R=$?"], { gitInit: true }));
    expect(existsSync(join(ws, ".git", "HEAD"))).toBe(true);
    expect(r.H).not.toBe("0");
    expect(r.C).not.toBe("0");
    expect(r.D).not.toBe("0");
    expect(r.R).not.toBe("0");
    expect(existsSync(join(ws, ".git", "hooks", "pre-commit"))).toBe(false);
    // What git init created holds no program that runs: only the template's *.sample hooks.
    const hooks = existsSync(join(ws, ".git", "hooks")) ? readdirSync(join(ws, ".git", "hooks")) : [];
    expect(hooks.filter((h) => !h.endsWith(".sample"))).toEqual([]);
  });

  it("--git-init with an existing .git (even a dangling symlink) does not run git init", async () => {
    const { ws, opts } = wsSetup({ git: false });
    symlinkSync(join(ws, "nowhere"), join(ws, ".git"));
    const warned: string[] = [];
    await runSandboxed(opts(["/bin/sh", "-c", "true"], { gitInit: true, warn: (s) => warned.push(s) }));
    expect(warned.join("\n")).toMatch(/already has \.git/);
    expect(lstatSync(join(ws, ".git")).isSymbolicLink()).toBe(true);
    expect(existsSync(join(ws, "nowhere"))).toBe(false);
  });

  it("without --git-init, .git cannot be created inside the run", async () => {
    const { ws, opts } = wsSetup({ git: false });
    const r = await codes(opts(["/bin/sh", "-c", "git init -q . >/dev/null 2>&1; echo I=$?; mkdir .git 2>/dev/null; echo M=$?"]));
    expect(r.I).not.toBe("0");
    expect(r.M).not.toBe("0");
    expect(existsSync(join(ws, ".git"))).toBe(false);
  });

  it("RN1: .git/commondir cannot be written or created (missing one included)", async () => {
    const { ws, opts } = wsSetup({ git: true });
    rmSync(join(ws, ".git", "commondir"), { force: true });
    const r = await codes(opts(["/bin/sh", "-c", "echo ../evil > .git/commondir 2>/dev/null; echo D=$?; ln -s ../evil .git/commondir 2>/dev/null; echo L=$?"]));
    expect(r.D).not.toBe("0");
    expect(r.L).not.toBe("0");
    expect(existsSync(join(ws, ".git", "commondir"))).toBe(false);
  });

  it("RN7/RN8: skills, agents, commands, .devcontainer and .vscode/settings.json cannot be created or changed", async () => {
    const { ws, opts } = wsSetup({ git: true });
    mkdirSync(join(ws, ".claude"));
    // With its settings files present, so Linux does not bind .claude read-only whole (the rule for a missing
    // settings file, docs/run.md): the skills and agents mounts alone refuse, and the control write lands.
    writeFileSync(join(ws, ".claude", "settings.json"), "{}");
    writeFileSync(join(ws, ".claude", "settings.local.json"), "{}");
    mkdirSync(join(ws, ".vscode"));
    const r = await codes(opts(["/bin/sh", "-c", "mkdir -p .claude/skills/x 2>/dev/null; echo S=$?; mkdir .claude/agents 2>/dev/null; echo A=$?; mkdir .devcontainer 2>/dev/null; echo D=$?; echo '{}' > .vscode/settings.json 2>/dev/null; echo V=$?; echo ok > .claude/notes.md; echo N=$?"]));
    expect(r.S).not.toBe("0");
    expect(r.A).not.toBe("0");
    expect(r.D).not.toBe("0");
    expect(r.V).not.toBe("0");
    expect(r.N).toBe("0");
    expect(readFileSync(join(ws, ".claude", "notes.md"), "utf8")).toBe("ok\n");
    for (const p of [".claude/skills", ".claude/agents", ".devcontainer", ".vscode/settings.json"]) expect(existsSync(join(ws, p)), p).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------------------
// Concurrent runs and stand-ins (unit level: the registry and the readers; bubblewrap itself is Linux-only).
// ---------------------------------------------------------------------------------------------------------
describe("concurrent runs: a directory reads as an absent policy only with proof", () => {
  it("an empty directory at the project policy path with no claim fails closed (error, not absent)", () => {
    const { ws, l } = wsSetup({ git: false });
    mkdirSync(join(ws, ".launchsafe-firewall.json"));
    expect(() => readText(join(ws, ".launchsafe-firewall.json"))).toThrow();
    const pol = loadPolicy(l, [ws], process.platform, join(ws, "no-managed.json"));
    expect(pol.error).toBeDefined();
  });

  it("a non-empty directory there is never absent, even with a live claim", () => {
    const root = mkdtempSync(join(testRoot(), "fa-reg-"));
    const ws = realpathSync(mkdtempSync(join(testRoot(), "fa-ws-")));
    const p = join(ws, ".launchsafe-firewall.json");
    mkdirSync(p);
    writeFileSync(join(p, "x"), "");
    const reg = mountRegistry(root);
    reg.claim([p]);
    expect(runMountPoint(p, root)).toBe(false);
    reg.release();
    expect(existsSync(join(p, "x"))).toBe(true);
  });

  it("a claim by a process that has exited is not proof", () => {
    const root = mkdtempSync(join(testRoot(), "fa-reg-"));
    const ws = realpathSync(mkdtempSync(join(testRoot(), "fa-ws-")));
    const p = join(ws, ".launchsafe-firewall.json");
    mkdirSync(p);
    const dead = mountRegistry(root, 2 ** 22 + 12345);
    dead.claim([p]);
    expect(runMountPoint(p, root)).toBe(false);
  });

  // FA3: "proof that a live run holds it" is a file named after ANY live pid in a registry directory under
  // $TMPDIR, writable by the same user with no check of owner, mode or that the pid is a run. pid 1 is always alive.
  // Inside a run TMPDIR is the run's own writable directory, so the registry the hooks consult there is the agent's.
  // No loosening today (replacing an existing policy with a directory is itself guarded), but it is not proof.
  it("FA3: a forged claim (a file named 1 in a group/world-writable registry directory) is not proof of a live run", () => {
    const root = mkdtempSync(join(testRoot(), "fa-reg-"));
    chmodSync(root, 0o777);
    const ws = realpathSync(mkdtempSync(join(testRoot(), "fa-ws-")));
    const p = join(ws, ".launchsafe-firewall.json");
    mkdirSync(p);
    const key = join(root, createHash("sha256").update(p).digest("hex").slice(0, 32));
    mkdirSync(key, { recursive: true });
    writeFileSync(join(key, "1"), p);
    expect(runMountPoint(p, root)).toBe(false);
  });

  it("a release never removes a mount point another live run still uses, and never one that is no longer empty", () => {
    const root = mkdtempSync(join(testRoot(), "fa-reg-"));
    const ws = realpathSync(mkdtempSync(join(testRoot(), "fa-ws-")));
    const a = join(ws, ".mcp.json");
    const b = join(ws, ".husky");
    mkdirSync(a);
    mkdirSync(b);
    const r1 = mountRegistry(root, process.pid);
    const r2 = mountRegistry(root, process.ppid);
    r1.claim([a, b]);
    r2.claim([a]);
    writeFileSync(join(b, "pre-commit"), "#!/bin/sh\n");
    expect(r1.release()).toEqual([]);
    expect(existsSync(a)).toBe(true);
    expect(existsSync(join(b, "pre-commit"))).toBe(true);
  });
});

describe("Linux file stand-ins (.git/commondir and friends)", () => {
  it("the stand-ins hold exactly what git assumes for an absent file, so one left behind loosens nothing", async () => {
    const { GIT_DIR_FILES } = await import("../../src/engine/run-profile.js");
    expect(GIT_DIR_FILES).toEqual({ commondir: ".\n", config: "", "config.worktree": "" });
    // git reads a left-over commondir of "." as the git directory itself: the hooks are still .git/hooks.
    const { ws, env } = wsSetup({ git: true });
    writeFileSync(join(ws, ".git", "commondir"), ".\n");
    const out = execFileSync("git", ["-C", ws, "rev-parse", "--git-common-dir"], { env, encoding: "utf8" }).trim();
    expect(realpathSync(resolve(ws, out))).toBe(realpathSync(join(ws, ".git")));
  });

  it("a changed, hard-linked or symlinked stand-in is not treated as one (not shared, not removed)", () => {
    const ws = realpathSync(mkdtempSync(join(testRoot(), "fa-ws-")));
    mkdirSync(join(ws, ".git"));
    const p = join(ws, ".git", "commondir");
    writeFileSync(p, ".\n");
    expect(placeholderFile(p)).toBe(true);
    writeFileSync(p, "../evil\n");
    expect(placeholderFile(p)).toBe(false);
    writeFileSync(p, ".\n");
    execFileSync("ln", [p, join(ws, "hard")]);
    expect(placeholderFile(p)).toBe(false);
    rmSync(p);
    rmSync(join(ws, "hard"));
    writeFileSync(join(ws, "dot"), ".\n");
    symlinkSync(join(ws, "dot"), p);
    expect(placeholderFile(p)).toBe(false);
    const root = mkdtempSync(join(testRoot(), "fa-reg-"));
    const reg = mountRegistry(root);
    reg.claim([p]);
    expect(reg.release()).toEqual([]);
    expect(lstatSync(p).isSymbolicLink()).toBe(true);
  });

  it("a stand-in that an agent changed while the run lasted is left for the person, not removed", () => {
    const ws = realpathSync(mkdtempSync(join(testRoot(), "fa-ws-")));
    mkdirSync(join(ws, ".git"));
    const p = join(ws, ".git", "commondir");
    writeFileSync(p, ".\n");
    const root = mkdtempSync(join(testRoot(), "fa-reg-"));
    const reg = mountRegistry(root);
    reg.claim([p]);
    writeFileSync(p, "../evil\n");
    expect(reg.release()).toEqual([]);
    expect(readFileSync(p, "utf8")).toBe("../evil\n");
  });
});

// ---------------------------------------------------------------------------------------------------------
// Install lifecycle: symlink write-through targets, --restore-backup, doctor --repair-state.
// ---------------------------------------------------------------------------------------------------------
describe("lifecycle: symlink write-through and restore", () => {
  let l: Lab;
  beforeEach(() => {
    l = lab();
  });
  afterEach(() => l.cleanup());

  it("precondition: an agent cannot replace a registered settings file with a symlink (FW-TAMPER)", () => {
    for (const cmd of ["ln -sf ~/.ssh/id_ed25519 ~/.claude/settings.json", "ln -sf ~/.launchsafe-firewall/policy.json ~/.gemini/settings.json"]) {
      const d = bash(cmd);
      expect(d.verdict, `${cmd}: ${explain(d)}`).toBe("deny");
    }
  });

  it("install through a symlink to a file the person does not own, or to a directory, is refused and nothing is written", () => {
    write(join(l.home, "dotfiles", "x"), "");
    mkdirSync(join(l.home, ".claude"), { recursive: true });
    symlinkSync(join(l.home, "dotfiles"), l.file("claude"));
    const r = cli(l, ["install", "--no-approver"]);
    expect(r.code).not.toBe(0);
    expect(lstatSync(l.file("claude")).isSymbolicLink()).toBe(true);
  });

  it("install keeps a 0640 settings file's mode and a new file is 0600 (LC7)", () => {
    write(l.file("claude"), "{}\n");
    chmodSync(l.file("claude"), 0o640);
    expect(cli(l, ["install", "--no-approver"]).code).toBe(0);
    expect(statSync(l.file("claude")).mode & 0o777).toBe(0o640);
    expect(cli(l, ["install", "--agent", "gemini", "--no-approver"]).code).toBe(0);
    expect(statSync(l.file("gemini")).mode & 0o777).toBe(0o600);
  });

  // FA4: writeTarget() checks only "regular file, owned by the person". It does not refuse a target inside the
  // firewall's own directory (or ~/.ssh and the other credential stores). If a settings file has become a link to
  // such a file, `uninstall --restore-backup` writes the backup over it: editsSinceInstall() reads the target, finds
  // it is not JSON (or differs) and with a non-JSON target counts 0 differences, so it does not even ask.
  it("FA4: --restore-backup does not write through a settings symlink into the firewall's own directory", () => {
    write(l.file("claude"), '{"model":"opus"}\n');
    expect(cli(l, ["install", "--no-approver"]).code).toBe(0);
    const policy = join(l.fwHome, "policy.json");
    write(policy, JSON.stringify({ version: 3, denyHosts: ["evil.example"] }));
    rmSync(l.file("claude"));
    symlinkSync(policy, l.file("claude"));
    const before = readFileSync(policy, "utf8");
    person(l, ["uninstall", "--restore-backup", "--force"]);
    expect(readFileSync(policy, "utf8")).toBe(before);
  });

  it("FA4b: --restore-backup through a settings symlink to ~/.ssh does not overwrite the key or copy it out beside the settings", () => {
    write(l.file("claude"), '{"model":"opus"}\n');
    expect(cli(l, ["install", "--no-approver"]).code).toBe(0);
    const key = join(l.home, ".ssh", "id_test");
    write(key, "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n");
    chmodSync(key, 0o600);
    rmSync(l.file("claude"));
    symlinkSync(key, l.file("claude"));
    person(l, ["uninstall", "--restore-backup"]);
    expect(readFileSync(key, "utf8")).toContain("PRIVATE KEY");
    const copies = readdirSync(join(l.home, ".claude")).filter((n) => n.includes("before-restore"));
    expect(copies.map((n) => readFileSync(join(l.home, ".claude", n), "utf8")).join("")).not.toContain("PRIVATE KEY");
  });

  it("--restore-backup with edits since install asks first and writes nothing on a no (LC3)", () => {
    write(l.file("claude"), '{"model":"opus"}\n');
    expect(cli(l, ["install", "--no-approver"]).code).toBe(0);
    const doc = JSON.parse(readFileSync(l.file("claude"), "utf8")) as Record<string, unknown>;
    doc.theme = "dark";
    write(l.file("claude"), `${JSON.stringify(doc, null, 2)}\n`);
    const before = readFileSync(l.file("claude"), "utf8");
    const r = person(l, ["uninstall", "--restore-backup"], [["Restore the backup anyway", "no"]]);
    expect(r.code).not.toBe(0);
    expect(readFileSync(l.file("claude"), "utf8")).toBe(before);
    expect(readdirSync(join(l.home, ".claude")).filter((n) => n.includes("before-restore"))).toEqual([]);
  });

  it("--restore-backup is refused without a terminal (an agent or a script), nothing changes", () => {
    write(l.file("claude"), '{"model":"opus"}\n');
    expect(cli(l, ["install", "--no-approver"]).code).toBe(0);
    const before = readFileSync(l.file("claude"), "utf8");
    const r = cli(l, ["uninstall", "--restore-backup", "--force"]);
    expect(r.code).not.toBe(0);
    expect(readFileSync(l.file("claude"), "utf8")).toBe(before);
  });
});

describe("lifecycle: doctor --repair-state is person-only", () => {
  let l: Lab;
  beforeEach(() => {
    l = lab();
  });
  afterEach(() => l.cleanup());

  it("an agent running it is FW-TAMPER (every spelling the parser accepts)", () => {
    expect(isReadOnlyInvocation(["doctor", "--repair-state"])).toBe(false);
    expect(isReadOnlyInvocation(["doctor", "--project", "/x", "--repair-state"])).toBe(false);
    expect(isReadOnlyInvocation(["doctor"])).toBe(true);
    for (const cmd of ["launchsafe-firewall doctor --repair-state", "npx launchsafe-firewall doctor --repair-state", "launchsafe-firewall doctor --project . --repair-state"]) {
      const d = bash(cmd);
      expect(d.verdict, `${cmd}: ${explain(d)}`).toBe("deny");
    }
  });

  it("without a terminal it is refused and install.json stays as it is", () => {
    write(l.file("claude"), "{}\n");
    expect(cli(l, ["install", "--no-approver"]).code).toBe(0);
    write(join(l.fwHome, "install.json"), "garbage");
    const r = cli(l, ["doctor", "--repair-state"]);
    expect(r.code).not.toBe(0);
    expect(readFileSync(join(l.fwHome, "install.json"), "utf8")).toBe("garbage");
    expect(readdirSync(l.fwHome).some((n) => n.startsWith("install.json.damaged-"))).toBe(false);
  });

  it("inside an agent session's terminal it is refused", () => {
    write(join(l.fwHome, "install.json"), "garbage");
    const r = person(l, ["doctor", "--repair-state"], [], { env: { CLAUDECODE: "1" } });
    expect(r.code).not.toBe(0);
    expect(readFileSync(join(l.fwHome, "install.json"), "utf8")).toBe("garbage");
  });
});

describe("FA4: where a settings symlink may be written through (unit)", () => {
  it("refuses the firewall's directory, credential stores, another agent's configuration and anything outside the home", async () => {
    const { linkTargetProblem } = await import("../../src/runtime/fsutil.js");
    const home = realpathSync(tempHome("fa4-"));
    const env = { ...process.env, LAUNCHSAFE_FIREWALL_HOME: join(home, ".launchsafe-firewall"), CLAUDE_CONFIG_DIR: "", CODEX_HOME: "", GEMINI_CLI_HOME: "" };
    const o = { home, env };
    const link = join(home, ".claude", "settings.json");
    expect(linkTargetProblem(link, join(home, ".launchsafe-firewall", "policy.json"), o)).toMatch(/firewall's own directory/);
    expect(linkTargetProblem(link, join(home, ".ssh", "id_ed25519"), o)).toMatch(/credential store/);
    expect(linkTargetProblem(link, join(home, ".gnupg", "x"), o)).toMatch(/credential store/);
    expect(linkTargetProblem(link, join(home, ".gemini", "settings.json"), o)).toMatch(/another agent's configuration \(gemini\)/);
    expect(linkTargetProblem(link, "/etc/hosts", o)).toMatch(/outside your home/);
    // A dotfiles repository, or the same agent's own directory, is fine.
    expect(linkTargetProblem(link, join(home, "dotfiles", "claude", "settings.json"), o)).toBeNull();
    expect(linkTargetProblem(link, join(home, ".claude", "shared.json"), o)).toBeNull();
    // A project's .claude/settings.json linking into ~/.codex is another agent's.
    expect(linkTargetProblem(join(home, "proj", ".claude", "settings.json"), join(home, ".codex", "hooks.json"), o)).toMatch(/codex/);
  });
});
