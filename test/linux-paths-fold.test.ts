/**
 * Linux and WSL paths (portability audit item I1), continued from linux-paths.test.ts: the folds that only add
 * protection outside the path lists. Removing a directory that holds a wrapped MCP configuration, stopping the
 * firewall's processes, an unseen patch when the workspace holds registered settings, the CLAUDE.md files nested in
 * the workspace, and the CLI's compile-cache guard all compare ignoring case on every platform
 * (PROTECTION_FOLDS_CASE, src/engine/canonical.ts). Every context below is a case-sensitive one
 * (`caseInsensitive: false`, what Node reports on Linux), where a different spelling used to slip past.
 *
 * Paths and commands are data; nothing is read or run (the CLI's source is read as text).
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { bash, explain, HOME, REPO, run, WS, type RunOpts } from "./helpers.js";

/** The verdicts that stop an action without a person: held, asked or denied. */
const NOT_ALLOWED = ["deny", "ask", "queue"];

function tamper(d: ReturnType<typeof run>, what: string): void {
  expect(d.verdict, `${what}: ${explain(d)}`).toBe("deny");
  expect(d.rules, `${what}: ${explain(d)}`).toContain("FW-TAMPER");
}

describe("I1: a directory holding a wrapped MCP client configuration, removed under another spelling", () => {
  const path = `${HOME}/.config/Claude/claude_desktop_config.json`;
  // The wrapped file cannot be read, so only its recorded path can tell that the directory holds it.
  const c: RunOpts = { ctx: { caseInsensitive: false, gatewayConfigs: [{ path, wrapped: {} }], readFile: () => null } };

  it("is tampering: the wrapped file goes with the directory", () => {
    for (const cmd of ["rm -rf ~/.config/claude", `rm -rf ${HOME}/.CONFIG/CLAUDE`]) tamper(bash(cmd, c), cmd);
  });
  it("control: a sibling whose name only starts the same does not hold it", () => {
    const d = bash("rm -rf ~/.config/claude-notes", c);
    expect(d.rules, explain(d)).not.toContain("FW-TAMPER");
  });
});

describe("I1: stopping the firewall's processes is matched ignoring case", () => {
  // A checkout whose path does not contain the command name, so the CLI file is matched on its own.
  const c: RunOpts = { ctx: { caseInsensitive: false, firewallInstallDir: "/Users/dev/src/agent-firewall" } };

  it("its CLI file, named in full, within a command line or by its end, in another case", () => {
    for (const cmd of ["pkill -f /USERS/DEV/SRC/AGENT-FIREWALL/DIST/CLI.JS", 'pkill -f "NODE /Users/Dev/Src/Agent-Firewall/dist/cli.js HOOK"', "pkill -f Agent-Firewall/Dist/CLI.js"]) tamper(bash(cmd, c), cmd);
  });
  it("pkill -i and killall -I match whatever case they are given: the command name, the marker, the relay and the local API", () => {
    for (const cmd of [
      "pkill -i -f LAUNCHSAFE-FIREWALL",
      "killall -I Launchsafe-Firewall",
      "pkill -i -f launchsafe_firewall_hook",
      'pkill -i -f "RELAY RUN"',
      'pkill -i -f "SERVE --API"',
      "pkill -i -f /x/API.SOCK",
    ])
      tamper(bash(cmd, c), cmd);
  });
  it("controls: other processes in any case are not the firewall's", () => {
    for (const cmd of ["pkill -i -f MY-SERVER", "killall -I Firefox", "pkill -f 'NPM RUN SERVE'", "kill %1"]) {
      const d = bash(cmd, c);
      expect(d.rules, `${cmd}: ${explain(d)}`).not.toContain("FW-TAMPER");
    }
  });
});

describe("I1: a patch the firewall cannot see, with registered settings in the workspace under another spelling", () => {
  it("is flagged in a session that has read nothing outside", () => {
    for (const settings of ["/Users/dev/PROJ/.claude/settings.json", `${WS}/.claude/settings.json`]) {
      const d = bash("cat x | git apply", { ctx: { caseInsensitive: false, registeredSettings: [settings] } });
      expect(NOT_ALLOWED, `${settings}: ${explain(d)}`).toContain(d.verdict);
      expect(d.rules, `${settings}: ${explain(d)}`).toContain("FW-UNCLASSIFIABLE");
    }
  });
  it("control: registered settings outside the workspace leave it allowed", () => {
    const d = bash("cat x | git apply", { ctx: { caseInsensitive: false, registeredSettings: [`${HOME}/.claude/settings.json`] } });
    expect(d.verdict, explain(d)).toBe("allow");
  });
});

describe("I1: a CLAUDE.md nested in the workspace, reached under another spelling of the workspace", () => {
  const nested = (dir: string): RunOpts["ctx"] => ({ caseInsensitive: false, readFile: (p: string) => (p === `${dir}/CLAUDE.md` ? "@notes.md\n" : null) });

  it("protects the file it imports: a write after outside content is held", () => {
    const d = run("Write", { file_path: "/Users/dev/PROJ/sub/notes.md", content: "x" }, { tainted: true, ctx: nested("/Users/dev/PROJ/sub") });
    expect(NOT_ALLOWED, explain(d)).toContain(d.verdict);
    expect(d.rules, explain(d)).toContain("FW-INSTRUCTIONS-HELD");
  });
  it("control: the same layout outside the workspace is an outside write, not an instruction file", () => {
    const d = run("Write", { file_path: "/Users/dev/other/sub/notes.md", content: "x" }, { tainted: true, ctx: nested("/Users/dev/other/sub") });
    expect(d.rules, explain(d)).not.toContain("FW-INSTRUCTIONS-HELD");
    expect(d.rules, explain(d)).toContain("FW-OUTSIDE-WRITE");
  });
});

describe("I1: the CLI's compile-cache guard", () => {
  // Running the guard against another spelling of the real home would need that spelling to exist, and would make the
  // cache there if the guard failed, so it is not run here: the source shows cli.ts uses the shared insideRealHome
  // (which folds case on every platform, tested in linux-paths.test.ts), not a copy of its own.
  it("is the shared insideRealHome from real-home.ts", () => {
    const cli = readFileSync(join(REPO, "src", "cli.ts"), "utf8");
    expect(cli).toContain('import { insideRealHome } from "./real-home.js";');
    expect(cli).toMatch(/if \(testing && insideRealHome\(home\)\) return;/);
    expect(cli).not.toMatch(/function insideRealHome/);
  });
});
