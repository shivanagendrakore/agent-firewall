/**
 * F-c, every state-changing subcommand under every way of invoking the installed CLI. The list of
 * subcommands comes from the CLI's own command table (COMMANDS, changesState), so a subcommand added
 * later (canary plant/remove, update, ...) is covered without touching this file; a subcommand the
 * table does not know yet is treated as state-changing.
 */
import { describe, expect, it } from "vitest";
import { COMMANDS, type CommandSpec } from "../src/cliargs.js";
import type { FirewallIdentity } from "../src/types.js";
import { bash, explain, HOME, type RunOpts } from "./helpers.js";

const P = "/Users/dev/src/agent-firewall";
const CLI = `${P}/dist/cli.js`;
const IDENTITY: FirewallIdentity = { cliFiles: [CLI], runtimeRoots: [`${P}/dist`, `${P}/node_modules`], runtimeFiles: [`${P}/package.json`], packageRoots: [P], nodeBinaries: [], dataRoots: [`${HOME}/.launchsafe-firewall`], binNames: ["launchsafe-firewall"], source: "hook-command" };
const LINK = `${HOME}/bin/lf`;
const realpath = (p: string): string => (p === LINK ? CLI : p);
const OPTS: RunOpts = { tainted: true, ctx: { identity: IDENTITY, firewallInstallDir: "", realpath } };

/** A valid argument list for a spec: its path plus placeholder positionals. */
function argv(s: CommandSpec): string {
  const pos = Array.from({ length: s.positionals.min }, (_, i) => (s.positionals.int === true ? "5" : `x${i}`));
  return [...s.path, ...pos].join(" ");
}

/** Every way to reach the CLI, as a function of its arguments. */
const FORMS: [string, (a: string) => string][] = [
  ["command name", (a) => `launchsafe-firewall ${a}`],
  ["absolute path to the CLI file", (a) => `${CLI} ${a}`],
  ["node on the CLI file", (a) => `node ${CLI} ${a}`],
  ["node with flags", (a) => `node --no-warnings ${CLI} ${a}`],
  ["bun on the CLI file", (a) => `bun ${CLI} ${a}`],
  ["a symlink whose target is the CLI", (a) => `${LINK} ${a}`],
  ["npx of the package", (a) => `npx @launchsafe/agent-firewall ${a}`],
  ["npx -y of a version", (a) => `npx -y @launchsafe/agent-firewall@0.2.0 ${a}`],
  ["npx -p ... command", (a) => `npx -p @launchsafe/agent-firewall launchsafe-firewall ${a}`],
  ["npm exec --", (a) => `npm exec -- @launchsafe/agent-firewall ${a}`],
  ["pnpm dlx", (a) => `pnpm dlx @launchsafe/agent-firewall ${a}`],
  ["yarn dlx", (a) => `yarn dlx @launchsafe/agent-firewall ${a}`],
  ["bunx", (a) => `bunx @launchsafe/agent-firewall ${a}`],
  ["sudo", (a) => `sudo node ${CLI} ${a}`],
  ["env", (a) => `env -i FOO=1 launchsafe-firewall ${a}`],
  ["nohup", (a) => `nohup node ${CLI} ${a} &`],
  ["timeout", (a) => `timeout 10 launchsafe-firewall ${a}`],
  ["xargs", (a) => `echo x | xargs node ${CLI} ${a}`],
  ["script", (a) => `script -q /dev/null launchsafe-firewall ${a}`],
  ["bash -c", (a) => `bash -c "node ${CLI} ${a}"`],
  ["a subshell", (a) => `(cd /tmp && launchsafe-firewall ${a})`],
];

const changing = COMMANDS.filter((s) => s.changesState && s.path[0] !== "hook");

describe("every state-changing subcommand in the command table is denied under every invocation form", () => {
  it("the table has state-changing subcommands to check", () => expect(changing.length).toBeGreaterThan(5));
  for (const s of changing) {
    for (const [form, make] of FORMS) {
      const cmd = make(argv(s));
      it(`${s.path.join(" ")} via ${form}`, () => {
        const d = bash(cmd, OPTS);
        expect(d.verdict, explain(d)).toBe("deny");
        expect(d.rules, explain(d)).toContain("FW-TAMPER");
      });
    }
  }
  it("doctor --fix (a read-only command with a state-changing flag) is denied under every form", () => {
    for (const [form, make] of FORMS) {
      const d = bash(make("doctor --fix"), OPTS);
      expect(d.verdict, `${form}: ${explain(d)}`).toBe("deny");
    }
  });
});

describe("a subcommand the table does not know yet (canary remove --all before it lands) is state-changing", () => {
  for (const [form, make] of FORMS) {
    it(form, () => {
      const d = bash(make("canary remove --all"), OPTS);
      expect(d.verdict, explain(d)).toBe("deny");
      expect(d.rules).toContain("FW-TAMPER");
    });
  }
});

describe("read-only subcommands stay allowed under every form, and --help on a changing one", () => {
  const readOnly = COMMANDS.filter((s) => !s.changesState && s.positionals.min === 0 && !s.stdin && s.path[0] !== "demo" && s.path[0] !== "check" && s.path[0] !== "explain");
  for (const [form, make] of FORMS) {
    it(form, () => {
      for (const a of [...readOnly.map(argv), "queue approve x0 --help", "uninstall -h"]) {
        const d = bash(make(a), OPTS);
        expect(d.rules, `${a}: ${explain(d)}`).not.toContain("FW-TAMPER");
      }
    });
  }
});
