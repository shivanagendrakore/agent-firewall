/**
 * Self-protection for the local API (docs/api.md): an agent's tool call that starts, stops or reconfigures
 * the API, or runs the token and tool-registry commands, is FW-TAMPER, as `relay run` is. Every command here
 * is a string the engine judges; none is executed.
 */

import { describe, expect, it } from "vitest";
import { isReadOnlyInvocation } from "../../src/cliargs.js";
import { bash, explain, HOME, run } from "../helpers.js";

const FW = `${HOME}/.launchsafe-firewall`;

describe("the API's commands from an agent's tool call", () => {
  const commands = [
    "launchsafe-firewall serve --api",
    "launchsafe-firewall serve --api --listen 127.0.0.1:8787",
    "nohup launchsafe-firewall serve --api &",
    "npx @launchsafe/agent-firewall serve --api",
    "launchsafe-firewall api token add bot",
    "launchsafe-firewall api token list",
    "launchsafe-firewall api token list --json",
    "launchsafe-firewall api token revoke bot",
    "launchsafe-firewall api tools set bot tools.json",
    "launchsafe-firewall api tools show bot",
  ];
  for (const c of commands) {
    it(`${c} is FW-TAMPER, trusted or not`, () => {
      for (const tainted of [false, true]) {
        const d = bash(c, { tainted });
        expect(d.verdict, explain(d)).toBe("deny");
        expect(d.rules).toContain("FW-TAMPER");
      }
    });
  }

  it("only --help is read-only", () => {
    expect(isReadOnlyInvocation(["serve", "--help"])).toBe(true);
    expect(isReadOnlyInvocation(["api", "token", "list", "--help"])).toBe(true);
    expect(bash("launchsafe-firewall serve --help").verdict).toBe("allow");
    for (const w of [["serve", "--api"], ["api", "token", "list"], ["api", "tools", "show", "bot"]]) expect(isReadOnlyInvocation(w), w.join(" ")).toBe(false);
  });
});

describe("stopping or rewiring the API from an agent", () => {
  for (const c of ['pkill -f "serve --api"', "pkill -f 'launchsafe-firewall serve'", "killall launchsafe-firewall", `pkill -f ${FW}/api.sock`]) {
    it(c, () => {
      const d = bash(c);
      expect(d.rules, explain(d)).toContain("FW-TAMPER");
    });
  }
  for (const c of [`rm ${FW}/api.sock`, `rm -f ${FW}/api/tokens.json`, `echo '{}' > ${FW}/api/tokens.json`, `cp evil.json ${FW}/api/tools/bot.json`, `mv ${FW}/api ${FW}/api.old`]) {
    it(c, () => {
      const d = bash(c);
      expect(d.verdict, explain(d)).toBe("deny");
      expect(d.rules).toContain("FW-TAMPER");
    });
  }
  it("writing a registry or token file with the agent's own tools is FW-TAMPER", () => {
    for (const [tool, input] of [
      ["Write", { file_path: `${FW}/api/tools/bot.json`, content: '{"tools":{}}' }],
      ["Edit", { file_path: `${FW}/api/tokens.json`, old_string: "a", new_string: "b" }],
    ] as const) {
      const d = run(tool, input);
      expect(d.verdict, explain(d)).toBe("deny");
      expect(d.rules).toContain("FW-TAMPER");
    }
  });
  it("an ordinary pkill is not", () => {
    expect(bash("pkill -f 'npm run serve'").rules).not.toContain("FW-TAMPER");
  });
});
