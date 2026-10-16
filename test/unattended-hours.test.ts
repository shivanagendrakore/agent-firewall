/**
 * unattendedHours through the whole hook: with the clock injected, a question asked inside the configured
 * hours is held for a person (queue) instead of asked; the hours may run across midnight; and a project
 * policy cannot remove the person's hours (it can only add its own). Commands are only analysed, never run.
 * Temporary homes only; the times are local, as inUnattendedHours reads them.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { adapterFor } from "../src/adapters/index.js";
import { runPreTool, type HookEnv } from "../src/hook/pipeline.js";
import { inUnattendedHours } from "../src/policy.js";
import { layout, PROJECT_POLICY_FILE } from "../src/runtime/layout.js";
import { tempHome } from "./helpers.js";

const at = (h: number, m = 0): Date => new Date(2026, 9, 14, h, m, 0);
const ASK = "sudo systemctl restart nginx";

function setup(prefix: string, user: unknown, project?: unknown) {
  const home = tempHome(prefix);
  const ws = join(home, "proj");
  mkdirSync(ws, { recursive: true });
  const l = layout(join(home, ".launchsafe-firewall"));
  mkdirSync(l.home, { recursive: true });
  if (user !== undefined) writeFileSync(l.policy, JSON.stringify(user));
  if (project !== undefined) writeFileSync(join(ws, PROJECT_POLICY_FILE), JSON.stringify(project));
  const a = adapterFor("claude");
  let n = 0;
  return (now: Date, command = ASK) => {
    const h: HookEnv = { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, home, scratchRoots: [join(home, "scratch")], detectNonInteractive: () => false, notifyDeps: { spawn: () => undefined }, noHold: true, now };
    const ev = a.parse({ hook_event_name: "PreToolUse", session_id: `uh-${n++}`, cwd: ws, permission_mode: "default", tool_name: "Bash", tool_input: { command } });
    return runPreTool(ev, a, h, l);
  };
}

describe("unattendedHours on the hook path", () => {
  const NIGHT = { version: 3, unattendedHours: [{ from: "22:00", to: "07:00" }] };

  it("at 23:00 an ask becomes a held question; at noon it is asked", () => {
    const pre = setup("uh-a-", NIGHT);
    const night = pre(at(23));
    expect(night.outcome.verdict).toBe("queue");
    expect(night.decision?.rules).toContain("FW-PRIVILEGE");
    expect(night.item).not.toBeNull();
    expect(night.item?.unattended).toBe(true);
    const noon = pre(at(12));
    expect(noon.outcome.verdict).toBe("ask");
    expect(noon.item).toBeNull();
  });

  it("the hours run across midnight: 02:00 and 06:59 are inside, 07:00 and 21:59 are not", () => {
    const pre = setup("uh-b-", NIGHT);
    expect(pre(at(2)).outcome.verdict).toBe("queue");
    expect(pre(at(6, 59)).outcome.verdict).toBe("queue");
    expect(pre(at(7)).outcome.verdict).toBe("ask");
    expect(pre(at(21, 59)).outcome.verdict).toBe("ask");
    expect(pre(at(22)).outcome.verdict).toBe("queue");
  });

  it("an allowed action stays allowed inside the hours, and a deny stays a deny", () => {
    const pre = setup("uh-c-", NIGHT);
    expect(pre(at(23), "ls").outcome.verdict).toBe("allow");
    expect(pre(at(23), "terraform destroy").outcome.verdict).toBe("deny");
  });

  it("a project policy cannot remove the person's hours", () => {
    const pre = setup("uh-d-", NIGHT, { version: 3, unattendedHours: [] });
    expect(pre(at(23)).outcome.verdict).toBe("queue");
  });

  it("a project policy can add hours of its own", () => {
    const pre = setup("uh-e-", NIGHT, { version: 3, unattendedHours: [{ from: "12:00", to: "13:00" }] });
    expect(pre(at(12, 30)).outcome.verdict).toBe("queue");
    expect(pre(at(23)).outcome.verdict).toBe("queue");
    expect(pre(at(15)).outcome.verdict).toBe("ask");
  });

  it("without hours, 23:00 is an ordinary ask", () => {
    const pre = setup("uh-f-", undefined);
    expect(pre(at(23)).outcome.verdict).toBe("ask");
  });
});

describe("inUnattendedHours", () => {
  it("is half-open: from is inside, to is not", () => {
    const day = [{ from: "09:00", to: "17:00" }];
    expect(inUnattendedHours(day, at(9))).toBe(true);
    expect(inUnattendedHours(day, at(16, 59))).toBe(true);
    expect(inUnattendedHours(day, at(17))).toBe(false);
    expect(inUnattendedHours(day, at(8, 59))).toBe(false);
  });
  it("an empty list is never unattended", () => {
    expect(inUnattendedHours([], at(3))).toBe(false);
  });
});
