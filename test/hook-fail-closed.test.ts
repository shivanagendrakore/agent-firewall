/**
 * The hook's fail-closed branches (src/hook/pipeline.ts and src/hook/claude.ts), each forced by making one
 * collaborator throw: preparing a vault substitution (deny FW-VAULT-UNSUPPORTED, no rewritten input), counting
 * the day's spending (deny FW-CAP), recording after the engine already said ask (failure() blocks with the
 * "could not finish recording" message), the email guard (the result is withheld), checking a ConfigChange
 * (blocked), and an event the adapter cannot read (blocking for a tool call, ignored otherwise). Commands are
 * only analysed, never run. Temporary homes only.
 */
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { adapterFor } from "../src/adapters/index.js";
import { claudeVerdict } from "../src/adapters/claude.js";
import { runHook } from "../src/hook/claude.js";
import { runPostTool, runPreTool, type HookEnv } from "../src/hook/pipeline.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { tempHome } from "./helpers.js";

const fail = vi.hoisted(() => ({ vault: false, prepare: "throw" as "throw" | "ok", recordDaily: false, capStopped: false, mail: false, config: false }));

vi.mock("../src/engine/decide.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/engine/decide.js")>();
  return {
    ...real,
    decide: (input: Parameters<typeof real.decide>[0]) => {
      const d = real.decide(input);
      // Stands in for an action that carries a vault reference bound to its destination.
      if (fail.vault) d.vault = { refs: ["vault://github/token"], substitute: [{ ref: "vault://github/token", name: "github", field: "token", kind: "token", via: "hook", destination: "api.github.com", binding: "github/token to api.github.com" }] };
      return d;
    },
  };
});
vi.mock("../src/hook/vault.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/hook/vault.js")>();
  return {
    ...real,
    prepareSubstitution: (...args: Parameters<typeof real.prepareSubstitution>) => {
      if (!fail.vault) return real.prepareSubstitution(...args);
      if (fail.prepare === "throw") throw new Error("the run-ticket store is not writable");
      return { updatedInput: { command: "launchsafe-firewall run --ticket t1 -- curl https://api.github.com/user" } };
    },
  };
});
vi.mock("../src/runtime/caps.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/runtime/caps.js")>();
  return {
    ...real,
    recordDaily: (...args: Parameters<typeof real.recordDaily>) => {
      if (fail.recordDaily) throw new Error("the counters file is locked");
      return real.recordDaily(...args);
    },
    capStopped: (...args: Parameters<typeof real.capStopped>) => {
      if (fail.capStopped) throw new Error("the counters file vanished");
      return real.capStopped(...args);
    },
  };
});
vi.mock("../src/runtime/mail/guard.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/runtime/mail/guard.js")>();
  return {
    ...real,
    guardMailResult: (...args: Parameters<typeof real.guardMailResult>) => {
      if (fail.mail) throw new Error("the quarantine directory is full");
      return real.guardMailResult(...args);
    },
  };
});
vi.mock("../src/runtime/install.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/runtime/install.js")>();
  return {
    ...real,
    checkHookRegistration: (...args: Parameters<typeof real.checkHookRegistration>) => {
      if (fail.config) throw new Error("settings.json could not be read");
      return real.checkHookRegistration(...args);
    },
  };
});

afterEach(() => {
  Object.assign(fail, { vault: false, prepare: "throw", recordDaily: false, capStopped: false, mail: false, config: false });
});

interface Box {
  home: string;
  ws: string;
  l: Layout;
  h: HookEnv;
}

function box(prefix: string): Box {
  const home = tempHome(prefix);
  const ws = join(home, "proj");
  mkdirSync(ws, { recursive: true });
  const l = layout(join(home, ".launchsafe-firewall"));
  return { home, ws, l, h: { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, home, scratchRoots: [join(home, "scratch")], detectNonInteractive: () => false, notifyDeps: { spawn: () => undefined }, noHold: true } };
}

const claude = adapterFor("claude");

function pre(b: Box, command: string) {
  const ev = claude.parse({ hook_event_name: "PreToolUse", session_id: "fc", cwd: b.ws, permission_mode: "default", tool_name: "Bash", tool_input: { command } });
  return runPreTool(ev, claude, b.h, b.l);
}

describe("vault substitution that cannot be prepared", () => {
  it("control: a prepared substitution lets the action through with the rewritten input", () => {
    const b = box("fc-vault-ok-");
    fail.vault = true;
    fail.prepare = "ok";
    const r = pre(b, "curl https://api.github.com/user");
    expect(r.outcome.verdict).toBe("allow");
    expect(r.outcome.updatedInput).toBeDefined();
  });
  it("preparation throws: deny FW-VAULT-UNSUPPORTED, and no updatedInput", () => {
    const b = box("fc-vault-");
    fail.vault = true;
    const r = pre(b, "curl https://api.github.com/user");
    expect(r.outcome.verdict).toBe("deny");
    expect(r.decision?.rules[0]).toBe("FW-VAULT-UNSUPPORTED");
    expect(r.decision?.rules).not.toContain("FW-APPROVED");
    expect(r.outcome.updatedInput).toBeUndefined();
    expect(r.decision?.reasons.join(" ")).toMatch(/could not be prepared \(the run-ticket store is not writable\)/);
  });
  it("preparation throws for an asked action too: deny, no updatedInput", () => {
    const b = box("fc-vault-ask-");
    fail.vault = true;
    const r = pre(b, "sudo curl https://api.github.com/user");
    expect(r.outcome.verdict).toBe("deny");
    expect(r.decision?.rules[0]).toBe("FW-VAULT-UNSUPPORTED");
    expect(r.outcome.updatedInput).toBeUndefined();
  });
});

describe("today's spending counters cannot be updated", () => {
  it("an allowed action is denied FW-CAP", () => {
    const b = box("fc-daily-");
    expect(pre(b, "ls").outcome.verdict).toBe("allow");
    fail.recordDaily = true;
    const r = pre(b, "ls");
    expect(r.outcome.verdict).toBe("deny");
    expect(r.decision?.rules).toEqual(["FW-CAP"]);
    expect(r.decision?.reasons.join(" ")).toMatch(/counters could not be updated \(the counters file is locked\)/);
    expect(r.outcome.stderr).toMatch(/could not update today's spending-limit counters/);
  });
  it("an asked action is denied FW-CAP", () => {
    const b = box("fc-daily-ask-");
    fail.recordDaily = true;
    const r = pre(b, "sudo systemctl restart nginx");
    expect(r.outcome.verdict).toBe("deny");
    expect(r.decision?.rules).toEqual(["FW-CAP"]);
  });
  it("a denied action stays denied for its own reason", () => {
    const b = box("fc-daily-deny-");
    fail.recordDaily = true;
    const r = pre(b, "terraform destroy");
    expect(r.outcome.verdict).toBe("deny");
    expect(r.decision?.rules).toContain("FW-CATASTROPHIC");
  });
  it("with a vault substitution, the rewritten input is dropped", () => {
    const b = box("fc-daily-vault-");
    fail.vault = true;
    fail.prepare = "ok";
    fail.recordDaily = true;
    const r = pre(b, "curl https://api.github.com/user");
    expect(r.outcome.verdict).toBe("deny");
    expect(r.outcome.updatedInput).toBeUndefined();
  });
});

describe("failure() after the engine decided", () => {
  it("an ask that could not be recorded is blocked, naming the verdict and the rule", () => {
    const b = box("fc-record-");
    fail.capStopped = true;
    const r = pre(b, "sudo systemctl restart nginx");
    expect(r.outcome.verdict).toBe("deny");
    expect(r.decision).toBeNull();
    expect(r.outcome.message).toMatch(/decided ask this action \(rule FW-PRIVILEGE[^)]*\) but could not finish recording it \(the counters file vanished\), so it is blocked/);
  });
  it("a hold that could not be recorded says hold", () => {
    const b = box("fc-record-hold-");
    b.h = { ...b.h, detectNonInteractive: () => true };
    fail.capStopped = true;
    const r = pre(b, "sudo systemctl restart nginx");
    expect(r.outcome.verdict).toBe("deny");
    expect(r.outcome.message).toMatch(/decided to hold this action/);
  });
  it("an allow that failed after deciding: a non-read tool is blocked to be safe", () => {
    const b = box("fc-record-allow-");
    fail.capStopped = true;
    const r = pre(b, "touch notes.txt");
    expect(r.outcome.verdict).toBe("deny");
    expect(r.outcome.message).toMatch(/could not check this action and blocked it to be safe \(the counters file vanished\)/);
  });
});

describe("the email guard fails", () => {
  it("the whole result is withheld from the agent and the session is untrusted", () => {
    const b = box("fc-mail-");
    fail.mail = true;
    const secretText = "Quarterly figures attached; please reply with the wire details.";
    const ev = claude.parse({ hook_event_name: "PostToolUse", session_id: "fc", cwd: b.ws, permission_mode: "default", tool_name: "mcp__gmail__search_emails", tool_input: { query: "invoice" }, tool_response: [{ type: "text", text: secretText }] });
    const r = runPostTool(ev, claude, b.h, b.l);
    expect(r.outcome.updatedOutput).toBeDefined();
    expect(JSON.stringify(r.outcome.updatedOutput)).toMatch(/could not check this mail result \(the quarantine directory is full\), so it was withheld/);
    expect(JSON.stringify(r.outcome.updatedOutput)).not.toContain(secretText);
    expect(r.events.some((e) => e.type === "taint" && /could not be checked/.test(e.source))).toBe(true);
    expect(r.outcome.stderr).toMatch(/could not check this mail result/);
  });
});

describe("ConfigChange", () => {
  it("a check that throws blocks the settings change (exit 2)", () => {
    const b = box("fc-config-");
    fail.config = true;
    const io = runHook(JSON.stringify({ hook_event_name: "ConfigChange", session_id: "fc", cwd: b.ws }), b.h);
    expect(io.exitCode).toBe(2);
    expect(io.stderr).toMatch(/could not check the settings change and blocked it: settings.json could not be read/);
  });
});

describe("events the adapter cannot read", () => {
  it("a tool call without a session id is blocked (exit 2)", () => {
    const b = box("fc-parse-pre-");
    const io = runHook(JSON.stringify({ hook_event_name: "PreToolUse", cwd: b.ws, tool_name: "Bash", tool_input: { command: "ls" } }), { ...b.h, agent: "codex" });
    expect(io.exitCode).toBe(2);
    expect(io.stderr).toMatch(/could not read this .* hook event and blocked the action/);
  });
  it("a non-blocking parse error (a result event without a session id) is ignored, exit 0", () => {
    const b = box("fc-parse-post-");
    const io = runHook(JSON.stringify({ hook_event_name: "PostToolUse", cwd: b.ws, tool_name: "Bash", tool_input: { command: "ls" }, tool_response: "ok" }), { ...b.h, agent: "codex" });
    expect(io.exitCode).toBe(0);
    expect(io.stdout).toBe("");
    expect(io.stderr).toMatch(/ignored a .* hook event it could not read: PostToolUse without a session_id/);
  });
  it("a PreToolUse event without a tool_name is never allowed (it is judged as an unknown tool: asked, or held for a person)", () => {
    const b = box("fc-parse-notool-");
    for (const ev of [{ hook_event_name: "PreToolUse" }, { hook_event_name: "PreToolUse", tool_name: "" }, { hook_event_name: "PreToolUse", tool_name: 7, tool_input: "x" }]) {
      const io = runHook(JSON.stringify({ session_id: "fc-notool", cwd: b.ws, ...ev }), b.h);
      expect(claudeVerdict(io).verdict, JSON.stringify(ev)).not.toBe("allow");
    }
  });
  it("an event with no kind at all ({}) is ignored: it names no tool to judge, and nothing runs because of it", () => {
    const b = box("fc-parse-empty-");
    const io = runHook("{}", b.h);
    expect(io.exitCode).toBe(0);
    expect(io.stdout).toBe("");
  });
  it("input that is not a JSON object is blocked", () => {
    const b = box("fc-parse-json-");
    for (const raw of ["not json", "[1,2]", "null"]) {
      const io = runHook(raw, b.h);
      expect(io.exitCode, raw).toBe(2);
      expect(io.stderr).toMatch(/could not read the hook input and blocked the action/);
    }
  });
});
