/**
 * Two agent-integration gaps the live campaign found (UNAT-003, DOC-006), pinned to captured evidence:
 * - Codex 0.162.1 skips a UserPromptSubmit group that has a matcher, so the firewall's "*" group never
 *   saw a prompt (no task scope, no destinations the person named) in `codex exec` or anywhere else.
 * - Gemini CLI's `-p` / yolo detection read only `ps`, which a macOS seatbelt sandbox forbids
 *   (Gemini CLI's own `-s`, or a sandbox-exec wrapper): those sessions were taken as attended.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CODEX_HOOK_EVENTS, codexAdapter, codexManagedSnippet, codexMatcherProblems } from "../../src/adapters/codex.js";
import { geminiUnattendedArgs, nonInteractiveGemini } from "../../src/adapters/gemini.js";
import { ancestorArgs, pgrepAncestors, type Run } from "../../src/runtime/ancestry.js";
import { codexTrustHash, trustStatus } from "../../src/runtime/codex-trust.js";
import { doctor } from "../../src/runtime/doctor.js";
import { install } from "../../src/runtime/install.js";
import { atomicWrite } from "../../src/runtime/fsutil.js";
import { loadState } from "../../src/runtime/store.js";
import { stateSessionId } from "../../src/hook/pipeline.js";
import { box, fixture, rules, send, verdict, type Box } from "./harness.js";

let b: Box;
beforeEach(() => {
  b = box();
});
afterEach(() => b.cleanup());

type Group = { matcher?: string; hooks: { command: string }[] };
const hooksOf = (p: string) => (JSON.parse(readFileSync(p, "utf8")) as { hooks: Record<string, Group[]> }).hooks;

describe("Codex: the prompt hook runs (captured matcher matrix, 0.162.1)", () => {
  const matrix = fixture("codex-0.162.1-hook-matchers.json") as { groups: { event: string; matcher: string | null; fired: boolean }[] };
  const fired = (event: string, matcher: string | undefined) => matrix.groups.find((g) => g.event === event && g.matcher === (matcher ?? null))?.fired;

  it("the capture shows Codex skips every UserPromptSubmit group with a matcher and runs the one without", () => {
    expect(fired("UserPromptSubmit", undefined)).toBe(true);
    for (const m of ["*", "", ".*", "startup"]) expect(fired("UserPromptSubmit", m), m).toBe(false);
    expect(fired("SessionStart", undefined)).toBe(true);
    expect(fired("SessionStart", "*")).toBe(true);
  });

  it("install writes every firewall group in a shape the capture shows Codex runs, and trusts each", () => {
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings });
    const path = join(b.home, ".codex", "hooks.json");
    const hooks = hooksOf(path);
    for (const ev of CODEX_HOOK_EVENTS) expect(fired(ev, hooks[ev]?.[0]?.matcher), `${ev} ${String(hooks[ev]?.[0]?.matcher)}`).toBe(true);
    expect(hooks.UserPromptSubmit?.[0]).not.toHaveProperty("matcher");
    expect(hooks.PreToolUse?.[0]?.matcher).toBe("*");
    const config = readFileSync(join(b.home, ".codex", "config.toml"), "utf8");
    expect(trustStatus(config, path, { hooks })).toEqual({ trusted: ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"], untrusted: [], modified: [] });
    expect(config).toContain(codexTrustHash("UserPromptSubmit", undefined, hooks.UserPromptSubmit?.[0]?.hooks[0] as unknown as Record<string, unknown>));
  });

  it("an install from before the fix (matcher on UserPromptSubmit) fails doctor; installing again repairs it and keeps trust", () => {
    install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings });
    const path = join(b.home, ".codex", "hooks.json");
    const hooks = hooksOf(path);
    for (const ev of CODEX_HOOK_EVENTS) (hooks[ev]?.[0] as Group).matcher = "*";
    writeFileSync(path, JSON.stringify({ hooks }, null, 2));
    expect(codexMatcherProblems({ hooks })).toEqual(["UserPromptSubmit"]);
    const opts = { home: b.home, platform: "darwin" as const, findBinary: () => null };
    const bad = doctor(b.l, b.ws, opts).find((c) => c.name.startsWith("Codex prompt hook"));
    expect(bad?.status).toBe("fail");
    expect(bad?.detail).toMatch(/never sees the prompt/);
    expect(install(b.l, "user", b.ws, "t", { home: b.home, agent: "codex", settings: codexAdapter.settings }).changed).toBe(true);
    expect(codexMatcherProblems({ hooks: hooksOf(path) })).toEqual([]);
    const after = doctor(b.l, b.ws, opts);
    expect(after.find((c) => c.name.startsWith("Codex prompt hook"))).toBeUndefined();
    expect(after.find((c) => c.name.startsWith("Codex hook trust"))?.status).toBe("ok");
  });

  it("a person's own matcher on another hook is not the firewall's problem", () => {
    expect(codexMatcherProblems({ hooks: { UserPromptSubmit: [{ matcher: "*", hooks: [{ type: "command", command: "mine" }] }] } })).toEqual([]);
  });

  it("the managed requirements.toml snippet gives only the tool events a matcher", () => {
    const t = codexManagedSnippet("LAUNCHSAFE_FIREWALL_HOOK=1 node cli hook --agent codex", true);
    expect(t).toMatch(/\[\[hooks\.PreToolUse\]\]\nmatcher = "\*"/);
    expect(t).toMatch(/\[\[hooks\.UserPromptSubmit\]\]\n\[\[hooks\.UserPromptSubmit\.hooks\]\]/);
    expect(t).not.toMatch(/\[\[hooks\.UserPromptSubmit\]\]\nmatcher/);
  });
});

describe("Codex exec: the captured prompt now reaches the firewall (DOC-006, UNAT-003)", () => {
  const prompt = fixture("codex-0.162.1-UserPromptSubmit-exec.json");
  const pre = (command: string) => ({ hook_event_name: "PreToolUse", permission_mode: "bypassPermissions", tool_name: "Bash", tool_input: { command } });
  const outside = () => send(b, "codex", { hook_event_name: "PostToolUse", permission_mode: "bypassPermissions", tool_name: "Bash", tool_input: { command: "curl -sS https://blog.example.org/post" }, tool_response: "(outside content placeholder)" });

  it("DOC-006: after outside content, curl to the host the person named is allowed; with no prompt event it is held", () => {
    outside();
    const held = send(b, "codex", pre("curl -fsS 'https://named.example.com/guide'"));
    expect(verdict("codex", held)).toBe("queue");
    send(b, "codex", { ...prompt, session_id: "s2", cwd: b.ws });
    expect([...loadState(b.l, stateSessionId("codex", "s2")).userDestinations]).toContain("named.example.com");
    send(b, "codex", { hook_event_name: "PostToolUse", session_id: "s2", permission_mode: "bypassPermissions", tool_name: "Bash", tool_input: { command: "curl -sS https://blog.example.org/post" }, tool_response: "(outside content placeholder)" });
    expect(verdict("codex", send(b, "codex", { ...pre("curl -fsS 'https://named.example.com/guide'"), session_id: "s2" }))).toBe("allow");
  });

  it("UNAT-003: task scope enforced, codex exec, a push the prompt never mentioned is held (FW-SCOPE)", () => {
    atomicWrite(b.l.policy, JSON.stringify({ version: 2, taskScope: { mode: "enforce" } }));
    mkdirSync(join(b.ws, "packages", "web"), { recursive: true });
    writeFileSync(join(b.ws, "packages", "web", "flaky.test.ts"), "x\n");
    // The harness stands in for the process check; in a live `codex exec` permission_mode bypassPermissions marks it.
    send(b, "codex", { ...prompt, session_id: "s1", cwd: b.ws, prompt: "fix the flaky test in packages/web" }, { unattended: true });
    const r = send(b, "codex", pre("git push"), { unattended: true });
    expect(verdict("codex", r)).toBe("queue");
    expect(rules("codex", r)).toContain("FW-SCOPE");
  });
});

describe("ancestry: ps, then pgrep where a seatbelt forbids ps (captured, Gemini CLI 0.63.0)", () => {
  const seat = fixture("gemini-0.63.0-ancestry-seatbelt.json") as { psError: string; pgrepWithAncestors: string; pgrepWithout: string };
  const psCap = fixture("gemini-0.63.0-ancestry-ps.json") as { lines: string[] };
  const eperm = (): never => {
    throw Object.assign(new Error(seat.psError), { code: "EPERM" });
  };
  const seatbelt: Run = (cmd, args) => (cmd === "ps" ? eperm() : args.includes("-a") ? seat.pgrepWithAncestors : seat.pgrepWithout);

  it("pgrep's two listings differ by exactly the ancestors (the unrelated process drops out)", () => {
    const a = pgrepAncestors(seat.pgrepWithAncestors, seat.pgrepWithout);
    expect(a.some((x) => /tail -f/.test(x))).toBe(false);
    expect(a.filter((x) => geminiUnattendedArgs(x) !== null)).toHaveLength(3);
  });

  it("ps denied (seatbelt): the pgrep fallback finds `gemini -p` on macOS", () => {
    const anc = ancestorArgs(4242, { pattern: "gemini", platform: "darwin", exec: seatbelt });
    expect(anc.via).toBe("pgrep");
    expect(anc.inspected).toBe(true);
    expect(anc.args.map(geminiUnattendedArgs).find((x) => x !== null)).toMatch(/-p/);
  });

  it("ps works: the walk reads the captured chain, nearest first, and stops at the depth", () => {
    const rows = psCap.lines.map((l) => /^(\d+)\s+(\d+)\s+(.*)$/.exec(l) as RegExpExecArray);
    const byPid = new Map(rows.map((r) => [r[1] as string, `${r[2] as string} ${r[3] as string}`]));
    const exec: Run = (cmd, args) => {
      if (cmd !== "ps") throw new Error("pgrep must not run when ps works");
      const v = byPid.get(args[args.length - 1] as string);
      if (v === undefined) throw Object.assign(new Error("no such process"), { status: 1 });
      return v;
    };
    const anc = ancestorArgs(Number(rows[0]?.[1]), { pattern: "gemini", platform: "darwin", exec, depth: 4 });
    expect(anc).toMatchObject({ via: "ps", inspected: true });
    expect(anc.args).toHaveLength(2);
    expect(geminiUnattendedArgs(anc.args[1] as string)).toMatch(/-p/);
    expect(ancestorArgs(Number(rows[0]?.[1]), { pattern: "gemini", platform: "darwin", exec, depth: 1 }).args).toHaveLength(1);
  });

  it("pgrep finding nothing (exit 1) is an empty, inspected listing", () => {
    const exec: Run = (cmd) => (cmd === "ps" ? eperm() : (() => { throw Object.assign(new Error("none"), { status: 1 }); })());
    expect(ancestorArgs(4242, { pattern: "gemini", platform: "darwin", exec })).toEqual({ args: [], via: "pgrep", inspected: true });
  });

  it("neither source readable, or neither macOS nor Linux (no pgrep fallback): not inspected", () => {
    const none: Run = () => eperm();
    expect(ancestorArgs(4242, { pattern: "gemini", platform: "darwin", exec: none })).toEqual({ args: [], via: "none", inspected: false });
    // Linux reads /proc and never runs ps (test/adapters/unattended-linux.test.ts), so the ps-only branch is another platform's.
    expect(ancestorArgs(4242, { pattern: "gemini", platform: "freebsd", exec: seatbelt })).toEqual({ args: [], via: "none", inspected: false });
  });

  it("another platform (FreeBSD) walks with ps and never reads /proc", () => {
    // A stand-in /proc with another answer for the same process: a walk sent there instead of to ps cannot pass.
    const procRoot = join(b.root, "proc");
    mkdirSync(join(procRoot, "4242"), { recursive: true });
    writeFileSync(join(procRoot, "4242", "stat"), "4242 (node) S 1 4242 4242 0\n");
    writeFileSync(join(procRoot, "4242", "cmdline"), "node\0gemini\0");
    const asked: string[][] = [];
    const exec: Run = (cmd, args) => {
      asked.push([cmd, ...args]);
      if (cmd === "ps" && args[args.length - 1] === "4242") return "1 node gemini -p fix it\n";
      throw new Error("no such process");
    };
    expect(ancestorArgs(4242, { pattern: "gemini", platform: "freebsd", procRoot, exec })).toEqual({ args: ["node gemini -p fix it"], via: "ps", inspected: true });
    expect(asked).toEqual([["ps", "-o", "ppid=,args=", "-p", "4242"]]);
  });
});

describe("Gemini CLI unattended detection", () => {
  const ev = { kind: "prompt" as const, agent: "gemini" as const, sessionId: "g1", cwd: "/w", raw: {} };
  beforeEach(() => mkdirSync(b.l.sessions, { recursive: true }));

  it("found through pgrep in a seatbelt, and cached for the session", () => {
    const seat = fixture("gemini-0.63.0-ancestry-seatbelt.json") as { pgrepWithAncestors: string; pgrepWithout: string };
    let calls = 0;
    const inspect = () => {
      calls++;
      return { args: pgrepAncestors(seat.pgrepWithAncestors, seat.pgrepWithout), via: "pgrep" as const, inspected: true };
    };
    expect(nonInteractiveGemini(ev, {}, b.l, inspect)).toMatch(/non-interactively \(-p\)/);
    expect(nonInteractiveGemini(ev, {}, b.l, inspect)).toMatch(/-p/);
    expect(calls).toBe(1);
  });

  it("an interactive Gemini CLI stays attended", () => {
    expect(nonInteractiveGemini(ev, {}, b.l, () => ({ args: ["/bin/sh -c hook", "node /opt/gemini/node_modules/.bin/gemini"], via: "ps", inspected: true }))).toBeNull();
  });

  it("no process readable at all: treated as unattended (the strict reading), with the reason", () => {
    expect(nonInteractiveGemini(ev, {}, b.l, () => ({ args: [], via: "none", inspected: false }))).toMatch(/could not be read.*treated as unattended/);
  });
});
