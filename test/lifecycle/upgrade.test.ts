/**
 * Lifecycle 4: upgrade from a v0.2 install. The v0.2 CLI (git ref v0.2/final, built into a temporary directory) installs, sets a
 * policy, records decisions and holds an action; then this build installs over it. Hooks are migrated without duplicates, the
 * person's settings, the policy, the signed log chain and the queue survive, and a restoring uninstall still reaches the
 * file as it was before v0.2 ever touched it. Approvals do not survive: one made before the upgrade, or one made after it
 * for an item v0.2 held, is not used, and the person approves the action again. v0.2 had no Cursor adapter.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { CLI, PASSPHRASE, hook, json, lab, ourEntryCount, person, readOrNull, run, write, type Agent, type Lab } from "./lab.js";
import { SPECS, ourEntries, seed, userText } from "./agents.js";
import { V02_REF, v02Cli, v02SkipReason } from "./v02.js";
import { POLICY_VERSION } from "../../src/policy.js";

// Without the v0.2 ref (the public repository has no v0.2 history) these tests skip, and say why in the suite names.
const SKIP = v02SkipReason();
const suite = describe.skipIf(SKIP !== null);
const why = SKIP === null ? "" : ` [skipped: ${SKIP}]`;

let old: string | null = null;
beforeAll(() => {
  if (SKIP === null) old = v02Cli();
}, 180000);
afterAll(() => {
  if (old !== null) rmSync(dirname(dirname(old)), { recursive: true, force: true });
});

let l: Lab;
beforeEach(() => {
  l = lab();
});
afterEach(() => l.cleanup());

const OLD_AGENTS = ["claude", "codex", "gemini"] as const;

function oldCli(): string {
  if (old === null) throw new Error(`the git ref ${V02_REF} is not in this clone: fetch it (or set LSFW_V02_REF) to run the upgrade tests`);
  return old;
}

const bashEvent = (a: Agent, command: string, extra: Record<string, unknown> = {}): Record<string, unknown> =>
  a === "gemini" ? { hook_event_name: "BeforeTool", tool_name: "run_shell_command", tool_input: { command }, ...extra } : { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, ...extra };

function logEntries(cli?: string): number {
  const m = /^OK: (\d+) entries/.exec(run(l, ["log", "verify"], cli === undefined ? {} : { cli }).stdout);
  return m === null ? -1 : Number(m[1]);
}

function commands(a: Agent): string[] {
  return ourEntries(json(l.file(a))).map(([, e]) => String(e.command));
}

suite(`upgrade is testable${why}`, () => {
  it("the v0.2 build exists and is the old version", () => {
    const r = run(l, ["version"], { cli: oldCli() });
    expect(r.stdout.trim()).toMatch(/^0\.2\./);
    expect(run(l, ["version"]).stdout.trim()).toMatch(/^0\.3\./);
  });

  it("v0.2 has no Cursor adapter (so there is nothing of Cursor to migrate)", () => {
    const r = run(l, ["install", "--agent", "cursor", "--no-approver"], { cli: oldCli() });
    expect(r.code).toBe(64);
  });
});

suite.each(OLD_AGENTS)(`v0.2 -> v0.3: %s${why}`, (a) => {
  const spec = SPECS[a];

  /** A v0.2 installation with a policy and a log. */
  function installedWithV02(): void {
    seed(l, a, write);
    expect(run(l, ["install", "--agent", a, "--no-approver"], { cli: oldCli() }).code).toBe(0);
    expect(person(l, ["policy", "init"], [], { cli: oldCli() }).code).toBe(0);
    for (const c of ["ls", "git status", "git push origin main"]) hook(l, a, bashEvent(a, c, { session_id: "old1" }), { cli: oldCli() });
  }

  it("keeps one hook per event, points them at this build, and keeps the person's settings", () => {
    installedWithV02();
    const oldCommands = commands(a);
    expect(oldCommands).toHaveLength(spec.events.length);
    for (const c of oldCommands) expect(c).toContain(oldCli());
    const r = run(l, ["install", "--agent", a, "--no-approver"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain(`Installed (${spec.label})`);
    const now = commands(a);
    expect(now).toHaveLength(spec.events.length);
    expect(ourEntries(json(l.file(a))).map(([ev]) => ev).sort()).toEqual([...spec.events].sort());
    for (const c of now) {
      expect(c).toContain(`'${CLI}'`);
      expect(c).not.toContain(oldCli());
      expect(c).toMatch(spec.tail);
    }
    // The person's own hooks are still after the firewall's, unchanged.
    const doc = json(l.file(a));
    const user = spec.user();
    for (const k of Object.keys(user).filter((k) => k !== "hooks")) expect(doc[k], k).toEqual(user[k]);
    // Installing again changes nothing.
    const stable = readFileSync(l.file(a), "utf8");
    expect(run(l, ["install", "--agent", a, "--no-approver"]).stdout).toContain("Already installed");
    expect(readFileSync(l.file(a), "utf8")).toBe(stable);
    // Records: one per file, the new version, and the first backup (the file before v0.2) is the one kept.
    const rec = JSON.parse(readFileSync(join(l.fwHome, "install.json"), "utf8")) as { path: string; version: string; backup: string }[];
    expect(rec).toHaveLength(1);
    expect(rec[0]?.version).toMatch(/^0\.3\./);
    expect(JSON.parse(readFileSync(rec[0]?.backup as string, "utf8")).content).toBe(userText(a));
  });

  it("keeps the policy file untouched and valid, and the log chain verifies before, after, and after new decisions", () => {
    installedWithV02();
    const policy = readFileSync(join(l.fwHome, "policy.json"), "utf8");
    const entriesBefore = logEntries(oldCli());
    expect(entriesBefore).toBeGreaterThan(0);
    expect(run(l, ["log", "verify"], { cli: oldCli() }).code).toBe(0);
    expect(run(l, ["install", "--agent", a, "--no-approver"]).code).toBe(0);
    expect(readFileSync(join(l.fwHome, "policy.json"), "utf8")).toBe(policy);
    const v = run(l, ["policy", "validate"]);
    expect(v.code, v.stdout + v.stderr).toBe(0);
    // The v0.2 file stays byte-identical (above); the effective policy is reported at the current schema version
    // (policy v3), since a v2 file loads unchanged into it.
    const shown = JSON.parse(run(l, ["policy", "show"]).stdout) as { version?: number };
    expect(JSON.parse(policy).version).toBe(2);
    expect(shown.version).toBe(POLICY_VERSION);
    // `log verify` across the upgrade: the old entries are still valid, then new ones extend the same chain.
    const across = run(l, ["log", "verify"]);
    expect(across.code, across.stdout + across.stderr).toBe(0);
    expect(logEntries()).toBe(entriesBefore);
    for (const c of ["ls", "git push origin main"]) hook(l, a, bashEvent(a, c, { session_id: "new1" }));
    expect(logEntries()).toBeGreaterThan(entriesBefore);
    const tail = run(l, ["log", "tail", "50"]).stdout;
    // Codex and Gemini CLI sessions are namespaced by agent in the log ("codex:old1").
    expect(tail).toMatch(/"session":"(?:\w+:)?old1"/);
    expect(tail).toMatch(/"session":"(?:\w+:)?new1"/);
    // The reverse also holds for what v0.2 can read of a v0.3-extended log is not promised, so it is not asserted.
    const doc = run(l, ["doctor", "--json"]);
    const checks = JSON.parse(doc.stdout) as { name: string; status: string; detail: string }[];
    expect(checks.find((c) => c.name === "decision log")?.status).toBe("ok");
    expect(checks.find((c) => c.name === "policy")?.status).toBe("ok");
    const hooks = checks.find((c) => c.name === (a === "claude" ? "hooks (user)" : `${spec.label} hooks (user)`));
    expect(hooks?.status, hooks?.detail).toBe("ok");
  });

  it("a restoring uninstall after the upgrade puts the file back as it was before v0.2", () => {
    installedWithV02();
    run(l, ["install", "--agent", a, "--no-approver"]);
    const r = person(l, ["uninstall", "--agent", a, "--restore-backup"]);
    expect(r.code, r.output).toBe(0);
    expect(readOrNull(l.file(a))).toBe(userText(a));
    expect(ourEntryCount(readOrNull(l.file(a)))).toBe(0);
  });

  it("a plain uninstall after the upgrade leaves no firewall entry and the log still verifies", () => {
    installedWithV02();
    run(l, ["install", "--agent", a, "--no-approver"]);
    expect(person(l, ["uninstall", "--agent", a]).code).toBe(0);
    expect(ourEntryCount(readOrNull(l.file(a)))).toBe(0);
    expect(run(l, ["log", "verify"]).code).toBe(0);
  });

  it("before reinstalling, v0.3's doctor and status read the v0.2 install without failing or claiming it is missing", () => {
    installedWithV02();
    const d = run(l, ["doctor", "--json"]);
    const checks = JSON.parse(d.stdout) as { name: string; status: string; detail: string }[];
    const hooks = checks.find((c) => c.name === (a === "claude" ? "hooks (user)" : `${spec.label} hooks (user)`));
    expect(hooks?.status, hooks?.detail).toBe("ok");
    expect(checks.find((c) => c.name === "decision log")?.status).toBe("ok");
    const s = run(l, ["status", "--json"]);
    expect(s.code, s.stderr).toBe(0);
    expect((JSON.parse(s.stdout) as { installedIn: string[] }).installedIn).toEqual([`user (${l.file(a)})`]);
  });
});

/**
 * Approvals do not carry over an upgrade from v0.2, by design (see docs/limitations.md and docs/threat-model.md): an
 * approval now signs a nonce, an expiry, the rules shown, the working directory and the project, and is used only in the
 * place it was given. A v1 approval line (made by v0.2: no nonce, no expiry) is ignored, and a v0.2 queue item records no
 * project, so an approval given for it after the upgrade is signed for no project and is not used in the agent's. In both
 * cases the held action stays held, the hook asks again under a new id, and approving that one lets the action run once.
 */
suite(`v0.2 -> v0.3: the queue and the approval passphrase${why}`, () => {
  const push = (): Record<string, unknown> => bashEvent("claude", "git push origin main", { permission_mode: "dontAsk" });
  const approve = (x: Lab, id: string, cli?: string): ReturnType<typeof person> =>
    person(x, ["queue", "approve", id], [["Approval passphrase", PASSPHRASE], ["Type \"yes\"", "yes"]], cli === undefined ? {} : { cli });
  const heldId = (out: string): string | undefined => /queue approve (\w+)/.exec(out)?.[1];

  /** A v0.2 install with its own passphrase and one held action; returns the pinned key and the held item's id. */
  function heldUnderV02(x: Lab): { pinOld: string; id: string } {
    seed(x, "claude", write);
    expect(person(x, ["approver", "init"], [["New approval passphrase", PASSPHRASE], ["Repeat it", PASSPHRASE]], { cli: oldCli() }).code).toBe(0);
    expect(run(x, ["install", "--no-approver"], { cli: oldCli() }).code).toBe(0);
    const pinOld = /LAUNCHSAFE_FIREWALL_APPROVER='([A-Za-z0-9+/=]+)'/.exec(commands2(x))?.[1];
    expect(pinOld, "v0.2 pins the key in its hook command").toBeDefined();
    hook(x, "claude", { hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: { url: "https://example.com" }, tool_response: "hello" }, { cli: oldCli() });
    const held = hook(x, "claude", push(), { cli: oldCli() });
    const id = heldId(held.stdout);
    expect(id, held.stdout).toBeDefined();
    expect(JSON.parse(run(x, ["queue", "--json"], { cli: oldCli() }).stdout)).toHaveLength(1);
    return { pinOld: pinOld as string, id: id as string };
  }

  /** Upgrades over the v0.2 install: the hook still pins the same key and the passphrase is still set. */
  function upgrade(x: Lab, pinOld: string): void {
    const up = run(x, ["install"]);
    expect(up.code, up.stderr).toBe(0);
    expect(up.stdout).toContain("The hook pins your approval key");
    expect(commands2(x)).toContain(`LAUNCHSAFE_FIREWALL_APPROVER='${pinOld}'`);
    expect(run(x, ["approver", "status"]).stdout).toContain("passphrase is set");
  }

  /** The action asks again under a new id; approving that one under v0.3 lets it run once, and only once. */
  function approveAgainRunsOnce(x: Lab, asked: string, oldId: string): void {
    const newId = heldId(asked);
    expect(newId, asked).toBeDefined();
    expect(newId).not.toBe(oldId);
    expect(pendingIds(x)).toEqual([newId]);
    const ok = approve(x, newId as string);
    expect(ok.code, ok.output).toBe(0);
    expect(run(x, ["log", "verify"]).code).toBe(0);
    expect(hook(x, "claude", push()).stdout).not.toContain("queue approve");
    expect(hook(x, "claude", push()).stdout).toContain("queue approve");
  }

  it("a held action and the approval passphrase set under v0.2 are still there under v0.3: the hook still pins the key and the person can approve; an approval of the v0.2 item is not used (it records no project), so the person approves the new item", () => {
    const l2 = lab();
    try {
      const { pinOld, id } = heldUnderV02(l2);
      upgrade(l2, pinOld);
      const q = JSON.parse(run(l2, ["queue", "--json"]).stdout) as { id: string; status: string; rules: string[] }[];
      expect(q.map((x) => x.id)).toEqual([id]);
      expect(q[0]?.status).toBe("pending");
      // The old key signs approvals that the new build accepts.
      const ok = approve(l2, id);
      expect(ok.code, ok.output).toBe(0);
      const after = JSON.parse(run(l2, ["queue", "--json"]).stdout) as { id: string; status: string }[];
      expect(after.find((x) => x.id === id)?.status ?? "approved").not.toBe("pending");
      expect(run(l2, ["log", "verify"]).code).toBe(0);
      // The v0.2 item names no project, so the approval is signed for none and is not used in the agent's project:
      // the action is held again, the message says why, and a new item shows what asks now.
      const again = hook(l2, "claude", push());
      expect(again.stdout).toContain("An earlier approval of this exact action was not used");
      approveAgainRunsOnce(l2, again.stdout, id);
    } finally {
      l2.cleanup();
    }
  });

  it("an approval given under v0.2 (v1: no nonce, no expiry) is not honoured after the upgrade: the hook asks again, and approving the new item under v0.3 lets the action run once", () => {
    const l2 = lab();
    try {
      const { pinOld, id } = heldUnderV02(l2);
      const old = approve(l2, id, oldCli());
      expect(old.code, old.output).toBe(0);
      upgrade(l2, pinOld);
      // The item v0.2 approved is no longer pending (`queue --json` lists pending items only).
      expect(pendingIds(l2)).toEqual([]);
      expect(run(l2, ["log", "verify"]).code).toBe(0);
      approveAgainRunsOnce(l2, hook(l2, "claude", push()).stdout, id);
    } finally {
      l2.cleanup();
    }
  });
});

/** The ids of the pending queue items, as this build lists them. */
function pendingIds(x: Lab): string[] {
  return (JSON.parse(run(x, ["queue", "--json"]).stdout) as { id: string }[]).map((i) => i.id);
}

function commands2(x: Lab): string {
  return readFileSync(x.file("claude"), "utf8");
}
