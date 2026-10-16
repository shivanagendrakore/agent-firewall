/**
 * Lifecycle 2: uninstall. The documented path is a person at a terminal (and, when one is set, the approval passphrase);
 * a script or an agent is refused. Plain uninstall removes the firewall's own entries; --restore-backup puts the files back
 * as they were before the first install.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { AGENTS, PASSPHRASE, assertTempHome, json, lab, ourEntryCount, person, readOrNull, run, setPassphrase, tree, write, type Agent, type Lab } from "./lab.js";
import { CODEX_TOML, SPECS, seed, userText, withoutOurs } from "./agents.js";

let l: Lab;
beforeEach(() => {
  l = lab();
});
afterEach(() => l.cleanup());

const install = (a: Agent, extra: string[] = []) => run(l, ["install", "--agent", a, "--no-approver", ...extra]);
const uninstall = (a: Agent, extra: string[] = [], inputs: [string, string][] = []) => person(l, ["uninstall", "--agent", a, ...extra], inputs);
const codexToml = (): string | null => readOrNull(join(l.home, ".codex", "config.toml"));

describe.each(AGENTS)("uninstall: %s", (a) => {
  const spec = SPECS[a];

  it("is refused from a script or an agent (no terminal) and the hooks stay", () => {
    seed(l, a, write);
    install(a);
    const installed = tree(l.home);
    const r = run(l, ["uninstall", "--agent", a]);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/interactive terminal/);
    expect(tree(l.home)).toEqual(installed);
  });

  it("is refused in a terminal that belongs to an agent session, and the hooks stay", () => {
    seed(l, a, write);
    install(a);
    const installed = tree(l.home);
    const r = person(l, ["uninstall", "--agent", a], [], { env: { CLAUDECODE: "1" } });
    expect(r.code).not.toBe(0);
    expect(r.output).toMatch(/inside a coding agent's session/);
    expect(tree(l.home)).toEqual(installed);
  });

  it("by a person removes every firewall entry and nothing of the person's, and the records and state commands agree", () => {
    seed(l, a, write);
    install(a);
    const r = uninstall(a);
    expect(r.code, r.output).toBe(0);
    expect(r.output).toContain("Removed the firewall's hooks from");
    expect(ourEntryCount(readOrNull(l.file(a)))).toBe(0);
    expect(JSON.stringify(spec.stripEnable(json(l.file(a))), null, 2)).toBe(JSON.stringify(spec.user(), null, 2));
    expect(JSON.parse(readFileSync(join(l.fwHome, "install.json"), "utf8"))).toEqual([]);
    expect((JSON.parse(run(l, ["status", "--json"]).stdout) as { installedIn: string[] }).installedIn).toEqual([]);
    if (a === "claude") expect((JSON.parse(run(l, ["doctor", "--json"]).stdout) as { name: string; status: string }[]).find((c) => c.name === "hooks")?.status).toBe("fail");
    if (a === "codex") expect(codexToml()).toBe(CODEX_TOML);
  });

  // The README says uninstall restores the backups; doctor and the docs say --restore-backup does. Plain uninstall should leave the
  // file as the person had it. For Gemini CLI it leaves the hooksConfig.enabled flag install added.
  const plainExact = it;
  plainExact("by a person leaves the file exactly as it was before install (LC1: Gemini CLI keeps hooksConfig.enabled)", () => {
    seed(l, a, write);
    install(a);
    uninstall(a);
    expect(readOrNull(l.file(a))).toBe(userText(a));
  });

  it("with --restore-backup puts the file back byte for byte (and Codex's config.toml too)", () => {
    seed(l, a, write);
    install(a);
    const r = uninstall(a, ["--restore-backup"]);
    expect(r.code, r.output).toBe(0);
    expect(r.output).toContain("Restored the backup of");
    expect(readOrNull(l.file(a))).toBe(userText(a));
    if (a === "codex") expect(codexToml()).toBe(CODEX_TOML);
  });

  // docs/cli.md: --restore-backup puts the file back "exactly as it was before the first install". For a person with no file that is no file.
  it("with --restore-backup removes a file the install created (LC2: it leaves an empty object behind)", () => {
    install(a);
    uninstall(a, ["--restore-backup"]);
    expect(existsSync(l.file(a))).toBe(false);
  });

  it("keeps a person's edit made after install (a new key, a new hook of their own, a changed value)", () => {
    seed(l, a, write);
    install(a);
    const doc = json(l.file(a));
    doc.addedAfterInstall = { note: "mine" };
    const hooks = doc.hooks as Record<string, unknown[]>;
    const ev = a === "gemini" ? "AfterAgent" : a === "cursor" ? "stop" : "Stop";
    hooks[ev] = [...(hooks[ev] ?? []), spec.flat ? { command: "/usr/local/bin/added-later" } : { hooks: [{ type: "command", command: "/usr/local/bin/added-later" }] }];
    if (a === "claude") (doc.env as Record<string, string>).EDITOR = "emacs";
    write(l.file(a), `${JSON.stringify(doc, null, 2)}\n`);
    const r = uninstall(a);
    expect(r.code, r.output).toBe(0);
    const left = json(l.file(a));
    expect(left.addedAfterInstall).toEqual({ note: "mine" });
    expect(JSON.stringify(left)).toContain("/usr/local/bin/added-later");
    if (a === "claude") expect((left.env as Record<string, string>).EDITOR).toBe("emacs");
    expect(ourEntryCount(readOrNull(l.file(a)))).toBe(0);
    // And everything from before install is still there.
    for (const k of Object.keys(spec.user())) expect(left[k], k).toBeDefined();
  });

  // LC3: a person's edit made after install is never discarded silently: the current file is saved first, and the edits need a yes or --force.
  describe("--restore-backup after an edit made since install (LC3)", () => {
    const edited = (): string => {
      seed(l, a, write);
      install(a);
      const doc = json(l.file(a));
      doc.addedAfterInstall = { note: "mine, written after install" };
      const text = `${JSON.stringify(doc, null, 2)}\n`;
      write(l.file(a), text);
      return text;
    };
    const copies = (): string[] => readdirSync(join(l.file(a), "..")).filter((n) => n.includes(".before-restore."));

    it("declined at the prompt: nothing is restored, the edit stays, the difference count is printed", () => {
      const text = edited();
      const r = uninstall(a, ["--restore-backup"], [["Restore the backup anyway", "no"]]);
      expect(r.code).not.toBe(0);
      expect(r.output).toMatch(/has 1 difference/);
      expect(readFileSync(l.file(a), "utf8")).toBe(text);
      expect(copies()).toEqual([]);
      expect(ourEntryCount(readOrNull(l.file(a)))).toBeGreaterThan(0);
    });

    it("confirmed at the prompt: the file is restored and the edited one is saved beside it, and the command says so", () => {
      const text = edited();
      const r = uninstall(a, ["--restore-backup"], [["Restore the backup anyway", "yes"]]);
      expect(r.code, r.output).toBe(0);
      expect(readOrNull(l.file(a))).toBe(userText(a));
      expect(copies()).toHaveLength(1);
      const copy = join(l.file(a), "..", copies()[0] as string);
      expect(readFileSync(copy, "utf8")).toBe(text);
      expect(r.output).toContain(copy);
    });

    it("--force restores without asking, and still saves the edited file", () => {
      edited();
      const r = uninstall(a, ["--restore-backup", "--force"]);
      expect(r.code, r.output).toBe(0);
      expect(readOrNull(l.file(a))).toBe(userText(a));
      expect(copies()).toHaveLength(1);
      expect(readFileSync(join(l.file(a), "..", copies()[0] as string), "utf8")).toContain("written after install");
    });

    it("an unedited file is restored without a prompt, and the current file is still saved first", () => {
      seed(l, a, write);
      install(a);
      const r = uninstall(a, ["--restore-backup"]);
      expect(r.code, r.output).toBe(0);
      expect(copies()).toHaveLength(1);
    });
  });

  it("twice: the second says the hooks were not installed and changes nothing", () => {
    seed(l, a, write);
    install(a);
    uninstall(a);
    const after = tree(l.home);
    const r = uninstall(a);
    expect(r.code, r.output).toBe(0);
    expect(r.output).toContain("not installed");
    expect(tree(l.home)).toEqual(after);
  });

  it("with the approval passphrase set asks for it: a wrong one is refused and the hooks stay, the right one works", () => {
    seed(l, a, write);
    expect(setPassphrase(l).code).toBe(0);
    expect(run(l, ["install", "--agent", a]).code).toBe(0);
    expect(ourEntryCount(readOrNull(l.file(a)))).toBe(spec.events.length);
    const installed = tree(l.home);
    const wrong = person(l, ["uninstall", "--agent", a], [["Approval passphrase", "not the passphrase at all"]]);
    expect(wrong.code).not.toBe(0);
    expect(tree(l.home)).toEqual(installed);
    const right = person(l, ["uninstall", "--agent", a], [["Approval passphrase", PASSPHRASE]]);
    expect(right.code, right.output).toBe(0);
    expect(ourEntryCount(readOrNull(l.file(a)))).toBe(0);
  });

  it("--purge deletes the firewall's state directory after removing the hooks", () => {
    install(a);
    expect(existsSync(l.fwHome)).toBe(true);
    const r = uninstall(a, ["--purge"], [["Type the path to confirm", l.fwHome]]);
    expect(r.code, r.output).toBe(0);
    expect(existsSync(l.fwHome)).toBe(false);
    expect(ourEntryCount(readOrNull(l.file(a)))).toBe(0);
    assertTempHome(l.home);
  });
});

describe("uninstall: several agents in one home", () => {
  it("--agent removes only that agent's hooks and record; without it every recorded file is processed", () => {
    for (const a of AGENTS) {
      seed(l, a, write);
      install(a);
    }
    expect(person(l, ["uninstall", "--agent", "cursor"]).code).toBe(0);
    expect(ourEntryCount(readOrNull(l.file("cursor")))).toBe(0);
    for (const a of ["claude", "codex", "gemini"] as const) expect(ourEntryCount(readOrNull(l.file(a))), a).toBe(SPECS[a].events.length);
    const rec = JSON.parse(readFileSync(join(l.fwHome, "install.json"), "utf8")) as { agent?: string }[];
    expect(rec.map((r) => r.agent ?? "claude").sort()).toEqual(["claude", "codex", "gemini"]);
    expect(person(l, ["uninstall"]).code).toBe(0);
    for (const a of AGENTS) expect(ourEntryCount(readOrNull(l.file(a))), a).toBe(0);
    expect(JSON.parse(readFileSync(join(l.fwHome, "install.json"), "utf8"))).toEqual([]);
    // What the person had besides hooks is intact in every file.
    for (const a of AGENTS) expect(withoutOurs(SPECS[a].stripEnable(json(l.file(a))))).toEqual(SPECS[a].user());
  });
});
