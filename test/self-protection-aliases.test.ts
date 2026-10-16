/**
 * SELF-016: protected locations are matched by what they are, not by the name that reaches them. The live
 * campaign denied `cd <realpath>/firewall && npm run build` (FW-TAMPER) but not the same directory through
 * /tmp (macOS /tmp -> /private/tmp) or `npm --prefix <alias>`. Real files and symlinks in the suite's
 * temporary root; the resolver is the runtime's (realpathStrict).
 */
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { collapseRules, MAX_ENTRIES_PER_RULE, MAX_RULE_ENTRIES } from "../src/engine/decide.js";
import { decide } from "../src/engine/decide.js";
import { emptyState } from "../src/engine/state.js";
import { defaultConfig } from "../src/policy.js";
import { buildContext } from "../src/runtime/context.js";
import { installDir, layout } from "../src/runtime/layout.js";
import { realpathStrict } from "../src/runtime/realpath.js";
import type { Context, FirewallIdentity } from "../src/types.js";
import { bash, explain, run, testRoot, type RunOpts } from "./helpers.js";

let B = ""; // the fixture's root, canonical
let PKG = ""; // the installed package (a dev install from a working copy)
let HOMEDIR = "";
let PROJ = "";
const CI = process.platform === "darwin" || process.platform === "win32";

function identity(pkg: string): FirewallIdentity {
  return {
    cliFiles: [`${pkg}/dist/cli.js`],
    runtimeRoots: [`${pkg}/dist`, `${pkg}/node_modules`],
    runtimeFiles: [`${pkg}/package.json`],
    packageRoots: [pkg],
    nodeBinaries: [],
    dataRoots: [],
    binNames: ["launchsafe-firewall"],
    source: "hook-command",
  };
}

function ctx(over: Partial<Context> = {}): RunOpts {
  return {
    ctx: {
      cwd: PROJ,
      workspaceRoots: [PROJ],
      home: HOMEDIR,
      firewallHome: `${HOMEDIR}/.launchsafe-firewall`,
      firewallInstallDir: "",
      identity: identity(PKG),
      caseInsensitive: CI,
      realpath: realpathStrict,
      ...over,
    },
  };
}

function tamper(d: ReturnType<typeof run>): void {
  expect(d.verdict, explain(d)).toBe("deny");
  expect(d.rules, explain(d)).toContain("FW-TAMPER");
}
function notAllowed(d: ReturnType<typeof run>): void {
  expect(d.verdict, explain(d)).not.toBe("allow");
}
function allowed(d: ReturnType<typeof run>): void {
  expect(d.verdict, explain(d)).toBe("allow");
}

function makePackage(dir: string): void {
  mkdirSync(join(dir, "dist"), { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@launchsafe/agent-firewall", scripts: { build: "tsc" } }));
  writeFileSync(join(dir, "dist", "cli.js"), "// cli\n");
}

beforeAll(() => {
  B = realpathSync(mkdtempSync(join(testRoot(), "self016-")));
  PKG = join(B, "install", "firewall");
  makePackage(PKG);
  HOMEDIR = join(B, "home");
  mkdirSync(join(HOMEDIR, ".claude", "agents"), { recursive: true });
  writeFileSync(join(HOMEDIR, ".claude", "settings.json"), "{}");
  mkdirSync(join(HOMEDIR, ".launchsafe-firewall", "sessions"), { recursive: true });
  PROJ = join(B, "proj");
  mkdirSync(join(PROJ, "src"), { recursive: true });
  writeFileSync(join(PROJ, "package.json"), JSON.stringify({ name: "app", scripts: { build: "tsc" } }));
  // Aliases: of the install's parent, of ~/.claude, of the firewall home, of the whole home, of the project.
  symlinkSync(join(B, "install"), join(B, "alias"));
  symlinkSync(join(HOMEDIR, ".claude"), join(B, "cfg"));
  symlinkSync(join(HOMEDIR, ".launchsafe-firewall"), join(B, "fwh"));
  symlinkSync(HOMEDIR, join(B, "homealias"));
  symlinkSync(PROJ, join(B, "projalias"));
  symlinkSync(join(PKG, "dist"), join(B, "distlink"));
  // A symlink loop, and a dangling link into the runtime.
  symlinkSync(join(B, "loop"), join(B, "loop"));
  symlinkSync(join(PKG, "dist", "new.js"), join(B, "dangling"));
  mkdirSync(join(B, "locked", "inner"), { recursive: true });
  chmodSync(join(B, "locked"), 0o000);
});

afterAll(() => {
  try {
    chmodSync(join(B, "locked"), 0o755);
  } catch {
    // Already gone.
  }
  rmSync(B, { recursive: true, force: true });
});

describe("SELF-016: the installed package root through an alias", () => {
  it("the real path is tampering (control)", () => tamper(bash(`cd ${PKG} && npm run build`, ctx())));
  it("cd through a symlinked alias, then build", () => tamper(bash(`cd ${B}/alias/firewall && npm run build`, ctx())));
  it("relative cds after an alias", () => {
    tamper(bash(`cd ${B}/alias && cd firewall && npm run build`, ctx()));
    tamper(bash(`cd ${B} && cd alias/firewall && npm run build`, ctx()));
  });
  it("pushd through an alias", () => tamper(bash(`pushd ${B}/alias/firewall && npm run build`, ctx())));
  it("the program's own directory option: npm --prefix/-C, pnpm -C, yarn --cwd, bun --cwd, make -C, env -C", () => {
    for (const c of [
      `npm --prefix ${B}/alias/firewall run build`,
      `npm --prefix=${B}/alias/firewall run build`,
      `npm -C ${B}/alias/firewall run build`,
      `pnpm -C ${B}/alias/firewall build`,
      `pnpm --dir ${B}/alias/firewall build`,
      `yarn --cwd ${B}/alias/firewall build`,
      `bun --cwd ${B}/alias/firewall run build`,
      `make -C ${B}/alias/firewall`,
      `env -C ${B}/alias/firewall npm run build`,
      `cd ${B} && npm --prefix ./alias/firewall run build`,
    ]) tamper(bash(c, ctx()));
  });
  it("a path with .. after a link is resolved physically (the program resolves it, not the shell)", () => {
    tamper(bash(`npm --prefix ${B}/distlink/.. run build`, ctx()));
    tamper(run("Write", { file_path: `${B}/distlink/../dist/cli.js`, content: "x" }, ctx()));
  });
  it("the hook's own working directory is an alias", () => tamper(bash("npm run build", ctx({ cwd: `${B}/alias/firewall` }))));
  it("writing the runtime through an alias, and a glob through one", () => {
    tamper(run("Write", { file_path: `${B}/alias/firewall/dist/cli.js`, content: "x" }, ctx()));
    tamper(run("Write", { file_path: `${B}/alias/firewall/dist/sub/new.js`, content: "x" }, ctx()));
    tamper(bash(`rm -rf ${B}/alias/firewall/dist/*`, ctx()));
    tamper(bash(`cd ${B}/alias/firewall && rm -rf dist`, ctx()));
  });
  it("a dangling link into the runtime: writing through it creates the runtime file", () => tamper(run("Write", { file_path: `${B}/dangling`, content: "x" }, ctx())));
  it("the identity recorded through the alias, the agent using the real path", () => {
    const viaAlias = identity(`${B}/alias/firewall`);
    tamper(bash(`cd ${PKG} && npm run build`, ctx({ identity: viaAlias })));
    tamper(run("Write", { file_path: `${PKG}/dist/cli.js`, content: "x" }, ctx({ identity: viaAlias })));
  });
  it("a link created and used in the same command line", () => {
    tamper(bash(`ln -s ${PKG} ${B}/newlink && cd ${B}/newlink && npm run build`, ctx()));
    tamper(bash(`ln -s ${B}/install ${B}/newlink2; npm --prefix ${B}/newlink2/firewall run build`, ctx()));
    tamper(bash(`cd ${B} && ln -s install/firewall rel && cd rel && npm run build`, ctx()));
    // Control: a link to an ordinary directory, then a build there.
    allowed(bash(`ln -s ${PROJ} ${B}/projlink && cd ${B}/projlink && npm run build`, ctx({ workspaceRoots: [PROJ, B] })));
  });
  it("git -C through an alias resolves its paths there", () => {
    tamper(bash(`git -C ${B}/alias/firewall/dist apply ../x.patch && cp /dev/null ${B}/alias/firewall/dist/cli.js`, ctx()));
  });
});

describe("SELF-016: agent config and the firewall home through an alias", () => {
  // The protected rule: a clean session may change the agent's files (the result is checked); an untrusted one may not.
  const cfg = (): RunOpts => ({ ...ctx({ cwd: B, workspaceRoots: [B] }), tainted: true });
  it("~/.claude through a link whose name hides it, including a path that does not exist yet", () => {
    notAllowed(run("Write", { file_path: `${B}/cfg/settings.local.json`, content: "{}" }, cfg()));
    notAllowed(run("Write", { file_path: `${B}/cfg/agents/new/deep/evil.md`, content: "x" }, cfg()));
    notAllowed(bash(`cd ${B}/cfg && echo '{}' > settings.json`, cfg()));
    const clean = run("Write", { file_path: `${B}/cfg/agents/new/deep/evil.md`, content: "x" }, ctx({ cwd: B, workspaceRoots: [B] }));
    expect(clean.effects.map((e) => e.cls), explain(clean)).toContain("write_protected");
  });
  it("the firewall home through an alias", () => {
    tamper(bash(`rm -rf ${B}/fwh/sessions`, ctx()));
    tamper(bash(`cd ${B}/fwh && rm -rf sessions`, ctx()));
    tamper(bash(`cp -r ${B}/homealias/.launchsafe-firewall /tmp/fw`, ctx()));
  });
  it("the firewall home recorded through an alias, the agent using the real path", () => {
    tamper(bash(`rm -rf ${HOMEDIR}/.launchsafe-firewall/sessions`, ctx({ firewallHome: `${B}/fwh`, home: `${B}/homealias` })));
  });
});

describe.runIf(process.platform === "darwin")("SELF-016: /tmp and /private/tmp", () => {
  let T = "";
  beforeAll(() => {
    T = mkdtempSync("/private/tmp/lsfw-self016-");
    makePackage(join(T, "firewall"));
  });
  afterAll(() => rmSync(T, { recursive: true, force: true }));
  const alias = (): string => T.replace(/^\/private\/tmp\//, "/tmp/");
  it("recorded as /private/tmp, reached through /tmp", () => {
    const o = ctx({ identity: identity(join(T, "firewall")) });
    tamper(bash(`cd ${alias()}/firewall && npm run build`, o));
    tamper(bash(`npm --prefix ${alias()}/firewall run build`, o));
  });
  it("recorded as /tmp, reached through /private/tmp", () => {
    const o = ctx({ identity: identity(join(alias(), "firewall")) });
    tamper(bash(`cd ${T}/firewall && npm run build`, o));
  });
});

describe("SELF-016: an unresolvable path fails closed (judged as a protected path)", () => {
  const u = (): RunOpts => ({ ...ctx({ cwd: B, workspaceRoots: [B] }), tainted: true });
  it("a build in a symlink loop is not allowed", () => notAllowed(bash(`cd ${B}/loop/x && npm run build`, ctx())));
  it("a write into a symlink loop is not allowed", () => {
    notAllowed(run("Write", { file_path: `${B}/loop/file.txt`, content: "x" }, u()));
    notAllowed(bash(`echo x > ${B}/loop/file.txt`, u()));
    // In a clean session it is what a protected path is: recorded as one (and checked like one).
    const d = run("Write", { file_path: `${B}/loop/file.txt`, content: "x" }, ctx({ cwd: B, workspaceRoots: [B] }));
    expect(d.effects.some((e) => e.cls === "write_protected" && e.tags?.includes("unresolved") === true), explain(d)).toBe(true);
    // A plain file next to the loop is ordinary.
    allowed(run("Write", { file_path: `${B}/plain.txt`, content: "x" }, ctx({ cwd: B, workspaceRoots: [B] })));
  });
  it.runIf(process.getuid?.() !== 0)("a write under a directory it may not search is not allowed", () => {
    notAllowed(run("Write", { file_path: `${B}/locked/inner/file.txt`, content: "x" }, u()));
  });
  it("the resolver throws on a loop and keeps a missing tail", () => {
    expect(() => realpathStrict(`${B}/loop/x`)).toThrow();
    expect(realpathStrict(`${B}/alias/firewall/dist/not/yet.js`)).toBe(`${PKG}/dist/not/yet.js`);
    expect(realpathStrict(`${B}/dangling`)).toBe(`${PKG}/dist/new.js`);
  });
});

describe("SELF-016 controls: ordinary symlinked projects still work", () => {
  const p = (): RunOpts => ctx({ cwd: `${B}/projalias`, workspaceRoots: [`${B}/projalias`, PROJ] });
  it("a build in a project reached through a symlink", () => {
    allowed(bash("npm run build", p()));
    allowed(bash(`cd ${B}/projalias && npm run build`, p()));
    allowed(bash(`npm --prefix ${B}/projalias run build`, p()));
    allowed(bash(`make -C ${B}/projalias`, p()));
  });
  it("editing the project's source through the symlink", () => {
    allowed(run("Write", { file_path: `${B}/projalias/src/a.ts`, content: "x" }, p()));
    allowed(bash("echo x > src/b.ts", p()));
  });
  it("building another checkout of the firewall (not the installed one) is ordinary work", () => {
    const other = join(B, "checkout");
    makePackage(other);
    allowed(bash("npm run build", ctx({ cwd: other, workspaceRoots: [other] })));
  });
});

describe("SELF-016: a decision's rules list is deduplicated and capped", () => {
  it("265 hits of one rule become a few entries that count the rest", () => {
    const pairs = Array.from({ length: 265 }, (_, i) => ({ rule: "FW-TAINTED-MANIFEST", reason: `npm runs /x/f${i}, which was downloaded` }));
    const r = collapseRules(pairs);
    expect(r.rules).toHaveLength(MAX_ENTRIES_PER_RULE);
    expect(r.reasons).toHaveLength(MAX_ENTRIES_PER_RULE);
    expect(r.reasons[MAX_ENTRIES_PER_RULE - 1]).toContain(`and ${265 - MAX_ENTRIES_PER_RULE} more like it`);
  });
  it("identical pairs appear once, distinct reasons of a rule stay, order is kept", () => {
    const r = collapseRules([
      { rule: "FW-FETCH", reason: "a" },
      { rule: "FW-FETCH", reason: "a" },
      { rule: "FW-SEND", reason: "s" },
      { rule: "FW-FETCH", reason: "b" },
    ]);
    expect(r.rules).toEqual(["FW-FETCH", "FW-SEND", "FW-FETCH"]);
    expect(r.reasons).toEqual(["a", "s", "b"]);
  });
  it("the list is capped", () => {
    const r = collapseRules(Array.from({ length: 40 }, (_, i) => ({ rule: `FW-R${i}`, reason: `r${i}` })));
    expect(r.rules).toHaveLength(MAX_RULE_ENTRIES);
    expect(r.reasons[MAX_RULE_ENTRIES - 1]).toContain("and more rules");
  });
  it("a decision for a build reading many changed files lists the rule a few times at most", () => {
    const events = Array.from({ length: 50 }, (_, i) => ({ type: "tainted_write" as const, path: `${PROJ}/f${i}.config.js` }));
    const d = bash("npm run build", { ...ctx(), tainted: true, events });
    expect(d.rules.length, explain(d)).toBeLessThanOrEqual(MAX_RULE_ENTRIES);
    for (const r of new Set(d.rules)) expect(d.rules.filter((x) => x === r).length).toBeLessThanOrEqual(MAX_ENTRIES_PER_RULE);
  });
});

describe("SELF-016 through the runtime's context (buildContext)", () => {
  // No install record here, so the identity falls back to the running package (this checkout) and the layout's home.
  function decideWith(command: string, cwd: string, fwHome: string): ReturnType<typeof run> {
    const { ctx: c } = buildContext({ l: layout(fwHome), cfg: defaultConfig(), basics: { sessionId: "self016", cwd }, env: {}, home: HOMEDIR, detectNonInteractive: () => false, scratchRoots: [join(B, "scratch")] });
    return decide({ action: { tool: "Bash", input: { command } }, state: emptyState(), config: defaultConfig(), ctx: c });
  }
  it("the running package reached through a symlinked alias", () => {
    const alias = join(B, "repoalias");
    symlinkSync(installDir(), alias);
    tamper(decideWith(`cd ${alias} && npm run build`, PROJ, `${HOMEDIR}/.launchsafe-firewall`));
    tamper(decideWith(`npm --prefix ${alias} run build`, PROJ, `${HOMEDIR}/.launchsafe-firewall`));
    tamper(decideWith("npm run build", alias, `${HOMEDIR}/.launchsafe-firewall`));
  });
  it("the firewall home recorded through an alias, deleted by its real path", () => {
    tamper(decideWith(`rm -rf ${HOMEDIR}/.launchsafe-firewall/sessions`, PROJ, `${B}/fwh`));
  });
});

