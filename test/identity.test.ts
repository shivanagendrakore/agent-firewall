/**
 * F-c: self-protection keyed to the installed runtime, not to names. Rows C1-C21 and FP1-FP6.
 * Fixture: the hook command runs {P}/dist/cli.js, where {P} is a
 * source checkout; the data directory is {H}/.launchsafe-firewall.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { identityOf } from "../src/engine/identity.js";
import { MARKER } from "../src/engine/settings.js";
import { doctor } from "../src/runtime/doctor.js";
import { buildIdentity, loadIdentity, parseHookCommand } from "../src/runtime/identity.js";
import { withOurs } from "../src/runtime/install.js";
import { layout } from "../src/runtime/layout.js";
import type { Context, FirewallIdentity } from "../src/types.js";
import { bash, explain, HOME, run, testRoot, type RunOpts } from "./helpers.js";

const P = "/Users/dev/src/agent-firewall";
const NODE = "/opt/homebrew/Cellar/node/22.9.0/bin/node";
const IDENTITY: FirewallIdentity = {
  cliFiles: [`${P}/dist/cli.js`],
  runtimeRoots: [`${P}/dist`, `${P}/node_modules`],
  runtimeFiles: [`${P}/package.json`],
  packageRoots: [P],
  nodeBinaries: [NODE],
  dataRoots: [`${HOME}/.launchsafe-firewall`],
  binNames: ["launchsafe-firewall"],
  source: "hook-command",
};
const PACKED: FirewallIdentity = { ...IDENTITY, cliFiles: ["/opt/lsfw/lib/node_modules/@launchsafe/agent-firewall/dist/cli.js"], runtimeRoots: ["/opt/lsfw/lib/node_modules/@launchsafe/agent-firewall/dist", "/opt/lsfw/lib/node_modules/@launchsafe/agent-firewall/node_modules"], runtimeFiles: ["/opt/lsfw/lib/node_modules/@launchsafe/agent-firewall/package.json"], packageRoots: ["/opt/lsfw/lib/node_modules/@launchsafe/agent-firewall"] };

const T = (ctx: Partial<Context> = {}): RunOpts => ({ ctx: { identity: IDENTITY, firewallInstallDir: "", ...ctx } });
const U = (ctx: Partial<Context> = {}): RunOpts => ({ ...T(ctx), tainted: true });

function allowed(d: ReturnType<typeof run>): void {
  expect(d.verdict, explain(d)).toBe("allow");
}
function tamper(d: ReturnType<typeof run>): void {
  expect(d.verdict, explain(d)).toBe("deny");
  expect(d.rules, explain(d)).toContain("FW-TAMPER");
}

describe("acceptance rows C1-C18, C21", () => {
  it("C1: a read-only clone of the firewall's checkout is allowed", () => allowed(bash(`git clone ${P} /tmp/review`, T())));
  it("C2: a folder named after the product is allowed", () => allowed(bash("mkdir -p ~/Developer/launchsafe-firewall-notes", T())));
  it("C3: a sibling folder named launchsafe-firewall is allowed", () => allowed(bash("mkdir ../launchsafe-firewall", T())));
  it("C4: reading its docs and searching its source in an untrusted session is allowed", () => {
    allowed(bash(`cat ${P}/docs/design.md`, U()));
    allowed(bash(`rg FW-SEND ${P}/src`, U()));
  });
  it("C5: copying its docs elsewhere is allowed", () => allowed(bash(`cp -r ${P}/docs /tmp/d`, T())));
  it("C6: editing its source with the checkout as the workspace is ordinary work", () => {
    allowed(run("Edit", { file_path: `${P}/src/engine/decide.ts`, old_string: "a", new_string: "b" }, T({ cwd: P, workspaceRoots: [P] })));
  });
  it("C7: building the installed runtime from inside the agent is tampering", () => tamper(bash("npm run build", T({ cwd: P, workspaceRoots: [P] }))));
  it("C7 (other runners): tsc, make, npm install, npx tsc in the package root", () => {
    for (const c of ["tsc -p tsconfig.build.json", "make", "npm install", "npx tsc", "pnpm build"]) tamper(bash(c, T({ cwd: P, workspaceRoots: [P] })));
  });
  it("C8: writing its CLI file is tampering", () => tamper(run("Write", { file_path: `${P}/dist/cli.js`, content: "x" }, T())));
  it("C9: running its CLI through node to approve a held action is tampering", () => tamper(bash(`node ${P}/dist/cli.js queue approve q1`, U())));
  it("C10: replacing a runtime file with a symlink is tampering", () => tamper(bash(`ln -s /tmp/x ${P}/dist/engine/decide.js`, T())));
  it("C11: a symlink to the CLI, then running it, is tampering", () => {
    tamper(bash(`ln -s ${P}/dist/cli.js ~/bin/lf && lf uninstall`, T()));
    const realpath = (p: string): string => (p === `${HOME}/bin/lf` ? `${P}/dist/cli.js` : p);
    tamper(bash("~/bin/lf uninstall", T({ realpath })));
  });
  it("C12: the package through npx is tampering", () => tamper(bash("npx @launchsafe/agent-firewall uninstall", T())));
  it("C12 (other runners): npm exec, pnpm dlx, bunx, npx -p", () => {
    for (const c of ["npm exec @launchsafe/agent-firewall -- uninstall", "pnpm dlx @launchsafe/agent-firewall@0.2.0 uninstall", "bunx @launchsafe/agent-firewall queue approve q1", "npx -p @launchsafe/agent-firewall launchsafe-firewall uninstall", "npx --package=@launchsafe/agent-firewall launchsafe-firewall uninstall"]) tamper(bash(c, T()));
  });
  it("C13: copying the data directory (keys) is tampering", () => tamper(bash("cp -r ~/.launchsafe-firewall /tmp/fw", T())));
  it("C13 (archives): tar of the data directory is tampering", () => tamper(bash("tar czf /tmp/fw.tgz -C ~/.launchsafe-firewall .", T())));
  it("C14: deleting its sessions is tampering", () => tamper(bash("rm -rf ~/.launchsafe-firewall/sessions", T())));
  it("C15: the CLI inside a pseudo-terminal wrapper is tampering", () => tamper(bash("script -q /dev/null launchsafe-firewall queue approve q1", U())));
  it("C16: writing over the node binary the hook command names is tampering", () => {
    tamper(run("Write", { file_path: NODE, content: "x" }, T()));
    tamper(bash(`cp /tmp/evil ${NODE}`, T()));
  });
  it("C17: pkill naming its command is tampering", () => tamper(bash("pkill -f launchsafe-firewall", T())));
  it("C17 (other forms): its CLI path or marker variable", () => {
    tamper(bash(`pkill -f ${P}/dist/cli.js`, T()));
    tamper(bash("pkill -f agent-firewall/dist/cli.js", T()));
    tamper(bash("pkill -f LAUNCHSAFE_FIREWALL_HOOK", T()));
  });
  it("C18: launchsafe-firewall status is allowed in an untrusted session", () => allowed(bash("launchsafe-firewall status", U())));
  it("C21: with a packed install elsewhere, building the checkout is ordinary work", () => {
    allowed(bash("npm run build", { ctx: { identity: PACKED, firewallInstallDir: "", cwd: P, workspaceRoots: [P] } }));
    tamper(bash("npm run build", { ctx: { identity: PACKED, firewallInstallDir: "", cwd: PACKED.packageRoots[0] as string, workspaceRoots: [P] } }));
  });
  it("C21 (I1): a build in the installed package spelled in other case is tampering on a case-sensitive platform", () => {
    const root = PACKED.packageRoots[0] as string;
    const ctx = { caseInsensitive: false, identity: PACKED, firewallInstallDir: "", workspaceRoots: [P] };
    tamper(bash("npm run build", { ctx: { ...ctx, cwd: root.toUpperCase() } }));
    tamper(bash(`cd ${root.replace("agent-firewall", "Agent-Firewall")} && npm run build`, { ctx: { ...ctx, cwd: P } }));
    // The checkout itself stays ordinary work.
    allowed(bash("npm run build", { ctx: { ...ctx, cwd: P } }));
  });
  it("C21 (tracked directory): a build that reaches the installed working copy by cd, -C or --prefix is tampering", () => {
    const W = "/Users/dev/work/app";
    const ctx = { identity: IDENTITY, firewallInstallDir: "", cwd: W, workspaceRoots: [W] };
    allowed(bash("npm run build", { ctx }));
    tamper(bash(`cd ${P} && npm run build`, { ctx }));
    tamper(bash(`make -C ${P}`, { ctx }));
    tamper(bash(`npm --prefix ${P} run build`, { ctx }));
    tamper(bash(`pnpm -C ${P} build`, { ctx }));
    tamper(bash(`(cd ${P}/src && tsc)`, { ctx }));
    // Leaving the package root again is ordinary work.
    allowed(bash(`cd ${P} && cd ${W} && npm run build`, { ctx }));
    // A build in a directory the firewall cannot follow, with a working-copy install, is not allowed silently.
    expect(bash('cd "$DIR" && npm run build', { ctx }).verdict).not.toBe("allow");
    // With a packed install the unknown directory cannot be the installed package's sources.
    allowed(bash('cd "$DIR" && npm run build', { ctx: { ...ctx, identity: PACKED } }));
  });
});

describe("false positives (allowed)", () => {
  it("FP1: pkill -f firewalld-mock, kill %1", () => {
    allowed(bash("pkill -f firewalld-mock", T()));
    allowed(bash("kill %1", T()));
  });
  it("FP2: ls ~/Developer/agent-firewall*, du -sh {P}", () => {
    allowed(bash("ls ~/Developer/agent-firewall*", T()));
    allowed(bash(`du -sh ${P}`, T()));
  });
  it("FP3: git -C {P} log --oneline -5, git -C {P} diff", () => {
    allowed(bash(`git -C ${P} log --oneline -5`, T()));
    allowed(bash(`git -C ${P} diff`, T()));
  });
  it("FP4: grep -rn launchsafe-firewall README.md", () => allowed(bash("grep -rn launchsafe-firewall README.md", T())));
  it("FP5: mv notes/launchsafe-firewall.md notes/old.md", () => allowed(bash("mv notes/launchsafe-firewall.md notes/old.md", T())));
  it("FP6: tar czf /tmp/src.tgz -C {P} src docs", () => allowed(bash(`tar czf /tmp/src.tgz -C ${P} src docs`, T())));
  it("running a file named like the CLI that resolves elsewhere is not the firewall (nothing by name)", () => {
    const realpath = (p: string): string => p;
    const d = bash("node scripts/launchsafe-firewall.js uninstall", T({ realpath }));
    expect(d.rules).not.toContain("FW-TAMPER");
  });
  it("copying the runtime out (a read) is allowed; copying into it is tampering", () => {
    allowed(bash(`cp -r ${P}/dist /tmp/x`, T()));
    tamper(bash(`cp evil.js ${P}/dist/cli.js`, T()));
  });
});

describe("fail closed", () => {
  it("a bare launchsafe-firewall is the CLI whatever PATH holds", () => tamper(bash("launchsafe-firewall uninstall", T())));
  it("a path named like the CLI is the CLI when symlinks cannot be resolved", () => {
    tamper(bash("/usr/local/bin/launchsafe-firewall uninstall", T()));
    tamper(bash("/usr/local/bin/launchsafe-firewall uninstall", T({ realpath: () => { throw new Error("EACCES"); } })));
  });
  it("without an identity, the deprecated install dir is narrowed to dist/, node_modules/ and package.json", () => {
    const opts: RunOpts = { ctx: { firewallInstallDir: P } };
    tamper(run("Write", { file_path: `${P}/dist/cli.js`, content: "x" }, opts));
    tamper(run("Write", { file_path: `${P}/package.json`, content: "{}" }, opts));
    allowed(run("Write", { file_path: `${P}/docs/x.md`, content: "x" }, { ctx: { firewallInstallDir: P, workspaceRoots: [P], cwd: P } }));
  });
  it("the data directory is protected even when the identity omits it", () => {
    tamper(bash("rm -rf ~/.launchsafe-firewall", { ctx: { identity: { ...IDENTITY, dataRoots: [] }, firewallInstallDir: "" } }));
  });
  it("identityOf adds the context's data roots and the CLI's command name", () => {
    const id = identityOf({ cwd: "/", workspaceRoots: [], home: HOME, scratchRoots: [], firewallHome: "/srv/fw", firewallInstallDir: "", interactive: true, caseInsensitive: false, identity: { ...IDENTITY, binNames: [], dataRoots: [] } });
    expect(id.dataRoots).toEqual(expect.arrayContaining(["/srv/fw", `${HOME}/.launchsafe-firewall`]));
    expect(id.binNames).toContain("launchsafe-firewall");
  });
});

describe("building the identity from what is installed (C19, C20)", () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(testRoot(), "fc-"));
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function pkg(dir: string): string {
    mkdirSync(join(dir, "dist"), { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@launchsafe/agent-firewall", version: "0.2.0" }));
    writeFileSync(join(dir, "dist", "cli.js"), "#!/usr/bin/env node\n");
    return join(dir, "dist", "cli.js");
  }
  function settings(cli: string, extra = ""): string {
    const p = join(root, "home", ".claude", "settings.json");
    mkdirSync(join(root, "home", ".claude"), { recursive: true });
    writeFileSync(p, JSON.stringify(withOurs({}, `${MARKER} ${extra}'/usr/local/bin/node' '${cli}' hook || exit 2`)));
    return p;
  }

  it("parses the installed hook command", () => {
    expect(parseHookCommand(`${MARKER} LAUNCHSAFE_FIREWALL_HOME='/srv/fw' LAUNCHSAFE_FIREWALL_APPROVER='AAAA' '/usr/bin/node' '/opt/lsfw/dist/cli.js' hook || exit 2`)).toEqual({ node: "/usr/bin/node", cli: "/opt/lsfw/dist/cli.js", firewallHome: "/srv/fw", clearsCompileCache: false, clearsLoaderEnv: false, pinsHome: false });
    expect(parseHookCommand(`${MARKER} NODE_COMPILE_CACHE= '/usr/bin/node' '/opt/lsfw/dist/cli.js' hook || exit 2`)?.clearsCompileCache).toBe(true);
    expect(parseHookCommand(`${MARKER} NODE_COMPILE_CACHE=/tmp/x '/usr/bin/node' '/opt/lsfw/dist/cli.js' hook || exit 2`)?.clearsCompileCache).toBe(false);
    expect(parseHookCommand("echo hi")).toBeNull();
    expect(parseHookCommand(`${MARKER} "$NODE" "$CLI" hook`)).toBeNull();
  });
  it("C19: the CLI named in the hook command and its package's dist/ are the runtime", () => {
    const cli = pkg(join(root, "opt", "lsfw"));
    const id = buildIdentity(layout(join(root, "home", ".launchsafe-firewall")), [settings(cli, "LAUNCHSAFE_FIREWALL_HOME='/srv/fw' ")], { home: join(root, "home"), env: {} });
    expect(id.source).toBe("hook-command");
    expect(id.cliFiles).toContain(cli);
    expect(id.runtimeRoots).toContain(join(root, "opt", "lsfw", "dist"));
    expect(id.runtimeFiles).toContain(join(root, "opt", "lsfw", "package.json"));
    expect(id.nodeBinaries).toContain("/usr/local/bin/node");
    expect(id.dataRoots).toContain("/srv/fw");
  });
  it("a CLI path that no longer exists is still protected (re-creating it would change what runs)", () => {
    const id = buildIdentity(layout(join(root, "fw")), [settings("/opt/gone/dist/cli.js")], { home: root, env: {} });
    expect(id.cliFiles).toContain("/opt/gone/dist/cli.js");
  });
  it("C20: no install record and no managed settings: fallback identity, and doctor warns", () => {
    const l = layout(join(root, "fw"));
    const id = buildIdentity(l, [], { home: root, env: {}, installDir: "/opt/x" });
    expect(id.source).toBe("fallback-install-dir");
    expect(id.runtimeRoots).toContain("/opt/x/dist");
    expect(id.dataRoots).toContain(join(root, "fw"));
    const check = doctor(l, root, { home: root, platform: "darwin", claudeVersion: "2.1.289" }).find((c) => c.name === "firewall identity");
    expect(check?.status).toBe("warn");
    expect(check?.detail).toMatch(/falls back/);
  });
  it("the identity is cached by the settings files' size and mtime, rebuilt when they change or the cache is corrupt", () => {
    const l = layout(join(root, "fw"));
    mkdirSync(l.home, { recursive: true });
    const s = settings(pkg(join(root, "a")));
    const first = loadIdentity(l, [s], { home: root, env: {} });
    expect(first.cliFiles).toContain(join(root, "a", "dist", "cli.js"));
    writeFileSync(s, JSON.stringify(withOurs({}, `${MARKER} '/usr/local/bin/node' '${pkg(join(root, "bb"))}' hook || exit 2`)));
    expect(loadIdentity(l, [s], { home: root, env: {} }).cliFiles).toContain(join(root, "bb", "dist", "cli.js"));
    writeFileSync(join(l.home, "identity.json"), "{not json");
    expect(loadIdentity(l, [s], { home: root, env: {} }).cliFiles).toContain(join(root, "bb", "dist", "cli.js"));
  });
});
