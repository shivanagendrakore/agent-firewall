/**
 * F-e (engine): how the provenance ledger's answers change classification. The ledger is stubbed here;
 * test/ledger.test.ts runs the real one through the hook. {O} is a sibling folder outside the workspace.
 */
import { describe, expect, it } from "vitest";
import { defaultConfig } from "../src/policy.js";
import type { Context, Decision, FirewallConfig, StateEvent } from "../src/types.js";
import { bash, explain, HOME, run, WS } from "./helpers.js";

const O = `${HOME}/Developer/ops`;
type Prov = { selfAuthored: boolean; taintedAtWrite: boolean } | null;

function withLedger(files: Record<string, Prov>, dirs: Record<string, { createdBySession: boolean; taintedAtWrite: boolean }> = {}): { ctx: Partial<Context>; calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    ctx: {
      provenance: (p: string) => {
        calls.push(p);
        return files[p] ?? null;
      },
      dirProvenance: (p: string) => dirs[p] ?? null,
    },
  };
}

const SELF: Prov = { selfAuthored: true, taintedAtWrite: false };
const SELF_TAINTED: Prov = { selfAuthored: true, taintedAtWrite: true };
const CHANGED: Prov = { selfAuthored: false, taintedAtWrite: false };
const CHANGED_TAINTED: Prov = { selfAuthored: false, taintedAtWrite: true };

const taints = (d: Decision): boolean => d.events.some((e) => e.type === "taint");
const taintSource = (d: Decision): string => d.events.filter((e): e is Extract<StateEvent, { type: "taint" }> => e.type === "taint").map((e) => e.source).join(" | ");
const provCfg = (p: Partial<FirewallConfig["provenance"]>): Partial<FirewallConfig> => ({ provenance: { ...defaultConfig().provenance, ...p } });

describe("F-e reads outside the workspace", () => {
  it("E1/E2: content a trusted session wrote reads without taint (Read, cat, rg)", () => {
    const { ctx } = withLedger({ [`${O}/notes.md`]: SELF });
    for (const d of [run("Read", { file_path: `${O}/notes.md` }, { ctx }), bash(`cat ${O}/notes.md`, { ctx }), bash(`rg TODO ${O}/notes.md`, { ctx })]) {
      expect(d.verdict, explain(d)).toBe("allow");
      expect(taints(d), explain(d)).toBe(false);
      expect(d.effects.some((e) => e.cls === "read_local_workspace" && (e.tags ?? []).includes("self-authored")), explain(d)).toBe(true);
    }
  });
  it("E3: changed since the agent wrote it: taints, and says why", () => {
    const d = run("Read", { file_path: `${O}/notes.md` }, { ctx: withLedger({ [`${O}/notes.md`]: CHANGED }).ctx });
    expect(d.verdict).toBe("allow");
    expect(taintSource(d)).toMatch(/something else changed since/);
  });
  it("E4: written by an untrusted session: taints, and says why", () => {
    const d = run("Read", { file_path: `${O}/notes.md` }, { ctx: withLedger({ [`${O}/notes.md`]: SELF_TAINTED }).ctx });
    expect(taintSource(d)).toMatch(/an untrusted session wrote/);
  });
  it("no entry: the v0.1 classification", () => {
    const d = run("Read", { file_path: `${O}/other.md` }, { ctx: withLedger({}).ctx });
    expect(taintSource(d)).toMatch(/a file outside the workspace/);
  });
  it("a ledger lookup that throws falls back to the v0.1 classification", () => {
    const d = run("Read", { file_path: `${O}/notes.md` }, { ctx: { provenance: () => { throw new Error("io"); } } });
    expect(taints(d)).toBe(true);
  });
  it("E12: trustSelfAuthored false: every outside read taints, the ledger is not consulted", () => {
    const { ctx, calls } = withLedger({ [`${O}/notes.md`]: SELF });
    const d = run("Read", { file_path: `${O}/notes.md` }, { ctx, config: provCfg({ trustSelfAuthored: false }) });
    expect(taints(d)).toBe(true);
    expect(calls).toEqual([]);
  });
  it("E15: a self-authored file that holds copied credentials is still a secret read", () => {
    const { ctx } = withLedger({ [`${O}/x`]: SELF });
    const d = run("Read", { file_path: `${O}/x` }, { ctx, events: [{ type: "secret_path", path: `${O}/x` }] });
    expect(d.effects[0]?.cls, explain(d)).toBe("read_secret");
    expect(d.events.some((e) => e.type === "sensitive")).toBe(true);
  });
  it("a downloaded file stays outside content even if the ledger had a trusted entry", () => {
    const { ctx } = withLedger({ [`${O}/x.txt`]: SELF });
    const d = bash(`cat ${O}/x.txt`, { ctx, events: [{ type: "downloaded", path: `${O}/x.txt` }] });
    expect(taintSource(d)).toMatch(/a downloaded file/);
  });
  it("ordinary workspace reads never consult the ledger (no hashing on the common path)", () => {
    const { ctx, calls } = withLedger({});
    run("Read", { file_path: `${WS}/src/a.ts` }, { ctx });
    bash("cat src/a.ts && git status && ls -la", { ctx });
    run("Grep", { pattern: "x", path: WS }, { ctx });
    expect(calls).toEqual([]);
  });
  it("credential stores and firewall files are unaffected by the ledger", () => {
    const { ctx } = withLedger({ [`${HOME}/.aws/credentials`]: SELF });
    expect(run("Read", { file_path: `${HOME}/.aws/credentials` }, { ctx }).effects[0]?.cls).toBe("read_secret");
  });
});

describe("F-e listings", () => {
  it("E8: a directory a trusted session created lists without taint (LS, Glob, ls)", () => {
    const { ctx } = withLedger({}, { [`${O}/drafts`]: { createdBySession: true, taintedAtWrite: false } });
    for (const d of [run("LS", { path: `${O}/drafts` }, { ctx }), run("Glob", { pattern: "*.md", path: `${O}/drafts` }, { ctx }), bash(`ls ${O}/drafts`, { ctx })]) {
      expect(d.verdict, explain(d)).toBe("allow");
      expect(taints(d), explain(d)).toBe(false);
    }
  });
  it("a directory an untrusted session created, or one nobody recorded, still taints when listed", () => {
    const { ctx } = withLedger({}, { [`${O}/drafts`]: { createdBySession: true, taintedAtWrite: true } });
    expect(taints(run("LS", { path: `${O}/drafts` }, { ctx }))).toBe(true);
    expect(taints(bash(`ls ${O}/drafts`, { ctx }))).toBe(true);
    expect(taints(bash(`ls ${O}/elsewhere`, { ctx }))).toBe(true);
  });
  it("trustSelfAuthored false: listings taint as in v0.1", () => {
    const { ctx } = withLedger({}, { [`${O}/drafts`]: { createdBySession: true, taintedAtWrite: false } });
    expect(taints(run("LS", { path: `${O}/drafts` }, { ctx, config: provCfg({ trustSelfAuthored: false }) }))).toBe(true);
  });
});

describe("F-e execution and manifests across sessions", () => {
  it("E5: npm test after an untrusted session changed package.json (still matching): ask FW-TAINTED-MANIFEST", () => {
    const d = bash("npm test", { ctx: withLedger({ [`${WS}/package.json`]: SELF_TAINTED }).ctx });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-TAINTED-MANIFEST");
  });
  it("E6: changed since by someone else (the person): allow", () => {
    expect(bash("npm test", { ctx: withLedger({ [`${WS}/package.json`]: CHANGED_TAINTED }).ctx }).verdict).toBe("allow");
  });
  it("a trusted session's own manifest change: allow", () => {
    expect(bash("npm test", { ctx: withLedger({ [`${WS}/package.json`]: SELF }).ctx }).verdict).toBe("allow");
  });
  it("E7: running a script an untrusted session wrote: ask FW-UNTRUSTED-CODE in a trusted session", () => {
    const { ctx } = withLedger({ [`${WS}/scripts/fix.sh`]: SELF_TAINTED });
    const d = bash("bash scripts/fix.sh", { ctx });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-UNTRUSTED-CODE");
    expect(bash("./scripts/fix.sh", { ctx }).rules).toContain("FW-UNTRUSTED-CODE");
  });
  it("E7 changed since: plain workspace code", () => {
    expect(bash("bash scripts/fix.sh", { ctx: withLedger({ [`${WS}/scripts/fix.sh`]: CHANGED_TAINTED }).ctx }).verdict).toBe("allow");
  });
  it("carryUntrustedWrites false: no cross-session carry", () => {
    const cfg = provCfg({ carryUntrustedWrites: false });
    expect(bash("npm test", { ctx: withLedger({ [`${WS}/package.json`]: SELF_TAINTED }).ctx, config: cfg }).verdict).toBe("allow");
    expect(bash("bash scripts/fix.sh", { ctx: withLedger({ [`${WS}/scripts/fix.sh`]: SELF_TAINTED }).ctx, config: cfg }).verdict).toBe("allow");
  });
  it("git commit runs a pre-commit hook an untrusted session wrote: ask FW-TAINTED-MANIFEST (GIT-003)", () => {
    const d = bash("git commit -m x", { ctx: withLedger({ [`${WS}/.git/hooks/pre-commit`]: SELF_TAINTED }).ctx });
    expect(d.rules, explain(d)).toContain("FW-TAINTED-MANIFEST");
  });
  it("a self-authored script outside the workspace runs as ordinary code, not outside code", () => {
    expect(bash(`bash ${O}/run.sh`, { ctx: withLedger({ [`${O}/run.sh`]: SELF }).ctx }).verdict).toBe("allow");
    expect(bash(`bash ${O}/run.sh`, { ctx: withLedger({}).ctx }).rules).toContain("FW-UNTRUSTED-CODE");
  });
  it("in an untrusted session, a script an earlier untrusted session wrote is denied like any untrusted code", () => {
    const d = bash("bash scripts/fix.sh", { tainted: true, ctx: withLedger({ [`${WS}/scripts/fix.sh`]: SELF_TAINTED }).ctx });
    expect(d.verdict).toBe("deny");
  });
});

describe("R3: install inputs (lockfiles, registry config, requirement files) carry like manifests", () => {
  const carried = (f: string): Partial<Context> => withLedger({ [`${WS}/${f}`]: SELF_TAINTED }).ctx;
  it.each([
    ["package-lock.json", "npm ci"],
    ["npm-shrinkwrap.json", "npm install"],
    ["yarn.lock", "yarn install --frozen-lockfile"],
    [".yarnrc.yml", "yarn"],
    ["bun.lockb", "bun install"],
    ["pnpm-lock.yaml", "pnpm i"],
    [".npmrc", "pnpm install"],
    ["requirements.txt", "pip3 install -r requirements.txt"],
    ["reqs/dev.txt", "pip install -r reqs/dev.txt"],
    ["constraints/base.txt", "pip install --constraint=constraints/base.txt ."],
    ["requirements.txt", "python -m pip install -r requirements.txt"],
    ["uv.lock", "uv sync --frozen"],
    ["poetry.lock", "poetry install"],
    ["Pipfile.lock", "pipenv install"],
    ["Gemfile.lock", "bundle install"],
    ["go.sum", "go mod download"],
    ["Cargo.lock", "cargo build"],
    ["composer.lock", "composer install"],
  ])("%s carried, then `%s` asks FW-TAINTED-MANIFEST", (f, cmd) => {
    const d = bash(cmd, { ctx: carried(f) });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-TAINTED-MANIFEST");
  });
  it("the same edits within the untrusted session itself (tainted_write) hold the install too", () => {
    const d = bash("npm ci", { tainted: true, events: [{ type: "tainted_write", path: `${WS}/package-lock.json` }] });
    expect(d.rules, explain(d)).toContain("FW-TAINTED-MANIFEST");
  });
  it("precision: a carried lockfile does not touch a script run, and a person's own later edit clears it", () => {
    expect(bash("npm test", { ctx: carried("package-lock.json") }).verdict).toBe("allow");
    expect(bash("npm ci", { ctx: withLedger({ [`${WS}/package-lock.json`]: CHANGED_TAINTED }).ctx }).verdict).toBe("allow");
    expect(bash("npm ci", { ctx: withLedger({ [`${WS}/package-lock.json`]: SELF }).ctx }).verdict).toBe("allow");
  });
});

describe("R8: a project script runs its JS tools' config-as-code; git commit runs hook-framework configs", () => {
  const written = (f: string): { tainted: true; events: StateEvent[] } => ({ tainted: true, events: [{ type: "tainted_write", path: `${WS}/${f}` }] });
  it.each([
    ["vite.config.mts", "pnpm run build"],
    ["eslint.config.js", "npm run lint"],
    ["playwright.config.ts", "yarn test"],
    ["next.config.mjs", "bun run dev"],
    ["webpack.config.js", "npm start"],
    ["lefthook.yml", "git commit -m wip"],
    [".pre-commit-config.yaml", "git merge main"],
  ])("an untrusted write of %s, then `%s`, needs a person", (f, cmd) => {
    const d = bash(cmd, written(f));
    expect(d.rules, explain(d)).toContain("FW-TAINTED-MANIFEST");
  });
  it("carried across sessions too", () => {
    expect(bash("npm test", { ctx: withLedger({ [`${WS}/vitest.config.ts`]: SELF_TAINTED }).ctx }).rules).toContain("FW-TAINTED-MANIFEST");
  });
  it("precision: an ordinary source file written after taint does not hold npm test", () => {
    expect(bash("npm test", written("src/index.ts")).verdict).toBe("allow");
  });
});

describe("R10: files CLAUDE.md imports are protected like CLAUDE.md", () => {
  const files: Record<string, string> = {
    [`${WS}/CLAUDE.md`]: "# proj\n\n@docs/conventions.md\n@~/.config/team/rules.md\n",
    [`${WS}/docs/conventions.md`]: "# c\n@./deeper.md\n",
    [`${WS}/pkg/CLAUDE.md`]: "@notes.md\n",
  };
  const readFile = (p: string): string | null => files[p] ?? null;
  it.each([`${WS}/docs/conventions.md`, `${WS}/docs/deeper.md`, `${HOME}/.config/team/rules.md`, `${WS}/pkg/notes.md`])("an untrusted write of %s is held as a proposal", (p) => {
    const d = run("Write", { file_path: p, content: "x" }, { tainted: true, ctx: { readFile } });
    expect(d.verdict, explain(d)).toBe("queue");
    expect(d.rules).toContain("FW-INSTRUCTIONS-HELD");
  });
  it("a shell write to an imported file is held too", () => {
    expect(bash("echo x >> docs/conventions.md", { tainted: true, ctx: { readFile } }).rules).toContain("FW-INSTRUCTIONS-HELD");
  });
  it("trusted writes stay allowed (allowInstructionWritesWhenTrusted), and files nothing imports are ordinary", () => {
    expect(run("Write", { file_path: `${WS}/docs/conventions.md`, content: "x" }, { ctx: { readFile } }).verdict).toBe("allow");
    expect(run("Write", { file_path: `${WS}/docs/other.md`, content: "x" }, { tainted: true, ctx: { readFile } }).verdict).toBe("allow");
  });
});
