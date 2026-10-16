/**
 * F-f: relative paths resolve against the directory the shell would be in (cd, pushd/popd, subshells,
 * brace groups, -C style flags). Acceptance rows F1-F18 and false positives FP1-FP6.
 * Workspace {W} = /Users/dev/proj, sibling {O} = /Users/dev/ops.
 */
import { describe, expect, it } from "vitest";
import { parseShell } from "../src/engine/shell/parse.js";
import type { StateEvent } from "../src/types.js";
import { bash, explain, TAINTED } from "./helpers.js";

const W = "/Users/dev/proj";
const O = "/Users/dev/ops";
const tw = (path: string): StateEvent => ({ type: "tainted_write", path });
const targets = (d: ReturnType<typeof bash>, cls: string): string[] => d.effects.filter((e) => e.cls === cls).map((e) => e.target);

describe("parser keeps connectors and group kinds", () => {
  it("records the connector after each pipeline and the kind of group", () => {
    const s = parseShell("cd a && ls; b || c & d\ne");
    expect(s.pipelines.map((p) => p.next)).toEqual(["&&", ";", "||", "&", "\n", undefined]);
    const g = parseShell("(cd x) && { cd y; }");
    expect(g.pipelines.map((p) => p.commands[0]?.groupKind)).toEqual(["subshell", "brace"]);
  });
});

describe("F-f acceptance", () => {
  it("F1: cd ../ops && cat > notes.md (untrusted) writes {O}/notes.md: FW-OUTSIDE-WRITE", () => {
    const d = bash("cd ../ops && cat > notes.md <<'EOF'\nx\nEOF", { tainted: true });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-OUTSIDE-WRITE");
    expect(targets(d, "write_outside_workspace")).toContain(`${O}/notes.md`);
  });
  it("F2: the same, trusted, is allowed", () => {
    const d = bash("cd ../ops && cat > notes.md <<'EOF'\nx\nEOF");
    expect(d.verdict, explain(d)).toBe("allow");
    expect(targets(d, "write_outside_workspace")).toContain(`${O}/notes.md`);
  });
  it("F3: cd ../ops && cat notes.md (trusted) is allowed and taints (outside read)", () => {
    const d = bash("cd ../ops && cat notes.md");
    expect(d.verdict, explain(d)).toBe("allow");
    expect(d.events.some((e) => e.type === "taint" && e.source.includes(`${O}/notes.md`))).toBe(true);
  });
  it("F4: cd .git && echo x > hooks/pre-commit (untrusted): FW-PERSISTENCE-HELD on {W}/.git/hooks/pre-commit", () => {
    const d = bash("cd .git && echo x > hooks/pre-commit", { tainted: true });
    // A git hook written by an untrusted session is held as a proposal (it was FW-PERSISTENCE, ask, before).
    expect(d.verdict, explain(d)).toBe("queue");
    expect(d.rules).toContain("FW-PERSISTENCE-HELD");
    expect(targets(d, "write_persistence")).toContain(`${W}/.git/hooks/pre-commit`);
  });
  it("F5: cd sub && echo x > ../../.bashrc (trusted) writes /Users/dev/.bashrc: FW-PERSISTENCE", () => {
    const d = bash("cd sub && echo x > ../../.bashrc");
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-PERSISTENCE");
    expect(targets(d, "write_persistence")).toContain("/Users/dev/.bashrc");
  });
  it("F6: (cd /tmp && rm -rf build) && rm -rf build is allowed (scratch, then the workspace build dir)", () => {
    const d = bash("(cd /tmp && rm -rf build) && rm -rf build");
    expect(d.verdict, explain(d)).toBe("allow");
    expect(d.effects.map((e) => e.target)).toEqual(expect.arrayContaining(["/tmp/build", `${W}/build`]));
  });
  it("F7: cd ~ && rm -rf * is FW-DESTROY-ROOT", () => {
    const d = bash("cd ~ && rm -rf *");
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).toContain("FW-DESTROY-ROOT");
  });
  it("F8: cd packages/web && npm test after its package.json was edited untrusted: FW-TAINTED-MANIFEST", () => {
    const d = bash("cd packages/web && npm test", { tainted: true, events: [tw(`${W}/packages/web/package.json`)] });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-TAINTED-MANIFEST");
  });
  it("F9: cd packages/web && npm test after edits to {W}/package.json only is allowed", () => {
    const d = bash("cd packages/web && npm test", { tainted: true, events: [tw(`${W}/package.json`)] });
    expect(d.verdict, explain(d)).toBe("allow");
  });
  it('F10: cd "$(git rev-parse --show-toplevel)" && echo x > CLAUDE.md (untrusted): held', () => {
    const d = bash('cd "$(git rev-parse --show-toplevel)" && echo x > CLAUDE.md', { tainted: true });
    expect(d.verdict, explain(d)).toBe("queue");
    expect(d.rules).toContain("FW-INSTRUCTIONS-HELD");
    expect(targets(d, "write_protected")).toContain(`${W}/CLAUDE.md`);
  });
  it('F11: cd "$SOME_DIR" && echo x > out.txt (trusted): FW-UNCLASSIFIABLE', () => {
    const d = bash('cd "$SOME_DIR" && echo x > out.txt');
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-UNCLASSIFIABLE");
  });
  it('F12: cd "$SOME_DIR" && cat README.md (trusted) is allowed without taint', () => {
    const d = bash('cd "$SOME_DIR" && cat README.md');
    expect(d.verdict, explain(d)).toBe("allow");
    expect(d.events.some((e) => e.type === "taint")).toBe(false);
  });
  it('F13: cd "$SOME_DIR" && cat .env (trusted) is allowed and marks the session sensitive', () => {
    const d = bash('cd "$SOME_DIR" && cat .env');
    expect(d.verdict, explain(d)).toBe("allow");
    expect(d.effects.some((e) => e.cls === "read_secret")).toBe(true);
    expect(d.events.some((e) => e.type === "sensitive")).toBe(true);
  });
  it("F14: pushd ../ops && touch a && popd && touch b (untrusted): FW-OUTSIDE-WRITE for {O}/a only", () => {
    const d = bash("pushd ../ops && touch a && popd && touch b", { tainted: true });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(targets(d, "write_outside_workspace")).toEqual([`${O}/a`]);
    expect(targets(d, "write_workspace")).toContain(`${W}/b`);
  });
  it("F15: git -C ../ops commit checks {O}'s git hooks", () => {
    const d = bash("git -C ../ops commit -am x", { tainted: true, events: [tw(`${O}/.git/hooks/pre-commit`)] });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-TAINTED-MANIFEST");
    expect(bash("git commit -am x", { tainted: true, events: [tw(`${O}/.git/hooks/pre-commit`)] }).verdict).toBe("allow");
  });
  it('F16: D=../ops; cd "$D" && echo x > n.md (untrusted): FW-OUTSIDE-WRITE on {O}/n.md', () => {
    const d = bash('D=../ops; cd "$D" && echo x > n.md', { tainted: true });
    expect(d.rules, explain(d)).toContain("FW-OUTSIDE-WRITE");
    expect(targets(d, "write_outside_workspace")).toContain(`${O}/n.md`);
  });
  it("F17: cd ../ops || true; echo x > n.md (untrusted): judged under both directories", () => {
    const d = bash("cd ../ops || true; echo x > n.md", { tainted: true });
    expect(d.rules, explain(d)).toContain("FW-OUTSIDE-WRITE");
    expect(d.effects.map((e) => e.target)).toEqual(expect.arrayContaining([`${O}/n.md`, `${W}/n.md`]));
  });
  it("F18: make -C ../ops install checks {O}'s Makefile", () => {
    const d = bash("make -C ../ops install", { tainted: true, events: [tw(`${O}/Makefile`)] });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-TAINTED-MANIFEST");
  });
  it("other directory flags: npm --prefix, pnpm -C, yarn --cwd, env -C", () => {
    for (const cmd of ["npm --prefix ../ops test", "pnpm -C ../ops test", "yarn --cwd ../ops test", "env -C ../ops npm test"]) {
      const d = bash(cmd, { tainted: true, events: [tw(`${O}/package.json`)] });
      expect(d.rules, `${cmd}: ${explain(d)}`).toContain("FW-TAINTED-MANIFEST");
    }
  });
  it("a cd in a pipeline stage or a background job does not persist; a brace group's does", () => {
    expect(targets(bash("cd ../ops | true; touch a", { tainted: true }), "write_workspace")).toContain(`${W}/a`);
    expect(targets(bash("cd ../ops & touch a", { tainted: true }), "write_workspace")).toContain(`${W}/a`);
    expect(targets(bash("{ cd ../ops; }; touch a", { tainted: true }), "write_outside_workspace")).toContain(`${O}/a`);
    expect(targets(bash("(cd ../ops); touch a", { tainted: true }), "write_workspace")).toContain(`${W}/a`);
  });
  it("cd is followed inside nested shells too", () => {
    const d = bash("bash -c 'cd ../ops && touch a'", { tainted: true });
    expect(targets(d, "write_outside_workspace")).toContain(`${O}/a`);
  });
});

describe("F-f false positives (allowed, trusted and untrusted, no new taint)", () => {
  for (const cmd of ["cd src && ls && cat index.ts", "cd packages/api && npx vitest run", 'cd "$(git rev-parse --show-toplevel)" && git status', "(cd web && npm run lint)", "cd - >/dev/null; pwd", "cd $TMPDIR && mkdir -p x && cd x && touch y"]) {
    it(cmd, () => {
      const t = bash(cmd);
      expect(t.verdict, explain(t)).toBe("allow");
      expect(t.events.some((e) => e.type === "taint"), explain(t)).toBe(false);
      const u = bash(cmd, { events: TAINTED });
      expect(u.verdict, explain(u)).toBe("allow");
    });
  }
});
