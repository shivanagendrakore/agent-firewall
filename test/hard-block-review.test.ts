/**
 * The security review's fixes to FW-CATASTROPHIC: the branch checked out decides a force push that names
 * none; words known only at run time make an ordinary destructive ask; the signed, user-level scratch-target
 * allowlist turns a throwaway database, namespace or app into an ask (never by default, never from a project);
 * protected branches are configurable; disk and root reasons. Commands are data; nothing is run.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { currentBranch, judgeCommand } from "../src/engine/catastrophic.js";
import { defaultConfig, mergeTighten, validatePolicy } from "../src/policy.js";
import { initApprover } from "../src/runtime/approver.js";
import { loadScratch, scratchPath, scratchPatterns, signScratch } from "../src/runtime/scratch.js";
import { main } from "../src/climain.js";
import type { Decision } from "../src/types.js";
import { bash, explain, run, WS } from "./helpers.js";
import { box, rules, send, verdict, write, type Box } from "./adapters/harness.js";

const noDeny = (d: Decision): void => {
  expect(d.verdict, explain(d)).toBe("ask");
  expect(d.rules, explain(d)).toContain("FW-DESTRUCTIVE");
  expect(d.rules).not.toContain("FW-CATASTROPHIC");
};

describe("a force push that names no branch: the branch checked out decides", () => {
  const head = (branch: string) => (p: string): string | null => (p === `${WS}/.git/HEAD` ? `ref: refs/heads/${branch}\n` : null);
  for (const cmd of ["git push --force", "git push -f origin", "git push -f origin HEAD", "git push --force-with-lease"]) {
    it(`${cmd} on main is denied, on a feature branch asked`, () => {
      const onMain = bash(cmd, { ctx: { readFile: head("main") } });
      expect(onMain.verdict, explain(onMain)).toBe("deny");
      expect(onMain.rules).toContain("FW-CATASTROPHIC");
      expect(bash(cmd, { ctx: { readFile: head("release/2.0") } }).verdict).toBe("deny");
      noDeny(bash(cmd, { ctx: { readFile: head("feature-x") } }));
    });
  }
  it("unreadable state (no file access, detached HEAD, no repository, unknown directory) asks", () => {
    noDeny(bash("git push --force"));
    noDeny(bash("git push --force", { ctx: { readFile: () => "3f9c2d1e0b\n" } }));
    noDeny(bash("git push --force", { ctx: { readFile: () => null } }));
    noDeny(bash('cd "$DIR" && git push --force', { ctx: { readFile: head("main") } }));
  });
  it("a subdirectory and a worktree's .git file are followed", () => {
    expect(currentBranch(`${WS}/src/lib`, head("main"))).toBe("main");
    const files: Record<string, string> = { [`${WS}/.git`]: "gitdir: /Users/dev/repo/.git/worktrees/proj\n", "/Users/dev/repo/.git/worktrees/proj/HEAD": "ref: refs/heads/trunk\n" };
    const read = (p: string): string | null => files[p] ?? null;
    expect(currentBranch(WS, read)).toBe("trunk");
    expect(bash("git push -f", { ctx: { readFile: read } }).verdict).toBe("deny");
  });
  it("git -C moves to the repository it names", () => {
    const read = (p: string): string | null => (p === "/Users/dev/other/.git/HEAD" ? "ref: refs/heads/main\n" : p === `${WS}/.git/HEAD` ? "ref: refs/heads/feature\n" : null);
    expect(bash("git -C /Users/dev/other push --force", { ctx: { readFile: read } }).verdict).toBe("deny");
    noDeny(bash("git push --force", { ctx: { readFile: read } }));
  });
});

describe("protected branches are configurable (main, master and trunk always)", () => {
  it("the policy adds patterns; a project may add more, never remove", () => {
    expect(bash("git push --force origin staging").verdict).not.toBe("deny");
    expect(bash("git push --force origin staging", { config: { protectedBranches: ["staging"] } }).verdict).toBe("deny");
    expect(bash("git push --force origin main", { config: { protectedBranches: [] } }).verdict).toBe("deny");
    expect(bash("git push --force origin develop", { config: { protectedBranches: [] } }).verdict).not.toBe("deny");
    const { config } = mergeTighten({ ...defaultConfig(), protectedBranches: ["develop"] }, validatePolicy({ version: 3, protectedBranches: ["qa"] }, "project"));
    expect(config.protectedBranches).toEqual(["develop", "qa"]);
  });
});

describe("words known only at run time: an ordinary destructive ask", () => {
  for (const cmd of ["terraform $CMD", "aws s3 $OP s3://prod-data", "kubectl delete $KIND prod", "gh api -X DELETE $ENDPOINT", "git push --force origin $BRANCH", "git push origin +$BRANCH", "heroku $(cat verb)"]) {
    it(cmd, () => noDeny(bash(cmd)));
  }
  it("a literal catastrophic verb with a run-time target is still denied", () => {
    for (const cmd of ["kubectl delete ns $NS", "dropdb $DB", "aws s3 rb s3://$BUCKET", "terraform destroy -var env=$ENV"]) expect(bash(cmd).verdict, cmd).toBe("deny");
  });
  it("run-time words that cannot be a catastrophic verb stay ordinary", () => {
    for (const cmd of ["aws s3 cp $SRC s3://prod-data/x", "terraform plan -var-file=$F", "kubectl get pods -n $NS", "docker run $IMAGE"]) expect(bash(cmd).rules, cmd).not.toContain("FW-DESTRUCTIVE");
  });
});

describe("the scratch-target allowlist", () => {
  const scratchTargets = ["*_test", "*-pr-*", "preview-*"];
  const withList = { ctx: { scratchTargets } };
  it("without it, dropping app_test is denied (never scratch by default)", () => {
    for (const cmd of ["dropdb app_test", 'psql -c "DROP DATABASE IF EXISTS app_test"']) expect(bash(cmd).verdict, cmd).toBe("deny");
  });
  it("with it, a matching database, namespace, app or bucket is asked", () => {
    for (const cmd of ["dropdb app_test", "dropdb --if-exists -h localhost app_test", 'psql -c "DROP DATABASE IF EXISTS app_test"', 'mysql -e "DROP SCHEMA shop_test"', "kubectl delete ns preview-42", "fly apps destroy web-pr-17 --yes", "heroku apps:destroy --app shop-pr-9 --confirm shop-pr-9", "aws s3 rb s3://preview-assets --force", "supabase branches delete preview-login"]) {
      const d = bash(cmd, withList);
      noDeny(d);
      expect(d.reasons.join(" "), cmd).toMatch(/scratch-target pattern/);
    }
    noDeny(run("mcp__supabase__execute_sql", { query: "drop database app_test" }, withList));
  });
  it("one non-matching name, a quoted or run-time name, or a kind that can never be scratch is still denied", () => {
    for (const cmd of ['psql -c "DROP DATABASE app_test, app"', 'psql -c \'DROP DATABASE "app_test"\'', "dropdb $DB", "kubectl delete ns preview-1 prod", "gcloud projects delete preview-1", "aws rds delete-db-instance --db-instance-identifier db_test", "terraform destroy", "git push --force origin main", "dropdb app"]) {
      expect(bash(cmd, withList).verdict, cmd).toBe("deny");
    }
  });
  it("a project policy cannot carry it (no such policy key)", () => {
    expect(() => validatePolicy({ version: 3, scratchTargets: ["*"] }, "project")).toThrow();
  });
});

describe("the scratch list on disk is signed with the approval key", () => {
  let b: Box;
  beforeEach(() => {
    b = box();
  });
  afterEach(() => b.cleanup());

  it("only a list that verifies is used", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const pub = (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
    const other = (generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
    write(scratchPath(b.l), JSON.stringify(signScratch(privateKey, ["app_*_test"])));
    expect(scratchPatterns(loadScratch(b.l, pub))).toEqual(["app_*_test"]);
    expect(loadScratch(b.l, other).state).toBe("unsigned");
    expect(scratchPatterns(loadScratch(b.l, other))).toBeUndefined();
    const forged = JSON.parse(readFileSync(scratchPath(b.l), "utf8")) as { patterns: string[] };
    forged.patterns.push("*_prod");
    writeFileSync(scratchPath(b.l), JSON.stringify(forged));
    expect(loadScratch(b.l, pub).state).toBe("unsigned");
    writeFileSync(scratchPath(b.l), JSON.stringify({ ...forged, patterns: ["*"] }));
    expect(loadScratch(b.l, pub).state).toBe("corrupt");
  });

  it("through the hook: the pinned approval key's list turns dropdb app_test into a question", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const pub = (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
    const pre = (command: string) => ({ hook_event_name: "PreToolUse", permission_mode: "bypassPermissions", tool_name: "Bash", tool_input: { command } });
    const env = { CLAUDE_PROJECT_DIR: b.ws, LAUNCHSAFE_FIREWALL_APPROVER: pub };
    expect(verdict("claude", send(b, "claude", pre("dropdb app_test"), { env }))).toBe("deny");
    write(scratchPath(b.l), JSON.stringify(signScratch(privateKey, ["*_test"])));
    const io = send(b, "claude", pre("dropdb app_test"), { env });
    // A question, which under bypassPermissions (unattended by default, I6) is held for a person.
    expect(verdict("claude", io)).toBe("queue");
    expect(rules("claude", io)).toContain("FW-DESTRUCTIVE");
    expect(verdict("claude", send(b, "claude", pre("dropdb app"), { env }))).toBe("deny");
  });

  it("scratch add and remove need a person and the passphrase; list is read-only", async () => {
    const pass = "correct horse battery";
    initApprover(b.l, pass);
    const lines: string[] = [];
    const o = { write: (_fd: 1 | 2, s: string) => void lines.push(s), humanAtKeyboard: async () => true, scratch: { readSecret: async () => pass } };
    expect(await main(["scratch", "add", "app_*_test"], b.l, o)).toBe(0);
    expect(await main(["scratch", "add", "*"], b.l, o)).toBe(64);
    expect(await main(["scratch", "add", "x_test"], b.l, { ...o, humanAtKeyboard: async () => false })).toBe(1);
    expect(await main(["scratch", "add", "x_test"], b.l, { ...o, scratch: { readSecret: async () => "wrong passphrase!" } })).toBe(1);
    lines.length = 0;
    expect(await main(["scratch", "list", "--json"], b.l, o)).toBe(0);
    expect(JSON.parse(lines.join(""))).toEqual({ signed: true, patterns: ["app_*_test"] });
    expect(await main(["scratch", "remove", "app_*_test"], b.l, o)).toBe(0);
    expect(scratchPatterns(loadScratch(b.l, null))).toBeUndefined();
  });
});

describe("reasons", () => {
  it("writing over a disk says so; deleting the root or home says what to do instead", () => {
    expect(bash("dd if=/dev/zero of=/dev/disk2").reasons.join(" ")).toMatch(/disk device/);
    expect(bash("rm -rf /").reasons.join(" ")).toMatch(/specific files or folders/);
  });
  it("a judgement over a whole word list, not a substring of a name", () => {
    expect(judgeCommand("kubectl", [{ text: "delete", dynamic: false }, { text: "secret", dynamic: false }, { text: "namespace-reader", dynamic: false }])).toBeNull();
  });
});
