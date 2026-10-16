/**
 * Off-machine anchors (docs/logs.md): `log anchor` writes the signed head to a place the person chooses, and
 * `log verify <bundle> --anchor` checks the bundle against it. The anchor is what catches a history rewritten
 * by someone who holds the signing key (a valid chain throughout), and a log cut back after it was anchored.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { sign } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { isReadOnlyInvocation } from "../src/cliargs.js";
import { main } from "../src/climain.js";
import { AnchorRefused, makeAnchorRecord, NOTES_OBJECT_TEXT, NOTES_REF, writeAnchor, type Runner } from "../src/logbundle/anchor.js";
import { exportLog } from "../src/logbundle/export.js";
import { entryHash, entryMessage, GENESIS, headMessage, verifyBundle } from "../src/logbundle/verify.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { appendLog, loadKey, tailLog, verifyLog, type LogEntry } from "../src/runtime/log.js";

let root: string;
let l: Layout;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-anchor-"));
  l = layout(join(root, "home"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

function fill(lay: Layout, n: number): void {
  for (let i = 1; i <= n; i++) appendLog(lay, { type: "decision", tool: "Bash", verdict: "allow", n: i });
}

/**
 * Someone who can write the firewall's directory (and so holds the key) rewrites the whole log: new events,
 * every entry re-hashed and re-signed, a new signed head. The chain is valid throughout.
 */
function rewriteHistory(lay: Layout, n: number): void {
  const key = loadKey(lay, false);
  if (key === null) throw new Error("no key");
  let prev = GENESIS;
  const out: string[] = [];
  for (let seq = 1; seq <= n; seq++) {
    const ts = new Date(Date.UTC(2026, 9, 1, 0, 0, seq)).toISOString();
    const event = { type: "decision", tool: "Bash", verdict: "allow", n: seq, rewritten: true };
    const hash = entryHash(prev, seq, ts, event);
    out.push(JSON.stringify({ seq, ts, prev, event, hash, sig: sign(null, entryMessage(hash, "signed"), key.priv).toString("base64"), heads: "signed" }));
    prev = hash;
  }
  writeFileSync(join(lay.log, "decisions.jsonl"), `${out.join("\n")}\n`);
  writeFileSync(join(lay.log, "head.json"), JSON.stringify({ seq: n, hash: prev, sig: sign(null, headMessage(n, prev), key.priv).toString("base64") }));
}

describe("anchor records", () => {
  it("a bundle checks against an anchor written to a file", () => {
    fill(l, 6);
    mkdirSync(join(root, "offsite"));
    const file = join(root, "offsite", "anchors.jsonl");
    const rec = makeAnchorRecord(l);
    expect(rec).toMatchObject({ seq: 6, format: "launchsafe-firewall-log-anchor", version: 1 });
    expect(writeAnchor(rec, { kind: "file", path: file })).toContain(file);
    fill(l, 3);
    // A second anchor is appended to the same file.
    writeAnchor(makeAnchorRecord(l), { kind: "file", path: file });
    expect(readFileSync(file, "utf8").trim().split("\n")).toHaveLength(2);
    const b = exportLog(l);
    const v = verifyBundle(b.text, { anchors: [readFileSync(file, "utf8")] });
    expect(v).toMatchObject({ ok: true, anchorsMatched: 2 });
    // An anchor pins the key: no note that the bundle is unpinned.
    expect(v.notes.join(" ")).not.toContain("not pinned");
  });

  it("detects a rewritten history that still has a valid chain", () => {
    fill(l, 5);
    const anchors = `${JSON.stringify(makeAnchorRecord(l))}\n`;
    rewriteHistory(l, 5);
    // The log verifies on its own, and so does its bundle: only the anchor shows the rewrite.
    expect(verifyLog(l).ok).toBe(true);
    const b = exportLog(l);
    expect(verifyBundle(b.text, { keys: [b.fingerprint] }).ok).toBe(true);
    const v = verifyBundle(b.text, { anchors: [anchors] });
    expect(v.status).toBe("invalid");
    expect(v.ok).toBe(false);
    expect(v.problems.join("\n")).toMatch(/history was rewritten after it was anchored/);
  });

  it("detects a log cut back below an anchored entry (an old signed head put back)", () => {
    fill(l, 5);
    const oldHead = readFileSync(join(l.log, "head.json"), "utf8");
    const oldLog = readFileSync(join(l.log, "decisions.jsonl"), "utf8");
    fill(l, 3);
    const anchors = JSON.stringify(makeAnchorRecord(l));
    writeFileSync(join(l.log, "decisions.jsonl"), oldLog);
    writeFileSync(join(l.log, "head.json"), oldHead);
    expect(verifyLog(l).ok).toBe(true);
    const b = exportLog(l);
    const v = verifyBundle(b.text, { anchors: [anchors] });
    expect(v.ok).toBe(false);
    expect(v.problems.join("\n")).toMatch(/entries were removed after it was anchored/);
  });

  it("an anchor from another install, or an edited anchor record, fails", () => {
    fill(l, 4);
    const other = layout(join(root, "other"));
    fill(other, 4);
    const theirs = JSON.stringify(makeAnchorRecord(other));
    const b = exportLog(l);
    expect(verifyBundle(b.text, { anchors: [theirs] }).problems.join("\n")).toMatch(/another install's log/);
    const rec = makeAnchorRecord(l);
    const edited = JSON.stringify({ ...rec, hash: (tailLog(l, 2)[0] as LogEntry).hash });
    expect(verifyBundle(b.text, { anchors: [edited] }).problems.join("\n")).toMatch(/bad signature/);
  });

  it("an anchor outside a range export is noted; when none falls inside, verify fails", () => {
    fill(l, 8);
    const anchors = JSON.stringify(makeAnchorRecord(l));
    const part = exportLog(l, { from: "2", to: "5" });
    const v = verifyBundle(part.text, { anchors: [anchors] });
    expect(v.ok).toBe(false);
    expect(v.problems.join("\n")).toMatch(/no anchor record falls inside this bundle/);
    expect(v.notes.join("\n")).toMatch(/outside this bundle/);
  });

  it("refuses to anchor a log that does not verify", () => {
    fill(l, 3);
    const f = join(l.log, "decisions.jsonl");
    writeFileSync(f, readFileSync(f, "utf8").replace('"n":2', '"n":9'));
    expect(() => makeAnchorRecord(l)).toThrow(AnchorRefused);
  });
});

describe("anchor targets", () => {
  it("git notes: the record is appended to the notes ref on the fixed object (runner stood in)", () => {
    fill(l, 2);
    const rec = makeAnchorRecord(l);
    const calls: { program: string; args: readonly string[]; input: string }[] = [];
    const run: Runner = (program, args, input) => {
      calls.push({ program, args, input });
      return { status: 0, stdout: args.includes("hash-object") ? `${"a".repeat(40)}\n` : "", stderr: "" };
    };
    writeAnchor(rec, { kind: "git", repo: "/r" }, run);
    expect(calls[0]).toEqual({ program: "git", args: ["-C", "/r", "hash-object", "-w", "--stdin"], input: NOTES_OBJECT_TEXT });
    expect(calls[1]).toEqual({ program: "git", args: ["-C", "/r", "notes", "--ref", NOTES_REF, "append", "-m", JSON.stringify(rec), "a".repeat(40)], input: "" });
  });

  it("exec: the program gets the record on standard input, no shell; a failure is reported", () => {
    fill(l, 2);
    const rec = makeAnchorRecord(l);
    let got: { program: string; args: readonly string[]; input: string } | null = null;
    writeAnchor(rec, { kind: "exec", argv: ["uploader", "--to", "bucket/key"] }, (program, args, input) => {
      got = { program, args, input };
      return { status: 0, stdout: "", stderr: "" };
    });
    expect(got).toEqual({ program: "uploader", args: ["--to", "bucket/key"], input: `${JSON.stringify(rec)}\n` });
    expect(() => writeAnchor(rec, { kind: "exec", argv: ["uploader"] }, () => ({ status: 3, stdout: "", stderr: "denied" }))).toThrow(/exit 3: denied/);
  });

  it("git notes in a real repository round-trip through git notes show", (ctx) => {
    if (spawnSync("git", ["--version"]).status !== 0) ctx.skip();
    const repo = join(root, "repo");
    mkdirSync(repo);
    const env = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid", GIT_CONFIG_NOSYSTEM: "1" };
    execFileSync("git", ["init", "-q", repo], { env });
    const run: Runner = (program, args, input) => {
      const r = spawnSync(program, args, { input, encoding: "utf8", env });
      return { status: r.status, stdout: r.stdout, stderr: r.stderr };
    };
    fill(l, 3);
    writeAnchor(makeAnchorRecord(l), { kind: "git", repo }, run);
    fill(l, 2);
    writeAnchor(makeAnchorRecord(l), { kind: "git", repo }, run);
    const blob = execFileSync("git", ["-C", repo, "hash-object", "--stdin"], { input: NOTES_OBJECT_TEXT, env, encoding: "utf8" }).trim();
    const notes = execFileSync("git", ["-C", repo, "notes", "--ref", NOTES_REF, "show", blob], { env, encoding: "utf8" });
    expect(verifyBundle(exportLog(l).text, { anchors: [notes] })).toMatchObject({ ok: true, anchorsMatched: 2 });
  });
});

describe("the commands", () => {
  async function cli(args: string[], human = true): Promise<{ status: number; stdout: string; stderr: string }> {
    let stdout = "";
    let stderr = "";
    const status = await main(args, l, { write: (fd, s) => (fd === 1 ? (stdout += s) : (stderr += s)), humanAtKeyboard: () => Promise.resolve(human) });
    return { status, stdout, stderr };
  }

  it("export, verify with the printed key, anchor to a file, verify against it", async () => {
    fill(l, 5);
    const bundle = join(root, "out", "log.bundle.jsonl");
    const e = await cli(["log", "export", "--out", bundle]);
    expect(e.status, e.stderr).toBe(0);
    const key = /Signed by (sha256:[0-9a-f]{64})/.exec(e.stdout)?.[1] as string;
    expect(key).toMatch(/^sha256:/);
    // An export never replaces a file.
    expect((await cli(["log", "export", "--out", bundle])).status).toBe(1);
    expect((await cli(["log", "verify", bundle, "--key", key])).status).toBe(0);
    const anchors = join(root, "offsite.jsonl");
    const a = await cli(["log", "anchor", "--file", anchors]);
    expect(a.status, a.stderr).toBe(0);
    // The anchoring is itself logged (without where it went).
    expect(tailLog(l, 1)[0]?.event).toMatchObject({ type: "log_anchor", seq: 5, to: "file" });
    const ok = await cli(["log", "verify", bundle, "--anchor", anchors]);
    expect(ok.status, ok.stdout).toBe(0);
    expect(ok.stdout).toContain("1 anchor record(s) match");
    const json = await cli(["log", "verify", bundle, "--anchor", anchors, "--json"]);
    expect(JSON.parse(json.stdout)).toMatchObject({ ok: true, anchorsMatched: 1 });
    // The local log still verifies with the plain form.
    expect((await cli(["log", "verify"])).status).toBe(0);
    expect((await cli(["log", "verify", "--json"])).status).toBe(64);
  });

  it("export to standard output writes the bundle byte for byte", async () => {
    fill(l, 3);
    const r = await cli(["log", "export", "--out", "-"]);
    expect(r.status).toBe(0);
    expect(verifyBundle(r.stdout).intact).toBe(true);
    expect(r.stderr).toContain("Exported 3 entries");
  });

  it("anchor is person-run only, and takes exactly one place", async () => {
    fill(l, 2);
    const f = join(root, "a.jsonl");
    expect((await cli(["log", "anchor", "--file", f], false)).status).toBe(1);
    expect(existsSync(f)).toBe(false);
    expect((await cli(["log", "anchor"])).status).toBe(64);
    expect((await cli(["log", "anchor", "--file", f, "--git-notes", root])).status).toBe(64);
    expect((await cli(["log", "anchor", "--exec"])).status).toBe(64);
    expect((await cli(["log", "anchor", "--file", f, "--", "extra"])).status).toBe(64);
    expect(existsSync(f)).toBe(false);
  });

  it("export and anchor are refused for agents; verifying a bundle is read-only", () => {
    expect(isReadOnlyInvocation(["log", "export", "--out", "x"])).toBe(false);
    expect(isReadOnlyInvocation(["log", "anchor", "--file", "x"])).toBe(false);
    expect(isReadOnlyInvocation(["log", "anchor", "--exec", "--", "sh", "-c", "x"])).toBe(false);
    expect(isReadOnlyInvocation(["log", "verify", "b.jsonl", "--key", "sha256:00"])).toBe(true);
    expect(isReadOnlyInvocation(["log", "verify"])).toBe(true);
  });
});
