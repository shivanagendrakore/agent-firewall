/**
 * `log anchor`: writes the log's current head (sequence number and hash, signed, with the key's fingerprint)
 * somewhere the person chooses, off this machine's firewall directory: appended to a file (a mounted drive, a
 * synced folder), as a git note in a repository they push, or handed on standard input to a command they name
 * (an upload to an object-lock bucket). `log verify <bundle> --anchor FILE` then checks that the entry at
 * each anchored position still has that hash, which catches a history rewritten by someone who holds the
 * signing key: the one thing the log cannot prove on its own (docs/limitations.md).
 *
 * Person-run only: the command is refused for agents (changesState, FW-TAMPER) and needs a person at the
 * keyboard; nothing in the firewall runs it on its own.
 */

import { sign } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { appendNoFollow } from "../runtime/fsutil.js";
import { entryHash, loadKey, tailLog, verifyLog } from "../runtime/log.js";
import type { Layout } from "../runtime/layout.js";
import { insideFirewallHome } from "./place.js";
import { ANCHOR_FORMAT, ANCHOR_VERSION, anchorRecordMessage, fingerprint, type AnchorRecord } from "./verify.js";

/** The git notes ref anchors are written under (refs/notes/launchsafe-firewall-log). */
export const NOTES_REF = "launchsafe-firewall-log";
/** The object the notes are attached to: a blob of this text, the same in every repository. */
export const NOTES_OBJECT_TEXT = "launchsafe-firewall log anchors\n";

export type AnchorTarget = { kind: "file"; path: string } | { kind: "git"; repo: string } | { kind: "exec"; argv: readonly string[] };

export interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
}

/** Runs a program with arguments (never through a shell), the given text on its standard input. */
export type Runner = (program: string, args: readonly string[], input: string, env?: NodeJS.ProcessEnv) => RunResult;

/** Output kept from a command (an upload tool can be chatty); past it the run is reported as failed. */
const MAX_OUTPUT = 1024 * 1024;

export const spawnRunner: Runner = (program, args, input, env) => {
  const r = spawnSync(program, args, { input, encoding: "utf8", shell: false, stdio: ["pipe", "pipe", "pipe"], timeout: 120_000, maxBuffer: MAX_OUTPUT, ...(env !== undefined ? { env } : {}) });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", ...(r.error !== undefined ? { error: r.error } : {}) };
};

/**
 * The environment git runs with: without the variables that point it at another repository, index, object
 * store or configuration, so the note lands in the repository the person named and nowhere else.
 */
export function gitEnv(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(env)) {
    if (/^GIT_(DIR|WORK_TREE|INDEX_FILE|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|COMMON_DIR|NAMESPACE|NOTES_REF|NOTES_DISPLAY_REF|NOTES_REWRITE_REF|CEILING_DIRECTORIES|DISCOVERY_ACROSS_FILESYSTEM|CONFIG.*)$/.test(k)) continue;
    Object.defineProperty(out, k, { value: v, writable: true, enumerable: true, configurable: true });
  }
  return out;
}

export class AnchorRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AnchorRefused";
  }
}

/** The signed record of the log's last entry. Refused when the log does not verify or has no entries. */
export function makeAnchorRecord(l: Layout, now = new Date()): AnchorRecord {
  const v = verifyLog(l);
  if (!v.ok) throw new AnchorRefused(`the log does not verify, so its head is not anchored (an anchor must record a good history):\n${v.problems.join("\n")}`);
  const key = loadKey(l, false);
  const last = tailLog(l, 1)[0];
  if (key === null || last === undefined) throw new AnchorRefused("the decision log has no entries yet");
  if (entryHash(last.prev, last.seq, last.ts, last.event) !== last.hash) throw new AnchorRefused("the log's last entry does not match its hash; run launchsafe-firewall log verify");
  const body = { format: ANCHOR_FORMAT, version: ANCHOR_VERSION, seq: last.seq, hash: last.hash, key: fingerprint(key.pub), at: now.toISOString() } as const;
  return { ...body, sig: sign(null, anchorRecordMessage(body), key.priv).toString("base64") };
}

function failed(what: string, r: RunResult): AnchorRefused {
  const why = r.error !== undefined ? r.error.message : `exit ${String(r.status)}${r.stderr.trim() !== "" ? `: ${r.stderr.trim().slice(0, 500)}` : ""}`;
  return new AnchorRefused(`${what} failed (${why})`);
}

/** Refuses a file or repository inside the firewall's directory: an anchor there proves nothing. */
export function assertAnchorPlace(l: Layout, target: AnchorTarget): void {
  const p = target.kind === "file" ? target.path : target.kind === "git" ? target.repo : null;
  if (p !== null && insideFirewallHome(l, p)) throw new AnchorRefused(`${p} is inside the firewall's directory (${l.home}); an anchor must live where whoever can write that directory cannot reach it`);
}

/** Writes one record to the target. Returns where it went, for the person. Throws AnchorRefused on failure. */
export function writeAnchor(record: AnchorRecord, target: AnchorTarget, run: Runner = spawnRunner): string {
  const line = JSON.stringify(record);
  if (target.kind === "file") {
    // Appended with fsync, never through a symbolic link: one file can collect every anchor over time.
    try {
      appendNoFollow(target.path, `${line}\n`);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      throw new AnchorRefused(code === "ELOOP" ? `${target.path} is a symbolic link; name the file itself` : `could not append to ${target.path} (${code ?? (e as Error).message})`);
    }
    // Success is reported only for a record that is there to read back.
    if (!readFileSync(target.path, "utf8").endsWith(`${line}\n`)) throw new AnchorRefused(`the record did not read back from ${target.path}`);
    return `appended to ${target.path}`;
  }
  if (target.kind === "git") {
    const env = gitEnv();
    const obj = run("git", ["-C", target.repo, "hash-object", "-w", "--stdin"], NOTES_OBJECT_TEXT, env);
    if (obj.status !== 0) throw failed(`git hash-object in ${target.repo}`, obj);
    const blob = obj.stdout.trim();
    if (!/^[0-9a-f]{40,64}$/.test(blob)) throw new AnchorRefused(`git hash-object in ${target.repo} printed no object id`);
    const note = run("git", ["-C", target.repo, "notes", "--ref", NOTES_REF, "append", "-m", line, blob], "", env);
    if (note.status !== 0) throw failed(`git notes append in ${target.repo}`, note);
    return `added to the git note refs/notes/${NOTES_REF} on object ${blob} in ${target.repo} (push it: git -C ${target.repo} push <remote> refs/notes/${NOTES_REF})`;
  }
  const [program, ...args] = target.argv;
  if (program === undefined || program === "") throw new AnchorRefused("--exec needs a command after --");
  const r = run(program, args, `${line}\n`);
  if (r.status !== 0) throw failed(`the command ${program}`, r);
  return `handed to ${program} on its standard input`;
}
