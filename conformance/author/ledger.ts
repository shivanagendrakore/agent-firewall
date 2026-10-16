/**
 * Vectors for the provenance ledger across sessions (src/runtime/ledger.ts): a file one session wrote and another runs
 * or reads. Taint is one session's; the ledger is what carries "an untrusted session wrote this" into the next one, so
 * a trusted session that runs such a script, or a build whose manifest it is, is asked.
 *
 * The tree is not changed by the steps: a `Write` step only asks, the host's tool would then write the file, and the
 * tree already holds the file's text from the setup. So when the writer's `result` step is recorded the file is on disk,
 * and every session that "wrote" it left the same text. Sessions are the agent's own (one firewall home, one ledger).
 * Nothing here is run: every string is data.
 *
 * These vectors need a persistent ledger (the file store's, in the firewall home); the contract leaves file provenance to
 * the host, so those whose outcome depends on it say so (`implementationSpecific`). Without a ledger an implementation
 * answers as a fresh session would: it allows the script, and the read taints.
 */

import { eng, inp, NO_TOOLS, OUTSIDE, PCTX, PHOME, PUNATTENDED, PWS, res, svec, type Ctx, type Skeleton, type SkStep } from "./kit.js";
import type { Setup } from "../setup.js";

const SCRIPT_TEXT = "#!/bin/sh\nnpm test\n";
const NOTE_TEXT = "# draft\nnotes for the next session\n";
const PACKAGE_TEXT = `${JSON.stringify({ name: "app", version: "1.0.0", scripts: { test: "vitest run" } }, null, 2)}\n`;
const SCRIPT = `${PWS}/scripts/fix.sh`;
const NOTE = `${PHOME}/notes/draft.md`;

const FILES: Setup = { files: { "workspace/scripts/fix.sh": SCRIPT_TEXT, "workspace/package.json": PACKAGE_TEXT, "home/notes/draft.md": NOTE_TEXT } };

/** The writers' sessions, and the one that runs or reads afterwards. */
const W1 = "writer-1";
const W2 = "writer-2";
const R1 = "runner-1";

const REQUIRES_LEDGER = "the contract leaves file provenance to the host: this needs a persistent provenance ledger (what an earlier session wrote, with the hash of what it left and whether it was untrusted), which this implementation keeps in the firewall home; an implementation with no persistent store carries nothing between sessions and answers as a fresh session would";

const write = (path: string, text: string, session: string): SkStep => eng("Write", { file_path: path, content: text }, PCTX, undefined, session);
const edit = (path: string, from: string, to: string, session: string): SkStep => eng("Edit", { file_path: path, old_string: from, new_string: to }, PCTX, undefined, session);
const bash = (command: string, session: string, ctx: Ctx = PCTX): SkStep => eng("Bash", { command }, ctx, undefined, session);
const read = (path: string, session: string): SkStep => eng("Read", { file_path: path }, PCTX, undefined, session);
/** The session reads outside content (an engine input, so it is untrusted from here). */
const outside = (session: string): SkStep => inp("a web page", OUTSIDE, false, session);

export function preparedLedger(): Skeleton[] {
  const out: Skeleton[] = [];
  const add = (id: string, description: string, steps: SkStep[], needsLedger: boolean): void => {
    out.push({ ...svec(`ledger-${id}`, description, "src/runtime/ledger.ts (the provenance ledger), docs/design.md (Provenance)", NO_TOOLS, FILES, steps), ...(needsLedger ? { implementationSpecific: REQUIRES_LEDGER } : {}) });
  };

  // A script written in one session and run in another.
  add("script-untrusted-writer-trusted-runner", "An untrusted session writes a script and its result is reported; a different, trusted session runs it", [outside(W1), write(SCRIPT, SCRIPT_TEXT, W1), res(1, undefined, W1), bash("bash scripts/fix.sh", R1)], true);
  add("script-untrusted-writer-unattended-runner", "An untrusted session writes a script; a different, trusted session with no person there runs it", [outside(W1), write(SCRIPT, SCRIPT_TEXT, W1), res(1, undefined, W1), bash("bash scripts/fix.sh", R1, PUNATTENDED)], true);
  add("script-untrusted-writer-untrusted-runner", "An untrusted session writes a script; another untrusted session runs it", [outside(W1), write(SCRIPT, SCRIPT_TEXT, W1), res(1, undefined, W1), outside(R1), bash("bash scripts/fix.sh", R1)], true);
  add("script-trusted-writer-trusted-runner", "A trusted session writes a script; a different trusted session runs it", [write(SCRIPT, SCRIPT_TEXT, W1), res(0, undefined, W1), bash("bash scripts/fix.sh", R1)], false);
  add("script-shell-write-untrusted-writer", "An untrusted session writes a script with a shell redirect; a different, trusted session runs it with sh", [outside(W1), bash("echo 'npm test' > scripts/fix.sh", W1), res(1, undefined, W1), bash("sh scripts/fix.sh", R1)], true);

  // Untrusted is sticky per content: a trusted session reporting a write of the same bytes does not clear it (a
  // rewrite with new content does; the vectors' files are fixed, so that case is in test/api/ledger.test.ts).
  add("script-same-content-rewrite-keeps", "An untrusted session writes a script, then a trusted session reports writing it again with the same content; a third session runs it", [outside(W1), write(SCRIPT, SCRIPT_TEXT, W1), res(1, undefined, W1), write(SCRIPT, SCRIPT_TEXT, W2), res(3, undefined, W2), bash("bash scripts/fix.sh", R1)], true);
  add("script-untrusted-rewrite-keeps", "A trusted session writes a script, then an untrusted session writes it again; a third session runs it", [write(SCRIPT, SCRIPT_TEXT, W2), res(0, undefined, W2), outside(W1), write(SCRIPT, SCRIPT_TEXT, W1), res(3, undefined, W1), bash("bash scripts/fix.sh", R1)], true);

  // A build manifest changed in one session and built in another.
  const scripts = (session: string): SkStep => edit(`${PWS}/package.json`, '"test": "vitest run"', '"test": "node scripts/fix.js"', session);
  add("manifest-untrusted-editor-trusted-runner", "An untrusted session edits the test script in package.json; a different, trusted session runs npm test", [outside(W1), scripts(W1), res(1, undefined, W1), bash("npm test", R1)], true);
  add("manifest-trusted-editor-trusted-runner", "A trusted session edits the test script in package.json; a different, trusted session runs npm test", [scripts(W1), res(0, undefined, W1), bash("npm test", R1)], false);

  // A note written outside the workspace and read in another session.
  add("note-trusted-writer-reader", "A trusted session writes a note outside the workspace; a different session reads it", [write(NOTE, NOTE_TEXT, W1), res(0, undefined, W1), read(NOTE, R1)], true);
  add("note-untrusted-writer-reader", "An untrusted session writes a note outside the workspace; a different session reads it", [outside(W1), write(NOTE, NOTE_TEXT, W1), res(1, undefined, W1), read(NOTE, R1)], true);
  add("note-unrecorded-reader", "A session reads a file outside the workspace that no session is known to have written", [read(NOTE, R1)], false);
  return out;
}
