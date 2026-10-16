/**
 * F2 (final review): what a patch-applying shell command writes. `git apply`, `git am`, `patch` and
 * Codex's `apply_patch` (which Codex puts on its shell's PATH) write the files their diff names, so the
 * analyzer turns each file in the diff into the action the agent's own file tools would be: a Write for a
 * new file, an edit (judged loosely: `patch` applies with fuzz) for a changed one, rm and mv for deletes and
 * renames. Each is then judged exactly like the Write/Edit tools. Anything the parser does not understand
 * makes the patch's targets unknown, and the caller treats that as an unresolvable write.
 *
 * Unified diffs are read by their hunk line counts (a removed line that starts with "-- " is not a header).
 * Linear in the patch length.
 */

import type { NormalizedAction } from "../../types.js";
import { parsePatch } from "../codex-patch.js";

export interface DiffFile {
  /** The paths named for the file before and after (without a/ b/ stripping; null for /dev/null). */
  oldName: string | null;
  newName: string | null;
  hunks: { old: string; new: string }[];
  /** The file's content cannot be read from the diff (a binary patch). */
  binary: boolean;
  /** Only the mode changed (chmod), or a rename with no hunks. */
  modeOnly: boolean;
}

export type DiffParse = { ok: true; files: DiffFile[] } | { ok: false; reason: string };

const MAX_DIFF = 8 * 1024 * 1024;

function headerName(raw: string): string | null {
  // "--- a/path\t2026-10-10 ..." (timestamps after a tab), quoted names in git's C style.
  let t = raw.replace(/\t.*$/, "").trim();
  if (t.startsWith('"') && t.endsWith('"') && t.length >= 2) {
    try {
      t = JSON.parse(t) as string;
    } catch {
      t = t.slice(1, -1);
    }
  }
  if (t === "/dev/null" || t === "") return null;
  return t;
}

/** Parses the unified diffs in a text (a plain diff, `git diff` output, or an mbox `git am` reads). */
export function parseUnifiedDiff(text: string): DiffParse {
  if (text.length > MAX_DIFF) return { ok: false, reason: "the patch is too large to check" };
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const files: DiffFile[] = [];
  let pendingGit: { oldName: string | null; newName: string | null; binary: boolean; mode: boolean; created: boolean; deleted: boolean } | null = null;
  const flushGit = (): void => {
    // A `diff --git` block with no ---/+++ lines: a mode change, a rename, an empty file or a binary patch.
    if (pendingGit !== null) {
      files.push({ oldName: pendingGit.created ? null : pendingGit.oldName, newName: pendingGit.deleted ? null : pendingGit.newName, hunks: [], binary: pendingGit.binary, modeOnly: !pendingGit.binary });
    }
    pendingGit = null;
  };
  let i = 0;
  while (i < lines.length) {
    const l = lines[i] as string;
    const git = /^diff --git (?:"([^"]+)"|(\S+)) (?:"([^"]+)"|(\S+))\s*$/.exec(l);
    if (git !== null) {
      flushGit();
      pendingGit = { oldName: git[1] ?? git[2] ?? null, newName: git[3] ?? git[4] ?? null, binary: false, mode: false, created: false, deleted: false };
      i++;
      continue;
    }
    if (pendingGit !== null) {
      const pg: { oldName: string | null; newName: string | null; binary: boolean; mode: boolean; created: boolean; deleted: boolean } = pendingGit;
      if (/^GIT binary patch$|^Binary files .* differ$/.test(l)) pg.binary = true;
      const rf = /^rename from (.+)$/.exec(l) ?? /^copy from (.+)$/.exec(l);
      if (rf !== null) pg.oldName = rf[1] as string;
      const rt = /^rename to (.+)$/.exec(l) ?? /^copy to (.+)$/.exec(l);
      if (rt !== null) pg.newName = rt[1] as string;
      if (/^new file mode /.test(l)) pg.created = true;
      if (/^deleted file mode /.test(l)) pg.deleted = true;
    }
    if (l.startsWith("--- ") && (lines[i + 1] ?? "").startsWith("+++ ")) {
      const file: DiffFile = { oldName: headerName(l.slice(4)), newName: headerName((lines[i + 1] as string).slice(4)), hunks: [], binary: false, modeOnly: false };
      pendingGit = null;
      i += 2;
      while (i < lines.length) {
        const h = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(lines[i] as string);
        if (h === null) break;
        let oldLeft = h[2] === undefined ? 1 : Number(h[2]);
        let newLeft = h[4] === undefined ? 1 : Number(h[4]);
        const o: string[] = [];
        const n: string[] = [];
        i++;
        while (i < lines.length && (oldLeft > 0 || newLeft > 0)) {
          const hl = lines[i] as string;
          if (hl.startsWith("\\")) {
            i++;
            continue;
          }
          const tag = hl === "" ? " " : hl[0];
          const body = hl.slice(1);
          if (tag === " ") {
            o.push(body);
            n.push(body);
            oldLeft--;
            newLeft--;
          } else if (tag === "-") {
            o.push(body);
            oldLeft--;
          } else if (tag === "+") {
            n.push(body);
            newLeft--;
          } else return { ok: false, reason: `a hunk of ${file.newName ?? file.oldName ?? "a file"} ends before its line counts say` };
          i++;
        }
        if (oldLeft > 0 || newLeft > 0) return { ok: false, reason: "the patch ends inside a hunk" };
        while (i < lines.length && (lines[i] as string).startsWith("\\")) i++;
        file.hunks.push({ old: o.join("\n"), new: n.join("\n") });
      }
      if (file.hunks.length === 0) return { ok: false, reason: `the diff of ${file.newName ?? file.oldName ?? "a file"} has no hunks` };
      files.push(file);
      continue;
    }
    i++;
  }
  flushGit();
  if (files.length === 0) return { ok: false, reason: "no file changes found in the patch" };
  return { ok: true, files };
}

/** Strips n leading path components (patch -pN); null when the path has fewer. */
export function stripPath(p: string, n: number): string | null {
  const parts = p.split("/").filter((x, i) => !(x === "" && i > 0));
  if (n === 0) return p;
  if (parts.length <= n) return null;
  return parts.slice(n).join("/");
}

/** How a diff names its files for one tool: the strip levels it may use, and an optional single target. */
export interface PathRule {
  strips: number[];
  /** `patch FILE`: every hunk goes to this file. */
  target?: string;
  /** `git apply --directory=<root>`. */
  prefix?: string;
  /** Also judge the bare file name (GNU patch without -p on a non-git diff). */
  basename?: boolean;
}

function candidates(name: string, rule: PathRule): string[] {
  if (rule.target !== undefined) return [rule.target];
  const out = new Set<string>();
  for (const n of rule.strips) {
    const s = stripPath(name, n);
    if (s !== null && s !== "") out.add(rule.prefix !== undefined ? `${rule.prefix.replace(/\/+$/, "")}/${s}` : s);
  }
  if (rule.basename === true) out.add(name.split("/").pop() ?? name);
  return [...out];
}

function shq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/**
 * The file-tool actions a unified diff amounts to. Every plausible path for a file (each strip level) is
 * judged, so the most severe reading wins. `loose`: the tool matches context loosely (`patch` fuzz,
 * `git apply --ignore-whitespace`/-C), so edits are judged against every plausible match.
 */
export function diffActions(files: readonly DiffFile[], rule: PathRule): NormalizedAction[] {
  const out: NormalizedAction[] = [];
  for (const f of files) {
    const olds = f.oldName === null ? [] : candidates(f.oldName, rule);
    const news = f.newName === null ? [] : candidates(f.newName, rule);
    if (f.binary) {
      // Content unknown: a shell-style write of each target (judged as unverifiable for settings and hooks).
      for (const p of news.length > 0 ? news : olds) out.push({ tool: "Bash", input: { command: `: > ${shq(p)}` } });
      continue;
    }
    if (f.newName === null) {
      for (const p of olds) out.push({ tool: "Bash", input: { command: `rm -- ${shq(p)}` } });
      continue;
    }
    if (f.oldName !== null && f.oldName !== f.newName && rule.target === undefined) {
      for (const from of olds) for (const to of news) if (from !== to) out.push({ tool: "Bash", input: { command: `mv -- ${shq(from)} ${shq(to)}` } });
    }
    if (f.modeOnly) {
      for (const p of news) out.push({ tool: "Bash", input: { command: `chmod +x -- ${shq(p)}` } });
      continue;
    }
    const created = f.oldName === null || f.hunks.every((h) => h.old === "");
    for (const p of news) {
      if (created && f.oldName === null) out.push({ tool: "Write", input: { file_path: p, content: `${f.hunks.map((h) => h.new).join("\n")}\n` } });
      else out.push({ tool: "MultiEdit", input: { file_path: p, edits: f.hunks.map((h) => ({ old_string: h.old, new_string: h.new })), match: "loose" } });
    }
  }
  return out;
}

/** The actions a Codex patch (`*** Begin Patch`) amounts to, or null when it does not parse. */
export function codexPatchActions(text: string): NormalizedAction[] | null {
  const p = parsePatch(text);
  if (!p.ok) return null;
  const out: NormalizedAction[] = [];
  for (const op of p.ops) {
    if (op.kind === "add") out.push({ tool: "Write", input: { file_path: op.path, content: op.content } });
    else if (op.kind === "delete") out.push({ tool: "Bash", input: { command: `rm -- ${shq(op.path)}` } });
    else {
      const target = op.moveTo ?? op.path;
      if (op.moveTo !== undefined) out.push({ tool: "Bash", input: { command: `mv -- ${shq(op.path)} ${shq(op.moveTo)}` } });
      const edits = op.chunks.map((c) => ({ old_string: c.old, new_string: c.new }));
      // An append chunk (no context) has an empty old text: its result is unknown without the file, so it is
      // judged as text added to the file (an edit whose old text matches nowhere: the worst case).
      if (edits.length > 0) out.push({ tool: "MultiEdit", input: { file_path: target, edits: edits.map((e) => (e.old_string === "" ? { old_string: "\u0000launchsafe:append\u0000", new_string: e.new_string } : e)), match: "loose" } });
    }
  }
  return out;
}

/** Whether a text looks like a patch of either kind. */
export function looksLikePatch(text: string): boolean {
  return /^\*\*\* Begin Patch\s*$/m.test(text) || /^(?:diff --git |--- \S)/m.test(text);
}
