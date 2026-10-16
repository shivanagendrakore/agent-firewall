/**
 * Codex's `apply_patch` format, parsed into per-file operations. The format is
 * line based:
 *
 *   *** Begin Patch
 *   *** Add File: path          (followed by "+" lines: the new file)
 *   *** Delete File: path
 *   *** Update File: path       (optionally "*** Move to: path", then chunks)
 *   @@ [context header]         (a chunk: " " context, "-" removed, "+" added)
 *   *** End of File             (optional, inside an update)
 *   *** End Patch
 *
 * The parser is strict: anything it does not understand makes the whole patch
 * unparseable, and the firewall then asks a person (FW-UNCLASSIFIABLE) instead
 * of guessing which files it touches. Linear in the patch length.
 */

export interface PatchChunk {
  /** The text the chunk expects to find (context and removed lines). */
  old: string;
  /** The text it leaves (context and added lines). */
  new: string;
  /** The chunk's own text, as written in the patch (the proposal a person reads). */
  text: string;
}

export type PatchOp =
  | { kind: "add"; path: string; content: string }
  | { kind: "delete"; path: string }
  | { kind: "update"; path: string; moveTo?: string; chunks: PatchChunk[] };

export type PatchParse = { ok: true; ops: PatchOp[] } | { ok: false; reason: string };

const MAX_PATCH = 8 * 1024 * 1024;

function header(line: string, name: string): string | null {
  const prefix = `*** ${name}: `;
  if (!line.startsWith(prefix)) return null;
  const p = line.slice(prefix.length).trim();
  // Rust's trim() (the tool's) also strips U+0085, JS's does not; any control or C1 character in a path is refused
  // at the end of parsePatch, so a trailing NEL cannot hide a suffix from the checks.
  return p === "" ? null : p;
}

/** Strips a heredoc wrapper (`apply_patch <<'EOF' ... EOF`) some models send. */
function unwrap(text: string): string {
  const m = /^\s*(?:apply_patch|applypatch)\s+<<\s*['"]?(\w+)['"]?\s*\n([\s\S]*?)\n\1\s*$/.exec(text);
  return m?.[2] ?? text;
}

export function parsePatch(raw: string): PatchParse {
  if (raw.length > MAX_PATCH) return { ok: false, reason: "the patch is too large to check" };
  const lines = unwrap(raw).replace(/\r\n/g, "\n").split("\n");
  while (lines.length > 0 && (lines[lines.length - 1] ?? "").trim() === "") lines.pop();
  let i = 0;
  while (i < lines.length && (lines[i] ?? "").trim() === "") i++;
  if ((lines[i] ?? "").trim() !== "*** Begin Patch") return { ok: false, reason: "the patch does not start with *** Begin Patch" };
  i++;
  const ops: PatchOp[] = [];
  let ended = false;
  while (i < lines.length) {
    const line = lines[i] ?? "";
    if (line.trim() === "*** End Patch") {
      ended = true;
      i++;
      break;
    }
    const add = header(line, "Add File");
    const del = header(line, "Delete File");
    const upd = header(line, "Update File");
    if (add !== null) {
      i++;
      const body: string[] = [];
      while (i < lines.length && (lines[i] ?? "").startsWith("+")) body.push((lines[i++] ?? "").slice(1));
      ops.push({ kind: "add", path: add, content: body.length > 0 ? `${body.join("\n")}\n` : "" });
      continue;
    }
    if (del !== null) {
      ops.push({ kind: "delete", path: del });
      i++;
      continue;
    }
    if (upd !== null) {
      i++;
      const op: PatchOp & { kind: "update" } = { kind: "update", path: upd, chunks: [] };
      const move = header(lines[i] ?? "", "Move to");
      if (move !== null) {
        op.moveTo = move;
        i++;
      }
      let cur: { old: string[]; new: string[]; text: string[] } | null = null;
      const flush = (): void => {
        if (cur !== null && (cur.old.length > 0 || cur.new.length > 0)) op.chunks.push({ old: cur.old.join("\n"), new: cur.new.join("\n"), text: cur.text.join("\n") });
        cur = null;
      };
      while (i < lines.length) {
        const l = lines[i] ?? "";
        if (l.startsWith("*** ") && l.trim() !== "*** End of File") break;
        if (l.trim() === "*** End of File") {
          i++;
          continue;
        }
        if (l.startsWith("@@")) {
          flush();
          cur = { old: [], new: [], text: [l] };
          i++;
          continue;
        }
        // The first chunk of an update may omit its @@ line.
        cur ??= { old: [], new: [], text: [] };
        const c: { old: string[]; new: string[]; text: string[] } = cur;
        if (l.startsWith("+")) c.new.push(l.slice(1));
        else if (l.startsWith("-")) c.old.push(l.slice(1));
        else if (l.startsWith(" ")) {
          c.old.push(l.slice(1));
          c.new.push(l.slice(1));
        } else if (l === "") {
          c.old.push("");
          c.new.push("");
        } else return { ok: false, reason: `the patch has a line that is not part of a change: ${l.slice(0, 80)}` };
        c.text.push(l);
        i++;
      }
      flush();
      if (op.chunks.length === 0 && op.moveTo === undefined) return { ok: false, reason: `the update of ${upd} has no changes` };
      ops.push(op);
      continue;
    }
    if (line.trim() === "") {
      i++;
      continue;
    }
    return { ok: false, reason: `the patch has a line the firewall does not understand: ${line.slice(0, 80)}` };
  }
  if (!ended) return { ok: false, reason: "the patch does not end with *** End Patch" };
  if (lines.slice(i).some((l) => l.trim() !== "")) return { ok: false, reason: "the patch has text after *** End Patch" };
  if (ops.length === 0) return { ok: false, reason: "the patch changes no files" };
  const bad = (x: string | undefined): boolean => x !== undefined && [...x].some((ch) => { const n = ch.codePointAt(0) ?? 0; return n <= 0x1f || (n >= 0x7f && n <= 0x9f); });
  if (ops.some((o) => bad(o.path) || (o.kind === "update" && bad(o.moveTo)))) return { ok: false, reason: "a path in the patch has a control character, so the file it names cannot be told" };
  return { ok: true, ops };
}
