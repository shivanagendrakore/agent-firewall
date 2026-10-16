/**
 * R10: the files an instruction file imports. Claude Code (and Gemini CLI) load `@path` references in
 * CLAUDE.md / GEMINI.md as instructions, recursively (Claude Code follows up to five hops), so an
 * imported file programs the agent exactly like CLAUDE.md does. Pure apart from ctx.readFile.
 *
 * Syntax followed: `@` at the start of a line or after whitespace, then a path (relative to the
 * importing file, `~/` for the home directory, or absolute), outside fenced code blocks and inline code
 * spans. A reference that does not exist yet is still listed (creating it later is the same write).
 */

import type { Context } from "../types.js";
import { isUnder, normalizeAbs, pathForms, PROTECTION_FOLDS_CASE } from "./paths.js";

export const MAX_IMPORT_DEPTH = 5;
const MAX_FILES = 64;
const MAX_TEXT = 512 * 1024;

/** The root instruction files whose imports load in a session, relative to a workspace root. */
const ROOT_FILES = ["CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md", "AGENTS.md", "GEMINI.md"];

/** The raw `@` references in an instruction file's text. */
export function parseImports(text: string): string[] {
  const out: string[] = [];
  let fenced = false;
  for (const line of text.slice(0, MAX_TEXT).split(/\r?\n/)) {
    if (/^\s*(?:```|~~~)/.test(line)) {
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;
    const bare = line.replace(/`[^`]*`/g, " ");
    for (const m of bare.matchAll(/(?:^|\s)@((?:~\/|\.{1,2}\/|\/)?[A-Za-z0-9_.][^\s`'"<>()[\]]*)/g)) {
      const p = (m[1] as string).replace(/[.,;:!?]+$/, "");
      // A path needs a file-like shape: a slash or an extension (not "@here" or "@team").
      if (p !== "" && (p.includes("/") || /\.[A-Za-z0-9]{1,8}$/.test(p))) out.push(p);
    }
  }
  return out;
}

function dirOf(abs: string): string {
  const i = abs.lastIndexOf("/");
  return i <= 0 ? "/" : abs.slice(0, i);
}

/** Resolves one reference from the file that names it. */
export function resolveImport(ref: string, fromFile: string, home: string): string {
  if (ref.startsWith("~/")) return normalizeAbs(`${home}/${ref.slice(2)}`);
  if (ref.startsWith("/")) return normalizeAbs(ref);
  return normalizeAbs(`${dirOf(fromFile)}/${ref}`);
}

const memo = new WeakMap<Context, Set<string>>();

/**
 * Every file the session's instruction files import, directly or through other imports (bounded),
 * keyed lower-case (I1: on every platform, as protected files are: PROTECTION_FOLDS_CASE, canonical.ts).
 * Instruction files: the root ones in each workspace root, ~/.claude/CLAUDE.md, and any extra (a nested
 * CLAUDE.md next to the target).
 */
export function importedInstructionFiles(ctx: Context, extra: readonly string[] = []): Set<string> {
  const read = ctx.readFile;
  if (read === undefined) return new Set();
  const cached = extra.length === 0 ? memo.get(ctx) : undefined;
  if (cached !== undefined) return cached;
  // Which files were read already follows the platform (two files that differ only in case are two files to read on a
  // case-sensitive disk); which files count as imported ignores case.
  const key = (p: string): string => (ctx.caseInsensitive ? p.toLowerCase() : p);
  const starts = [...ctx.workspaceRoots.flatMap((r) => ROOT_FILES.map((f) => normalizeAbs(`${r}/${f}`))), normalizeAbs(`${ctx.home}/.claude/CLAUDE.md`), ...extra];
  const seen = new Set<string>(starts.map(key));
  const out = new Set<string>();
  let frontier = starts;
  let reads = 0;
  for (let depth = 0; depth < MAX_IMPORT_DEPTH && frontier.length > 0; depth++) {
    const next: string[] = [];
    for (const file of frontier) {
      if (reads++ >= MAX_FILES) break;
      let text: string | null = null;
      try {
        text = read(file);
      } catch {
        text = null;
      }
      if (text === null) continue;
      for (const ref of parseImports(text)) {
        const abs = resolveImport(ref, file, ctx.home);
        out.add(abs.toLowerCase());
        // A reference through a symlinked directory is the file the link leads to as well.
        for (const form of pathForms(abs, ctx).paths) out.add(form.toLowerCase());
        const k = key(abs);
        if (!seen.has(k)) {
          seen.add(k);
          next.push(abs);
        }
      }
    }
    frontier = next;
  }
  if (extra.length === 0) memo.set(ctx, out);
  return out;
}

/** The nested CLAUDE.md files that load when the agent works in `abs`'s directory (between a workspace root and it). */
export function nestedInstructionFiles(ctx: Context, abs: string): string[] {
  // I1: this only adds protected files, so it ignores case on every platform (PROTECTION_FOLDS_CASE, canonical.ts).
  const root = ctx.workspaceRoots.find((r) => isUnder(abs, r, PROTECTION_FOLDS_CASE));
  if (root === undefined) return [];
  const out: string[] = [];
  let dir = dirOf(abs);
  for (let i = 0; i < 16 && dir.length > root.length && isUnder(dir, root, PROTECTION_FOLDS_CASE); i++) {
    out.push(`${dir}/CLAUDE.md`);
    dir = dirOf(dir);
  }
  return out;
}

/** Whether `abs` is a file an instruction file imports (R10). */
export function isImportedInstruction(ctx: Context, abs: string): boolean {
  // The path as written and where its symlinks lead: a write through an alias of an imported file is that file.
  for (const form of pathForms(abs, ctx).paths) {
    const k = form.toLowerCase();
    if (importedInstructionFiles(ctx).has(k)) return true;
    const nested = nestedInstructionFiles(ctx, form);
    if (nested.length > 0 && importedInstructionFiles(ctx, nested).has(k)) return true;
  }
  return false;
}
