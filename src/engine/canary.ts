/**
 * Decoy files the engine's side: pure lookups against the index the
 * runtime built from the registry. A decoy is a file the person planted that
 * no legitimate task needs. Touching one is a tripwire; its unique value in
 * outbound data is denied. Nothing here does I/O.
 */

import type { CanaryIndex, Context } from "../types.js";
import { containsFingerprint } from "./secrets.js";
import { isUnder, normalizeAbs } from "./paths.js";

/** The key a path is stored and looked up under. */
export function pathKey(abs: string, caseInsensitive: boolean): string {
  return caseInsensitive ? abs.toLowerCase() : abs;
}

export interface CanaryEntry {
  id: string;
  path: string;
  fingerprint: string;
}

/** Builds the index the engine reads. `paths` holds each decoy's path and its realpath. */
export function buildCanaryIndex(entries: readonly CanaryEntry[], caseInsensitive: boolean, realpath?: (p: string) => string): CanaryIndex {
  const idx: CanaryIndex = { paths: new Set(), fingerprints: new Set(), byPath: new Map(), byFingerprint: new Map() };
  for (const e of entries) {
    const forms = new Set([e.path]);
    try {
      if (realpath !== undefined) forms.add(normalizeAbs(realpath(e.path)));
    } catch {
      // The path as registered is what we have.
    }
    for (const f of forms) {
      idx.paths.add(f);
      idx.byPath.set(pathKey(f, caseInsensitive), e.id);
    }
    idx.fingerprints.add(e.fingerprint);
    idx.byFingerprint.set(e.fingerprint, e.id);
  }
  return idx;
}

/** The decoy id when this absolute path is a decoy (checked as written and after resolving symlinks). */
export function canaryAtPath(ctx: Context, abs: string): string | null {
  const idx = ctx.canaries;
  if (idx === undefined || idx.byPath.size === 0) return null;
  const forms = [abs];
  try {
    if (ctx.realpath !== undefined) forms.push(normalizeAbs(ctx.realpath(abs)));
  } catch {
    // Judge the path as written.
  }
  for (const f of forms) {
    const id = idx.byPath.get(pathKey(f, ctx.caseInsensitive));
    if (id !== undefined) return id;
  }
  return null;
}

/** Decoy ids whose path lies under a directory (a recursive read of it would reach them). */
export function canariesUnder(ctx: Context, dirAbs: string): { id: string; path: string }[] {
  const idx = ctx.canaries;
  if (idx === undefined) return [];
  const out: { id: string; path: string }[] = [];
  for (const p of idx.paths) {
    const id = idx.byPath.get(pathKey(p, ctx.caseInsensitive));
    if (id !== undefined && isUnder(p, dirAbs, ctx.caseInsensitive) && !out.some((o) => o.id === id)) out.push({ id, path: p });
  }
  return out;
}

/** Whether a text carries any decoy value, in the clear or in an encoding containsFingerprint() checks. */
export function carriesCanary(text: string, idx: CanaryIndex | undefined): boolean {
  if (idx === undefined || idx.fingerprints.size === 0 || text === "") return false;
  return containsFingerprint(text, idx.fingerprints);
}

/** Ids of the decoys whose value is in the text. Only called after carriesCanary() said yes. */
export function canaryIdsIn(text: string, idx: CanaryIndex): string[] {
  const ids: string[] = [];
  for (const [fp, id] of idx.byFingerprint) if (containsFingerprint(text, [fp])) ids.push(id);
  return ids;
}
