/**
 * The scratch-target allowlist: name patterns a person declares throwaway (`app_*_test`, `*-pr-*`,
 * `preview-*`), so deleting a database, namespace, app or bucket with such a name is asked instead of
 * denied (FW-CATASTROPHIC, src/engine/catastrophic.ts). User level only: the file lives in the firewall's
 * home (which the agent may not write) and is signed with the approval key, so neither a project policy nor
 * an agent can add a pattern; `scratch add` and `scratch remove` need a person and the passphrase.
 */

import { createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { join } from "node:path";
import { canonicalJson } from "../engine/decide.js";
import { validScratchPattern } from "../engine/catastrophic.js";
import { atomicWrite, ensureDir, readText, withLock } from "./fsutil.js";
import { assertNotRealHome } from "./guard.js";
import type { Layout } from "./layout.js";

export interface ScratchFile {
  version: 1;
  patterns: string[];
  signedAt: string;
  /** Ed25519 over the canonical JSON of {version, patterns, signedAt}, with the approver key, base64. */
  sig: string;
}

export type ScratchState = { state: "absent" } | { state: "corrupt"; error: string } | { state: "unsigned"; file: ScratchFile; reason: string } | { state: "ok"; file: ScratchFile };

export function scratchPath(l: Layout): string {
  return join(l.home, "scratch-targets.json");
}

function message(version: 1, patterns: readonly string[], signedAt: string): Buffer {
  return Buffer.from(`launchsafe-firewall/scratch-targets/v1\n${canonicalJson({ version, patterns, signedAt })}`, "utf8");
}

export function signScratch(priv: KeyObject, patterns: readonly string[], now: Date = new Date()): ScratchFile {
  const signedAt = now.toISOString();
  return { version: 1, patterns: [...patterns], signedAt, sig: sign(null, message(1, patterns, signedAt), priv).toString("base64") };
}

export function verifyScratch(f: ScratchFile, publicKeyB64: string | null): boolean {
  if (publicKeyB64 === null || publicKeyB64 === "") return false;
  try {
    const pub = createPublicKey({ key: Buffer.from(publicKeyB64, "base64"), format: "der", type: "spki" });
    return verify(null, message(f.version, f.patterns, f.signedAt), pub, Buffer.from(f.sig, "base64"));
  } catch {
    return false;
  }
}

export function parseScratch(text: string): ScratchFile | null {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null) return null;
  const o = raw as Record<string, unknown>;
  if (o.version !== 1 || !Array.isArray(o.patterns) || typeof o.signedAt !== "string" || typeof o.sig !== "string") return null;
  if (!o.patterns.every((p) => typeof p === "string" && validScratchPattern(p))) return null;
  return { version: 1, patterns: o.patterns as string[], signedAt: o.signedAt, sig: o.sig };
}

/** Reads and verifies the file against the approver key the caller trusts. Never throws. */
export function loadScratch(l: Layout, trustedKey: string | null): ScratchState {
  let text: string | null;
  try {
    text = readText(scratchPath(l));
  } catch (e) {
    return { state: "corrupt", error: `${scratchPath(l)} cannot be read (${(e as Error).message})` };
  }
  if (text === null) return { state: "absent" };
  const f = parseScratch(text);
  if (f === null) return { state: "corrupt", error: `${scratchPath(l)} is not a valid scratch-target list` };
  if (trustedKey === null) return { state: "unsigned", file: f, reason: "no approval key is set or pinned" };
  if (!verifyScratch(f, trustedKey)) return { state: "unsigned", file: f, reason: "the scratch-target list is not signed by your approval key" };
  return { state: "ok", file: f };
}

/** The patterns the engine may use: only from a list that verifies. */
export function scratchPatterns(st: ScratchState): string[] | undefined {
  return st.state === "ok" && st.file.patterns.length > 0 ? [...st.file.patterns] : undefined;
}

/** Changes the list under its lock and re-signs it; refuses to build on a list that does not verify. */
export function updateScratch(l: Layout, priv: KeyObject, change: (patterns: string[]) => void, now: Date = new Date()): string[] {
  assertNotRealHome(scratchPath(l));
  ensureDir(l.locks);
  const pub = (createPublicKey(priv).export({ type: "spki", format: "der" }) as Buffer).toString("base64");
  return withLock(join(l.locks, "scratch-targets.lock"), () => {
    const st = loadScratch(l, pub);
    if (st.state === "corrupt") throw new Error(`${st.error}. Nothing was changed; move it aside to start an empty list.`);
    if (st.state === "unsigned") throw new Error(`${st.reason}, so something other than you may have changed it. Nothing was changed; check ${scratchPath(l)} or move it aside.`);
    const patterns = st.state === "ok" ? [...st.file.patterns] : [];
    change(patterns);
    atomicWrite(scratchPath(l), `${JSON.stringify(signScratch(priv, patterns, now), null, 2)}\n`, 0o600);
    return patterns;
  });
}
