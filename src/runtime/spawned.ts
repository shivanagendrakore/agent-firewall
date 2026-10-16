/**
 * R4: prompts proposed for new sessions (the desktop app's spawn_task chip). The agent wrote them, so
 * when one arrives as a session's prompt it is not the person naming destinations, and when the session
 * that proposed it had read outside content, the new session starts untrusted.
 *
 * Assumption (not verified against a captured event): the app delivers the proposed prompt to the new
 * session as its first UserPromptSubmit, verbatim or wrapped in other text. We therefore match a prompt
 * that equals a recorded one or contains it (recorded prompts of at least MIN_MATCH characters). If the
 * app delivers it some other way, nothing here loosens anything: PreToolUse already asks before an
 * untrusted session proposes one (FW-AGENT-SPAWN), with the full prompt shown.
 *
 * Kept in the firewall home (the agent cannot write there), at most MAX_ENTRIES, for MAX_AGE_MS.
 */

import { createHash } from "node:crypto";
import { join } from "node:path";
import { atomicWrite, readText, withLock } from "./fsutil.js";
import type { Layout } from "./layout.js";

const MAX_ENTRIES = 50;
const MAX_AGE_MS = 7 * 24 * 3600 * 1000;
const MAX_PROMPT = 64 * 1024;
const MIN_MATCH = 24;

export interface SpawnedPrompt {
  hash: string;
  prompt: string;
  /** The proposing session had read outside content. */
  tainted: boolean;
  session: string;
  at: number;
}

function path(l: Layout): string {
  return join(l.home, "spawned.json");
}

function read(l: Layout): SpawnedPrompt[] {
  try {
    const t = readText(path(l));
    if (t === null) return [];
    const o = JSON.parse(t) as unknown;
    return Array.isArray(o) ? (o as SpawnedPrompt[]).filter((e) => typeof e === "object" && e !== null && typeof e.prompt === "string" && typeof e.hash === "string") : [];
  } catch {
    return [];
  }
}

const hashOf = (s: string): string => createHash("sha256").update(s).digest("hex");

/** Records a proposed prompt (called by PreToolUse for an allowed or asked spawn_task). */
export function recordSpawned(l: Layout, prompt: string, tainted: boolean, session: string, now = Date.now()): void {
  const p = prompt.slice(0, MAX_PROMPT);
  withLock(join(l.locks, "spawned.lock"), () => {
    const keep = read(l).filter((e) => now - e.at < MAX_AGE_MS && e.hash !== hashOf(p));
    keep.push({ hash: hashOf(p), prompt: p, tainted, session, at: now });
    atomicWrite(path(l), JSON.stringify(keep.slice(-MAX_ENTRIES)));
  });
}

/** The recorded proposal a session prompt carries, if any (a tainted one wins). */
export function matchSpawned(l: Layout, prompt: string, now = Date.now()): SpawnedPrompt | null {
  if (prompt === "") return null;
  const h = hashOf(prompt.slice(0, MAX_PROMPT));
  const hits = read(l).filter((e) => now - e.at < MAX_AGE_MS && (e.hash === h || (e.prompt.trim().length >= MIN_MATCH && prompt.includes(e.prompt.trim()))));
  return hits.find((e) => e.tainted) ?? hits[0] ?? null;
}
