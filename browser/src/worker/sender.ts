/**
 * What the worker knows about a content message's sender, from Chrome alone
 * (threat model 5, "Messages from pages"). A page can write anything into a
 * message body, so origins, hosts and page URLs are taken from `sender`; a
 * body value is at most a hint, and a hint can only make a decision stricter
 * (`strictest`), never looser.
 */
import { hostOf, originOf } from "../engine/domain.js";
import type { Decision, Verdict } from "../engine/types.js";

export interface SenderFacts {
  tabId: number;
  frameId: number;
  /** The frame's document URL (sender.url), "" when Chrome gave none. */
  url: string;
  /** The frame's origin: sender.origin, else the origin of sender.url, else "". */
  origin: string;
  /** The frame's host (from its origin, else its URL; OPAQUE_HOST for a data: or srcdoc document), "" when it has none. */
  host: string;
  /** The tab's top-level URL (sender.tab.url), "" when Chrome gave none. */
  tabUrl: string;
}

export interface ChromeSender {
  url?: string;
  origin?: string;
  tab: { id: number; url?: string };
  frameId: number;
}

export function senderFacts(sender: ChromeSender): SenderFacts {
  const url = sender.url ?? "";
  const origin = sender.origin ?? originOf(url) ?? "";
  // An opaque origin ("null") falls back to the URL's host: a data: or srcdoc document gets the untrusted
  // stand-in (domain.ts OPAQUE_HOST, which no exemption or grant covers); about:blank frames carry their creator's origin.
  const host = (origin !== "" && origin !== "null" ? hostOf(origin) : null) ?? hostOf(url) ?? "";
  const tabUrl = sender.tab.url ?? (sender.frameId === 0 ? url : "");
  return { tabId: sender.tab.id, frameId: sender.frameId, url, origin, host, tabUrl };
}

const RANK: Record<Verdict, number> = { allow: 0, log: 1, warn: 2, approve: 3, deny: 4 };

/** The strictest of several decisions about one action; on a tie the earliest (put the authoritative one first). */
export function strictest<T extends { decision: Decision }>(results: readonly [T, ...T[]]): T {
  let best = results[0];
  for (const r of results) if (RANK[r.decision.verdict] > RANK[best.decision.verdict]) best = r;
  return best;
}

/** Distinct values in order, the authoritative value first (each is judged; the strictest decision wins). */
export function candidates(first: string, ...hints: readonly string[]): [string, ...string[]] {
  const out: [string, ...string[]] = [first];
  for (const v of hints) if (!out.includes(v)) out.push(v);
  return out;
}
