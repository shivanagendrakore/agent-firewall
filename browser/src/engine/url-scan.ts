/**
 * URL scanning (design 4.3): the query string and fragment are scanned as text
 * on every navigation (CometJacking, HashJack). Nobody reads a URL's query or
 * fragment as page content, so text in them addressed to an AI agent is judged
 * as unshown text: an instruction there is a quarantine, as hidden text is.
 *
 * In agent mode a quarantine-class fragment is removed with
 * history.replaceState before the page settles (`stripFragment`); the agent
 * may already have the URL from its own context, so this only removes it
 * from the page.
 */
import { scanContent, type QuarantineReason, type Verdict } from "../vendor/firewall/engine/content-scan.js";

export interface UrlScan {
  verdict: Verdict;
  reasons: QuarantineReason[];
  /** Which part carried the worst verdict. */
  part: "query" | "fragment" | null;
  /** Agent mode: remove the fragment (the query cannot be removed without reloading). */
  stripFragment: boolean;
  /** Up to 200 escaped characters of what was found, for evidence. */
  preview: string;
}

const ORDER: readonly Verdict[] = ["deliver", "neutralize", "flag", "quarantine"];

function decodeLoosely(s: string): string {
  let out = s.replace(/\+/g, " ");
  // Twice, for double encoding; stop at the first malformed escape.
  for (let i = 0; i < 2; i++) {
    try {
      const next = decodeURIComponent(out);
      if (next === out) break;
      out = next;
    } catch {
      break;
    }
  }
  return out;
}

function scanPart(raw: string): { verdict: Verdict; reasons: QuarantineReason[]; preview: string } {
  if (raw.length === 0) return { verdict: "deliver", reasons: [], preview: "" };
  const text = decodeLoosely(raw).replace(/[&=]/g, " ");
  const r = scanContent(text, { unshown: { visible: "" }, maxBytes: 64 * 1024, timeoutMs: 50 });
  return { verdict: r.verdict, reasons: r.reasons, preview: r.hiddenPreview };
}

export function scanUrl(url: string, agentMode: boolean): UrlScan {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return { verdict: "deliver", reasons: [], part: null, stripFragment: false, preview: "" };
  }
  const q = scanPart(u.search.replace(/^\?/, ""));
  const f = scanPart(u.hash.replace(/^#/, ""));
  const worst = ORDER.indexOf(f.verdict) >= ORDER.indexOf(q.verdict) ? { ...f, part: "fragment" as const } : { ...q, part: "query" as const };
  const part = worst.verdict === "deliver" ? null : worst.part;
  return {
    verdict: worst.verdict,
    reasons: worst.reasons,
    part,
    stripFragment: agentMode && f.verdict === "quarantine",
    preview: worst.preview,
  };
}
