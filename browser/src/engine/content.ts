/**
 * The content guard's scanning entry points (design 4.2, 4.4), over the
 * vendored firewall scanner.
 *
 * In a live page the browser already knows what is visible, so the content
 * script classifies text runs itself (checkVisibility, contrast, clipping) and
 * hands them here. The runs are rebuilt as minimal HTML with the hidden ones
 * in `display:none` spans, so `scanContent` applies exactly the signals and
 * verdicts the firewall's email guard applies to hidden text. Static HTML that
 * is never rendered (srcdoc, <template>, <noscript>, HTML in attributes) goes
 * through `scanHtml`, which runs the firewall's own CSS resolver.
 */
import { scanContent, SCAN_LIMITS, type QuarantineReason, type ScanResult, type Verdict } from "../vendor/firewall/engine/content-scan.js";

export type { QuarantineReason, ScanResult, Signal, Verdict as ContentVerdict } from "../vendor/firewall/engine/content-scan.js";
export { SCAN_LIMITS, verdictFor } from "../vendor/firewall/engine/content-scan.js";

/** How the content script judged a run hidden (design 4.2), for evidence; the scanner only needs `hidden`. */
export type HiddenKind = "not_rendered" | "zero_box" | "clipped" | "offscreen" | "tiny_font" | "low_contrast" | "aria_hidden" | "comment" | "folded";

export interface TextRun {
  text: string;
  hidden: boolean;
  how?: HiddenKind;
  /** The run came from an attribute (alt, title, aria-label, placeholder, value, meta content). */
  attribute?: string;
}

export interface PageScan {
  verdict: Verdict;
  reasons: QuarantineReason[];
  /** Indexes of the runs that carried hidden content (to strip or replace in agent mode). */
  hiddenRunIndexes: number[];
  scanIncomplete: boolean;
  /** Up to 200 escaped characters of hidden text, for evidence (kept only with "keep evidence" on). */
  preview: string;
  result: ScanResult;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** The runs as minimal HTML: visible runs as paragraphs, hidden runs as display:none spans. */
export function runsToHtml(runs: readonly TextRun[]): string {
  return runs.map((r) => (r.hidden ? `<p><span style="display:none">${escapeHtml(r.text)}</span></p>` : `<p>${escapeHtml(r.text)}</p>`)).join("\n");
}

export interface PageScanOptions {
  timeoutMs?: number;
  now?: () => number;
}

/** Scans the text runs of a live page (or a subtree added later). Never throws. */
export function scanPageRuns(runs: readonly TextRun[], opts: PageScanOptions = {}): PageScan {
  const result = scanContent(runsToHtml(runs), { html: true, timeoutMs: opts.timeoutMs ?? SCAN_LIMITS.timeoutMs, ...(opts.now !== undefined ? { now: opts.now } : {}) });
  const hiddenRunIndexes = result.verdict === "deliver" ? [] : runs.flatMap((r, i) => (r.hidden && r.text.trim() !== "" ? [i] : []));
  return {
    verdict: result.verdict,
    reasons: result.reasons,
    hiddenRunIndexes,
    scanIncomplete: result.signals.some((s) => s.id === "scan_incomplete"),
    preview: result.hiddenPreview,
    result,
  };
}

/** Scans static HTML that is not rendered (srcdoc, <template>, <noscript>, fetched fragments, the test corpus). */
export function scanHtml(html: string, opts: PageScanOptions = {}): ScanResult {
  return scanContent(html, { html: true, timeoutMs: opts.timeoutMs ?? SCAN_LIMITS.timeoutMs, ...(opts.now !== undefined ? { now: opts.now } : {}) });
}
