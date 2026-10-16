/**
 * The content guard's judgement over a live page (design 4.2 to 4.4): the
 * page verdict from the vendored scanner, plus which runs, links and static
 * fragments to neutralise in agent mode.
 *
 * The page verdict comes from one `scanPageRuns` over every run, so the
 * scanner's own rules (duplicates of visible text, preheaders, lexicons) decide
 * it. Attribution is a second, narrower pass that runs only when there is
 * something to remove: each hidden run is scanned alone, and only a run that is
 * itself quarantine-class (and not a copy of visible text) is offending. So a
 * page is never stripped wholesale: screen-reader text, closed menus and
 * hidden panels stay unless they carry an instruction.
 */
import { scanCharacters } from "../vendor/firewall/engine/content-scan.js";
import { LEXICON_A, lexiconHits } from "../vendor/firewall/engine/content-lexicon.js";
import { entropy, isCaptureUrl, parseUrlLike } from "../vendor/firewall/engine/network.js";
import { scanHtml, scanPageRuns, type ContentVerdict, type QuarantineReason, type TextRun } from "./content.js";
import { sameSite } from "./domain.js";

/** A run as the content script collected it; `folded` runs count as hidden only with an agent-addressed hit (design 4.2). */
export interface GuardRun extends TextRun {
  folded?: boolean;
}

export interface RunJudgement {
  verdict: ContentVerdict;
  reasons: QuarantineReason[];
  /** Runs to remove in agent mode (hidden, quarantine-class on their own). */
  offending: number[];
  /** Runs whose invisible characters (tag characters, zero-width runs, bidi controls) to strip; visible text stays. */
  stripChars: number[];
  scanIncomplete: boolean;
  preview: string;
}

const ORDER: readonly ContentVerdict[] = ["deliver", "neutralize", "flag", "quarantine"];
export const worse = (a: ContentVerdict, b: ContentVerdict): ContentVerdict => (ORDER.indexOf(a) >= ORDER.indexOf(b) ? a : b);

const LEX_STRIP = /[\u00AD\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\s\u00A0]|\u034F|\uDB40[\uDC00-\uDC7F]/g;
/** The scanner's duplicate rule, restated: lower case without spacing and invisible characters. */
export function normalizeForDuplicate(s: string): string {
  return s.toLowerCase().replace(LEX_STRIP, "");
}

/**
 * Lexicon A read as visible text: the entries that are strong anywhere. The hidden-only entry (an agent
 * directive such as "curl ... | sh") is left out on purpose: a closed install tab is full of those.
 */
function hasAgentAddress(text: string): boolean {
  return lexiconHits(text, LEXICON_A, false).length > 0;
}

/**
 * A folded run (closed details, spoiler, hidden=until-found, a closed tab panel, menu or dialog) is shown when
 * a person interacts, so it is judged like visible text: hidden only when it addresses an agent, and then
 * scanned as hidden (so the instruction quarantines).
 */
function effective(run: GuardRun): TextRun {
  if (run.folded !== true) return run;
  return hasAgentAddress(run.text) ? { ...run, hidden: true, how: "folded" } : { ...run, hidden: false };
}

/**
 * Whether a hidden run that holds most of the page's text may be read as a loading veil (a fade-in, a page not
 * shown yet) rather than hidden text: only when it neither addresses an agent nor is quarantine- or flag-class
 * when scanned on its own as hidden text (RR5).
 */
export function isBenignVeil(run: GuardRun): boolean {
  if (hasAgentAddress(run.text)) return false;
  const r = scanPageRuns([{ ...run, hidden: true, how: run.how ?? "not_rendered" }], { timeoutMs: 50 });
  if (r.scanIncomplete) return false;
  return r.verdict !== "quarantine" && !r.result.signals.some((sg) => sg.id === "agent_directed" || sg.id === "exfil_link");
}

export interface JudgeOptions {
  /** Visible text of the rest of the page (for late subtrees), so a hidden copy of it is not an instruction. */
  visibleContext?: string;
  timeoutMs?: number;
  now?: () => number;
}

/** Judges a page's (or a late subtree's) runs. Never throws. */
export function judgeRuns(runs: readonly GuardRun[], opts: JudgeOptions = {}): RunJudgement {
  const eff = runs.map(effective);
  const page = scanPageRuns(eff, { ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}), ...(opts.now !== undefined ? { now: opts.now } : {}) });
  let verdict = page.verdict;
  const reasons = new Set<QuarantineReason>(page.reasons);
  // The scanner ranks neutralize (hidden content) above flag (visible agent-addressed text), which suits mail.
  // Live pages nearly always carry hidden UI (closed menus, screen-reader text), so that order would hide every
  // visible instruction; for a page, visible agent-addressed text is the stronger fact.
  if (verdict === "neutralize" && page.result.signals.some((sg) => (sg.id === "agent_directed" || sg.id === "exfil_link") && !sg.hidden)) verdict = "flag";

  const stripChars: number[] = [];
  eff.forEach((r, i) => {
    if (scanCharacters(r.text).remove.length > 0) stripChars.push(i);
  });

  const offending: number[] = [];
  if (verdict === "quarantine") {
    const visibleNorm = normalizeForDuplicate([opts.visibleContext ?? "", ...eff.filter((r) => !r.hidden).map((r) => r.text)].join(" "));
    eff.forEach((r, i) => {
      if (!r.hidden || !/\p{L}/u.test(r.text)) return;
      const norm = normalizeForDuplicate(r.text);
      if (norm !== "" && visibleNorm.includes(norm)) return;
      if (scanPageRuns([r], { timeoutMs: 50 }).verdict === "quarantine") offending.push(i);
    });
    // Tag characters smuggle text wherever they sit; a hidden run that carries them goes, a visible one is stripped.
    if (reasons.has("tag_chars")) {
      eff.forEach((r, i) => {
        if (r.hidden && scanCharacters(r.text).tagCount > 0 && !offending.includes(i)) offending.push(i);
      });
    }
    // A late subtree whose only "instruction" copies text visible elsewhere on the page is not one.
    if (offending.length === 0 && reasons.size === 1 && reasons.has("hidden_instruction") && opts.visibleContext !== undefined) {
      const anyFresh = eff.some((r) => r.hidden && /\p{L}/u.test(r.text) && !visibleNorm.includes(normalizeForDuplicate(r.text)));
      if (!anyFresh) {
        verdict = "neutralize";
        reasons.clear();
      }
    }
  }
  return { verdict, reasons: [...reasons], offending: offending.sort((a, b) => a - b), stripChars, scanIncomplete: page.scanIncomplete, preview: page.preview };
}

// ---- links --------------------------------------------------------------------------------------

export interface GuardLink {
  url: string;
  kind: "image" | "link";
  hidden: boolean;
  /** A 1x1 (or smaller) image: a tracking pixel, not a carrier for random query data. */
  pixel: boolean;
}

export type ExfilWhy = "template" | "capture_host" | "query_entropy";

/** What the guard knows about the page a link sits on. */
export interface LinkContext {
  /** The page's host name; a slot on a link to another registrable domain counts for more. */
  pageHost?: string;
}

/**
 * A slot for a model to fill: {name}, {{name}}, ${name} or <name>, where the name is one identifier (no spaces).
 * Matched on decoded text, so the encodings (%7B...%7D, %3C...%3E) are the same slot.
 */
const SLOT = /\$?\{\{?\s*([A-Za-z_][\w.-]{0,60})\s*\}\}?|<([A-Za-z_][\w.-]{0,60})>/g;

/**
 * Markup, not a slot: a pre-filled issue body or a code sample carries real HTML tags (<details>, <summary>,
 * <br>) and type parameters (Vec<T>), never a request for data.
 */
const HTML_TAGS = new Set(
  "a abbr b bdi bdo blockquote br button caption cite code col dd del details dfn div dl dt em figcaption figure footer h1 h2 h3 h4 h5 h6 header hr i img input ins kbd label li main mark nav ol p pre q s samp section small span strong sub summary sup table tbody td th thead time tr u ul var wbr html head body title meta link script style".split(" "),
);

/**
 * Slot names that ask for secrets (split on _ . - and matched per word): what an exfiltration template is written
 * to collect. A REST path placeholder ("/objects/{key}", "/sessions/{session_id}") or "user-name" in a return
 * path is not one.
 */
const SECRET_WORD = /^(?:secrets?|tokens?|passwords?|passwd|pwd|passcode|credentials?|creds|cookies?|ssn|cvv|cvc|otp|conversations?|transcripts?|clipboard|prompts?|memory|memories|pii|inbox)$/i;
const SECRET_NAME = /api[_.-]?key|private[_.-]?key|access[_.-]?key|secret[_.-]?key/i;
/** Wider: personal data a template might also ask for, counted only in a short one-line value or a hidden off-site link. */
const PRIVATE_WORD = /^(?:emails?|mail|phone|card|iban|history|chat|summary|address(?:es)?|dob|birthday|salary|bank|personal|private|sessions?|messages?|contacts?|location)$/i;

function secretSlot(name: string): boolean {
  return SECRET_NAME.test(name) || name.split(/[_.-]+/).some((w) => SECRET_WORD.test(w));
}

function privateSlot(name: string): boolean {
  return secretSlot(name) || name.split(/[_.-]+/).some((w) => PRIVATE_WORD.test(w));
}

function decodeLoose(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    // A malformed escape: decode what can be decoded.
    return s.replace(/\+/g, " ").replace(/(?:%[0-9a-f]{2})+/gi, (m) => {
      try {
        return decodeURIComponent(m);
      } catch {
        return m;
      }
    });
  }
}

interface Slot {
  name: string;
  /** The slot is the whole of a query or fragment value (`?d={user_email}`), or a whole line of one. */
  wholeValue: boolean;
  /** The slot is a whole path segment or host label (`/{secret}/p.gif`). */
  wholeSegment: boolean;
  /** A query or fragment value that is short and on one line (not a code sample or a pre-filled document). */
  shortValue: boolean;
}

function slotsIn(value: string, where: "query" | "segment"): Slot[] {
  const out: Slot[] = [];
  const trimmed = value.trim();
  const lines = value.split(/\r?\n/).map((l) => l.trim());
  const shortValue = where === "query" && value.length <= 256 && !/[\r\n]/.test(value);
  for (const m of value.matchAll(SLOT)) {
    const name = (m[1] ?? m[2]) as string;
    if (m[2] !== undefined && HTML_TAGS.has(name.toLowerCase())) continue;
    const whole = trimmed === m[0] || lines.includes(m[0]);
    out.push({ name, wholeValue: where === "query" && whole, wholeSegment: where === "segment" && whole, shortValue });
  }
  return out;
}

/** Every slot in a URL, with where it sits. */
function urlSlots(raw: string, p: { host: string; path: string; query: string }): Slot[] {
  const out: Slot[] = [];
  // A slot in the host ("{secret}.attacker.test") cannot survive URL parsing; read it from the raw text.
  const rawHost = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(raw)?.[1] ?? "";
  for (const label of decodeLoose(rawHost).split(".")) out.push(...slotsIn(label, "segment"));
  for (const seg of p.path.split("/")) out.push(...slotsIn(decodeLoose(seg), "segment"));
  for (const kv of p.query.replace(/^[?#]/, "").split(/[&#;]/)) {
    const eq = kv.indexOf("=");
    out.push(...slotsIn(decodeLoose(eq === -1 ? kv : kv.slice(eq + 1)), "query"));
  }
  return out;
}

/**
 * The template rule, restated for live links (FP-1 to FP-3 in docs/real-corpus-findings.md). A slot alone is
 * not enough: ordinary links carry encoded placeholders ("ref_page=/<user-name>/<repo-name>"), code
 * ("play.rust-lang.org/?code=fn main() {...}") and markup (a pre-filled issue's <details>). A slot counts when
 * it is the whole of a query value (what an exfiltration template looks like: `?d={user_email}`), a whole
 * path segment or host label that names a secret, a private-data name in a short one-line value, or, for a
 * hidden link to another site, a private-data name anywhere.
 */
function isTemplate(link: GuardLink, p: { host: string; path: string; query: string }, ctx: LinkContext): boolean {
  const slots = urlSlots(link.url, p);
  if (slots.length === 0) return false;
  const offsite = ctx.pageHost !== undefined && ctx.pageHost !== "" && !sameSite(ctx.pageHost, p.host);
  return slots.some((s) => {
    if (s.wholeValue) return true;
    if (s.wholeSegment && secretSlot(s.name)) return true;
    if (!privateSlot(s.name)) return false;
    return s.shortValue || (link.hidden && offsite);
  });
}

/** Why a link or image URL looks like an exfiltration channel (the scanner's `exfil_link` rule, for live elements), or null. */
export function exfilWhy(link: GuardLink, ctx: LinkContext = {}): ExfilWhy | null {
  const p = parseUrlLike(link.url.replace(/[{}<>]/g, (c) => encodeURIComponent(c)));
  if (p === null || !/^(?:https?|wss?)$/.test(p.scheme)) return null;
  if (isTemplate(link, p, ctx)) return "template";
  if (isCaptureUrl(p)) return "capture_host";
  if (link.hidden && !link.pixel && link.kind === "image") {
    for (const kv of p.query.replace(/^[?#]/, "").split(/[&#;]/)) {
      const eq = kv.indexOf("=");
      let value = eq === -1 ? kv : kv.slice(eq + 1);
      try {
        value = decodeURIComponent(value.replace(/\+/g, " "));
      } catch {
        // A malformed escape is still data.
      }
      if (value.length > 64 && entropy(value) > 4.0) return "query_entropy";
    }
  }
  return null;
}

export interface LinkJudgement {
  verdict: ContentVerdict;
  reasons: QuarantineReason[];
  /** Hidden exfiltration links and images: removed in agent mode. */
  offending: number[];
}

/** Hidden exfil links quarantine; visible ones (a link to a request bin a person can see) flag. */
export function judgeLinks(links: readonly GuardLink[], ctx: LinkContext = {}): LinkJudgement {
  const offending: number[] = [];
  let visible = false;
  links.forEach((l, i) => {
    if (exfilWhy(l, ctx) === null) return;
    if (l.hidden) offending.push(i);
    else visible = true;
  });
  if (offending.length > 0) return { verdict: "quarantine", reasons: ["hidden_exfil_link"], offending };
  return { verdict: visible ? "flag" : "deliver", reasons: [], offending };
}

// ---- static fragments ----------------------------------------------------------------------------

export interface StaticJudgement {
  verdict: ContentVerdict;
  reasons: QuarantineReason[];
}

/**
 * HTML that is never rendered but that an agent reading the DOM reads
 * (<template>, <noscript>, iframe srcdoc): the firewall's own CSS resolver
 * decides. Only a quarantine counts: a template's markup is not shown, so its
 * ordinary text must not make the page look hidden-heavy.
 */
export function judgeStatic(html: string): StaticJudgement {
  const r = scanHtml(html, { timeoutMs: 100 });
  if (r.verdict === "quarantine") return { verdict: "quarantine", reasons: r.reasons };
  // Visible text addressed to an agent inside unrendered markup is still addressed to whoever reads the DOM.
  const directed = r.signals.some((s) => s.id === "agent_directed");
  return { verdict: directed ? "quarantine" : "deliver", reasons: directed ? ["hidden_instruction"] : [] };
}
