/**
 * The email detector (email guard): one message in, one
 * verdict out.
 *
 * Every text channel a model could read (subject, sender name, Reply-To, the
 * provider's snippet, text and HTML bodies, calendar descriptions, attachment
 * names, forwarded messages) goes through the shared content scanner (C0).
 * The signals are merged and the C0 verdict rule decides once for the whole
 * message, with the sender-authentication rule added: a provider-reported
 * authentication failure together with text addressed to an AI agent.
 *
 * On the read path the detector fails closed: a message it could not fully
 * parse or scan (too large, nested too deep, a scanner bound) is withheld,
 * and the person can release it. On the mailbox path (moving mail the person
 * sees) those never move a message.
 *
 * Pure apart from hashing: no I/O.
 */
import { createHash } from "node:crypto";
import { decodeEntities } from "../content-html.js";
import { scanContent, verdictFor, workBudget, type QuarantineReason, type ScanResult, type Signal, type UnshownContext, type Verdict, type WorkBudget } from "../content-scan.js";
import { readAuth, senderNotes, type SenderNote } from "./auth.js";
import { asParsed, channels, fromStructured, headerText, headerValue, isParsed, looksLikeRawMessage, parseAddresses, parseMime, pieceMessage, toBytes, type Channel, type ChannelName, type MailMessage, type MailProblem } from "./mime.js";
import { own } from "../../own.js";

export type MailSignal = Signal | { id: "scan_failed"; reason: string };

/** Why a message is withheld: a C0 quarantine rule, or (read path only) a message that could not be fully read. */
export type MailReason = QuarantineReason | "scan_incomplete" | "scan_failed";

export interface ChannelResult {
  name: ChannelName;
  path: string;
  html: boolean;
  verdict: Verdict;
  /** The channel's text with hidden parts stripped (present when something was stripped). */
  neutralized?: string;
  /** The channel carries text addressed to an AI agent, an imperative in hidden text, or smuggled tag characters. */
  directed: boolean;
}

export interface MailScan {
  /** The Message-ID header, when there is one. */
  messageId: string;
  /** sha256 of the raw message (or of the structured object, canonically serialized). */
  sha256: string;
  size: number;
  /** As a person reads them (encoded words decoded). */
  from: string;
  subject: string;
  date: string;
  verdict: Verdict;
  reasons: MailReason[];
  signals: MailSignal[];
  auth: { fail: boolean | null; detail: string; arcPass: boolean };
  sender: SenderNote[];
  /** Up to 200 escaped characters of the hidden text (what the agent would have read). */
  hiddenPreview: string;
  strippedChars: number;
  problems: MailProblem[];
  /** The person released this exact message (`mail quarantine release`): delivered with neutralization only. */
  released: boolean;
  channels: ChannelResult[];
}

export interface MailScanOptions {
  /** Extra trusted Authentication-Results authserv-ids (`emailGuard.authservIds`). */
  authservIds?: readonly string[];
  /** The quarantine rules in effect (`emailGuard.quarantineOn`; default all five). */
  quarantineOn?: readonly QuarantineReason[];
  /** "read" (default): unreadable means withheld. "mailbox": unreadable never moves mail. */
  path?: "read" | "mailbox";
  /** sha256 values the person released. */
  released?: (sha256: string) => boolean;
  /** Per-channel scanner time budget (ms), and a clock for tests. */
  timeoutMs?: number;
  now?: () => number;
  /**
   * The message's work budget, shared by every part and channel (see WorkBudget); without one, the message
   * gets a fresh budget of `maxWork` units (default SCAN_LIMITS.maxWork). The mail filter's rewriting pass
   * has a budget of its own.
   */
  budget?: WorkBudget;
  maxWork?: number;
}

export type MailInput = string | Uint8Array | MailMessage | Record<string, unknown>;


/**
 * Canonical JSON (sorted keys), so the same structured message always hashes the same, and two messages that differ
 * anywhere, however deep, hash differently (a release names one exact message). Iterative, with no depth bound; an
 * object that contains itself is written as the string "[cycle]" at the point it recurs.
 */
export function canonicalJson(v: unknown): string {
  const out: string[] = [];
  const open = new Set<object>();
  // A task is a value to write, or a piece of text to emit, or an object whose writing is finished (`close`).
  type Task = { value: unknown } | { text: string } | { close: object };
  const stack: Task[] = [{ value: v }];
  while (stack.length > 0) {
    const t = stack.pop() as Task;
    if ("text" in t) {
      out.push(t.text);
      continue;
    }
    if ("close" in t) {
      open.delete(t.close);
      continue;
    }
    const x = t.value;
    if (typeof x !== "object" || x === null) {
      out.push(JSON.stringify(x) ?? "null");
      continue;
    }
    if (open.has(x)) {
      out.push('"[cycle]"');
      continue;
    }
    open.add(x);
    const tasks: Task[] = [];
    if (Array.isArray(x)) {
      tasks.push({ text: "[" });
      x.forEach((y, i) => {
        if (i > 0) tasks.push({ text: "," });
        tasks.push({ value: y });
      });
      tasks.push({ text: "]" });
    } else {
      tasks.push({ text: "{" });
      Object.keys(x)
        .sort()
        .forEach((k, i) => {
          tasks.push({ text: `${i > 0 ? "," : ""}${JSON.stringify(k)}:` });
          tasks.push({ value: own(x as Record<string, unknown>, k) });
        });
      tasks.push({ text: "}" });
    }
    tasks.push({ close: x });
    for (let i = tasks.length - 1; i >= 0; i--) stack.push(tasks[i] as Task);
  }
  return out.join("");
}

/** The message, its sha256 and size, from any accepted input. */
export function readMessage(input: MailInput): { msg: MailMessage; sha256: string; size: number } {
  const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
  if (typeof input === "string") {
    const bytes = toBytes(input);
    const msg = looksLikeRawMessage(input) ? parseMime(bytes) : pieceMessage(input);
    return { msg, sha256: sha(bytes), size: bytes.length };
  }
  if (input instanceof Uint8Array) return { msg: parseMime(input), sha256: sha(input), size: input.length };
  // Only a message the firewall built is taken as it is: any other object, whatever keys it has (one parsed from
  // JSON text in a subject can spell a MailMessage), is read by fromStructured, so its every string is read.
  if (isParsed(input)) {
    const s = toBytes(canonicalJson(input));
    return { msg: input, sha256: sha(s), size: s.length };
  }
  const s = toBytes(canonicalJson(input));
  let msg: MailMessage;
  try {
    msg = fromStructured(input);
  } catch (e) {
    // Nothing of the object was read: the scan fails (scan_failed), so it is withheld on the read path.
    msg = asParsed({ headers: [], text: [], html: [], calendar: [], attachments: [], nested: [], problems: [{ kind: "malformed", detail: `${OBJECT_FAILED}: ${(e as Error).message}`.slice(0, 200) }] });
  }
  return { msg, sha256: sha(s), size: s.length };
}

/** The detail of the problem a message object that could not be read at all has (a parser failure, like PARSER_FAILED). */
const OBJECT_FAILED = "the message object could not be read";
const PARSER_FAILED = "the parser failed";

/** A signal of text addressed to an AI agent, an imperative in hidden text, smuggled tag text or a hidden exfiltration link. */
export const isDirected = (s: Signal): boolean => s.id === "agent_directed" || s.id === "imperative" || (s.id === "tag_chars" && s.decoded.trim() !== "") || (s.id === "exfil_link" && s.hidden);
const DIRECTED = isDirected;

function key(s: MailSignal): string {
  return JSON.stringify(s);
}

/** Markup removed, with scripts, styles, titles and comments (whose text is judged on its own). Linear. */
function roughText(html: string): string {
  let out = "";
  let i = 0;
  while (i < html.length) {
    const lt = html.indexOf("<", i);
    if (lt === -1) {
      out += html.slice(i);
      break;
    }
    out += `${html.slice(i, lt)} `;
    if (html.startsWith("<!--", lt)) {
      const e = html.indexOf("-->", lt + 4);
      i = e === -1 ? html.length : e + 3;
      continue;
    }
    const raw = /^<(script|style|title|textarea)\b/i.exec(html.slice(lt, lt + 12));
    if (raw !== null) {
      const closeRe = new RegExp(`</${raw[1] as string}`, "gi");
      closeRe.lastIndex = lt;
      const close = closeRe.exec(html)?.index ?? -1;
      const gt = close === -1 ? -1 : html.indexOf(">", close);
      i = gt === -1 ? html.length : gt + 1;
      continue;
    }
    const gt = html.indexOf(">", lt);
    i = gt === -1 ? html.length : gt + 1;
  }
  return decodeEntities(out);
}

/**
 * The text of a message's displayed channels, for the echo test of text no client displays (an echo
 * counts only when it copies text that is in the message as text, not in an attribute or a script).
 */
function displayedText(chans: readonly Channel[]): string {
  const parts: string[] = [];
  let size = 0;
  for (const c of chans) {
    if (c.unshown === true) continue;
    const t = c.html ? roughText(c.text) : c.text;
    parts.push(t);
    size += t.length;
    if (size > 4 * 1024 * 1024) break;
  }
  return parts.join("\n");
}

/**
 * The problems of a message and of every message forwarded in it (iterative: the parser bounds how many there are).
 * A MailMessage handed in directly is taken as it is, so a field that is not a list is skipped, never iterated.
 */
function allProblems(msg: MailMessage): MailProblem[] {
  const out: MailProblem[] = [];
  const stack: unknown[] = [msg];
  const seen = new Set<unknown>();
  while (stack.length > 0) {
    const m = stack.pop();
    if (typeof m !== "object" || m === null || seen.has(m)) continue;
    seen.add(m);
    const { problems, nested } = m as Partial<MailMessage>;
    if (Array.isArray(problems)) for (const p of problems) if (typeof p === "object" && p !== null && typeof (p as MailProblem).kind === "string" && typeof (p as MailProblem).detail === "string") out.push(p);
    if (Array.isArray(nested)) for (const n of nested) stack.push(n);
  }
  return out;
}

/** Scans one message. Never throws. */
export function scanMail(input: MailInput, opts: MailScanOptions = {}): MailScan {
  const path = opts.path ?? "read";
  let read: ReturnType<typeof readMessage>;
  try {
    read = readMessage(input);
  } catch (e) {
    const failed: MailScan = {
      messageId: "", sha256: "", size: 0, from: "", subject: "", date: "", verdict: path === "read" ? "quarantine" : "deliver", reasons: path === "read" ? ["scan_failed"] : [],
      signals: [{ id: "scan_failed", reason: `the message could not be read: ${(e as Error).message}`.slice(0, 200) }], auth: { fail: null, detail: "not read", arcPass: false }, sender: [],
      hiddenPreview: "", strippedChars: 0, problems: [], released: false, channels: [],
    };
    return failed;
  }
  const { msg, sha256, size } = read;
  // One budget for the whole message: its parts share it, so a message of many parts costs no more than one large part.
  const budget = opts.budget ?? workBudget(opts.maxWork);
  const auth = readAuth(msg.headers, opts.authservIds ?? []);
  const sender = senderNotes(msg.headers);
  const signals: MailSignal[] = [];
  const seen = new Set<string>();
  const add = (s: MailSignal) => {
    const k = key(s);
    if (seen.has(k)) return;
    seen.add(k);
    signals.push(s);
  };
  // A parser that failed read nothing past where it failed (a MIME source, or the whole structured object).
  // A forwarded message's problems are the message's own: a part it could not read was not read.
  const problems = allProblems(msg);
  for (const p of problems) if (p.kind === "malformed" && (p.detail.startsWith(PARSER_FAILED) || p.detail.startsWith(OBJECT_FAILED))) add({ id: "scan_failed", reason: p.detail.slice(0, 200) });
  const previews: string[] = [];
  let stripped = 0;
  const results: ChannelResult[] = [];
  let chans: Channel[] = [];
  try {
    chans = channels(msg);
  } catch (e) {
    add({ id: "scan_failed", reason: `the message's parts could not be listed: ${(e as Error).message}`.slice(0, 200) });
  }
  // One echo context per message: its displayed text is built, charged and normalized once, however many
  // unshown channels (a header block per forwarded level) are compared with it.
  let displayed: UnshownContext | null = null;
  const subjects = chans.filter((c) => c.name === "subject").map((c) => c.text);
  for (const c of chans) {
    let r: ScanResult;
    try {
      const unshown = c.unshown === true ? (displayed ??= { visible: displayedText(chans) }) : undefined;
      r = scanContent(c.text, { html: c.html, subjects, budget, authFail: auth.fail === true, ...(unshown !== undefined ? { unshown } : {}), ...(opts.quarantineOn !== undefined ? { quarantineOn: opts.quarantineOn } : {}), ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}), ...(opts.now !== undefined ? { now: opts.now } : {}) });
    } catch (e) {
      add({ id: "scan_failed", reason: `the ${c.name} part could not be scanned: ${(e as Error).message}`.slice(0, 200) });
      continue;
    }
    for (const s of r.signals) add(s);
    if (r.hiddenPreview !== "") previews.push(r.hiddenPreview);
    stripped += r.strippedChars;
    results.push({ name: c.name, path: c.path, html: c.html, verdict: r.verdict, ...(r.neutralized !== undefined ? { neutralized: r.neutralized } : {}), directed: r.signals.some(DIRECTED) });
  }
  const c0Signals = signals.filter((s): s is Signal => s.id !== "scan_failed");
  const base = verdictFor(c0Signals, { authFail: auth.fail === true, ...(opts.quarantineOn !== undefined ? { quarantineOn: opts.quarantineOn } : {}) });
  let verdict: Verdict = base.verdict;
  const reasons: MailReason[] = [...base.reasons];
  // Read path: what was not fully read is withheld (fail closed). A charset problem is only noted.
  const unreadKinds = [...new Set(problems.filter((p) => p.kind === "too_large" || p.kind === "depth" || p.kind === "parts" || p.kind === "fields").map((p) => p.kind))];
  const incomplete = unreadKinds.length > 0 || c0Signals.some((s) => s.id === "scan_incomplete");
  const failed = signals.some((s) => s.id === "scan_failed");
  if (path === "read") {
    if (incomplete) reasons.push("scan_incomplete");
    if (failed) reasons.push("scan_failed");
    if (incomplete || failed) verdict = "quarantine";
  }
  // Every bound the parser met is said in a signal, on both paths: on the mailbox path a message not fully read is not
  // withheld, but it is rewritten (and noted) rather than passed on as it was (filter.ts).
  for (const kind of unreadKinds) add({ id: "scan_incomplete", reason: kind === "too_large" ? "max_message_bytes" : kind });
  const released = verdict === "quarantine" && opts.released?.(sha256) === true;
  const fromAddr = parseAddresses(headerValue(msg.headers, "from") ?? "")[0];
  const scan: MailScan = {
    messageId: (headerValue(msg.headers, "message-id") ?? "").slice(0, 300),
    sha256,
    size,
    from: fromAddr === undefined ? "" : (fromAddr.name !== "" ? `${fromAddr.name} <${fromAddr.address}>` : fromAddr.address).slice(0, 300),
    subject: headerText(msg.headers, "subject").slice(0, 300),
    date: (headerValue(msg.headers, "date") ?? "").slice(0, 100),
    verdict: released ? "neutralize" : verdict,
    reasons: released ? [] : reasons,
    signals,
    auth: { fail: auth.fail, detail: auth.detail, arcPass: auth.arcPass },
    sender,
    hiddenPreview: Array.from(previews.join(" ")).slice(0, 200).join(""),
    strippedChars: stripped,
    problems,
    released,
    channels: results,
  };
  return scan;
}

/** The signal names of a scan, once each (for records, stubs and logs). */
export function signalNames(scan: Pick<MailScan, "signals">): string[] {
  return [...new Set(scan.signals.map((s) => s.id))];
}

/** One line for a person: the rules that withheld it, or the verdict. */
export function scanSummary(scan: MailScan): string {
  if (scan.verdict === "quarantine") return `withheld (${scan.reasons.join(", ")})`;
  return scan.verdict;
}
