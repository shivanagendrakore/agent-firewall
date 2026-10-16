/**
 * The dashboard's screens, rendered on the server from the read-only views in data.ts. Pure: data in,
 * HTML out. Every value goes through the escaping `html` template (R6); links are built only from
 * validated identifiers (queue ids, log sequence numbers, session ids, filter values from a fixed list
 * or the log's own types) and URL-encoded.
 *
 * Layout follows LaunchSafe's product rules: a title, one line of facts, then content; one focal point
 * per screen; hairline rows rather than boxes; labels rather than sentences; the accent only on
 * something held or found. Paths are shown project-relative or ~-shortened, cut in the middle, with
 * the full path in a tooltip.
 */

import { describeSource, ruleSentence } from "../engine/summary.js";
import { ruleDoc } from "../rules.js";
import type { Check } from "../runtime/doctor.js";
import { safeId } from "../runtime/layout.js";
import type { LogEntry, VerifyResult } from "../runtime/log.js";
import { itemSummary, localTime, proposalDiff } from "../runtime/report.js";
import type { QueueItem, SessionSummary } from "../runtime/store.js";
import { VERSION } from "../version.js";
import type { GuardsView, IntegrityView, ItemView, LogView, Overview, QueueView, Result, SessionView, VaultSummary } from "./data.js";
import { sideBySide, type Row } from "./diff.js";
import { boundedValue, Html, html, longText } from "./html.js";
import { middle, shortenIn, shortPath, type PathContext } from "./paths.js";
import { own } from "../own.js";

export type Tab = "overview" | "queue" | "log" | "integrity" | "vault" | "guards";

export interface PageContext {
  /** "/<token>/": every link is under it. */
  base: string;
  now: Date;
  /** Pending queue items, for the tab's count (null when the queue could not be read). */
  held: number | null;
  /** How paths are shortened for lists. */
  paths: PathContext;
  /** Why stored values cannot be recognised on this page (the vault index is damaged or unreadable). */
  maskingUnavailable?: string;
}

const CLI = "launchsafe-firewall";
/** The store's queue id format (runtime/store.ts getQueueItem). */
const QUEUE_ID = /^[a-z0-9]{4,32}$/;
/** The longest pre block (a tool input, an explanation) a page shows. */
const MAX_BLOCK = 100_000;
const RAW = (s: string): Html => new Html(s);

// --- small parts ----------------------------------------------------------------------------------

function when(d: Date | string, now: Date): Html {
  const date = typeof d === "string" ? new Date(d) : d;
  if (Number.isNaN(date.getTime())) return html`${String(d)}`;
  return html`<time datetime="${date.toISOString()}" title="${date.toString()}">${localTime(date, now)}</time>`;
}

type DotKind = "ok" | "warn" | "fail" | "held" | "idle";

function dot(kind: DotKind, word: string): Html {
  return html`<span class="status ${kind}"><span class="dot" aria-hidden="true"></span>${word}</span>`;
}

function checkDot(status: Check["status"]): Html {
  return status === "ok" ? dot("ok", "OK") : status === "warn" ? dot("warn", "Warning") : dot("fail", "Failing");
}

function path(c: PageContext, p: string, max = 56): Html {
  return html`<span class="mono" title="${p}">${middle(shortPath(p, c.paths), max)}</span>`;
}

function text(c: PageContext, s: string): string {
  return shortenIn(s, c.paths);
}

function cmd(command: string, label: string): Html {
  return html`<div class="cmd"><code>${command}</code><button type="button" class="copy" data-copy="${command}" aria-label="Copy: ${label}">Copy</button></div>`;
}

function failed(what: string, error: string): Html {
  return html`<p class="error" role="alert">${what} could not be read: ${error}</p>`;
}

function empty(message: string): Html {
  return html`<p class="empty">${message}</p>`;
}

function header(title: Html | string, meta: Html | null, back: Html | null = null): Html {
  return html`<div class="ph">${back !== null ? html`<p class="back">${back}</p>` : null}<h1>${title}</h1>${meta !== null ? html`<p class="meta">${meta}</p>` : null}</div>`;
}

function facts(parts: readonly (Html | string | null | false)[]): Html {
  const shown = parts.filter((p): p is Html | string => p !== null && p !== false && p !== "");
  return html`${shown.map((p, i) => html`${i > 0 ? RAW('<span class="sep" aria-hidden="true">·</span>') : null}<span>${p}</span>`)}`;
}

/** A rule's title without the "after outside content" tail: a few words for a list. */
function shortWhy(rules: readonly string[], reasons: readonly string[]): string {
  for (const r of rules) {
    const t = ruleDoc(r)?.title;
    if (t !== undefined) return t.replace(/,? after (?:reading )?outside content$/, "").replace(/ \(strict mode\)$/, "");
  }
  return ruleSentence(rules, reasons);
}

/** A session id as people say it: the first 8 characters (Claude Code's ids are UUIDs). */
function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

export function layout(c: PageContext, tab: Tab | null, title: string, body: Html): string {
  const link = (t: Tab, href: string, label: string, extra: Html | null = null): Html => html`<a href="${c.base}${href}"${tab === t ? RAW(' aria-current="page"') : ""}>${label}${extra}</a>`;
  const count = c.held !== null && c.held > 0 ? html`<span class="count" aria-label="${c.held} held">${c.held}</span>` : null;
  return `<!doctype html>${html`<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>${title} | LaunchSafe Firewall</title><link rel="stylesheet" href="${c.base}assets/app.css"><script src="${c.base}assets/app.js" defer></script></head><body>
<a class="skip" href="#main">Skip to content</a>
<header class="top"><div class="bar"><a class="brand" href="${c.base}">LaunchSafe <span>Firewall</span></a>
<nav class="tabs" aria-label="Sections">${link("overview", "", "Overview")}${link("queue", "queue", "Queue", count)}${link("log", "log", "Log")}${link("integrity", "integrity", "Pins and decoys")}${link("vault", "vault", "Vault")}${link("guards", "guards", "Gateway and mail")}</nav>
<span class="ro">Read-only</span></div></header>
<main id="main">${c.maskingUnavailable !== undefined ? html`<p class="error" role="alert">Masking unavailable: the vault index could not be used (${text(c, c.maskingUnavailable)}), so a stored value on this page would not be hidden. Run ${CLI} doctor in your terminal.</p>` : null}${body}</main>
<footer class="foot">LaunchSafe Firewall ${VERSION} · local only · ${localTime(c.now, c.now)}</footer>
</body></html>`}`;
}

// --- overview -------------------------------------------------------------------------------------

function sessionStatus(s: SessionSummary): Html {
  if (s.canary === true) return dot("held", "Decoy touched");
  return s.trusted ? dot("ok", "Trusted") : dot("warn", "Untrusted");
}

function sessionReason(c: PageContext, s: SessionSummary): string {
  if (!s.trusted) return text(c, `read ${s.firstSource !== null ? describeSource(s.firstSource) : "outside content"}`);
  return "no outside content read";
}

function sessionList(c: PageContext, sessions: readonly SessionSummary[]): Html {
  return html`<ul class="rows" aria-label="Sessions">${sessions.map((s) => {
    const reason = sessionReason(c, s);
    return html`<li class="row session"><span class="c-status">${sessionStatus(s)}</span><a class="name mono" href="${c.base}sessions/${encodeURIComponent(s.id)}" title="${s.id}">${shortId(s.id)}</a><span class="c-grow trunc muted" title="${reason}">${reason}${s.unattended !== null ? html` <span class="tag">unattended</span>` : null}</span><span class="c-time muted">${when(s.lastActivity, c.now)}</span></li>`;
  })}</ul>`;
}

export function overviewPage(c: PageContext, o: Overview): string {
  const checks = o.checks.ok ? o.checks.value : [];
  const score = checks.find((x) => x.name === "protection score");
  const toImprove = checks.filter((x) => x.status !== "ok" && x.name !== "protection score").length;
  const sessions = o.sessions.ok ? o.sessions.value : [];
  const untrusted = sessions.filter((s) => !s.trusted).length;
  const held = o.held.ok ? o.held.value : null;
  const d = o.decisions.ok ? o.decisions.value : null;
  const installs = o.installs.ok ? o.installs.value : [];
  const installedMeta = !o.installs.ok ? "install record unreadable" : installs.length === 0 ? "Not installed" : [...new Set(installs.map((r) => `${agentName(r.agent ?? "claude")} (${r.scope})`))].join(", ");

  const unreadable = o.unreadable.ok ? o.unreadable.value.length : 0;
  let focus: Html;
  if (held === null) focus = html`<section class="focus" aria-label="Needs you">${failed("The queue", o.held.ok ? "" : o.held.error)}</section>`;
  // An unreadable queue file may be an action waiting for the person that no screen can show: it outranks the rest.
  else if (unreadable > 0) focus = html`<section class="focus" aria-label="Needs you"><p class="focus-title" role="alert"><span class="status fail"><span class="dot" aria-hidden="true"></span></span>${plural(unreadable, "queue file")} could not be read</p><p class="muted">${held > 0 ? `${plural(held, "action")} also held for you. ` : ""}An unreadable file may be an action waiting for you; check it with ${CLI} queue in your terminal.</p><a class="button" href="${c.base}queue">Open queue</a></section>`;
  else if (held > 0) focus = html`<section class="focus" aria-label="Needs you"><p class="focus-title"><span class="dot held" aria-hidden="true"></span>${plural(held, "action")} held for you</p><a class="button" href="${c.base}queue">Review queue</a></section>`;
  else focus = html`<section class="focus" aria-label="Needs you"><p class="focus-title">Nothing needs you</p><p class="muted">Risky actions the firewall holds will wait here.</p></section>`;

  const protection = !o.checks.ok
    ? html`<span class="muted">doctor could not run</span>`
    : score === undefined
      ? html`<span class="muted">not scored</span>`
      : html`<a href="${c.base}protection"><span class="num">${score.score ?? 0}</span>/100</a>${toImprove > 0 ? html`<span class="sep" aria-hidden="true">·</span><a href="${c.base}protection">${plural(toImprove, "thing")} to improve</a>` : null}`;
  const decisions = d === null ? html`<span class="muted">log unreadable</span>` : d.total === 0 ? html`<span class="muted">none yet</span>` : html`<a href="${c.base}log">${facts([d.deny > 0 ? `${d.deny} blocked` : null, d.queue > 0 ? `${d.queue} held` : null, d.ask > 0 ? `${d.ask} asked` : null, `${d.allow} allowed`])}</a>`;
  const logGlance = o.log.ok && o.log.value.ok && o.log.value.entries === 0 ? html`<span class="muted">no entries yet</span>` : html`<a href="${c.base}log">${logBadge(o.log)}</a>`;
  const glance = html`<dl class="glance">
<div><dt>Protection</dt><dd>${protection}</dd></div>
<div><dt>Last ${d?.total ?? 0} decisions</dt><dd>${decisions}</dd></div>
<div><dt>Log</dt><dd>${logGlance}</dd></div>
<div><dt>Unattended mode</dt><dd>${o.unattended.ok ? html`<span title="${o.unattended.value.why}">${o.unattended.value.on ? "On" : "Off"}</span>` : html`<span class="muted">unknown</span>`}</dd></div>
</dl>`;
  const sessionsBlock = !o.sessions.ok ? failed("Session state", o.sessions.error) : sessions.length === 0 ? empty("No sessions in the last 7 days.") : sessionList(c, sessions);
  const body = html`${header("Overview", o.homeExists ? facts([installedMeta, plural(sessions.length, "session") + " this week", untrusted > 0 ? `${untrusted} untrusted` : null]) : facts(["No firewall state yet", installedMeta]))}
${focus}${glance}
<section aria-labelledby="sessions-h"><h2 id="sessions-h">Sessions</h2>${sessionsBlock}</section>`;
  return layout(c, "overview", "Overview", body);
}

function agentName(id: string): string {
  return id === "claude" ? "Claude Code" : id === "codex" ? "Codex" : id === "gemini" ? "Gemini CLI" : id === "cursor" ? "Cursor" : id;
}

/** A pin's source as a person reads it: another agent's servers are pinned under that agent (`cursor-user`). */
function pinSource(source: string): string {
  const m = /^(codex|gemini|cursor)-(.+)$/.exec(source);
  return m === null ? source : `${agentName(m[1] as string)} · ${m[2] as string}`;
}

// --- protection -----------------------------------------------------------------------------------

export function protectionPage(c: PageContext, o: Overview): string {
  if (!o.checks.ok) return layout(c, "overview", "Protection", html`${header("Protection", null, html`<a href="${c.base}">Overview</a>`)}${failed("Doctor's checks", o.checks.error)}`);
  const all = o.checks.value;
  const score = all.find((x) => x.name === "protection score");
  const rank = (s: Check["status"]): number => (s === "fail" ? 0 : s === "warn" ? 1 : 2);
  const checks = all.filter((x) => x.name !== "protection score").sort((a, b) => rank(a.status) - rank(b.status));
  const toImprove = checks.filter((x) => x.status !== "ok").length;
  const installs = !o.installs.ok
    ? failed("The install record", o.installs.error)
    : o.installs.value.length === 0
      ? html`<p class="empty">Not installed in any agent's settings yet.</p>${cmd(`${CLI} install`, "install")}`
      : html`<ul class="rows" aria-label="Installed">${o.installs.value.map((r) => html`<li class="row"><span class="name">${agentName(r.agent ?? "claude")}</span><span class="c-tag muted">${r.scope}</span><span class="c-grow">${path(c, r.path)}</span><span class="c-time muted mono">${r.version}</span></li>`)}</ul>`;
  const rows = (list: readonly Check[], label: string): Html =>
    html`<ul class="rows checks" aria-label="${label}">${list.map((x) => html`<li><details><summary class="row"><span class="c-status">${checkDot(x.status)}</span><span class="name">${x.name}</span><span class="c-grow"></span><span class="c-time muted">${x.weight !== undefined ? `${x.points ?? 0}/${x.weight}` : ""}</span></summary><p class="detail">${text(c, x.detail)}</p></details></li>`)}</ul>`;
  const improve = checks.filter((x) => x.status !== "ok");
  const passing = checks.filter((x) => x.status === "ok");
  const list =
    checks.length === 0
      ? empty("Doctor returned no checks.")
      : html`${improve.length === 0 ? empty("Every check passes.") : rows(improve, "To improve")}${passing.length > 0 ? html`<details class="more"><summary>${plural(passing.length, "passing check")}</summary><div class="more-body">${rows(passing, "Passing checks")}</div></details>` : null}`;
  const body = html`${header("Protection", facts([score !== undefined ? html`<span class="num">${score.score ?? 0}</span>/100` : "not scored", toImprove > 0 ? `${toImprove} to improve` : "every check passes", o.checkedAt !== null ? html`checked ${when(o.checkedAt, c.now)}` : null]), html`<a href="${c.base}">Overview</a>`)}
<section aria-labelledby="checks-h"><h2 id="checks-h">To improve</h2>${list}<div class="after">${cmd(`${CLI} doctor`, "doctor")}</div></section>
<section aria-labelledby="installed-h"><h2 id="installed-h">Installed</h2>${installs}</section>`;
  return layout(c, "overview", "Protection", body);
}

// --- sessions -------------------------------------------------------------------------------------

function verdictWord(v: string): Html | string {
  return v === "queue" ? dot("held", "Held") : v === "deny" ? html`<span class="strong">Blocked</span>` : v === "ask" ? "Asked" : v === "allow" ? html`<span class="muted">Allowed</span>` : "";
}

function entryLine(e: LogEntry): { tool: string; what: string } {
  const ev = e.event;
  const s = (k: string): string => {
    const v = own(ev, k);
    return typeof v === "string" ? v : "";
  };
  if (ev.type === "decision") return { tool: s("tool"), what: s("what") };
  if (ev.type === "approval" || ev.type === "rejection") return { tool: "", what: `${ev.type} of queue item ${s("queue")}` };
  if (ev.type === "canary") return { tool: s("tool"), what: s("message") };
  if (ev.type === "mcp_pin") return { tool: "", what: `MCP pin ${s("change")} ${s("server")}`.trim() };
  if (ev.type === "scope_widen") return { tool: "", what: `scope widened: ${s("kind")} ${s("value")}`.trim() };
  if (ev.type === "spawned_prompt") return { tool: s("tool"), what: `proposed a session: ${s("preview")}` };
  return { tool: s("tool"), what: String(ev.type ?? "event").replace(/_/g, " ") };
}

function logTable(c: PageContext, entries: readonly LogEntry[], label: string): Html {
  return html`<div class="table"><table aria-label="${label}"><thead><tr><th class="n">#</th><th>When</th><th>Verdict</th><th class="hide-sm">Tool</th><th>What</th><th class="hide-sm">Rules</th></tr></thead><tbody>${entries.map((e) => {
    const { tool, what } = entryLine(e);
    // A command or summary line is shown as written: shortening a path inside it would change what it says ran.
    const short = what;
    const rules = Array.isArray(e.event.rules) ? (e.event.rules as unknown[]).map(String) : [];
    const verdict = typeof e.event.verdict === "string" ? verdictWord(e.event.verdict) : e.event.type === "canary" ? dot("held", "Decoy") : html`<span class="muted">${String(e.event.type ?? "").replace(/_/g, " ")}</span>`;
    return html`<tr><td class="n"><a href="${c.base}log/${e.seq}">${e.seq}</a></td><td class="nowrap muted">${when(e.ts, c.now)}</td><td class="nowrap">${verdict}</td><td class="mono nowrap hide-sm">${middle(tool, 24)}</td><td class="what"><span class="trunc" title="${short}">${short}</span></td><td class="mono muted nowrap hide-sm">${rules.join(" ")}</td></tr>`;
  })}</tbody></table></div>`;
}

export function sessionPage(c: PageContext, v: Result<SessionView | null>, id: string): string {
  const back = html`<a href="${c.base}">Overview</a>`;
  if (!v.ok) return layout(c, "overview", "Session", html`${header("Session", null, back)}${failed("Session state", v.error)}`);
  if (v.value === null) return layout(c, "overview", "Not found", html`${header(`No session ${middle(id, 24)}`, null, back)}`);
  const { summary: s, taintSources, decisions } = v.value;
  const body = html`${header(html`Session <span class="mono" title="${id}">${shortId(id)}</span>`, facts([s !== null ? sessionStatus(s) : null, s !== null ? html`last active ${when(s.lastActivity, c.now)}` : null, s?.unattended !== null && s?.unattended !== undefined ? "ran unattended" : null, s?.sensitive === true ? "read private data" : null]), back)}
<section aria-labelledby="why-h"><h2 id="why-h">What made it untrusted</h2>${taintSources.length === 0 ? empty("Nothing: no outside content was read.") : html`<ul class="rows" aria-label="Sources">${taintSources.map((t) => html`<li class="row"><span class="c-grow break">${text(c, describeSource(t))}</span></li>`)}</ul>`}</section>
<section aria-labelledby="dec-h"><h2 id="dec-h">Decisions</h2>${decisions.length === 0 ? empty("No logged decisions for this session.") : logTable(c, decisions, "Decisions in this session")}</section>`;
  return layout(c, "overview", "Session", body);
}

// --- queue ----------------------------------------------------------------------------------------

export function queuePage(c: PageContext, q: Result<QueueView>): string {
  if (!q.ok) return layout(c, "queue", "Queue", html`${header("Queue", null)}${failed("The queue", q.error)}`);
  const { pending, corrupt, total, page, pages } = q.value;
  const away = pending.length > 0 && pending.every((i) => i.unattended === true || i.kind === "proposal");
  const list =
    total === 0
      ? empty("Nothing is waiting for you.")
      : html`<ul class="rows" aria-label="Held actions">${pending.map((it) => {
          const what = itemSummary(it);
          return html`<li class="row item"><span class="dot held" aria-hidden="true"></span><a class="name trunc" href="${c.base}queue/${encodeURIComponent(it.id)}" title="${what}">${what}</a><span class="c-grow trunc muted">${shortWhy(it.rules, it.reasons)}</span><span class="c-time muted">${when(it.createdAt, c.now)}</span><a class="c-act" href="${c.base}queue/${encodeURIComponent(it.id)}" aria-label="Review ${what}">Review</a></li>`;
        })}</ul>`;
  const body = html`${header("Queue", total === 0 ? null : facts([`${total} held`, pages > 1 ? `page ${page} of ${pages}` : null, away ? "while you were away" : null]))}
${list}
${pages > 1 ? html`<p class="pager">${page > 1 ? html`<a href="${c.base}${page === 2 ? "queue" : `queue?page=${page - 1}`}">Earlier items</a>` : null}${page > 1 && page < pages ? RAW(" · ") : null}${page < pages ? html`<a href="${c.base}queue?page=${page + 1}">Later items</a>` : null}</p>` : null}
${total > 0 ? html`<div class="after">${cmd(`${CLI} queue review`, "review all")}<p class="hint">Review all in your terminal; it asks for your passphrase once.</p></div>` : null}
${corrupt.length > 0 ? html`<p class="error">Unreadable queue files: ${corrupt.join(", ")}</p>` : null}`;
  return layout(c, "queue", "Queue", body);
}

/** The most diff rows a queue item page shows; the rest are left to `queue show` in the terminal. */
export const MAX_DIFF_ROWS = 500;

function diffTable(it: QueueItem, current: string | null, id: string): Html {
  const all = sideBySide(proposalDiff(it, current));
  if (all.length === 0) return empty("The proposal has no text change.");
  const rows = all.slice(0, MAX_DIFF_ROWS);
  const more = all.length - rows.length;
  const rest = more > 0 ? html`<p class="hint">+${more} more lines not shown here.${QUEUE_ID.test(id) ? " See the whole change in your terminal:" : ""}</p>${QUEUE_ID.test(id) ? cmd(`${CLI} queue show ${shellWord(id)}`, "show the whole change") : null}` : null;
  return html`${diffRows(rows)}${rest}`;
}

function diffRows(rows: readonly Row[]): Html {
  const side = (s: { n: number; text: string } | null, cls: string, mark: string): Html =>
    s === null ? html`<td class="ln gap"></td><td class="mark gap"></td><td class="gap"></td>` : html`<td class="ln">${s.n}</td><td class="mark ${cls}">${mark}</td><td class="${cls}">${s.text}</td>`;
  return html`<div class="diff"><table aria-label="Proposed change, side by side"><colgroup><col class="c-ln"><col class="c-mark"><col><col class="c-ln"><col class="c-mark"><col></colgroup><thead><tr><th colspan="3">Now</th><th colspan="3">After approval</th></tr></thead><tbody>${rows.map((r) => {
    const changed = r.kind !== "same";
    return html`<tr>${side(r.left, changed ? "del" : "", changed ? "-" : "")}${side(r.right, changed ? "add" : "", changed ? "+" : "")}</tr>`;
  })}</tbody></table></div><div class="diff diff-unified"><table aria-label="Proposed change, unified"><colgroup><col class="c-ln"><col class="c-mark"><col></colgroup><tbody>${rows.flatMap((r) => {
    if (r.kind === "same") return [html`<tr><td class="ln">${r.right?.n ?? ""}</td><td class="mark"></td><td>${r.right?.text ?? ""}</td></tr>`];
    const out: Html[] = [];
    if (r.left !== null) out.push(html`<tr><td class="ln">${r.left.n}</td><td class="mark del">-</td><td class="del">${r.left.text}</td></tr>`);
    if (r.right !== null) out.push(html`<tr><td class="ln">${r.right.n}</td><td class="mark add">+</td><td class="add">${r.right.text}</td></tr>`);
    return out;
  })}</tbody></table></div>`;
}

export function itemPage(c: PageContext, v: Result<ItemView | null>, id: string): string {
  const back = html`<a href="${c.base}queue">Queue</a>`;
  if (!v.ok) return layout(c, "queue", "Queue item", html`${header("Queue item", null, back)}${failed("The queue item", v.error)}`);
  if (v.value === null) return layout(c, "queue", "Not found", html`${header(`No queue item ${id}`, html`It may have been decided and pruned.`, back)}`);
  const { item: it, current, currentNote } = v.value;
  const pending = it.status === "pending";
  const pr = it.proposal;
  const title = itemSummary(it);
  // The commands name the queue file the store loaded (its name is checked against the store's id format),
  // never the file's own id field, and quote it as one shell word (DB1).
  const idOk = QUEUE_ID.test(id);
  const commands = pending && !idOk
    ? html`<p class="error" role="alert">This item's id is not in the store's id format, so no command is shown for it.</p>`
    : pending
    ? html`${it.id !== id ? html`<p class="error" role="alert">The file's own id field does not match its name; the commands below use the file's name.</p>` : null}<div class="cmds">${cmd(`${CLI} queue approve ${shellWord(id)}`, "approve")}${cmd(`${CLI} queue reject ${shellWord(id)}`, "reject")}${cmd(`${CLI} queue show ${shellWord(id)}`, "details")}</div><p class="hint">Run these in your terminal. Approving asks for your passphrase there; this page never does.</p>`
    : html`<p class="meta">${it.status === "approved" ? "Approved" : "Rejected"}${it.decidedAt !== undefined ? html` ${when(it.decidedAt, c.now)}` : null}.</p>`;
  const change =
    pr !== undefined
      ? html`<section aria-labelledby="change-h"><h2 id="change-h">Proposed change <span class="h-meta">${path(c, pr.target, 64)}</span></h2>${currentNote !== null ? html`<p class="hint">${currentNote}</p>` : null}${diffTable(it, current, id)}</section>`
      : html`<section aria-labelledby="input-h"><h2 id="input-h">Input <span class="h-meta">credentials masked</span></h2><pre class="block">${longText(JSON.stringify(boundedValue(it.input), null, 2), MAX_BLOCK)}</pre></section>`;
  const why = html`<details class="more"><summary>Why it was held</summary><div class="more-body">
<h3>Rules</h3><ul class="plain">${it.rules.map((r) => {
    const d = ruleDoc(r);
    return html`<li><span class="mono">${r}</span>${d !== null ? html`<span class="muted"> · ${d.sentence}</span>` : null}</li>`;
  })}</ul>
${(it.trustSources ?? []).length > 0 ? html`<h3>What made the session untrusted</h3><ul class="plain">${(it.trustSources ?? []).map((s) => html`<li class="break">${describeSource(s)}</li>`)}</ul>` : null}
<h3>Every reason</h3><ul class="plain">${it.reasons.map((r) => html`<li class="break">${r}</li>`)}</ul></div></details>`;
  const body = html`${header(html`${pending ? html`<span class="dot held" aria-hidden="true"></span>` : null}${title}`, facts([it.kind === "proposal" ? "Proposed change" : "Needs approval", it.tool, when(it.createdAt, c.now), it.unattended === true ? "while you were away" : null]), back)}
<p class="why">${ruleSentence(it.rules, it.reasons)}</p>
${commands}
${change}
${why}`;
  return layout(c, "queue", `Queue item ${it.id}`, body);
}

// --- log ------------------------------------------------------------------------------------------

const VERDICTS: readonly [string, string][] = [["queue", "Held"], ["deny", "Blocked"], ["ask", "Asked"], ["allow", "Allowed"]];

/**
 * `log verify`'s answer as a badge. Decided by its `ok` alone: a log that was deleted or emptied, or whose
 * key is damaged, has no entries and still does not verify, and that must show as loudly as an edit.
 */
function logBadge(verify: Result<VerifyResult>): Html | null {
  if (!verify.ok) return dot("fail", "Check failed");
  if (!verify.value.ok) return dot("fail", "Does not verify");
  return verify.value.entries === 0 ? null : dot("ok", "Verified");
}

export function logPage(c: PageContext, v: Result<LogView>, verify: Result<VerifyResult>, f: { type?: string; verdict?: string }): string {
  const verified = logBadge(verify);
  const problems = !verify.ok
    ? failed("The log check", verify.error)
    : !verify.value.ok
      ? html`<div class="error" role="alert"><p>The log does not verify: entries were changed, removed or reordered, or the log or its key was damaged or deleted.</p>${verify.value.problems.length > 0 ? html`<ul class="plain">${verify.value.problems.slice(0, 20).map((p) => html`<li>${p}</li>`)}</ul>${verify.value.problems.length > 20 ? html`<p class="hint">+${verify.value.problems.length - 20} more problems. Run ${CLI} log verify in your terminal for all of them.</p>` : null}` : null}</div>`
      : null;
  if (!v.ok) return layout(c, "log", "Decision log", html`${header("Decision log", verified)}${problems}${failed("The decision log", v.error)}`);
  const q = (o: { type?: string | undefined; verdict?: string | undefined; before?: number | undefined }): string => {
    const p = new URLSearchParams();
    if (o.type !== undefined) p.set("type", o.type);
    if (o.verdict !== undefined) p.set("verdict", o.verdict);
    if (o.before !== undefined) p.set("before", String(o.before));
    const s = p.toString();
    return s === "" ? "log" : `log?${s}`;
  };
  const seg = (label: string, href: string, on: boolean): Html => html`<a href="${c.base}${href}"${on ? RAW(' aria-current="true"') : ""}>${label}</a>`;
  const filters = html`<nav class="seg" aria-label="Filter the log">${seg("All", q({}), f.type === undefined && f.verdict === undefined)}${VERDICTS.map(([x, label]) => seg(label, q({ type: "decision", verdict: x }), f.verdict === x))}${v.value.types.filter((t) => t !== "decision").map((t) => seg(t === "canary" ? "Decoys" : t.replace(/_/g, " ").replace(/^./, (ch) => ch.toUpperCase()), q({ type: t }), f.type === t && f.verdict === undefined))}</nav>`;
  const table = v.value.entries.length === 0 ? empty(f.type !== undefined || f.verdict !== undefined ? "No entries match this filter." : "The log is empty.") : logTable(c, v.value.entries, "Decision log");
  const total = verify.ok ? verify.value.entries : null;
  const body = html`${header("Decision log", facts([total !== null ? plural(total, "entry", "entries") : null, verified]))}
${problems}${v.value.types.length > 0 ? filters : null}${table}
${v.value.older !== null ? html`<p class="pager"><a href="${c.base}${q({ type: f.type, verdict: f.verdict, before: v.value.older })}">Older entries</a></p>` : null}`;
  return layout(c, "log", "Decision log", body);
}

export function logEntryPage(c: PageContext, e: Result<LogEntry | null>, explained: string | null, seq: number): string {
  const back = html`<a href="${c.base}log">Decision log</a>`;
  if (!e.ok) return layout(c, "log", "Log entry", html`${header(`Entry ${seq}`, null, back)}${failed("The decision log", e.error)}`);
  if (e.value === null) return layout(c, "log", "Not found", html`${header(`No log entry ${seq}`, null, back)}`);
  const ev = e.value.event;
  const queue = typeof ev.queue === "string" && /^[a-z0-9]{4,32}$/.test(ev.queue) ? ev.queue : null;
  // The session page is named by the id the session's file carries: an id with other characters is shown by its hash.
  const session = typeof ev.session === "string" && ev.session !== "" ? safeId(ev.session) : null;
  const verdict = typeof ev.verdict === "string" ? verdictWord(ev.verdict) : null;
  const body = html`${header(`Entry ${seq}`, facts([verdict, String(ev.type ?? "event").replace(/_/g, " "), when(e.value.ts, c.now), queue !== null ? html`<a href="${c.base}queue/${encodeURIComponent(queue)}">queue item ${queue}</a>` : null, session !== null ? html`<a href="${c.base}sessions/${encodeURIComponent(session)}">session ${shortId(session)}</a>` : null]), back)}
<pre class="block">${longText(explained ?? "No explanation is available for this entry.", MAX_BLOCK)}</pre>
<div class="after">${cmd(`${CLI} explain ${seq}`, "explain")}</div>
<details class="more"><summary>Signed entry</summary><div class="more-body"><pre class="block">${longText(JSON.stringify(boundedValue(e.value), null, 2), MAX_BLOCK)}</pre></div></details>`;
  return layout(c, "log", `Log entry ${seq}`, body);
}

// --- MCP pins and decoys --------------------------------------------------------------------------

export function integrityPage(c: PageContext, v: IntegrityView): string {
  const file = v.pins.ok ? v.pins.value : null;
  const servers = file === null ? [] : Object.values(file.servers).sort((a, b) => (a.key < b.key ? -1 : 1));
  const changes = file?.pending ?? [];
  const decoys = v.canaries.ok ? v.canaries.value : [];
  let pins: Html;
  if (!v.pins.ok) pins = failed("The MCP pins", v.pins.error);
  else if (v.pinsUnreadable) pins = html`<p class="error" role="alert">The pins file is unreadable. The next session moves it aside and pins every server again.</p>`;
  else
    pins =
      servers.length === 0
        ? empty("No MCP server is pinned yet.")
        : html`<div class="table"><table aria-label="Pinned servers"><thead><tr><th>Server</th><th>Source</th><th class="hide-sm">Launch</th><th class="num">Tools</th><th class="hide-sm">Pinned</th></tr></thead><tbody>${servers.map((s) => html`<tr><td class="mono strong">${middle(s.name, 32)}</td><td>${s.file !== undefined ? html`<span title="${s.file}">${pinSource(s.source)}</span>` : pinSource(s.source)}</td><td class="hide-sm muted">${s.launch.pin.replace(/_/g, " ")}</td><td class="num">${s.tools.length}</td><td class="nowrap muted hide-sm">${when(s.pinnedAt, c.now)} · ${s.pinnedBy === "person" ? "you" : "first use"}</td></tr>`)}</tbody></table></div>`;
  const pending =
    changes.length === 0
      ? null
      : html`<section aria-labelledby="pending-h"><h2 id="pending-h"><span class="dot held" aria-hidden="true"></span>Waiting for review</h2>
<ul class="rows" aria-label="Pin changes">${changes.map((x) => html`<li class="row"><span class="name mono">${middle(x.name, 28)}</span><span class="c-tag muted">${x.kind.replace(/_/g, " ")}${x.tool !== undefined ? html` · <span class="mono" title="${x.tool}">${middle(x.tool, 24)}</span>` : null}</span><span class="c-grow trunc muted" title="${redactLaunch(x.detail)}">${redactLaunch(x.detail)}</span><span class="c-time muted">${when(x.lastSeen, c.now)}</span></li>`)}</ul>
<div class="after">${[...new Set(changes.map((x) => x.name))].map((n) => cmd(`${CLI} pins accept ${shellWord(n)}`, `accept ${n}`))}<p class="hint">Check the change first. Accepting asks for your passphrase in your terminal.</p></div></section>`;
  const decoyTable = !v.canaries.ok
    ? failed("The decoy registry", v.canaries.error)
    : decoys.length === 0
      ? html`${empty("No decoys are planted.")}${cmd(`${CLI} canary plant`, "plant decoys")}`
      : html`<div class="table"><table aria-label="Decoys"><thead><tr><th>Kind</th><th>File</th><th>Status</th><th class="hide-sm">Planted</th></tr></thead><tbody>${decoys.map((x) => html`<tr><td>${x.kind}</td><td class="what">${path(c, x.path, 48)}</td><td class="nowrap">${x.present ? dot("ok", "Present") : dot("warn", "Missing")}</td><td class="nowrap muted hide-sm">${when(x.plantedAt, c.now)}</td></tr>`)}</tbody></table></div>`;
  const tripped = v.canarySessions.ok ? v.canarySessions.value : [];
  const alerts = !v.canarySessions.ok
    ? failed("Session state", v.canarySessions.error)
    : tripped.length === 0
      ? empty("No session has touched a decoy in the last 30 days.")
      : html`<ul class="rows" aria-label="Sessions that touched a decoy">${tripped.map((s) => html`<li class="row session"><span class="c-status">${dot("held", "Decoy touched")}</span><a class="name mono" href="${c.base}sessions/${encodeURIComponent(s.id)}" title="${s.id}">${shortId(s.id)}</a><span class="c-grow"></span><span class="c-time muted">${when(s.lastActivity, c.now)}</span></li>`)}</ul>`;
  const body = html`${header("Pins and decoys", facts([plural(servers.length, "MCP server"), changes.length > 0 ? `${changes.length} waiting for review` : null, plural(decoys.length, "decoy")]))}
${pending}
<section aria-labelledby="servers-h"><h2 id="servers-h">Pinned MCP servers</h2>${pins}</section>
<section aria-labelledby="decoys-h"><h2 id="decoys-h">Decoys</h2>${decoyTable}</section>
<section aria-labelledby="alerts-h"><h2 id="alerts-h">Decoy alerts</h2>${alerts}</section>`;
  return layout(c, "integrity", "Pins and decoys", body);
}

// --- the vault ------------------------------------------------------------------------------------

/** The vault: names, kinds, fields, stores and where each value may go. Values and fingerprints never reach this page. */
export function vaultPage(c: PageContext, v: Result<VaultSummary>): string {
  if (!v.ok) return layout(c, "vault", "Vault", html`${header("Vault", null)}${failed("The vault index", v.error)}${cmd(`${CLI} doctor`, "doctor")}`);
  const { state, rows } = v.value;
  const unbound = rows.filter((r) => r.rules.length === 0).length;
  const warning = state === "unsigned" ? html`<div class="error" role="alert"><p>The vault index does not verify${v.value.problem !== undefined ? html` (${v.value.problem})` : null}. No secret is bound to any destination until this is resolved; stored values are still blocked everywhere.</p></div>${cmd(`${CLI} doctor`, "doctor")}` : null;
  const list =
    rows.length === 0
      ? html`${empty("The vault is empty.")}${cmd(`${CLI} vault add <name>`, "add a secret")}<p class="hint">Run it in your own terminal; it asks for each value with echo off and for your passphrase.</p>`
      : html`<div class="table"><table aria-label="Stored secrets"><thead><tr><th>Reference</th><th>Kind</th><th class="hide-sm">Fields</th><th>May go to</th><th class="hide-sm">Store</th><th class="hide-sm">Added</th></tr></thead><tbody>${rows.map(
          (r) =>
            html`<tr><td class="mono strong">${r.ref}</td><td>${r.kind.replace(/_/g, " ")}</td><td class="mono muted hide-sm">${r.fields.join(", ")}</td><td>${r.rules.length === 0 ? html`<span class="muted">nowhere yet</span>` : html`<ul class="plain">${r.rules.map((x) => html`<li class="mono">${x}</li>`)}</ul>`}</td><td class="muted hide-sm">${r.backend}${r.backend === "keychain" ? ` · confirm ${r.confirm}` : ""}</td><td class="nowrap muted hide-sm">${when(r.rotatedAt ?? r.createdAt, c.now)}${r.rotatedAt !== undefined ? " · rotated" : ""}</td></tr>`,
        )}</tbody></table></div>`;
  const body = html`${header("Vault", facts([plural(rows.length, "secret"), unbound > 0 ? `${unbound} bound to nothing` : null, state === "unsigned" ? dot("fail", "Does not verify") : rows.length > 0 ? dot("ok", "Signed") : null]))}
${warning}
<section aria-labelledby="secrets-h"><h2 id="secrets-h">Stored secrets <span class="h-meta">values are never shown</span></h2>${list}</section>
${rows.length > 0 ? html`<div class="after">${cmd(`${CLI} vault allow <name> --host <host>`, "bind a secret")}<p class="hint">An agent writes a reference such as vault://&lt;name&gt; where the value would go. A stored value sent anywhere it is not bound to is blocked (FW-VAULT-EGRESS). Changes happen in your terminal with your passphrase.</p></div>` : null}`;
  return layout(c, "vault", "Vault", body);
}

// --- v0.3: the MCP gateway, the quarantine, phones and run -----------------------------------------

/**
 * What the v0.3 guards are doing. The quarantine shows names, senders, subjects and signals only: the
 * withheld text (and its escaped preview) is never put on a page; a person reads it in their own terminal.
 */
export function guardsPage(c: PageContext, g: GuardsView, checks: Result<Check[]>): string {
  const wrapped = !g.wrapped.ok
    ? failed("The gateway's install record", g.wrapped.error)
    : g.wrapped.value.length === 0
      ? html`${empty("No MCP server is behind the gateway.")}${cmd(`${CLI} mcp wrap-config --client <client>`, "wrap a client's servers")}`
      : html`<ul class="rows" aria-label="Wrapped MCP servers">${g.wrapped.value.map((w) => html`<li class="row"><span class="name mono">${w.server}</span><span class="c-tag muted">${w.client}</span><span class="c-grow muted">${w.mode} mode · ${w.upstream}</span></li>`)}</ul>`;
  const q = g.quarantine;
  const held = q.ok ? q.value.rows.filter((r) => r.status === "held") : [];
  const quarantine = !q.ok
    ? failed("The quarantine store", q.error)
    : q.value.rows.length === 0
      ? empty("Nothing has been withheld.")
      : html`<div class="table"><table aria-label="Withheld items"><thead><tr><th>Withheld</th><th>From</th><th class="hide-sm">Why</th><th>Status</th><th class="hide-sm">When</th></tr></thead><tbody>${q.value.rows.map(
          (r) =>
            html`<tr><td>${r.kind === "email" ? html`<span class="strong">${r.subject ?? "(no subject)"}</span>` : html`<span class="mono">${r.tool ?? "an MCP result"}</span>`}<div class="muted mono">${r.id}</div></td><td>${r.kind === "email" ? (r.from ?? "") : (r.server ?? "")}${r.client !== undefined ? html`<div class="muted">${r.client}</div>` : null}</td><td class="mono muted hide-sm">${r.signals.join(", ")}</td><td>${r.status === "held" ? dot("held", "Held") : r.status}</td><td class="nowrap muted hide-sm">${when(r.createdAt, c.now)}</td></tr>`,
        )}</tbody></table></div>${q.value.corrupt > 0 ? html`<p class="error">${plural(q.value.corrupt, "unreadable record")}</p>` : null}`;
  const p = g.phones;
  const phones = !p.ok
    ? failed("The paired phones", p.error)
    : p.value.labels.length === 0
      ? html`${empty("No phone is paired.")}${cmd(`${CLI} phone pair`, "pair a phone")}`
      : html`<ul class="rows" aria-label="Paired phones">${p.value.labels.map((x) => html`<li class="row"><span class="name">${x.label}</span><span class="c-grow"></span><span class="c-time muted">paired ${when(x.pairedAt, c.now)}</span></li>`)}</ul>${p.value.relay !== null ? html`<p class="hint">${text(c, p.value.relay)}</p>` : null}`;
  const runCheck = checks.ok ? checks.value.find((x) => x.name === "run mode") : undefined;
  const run = runCheck === undefined ? empty("Not checked yet: doctor reports whether run can sandbox agents here.") : html`<p>${checkDot(runCheck.status)} ${text(c, runCheck.detail)}</p>`;
  const body = html`${header("Gateway and mail", facts([g.wrapped.ok ? plural(g.wrapped.value.length, "wrapped server") : null, held.length > 0 ? `${held.length} withheld, waiting for you` : "nothing waiting"]))}
<section aria-labelledby="gw-h"><h2 id="gw-h">MCP gateway</h2>${wrapped}</section>
<section aria-labelledby="q-h"><h2 id="q-h">Withheld <span class="h-meta">withheld text is never shown here</span></h2>${quarantine}${held.length > 0 ? html`<div class="after">${cmd(`${CLI} mail quarantine`, "review mail")}${cmd(`${CLI} gateway quarantine`, "review MCP results")}<p class="hint">Read and release withheld items in your own terminal.</p></div>` : null}</section>
<section aria-labelledby="ph-h"><h2 id="ph-h">Phone approvals</h2>${phones}</section>
<section aria-labelledby="run-h"><h2 id="run-h">Run mode</h2>${run}</section>`;
  return layout(c, "guards", "Gateway and mail", body);
}

/**
 * A server name as one shell word for the copied command (names are agent-configured text). A name with
 * any character outside printable ASCII is written as `$'...'` with \uXXXX escapes, so a look-alike letter
 * (a Cyrillic "о" in "nоtes") is visible in the command the person copies instead of passing for another name.
 */
export function shellWord(s: string): string {
  if (/^[A-Za-z0-9_.:@/-]+$/.test(s)) return s;
  if (/^[\x20-\x7e]*$/.test(s)) return `'${s.replace(/'/g, "'\\''")}'`;
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0) as number;
    if (cp >= 0x20 && cp <= 0x7e) out += ch === "\\" || ch === "'" ? `\\${ch}` : ch;
    else out += cp <= 0xffff ? `\\u${cp.toString(16).padStart(4, "0")}` : `\\U${cp.toString(16).padStart(8, "0")}`;
  }
  return `$'${out}'`;
}

/**
 * A launch line as the dashboard shows it: the value after a --token, --key, --secret or --password style
 * argument, and every URL's query string and user info, are replaced, so a credential in an MCP server's
 * configuration does not reach the page.
 */
export function redactLaunch(s: string): string {
  return s
    .replace(/(--?[A-Za-z0-9_-]*?(?:token|key|secret|password|passwd|pat|auth|credentials?)s?)(=|\s+)(?!-)("[^"]*"|'[^']*'|[^\s"']+)/gi, "$1$2[redacted]")
    .replace(/\b([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^\s/@?#]*@/g, "$1[redacted]@")
    .replace(/\b([A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s?#]*)\?[^\s#]*/g, "$1?[redacted]");
}

// --- errors ---------------------------------------------------------------------------------------

export function plainPage(title: string, message: string): string {
  return `<!doctype html>${html`<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title></head><body><h1>${title}</h1><p>${message}</p></body></html>`}`;
}
