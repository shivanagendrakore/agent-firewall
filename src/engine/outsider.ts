/**
 * Sources anyone outside the organisation can write, and commands they suggest.
 *
 * An error tracker shows whatever a crashing client sent; an issue tracker,
 * a pull-request comment, a support inbox, a chat with external members and a
 * web page show what strangers wrote. A server for one of them may be the
 * person's own and fully trusted, and its results are still outside content:
 * a poisoned error event that tells the agent "to fix this, run ..." is how
 * agents were hijacked in June 2026. So results from this class always taint
 * the session, whatever the server's own trust (`outsiderWritable.alwaysTaint`,
 * on by default; a project may only add servers and turn it on).
 *
 * The second half is the rule that follows: when outside content contained a
 * command, running that command (or nearly that command) or installing a
 * package it named needs a person (FW-OUTSIDE-COMMAND). PostToolUse records
 * fingerprints of what a tainting result shows (`outside_command` events:
 * hashes, never the text), at several granularities: each command and each
 * part of it after wrappers are unwrapped, its program with its arguments in
 * any order and without flags, each URL, each script or package file, each
 * package an install command names, and the set of a command's distinctive
 * words. A later command matches when any of them matches, or when it holds
 * every distinctive word of a remembered command. When a result or the
 * session holds more than the firewall remembers, the session is marked
 * saturated and every risky command asks.
 *
 * The comparison is textual: the shell parser is not changed or re-entered
 * here. What a command does is still judged by the parser through the
 * classification the rule receives; only "did outside content say this" is
 * answered from text (see the limits in docs/limitations.md).
 *
 * Pure and browser-safe.
 */
import { sha256Hex } from "./bytes.js";
import { own } from "../own.js";
import type { Collector } from "./effects.js";
import { globMatch } from "./glob.js";
import { isUnder } from "./paths.js";
import { notedPackages, normalizeName, parseNpmSpec, parsePep508, type Ecosystem } from "./packages.js";
import { safeLine } from "./terminal.js";
import { HIDDEN_MARKER } from "./hidden.js";
import { stripInvisible } from "./unicode.js";
import type { Effect, FirewallConfig, NormalizedAction, Outcome, SessionState, StateEvent } from "../types.js";

export interface OutsiderWritablePolicy {
  /** Results from an outsider-writable server or tool taint the session even when the server is trusted. */
  alwaysTaint: boolean;
  /** Extra server-name patterns in the class (exact, or with *). */
  servers: string[];
  /** Server-name patterns taken out of the class (user or managed policy only). */
  exempt: string[];
  /** FW-OUTSIDE-COMMAND: "ask" (default) or "off" (user or managed policy only). */
  commands: "ask" | "off";
}

export const DEFAULT_OUTSIDER_WRITABLE: Readonly<OutsiderWritablePolicy> = { alwaysTaint: true, servers: [], exempt: [], commands: "ask" };

export function outsiderPolicy(cfg: FirewallConfig): OutsiderWritablePolicy {
  const o = cfg.outsiderWritable ?? {};
  return { ...DEFAULT_OUTSIDER_WRITABLE, ...o, servers: [...(o.servers ?? [])], exempt: [...(o.exempt ?? [])] };
}

// --- the class ----------------------------------------------------------------------------------

/**
 * Products whose content outsiders write, matched in a server name or a tool name (mcp__acme__get_sentry_issue):
 * error trackers, monitoring and log services, code forges and issue trackers, wikis and docs others edit,
 * support desks and CRMs, chat platforms, mail and calendars, web search, scraping and browser automation.
 */
const BRANDS = new Set([
  // Error tracking, monitoring, logs, analytics.
  "sentry", "datadog", "bugsnag", "rollbar", "honeybadger", "raygun", "airbrake", "newrelic", "appsignal", "logrocket", "loki", "papertrail", "logtail", "betterstack", "splunk", "cloudwatch", "pagerduty", "opsgenie", "highlight", "glitchtip", "axiom", "logz", "sumologic", "grafana", "posthog", "crashlytics",
  // Code forges, issue trackers, wikis and docs.
  "github", "gitlab", "bitbucket", "gitea", "forgejo", "codeberg", "jira", "atlassian", "confluence", "youtrack", "linear", "shortcut", "asana", "trello", "clickup", "notion", "stackoverflow",
  // Support desks, CRMs, messaging APIs.
  "intercom", "zendesk", "freshdesk", "helpscout", "hubspot", "salesforce", "crisp", "frontapp", "twilio",
  // Chat with people outside.
  "slack", "discord", "telegram", "whatsapp", "msteams", "reddit", "twitter", "mattermost", "rocketchat", "matrix",
  // Mail and calendars.
  "gmail", "outlook", "imap", "protonmail", "fastmail", "gcal", "googlecalendar",
  // The web.
  "firecrawl", "tavily", "perplexity", "brave", "browserbase", "puppeteer", "playwright", "exa", "serpapi", "searxng", "duckduckgo", "bing", "jina", "apify", "kagi",
]);

/** Generic words that name the class as a word of the server name, or of a tool name on a server the class does not cover otherwise. */
const SERVER_WORDS = new Set(["fetch", "browser", "web", "websearch", "mail", "email", "inbox", "logs", "issues", "tickets", "helpdesk", "support", "calendar", "comments", "errors", "crawl", "scrape"]);

/**
 * Servers that front many other services (Zapier, Composio, MCP proxies and toolboxes): what they return
 * is whatever the service behind them returns, so they are in the class unless exempted.
 */
const AGGREGATORS = new Set(["zapier", "composio", "toolbox", "mcpproxy", "pipedream", "n8n", "ifttt", "smithery", "metamcp", "rube", "toolhouse", "arcade"]);

/** Tool-name words too common to say the tool reads an outsider product (linear_regression, brave_mode, matrix_multiply). */
const NOT_IN_TOOLS = new Set(["linear", "brave", "highlight", "axiom", "shortcut", "exa", "bing", "crisp", "imap", "matrix", "notion", "make", "hub", "gateway"]);

/**
 * The words of a name, for matching: split at separators and at camelCase, with every adjacent pair joined
 * (GitHub -> git, hub, github; Page_Duty -> pageduty), and the whole name with separators removed (githubmcp
 * is matched by substring separately). A plugin prefix (plugin_slack_tools) keeps its plugin segment.
 */
function words(name: string): string[] {
  const parts = name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((w) => w !== "");
  const out = new Set(parts);
  for (let i = 0; i + 1 < parts.length; i++) out.add(`${parts[i] as string}${parts[i + 1] as string}`);
  for (let i = 0; i + 2 < parts.length; i++) out.add(`${parts[i] as string}${parts[i + 1] as string}${parts[i + 2] as string}`);
  out.add(name.toLowerCase().replace(/[^a-z0-9]/g, ""));
  return [...out];
}

/** Brands long and distinctive enough to find inside a name written without separators (githubmcp, mysentryserver). */
const SUBSTRING_BRANDS = [...BRANDS].filter((b) => b.length >= 5 && !NOT_IN_TOOLS.has(b));

const patternHit = (patterns: readonly string[], server: string): boolean => patterns.some((p) => (p.includes("*") ? globMatch(p, server, true) : p.toLowerCase() === server.toLowerCase()));

function brandIn(name: string, generic: ReadonlySet<string> | null, skip: ReadonlySet<string>): string | undefined {
  const ws = words(name);
  const hit = ws.find((w) => (BRANDS.has(w) && !skip.has(w)) || (generic !== null && generic.has(w)));
  if (hit !== undefined) return hit;
  const flat = name.toLowerCase().replace(/[^a-z0-9]/g, "");
  return SUBSTRING_BRANDS.find((b) => !skip.has(b) && flat.includes(b));
}

/** Why a server (and tool) is in the outsider-writable class, or null when it is not. */
export function outsiderWritable(server: string, cfg: FirewallConfig, tool?: string): string | null {
  const pol = outsiderPolicy(cfg);
  if (patternHit(pol.exempt, server)) return null;
  if (patternHit(pol.servers, server)) return `the policy lists ${server} as writable by outsiders`;
  const brand = brandIn(server, SERVER_WORDS, new Set());
  if (brand !== undefined) return `${brand} content can be written by people outside your organisation`;
  const agg = words(server).find((w) => AGGREGATORS.has(w)) ?? (/mcp-?proxy|toolbox/i.test(server) ? "proxy" : undefined);
  if (agg !== undefined) return `${server} passes on content from other services (${agg}), which people outside your organisation can write`;
  if (tool !== undefined) {
    // A product in the tool's name; a generic word too (list_errors, search_issues) on a server the policy does
    // not name (a server the person configured by name keeps its own tools' names).
    const named = Object.keys(cfg.mcpServers).some((k) => (k.includes("*") ? globMatch(k, server, true) : k === server));
    const tw = brandIn(tool, named ? null : SERVER_WORDS, NOT_IN_TOOLS);
    if (tw !== undefined) return `${tw} content can be written by people outside your organisation`;
  }
  return null;
}

/** Whether results from this server (and tool) must taint whatever the server's own trust says. */
export function forcedUntrusted(server: string, cfg: FirewallConfig, tool?: string): boolean {
  return outsiderPolicy(cfg).alwaysTaint && outsiderWritable(server, cfg, tool) !== null;
}

// --- commands in outside content ---------------------------------------------------------------

/**
 * The form both sides of FW-OUTSIDE-COMMAND are compared in: the gateway's ⟦hidden⟧ markers and invisible
 * characters (zero-width, bidi controls, tag characters) removed, then NFKC (fullwidth and compatibility
 * letters folded). A command hidden in outside content with a zero-width space, or shown with fullwidth
 * letters, matches the plain command the agent types, and the reverse. Bounded by the callers' own limits.
 */
export function outsideText(s: string): string {
  const unmarked = s.includes(HIDDEN_MARKER) ? s.split(HIDDEN_MARKER).join("") : s;
  return stripInvisible(unmarked).normalize("NFKC");
}

/** At most this many command parts are fingerprinted from one result, and this many fingerprints recorded. */
export const MAX_SUGGESTIONS_PER_RESULT = 64;
export const MAX_FINGERPRINTS_PER_RESULT = 512;
/** A session remembers at most this many fingerprints. Past either cap the session is saturated. */
export const MAX_SUGGESTIONS_PER_SESSION = 4096;
/** Outside content past this is not searched for commands (the session is saturated: every risky command asks). */
export const MAX_SUGGESTION_TEXT = 512 * 1024;
/** The hash a saturation event carries. */
export const SATURATED = "x:saturated";
const MAX_LINE = 4096;

/** Programs a suggested command starts with (after a prompt marker, sudo and variable assignments). */
const PROGRAMS = new Set(
  `curl wget bash sh zsh fish dash ksh python python2 python3 py node nodejs deno bun bunx npx pnpx npm pnpm yarn pip pip3 pipx uv uvx poetry pdm pipenv conda mamba
   cargo rustup go gem bundle bundler composer brew apt apt-get yum dnf apk pacman snap port choco winget scoop docker podman kubectl helm git gh glab make cmake just
   chmod chown rm mv cp ln tar unzip gunzip ssh scp rsync sftp nc ncat netcat socat telnet eval exec source perl ruby php java javac mvn gradle dotnet powershell pwsh iex
   osascript open xdg-open sudo doas env export base64 openssl dd mkfifo crontab launchctl systemctl service sed awk xargs find tee claude codex gemini cursor aws gcloud az
   terraform pulumi kill pkill killall echo printf cat sqlite3 psql mysql redis-cli mongosh firebase vercel netlify supabase wrangler heroku fly flyctl stripe nohup timeout
   invoke-webrequest invoke-expression iwr irm start-process`
    .split(/\s+/)
    .filter((x) => x !== ""),
);

const PROMPT = /^\s*(?:[$%#>❯➜]|PS [^>]{0,80}>|[\w.-]{1,40}@[\w.-]{1,60}[:~][^$#]{0,120}[$#])\s+/u;
/** Flags that change nothing about what runs. */
const QUIET = new Set(["-y", "--yes", "-q", "--quiet", "-s", "--silent", "--no-input", "--non-interactive", "-f", "-fssl", "-fsl", "-ssl", "-sl", "-l", "-sfl", "-k", "--insecure"]);
const SHELLS = new Set(["bash", "sh", "zsh", "dash", "ksh", "fish"]);
/** Script, archive and package files: a path ending so is remembered by its file name. */
const FILE_LIKE = /\.(?:sh|bash|zsh|py|js|mjs|cjs|ts|ps1|psm1|rb|pl|php|bat|cmd|command|tgz|tar\.gz|tar|whl|gem|crate|zip|deb|rpm|pkg|dmg|appimage|exe|msi|jar)$/;

/** Program names compared without their path or version (/usr/bin/curl, python3.12, pip3, nodejs). */
function programName(w: string): string {
  const base = w.replace(/^.*[/\\]/, "");
  if (/^python[\d.]*$/.test(base)) return "python";
  if (/^pip[\d.]*$/.test(base)) return "pip";
  if (base === "nodejs") return "node";
  return base;
}

/** Strips one wrapper from the front of a token list: sudo, env, nohup, time, timeout, command, exec, xargs, nice, a shell's -c. */
function unwrapOnce(t: string[]): string[] | null {
  const first = programName(t[0] ?? "");
  const skipFlags = (from: number): number => {
    let k = from;
    while (k < t.length && (t[k] as string).startsWith("-")) k++;
    return k;
  };
  if (/^[a-z_][a-z0-9_]*=/.test(t[0] ?? "")) return t.slice(1);
  if (first === "sudo" || first === "doas" || first === "nohup" || first === "time" || first === "command" || first === "exec" || first === "stdbuf" || first === "caffeinate") return t.slice(skipFlags(1));
  if (first === "env") {
    let k = skipFlags(1);
    while (k < t.length && /=/.test(t[k] as string)) k++;
    return t.slice(k);
  }
  if (first === "timeout") return t.slice(skipFlags(1) + 1);
  if (first === "nice") return t.slice(t[1] === "-n" ? 3 : skipFlags(1));
  if (first === "xargs") return t.slice(skipFlags(1));
  if (SHELLS.has(first) && t[1] === "-c") return t.slice(2);
  return null;
}

/** The tokens of one command part, canonical: no quotes, lower case, wrappers unwrapped, program by name, quiet flags dropped. */
function tokensOf(part: string): string[] {
  let t = part
    .replace(/["'`]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/[;&\s]+$/, "")
    .toLowerCase()
    .split(" ")
    .filter((x) => x !== "");
  for (let i = 0; i < 8 && t.length > 0; i++) {
    const next = unwrapOnce(t);
    if (next === null) break;
    t = next;
  }
  if (t.length === 0) return t;
  t[0] = programName(t[0] as string);
  return t.filter((x, i) => i === 0 || !QUIET.has(x));
}

/**
 * The comparable form of one command: prompt markers, wrappers (sudo, env, nohup, timeout, bash -c, ...),
 * quotes, quiet flags and spacing removed, lower case, the program by its name.
 */
export function canonicalCommand(raw: string): string {
  return tokensOf(raw.trim().replace(/^`+|`+$/g, "").replace(PROMPT, "")).join(" ");
}

/** Joins backslash line continuations. */
const joinContinuations = (s: string): string => s.replace(/\\\r?\n[ \t]*/g, " ");

/**
 * The parts of a command line: at newlines, sequence and pipe operators, background jobs, command
 * substitutions and backticks. Textual and quote-blind (the shell parser is not used here).
 */
function partsOf(line: string): string[] {
  return joinContinuations(line)
    .split(/\r?\n|&&|\|\||[;|&`]|\$\(|\)/)
    .map((x) => x.trim())
    .filter((x) => x !== "")
    .slice(0, 64);
}

const URLISH = /^(?:(?:git\+)?(?:https?|ftp|ssh|git):\/\/\S+|git@[\w.-]+:\S+|(?:github|gitlab|bitbucket):[\w.-]+\/[\w.-]+)$/;

/** A URL-like token, compared without its trailing slash or .git. */
const normalUrl = (u: string): string => u.replace(/[),.;]+$/, "").replace(/\/+$/, "").replace(/\.git$/, "");

/** Whether a token says something specific about what runs (a URL, a path, a versioned or long name). */
function distinctive(tok: string): boolean {
  if (tok.startsWith("-")) return false;
  if (URLISH.test(tok)) return true;
  if (/[/@:=]/.test(tok)) return tok.length >= 4;
  if (/\./.test(tok) && tok.length >= 4) return true;
  return tok.length >= 8 && /[a-z]/.test(tok);
}

const fp = (kind: string, s: string): string => `${kind}:${sha256Hex(s).slice(0, 32)}`;
const tokenHash = (s: string): string => sha256Hex(`t\u0000${s}`).slice(0, 16);

interface PartPrints {
  /** Fingerprints any of which matches. */
  keys: string[];
  /** Hashes of the distinctive tokens (all must appear in a later command). */
  tokens: string[];
}

/** Every fingerprint of one command part. */
function partPrints(part: string): PartPrints | null {
  const t = tokensOf(part.replace(PROMPT, ""));
  if (t.length === 0) return null;
  const program = t[0] as string;
  const args = t.slice(1);
  const keys: string[] = [fp("c", t.join(" "))];
  const nonFlag = args.filter((a) => !a.startsWith("-"));
  keys.push(fp("k", [program, ...[...nonFlag].sort()].join(" ")));
  if (nonFlag[0] !== undefined && distinctive(nonFlag[0])) keys.push(fp("a", `${program} ${nonFlag[0]}`));
  // URLs anywhere in the part, also in an assignment a wrapper or a variable carries (U=https://...; curl $U).
  for (const m of part.toLowerCase().matchAll(/(?:git\+)?(?:https?|ftp|ssh|git):\/\/[^\s"'`<>)]{3,2000}/g)) keys.push(fp("u", normalUrl(m[0])));
  for (const a of t) {
    if (URLISH.test(a)) keys.push(fp("u", normalUrl(a)));
    const file = a.replace(/^.*[/\\]/, "");
    if (FILE_LIKE.test(file) && !URLISH.test(a)) keys.push(fp("s", file));
  }
  const uniq = [...new Set(keys)];
  keys.length = 0;
  keys.push(...uniq);
  const tokens = [...new Set(t.filter((x, i) => (i > 0 || /[/.]/.test(x)) && distinctive(x)).map((x) => tokenHash(URLISH.test(x) ? normalUrl(x) : x)))].slice(0, 12);
  return { keys, tokens };
}

/** Whether a canonical text is shaped like a command worth remembering. */
function commandLike(canon: string): boolean {
  if (canon.length < 4 || canon.length > MAX_LINE) return false;
  const first = canon.split(" ")[0] ?? "";
  if (/^(?:\.{1,2}\/|\/|~\/)\S/.test(first)) return true;
  return PROGRAMS.has(programName(first)) && canon.includes(" ");
}

/** Program words common in English prose ("make sure", "find the", "open a ticket"): not searched for inside a sentence. */
const PROSE_WORDS = new Set(["make", "open", "find", "source", "kill", "env", "export", "echo", "printf", "cat", "service", "go", "port", "fly", "snap", "just", "dd", "tee", "sed", "awk", "gem", "bundle", "java", "stripe", "exec", "eval", "py", "sh", "apk", "heroku", "cursor", "time", "command"]);
const escapeRe = (w: string): string => w.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&");
/** A program word inside a sentence (after a space, a colon, a quote or an opening bracket). */
const IN_PROSE = new RegExp(`(?:^|[\\s:("'])((?:sudo\\s+)?(?:${[...PROGRAMS].filter((p) => !PROSE_WORDS.has(p)).map(escapeRe).join("|")}))(?=\\s)`, "g");
/** Where a command inside a sentence ends: a connecting word, a clause break, a sentence end. */
const CLAUSE_END = /\s+(?:and then|then|and|or|before|after)\s+|[,;]\s|\.(?:\s|$)|\s[-–—]\s/;
/** HTML elements that start a new piece of text; bounded so a stray "<p" without ">" costs little. */
const BLOCK_TAG = /<\/?(?:pre|code|p|li|br|div|td|th|tr|h[1-6]|kbd|samp|blockquote)\b[^<>]{0,200}>/gi;
const ANY_TAG = /<\/?[a-z][^<>]{0,200}>/gi;
const decodeEntities = (s: string): string => s.replace(/&(?:amp|lt|gt|quot|#39|#x27|nbsp);/g, (m) => ({ "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#39;": "'", "&#x27;": "'", "&nbsp;": " " })[m] ?? m);

/** How much a candidate looks like an attack worth remembering first: URLs, pipes into a shell, installs, privileges, scripts. */
function riskScore(s: string): number {
  let n = 0;
  if (/(?:https?|ftp):\/\/|git@/.test(s)) n += 3;
  if (/\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\biex\b|invoke-expression/i.test(s)) n += 4;
  if (/\b(?:install|add|i|dlx|exec|x)\b/.test(s) && /\b(?:npm|pnpm|yarn|bun|pip3?|uv|pipx|cargo|gem|go|brew|apt|npx|uvx|bunx)\b/.test(s)) n += 3;
  if (/\b(?:sudo|chmod|chown|crontab|launchctl|systemctl)\b/.test(s)) n += 2;
  if (FILE_LIKE.test(s.split(/\s+/).find((w) => FILE_LIKE.test(w)) ?? "")) n += 2;
  return n;
}

/**
 * Pieces of a text that may be commands, riskiest first. Code (inline spans, fenced blocks, prompt lines),
 * lines that start like a command, and a command written inside a sentence ("then run git clone ..."),
 * cut where the clause ends. `cut` says whether the text was longer than the search reaches.
 */
function candidates(input: string): { list: string[]; cut: boolean } {
  const cut = input.length > MAX_SUGGESTION_TEXT;
  const text = joinContinuations(cut ? input.slice(0, MAX_SUGGESTION_TEXT) : input);
  const found: { s: string; score: number }[] = [];
  const seen = new Set<string>();
  const add = (bonus: number, raw: string): void => {
    const t = raw.trim();
    if (t === "" || t.length > MAX_LINE || seen.has(t) || seen.size > 20_000) return;
    seen.add(t);
    found.push({ s: t, score: riskScore(t) + bonus });
  };
  for (const m of text.matchAll(/`([^`\n]{4,4096})`/g)) add(1, m[1] as string);
  let fenced = false;
  let lines = 0;
  for (const rawLine of text.split(/\r?\n/)) {
    if (++lines > 100_000) break;
    if (/^\s*(?:```|~~~)/.test(rawLine)) {
      fenced = !fenced;
      continue;
    }
    BLOCK_TAG.lastIndex = 0;
    for (const piece of rawLine.split(BLOCK_TAG)) {
      const raw = decodeEntities(piece.replace(ANY_TAG, " "));
      const line = raw.replace(/^\s*(?:[-*+]|\d+[.)])\s+/, "").trim();
      if (line === "") continue;
      if (fenced || PROMPT.test(raw)) add(1, line.replace(PROMPT, ""));
      else if (/^[a-z.~/]/.test(line)) add(0, line);
      let n = 0;
      IN_PROSE.lastIndex = 0;
      for (const m of line.slice(0, 8 * MAX_LINE).matchAll(IN_PROSE)) {
        if (++n > 8) break;
        const rest = line.slice(m.index + m[0].length - (m[1] as string).length);
        const end = CLAUSE_END.exec(rest);
        add(0, (end === null ? rest : rest.slice(0, end.index)).slice(0, MAX_LINE).replace(/[.:!?)"']+$/, ""));
      }
    }
  }
  found.sort((a, b) => b.score - a.score);
  return { list: found.map((f) => f.s), cut };
}

/** The fingerprint FW-OUTSIDE-COMMAND compares for a command (its canonical form, hashed). */
export const commandFingerprint = (command: string): string => fp("c", canonicalCommand(outsideText(command)));
/** The fingerprint for a package an install command names. */
export const packageFingerprint = (eco: Ecosystem, name: string): string => fp("p", `${eco}:${normalizeName(eco, name)}`);
/** The fingerprint for a URL a command uses. */
export const urlFingerprint = (url: string): string => fp("u", normalUrl(outsideText(url).toLowerCase()));

/** Package names an install or runner command in outside content names, as `${ecosystem}:${normalized name}`. */
export function suggestedPackages(canon: string): string[] {
  const toks = canon.split(" ");
  const prog = programName(toks[0] ?? "");
  const verb = toks[1] ?? "";
  const rest = (from: number): string[] => toks.slice(from).filter((t) => t !== "" && !t.startsWith("-"));
  const out: string[] = [];
  const add = (eco: Ecosystem, parsed: { name: string } | null): void => {
    if (parsed !== null && parsed.name !== "") out.push(`${eco}:${normalizeName(eco, parsed.name)}`);
  };
  if (["npm", "pnpm", "yarn", "bun"].includes(prog)) {
    if (["install", "i", "add", "in"].includes(verb)) for (const t of rest(2)) add("npm", parseNpmSpec(t));
    else if (["exec", "x", "dlx"].includes(verb)) add("npm", parseNpmSpec(rest(2)[0] ?? ""));
  } else if (["npx", "pnpx", "bunx"].includes(prog)) add("npm", parseNpmSpec(rest(1)[0] ?? ""));
  else if (prog === "pip" || (prog === "uv" && verb === "pip") || (prog === "python" && verb === "-m" && toks[2] === "pip")) {
    const at = toks.indexOf("install");
    if (at > 0 && !toks.includes("-r")) for (const t of rest(at + 1)) add("PyPI", parsePep508(t));
  } else if (prog === "uv" && verb === "add") for (const t of rest(2)) add("PyPI", parsePep508(t));
  else if (prog === "uvx" || (prog === "pipx" && (verb === "run" || verb === "install")) || (prog === "uv" && verb === "tool")) {
    const from = prog === "uvx" ? 1 : prog === "uv" ? 3 : 2;
    add("PyPI", parsePep508(rest(from)[0] ?? ""));
  } else if (prog === "cargo" && (verb === "install" || verb === "add")) for (const t of rest(2)) add("crates.io", { name: t.split("@")[0] ?? "" });
  else if (prog === "gem" && verb === "install") for (const t of rest(2)) add("RubyGems", { name: t });
  else if (prog === "go" && (verb === "install" || verb === "get")) for (const t of rest(2)) add("Go", { name: t.split("@")[0] ?? "" });
  return out.slice(0, 16);
}

/**
 * The `outside_command` events for a result that brought outside content in. Already known fingerprints are
 * skipped. When the result holds more than one result's share, or the session's memory is full, a
 * saturation event is added instead of dropping silently. Never throws (a failure saturates).
 */
export function suggestionEvents(input: string, source: string, known?: ReadonlyMap<string, string>, opts: { saturated?: boolean } = {}): StateEvent[] {
  const src = source.slice(0, 200);
  const out: StateEvent[] = [];
  let saturate = false;
  let text = input;
  try {
    // Only what the search reaches is normalised (NFKC on a huge text costs time for nothing past the bound).
    const over = text.length > MAX_SUGGESTION_TEXT;
    text = outsideText(over ? text.slice(0, MAX_SUGGESTION_TEXT) : text);
    const room = MAX_SUGGESTIONS_PER_SESSION - (known?.size ?? 0);
    const have = new Set<string>();
    let keys = 0;
    const push = (hash: string, tokens?: string[]): boolean => {
      if (have.has(hash) || known?.has(hash) === true) return true;
      if (keys >= MAX_FINGERPRINTS_PER_RESULT || keys >= room) return false;
      have.add(hash);
      keys++;
      out.push(tokens !== undefined && tokens.length > 0 ? { type: "outside_command", hash, source: src, tokens } : { type: "outside_command", hash, source: src });
      return true;
    };
    const { list, cut } = candidates(text);
    saturate = cut || over;
    let parts = 0;
    outer: for (const line of list) {
      const canonLine = canonicalCommand(line);
      for (const piece of [line, ...partsOf(line)]) {
        const canon = piece === line ? canonLine : canonicalCommand(piece);
        if (!commandLike(canon)) continue;
        if (++parts > MAX_SUGGESTIONS_PER_RESULT) {
          saturate = true;
          break outer;
        }
        const pp = partPrints(piece);
        if (pp === null) continue;
        let ok = true;
        for (const k of pp.keys) ok = push(k) && ok;
        if (pp.tokens.length > 0) ok = push(fp("t", [...pp.tokens].sort().join(",")), pp.tokens) && ok;
        for (const pkg of suggestedPackages(canon)) ok = push(fp("p", pkg)) && ok;
        if (!ok) {
          saturate = true;
          break outer;
        }
      }
    }
    // Every URL the content shows, not only those inside a command shape.
    for (const m of text.slice(0, MAX_SUGGESTION_TEXT).matchAll(/\b(?:https?|ftp):\/\/[^\s<>"'`)\]]{3,2000}/g)) {
      if (!push(urlFingerprint(m[0]))) {
        saturate = true;
        break;
      }
    }
  } catch {
    saturate = true;
  }
  if (saturate && opts.saturated !== true && known?.has(SATURATED) !== true) out.push({ type: "outside_command", hash: SATURATED, source: src });
  return out;
}

// --- the rule -----------------------------------------------------------------------------------

/**
 * Effects that make running an outsider's command risky. Reading, writing inside the workspace, running
 * the project's own code (guarded by FW-TAINTED-MANIFEST once outside content changed it) and fetching
 * without keeping a file are left to the other rules (see docs/limitations.md).
 */
function risky(e: Effect): boolean {
  if ((e.tags ?? []).includes("install") || e.download !== undefined) return true;
  switch (e.cls) {
    case "execute_untrusted":
    case "execute_opaque":
    case "privilege":
    case "destructive":
    case "write_persistence":
    case "write_protected":
    case "write_outside_workspace":
    case "egress_send":
    case "agent_spawn":
    case "firewall_tamper":
    case "unknown":
      return true;
    default:
      return false;
  }
}

export interface OutsideCommandHit {
  rule: "FW-OUTSIDE-COMMAND";
  outcome: Outcome;
  reason: string;
}

/** Shell-like tools whose input is a command line. */
const SHELL_TOOLS = new Set(["Bash", "Monitor", "PowerShell"]);

/** Argument names that carry a command line in an MCP or unknown tool (run_command's `command`, a CI tool's `script`). */
const COMMAND_ARGS = /^(?:command|commands|cmd|cmdline|command_?line|script|shell|shell_?command|run)$/i;
/** How many command arguments of one call are compared, and how deep its arguments are looked into. */
const MAX_COMMAND_ARGS = 16;
const MAX_ARG_DEPTH = 4;

/** Built-in agent tools whose arguments are not command lines (a file's content may well show a command). */
const KNOWN_NON_SHELL = new Set(["Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "NotebookRead", "Glob", "Grep", "LS", "WebFetch", "WebSearch", "TodoWrite", "Task", "Agent", "ToolSearch", "ExitPlanMode", "apply_patch", "read_file", "write_file", "replace", "glob", "search_file_content", "list_directory", "web_fetch", "google_web_search", "save_memory", "read_many_files"]);

/**
 * The command lines an action carries: a shell tool's command, else (an MCP tool, a tool the firewall does not
 * know) every string argument named like a command (command, cmd, script, ...), a few levels deep, and the
 * strings of an array under such a name joined as one line each. Built-in tools that are not shells carry none.
 */
function commandTexts(action: NormalizedAction): string[] {
  const input = action.input;
  if (SHELL_TOOLS.has(action.tool)) {
    const raw = typeof input.command === "string" ? input.command : typeof input.cmd === "string" ? input.cmd : null;
    return raw === null ? [] : [raw];
  }
  if (!action.tool.startsWith("mcp__") && KNOWN_NON_SHELL.has(action.tool)) return [];
  const out: string[] = [];
  let nodes = 0;
  const walk = (v: unknown, depth: number): void => {
    if (out.length >= MAX_COMMAND_ARGS || depth > MAX_ARG_DEPTH || typeof v !== "object" || v === null) return;
    for (const k of Object.keys(v)) {
      if (out.length >= MAX_COMMAND_ARGS || ++nodes > 2000) return;
      const x = own(v as Record<string, unknown>, k);
      if (COMMAND_ARGS.test(k)) {
        if (typeof x === "string" && x.trim() !== "") out.push(x);
        else if (Array.isArray(x) && x.length > 0 && x.every((y) => typeof y === "string")) out.push((x as string[]).join(" "));
        else walk(x, depth + 1);
      } else walk(x, depth + 1);
    }
  };
  walk(input, 0);
  return out;
}

const shown = (s: string): string => safeLine(s.length > 200 ? `${s.slice(0, 200)}...` : s);

/** FW-OUTSIDE-COMMAND for one classified action. */
export function outsideCommandRules(action: NormalizedAction, c: Collector, state: SessionState, cfg: FirewallConfig): OutsideCommandHit[] {
  const known = state.outsideCommands;
  if (known === undefined || known.size === 0 || outsiderPolicy(cfg).commands === "off") return [];
  // Running the project's own tools (npx vitest, a local binary) is not risky, whatever outside content said;
  // running a file from outside the workspace (a script in /tmp) is.
  const outsideRun = (e: Effect): boolean => e.cls === "execute" && e.target.startsWith("/") && !c.ctx.workspaceRoots.some((r) => isUnder(e.target, r, c.ctx.caseInsensitive));
  if (!c.effects.some((e) => risky(e) || outsideRun(e))) return [];
  const hits: OutsideCommandHit[] = [];
  const why = (src: string): string => ` It appears in content the session read from a source outsiders can write (${safeLine(src)}), so the instruction to run it may be someone else's. Check it before it runs.`;
  for (const raw of commandTexts(action)) {
    // Compared in the same form outside content was remembered in (outsideText): hidden characters removed, NFKC.
    const command = outsideText(raw.slice(0, 64 * 1024));
    const pieces = [command, ...partsOf(command)];
    const tokenSet = new Set<string>();
    let matched: { what: string; src: string } | null = null;
    for (const piece of pieces) {
      const pp = partPrints(piece);
      if (pp === null) continue;
      for (const t of pp.tokens) tokenSet.add(t);
      for (const k of pp.keys) {
        const src = known.get(k);
        if (src !== undefined && matched === null) matched = { what: k.startsWith("u:") ? "uses an address" : k.startsWith("s:") ? "runs or installs a file" : "runs a command", src };
      }
    }
    if (matched === null) {
      for (const [t, src] of state.outsideTokenSets ?? []) {
        if (t.length > 0 && t.every((x) => tokenSet.has(x))) {
          matched = { what: "runs a command with every specific word", src };
          break;
        }
      }
    }
    if (matched !== null) {
      const via = SHELL_TOOLS.has(action.tool) ? "" : ` (an argument of ${safeLine(action.tool.slice(0, 120))})`;
      hits.push({ rule: "FW-OUTSIDE-COMMAND", outcome: "approve", reason: `\`${shown(canonicalCommand(command))}\`${via} ${matched.what} that outside content showed.${why(matched.src)}` });
      break;
    }
  }
  for (const r of notedPackages(c).requests) {
    const src = known.get(fp("p", `${r.eco}:${normalizeName(r.eco, r.name)}`));
    if (src !== undefined) hits.push({ rule: "FW-OUTSIDE-COMMAND", outcome: "approve", reason: `${r.via} installs or runs the package ${safeLine(r.name)} (${r.eco}).${why(src)}` });
  }
  const saturated = known.get(SATURATED);
  if (hits.length === 0 && saturated !== undefined) {
    hits.push({ rule: "FW-OUTSIDE-COMMAND", outcome: "approve", reason: `this session read more commands from sources outsiders can write than the firewall remembers (${safeLine(saturated)}), so it cannot tell whether this one came from them; every risky command needs you.` });
  }
  return hits.slice(0, 4);
}
