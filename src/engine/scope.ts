/**
 * The task scope. The person's prompt says what the task is about
 * ("fix the failing test in `packages/web`", "open a PR against acme/api");
 * the scope records the paths, repositories, hosts and publish-type verbs it
 * named, and FW-SCOPE uses it to narrow what an untrusted or unattended
 * session may do without asking. The scope never loosens anything: an action
 * inside it is judged by the other rules exactly as before.
 *
 * Extraction is deliberately conservative, because everything it finds is
 * something the session may then do without FW-SCOPE asking: no fuzzy
 * matching, no model, nothing from pasted blocks (fenced code, quoted lines,
 * quoted strings), no verb that is negated, asked about, or not in the
 * position of a request. Pure: existence checks are injected.
 */

import type { Context, Effect, FirewallConfig, Outcome, SessionState } from "../types.js";
import { hostInList, hostMatches } from "./network.js";
import { isUnder, normalizeAbs } from "./paths.js";
import { destinationsFromPrompt } from "./post.js";

export const INTENTS = ["push", "pr", "publish", "deploy", "message", "delete", "install", "migrate"] as const;
export type Intent = (typeof INTENTS)[number];

export const SCOPE_MODES = ["off", "log", "enforce"] as const;
export type ScopeMode = (typeof SCOPE_MODES)[number];

export const WIDEN_KINDS = ["path", "repo", "host", "intent"] as const;
export type WidenKind = (typeof WIDEN_KINDS)[number];

/** The policy key `taskScope` (src/policy-scope.ts). */
export interface TaskScopePolicy {
  /** off: nothing is extracted or logged · log: compute and log what the scope would do, change no decision (default) · enforce. */
  mode: ScopeMode;
  /** Apply the intent rules (push, PR, publish, deploy, message, install) to unattended sessions even when trusted. */
  unattendedIntents: boolean;
}

export interface TaskScope {
  /** sha256 of the prompt text (the text itself is not stored). */
  prompt: string;
  at: string;
  /** Absolute; directories or files the prompt named that exist in the workspace (a named file adds its directory). */
  paths: string[];
  /** github:owner/repo, from the prompt. */
  repos: string[];
  /** Hosts the prompt named. */
  hosts: string[];
  /** Publish-type verbs the prompt used as a request. */
  intents: Intent[];
  /** True when paths or intents were found; false: the whole workspace, no intent limits. */
  narrowed: boolean;
}

/** A person's signed widening, as folded into the session state. */
export interface ScopeWidening {
  kind: string;
  value: string;
  id: string;
}

export interface ScopeWiden {
  kind: WidenKind;
  value: string;
}

export interface ScopeHit {
  rule: "FW-SCOPE";
  outcome: Outcome;
  reason: string;
  /** What `queue approve` offers to add to the scope for the rest of the session. */
  widen?: ScopeWiden;
}

/** What the scope did to one decision (logged; shown by `explain`). */
export interface ScopeEffect {
  mode: "log" | "enforce";
  /** The hits were part of the verdict (enforce). */
  applied: boolean;
  /** The verdict with the scope enforced. */
  verdict: "allow" | "ask" | "queue" | "deny";
  /** The verdict without the scope (the decision in log mode). */
  baseVerdict: "allow" | "ask" | "queue" | "deny";
  /** Enforcing changes the verdict. */
  changes: boolean;
  reasons: string[];
  widen: ScopeWiden[];
}

export const MAX_PROMPT_CHARS = 8000;
/** Existence checks per prompt (UserPromptSubmit latency budget). */
export const MAX_EXISTS_CHECKS = 50;
const MAX_LIST = 50;

export function defaultTaskScope(): TaskScopePolicy {
  return { mode: "log", unattendedIntents: true };
}

// --- prompt kinds ------------------------------------------------------------------------------------

const CONTINUATION = /^(?:y|yes|yep|yeah|yup|ok|okay|k|sure|go|go on|go ahead|continue|keep going|carry on|proceed|do it|please do|please continue|next|sounds good|looks good|lgtm|thanks|thank you|thx|great|perfect|right|correct|agreed|fine|done|retry|try again|again)[\s.!,]*$/i;
// F24: "Next.js ..." (a dot inside a word) and greetings ("Good morning") start a new task, not a follow-up.
const FOLLOW_UP = /^(?!good\s+(?:morning|afternoon|evening|night|day)\b)(?:yes|yep|yeah|ok|okay|sure|great|good|thanks|perfect|and|also|now|then|next|plus)\b(?:[\s,!:;-]|\.(?:\s|$))/i;

export type PromptKind = "continuation" | "followup" | "task";

/**
 * A slash command or a bare continuation ("yes", "go on") keeps the previous scope. A follow-up that
 * starts like one ("yes, and push", "also update the docs") keeps whatever it does not name itself and
 * adds the verbs it uses. Anything else is a new task and replaces the scope.
 */
export function promptKind(prompt: string): PromptKind {
  const p = prompt.trim();
  if (p === "" || /^\/[A-Za-z][\w:.-]*(?:\s|$)/.test(p) || CONTINUATION.test(p)) return "continuation";
  if (FOLLOW_UP.test(p)) return "followup";
  return "task";
}

// --- cleaning -----------------------------------------------------------------------------------------

/**
 * The text the person wrote themselves, as far as the shape shows: fenced code blocks and quoted lines
 * (pasted logs, issues, emails) are removed. Pasted text may be someone else's words.
 */
export function ownText(prompt: string): string {
  return prompt
    .slice(0, MAX_PROMPT_CHARS)
    .replace(/(?:^|\n)[ \t]*(```|~~~)[^\n]*\n[\s\S]*?(?:\n[ \t]*\1[^\n]*(?=\n|$)|$)/g, "\n")
    .split("\n")
    .filter((line) => !/^\s*>/.test(line))
    .join("\n");
}

/** Also without quoted strings: for verbs and destinations, a quote is someone else's words. */
function unquoted(text: string): string {
  return text.replace(/"[^"\n]*"|“[^”\n]*”|‘[^’\n]*’|(?<![\w])'[^'\n]{2,}'(?![\w])/g, " ");
}

// --- intents ------------------------------------------------------------------------------------------

/** Phrases that request an intent when they open a clause (after fillers like "please", "can you"). */
const PHRASES: { intent: Intent; re: RegExp }[] = [
  { intent: "pr", re: /^(?:open|create|make|raise|submit|file|put up|send)\s+(?:a\s+|an\s+|the\s+)?(?:draft\s+)?(?:pr|pull request|merge request|mr)\b/ },
  { intent: "push", re: /^(?:commit and push|push)\b/ },
  { intent: "publish", re: /^(?:publish|release|cut a release|tag and release)\b/ },
  { intent: "deploy", re: /^(?:deploy|ship)\b/ },
  { intent: "message", re: /^(?:send|post|email|message)\b/ },
  { intent: "delete", re: /^(?:delete|remove|drop|rm)\b/ },
  { intent: "install", re: /^(?:install|add (?:the|a|this|that|these) (?:dependency|dependencies|package|packages)|add (?:dependency|dependencies))\b/ },
  { intent: "migrate", re: /^(?:migrate|run (?:the )?migrations?)\b/ },
];

const FILLERS = /^(?:(?:please|pls|plz|kindly|also|then|and|now|finally|just|so|ok|okay|yes|sure|great|after that|afterwards|once done|when done|when you are done|when you're done|if (?:it|they|that|the tests?|everything) (?:passes|pass|works|is green|are green),?|can you|could you|would you|will you|go ahead and|feel free to|you can|you may|let's|lets|i want you to|i'd like you to|i need you to|make sure to|remember to|be sure to)\s+)+/;


/**
 * The word after a verb that shows it is used as a noun ("push notifications are broken", "the deploy
 * script fails", "send button"): then it is not a request.
 */
const NOUN_FOLLOW = /^(?:s|es|ed|ing|is|was|are|were|fails?|failed|failing|broke|breaks|broken|doesn't|does|did|has|had|seems|keeps|throws|errors?|crashes|notifications?|button|buttons|events?|services?|tokens?|subscriptions?|handler|handlers|hooks?|form|template|templates|fields?|function|functions|methods?|requests?|endpoints?|routes?|queue|body|component|validation|script|scripts|config|configuration|steps?|jobs?|pipelines?|keys?|logs?|notes?|branch|process|instructions|guide|docs|section|model|class|entity|date|target|time|status|count|size|path|url|flow|logic|code|module|page|screen|dialog|modal|api|apis|webhook|webhooks)\b/;

const QUESTION_LEADS = /^(?:should|shall|do|does|did|is|are|was|were|why|how|what|when|where|which|who|whether|have|has|am)\b/;

/** Exact command words in the prompt (`git push`, `npm publish`...), anywhere outside quotes and blocks. */
const COMMANDS: { intent: Intent; re: RegExp }[] = [
  { intent: "push", re: /\bgit\s+push\b/g },
  { intent: "pr", re: /\bgh\s+pr\s+create\b/g },
  { intent: "publish", re: /\b(?:(?:npm|pnpm|yarn|bun|cargo|gem|poetry|flit|hatch)\s+publish|twine\s+upload|gh\s+release\s+create)\b/g },
  { intent: "deploy", re: /\b(?:(?:vercel|netlify|fly|flyctl|firebase|wrangler|railway|serverless|sls)\s+deploy|vercel\s+--prod)\b/g },
  { intent: "install", re: /\b(?:(?:npm|pnpm|bun)\s+(?:install|i|add)\s+(?!-)[@a-z0-9]|yarn\s+add\s+(?!-)[@a-z0-9]|pip3?\s+install\s+(?!-r\b)(?!-)[a-z0-9]|uv\s+(?:add|pip install)\s+(?!-)[a-z0-9]|cargo\s+add\s+[a-z0-9]|go\s+get\s+[a-z0-9])/g },
];

/**
 * F22: a verb followed later in its clause by a verb that describes (is, fails, was rejected...) is the
 * subject of a description ("Release workflow fails", "Push to talk is broken", "git push was rejected"),
 * not a request. Only up to a subordinate clause ("deploy it once the build is green" still asks to deploy).
 */
const DESCRIBES = /\b(?:is|are|was|were|be|been|fails?|failed|failing|broke|breaks|broken|doesn't|does not|don't work|isn't|aren't|wasn't|weren't|errors?|errored|crash(?:es|ed)?|throws?|threw|hangs?|hung|times? out|timed out|keeps|stopped|stops|returns?|returned|rejected|refused|exits?|exited|says|said|shows?|showed|works?|worked|looks?|seems?|got|gets|has|have|had)\b/;
const SUBORDINATE = /\b(?:if|when|once|after|before|unless|until|so that|because|while|as soon as)\b/;

function describes(rest: string): boolean {
  const cut = rest.search(SUBORDINATE);
  return DESCRIBES.test(cut === -1 ? rest : rest.slice(0, cut));
}

/** Words that run a command when they open a clause ("run npm publish", "then do git push"). */
const RUN_VERB = /^(?:(?:then\s+)?(?:run|execute|do|invoke|type|call)\s+)?/;

function clauses(sentence: string): string[] {
  return sentence
    .split(/[,;:()]+|\s+(?:and then|and|then|but|also|plus)\s+/)
    .map((c) => c.trim())
    .filter((c) => c !== "");
}

/** The intents the person asked for. Lower-cased text, quotes and blocks already removed. */
export function intentsIn(text: string): Intent[] {
  const found = new Set<Intent>();
  // File names and paths are names, not verbs ("push.ts is broken"); their dots would also split sentences.
  const lower = text
    .toLowerCase()
    .replace(/[`*_]/g, " ")
    .replace(/(?<![\w-])(?:[\w@~.-]*\/[\w@~./-]*|[\w-]+(?:\.[\w-]+)*\.[a-z0-9]{1,10})(?![\w/-])/g, (m) => (/^(?:\.+|v?\d+(?:\.\d+)*)$/.test(m) ? m : " it "))
    .replace(/[ \t]+/g, " ");
  // Sentences keep their terminator so questions can be recognised.
  for (const m of lower.matchAll(/[^.!?\n]+[.!?]*/g)) {
    const sentence = m[0].trim();
    if (sentence === "") continue;
    const question = sentence.endsWith("?");
    const body = sentence.replace(/[.!?]+$/, "");
    if (question && QUESTION_LEADS.test(body)) continue;
    for (const clause of clauses(body)) {
      const rest = clause.replace(FILLERS, "");
      for (const p of PHRASES) {
        const m = p.re.exec(rest);
        if (m === null) continue;
        const after = rest.slice(m[0].length).trimStart();
        if (!NOUN_FOLLOW.test(after) && !describes(after)) found.add(p.intent);
      }
      // F22: a command word asks for its intent only as a request: opening its clause (after fillers and a
      // run verb), not inside a description ("the CI step that runs npm publish fails").
      const cmd = rest.replace(RUN_VERB, "");
      for (const c of COMMANDS) {
        const m = new RegExp(`^(?:${c.re.source})`).exec(cmd);
        if (m !== null && !describes(cmd.slice(m[0].length))) found.add(c.intent);
      }
    }
  }
  return INTENTS.filter((i) => found.has(i));
}

// --- paths --------------------------------------------------------------------------------------------

export type PathKind = "file" | "dir" | null;

/** Root files a prompt names without an extension ("update the README"); exact names only. */
const ROOT_DOCS = /^(?:readme|changelog|license|licence|contributing|security|code_of_conduct|makefile|dockerfile|gemfile|procfile|justfile|rakefile|brewfile)$/i;
const ROOT_DOC_EXTS = ["", ".md", ".markdown", ".rst", ".txt", ".adoc"];

function pathCandidates(text: string): { token: string; bare: boolean }[] {
  const out: { token: string; bare: boolean }[] = [];
  const seen = new Set<string>();
  const add = (raw: string, backticked: boolean): void => {
    // F26: Claude Code's file mention (@src/foo.ts) and a file:line reference (src/foo.ts:42:7) name the file.
    let t = raw.trim().replace(/^[([{<"'“‘]+/, "").replace(/^@(?=[\w./])/, "").replace(/[)\]}>"'”’,;:!?]+$/, "").replace(/\.+$/, "").replace(/:\d+(?::\d+)?$/, "").replace(/#L\d+(?:-L?\d+)?$/, "");
    if (t === "" || /\s/.test(t) || t.length > 300) return;
    if (/:\/\//.test(t) || t.startsWith("~") || t.startsWith("-") || t.startsWith("$")) return;
    // A glob names the directory before its first wildcard.
    const glob = t.search(/[*?[\]{}]/);
    const fromGlob = glob !== -1;
    if (fromGlob) {
      const prefix = t.slice(0, glob);
      t = prefix.includes("/") ? prefix.slice(0, prefix.lastIndexOf("/")) : "";
      if (t === "") return;
    }
    if (t === "." || t === ".." || t === "/" || t === "./") return;
    const looksLikePath = t.includes("/") || /\.[A-Za-z0-9]{1,10}$/.test(t) || backticked || fromGlob;
    const bare = !looksLikePath && ROOT_DOCS.test(t);
    if (!looksLikePath && !bare) return;
    if (seen.has(t)) return;
    seen.add(t);
    out.push({ token: t, bare });
  };
  for (const m of text.matchAll(/`([^`\n]{1,300})`/g)) add(m[1] as string, true);
  for (const w of text.replace(/`[^`\n]*`/g, " ").split(/\s+/)) add(w, false);
  return out;
}

export interface ScopeIO {
  /** "file", "dir" or null (missing). Called at most MAX_EXISTS_CHECKS times per prompt. */
  stat: (abs: string) => PathKind;
}

function inWorkspace(abs: string, ctx: Pick<Context, "workspaceRoots" | "caseInsensitive">): boolean {
  return ctx.workspaceRoots.some((r) => isUnder(abs, r, ctx.caseInsensitive));
}

function isRoot(abs: string, ctx: Pick<Context, "workspaceRoots" | "caseInsensitive">): boolean {
  const norm = (p: string): string => (ctx.caseInsensitive ? p.toLowerCase() : p).replace(/\/+$/, "");
  return ctx.workspaceRoots.some((r) => norm(r) === norm(abs));
}

function dirOf(abs: string): string {
  const i = abs.lastIndexOf("/");
  return i <= 0 ? "/" : abs.slice(0, i);
}

/** Workspace paths the prompt named. `whole` is true when it named a workspace root itself. */
export function pathsIn(text: string, ctx: Pick<Context, "cwd" | "workspaceRoots" | "caseInsensitive" | "realpath">, io: ScopeIO): { paths: string[]; whole: boolean; tokens: string[] } {
  const paths: string[] = [];
  const tokens: string[] = [];
  let whole = false;
  let budget = MAX_EXISTS_CHECKS;
  const stat = (abs: string): PathKind => {
    if (budget <= 0) return null;
    budget--;
    try {
      return io.stat(abs);
    } catch {
      return null;
    }
  };
  // F20: never more entries than the event validator accepts (a file adds its directory too).
  const add = (p: string): void => {
    if (!paths.includes(p) && paths.length < MAX_LIST) paths.push(p);
  };
  const bases = [...ctx.workspaceRoots, ...(inWorkspace(ctx.cwd, ctx) && !ctx.workspaceRoots.includes(ctx.cwd) ? [ctx.cwd] : [])];
  for (const { token, bare } of pathCandidates(text)) {
    if (budget <= 0 || paths.length >= MAX_LIST) break;
    const tries: string[] = [];
    if (bare) for (const r of ctx.workspaceRoots) for (const ext of ROOT_DOC_EXTS) tries.push(normalizeAbs(`${r}/${token}${ext}`));
    else if (token.startsWith("/")) tries.push(normalizeAbs(token));
    else for (const b of bases) tries.push(normalizeAbs(`${b}/${token}`));
    for (const t of tries) {
      if (!inWorkspace(t, ctx)) continue;
      const kind = stat(t);
      if (kind === null) continue;
      let abs = t;
      try {
        if (ctx.realpath !== undefined) abs = ctx.realpath(t);
      } catch {
        // SELF-016: an unresolvable path widens nothing.
        continue;
      }
      if (!inWorkspace(abs, ctx)) break;
      tokens.push(token);
      if (isRoot(abs, ctx)) whole = true;
      else if (kind === "dir") add(abs);
      else {
        add(abs);
        // Tests and snapshots next to a named file belong to the task; a file at the root adds only itself.
        if (!isRoot(dirOf(abs), ctx)) add(dirOf(abs));
      }
      break;
    }
  }
  return { paths, whole, tokens };
}

// --- extraction ---------------------------------------------------------------------------------------

export function scopeFromPrompt(prompt: string, promptHash: string, ctx: Pick<Context, "cwd" | "workspaceRoots" | "caseInsensitive" | "realpath">, io: ScopeIO, now: Date = new Date()): TaskScope {
  const own = ownText(prompt);
  const plain = unquoted(own);
  // F23: nothing from quoted strings, paths included (policy.md).
  const p = pathsIn(plain, ctx, io);
  const named = new Set(p.tokens.map((t) => t.toLowerCase().replace(/^\.\//, "").replace(/\/+$/, "")));
  const dests = destinationsFromPrompt(plain);
  // owner/repo that is really a workspace path ("fix web/app") is a path, not a repository.
  // F8: only values the event validator accepts are kept (an underscore or wildcard host is dropped, not stored
  // as a scope that would read back corrupt and make the session untrusted).
  const repos = dests.filter((d) => d.startsWith("github:") && !named.has(d.slice(7)) && REPO_OK(d)).slice(0, MAX_LIST);
  const hosts = dests.filter((d) => !d.includes(":") && HOST_OK(d)).slice(0, MAX_LIST);
  const intents = intentsIn(plain);
  const paths = (p.whole ? [] : p.paths).filter(PATH_OK).slice(0, MAX_LIST);
  return { prompt: promptHash, at: now.toISOString(), paths, repos, hosts, intents, narrowed: paths.length > 0 || intents.length > 0 };
}

/** The scope after a prompt: kept (continuation), merged (follow-up) or replaced (a new task). */
export function nextScope(previous: TaskScope | null, prompt: string, fresh: () => TaskScope): TaskScope | null {
  const kind = promptKind(prompt);
  if (kind === "continuation") return null;
  const next = fresh();
  if (kind === "task" || previous === null) return next;
  const pick = <T>(a: T[], b: T[]): T[] => (a.length > 0 ? a : b);
  const paths = pick(next.paths, previous.paths);
  const intents = INTENTS.filter((i) => next.intents.includes(i) || previous.intents.includes(i));
  return { ...next, paths, repos: pick(next.repos, previous.repos), hosts: pick(next.hosts, previous.hosts), intents, narrowed: paths.length > 0 || intents.length > 0 };
}

// --- validation (state events) -----------------------------------------------------------------------

const MAX_ITEM = 1000;
const ITEM_OK = (s: string): boolean => s.length > 0 && s.length <= MAX_ITEM;
const PATH_OK = (s: string): boolean => ITEM_OK(s) && s.startsWith("/");
const REPO_OK = (s: string): boolean => ITEM_OK(s) && /^github:[a-z0-9][a-z0-9-]*\/[a-z0-9._-]+$/.test(s);
const HOST_OK = (s: string): boolean => ITEM_OK(s) && /^[a-z0-9.-]+$/.test(s);

/** Validates a scope read from a session file; null when anything is off (the event becomes corrupt). */
export function parseTaskScope(raw: unknown): TaskScope | null {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  const list = (v: unknown, ok: (s: string) => boolean): string[] | null => (Array.isArray(v) && v.length <= MAX_LIST && v.every((x) => typeof x === "string" && ok(x)) ? (v as string[]) : null);
  if (typeof o.prompt !== "string" || !/^[0-9a-f]{64}$/.test(o.prompt)) return null;
  if (typeof o.at !== "string" || Number.isNaN(Date.parse(o.at))) return null;
  if (typeof o.narrowed !== "boolean") return null;
  const paths = list(o.paths, PATH_OK);
  const repos = list(o.repos, REPO_OK);
  const hosts = list(o.hosts, HOST_OK);
  const intents = list(o.intents, (s) => (INTENTS as readonly string[]).includes(s));
  if (paths === null || repos === null || hosts === null || intents === null) return null;
  if (o.narrowed !== (paths.length > 0 || intents.length > 0)) return null;
  return { prompt: o.prompt, at: o.at, paths, repos, hosts, intents: intents as Intent[], narrowed: o.narrowed };
}

/** Normalizes a widening value; null when it is not valid for its kind. Paths must already be absolute. */
export function normalizeWiden(kind: string, value: string): ScopeWiden | null {
  const v = value.trim();
  switch (kind) {
    case "path":
      return v.startsWith("/") && v.length <= MAX_ITEM ? { kind, value: normalizeAbs(v) } : null;
    case "repo": {
      const m = /^(?:github:|https?:\/\/github\.com\/)?([A-Za-z0-9][A-Za-z0-9-]{0,38})\/([A-Za-z0-9._-]{1,100}?)(?:\.git)?\/?$/.exec(v);
      return m === null ? null : { kind, value: `github:${(m[1] as string).toLowerCase()}/${(m[2] as string).toLowerCase()}` };
    }
    case "host": {
      const h = v.toLowerCase().replace(/\.$/, "");
      // F25: an IPv4 address is a host FW-SCOPE offers too (a single label such as localhost is still refused).
      return /^(?:[a-z0-9-]+\.)+[a-z]{2,63}$/.test(h) || (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(h) && h.split(".").every((x) => Number(x) <= 255) && !h.startsWith("127.") && !h.startsWith("0.")) ? { kind, value: h } : null;
    }
    case "intent":
      return (INTENTS as readonly string[]).includes(v) ? { kind, value: v } : null;
    default:
      return null;
  }
}

// --- the rule -----------------------------------------------------------------------------------------

const BUILD_DIRS = new Set(["dist", "build", "coverage", ".next", "target", "out", ".turbo", ".nuxt", ".svelte-kit", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache"]);
const LOCKFILES = new Set(["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock", "cargo.lock", "poetry.lock", "uv.lock", "pipfile.lock", "gemfile.lock", "composer.lock", "go.sum", "package.resolved", "podfile.lock", "flake.lock", "mix.lock", "pubspec.lock", "deno.lock"]);

/** Writes the scope never narrows: build outputs, lockfiles, caches. */
export function exemptWrite(abs: string, root: string): boolean {
  const rel = abs.slice(root.replace(/\/+$/, "").length + 1);
  const segs = rel.split("/");
  if (LOCKFILES.has((segs.at(-1) ?? "").toLowerCase())) return true;
  // "target" and "out" are ordinary source directory names too (a Rust crate's output is at the root, but
  // src/target/ or lib/out/ holds code): they are build output only as the first directory under the root.
  return segs.slice(0, -1).some((s, i) => BUILD_DIRS.has(s) && (i === 0 || (s !== "target" && s !== "out")));
}

/** The publish-type intent an outgoing send carries, or null for a plain send. */
export function sendIntent(e: Effect): Intent | null {
  const dest = (e.destination ?? e.target).toLowerCase();
  const detail = e.detail.toLowerCase();
  if ((e.tags ?? []).includes("message")) return "message";
  if (dest.startsWith("git-remote:") || detail.startsWith("push commits") || detail.includes("(git push)")) return "push";
  if (/^(?:github|gitlab|gh):/.test(dest)) {
    if (/\b(?:pr|mr)\b|pull request|pull_request|merge request/.test(detail)) return "pr";
    if (/\brelease\b/.test(detail)) return "publish";
    return null;
  }
  if (/pull request|pull_request/.test(detail)) return "pr";
  if (dest.endsWith(":registry") || /publish to a package registry/.test(detail)) return "publish";
  if (dest.startsWith("cloud:")) return "deploy";
  return null;
}

/** An install that only restores what the project already declares (npm ci, npm install, pip install -r). */
export function restoresOnly(e: Effect): boolean {
  const i = e.detail.indexOf(": download packages");
  if (i === -1 || !e.detail.startsWith(e.target)) return false;
  const rest = e.detail.slice(e.target.length, i).trim();
  if (rest === "") return true;
  const toks = rest.split(/\s+/);
  // The detail names only the first five packages: five or more names may hide others.
  if (toks.length >= 5) return false;
  return toks.every((t) => /^(?:\.|\/)/.test(t) || /\.(?:txt|toml|lock|cfg|in|json)$/i.test(t));
}

export function taskScopePolicy(cfg: FirewallConfig): TaskScopePolicy {
  // Absent only in a hand-built config (tests, older callers): the default then applies.
  return { ...defaultTaskScope(), ...((cfg as Partial<FirewallConfig>).taskScope ?? {}) };
}

function has(scope: TaskScope, widened: readonly ScopeWidening[], intent: Intent): boolean {
  const all = new Set<string>([...scope.intents, ...widened.filter((w) => w.kind === "intent").map((w) => w.value)]);
  // A pull request is impossible without pushing its branch.
  return all.has(intent) || (intent === "push" && all.has("pr"));
}

function named(scope: TaskScope): string {
  const parts: string[] = [];
  if (scope.paths.length > 0) parts.push(scope.paths.slice(0, 3).join(", ") + (scope.paths.length > 3 ? ", ..." : ""));
  if (scope.intents.length > 0) parts.push(`to ${scope.intents.join(", ")}`);
  return parts.length === 0 ? "nothing specific" : parts.join("; ");
}

/**
 * FW-SCOPE: the cases the task scope adds. Empty when the mode is off, when no prompt narrowed the
 * scope, or when the session is trusted and interactive (zero added friction for normal work).
 */
export function scopeHits(effects: readonly Effect[], state: SessionState, cfg: FirewallConfig, ctx: Context): ScopeHit[] {
  const pol = taskScopePolicy(cfg);
  const scope = state.scope;
  if (pol.mode === "off" || scope === null || !scope.narrowed) return [];
  const untrusted = state.tainted;
  const unattended = !ctx.interactive;
  if (!untrusted && !unattended) return [];
  const widened = state.scopeWidenings;
  const wPaths = widened.filter((w) => w.kind === "path").map((w) => w.value);
  const wRepos = widened.filter((w) => w.kind === "repo").map((w) => w.value);
  const wHosts = widened.filter((w) => w.kind === "host").map((w) => w.value);
  const task = `the task you gave named ${named(scope)}`;
  const hits: ScopeHit[] = [];
  const add = (h: Omit<ScopeHit, "rule">): void => {
    if (!hits.some((x) => x.reason === h.reason)) hits.push({ rule: "FW-SCOPE", ...h });
  };
  const ci = ctx.caseInsensitive;
  for (const e of effects) {
    switch (e.cls) {
      case "write_workspace":
      case "write_protected":
      case "write_persistence": {
        if (scope.paths.length === 0 || !e.target.startsWith("/")) break;
        const root = ctx.workspaceRoots.find((r) => isUnder(e.target, r, ci));
        if (root === undefined || ctx.scratchRoots.some((r) => isUnder(e.target, r, ci))) break;
        if ([...scope.paths, ...wPaths].some((p) => isUnder(e.target, p, ci)) || exemptWrite(e.target, root)) break;
        add({ outcome: "approve", reason: `${e.detail}: outside the task you gave (${task})`, widen: { kind: "path", value: dirOf(e.target) } });
        break;
      }
      case "egress_send": {
        const dest = (e.destination ?? e.host ?? e.target).toLowerCase();
        if (untrusted && !dest.startsWith("git-remote:") && dest !== "github:current-repo") {
          const hostOk = e.host !== undefined && (hostInList(e.host, cfg.sendAllowHosts) || [...scope.hosts, ...wHosts].some((h) => hostMatches(e.host as string, h)));
          const repoOk = [...scope.repos, ...wRepos].includes(dest);
          if (!hostOk && !repoOk) {
            // F25: only a widening `scope widen` accepts is offered.
            const widen: ScopeWiden | undefined = dest.startsWith("github:") ? (normalizeWiden("repo", dest) ?? undefined) : e.host !== undefined ? (normalizeWiden("host", e.host) ?? undefined) : undefined;
            add({ outcome: "approve", reason: `${e.detail}: a destination outside the task you gave (it named ${[...scope.repos, ...scope.hosts].slice(0, 3).join(", ") || "no destination"})`, ...(widen !== undefined ? { widen } : {}) });
          }
        }
        const intent = sendIntent(e);
        if (unattended && pol.unattendedIntents && intent !== null && !has(scope, widened, intent)) {
          add({ outcome: "approve", reason: `${e.detail}: the task you gave did not ask to ${intent === "pr" ? "open a pull request" : intent} (${task}), and no one is here to confirm it`, widen: { kind: "intent", value: intent } });
        }
        break;
      }
      case "destructive":
        if (!has(scope, widened, "delete")) add({ outcome: "approve", reason: `${e.detail}: the task you gave did not ask to delete anything (${task})`, widen: { kind: "intent", value: "delete" } });
        break;
      case "execute":
        if (unattended && pol.unattendedIntents && (e.tags ?? []).includes("install") && !restoresOnly(e) && !has(scope, widened, "install")) {
          add({ outcome: "approve", reason: `${e.detail}: the task you gave did not ask to install packages (${task}), and no one is here to confirm it`, widen: { kind: "intent", value: "install" } });
        }
        break;
      default:
        break;
    }
  }
  return hits;
}
