/**
 * The shell half of the vault's hook rewrite (the hook rewrite).
 * Pure: it finds each `vault://` reference in a command, decides from the
 * quoting around it whether it can be replaced by an environment variable
 * without changing what the shell does, and builds the rewritten command.
 *
 * A reference in plain words becomes `"${__LSV_1}"`; inside double quotes
 * `${__LSV_1}`. A reference inside single quotes, `$'...'`, backticks, a
 * command or parameter substitution, or a command with a here-document cannot
 * be rewritten safely (the shell would not expand the variable, or the word is
 * computed): the caller denies it (FW-VAULT-UNSUPPORTED) with the
 * `run --env` hint. The value itself never appears here: only variable names.
 *
 * V1: the values never enter the agent's shell. Each references-carrying
 * simple command must be curl or wget, written out (no variables or
 * substitutions in it, every option on the allowlist in vault-options.ts),
 * and becomes its own ticketed run (`parts`): only that one process gets the
 * values in its environment, while pipes, lists and redirections around it run
 * in the agent's shell on its filtered output. A command that names the
 * substitution variables (`__LSV_`) is refused as a read of the secret.
 */

import { allErrors, parseShell, type Script, type SimpleCommand } from "./shell/parse.js";
import { checkSenderArgs, SAFE_ASSIGN, type Sender, type SenderUrl } from "./vault-options.js";
import { findRefs, type VaultRef } from "./vault-ref.js";
import { own } from "../own.js";

type Kind = "plain" | "dq" | "sq" | "ansi" | "nested" | "comment";
type Frame = "dq" | "sub" | "bt" | "param";

/** The quoting context of every character of a command (a conservative scanner; it never runs anything). */
export function quoteContexts(cmd: string): { kinds: Kind[]; heredoc: boolean } {
  const n = cmd.length;
  const kinds: Kind[] = new Array<Kind>(n).fill("plain");
  const stack: Frame[] = [];
  let heredoc = false;
  let i = 0;
  const nested = (): boolean => stack.some((f) => f !== "dq");
  const mark = (from: number, to: number, k: Kind): void => {
    for (let j = from; j < Math.min(to, n); j++) kinds[j] = k;
  };
  while (i < n) {
    const c = cmd[i];
    const top = stack[stack.length - 1];
    if (top === "dq") {
      const here: Kind = nested() ? "nested" : "dq";
      if (c === "\\") {
        mark(i, i + 2, here);
        i += 2;
      } else if (c === '"') {
        kinds[i] = here;
        stack.pop();
        i++;
      } else if (c === "`") {
        kinds[i] = "nested";
        stack.push("bt");
        i++;
      } else if (c === "$" && (cmd[i + 1] === "(" || cmd[i + 1] === "{")) {
        mark(i, i + 2, "nested");
        stack.push(cmd[i + 1] === "(" ? "sub" : "param");
        i += 2;
      } else {
        kinds[i] = here;
        i++;
      }
      continue;
    }
    if (top === "bt") {
      if (c === "\\") {
        mark(i, i + 2, "nested");
        i += 2;
        continue;
      }
      if (c === "`") stack.pop();
      kinds[i] = "nested";
      i++;
      continue;
    }
    // Unquoted (top level), or inside $( ) / ${ }.
    const here: Kind = top === undefined ? "plain" : "nested";
    if (c === "\\") {
      mark(i, i + 2, here);
      i += 2;
    } else if (c === "'") {
      const close = cmd.indexOf("'", i + 1);
      const end = close === -1 ? n : close + 1;
      mark(i, end, top === undefined ? "sq" : "nested");
      i = end;
    } else if (c === "$" && cmd[i + 1] === "'") {
      let j = i + 2;
      while (j < n && cmd[j] !== "'") j += cmd[j] === "\\" ? 2 : 1;
      mark(i, j + 1, top === undefined ? "ansi" : "nested");
      i = j + 1;
    } else if (c === '"') {
      kinds[i] = here;
      stack.push("dq");
      i++;
    } else if (c === "`") {
      kinds[i] = "nested";
      stack.push("bt");
      i++;
    } else if (c === "$" && (cmd[i + 1] === "(" || cmd[i + 1] === "{")) {
      mark(i, i + 2, "nested");
      stack.push(cmd[i + 1] === "(" ? "sub" : "param");
      i += 2;
    } else if (c === "(" && top === "sub") {
      kinds[i] = "nested";
      stack.push("sub");
      i++;
    } else if ((c === ")" && top === "sub") || (c === "}" && top === "param")) {
      kinds[i] = "nested";
      stack.pop();
      i++;
    } else if (c === "<" && cmd[i + 1] === "<" && cmd[i + 2] !== "<") {
      heredoc = true;
      mark(i, i + 2, here);
      i += 2;
    } else if (c === "#" && top === undefined && (i === 0 || /[\s;&|()]/.test(cmd[i - 1] ?? ""))) {
      const nl = cmd.indexOf("\n", i);
      const end = nl === -1 ? n : nl;
      mark(i, end, "comment");
      i = end;
    } else {
      kinds[i] = here;
      i++;
    }
  }
  return { kinds, heredoc };
}

const WHY: Record<Exclude<Kind, "plain" | "dq" | "comment">, string> = {
  sq: "it is inside single quotes, where the shell expands nothing",
  ansi: "it is inside a $'...' string",
  nested: "it is inside a command or parameter substitution or backticks (a computed word)",
};

/**
 * One command of the rewrite that gets values: the simple command that carries references, run on its own
 * by a ticketed `launchsafe-firewall run` (V1). Only that one process (curl or wget) ever has the values in
 * its environment; the rest of the agent's command runs in the agent's own shell, which never sees them.
 */
export interface ShellPart {
  /** Where the simple command sits in the original command (replaced by the ticketed run). */
  start: number;
  end: number;
  /** The program: "curl" or "wget" (the hook resolves it to an absolute path; a PATH the agent set cannot swap it). */
  program: Sender;
  /** The prefix assignments ("NAME=value ..."), shell-quoted; "" when none. */
  assigns: string;
  /**
   * The arguments, shell-quoted, with no shell expansion of a value in them (B2): for curl, `--variable
   * %__LSV_n` first and each value-carrying option as `--expand-<option> '…{{__LSV_n}}…'`; for wget, the
   * arguments without the value-carrying options, which `feed` supplies.
   */
  args: string;
  /** wget: the shell's `printf '%s\n' "header = …${__LSV_n}…"` that feeds `--config=/dev/stdin`; "" for curl. */
  feed: string;
  /** Its redirections, kept in the agent's shell around the ticketed run (so they see only filtered output). */
  redirects: string;
  /** The variables of this part: `__LSV_1`, ... numbered per part. */
  vars: { name: string; ref: VaultRef }[];
  /** The URLs it requests (checked against the bindings: exact host, https, not local). */
  urls: SenderUrl[];
}

export type ShellPlan =
  | {
      ok: true;
      /** The command with each reference written as its variable in place: for display only, never run (run `parts`). */
      command: string;
      vars: { name: string; ref: VaultRef }[];
      parts: ShellPart[];
    }
  | { ok: false; why: string; ref?: string; /** "option": an option or variable off the allowlist (FW-VAULT-OPTION). */ rule?: "option" };

/** The environment variable a reference becomes ("__LSV_1", ...): one per distinct reference text. */
export const VAR_PREFIX = "__LSV_";

/** The programs a shell command may hand a value to: network clients that run no other program. */
export type { Sender } from "./vault-options.js";
const SENDERS: readonly Sender[] = ["curl", "wget"];

/** A word for the rewritten command: its literal text, with each reference as `${__LSV_n}`, quoted for sh. */
function wordWithVars(text: string, varFor: (r: VaultRef) => string): string {
  const refs = findRefs(text);
  if (refs.length === 0) {
    // A leading ~ stays unquoted so the shell still expands it as the person wrote it.
    const tilde = /^~[A-Za-z0-9._-]*(?=\/|$)/.exec(text);
    if (tilde !== null) return tilde[0] + (text.length > tilde[0].length ? shellQuote(text.slice(tilde[0].length)) : "");
    return shellQuote(text);
  }
  const lit = (t: string): string => t.replace(/["\\$`]/g, "\\$&");
  let out = "";
  let at = 0;
  for (const r of refs) {
    out += lit(text.slice(at, r.index)) + `\${${varFor(r)}}`;
    at = r.index + r.text.length;
  }
  return `"${out}${lit(text.slice(at))}"`;
}

/** The simple commands of a script that share its source text: the top level and its ( ) and { } groups. */
function commandsInSource(sc: Script, out: SimpleCommand[] = []): SimpleCommand[] {
  for (const pl of sc.pipelines) {
    for (const c of pl.commands) {
      out.push(c);
      if (c.group !== undefined) commandsInSource(c.group, out);
    }
  }
  return out;
}

const hasRef = (t: string): boolean => findRefs(t).length > 0;

/** Builds one part from a simple command that carries references, or says why it cannot get a value. */
function planPart(sc: SimpleCommand, refCount: { n: number }): ShellPart | { why: string; rule?: "option" } {
  if (sc.start === undefined || sc.end === undefined) return { why: "the firewall could not place the command that carries it" };
  if (sc.assigns.some((a) => hasRef(a.value.text))) return { why: "it is in a variable assignment" };
  if (sc.redirects.some((r) => r.heredoc !== undefined || (r.target !== null && hasRef(r.target.text)))) return { why: "it is in a redirection or a here-document" };
  const first = sc.words[0];
  if (first === undefined) return { why: "it is not in a command's arguments" };
  const program = SENDERS.find((p) => p === first.text);
  if (program === undefined || first.quoted || first.dynamic) {
    return { why: `only curl or wget, named as such, can be given a value in a shell command (not "${first.text.slice(0, 60)}"), so nothing else running in the shell can read it` };
  }
  const dynamic = [...sc.words, ...sc.assigns.map((a) => a.value), ...sc.redirects.flatMap((r) => (r.target === null ? [] : [r.target]))].find((w) => w.dynamic || w.subs.length > 0);
  if (dynamic !== undefined) return { why: `the ${program} command that carries it uses a variable or a substitution (${dynamic.text.slice(0, 60)}); write that command out in full` };
  // Only variables that cannot change routing, name resolution, trust or what runs (no proxy, PATH, CURL_HOME, ...).
  const assign = sc.assigns.find((a) => !SAFE_ASSIGN.test(a.name));
  if (assign !== undefined) return { why: `the ${program} command sets ${assign.name}, which is not on the vault's list of variables a sending command may set (it could change where the request goes, what is trusted, or what runs)`, rule: "option" };
  const checked = checkSenderArgs(program, sc.words.slice(1).map((w) => w.text));
  if (!checked.ok) return { why: `${program}'s ${checked.option} is not allowed with a vault value: ${checked.why}`, rule: "option" };
  const vars: { name: string; ref: VaultRef }[] = [];
  const varFor = (r: VaultRef): string => {
    const have = vars.find((v) => v.ref.text === r.text);
    if (have !== undefined) return have.name;
    const name = `${VAR_PREFIX}${vars.length + 1}`;
    vars.push({ name, ref: r });
    return name;
  };
  const assigns = sc.assigns.map((a) => `${a.name}=${shellQuote(a.value.text)}`).join(" ");
  // B2: the value never becomes an argument of curl or wget (any user on the machine can read a process's
  // arguments). curl reads it from its environment (--variable %NAME, then --expand-<option>); wget reads the
  // options that carry it from a configuration fed on its standard input by the shell's printf builtin.
  const built = program === "curl" ? curlArgs(sc.words.slice(1).map((w) => w.text), varFor) : wgetArgs(sc.words.slice(1).map((w) => w.text), varFor);
  if ("why" in built) return { why: built.why, rule: "option" };
  const args = built.args.join(" ");
  refCount.n += sc.words.reduce((n, w) => n + findRefs(w.text).length, 0);
  const redirects: string[] = [];
  for (const r of sc.redirects) {
    const fd = r.fd === null ? "" : String(r.fd);
    if (r.target !== null) redirects.push(`${fd}${r.op} ${shellQuote(r.target.text)}`);
    else if (r.dup !== undefined && /^(?:\d+|-)$/.test(r.dup)) redirects.push(`${fd}${r.op}${r.dup}`);
    else return { why: `the ${program} command has a redirection the firewall cannot carry over` };
  }
  return { start: sc.start, end: sc.end, program, assigns, args, feed: built.feed, redirects: redirects.join(" "), vars, urls: checked.urls };
}

/**
 * Whether a shell word of the sender's arguments would expand a substitution variable (the value) into the
 * argument itself. B2: never; the caller refuses rather than build such a word. (The command as written may
 * not name the variables at all, planShellRewrite refuses that, so any `${__LSV_` here came from a reference.)
 */
export function expandsValue(word: string): boolean {
  return word.includes(`\${${VAR_PREFIX}`) || new RegExp(`\\$${VAR_PREFIX}`).test(word);
}

/** curl options (on the vault's allowlist, vault-options.ts) that take a value; short letters by their long name. */
const CURL_VALUE_LONG = new Set(["--request", "--header", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode", "--json", "--user", "--user-agent", "--max-time", "--connect-timeout", "--retry", "--output", "--write-out", "--url"]);
const CURL_SHORT_LONG: Readonly<Record<string, string>> = { s: "--silent", S: "--show-error", f: "--fail", i: "--include", I: "--head", G: "--get", X: "--request", H: "--header", d: "--data", u: "--user", A: "--user-agent", m: "--max-time", o: "--output", O: "--remote-name", w: "--write-out" };

/**
 * A value with references for curl's --expand-<option>: each reference becomes `{{__LSV_n}}`, which curl
 * replaces with the variable it imported from its environment. Literal text that curl's expansion would read
 * (`{{`, or a backslash right before a reference, which would escape it) is refused rather than escaped.
 */
function curlExpanded(text: string, varFor: (r: VaultRef) => string): string | { why: string } {
  const refs = findRefs(text);
  let out = "";
  let at = 0;
  for (const r of refs) {
    const lit = text.slice(at, r.index);
    if (lit.includes("{{") || lit.endsWith("\\")) return { why: `the text around the reference (${text.slice(0, 60)}) holds "{{" or a backslash before it, which curl's variable expansion would read; write it without` };
    out += `${lit}{{${varFor(r)}}}`;
    at = r.index + r.text.length;
  }
  const tail = text.slice(at);
  if (tail.includes("{{")) return { why: `the text around the reference (${text.slice(0, 60)}) holds "{{", which curl's variable expansion would read; write it without` };
  return out + tail;
}

/**
 * curl's arguments with every value-carrying option rewritten to its --expand- form (curl 8.3 or later):
 * `-H "Authorization: Bearer vault://x"` becomes `--expand-header 'Authorization: Bearer {{__LSV_1}}'`, and
 * `--variable %__LSV_1` comes first. Words are shell-quoted; none holds the value or a shell expansion of it.
 */
export function curlArgs(words: readonly string[], varFor: (r: VaultRef) => string): { args: string[]; feed: string } | { why: string } {
  const out: string[] = [];
  const lit = (w: string): string => wordWithVars(w, varFor);
  let ended = false;
  let endAt = -1;
  const valued = (long: string, value: string): { why: string } | null => {
    if (!hasRef(value)) {
      out.push(long, lit(value));
      return null;
    }
    const v = curlExpanded(value, varFor);
    if (typeof v !== "string") return v;
    out.push(`--expand-${long.slice(2)}`, shellQuote(v));
    return null;
  };
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as string;
    if (ended || !w.startsWith("-") || w === "-") {
      if (!hasRef(w)) {
        out.push(lit(w));
        continue;
      }
      const v = curlExpanded(w, varFor);
      if (typeof v !== "string") return v;
      // A URL: as --expand-url, which goes before a "--" (after it every word is a URL).
      const pair = ["--expand-url", shellQuote(v)];
      if (ended) {
        out.splice(endAt, 0, ...pair);
        endAt += 2;
      } else out.push(...pair);
      continue;
    }
    if (w === "--") {
      ended = true;
      endAt = out.length;
      out.push("--");
      continue;
    }
    if (w.startsWith("--")) {
      if (CURL_VALUE_LONG.has(w)) {
        const r = valued(w, words[++i] ?? "");
        if (r !== null) return r;
      } else out.push(lit(w));
      continue;
    }
    // A short cluster: the letters before the first one that takes a value stay a cluster of their own.
    let flags = "";
    let handled = false;
    for (let j = 1; j < w.length; j++) {
      const long = own(CURL_SHORT_LONG, w[j] as string);
      if (long === undefined || !CURL_VALUE_LONG.has(long)) {
        flags += w[j] as string;
        continue;
      }
      if (flags !== "") out.push(lit(`-${flags}`));
      const rest = w.slice(j + 1);
      const r = valued(long, rest !== "" ? rest : (words[++i] ?? ""));
      if (r !== null) return r;
      handled = true;
      break;
    }
    if (!handled) out.push(lit(w));
  }
  if (out.some(expandsValue)) return { why: "a reference is somewhere curl's options cannot take it from the environment" };
  const vars: string[] = [];
  for (const w of words) for (const r of findRefs(w)) if (!vars.includes(varFor(r))) vars.push(varFor(r));
  return { args: [...vars.flatMap((v) => ["--variable", `%${v}`]), ...out], feed: "" };
}

/** wget options that may carry a value (vault-options.ts), and the wgetrc command each one is. */
const WGET_RC: Readonly<Record<string, string>> = { "--header": "header", "--post-data": "post_data", "--body-data": "body_data", "--user": "user", "--password": "password", "--http-user": "http_user", "--http-password": "http_password" };
const WGET_VALUE_LONG = new Set(["--output-document", "--header", "--method", "--post-data", "--body-data", "--user", "--password", "--http-user", "--http-password", "--user-agent", "--timeout", "--tries", "--max-redirect"]);
const WGET_SHORT_VALUE = new Set(["O", "U", "T", "t"]);

/**
 * wget's arguments without the options that carry a reference, and those options as wgetrc lines (`feed`, the
 * shell words of a printf) that `wget --config=/dev/stdin` reads from the pipe: the shell expands the
 * variables inside its own printf builtin, so the value is never an argument of any process. A reference
 * in a URL is refused (wget cannot read a URL from its configuration; curl can take it there).
 */
export function wgetArgs(words: readonly string[], varFor: (r: VaultRef) => string): { args: string[]; feed: string } | { why: string } {
  const out: string[] = [];
  const lines: string[] = [];
  const lit = (w: string): string => wordWithVars(w, varFor);
  const rc = (cmd: string, value: string): { why: string } | null => {
    if (/[\r\n]/.test(value)) return { why: "a line break in a value wget is given would add configuration commands" };
    lines.push(wordWithVars(`${cmd} = ${value}`, varFor));
    return null;
  };
  let ended = false;
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as string;
    if (ended || !w.startsWith("-") || w === "-") {
      if (hasRef(w)) return { why: "wget cannot be given a value in its URL without putting it on its command line, where every user on this machine can read it; use curl (8.3 or later), which reads it from its environment" };
      out.push(lit(w));
      continue;
    }
    if (w === "--") {
      ended = true;
      out.push("--");
      continue;
    }
    if (w.startsWith("--")) {
      const eq = w.indexOf("=");
      const name = eq === -1 ? w : w.slice(0, eq);
      // --config=/dev/stdin replaces every configuration file already; a --no-config would switch it off.
      if (name === "--no-config") continue;
      const value = !WGET_VALUE_LONG.has(name) ? null : eq !== -1 ? w.slice(eq + 1) : (words[++i] ?? "");
      const cmd = own(WGET_RC, name);
      if (value !== null && hasRef(value) && cmd !== undefined) {
        const bad = rc(cmd, value);
        if (bad !== null) return bad;
      } else if (value !== null) out.push(lit(`${name}=${value}`));
      else out.push(lit(w));
      continue;
    }
    // Short options (-qO-, -O -): none of them may carry a reference (the allowlist refused that already).
    out.push(lit(w));
    for (let j = 1; j < w.length; j++) {
      if (!WGET_SHORT_VALUE.has(w[j] as string)) continue;
      if (j === w.length - 1 && i + 1 < words.length) out.push(lit(words[++i] as string));
      break;
    }
  }
  if (out.some(expandsValue)) return { why: "a reference is somewhere wget's configuration cannot carry it" };
  return { args: out, feed: lines.length === 0 ? "" : `printf '%s\\n' ${lines.join(" ")}` };
}

/**
 * Plans the rewrite of a command's references into environment variables, or says why it cannot be done.
 * A command without references is returned unchanged with no variables or parts.
 */
export function planShellRewrite(command: string): ShellPlan {
  const refs = findRefs(command);
  if (refs.length === 0) return { ok: true, command, vars: [], parts: [] };
  if (/__LSV_/i.test(command)) return { ok: false, why: `it names the firewall's substitution variables (${VAR_PREFIX}…), which would read the value`, ref: refs[0]?.text };
  const { kinds, heredoc } = quoteContexts(command);
  const vars: { name: string; ref: VaultRef }[] = [];
  const varFor = (r: VaultRef): string => {
    const have = vars.find((v) => v.ref.text === r.text);
    if (have !== undefined) return have.name;
    const name = `${VAR_PREFIX}${vars.length + 1}`;
    vars.push({ name, ref: r });
    return name;
  };
  let out = "";
  let at = 0;
  let live = 0;
  for (const r of refs) {
    const kind = kinds[r.index] ?? "plain";
    const span = kinds.slice(r.index, r.index + r.text.length);
    if (span.some((k) => k !== kind)) return { ok: false, why: "it is split across quoting", ref: r.text };
    if (kind === "comment") continue;
    if (kind !== "plain" && kind !== "dq") return { ok: false, why: WHY[kind], ref: r.text };
    if (heredoc) return { ok: false, why: "the command has a here-document", ref: r.text };
    live++;
    const v = varFor(r);
    out += command.slice(at, r.index) + (kind === "plain" ? `"\${${v}}"` : `\${${v}}`);
    at = r.index + r.text.length;
  }
  out += command.slice(at);
  if (live === 0) return { ok: true, command: out, vars, parts: [] };
  // V1: every reference must sit in the arguments of one curl or wget command, which alone gets the values.
  const script = parseShell(command);
  if (allErrors(script).length > 0) return { ok: false, why: `the command could not be parsed (${allErrors(script)[0] ?? ""})`, ref: refs[0]?.text };
  const parts: ShellPart[] = [];
  const counted = { n: 0 };
  for (const sc of commandsInSource(script)) {
    const carries = sc.words.some((w) => hasRef(w.text)) || sc.assigns.some((a) => hasRef(a.value.text)) || sc.redirects.some((r) => (r.target !== null && hasRef(r.target.text)) || (r.heredoc !== undefined && hasRef(r.heredoc.body)));
    if (!carries) continue;
    const p = planPart(sc, counted);
    if ("why" in p) return { ok: false, why: p.why, ref: findRefs(sc.words.map((w) => w.text).join(" "))[0]?.text ?? refs[0]?.text, ...(p.rule !== undefined ? { rule: p.rule } : {}) };
    parts.push(p);
  }
  // Every live reference must be in one of those commands' words; one found anywhere else is not placed.
  if (counted.n !== live) return { ok: false, why: "it is somewhere in the command the firewall cannot rewrite on its own", ref: refs[0]?.text };
  return { ok: true, command: out, vars, parts };
}

/** One word for a POSIX shell, single-quoted unless it is plainly safe. */
export function shellQuote(word: string): string {
  if (word !== "" && /^[A-Za-z0-9_@%+=:,./-]+$/.test(word)) return word;
  return `'${word.replace(/'/g, `'\\''`)}'`;
}
