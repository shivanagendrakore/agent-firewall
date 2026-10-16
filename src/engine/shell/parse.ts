import { own } from "../../own.js";
/**
 * A conservative parser for POSIX sh / bash command lines. It does not run
 * anything and does not expand variables. It recovers the structure an
 * attacker would use to hide an action: quoting, ANSI-C strings ($'\x72\x6d'),
 * command and process substitution, subshells, here-documents, pipelines and
 * redirections. Whatever it cannot know statically is marked `dynamic`, and the
 * analyzer treats dynamic parts as the riskiest thing they could be.
 */

export interface Word {
  /** Quote-removed text. Expansions stay as written ($VAR, $(cmd)), so `dynamic` tells whether it is literal. */
  text: string;
  /** Contains a variable, command substitution or arithmetic: the runtime value is unknown. */
  dynamic: boolean;
  /** Contains unquoted glob or brace-expansion characters. */
  glob: boolean;
  /** Any part was quoted. */
  quoted: boolean;
  /** Command / process substitutions inside the word, parsed. */
  subs: Script[];
  /** Variable names referenced ($NAME, ${NAME...}). */
  vars: string[];
}

export interface Redirect {
  op: string;
  fd: number | null;
  target: Word | null;
  /** Here-document body, for << and <<-. */
  heredoc?: { body: string; expand: boolean };
  /** A descriptor duplication's target ("1" in 2>&1, "-" in >&-); target is null then. */
  dup?: string;
}

export interface SimpleCommand {
  assigns: { name: string; value: Word }[];
  words: Word[];
  redirects: Redirect[];
  /** A ( subshell ) or { group } in command position. */
  group?: Script;
  /** Which kind of group: a subshell's cd does not outlive it, a brace group's does. */
  groupKind?: "subshell" | "brace";
  /**
   * FZ8/FZ10: the group is the body of a function definition (`f() { ...; }`, `function f { ...; }`): it runs
   * where `f` is called, not where it is defined.
   */
  func?: string;
  /**
   * Where the command's tokens start and end in the source this parser read (the top-level command and
   * its ( ) / { } groups share it; a substitution's commands are positions in the substitution's text).
   */
  start?: number;
  end?: number;
}

export interface Pipeline {
  commands: SimpleCommand[];
  /** The connector after this pipeline (F-f: the working directory is tracked across them). */
  next?: ";" | "&&" | "||" | "&" | "\n";
}

export interface Script {
  pipelines: Pipeline[];
  errors: string[];
}

export const MAX_COMMAND_LENGTH = 256 * 1024;
const MAX_DEPTH = 12;
/** FZ1: a glob word longer than this is not matched against anything; the command is unanalyzable instead. */
export const MAX_GLOB_WORD = 4096;
/** Brace expansion past this many words, or this many characters in all, is not followed (the command is unanalyzable). */
const MAX_BRACE_WORDS = 256;
const MAX_BRACE_CHARS = 64 * 1024;

const META = new Set([" ", "\t", "\n", ";", "&", "|", "<", ">", "(", ")"]);
/**
 * Reserved words that can stand before a command inside the same simple command as this parser reads it
 * (it flattens compound commands: `if x; then rm y; fi` is `if x`, `then rm y`, `fi`). The command after
 * them is still in command position: `then f() { ...; }` defines a function, `do ( ... )` is a subshell.
 */
const KEYWORD_PREFIX = new Set(["if", "then", "else", "elif", "do", "while", "until", "!", "time"]);
/** Words that end a compound command, after which a brace group's "}" is recognised (`{ if x; then y; fi }`). */
const CLOSERS = new Set(["fi", "done", "esac", "}"]);

function newWord(): Word {
  return { text: "", dynamic: false, glob: false, quoted: false, subs: [], vars: [] };
}

function literalWord(text: string): Word {
  return { ...newWord(), text };
}

function newCommand(): SimpleCommand {
  return { assigns: [], words: [], redirects: [] };
}

export function parseShell(src: string, depth = 0): Script {
  if (src.length > MAX_COMMAND_LENGTH) return { pipelines: [], errors: ["command too large to analyze"] };
  const p = new Parser(src, depth);
  const script = p.parseScript(null);
  if (p.pos < src.length) script.errors.push(`unexpected "${src[p.pos]}"`);
  if (p.unreadHeredocs() > 0) script.errors.push("here-document without a body");
  return script;
}

/** A word as read, before brace expansion: `unquoted` holds the indexes of its characters that were written unquoted. */
interface RawWord {
  w: Word;
  unquoted: Set<number>;
}

interface Tok {
  ch: string;
  /** Written unquoted, so it can be brace-expansion syntax or a glob character. */
  u: boolean;
}

/** `{1..5}`, `{a..e}`, `{01..10..2}`: the words of a sequence expression, null if `inner` is not one, "big" past the limit. */
function braceSequence(inner: string, limit: number): string[] | null | "big" {
  const num = /^([+-]?\d+)\.\.([+-]?\d+)(?:\.\.([+-]?\d+))?$/.exec(inner);
  const chr = /^([A-Za-z])\.\.([A-Za-z])(?:\.\.([+-]?\d+))?$/.exec(inner);
  const m = num ?? chr;
  if (m === null) return null;
  const step = Math.max(1, Math.abs(Number(m[3] ?? "1")) || 1);
  const a = num !== null ? Number(m[1]) : (m[1] as string).charCodeAt(0);
  const b = num !== null ? Number(m[2]) : (m[2] as string).charCodeAt(0);
  if (!Number.isSafeInteger(a) || !Number.isSafeInteger(b)) return "big";
  if (Math.floor(Math.abs(b - a) / step) + 1 > limit) return "big";
  // A leading zero on either end pads every number to the longer width ({01..10}).
  const pad = num !== null && (/^[+-]?0\d/.test(m[1] as string) || /^[+-]?0\d/.test(m[2] as string)) ? Math.max((m[1] as string).length, (m[2] as string).length) : 0;
  const out: string[] = [];
  for (let v = a; a <= b ? v <= b : v >= b; v += a <= b ? step : -step) {
    if (num === null) out.push(String.fromCharCode(v));
    else out.push(v < 0 ? `-${String(-v).padStart(pad - 1, "0")}` : String(v).padStart(pad, "0"));
  }
  return out;
}

/**
 * Bash brace expansion of one word (`{a,b}`, `{1..3}`, nested), on its unquoted braces only. The words in
 * order, or null when there would be more than `limit` of them or the work to find them is too large.
 */
function braceExpand(raw: RawWord, limit: number): { text: string; glob: boolean }[] | null {
  const text = raw.w.text;
  let brace = false;
  for (let i = text.indexOf("{"); i !== -1 && !brace; i = text.indexOf("{", i + 1)) brace = raw.unquoted.has(i);
  if (!brace) return [{ text, glob: raw.w.glob }];
  if (text.length > MAX_GLOB_WORD) return null;
  const toks: Tok[] = [];
  for (let i = 0; i < text.length; i++) toks.push({ ch: text[i] as string, u: raw.unquoted.has(i) });
  const out: Tok[][] = [];
  const budget = { steps: 0 };
  if (!expandToks(toks, 0, out, limit, budget)) return null;
  return out.map((t) => ({ text: t.map((x) => x.ch).join(""), glob: t.some((x) => x.u && (x.ch === "*" || x.ch === "?" || x.ch === "[")) }));
}

/**
 * The unquoted "}" that closes each unquoted "{" (-1 when none does), in one pass with a stack: the same pairs as
 * counting depth forward from each "{", without rescanning to the end of the word from every "{" that never
 * closes (quadratic on a word of many: shell:robust seed 56825).
 */
function braceMatches(t: readonly Tok[]): Int32Array {
  const match = new Int32Array(t.length).fill(-1);
  const stack: number[] = [];
  for (let j = 0; j < t.length; j++) {
    const x = t[j] as Tok;
    if (!x.u) continue;
    if (x.ch === "{") stack.push(j);
    else if (x.ch === "}" && stack.length > 0) match[stack.pop() as number] = j;
  }
  return match;
}

function expandToks(t: Tok[], from: number, out: Tok[][], limit: number, budget: { steps: number }): boolean {
  const match = braceMatches(t);
  budget.steps += t.length;
  if (budget.steps > 1_000_000) return false;
  for (let i = from; i < t.length; i++) {
    const open = t[i] as Tok;
    if (!open.u || open.ch !== "{" || (i > 0 && (t[i - 1] as Tok).ch === "$")) continue;
    const close = match[i] as number;
    if (close === -1) continue;
    let depth = 0;
    const commas: number[] = [];
    for (let j = i; j < close; j++) {
      if (++budget.steps > 1_000_000) return false;
      const x = t[j] as Tok;
      if (!x.u) continue;
      if (x.ch === "{") depth++;
      else if (x.ch === "}") depth--;
      else if (x.ch === "," && depth === 1) commas.push(j);
    }
    let alts: Tok[][];
    if (commas.length > 0) {
      alts = [];
      let at = i + 1;
      for (const k of [...commas, close]) {
        alts.push(t.slice(at, k));
        at = k + 1;
      }
    } else {
      const seq = braceSequence(t.slice(i + 1, close).map((x) => x.ch).join(""), limit);
      if (seq === "big") return false;
      if (seq === null) continue;
      alts = seq.map((v) => Array.from(v, (ch) => ({ ch, u: false })));
    }
    const pre = t.slice(0, i);
    const post = t.slice(close + 1);
    for (const a of alts) if (!expandToks([...pre, ...a, ...post], i, out, limit, budget)) return false;
    return true;
  }
  if (out.length >= limit) return false;
  out.push(t);
  return true;
}

/** Where a case statement is: after `case`, before `in`, between items, or in an item's commands. */
type CasePhase = "subject" | "in" | "pattern" | "body";

class Parser {
  pos = 0;
  private pendingHeredocs: { redirect: Redirect; delim: string; stripTabs: boolean }[] = [];

  constructor(
    private readonly src: string,
    private readonly depth: number,
  ) {}

  unreadHeredocs(): number {
    return this.pendingHeredocs.length;
  }

  private sub(text: string): Script {
    if (this.depth + 1 > MAX_DEPTH) return { pipelines: [], errors: ["nesting too deep to analyze"] };
    return parseShell(text, this.depth + 1);
  }

  /** Whether an unquoted reserved word `kw` starts at the cursor (followed by a separator or the end). */
  private atWord(kw: string): boolean {
    const after = this.src[this.pos + kw.length];
    return this.src.startsWith(kw, this.pos) && (after === undefined || META.has(after));
  }

  parseScript(stop: ")" | "}" | null): Script {
    const s = this.src;
    const script: Script = { pipelines: [], errors: [] };
    let cur = newCommand();
    let pipe: SimpleCommand[] = [];
    /** FZ8/FZ10: a function's name, read (`f()`, `function f`), waiting for its body. */
    let pendingFunc: string | null = null;
    /** FZ9: open case statements, innermost last. */
    const cases: CasePhase[] = [];
    const casePhase = (): CasePhase | undefined => cases[cases.length - 1];
    const setCasePhase = (p: CasePhase): void => {
      cases[cases.length - 1] = p;
    };
    // The span of the current command's tokens in the source (SimpleCommand.start/end).
    const begin = (at: number): void => {
      if (cur.start === undefined) cur.start = at;
    };
    const finish = (): void => {
      cur.end = this.pos;
    };
    const endCommand = (): void => {
      if (cur.words.length > 0 || cur.assigns.length > 0 || cur.redirects.length > 0 || cur.group !== undefined) pipe.push(cur);
      cur = newCommand();
    };
    const endPipeline = (next?: Pipeline["next"]): void => {
      endCommand();
      if (pipe.length > 0) script.pipelines.push(next === undefined ? { commands: pipe } : { commands: pipe, next });
      pipe = [];
    };
    const isKeyword = (w: Word): boolean => !w.quoted && !w.dynamic && KEYWORD_PREFIX.has(w.text);
    /** How many of the current command's words are leading reserved words. */
    const leading = (): number => {
      let k = 0;
      while (k < cur.words.length && isKeyword(cur.words[k] as Word)) k++;
      return k;
    };
    /** Whether the cursor is in command position: nothing but reserved words read for this command yet. */
    const atStart = (): boolean => cur.group === undefined && cur.assigns.length === 0 && cur.redirects.length === 0 && leading() === cur.words.length;
    while (this.pos < s.length) {
      const c = s[this.pos] as string;
      const next = s[this.pos + 1];
      if (casePhase() === "pattern") {
        // Between case items: blanks, newlines and comments, then `esac` or the next item's patterns.
        if (c === " " || c === "\t" || c === "\r" || c === "\n") {
          this.pos++;
          if (c === "\n") this.readHeredocBodies(script);
          continue;
        }
        if (c === "\\" && next === "\n") {
          this.pos += 2;
          continue;
        }
        if (c === "#") {
          while (this.pos < s.length && s[this.pos] !== "\n") this.pos++;
          continue;
        }
        if (this.atWord("esac")) {
          cases.pop();
          // Read as a word below: what follows `esac` (a pipe, a redirection, `;`) belongs to the case statement.
        } else {
          if (this.readCasePattern(script)) setCasePhase("body");
          else {
            script.errors.push("a case pattern the firewall cannot read");
            cases.pop();
          }
          continue;
        }
      }
      if (stop === ")" && c === ")") break;
      if (stop === "}" && c === "}" && cur.assigns.length === 0 && cur.redirects.length === 0 && cur.words.every((w) => !w.quoted && CLOSERS.has(w.text))) break;
      if (c === " " || c === "\t" || c === "\r") {
        this.pos++;
        continue;
      }
      if (c === "\\" && next === "\n") {
        this.pos += 2;
        continue;
      }
      if (c === "\n") {
        endPipeline("\n");
        this.pos++;
        this.readHeredocBodies(script);
        continue;
      }
      if (c === "#") {
        while (this.pos < s.length && s[this.pos] !== "\n") this.pos++;
        continue;
      }
      if (c === ";") {
        endPipeline(";");
        const item = next === ";" || next === "&";
        this.pos += next === ";" ? 2 : 1;
        if (s[this.pos] === "&") this.pos++; // ;& and ;;& in case
        if (item) {
          // ;; ;& ;;& end a case item: anywhere else bash refuses the command.
          if (casePhase() === "body") setCasePhase("pattern");
          else script.errors.push("unexpected ;; outside a case statement");
        }
        continue;
      }
      if (c === "&") {
        if (next === "&") {
          endPipeline("&&");
          this.pos += 2;
          continue;
        }
        if (next === ">") {
          begin(this.pos);
          this.readRedirect(cur, script, null);
          finish();
          continue;
        }
        endPipeline("&");
        this.pos++;
        continue;
      }
      if (c === "|") {
        if (next === "|") {
          endPipeline("||");
          this.pos += 2;
          continue;
        }
        endCommand();
        this.pos += next === "&" ? 2 : 1;
        continue;
      }
      if (c === "(") {
        const k = leading();
        const plain = cur.group === undefined && cur.assigns.length === 0 && cur.redirects.length === 0;
        if (plain && cur.words.length === k + 1 && /^[ \t]*\)/.test(s.slice(this.pos + 1, this.pos + 64))) {
          // name() body: a function definition. The body (next) runs where the name is called.
          const name = cur.words[k] as Word;
          if (name.dynamic || isKeyword(name)) script.errors.push(`a function definition the firewall cannot read (${name.text.slice(0, 40)})`);
          pendingFunc = name.text;
          cur.words = cur.words.slice(0, k);
          this.pos = s.indexOf(")", this.pos) + 1;
          continue;
        }
        begin(this.pos);
        const forArith = plain && cur.words.length === k + 1 && !(cur.words[k] as Word).quoted && (cur.words[k] as Word).text === "for";
        if (next === "(" && (atStart() || forArith)) {
          // FZ2: "((" is arithmetic only when bash reads it as arithmetic: up to a "))" that closes it. Otherwise
          // ("((cmd); cmd)") bash reads nested subshells, and so does this parser.
          const end = this.dparenEnd(this.pos + 2);
          if (end !== -1) {
            pendingFunc = null;
            this.scanArithmetic(s.slice(this.pos + 2, end), cur, script);
            this.pos = end + 2;
            finish();
            continue;
          }
          if (forArith) script.errors.push("a for (( )) loop the firewall cannot read");
        }
        if (!atStart()) {
          // `echo (x)`, `ls *(e:...:)` (a zsh glob qualifier that can run code), `!(x)`: not a subshell bash runs,
          // and not something this parser models. Read on as a subshell, but the command is unclassifiable.
          script.errors.push("a parenthesis in the middle of a command");
        }
        this.pos++;
        const inner = this.depth + 1 > MAX_DEPTH ? { pipelines: [], errors: ["nesting too deep to analyze"] } : this.nested(")");
        if (s[this.pos] === ")") this.pos++;
        else script.errors.push("unterminated subshell");
        // `()` alone: bash refuses it (zsh runs `() { ...; }` as an anonymous function).
        if (inner.pipelines.length === 0 && inner.errors.length === 0) script.errors.push("an empty subshell");
        cur.group = inner;
        cur.groupKind = "subshell";
        if (pendingFunc !== null) cur.func = pendingFunc;
        pendingFunc = null;
        finish();
        continue;
      }
      if (c === ")") {
        // Not closing anything this parser opened: bash refuses the command. Read on as a separator.
        script.errors.push("unexpected )");
        endCommand();
        this.pos++;
        continue;
      }
      if (c === "{" && atStart() && (next === " " || next === "\n" || next === "\t")) {
        begin(this.pos);
        this.pos++;
        const inner = this.depth + 1 > MAX_DEPTH ? { pipelines: [], errors: ["nesting too deep to analyze"] } : this.nested("}");
        if (s[this.pos] === "}") this.pos++;
        else script.errors.push("unterminated group");
        cur.group = inner;
        cur.groupKind = "brace";
        if (pendingFunc !== null) cur.func = pendingFunc;
        pendingFunc = null;
        finish();
        continue;
      }
      // `<(...)` / `>(...)` is process substitution (a word), not a redirection; readWordRaw reads it below.
      if ((c === "<" || c === ">") && next !== "(") {
        begin(this.pos);
        this.readRedirect(cur, script, null);
        finish();
        continue;
      }
      const fd = /^(\d+)(?=[<>])/.exec(s.slice(this.pos, this.pos + 12));
      if (fd !== null) {
        begin(this.pos);
        this.pos += (fd[1] as string).length;
        this.readRedirect(cur, script, Number(fd[1]));
        finish();
        continue;
      }
      const startPos = this.pos;
      const start = atStart();
      const raw = this.readWordRaw(script);
      const w = raw.w;
      if (this.pos === startPos) {
        // Defensive: never loop forever on an unexpected character.
        this.pos++;
        continue;
      }
      pendingFunc = null;
      begin(startPos);
      finish();
      const bare = !w.quoted && !w.dynamic;
      if (start && bare && w.text === "function") {
        // FZ8: `function name { ...; }`, `function name() ...`: a definition, not a command named "function".
        while (s[this.pos] === " " || s[this.pos] === "\t") this.pos++;
        const at = this.pos;
        const name = this.readWord(script);
        if (this.pos === at || name.dynamic) script.errors.push("a function definition the firewall cannot read");
        const parens = /^[ \t]*\([ \t]*\)/.exec(s.slice(this.pos, this.pos + 64));
        if (parens !== null) this.pos += parens[0].length;
        pendingFunc = name.text;
        continue;
      }
      if (start && bare && w.text === "coproc") {
        // SH4: `coproc [NAME] command`. A NAME is there only when a group or compound command follows it;
        // dropping both leaves the body to parse as commands (`coproc { rm; }`, `coproc NAME { rm; }`, `coproc rm`).
        const name = /^[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]+(?=[{(]|if\b|while\b|until\b|for\b|case\b|select\b)/.exec(s.slice(this.pos, this.pos + 128));
        if (name !== null) this.pos += (name[0] as string).length;
        cur.words = cur.words.slice(0, leading());
        continue;
      }
      if (start && bare && w.text === "}" && stop !== "}") script.errors.push("unexpected }");
      if (start && bare && w.text === "case") cases.push("subject");
      else if (casePhase() === "subject") setCasePhase("in");
      else if (casePhase() === "in") {
        if (bare && w.text === "in") {
          cur.words.push(w);
          endPipeline();
          setCasePhase("pattern");
          continue;
        }
        script.errors.push("a case statement without in");
        cases.pop();
      } else if (start && bare && w.text === "esac" && casePhase() === "body") cases.pop();
      const assign = /^([A-Za-z_][A-Za-z0-9_]*)(\+?)=/.exec(w.text);
      // Assignments come before the command's name, after other assignments and redirections, and after reserved words.
      const assignPos = cur.group === undefined && leading() === cur.words.length;
      if (assignPos && assign !== null && !w.text.startsWith("'") && !this.quotedPrefix(startPos, (assign[1] as string).length)) {
        // An assignment: no brace expansion (bash does not expand braces in assignments).
        const valueWord: Word = { ...w, text: w.text.slice(assign[0].length) };
        cur.assigns.push({ name: assign[1] as string, value: valueWord });
        continue;
      }
      cur.words.push(...this.expandWord(raw, script));
      if (start && bare && w.text === "[[") {
        this.readCond(cur, script);
        // SH18: bash needs a control operator after `]]` (`[[ x ]] && y`); a bare command after it
        // (`if [[ x ]] cmd`, zsh's short if) is a syntax error there, so the command is unclassifiable.
        while (s[this.pos] === " " || s[this.pos] === "\t") this.pos++;
        const after = s[this.pos];
        if (after !== undefined && !META.has(after) && after !== "#") script.errors.push("a command after ]] without a separator");
      }
    }
    endPipeline();
    if (cases.length > 0) script.errors.push("unterminated case statement");
    if (pendingFunc !== null) script.errors.push("a function definition without a body");
    // A pathological command (`j(((((…` a quarter-million times) pushes the same error per character; only
    // the distinct messages matter, and `out.push(...errors)` elsewhere would exceed the argument limit.
    if (script.errors.length > 1) script.errors = [...new Set(script.errors)];
    return script;
  }

  /**
   * Parses a nested ( ... ) or { ... } with this same parser, so positions stay shared. Here-documents
   * started before it or inside it are read at the next newline, wherever that is, as bash does.
   */
  private nested(stop: ")" | "}"): Script {
    // Bound the recursion (and the tree) at every nested form, process substitution included: deeper than
    // this, skip to the matching close and report it, so a quarter-million nested `(` cannot overflow.
    if (this.depth + 1 > MAX_DEPTH) {
      this.skipToClose(stop);
      return { pipelines: [], errors: ["nesting too deep to analyze"] };
    }
    const inner = new Parser(this.src, this.depth + 1);
    inner.pos = this.pos;
    inner.pendingHeredocs = this.pendingHeredocs;
    this.pendingHeredocs = [];
    const script = inner.parseScript(stop);
    this.pos = inner.pos;
    this.pendingHeredocs = inner.pendingHeredocs;
    return script;
  }

  /** Advances the cursor to the matching `stop`, counting nested opens of the same delimiter (quotes ignored). */
  private skipToClose(stop: ")" | "}"): void {
    const s = this.src;
    const open = stop === ")" ? "(" : "{";
    let depth = 1;
    while (this.pos < s.length) {
      const c = s[this.pos];
      if (c === "\\") {
        this.pos += 2;
        continue;
      }
      if (c === open) depth++;
      else if (c === stop && --depth === 0) return;
      this.pos++;
    }
  }

  private quotedPrefix(start: number, nameLen: number): boolean {
    return /["'\\$]/.test(this.src.slice(start, start + nameLen));
  }

  /**
   * FZ2: where the "))" that closes an arithmetic command or expansion starts, reading from just after
   * its "((" the way bash does: parentheses must balance, and the first ")" that closes the opening one
   * must be followed by another ")". -1 when it is not arithmetic (bash then reads nested subshells).
   */
  private dparenEnd(from: number): number {
    const s = this.src;
    let depth = 0;
    for (let i = from; i < s.length; i++) {
      const ch = s[i];
      if (ch === "\\") {
        i++;
        continue;
      }
      if (ch === "'" || ch === '"') {
        let j = i + 1;
        while (j < s.length && s[j] !== ch) j += ch === '"' && s[j] === "\\" ? 2 : 1;
        if (j >= s.length) return -1;
        i = j;
        continue;
      }
      if (ch === "(") depth++;
      else if (ch === ")") {
        if (depth === 0) return s[i + 1] === ")" ? i : -1;
        depth--;
      }
    }
    return -1;
  }

  /** Arithmetic is not a command, but $(...) and `...` inside it are. */
  private scanArithmetic(text: string, cur: SimpleCommand, script: Script): void {
    const w = newWord();
    w.dynamic = true;
    const inner = new Parser(text, this.depth + 1);
    while (inner.pos < text.length) {
      const ch = text[inner.pos];
      if (ch === "$" && text[inner.pos + 1] === "(") inner.readDollar(w, script);
      else if (ch === "`") inner.readBacktick(w, script);
      else inner.pos++;
    }
    if (w.subs.length > 0) {
      cur.group = { pipelines: w.subs.flatMap((sc) => sc.pipelines), errors: w.subs.flatMap((sc) => sc.errors) };
      cur.groupKind = "subshell";
    }
  }

  /**
   * FZ9: one case item's patterns, `(a|b)` or `a|b)`, up to and including the ")". Command substitutions in a
   * pattern run, so a pattern carrying one is kept as a command whose first word is `case` (data, not a program).
   */
  private readCasePattern(script: Script): boolean {
    const s = this.src;
    const holder = newCommand();
    holder.start = this.pos;
    holder.words.push(literalWord("case"));
    if (s[this.pos] === "(") this.pos++;
    let any = false;
    let ok = false;
    while (this.pos < s.length) {
      const ch = s[this.pos] as string;
      if (ch === " " || ch === "\t") {
        this.pos++;
        continue;
      }
      if (ch === ")") {
        this.pos++;
        ok = any;
        break;
      }
      if (ch === "|" && any) {
        this.pos++;
        continue;
      }
      if (META.has(ch)) break;
      const at = this.pos;
      const w = this.readWord(script);
      if (this.pos === at) break;
      any = true;
      holder.words.push(w);
    }
    holder.end = this.pos;
    if (holder.words.some((w) => w.subs.length > 0)) script.pipelines.push({ commands: [holder] });
    return ok;
  }

  /**
   * The rest of a `[[ ... ]]` test after its `[[`: inside it ( ) && || < > are the test's own operators, not
   * subshells, lists or redirections, and a regular expression after =~ may hold ( ) and |. Substitutions in
   * its words still run, so every word is kept.
   */
  private readCond(cur: SimpleCommand, script: Script): void {
    const s = this.src;
    while (this.pos < s.length) {
      const c = s[this.pos] as string;
      if (c === " " || c === "\t" || c === "\r" || c === "\n") {
        this.pos++;
        continue;
      }
      if (c === "\\" && s[this.pos + 1] === "\n") {
        this.pos += 2;
        continue;
      }
      if (this.atWord("]]")) {
        cur.words.push(literalWord("]]"));
        this.pos += 2;
        cur.end = this.pos;
        return;
      }
      if (c === "(" || c === ")") {
        this.pos++;
        continue;
      }
      if (s.startsWith("&&", this.pos) || s.startsWith("||", this.pos)) {
        cur.words.push(literalWord(s.slice(this.pos, this.pos + 2)));
        this.pos += 2;
        continue;
      }
      if (c === "<" || c === ">") {
        cur.words.push(literalWord(c));
        this.pos++;
        continue;
      }
      if (META.has(c)) break;
      const prev = cur.words[cur.words.length - 1];
      const at = this.pos;
      const w = prev !== undefined && !prev.quoted && prev.text === "=~" ? this.readRegex(script) : this.readWord(script);
      if (this.pos === at) break;
      cur.words.push(w);
    }
    script.errors.push("unterminated [[ test");
  }

  /** The regular expression after =~ in [[ ]]: words joined by ( ) | < > (balanced parentheses are part of it). */
  private readRegex(script: Script): Word {
    const s = this.src;
    const out = newWord();
    let depth = 0;
    while (this.pos < s.length) {
      const c = s[this.pos] as string;
      if ((c === " " || c === "\t" || c === "\n" || c === "\r") && depth === 0) break;
      if (c === "(") depth++;
      else if (c === ")") {
        if (depth === 0) break;
        depth--;
      } else if (depth === 0 && (c === ";" || c === "&" || (c === "|" && s[this.pos + 1] === "|"))) break;
      if (META.has(c)) {
        out.text += c;
        this.pos++;
        continue;
      }
      const at = this.pos;
      const piece = this.readWord(script);
      if (this.pos === at) break;
      out.text += piece.text;
      out.dynamic ||= piece.dynamic;
      out.quoted ||= piece.quoted;
      out.subs.push(...piece.subs);
      out.vars.push(...piece.vars);
    }
    return out;
  }

  private readRedirect(cur: SimpleCommand, script: Script, fd: number | null): void {
    const s = this.src;
    const ops = ["&>>", "&>", "<<<", "<<-", "<<", "<>", ">>", ">|", ">&", "<&", ">", "<"];
    const op = ops.find((o) => s.startsWith(o, this.pos)) as string;
    this.pos += op.length;
    while (s[this.pos] === " " || s[this.pos] === "\t") this.pos++;
    if (op === "<<" || op === "<<-") {
      const start = this.pos;
      const w = this.readWord(script);
      const rawDelim = s.slice(start, this.pos);
      if (rawDelim === "") script.errors.push("here-document without a delimiter");
      const expand = !/["'\\]/.test(rawDelim);
      const r: Redirect = { op, fd, target: null, heredoc: { body: "", expand } };
      cur.redirects.push(r);
      this.pendingHeredocs.push({ redirect: r, delim: w.text, stripTabs: op === "<<-" });
      return;
    }
    if ((op === ">&" || op === "<&") && /^(?:\d+|-)(?=$|[\s;&|)<>])/.test(s.slice(this.pos))) {
      // Descriptor duplication (2>&1, >&-): no file involved.
      const m = /^(?:\d+|-)/.exec(s.slice(this.pos)) as RegExpExecArray;
      this.pos += m[0].length;
      cur.redirects.push({ op, fd, target: null, dup: m[0] });
      return;
    }
    const start = this.pos;
    const raw = this.readWordRaw(script);
    if (this.pos === start) script.errors.push(`redirect ${op} without a target`);
    // A target that brace-expands to several words is an "ambiguous redirect": bash runs nothing.
    if ((braceExpand(raw, MAX_BRACE_WORDS)?.length ?? 2) > 1) script.errors.push(`redirect ${op} to several files`);
    cur.redirects.push({ op, fd, target: raw.w });
  }

  private readHeredocBodies(script: Script): void {
    const s = this.src;
    for (const h of this.pendingHeredocs) {
      const lines: string[] = [];
      let found = false;
      const expand = h.redirect.heredoc?.expand === true;
      const physical = (): string => {
        let end = s.indexOf("\n", this.pos);
        if (end === -1) end = s.length;
        const line = s.slice(this.pos, end);
        this.pos = Math.min(s.length, end + 1);
        return h.stripTabs ? line.replace(/^\t+/, "") : line;
      };
      while (this.pos < s.length) {
        let line = physical();
        // An unquoted body is read with backslash-newline removed (an odd run of backslashes at the end of a
        // line), so `$\` + newline + `(cmd)` is `$(cmd)`. Should the next line be the delimiter, shells could
        // disagree on where the body ends: the command is unclassifiable then.
        while (expand && /(?:^|[^\\])(?:\\\\)*\\$/.test(line) && this.pos < s.length) {
          const next = physical();
          if (next === h.delim) script.errors.push(`a here-document line continued onto its "${h.delim}" line`);
          line = line.slice(0, -1) + next;
        }
        if (line === h.delim) {
          found = true;
          break;
        }
        lines.push(line);
      }
      if (!found) script.errors.push(`here-document without its "${h.delim}" line`);
      (h.redirect.heredoc as { body: string }).body = lines.join("\n");
    }
    this.pendingHeredocs = [];
  }

  readWord(script: Script): Word {
    return this.readWordRaw(script).w;
  }

  /** A command word after brace expansion: one word, or the several bash makes of `{a,b}` and `{1..3}`. */
  private expandWord(raw: RawWord, script: Script): Word[] {
    if (![...raw.unquoted].some((i) => raw.w.text[i] === "{")) return [raw.w];
    const texts = braceExpand(raw, MAX_BRACE_WORDS);
    if (texts !== null && texts.length === 1 && texts[0]?.text === raw.w.text) return [raw.w];
    if (texts === null || texts.length === 0 || texts.reduce((n, t) => n + t.text.length, 0) > MAX_BRACE_CHARS) {
      script.errors.push("brace expansion too large to analyze");
      return [raw.w];
    }
    // Substitutions run once per copy; analysing them once is enough.
    return texts.map((t, i) => ({ ...raw.w, text: t.text, glob: t.glob, subs: i === 0 ? raw.w.subs : [] }));
  }

  readWordRaw(script: Script): RawWord {
    const s = this.src;
    const w = newWord();
    const unquoted = new Set<number>();
    const start = this.pos;
    while (this.pos < s.length) {
      const c = s[this.pos] as string;
      if (META.has(c)) {
        // name=( array ): the elements are words (with substitutions that run) up to the closing ")".
        if (c === "(" && this.pos > start && /^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=$/.test(w.text)) {
          this.readArray(w, script);
          continue;
        }
        // <(cmd) and >(cmd) process substitution inside a word position.
        break;
      }
      if (c === "\\") {
        if (s[this.pos + 1] === "\n") {
          this.pos += 2;
          continue;
        }
        w.text += s[this.pos + 1] ?? "";
        w.quoted = true;
        this.pos += 2;
        continue;
      }
      if (c === "'") {
        const end = s.indexOf("'", this.pos + 1);
        w.quoted = true;
        if (end === -1) {
          script.errors.push("unterminated single quote");
          w.text += s.slice(this.pos + 1);
          this.pos = s.length;
          break;
        }
        w.text += s.slice(this.pos + 1, end);
        this.pos = end + 1;
        continue;
      }
      if (c === "$" && s[this.pos + 1] === "'") {
        this.pos += 2;
        w.text += this.readAnsiC(script);
        w.quoted = true;
        continue;
      }
      if (c === "$" && s[this.pos + 1] === '"') {
        this.pos++;
        continue;
      }
      if (c === '"') {
        this.pos++;
        this.readDouble(w, script);
        w.quoted = true;
        continue;
      }
      if (c === "`") {
        this.readBacktick(w, script);
        continue;
      }
      if (c === "$") {
        this.readDollar(w, script);
        continue;
      }
      if (c === "*" || c === "?" || c === "[") w.glob = true;
      if (c === "{" && /^\{[^\s{}]*(?:,|\.\.)[^\s{}]*\}/.test(s.slice(this.pos, this.pos + 4096))) w.glob = true;
      unquoted.add(w.text.length);
      w.text += c;
      this.pos++;
    }
    // Process substitution: <(...) or >(...) right where a word starts.
    if (this.pos === start && (s.startsWith("<(", this.pos) || s.startsWith(">(", this.pos))) {
      this.pos += 2;
      const inner = this.nested(")");
      if (s[this.pos] === ")") this.pos++;
      else script.errors.push("unterminated process substitution");
      w.subs.push(inner);
      w.dynamic = true;
      w.text = "/dev/fd/63";
    }
    // FZ1: a glob this long is not a path anyone types; it is not matched (no giant patterns), it is unanalyzable.
    if (w.glob && w.text.length > MAX_GLOB_WORD) script.errors.push("a glob pattern too long to analyze");
    return { w, unquoted };
  }

  /** An array assignment's ( elements ), read as words so substitutions in them are seen. */
  private readArray(w: Word, script: Script): void {
    const s = this.src;
    w.text += "(";
    w.dynamic = true;
    this.pos++;
    while (this.pos < s.length) {
      const c = s[this.pos] as string;
      if (c === " " || c === "\t" || c === "\r" || c === "\n") {
        this.pos++;
        continue;
      }
      if (c === "#") {
        while (this.pos < s.length && s[this.pos] !== "\n") this.pos++;
        continue;
      }
      if (c === ")") {
        w.text += ")";
        this.pos++;
        return;
      }
      const at = this.pos;
      const el = this.readWordRaw(script);
      if (this.pos === at) break;
      for (const x of this.expandWord(el, script)) {
        w.text += `${w.text.endsWith("(") ? "" : " "}${x.text}`;
        w.subs.push(...x.subs);
        w.vars.push(...x.vars);
      }
    }
    script.errors.push("unterminated array assignment");
  }

  private readAnsiC(script: Script): string {
    const s = this.src;
    let out = "";
    while (this.pos < s.length) {
      const c = s[this.pos] as string;
      if (c === "'") {
        this.pos++;
        return out;
      }
      if (c !== "\\") {
        out += c;
        this.pos++;
        continue;
      }
      const e = s[this.pos + 1] ?? "";
      this.pos += 2;
      const simple: Record<string, string> = { n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", v: "\v", "\\": "\\", "'": "'", '"': '"', "?": "?" };
      if (e in simple) {
        out += own(simple, e) as string;
      } else if (e === "x") {
        const m = /^[0-9a-fA-F]{1,2}/.exec(s.slice(this.pos));
        if (m !== null) {
          out += String.fromCharCode(parseInt(m[0], 16));
          this.pos += m[0].length;
        } else out += "\\x";
      } else if (e === "u" || e === "U") {
        const m = (e === "u" ? /^[0-9a-fA-F]{1,4}/ : /^[0-9a-fA-F]{1,8}/).exec(s.slice(this.pos));
        if (m !== null) {
          const cp = parseInt(m[0], 16);
          out += cp <= 0x10ffff ? String.fromCodePoint(cp) : "";
          this.pos += m[0].length;
        }
      } else if (/[0-7]/.test(e)) {
        const m = /^[0-7]{0,2}/.exec(s.slice(this.pos)) as RegExpExecArray;
        out += String.fromCharCode(parseInt(e + m[0], 8) & 0xff);
        this.pos += m[0].length;
      } else if (e === "c") {
        const ch = s[this.pos] ?? "";
        out += String.fromCharCode(ch.toUpperCase().charCodeAt(0) & 0x1f);
        this.pos++;
      } else {
        out += `\\${e}`;
      }
    }
    script.errors.push("unterminated $'...' string");
    return out;
  }

  private readDouble(w: Word, script: Script): void {
    const s = this.src;
    while (this.pos < s.length) {
      const c = s[this.pos] as string;
      if (c === '"') {
        this.pos++;
        return;
      }
      if (c === "\\") {
        const n = s[this.pos + 1] ?? "";
        if (n === "\n") {
          this.pos += 2;
          continue;
        }
        if ("$`\"\\".includes(n)) {
          w.text += n;
          this.pos += 2;
          continue;
        }
        w.text += c;
        this.pos++;
        continue;
      }
      if (c === "$") {
        this.readDollar(w, script);
        continue;
      }
      if (c === "`") {
        this.readBacktick(w, script);
        continue;
      }
      w.text += c;
      this.pos++;
    }
    script.errors.push("unterminated double quote");
  }

  readBacktick(w: Word, script: Script): void {
    const s = this.src;
    let i = this.pos + 1;
    let inner = "";
    while (i < s.length && s[i] !== "`") {
      if (s[i] === "\\" && (s[i + 1] === "`" || s[i + 1] === "\\" || s[i + 1] === "$")) {
        inner += s[i + 1];
        i += 2;
        continue;
      }
      inner += s[i];
      i++;
    }
    if (i >= s.length) script.errors.push("unterminated backtick");
    w.text += `\`${inner}\``;
    w.dynamic = true;
    w.subs.push(this.sub(inner));
    this.pos = Math.min(s.length, i + 1);
  }

  readDollar(w: Word, script: Script): void {
    const s = this.src;
    const n = s[this.pos + 1];
    // FZ2: "$((" is arithmetic only when bash reads it so; "$((cmd); cmd)" is a command substitution of a subshell.
    const arith = n === "(" && s[this.pos + 2] === "(" ? this.dparenEnd(this.pos + 3) : -1;
    if (arith !== -1) {
      const end = arith;
      const text = s.slice(this.pos + 3, end);
      const holder: SimpleCommand = newCommand();
      this.scanArithmetic(text, holder, script);
      if (holder.group !== undefined) w.subs.push(holder.group);
      w.text += s.slice(this.pos, end + 2);
      w.dynamic = true;
      this.pos = end + 2;
      return;
    }
    if (n === "[") {
      // SH1: `$[ expr ]` is the old form of arithmetic expansion. Like $(( )): not a command, but $(...) inside runs.
      const end = s.indexOf("]", this.pos + 2);
      const stop = end === -1 ? s.length : end;
      const holder: SimpleCommand = newCommand();
      this.scanArithmetic(s.slice(this.pos + 2, stop), holder, script);
      if (holder.group !== undefined) w.subs.push(holder.group);
      if (end === -1) script.errors.push("unterminated $[");
      w.text += s.slice(this.pos, Math.min(s.length, stop + 1));
      w.dynamic = true;
      this.pos = Math.min(s.length, stop + 1);
      return;
    }
    if (n === "(") {
      const start = this.pos;
      this.pos += 2;
      const inner = this.depth + 1 > MAX_DEPTH ? { pipelines: [], errors: ["nesting too deep to analyze"] } : this.nested(")");
      if (s[this.pos] === ")") this.pos++;
      else script.errors.push("unterminated $(");
      w.subs.push(inner);
      w.text += s.slice(start, this.pos);
      w.dynamic = true;
      return;
    }
    if (n === "{") {
      let depth = 0;
      let i = this.pos + 1;
      for (; i < s.length; i++) {
        if (s[i] === "{") depth++;
        else if (s[i] === "}") {
          depth--;
          if (depth === 0) break;
        }
      }
      const body = s.slice(this.pos + 2, i);
      const name = /^[!#]?([A-Za-z_][A-Za-z0-9_]*)/.exec(body);
      if (name !== null) w.vars.push(name[1] as string);
      // ${x:-$(cmd)} runs cmd.
      if (/\$\(|`/.test(body)) {
        const holder = newWord();
        const inner = new Parser(body, this.depth + 1);
        while (inner.pos < body.length) {
          const ch = body[inner.pos];
          if (ch === "$" && body[inner.pos + 1] === "(") inner.readDollar(holder, script);
          else if (ch === "`") inner.readBacktick(holder, script);
          else inner.pos++;
        }
        w.subs.push(...holder.subs);
      }
      if (i >= s.length) script.errors.push("unterminated ${");
      w.text += s.slice(this.pos, Math.min(s.length, i + 1));
      w.dynamic = true;
      this.pos = Math.min(s.length, i + 1);
      return;
    }
    const m = /^\$(?:([A-Za-z_][A-Za-z0-9_]*)|([0-9@*#?$!-]))/.exec(s.slice(this.pos));
    if (m !== null) {
      if (m[1] !== undefined) w.vars.push(m[1]);
      w.text += m[0];
      w.dynamic = true;
      this.pos += m[0].length;
      return;
    }
    w.text += "$";
    this.pos++;
  }
}

/** Every simple command in a script, depth-first, including those in groups and substitutions. */
export function allCommands(script: Script): SimpleCommand[] {
  const out: SimpleCommand[] = [];
  const visitWord = (w: Word): void => {
    for (const sub of w.subs) walk(sub);
  };
  const walk = (sc: Script): void => {
    for (const pl of sc.pipelines) {
      for (const cmd of pl.commands) {
        out.push(cmd);
        if (cmd.group !== undefined) walk(cmd.group);
        for (const w of cmd.words) visitWord(w);
        for (const a of cmd.assigns) visitWord(a.value);
        for (const r of cmd.redirects) if (r.target !== null) visitWord(r.target);
      }
    }
  };
  walk(script);
  return out;
}

/** Every pipeline in a script, including nested ones. */
export function allPipelines(script: Script): Pipeline[] {
  const out: Pipeline[] = [];
  const walk = (sc: Script): void => {
    for (const pl of sc.pipelines) {
      out.push(pl);
      for (const cmd of pl.commands) {
        if (cmd.group !== undefined) walk(cmd.group);
        for (const w of [...cmd.words, ...cmd.assigns.map((a) => a.value), ...cmd.redirects.flatMap((r) => (r.target === null ? [] : [r.target]))]) {
          for (const sub of w.subs) walk(sub);
        }
      }
    }
  };
  walk(script);
  return out;
}

export function allErrors(script: Script): string[] {
  const out = [...script.errors];
  const walk = (sc: Script): void => {
    for (const pl of sc.pipelines)
      for (const cmd of pl.commands) {
        if (cmd.group !== undefined) {
          out.push(...cmd.group.errors);
          walk(cmd.group);
        }
        for (const w of [...cmd.words, ...cmd.assigns.map((a) => a.value), ...cmd.redirects.flatMap((r) => (r.target === null ? [] : [r.target]))]) {
          for (const sub of w.subs) {
            out.push(...sub.errors);
            walk(sub);
          }
        }
      }
  };
  walk(script);
  return out;
}
