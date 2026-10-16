/**
 * A getopt-style reader for command arguments: which options take a value,
 * which words are positional. Unknown options are treated as flags, and the
 * analyzer never relies on a positional being "safe" because of that.
 */

import type { Word } from "./parse.js";

export interface OptSpec {
  /** Short options that take a value, e.g. "oHdXu" for curl. */
  short?: string;
  /** Long options that take a value (without leading dashes). */
  long?: readonly string[];
  /** Stop option parsing at the first positional (like `ssh host cmd`, `xargs cmd`). */
  stopAtPositional?: boolean;
}

export interface ParsedArgs {
  /** Option name (without dashes) to its values, in order. Flags get the value "". */
  opts: Map<string, string[]>;
  positionals: Word[];
  /** Index (in the input) of the first positional when stopAtPositional is set, else -1. */
  stopIndex: number;
}

export function parseArgs(args: readonly Word[], spec: OptSpec): ParsedArgs {
  const opts = new Map<string, string[]>();
  const positionals: Word[] = [];
  const put = (k: string, v: string): void => {
    const list = opts.get(k) ?? [];
    list.push(v);
    opts.set(k, list);
  };
  const short = spec.short ?? "";
  const long = new Set(spec.long ?? []);
  let stopIndex = -1;
  for (let i = 0; i < args.length; i++) {
    const w = args[i] as Word;
    const t = w.text;
    if (t === "--") {
      positionals.push(...args.slice(i + 1));
      break;
    }
    if (t.startsWith("--") && t.length > 2) {
      const eq = t.indexOf("=");
      const name = eq === -1 ? t.slice(2) : t.slice(2, eq);
      if (eq !== -1) put(name, t.slice(eq + 1));
      else if (long.has(name)) {
        put(name, args[i + 1]?.text ?? "");
        i++;
      } else put(name, "");
      continue;
    }
    if (t.startsWith("-") && t.length > 1 && !/^-\d/.test(t)) {
      for (let j = 1; j < t.length; j++) {
        const ch = t[j] as string;
        if (short.includes(ch)) {
          const rest = t.slice(j + 1);
          if (rest !== "") put(ch, rest);
          else {
            put(ch, args[i + 1]?.text ?? "");
            i++;
          }
          break;
        }
        put(ch, "");
      }
      continue;
    }
    positionals.push(w);
    if (spec.stopAtPositional === true) {
      stopIndex = i;
      positionals.push(...args.slice(i + 1));
      break;
    }
  }
  return { opts, positionals, stopIndex };
}

/**
 * The options a command wrapper (xargs, nice, env, timeout, sudo...) accepts before the program it runs. An
 * option it does not list is reported as unknown, never taken as the program's name.
 */
export interface WrapperSpec {
  /** Short options without a value. */
  flags?: string;
  /** Short options with a value, attached (`-n1`) or the next word (`-n 1`). */
  values?: string;
  /** Short options whose value can only be attached (`-i{}`, `-e`): alone, they take none. */
  optional?: string;
  longFlags?: readonly string[];
  /** Long options with a value, after `=` or the next word. */
  longValues?: readonly string[];
  /** Long options whose value can only follow `=` (`--replace[=R]`). */
  longOptional?: readonly string[];
  /** A number as an option (`nice -10`, `nice --5`). */
  numeric?: boolean;
}

export interface WrapperArgs {
  /** Option name (a short letter, or a long name in full) to its values; flags get "". */
  opts: Map<string, string[]>;
  /** The program and its arguments: everything after the options (and after `--`). */
  rest: Word[];
  /** Options the wrapper does not list, as written. */
  unknown: string[];
}

export function wrapperArgs(args: readonly Word[], spec: WrapperSpec): WrapperArgs {
  const opts = new Map<string, string[]>();
  const unknown: string[] = [];
  const put = (k: string, v: string): void => {
    const list = opts.get(k) ?? [];
    list.push(v);
    opts.set(k, list);
  };
  const flags = spec.flags ?? "";
  const vals = spec.values ?? "";
  const optional = spec.optional ?? "";
  const longs = [...(spec.longFlags ?? []), ...(spec.longValues ?? []), ...(spec.longOptional ?? [])];
  /** getopt_long accepts an unambiguous prefix of a long option. */
  const longName = (n: string): string | null => {
    if (longs.includes(n)) return n;
    const hits = longs.filter((l) => l.startsWith(n));
    return n !== "" && hits.length === 1 ? (hits[0] as string) : null;
  };
  for (let i = 0; i < args.length; i++) {
    const t = (args[i] as Word).text;
    if (t === "--") return { opts, rest: args.slice(i + 1), unknown };
    if (spec.numeric === true && /^--?\d+$/.test(t)) {
      put("adjustment", t.replace(/^-(?=-)/, ""));
      continue;
    }
    if (t.startsWith("--")) {
      const eq = t.indexOf("=");
      const raw = eq === -1 ? t.slice(2) : t.slice(2, eq);
      const name = longName(raw);
      if (name === null) {
        unknown.push(t);
        continue;
      }
      if ((spec.longValues ?? []).includes(name)) {
        if (eq !== -1) put(name, t.slice(eq + 1));
        else put(name, args[++i]?.text ?? "");
      } else if ((spec.longOptional ?? []).includes(name)) put(name, eq === -1 ? "" : t.slice(eq + 1));
      else {
        if (eq !== -1) unknown.push(t);
        put(name, "");
      }
      continue;
    }
    if (t.startsWith("-") && t.length > 1) {
      for (let j = 1; j < t.length; j++) {
        const ch = t[j] as string;
        if (vals.includes(ch)) {
          const attached = t.slice(j + 1);
          put(ch, attached !== "" ? attached : (args[++i]?.text ?? ""));
          break;
        }
        if (optional.includes(ch)) {
          put(ch, t.slice(j + 1));
          break;
        }
        if (!flags.includes(ch)) unknown.push(`-${ch}`);
        put(ch, "");
      }
      continue;
    }
    return { opts, rest: args.slice(i), unknown };
  }
  return { opts, rest: [], unknown };
}

export function has(p: Pick<ParsedArgs, "opts">, ...names: string[]): boolean {
  return names.some((n) => p.opts.has(n));
}

export function values(p: Pick<ParsedArgs, "opts">, ...names: string[]): string[] {
  return names.flatMap((n) => p.opts.get(n) ?? []);
}
