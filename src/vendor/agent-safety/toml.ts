// Not vendored: written in the LaunchSafe Agent Firewall (firewall audit I6) for its copy of
// LaunchSafe's agent-safety package, Apache-2.0. Upstream should take this file (and add it to the
// file list in scripts/sync-agent-safety.mjs) so Codex's config.toml and Gemini's command files are
// read by a real TOML parser everywhere.

/**
 * A TOML 1.0 reader (with TOML 1.1's newlines in inline tables) that gives the same line-numbered tree
 * as the JSONC reader, so the MCP server and settings checks read Codex's config.toml and Gemini CLI's
 * command files exactly like JSON. Multi-line strings and arrays, dotted and quoted keys, tables and
 * arrays of tables are all read; anything it cannot read is a failure the caller reports (an agent
 * reading the same file either reads it as this does or refuses it). Dates and times are kept as
 * strings. Pure and dependency-free.
 */
import type { JNode } from "./jsonc.js";

type TObject = Extract<JNode, { kind: "object" }>;
type TArray = Extract<JNode, { kind: "array" }>;
type Entry = TObject["entries"][number];

export type TomlResult = { ok: true; root: TObject } | { ok: false; line: number; reason: string };

class TomlError extends Error {
  constructor(
    readonly line: number,
    message: string,
  ) {
    super(message);
  }
}

/** Nesting deeper than this (arrays in arrays, inline tables in inline tables) is refused, not recursed into. */
const MAX_DEPTH = 256;

export function parseToml(text: string): TomlResult {
  const s = text.startsWith("﻿") ? text.slice(1) : text;
  const n = s.length;
  let i = 0;
  let line = 1;
  const fail = (reason: string): never => {
    throw new TomlError(line, reason);
  };
  const index = new WeakMap<TObject, Map<string, Entry>>();
  /** Tables a [header] defined, and inline tables and arrays (which nothing may extend later). */
  const defined = new WeakSet<TObject>();
  const frozen = new WeakSet<JNode>();
  const root: TObject = { kind: "object", line: 1, entries: [] };

  const lookup = (o: TObject, k: string): Entry | undefined => index.get(o)?.get(k);
  const put = (o: TObject, k: string, keyLine: number, value: JNode): void => {
    let m = index.get(o);
    if (m === undefined) {
      m = new Map();
      index.set(o, m);
    }
    if (m.has(k)) fail(`the key "${k.slice(0, 40)}" is set twice`);
    const e: Entry = { key: k, keyLine, value };
    m.set(k, e);
    o.entries.push(e);
  };

  const ws = (): void => {
    while (i < n && (s[i] === " " || s[i] === "\t")) i += 1;
  };
  const comment = (): void => {
    if (s[i] === "#") while (i < n && s[i] !== "\n") i += 1;
  };
  const newline = (): boolean => {
    if (s[i] === "\r" && s[i + 1] === "\n") {
      i += 2;
      line += 1;
      return true;
    }
    if (s[i] === "\n") {
      i += 1;
      line += 1;
      return true;
    }
    return false;
  };
  const eol = (): void => {
    ws();
    comment();
    if (i >= n) return;
    if (!newline()) fail("expected the end of the line");
  };
  const blank = (): void => {
    for (;;) {
      ws();
      comment();
      if (!newline()) return;
    }
  };

  const escape = (multi: boolean): string => {
    // At the backslash.
    const e = s[i + 1];
    i += 2;
    switch (e) {
      case "b":
        return "\b";
      case "t":
        return "\t";
      case "n":
        return "\n";
      case "f":
        return "\f";
      case "r":
        return "\r";
      case "e":
        return "\x1b";
      case '"':
        return '"';
      case "\\":
        return "\\";
      case "u":
      case "U": {
        const len = e === "u" ? 4 : 8;
        const hex = s.slice(i, i + len);
        if (!new RegExp(`^[0-9a-fA-F]{${len}}$`).test(hex)) fail("bad unicode escape");
        const cp = Number.parseInt(hex, 16);
        if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) fail("bad unicode escape");
        i += len;
        return String.fromCodePoint(cp);
      }
      default: {
        if (multi) {
          // A line-ending backslash: the newline and the whitespace after it are dropped.
          let j = i - 1;
          while (j < n && (s[j] === " " || s[j] === "\t")) j += 1;
          if (s[j] === "\n" || (s[j] === "\r" && s[j + 1] === "\n")) {
            i = j;
            for (;;) {
              ws();
              if (!newline()) break;
            }
            return "";
          }
        }
        return fail("bad escape");
      }
    }
  };

  const basic = (): string => {
    const multi = s.startsWith('"""', i);
    i += multi ? 3 : 1;
    if (multi) newline();
    const parts: string[] = [];
    for (;;) {
      if (i >= n) fail("unterminated string");
      const c = s[i] as string;
      if (multi && s.startsWith('"""', i)) {
        // Up to two quotes may end the content just before the closing three.
        let extra = 0;
        while (extra < 2 && s[i + 3 + extra] === '"') extra += 1;
        parts.push('"'.repeat(extra));
        i += 3 + extra;
        return parts.join("");
      }
      if (!multi && c === '"') {
        i += 1;
        return parts.join("");
      }
      if (c === "\\") parts.push(escape(multi));
      else if (c === "\n" || (c === "\r" && s[i + 1] === "\n")) {
        if (!multi) fail("newline in a string");
        parts.push("\n");
        newline();
      } else {
        parts.push(c);
        i += 1;
      }
    }
  };

  const literal = (): string => {
    const multi = s.startsWith("'''", i);
    i += multi ? 3 : 1;
    if (multi) newline();
    const parts: string[] = [];
    for (;;) {
      if (i >= n) fail("unterminated string");
      const c = s[i] as string;
      if (multi && s.startsWith("'''", i)) {
        let extra = 0;
        while (extra < 2 && s[i + 3 + extra] === "'") extra += 1;
        parts.push("'".repeat(extra));
        i += 3 + extra;
        return parts.join("");
      }
      if (!multi && c === "'") {
        i += 1;
        return parts.join("");
      }
      if (c === "\n" || (c === "\r" && s[i + 1] === "\n")) {
        if (!multi) fail("newline in a string");
        parts.push("\n");
        newline();
      } else {
        parts.push(c);
        i += 1;
      }
    }
  };

  const simpleKey = (): string => {
    ws();
    if (s[i] === '"') {
      if (s.startsWith('"""', i)) fail("a key cannot be a multi-line string");
      return basic();
    }
    if (s[i] === "'") {
      if (s.startsWith("'''", i)) fail("a key cannot be a multi-line string");
      return literal();
    }
    const start = i;
    while (i < n && /[A-Za-z0-9_-]/.test(s[i] as string)) i += 1;
    if (i === start) fail("expected a key");
    return s.slice(start, i);
  };
  const dottedKey = (): string[] => {
    const parts = [simpleKey()];
    for (;;) {
      ws();
      if (s[i] !== ".") return parts;
      i += 1;
      parts.push(simpleKey());
    }
  };

  /** Sets `keys` = `value` under `table`, creating the intermediate tables a dotted key names. */
  const assign = (table: TObject, keys: string[], keyLine: number, value: JNode): void => {
    let o = table;
    for (let k = 0; k < keys.length - 1; k += 1) {
      const key = keys[k] as string;
      const e = lookup(o, key);
      if (e === undefined) {
        const t: TObject = { kind: "object", line: keyLine, entries: [] };
        put(o, key, keyLine, t);
        o = t;
      } else if (e.value.kind === "object" && !frozen.has(e.value)) o = e.value;
      else fail(`the key "${key.slice(0, 40)}" is not a table`);
    }
    put(o, keys[keys.length - 1] as string, keyLine, value);
  };

  const value = (depth: number): JNode => {
    if (depth > MAX_DEPTH) fail("nested too deeply");
    const at = line;
    const c = s[i];
    if (c === '"') return { kind: "string", line: at, value: basic() };
    if (c === "'") return { kind: "string", line: at, value: literal() };
    if (c === "[") {
      i += 1;
      const node: TArray = { kind: "array", line: at, items: [] };
      for (;;) {
        blank();
        if (s[i] === "]") {
          i += 1;
          frozen.add(node);
          return node;
        }
        node.items.push(value(depth + 1));
        blank();
        if (s[i] === ",") i += 1;
        else if (s[i] !== "]") fail('expected a comma or "]"');
      }
    }
    if (c === "{") {
      i += 1;
      const node: TObject = { kind: "object", line: at, entries: [] };
      blank();
      if (s[i] === "}") {
        i += 1;
        frozen.add(node);
        return node;
      }
      for (;;) {
        blank();
        const keyLine = line;
        const keys = dottedKey();
        ws();
        if (s[i] !== "=") fail('expected "="');
        i += 1;
        ws();
        assign(node, keys, keyLine, value(depth + 1));
        blank();
        if (s[i] === ",") {
          i += 1;
          blank();
          if (s[i] === "}") {
            i += 1;
            break;
          }
          continue;
        }
        if (s[i] === "}") {
          i += 1;
          break;
        }
        fail('expected a comma or "}"');
      }
      // Nothing may add to an inline table later, nor to the tables inside it.
      const stack: JNode[] = [node];
      while (stack.length > 0) {
        const x = stack.pop() as JNode;
        frozen.add(x);
        if (x.kind === "object") for (const e of x.entries) stack.push(e.value);
      }
      return node;
    }
    if (s.startsWith("true", i) && !/[A-Za-z0-9_-]/.test(s[i + 4] ?? "")) {
      i += 4;
      return { kind: "boolean", line: at, value: true };
    }
    if (s.startsWith("false", i) && !/[A-Za-z0-9_-]/.test(s[i + 5] ?? "")) {
      i += 5;
      return { kind: "boolean", line: at, value: false };
    }
    const start = i;
    while (i < n && /[0-9A-Za-z_:+.-]/.test(s[i] as string)) i += 1;
    let token = s.slice(start, i);
    // A date and a time may be separated by a space.
    if (/^\d{4}-\d{2}-\d{2}$/.test(token) && s[i] === " " && /^\d{2}:/.test(s.slice(i + 1, i + 4))) {
      i += 1;
      const t = i;
      while (i < n && /[0-9A-Za-z_:+.-]/.test(s[i] as string)) i += 1;
      token = `${token} ${s.slice(t, i)}`;
    }
    if (/^\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:[Zz]|[+-]\d{2}:\d{2})?)?$|^\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/.test(token)) return { kind: "string", line: at, value: token };
    if (/^[+-]?(?:inf|nan)$/.test(token)) return { kind: "number", line: at, value: token.endsWith("nan") ? Number.NaN : token.startsWith("-") ? -Infinity : Infinity };
    if (/^0x[0-9a-fA-F](?:_?[0-9a-fA-F])*$|^0o[0-7](?:_?[0-7])*$|^0b[01](?:_?[01])*$/.test(token)) {
      const base = token[1] === "x" ? 16 : token[1] === "o" ? 8 : 2;
      return { kind: "number", line: at, value: Number.parseInt(token.slice(2).replace(/_/g, ""), base) };
    }
    if (/^[+-]?(?:0|[1-9](?:_?\d)*)(?:\.\d(?:_?\d)*)?(?:[eE][+-]?\d(?:_?\d)*)?$/.test(token)) return { kind: "number", line: at, value: Number(token.replace(/_/g, "")) };
    return fail(i >= n && token === "" ? "unexpected end of the file" : "unexpected value");
  };

  try {
    let current = root;
    for (;;) {
      blank();
      if (i >= n) break;
      if (s[i] === "[") {
        const headerLine = line;
        const many = s[i + 1] === "[";
        i += many ? 2 : 1;
        ws();
        const keys = dottedKey();
        ws();
        if (many ? !s.startsWith("]]", i) : s[i] !== "]") fail("unterminated table header");
        i += many ? 2 : 1;
        eol();
        let o = root;
        for (let k = 0; k < keys.length; k += 1) {
          const key = keys[k] as string;
          const last = k === keys.length - 1;
          const e = lookup(o, key);
          if (last && many) {
            let arr: TArray;
            if (e === undefined) {
              arr = { kind: "array", line: headerLine, items: [] };
              put(o, key, headerLine, arr);
            } else if (e.value.kind === "array" && !frozen.has(e.value)) arr = e.value;
            else return { ok: false, line: headerLine, reason: `"${key.slice(0, 40)}" is not an array of tables` };
            const t: TObject = { kind: "object", line: headerLine, entries: [] };
            arr.items.push(t);
            o = t;
          } else if (e === undefined) {
            const t: TObject = { kind: "object", line: headerLine, entries: [] };
            put(o, key, headerLine, t);
            o = t;
          } else if (e.value.kind === "object" && !frozen.has(e.value)) o = e.value;
          else if (e.value.kind === "array" && !frozen.has(e.value) && e.value.items[e.value.items.length - 1]?.kind === "object") o = e.value.items[e.value.items.length - 1] as TObject;
          else return { ok: false, line: headerLine, reason: `"${key.slice(0, 40)}" is not a table` };
        }
        if (!many) {
          if (defined.has(o)) return { ok: false, line: headerLine, reason: "a table is defined twice" };
          defined.add(o);
        }
        current = o;
        continue;
      }
      const keyLine = line;
      const keys = dottedKey();
      ws();
      if (s[i] !== "=") fail('expected "="');
      i += 1;
      ws();
      assign(current, keys, keyLine, value(0));
      eol();
    }
    return { ok: true, root };
  } catch (error) {
    if (error instanceof TomlError) return { ok: false, line: error.line, reason: error.message };
    throw error;
  }
}
