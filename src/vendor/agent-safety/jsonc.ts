// Vendored from LaunchSafe's agent-safety package (src/jsonc.ts), Apache-2.0, at commit fc329d4314dc07a65da266a1256b1da0d17ec97c.
// Licence: Apache-2.0 (see NOTICE).
// Transform: add ".js" to relative import specifiers.
// Do not edit here: it is copied from the upstream package by
// `node scripts/sync-agent-safety.mjs` (`--check` verifies the copy).

// DIVERGES FROM UPSTREAM (firewall audit B2/B3): the parser is iterative (no depth limit, no
// recursion), reports where and why it failed (parseJsoncResult), and converts a tree to plain
// values without recursion (jsonValueOf). Upstream should take these changes; until then
// `sync-agent-safety.mjs --check` with the product checkout reports this file as drift.

/**
 * A small, tolerant JSON-with-comments reader that remembers the line of
 * every value. Agent configuration is JSON (`.mcp.json`,
 * `.claude/settings.json`) or JSONC (`.vscode/*.json`: comments and trailing
 * commas), and a finding has to point at the exact line, so a plain
 * `JSON.parse` is not enough. Pure and dependency-free: it runs in the
 * browser too (the free paste checker).
 *
 * It accepts everything the agents accept (JSON, comments, trailing commas, a
 * byte order mark) and walks the text with an explicit stack, so a deeply
 * nested file cannot exhaust the call stack: a file it cannot read is
 * reported by the caller, never skipped.
 */

export type JNode =
  | { kind: "object"; line: number; entries: { key: string; keyLine: number; value: JNode }[] }
  | { kind: "array"; line: number; items: JNode[] }
  | { kind: "string"; line: number; value: string }
  | { kind: "number"; line: number; value: number }
  | { kind: "boolean"; line: number; value: boolean }
  | { kind: "null"; line: number };

/** A byte order mark and the Unicode line and paragraph separators, as whitespace (written as code points on purpose). */
const BOM = String.fromCharCode(0xfeff);
const LS = String.fromCharCode(0x2028);
const PS = String.fromCharCode(0x2029);

type JObject = Extract<JNode, { kind: "object" }>;
type JArray = Extract<JNode, { kind: "array" }>;

export type JsoncResult = { ok: true; root: JNode } | { ok: false; line: number; reason: string };

class ParseError extends Error {
  constructor(
    readonly line: number,
    message: string,
  ) {
    super(message);
  }
}

interface Frame {
  node: JObject | JArray;
  /** What comes next: a key (objects), a value, or a comma or the closing bracket. */
  expect: "key" | "value" | "next";
  key?: string;
  keyLine?: number;
}

/** Parses JSON or JSONC, saying where and why it stopped when the text is not valid. */
export function parseJsoncResult(text: string): JsoncResult {
  let i = 0;
  let line = 1;
  const n = text.length;
  const fail = (reason: string): never => {
    throw new ParseError(line, reason);
  };

  const skip = (): void => {
    while (i < n) {
      const c = text[i];
      if (c === "\n") {
        line += 1;
        i += 1;
      } else if (c === " " || c === "\t" || c === "\r" || c === BOM || c === LS || c === PS) i += 1;
      else if (c === "/" && text[i + 1] === "/") {
        while (i < n && text[i] !== "\n") i += 1;
      } else if (c === "/" && text[i + 1] === "*") {
        const start = line;
        i += 2;
        while (i < n && !(text[i] === "*" && text[i + 1] === "/")) {
          if (text[i] === "\n") line += 1;
          i += 1;
        }
        if (i >= n) throw new ParseError(start, "unterminated comment");
        i += 2;
      } else break;
    }
  };

  const str = (): string => {
    // At the opening quote.
    i += 1;
    const parts: string[] = [];
    let from = i;
    while (i < n) {
      const c = text[i] as string;
      if (c === '"') {
        parts.push(text.slice(from, i));
        i += 1;
        return parts.join("");
      }
      if (c === "\n") fail("newline in a string");
      if (c === "\\") {
        parts.push(text.slice(from, i));
        const e = text[i + 1];
        i += 2;
        if (e === "n") parts.push("\n");
        else if (e === "t") parts.push("\t");
        else if (e === "r") parts.push("\r");
        else if (e === "b") parts.push("\b");
        else if (e === "f") parts.push("\f");
        else if (e === "u") {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("bad \\u escape");
          parts.push(String.fromCharCode(Number.parseInt(hex, 16)));
          i += 4;
        } else if (e === undefined) fail("unterminated string");
        else parts.push(e);
        from = i;
        continue;
      }
      i += 1;
    }
    return fail("unterminated string");
  };

  const scalar = (): JNode => {
    const at = line;
    const c = text[i];
    if (c === '"') return { kind: "string", line: at, value: str() };
    if (text.startsWith("true", i)) {
      i += 4;
      return { kind: "boolean", line: at, value: true };
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return { kind: "boolean", line: at, value: false };
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return { kind: "null", line: at };
    }
    const num = /^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(i, i + 64));
    if (num !== null) {
      i += num[0].length;
      return { kind: "number", line: at, value: Number(num[0]) };
    }
    return fail(i >= n ? "unexpected end of the file" : "unexpected character");
  };

  const stack: Frame[] = [];
  let root: JNode | undefined;
  const attach = (v: JNode): void => {
    const top = stack[stack.length - 1];
    if (top === undefined) {
      root = v;
      return;
    }
    if (top.node.kind === "array") top.node.items.push(v);
    else top.node.entries.push({ key: top.key ?? "", keyLine: top.keyLine ?? v.line, value: v });
    top.expect = "next";
  };

  try {
    for (;;) {
      skip();
      const top = stack[stack.length - 1];
      if (top === undefined && root !== undefined) break;
      const c = text[i];
      if (top !== undefined && top.expect === "next") {
        const close = top.node.kind === "object" ? "}" : "]";
        if (c === ",") {
          i += 1;
          top.expect = top.node.kind === "object" ? "key" : "value";
        } else if (c === close) {
          i += 1;
          stack.pop();
          attach(top.node);
        } else fail(i >= n ? "unexpected end of the file" : `expected a comma or "${close}"`);
        continue;
      }
      if (top !== undefined && top.node.kind === "object" && top.expect === "key") {
        // An empty object, or a trailing comma before the closing brace (JSONC).
        if (c === "}") {
          i += 1;
          stack.pop();
          attach(top.node);
          continue;
        }
        if (c !== '"') fail(i >= n ? "unexpected end of the file" : "expected a key");
        top.keyLine = line;
        top.key = str();
        skip();
        if (text[i] !== ":") fail("expected a colon");
        i += 1;
        top.expect = "value";
        continue;
      }
      if (top !== undefined && top.node.kind === "array" && c === "]") {
        // An empty array, or a trailing comma (JSONC).
        i += 1;
        stack.pop();
        attach(top.node);
        continue;
      }
      if (c === "{") {
        const node: JObject = { kind: "object", line, entries: [] };
        i += 1;
        stack.push({ node, expect: "key" });
      } else if (c === "[") {
        const node: JArray = { kind: "array", line, items: [] };
        i += 1;
        stack.push({ node, expect: "value" });
      } else attach(scalar());
    }
    skip();
    if (i < n) fail("text after the end of the document");
    return { ok: true, root: root as JNode };
  } catch (error) {
    if (error instanceof ParseError) return { ok: false, line: error.line, reason: error.message };
    throw error;
  }
}

/** Parses JSON or JSONC. Returns null when the text is not valid (callers report that as a finding). */
export function parseJsonc(text: string): JNode | null {
  const r = parseJsoncResult(text);
  return r.ok ? r.root : null;
}

/**
 * A tree as plain values (objects, arrays, strings, numbers, booleans, null), the way JSON.parse
 * gives them: a repeated key keeps its last value, and a key such as "__proto__" is an ordinary own
 * property. Iterative, so any depth the parser accepted converts.
 */
export function jsonValueOf(node: JNode): unknown {
  const scalarOf = (x: JNode): unknown => (x.kind === "object" ? {} : x.kind === "array" ? [] : x.kind === "null" ? null : x.value);
  const out = scalarOf(node);
  const work: { from: JNode; to: unknown }[] = [{ from: node, to: out }];
  while (work.length > 0) {
    const { from, to } = work.pop() as { from: JNode; to: unknown };
    if (from.kind === "object") {
      for (const e of from.entries) {
        const v = scalarOf(e.value);
        Object.defineProperty(to as object, e.key, { value: v, enumerable: true, writable: true, configurable: true });
        if (e.value.kind === "object" || e.value.kind === "array") work.push({ from: e.value, to: v });
      }
    } else if (from.kind === "array") {
      for (const item of from.items) {
        const v = scalarOf(item);
        (to as unknown[]).push(v);
        if (item.kind === "object" || item.kind === "array") work.push({ from: item, to: v });
      }
    }
  }
  return out;
}

/** The value under a key of an object node, or undefined. */
export function member(node: JNode | undefined, key: string): JNode | undefined {
  if (node?.kind !== "object") return undefined;
  for (let k = node.entries.length - 1; k >= 0; k -= 1) {
    const entry = node.entries[k];
    if (entry?.key === key) return entry.value;
  }
  return undefined;
}

export function entriesOf(node: JNode | undefined): { key: string; keyLine: number; value: JNode }[] {
  return node?.kind === "object" ? node.entries : [];
}

export function itemsOf(node: JNode | undefined): JNode[] {
  return node?.kind === "array" ? node.items : [];
}

export function stringOf(node: JNode | undefined): string | null {
  return node?.kind === "string" ? node.value : null;
}

/** Every string in an array node, skipping anything else. */
export function stringsOf(node: JNode | undefined): string[] {
  return itemsOf(node).flatMap((item) => (item.kind === "string" ? [item.value] : []));
}
