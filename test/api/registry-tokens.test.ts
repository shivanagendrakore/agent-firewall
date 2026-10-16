/**
 * The API's tool registry (validated as strictly as the library's tool specs, `map` dot paths only) and its
 * token store (only SHA-256 kept, revocation, constant-shape lookup).
 */

import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { tokensPath } from "../../src/api/files.js";
import { parseRegistry, readRegistry, toolSpecs, valueAt, writeRegistry } from "../../src/api/registry.js";
import { addToken, agentOfToken, bearer, readTokens, revokeTokens } from "../../src/api/tokens.js";
import { toAction } from "../../src/sdk/tools.js";
import { apiTree, REGISTRY, removeApiTree, type ApiTree } from "./harness.js";

describe("tool registry", () => {
  it("accepts the contract's example and maps `as` tools through their dot paths", () => {
    const r = parseRegistry(REGISTRY);
    const specs = toolSpecs(r);
    expect(toAction({ tool: "run_shell", input: { cmd: "ls", other: 1 } }, specs).action).toEqual({ tool: "Bash", input: { command: "ls" } });
    expect(toAction({ tool: "http_get", input: { url: "https://example.com" } }, specs).action).toEqual({ tool: "WebFetch", input: { url: "https://example.com" } });
    expect(toAction({ tool: "send_email", input: { to: "a@b.example" } }, specs).action.tool).toBe("mcp__send_email__send_email");
    expect(toAction({ tool: "get_customer", input: {} }, specs).action.tool).toBe("mcp__crm__get_customer");
    // A missing path leaves the field out.
    expect(toAction({ tool: "run_shell", input: {} }, specs).action).toEqual({ tool: "Bash", input: {} });
  });

  it("dot paths read own properties only", () => {
    expect(valueAt({ a: { b: 2 } }, "$.a.b")).toBe(2);
    expect(valueAt({ a: {} }, "$.a.toString")).toBeUndefined();
    expect(valueAt({ a: [1] }, "$.a.length")).toBeUndefined();
    expect(valueAt("x", "$.length")).toBeUndefined();
  });

  const bad: [string, unknown, RegExp][] = [
    ["not an object", [], /must be an object/],
    ["no tools", {}, /needs "tools"/],
    ["an unknown top-level field", { tools: {}, version: 2 }, /unknown field "version"/],
    ["both as and kind", { tools: { t: { as: "Bash", kind: "read" } } }, /either "as" or "kind"/],
    ["neither", { tools: { t: { results: "trusted" } } }, /needs "as"/],
    ["a bad kind", { tools: { t: { kind: "write" } } }, /kind must be/],
    ["an unknown spec field", { tools: { t: { kind: "read", dataClasses: ["pii"] } } }, /unknown field "dataClasses"/],
    ["an unknown as field", { tools: { t: { as: "Bash", input: {} } } }, /unknown field "input"/],
    ["a bracket path", { tools: { t: { as: "Bash", map: { command: "$.args[0]" } } } }, /dot path/],
    ["a filter path", { tools: { t: { as: "Bash", map: { command: "$..cmd" } } } }, /dot path/],
    ["a bare $", { tools: { t: { as: "Bash", map: { command: "$" } } } }, /dot path/],
    ["a non-string path", { tools: { t: { as: "Bash", map: { command: 3 } } } }, /dot path/],
    ["a bad field name", { tools: { t: { as: "Bash", map: { "a-b": "$.x" } } } }, /not a field name/],
    ["a glob in a kind tool name", { tools: { "send*": { kind: "send" } } }, /glob|\*/],
    ["servers that disagree", { tools: { a: { kind: "read", server: "s", results: "trusted" }, b: { kind: "read", server: "s", results: "untrusted" } } }, /disagree/],
    ["results not an enum", { tools: { t: { kind: "read", results: "maybe" } } }, /results must be/],
    ["privateData not a boolean", { tools: { t: { kind: "read", privateData: "yes" } } }, /privateData must be/],
    ["an empty tool name", { tools: { "": { kind: "read" } } }, /not valid/],
  ];
  for (const [name, doc, why] of bad) it(`refuses ${name}`, () => expect(() => parseRegistry(doc)).toThrow(why));

  it("__proto__ as a tool or map field is data, not the prototype", () => {
    const r = parseRegistry(JSON.parse('{"tools":{"__proto__":{"kind":"read"},"x":{"as":"Bash","map":{"command":"$.__proto__"}}}}'));
    expect(Object.keys(r.tools)).toEqual(["__proto__", "x"]);
    expect(({} as Record<string, unknown>).kind).toBeUndefined();
  });

  describe("stored per agent", () => {
    let t: ApiTree;
    beforeEach(() => {
      t = apiTree();
    });
    afterEach(() => removeApiTree(t));

    it("written normalized, read back, and absent for another agent", () => {
      writeRegistry(t.l, "bot", REGISTRY);
      expect(readRegistry(t.l, "bot")).toEqual(REGISTRY);
      expect(readRegistry(t.l, "other")).toBeNull();
      expect(() => writeRegistry(t.l, "../escape", REGISTRY)).toThrow(/not valid/);
      expect(() => writeRegistry(t.l, "bot", { tools: { t: { kind: "nope" } } })).toThrow();
      expect(readRegistry(t.l, "bot")).toEqual(REGISTRY);
    });
  });
});

describe("tokens", () => {
  let t: ApiTree;
  beforeEach(() => {
    t = apiTree();
  });
  afterEach(() => removeApiTree(t));

  it("a new token is returned once; the file holds only its SHA-256, mode 0600", () => {
    const tok = addToken(t.l, "bot");
    expect(tok).toMatch(/^lsfw_[A-Za-z0-9_-]{43}$/);
    const text = readFileSync(tokensPath(t.l), "utf8");
    expect(text).not.toContain(tok);
    expect(text).not.toContain(tok.slice(5, 20));
    expect(readTokens(t.l)).toEqual([{ agent: "bot", hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/), createdAt: expect.any(String) }]);
    expect(agentOfToken(readTokens(t.l), tok)).toBe("bot");
  });

  it("a wrong, malformed or revoked token names no agent; revoke removes every token of that agent only", () => {
    const a1 = addToken(t.l, "bot");
    const a2 = addToken(t.l, "bot");
    const b = addToken(t.l, "other");
    const recs = readTokens(t.l);
    expect(agentOfToken(recs, a2)).toBe("bot");
    expect(agentOfToken(recs, `${a1.slice(0, -1)}${a1.endsWith("A") ? "B" : "A"}`)).toBeNull();
    expect(agentOfToken(recs, "lsfw_short")).toBeNull();
    expect(agentOfToken(recs, "")).toBeNull();
    expect(revokeTokens(t.l, "bot")).toBe(2);
    expect(revokeTokens(t.l, "bot")).toBe(0);
    const after = readTokens(t.l);
    expect(agentOfToken(after, a1)).toBeNull();
    expect(agentOfToken(after, b)).toBe("other");
  });

  it("refuses bad agent ids and parses only Bearer headers", () => {
    for (const bad of ["", "a/b", "../x", "-x", "a".repeat(65), "a b", "a..b"]) expect(() => addToken(t.l, bad), bad).toThrow(/not valid/);
    expect(bearer("Bearer abc")).toBe("abc");
    for (const h of [undefined, "", "bearer abc", "Basic abc", "Bearer ", "Bearer a b"]) expect(bearer(h)).toBeNull();
  });
});
