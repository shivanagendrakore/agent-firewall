/**
 * Vault: the reference grammar and the per-secret destination rules (pure).
 */
import { describe, expect, it } from "vitest";
import { bindingSummary, egressBound, entriesIn, findRefs, formatRef, hostBindingMatches, isValidName, parseRef, processBindingMatches, resolveRef, toolMatches, validHostPattern, type VaultView } from "../../src/engine/vault-ref.js";
import { fingerprint } from "../../src/engine/secrets.js";
import type { Effect } from "../../src/types.js";
import { OPAQUE } from "./fake.js";

const view: VaultView = {
  signed: true,
  entries: [
    { name: "github/token", kind: "credential", fields: ["value"], bindings: [{ kind: "host", host: "api.github.com" }], fingerprints: { value: fingerprint(OPAQUE) as string } },
    { name: "bank/primary", kind: "iban", fields: ["iban", "bic", "holder"], bindings: [{ kind: "host", host: "*.bank.example" }], fingerprints: {} },
  ],
};

describe("reference grammar", () => {
  it("finds references with and without a field, inside quotes and JSON strings", () => {
    const t = `curl -H "Authorization: Bearer vault://github/token" -d '{"iban":"vault://bank/primary#iban"}'`;
    expect(findRefs(t).map((r) => [r.name, r.field])).toEqual([
      ["github/token", undefined],
      ["bank/primary", "iban"],
    ]);
    expect(findRefs(JSON.stringify({ a: "vault://mcp/linear" })).map((r) => r.text)).toEqual(["vault://mcp/linear"]);
  });
  it("VFP2: needs a word boundary before vault:// (a URL path is not a reference)", () => {
    expect(findRefs("https://example.com/vault://docs")).toEqual([]);
    expect(findRefs("x.vault://a")).toEqual([]);
    expect(findRefs("see vault://docs.")).toHaveLength(1);
  });
  it("names are 1 to 4 lower-case segments; fields [a-z0-9_]{1,32}", () => {
    expect(isValidName("github/token")).toBe(true);
    expect(isValidName("a/b/c/d")).toBe(true);
    expect(isValidName("a/b/c/d/e")).toBe(false);
    expect(isValidName("GitHub/token")).toBe(false);
    expect(isValidName("-x")).toBe(false);
    expect(isValidName("a//b")).toBe(false);
    expect(findRefs("vault://a/b/c/d/e")).toEqual([]);
    expect(findRefs("vault://Upper")).toEqual([]);
    expect(findRefs(`vault://x#${"f".repeat(33)}`)).toEqual([]);
    expect(parseRef("vault://bank/primary#iban")?.field).toBe("iban");
    expect(parseRef("vault://bank/primary trailing")).toBeNull();
    expect(formatRef("bank/primary", "iban")).toBe("vault://bank/primary#iban");
  });
  it("V17: an unknown name or field is an unknown reference, never a value", () => {
    expect(resolveRef({ name: "github/tokn" }, view)).toEqual({ ok: false, reason: "no such secret: vault://github/tokn" });
    expect(resolveRef({ name: "bank/primary", field: "pin" }, view).ok).toBe(false);
    expect(resolveRef({ name: "bank/primary" }, view).ok).toBe(false);
    expect(resolveRef({ name: "github/token" }, view)).toMatchObject({ ok: true, field: "value" });
    expect(resolveRef({ name: "github/token" }, undefined).ok).toBe(false);
  });
});

describe("binding matchers", () => {
  it("host: exact, or subdomains for *.; never the apex through *.", () => {
    expect(hostBindingMatches("api.github.com", "API.github.com.")).toBe(true);
    expect(hostBindingMatches("api.github.com", "evil-api.github.com")).toBe(false);
    expect(hostBindingMatches("api.github.com", "api.github.com.attacker.example")).toBe(false);
    expect(hostBindingMatches("*.bank.example", "api.bank.example")).toBe(true);
    expect(hostBindingMatches("*.bank.example", "bank.example")).toBe(false);
    expect(validHostPattern("*")).toBe(false);
    expect(validHostPattern("*.com")).toBe(false);
    expect(validHostPattern("*.bank.example")).toBe(true);
    expect(validHostPattern("https://x.com")).toBe(false);
  });
  it("process: word for word; * only as a whole trailing word; never a bare * program", () => {
    expect(processBindingMatches(["npm", "publish"], ["npm", "publish"])).toBe(true);
    expect(processBindingMatches(["npm", "publish"], ["npm", "publish", "--tag", "x"])).toBe(false);
    expect(processBindingMatches(["gh", "pr", "*"], ["gh", "pr", "create", "--fill"])).toBe(true);
    expect(processBindingMatches(["gh", "pr", "*"], ["gh", "issue"])).toBe(false);
    expect(processBindingMatches(["*"], ["anything"])).toBe(false);
    expect(processBindingMatches(["gh", "*", "x"], ["gh", "a", "x"])).toBe(false);
  });
  it("mcp tool patterns are globs", () => {
    expect(toolMatches(undefined, "anything")).toBe(true);
    expect(toolMatches("create_*", "create_issue")).toBe(true);
    expect(toolMatches("create_*", "delete_issue")).toBe(false);
    expect(toolMatches("create_*", undefined)).toBe(false);
  });
  it("summaries name the destination and nothing secret", () => {
    expect(bindingSummary({ kind: "host", host: "api.github.com", allowInUrl: true })).toBe("host api.github.com (also in the URL)");
    expect(bindingSummary({ kind: "mcp", server: "linear", tool: "create_*" })).toBe("mcp linear:create_*");
    expect(bindingSummary({ kind: "process", argv: ["npm", "publish"], display: "npm publish" })).toBe("process npm publish");
  });
});

describe("egressBound", () => {
  const entry = view.entries[0] as (typeof view.entries)[number];
  const send = (over: Partial<Effect>): Effect => ({ cls: "egress_send", target: "https://api.github.com/user", host: "api.github.com", detail: "send", payload: OPAQUE, ...over });
  it("a host binding binds its host over https; a value in the URL needs allowInUrl; plain http needs allowHttp", () => {
    expect(egressBound(entry, send({}), view)).toBe(true);
    expect(egressBound(entry, send({ host: "attacker.example", target: "https://attacker.example/" }), view)).toBe(false);
    expect(egressBound(entry, send({ target: `https://api.github.com/user?t=${OPAQUE}` }), view)).toBe(false);
    const inUrl = { ...entry, bindings: [{ kind: "host" as const, host: "api.github.com", allowInUrl: true }] };
    expect(egressBound(inUrl, send({ target: `https://api.github.com/user?t=${OPAQUE}` }), view)).toBe(true);
    expect(egressBound(entry, send({ target: "http://api.github.com/user" }), view)).toBe(false);
    const allowHttp = { ...entry, bindings: [{ kind: "host" as const, host: "api.github.com", allowHttp: true }] };
    expect(egressBound(allowHttp, send({ target: "http://api.github.com/user" }), view)).toBe(true);
    expect(egressBound(allowHttp, send({ target: "ftp://api.github.com/user" }), view)).toBe(false);
  });
  it("an mcp binding binds its server, tool pattern and optional argument path", () => {
    const mcp = { ...entry, bindings: [{ kind: "mcp" as const, server: "linear", tool: "create_*" }] };
    const call = (tool: string, payload = OPAQUE): Effect => ({ cls: "egress_fetch", target: "mcp:linear", detail: "args", payload, tags: ["mcp-args", "mcp-call:linear", `mcp-tool:${tool}`] });
    expect(egressBound(mcp, call("create_issue"), view)).toBe(true);
    expect(egressBound(mcp, call("delete_issue"), view)).toBe(false);
    expect(egressBound(mcp, { ...call("create_issue"), tags: ["mcp-args", "mcp-call:other", "mcp-tool:create_issue"] }, view)).toBe(false);
    const mcpArg = { ...entry, bindings: [{ kind: "mcp" as const, server: "linear", tool: "create_*", arg: "headers.token" }] };
    expect(egressBound(mcpArg, call("create_issue"), view)).toBe(false);
    expect(egressBound(mcpArg, call("create_issue", JSON.stringify({ title: OPAQUE })), view)).toBe(false);
    expect(egressBound(mcpArg, call("create_issue", JSON.stringify({ headers: { token: OPAQUE }, title: OPAQUE })), view)).toBe(false);
    expect(egressBound(mcpArg, call("create_issue", JSON.stringify({ headers: { token: OPAQUE }, title: "bug" })), view)).toBe(true);
  });
  it("process bindings and oauth entries never bind an egress effect; an unsigned index binds nothing", () => {
    const proc = { ...entry, bindings: [{ kind: "process" as const, argv: ["curl", "*"], display: "curl *" }] };
    expect(egressBound(proc, send({}), view)).toBe(false);
    const oauth = { ...entry, kind: "oauth" as const, bindings: [{ kind: "host" as const, host: "api.github.com" }, { kind: "mcp" as const, server: "linear" }] };
    expect(egressBound(oauth, send({}), view)).toBe(false);
    expect(egressBound(oauth, { cls: "egress_fetch", target: "mcp:linear", detail: "args", payload: OPAQUE, tags: ["mcp-args", "mcp-call:linear", "mcp-tool:create_issue"] }, view)).toBe(false);
    expect(egressBound(entry, send({}), { ...view, signed: false })).toBe(false);
  });
  it("entriesIn finds a value in the clear, base64 and URL-encoded, and nothing in unrelated text", () => {
    expect(entriesIn(`x=${OPAQUE}`, view).map((e) => e.name)).toEqual(["github/token"]);
    expect(entriesIn(Buffer.from(OPAQUE).toString("base64"), view)).toHaveLength(1);
    expect(entriesIn(encodeURIComponent(`k=${OPAQUE}&`), view)).toHaveLength(1);
    expect(entriesIn("nothing here at all, just text", view)).toEqual([]);
    expect(entriesIn(OPAQUE, undefined)).toEqual([]);
  });
});
