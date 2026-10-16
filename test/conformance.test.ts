/**
 * The API conformance vectors (conformance/README.md) stay true: every recorded step is what the in-process
 * library gives now. A changed verdict or rule set fails here until `npm run conformance:generate` is run and
 * the change is reviewed in the diff of conformance/vectors. Also checks the vector set itself (shape,
 * coverage, the same vectors conformance/author writes) and the contract translation.
 */

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { groups } from "../conformance/author/index.js";
import { runVectorRoutes, type Vector } from "../conformance/run.js";
import { translateDecide, translateRegistry, UNREGISTERED_PREFIX } from "../conformance/translate.js";
import { RULES } from "../src/rules.js";
import { SCENARIOS } from "../src/scenarios.js";

const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "conformance", "vectors");
const files = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
const texts = new Map(files.map((f) => [f, readFileSync(join(dir, f), "utf8")]));
const vectors: Vector[] = files.flatMap((f) => JSON.parse(texts.get(f) ?? "[]") as Vector[]);

/**
 * Rules no vector can show, and why. Every other rule id in src/rules.ts must appear in some vector's recorded
 * rules; a rule listed here must not (so the list shrinks when a vector starts covering one).
 */
const API_OR_TRANSPORT = "the API's or the SDK's own answer to a transport or memory condition (an unreachable or failing sidecar, a rate limit, a forgotten decision), not a verdict on a request; tested by the transport tests";
const GATEWAY_MAIL = "emitted by the MCP gateway or the mail guard on traffic they relay, never by decide";
const SIGNED_STATE = "needs state a person signs with the approval key (the vault index, learned choices, MCP tool pins), which a vector cannot carry without a key in the vectors";
const UNCOVERED: Record<string, string> = {
  "FW-UNAVAILABLE": API_OR_TRANSPORT,
  "FW-RATE-LIMITED": API_OR_TRANSPORT,
  "FW-API-ERROR": API_OR_TRANSPORT,
  "FW-RESULT-UNRECORDED": API_OR_TRANSPORT,
  "FW-LOG-UNRECORDED": "needs a log store that refuses to record (a store failure), which no environment the vectors fix has",
  "FW-HIDDEN-OUTPUT": "not a rule in any decision of the library or the API (the hook logs it); its effect, a result with hidden characters making the session untrusted, is pinned by rule-hidden-output-*",
  "FW-LEARNED-ALLOW": SIGNED_STATE,
  "FW-LEARNED-DENY": SIGNED_STATE,
  "FW-MCP-CHANGED": SIGNED_STATE,
  "FW-VAULT-EGRESS": SIGNED_STATE,
  "FW-VAULT-UNBOUND": SIGNED_STATE,
  "FW-VAULT-INDEX": SIGNED_STATE,
  "FW-VAULT-UNSUPPORTED": SIGNED_STATE,
  "FW-VAULT-OPTION": SIGNED_STATE,
  "FW-VAULT-APPROVE": SIGNED_STATE,
  "FW-MCP-TOOL-HELD": GATEWAY_MAIL,
  "FW-MCP-WITHHELD": GATEWAY_MAIL,
  "FW-MCP-SAMPLING": GATEWAY_MAIL,
  "FW-MCP-METHOD": GATEWAY_MAIL,
  "FW-MCP-AUTH": GATEWAY_MAIL,
  "FW-MAIL-WITHHELD": GATEWAY_MAIL,
};

describe("conformance vectors: the library gives the recorded verdicts", () => {
  for (const v of vectors) {
    it(v.id, () => {
      const got = runVectorRoutes(v);
      expect(got.expects).toEqual(v.steps.map((s) => s.expect));
      // Where the API answers otherwise by design (its request limits), that answer is recorded too.
      expect(got.api).toEqual(v.steps.map((s) => s.expectApi));
    });
  }
});

/** A step's request as an object: the invalid-body-* vectors send JSON null and an array on purpose. */
const body = (s: { request: unknown }): Record<string, unknown> => (typeof s.request === "object" && s.request !== null && !Array.isArray(s.request) ? (s.request as Record<string, unknown>) : {});

describe("conformance vectors: the set", () => {
  const decides = vectors.flatMap((v) => v.steps.filter((s) => s.kind === "decide"));
  const formats = new Set(decides.map((s) => (body(s).action as { format?: string } | undefined)?.format));
  const verdicts = new Set(decides.map((s) => s.expect.verdict));
  const rules = new Set(decides.flatMap((s) => s.expect.ruleIds ?? []));

  it("is a sensible size, with unique ids and well-formed steps", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(150);
    expect(vectors.length).toBeLessThanOrEqual(800);
    expect(new Set(vectors.map((v) => v.id)).size).toBe(vectors.length);
    for (const v of vectors) {
      expect(v.description, v.id).not.toBe("");
      // Each description stands alone: no "the same ..." pointing at another vector.
      expect(v.description, v.id).not.toMatch(/^the same\b/i);
      expect(v.steps.length, v.id).toBeGreaterThan(0);
      v.steps.forEach((s, i) => {
        expect(["decide", "result", "input", "prompt", "approve"], `${v.id} step ${i}`).toContain(s.kind);
        if (s.token !== undefined) expect(["agent", "network"], `${v.id} step ${i}`).toContain(s.token);
        if (s.expectApi !== undefined) expect(i, `${v.id}: expectApi only on the last step`).toBe(v.steps.length - 1);
        const ref = body(s).decisionId;
        if (typeof ref === "string" && s.expect.error === undefined) {
          const n = Number(/^@step:(\d+)$/.exec(ref)?.[1]);
          expect(n, `${v.id} step ${i}`).toBeLessThan(i);
          expect(v.steps[n]?.kind, `${v.id} step ${i}`).toBe("decide");
        }
        if (s.kind === "decide" && s.expect.error === undefined) {
          expect(s.expect.ruleIds, `${v.id} step ${i}`).toEqual([...(s.expect.ruleIds ?? [])].sort());
        }
      });
    }
  });

  it("is what the authoring files write: every authored vector is recorded, in its file and order, and nothing else is", () => {
    const authored = groups();
    expect(Object.keys(authored).map((g) => `${g}.json`).sort()).toEqual(files);
    for (const [g, skeletons] of Object.entries(authored)) {
      const recorded = (JSON.parse(texts.get(`${g}.json`) ?? "[]") as Vector[]).map((v) => v.id);
      expect(recorded, `${g}.json is stale: run npm run conformance:generate`).toEqual(skeletons.map((s) => s.id));
    }
    expect(authored.rules?.map((s) => s.id)).toContain("rule-hidden-output-zwsp-run");
  });

  it("covers every rule in src/rules.ts, or says why it cannot", () => {
    const recorded = new Set(vectors.flatMap((v) => v.steps.flatMap((s) => [...(s.expect.ruleIds ?? []), ...(s.expectApi?.ruleIds ?? [])])));
    for (const id of Object.keys(RULES)) {
      if (id in UNCOVERED) expect(recorded.has(id), `${id} is covered now: take it off the exemption list`).toBe(false);
      else expect(recorded.has(id), `${id}: no vector records it; add one, or add it to UNCOVERED with the reason`).toBe(true);
    }
    for (const [id, why] of Object.entries(UNCOVERED)) {
      expect(RULES[id], `${id} is not a rule`).toBeDefined();
      expect(why.length, id).toBeGreaterThan(20);
    }
    // Every recorded rule is one the catalogue documents.
    for (const id of recorded) expect(RULES[id], id).toBeDefined();
  });

  it("is ASCII on disk: every other character is a \\u escape", () => {
    for (const [f, text] of texts) expect(/[^\t\n\r\x20-\x7e]/.test(text), f).toBe(false);
  });

  it("sends network traffic only with the network token, and has both kinds of network vector", () => {
    const network = vectors.flatMap((v) => v.steps.filter((s) => s.kind === "decide" && (body(s).context as { traffic?: string } | undefined)?.traffic === "network"));
    expect(network.some((s) => s.token === "network" && s.expect.verdict !== undefined)).toBe(true);
    expect(network.some((s) => s.token !== "network" && s.expect.error === 400)).toBe(true);
    for (const s of network) if (s.token !== "network") expect(s.expect).toEqual({ error: 400 });
  });

  it("covers every format, every verdict and the rule families", () => {
    for (const f of ["native", "engine", "openai.chat", "anthropic", "mcp"]) expect(formats.has(f), f).toBe(true);
    for (const x of ["allow", "ask", "hold", "deny"]) expect(verdicts.has(x as never), x).toBe(true);
    for (const r of ["FW-SEND", "FW-MESSAGE", "FW-DLP-CREDENTIAL", "FW-CREDENTIAL-READ", "FW-DESTRUCTIVE", "FW-DESTROY-ROOT", "FW-UNKNOWN-TOOL", "FW-BLOCKED-TOOL", "FW-FETCH", "FW-INSTALL", "FW-INSTRUCTIONS-HELD", "FW-TAMPER", "FW-APPROVED"]) expect(rules.has(r), r).toBe(true);
  });

  it("covers every tool-spec kind, as with and without map, attended and unattended, dryRun and the refusals", () => {
    const entries = vectors.flatMap((v) => Object.values(v.agentTools.tools));
    for (const k of ["read", "send", "destroy", "blocked"]) expect(entries.some((e) => "kind" in e && e.kind === k), k).toBe(true);
    expect(entries.some((e) => "as" in e && e.map !== undefined)).toBe(true);
    expect(entries.some((e) => "as" in e && e.map === undefined)).toBe(true);
    expect(entries.some((e) => "kind" in e && e.results === "trusted")).toBe(true);
    expect(entries.some((e) => "kind" in e && e.privateData === false)).toBe(true);
    expect(decides.some((s) => (body(s).context as { attended?: boolean } | undefined)?.attended === false)).toBe(true);
    expect(decides.some((s) => body(s).dryRun === true)).toBe(true);
    expect(decides.some((s) => s.expect.error === 400)).toBe(true);
    for (const k of ["result", "input", "prompt", "approve"]) expect(vectors.some((v) => v.steps.some((s) => s.kind === k)), k).toBe(true);
  });

  it("covers the rules that need a prepared environment (setup)", () => {
    const prepared = vectors.filter((v) => v.setup !== undefined);
    expect(prepared.length).toBeGreaterThanOrEqual(40);
    const pr = new Set(prepared.flatMap((v) => v.steps.flatMap((s) => s.expect.ruleIds ?? [])));
    for (const r of ["FW-CANARY-READ", "FW-CANARY-EGRESS", "FW-MALICIOUS-PACKAGE", "FW-TYPOSQUAT", "FW-BUDGET-REQUESTS", "FW-BUDGET-BYTES", "FW-BUDGET-MCP", "FW-LOOP", "FW-SCOPE", "FW-AUTORUN", "FW-INSTRUCTIONS", "FW-INSTRUCTIONS-HELD", "FW-SECRET-FILE-PUBLISH", "FW-CAPTURE-HOST", "FW-CAP", "FW-CAP-WARN", "FW-NEW-HOST", "FW-STOPPED", "FW-OUTSIDE-COMMAND"]) expect(pr.has(r), r).toBe(true);
    for (const k of ["files", "decoys", "policy", "budgets", "packages"]) expect(prepared.some((v) => v.setup?.[k as keyof typeof v.setup] !== undefined), k).toBe(true);
    expect(prepared.some((v) => v.steps.some((s) => s.expect.redacted !== undefined))).toBe(true);
    // Paths in a prepared vector are the tree's placeholders, never a real directory.
    for (const v of prepared) expect(JSON.stringify(v), v.id).not.toMatch(/\/(?:Users|private|var\/folders|tmp)\//);
  });

  it("the incident vectors stop what the incident scenarios say must be stopped", () => {
    for (const s of SCENARIOS) {
      const v = vectors.find((x) => x.id === `incident-${s.id.toLowerCase()}`);
      expect(v, s.id).toBeDefined();
      const decided = (v?.steps ?? []).filter((x) => x.kind === "decide");
      const pres = s.steps.filter((x) => x.event.hook_event_name === "PreToolUse");
      expect(decided.length, s.id).toBe(pres.length);
      pres.forEach((st, i) => {
        if (st.expect === undefined) return;
        const got = decided[i]?.expect.verdict === "hold" ? "queue" : decided[i]?.expect.verdict;
        expect(st.expect, `${s.id} step ${i}`).toContain(got);
        if (st.rule !== undefined) expect(decided[i]?.expect.ruleIds, `${s.id} step ${i}`).toContain(st.rule);
      });
    }
  });
});

describe("conformance translation (docs/api-v0.md)", () => {
  const names = ["run_shell"];
  const dec = (action: Record<string, unknown>) => translateDecide({ session: "s", action }, names);

  it("openai.chat: the arguments are parsed, the call id is the raw id", () => {
    const t = dec({ format: "openai.chat", raw: { id: "call_9", type: "function", function: { name: "run_shell", arguments: '{"cmd":"ls"}' } } });
    expect(t).toMatchObject({ ok: true, call: { tool: "run_shell", input: { cmd: "ls" }, callId: "call_9" }, useRegistry: true });
  });
  it("anthropic: the tool_use block is read", () => {
    const t = dec({ format: "anthropic", raw: { type: "tool_use", id: "toolu_1", name: "run_shell", input: { cmd: "ls" } } });
    expect(t).toMatchObject({ ok: true, call: { tool: "run_shell", input: { cmd: "ls" }, callId: "toolu_1" } });
  });
  it("mcp: the engine sees mcp__<server>__<tool>, with the source, and no registry", () => {
    const t = dec({ format: "mcp", tool: "send", input: {}, mcp: { server: "gmail", source: "user" } });
    expect(t).toMatchObject({ ok: true, call: { tool: "mcp__gmail__send", mcpSource: "user" }, useRegistry: false });
  });
  it("native: a tool the registry does not list is named so no engine tool can match it", () => {
    expect(dec({ format: "native", tool: "Bash", input: {} })).toMatchObject({ ok: true, call: { tool: `${UNREGISTERED_PREFIX}Bash` } });
    expect(dec({ format: "engine", tool: "Bash", input: {} })).toMatchObject({ ok: true, call: { tool: "Bash" }, useRegistry: false });
  });
  it("refuses what the contract refuses", () => {
    expect(dec({ format: "native", tool: "x", input: {}, extra: 1 })).toMatchObject({ ok: false, status: 400 });
    expect(dec({ format: "openai.chat", raw: { id: "c", type: "function", function: { name: "x", arguments: "nope" } } })).toMatchObject({ ok: false, status: 400 });
    expect(translateDecide({ session: "s", action: { format: "native", tool: "x", input: {} }, more: 1 }, [])).toMatchObject({ ok: false, status: 400 });
  });
  it("registry: map is dot paths only, and an entry is a kind or an as", () => {
    expect(translateRegistry({ tools: { a: { as: "Bash", map: { command: "$.a.b" } } } }).ok).toBe(true);
    expect(translateRegistry({ tools: { a: { as: "Bash", map: { command: "$.a[0]" } } } }).ok).toBe(false);
    expect(translateRegistry({ tools: { a: { as: "Bash", map: { command: "$..a" } } } }).ok).toBe(false);
    expect(translateRegistry({ tools: { a: { kind: "send", as: "Bash" } } }).ok).toBe(false);
    expect(translateRegistry({ tools: { a: { kind: "mail" } } }).ok).toBe(false);
    expect(translateRegistry({ tools: { a: { kind: "send", server: "x" } } }).ok).toBe(false);
  });
});
