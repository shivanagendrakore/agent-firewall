/**
 * Independent review of v0.3, the vault lane: substitution, FW-VAULT-EGRESS and run --env tickets.
 * Each case was an it.fails in the review; kept as a regression test now the finding is fixed.
 * Placeholders only (the fake TOKEN from test/vault/fake.ts); no store, keychain or network is touched.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { fingerprint } from "../../src/engine/secrets.js";
import type { VaultView } from "../../src/engine/vault-ref.js";
import { planShellRewrite } from "../../src/engine/vault-shell.js";
import { scrubOutput } from "../../src/hook/vault.js";
import { OutputScrubber, runTicketed } from "../../src/runtime/run/vault-env.js";
import { substituteJson } from "../../src/runtime/vault/substitute.js";
import type { Context } from "../../src/types.js";
import { bash, explain, run, type RunOpts } from "../helpers.js";
import { TOKEN } from "../vault/fake.js";

const view = (): VaultView => ({
  signed: true,
  entries: [
    { name: "github/token", kind: "credential", fields: ["value"], confirm: "never", bindings: [{ kind: "host", host: "api.github.com" }], fingerprints: { value: fingerprint(TOKEN) as string } },
    { name: "mcp/linear", kind: "credential", fields: ["value"], confirm: "never", bindings: [{ kind: "mcp", server: "linear", tool: "create_*", arg: "token" }], fingerprints: {} },
  ],
});
const o = (over: Partial<Context> = {}, rest: Omit<RunOpts, "ctx"> = {}): RunOpts => ({ ...rest, ctx: { vault: view(), vaultPaths: { shellRewrite: true, gatewayServers: ["linear"] }, ...over } });
const H = '-H "Authorization: Bearer vault://github/token"';
const reverse = (s: string): string => [...s].reverse().join("");

/** curl --trace's format: offset, 16 hex bytes, then the same 16 bytes as text ("." for non-printables). */
function curlTrace(data: string): string {
  const buf = Buffer.from(data, "utf8");
  const lines = [`=> Send header, ${buf.length} bytes (0x${buf.length.toString(16)})`];
  for (let i = 0; i < buf.length; i += 16) {
    const row = buf.subarray(i, i + 16);
    const hex = [...row].map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
    const txt = [...row].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${i.toString(16).padStart(4, "0")}: ${hex} ${txt}`);
  }
  return `${lines.join("\n")}\n`;
}

/** Whether the token can be read back from a curl --trace dump (its hex columns, joined). */
function tokenInTrace(out: string): boolean {
  const hex = [...out.matchAll(/^[0-9a-f]{4}: ((?:[0-9a-f]{2} )+)/gm)].map((m) => (m[1] ?? "").replace(/ /g, "")).join("");
  return Buffer.from(hex, "hex").toString("utf8").includes(TOKEN);
}

describe("review v0.3: the vault", () => {
  it("V1 vault (VA1): the substitution variable is readable by the rest of the rewritten command (echo \"$__LSV_1\" | rev)", async () => {
    // docs/vault.md:11-12 "scrubs it back to the reference in everything the model reads"; the engine refuses
    // `echo vault://…` because "the value would be put where the agent could read it" (vault-checks.ts:58-64),
    // but the agent can name the variable the rewrite creates: it is in the environment of the whole /bin/sh -c script.
    const cmd = `curl ${H} https://api.github.com/user; echo "$__LSV_1" | rev`;
    const d = bash(cmd, o());
    let model = "";
    if (d.verdict === "allow") {
      const plan = planShellRewrite(cmd);
      if (!plan.ok) throw new Error(plan.why);
      // Run what the hook's ticketed run would run, with curl stubbed out (no network): only the echo | rev part matters.
      const script = plan.command.replace(/^curl[^;]*;/, "true;");
      await runTicketed({ argv: ["/bin/sh", "-c", script], base: { PATH: "/usr/bin:/bin" }, extra: { __LSV_1: TOKEN }, values: [{ ref: "vault://github/token", value: TOKEN }], cwd: process.cwd(), stdout: (t) => (model += t), stderr: (t) => (model += t) });
      const hook = scrubOutput({ stdout: model }, model, view());
      if (hook !== undefined) model = hook;
    }
    expect(reverse(model), explain(d)).not.toContain(TOKEN);
  });

  it("V16 vault (VA2): curl --trace - on a bound reference shows the value to the model as a hex dump (run filter and PostToolUse miss it)", () => {
    // docs/run.md:234-236 "The child's output is filtered back to the references (every value and its encodings,
    // also across chunks) before the agent reads it; PostToolUse scrubs again." docs/vault.md:200-201 "output in
    // which a value is still detectable is replaced by a withheld note".
    // Since the option allowlist, curl --trace is refused before anything runs (FW-VAULT-OPTION); the filters
    // below stay as the second line, for a trace that reaches the output some other way.
    const cmd = `curl --trace - ${H} https://api.github.com/user`;
    const d = bash(cmd, o());
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).toContain("FW-VAULT-OPTION");
    const trace = curlTrace(`GET /user HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer ${TOKEN}\r\n\r\n`);
    const f = new OutputScrubber([{ ref: "vault://github/token", value: TOKEN }]);
    let model = f.push(trace) + f.end();
    model = scrubOutput({ stdout: model }, model, view()) ?? model;
    expect(tokenInTrace(model)).toBe(false);
  });

  it("V17 vault (VA3): an MCP argument binding (linear:create_*:token) is bypassed past refPaths' caps: the value is also put into another argument", () => {
    // docs/vault.md:33 `--mcp S[:tool[:arg]]`; vault-checks.ts:110 refuses a reference "not as argument <path>".
    // refPaths stops after 1000 references or 64 levels (vault-ref.ts:191), substituteJson replaces every string.
    for (const input of [
      { token: "vault://mcp/linear ".repeat(1001).trim(), description: "vault://mcp/linear" },
      { token: "vault://mcp/linear", description: JSON.parse(`${"[".repeat(70)}"vault://mcp/linear"${"]".repeat(70)}`) as unknown },
    ]) {
      const d = run("mcp__linear__create_issue", input, o());
      const sent = d.verdict === "allow" ? substituteJson(input, [{ ref: "vault://mcp/linear", value: TOKEN }]) : input;
      expect(JSON.stringify(sent.description), explain(d)).not.toContain(TOKEN);
    }
  });

  it("V42 docs (VA4): the docs still says substitution is not built, while docs/vault.md and the CHANGELOG say it is", () => {
    // docs/vault.md:14-18 "Built: ... substitution: through the MCP gateway (every client), and through the hooks";
    // CHANGELOG 0.3.0-dev "the vault's substitution hookup" and run --env merged.
    const readme = readFileSync(new URL("../../docs/how-it-works.md", import.meta.url), "utf8");
    const section = readme.slice(readme.indexOf("### Secrets by reference"), readme.indexOf("### The MCP gateway"));
    expect(section).not.toMatch(/not built yet/);
  });
});
