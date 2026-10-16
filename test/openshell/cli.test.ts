/**
 * `openshell serve` and `openshell policy` from the command line: who may start the middleware, what it
 * refuses before it listens, and the policy it prints (docs/sandboxes.md).
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { isReadOnlyInvocation } from "../../src/cliargs.js";
import { main } from "../../src/climain.js";
import { layout } from "../../src/runtime/layout.js";
import { isLoopbackHost, OPENSHELL_HANDLERS, parseHostPort } from "../../src/openshell-cli.js";
import { bash, explain, tempHome } from "../helpers.js";

function cli(args: string[], human = true, policy: Record<string, unknown> = { version: 3, fetchAllowHosts: ["docs.example.com"], sendAllowHosts: [] }): Promise<{ code: number; out: string; err: string }> {
  const home = tempHome("oscli-");
  const l = layout(join(home, ".launchsafe-firewall"));
  mkdirSync(l.home, { recursive: true, mode: 0o700 });
  writeFileSync(l.policy, JSON.stringify(policy));
  let out = "";
  let err = "";
  return main(args, l, { write: (fd, s) => void (fd === 1 ? (out += s) : (err += s)), humanAtKeyboard: async () => human }).then((code) => ({ code, out, err }));
}

describe("openshell serve: refusals before anything listens", () => {
  it("an agent may not start it (FW-TAMPER from a tool call; refused in an agent session)", async () => {
    const d = bash("launchsafe-firewall openshell serve --insecure --listen 0.0.0.0:50051");
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).toContain("FW-TAMPER");
    expect(isReadOnlyInvocation(["openshell", "serve"])).toBe(false);
    expect(isReadOnlyInvocation(["openshell", "policy"])).toBe(true);
    const r = await cli(["openshell", "serve"], false);
    expect(r.code).toBe(1);
    expect(r.err).toContain("inside an agent session");
  });
  it("a non-loopback address needs TLS and the gateway's key, or --insecure; the TLS flags go together", async () => {
    const r = await cli(["openshell", "serve", "--listen", "0.0.0.0:50051"]);
    expect(r.code).toBe(64);
    expect(r.err).toContain("without TLS and the gateway's key");
    const partial = await cli(["openshell", "serve", "--tls-cert", "c.pem"]);
    expect(partial.code).toBe(64);
    expect(partial.err).toContain("go together");
    expect((await cli(["openshell", "serve", "--listen", "nonsense"])).code).toBe(64);
  });
  it("without an API token it says how to make one, and listens on nothing", async () => {
    const saved = process.env.LAUNCHSAFE_FIREWALL_API_TOKEN;
    delete process.env.LAUNCHSAFE_FIREWALL_API_TOKEN;
    try {
      const r = await cli(["openshell", "serve"]);
      expect(r.code).toBe(1);
      expect(r.err).toContain("api token add openshell");
    } finally {
      if (saved !== undefined) process.env.LAUNCHSAFE_FIREWALL_API_TOKEN = saved;
    }
  });
  it("parses HOST:PORT and knows loopback", () => {
    expect(parseHostPort("127.0.0.1:50051")).toEqual({ host: "127.0.0.1", port: 50051 });
    expect(parseHostPort("[::1]:9")).toEqual({ host: "::1", port: 9 });
    expect(() => parseHostPort("host:0")).toThrow();
    expect(isLoopbackHost("127.0.0.1") && isLoopbackHost("::1") && isLoopbackHost("localhost")).toBe(true);
    expect(isLoopbackHost("0.0.0.0") || isLoopbackHost("host.openshell.internal")).toBe(false);
  });
});

describe("openshell policy", () => {
  it("prints the policy from the user's firewall policy, with the agent's model API and the middleware", async () => {
    const r = await cli(["openshell", "policy", "--agent", "codex", "--endpoint", "https://fw.internal:50051"]);
    expect(r.code, r.err).toBe(0);
    expect(r.out).toContain('host: "docs.example.com"');
    expect(r.out).toContain('host: "api.openai.com"');
    expect(r.out).toContain('grpc_endpoint = "https://fw.internal:50051"');
    expect(r.out).toContain("network_middlewares:");
  });
  it("--no-middleware, and a refused --send-host", async () => {
    expect((await cli(["openshell", "policy", "--no-middleware"])).out).not.toContain("network_middlewares");
    const bad = await cli(["openshell", "policy", "--send-host", "169.254.169.254"]);
    expect(bad.code).toBe(1);
    expect(bad.err).toContain("cannot be admitted");
  });
});

describe("review fixes", () => {
  it("--no-middleware with a deny only the middleware enforces warns loudly on standard error, and a control character in --send-host is refused", async () => {
    const r = await cli(["openshell", "policy", "--no-middleware"], true, { version: 3, fetchAllowHosts: ["github.com"], sendAllowHosts: [], denyHosts: ["gist.github.com"] });
    expect(r.code, r.err).toBe(0);
    expect(r.err).toContain('WARNING: without the middleware nothing refuses "gist.github.com"');
    expect(r.out).toContain("# WARNING:");
    const bad = await cli(["openshell", "policy", "--send-host", "x.example\n# injected"]);
    expect(bad.code).toBe(1);
    expect(bad.err).toContain("control character");
  });

  it("serve without TLS warns on every start, on loopback too: unverified callers, and approvals anyone can use up", async () => {
    const home = tempHome("oscli-");
    const l = layout(join(home, ".launchsafe-firewall"));
    mkdirSync(l.home, { recursive: true, mode: 0o700 });
    let out = "";
    let err = "";
    const port = 40000 + Math.floor(Math.random() * 20000);
    const parsed = { kind: "ok", flags: new Map<string, string | true>([["--listen", `127.0.0.1:${port}`]]), positionals: [] } as unknown as Parameters<NonNullable<(typeof OPENSHELL_HANDLERS)["openshell serve"]>>[0];
    const code = await (OPENSHELL_HANDLERS["openshell serve"] as NonNullable<(typeof OPENSHELL_HANDLERS)["openshell serve"]>)(parsed, l, {
      out: (s) => void (out += s),
      err: (s) => void (err += s),
      notAgent: async () => true,
      cwd: home,
      env: {},
      client: { decide: async () => ({ decisionId: "d", verdict: "allow", rules: [] }), result: async () => ({}), input: async () => undefined },
      onListening: (stop) => stop(),
    });
    expect(code, err).toBe(0);
    expect(out).toContain("plaintext, callers not verified");
    expect(err).toContain("WARNING: plaintext, callers not verified");
    expect(err).toContain("every process on this machine");
    expect(err).toContain("use up a person's approval");
  });
});
