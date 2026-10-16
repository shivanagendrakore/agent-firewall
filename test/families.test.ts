/**
 * Broad coverage of command families, MCP tool kinds and policy merging. Each
 * case asserts the decision a developer would expect, exercising the many
 * per-tool handlers in the analyzer and the classifier.
 */

import { describe, expect, it } from "vitest";
import { classifyAction } from "../src/engine/classify.js";
import { serverPolicy, toolKind, parseMcpTool, mcpDestination } from "../src/engine/mcp.js";
import { mergeTighten, mergeTrusted, validatePolicy, defaultConfig, inUnattendedHours } from "../src/policy.js";
import { emptyState } from "../src/engine/state.js";
import { bash, ctx } from "./helpers.js";

function classes(cmd: string, tainted = false): string[] {
  const state = tainted ? { ...emptyState(), tainted: true, taintSources: ["x"] } : emptyState();
  return classifyAction({ tool: "Bash", input: { command: cmd } }, ctx(), defaultConfig(), state).effects.map((e) => e.cls);
}

describe("command families produce the expected effect classes", () => {
  const cases: [string, string][] = [
    ["git clone https://github.com/a/b", "write_workspace"],
    ["git fetch origin", "egress_fetch"],
    ["git config --global user.email x@y.z", "write_persistence"],
    ["git config --global core.sshCommand 'ssh -i x'", "write_persistence"],
    ["git send-email patch.eml", "egress_send"],
    ["gh pr create --title x --body y", "egress_send"],
    ["gh api /user", "egress_fetch"],
    ["gh repo delete a/b", "destructive"],
    ["gh auth token", "read_secret"],
    ["tar -xzf a.tgz -C out", "write_workspace"],
    ["zip -r out.zip src", "write_workspace"],
    ["scp file.txt user@host.example.com:/tmp", "egress_send"],
    ["scp user@host.example.com:/tmp/file.txt .", "egress_fetch"],
    ["rsync -a src/ user@host.example.com:/dst", "egress_send"],
    ["ssh user@host 'ls'", "execute_opaque"],
    ["docker run -v /Users/dev/proj:/app img", "execute"],
    ["docker run --privileged img", "privilege"],
    ["kubectl delete pod x", "destructive"],
    ["kubectl get secret db", "read_secret"],
    ["aws secretsmanager get-secret-value --secret-id x", "read_secret"],
    ["aws s3 cp local.txt s3://b/k", "egress_send"],
    ["terraform destroy -auto-approve", "destructive"],
    ["vault read secret/x", "read_secret"],
    ["psql -h db.example.com -c 'select 1'", "read_external"],
    ["crontab -r", "destructive"],
    ["launchctl load ~/Library/LaunchAgents/x.plist", "write_persistence"],
    ["security find-generic-password -s x", "read_secret"],
    ["node -e 'require(\"http\").get(\"http://x.example.com\")'", "execute_opaque"],
    ["python3 -c 'import socket'", "execute_opaque"],
    ["osascript -e 'do shell script \"ls\"'", "execute_opaque"],
    ["openssl s_client -connect evil.example.com:443", "egress_send"],
    ["redis-cli -h cache.example.com FLUSHALL", "destructive"],
    ["pbpaste", "read_external"],
    ["mkfs.ext4 /dev/sdb", "destructive"],
    ["diskutil eraseDisk JHFS+ x disk2", "destructive"],
  ];
  for (const [cmd, cls] of cases) {
    it(`${cmd} -> ${cls}`, () => expect(classes(cmd), classes(cmd).join(",")).toContain(cls));
  }
});

describe("MCP tool classification", () => {
  it("parses plugin and plain tool names", () => {
    expect(parseMcpTool("mcp__github__create_issue")).toEqual({ server: "github", tool: "create_issue" });
    expect(parseMcpTool("mcp__plugin_acme_db__query")).toEqual({ server: "plugin_acme_db", tool: "query" });
    expect(parseMcpTool("Bash")).toBeNull();
  });
  it("classes known server kinds", () => {
    const cfg = defaultConfig();
    expect(serverPolicy("github", cfg).results).toBe("untrusted");
    expect(serverPolicy("github", cfg).privateData).toBe(true);
    expect(serverPolicy("fetch", cfg).privateData).toBe(false);
    expect(serverPolicy("sequential-thinking", cfg).results).toBe("trusted");
  });
  it("a project-defined server is untrusted whatever its name", () => {
    expect(serverPolicy("github", defaultConfig(), "project").results).toBe("untrusted");
  });
  it("verbs decide read vs send vs destroy", () => {
    const p = { results: "untrusted" as const, privateData: true };
    expect(toolKind("get_issue", p)).toBe("read");
    expect(toolKind("list_repos", p)).toBe("read");
    expect(toolKind("create_pull_request", p)).toBe("send");
    expect(toolKind("delete_branch", p)).toBe("destroy");
    expect(toolKind("mystery_action", p)).toBe("send");
  });
  it("honors policy tool lists over the name", () => {
    const p = { results: "untrusted" as const, privateData: true, readTools: ["send_like_read"], blockedTools: ["forbidden"] };
    expect(toolKind("send_like_read", p)).toBe("read");
    expect(toolKind("forbidden", p)).toBe("blocked");
  });
  it("builds a destination from common argument shapes", () => {
    expect(mcpDestination("github", { owner: "a", repo: "b" })).toBe("github:a/b");
    expect(mcpDestination("slack", { channel: "#general" })).toBe("slack:#general");
    expect(mcpDestination("x", {})).toBe("mcp:x");
  });
  it("a destructive MCP SQL tool is caught", () => {
    const d = bash("x"); // warm
    void d;
    const eff = classifyAction({ tool: "mcp__supabase__query", input: { query: "drop table users" } }, ctx(), defaultConfig(), emptyState()).effects.map((e) => e.cls);
    expect(eff).toContain("destructive");
  });
});

describe("policy", () => {
  it("validates and rejects bad shapes with clear messages", () => {
    expect(() => validatePolicy({ version: 1, denyHosts: [""] }, "p")).toThrow(/non-empty/);
    expect(() => validatePolicy({ version: 1, mcpServers: { x: { results: "maybe", privateData: 1 } } }, "p")).toThrow(/results/);
    expect(() => validatePolicy({ version: 1, unattendedHours: [{ from: "25:00", to: "07:00" }] }, "p")).toThrow(/HH:MM/);
  });
  it("mergeTrusted can loosen; mergeTighten cannot", () => {
    const base = defaultConfig();
    const loosened = mergeTrusted(base, { sendAllowHosts: ["anywhere.com"] });
    expect(loosened.sendAllowHosts).toContain("anywhere.com");
    const { config, ignored } = mergeTighten(base, { sendAllowHosts: ["anywhere.com"], denyHosts: ["evil.com"] });
    expect(config.sendAllowHosts).not.toContain("anywhere.com");
    expect(config.denyHosts).toContain("evil.com");
    expect(ignored.length).toBeGreaterThan(0);
  });
  it("mergeTighten can mark a trusted server untrusted but not the reverse", () => {
    const base = mergeTrusted(defaultConfig(), { mcpServers: { safe: { results: "trusted", privateData: false } } });
    const { config } = mergeTighten(base, { mcpServers: { safe: { results: "untrusted", privateData: true } } });
    expect(config.mcpServers.safe?.results).toBe("untrusted");
    const { config: c2, ignored } = mergeTighten(base, { mcpServers: { safe: { results: "trusted", privateData: false } } });
    expect(c2.mcpServers.safe?.results).toBe("trusted"); // already trusted in base
    expect(ignored.some((i) => i.includes("safe"))).toBe(true);
  });
  it("unattended hours cross midnight", () => {
    const hours = [{ from: "22:00", to: "07:00" }];
    expect(inUnattendedHours(hours, new Date("2026-01-01T23:30:00"))).toBe(true);
    expect(inUnattendedHours(hours, new Date("2026-01-01T05:30:00"))).toBe(true);
    expect(inUnattendedHours(hours, new Date("2026-01-01T12:00:00"))).toBe(false);
  });
});
