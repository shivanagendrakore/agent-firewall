/**
 * Gateway false-positive table (GFP1-GFP8): ordinary MCP
 * results and tool lists must not be blocked, withheld or hidden.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Json } from "../../src/gateway/jsonrpc.js";
import { tailLog } from "../../src/runtime/log.js";
import { loadPins } from "../../src/runtime/pins.js";
import { listRecords } from "../../src/runtime/quarantine.js";
import { REPO } from "../helpers.js";
import { gw, NOTES_TOOLS, textOf } from "./harness.js";

const READ_TOOL = [{ name: "read_file", description: "Read a file.", inputSchema: { type: "object", properties: { path: { type: "string" } } } }];

function deliver(server: string, text: string, structured?: unknown) {
  const g = gw({ server, cfg: { era: "modern", tools: READ_TOOL, results: { read_file: { content: [{ type: "text", text }], ...(structured !== undefined ? { structuredContent: structured } : {}) } } } });
  g.call("tools/list");
  const r = g.call("tools/call", { name: "read_file", arguments: { path: "x" } });
  return { g, r, content: (r.result?.content ?? []) as Json[] };
}

describe("gateway false positives", () => {
  it("GFP1: this repository's README and docs (they discuss prompt injection in visible prose) are delivered, at most annotated", () => {
    for (const f of ["README.md", "docs/threat-model.md", "docs/design.md", "SECURITY.md"]) {
      const text = readFileSync(join(REPO, f), "utf8");
      const { g, content } = deliver("filesystem", text);
      expect(listRecords(g.l).records, f).toHaveLength(0);
      const body = content.filter((c) => !String(c.text).startsWith("Note from LaunchSafe Firewall"));
      expect(body[0]?.text, f).toBe(text);
    }
  });

  it("GFP2: a GitHub issue with emoji, an England flag sequence and Hindi with ZWJ/ZWNJ is delivered unchanged", () => {
    const text = "Thanks 👍🏽 great work! 👩‍💻 from 🏴󠁧󠁢󠁥󠁮󠁧󠁿 — नमस्‍ते क्‌ष ✔️";
    const { content, g } = deliver("github", text);
    expect(content).toHaveLength(1);
    expect(content[0]?.text).toBe(text);
    expect(listRecords(g.l).records).toHaveLength(0);
  });

  it("GFP3: search results with &nbsp;, soft hyphens in long words and RTL Arabic with directional marks are delivered", () => {
    const text = "<p>Results&nbsp;for&nbsp;query</p><p>Donau­dampf­schiff­fahrts­gesellschaft</p><p dir=\"rtl\">‏مرحبا بالعالم‏ ⁧مثال⁩</p>";
    const { content, g } = deliver("web-search", text);
    expect(listRecords(g.l).records).toHaveLength(0);
    expect(String(content[0]?.text)).toContain("مرحبا بالعالم");
    expect(String(content[0]?.text)).toContain("Donau");
  });

  it("GFP4: new tools within 24 h of the first pin are visible, with no alert", () => {
    const tools: Json[] = structuredClone(NOTES_TOOLS);
    const g = gw({ cfg: () => ({ era: "modern", tools }) });
    g.call("tools/list");
    tools.push({ name: "archive_list", description: "List archives.", inputSchema: { type: "object" } });
    expect((g.call("tools/list").result?.tools as Json[]).map((t) => t.name)).toContain("archive_list");
    expect(g.diag).toEqual([]);
    expect(loadPins(g.l).pins.pending).toEqual([]);
  });

  it("GFP5: the same tools in a different order are no change", () => {
    const tools: Json[] = structuredClone(NOTES_TOOLS);
    const g = gw({ cfg: () => ({ era: "modern", tools }) });
    g.call("tools/list");
    tools.reverse();
    expect((g.call("tools/list").result?.tools as Json[]).map((t) => t.name)).toEqual(["create_note", "search"]);
    expect(loadPins(g.l).pins.pending).toEqual([]);
  });

  it("GFP6: a 3 MiB JSON result from a database server is delivered within the latency budget", () => {
    const rows = Array.from({ length: 30000 }, (_, i) => ({ id: i, name: `customer ${i}`, email: `user${i}@example.com`, note: "regular order, shipped on time ".repeat(2) }));
    const json = JSON.stringify(rows);
    expect(json.length).toBeGreaterThan(3 * 1024 * 1024);
    const t0 = performance.now();
    const { r, g } = deliver("postgres", json.slice(0, 1000), { rows });
    const ms = performance.now() - t0;
    expect(r.result?.isError).not.toBe(true);
    expect(((r.result?.structuredContent as Json).rows as unknown[]).length).toBe(30000);
    expect(listRecords(g.l).records).toHaveLength(0);
    expect(ms).toBeLessThan(5000);
  });

  it("GFP7: MCP calls in hook mode add no decision and no ask (the client's hook decides)", () => {
    const calls: [string, string, Json][] = [
      ["github", "get_issue", { owner: "acme", repo: "app", issue_number: 1 }],
      ["github", "create_pull_request", { owner: "acme", repo: "app", title: "t", head: "h", base: "main" }],
      ["filesystem", "read_file", { path: "/tmp/x" }],
      ["slack", "post_message", { channel: "#dev", text: "deployed" }],
      ["linear", "list_issues", {}],
    ];
    for (const [server, tool, args] of calls) {
      const g = gw({ client: "claude-code", mode: "hook", server, cfg: { era: "modern", tools: [{ name: tool, description: `${tool}.`, inputSchema: { type: "object" } }] } });
      g.call("tools/list");
      const r = g.call("tools/call", { name: tool, arguments: args });
      expect(textOf(r), `${server} ${tool}`).toBe(`ok ${tool}`);
      expect(tailLog(g.l, 20).filter((e) => e.event.type === "decision")).toHaveLength(0);
    }
  });

  it("GFP8: responsive marketing HTML (desktop/mobile alternates hidden with display:none, duplicating visible text) is delivered unchanged", () => {
    const html = `<html><body><table><tr><td class="desktop">Autumn sale: 20% off all boots this week.</td></tr></table><div style="display:none">Autumn sale: 20% off all boots this week.</div><p>Shop now at our store.</p></body></html>`;
    const { content, g } = deliver("gmail", html);
    expect(content).toHaveLength(1);
    expect(content[0]?.text).toBe(html);
    expect(listRecords(g.l).records).toHaveLength(0);
  });
});
