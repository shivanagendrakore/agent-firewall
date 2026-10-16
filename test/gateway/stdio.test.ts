/**
 * The stdio wrapper end to end: runWrap() starts the fake upstream as a real
 * child process (node test/fixtures/mcp-upstream/server.ts <config>) and
 * relays newline-delimited JSON-RPC through the pipeline; and the CLI's
 * `mcp wrap` is wired (help and usage, no side effects).
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { runWrap } from "../../src/gateway/stdio.js";
import type { Json } from "../../src/gateway/jsonrpc.js";
import { REPO, spawnCli } from "../helpers.js";
import { MODERN, newHome, NOTES_TOOLS, writePolicy } from "./harness.js";

const SERVER = join(REPO, "test", "fixtures", "mcp-upstream", "server.ts");

function client(era: "legacy" | "modern") {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const lines: Json[] = [];
  let buf = "";
  stdout.setEncoding("utf8");
  stdout.on("data", (c: string) => {
    buf += c;
    let nl = buf.indexOf("\n");
    while (nl !== -1) {
      lines.push(JSON.parse(buf.slice(0, nl)) as Json);
      buf = buf.slice(nl + 1);
      nl = buf.indexOf("\n");
    }
  });
  let id = 0;
  const meta = { "io.modelcontextprotocol/protocolVersion": MODERN, "io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/clientInfo": { name: "t", version: "1" } };
  const send = async (method: string, params: Json = {}): Promise<Json> => {
    const rid = ++id;
    stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: rid, method, params: era === "modern" && method !== "initialize" ? { ...params, _meta: meta } : params })}\n`);
    for (let i = 0; i < 400; i++) {
      const r = lines.find((x) => x.id === rid);
      if (r !== undefined) return r;
      await new Promise((res) => setTimeout(res, 10));
    }
    throw new Error(`no answer to ${method}`);
  };
  return { stdin, stdout, stderr, send, lines };
}

describe("stdio wrapper (runWrap) with a real child process", () => {
  it("GW19 over stdio: a legacy client to a modern upstream child; tools/list and tools/call relayed; exits with the child", async () => {
    const { l, home } = newHome();
    writePolicy(l, { mcpServers: { notes: { results: "trusted", privateData: false } } });
    const cfg = join(home, "upstream.json");
    writeFileSync(cfg, JSON.stringify({ era: "modern", tools: NOTES_TOOLS }));
    const c = client("legacy");
    const done = runWrap({ l, env: { ...process.env }, client: "claude-desktop", server: "notes", mode: "full", command: process.execPath, args: [SERVER, cfg], cwd: home, stdin: c.stdin, stdout: c.stdout, stderr: c.stderr, home, sessionStart: "test", core: { detectNonInteractive: () => true, notifyDeps: { spawn: () => undefined } } });
    const init = await c.send("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "desk", version: "1" } });
    expect((init.result as Json).protocolVersion).toBe("2025-11-25");
    c.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    const list = await c.send("tools/list");
    expect(((list.result as Json).tools as Json[]).map((t) => t.name)).toEqual(["search", "create_note"]);
    const call = await c.send("tools/call", { name: "search", arguments: { q: "x" } });
    expect(((call.result as Json).content as Json[])[0]?.text).toBe("ok search");
    const bad = await c.send("bogus/method");
    expect((bad.error as Json).code).toBe(-32601);
    c.stdin.end();
    expect(await done).toBe(0);
  });

  it("malformed JSON from the client gets a parse error and the wrapper keeps running", async () => {
    const { l, home } = newHome();
    const cfg = join(home, "upstream.json");
    writeFileSync(cfg, JSON.stringify({ era: "legacy", tools: NOTES_TOOLS }));
    const c = client("modern");
    const done = runWrap({ l, env: { ...process.env }, client: "cursor", server: "notes", mode: "full", command: process.execPath, args: [SERVER, cfg], cwd: home, stdin: c.stdin, stdout: c.stdout, stderr: c.stderr, home, sessionStart: "test", core: { detectNonInteractive: () => true, notifyDeps: { spawn: () => undefined } } });
    c.stdin.write("{not json\n");
    const d = await c.send("server/discover");
    expect((d.result as Json).supportedVersions).toEqual([MODERN]);
    expect(c.lines.some((x) => (x.error as Json | undefined)?.code === -32700)).toBe(true);
    c.stdin.end();
    expect(await done).toBe(0);
  });

  it("the CLI knows mcp wrap (help changes nothing; a missing command is a usage error)", () => {
    const help = spawnCli(["mcp", "wrap", "--help"]);
    expect(help.status).toBe(0);
    expect(help.stdout).toContain("mcp wrap --client CLIENT --server NAME");
    const usage = spawnCli(["mcp", "wrap", "--client", "cursor", "--server", "x"]);
    expect(usage.status).toBe(64);
  });
});
