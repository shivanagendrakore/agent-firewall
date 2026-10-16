/**
 * A fake upstream MCP server for the gateway tests, in both eras
 * (the gateway's acceptance tests). In-process: `new FakeUpstream(cfg)`
 * and `handle(message)`. As a stdio server: `node server.ts <config.json>`
 * (Node strips the types; the config file is reread on every message, so a
 * test can change the tool list between two tools/list calls). Every message
 * it receives is appended to `cfg.logFile` when set, so a test can show that
 * nothing reached the server.
 *
 * Self-contained on purpose (Node built-ins only, erasable TypeScript), so
 * Node can run it directly.
 */
import { appendFileSync, readFileSync } from "node:fs";

type Json = Record<string, unknown>;

export interface FakeConfig {
  era: "modern" | "legacy";
  serverInfo?: { name: string; version: string };
  tools: Json[];
  /** Result per tool name (default: one text block "ok <name>"). */
  results?: Record<string, Json>;
  /** Tools whose result echoes the arguments they received, as JSON text and structured content (vault scrub tests). */
  echo?: string[];
  /** Tools whose result is the base64 of the arguments they received, as one block. */
  echo64?: string[];
  /** Each argument value echoed in base64 and hex, one block per encoding. */
  echoEncoded?: string[];
  /** resources/read contents per URI. */
  resources?: Record<string, Json[]>;
  /** prompts/get result per prompt name. */
  prompts?: Record<string, Json>;
  /** An InputRequiredResult per tool name, returned while the call carries no inputResponses (modern). */
  inputRequired?: Record<string, Json>;
  /** A server-to-client request sent before answering a tool call (legacy). */
  serverRequests?: Record<string, Json>;
  /** A legacy server that never answers a request it does not know (the probe then times out). */
  silentOnUnknown?: boolean;
  logFile?: string;
}

const MODERN = "2026-07-28";

export class FakeUpstream {
  readonly received: Json[] = [];
  private initialized = false;
  private seq = 0;
  private readonly cfg: () => FakeConfig;
  constructor(cfg: FakeConfig | (() => FakeConfig)) {
    this.cfg = typeof cfg === "function" ? cfg : () => cfg;
  }

  handle(m: Json): Json[] {
    this.received.push(m);
    const c = this.cfg();
    if (c.logFile !== undefined) appendFileSync(c.logFile, `${JSON.stringify(m)}\n`);
    if (typeof m.method !== "string") return [];
    if (m.id === undefined) {
      if (m.method === "notifications/initialized") this.initialized = true;
      return [];
    }
    const id = m.id;
    const params = (typeof m.params === "object" && m.params !== null ? m.params : {}) as Json;
    const meta = (typeof params._meta === "object" && params._meta !== null ? params._meta : {}) as Json;
    const ok = (result: Json): Json => ({ jsonrpc: "2.0", id, result });
    const err = (code: number, message: string, data?: unknown): Json => ({ jsonrpc: "2.0", id, error: { code, message, ...(data !== undefined ? { data } : {}) } });
    const info = c.serverInfo ?? { name: "fake", version: "1.0.0" };
    if (c.era === "modern") {
      if (m.method === "initialize") return [err(-32601, `initialize is not supported; this server speaks ${MODERN}`)];
      if (meta["io.modelcontextprotocol/protocolVersion"] !== MODERN) return [err(-32022, "Unsupported protocol version", { supported: [MODERN], requested: meta["io.modelcontextprotocol/protocolVersion"] ?? null })];
      if (m.method === "server/discover") return [ok({ resultType: "complete", supportedVersions: [MODERN], capabilities: { tools: {}, resources: {}, prompts: {} }, _meta: { "io.modelcontextprotocol/serverInfo": info } })];
    } else {
      if (m.method === "initialize") {
        return [ok({ protocolVersion: typeof params.protocolVersion === "string" ? params.protocolVersion : "2025-11-25", capabilities: { tools: {}, resources: {}, prompts: {} }, serverInfo: info })];
      }
      if (!this.initialized && m.method !== "ping") return c.silentOnUnknown === true ? [] : [err(-32601, "Method not found (not initialized)")];
    }
    switch (m.method) {
      case "ping":
        return [ok({})];
      case "tools/list":
        return [ok({ ...(c.era === "modern" ? { resultType: "complete", ttlMs: 60000, cacheScope: "private" } : {}), tools: c.tools })];
      case "tools/call": {
        const name = String(params.name ?? "");
        if (c.era === "modern" && c.inputRequired?.[name] !== undefined && params.inputResponses === undefined) return [ok(c.inputRequired[name] as Json)];
        const echoed = JSON.stringify(params.arguments ?? {});
        const values = Object.values((params.arguments ?? {}) as Json).map(String);
        const result =
          c.echo?.includes(name) === true
            ? { content: [{ type: "text", text: `got ${echoed}` }], structuredContent: { received: params.arguments ?? {} } }
            : c.echo64?.includes(name) === true
              ? { content: [{ type: "text", text: Buffer.from(echoed).toString("base64") }] }
              : c.echoEncoded?.includes(name) === true
                ? { content: values.flatMap((v) => [{ type: "text", text: `b64 ${Buffer.from(v).toString("base64")}` }, { type: "text", text: `hex ${Buffer.from(v).toString("hex")}` }, { type: "text", text: `url ${encodeURIComponent(v)}` }]) }
                : (c.results?.[name] ?? { content: [{ type: "text", text: `ok ${name}` }] });
        const out: Json[] = [];
        const req = c.serverRequests?.[name];
        if (c.era === "legacy" && req !== undefined) out.push({ jsonrpc: "2.0", id: `srv-${++this.seq}`, ...req });
        out.push(ok({ ...(c.era === "modern" ? { resultType: "complete" } : {}), ...result }));
        return out;
      }
      case "resources/read": {
        const uri = String(params.uri ?? "");
        const contents = c.resources?.[uri];
        if (contents === undefined) return [err(-32602, "resource not found")];
        return [ok({ ...(c.era === "modern" ? { resultType: "complete" } : {}), contents })];
      }
      case "prompts/get": {
        const p = c.prompts?.[String(params.name ?? "")];
        if (p === undefined) return [err(-32602, "prompt not found")];
        return [ok({ ...(c.era === "modern" ? { resultType: "complete" } : {}), ...p })];
      }
      case "resources/list":
        return [ok({ resources: [] })];
      case "prompts/list":
        return [ok({ prompts: [] })];
      default:
        return c.silentOnUnknown === true ? [] : [err(-32601, `Method not found: ${m.method}`)];
    }
  }
}

/** Runs as a stdio MCP server when started directly. */
function main(configPath: string): void {
  const up = new FakeUpstream(() => JSON.parse(readFileSync(configPath, "utf8")) as FakeConfig);
  let buf = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => {
    buf += chunk;
    let nl = buf.indexOf("\n");
    while (nl !== -1) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (line.trim() !== "") for (const out of up.handle(JSON.parse(line) as Json)) process.stdout.write(`${JSON.stringify(out)}\n`);
      nl = buf.indexOf("\n");
    }
  });
  process.stdin.on("end", () => process.exit(0));
  process.stderr.write("fake upstream ready\n");
}

const script = process.argv[1] ?? "";
if (script.endsWith("mcp-upstream/server.ts")) main(process.argv[2] ?? "");
