/**
 * The gateway pipeline wired to the in-process fake upstream
 * (test/fixtures/mcp-upstream/server.ts), synchronously: what the core sends
 * upstream is answered at once, what it sends the client is collected.
 */
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { GatewayCore, type CoreOptions } from "../../src/gateway/pipeline.js";
import type { Json, Message, Response } from "../../src/gateway/jsonrpc.js";
import { layout, type Layout } from "../../src/runtime/layout.js";
import { FakeUpstream, type FakeConfig } from "../fixtures/mcp-upstream/server.js";
import { testRoot } from "../helpers.js";

export const MODERN = "2026-07-28";

export interface Gw {
  core: GatewayCore;
  up: FakeUpstream;
  inbox: Message[];
  l: Layout;
  home: string;
  diag: string[];
  /** Sends a request as the client and returns the gateway's answer to it. */
  call(method: string, params?: Json): Response;
  notify(method: string, params?: Json): void;
  /** The last request the upstream received with this method. */
  received(method: string): Json | undefined;
}

export interface GwOptions {
  cfg: FakeConfig | (() => FakeConfig);
  clientEra?: "modern" | "legacy";
  client?: string;
  server?: string;
  mode?: "full" | "hook";
  source?: string;
  pinSource?: string;
  policy?: Json;
  session?: string;
  l?: Layout;
  home?: string;
  core?: Partial<CoreOptions>;
  clientInfo?: Json;
  clientCaps?: Json;
}

let seq = 0;

export function newHome(): { home: string; l: Layout } {
  const home = mkdtempSync(join(testRoot(), "gw-"));
  const l = layout(join(home, ".launchsafe-firewall"));
  mkdirSync(l.home, { recursive: true });
  return { home, l };
}

export function writePolicy(l: Layout, policy: Json): void {
  writeFileSync(l.policy, JSON.stringify({ version: 2, ...policy }));
}

export function gw(o: GwOptions): Gw {
  const base = o.l !== undefined && o.home !== undefined ? { l: o.l, home: o.home } : newHome();
  const { l, home } = base;
  if (o.policy !== undefined) writePolicy(l, o.policy);
  const up = new FakeUpstream(o.cfg);
  const inbox: Message[] = [];
  const diag: string[] = [];
  const timers: { fn: () => void; live: boolean }[] = [];
  const client = o.client ?? "claude-desktop";
  const server = o.server ?? "notes";
  const mode = o.mode ?? "full";
  const session = o.session ?? `t${++seq}`;
  const ws = join(home, "ws");
  mkdirSync(ws, { recursive: true });
  // eslint-disable-next-line prefer-const -- assigned after the sink that refers to it is built
  let core: GatewayCore;
  const sink = {
    client: (m: Message) => void inbox.push(m),
    upstream: (m: Message) => {
      for (const r of up.handle(m as unknown as Json)) core.fromUpstream(r as unknown as Message);
    },
  };
  core = new GatewayCore(
    {
      l,
      env: {},
      client,
      server,
      mode,
      source: o.source ?? "user",
      pinSource: o.pinSource ?? (mode === "full" ? `gw-${client}` : "user"),
      session: () => session,
      cwd: ws,
      workspaceRoots: [],
      transport: "stdio",
      home,
      detectNonInteractive: () => true,
      notifyDeps: { spawn: () => undefined },
      setTimer: (fn) => {
        const t = { fn, live: true };
        timers.push(t);
        return () => void (t.live = false);
      },
      diag: (s) => void diag.push(s),
      ...(o.core ?? {}),
    },
    sink,
  );
  let id = 0;
  const fire = (): void => {
    for (const t of timers.splice(0)) if (t.live) t.fn();
  };
  const era = o.clientEra ?? "modern";
  const info = o.clientInfo ?? { name: "test-client", version: "1.0" };
  const caps = o.clientCaps ?? {};
  const meta = (p: Json = {}): Json => (era === "modern" ? { ...p, _meta: { "io.modelcontextprotocol/protocolVersion": MODERN, "io.modelcontextprotocol/clientCapabilities": caps, "io.modelcontextprotocol/clientInfo": info } } : p);
  const call = (method: string, params?: Json): Response => {
    const rid = ++id;
    core.fromClient({ jsonrpc: "2.0", id: rid, method, params: method === "initialize" ? (params ?? {}) : meta(params) });
    let r = inbox.find((m) => "id" in m && m.id === rid && !("method" in m));
    if (r === undefined) {
      // A silent upstream: let the probe time out.
      fire();
      r = inbox.find((m) => "id" in m && m.id === rid && !("method" in m));
    }
    if (r === undefined) throw new Error(`no answer to ${method}: ${JSON.stringify(inbox.slice(-3))}`);
    return r as Response;
  };
  const notify = (method: string, params?: Json): void => core.fromClient({ jsonrpc: "2.0", method, ...(params !== undefined ? { params } : {}) });
  if (era === "legacy") {
    call("initialize", { protocolVersion: "2025-06-18", capabilities: caps, clientInfo: info });
    notify("notifications/initialized");
  }
  const received = (method: string): Json | undefined => [...up.received].reverse().find((m) => m.method === method);
  return { core, up, inbox, l, home, diag, call, notify, received };
}

/** The text of a tools/call result (all text blocks). */
export function textOf(r: Response): string {
  const content = (r.result?.content ?? []) as Json[];
  return content.map((c) => (typeof c.text === "string" ? c.text : "")).join("\n");
}

export const NOTES_TOOLS: Json[] = [
  { name: "search", description: "Search your notes.", inputSchema: { type: "object", properties: { q: { type: "string" } } } },
  { name: "create_note", description: "Create a note.", inputSchema: { type: "object", properties: { text: { type: "string" } } } },
];
