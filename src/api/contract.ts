/**
 * Contract (docs/api-v0.md) to library calls. The one reading of a request: the sidecar (src/api/request.ts)
 * and the conformance runner (conformance/translate.ts re-exports this file) use it, so both read a decide
 * request the same way. Name-keyed maps go through own()/setOwn() (src/own.ts).
 * Pure and browser-safe: no Node module, no file access.
 * The conformance runner uses it, and the sidecar can import it so both read a decide request the same way.
 *
 * Every refusal is a 400 (bad request): unknown or misplaced fields, an unknown format, a body that is
 * not what the format says. Inside `raw` (the framework's own block) only the documented keys are read and
 * any other key is ignored: frameworks add keys to their blocks over time (Anthropic's `caller`,
 * `cache_control`), and none of them changes what the call does. The sidecar's other errors (401, 403, 404, 413) are not decided here.
 */

import { own, ownMap, setOwn } from "../own.js";
import { usageProblem, type ModelUsage } from "../engine/caps.js";
import { NETWORK_REFUSED_TOOL, UNPARSEABLE_TOOL } from "../engine/classify.js";
import type { ToolCall, ToolSpec } from "../sdk/types.js";

export const FORMATS = ["native", "engine", "openai.chat", "anthropic", "mcp"] as const;
export type Format = (typeof FORMATS)[number];

/** One entry of the tool registry, in the contract's shape. */
export type RegistryEntry = { kind: "read" | "send" | "destroy" | "blocked"; results?: "trusted" | "untrusted"; privateData?: boolean } | { as: string; map?: Record<string, string> };
export interface Registry {
  tools: Record<string, RegistryEntry>;
}

export interface DecideRequest {
  session: string;
  action: {
    format: Format;
    tool?: string;
    input?: Record<string, unknown>;
    callId?: string;
    mcp?: { server: string; source?: string };
    raw?: unknown;
  };
  /** `traffic` "network": a network middleware's request on the agent's behalf (not a tool call; middlewareDecideContext()). */
  context?: { attended?: boolean; workspace?: string[]; cwd?: string; traffic?: "tool" | "network" };
  dryRun?: boolean;
  /** Model usage behind this call (counted toward the token and cost spending limits). */
  usage?: ModelUsage;
}

export type Translated<T> = ({ ok: true } & T) | { ok: false; status: 400; detail: string };

export interface TranslatedDecide {
  session: string;
  call: ToolCall;
  /** Whether the agent's registry applies (native, openai.chat, anthropic); false for engine and mcp. */
  useRegistry: boolean;
  attended: boolean;
  workspace: string[];
  cwd: string | undefined;
  dryRun: boolean;
  /** "network": the call is a network middleware's request, not the agent's tool call (GuardOptions.traffic). */
  traffic: "tool" | "network";
}

/** What the engine is told for a native tool the registry does not list: a name no engine tool can have, so FW-UNKNOWN-TOOL. */
export const UNREGISTERED_PREFIX = "unregistered:";

const bad = (detail: string): { ok: false; status: 400; detail: string } => ({ ok: false, status: 400, detail });
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const hasOwn = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

function unknownKeys(o: Record<string, unknown>, allowed: readonly string[], where: string): string | null {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) return `unknown field ${where}${k}`;
  return null;
}

const PATH = /^\$(\.[A-Za-z0-9_-]+)+$/;

/** A JSONPath of the form $.a.b (dot paths only in v0): the value, or undefined when any step is missing. */
export function readPath(args: Record<string, unknown>, path: string): unknown {
  let cur: unknown = args;
  for (const part of path.slice(2).split(".")) {
    if (!isObj(cur) || !hasOwn(cur, part)) return undefined;
    cur = own(cur, part);
  }
  return cur;
}

/** The registry as the library's tool specs. A `map` becomes the spec's input function: only the mapped fields, a missing source field left out. */
export function translateRegistry(reg: unknown): Translated<{ tools: Record<string, ToolSpec> }> {
  if (!isObj(reg)) return bad("the registry must be an object");
  const extra = unknownKeys(reg, ["tools"], "");
  if (extra !== null) return bad(extra);
  if (!isObj(reg.tools)) return bad("tools must be an object");
  const out = ownMap<ToolSpec>();
  for (const [name, e] of Object.entries(reg.tools)) {
    if (!isObj(e)) return bad(`tool ${name}: the spec must be an object`);
    if ("kind" in e === "as" in e) return bad(`tool ${name}: give exactly one of kind and as`);
    if ("kind" in e) {
      const x = unknownKeys(e, ["kind", "results", "privateData"], `of tool ${name}: `);
      if (x !== null) return bad(x);
      if (e.kind !== "read" && e.kind !== "send" && e.kind !== "destroy" && e.kind !== "blocked") return bad(`tool ${name}: kind must be read, send, destroy or blocked`);
      if (e.results !== undefined && e.results !== "trusted" && e.results !== "untrusted") return bad(`tool ${name}: results must be trusted or untrusted`);
      if (e.privateData !== undefined && typeof e.privateData !== "boolean") return bad(`tool ${name}: privateData must be a boolean`);
      if (/[*?{},]/.test(name)) return bad(`tool ${name}: a tool name with *, ?, {, } or , cannot be declared`);
      setOwn(out, name, { kind: e.kind, ...(e.results !== undefined ? { results: e.results } : {}), ...(e.privateData !== undefined ? { privateData: e.privateData } : {}) });
    } else {
      const x = unknownKeys(e, ["as", "map"], `of tool ${name}: `);
      if (x !== null) return bad(x);
      if (typeof e.as !== "string" || e.as === "") return bad(`tool ${name}: as must be a tool name`);
      if (e.map === undefined) {
        setOwn(out, name, { as: e.as });
        continue;
      }
      if (!isObj(e.map)) return bad(`tool ${name}: map must be an object`);
      const map = ownMap<string>();
      for (const [field, p] of Object.entries(e.map)) {
        if (typeof p !== "string" || !PATH.test(p)) return bad(`tool ${name}: map.${field} must be a path like $.a.b`);
        setOwn(map, field, p);
      }
      setOwn(out, name, {
        as: e.as,
        input: (args) => {
          const r = ownMap<unknown>();
          for (const [field, p] of Object.entries(map)) {
            const v = readPath(args, p);
            if (v !== undefined) setOwn(r, field, v);
          }
          return { ...r };
        },
      });
    }
  }
  return { ok: true, tools: { ...out } };
}

const TOP = ["session", "action", "context", "dryRun", "usage"] as const;
const ACTION = ["format", "tool", "input", "callId", "mcp", "raw"] as const;

const NETWORK_SHAPE = `context.traffic "network" is only for a network middleware's request: format "engine" with tool "HttpRequest" (or the unreadable-request wrapper whose input.tool is "HttpRequest", or "${NETWORK_REFUSED_TOOL}" for a request the middleware refused)`;
const REFUSED_ONLY = `tool "${NETWORK_REFUSED_TOOL}" is a network middleware's record of a request it refused: it is accepted only with context.traffic "network" (from a network middleware's token)`;

/**
 * A network middleware's request: an HttpRequest, the wrapper for one whose body it cannot read, or its record of a
 * request it refused before asking (NETWORK_REFUSED_TOOL: a loopback or other non-public address target, a Host or pseudo-header naming another
 * target), which the engine always denies under FW-NET-REFUSED.
 */
function networkShape(call: ToolCall): boolean {
  if (call.tool === "HttpRequest" || call.tool === NETWORK_REFUSED_TOOL) return true;
  return call.tool === UNPARSEABLE_TOOL && call.input.tool === "HttpRequest";
}

/**
 * Reads a decide request into the library's call and options. `registryTools`: the names the registry lists.
 * A call of NETWORK_REFUSED_TOOL is refused unless it is network traffic: only a network middleware's token may send
 * that (request.ts checks the token), so an agent cannot write refusal entries the middleware never made into its
 * own log.
 */
export function translateDecide(body: unknown, registryTools: readonly string[]): Translated<TranslatedDecide> {
  const t = translateAny(body, registryTools);
  if (t.ok && t.call.tool === NETWORK_REFUSED_TOOL && t.traffic !== "network") return bad(REFUSED_ONLY);
  return t;
}

function translateAny(body: unknown, registryTools: readonly string[]): Translated<TranslatedDecide> {
  if (!isObj(body)) return bad("the body must be a JSON object");
  let x = unknownKeys(body, TOP, "");
  if (x !== null) return bad(x);
  if (typeof body.session !== "string" || body.session === "") return bad("session must be a non-empty string");
  if (body.dryRun !== undefined && typeof body.dryRun !== "boolean") return bad("dryRun must be a boolean");
  if (body.usage !== undefined) {
    const p = usageProblem(body.usage);
    if (p !== null) return bad(p);
  }
  const a = body.action;
  if (!isObj(a)) return bad("action must be an object");
  x = unknownKeys(a, ACTION, "action.");
  if (x !== null) return bad(x);
  if (typeof a.format !== "string" || !(FORMATS as readonly string[]).includes(a.format)) return bad("action.format must be native, engine, openai.chat, anthropic or mcp");
  if (a.callId !== undefined && typeof a.callId !== "string") return bad("action.callId must be a string");
  let attended = true;
  let workspace: string[] = [];
  let cwd: string | undefined;
  let traffic: "tool" | "network" = "tool";
  if (body.context !== undefined) {
    const c = body.context;
    if (!isObj(c)) return bad("context must be an object");
    x = unknownKeys(c, ["attended", "workspace", "cwd", "traffic"], "context.");
    if (x !== null) return bad(x);
    if (c.attended !== undefined && typeof c.attended !== "boolean") return bad("context.attended must be a boolean");
    if (c.workspace !== undefined && (!Array.isArray(c.workspace) || c.workspace.some((w) => typeof w !== "string"))) return bad("context.workspace must be an array of strings");
    if (c.cwd !== undefined && typeof c.cwd !== "string") return bad("context.cwd must be a string");
    if (c.traffic !== undefined && c.traffic !== "tool" && c.traffic !== "network") return bad('context.traffic must be "tool" or "network"');
    if (c.traffic === "network") traffic = "network";
    attended = c.attended ?? true;
    workspace = (c.workspace as string[] | undefined) ?? [];
    cwd = c.cwd as string | undefined;
  }
  const rest = { session: body.session, attended, workspace, cwd, dryRun: body.dryRun === true, traffic };
  const usage = body.usage as ModelUsage | undefined;
  const withUsage = (call: ToolCall): ToolCall => (usage !== undefined ? { ...call, usage: { ...usage } } : call);
  const format = a.format as Format;
  // Network traffic is a middleware's HTTP request, in the engine's vocabulary; anything else is a tool call.
  if (traffic === "network" && format !== "engine") return bad(NETWORK_SHAPE);
  const only = (allowedFields: readonly string[]): string | null => {
    for (const k of ["tool", "input", "mcp", "raw"]) if (own(a, k) !== undefined && !allowedFields.includes(k)) return `action.${k} does not belong to format ${format}`;
    return null;
  };

  if (format === "native" || format === "engine") {
    const m = only(["tool", "input"]);
    if (m !== null) return bad(m);
    if (typeof a.tool !== "string" || a.tool === "") return bad("action.tool must be a non-empty string");
    if (!isObj(a.input)) return bad("action.input must be an object");
    const call: ToolCall = { tool: a.tool, input: a.input, ...(a.callId !== undefined ? { callId: a.callId } : {}) };
    if (format === "engine") {
      if (traffic === "network" && !networkShape(call)) return bad(NETWORK_SHAPE);
      return { ok: true, ...rest, call: withUsage(call), useRegistry: false };
    }
    if (!registryTools.includes(a.tool)) call.tool = `${UNREGISTERED_PREFIX}${a.tool}`;
    return { ok: true, ...rest, call: withUsage(call), useRegistry: true };
  }

  if (format === "mcp") {
    const m = only(["tool", "input", "mcp"]);
    if (m !== null) return bad(m);
    if (typeof a.tool !== "string" || a.tool === "") return bad("action.tool must be a non-empty string");
    if (!isObj(a.input)) return bad("action.input must be an object");
    if (!isObj(a.mcp)) return bad("action.mcp must be an object for format mcp");
    x = unknownKeys(a.mcp, ["server", "source"], "action.mcp.");
    if (x !== null) return bad(x);
    if (typeof a.mcp.server !== "string" || a.mcp.server === "") return bad("action.mcp.server must be a non-empty string");
    if (a.mcp.source !== undefined && typeof a.mcp.source !== "string") return bad("action.mcp.source must be a string");
    const call: ToolCall = { tool: `mcp__${a.mcp.server}__${a.tool}`, input: a.input, ...(a.callId !== undefined ? { callId: a.callId } : {}), ...(a.mcp.source !== undefined ? { mcpSource: a.mcp.source } : {}) };
    return { ok: true, ...rest, call: withUsage(call), useRegistry: false };
  }

  const m = only(["raw"]);
  if (m !== null) return bad(m);
  const raw = a.raw;
  if (!isObj(raw)) return bad("action.raw must be an object");
  let name: string;
  let input: unknown;
  let id: unknown;
  if (format === "openai.chat") {
    if (raw.type !== "function") return bad('action.raw.type must be "function"');
    const f = raw.function;
    if (!isObj(f)) return bad("action.raw.function must be an object");
    if (typeof f.name !== "string" || f.name === "") return bad("action.raw.function.name must be a non-empty string");
    if (typeof f.arguments !== "string") return bad("action.raw.function.arguments must be a JSON string");
    try {
      input = JSON.parse(f.arguments);
    } catch {
      return bad("action.raw.function.arguments is not valid JSON");
    }
    name = f.name;
    id = raw.id;
  } else {
    if (raw.type !== "tool_use") return bad('action.raw.type must be "tool_use"');
    if (typeof raw.name !== "string" || raw.name === "") return bad("action.raw.name must be a non-empty string");
    name = raw.name;
    input = raw.input;
    id = raw.id;
  }
  if (!isObj(input)) return bad("the tool's arguments must be a JSON object");
  if (id !== undefined && typeof id !== "string") return bad("action.raw.id must be a string");
  const callId = a.callId ?? (id as string | undefined);
  const call: ToolCall = { tool: registryTools.includes(name) ? name : `${UNREGISTERED_PREFIX}${name}`, input, ...(callId !== undefined ? { callId } : {}) };
  return { ok: true, ...rest, call: withUsage(call), useRegistry: true };
}

export interface ResultBody { session: string; decisionId: string; output: unknown; failed?: boolean }
export interface InputBody { session: string; source: string; content: unknown; private?: boolean }
export interface PromptBody { session: string; text: string }

/** The body of POST /v1/sessions/{session}/results (the session is the path; vectors carry it in the body). */
export function translateResult(body: unknown): Translated<ResultBody> {
  if (!isObj(body)) return bad("the body must be a JSON object");
  const x = unknownKeys(body, ["session", "decisionId", "output", "failed"], "");
  if (x !== null) return bad(x);
  if (typeof body.session !== "string" || body.session === "") return bad("session must be a non-empty string");
  if (typeof body.decisionId !== "string" || body.decisionId === "") return bad("decisionId must be a non-empty string");
  if (!hasOwn(body, "output")) return bad("output is required");
  if (body.failed !== undefined && typeof body.failed !== "boolean") return bad("failed must be a boolean");
  return { ok: true, session: body.session, decisionId: body.decisionId, output: body.output, ...(body.failed !== undefined ? { failed: body.failed } : {}) };
}

export function translateInput(body: unknown): Translated<InputBody> {
  if (!isObj(body)) return bad("the body must be a JSON object");
  const x = unknownKeys(body, ["session", "source", "content", "private"], "");
  if (x !== null) return bad(x);
  if (typeof body.session !== "string" || body.session === "") return bad("session must be a non-empty string");
  if (typeof body.source !== "string" || body.source === "") return bad("source must be a non-empty string");
  if (!hasOwn(body, "content")) return bad("content is required");
  if (body.private !== undefined && typeof body.private !== "boolean") return bad("private must be a boolean");
  return { ok: true, session: body.session, source: body.source, content: body.content, ...(body.private !== undefined ? { private: body.private } : {}) };
}

export function translatePrompt(body: unknown): Translated<PromptBody> {
  if (!isObj(body)) return bad("the body must be a JSON object");
  const x = unknownKeys(body, ["session", "text"], "");
  if (x !== null) return bad(x);
  if (typeof body.session !== "string" || body.session === "") return bad("session must be a non-empty string");
  if (typeof body.text !== "string") return bad("text must be a string");
  return { ok: true, session: body.session, text: body.text };
}
