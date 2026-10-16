/**
 * The local API's request bodies (docs/api-v0.md), validated strictly: an unknown field, a missing one or
 * a wrong type is a 400 naming it. The five action formats become one ToolCall the library's guard
 * decides, with the same mapping the library applies:
 *
 * - engine: tool and input are already the engine's vocabulary (no registry);
 * - native: tool is looked up in the agent's registry (a tool it does not list is FW-UNKNOWN-TOOL);
 * - openai.chat: raw is one tool_call ({ id, type: "function", function: { name, arguments } }), then native;
 * - anthropic: raw is one tool_use block ({ type: "tool_use", id, name, input }), then native;
 * - mcp: the engine sees mcp__<server>__<tool>, with the source the caller states (unstated: untrusted).
 *
 * The decide request is read by src/api/contract.ts, the translation the conformance vectors use too; every
 * object in it is closed except `raw`, where only the documented keys are read. The session endpoints'
 * bodies are read here.
 */

import { hasOwn } from "../own.js";
import { MAX_INPUT_DEPTH, nestedDeeperThan } from "../engine/input-depth.js";
import { FORMATS, translateDecide, type Format } from "./contract.js";
import type { ToolCall } from "../sdk/types.js";

export class BadRequest extends Error {
  constructor(
    message: string,
    readonly slug = "bad-request",
  ) {
    super(message);
  }
}

export { FORMATS, type Format };

export interface DecideRequest {
  /** The caller's session id (namespaced by agent before use). */
  session: string;
  format: Format;
  call: ToolCall;
  /** "registry": the agent's tool registry maps the call; "engine": the call is in the engine's vocabulary already. */
  mode: "registry" | "engine";
  attended: boolean;
  workspace?: string[];
  cwd?: string;
  dryRun: boolean;
  /** "network": a network middleware's request on the agent's behalf (middlewareDecideContext()). */
  traffic: "tool" | "network";
}

/**
 * The decide request's `context` for a network middleware (the OpenShell supervisor middleware,
 * src/openshell/middleware.ts): its HTTP requests are judged like the agent's own, but they are not the agent's
 * tool calls, so they are not counted toward the toolCalls spending limit or the agent-wide behaviour monitor
 * (docs/design.md, "Network middleware traffic").
 */
export function middlewareDecideContext(attended: boolean): { attended: boolean; traffic: "network" } {
  return { attended, traffic: "network" };
}

type Obj = Record<string, unknown>;

function isObject(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** A short id or name: no control characters. */
function text(v: unknown, where: string, max = 200): string {
  // eslint-disable-next-line no-control-regex -- refusing control characters is the point
  if (typeof v !== "string" || v === "" || v.length > max || /[\u0000-\u001f\u007f-\u009f]/.test(v)) throw new BadRequest(`${where} must be a non-empty string of at most ${max} characters without control characters`);
  return v;
}

/** Session ids: letters, digits and . _ - : / (after percent-decoding), 1 to 200 characters. */
export const SESSION_ID = /^[A-Za-z0-9._:/-]{1,200}$/;

export function sessionId(v: unknown): string {
  if (typeof v !== "string" || !SESSION_ID.test(v)) throw new BadRequest("the session id must be 1 to 200 letters, digits, '.', '_', '-', ':' or '/'");
  return v;
}

/**
 * A decide request, read by the contract's translation (src/api/contract.ts, shared with the conformance
 * vectors) and then held to the sidecar's own limits: a session id without control characters, absolute
 * workspace and cwd paths, an MCP server name without "__", bounded ids. `registryTools`: the names the
 * agent's registry lists (a native tool it does not list is FW-UNKNOWN-TOOL).
 */
export function parseDecide(body: unknown, registryTools: readonly string[], caller: { networkTraffic?: boolean } = {}): DecideRequest {
  const t = translateDecide(body, registryTools);
  if (!t.ok) {
    const slug = /^unknown field/.test(t.detail) ? "unknown-field" : /format must be/.test(t.detail) ? "unknown-format" : "bad-request";
    throw new BadRequest(t.detail, slug);
  }
  // Network traffic is not counted toward the toolCalls limit, the agent-wide monitor or agent stops, so it is
  // the middleware's token's to declare, never the caller's own say (TokenRecord.traffic).
  if (t.traffic === "network" && caller.networkTraffic !== true) throw new BadRequest('context.traffic "network" is accepted only from a network middleware\'s token (launchsafe-firewall api token add <agentId> --traffic network); this token is an ordinary agent token');
  sessionId(t.session);
  t.workspace.forEach((w, i) => {
    if (!text(w, `context.workspace[${i}]`, 4096).startsWith("/")) throw new BadRequest(`context.workspace[${i}] must be an absolute path`);
  });
  if (t.workspace.length > 32) throw new BadRequest("context.workspace takes at most 32 paths");
  if (t.cwd !== undefined && !text(t.cwd, "context.cwd", 4096).startsWith("/")) throw new BadRequest("context.cwd must be an absolute path");
  if (t.call.callId !== undefined) text(t.call.callId, "the call id", 500);
  text(t.call.tool, "the tool name", 300);
  const a = (body as { action: { format: string; mcp?: { server?: unknown } } }).action;
  if (a.format === "mcp" && typeof a.mcp?.server === "string" && a.mcp.server.includes("__")) throw new BadRequest('action.mcp.server cannot contain "__" (the separator in mcp__<server>__<tool>)');
  // FZ15: a server ending in "_" runs into the separator (mcp__crm___x), and the engine reads the name back as
  // server "crm", tool "_x": the call would be judged under another server's policy.
  if (a.format === "mcp" && typeof a.mcp?.server === "string" && a.mcp.server.endsWith("_")) throw new BadRequest('action.mcp.server cannot end with "_" (it would run into the "__" separator in mcp__<server>__<tool>)');
  // FZ14: arguments nested past what any tool takes are refused here; the engine would not judge them.
  if (nestedDeeperThan(t.call.input, MAX_INPUT_DEPTH)) throw new BadRequest(`the tool's arguments are nested deeper than ${MAX_INPUT_DEPTH} levels`);
  return { session: t.session, format: a.format as Format, call: t.call, mode: t.useRegistry ? "registry" : "engine", attended: t.attended, ...(t.workspace.length > 0 ? { workspace: t.workspace } : {}), ...(t.cwd !== undefined ? { cwd: t.cwd } : {}), dryRun: t.dryRun, traffic: t.traffic };
}

function object(v: unknown, where: string): Obj {
  if (!isObject(v)) throw new BadRequest(`${where} must be an object`);
  return v;
}

function closed(o: Obj, allowed: readonly string[], where: string): void {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) throw new BadRequest(`unknown field ${where}${k.slice(0, 80)}`, "unknown-field");
}

export function parseResult(body: unknown): { decisionId: string; output: unknown; failed: boolean } {
  const b = object(body, "the request body");
  closed(b, ["decisionId", "output", "failed"], "");
  if (!hasOwn(b, "output")) throw new BadRequest("output is required (what the tool returned)");
  if (hasOwn(b, "failed") && typeof b.failed !== "boolean") throw new BadRequest("failed must be true or false");
  return { decisionId: text(b.decisionId, "decisionId", 100), output: b.output, failed: b.failed === true };
}

export function parseInput(body: unknown): { source: string; content: unknown; private: boolean } {
  const b = object(body, "the request body");
  closed(b, ["source", "content", "private"], "");
  if (!hasOwn(b, "content")) throw new BadRequest("content is required");
  if (hasOwn(b, "private") && typeof b.private !== "boolean") throw new BadRequest("private must be true or false");
  return { source: text(b.source, "source"), content: b.content, private: b.private === true };
}

export function parsePrompt(body: unknown): { text: string } {
  const b = object(body, "the request body");
  closed(b, ["text"], "");
  if (typeof b.text !== "string") throw new BadRequest("text must be a string (what the person typed)");
  return { text: b.text };
}
