/** Small builders for vector skeletons: the requests only. generate.ts runs them and records what the engine says. */

import { fingerprint } from "../../src/engine/secrets.js";
import type { Registry, RegistryEntry } from "../translate.js";
import type { Step, Vector } from "../run.js";
import type { Setup, SetupDecoy } from "../setup.js";

export type SkStep = Omit<Step, "expect" | "expectApi">;
export type Skeleton = Omit<Vector, "steps"> & { steps: SkStep[] };

export const WS = "/srv/app";
export const HOME = "/home/agent";
export const SESSION = "run-1";

/**
 * Made-up credentials in the shapes the engine recognises, each carrying the marker LSFWCONF so a secret scanner
 * can tell them from real ones (none opens anything). The engine still detects them: the vectors record it.
 */
export const STRIPE_LIVE = "sk_live_LSFWCONF9fQ2xLm7Rt4Vb8N";
export const SLACK_BOT = "xoxb-LSFWCONF-4827364519-Hq8Lr2Vt6Np0";
export const NPM_TOKEN = "npm_LSFWCONFRk3Vq8Lt2Wp7Yz5Nc9Hm4Bx6Fd1G";

export interface Ctx {
  attended?: boolean;
  workspace?: string[];
  cwd?: string;
  /** "network": a network middleware's request (only with a step's `token: "network"`). */
  traffic?: "tool" | "network";
}
const CTX: Ctx = { attended: true, workspace: [WS], cwd: WS };
const UNATTENDED: Ctx = { ...CTX, attended: false };
export const ctxOf = (unattended: boolean | undefined): Ctx => (unattended === true ? UNATTENDED : CTX);

const decide = (action: Record<string, unknown>, ctx: Ctx = CTX, extra: Record<string, unknown> = {}, session = SESSION): SkStep => ({ kind: "decide", request: { session, action, context: ctx, ...extra } });

export const eng = (tool: string, input: Record<string, unknown>, ctx?: Ctx, extra?: Record<string, unknown>, session?: string): SkStep => decide({ format: "engine", tool, input }, ctx, extra, session);
export const nat = (tool: string, input: Record<string, unknown>, ctx?: Ctx, extra?: Record<string, unknown>, session?: string): SkStep => decide({ format: "native", tool, input }, ctx, extra, session);
export const oai = (name: string, args: Record<string, unknown>, ctx?: Ctx, id = "call_1", extra?: Record<string, unknown>): SkStep => decide({ format: "openai.chat", raw: { id, type: "function", function: { name, arguments: JSON.stringify(args) } } }, ctx, extra);
export const ant = (name: string, input: Record<string, unknown>, ctx?: Ctx, id = "toolu_1", extra?: Record<string, unknown>): SkStep => decide({ format: "anthropic", raw: { type: "tool_use", id, name, input } }, ctx, extra);
export const mcp = (server: string, tool: string, input: Record<string, unknown>, source?: string, ctx?: Ctx, extra?: Record<string, unknown>): SkStep => decide({ format: "mcp", tool, input, mcp: { server, ...(source !== undefined ? { source } : {}) } }, ctx, extra);

export const res = (decideStep: number, output: unknown = "(tool output placeholder)", session = SESSION): SkStep => ({ kind: "result", request: { session, decisionId: `@step:${decideStep}`, output } });
export const inp = (source: string, content: unknown, priv?: boolean, session = SESSION): SkStep => ({ kind: "input", request: { session, source, content, ...(priv !== undefined ? { private: priv } : {}) } });
export const prm = (text: string, session = SESSION): SkStep => ({ kind: "prompt", request: { session, text } });
export const apr = (decideStep: number, session = SESSION): SkStep => ({ kind: "approve", request: { session, decisionId: `@step:${decideStep}` } });

/** The step sent with the agent's network-middleware token instead of its ordinary one. */
export const withNet = (s: SkStep): SkStep => ({ ...s, token: "network" });
/** A network middleware's HTTP request (engine format, context.traffic "network"), sent with the network token. */
export const http = (method: string, url: string, body?: string, ctx: Ctx = CTX): SkStep => withNet(eng("HttpRequest", { method, url, ...(body !== undefined ? { body } : {}) }, { ...ctx, traffic: "network" }));
/** Sets dryRun on a decide step. */
export const dry = (s: SkStep): SkStep => ({ ...s, request: { ...s.request, dryRun: true } });

export const NO_TOOLS: Registry = { tools: {} };
export const reg = (tools: Record<string, RegistryEntry>): Registry => ({ tools });

export const OUTSIDE = "(outside content placeholder)";
export const PRIVATE = "(private data placeholder)";

/** Steps that make the session untrusted: an engine WebFetch and its result. Starts at step index `at`. */
export const taintEngine = (at: number, ctx?: Ctx): SkStep[] => [eng("WebFetch", { url: "https://blog.example.org/post", prompt: "read" }, ctx), res(at, OUTSIDE)];

export function vec(id: string, description: string, source: string | undefined, agentTools: Registry, steps: SkStep[]): Skeleton {
  return { id, description, ...(source !== undefined ? { source } : {}), agentTools, steps };
}

// --- the prepared environment (conformance/setup.ts) --------------------------------------------------------

/** The prepared tree's workspace and home, replaced by the runner with the real temporary paths. */
export const PWS = "{{workspace}}";
export const PHOME = "{{home}}";
/** Attended, the prepared workspace as the only root and the cwd. */
export const PCTX: Ctx = { attended: true, workspace: [PWS], cwd: PWS };
export const PUNATTENDED: Ctx = { ...PCTX, attended: false };
export const pctxOf = (unattended: boolean | undefined): Ctx => (unattended === true ? PUNATTENDED : PCTX);

/** A decoy with a fixed value; its fingerprint is the engine's, recorded in the vector so no runner computes it. */
export function decoy(id: string, path: string, kind: SetupDecoy["kind"], token: string): SetupDecoy {
  const fp = fingerprint(token);
  if (fp === null) throw new Error(`decoy ${id}: the value is too short or too long to fingerprint`);
  return { id, path, kind, token, fingerprint: fp };
}

export function svec(id: string, description: string, source: string | undefined, agentTools: Registry, setup: Setup, steps: SkStep[]): Skeleton {
  return { id, description, ...(source !== undefined ? { source } : {}), agentTools, setup, steps };
}
