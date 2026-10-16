/**
 * Where the local API keeps its files, inside the firewall home (which the agent may never write): the
 * agents' token hashes (api/tokens.json), their tool registries (api/tools/<agent>.json) and the socket
 * (api.sock). Agent ids are validated here once, so every path built from one is safe.
 */

import { join } from "node:path";
import type { Layout } from "../runtime/layout.js";

/** An agent id: a short name a person picks (`api token add <agentId>`). No "/" (sessions are `<agentId>/<session>`). */
export const AGENT_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;

export function isAgentId(s: string): boolean {
  return AGENT_ID.test(s) && !s.includes("..");
}

export function assertAgentId(s: string): void {
  if (!isAgentId(s)) throw new Error(`agent id "${s.slice(0, 80)}" is not valid: use 1 to 64 letters, digits, "_", "-" or ".", starting with a letter or digit`);
}

export function apiDir(l: Layout): string {
  return join(l.home, "api");
}

export function tokensPath(l: Layout): string {
  return join(apiDir(l), "tokens.json");
}

export function toolsDir(l: Layout): string {
  return join(apiDir(l), "tools");
}

export function toolsPath(l: Layout, agentId: string): string {
  assertAgentId(agentId);
  return join(toolsDir(l), `${agentId}.json`);
}

/** The default unix socket. */
export function socketPath(l: Layout): string {
  return join(l.home, "api.sock");
}

/** The session id the engine and the queue see: one agent can never name another's session. */
export function sessionOf(agentId: string, session: string): string {
  return `${agentId}/${session}`;
}
