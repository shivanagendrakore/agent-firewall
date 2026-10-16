/** Shared helpers for the adapter suites: a throwaway firewall home and workspace, and one call per event. */
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { runHook, type HookEnv } from "../../src/hook/claude.js";
import { layout, type Layout } from "../../src/runtime/layout.js";
import type { AgentId, HookIO } from "../../src/adapters/types.js";
import { verdictFor } from "../../src/agent-replay.js";
import { testRoot } from "../helpers.js";

export interface Box {
  root: string;
  home: string;
  ws: string;
  l: Layout;
  cleanup(): void;
}

export function box(): Box {
  const root = realpathSync(mkdtempSync(join(testRoot(), "lsfw-adapter-")));
  const home = join(root, "home");
  const ws = join(home, "proj");
  mkdirSync(ws, { recursive: true });
  return { root, home, ws, l: layout(join(home, ".launchsafe-firewall")), cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

export function write(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

export interface SendOptions {
  unattended?: boolean;
  env?: NodeJS.ProcessEnv;
}

/** Sends one event as `agent` (session_id and cwd default to the box's). */
export function send(b: Box, agent: AgentId, event: Record<string, unknown>, o: SendOptions = {}): HookIO {
  const h: HookEnv = { env: o.env ?? (agent === "claude" ? { CLAUDE_PROJECT_DIR: b.ws } : {}), layout: b.l, agent, home: b.home, scratchRoots: [join(b.root, "scratch")], detectNonInteractive: () => o.unattended === true, notifyDeps: { spawn: () => undefined } };
  return runHook(JSON.stringify({ session_id: "s1", cwd: b.ws, ...event }), h);
}

export function verdict(agent: AgentId, io: HookIO): string {
  return verdictFor(agent, io).verdict;
}

/** The rules named at the end of the firewall's message. */
export function rules(agent: AgentId, io: HookIO): string[] {
  const reason = verdictFor(agent, io).reason;
  return (/\(rule ([A-Z0-9, -]+)\)\s*$/.exec(reason)?.[1] ?? "").split(", ").filter((x) => x !== "");
}

export function fixture(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(dirname(new URL(import.meta.url).pathname), "..", "fixtures", name), "utf8")) as Record<string, unknown>;
}
