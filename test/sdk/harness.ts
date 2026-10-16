/**
 * Runs the same tool calls through the hook path (runHook, the Claude Code
 * adapter) and through the library (createNodeGuard), in one throwaway tree:
 * its own workspace, home, scratch and firewall home. The real home is never
 * read or written (the suite's home is temporary, and every path here is under
 * the tree).
 */

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verdictOf } from "../../src/demo.js";
import { runHook } from "../../src/hook/claude.js";
import { layout, type Layout } from "../../src/runtime/layout.js";
import { createNodeGuard, fileStore, type Guard } from "../../src/sdk/node.js";
import type { GuardVerdict } from "../../src/sdk/types.js";

export interface Tree {
  root: string;
  ws: string;
  home: string;
  scratch: string;
  l: Layout;
}

export function makeTree(): Tree {
  const root = mkdtempSync(join(tmpdir(), "lsfw-sdk-"));
  const ws = join(root, "workspace");
  const home = join(root, "home");
  const scratch = join(root, "scratch");
  for (const d of [ws, home, scratch, join(root, "claude-config")]) mkdirSync(d, { recursive: true });
  return { root, ws, home, scratch, l: layout(join(root, "state")) };
}

export function removeTree(t: Tree): void {
  rmSync(t.root, { recursive: true, force: true });
}

export function fill(v: unknown, t: Tree): unknown {
  if (typeof v === "string") return v.replaceAll("{WS}", t.ws).replaceAll("{HOME}", t.home);
  if (Array.isArray(v)) return v.map((x) => fill(x, t));
  if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x, t)]));
  return v;
}

export interface Outcome {
  verdict: GuardVerdict;
  rules: string[];
}

/** One hook event through the real hook, as Claude Code would send it. Returns the outcome of a PreToolUse. */
export function hookEvent(t: Tree, session: string, event: Record<string, unknown>, unattended = false): Outcome | null {
  const ev = fill({ session_id: session, cwd: t.ws, permission_mode: "default", ...event }, t) as Record<string, unknown>;
  const res = runHook(JSON.stringify(ev), { env: { CLAUDE_PROJECT_DIR: t.ws, CLAUDE_CONFIG_DIR: join(t.root, "claude-config") }, layout: t.l, home: t.home, scratchRoots: [t.scratch], detectNonInteractive: () => unattended });
  if (ev.hook_event_name !== "PreToolUse") return null;
  const { verdict, reason } = verdictOf(res.stdout, res.exitCode);
  const rules = (/\(rule ([A-Z0-9, -]+)\)\s*$/.exec(reason)?.[1] ?? "").split(", ").filter((x) => x !== "");
  return { verdict: verdict === "queue" ? "hold" : verdict, rules };
}

/** A library guard over the same tree (memory store by default, or the runtime's files). */
export function guardFor(t: Tree, session: string, o: { unattended?: boolean; persist?: "memory" | "file" } = {}): Guard {
  return createNodeGuard({
    session,
    workspace: t.ws,
    home: t.home,
    scratch: [t.scratch],
    firewallHome: t.l.home,
    attended: o.unattended !== true,
    ...(o.persist === "file" ? { store: fileStore({ home: t.l.home }) } : {}),
  });
}

/** The same event through the library: PreToolUse decides, PostToolUse records the result, a prompt records the prompt. */
export function guardEvent(g: Guard, t: Tree, event: Record<string, unknown>): Outcome | null {
  const ev = fill(event, t) as Record<string, unknown>;
  const name = ev.hook_event_name;
  if (name === "UserPromptSubmit") {
    g.recordPrompt(String(ev.prompt ?? ""));
    return null;
  }
  const call = { tool: String(ev.tool_name), input: (ev.tool_input ?? {}) as Record<string, unknown> };
  if (name === "PostToolUse") {
    g.recordResult(call, ev.tool_response ?? "");
    return null;
  }
  const d = g.decide(call);
  // The hook shows rules only when it does not allow (an allow is silent).
  return { verdict: d.verdict, rules: d.verdict === "allow" ? [] : d.rules };
}
