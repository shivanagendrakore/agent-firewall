/**
 * The adapter registry: `hook --agent <id>` picks one; every adapter feeds the
 * same pipeline (src/hook/claude.ts).
 */

import { claudeAdapter } from "./claude.js";
import { codexAdapter } from "./codex.js";
import { cursorAdapter } from "./cursor.js";
import { geminiAdapter } from "./gemini.js";
import type { AgentAdapter, AgentId } from "./types.js";

const ADAPTERS: Record<AgentId, AgentAdapter | undefined> = { claude: claudeAdapter, codex: codexAdapter, gemini: geminiAdapter, cursor: cursorAdapter };

export function adapterFor(id: AgentId): AgentAdapter {
  const a = ADAPTERS[id];
  if (a === undefined) throw new Error(`no adapter for ${id}`);
  return a;
}

export function allAdapters(): AgentAdapter[] {
  return Object.values(ADAPTERS).filter((a): a is AgentAdapter => a !== undefined);
}
