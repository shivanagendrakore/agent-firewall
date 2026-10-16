/**
 * Simulator B: another extension that drives tabs
 * with chrome.debugger (the Claude in Chrome / Comet input path).
 *
 * The extension in test/agents/debugger-agent/ loads next to ours (fixture
 * option `extraExtensions: [DEBUGGER_AGENT_DIR]`) and exposes an `agent`
 * object on its service worker global; these wrappers call it through
 * Playwright's worker.evaluate. Errors from chrome.debugger come back as
 * rejected promises with Chrome's message, so tests can record them.
 */
import type { BrowserContext, Worker } from "@playwright/test";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const DEBUGGER_AGENT_DIR = resolve(fileURLToPath(new URL("./debugger-agent/", import.meta.url)));

/** The debugger agent's service worker (its file is background.js, ours is worker.js). */
export async function debuggerAgentWorker(context: BrowserContext): Promise<Worker> {
  return context.serviceWorkers().find((w) => w.url().endsWith("/background.js")) ?? (await context.waitForEvent("serviceworker", { predicate: (w) => w.url().endsWith("/background.js") }));
}

export interface DebuggerTarget {
  id: string;
  type: string;
  url: string;
  attached: boolean;
  tabId?: number;
  extensionId?: string;
}

export interface DebuggerAgent {
  attach(tabId: number): Promise<void>;
  attachTarget(targetId: string): Promise<void>;
  detach(tabId: number): Promise<void>;
  detachTarget(targetId: string): Promise<void>;
  targets(): Promise<DebuggerTarget[]>;
  findTabs(urlPrefix: string): Promise<{ id: number; url: string; windowId: number }[]>;
  click(tabId: number, x: number, y: number): Promise<void>;
  clickSelector(tabId: number, selector: string): Promise<void>;
  focusSelector(tabId: number, selector: string): Promise<void>;
  insertText(tabId: number, text: string): Promise<void>;
  /** CDP modifiers bitmask: 2 = Ctrl, 4 = Meta. */
  pressKey(tabId: number, key: "Enter", modifiers?: number): Promise<void>;
  setFileInputFiles(tabId: number, selector: string, paths: string[]): Promise<void>;
  evaluate(tabId: number, expression: string): Promise<unknown>;
}

type AgentGlobal = { agent: Record<string, (...args: unknown[]) => Promise<unknown>> };

export function debuggerAgent(worker: Worker): DebuggerAgent {
  const call =
    <T>(method: string) =>
    (...args: unknown[]): Promise<T> =>
      worker.evaluate(([m, a]) => (globalThis as unknown as AgentGlobal).agent[m as string]?.(...(a as unknown[])), [method, args] as const) as Promise<T>;
  return {
    attach: call("attach"),
    attachTarget: call("attachTarget"),
    detach: call("detach"),
    detachTarget: call("detachTarget"),
    targets: call("targets"),
    findTabs: call("findTabs"),
    click: call("click"),
    clickSelector: call("clickSelector"),
    focusSelector: call("focusSelector"),
    insertText: call("insertText"),
    pressKey: call("pressKey"),
    setFileInputFiles: call("setFileInputFiles"),
    evaluate: call("evaluate"),
  };
}
