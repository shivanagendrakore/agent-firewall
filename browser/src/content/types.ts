/**
 * Interfaces shared by the content-script modules. Each module is owned by
 * one lane (guard, gate, leak, nav) and wired together only in index.ts.
 */
import type { AnyMessage, ReplyMap } from "../shared/bridge.js";

export type SendToWorker = <M extends AnyMessage>(msg: M) => Promise<ReplyMap[M["type"]]>;

export interface ContentDeps {
  send: SendToWorker;
  /** The window the content script runs in (a parameter, so modules can be driven in tests). */
  win: Window;
  /** Whether agent mode is on, as last told by the worker (agent.mode messages). */
  agentMode: () => boolean;
}

/** Lifecycle every content module implements. `install` runs synchronously at document_start. */
export interface ContentModule {
  install(): void;
  uninstall(): void;
}
