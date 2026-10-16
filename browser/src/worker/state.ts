/**
 * Tab trust and agent-session state (engine/session.ts) kept in
 * chrome.storage.session, so it survives service-worker restarts and is
 * cleared when the browser closes (design 4.5, 12).
 *
 * Updates are serialized through one promise chain: two messages arriving
 * together cannot lose each other's change. Reads wait on the same chain, so a
 * decision always sees every update requested before it (a quarantine
 * reported just before an action is never missed by a stale read).
 */
import { emptyState, type BrowserState } from "../engine/session.js";

export const STATE_KEY = "ls.state";

/** The part of chrome.storage.StorageArea the store uses (an in-memory fake in tests). */
export interface KeyValueArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

export interface StateStore {
  /** The state after every update requested so far has landed. */
  load(): Promise<BrowserState>;
  /** Applies a pure update and persists it; resolves to the new state. */
  update(fn: (s: BrowserState) => BrowserState): Promise<BrowserState>;
}

function isState(x: unknown): x is BrowserState {
  return typeof x === "object" && x !== null && Array.isArray((x as BrowserState).tabs) && "session" in x;
}

export function createStateStore(area: KeyValueArea): StateStore {
  let chain: Promise<unknown> = Promise.resolve();
  const read = async (): Promise<BrowserState> => {
    const got = await area.get(STATE_KEY);
    const v = got[STATE_KEY];
    return isState(v) ? v : emptyState();
  };
  return {
    // Not appended to the chain: reads do not hold up later updates, they only wait for earlier ones.
    load: () => chain.then(read),
    update(fn) {
      const next = chain.then(async () => {
        const s = fn(await read());
        await area.set({ [STATE_KEY]: s });
        return s;
      });
      chain = next.catch(() => undefined);
      return next;
    },
  };
}
