import { describe, expect, it } from "vitest";
import { pageShown, startAgentSession } from "../engine/session.js";
import { DEFAULT_POLICY } from "../engine/types.js";
import { createStateStore, STATE_KEY, type KeyValueArea } from "./state.js";

function memoryArea(): KeyValueArea & { data: Map<string, unknown> } {
  const data = new Map<string, unknown>();
  return {
    data,
    get: async (k) => (data.has(k) ? { [k]: structuredClone(data.get(k)) } : {}),
    set: async (items) => {
      for (const [k, v] of Object.entries(items)) data.set(k, structuredClone(v));
    },
  };
}

describe("state store", () => {
  it("starts empty and persists updates", async () => {
    const area = memoryArea();
    const store = createStateStore(area);
    expect(await store.load()).toEqual({ tabs: [], session: null });
    await store.update((s) => pageShown(s, 1, { url: "https://shop.test/" }, DEFAULT_POLICY));
    expect((area.data.get(STATE_KEY) as { tabs: unknown[] }).tabs.length).toBe(1);
  });

  it("serializes concurrent updates so none is lost", async () => {
    const store = createStateStore(memoryArea());
    await Promise.all([1, 2, 3, 4, 5].map((id) => store.update((s) => pageShown(s, id, { url: "https://shop.test/" }, DEFAULT_POLICY))));
    expect((await store.load()).tabs.map((t) => t.tabId).sort()).toEqual([1, 2, 3, 4, 5]);
  });

  it("a read requested after an update sees that update (no stale read)", async () => {
    const store = createStateStore(memoryArea());
    void store.update((s) => startAgentSession(s, { now: 1, tabIds: [1] }));
    expect((await store.load()).session).not.toBeNull();
  });

  it("ignores a corrupt stored value and starts empty (never trusts it)", async () => {
    const area = memoryArea();
    area.data.set(STATE_KEY, { tabs: "nope" });
    expect(await createStateStore(area).load()).toEqual({ tabs: [], session: null });
  });

  it("a failed update does not wedge later ones", async () => {
    const store = createStateStore(memoryArea());
    await expect(store.update(() => { throw new Error("boom"); })).rejects.toThrow("boom");
    const s = await store.update((x) => startAgentSession(x, { now: 1, tabIds: [1] }));
    expect(s.session).not.toBeNull();
  });
});
