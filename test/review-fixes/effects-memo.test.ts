/**
 * Two engine details from the second review: an equal effect recorded twice keeps what the second one adds
 * (addEffect merges instead of dropping), and an input object edited between calls is never hashed from memory
 * outside a decision (memoByInput remembers only inside one).
 */
import { describe, expect, it } from "vitest";
import { actionHash, decide } from "../../src/engine/decide.js";
import { addEffect, newCollector } from "../../src/engine/effects.js";
import { learnKey } from "../../src/engine/learn.js";
import { emptyState } from "../../src/engine/state.js";
import { defaultConfig } from "../../src/policy.js";
import { ctx } from "../helpers.js";

describe("addEffect: an equal effect merges what it adds", () => {
  it("taints, private data, tags, a download and a second payload are kept on the first effect", () => {
    const c = newCollector(ctx(), defaultConfig(), emptyState());
    expect(addEffect(c, { cls: "egress_send", target: "https://x.example/a", detail: "send to x", payload: "first", tags: ["message"] })).toBe(true);
    expect(addEffect(c, { cls: "egress_send", target: "https://x.example/a", detail: "send to x", payload: "second", taints: true, private: true, tags: ["install"], uploadBytes: 10, download: "/w/f" })).toBe(false);
    expect(addEffect(c, { cls: "egress_send", target: "https://x.example/a", detail: "send to x", payload: "first", uploadBytes: 4 })).toBe(false);
    expect(c.effects).toHaveLength(1);
    const e = c.effects[0];
    expect(e?.taints).toBe(true);
    expect(e?.private).toBe(true);
    expect(e?.tags).toEqual(["message", "install"]);
    expect(e?.payload).toBe("first\nsecond");
    expect(e?.uploadBytes).toBe(10);
    expect(e?.download).toBe("/w/f");
  });
});

describe("memoByInput outside a decision", () => {
  it("an input object edited after a hash is hashed again (actionHash, learnKey)", () => {
    const input: Record<string, unknown> = { command: "ls" };
    const action = { tool: "Bash", input };
    const h1 = actionHash(action);
    const k1 = learnKey(action);
    input.command = "rm -rf ./build";
    expect(actionHash(action)).not.toBe(h1);
    expect(learnKey(action)).not.toBe(k1);
    expect(actionHash(action)).toBe(actionHash({ tool: "Bash", input: { command: "rm -rf ./build" } }));
  });

  it("a decision on the object, then an edit: the hash after the decision is the edited object's", () => {
    const input: Record<string, unknown> = { file_path: "/Users/dev/proj/a.ts" };
    const d = decide({ action: { tool: "Read", input }, state: emptyState(), config: defaultConfig(), ctx: ctx() });
    input.file_path = "/Users/dev/.ssh/id_ed25519";
    expect(actionHash({ tool: "Read", input })).not.toBe(d.actionHash);
  });
});
