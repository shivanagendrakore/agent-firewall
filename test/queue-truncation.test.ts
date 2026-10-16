/**
 * I3: a held action is never approved looking complete when it is not. Storage marks every cut with how
 * much is missing and records it on the item; the approval screens show every part and refuse to approve
 * a cut item without --i-saw-truncated; the phone's item says what it leaves out.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { main } from "../src/climain.js";
import { initApprover } from "../src/runtime/approver.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { buildPhoneItem } from "../src/runtime/relay/seal.js";
import { enqueue, getQueueItem, itemTruncation, type QueueItem } from "../src/runtime/store.js";

process.env.LAUNCHSAFE_FIREWALL_TEST = "1";

const PASS = "correct horse battery";
let root: string;
let l: Layout;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-trunc-"));
  l = layout(join(root, "home"));
  initApprover(l, PASS);
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const base = { sessionId: "s", cwd: "/w", projectDir: "/w", tool: "Bash", actionHash: "h1", rules: ["FW-SEND"], reasons: ["it sends data"], kind: "approval" as const };

async function cli(args: string[], answers: string[] = ["yes"]): Promise<{ status: number; out: string }> {
  let out = "";
  const status = await main(args, l, {
    write: (_fd, s) => void (out += s),
    humanAtKeyboard: () => Promise.resolve(true),
    learned: { readSecret: () => Promise.resolve(PASS), ask: () => Promise.resolve(answers.shift() ?? "") },
  });
  return { status, out };
}

describe("I3: storage marks what it cuts", () => {
  it("a list past 200 items, an object past 200 keys and a text past 20,000 characters are marked and recorded", () => {
    const keys = Object.fromEntries(Array.from({ length: 205 }, (_, i) => [`k${i}`, i]));
    const it = enqueue(l, { ...base, input: { list: Array.from({ length: 250 }, (_, i) => i), keys, text: "x".repeat(25000) } });
    const input = it.input as { list: unknown[]; keys: Record<string, unknown>; text: string };
    expect(input.list).toHaveLength(201);
    expect(input.list[200]).toBe("… [50 more items]");
    expect(input.keys["…"]).toBe("[5 more keys]");
    expect(input.text.endsWith("… [5000 more characters]")).toBe(true);
    const notes = itemTruncation(it).join("\n");
    expect(notes).toContain("a list of 250 items (50 more not shown)");
    expect(notes).toContain("an object with 205 keys (5 more not shown)");
    expect(notes).toContain("a text of 25000 characters (5000 more not shown)");
  });

  it("parts past 200 are counted", () => {
    const parts = Array.from({ length: 203 }, (_, i) => ({ tool: "Write", target: `/w/f${i}`, change: "c" }));
    const it = enqueue(l, { ...base, input: {}, parts });
    expect(it.parts).toHaveLength(200);
    expect(itemTruncation(it)).toContain("3 more parts not shown (203 in all)");
  });

  it("an item that fits is not marked", () => {
    const it = enqueue(l, { ...base, input: { command: "git push" } });
    expect(it.truncated).toBeUndefined();
    expect(itemTruncation(it)).toEqual([]);
  });
});

describe("I3: the approval screens", () => {
  it("queue approve refuses a cut item without --i-saw-truncated, and approves it with the flag", async () => {
    const it = enqueue(l, { ...base, input: { text: "y".repeat(30000) } });
    const r = await cli(["queue", "approve", it.id]);
    expect(r.out).toMatch(/Not shown in full: a text of 30000 characters \(10000 more not shown\)/);
    expect(r.out).toMatch(/Not approved: parts of this action are not shown/);
    expect(getQueueItem(l, it.id)?.status).toBe("pending");
    await cli(["queue", "approve", it.id, "--i-saw-truncated"]);
    expect(getQueueItem(l, it.id)?.status).toBe("approved");
  });

  it("queue review refuses [a] for a cut item without the flag (reject still works)", async () => {
    const it = enqueue(l, { ...base, input: { text: "y".repeat(30000) } });
    const r = await cli(["queue", "review"], ["a"]);
    expect(r.out).toMatch(/Not approved/);
    expect(getQueueItem(l, it.id)?.status).toBe("pending");
    await cli(["queue", "review"], ["r"]);
    expect(getQueueItem(l, it.id)?.status).toBe("rejected");
  });

  it("every part of a multi-part action is shown before approving, and a whole item approves as before", async () => {
    const parts = [
      { tool: "Write", target: "/w/a.txt", change: "first change" },
      { tool: "Write", target: "/w/b.txt", change: "second change", held: true },
    ];
    const it = enqueue(l, { ...base, input: { patch: "p" }, parts });
    const r = await cli(["queue", "approve", it.id]);
    expect(r.out).toMatch(/Approving lets all 2 parts run, as a whole/);
    expect(r.out).toMatch(/1\. Write \/w\/a\.txt[\s\S]*first change[\s\S]*2\. Write \/w\/b\.txt \(held\)[\s\S]*second change/);
    expect(r.out).not.toMatch(/Not shown in full/);
    expect(getQueueItem(l, it.id)?.status).toBe("approved");
  });

  it("queue show says what was cut when the action was held", async () => {
    const it = enqueue(l, { ...base, input: { list: Array.from({ length: 220 }, (_, i) => i) } });
    const r = await cli(["queue", "show", it.id]);
    expect(r.out).toMatch(/Not shown in full \(cut when it was held\): a list of 220 items/);
  });
});

describe("I3: the phone's item says what it leaves out", () => {
  it("rules past 10, reasons past 3 and the parts are counted in a last line", () => {
    const rules = Array.from({ length: 12 }, (_, i) => `FW-R${i}`);
    const it: QueueItem = { version: 1, id: "abcd", createdAt: new Date().toISOString(), status: "pending", ...base, rules, reasons: ["a", "b", "c", "d", "e"], input: {}, parts: [{ tool: "Write", target: "/w/a", change: "x" }, { tool: "Write", target: "/w/b", change: "y" }] };
    const p = buildPhoneItem(it, { deviceId: "dev", machine: "mac", nonce: "n", expiresAt: new Date().toISOString(), home: "/home/u" });
    expect(p.rules).toHaveLength(10);
    expect(p.why.at(-1)).toMatch(/^Not shown here: 2 more rules; 2 more reasons; the action runs as 2 parts/);
  });

  it("an item that fits whole carries no such line", () => {
    const it: QueueItem = { version: 1, id: "abcd", createdAt: new Date().toISOString(), status: "pending", ...base, input: {} };
    const p = buildPhoneItem(it, { deviceId: "dev", machine: "mac", nonce: "n", expiresAt: new Date().toISOString(), home: "/home/u" });
    expect(p.why).toEqual(["it sends data"]);
  });
});
