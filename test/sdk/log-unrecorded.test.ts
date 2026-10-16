/**
 * LR11: the library follows the hook's rule that no decision is carried out without a log entry. Events are
 * bounded and fall back to a short entry (src/engine/log-bound.ts); when the store refuses even that, an
 * allow becomes ask (a person can answer) or deny (FW-LOG-UNRECORDED), a yes whose approval entry is
 * refused does not run, and every log failure is reported (problems, onLogError) instead of swallowed.
 * An I/O-style failure (any other error) is reported and the decision stands, as on the hook path.
 */

import { appendFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MAX_TAIL_SEARCH, tailLog } from "../../src/runtime/log.js";
import { createGuard, LogRefused, LogUnrecorded, memoryStore, type StateStore } from "../../src/sdk/index.js";
import { createNodeGuard, fileStore } from "../../src/sdk/node.js";
import type { GuardOptions } from "../../src/sdk/types.js";
import { makeTree, removeTree, type Tree } from "./harness.js";

const READ = { tool: "read_ticket", input: { id: "1" } };
const breakLog = (t: Tree): void => appendFileSync(join(t.l.log, "decisions.jsonl"), `${"q".repeat(MAX_TAIL_SEARCH + 5)}\n`);

/** A memory store whose appendLog is replaced. */
function storeWith(appendLog: StateStore["appendLog"]): StateStore {
  return { ...memoryStore(), appendLog };
}

describe("LR11: the SDK guard never carries out an unrecorded decision", () => {
  let t: Tree;
  beforeEach(() => {
    t = makeTree();
  });
  afterEach(() => removeTree(t));

  function fileGuard(o: Partial<GuardOptions> = {}) {
    return createNodeGuard({ session: "lr11", workspace: t.ws, home: t.home, scratch: [t.scratch], tools: { read_ticket: { kind: "read" } }, store: fileStore({ home: t.l.home }), onLogError: () => undefined, ...o });
  }

  it("file store, no one there: an allowed read is denied with FW-LOG-UNRECORDED and the reason is surfaced", () => {
    const errors: string[] = [];
    const g = fileGuard({ attended: false, onLogError: (m) => void errors.push(m) });
    expect(g.decide(READ).verdict).toBe("allow");
    breakLog(t);
    const d = g.decide({ ...READ, input: { id: "2" } });
    expect(d.verdict).toBe("deny");
    expect(d.rules[0]).toBe("FW-LOG-UNRECORDED");
    expect(d.message).toMatch(/refused to record/);
    expect(d.problems?.join("\n")).toMatch(/fallback entry/);
    expect(errors).toHaveLength(1);
  });

  it("file store, a person there: the allow becomes ask, and a yes whose approval entry is refused is not a yes", async () => {
    let asked = 0;
    const g = fileGuard({ onApproval: () => (asked++, true) });
    g.recordPrompt("look at ticket 1");
    breakLog(t);
    const a = await g.authorize(READ);
    expect(a.decision.verdict).toBe("ask");
    expect(a.decision.rules[0]).toBe("FW-LOG-UNRECORDED");
    expect(asked).toBe(1);
    expect(a.allowed).toBe(false);
    expect(a.approval?.note).toMatch(/FW-LOG-UNRECORDED/);
  });

  it("file store: an event over the cap is bounded or replaced by its fallback entry, and the call is still allowed", () => {
    const g = fileGuard({ attended: false });
    const d = g.decide({ tool: "read_ticket", input: { id: "1" }, callId: "c".repeat(400_000) });
    expect(d.verdict).toBe("allow");
    expect(d.problems).toBeUndefined();
    const last = tailLog(t.l, 1)[0]?.event as Record<string, unknown>;
    expect(last.type).toBe("decision");
    expect(last.verdict).toBe("allow");
    expect(String(last.callId).length).toBeLessThanOrEqual(1024);
  });

  it("custom store: a LogRefused entry gets the fallback entry and the decision stands", () => {
    const written: Record<string, unknown>[] = [];
    const inner = memoryStore();
    const store = storeWith((e) => {
      if (e.fallback !== true) throw new LogRefused("size", "too large for this store");
      written.push(e);
      return inner.appendLog(e);
    });
    const g = createGuard({ session: "s", tools: { read_ticket: { kind: "read" } }, store, attended: false, onLogError: () => undefined });
    const d = g.decide(READ);
    expect(d.verdict).toBe("allow");
    expect(written[0]).toMatchObject({ type: "decision", fallback: true, verdict: "allow", refused: "size" });
  });

  it("custom store: refusing every entry (or throwing LogUnrecorded, or its own error of that name) fails closed", () => {
    const named = Object.assign(new Error("db said no"), { name: "LogUnrecorded" });
    for (const thrower of [() => new LogRefused("unsearchable", "chain end unknown"), () => new LogUnrecorded("nothing written"), () => named]) {
      const g = createGuard({ session: "s", tools: { read_ticket: { kind: "read" } }, store: storeWith(() => { throw thrower(); }), attended: false, onLogError: () => undefined });
      const d = g.decide(READ);
      expect(d.verdict).toBe("deny");
      expect(d.rules).toContain("FW-LOG-UNRECORDED");
    }
  });

  it("custom store: any other error (I/O) is reported and the decision stands, as on the hook path", () => {
    const errors: string[] = [];
    const g = createGuard({ session: "s", tools: { read_ticket: { kind: "read" } }, store: storeWith(() => { throw new Error("disk full"); }), attended: false, onLogError: (m) => void errors.push(m) });
    const d = g.decide(READ);
    expect(d.verdict).toBe("allow");
    expect(d.problems?.join("\n")).toMatch(/disk full/);
    expect(errors.join("\n")).toMatch(/disk full/);
  });

  it("an ask whose entry is refused carries FW-LOG-UNRECORDED, and the deny of an unrecorded send stays a deny", async () => {
    const store = storeWith(() => { throw new LogUnrecorded("nothing written"); });
    const g = createGuard({ session: "s", tools: { send_email: { kind: "send" } }, store, onLogError: () => undefined, onApproval: () => true });
    const a = await g.authorize({ tool: "send_email", input: { to: "a@b.example", body: "hi" } });
    expect(a.decision.verdict).toBe("ask");
    expect(a.decision.rules[0]).toBe("FW-LOG-UNRECORDED");
    expect(a.allowed).toBe(false);
  });

  it("deciding fails and the failure entry is refused: a read-only tool is not let through", () => {
    const store: StateStore = { ...memoryStore(), load: () => { throw new Error("state unreadable"); }, appendLog: () => { throw new LogUnrecorded("nothing written"); } };
    const g = createGuard({ session: "s", store, onLogError: () => undefined });
    const d = g.decide({ tool: "Read", input: { file_path: "/w/a.txt" } });
    expect(d.verdict).toBe("deny");
    expect(d.rules).toContain("FW-LOG-UNRECORDED");
  });

  it("the default reporter is console.warn (never silent)", () => {
    const seen: unknown[] = [];
    const warn = console.warn;
    console.warn = (...a: unknown[]) => void seen.push(a.join(" "));
    try {
      createGuard({ session: "s", tools: { read_ticket: { kind: "read" } }, store: storeWith(() => { throw new Error("disk full"); }) }).decide(READ);
    } finally {
      console.warn = warn;
    }
    expect(seen.join("\n")).toMatch(/could not write its decision log: disk full/);
  });
});
