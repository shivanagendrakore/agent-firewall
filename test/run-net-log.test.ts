/**
 * `run`'s proxy events in the signed log (runNetEvents): bounded entries with the fallback entry, as the hook
 * writes them. LG1: a host's first allowed connection is refused when the log refuses its entry and the
 * fallback entry (FW-LOG-UNRECORDED), and the next one tries again; an I/O failure is reported and the
 * connection stands. Temporary homes only; no sandbox, no network.
 */
import { appendFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { layout } from "../src/runtime/layout.js";
import { loadKey, MAX_TAIL_SEARCH, tailLog } from "../src/runtime/log.js";
import { appendBounded, isLogUnrecorded } from "../src/runtime/logbound.js";
import { MAX_DENY_KEYS, MAX_DENY_LOG_TOTAL, runNetEvents, type RunResult } from "../src/runtime/run/run.js";
import type { ProxyEvent } from "../src/runtime/run/proxy.js";
import { tempHome } from "./helpers.js";

const allow = (host: string): ProxyEvent => ({ type: "net", method: "CONNECT", host, port: 443, verdict: "allow", reason: "listed" });

describe("runNetEvents", () => {
  it("records a host's first allow once; a refused entry refuses the connection and the next one tries again", () => {
    const outcomes: ("ok" | "failed" | "unrecorded")[] = ["unrecorded", "unrecorded", "ok"];
    const recorded: Record<string, unknown>[] = [];
    const refusals: RunResult["refusals"] = [];
    const on = runNetEvents((e) => (recorded.push(e), outcomes.shift() ?? "ok"), refusals);
    expect(on(allow("a.test"))).toBe(false);
    expect(on(allow("a.test"))).toBe(false);
    expect(on(allow("a.test"))).toBe(true);
    expect(on(allow("a.test"))).toBe(true);
    expect(recorded).toHaveLength(3);
    expect(refusals).toEqual([{ host: "a.test", why: "unrecorded", reason: expect.stringContaining("FW-LOG-UNRECORDED") }]);
    expect(on.refused()).toBe(2);
  });

  it("an I/O failure (not a refusal) lets the connection stand", () => {
    const on = runNetEvents(() => "failed", []);
    expect(on(allow("b.test"))).toBe(true);
  });

  it("with the runtime log: a long host name is bounded, and a log that refuses everything refuses the connection", () => {
    const l = layout(join(tempHome("run-net-"), "fw"));
    loadKey(l);
    const record = (e: Record<string, unknown>): "ok" | "failed" | "unrecorded" => {
      try {
        appendBounded(l, e);
        return "ok";
      } catch (err) {
        return isLogUnrecorded(err) ? "unrecorded" : "failed";
      }
    };
    const on = runNetEvents(record, []);
    expect(on(allow(`${"h".repeat(5000)}.test`))).toBe(true);
    const last = tailLog(l, 1)[0]?.event as Record<string, unknown>;
    expect(last).toMatchObject({ type: "run_net", verdict: "allow" });
    expect(String(last.host).length).toBe(1024);
    appendFileSync(join(l.log, "decisions.jsonl"), `${"q".repeat(MAX_TAIL_SEARCH + 5)}\n`);
    expect(on(allow("c.test"))).toBe(false);
  });

  it("refusals: distinct hosts past the cap share one *other* bucket, and the signed refusal entries per run are capped", () => {
    const recorded: Record<string, unknown>[] = [];
    const refusals: RunResult["refusals"] = [];
    const on = runNetEvents((e) => (recorded.push(e), "ok"), refusals);
    const deny = (host: string): ProxyEvent => ({ type: "net", method: "CONNECT", host, port: 443, verdict: "deny", why: "not-listed", reason: "not listed" });
    for (let i = 0; i < MAX_DENY_KEYS + 300; i++) on(deny(`h${i}.test`));
    expect(refusals).toHaveLength(MAX_DENY_KEYS + 1);
    expect(refusals.filter((r) => r.host === "*other*")).toHaveLength(1);
    expect(on.refused()).toBe(MAX_DENY_KEYS + 300);
    expect(recorded.length).toBeLessThanOrEqual(MAX_DENY_LOG_TOTAL);
    // The total cap: 512 hosts refused 25 times each would sign 20 entries apiece; the run signs MAX_DENY_LOG_TOTAL at most.
    const more: Record<string, unknown>[] = [];
    const on2 = runNetEvents((e) => (more.push(e), "ok"), []);
    for (let r = 0; r < 25; r++) for (let i = 0; i < MAX_DENY_KEYS; i++) on2(deny(`k${i}.test`));
    expect(more).toHaveLength(MAX_DENY_LOG_TOTAL);
  });
});
