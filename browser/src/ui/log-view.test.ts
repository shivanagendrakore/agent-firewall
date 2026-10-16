import { describe, expect, it } from "vitest";
import type { ChainedEntry } from "../shared/messages.js";
import { ALWAYS_ON_LABELS, entryLine, exportFileName, refusedLine, verifyLine } from "./log-view.js";

const entry: ChainedEntry = { seq: 4, at: Date.UTC(2026, 9, 11, 12, 0, 0), site: "attacker.test", actionClass: null, verdict: "approve", rules: ["leak.seen_elsewhere"], event: "leak", detail: ["type", "seen_elsewhere"], prevHash: "a", hash: "b" };

describe("log and settings copy", () => {
  it("never claims the person is protected", () => {
    const all = [verifyLine({ brokenAt: null, count: 2 }), verifyLine({ brokenAt: 1, count: 2 }), ...Object.values(ALWAYS_ON_LABELS)];
    for (const s of all) expect(s.toLowerCase()).not.toContain("protected");
  });
  it("says whether the chain is intact, broken or empty", () => {
    expect(verifyLine({ brokenAt: null, count: 0 })).toBe("The log is empty.");
    expect(verifyLine({ brokenAt: null, count: 1 })).toContain("1 entry");
    expect(verifyLine({ brokenAt: 3, count: 9 })).toContain("broken at entry 3");
  });
  it("formats an entry with its site, verdict, rule and codes", () => {
    const line = entryLine(entry);
    expect(line).toContain("#4");
    expect(line).toContain("2026-10-11 12:00:00");
    expect(line).toContain("attacker.test");
    expect(line).toContain("leak.seen_elsewhere");
    expect(line).toContain("seen_elsewhere");
  });
  it("names refused settings, and nothing when none were", () => {
    expect(refusedLine([])).toBe("");
    expect(refusedLine(["detectWebdriver"])).toContain("agent mode is on");
  });
  it("names the export file by date", () => {
    expect(exportFileName(Date.UTC(2026, 9, 11))).toBe("launchsafe-browser-log-2026-10-11.json");
  });
});
