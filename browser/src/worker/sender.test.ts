import { describe, expect, it } from "vitest";
import { OPAQUE_HOST } from "../engine/domain.js";
import type { Decision } from "../engine/types.js";
import { candidates, senderFacts, strictest } from "./sender.js";

const d = (verdict: Decision["verdict"], rule = "gate.always_on"): { decision: Decision } => ({ decision: { verdict, rule: rule as Decision["rule"], actionClass: null, reasons: [] } });

describe("sender facts", () => {
  it("takes origin, host and URLs from Chrome's sender", () => {
    expect(senderFacts({ url: "https://Evil.test./form", origin: "https://evil.test", tab: { id: 3, url: "https://top.test/" }, frameId: 2 })).toEqual({
      tabId: 3,
      frameId: 2,
      url: "https://Evil.test./form",
      origin: "https://evil.test",
      host: "evil.test",
      tabUrl: "https://top.test/",
    });
  });

  it("an about:blank frame has its creator's host; a data: frame with an opaque origin has the untrusted stand-in", () => {
    expect(senderFacts({ url: "about:blank", origin: "https://shop.test", tab: { id: 1 }, frameId: 4 }).host).toBe("shop.test");
    expect(senderFacts({ url: "data:text/html,x", origin: "null", tab: { id: 1 }, frameId: 4 }).host).toBe(OPAQUE_HOST);
  });

  it("without sender.origin, the URL's origin; without tab.url, the top frame's own URL", () => {
    const f = senderFacts({ url: "https://shop.test/a", tab: { id: 1 }, frameId: 0 });
    expect(f.origin).toBe("https://shop.test");
    expect(f.tabUrl).toBe("https://shop.test/a");
    expect(senderFacts({ url: "https://shop.test/a", tab: { id: 1 }, frameId: 1 }).tabUrl).toBe("");
  });
});

describe("strictest", () => {
  it("picks the strictest verdict and keeps the first on a tie", () => {
    expect(strictest([d("allow"), d("approve"), d("warn")]).decision.verdict).toBe("approve");
    expect(strictest([d("deny"), d("approve")]).decision.verdict).toBe("deny");
    const first = d("approve", "gate.always_on");
    expect(strictest([first, d("approve", "gate.agent_mode")])).toBe(first);
  });

  it("candidates keep the authoritative value first and drop repeats", () => {
    expect(candidates("a", "b", "a", "b")).toEqual(["a", "b"]);
    expect(candidates("")).toEqual([""]);
  });
});
