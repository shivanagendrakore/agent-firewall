import { describe, expect, it } from "vitest";
import { hrefScheme } from "./nav.js";

describe("href schemes as the browser reads them", () => {
  it("finds javascript: however it is spelled", () => {
    for (const h of ["javascript:alert(1)", "JavaScript:void(0)", "  javascript:x", "\u0001javascript:x", "java\tscript:x", "jav\nascript:x"]) expect(hrefScheme(h)).toBe("javascript");
  });
  it("reads ordinary links", () => {
    expect(hrefScheme("https://shop.test/")).toBe("https");
    expect(hrefScheme("/relative/path")).toBe("");
    expect(hrefScheme("#top")).toBe("");
    expect(hrefScheme("mailto:a@b.test")).toBe("mailto");
  });
});
