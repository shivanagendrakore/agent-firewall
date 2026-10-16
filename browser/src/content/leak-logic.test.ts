import { describe, expect, it } from "vitest";
import { formText, holdsBack, insertsText, isTextInputType, noticeText, prospectiveValue, reported } from "./leak-logic.js";

describe("leak guard helpers", () => {
  it("computes the value an insertion produces", () => {
    expect(prospectiveValue("48291", 5, 5, "5")).toBe("482915");
    expect(prospectiveValue("abc", 1, 2, "XY")).toBe("aXYc");
    expect(prospectiveValue("abc", null, null, "d")).toBe("abcd");
    expect(prospectiveValue("abc", 2, 1, "d")).toBe("abcd");
    expect(prospectiveValue("abc", 0, 9, "d")).toBe("abcd");
  });
  it("holds back only approve and deny; reports everything but allow", () => {
    expect(holdsBack("approve")).toBe(true);
    expect(holdsBack("deny")).toBe(true);
    expect(holdsBack("warn")).toBe(false);
    expect(holdsBack("log")).toBe(false);
    expect(holdsBack("allow")).toBe(false);
    expect(reported("allow")).toBe(false);
    expect(reported("log")).toBe(true);
  });
  it("treats text insertions as data and deletions as not", () => {
    expect(insertsText("insertText")).toBe(true);
    expect(insertsText("insertFromPaste")).toBe(true);
    expect(insertsText("insertReplacementText")).toBe(true);
    expect(insertsText("deleteContentBackward")).toBe(false);
    expect(insertsText("insertParagraph")).toBe(false);
    expect(insertsText("formatBold")).toBe(false);
  });
  it("checks free-text inputs only", () => {
    for (const t of ["text", "", "email", "password", "search", "tel", "url", "number"]) expect(isTextInputType(t)).toBe(true);
    for (const t of ["checkbox", "radio", "file", "submit", "hidden", "range"]) expect(isTextInputType(t)).toBe(false);
  });
  it("joins a form's fields with names, skipping empty ones", () => {
    expect(formText([{ name: "code", value: "482915" }, { name: "note", value: "" }, { name: "x", value: "y" }])).toBe("code=482915\nx=y");
  });
  it("the notice names findings, never values, and points to the side panel", () => {
    const t = noticeText("approve", [{ kind: "seen_elsewhere", name: "private string", masked: "", seenOn: "mail.test" }], "attacker.test");
    expect(t).toContain("mail.test");
    expect(t).toContain("side panel");
    expect(noticeText("warn", [{ kind: "card", name: "card", masked: "4539…11" }], "attacker.test")).not.toContain("4539");
    expect(noticeText("deny", [], "attacker.test").toLowerCase()).not.toContain("protected");
  });
});
