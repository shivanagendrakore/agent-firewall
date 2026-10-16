import { describe, expect, it } from "vitest";
import { clipIsTiny, clipPathIsEmpty, hiddenKindOf, ownRendered, type StyleFacts } from "./visibility.js";

const SHOWN: StyleFacts = {
  rendered: true,
  opacity: 1,
  fontSizePx: 16,
  color: "rgb(17, 19, 24)",
  background: "rgb(255, 255, 255)",
  clip: "auto",
  clipPath: "none",
  position: "static",
  overflowX: "visible",
  overflowY: "visible",
  textIndentPx: 0,
  rect: { left: 10, top: 10, width: 300, height: 20 },
  displayContents: false,
};
const f = (over: Partial<StyleFacts>): StyleFacts => ({ ...SHOWN, ...over });

describe("live visibility (design 4.2)", () => {
  it("ordinary text is shown", () => {
    expect(hiddenKindOf(SHOWN)).toBeNull();
  });

  it("each hiding technique is caught", () => {
    expect(hiddenKindOf(f({ rendered: false }))).toBe("not_rendered"); // display none, visibility hidden, hidden, content-visibility
    expect(hiddenKindOf(f({ opacity: 0.02 }))).toBe("not_rendered");
    expect(hiddenKindOf(f({ fontSizePx: 0 }))).toBe("tiny_font");
    expect(hiddenKindOf(f({ fontSizePx: 1 }))).toBe("tiny_font");
    expect(hiddenKindOf(f({ position: "absolute", clip: "rect(0px, 0px, 0px, 0px)" }))).toBe("clipped");
    expect(hiddenKindOf(f({ clipPath: "inset(50%)" }))).toBe("clipped");
    expect(hiddenKindOf(f({ rect: { left: 0, top: 0, width: 0, height: 0 }, overflowX: "hidden", overflowY: "hidden" }))).toBe("zero_box");
    expect(hiddenKindOf(f({ rect: { left: 0, top: 0, width: 1, height: 1 }, overflowX: "clip", overflowY: "clip" }))).toBe("zero_box");
    expect(hiddenKindOf(f({ rect: { left: -9999, top: 10, width: 300, height: 20 }, position: "absolute" }))).toBe("offscreen");
    expect(hiddenKindOf(f({ rect: { left: 10, top: -5000, width: 300, height: 20 }, position: "absolute" }))).toBe("offscreen");
    expect(hiddenKindOf(f({ rect: { left: 12000, top: 10, width: 300, height: 20 }, position: "absolute" }))).toBe("offscreen");
    expect(hiddenKindOf(f({ textIndentPx: -9999 }))).toBe("offscreen");
    expect(hiddenKindOf(f({ color: "rgb(255, 255, 255)" }))).toBe("low_contrast"); // same colour as the page
    expect(hiddenKindOf(f({ color: "rgb(250, 250, 250)" }))).toBe("low_contrast"); // near-same colour
    expect(hiddenKindOf(f({ color: "rgba(0, 0, 0, 0)" }))).toBe("low_contrast"); // transparent text
  });

  it("does not call ordinary layouts hidden", () => {
    expect(hiddenKindOf(f({ color: "rgb(120, 120, 120)" }))).toBeNull(); // muted grey text
    expect(hiddenKindOf(f({ color: "rgb(255, 255, 255)", background: null }))).toBeNull(); // white text over an image: unknown, not hidden
    expect(hiddenKindOf(f({ color: "rgb(255, 255, 255)", background: "rgb(17, 19, 24)" }))).toBeNull(); // dark mode
    expect(hiddenKindOf(f({ rect: { left: 0, top: 0, width: 300, height: 0 } }))).toBeNull(); // zero height, overflow visible: text still shows
    expect(hiddenKindOf(f({ rect: { left: -40, top: 10, width: 300, height: 20 } }))).toBeNull(); // partly off the left edge
    expect(hiddenKindOf(f({ displayContents: true, rect: { left: 0, top: 0, width: 0, height: 0 }, overflowX: "hidden" }))).toBeNull();
    expect(hiddenKindOf(f({ clip: "rect(0px, 0px, 0px, 0px)", position: "static" }))).toBeNull(); // clip applies only to positioned boxes
    expect(hiddenKindOf(f({ opacity: 0.6 }))).toBeNull();
    expect(hiddenKindOf(f({ fontSizePx: 11 }))).toBeNull();
  });

  it("parses clip and clip-path values", () => {
    expect(clipIsTiny("rect(0px, 0px, 0px, 0px)")).toBe(true);
    expect(clipIsTiny("rect(1px 1px 1px 1px)")).toBe(true);
    expect(clipIsTiny("rect(0px, 200px, 40px, 0px)")).toBe(false);
    expect(clipIsTiny("auto")).toBe(false);
    expect(clipPathIsEmpty("inset(50%)")).toBe(true);
    expect(clipPathIsEmpty("inset(100% 0 0 0)")).toBe(true);
    expect(clipPathIsEmpty("circle(0px at 50% 50%)")).toBe(true);
    expect(clipPathIsEmpty("polygon(0px 0px, 0px 0px, 0px 0px)")).toBe(true);
    expect(clipPathIsEmpty("inset(10px)")).toBe(false);
    expect(clipPathIsEmpty("circle(40% at 50% 50%)")).toBe(false);
    expect(clipPathIsEmpty("none")).toBe(false);
  });
});

describe("FP-4: display: contents is transparent", () => {
  it("an element with no box of its own is rendered unless its own visibility hides it", () => {
    const never = () => false; // checkVisibility() is false for display: contents
    expect(ownRendered("contents", "visible", never)).toBe(true);
    expect(ownRendered("contents", "hidden", never)).toBe(false);
    expect(ownRendered("contents", "collapse", never)).toBe(false);
  });
  it("other elements take checkVisibility() as it is, or display and visibility without it", () => {
    expect(ownRendered("block", "visible", () => false)).toBe(false);
    expect(ownRendered("block", "visible", () => true)).toBe(true);
    expect(ownRendered("none", "visible", null)).toBe(false);
    expect(ownRendered("inline", "hidden", null)).toBe(false);
    expect(ownRendered("flex", "visible", null)).toBe(true);
  });
  it("clip and clip-path do not hide an element with no box", () => {
    expect(hiddenKindOf(f({ displayContents: true, clipPath: "inset(50%)" }))).toBeNull();
    expect(hiddenKindOf(f({ displayContents: true, position: "absolute", clip: "rect(0px, 0px, 0px, 0px)" }))).toBeNull();
  });
});
