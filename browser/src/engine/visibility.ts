/**
 * Live-DOM visibility (design 4.2), as a pure function of facts the content
 * script reads from the browser (checkVisibility, computed style, the box).
 * Kept here, outside the content script, so every rule has a Node test.
 *
 * One element's own reason only: the content script inherits a parent's
 * verdict itself (a child of a hidden element is hidden whatever its style).
 */
import { contrastRatio, parseColour } from "../vendor/firewall/engine/content-html.js";
import type { HiddenKind } from "./content.js";

export interface StyleFacts {
  /** ownRendered(): element.checkVisibility({ opacityProperty, visibilityProperty, contentVisibilityAuto }), display: contents transparent. */
  rendered: boolean;
  /** Opacity multiplied along the ancestor chain. */
  opacity: number;
  fontSizePx: number;
  /** Computed `color`. */
  color: string;
  /** The first opaque background colour behind the element, or null when an image or unknown paint sits behind it. */
  background: string | null;
  clip: string;
  clipPath: string;
  position: string;
  overflowX: string;
  overflowY: string;
  textIndentPx: number;
  /** The border box in document coordinates. */
  rect: { left: number; top: number; width: number; height: number };
  /** display: contents boxes have no rect of their own; they are judged by their children. */
  displayContents: boolean;
}

/** Below this contrast against the background, text is the same colour as the page (design 4.2). */
export const MIN_CONTRAST = 1.2;
/** Effective opacity under which text is invisible. */
export const MIN_OPACITY = 0.1;
/** Font size under which text is unreadable. */
export const MIN_FONT_PX = 2;
/** A box narrower or shorter than this, with its overflow clipped, shows nothing. */
export const MIN_BOX_PX = 2;
/** Far enough left or up that the text sits outside any document. */
export const OFFSCREEN_PX = 999;

const CLIPS = /^(?:hidden|clip)$/;

/** True when a `clip: rect(...)` value leaves under 2 px either way. */
export function clipIsTiny(clip: string): boolean {
  const m = /^rect\(\s*([-\d.]+)px[\s,]+([-\d.]+)px[\s,]+([-\d.]+)px[\s,]+([-\d.]+)px\s*\)$/.exec(clip.trim());
  if (m === null) return false;
  const [top, right, bottom, left] = m.slice(1).map(Number) as [number, number, number, number];
  return right - left < MIN_BOX_PX || bottom - top < MIN_BOX_PX;
}

/** True for clip-path values that show nothing: inset(50%) and beyond, a zero circle or ellipse, a degenerate polygon. */
export function clipPathIsEmpty(clipPath: string): boolean {
  const v = clipPath.trim().toLowerCase();
  if (v === "" || v === "none") return false;
  const inset = /^inset\(\s*([\d.]+)(%|px)?/.exec(v);
  if (inset !== null) return inset[2] === "%" && Number(inset[1]) >= 50;
  if (/^(?:circle|ellipse)\(\s*0(?:px|%)?(?:\s|\)|,)/.test(v)) return true;
  const poly = /^polygon\((.*)\)$/.exec(v);
  if (poly !== null) {
    const pts = (poly[1] ?? "").split(",").map((p) => p.trim());
    return pts.length > 0 && pts.every((p) => p === pts[0]);
  }
  return false;
}

/**
 * Whether the element itself is rendered. `checkVisibility()` is false for `display: contents` (no box of its
 * own), but its children render as if they were its parent's, so such an element is transparent (FP-4): only
 * its own `visibility`, which its children inherit, can hide it; each child is judged on its own box.
 * `check` is element.checkVisibility(...), or null in a browser without it.
 */
export function ownRendered(display: string, visibility: string, check: (() => boolean) | null): boolean {
  if (display === "contents") return visibility !== "hidden" && visibility !== "collapse";
  if (check !== null) return check();
  return display !== "none" && visibility !== "hidden" && visibility !== "collapse";
}

/** The element's own reason to be hidden, or null when its own style shows its text. */
export function hiddenKindOf(f: StyleFacts): HiddenKind | null {
  if (!f.rendered) return "not_rendered";
  if (f.opacity < MIN_OPACITY) return "not_rendered";
  if (f.fontSizePx < MIN_FONT_PX) return "tiny_font";
  const absolute = f.position === "absolute" || f.position === "fixed";
  // clip and clip-path do not apply to an element with no box (display: contents).
  if (!f.displayContents && ((absolute && clipIsTiny(f.clip)) || clipPathIsEmpty(f.clipPath))) return "clipped";
  if (!f.displayContents && (f.rect.width < MIN_BOX_PX || f.rect.height < MIN_BOX_PX) && (CLIPS.test(f.overflowX) || CLIPS.test(f.overflowY))) return "zero_box";
  if (!f.displayContents && (f.rect.left + f.rect.width <= -OFFSCREEN_PX / 10 || f.rect.top + f.rect.height <= -OFFSCREEN_PX / 10)) return "offscreen";
  if (!f.displayContents && absolute && (f.rect.left >= 5000 || f.rect.top >= 20000)) return "offscreen";
  if (f.textIndentPx <= -OFFSCREEN_PX) return "offscreen";
  const fg = parseColour(f.color);
  if (fg !== null && fg[3] < MIN_OPACITY) return "low_contrast";
  if (fg !== null && f.background !== null) {
    const bg = parseColour(f.background);
    if (bg !== null && bg[3] >= 0.99 && contrastRatio(fg, bg) < MIN_CONTRAST) return "low_contrast";
  }
  return null;
}
