/**
 * Builders for engine tests. Not imported by product code (lint keeps the
 * engine pure; this file only builds plain data).
 */
import type { EffectiveTrust } from "./session.js";
import type { ControlContext, FieldInfo, FrameRef, NormalizedAction } from "./types.js";

export function trust(over: Partial<EffectiveTrust> = {}): EffectiveTrust {
  return { agentMode: false, declaredClass: null, untrusted: false, private: false, quarantined: false, sessionDomains: new Set(), grants: new Set(), prints: [], ...over };
}

export function agentTrust(over: Partial<EffectiveTrust> = {}): EffectiveTrust {
  return trust({ agentMode: true, declaredClass: "unknown", ...over });
}

export function frame(origin = "https://shop.test", tabId = 1, frameId = 0): FrameRef {
  return { tabId, frameId, origin };
}

export function ctx(pageUrl = "https://shop.test/", over: Partial<ControlContext> = {}): ControlContext {
  return { pageUrl, ...over };
}

export function activate(label: string, over: Partial<Extract<NormalizedAction, { kind: "activate" }>> = {}): Extract<NormalizedAction, { kind: "activate" }> {
  return { kind: "activate", frame: frame(), elementPath: "html>body>main>button:nth-of-type(1)", label, role: "button", tag: "button", context: ctx(), ...over };
}

export function submit(fields: FieldInfo[], over: Partial<Extract<NormalizedAction, { kind: "submit" }>> = {}): Extract<NormalizedAction, { kind: "submit" }> {
  return { kind: "submit", frame: frame(), elementPath: "html>body>form:nth-of-type(1)", form: { fields, targetUrl: "https://shop.test/order", method: "post" }, context: ctx(), ...over };
}

export function upload(over: Partial<Extract<NormalizedAction, { kind: "upload" }>> = {}): Extract<NormalizedAction, { kind: "upload" }> {
  return { kind: "upload", frame: frame(), elementPath: "html>body>form>input[type=file]", files: [{ name: "passport.pdf", size: 120_000, type: "application/pdf" }], context: ctx(), ...over };
}

export function download(filename: string, mime = "application/octet-stream"): Extract<NormalizedAction, { kind: "download" }> {
  return { kind: "download", tabId: 1, url: `https://shop.test/files/${filename}`, filename, mime };
}

/** A Luhn-valid card number that is not a published test number. */
export function realLookingCard(prefix = "453914880343646"): string {
  for (let d = 0; d <= 9; d++) {
    const n = `${prefix}${d}`;
    let sum = 0;
    let dbl = false;
    for (let i = n.length - 1; i >= 0; i--) {
      let x = Number(n[i]);
      if (dbl) {
        x *= 2;
        if (x > 9) x -= 9;
      }
      sum += x;
      dbl = !dbl;
    }
    if (sum % 10 === 0) return n;
  }
  throw new Error("unreachable");
}
