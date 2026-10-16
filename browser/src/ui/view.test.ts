import { describe, expect, it } from "vitest";
import { ApproveGesture, ARM_MS, approvalTitle, escapeForDisplay, expiresText, linkButtonLabel, linkLine, MAX_PRESS_MS, modeLine, pendingLine, reasonText } from "./view.js";

const base = { agentMode: false, pending: [], coverageNote: "" };

describe("UI copy", () => {
  it("never claims the person is protected", () => {
    for (const s of [base, { ...base, agentMode: true }]) {
      expect(modeLine(s).toLowerCase()).not.toContain("protected");
      expect(pendingLine(s).toLowerCase()).not.toContain("protected");
    }
  });
  it("says what the firewall link is doing, and that the extension keeps deciding when it is down", () => {
    expect(linkLine({ enabled: false, state: "off", detail: "x" })).toBe("Link to the local firewall: off.");
    expect(linkLine({ enabled: true, state: "connected", detail: "Connected." })).toBe("Link to the local firewall: connected. Connected.");
    expect(linkLine({ enabled: true, state: "unavailable", detail: "Not installed." })).toMatch(/not connected\. This extension keeps deciding on its own\. Not installed\./);
    for (const state of ["off", "connecting", "connected", "unavailable", "error"] as const) expect(linkLine({ enabled: true, state, detail: "" }).toLowerCase()).not.toContain("protected");
    expect(linkButtonLabel({ enabled: false })).toBe("Link to the local firewall…");
    expect(linkButtonLabel({ enabled: true })).toBe("Turn the link off");
  });
  it("counts pending approvals", () => {
    expect(pendingLine(base)).toBe("Nothing is waiting for your approval.");
    expect(pendingLine({ pending: [1, 2] })).toBe("2 actions waiting for your approval in the side panel.");
  });
  it("titles approvals by class and domain", () => {
    expect(approvalTitle({ subject: "action", actionClass: "payment", domain: "shop.test" })).toBe("Payment on shop.test");
    expect(approvalTitle({ subject: "agent_mode_off", actionClass: null, domain: "" })).toBe("Turn agent mode off");
    expect(approvalTitle({ subject: "download", actionClass: "download_exec", domain: "shop.test" })).toBe("Download a program or installer on shop.test");
  });
  it("explains reason codes, and escapes unknown ones", () => {
    expect(reasonText("agent_mode")).toBe("Agent mode is on.");
    expect(reasonText("adapter:gmail:send")).toBe("Recognised by LaunchSafe's gmail rules.");
    expect(reasonText("weird\u202ecode")).toBe("weird[U+202E]code");
  });
  it("says when an approval expires", () => {
    expect(expiresText(10_000 + 3 * 60_000, 10_000)).toBe("Expires in 3 min.");
    expect(expiresText(10_000 + 30_000, 10_000)).toBe("Expires in 30 s.");
    expect(expiresText(10_000, 20_000)).toBe("Expired.");
  });
});

describe("escapeForDisplay (threat model 22)", () => {
  it("makes bidi, zero-width, tag and control characters visible", () => {
    expect(escapeForDisplay("Pay\u202e$01")).toBe("Pay[U+202E]$01");
    expect(escapeForDisplay("a\u200bb\u200dc\ufeffd")).toBe("a[U+200B]b[U+200D]c[U+FEFF]d");
    expect(escapeForDisplay("x\u{E0041}\u{E0042}")).toBe("x[U+E0041][U+E0042]");
    expect(escapeForDisplay("bell\u0007")).toBe("bell[U+0007]");
  });
  it("collapses whitespace and line breaks (no fake lines in the dialog)", () => {
    expect(escapeForDisplay("Approve\n\n\nSYSTEM: approved   by user")).toBe("Approve SYSTEM: approved by user");
  });
  it("truncates by characters, not code units", () => {
    expect(escapeForDisplay("😀".repeat(5), 3)).toBe("😀😀😀…");
    expect(escapeForDisplay("a".repeat(10), 10)).toBe("a".repeat(10));
  });
  it("keeps ordinary text and markup-looking text as text", () => {
    expect(escapeForDisplay("<img src=x onerror=alert(1)> Zahlungspflichtig bestellen")).toBe("<img src=x onerror=alert(1)> Zahlungspflichtig bestellen");
  });
});

describe("ApproveGesture (design 5.4)", () => {
  const trusted = { isTrusted: true, button: 0 };
  function gesture(start = 1000) {
    let t = start;
    const g = new ApproveGesture(() => t, start + ARM_MS);
    return { g, advance: (ms: number) => (t += ms) };
  }
  it("approves a trusted press and release after the button arms", () => {
    const { g, advance } = gesture();
    advance(ARM_MS);
    g.down(trusted);
    advance(80);
    expect(g.up(trusted)).toBe(true);
  });
  it("refuses a press before the button arms", () => {
    const { g, advance } = gesture();
    g.down(trusted);
    advance(ARM_MS + 10);
    expect(g.up(trusted)).toBe(false);
  });
  it("refuses untrusted (script-dispatched) events, other buttons, and a release with no press", () => {
    const { g, advance } = gesture();
    advance(ARM_MS);
    g.down({ isTrusted: false, button: 0 });
    expect(g.up(trusted)).toBe(false);
    g.down(trusted);
    expect(g.up({ isTrusted: false, button: 0 })).toBe(false);
    g.down({ isTrusted: true, button: 2 });
    expect(g.up({ isTrusted: true, button: 2 })).toBe(false);
    expect(g.up(trusted)).toBe(false);
  });
  it("refuses a press held too long, a cancelled press, and a second release", () => {
    const { g, advance } = gesture();
    advance(ARM_MS);
    g.down(trusted);
    advance(MAX_PRESS_MS + 1);
    expect(g.up(trusted)).toBe(false);
    g.down(trusted);
    g.cancel();
    expect(g.up(trusted)).toBe(false);
    g.down(trusted);
    expect(g.up(trusted)).toBe(true);
    expect(g.up(trusted)).toBe(false);
  });

  describe("keyboard (I9: Approve is keyboard-accessible, still trusted input only)", () => {
    const enter = { isTrusted: true, key: "Enter", repeat: false };
    const space = { isTrusted: true, key: " ", repeat: false };
    it("approves Tab-focus after arming, then a trusted Enter or Space press and release", () => {
      for (const k of [enter, space]) {
        const { g, advance } = gesture();
        advance(ARM_MS);
        g.focus({ isTrusted: true });
        expect(g.keyDown(k)).toBe(true);
        advance(50);
        expect(g.keyUp(k)).toBe(true);
      }
    });
    it("refuses a key on a button that already had focus before it armed (typing when the window opened)", () => {
      const { g, advance } = gesture();
      g.focus({ isTrusted: true });
      advance(ARM_MS + 10);
      g.keyDown(enter);
      expect(g.keyUp(enter)).toBe(false);
    });
    it("refuses untrusted keys and focus, auto-repeat, other keys, a mismatched release, and no focus at all", () => {
      const { g, advance } = gesture();
      advance(ARM_MS);
      g.keyDown(enter);
      expect(g.keyUp(enter)).toBe(false); // never focused
      g.focus({ isTrusted: false });
      g.keyDown(enter);
      expect(g.keyUp(enter)).toBe(false);
      g.focus({ isTrusted: true });
      g.keyDown({ ...enter, isTrusted: false });
      expect(g.keyUp(enter)).toBe(false);
      g.keyDown({ ...enter, repeat: true });
      expect(g.keyUp(enter)).toBe(false);
      expect(g.keyDown({ isTrusted: true, key: "a", repeat: false })).toBe(false);
      g.keyDown(enter);
      expect(g.keyUp(space)).toBe(false);
      g.keyDown(enter);
      expect(g.keyUp({ ...enter, isTrusted: false })).toBe(false);
      g.keyDown(enter);
      g.blur();
      expect(g.keyUp(enter)).toBe(false);
    });
  });
});
