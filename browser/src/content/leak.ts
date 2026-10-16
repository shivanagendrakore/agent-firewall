/**
 * Data-leak guard (design 6), content side.
 *
 * Checks the data a field, paste or form is about to carry, inside the event
 * that would carry it, so a block is a real block:
 *
 * - `beforeinput` (keystrokes, Input.insertText, form_input-style insertions):
 *   cancelled when the value it would produce holds data back;
 * - `input`: the value after a change that could not be cancelled (IME,
 *   execCommand) is checked and reverted to the last allowed value;
 * - `paste`: cancelled the same way;
 * - `submit`: every field of the form (hidden ones too) is checked, which also
 *   catches values a script set with no event at all;
 * - a value poller catches values set without events before any submit.
 *
 * Decisions are made synchronously from the leak context the worker pushes
 * (agent mode, trust flags, print hashes; engine.decideLeakLocally). Until the
 * first context arrives, or while the last one the worker sent was refused
 * (stale), the frame decides as if agent mode were on, and every non-empty
 * insertion or paste is cancelled and the field frozen until the worker
 * answers (an allow puts the value in), so nothing reaches the page before a
 * decision it can trust; values that changed with no cancellable event (IME,
 * execCommand, script) and every submit also go to the worker, so a page cannot
 * win the start-up race and a refused context fails toward "ask the worker",
 * never "allow". A value or form over 64 KB is never judged here (one scan
 * call is bounded): it is held and the worker, which rate-limits each frame,
 * decides. Every non-allow verdict goes to the worker (`leak.guard`), which
 * re-decides authoritatively, logs, and creates the approval; if it says allow
 * (a stale context), the held value is put back at once; if it is stricter than
 * the local warn or allow, its verdict wins and the value is taken back.
 *
 * An approved hold is replayed exactly once, after the worker redeems its
 * token against the same binding (engine.leakSnapshot): the field gets the
 * approved value back, or the form is submitted again.
 *
 * Seen-elsewhere fingerprints: the page's visible text is fingerprinted at
 * DOMContentLoaded and after changes (debounced); only one-way hashes go to the
 * worker (`private.prints`), never the strings.
 *
 * Link clicks: a click on a link whose query values carry private data (a
 * print from another site, a secret, a card) and would be held (agent mode, or
 * no trusted context yet) is cancelled and asked about like a submit; an
 * approval opens the link once. A navigation started by script or typed into
 * the address bar is not seen here (the navigation lane's rules still apply).
 *
 * Shadow DOM: field events are read from the composed path (the real field,
 * not the shadow host), and forms in open shadow roots get their own submit
 * listener (submit is not composed). Closed shadow roots are a residual.
 *
 * A page can clobber a form's properties with named controls (`name="action"`,
 * `name="elements"`): forms are read through prototype getters (dom-safe.ts),
 * and any listener that still throws fails closed: the event is cancelled and
 * the worker is told (it logs the attempt); the person or agent tries again.
 */
import { APPROVAL_TTL_MS } from "../engine/bindings.js";
import { DEFAULT_POLICY } from "../engine/types.js";
import { decideLeakLocally, EMPTY_LEAK_CONTEXT, leakSnapshot, type LeakBindingInput, type LeakContext, type LeakFinding, type LeakVia } from "../engine/leak.js";
import { printsFor } from "../engine/private-data.js";
import { LIMITS, parseWorkerMessage, type LeakReply } from "../shared/messages.js";
import { attr, childrenOf, connected, containsNode, formAction, formControls, idOf, isElement, isForm, parentOf, rootOf, submitForm, tagOf } from "./dom-safe.js";
import { randomMark } from "./gate-notice.js";
import { exceedsLocalScan, formText, holdsBack, insertsText, isTextInputType, linkQueryText, noticeText, prospectiveValue, reported } from "./leak-logic.js";
import { shadowRootWatcher } from "./shadow-roots.js";
import type { ContentDeps, ContentModule } from "./types.js";

export interface LeakGuard extends ContentModule {
  /** Fingerprint the private strings in a page's visible text (also called by the content guard after a scan). */
  notePrivateText(text: string): void;
  /** The worker pushed a new leak context. */
  setContext(ctx: LeakContext): void;
  /** The worker sent a context this frame refused (malformed or over a bound): stop trusting the last one. */
  markStale(): void;
  /** An approval was granted; returns true when it was one of the leak guard's holds (then it replays it once). */
  onApprovalGranted(approvalId: string, token: string): boolean;
  /** An approval was denied or expired; returns true when it was a leak hold. */
  onApprovalDenied(approvalId: string): boolean;
}

export interface LeakGuardOptions {
  /** Called with each context from the worker (index.ts keeps agent mode current from it). */
  onContext?: (ctx: LeakContext) => void;
  /** Value poller period (ms); 0 turns it off. */
  pollMs?: number;
}

type Field = HTMLInputElement | HTMLTextAreaElement;
type Editable = Field | HTMLElement;

interface Hold {
  via: LeakVia;
  el: Editable;
  form?: HTMLFormElement;
  submitter?: HTMLElement | null;
  /** A link click held for its query values: opened once on release. */
  navigate?: string;
  text: string;
  fieldName: string;
  elementPath: string;
  destinationHost: string;
}

const MAX_TEXT_SCAN = 300_000;
const MAX_POLLED = 300;
const PRINT_DEBOUNCE_MS = 400;

function isField(el: Element | null): el is Field {
  if (el === null || !isElement(el)) return false;
  const tag = tagOf(el);
  if (tag === "TEXTAREA") return true;
  return tag === "INPUT" && isTextInputType((el as HTMLInputElement).type);
}

/** A stable path to the element: ids where present, else nth-of-type, up to 16 levels (read through dom-safe getters: forms can be clobbered). */
export function elementPath(el: Element): string {
  const parts: string[] = [];
  let cur: Element | null = el;
  for (let depth = 0; cur !== null && depth < 16; depth++) {
    const tag = tagOf(cur).toLowerCase();
    const id = idOf(cur);
    if (id !== "") {
      parts.unshift(`${tag}#${id}`);
      break;
    }
    const parent: Element | null = parentOf(cur);
    if (parent === null) {
      parts.unshift(tag);
      break;
    }
    const me: Element = cur;
    const same = childrenOf(parent).filter((c) => tagOf(c) === tagOf(me));
    parts.unshift(same.length > 1 ? `${tag}:nth-of-type(${same.indexOf(me) + 1})` : tag);
    cur = parent;
  }
  return parts.join(" > ");
}

function fieldNameOf(el: Editable): string {
  const n = isField(el) ? el.name : "";
  if (n !== "") return n;
  const id = idOf(el);
  return id !== "" ? id : tagOf(el).toLowerCase();
}

/** The first element of an event's composed path: the real field inside an open shadow root, not its host. */
function originOf(e: Event): Element | null {
  let first: EventTarget | undefined;
  try {
    first = e.composedPath()[0];
  } catch {
    first = undefined;
  }
  const t = first ?? e.target;
  if (isElement(t)) return t;
  if (t !== null && typeof t === "object" && (t as Node).nodeType === 3) return parentOf(t as Node);
  return null;
}

/** `closest` across open shadow roots (a contenteditable host may sit outside the root its text is in). */
function closestEditable(start: Element): HTMLElement | null {
  let el: Element | null = start;
  while (el !== null) {
    const hit = el.closest("[contenteditable]:not([contenteditable=false])");
    if (hit !== null) return hit as HTMLElement;
    const root = rootOf(el);
    el = root instanceof ShadowRoot ? root.host : null;
  }
  return null;
}

function valueOf(el: Editable): string {
  return isField(el) ? el.value : (el.innerText ?? "");
}

function setValue(el: Editable, v: string): void {
  if (isField(el)) el.value = v;
  else el.textContent = v;
}

/** The text an insertion or paste event carries, read without trusting anything else on the page. */
function eventText(e: Event): string {
  try {
    const ie = e as InputEvent & ClipboardEvent;
    return ie.data ?? ie.dataTransfer?.getData("text/plain") ?? ie.clipboardData?.getData("text/plain") ?? "";
  } catch {
    return "";
  }
}

export function createLeakGuard(deps: ContentDeps, opts: LeakGuardOptions = {}): LeakGuard {
  const win = deps.win;
  const doc = win.document;
  let ctx: LeakContext = EMPTY_LEAK_CONTEXT;
  let ctxLoaded = false;
  /** The worker's last push was refused: the context in hand may lack prints or flags the worker has. */
  let ctxStale = false;
  /** Whether a local allow can stand on its own; otherwise the worker is asked and its stricter verdict wins. */
  const ctxTrusted = (): boolean => ctxLoaded && !ctxStale;
  /** The value last confirmed safe per field (a trusted local allow, or the worker's allow): what the worker's overruling hold reverts to. */
  const confirmed = new WeakMap<Editable, string>();
  /** The value last allowed per field: what a block reverts to. */
  const lastAllowed = new WeakMap<Editable, string>();
  /** The value the poller last saw per field. */
  const lastSeen = new WeakMap<Editable, string>();
  /** A value the worker allowed or a person approved for this field: let it through once more. */
  const passValue = new WeakMap<Editable, string>();
  /** A form whose next submit is our own replay of an allowed or approved submit. */
  const passForm = new WeakSet<HTMLFormElement>();
  /** Fields with a hold waiting for the person or the worker: further insertions are refused until it resolves. */
  const frozen = new WeakSet<Editable>();
  const holds = new Map<string, Hold>();
  const holdTimers = new Map<string, ReturnType<typeof setTimeout>>();
  const dropTimer = (approvalId: string): void => {
    const t = holdTimers.get(approvalId);
    if (t !== undefined) clearTimeout(t);
    holdTimers.delete(approvalId);
  };
  /** Waits for the person's decision. The worker expires an unanswered approval silently, so the frame lets go of the field itself. */
  const holdUntilDecided = (approvalId: string, h: Hold): void => {
    holds.set(approvalId, h);
    dropTimer(approvalId);
    holdTimers.set(
      approvalId,
      setTimeout(() => {
        holdTimers.delete(approvalId);
        if (holds.get(approvalId) !== h) return;
        holds.delete(approvalId);
        frozen.delete(h.el);
      }, APPROVAL_TTL_MS + 1000),
    );
  };
  const sentPrints = new Set<string>();
  /** The last reported warn/log per field, so a warning is not sent on every keystroke. */
  const lastReport = new WeakMap<Editable, string>();
  const listeners: [string, EventListener][] = [];
  /** Open shadow roots we listen in (submit is not composed). */
  const rootListeners: ShadowRoot[] = [];
  let unsubscribeRoots: (() => void) | undefined;
  let poller: number | undefined;
  let observer: MutationObserver | undefined;
  let printTimer: number | undefined;

  const host = (): string => win.location.hostname;

  // ---- notice -----------------------------------------------------------------

  /**
   * A plain <div> host (never a custom element name a page could define and upgrade), marked with a random
   * attribute name, holding a closed shadow root: page script cannot read or restyle it. It explains; it is
   * never the approval.
   */
  const noticeMark = randomMark();
  let noticeHost: HTMLElement | null = null;
  let noticeBox: HTMLElement | null = null;
  let noticeTimer: number | undefined;
  const notice = (text: string): void => {
    try {
      if (doc.documentElement === null) return;
      if (noticeHost === null || !noticeHost.isConnected) {
        noticeHost = doc.createElement("div");
        noticeHost.setAttribute(noticeMark, "");
        const root = noticeHost.attachShadow({ mode: "closed" });
        noticeBox = doc.createElement("div");
        noticeBox.setAttribute("role", "status");
        noticeBox.style.cssText =
          "position:fixed;z-index:2147483647;right:16px;bottom:16px;max-width:360px;padding:10px 12px;border-radius:8px;background:#111318;color:#eceef3;font:13px/1.4 system-ui,sans-serif;box-shadow:0 4px 16px rgba(0,0,0,.3)";
        root.append(noticeBox);
        doc.documentElement.append(noticeHost);
      }
      if (noticeBox !== null) noticeBox.textContent = text;
      if (noticeTimer !== undefined) win.clearTimeout(noticeTimer);
      noticeTimer = win.setTimeout(() => noticeHost?.remove(), 10_000);
    } catch {
      // A page that broke the DOM methods we use: the side panel still shows any approval.
    }
  };

  // ---- decisions ----------------------------------------------------------------

  const clip = (s: string, max: number): string => (s.length > max ? s.slice(0, max) : s);

  /** Where the data goes: the form's target host for a submit, this frame's host for typing and pasting. */
  const destinationFor = (form?: HTMLFormElement, submitter?: HTMLElement | null): string => {
    if (form !== undefined) {
      try {
        const sub = submitter != null && connected(submitter) && containsNode(form, submitter) ? attr(submitter, "formaction") : null;
        return new URL(sub !== null && sub !== "" ? sub : formAction(form), win.location.href).hostname || host();
      } catch {
        return host();
      }
    }
    return host();
  };

  const merchantFor = (fields: readonly Editable[]): string | undefined => (fields.some((f) => isField(f) && /^cc-/i.test(attr(f, "autocomplete") ?? "")) ? host() : undefined);

  const decide = (text: string, destinationHost: string, merchant: string | undefined) => {
    // Before the worker's first context, or with a stale one, decide as agent mode on: fail closed, the worker can release it.
    const c = ctxTrusted() ? ctx : { ...ctx, agentMode: true };
    return decideLeakLocally({ text, destinationHost, frameHost: host(), ...(merchant !== undefined ? { checkoutMerchantHost: merchant } : {}) }, c, DEFAULT_POLICY);
  };

  const fieldsOf = (form: HTMLFormElement): Field[] =>
    formControls(form).filter((x): x is Field => {
      const tag = tagOf(x);
      return tag === "TEXTAREA" || (tag === "INPUT" && (isTextInputType((x as HTMLInputElement).type) || (x as HTMLInputElement).type === "hidden"));
    });

  const formTextOf = (fields: readonly Field[]): string => formText(fields.map((f) => ({ name: f.name || idOf(f) || f.type, value: f.value })));

  /** Re-reads the held element, form or link from the live DOM; null when disconnected or no longer a link. */
  const liveBinding = (h: Hold): LeakBindingInput | null => {
    try {
      if (!connected(h.el)) return null;
      if (h.navigate !== undefined) {
        const raw = attr(h.el, "href");
        if (raw === null) return null;
        const url = new URL(raw, win.location.href);
        if (url.protocol !== "http:" && url.protocol !== "https:") return null;
        return {
          tabId: 0,
          frameId: 0,
          frameOrigin: win.location.origin,
          via: h.via,
          elementPath: clip(elementPath(h.el), LIMITS.path),
          fieldName: clip(h.fieldName, LIMITS.name),
          text: clip(linkQueryText(url), LIMITS.text),
          destinationHost: url.hostname,
        };
      }
      if (h.via === "submit" && h.form !== undefined) {
        if (!connected(h.form)) return null;
        const fields = fieldsOf(h.form);
        return {
          tabId: 0,
          frameId: 0,
          frameOrigin: win.location.origin,
          via: "submit",
          elementPath: clip(elementPath(h.form), LIMITS.path),
          fieldName: clip(h.fieldName, LIMITS.name),
          text: clip(formTextOf(fields), LIMITS.text),
          destinationHost: destinationFor(h.form, h.submitter),
        };
      }
      return {
        tabId: 0,
        frameId: 0,
        frameOrigin: win.location.origin,
        via: h.via,
        elementPath: clip(elementPath(h.el), LIMITS.path),
        fieldName: clip(fieldNameOf(h.el), LIMITS.name),
        text: clip(h.text, LIMITS.text),
        destinationHost: destinationFor(),
      };
    } catch {
      return null;
    }
  };

  const sameBinding = (live: LeakBindingInput | null, h: Hold): boolean =>
    live !== null &&
    live.elementPath === clip(h.elementPath, LIMITS.path) &&
    live.fieldName === clip(h.fieldName, LIMITS.name) &&
    live.text === clip(h.text, LIMITS.text) &&
    live.destinationHost === h.destinationHost;

  const ask = (h: Hold): Promise<LeakReply | undefined> => {
    let merchant: string | undefined;
    try {
      merchant = merchantFor(h.form !== undefined ? fieldsOf(h.form) : [h.el]);
    } catch {
      merchant = undefined;
    }
    return deps
      .send({
        type: "leak.guard",
        via: h.via,
        text: clip(h.text, LIMITS.text),
        destinationHost: h.destinationHost,
        ...(merchant !== undefined ? { checkoutMerchantHost: host() } : {}),
        elementPath: clip(h.elementPath, LIMITS.path),
        fieldName: clip(h.fieldName, LIMITS.name),
      })
      .catch(() => undefined);
  };

  /** A link the person approved (or the worker allowed): our own navigation to it passes once. */
  let passNavigate: string | null = null;

  /** Puts a held value back (the worker allowed it, or a person approved it). */
  const release = (h: Hold): void => {
    frozen.delete(h.el);
    if (!sameBinding(liveBinding(h), h)) return;
    if (h.navigate !== undefined) {
      let href: string;
      try {
        href = new URL(attr(h.el, "href") ?? "", win.location.href).href;
      } catch {
        return;
      }
      if (href !== h.navigate) return;
      passNavigate = href;
      win.location.assign(href);
      return;
    }
    if (h.via === "submit" && h.form !== undefined) {
      const form = h.form;
      passForm.add(form);
      try {
        submitForm(form, h.submitter != null && connected(h.submitter) && containsNode(form, h.submitter) ? h.submitter : undefined);
      } finally {
        passForm.delete(form);
      }
      return;
    }
    passValue.set(h.el, h.text);
    lastAllowed.set(h.el, h.text);
    setValue(h.el, h.text);
    h.el.dispatchEvent(new Event("input", { bubbles: true }));
    h.el.dispatchEvent(new Event("change", { bubbles: true }));
  };

  /**
   * Held back locally: tell the worker, which logs it and creates the approval. `quiet` holds (no trusted
   * context yet, or a value over the local bound) show a notice only once the worker says it holds too.
   */
  const hold = (h: Hold, verdict: string, findings: readonly LeakFinding[], quiet = false): void => {
    if (h.via !== "submit" || h.navigate !== undefined) frozen.add(h.el);
    if (!quiet) notice(noticeText(verdict as "approve" | "deny", findings, h.destinationHost));
    void ask(h).then((reply) => {
      if (reply === undefined) return; // Worker unreachable: stay held (fail closed).
      if (reply.decision.verdict === "allow" || reply.decision.verdict === "log" || reply.decision.verdict === "warn") {
        if (quiet && reply.decision.verdict === "warn") notice(noticeText("warn", reply.findings, h.destinationHost));
        release(h);
        return;
      }
      if (quiet) notice(noticeText(reply.decision.verdict, reply.findings, h.destinationHost));
      if (reply.approvalId !== undefined) holdUntilDecided(reply.approvalId, h);
      else frozen.delete(h.el); // Denied outright: nothing to wait for; the next attempt is checked again.
    });
  };

  /**
   * A value this frame let through (a local warn or log, or an uncancellable change it could not trust) goes to
   * the worker, and the worker's stricter verdict wins: the field is put back to its last confirmed value and
   * frozen until the person decides. A worker allow confirms the value.
   */
  const deferToWorker = (h: Hold): void => {
    void ask(h).then((reply) => {
      if (reply === undefined) return;
      if (!holdsBack(reply.decision.verdict)) {
        if (h.via !== "submit" && !frozen.has(h.el) && valueOf(h.el) === h.text) confirmed.set(h.el, h.text);
        return;
      }
      if (h.via !== "submit") {
        const back = confirmed.get(h.el) ?? (isField(h.el) ? h.el.defaultValue : "");
        if (valueOf(h.el) !== back) setValue(h.el, back);
        lastAllowed.set(h.el, back);
        passValue.delete(h.el);
        frozen.add(h.el);
      }
      if (reply.approvalId !== undefined) holdUntilDecided(reply.approvalId, h);
      else frozen.delete(h.el);
      notice(noticeText(reply.decision.verdict, reply.findings, h.destinationHost));
    });
  };

  /** Let through but reported (warn: notice; log: silent). Once per field and finding set. */
  const report = (h: Hold, verdict: string, findings: readonly LeakFinding[]): void => {
    const key = `${verdict}|${findings.map((f) => `${f.kind}:${f.masked}`).join(",")}`;
    if (lastReport.get(h.el) === key) return;
    lastReport.set(h.el, key);
    if (verdict === "warn") notice(noticeText("warn", findings, h.destinationHost));
    deferToWorker(h);
  };

  /**
   * Judges a value for a field. Returns true when it is held back. `revertTo`
   * is set for values already in the field (input, poller): they are put back.
   * Without `revertTo` the caller can cancel the event (beforeinput, paste).
   */
  const judgeField = (el: Editable, text: string, via: LeakVia, revertTo?: string): boolean => {
    if (passValue.get(el) === text) {
      passValue.delete(el);
      lastAllowed.set(el, text);
      confirmed.set(el, text);
      return false;
    }
    const h: Hold = { via, el, text, fieldName: fieldNameOf(el), elementPath: elementPath(el), destinationHost: destinationFor() };
    if (frozen.has(el)) {
      if (revertTo !== undefined) setValue(el, revertTo);
      return true;
    }
    // Over the local bound, or (for a cancellable insertion) no context this frame can trust: nothing goes into
    // the field until the worker answers; an allow puts the value in.
    if (text !== "" && (exceedsLocalScan(text) || (!ctxTrusted() && revertTo === undefined))) {
      if (revertTo !== undefined) setValue(el, revertTo);
      hold(h, "approve", [], true);
      return true;
    }
    const merchant = merchantFor([el]);
    const { decision, findings } = decide(text, h.destinationHost, merchant);
    if (holdsBack(decision.verdict)) {
      if (revertTo !== undefined) setValue(el, revertTo);
      hold(h, decision.verdict, findings);
      return true;
    }
    if (reported(decision.verdict)) report(h, decision.verdict, findings);
    else if (!ctxTrusted() && text !== "") {
      // An uncancellable change with no context yet, or a stale one: the worker sees it, and its block takes it back.
      deferToWorker(h);
    } else confirmed.set(el, text);
    lastAllowed.set(el, text);
    return false;
  };

  const editableTarget = (e: Event): Editable | null => {
    const el = originOf(e);
    if (el === null) return null;
    if (isField(el)) return el;
    return closestEditable(el);
  };

  const selection = (el: Editable): [number | null, number | null] => {
    if (!isField(el)) return [null, null];
    try {
      return [el.selectionStart, el.selectionEnd];
    } catch {
      return [null, null]; // email and number inputs have no selection API
    }
  };

  const cancel = (e: Event): void => {
    e.preventDefault();
    e.stopImmediatePropagation();
  };

  /**
   * A listener that threw (a page that clobbered or broke something we read): the event is cancelled, and the
   * worker is told what it carried, so the attempt is judged and logged. Nothing is replayed; it can be retried.
   */
  const failClosed = (e: Event, via: LeakVia): void => {
    try {
      if (e.cancelable) cancel(e);
      else e.stopImmediatePropagation();
    } catch {
      // Nothing more we can do with this event.
    }
    notice("LaunchSafe could not check this on this page, so it did not let it through. Try again, or check the LaunchSafe side panel.");
    const text = eventText(e);
    void deps.send({ type: "leak.guard", via, text: text.slice(0, LIMITS.text), destinationHost: host(), elementPath: "", fieldName: "unchecked" }).catch(() => undefined);
  };

  const guarded =
    (via: LeakVia, fn: (e: Event) => void): EventListener =>
    (e: Event) => {
      try {
        fn(e);
      } catch {
        failClosed(e, via);
      }
    };

  // ---- listeners -------------------------------------------------------------------

  const onBeforeInput = (e: Event): void => {
    const ie = e as InputEvent;
    if (!insertsText(ie.inputType ?? "")) return;
    const el = editableTarget(e);
    if (el === null) return;
    const inserted = eventText(e);
    const [s, en] = selection(el);
    const next = prospectiveValue(valueOf(el), s, en, inserted);
    if (judgeField(el, next, "type")) cancel(e);
  };

  const onInput = (e: Event): void => {
    const el = editableTarget(e);
    if (el === null || !isField(el)) return;
    const v = el.value;
    lastSeen.set(el, v);
    if (lastAllowed.get(el) === v) return;
    judgeField(el, v, "type", lastAllowed.get(el) ?? el.defaultValue);
  };

  const onPaste = (e: Event): void => {
    const el = editableTarget(e);
    if (el === null) return;
    const pasted = eventText(e);
    if (pasted === "") return;
    const [s, en] = selection(el);
    const next = prospectiveValue(valueOf(el), s, en, pasted);
    if (judgeField(el, next, "paste")) cancel(e);
  };

  const onSubmit = (e: Event): void => {
    const form = e.target;
    if (!isForm(form)) return;
    if (passForm.has(form)) {
      passForm.delete(form);
      return;
    }
    const fields = fieldsOf(form);
    const text = formTextOf(fields);
    if (text === "") return;
    const submitter = (e as SubmitEvent).submitter ?? null;
    const h: Hold = { via: "submit", el: form, form, submitter, text, fieldName: "form", elementPath: elementPath(form), destinationHost: destinationFor(form, submitter) };
    if (exceedsLocalScan(text)) {
      // Too large to judge here: the worker decides, and the submit waits for it.
      cancel(e);
      hold(h, "approve", [], true);
      return;
    }
    const { decision, findings } = decide(text, h.destinationHost, merchantFor(fields));
    if (holdsBack(decision.verdict)) {
      cancel(e);
      hold(h, decision.verdict, findings);
    } else if (reported(decision.verdict) || !ctxTrusted()) {
      // A submit cannot be taken back once it leaves: with a warning, or without a context this frame can trust,
      // it waits for the worker, which releases it (allow, warn, log) or holds it for the person.
      cancel(e);
      if (decision.verdict === "warn") notice(noticeText("warn", findings, h.destinationHost));
      void ask(h).then((reply) => {
        if (reply === undefined) return; // Worker unreachable: stay held (fail closed).
        if (!holdsBack(reply.decision.verdict)) {
          release(h);
          return;
        }
        if (reply.approvalId !== undefined) holdUntilDecided(reply.approvalId, h);
        notice(noticeText(reply.decision.verdict, reply.findings, h.destinationHost));
      });
    }
  };

  /** A link whose query values carry data this frame would hold back (in agent mode, or with no trusted context). */
  const onClick = (e: Event): void => {
    let path: EventTarget[];
    try {
      path = e.composedPath();
    } catch {
      path = [];
    }
    const link = path.find((n): n is HTMLElement => isElement(n) && (tagOf(n).toUpperCase() === "A" || tagOf(n).toUpperCase() === "AREA") && attr(n, "href") !== null);
    if (link === undefined) return;
    let url: URL;
    try {
      url = new URL(attr(link, "href") ?? "", win.location.href);
    } catch {
      return;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return;
    const text = linkQueryText(url);
    if (text === "") return;
    if (passNavigate === url.href) {
      passNavigate = null;
      return;
    }
    const h: Hold = { via: "submit", el: link, navigate: url.href, text, fieldName: "link", elementPath: elementPath(link), destinationHost: url.hostname };
    if (exceedsLocalScan(text)) {
      cancel(e);
      hold(h, "approve", [], true);
      return;
    }
    const { decision, findings } = decide(text, url.hostname, undefined);
    if (!holdsBack(decision.verdict)) return;
    cancel(e);
    hold(h, decision.verdict, findings);
  };

  /** Values set with no event at all (form_input-style setters): checked within one poll period, in the document and open shadow roots. */
  const poll = (): void => {
    try {
      const els: Element[] = [...doc.querySelectorAll("input, textarea")];
      for (const r of rootListeners) {
        if (els.length >= MAX_POLLED) break;
        els.push(...r.querySelectorAll("input, textarea"));
      }
      let n = 0;
      for (const node of els) {
        if (n++ >= MAX_POLLED) break;
        if (!isField(node)) continue;
        const v = node.value;
        const seen = lastSeen.get(node);
        lastSeen.set(node, v);
        if (seen === undefined && v === node.defaultValue) {
          lastAllowed.set(node, v);
          continue;
        }
        if (v === seen || v === lastAllowed.get(node)) continue;
        judgeField(node, v, "type", lastAllowed.get(node) ?? node.defaultValue);
      }
    } catch {
      // A page that broke querySelectorAll: submits are still checked.
    }
  };

  // ---- prints --------------------------------------------------------------------

  const notePrivateText = (text: string): void => {
    const prints = printsFor(text.length > MAX_TEXT_SCAN ? text.slice(0, MAX_TEXT_SCAN) : text, host(), ctx.printSalt ?? "").filter((p) => !sentPrints.has(`${p.kind}|${p.fp}`));
    if (prints.length === 0) return;
    for (const p of prints) sentPrints.add(`${p.kind}|${p.fp}`);
    deps.send({ type: "private.prints", prints: prints.slice(0, 2_000) }).catch(() => undefined);
  };

  const scanVisibleText = (): void => {
    printTimer = undefined;
    const body = doc.body;
    if (body === null) return;
    let text = body.innerText ?? "";
    for (const r of rootListeners) {
      if (connected(r)) text += "\n" + ((r as unknown as { innerText?: string }).innerText ?? r.textContent ?? "");
    }
    notePrivateText(text);
  };

  const scheduleScan = (): void => {
    if (printTimer === undefined) printTimer = win.setTimeout(scanVisibleText, PRINT_DEBOUNCE_MS);
  };

  const setContext = (c: LeakContext): void => {
    const turnedOn = c.agentMode && !(ctxLoaded && ctx.agentMode);
    ctx = c;
    ctxLoaded = true;
    ctxStale = false;
    opts.onContext?.(c);
    // The worker keeps prints only in an agent session: when one starts, send this page's prints again.
    if (turnedOn && doc.readyState !== "loading") {
      sentPrints.clear();
      scheduleScan();
    }
  };

  const markStale = (): void => {
    ctxStale = true;
  };

  const safeSubmit = guarded("submit", onSubmit);

  const add = (type: string, fn: EventListener): void => {
    win.addEventListener(type, fn, { capture: true });
    listeners.push([type, fn]);
  };

  return {
    install() {
      add("beforeinput", guarded("type", onBeforeInput));
      add("input", guarded("type", onInput));
      add("paste", guarded("paste", onPaste));
      add("submit", safeSubmit);
      add("click", guarded("submit", onClick));
      // Forms and visible text inside open shadow roots: submit is not composed, and MutationObserver does not cross shadow roots.
      unsubscribeRoots = shadowRootWatcher(win).subscribe((root) => {
        root.addEventListener("submit", safeSubmit, { capture: true });
        rootListeners.push(root);
        if (observer !== undefined) {
          observer.observe(root, { childList: true, subtree: true, characterData: true });
          scheduleScan();
        }
      });
      const pollMs = opts.pollMs ?? 400;
      if (pollMs > 0) poller = win.setInterval(poll, pollMs);
      deps
        .send({ type: "leak.context" })
        .then((c) => {
          // The reply is checked like a push: a context this frame cannot read is never trusted.
          const msg = parseWorkerMessage({ type: "leak.context", context: c });
          if (msg !== null && msg.type === "leak.context") setContext(msg.context);
          else if (c !== undefined && c !== null) markStale();
        })
        .catch(() => undefined);
      const startPrints = (): void => {
        scanVisibleText();
        observer = new MutationObserver(scheduleScan);
        observer.observe(doc.documentElement, { childList: true, subtree: true, characterData: true });
        for (const r of rootListeners) observer.observe(r, { childList: true, subtree: true, characterData: true });
      };
      if (doc.readyState === "loading") doc.addEventListener("DOMContentLoaded", startPrints, { once: true });
      else startPrints();
    },
    uninstall() {
      for (const [type, fn] of listeners) win.removeEventListener(type, fn, { capture: true });
      listeners.length = 0;
      for (const r of rootListeners.splice(0)) r.removeEventListener("submit", safeSubmit, { capture: true });
      unsubscribeRoots?.();
      for (const id of [...holdTimers.keys()]) dropTimer(id);
      if (poller !== undefined) win.clearInterval(poller);
      if (printTimer !== undefined) win.clearTimeout(printTimer);
      observer?.disconnect();
    },
    notePrivateText,
    setContext,
    markStale,
    onApprovalGranted(approvalId, token) {
      const h = holds.get(approvalId);
      if (h === undefined) return false;
      holds.delete(approvalId);
      dropTimer(approvalId);
      const live = liveBinding(h);
      if (live === null) {
        frozen.delete(h.el);
        return true;
      }
      // Tab and frame come from the sender on the worker side; the rest must match the approved binding.
      const snapshot = leakSnapshot(live);
      deps
        .send({ type: "approval.redeem", token, snapshot })
        .then((r) => {
          if (r?.ok === true) release(h);
          else frozen.delete(h.el);
        })
        .catch(() => frozen.delete(h.el));
      return true;
    },
    onApprovalDenied(approvalId) {
      const h = holds.get(approvalId);
      if (h === undefined) return false;
      holds.delete(approvalId);
      dropTimer(approvalId);
      frozen.delete(h.el);
      return true;
    },
  };
}
