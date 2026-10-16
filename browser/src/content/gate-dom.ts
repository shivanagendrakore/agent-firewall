/**
 * DOM measurements for the gate: turn an element, form or file list into the
 * engine's NormalizedAction. Reads only; never changes the page.
 *
 * Tab and frame ids are placeholders (0): the worker always replaces them
 * with the sender's (messages.ts trust rules).
 *
 * Forms are read through prototype getters (dom-safe.ts): a page's named
 * controls (`<input name="action">`, `name="elements"`, `name="method"`) would
 * otherwise replace what the gate measures and binds.
 */
import type { FieldInfo, FileInfo } from "../engine/types.js";
import { LIMITS, type InPageAction } from "../shared/messages.js";
import { attr, closestOf, controlForm, formAction, formControls, formMethod, parentOf, previousOf, queryAllIn, queryIn, rootOf, tagOf } from "./dom-safe.js";

type Activate = Extract<InPageAction, { kind: "activate" }>;
type Submit = Extract<InPageAction, { kind: "submit" }>;
type Upload = Extract<InPageAction, { kind: "upload" }>;

/** Controls the gate judges on click (links are judged only as navigations, by the engine and the nav lane). */
export const ACTIONABLE = 'button, input[type="submit"], input[type="button"], input[type="image"], a[href], [role="button"], [role="menuitem"], [role="link"], [role="option"]';

const clip = (s: string, max: number): string => (s.length > max ? s.slice(0, max) : s);

/** `closest` that walks out of open shadow roots to their hosts. */
export function closestAcross(start: Element | null, selector: string): Element | null {
  let el: Element | null = start;
  while (el !== null) {
    const hit = closestOf(el, selector);
    if (hit !== null) return hit;
    const root = rootOf(el);
    el = root instanceof ShadowRoot ? root.host : null;
  }
  return null;
}

/** The first element of an event's composed path (inside open shadow roots), else its target. */
export function eventElement(e: Event): Element | null {
  const first = e.composedPath()[0];
  if (first instanceof Element) return first;
  if (first instanceof Text) return first.parentElement;
  return e.target instanceof Element ? e.target : null;
}

/**
 * A structural path (tag and nth-of-type, through open shadow roots). Ids are
 * left out on purpose: frameworks regenerate them on re-render, and the
 * binding must survive a re-render of the same control but not a move to a
 * different one.
 */
export function elementPath(el: Element): string {
  const parts: string[] = [];
  let cur: Element | null = el;
  while (cur !== null) {
    const parent: Element | null = parentOf(cur);
    const tag = tagOf(cur).toLowerCase();
    if (parent === null) {
      const root = rootOf(cur);
      if (root instanceof ShadowRoot) {
        parts.push(tag, ">>");
        cur = root.host;
        continue;
      }
      parts.push(tag);
      break;
    }
    let i = 1;
    const own = tagOf(cur);
    for (let s = previousOf(cur); s !== null; s = previousOf(s)) if (tagOf(s) === own) i++;
    parts.push(`${tag}:nth-of-type(${i})`);
    cur = parent;
  }
  return clip(parts.reverse().join(">").replace(/>>>>/g, ">>"), LIMITS.path);
}

function text(el: Element): string {
  const t = el instanceof HTMLElement ? el.innerText : (el.textContent ?? "");
  return t.replace(/\s+/g, " ").trim();
}

/** What a person reads on the control: aria-label, the button value, its text, or its title. */
export function labelOf(el: Element): string {
  const aria = attr(el, "aria-label")?.trim();
  if (aria) return clip(aria, LIMITS.label);
  const labelledBy = attr(el, "aria-labelledby");
  if (labelledBy) {
    const t = labelledBy
      .split(/\s+/)
      .map((id) => el.ownerDocument.getElementById(id))
      .filter((x): x is HTMLElement => x !== null)
      .map(text)
      .join(" ")
      .trim();
    if (t) return clip(t, LIMITS.label);
  }
  if (el instanceof HTMLInputElement && (el.type === "submit" || el.type === "button" || el.type === "image")) return clip(el.value || el.alt || el.type, LIMITS.label);
  const t = text(el);
  if (t) return clip(t, LIMITS.label);
  return clip(attr(el, "title")?.trim() ?? attr(el, "data-tooltip")?.trim() ?? "", LIMITS.label);
}

function fieldLabel(el: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement): string | undefined {
  const l = el.labels?.[0];
  const t = (l ? text(l) : "") || el.getAttribute("aria-label") || el.getAttribute("placeholder") || "";
  return t ? clip(t, LIMITS.label) : undefined;
}

/** The fields of a form, in document order, with their values (for the binding digest and the leak guard; masked before display). */
export function fieldsOf(form: HTMLFormElement): FieldInfo[] {
  const out: FieldInfo[] = [];
  let i = 0;
  for (const el of formControls(form)) {
    i++;
    if (!(el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement)) continue;
    if (el instanceof HTMLInputElement && ["submit", "button", "image", "reset"].includes(el.type)) continue;
    const type = el instanceof HTMLInputElement ? el.type : el instanceof HTMLTextAreaElement ? "textarea" : "select";
    let value: string;
    if (el instanceof HTMLInputElement && (el.type === "checkbox" || el.type === "radio")) value = el.checked ? el.value || "on" : "";
    else if (el instanceof HTMLInputElement && el.type === "file") value = Array.from(el.files ?? []).map((f) => `${f.name}\u0000${f.size}`).join("\u0001");
    else value = el.value;
    const f: FieldInfo = { name: clip(el.name || el.id || `${type}[${i}]`, LIMITS.name), type: clip(type, 64), value: clip(value, 64 * 1024) };
    if (el.autocomplete) f.autocomplete = clip(el.autocomplete, LIMITS.name);
    const label = fieldLabel(el);
    if (label !== undefined) f.label = label;
    out.push(f);
    if (out.length >= LIMITS.fields) break;
  }
  return out;
}

const RECIPIENT = 'input[type="email"], input[name="to" i], input[name="cc" i], input[name="bcc" i], input[name*="recipient" i], input[aria-label^="to" i], [role="combobox"][aria-label^="to" i], [aria-label*="recipients" i], textarea[name="to" i]';
const BODY = 'textarea, [contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"], [role="textbox"]';
const SEND = /^\s*(?:send|post|reply|reply all|publish|tweet|share|comment|submit post|senden|envoyer|enviar|publicar)\b/i;

/** The smallest surrounding container that holds a message body, up to a few levels (form, dialog, or the compose region). */
function composeContainer(el: Element): Element | null {
  const explicit = closestAcross(el, 'form, [role="dialog"], [role="region"][aria-label*="compose" i], [data-compose]');
  if (explicit !== null && queryIn(explicit, BODY) !== null) return explicit;
  let cur: Element | null = parentOf(el);
  for (let depth = 0; cur !== null && depth < 8; depth++, cur = parentOf(cur)) {
    if (cur === el.ownerDocument.body) break;
    if (queryIn(cur, BODY) !== null) return cur;
  }
  return null;
}

export function composeContext(el: Element): { hasRecipient: boolean; hasBody: boolean } | undefined {
  const c = composeContainer(el);
  if (c === null) return undefined;
  return { hasRecipient: queryIn(c, RECIPIENT) !== null, hasBody: true };
}

/** The send control of the compose surface around a body field (for keyboard sends), or null. */
export function sendControlNear(body: Element): Element | null {
  const c = composeContainer(body);
  if (c === null) return null;
  for (const b of queryAllIn(c, ACTIONABLE)) if (SEND.test(labelOf(b))) return b;
  return null;
}

/** The body fields of the compose surface around an element, as fields (for the binding digest of a keyboard send). */
export function composeFields(el: Element): FieldInfo[] {
  const c = composeContainer(el) ?? el;
  const out: FieldInfo[] = [];
  let i = 0;
  for (const f of queryAllIn(c, `input, ${BODY}`)) {
    i++;
    if (f instanceof HTMLInputElement && ["submit", "button", "image", "reset", "hidden", "file"].includes(f.type)) continue;
    const value = f instanceof HTMLInputElement || f instanceof HTMLTextAreaElement ? f.value : (f.textContent ?? "");
    out.push({ name: clip(f.getAttribute("name") || f.id || f.getAttribute("aria-label") || `field[${i}]`, LIMITS.name), type: f instanceof HTMLInputElement ? f.type : f instanceof HTMLTextAreaElement ? "textarea" : "contenteditable", value: clip(value, 64 * 1024) });
    if (out.length >= LIMITS.fields) break;
  }
  return out;
}

function frameOf(win: Window): { tabId: number; frameId: number; origin: string } {
  return { tabId: 0, frameId: 0, origin: clip(win.location.origin, LIMITS.url) };
}

/** The frame's own URL: what the adapters' path rules and the payment-frame rule need (a cross-origin frame cannot read the top URL). */
function pageUrl(win: Window): string {
  return clip(win.location.href, LIMITS.url);
}

export function formOf(el: Element): HTMLFormElement | null {
  const tag = tagOf(el);
  if (tag === "BUTTON" || tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return controlForm(el);
  return closestOf(el, "form") as HTMLFormElement | null;
}

export function buildActivate(el: Element, win: Window, over: { label?: string; role?: string; path?: Element } = {}): Activate {
  const form = formOf(el);
  const compose = composeContext(el);
  const tag = tagOf(el).toLowerCase();
  const role = over.role ?? attr(el, "role") ?? (tag === "a" ? "link" : tag === "button" || tag === "input" ? "button" : tag);
  const submits = form !== null && (tag === "button" || tag === "input");
  const formTarget = submits ? { url: clip(submitterOverride(el as HTMLElement, "formaction", win) || formAction(form), LIMITS.url), method: clip(submitterOverride(el as HTMLElement, "formmethod", win) || formMethod(form) || "get", 16) } : null;
  const a: Activate = {
    kind: "activate",
    frame: frameOf(win),
    elementPath: elementPath(over.path ?? el),
    label: over.label ?? labelOf(el),
    role: clip(role, 64),
    tag: clip(tag, 64),
    context: { pageUrl: pageUrl(win), ...(form !== null ? { formFields: fieldsOf(form) } : compose !== undefined ? { formFields: composeFields(el) } : {}), ...(compose !== undefined ? { compose } : {}), ...(formTarget !== null ? { formTarget } : {}) },
  };
  if (el instanceof HTMLInputElement) a.inputType = el.type;
  if (el instanceof HTMLAnchorElement && attr(el, "href") !== null) a.href = clip(el.href, LIMITS.url);
  return a;
}

/** A submitter's own formaction / formmethod (attributes only: the properties fall back to the document URL). */
function submitterOverride(submitter: HTMLElement | null, name: "formaction" | "formmethod", win: Window): string {
  if (submitter === null) return "";
  const v = attr(submitter, name);
  if (v === null) return "";
  if (name === "formmethod") return v.toLowerCase();
  try {
    return new URL(v, win.location.href).href;
  } catch {
    return "";
  }
}

export function buildSubmit(form: HTMLFormElement, submitter: HTMLElement | null, win: Window): Submit {
  const targetUrl = submitterOverride(submitter, "formaction", win) || formAction(form);
  const method = submitterOverride(submitter, "formmethod", win) || formMethod(form);
  const s: Submit = { kind: "submit", frame: frameOf(win), elementPath: elementPath(form), form: { fields: fieldsOf(form), targetUrl: clip(targetUrl, LIMITS.url), method: clip(method || "get", 16) }, context: { pageUrl: pageUrl(win), formFields: fieldsOf(form) } };
  if (submitter !== null) s.label = labelOf(submitter);
  return s;
}

export function filesInfo(files: FileList | readonly File[]): FileInfo[] {
  return Array.from(files)
    .slice(0, LIMITS.files)
    .map((f) => ({ name: clip(f.name, LIMITS.name), size: f.size, type: clip(f.type, LIMITS.name) }));
}

export function buildUpload(el: Element, files: FileList | readonly File[], win: Window): Upload {
  const form = formOf(el);
  const u: Upload = { kind: "upload", frame: frameOf(win), elementPath: elementPath(el), files: filesInfo(files), context: { pageUrl: pageUrl(win), ...(form !== null ? { formFields: fieldsOf(form) } : {}) } };
  if (form !== null) u.targetUrl = clip(formAction(form), LIMITS.url);
  return u;
}
