/**
 * DOM reads a page cannot clobber.
 *
 * A form's named controls shadow its own properties ([LegacyOverrideBuiltIns]):
 * `<input name="action">` makes `form.action` the input, `<input name="elements">`
 * replaces `form.elements`, and `<input name="tagName">` or `name="requestSubmit"`
 * break the checks and the replay. The isolated world does not help, because
 * named properties are part of the DOM bindings in every world. So the gate and
 * the leak guard read forms (and the elements they walk) through the prototype
 * getters captured here, at document_start, before any page script runs.
 */

function getter<T>(proto: object, name: string): (this: unknown) => T {
  // The nearest prototype that defines it (browsers put most on the interface itself; a mixin may sit higher).
  for (let p: object | null = proto; p !== null; p = Object.getPrototypeOf(p) as object | null) {
    const g = Object.getOwnPropertyDescriptor(p, name)?.get;
    if (g !== undefined) return g as (this: unknown) => T;
  }
  throw new Error(`no getter for ${name}`);
}

const formElementsGet = getter<HTMLFormControlsCollection>(HTMLFormElement.prototype, "elements");
const formActionGet = getter<string>(HTMLFormElement.prototype, "action");
const formMethodGet = getter<string>(HTMLFormElement.prototype, "method");
const requestSubmitFn = HTMLFormElement.prototype.requestSubmit;
const tagNameGet = getter<string>(Element.prototype, "tagName");
const idGet = getter<string>(Element.prototype, "id");
const parentElementGet = getter<Element | null>(Node.prototype, "parentElement");
const isConnectedGet = getter<boolean>(Node.prototype, "isConnected");
const childrenGet = getter<HTMLCollection>(Element.prototype, "children");
const previousSiblingGet = getter<Element | null>(Element.prototype, "previousElementSibling");
const getRootNodeFn = Node.prototype.getRootNode;
const containsFn = Node.prototype.contains;
const getAttributeFn = Element.prototype.getAttribute;
const closestFn = Element.prototype.closest;
const querySelectorFn = Element.prototype.querySelector;
const querySelectorAllFn = Element.prototype.querySelectorAll;
const shadowHostGet = getter<Element>(ShadowRoot.prototype, "host");
const controlFormGet = {
  input: getter<HTMLFormElement | null>(HTMLInputElement.prototype, "form"),
  button: getter<HTMLFormElement | null>(HTMLButtonElement.prototype, "form"),
  textarea: getter<HTMLFormElement | null>(HTMLTextAreaElement.prototype, "form"),
  select: getter<HTMLFormElement | null>(HTMLSelectElement.prototype, "form"),
};

export function tagOf(el: Element): string {
  return tagNameGet.call(el).toUpperCase();
}

export function idOf(el: Element): string {
  return idGet.call(el);
}

export function parentOf(n: Node): Element | null {
  return parentElementGet.call(n);
}

export function connected(n: Node): boolean {
  return isConnectedGet.call(n);
}

export function childrenOf(el: Element): Element[] {
  return Array.from(childrenGet.call(el));
}

export function previousOf(el: Element): Element | null {
  return previousSiblingGet.call(el);
}

export function rootOf(n: Node): Node {
  return getRootNodeFn.call(n);
}

export function hostOfRoot(r: ShadowRoot): Element {
  return shadowHostGet.call(r);
}

export function containsNode(a: Node, b: Node): boolean {
  return containsFn.call(a, b);
}

export function attr(el: Element, name: string): string | null {
  return getAttributeFn.call(el, name);
}

export function closestOf(el: Element, selector: string): Element | null {
  return closestFn.call(el, selector);
}

export function queryIn(el: Element, selector: string): Element | null {
  return querySelectorFn.call(el, selector);
}

export function queryAllIn(el: Element, selector: string): Element[] {
  return Array.from(querySelectorAllFn.call(el, selector));
}

/** Whether a value is an element, by the real tagName getter (not instanceof: a frame's nodes may come from another realm). */
export function isElement(x: unknown): x is Element {
  if (typeof x !== "object" || x === null) return false;
  try {
    return typeof tagNameGet.call(x) === "string";
  } catch {
    return false;
  }
}

/** Whether a value is a form element (by its real tag name, not a clobberable property). */
export function isForm(x: unknown): x is HTMLFormElement {
  return isElement(x) && tagNameGet.call(x) === "FORM";
}

/** The form's controls, read through the prototype getter. */
export function formControls(form: HTMLFormElement): Element[] {
  return Array.from(formElementsGet.call(form));
}

/** The form's resolved action URL, read through the prototype getter. */
export function formAction(form: HTMLFormElement): string {
  return formActionGet.call(form);
}

/** The form's method ("get", "post" or "dialog"), read through the prototype getter. */
export function formMethod(form: HTMLFormElement): string {
  return formMethodGet.call(form);
}

/** form.requestSubmit(submitter) through the prototype, so a control named "requestSubmit" cannot replace it. */
export function submitForm(form: HTMLFormElement, submitter?: HTMLElement | null): void {
  if (submitter != null) requestSubmitFn.call(form, submitter);
  else requestSubmitFn.call(form);
}

/** The form a control belongs to (its `form` getter: the form attribute or the nearest ancestor form). */
export function controlForm(el: Element): HTMLFormElement | null {
  switch (tagOf(el)) {
    case "INPUT":
      return controlFormGet.input.call(el);
    case "BUTTON":
      return controlFormGet.button.call(el);
    case "TEXTAREA":
      return controlFormGet.textarea.call(el);
    case "SELECT":
      return controlFormGet.select.call(el);
    default:
      return null;
  }
}
