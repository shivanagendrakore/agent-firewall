/**
 * Open shadow roots, found so the gate and the leak guard can listen inside
 * them.
 *
 * `submit` and `change` are not composed: dispatched inside a shadow root they
 * stop at that root and never reach our capture listeners on `window`. So each
 * open root we find gets its own capture listeners (the subscribers'). Roots are
 * found:
 *
 * - from composed events (pointerdown, click, keydown, focusin, input) whose
 *   path crosses them, in the capture phase, before the click's or the Enter
 *   key's default action submits a form inside the root;
 * - from a walk of the document at DOMContentLoaded (bounded);
 * - from added nodes (a MutationObserver per document and per root found).
 *
 * Closed shadow roots are never found: their nodes are not in any path we see
 * and `shadowRoot` is null for them. That is a residual (threat model 5).
 * A form a page script creates in a new root and submits in the same task,
 * before any observer runs, is missed too.
 */
export interface ShadowRootWatcher {
  /** Calls `fn` for every open root found so far and every one found later. Returns the unsubscribe. */
  subscribe(fn: (root: ShadowRoot) => void): () => void;
  /** Roots found so far (tests). */
  roots(): readonly ShadowRoot[];
}

const WALK_LIMIT = 20_000;
const ROOT_LIMIT = 2_000;
const EVENTS = ["pointerdown", "mousedown", "click", "keydown", "focusin", "input", "beforeinput", "dragenter", "drop"] as const;

const watchers = new WeakMap<Window, ShadowRootWatcher>();
const attachListeners = new Set<(root: ShadowRoot) => void>();
const patchedProtos = new WeakSet<object>();

function hookAttachShadow(win: Window, onOpenRoot: (root: ShadowRoot) => void): () => void {
  const proto = ((win as unknown as { Element?: typeof Element }).Element ?? Element).prototype;
  if (!patchedProtos.has(proto) && typeof proto.attachShadow === "function") {
    const orig = proto.attachShadow;
    patchedProtos.add(proto);
    proto.attachShadow = function (init: ShadowRootInit): ShadowRoot {
      const sr = orig.call(this, init);
      if (sr.mode === "open") for (const fn of attachListeners) fn(sr);
      return sr;
    };
  }
  attachListeners.add(onOpenRoot);
  return () => {
    attachListeners.delete(onOpenRoot);
  };
}

/** The one watcher for a window (shared by the content modules). */
export function shadowRootWatcher(win: Window): ShadowRootWatcher {
  let w = watchers.get(win);
  if (w === undefined) {
    w = createWatcher(win);
    watchers.set(win, w);
  }
  return w;
}

function createWatcher(win: Window): ShadowRootWatcher {
  const doc = win.document;
  const seen = new WeakSet<ShadowRoot>();
  const found: ShadowRoot[] = [];
  const subscribers = new Set<(root: ShadowRoot) => void>();
  const observers: MutationObserver[] = [];
  let unhookAttach: (() => void) | null = null;
  let installed = false;

  const add = (root: ShadowRoot): void => {
    if (seen.has(root) || found.length >= ROOT_LIMIT) return;
    seen.add(root);
    found.push(root);
    for (const fn of subscribers) {
      try {
        fn(root);
      } catch {
        // One subscriber's failure must not keep the root from the others.
      }
    }
    observe(root);
    walk(root);
  };

  /** Open roots under a node (bounded). */
  const walk = (start: Node): void => {
    const tw = doc.createTreeWalker(start, NodeFilter.SHOW_ELEMENT);
    let n = 0;
    for (let el = (start.nodeType === 1 ? start : tw.nextNode()) as Element | null; el !== null && n < WALK_LIMIT; el = tw.nextNode() as Element | null, n++) {
      const sr = el.shadowRoot;
      if (sr !== null) add(sr);
    }
  };

  const observe = (target: Node): void => {
    const mo = new MutationObserver((records) => {
      for (const r of records) {
        if (r.target.nodeType === 1 && (r.target as Element).shadowRoot !== null) add((r.target as Element).shadowRoot as ShadowRoot);
        for (const node of Array.from(r.addedNodes)) if (node.nodeType === 1) walk(node);
      }
    });
    mo.observe(target, { childList: true, subtree: true });
    observers.push(mo);
  };

  const fromEvent = (e: Event): void => {
    let path: EventTarget[];
    try {
      path = e.composedPath();
    } catch {
      return;
    }
    for (const t of path) if (t instanceof ShadowRoot && t.mode === "open") add(t);
  };

  const install = (): void => {
    if (installed) return;
    installed = true;
    unhookAttach = hookAttachShadow(win, (sr) => {
      if (sr.ownerDocument === doc) add(sr);
    });
    for (const type of EVENTS) win.addEventListener(type, fromEvent, { capture: true });
    const start = (): void => {
      if (doc.documentElement === null) return;
      walk(doc.documentElement);
      observe(doc.documentElement);
    };
    if (doc.readyState === "loading") doc.addEventListener("DOMContentLoaded", start, { once: true });
    else start();
  };

  const uninstall = (): void => {
    if (!installed) return;
    installed = false;
    unhookAttach?.();
    unhookAttach = null;
    for (const type of EVENTS) win.removeEventListener(type, fromEvent, { capture: true });
    for (const mo of observers.splice(0)) mo.disconnect();
  };

  return {
    subscribe(fn) {
      subscribers.add(fn);
      install();
      for (const r of found) fn(r);
      return () => {
        subscribers.delete(fn);
        if (subscribers.size === 0) uninstall();
      };
    },
    roots: () => [...found],
  };
}
