/**
 * Sensitive-action gate (design 5): capture-phase listeners on `window`,
 * registered at document_start before any page script runs, so ours fire
 * first for every event dispatched in this document, trusted (a person, CDP,
 * a built-in agent) or not (page script).
 *
 *   event                         action     notes
 *   click, auxclick               activate   buttons, submit inputs, role=button/menuitem/link
 *   submit                        submit     requestSubmit, Enter, submit buttons
 *   keydown Enter / Ctrl+Enter    activate   only inside a compose surface (keyboard send)
 *   input, change on file inputs  upload     the files are taken out of the input while held
 *   drop with files               upload
 *   paste with files              upload     (text paste is the leak guard's)
 *
 * For each, the gate builds the engine's NormalizedAction and classifies it
 * here with the same engine and adapters the worker uses. An unclassified
 * action, or one the rule table cannot gate in the current posture (payment,
 * send, delete, upload with agent mode off on a tab without a quarantine
 * verdict), is left alone. Otherwise the event is cancelled
 * (preventDefault + stopImmediatePropagation) and the worker decides:
 *
 * - allow: replayed at once;
 * - approve, or deny with a side-panel override: held under its approvalId;
 *   the in-page notice points to the side panel; on `approval.granted` the
 *   gate re-measures the action, redeems the token with that fresh snapshot
 *   (the worker refuses a changed form, element, frame or tab), and replays
 *   it exactly once;
 * - deny: dropped.
 *
 * Replay runs our own `click()` / `requestSubmit()` / `dispatchEvent` with a
 * pass that covers only the approved element (and its form) for the duration
 * of that synchronous call; page script cannot set the pass (isolated world).
 * Replayed events are untrusted, so a site that ignores untrusted events will
 * not act on the replay: the person then repeats the action with agent mode
 * on and an approval, or acts with agent mode off. Listed in the UI.
 *
 * Shadow DOM: every listener reads the event's composed path (the control
 * inside an open shadow root, not its host); `submit` and `change` are not
 * composed, so each open shadow root gets its own capture listeners for them
 * (shadow-roots.ts). Closed shadow roots are not covered (threat model 5).
 *
 * A listener that throws (a page that clobbered a form's properties with named
 * controls, or broke a DOM method) fails closed: the event is cancelled and
 * dropped, never replayed, the in-page notice says LaunchSafe could not check
 * it, and the worker is sent a bare activation for the frame so the attempt is
 * decided and logged. The person can try again.
 *
 * Known bypasses (tested as bypasses, listed in the UI): page or agent script
 * that calls `form.submit()` (no submit event), `fetch`, XHR or `sendBeacon`
 * never raises an event here.
 */
import { ADAPTERS } from "../engine/adapters.js";
import { APPROVAL_TTL_MS } from "../engine/bindings.js";
import { classify } from "../engine/classify.js";
import { snapshotOf } from "../engine/fingerprint.js";
import { ALWAYS_ON_CLASSES, type ActionClass } from "../engine/types.js";
import type { GatePosture, InPageAction } from "../shared/messages.js";
import { connected, isForm, submitForm, tagOf } from "./dom-safe.js";
import { ACTIONABLE, buildActivate, buildSubmit, buildUpload, closestAcross, composeContext, elementPath, eventElement, formOf, labelOf, sendControlNear } from "./gate-dom.js";
import { createNotice, type Notice, type NoticeKind } from "./gate-notice.js";
import { shadowRootWatcher } from "./shadow-roots.js";
import type { ContentDeps, ContentModule } from "./types.js";

export interface ActionGate extends ContentModule {
  /** The person approved in extension UI: redeem and replay exactly once. */
  onApprovalGranted(approvalId: string, token: string): void;
  /** The person denied, or the approval expired: drop the pending action. */
  onApprovalDenied(approvalId: string): void;
  /** The worker told this tab its posture (agent mode, quarantine). */
  onPosture(posture: Partial<GatePosture>): void;
}

interface Held {
  key: string;
  actionClass: ActionClass | null;
  /** Re-measures the action at approval time; null when the control is gone. */
  resnapshot: () => InPageAction | null;
  replay: () => void;
  /** Called when the held action is dropped (denied, refused, unreachable). */
  drop?: () => void;
}

const COMPOSE_BODY = 'textarea, [contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"], [role="textbox"]';
const ALWAYS: ReadonlySet<string> = new Set(ALWAYS_ON_CLASSES);

export function createActionGate(deps: ContentDeps): ActionGate {
  const win = deps.win;
  /** null until the worker answers: until then every classified action is held and asked about (fail closed). */
  let posture: GatePosture | null = null;
  const pending = new Map<string, Held>();
  /** One timer per pending approval: the worker expires it silently after APPROVAL_TTL_MS, so the frame lets go itself. */
  const expiry = new Map<string, ReturnType<typeof setTimeout>>();
  const forget = (approvalId: string): void => {
    const t = expiry.get(approvalId);
    if (t !== undefined) clearTimeout(t);
    expiry.delete(approvalId);
  };
  /** Actions held or being checked, by kind and element: repeated clicks do not stack approvals. */
  const busy = new Set<string>();
  /** File inputs whose files are taken out while held: their follow-up events are swallowed. */
  const heldInputs = new WeakSet<HTMLInputElement>();
  /** The targets our own replay may pass, only during the synchronous replay call. */
  let passing: ReadonlySet<EventTarget> | null = null;
  let notice: Notice | null = null;

  const shouldGate = (c: ActionClass): boolean => ALWAYS.has(c) || posture === null || posture.agentMode || posture.quarantined || deps.agentMode();
  const passes = (t: EventTarget | null): boolean => passing !== null && t !== null && passing.has(t);
  const hold = (e: Event): void => {
    e.preventDefault();
    e.stopImmediatePropagation();
  };
  const tell = (kind: NoticeKind, c: ActionClass | null): void => {
    try {
      notice ??= createNotice(win.document);
      notice.show(kind, c);
    } catch {
      // A page without a document element yet: the side panel still shows the approval.
    }
  };
  function withPass(targets: (EventTarget | null | undefined)[], fn: () => void): void {
    const prev = passing;
    passing = new Set(targets.filter((t): t is EventTarget => t != null));
    try {
      fn();
    } finally {
      passing = prev;
    }
  }

  /** The approval ran out unanswered: the control and its notice are released, nothing is carried out. */
  function expire(approvalId: string): void {
    expiry.delete(approvalId);
    const h = pending.get(approvalId);
    if (h === undefined) return;
    pending.delete(approvalId);
    busy.delete(h.key);
    h.drop?.();
    tell("expired", h.actionClass);
  }

  function check(action: InPageAction, localClass: ActionClass, h: Omit<Held, "key" | "actionClass">): void {
    const key = `${action.kind}|${action.elementPath}`;
    if (busy.has(key)) {
      // Already held: one approval per control. The page still gets nothing (and the held one keeps its files).
      tell("waiting", localClass);
      return;
    }
    busy.add(key);
    const fail = (kind: NoticeKind) => {
      busy.delete(key);
      h.drop?.();
      tell(kind, localClass);
    };
    deps.send({ type: "action.check", action }).then(
      (reply) => {
        if (reply == null || typeof reply !== "object" || reply.decision == null) return fail("unreachable");
        const d = reply.decision;
        const overridable = d.verdict === "deny" && d.override !== undefined;
        if ((d.verdict === "approve" || overridable) && typeof reply.approvalId === "string") {
          const approvalId = reply.approvalId;
          pending.set(approvalId, { ...h, key, actionClass: d.actionClass });
          // A second beyond the worker's own limit, so a late approval is refused there, not raced here.
          expiry.set(approvalId, setTimeout(() => expire(approvalId), APPROVAL_TTL_MS + 1000));
          tell(overridable ? "waiting_override" : "waiting", d.actionClass);
          return;
        }
        if (d.verdict === "approve" || d.verdict === "deny") return fail("blocked");
        busy.delete(key);
        h.replay();
      },
      () => fail("unreachable"),
    );
  }

  // ---- click / auxclick -> activate --------------------------------------------
  const onClick = (e: MouseEvent): void => {
    const el = closestAcross(eventElement(e), ACTIONABLE);
    if (el === null || passes(el)) return;
    const action = buildActivate(el, win);
    const c = classify(action, ADAPTERS).actionClass;
    if (c === null || !shouldGate(c)) return;
    hold(e);
    if (e.type === "auxclick") return; // a middle click on a sensitive control does nothing; no approval for it
    check(action, c, {
      resnapshot: () => (el.isConnected ? buildActivate(el, win) : null),
      replay: () =>
        withPass([el, formOf(el)], () => {
          // SVG controls (role=button on an <svg>) have no click(); a dispatched click reaches the same handlers.
          if (el instanceof HTMLElement) el.click();
          else el.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, composed: true, view: win }));
        }),
    });
  };

  // ---- submit -------------------------------------------------------------------
  const onSubmit = (e: Event): void => {
    const form = e.target;
    if (!isForm(form) || passes(form)) return;
    const submitter = (e as SubmitEvent).submitter ?? null;
    const action = buildSubmit(form, submitter, win);
    const c = classify(action, ADAPTERS).actionClass;
    if (c === null || !shouldGate(c)) return;
    hold(e);
    const liveSubmitter = (): HTMLElement | null => (submitter !== null && connected(submitter) && formOf(submitter) === form ? submitter : null);
    check(action, c, {
      resnapshot: () => (connected(form) ? buildSubmit(form, liveSubmitter(), win) : null),
      replay: () =>
        withPass([form, submitter], () => {
          const s = liveSubmitter();
          try {
            submitForm(form, s);
          } catch {
            submitForm(form);
          }
        }),
    });
  };

  // ---- keydown Enter in a compose surface -> activate (keyboard send) ----------
  const onKeydown = (e: KeyboardEvent): void => {
    if (e.key !== "Enter" || e.isComposing || e.shiftKey || e.altKey) return;
    const body = closestAcross(eventElement(e), COMPOSE_BODY);
    if (body === null || passes(body)) return;
    const compose = composeContext(body);
    if (compose === undefined) return;
    const modified = e.ctrlKey || e.metaKey;
    const sendCtl = sendControlNear(body);
    // Plain Enter is a newline in mail (a recipient field) and in a box with no send control; only a chat composer sends on it.
    if (!modified && (compose.hasRecipient || sendCtl === null)) return;
    const label = sendCtl !== null ? labelOf(sendCtl) : "Send";
    const action = buildActivate(body, win, { label, role: "shortcut" });
    const c = classify(action, ADAPTERS).actionClass;
    if (c === null || !shouldGate(c)) return;
    hold(e);
    const init: KeyboardEventInit = { key: "Enter", code: "Enter", ctrlKey: e.ctrlKey, metaKey: e.metaKey, bubbles: true, cancelable: true, composed: true };
    check(action, c, {
      resnapshot: () => (body.isConnected ? buildActivate(body, win, { label: sendCtl !== null && sendCtl.isConnected ? labelOf(sendCtl) : label, role: "shortcut" }) : null),
      replay: () => withPass([body], () => body.dispatchEvent(new KeyboardEvent("keydown", init))),
    });
  };

  // ---- file inputs -> upload ----------------------------------------------------
  const onFileEvent = (e: Event): void => {
    // The input itself, also inside an open shadow root (input is composed and retargeted to the host at window).
    const el = eventElement(e);
    if (el === null || tagOf(el) !== "INPUT" || (el as HTMLInputElement).type !== "file" || passes(el)) return;
    if (!(el instanceof HTMLInputElement)) return;
    const files = el.files;
    if (heldInputs.has(el) && (files === null || files.length === 0)) {
      // The change that follows a held input event (the files are already taken out), or events while held.
      e.stopImmediatePropagation();
      return;
    }
    if (files === null || files.length === 0 || !shouldGate("upload")) return;
    const action = buildUpload(el, files, win);
    hold(e);
    const kept = new DataTransfer();
    for (const f of Array.from(files)) kept.items.add(f);
    // While held the page can neither read the files nor submit them with the form.
    el.value = "";
    heldInputs.add(el);
    check(action, "upload", {
      resnapshot: () => (el.isConnected ? { ...action, elementPath: elementPath(el) } : null),
      replay: () => {
        heldInputs.delete(el);
        el.files = kept.files;
        withPass([el], () => {
          el.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
          el.dispatchEvent(new Event("change", { bubbles: true }));
        });
      },
      drop: () => heldInputs.delete(el),
    });
  };

  // ---- drop and paste with files -> upload --------------------------------------
  const onFilesTransfer = (e: DragEvent | ClipboardEvent): void => {
    const dt = e instanceof DragEvent ? e.dataTransfer : e.clipboardData;
    const files = dt?.files;
    if (files == null || files.length === 0) return;
    const el = eventElement(e);
    if (el === null || passes(el) || !shouldGate("upload")) return;
    const action = buildUpload(el, files, win);
    hold(e);
    const kept = new DataTransfer();
    for (const f of Array.from(files)) kept.items.add(f);
    const isDrop = e instanceof DragEvent;
    const point = e instanceof DragEvent ? { clientX: e.clientX, clientY: e.clientY } : {};
    check(action, "upload", {
      resnapshot: () => (el.isConnected ? { ...action, elementPath: elementPath(el) } : null),
      replay: () =>
        withPass([el], () => {
          el.dispatchEvent(isDrop ? new DragEvent("drop", { bubbles: true, cancelable: true, composed: true, dataTransfer: kept, ...point }) : new ClipboardEvent("paste", { bubbles: true, cancelable: true, composed: true, clipboardData: kept }));
        }),
    });
  };

  /**
   * A listener that threw: fail closed. The event is cancelled and dropped (never replayed), the notice says so,
   * and the worker is sent a bare activation for this frame so the attempt is decided and logged.
   */
  const failClosed = (e: Event): void => {
    try {
      hold(e);
    } catch {
      // Nothing more we can do with this event.
    }
    tell("unchecked", null);
    const pageUrl = ((): string => {
      try {
        return win.location.href.slice(0, 8 * 1024);
      } catch {
        return "";
      }
    })();
    const bare: InPageAction = { kind: "activate", frame: { tabId: 0, frameId: 0, origin: "" }, elementPath: "", label: "", role: "unchecked", tag: e.type.slice(0, 64), context: { pageUrl } };
    deps.send({ type: "action.check", action: bare }).catch(() => undefined);
  };

  const guarded =
    (fn: (e: Event) => void): EventListener =>
    (e: Event) => {
      try {
        fn(e);
      } catch {
        failClosed(e);
      }
    };

  const listeners: [string, EventListener][] = [
    ["click", guarded(onClick as (e: Event) => void)],
    ["auxclick", guarded(onClick as (e: Event) => void)],
    ["submit", guarded(onSubmit)],
    ["keydown", guarded(onKeydown as (e: Event) => void)],
    ["input", guarded(onFileEvent)],
    ["change", guarded(onFileEvent)],
    ["drop", guarded(onFilesTransfer as (e: Event) => void)],
    ["paste", guarded(onFilesTransfer as (e: Event) => void)],
  ];
  /** Not composed: inside an open shadow root they stop at the root, so each root gets these too. */
  const rootListeners = listeners.filter(([type]) => type === "submit" || type === "change");
  const roots: ShadowRoot[] = [];
  let unsubscribeRoots: (() => void) | undefined;

  return {
    install() {
      for (const [type, fn] of listeners) win.addEventListener(type, fn, { capture: true });
      unsubscribeRoots = shadowRootWatcher(win).subscribe((root) => {
        for (const [type, fn] of rootListeners) root.addEventListener(type, fn, { capture: true });
        roots.push(root);
      });
      deps.send({ type: "gate.posture" }).then(
        (p) => {
          if (p != null && typeof p.agentMode === "boolean" && typeof p.quarantined === "boolean") posture = { agentMode: p.agentMode, quarantined: p.quarantined };
        },
        () => undefined, // stays null: fail closed
      );
    },
    uninstall() {
      for (const [type, fn] of listeners) win.removeEventListener(type, fn, { capture: true });
      for (const r of roots.splice(0)) for (const [type, fn] of rootListeners) r.removeEventListener(type, fn, { capture: true });
      unsubscribeRoots?.();
      for (const id of [...expiry.keys()]) forget(id);
      notice?.remove();
    },
    onPosture(p) {
      posture = { agentMode: p.agentMode ?? posture?.agentMode ?? false, quarantined: p.quarantined ?? posture?.quarantined ?? false };
    },
    onApprovalGranted(approvalId, token) {
      const h = pending.get(approvalId);
      if (h === undefined) return;
      pending.delete(approvalId);
      forget(approvalId);
      const fresh = h.resnapshot();
      if (fresh === null) {
        busy.delete(h.key);
        h.drop?.();
        tell("gone", h.actionClass);
        return;
      }
      deps.send({ type: "approval.redeem", token, snapshot: snapshotOf(fresh, h.actionClass) }).then(
        (r) => {
          busy.delete(h.key);
          if (r != null && r.ok === true) {
            notice?.remove();
            h.replay();
          } else {
            h.drop?.();
            tell("refused", h.actionClass);
          }
        },
        () => {
          busy.delete(h.key);
          h.drop?.();
          tell("unreachable", h.actionClass);
        },
      );
    },
    onApprovalDenied(approvalId) {
      const h = pending.get(approvalId);
      if (h === undefined) return;
      pending.delete(approvalId);
      forget(approvalId);
      busy.delete(h.key);
      h.drop?.();
      tell("denied", h.actionClass);
    },
  };
}
