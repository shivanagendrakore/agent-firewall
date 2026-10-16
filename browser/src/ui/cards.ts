/**
 * Approval cards, shared by the side panel and the approval window. Every
 * page-derived string goes through escapeForDisplay and is set with
 * textContent, never innerHTML.
 *
 * Cards are kept by approval id across refreshes, so a card's arming time and
 * an in-progress press survive the worker's `ui.changed` broadcasts.
 */
import { sendToWorker } from "../shared/bridge.js";
import type { GateApprovalView } from "../shared/messages.js";
import { displayHost, displayUrlHost } from "./host-display.js";
import { ApproveGesture, ARM_MS, approvalTitle, escapeForDisplay, expiresText, reasonText } from "./view.js";

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (cls !== undefined) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function row(dl: HTMLElement, term: string, value: string): void {
  if (value === "") return;
  dl.append(el("dt", undefined, term), el("dd", undefined, escapeForDisplay(value)));
}

/**
 * Wires the approve gesture on a button (view.ts ApproveGesture): a trusted pointer press and release, or a
 * trusted Enter or Space on the button after Tab moved focus to it, after the card arms. The button's own
 * click (which a script can dispatch) never approves.
 */
function guardedButton(label: string, cls: string, armedAt: number, hint: HTMLElement, onApprove: () => void): HTMLButtonElement {
  const b = el("button", cls, label);
  b.type = "button";
  const g = new ApproveGesture(() => performance.now(), armedAt);
  const active = (): boolean => (navigator as Navigator & { userActivation?: { isActive: boolean } }).userActivation?.isActive !== false;
  const tooSoon = (): void => {
    if (!g.armed()) hint.textContent = "Take a moment to read the request, then try again.";
  };
  b.addEventListener("pointerdown", (e) => g.down(e));
  b.addEventListener("pointerleave", () => g.cancel());
  b.addEventListener("pointercancel", () => g.cancel());
  b.addEventListener("pointerup", (e) => {
    if (g.up(e) && active()) onApprove();
    else tooSoon();
  });
  b.addEventListener("focus", (e) => g.focus(e));
  b.addEventListener("blur", () => g.blur());
  b.addEventListener("keydown", (e) => {
    // Enter and Space never produce the button's own click: the gesture decides on the key release.
    if (g.keyDown(e)) e.preventDefault();
  });
  b.addEventListener("keyup", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    e.preventDefault();
    if (g.keyUp(e) && active()) onApprove();
    else if (!g.armed()) tooSoon();
    else hint.textContent = "Press Tab to move to this button, then press Enter or Space once.";
  });
  return b;
}

function card(v: GateApprovalView): HTMLElement {
  const root = el("article", "card");
  root.dataset.approvalId = v.approvalId;
  root.dataset.subject = v.subject;
  root.append(el("h3", undefined, approvalTitle(v)));
  if (v.overridesDeny) root.append(el("p", "warn", "LaunchSafe blocked this because the tab showed hidden instructions aimed at AI agents. Approve only if you started this yourself and know why."));

  const dl = el("dl");
  // Hosts and addresses: an internationalised host shown in Unicode and as its xn-- form (m12).
  const where = (s: string): string => (s.includes("://") ? displayUrlHost(s) : displayHost(s));
  if (v.subject !== "navigation") row(dl, "Site", where(v.origin));
  if (v.subject === "download") {
    row(dl, "File", v.filename ?? v.label);
    row(dl, "From", where(v.target));
  } else if (v.subject === "navigation") {
    row(dl, "Opens", where(v.target));
    row(dl, "Address", v.label);
  } else if (v.subject === "leak") {
    row(dl, "Held", v.label);
    row(dl, "Going to", where(v.target));
  } else if (v.subject === "action") {
    row(dl, "Control", v.label);
    row(dl, "Sends to", where(v.target));
    row(dl, "Page", where(v.pageUrl));
  }
  if (dl.childElementCount > 0) root.append(dl);

  if (v.fields.length > 0) {
    root.append(el("h4", undefined, v.subject === "leak" ? "What was found (masked)" : "What it sends (masked)"));
    const ul = el("ul", "fields");
    for (const f of v.fields) {
      const li = el("li");
      li.append(el("span", "fname", escapeForDisplay(f.name, 60)), document.createTextNode(": "), el("span", "fval", escapeForDisplay(f.masked, 120)));
      ul.append(li);
    }
    root.append(ul);
  }

  const why = [...v.reasons.map(reasonText), ...v.untrustedBecause.map(reasonText)];
  if (why.length > 0) {
    root.append(el("h4", undefined, "Why it is waiting"));
    const ul = el("ul", "why");
    for (const w of new Set(why)) ul.append(el("li", undefined, w));
    root.append(ul);
  }

  root.append(el("p", "muted expires", expiresText(v.expiresAt, Date.now())));
  const hint = el("p", "hint");
  hint.setAttribute("role", "status");
  const armedAt = performance.now() + ARM_MS;
  const actions = el("div", "actions");
  const done = (ok: boolean) => {
    hint.textContent = ok ? "Done." : "This request is no longer waiting.";
    for (const b of Array.from(actions.querySelectorAll("button"))) b.disabled = true;
  };
  actions.append(
    guardedButton(v.subject === "agent_mode_off" ? "Turn agent mode off" : v.subject === "navigation" ? "Open it once" : "Approve", "approve", armedAt, hint, () => {
      void sendToWorker({ type: "ui.approve", approvalId: v.approvalId }).then((r) => done(r?.ok === true), () => done(false));
    }),
  );
  if (v.siteGrantable) {
    // The grant covers exactly the site the card names (the frame's own host), never a form target elsewhere (RR3).
    const site = v.domain === "" ? "this site" : v.domain;
    const targetSite = (() => {
      try {
        return v.target === "" ? "" : new URL(v.target).hostname;
      } catch {
        return "";
      }
    })();
    if (targetSite !== "" && v.domain !== "" && targetSite !== v.domain && !targetSite.endsWith(`.${v.domain}`)) {
      root.append(el("p", "muted grant-scope", escapeForDisplay(`"Approve for ${site}" covers ${site} only. This form sends to ${targetSite}, which will still ask each time.`, 300)));
    }
    actions.append(
      guardedButton(`Approve for ${escapeForDisplay(site, 80)} until agent mode ends`, "approve-site", armedAt, hint, () => {
        void sendToWorker({ type: "ui.approveForSite", approvalId: v.approvalId }).then((r) => done(r?.ok === true), () => done(false));
      }),
    );
  }
  const deny = el("button", "deny", "Deny");
  deny.type = "button";
  // Deny is always safe to press, by any means.
  deny.addEventListener("click", () => void sendToWorker({ type: "ui.deny", approvalId: v.approvalId }).then(() => done(true), () => done(false)));
  actions.append(deny);
  root.append(actions, hint);
  return root;
}

/** Renders the approvals into `list`, keeping existing cards (and their arming) by id. */
export function renderApprovals(list: HTMLElement, approvals: readonly GateApprovalView[]): void {
  const keep = new Set(approvals.map((a) => a.approvalId));
  for (const c of Array.from(list.querySelectorAll<HTMLElement>("article.card"))) if (!keep.has(c.dataset.approvalId ?? "")) c.remove();
  const have = new Set(Array.from(list.querySelectorAll<HTMLElement>("article.card")).map((c) => c.dataset.approvalId));
  for (const a of approvals) if (!have.has(a.approvalId)) list.append(card(a));
}
