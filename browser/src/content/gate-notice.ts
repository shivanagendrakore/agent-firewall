/**
 * The in-page notice (design 5.4, threat model 18): explains why the control
 * did nothing and points to the side panel. It is never the approval: it has
 * no approve control, only a close button, and it says that nothing on the
 * page can approve. It lives in a closed shadow root so page CSS cannot
 * restyle it and page script cannot read it through the host. The host is a
 * plain <div>, never a custom element name: a page could define a custom
 * element under a fixed name before we create it and run its own code in the
 * upgrade. It carries a random attribute name, not a fixed marker.
 */
import type { ActionClass } from "../engine/types.js";

export type NoticeKind = "waiting" | "waiting_override" | "denied" | "blocked" | "unreachable" | "refused" | "expired" | "gone" | "unchecked";

const CLASS_WORDS: Record<ActionClass, string> = {
  payment: "payment",
  send: "message",
  account_security: "account security change",
  oauth_consent: "app access grant",
  upload: "file upload",
  download_exec: "download",
  delete: "deletion",
};

export function noticeText(kind: NoticeKind, actionClass: ActionClass | null): string {
  const what = actionClass === null ? "action" : CLASS_WORDS[actionClass];
  switch (kind) {
    case "waiting":
      return `LaunchSafe is holding this ${what} until you approve it. Approve or deny it in the LaunchSafe side panel or approval window. Nothing on this page can approve it.`;
    case "waiting_override":
      return `This page showed hidden instructions aimed at AI agents, so LaunchSafe blocked this ${what}. You can still approve it in the LaunchSafe side panel, where the reason is shown.`;
    case "denied":
      return `This ${what} was denied in LaunchSafe. It did not happen.`;
    case "blocked":
      return `LaunchSafe blocked this ${what}. It did not happen.`;
    case "unreachable":
      return `LaunchSafe could not check this ${what}, so it did not happen. Reload the page, or reload the extension.`;
    case "refused":
      return `The page changed after you approved this ${what}, so LaunchSafe did not carry it out. Try again and approve the new request.`;
    case "expired":
      return `This ${what} was not approved in time, so it did not happen. Try again if you still want it.`;
    case "gone":
      return `The control for this ${what} is gone from the page, so LaunchSafe did not carry it out.`;
    case "unchecked":
      return `LaunchSafe could not check this ${what} on this page, so it did not happen. Try again; if it keeps happening, the page is interfering with LaunchSafe.`;
  }
}

const STYLE = `
:host { all: initial; }
.box { position: fixed; top: 12px; right: 12px; z-index: 2147483647; max-width: 360px; box-sizing: border-box;
  padding: 12px 36px 12px 14px; border-radius: 10px; border: 1px solid #c9cedb; background: #ffffff; color: #111318;
  font: 13px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; box-shadow: 0 6px 24px rgba(17,19,24,.18); }
.title { font-weight: 600; margin: 0 0 4px; }
.close { position: absolute; top: 6px; right: 8px; border: 0; background: transparent; color: inherit; font-size: 18px; line-height: 1; cursor: pointer; padding: 4px; }
@media (prefers-color-scheme: dark) { .box { background: #1a1d24; color: #eceef3; border-color: #2a2e38; } }
`;

export interface Notice {
  show(kind: NoticeKind, actionClass: ActionClass | null): void;
  remove(): void;
}

/** A random attribute name for the notice host (fresh per notice instance). */
export function randomMark(): string {
  const b = new Uint8Array(6);
  crypto.getRandomValues(b);
  return `data-${Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")}`;
}

export function createNotice(doc: Document): Notice {
  const mark = randomMark();
  let host: HTMLElement | null = null;
  let root: ShadowRoot | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const remove = () => {
    if (timer !== undefined) clearTimeout(timer);
    host?.remove();
    host = null;
    root = null;
  };
  return {
    show(kind, actionClass) {
      if (host === null || !host.isConnected) {
        host = doc.createElement("div");
        host.setAttribute(mark, "");
        root = host.attachShadow({ mode: "closed" });
        (doc.body ?? doc.documentElement).appendChild(host);
      }
      if (root === null) return;
      const style = doc.createElement("style");
      style.textContent = STYLE;
      const box = doc.createElement("div");
      box.className = "box";
      box.setAttribute("role", "status");
      const title = doc.createElement("p");
      title.className = "title";
      title.textContent = "LaunchSafe Agent Firewall";
      const body = doc.createElement("p");
      body.style.margin = "0";
      body.textContent = noticeText(kind, actionClass);
      const close = doc.createElement("button");
      close.className = "close";
      close.type = "button";
      close.setAttribute("aria-label", "Close this notice");
      close.textContent = "×";
      close.addEventListener("click", remove);
      box.append(title, body, close);
      root.replaceChildren(style, box);
      if (timer !== undefined) clearTimeout(timer);
      timer = setTimeout(remove, 20_000);
    },
    remove,
  };
}
