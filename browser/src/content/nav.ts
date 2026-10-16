/**
 * In-page navigation checks (design 4.3, 7):
 *
 * - The URL scan on load and on same-document navigations (CometJacking,
 *   HashJack): a query or fragment that carries text addressed to an agent is
 *   reported as the page's verdict, and in agent mode a quarantine-class
 *   fragment is removed with history.replaceState (the query cannot be
 *   removed without reloading; the worker's mark on the tab stays either way).
 * - Clicks on javascript: links in agent mode, which declarativeNetRequest
 *   cannot see: the default action (running the URL) is cancelled, and the
 *   page's own click handlers still run, so sites that use
 *   href="javascript:void(0)" as a button keep working.
 *
 * Everything else about navigation is the worker's declarativeNetRequest
 * rules (engine/nav-rules.ts), which hold whatever drives the browser.
 */
import { scanUrl } from "../engine/url-scan.js";
import type { ContentDeps, ContentModule } from "./types.js";

export interface NavGuard extends ContentModule {
  /** Scan the current URL (on load and on same-document navigations). */
  checkCurrentUrl(): void;
}

/** The scheme of an href as the browser would read it (leading spaces and control characters ignored, case-insensitive). */
export function hrefScheme(href: string): string {
  // eslint-disable-next-line no-control-regex -- browsers strip C0 controls and spaces before parsing a URL's scheme
  const s = href.replace(/^[\u0000- ]+/, "").replace(/[\t\n\r]/g, "");
  return /^([a-z][a-z0-9+.-]*):/i.exec(s)?.[1]?.toLowerCase() ?? "";
}

export function createNavGuard(deps: ContentDeps): NavGuard {
  const win = deps.win;
  /** URLs already reported, so a hash that flips back and forth is reported once. */
  const reported = new Set<string>();

  const checkCurrentUrl = () => {
    const href = win.location.href;
    const r = scanUrl(href, deps.agentMode());
    if (r.verdict !== "deliver" && !reported.has(href)) {
      reported.add(href);
      deps.send({ type: "page.scanned", url: href, verdict: r.verdict, reasons: [`url_${r.part ?? "query"}`, ...r.reasons].slice(0, 32), scanIncomplete: false }).catch(() => undefined);
    }
    if (r.stripFragment) {
      const clean = href.slice(0, href.length - win.location.hash.length);
      try {
        win.history.replaceState(win.history.state, "", clean);
      } catch {
        // A sandboxed frame may refuse; the tab is marked regardless.
      }
    }
  };

  const onClick = (e: Event) => {
    if (!deps.agentMode()) return;
    const path = e.composedPath();
    // By tag name, not instanceof: the content script's window and the frame's differ in tests and in about:blank frames.
    const link = path.find((n): n is Element => {
      const tag = typeof (n as Element).tagName === "string" ? (n as Element).tagName.toUpperCase() : "";
      return (tag === "A" || tag === "AREA") && (n as Element).hasAttribute("href");
    });
    if (link === undefined) return;
    const scheme = hrefScheme(link.getAttribute("href") ?? "");
    if (scheme !== "javascript") return;
    // Only the navigation is cancelled: page handlers still run (stopping them would break sites that use such links as buttons).
    e.preventDefault();
    deps.send({ type: "nav.blocked", rule: "nav.script_url", scheme: "javascript" }).catch(() => undefined);
  };

  return {
    install() {
      checkCurrentUrl();
      win.addEventListener("hashchange", checkCurrentUrl, true);
      win.addEventListener("popstate", checkCurrentUrl, true);
      win.addEventListener("click", onClick, true);
      win.addEventListener("auxclick", onClick, true);
    },
    uninstall() {
      win.removeEventListener("hashchange", checkCurrentUrl, true);
      win.removeEventListener("popstate", checkCurrentUrl, true);
      win.removeEventListener("click", onClick, true);
      win.removeEventListener("auxclick", onClick, true);
    },
    checkCurrentUrl,
  };
}
