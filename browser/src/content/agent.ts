/**
 * Agent signals a page can show (design 8), content side. v0.1 reads only
 * what needs no extra permission: `navigator.webdriver === true` means the
 * browser was launched for automation (Playwright, Puppeteer, Selenium,
 * Browser Use). The worker turns agent mode on for it when the person has
 * detection on (the default); turning it off stays gated.
 *
 * The isolated world reads the real navigator: a page can redefine
 * navigator.webdriver in its own world, but not in ours.
 */
import type { ContentDeps, ContentModule } from "./types.js";

export interface AgentSignals extends ContentModule {
  /** Whether this frame saw navigator.webdriver === true. */
  webdriver(): boolean;
}

export function createAgentSignals(deps: ContentDeps, onAgentMode: (on: boolean) => void): AgentSignals {
  let seen = false;
  return {
    install() {
      seen = deps.win.navigator.webdriver === true;
      if (!seen) return;
      deps
        .send({ type: "agent.signal", signal: "webdriver" })
        .then((r) => {
          if (r !== undefined && r !== null && typeof r.agentMode === "boolean") onAgentMode(r.agentMode);
        })
        .catch(() => undefined);
    },
    uninstall() {},
    webdriver: () => seen,
  };
}
