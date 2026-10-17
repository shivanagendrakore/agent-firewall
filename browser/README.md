# LaunchSafe Agent Firewall for browsers

A Manifest V3 extension for Chromium browsers, part of the
[LaunchSafe Agent Firewall](../README.md) repository. It carries the
firewall's stance into the browser. In agent mode, which you turn on (or which
turns on when the browser reports automation), purchases, sends and deletions,
uploads to a new site or from a session that has seen private data, and private
data moving to a new site are held for your approval in the
extension's side panel, which the agent cannot reach. With agent mode off, it
holds OAuth consent, account-security changes and executable downloads, and
warns about private data. All within the limits in the
[threat model](docs/threat-model.md). Deterministic, no model calls. It makes
no requests of its own; the only requests it causes are ones you approve:
re-downloading a held file and reopening a held address.

Minimum Chrome 121; Chrome, Chromium, Edge and Brave for the native link; the
end-to-end tests run only in Playwright's Chromium on Linux.

Status: built, not released; it is not in any extension store yet. It has the
content guard and navigation policy, the sensitive-action gate with persistent
approvals, the downloads gate, the leak guard, agent mode, a hash-chained
decision log, and an optional [link to the local firewall](../docs/browser-link.md).
Read [docs/design.md](docs/design.md) and
[docs/threat-model.md](docs/threat-model.md).

The extension has its own `package.json`, tests and release (the Chrome Web
Store). It is not part of the npm package built from the repository root.

## Layout

| Path | What |
|---|---|
| `src/engine/` | the pure engine: actions, classes, rule table, leak and navigation decisions, URL scan, bindings, session trust. No browser APIs (lint enforces it); unit-tested in Node |
| `src/vendor/firewall/` | the firewall's browser-safe scanners, copied from `../src` (see below); never edit here |
| `src/shared/messages.ts` | the message contract between content scripts, worker and UI, with sender checks and validation |
| `src/content/` | content script: `guard.ts` (live DOM scan, neutralise in agent mode), `nav.ts` (URL scan, `javascript:` links), `gate.ts` (sensitive-action gate), `leak.ts` (leak guard), `agent.ts` (webdriver signal), wired in `index.ts` |
| `src/worker/` | service worker: session state, agent-mode navigation rules, the approvals queue, downloads, leak checks, the IndexedDB log, settings, and `link.ts` (the optional native link to the local firewall) |
| `src/ui/` | side panel, approval window, popup, `limits.html`, and `blocked.html`, the page a stopped navigation lands on |
| `src/manifest.ts` | the manifest's one source; `manifest.test.ts` fails on any permission beyond design section 11 |
| `test/e2e/` | Playwright: fixtures (fresh temp profile, loopback only), corpus server, specs |
| `test/corpus/` | pages served from 127.0.0.1 as `shop.test`, `mail.test`, `attacker.test`, `accounts.test`, and false-positive cases; the snapshots of real pages used for false-positive checks are kept outside the repository (`scripts/capture-corpus.mjs` makes them; the counts in `docs/real-corpus-findings.md` are from a capture dated 2026-10-11) |
| `test/agents/` | agent simulators: A (page script), D (Playwright input), B (test-only `chrome.debugger` extension) |
| `store/` | Chrome Web Store listing, permission justifications and privacy policy (submitted for review on 16 October 2026) |

## Commands

Run from `browser/`:

```sh
npm ci
npm run typecheck     # tsc, strict
npm run lint          # eslint, zero warnings
npm test              # Vitest unit tests (engine, messages, manifest, build output, vendored scanners)
npm run check:vendor  # vendored scanners carry their pinned commit and match it
npm run check:psl     # Public Suffix List copy: digest, and the pinned upstream commit when online
npm run build         # esbuild -> dist/ (load it unpacked in chrome://extensions)
npm run e2e:install   # Playwright's bundled Chromium, once
npm run test:e2e      # Playwright end-to-end tests against dist/ (build first)
npm run check         # typecheck, lint, vendor and PSL checks, unit tests, build
```

## Scanners shared with the firewall

`src/vendor/firewall/` holds the firewall's browser-safe scanners (content
scan, HTML analysis, lexicon, network predicates, secret and personal-data
detectors) copied from `../src`, so the extension runs the same scanners as the
firewall's MCP gateway and email guard. Each copy starts with a header naming
its source file and the commit it was copied at
(`src/vendor/firewall-commit.ts`). To change a scanner, change it in `../src`,
commit, then run `npm run sync:firewall` here (it copies at `HEAD`).
`npm test` fails when a copy differs from `../src`; `npm run check:vendor`
compares the copies with the pinned commit.

## Test rules

- Each e2e test launches Playwright's bundled Chromium with a fresh profile in
  the OS temp directory, headless, with only this extension (and, for
  simulator B, the test agent) loaded. Never a real browser profile.
- Host names resolve only through `--host-resolver-rules` (the `.test` hosts map
  to 127.0.0.1, everything else fails), and every request to another host is
  routed to a failing handler and recorded; tests assert none happened.
- Corpus payloads are inert and name only `attacker.test`.
- Verified only in Playwright's Chromium against simulated agents and local
  pages. Not yet run on stable Chrome, Edge or Brave, on Chrome 121, or on live
  sites. Tests that need inputs kept outside the repo (a corpus of real pages,
  the real firewall, a live agent) skip when those are absent.

## Link to the local firewall (manual check)

The e2e suite covers the link with a stand-in host in a temporary profile, and
against the real firewall when `LAUNCHSAFE_FIREWALL_CLI` names a built
firewall's `dist/cli.js` (from the root: `npm run build`). Setup is in
[docs/browser-link.md](../docs/browser-link.md). What only a person can check,
in each browser (Chrome, Edge, Brave) with their own profile:

1. Load `dist/` unpacked, then in a terminal (not an agent) run
   `launchsafe-firewall install --browser chrome --extension-id <id>`;
   `launchsafe-firewall doctor` shows "browser link (chrome)" ok.
2. Side panel, "Link to the local firewall…": the browser's prompt names
   "Communicate with cooperating native applications"; allow it. The status
   line says connected.
3. Turn agent mode on, open any site: `launchsafe-firewall log tail` shows
   `browser_decision` and `browser_taint` entries; `launchsafe-firewall log
   verify` passes.
4. With an approval passphrase set, turn agent mode off: the approval appears
   in `launchsafe-firewall queue`; `queue approve <id>` (passphrase) ends agent
   mode in the browser.
5. Turn the link off: the permission is removed (`chrome://extensions`,
   Details). `launchsafe-firewall uninstall --browser chrome` removes the
   manifest; turning the link on again says the firewall is not installed.

## Not built

Described in the design and not in the code (the threat model marks each):

- the main-world shim (requests page script makes: `fetch`, XHR,
  `sendBeacon`, `form.submit()` are not seen);
- the hard lock (a frame that refuses other extensions' debugger on a tab);
- the optional `debugger`, `management` and `tabGroups` permissions and the
  agent detection that would use them;
- a keyboard command or toolbar toggle for agent mode (the side panel has the
  switch);
- input-shape detection (values without key events, centred clicks) and
  detection of browsers with built-in agents;
- biometric and phone approval;
- badge counts and the side-panel note for flagged pages;
- an enterprise build with `webRequestBlocking` body inspection;
- a dedicated fake-CAPTCHA rule (the generic hidden-text rules catch the test
  page);
- the agent origin set in the UI (the engine supports it; it is never on).

## Testing notes

- Unit tests run in Node; the content-script tests (`src/content/*-dom.test.ts`)
  run in happy-dom, a devDependency used only by tests.
- The worker accepts approve, deny, agent-mode, settings, log and link
  messages only from the real side panel or its own approval window (threat
  model, section 5). So the e2e specs open the real side panel the way the
  toolbar popup does (`test/e2e/side-panel.ts`: `chrome.sidePanel.open` from
  `popup.html`, inside Playwright's user gesture) and decide from it; the
  shipped build is the one tested, with no test-only switch. Chrome reports a
  side panel as a DevTools target of type "other", which Playwright ignores
  unless `PW_CHROMIUM_ATTACH_TO_OTHER` is set; the fixtures set it, so the
  panel arrives as an ordinary Playwright page. When it does not, the error
  lists every target with its type and url. `sidepanel.html`
  opened in an ordinary tab is used only to show that such a page reads but
  cannot decide. The e2e specs need Playwright's Chromium (`npm run
  e2e:install`).
- On GitHub, the Browser extension workflow can be run by hand
  (workflow_dispatch) with an optional `spec` input (a spec file or path
  regex, or `-g <title regex>`): only the e2e job runs, on those specs, and it
  stops after three failures.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for the vendored code.

To report a security problem, see [SECURITY.md](https://github.com/shivanagendrakore/agent-firewall/blob/main/SECURITY.md).
