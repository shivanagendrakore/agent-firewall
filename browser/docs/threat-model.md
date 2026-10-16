# Threat model: LaunchSafe Agent Firewall for browsers

Status: built, not released (extension version 0.0.1, not in any store). This
document describes the code as built; anything planned and not built is marked
"not built". Companion to [design.md](design.md).

## 1. What we defend against

An AI agent acting in the person's own browser, with the person's sessions,
reads content an attacker controls and is steered into an action that harms
the person:

- **Exfiltration:** reading private data on one site (mail, OTPs, account
  details, documents) and moving it to another (typing it into a form,
  putting it in a URL, posting it).
- **Unwanted transactions:** purchases, payments, bookings.
- **Unwanted sends:** emails, messages, posts, replies, invitations.
- **Account takeover steps:** changing password, MFA, recovery details, mail
  forwarding and filter rules, creating API keys, granting OAuth consent.
- **Malware delivery:** downloading and opening executables or installers.
- **Data loss:** deleting accounts, repositories, files.

### Attacker capability

The attacker can put content where the agent will read it: a whole site they
own, a comment, review, listing, email, shared document or ad on a site they do
not own, a URL (query and fragment), an image. They know which agents and
which extension the person uses. They do **not** run code on the machine, do
not control the agent vendor, and do not control the person's own
instructions to the agent.

### The defender's goal

As in the coding firewall, the goal is to limit what a fooled agent can do: the damage above is meant to need a person's approval somewhere the agent cannot reach, within the limits listed below. We also try to
keep the agent from being fooled (content guard), but nothing rests on that.

### The trifecta in the browser

An agent is dangerous when it has private data, untrusted content and a way
out at once (<https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>).
In a browser all three are always present: every page is outside content,
signed-in sites are private data, and every form and URL is a way out. The
extension tracks the first two per agent session (`untrusted`, `private`) and
gates the third where the browser lets it.

## 2. Assets and trust boundaries

| Asset | Where it lives | Boundary the extension can enforce |
|---|---|---|
| Sessions and cookies | browser profile | none directly; the agent uses them as the person |
| Private data shown in pages | DOM of private tabs | content scripts see it; fingerprints let us notice it moving |
| Money, payment methods | merchant and payment frames | the submit/activate gate in those frames |
| Account control | settings pages, OAuth consent pages | the gate on adapters and heuristics |
| Files on disk | the OS, reached through uploads | the upload gate (file inputs and drops) |
| The approval | extension UI, native host, phone | depends on agent class (section 3) |
| The extension's own policy and log | extension storage | page script cannot reach it; the profile owner and OS-level agents can |

Trusted: the person; the extension's own pages and worker; the native host and
local firewall (when linked). Untrusted: every page and frame, every URL, every
file offered for download, and **the agent itself** (it may be acting on an
attacker's instructions).

## 3. Agent classes and what holds against each

| Class | How it drives the browser | Input path | Gate (cancel in page) | Approval out of reach | Leak guard | Navigation policy | Content guard |
|---|---|---|---|---|---|---|---|
| A. Page-script automation | script in the page dispatching events | page JS, `isTrusted: false` | **holds** for events (clicks, submits, Enter, file inputs, drops, pastes); **not covered**: `form.submit()`, `fetch`, XHR, `sendBeacon` (no event) | **holds** (any surface) | holds on typed, pasted and submitted values and clicked links; **not covered**: requests page script makes itself | holds | holds |
| B. Another extension driving tabs through `chrome.debugger` (CDP input) | trusted CDP input into the tab | trusted CDP input | **holds** for input | **holds** with extension UI | holds on typed, pasted and submitted values and clicked links | holds | holds when hidden text is removed before the agent reads; an agent that snapshots the page first can read it |
| B'. Same, running its own script in the page | CDP `Runtime.evaluate` or a script tool | page-world script | **not covered** (a main-world shim is planned and is not built) | holds | **not covered** for requests the script makes; values it types or submits through events are checked | holds for navigations | as B |
| C. An agent built into the browser | renderer-level trusted input, accessibility clicks | browser-internal | **holds** if our content script runs in its tabs (unverified) | **unverified** | as B | holds for browser navigations; not for server-side fetches | as B, for DOM and accessibility-tree readers |
| D. Remote CDP automation with our extension loaded | an automation library or a DevTools client | remote CDP | holds against input | **does not hold** (CDP reaches our pages) | as B | holds unless it changes rules through our pages | as B |
| D'. Remote CDP in its own profile | the same, default setup | remote CDP | **not present** | not present | not present | not present | not present |
| E. OS-level computer use on the person's machine | a desktop computer-use agent | OS input | holds against input | **does not hold** (biometric or phone approval is not built) | as B | holds | holds for DOM readers; not for screenshots |
| F. Cloud agents | a remote browser or server-side fetches | remote | **not present** | not present | not present | not present | not present |

Reading the table: "holds" means a deterministic check on the path named, not
that the agent class is safe. The extension has been tested only against its
own test simulators (A: page script, B: a test-only `chrome.debugger`
extension, D: Playwright); it has not been tested against any named agent
product, so no product is listed here. B', D, E and F are shown in the UI as
not protected or partly protected.

## 4. Attacks and the controls that answer them

| # | Attack | Primary control | Residual |
|---|---|---|---|
| 1 | Hidden text instructions (display:none, tiny or same-colour text, off-screen, comments, aria-hidden, spoilers, attributes an agent reads such as aria-label, aria-roledescription and aria-valuetext) | content guard removes them in agent mode; tab marked untrusted; quarantine tabs deny sensitive actions; class and style changes are rescanned (budgeted) | an agent that reads or snapshots the page before the guard removes the text (removal races the read); server-side fetch; novel hiding the scanner misses; text a stylesheet generates (`::before`/`::after` `content`), which is in no DOM node; anything inside a closed shadow root |
| 2 | Visible instructions ("AI assistants must ...") | lexicon flags the tab; gate and leak guard hold regardless | visible text is not removed (a person must see the page as it is) |
| 3 | Instructions in URL query or fragment (CometJacking, HashJack) | URL scan on every navigation; fragment stripped in agent mode | the agent may have read the URL from its own input before the page loads |
| 4 | Fake CAPTCHA or security check | no dedicated rule: the generic hidden-text and agent-addressed lexicon rules catch the test page's hidden instruction; the gate holds what it asks for | well-made lures with no hidden text are only caught at the action |
| 5 | Text in images (screenshot attacks) | none (no OCR) | full; the gate is the backstop |
| 6 | Exfil by typing private data into an attacker form | fingerprints and data detectors on type/paste/submit to a different registrable domain; values are matched after normalising (case, compatibility forms, zero-width characters, separators, "[at]"/"(dot)") | script-set values posted by script (B'); a string split across several fields or messages, reordered, paraphrased or spelled out in words |
| 7 | Exfil by navigating to a URL carrying data | DNR capture-host list, high-entropy rule (tenant hosts such as Forms, Apps Script, Sites and Groups are their own sites, also in the DNR rule); the site that injected outside content is not a trusted destination while the session is quarantined; a clicked link's query values are checked against the leak guard's fingerprints and detectors | low-entropy or chunked data to an unlisted host; coarse regex; navigations started by script or typed into the address bar are not checked against fingerprints; see 4.1 for the injecting-site cases that remain |
| 8 | Exfil by `fetch`/beacon from page script | none (a main-world shim is planned and is not built) | full |
| 9 | Exfil through the agent vendor (connectors, server-side tools, the model call) | none | full; out of scope |
| 10 | Purchase on a fake or real store | `payment` gate in agent mode | heuristic miss on an unusual checkout; agent mode off and undetected |
| 11 | Send email or message | `send` gate in agent mode; adapters for top sites | SPA sends without a labelled control on a site with no adapter |
| 12 | Change password, MFA, recovery, forwarding rules; create API keys | `account_security` gate, always on | sites with no adapter and unusual forms |
| 13 | OAuth consent to an attacker app | `oauth_consent` gate, always on, for known providers | unknown identity providers |
| 14 | Download and run | `download_exec` gate, always on: an executable, installer, script, shortcut, disk image or macro document is cancelled before the file is written under its name, and downloaded again once approved | the agent opening a file through the OS (class E); archives (.zip, .7z, .rar, .tar.gz) are not held, so an executable inside one is only caught if it is downloaded on its own; the first request for the file has already reached the server |
| 15 | Upload private files (CDP `setFileInputFiles`, drag and drop) | `upload` gate in private or new-origin sessions | uploads by page script building `FormData` (B') |
| 16 | Agent clicks the approval | extension UI out of reach for A, B (C unverified); approve, deny and agent-mode messages accepted only from the side panel or the approval window the worker opened, never from our pages loaded in an ordinary tab; settings, log and link changes only from the side panel | D and E (biometric or phone approval is not built) |
| 17 | Agent turns agent mode off or disables the extension | turning agent mode off is gated; `chrome://extensions` is not reachable by A, B, C | D and E can do both |
| 18 | Page spoofs our UI (fake "LaunchSafe approved" overlay) | approvals never happen in the page; the in-page notice says "approve in the side panel" | a person who trusts an in-page fake; we teach "approvals are only in the side panel" |
| 19 | Malicious extension spoofs our UI or the agent sidebar (SquareX) | out of scope (section 6) | full |
| 20 | Page fights our content script (removing markers, re-adding hidden nodes, timing, wearing our marker attribute, padding a hidden instruction past half the page so it reads as a loading veil) | isolated world; our capture listeners registered first at `document_start`; MutationObserver rescans; our markers known by identity (private `WeakSet`), not by attribute; the loading-veil exemption only for hidden text that is benign on its own | a page that re-adds content faster than the debounce in a tight loop: rescans slow down and the page is reported `scan_incomplete`, which marks the tab untrusted (in agent mode a page over the scan budget is quarantined) |
| 25 | Page floods the session or the worker (thousands of private-looking strings, hundreds of held actions, a decision per keystroke, huge field values, many link hosts) to push out what matters or keep the worker busy | prints capped at 2,000 (codes evicted last); a refused context makes the frame ask the worker; approvals coalesced and capped per tab (50) and in total (200); per-frame budgets in the worker for scans (calls and characters), log rows (counted, then dropped with one `log_throttled` row) and link hosts (200); the log keeps at most 20,000 entries and reads them by cursor; the session records at most 500 domains (past that a domain stays "new", which is stricter); one in-page scan reads at most 64 KB (more is held for the worker) | a page that shows more than 2,000 one-time-code-shaped strings can still evict an older code; a frame over its budget gets no answer, so its held values stay held until it slows down |
| 26 | "Approve for this site" stretched to a page-named target | the grant covers only the frame's own site (the one on the card), saved only after the approval is confirmed | none known |
| 21 | Approval reuse for a changed form | approval bound to element path, field names and value digest; replay re-checks | none known |
| 22 | Prompt-injecting the person through our UI (hidden text echoed in the approval dialog) | evidence shown escaped (control, bidi, zero-width characters visible), truncated, labelled as page content | none known |
| 23 | Omnibox-style first-party trust (NeuralTrust) | out of reach (browser UI); documented | full |
| 24 | CSRF into the agent's memory (Tainted Memories) | out of reach (vendor side) | full |
| 27 | Link or image whose URL is a template for the model to fill (`https://x/p.gif?d={user_email}`, EchoLeak-style) | content guard's template rule (4.2): hidden quarantines and is removed in agent mode, visible flags; capture hosts always count | a slot embedded in a longer value with an ordinary name (`?ref=/u/{name}`) is not a template; a code- or document-shaped value counts only with a private-data name on a hidden off-site link |

### 4.1 The injecting site as a destination

A domain whose page or frame got a **quarantine** verdict in an agent session
is recorded as an injector. While the session is quarantined, a data-carrying
URL to it needs approval even though the session "knows" it, in the engine and
in the DNR rule. What remains:

- **Undetected injection.** A page whose instruction the content guard did not
  catch (verdict `deliver` or `neutralize`) is not an injector; its domain stays
  a known destination. The capture-host list and the high-entropy rule still
  apply to other domains, and the leak guard still judges typed and submitted
  data.
- **`flag` verdicts.** Visible agent-addressed text flags the tab but does not
  make its domain an injector (a person can see that text).
- **Shared domains.** An injection in a frame or post on a big site (an email
  in Gmail, a comment on a forum) makes that whole registrable domain an
  injector for the rest of the session, which is strict for the person (more
  approvals there); it never relaxes anything. Tenant hosts
  (`engine/domain.ts`) keep Forms, Apps Script, Sites, Groups and similar hosts
  separate from the first party.
- **Session not quarantined.** Injector domains are excluded only while the
  session carries a quarantine. Agent sessions never clear a quarantine, so in
  practice this holds until agent mode is turned off (which needs an approval).

### 4.2 Real-page tuning of the content guard

The real-page corpus (`docs/real-corpus-findings.md`) found false positives; the fixes narrowed these rules,
and each narrowing is a residual:

- **`display: contents` is transparent.** An element with no box of its own is hidden only by its own
  `visibility` (which its children inherit); `opacity`, `clip` and `clip-path` do not apply to it, so they are
  ignored, as the browser ignores them. Its children are judged on their own boxes, so hidden text inside it is
  still hidden. Residual: none known beyond the rules for ordinary elements.
- **Template rule.** A slot (`{x}`, `{{x}}`, `${x}`, `<x>`, or their encodings) counts when it is the whole of a
  query or fragment value (or a whole line of one), a whole path segment or host label that names a secret, a
  private-data name in a short one-line query value, or a private-data name anywhere in a hidden link to another
  registrable domain. HTML tag names and type parameters are not slots. Residual: an exfiltration template that
  embeds an ordinarily named slot inside a longer value, or a private-data slot inside code-shaped text on a
  same-site or visible link, is not caught by this rule (the leak guard and the navigation rules still apply to
  the data itself). The vendored scanner's own template rule, used for unrendered markup and mail, is unchanged.
- **One-time codes.** A 4 to 8 digit number is a code only near an OTP phrase (verification, one-time, passcode,
  sign-in code, "your code", "code is", 2FA and similar) or right after "code", "PIN" or "passcode"; a plausible
  year (1900 to 2099) only after "code is" or "code:"; never part of a date, decimal, price, percentage or
  thousands group. Residual: a code shown with none of those words, or a year-shaped code with a looser label,
  is not fingerprinted (the leak guard's other detectors still apply).

## 5. The extension as a target

- **Content script integrity.** Runs in the isolated world; page script cannot
  read its variables or remove its listeners. A page can detect it (its
  notices, timing) and behave differently for protected users. Accepted. The
  in-page notices are plain `<div>` hosts with a random attribute name (never a
  custom element name a page could define first and run code in) holding a
  closed shadow root.
- **DOM clobbering.** A form's named controls shadow its properties for every
  world (`<input name="action">` replaces `form.action`; `name="elements"`,
  `name="tagName"`, `name="requestSubmit"` likewise). The gate and the leak
  guard read forms through prototype getters captured at `document_start`
  (`src/content/dom-safe.ts`), and every capture listener fails closed: if it
  throws, the event is cancelled and dropped (never replayed), the notice says
  LaunchSafe could not check it, and the worker is told so the attempt is
  decided and logged. The person can try again.
- **Shadow DOM.** Listeners read the event's composed path, so a control in an
  open shadow root is judged as itself, not as its host. `submit` and `change`
  are not composed, so every open shadow root found (from composed events in
  the capture phase, a walk at `DOMContentLoaded`, and added nodes) gets its own
  capture listeners. Residuals: **closed shadow roots** are invisible to all
  three content modules (the gate, the leak guard and the content guard: their
  nodes are in no event path we see and in no tree walk, so hidden text in one
  is not scanned and a form in one is not checked on submit); a form that page
  script creates in a new shadow root and submits in the same task, before any
  observer runs, is missed.
- **Before the worker answers.** Until a frame has a leak context it can trust,
  every non-empty insertion or paste is cancelled and the field frozen until
  the worker answers (an allow puts the value in): nothing is let in first and
  taken back later. Changes that cannot be cancelled (IME composition,
  `execCommand`, script) are checked and taken back if the worker holds them.
- **Main-world shim.** Not built. Requests page script makes (`fetch`, XHR,
  `sendBeacon`, `form.submit()`) are not seen by the extension.
- **Messages from pages.** The worker accepts content messages only from its
  own content scripts (`sender.id`, `sender.tab`, `sender.frameId`) and
  validates every field. Pages never get `externally_connectable`. UI messages
  are accepted only from our own pages, and what each page may ask depends on
  where it is (`src/worker/ui-surface.ts`): approve, deny and agent mode only
  from the side panel (no tab) or the approval window the worker opened (its
  window id); settings, the log and the link switch only from the side panel;
  our pages loaded in an ordinary tab, which an automation client can open,
  can only read. Each content sender has budgets for scans, log rows and link
  hosts; over budget it gets no answer, which the content script treats as
  "worker unreachable" (fail closed).
- **Approval replay.** Pass tokens are one-shot, random, bound to tab, frame,
  element path and value digest, and expire with the pending action. The
  navigation one-time pass allows exactly the approved address (scheme, host,
  port, path and query; no other address on that host, no subdomains) in that
  tab, for 30 seconds or until the tab commits; its bookkeeping survives a
  worker restart, and orphaned allow rules are removed at start. A literal `*`
  in the approved address is a wildcard to the browser's rule matcher, so the
  pass also covers addresses that differ only there.
- **The approval gesture.** Approve takes a trusted pointer press and release,
  or a trusted Enter or Space on the button after Tab moved focus to it, in
  both cases only after the card has been shown for 400 ms. A button that
  already had focus when the card appeared, a held-down (repeating) key and any
  script-dispatched click or key do not approve. Our pages cannot be reached by
  page script or by agents whose input goes to a tab, so a trusted key event
  there, like a trusted pointer event, comes from the person's devices, from
  remote debugging (D) or from the OS (E), and those can click as well.
- **What is kept.** Approval records hold masked previews and digests, never
  field values or a blocked address; the log's binding is salted per agent
  session; deleting the log leaves a record of the deletion. The native link
  carries the same: mirrored entries keep the salted binding and the
  log-deleted marker, and approvals filed with the firewall carry only the
  masked preview, never a value or a held blocked address.
- **Native host.** Accepts only our extension id (Chrome's `allowed_origins`,
  and the host checks the origin again); validates message shape and size on
  both sides and drops the link on anything else; never executes anything from
  a message; approvals from the host are honoured only for a pending approval
  with that binding, and the host sends `approve` only for a queue item signed
  with the firewall's approval key. The host is the local firewall's binary,
  with its existing protections; its manifest directory is a persistence path
  the firewall's hook guards. Taint from the host only ever adds.
- **Policy tampering.** Policy lives in extension storage, closed to content
  scripts (`chrome.storage.session` and, where the browser supports it,
  `chrome.storage.local` are set to trusted contexts only). A remote CDP client
  or OS-level agent can change it through our pages; with the native link,
  settings changes are mirrored to the firewall's signed log.
- **Denial of service.** Scans are budgeted (runs and characters per scan,
  rescans per second, class and style rescans per flush); a page over budget is
  marked `scan_incomplete`, which marks the tab untrusted rather than trusted,
  and in agent mode a page the guard could not judge in full (over the scan
  budget, or a scan that threw) is quarantined. Going over the class and style
  rescan budget only marks the tab untrusted: a page that toggles many classes
  must not deny every sensitive action in every tab. Page-controlled regular expressions are
  bounded (see the vendored-scanner note below). Per-frame budgets in the
  worker are listed in row 25.
- **Vendored scanners.** Some secret patterns in the vendored scanner
  (`src/vendor/firewall/engine/secrets.ts`, copied from the firewall) are
  unbounded (`{20,}`, a lazy `[\s\S]{20,}?` between private-key markers). The
  extension bounds what reaches them (64 KB per in-page scan, per-frame
  character budgets in the worker); bounded forms are to be made in the
  firewall and synced, never edited here.
- **Supply chain.** No runtime dependencies beyond the vendored engine;
  lexicons and rules are bundled, not fetched. A reproducible build is a goal
  and has not been verified.

## 6. Out of scope

- Malicious or compromised extensions, including other agent extensions, and
  extensions that spoof UI (SquareX). An extension with host access can do
  anything in pages that we can.
- Malware on the machine, a compromised browser, a compromised agent vendor.
- What the agent sends to its own vendor, and agents' server-side fetches and
  connectors.
- Cloud browsers and agents in their own profile or browser.
- The browser's own UI: omnibox, built-in assistant panels, `chrome://` pages.
- Agents with OS-level control, except that biometric or phone approvals still
  hold for actions the extension gates; they can still disable the extension,
  use another browser, or act outside the browser.
- Mobile browsers (no extension support where agents run, or none at all).
- A person approving without reading. The approval UI makes the request
  clear; it cannot make it read.

## 7. Assumptions to verify (from research)

1. Our content scripts run in the tabs each built-in agent acts in (Atlas
   agent mode, Gemini auto browse, Edge Copilot, Neon Do).
2. Built-in agents and `chrome.debugger` agents cannot act on extension pages
   or the side panel.
3. The cross-extension frame check refuses and detaches debugger sessions
   (hard lock), including component extensions.
4. Capture-phase listeners registered at `document_start` precede page
   listeners in every frame type we gate (including `about:blank` and
   `srcdoc` frames with `match_origin_as_fallback`).
5. CDP `DOM.setFileInputFiles` raises `input`/`change` events on the input.

Each becomes a test in the spike; any that fails changes a "holds" cell in
section 3 to "does not hold", and the UI with it.
