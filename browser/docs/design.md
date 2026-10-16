# Design: LaunchSafe Agent Firewall for browsers

Status: the design the extension is built to; the [README](../README.md) says
which parts are built. Read with [threat-model.md](threat-model.md) (what
holds against whom).

## 1. Goal and stance

AI agents now act in people's own browsers, signed in to mail, banks, shops
and admin consoles. A page the agent reads can steer it (indirect prompt
injection). The existing LaunchSafe Agent Firewall answers this for coding
agents at their pre-tool hooks: we do not try to stop the agent being fooled;
we constrain what any agent, fooled or not, can do. This extension carries the
same stance into the browser:

> A hijacked browser agent cannot buy, send, grant, change account security,
> upload, download-and-run, or move private data to a new place without a
> person approving it somewhere the agent cannot reach.

What is held depends on agent mode, which the person turns on (or which turns
on when the browser reports automation, `navigator.webdriver`). In agent mode,
purchases, sends, deletions and uploads are held for the person's approval.
With agent mode off, OAuth consent, account-security changes and executable
downloads are still held; the rest is not (section 5.3).

It is deterministic and never calls a model. It makes no requests of its own;
the only requests it causes are ones the person approves: re-downloading a held
file and reopening a held address.

**Honesty rule.** The extension enforces only what the browser lets an
extension enforce. Which agents that covers is a table, not a promise
([threat-model.md](threat-model.md), section 3). The UI must never say
"protected" for an agent class the extension cannot stop.

## 2. What an MV3 extension can and cannot do

### Can, deterministically

| Capability | API | Note |
|---|---|---|
| See and cancel any DOM event before page handlers run | content script at `document_start`, capture listener on `window` | ours is registered first, so it runs first; covers trusted CDP and renderer input and accessibility clicks |
| Read and rewrite the live DOM, including computed style | content scripts, `all_frames`, `match_origin_as_fallback` | runs in cross-origin iframes when host permission covers them (payment frames) |
| Block navigations and subresource requests by URL, host, type, initiator | `declarativeNetRequest` (static, dynamic, session rules) | no request bodies |
| Pause, cancel or erase downloads | `chrome.downloads` | before the file is opened |
| Draw UI no page can draw into | popup, side panel, extension windows (`chrome-extension://`) | not attachable by other extensions' `chrome.debugger` |
| Refuse another extension's debugger on a tab | a frame of ours in the tab | source-verified, end-to-end unverified ("hard lock") |
| Know a debugger is attached | `chrome.debugger.getTargets()` | needs our own `debugger` permission (optional) |
| Talk to a local program | `chrome.runtime.connectNative` | needs `nativeMessaging` and an installed host |

### Cannot

- Tell a person's input from CDP, renderer-level or OS-level input
  (`isTrusted` and user activation are both satisfied by all three).
- Inspect or block request **bodies** (`fetch`, XHR, beacons) except by
  wrapping page APIs in the main world, which page or agent script can undo.
- See what an agent sends to its own vendor (the model call, server-side
  fetches, connectors such as Gmail APIs), or anything in a cloud browser.
- Run on `chrome://` pages, the Web Store, or pages a browser reserves for
  itself.
- Stop an agent that runs JavaScript in the page (CDP `Runtime.evaluate`, an
  agent's script tool) from calling `fetch` or `form.submit()` directly. Not
  covered: a main-world shim is planned and is not built.
- Stop an agent with OS-level control from clicking our approval UI, disabling
  the extension at `chrome://extensions`, or using another browser.
- Stop a remote-debugging CDP client (an automation library) that has our
  extension loaded: it can attach to our pages too.

## 3. Shape

```
  Page (any frame)                                  Extension
  ┌──────────────────────────────┐                 ┌──────────────────────────────┐
  │ content script (isolated)    │  messages       │ service worker               │
  │  • content guard (scan,      │◀──────────────▶ │  • tab state (trust, taint,  │
  │    neutralise, URL scan)     │                 │    private data, agent mode) │
  │  • action gate (capture      │                 │  • decide(): pure engine     │
  │    listeners, form/file/     │                 │  • DNR rule manager          │
  │    paste/input watchers)     │                 │  • downloads gate            │
  │  • leak guard (field values) │                 │  • approvals queue           │
  │ main-world shim: NOT BUILT   │                 │  • log (hash chain)          │
  │  (planned: submit/fetch/XHR) │                 │  • native link (optional)    │
  └──────────────────────────────┘                 └──────────────┬───────────────┘
                                                                  │
  approval surfaces: side panel · approval window ·  (not built: biometric · phone)
                                                                  ▼
                                               local LaunchSafe firewall (native messaging)
```

Code layout mirrors the coding firewall: a **pure engine** (`src/engine/`, no
browser APIs, unit-tested in Node) and thin **adapters** (`src/content/`,
`src/worker/`, `src/ui/`). The engine's interface is
`decide(action, tabState, policy) -> Decision` where `action` is a normalized
browser action (section 5.1), so the same rule table can later run inside the
coding firewall for `mcp__claude-in-chrome__*` calls (section 10).

## 4. Component 1: page content guard

**Job:** find instructions a person would not see, neutralise them in agent
mode before an agent reads the page, and record that the tab showed outside
content.

### 4.1 Reuse

Vendored (Apache-2.0, with NOTICE, by `scripts/sync-firewall.mjs`) from the
firewall's `src/engine/` at the root of this repository, all browser-safe (no
Node imports; `bytes.ts` replaces Node crypto):

| Module | Used for |
|---|---|
| `content-scan.ts` (`scanContent`, `scanCharacters`, `verdictFor`) | tag characters, dense zero-width, bidi, lexicon hits over hidden and visible text, verdicts |
| `content-lexicon.ts` + vendored `agent-safety/signals.ts` | agent-addressed phrases, outbound instructions, standing overrides |
| `content-html.ts` (`analyzeHtml`) | static HTML that is not rendered: `srcdoc`, `<template>`, `<noscript>`, HTML in attributes, fetched fragments, and the test corpus |
| `network.ts` (`isCaptureHost`, `urlCarriesData`, `isDnsExfilShape`, `entropy`) | links and navigation targets |
| `secrets.ts`, `pii.ts` | leak guard (section 6) |

### 4.2 Live DOM scan

In a live page we do not need the CSS resolver: the browser already knows what
is visible. The content script walks text nodes and attributes the agent may
read (`alt`, `title`, `aria-label`, `aria-description`,
`aria-roledescription`, `aria-valuetext`, `placeholder`, `value`, `<meta>`
content) and classifies each run as:

- **hidden**: `!el.checkVisibility({ opacityProperty: true, visibilityProperty: true, contentVisibilityAuto: true })`,
  zero box, clipped to under 2 px, off-screen beyond the document, font size
  under 2 px, colour contrast under 1.2:1 against the computed background
  (reuse `contrastRatio`), `aria-hidden` subtrees with text, HTML comments;
- **folded**: collapsed `<details>`, spoiler classes, `hidden=until-found`
  (shown on interaction: judged as hidden only with an instruction hit, which
  is what the Brave Reddit spoiler needed);
- **visible**.

Hidden and visible text are passed to `scanContent` as text with the hidden
spans marked, so the same signals and verdicts as the email guard apply.
Screen-reader-only text (`.sr-only` patterns) is hidden by these tests; it is
only neutralised when it carries a quarantine-class hit, never wholesale.

**As built (re-review fixes).** A page that hides most of its text (a hidden
run longer than half the page's text: a fade-in, a loading veil) is read as
not shown yet rather than as hidden text, but only when that run is benign on
its own (`isBenignVeil`: no agent-addressed lexicon hit, not quarantine-class
and no agent-directed or exfil-link signal when scanned alone); padding an
instruction past half the page no longer makes it "visible". The guard
recognises its own markers by identity (a private `WeakSet` of the elements it
inserted), never by their `data-launchsafe-removed` attribute, which a page can
set on anything.

Not read: text a stylesheet generates (`::before`/`::after` `content`,
counters, `attr()`), which is in no DOM node, and anything inside a closed
shadow root. Both are residuals (threat model, row 1 and section 5).

### 4.3 Other channels

- **The URL.** Query string and fragment are scanned as text on every
  navigation (CometJacking, HashJack). A fragment or parameter with a
  quarantine-class hit marks the tab and, in agent mode, is replaced via
  `history.replaceState` with the fragment removed before the page settles.
  The agent may already have the URL from its own context; this only removes
  it from the page.
- **Fake verification lures.** Planned: a lexicon family for "verify you are
  human / security check / to continue, the assistant must ..." and a
  CAPTCHA-shape rule. Not built as a dedicated rule: the generic hidden-text
  and agent-addressed lexicon rules catch the test lure's hidden instruction,
  and the gate holds what a lure asks for.
- **Images.** Text inside images (faint-text screenshots) is out of reach
  without OCR. The extension does not run OCR; this is a listed miss.
- **Dynamic content.** A `MutationObserver` rescans added subtrees and changed
  text and attributes (including `class` and `style`, which can reveal or hide
  text), debounced (40 ms) and budgeted (runs and characters per scan, rescans
  per second, class and style rescans per flush), so comments and chat widgets
  that load late are covered. A page over budget is reported as not fully
  scanned (the tab is untrusted); in agent mode a page the guard could not judge
  in full is quarantined.

### 4.4 Verdicts and actions

| Verdict (from `verdictFor`) | Agent mode off | Agent mode on |
|---|---|---|
| `deliver` | nothing | nothing |
| `neutralize` (hidden padding, no instruction) | badge count | strip hidden spans |
| `flag` | badge | badge, side-panel note |
| `quarantine` (hidden instruction, tag chars, hidden exfil link) | badge, optional page notice | remove the offending nodes (replace with an inert, visible marker: "LaunchSafe removed hidden text addressed to an AI agent"), mark the tab |

Badge counts and the side-panel note are not built; the verdict marks the tab
(and the log) only.

Neutralising before the agent reads is a race the extension usually wins for
agents that read the DOM or accessibility tree after `document_idle`, and can
lose against an agent that snapshots the moment the page commits. It never
affects server-side fetches. So the content guard reduces exposure; the action
gate and leak guard are what hold.

**As built (content guard).** Three refinements of the table above, each
forced by real page shapes:

- *Folded* also covers closed tab panels, menus, dialogs, tooltips and
  anything a control names in `aria-controls`: a closed "Linux" install tab
  holds `curl ... | sh`, which the scanner's hidden-only agent-directive
  entry would otherwise quarantine. Folded text is judged as visible text,
  and counts as hidden only with a Lexicon A hit.
- For a live page, `flag` outranks `neutralize` (the scanner's order suits
  mail): almost every page carries hidden UI, which would otherwise mask
  every visible instruction.
- In agent mode only quarantine-class runs are removed, plus invisible
  smuggling characters (tag characters, bidi controls, dense zero-width runs)
  stripped from text that stays. Hidden menus, modals and screen-reader text
  are never removed, so neutralising changes nothing visible on benign pages.

### 4.5 Tab trust

Each tab carries state in the service worker (`chrome.storage.session`):

- `untrusted`: the tab showed content from an origin outside the person's
  trusted set (default: every origin is outside; the trusted set is what the
  person adds), or any `flag`/`quarantine` verdict. Inherited by tabs it opens
  (`openerTabId`) and by tabs in the same agent tab group.
- `private`: the tab showed a sensitive origin (mail, bank, cloud console,
  password manager, health; a bundled list plus the person's) or a page the
  leak guard found private data on.
- **Agent session**: while agent mode is on, the union over the agent's tabs.
  This is the browser's version of the coding firewall's session: taint never
  clears within it; it ends when agent mode is turned off by a person.

`untrusted` and `private` together are Willison's trifecta minus the third leg;
the leak guard and navigation policy own that third leg (section 6, 7).

## 5. Component 2: sensitive-action gate

### 5.1 Normalized actions

The content script turns DOM activity into actions the engine judges:

| Action | Raised by |
|---|---|
| `submit { form, fields, target_origin, method }` | `submit` event, `requestSubmit`, Enter in a field, also in open shadow roots (each gets its own listener: `submit` is not composed); `form.submit()` raises no event and is not seen (a shim is not built) |
| `activate { element, label, role, context }` | `click`/`auxclick`/`keydown Enter|Space` on buttons, links, `[role=button]`, inputs of type submit |
| `upload { input, files: [{name, size, type}] }` | `change` on `input[type=file]` (including CDP `DOM.setFileInputFiles`), `drop` with files |
| `paste { target, text }` | `paste` event |
| `type { field, value }` | `input`/`change`, plus a periodic value check for values set without events (`form_input`-style setters) |
| `navigate { url, initiator }` | `webNavigation`, DNR matches |
| `download { url, filename, mime }` | `chrome.downloads.onDeterminingFilename` |

Forms are read through prototype getters, never through their own properties,
which a page's named controls can replace (`<input name="action">`); a capture
listener that throws fails closed (threat model, section 5).

### 5.2 Action classes

Classification is by **site adapters** (precise, for the top sites) and
**generic heuristics** (everything else):

| Class | Generic signals | Adapters (as built) |
|---|---|---|
| `payment` | form with `autocomplete="cc-*"` fields, payment provider frames (Stripe, Adyen, Braintree, PayPal frames and others in `PAYMENT_FRAME_HOSTS`), button labels ("Place order", "Pay", "Buy now", "Confirm purchase", localised); `PaymentRequest.show()` would need the main-world shim, which is not built | Amazon, Shopify checkout (the card exemption covers only Shopify's own checkout hosts, exactly), Stripe Checkout (PayPal has no adapter) |
| `send` | compose surfaces: a recipient field plus a body plus a "Send/Post/Reply/Publish" control | Gmail, Outlook web, Slack, LinkedIn messages, X/Reddit post forms |
| `account_security` | password change, MFA, recovery email/phone, session/device lists, API key creation, mail forwarding and filter rules | Google Account, Microsoft account, GitHub settings and repository keys/secrets, Apple ID, AWS IAM console and billing, Slack and X/Reddit/LinkedIn settings, Gmail forwarding/filters, Outlook rules |
| `oauth_consent` | known consent endpoints and their "Allow/Authorize/Accept" control | Google, Microsoft, GitHub, Slack, Atlassian, Notion OAuth pages |
| `upload` | any `upload` action | n/a |
| `download_exec` | download whose name or MIME is executable or installer (`.exe .msi .dmg .pkg .app .sh .command .bat .ps1 .reg .lnk .url .jar .apk .deb .rpm .appimage .iso` and more in `EXECUTABLE_EXTENSIONS`, Office macro and add-in formats); archives are not held | n/a |
| `delete` | destructive controls ("Delete account", "Delete repository", "Empty trash") behind a confirm step | GitHub, Google Drive, Gmail |

A generic heuristic match is approvable; an adapter match is precise. Unknown
is not risky by default here (unlike the coding firewall's unknown tool): the
web has too many buttons. The leak guard covers data leaving through
unclassified forms.

### 5.3 Rule table

| Class | Agent mode off | Agent mode on |
|---|---|---|
| `oauth_consent`, `account_security`, `download_exec` | **approve** (one click in extension UI; on by default, can be turned off per class) | approve |
| `payment`, `send`, `delete` | allow | approve |
| `upload` | allow | approve when the session is `private` or the target origin is new to the session |
| any class, on a tab with a `quarantine` verdict | approve | **deny** unless the person approves from the side panel with the reason shown |

"Approve" means: the content script cancels the event
(`preventDefault()` and `stopImmediatePropagation()` in the capture phase),
records a pending action keyed to the exact element and form state, and asks
the service worker for a decision. On approval the content script **replays
the action itself** (`requestSubmit()` on the same form after re-checking the
fields still match the approved snapshot, or `click()` on the element with a
one-shot pass token so our own listener lets it through). The approval binds
to a hash of (origin, action class, element path, field names and a digest of
values), so an approval cannot be reused for a changed form.

### 5.4 Approval surfaces

The page and the agent must not be able to produce the approval. Surfaces in
increasing strength:

| Surface | Stops | Does not stop |
|---|---|---|
| In-page overlay (closed shadow root) | page script, untrusted synthetic events | CDP input, renderer agents, OS input. **Never used as the approval**; only to explain why the button did nothing |
| Extension side panel, popup, or approval window (default) | page script; agents whose input goes to the tab (CDP via `chrome.debugger`, likely built-in agents); screenshot-based agents that only see the tab | remote-debugging CDP clients, OS-level input |
| Native dialog with biometric (Touch ID, Windows Hello) through the native host (**not built**) | everything above plus OS-level input (no finger, no approval) | a person who approves without reading |
| Phone approval through the LaunchSafe firewall's relay (**not built**) | as above | as above |

The approval UI always shows: the action class, the origin and its
registrable domain (an internationalised host in Unicode and in its `xn--`
form, with a warning when it mixes alphabets), the visible label of the
control, the destination of a form, a summary of fields (masked as section 9
says), and why the tab is untrusted (with the hidden text that was found,
escaped). It has no keyboard shortcut that a page can reach. Its Approve button
needs, after the card has been shown for 400 ms, either a fresh trusted pointer
down and up, or Tab to the button and a trusted, non-repeating Enter or Space
pressed and released on it; a button that already had focus when the card
appeared, and any script-dispatched click or key, do not approve. Approve, deny
and agent-mode messages are accepted only from the side panel and the approval
window the worker opened; our pages loaded in an ordinary tab can only read.

When agent mode is on and the agent class is detected or declared as OS-level,
the default surface escalates to biometric if the native host is present, and
otherwise the UI says plainly that approvals can be clicked by the agent.

### 5.5 Known holes in the gate

- Script-executing agents: `fetch`, XHR, `sendBeacon`, `form.submit()`,
  `location.assign` called from page-world script are not seen. A main-world
  shim wrapping `HTMLFormElement.prototype.submit`, `fetch`, `XMLHttpRequest`,
  `navigator.sendBeacon` and `PaymentRequest` is planned and is not built; even
  built, a determined script could restore the originals from a fresh iframe.
- Closed shadow roots: controls and forms inside one are not seen (open roots
  are).
- Apps whose sends are API calls not bound to a form (most SPAs). The
  activate-on-labelled-control path and site adapters cover the top sites;
  others are covered only by the leak guard's destination rules.
- Keyboard shortcuts that send (`Ctrl+Enter` in mail). Adapters list them;
  the generic path catches `keydown` with modifiers inside compose surfaces.

## 6. Component 3: data-leak guard

**Job:** stop secrets and private data moving from where the agent read them
to an origin the person did not intend, within MV3 limits.

### 6.1 What is checked

On `type`, `paste`, `submit`, and `upload` (file names only), the field value or
pasted text is checked for:

1. **Secret shapes** (`secrets.findSecrets`: cloud keys, tokens, private keys,
   connection strings), excluding test values.
2. **Personal data** (`pii.findPersonalData`: Luhn-valid cards, IBANs,
   national ids), excluding published test values.
3. **Seen-elsewhere fingerprints.** While a tab is `private`, sensitive-looking
   strings it renders (OTP-shaped codes near "code"/"verification", email
   addresses, account numbers, anything matching 1 or 2, password-reset
   links) are fingerprinted with the coding firewall's rolling hash
   (`secrets.fingerprint`, minimum 12 characters; OTPs use a short-value table
   with an exact-match hash) and kept for the agent session in
   `chrome.storage.session`. A fingerprint typed or pasted on a **different
   registrable domain** is a leak candidate. This is the browser form of the
   coding firewall's "secret flow" rule and catches the published "OTP from
   mail typed into the attacker's form" case. Strings are also matched in a
   canonical form (compatibility forms folded, case folded, "[at]"/"(at)" read
   as "@" and "[dot]"/"(dot)" as ".", zero-width characters, spaces and
   separators dropped), so "Alice.Smith [at] mail (dot) test" or a code split by
   zero-width characters still matches. A string split across fields or
   messages, reordered, paraphrased or spelled out in words is not.
4. **Decoded variants** (`secrets.decodedVariants`: base64, hex, URL encoding),
   because published attacks base64-encoded their payload.
5. **Link query values.** A click on a link whose query values (and fragment)
   carry any of the above is held like a submit, in agent mode or before the
   frame has a trusted context.

One in-page decision reads at most 64 KB (a field value, a form, a link's
query); a larger value is held and the worker decides, under per-frame budgets
for calls and characters.

**As built (re-review fixes).** The session keeps at most 2,000
prints (`MAX_SESSION_PRINTS`, the same bound the content script accepts for a
leak context): over it, the oldest long prints go first and one-time codes
last, and a print shown again moves to the newest end, so a page that shows
thousands of addresses cannot push out the code the agent just read, nor make
every later context too large to deliver. The content script decides
synchronously only from a context it trusts: before the first context, or after
the worker sent one it refused (malformed or over a bound), every non-empty
insertion or paste is cancelled and the field frozen until the worker answers
(an allow puts the value in), changes that cannot be cancelled (IME,
`execCommand`, script) and every submit also go to the worker, and the worker's
stricter verdict wins (the field is put back to its last confirmed value and
frozen until the person decides; a submit waits for the worker's answer). A local warn or log is
also re-decided by the worker and its hold takes the value back. A stale or
refused context fails toward "ask the worker", never toward "allow".

### 6.2 Decisions

| Finding | Destination | Agent mode off | Agent mode on |
|---|---|---|---|
| secret shape | any origin not on the per-secret allow list | warn in page (lets it through, logs it) | block the keystroke/paste/submit, approve to continue |
| card or national id | origin that is not a known merchant/payment frame for this checkout | warn | approve |
| seen-elsewhere fingerprint | different registrable domain | log | approve; **deny** if the tab is `untrusted` with a `quarantine` verdict |

Blocking typing is done by cancelling `beforeinput` and restoring the previous
value for values set without events. Values set by script with no event at all
are caught at `submit` (field snapshot) or not at all (if the script posts them
itself; see 5.5).

### 6.3 What it cannot do

No request body inspection in standard MV3. Data placed into a URL is handled
by the navigation policy (section 7) and, for clicked links, by item 5. Data
sent by page script with `fetch` is not seen (the main-world shim is not
built). Data the agent sends to its vendor is invisible. The guard is a strong
check on the form and keyboard path and a weak one elsewhere; the docs and UI
say which. With agent mode off it warns and lets the data through; in agent
mode it asks first.

Planned, not built: an enterprise build installed by policy could use
`webRequestBlocking` to inspect form-encoded and JSON bodies for the same
findings (a separate, policy-only build, never the Web Store version).

## 7. Component 4: navigation policy

All by `declarativeNetRequest`, so it holds for every agent that navigates the
person's browser, whatever its input path:

| Rule | Mode | Mechanism |
|---|---|---|
| Known capture and paste hosts (request bins, webhook catchers, paste sites, tunnels; `CAPTURE_HOSTS`; no URL shorteners) | always for subresources; main-frame in agent mode | static ruleset, block |
| `data:` and `javascript:` top-level navigations | agent mode | DNR cannot see `javascript:` URLs; the content script cancels clicks on such links; `data:` main-frame is already blocked by Chrome |
| Long high-entropy query values to an origin new to the agent session while the session is `private` | agent mode | DNR `regexFilter` (RE2) for a coarse match; the rule blocks, and the worker opens the explanation page and files an approval in the side panel |
| Raw IPs, DNS-exfil-shaped hosts (`isDnsExfilShape`), cloud metadata addresses | agent mode | session rules built from the engine's predicates, plus exact hosts seen in links (at most 200 per page and per frame) |
| **Agent origin set** | agent mode | engine support only; not exposed in the UI or settings, so it is never on |
| Known-bad domains | always | Safe Browsing already covers this in Chrome; we do not ship our own malware list |

DNR has rule-count limits (static rulesets and dynamic/session caps) and a 2 KB
regex limit; the high-entropy rule is coarse and backed by the content
script's link check. No rule redirects: the approval stays out of the page
because it is filed in the side panel, not on the explanation page.

**As built (navigation).** Every rule blocks; none redirects. A
blocked top-level navigation fails with `ERR_BLOCKED_BY_CLIENT`, and the
worker opens `blocked.html` in that tab with `tabs.update`, so the page needs
no `web_accessible_resources` and no page can frame any of our pages. The
explanation page shows the rule, the destination host and the length of the
data, never the data, and offers no approval (the agent drives that tab).
**As integrated:** when the engine's verdict for the blocked navigation is
approve (raw IP, DNS-exfil host, data to a new origin in a private session,
outside the origin set; never a capture host or metadata address, which are
denies), the worker also creates an approval in the gate's approval service,
bound to the tab and the exact address and shown in the side panel and
approval window with the destination origin and the data length only.
Approved there, the worker adds a one-shot session `allow` rule (that tab,
that exact address, `main_frame`, above every block rule, ids 2000-2999), reopens the
address, and drops the rule when the tab commits or after 30 s; a tab that has
left the explanation page is not reopened. DNR
compiles regexes with RE2 under a small memory budget (a 32-character counted
class is refused), so the data-in-URL rule is a run of 28 or more letters and
digits, and the DNS-exfil regex covers only the hex-label shape; the content
script reports raw-IP and DNS-exfil-shaped hosts from links, and the worker
adds exact-host rules for them. The always-on rows ship as the static ruleset
(`dist/rules.json`); the agent-mode rows are session rules kept in step with
the agent session through `chrome.storage.onChanged`.

**As built (re-review fixes).**

- *Tenant hosts.* DNR's `excludedRequestDomains` exempts a domain
  and every subdomain, and wins over `requestDomains` in the same rule. A
  session that showed `mail.google.com` knows `google.com`, but
  `docs.google.com` (Forms), `script.google.com` (Apps Script),
  `sites.google.com`, `groups.google.com`, `colab.research.google.com`, Looker
  Studio, Microsoft Forms and Sway, `answers.microsoft.com`,
  `discussions.apple.com` and `gist.github.com` are separate sites to the
  engine (`TENANT_HOSTS` in `engine/domain.ts`). The data-in-URL rule therefore
  has a second rule with `requestDomains` set to the tenant hosts under a known
  domain that the session has not itself shown, which the parent's exemption
  cannot reach. A known domain that is itself a public suffix is never an
  exemption (it would exempt every site under it).
- *The injecting site.* A domain whose page or frame got a quarantine
  verdict is recorded as an injector. While the session is quarantined it is
  not a known destination for data-carrying URLs, in the engine and in the DNR
  rule's exemption list (the threat model lists what remains).
- *The one-time pass.* The allow rule pins the exact address with a
  `urlFilter` anchored at both ends (scheme, host, port, path and query; no
  subdomains, no other address on the host; a regex would exceed DNR's regex
  memory budget for a long address). A literal `*` in the address is a
  wildcard to DNR, a residual. Its bookkeeping (which tabs show the explanation page, the
  live passes and their expiry, a per-browser-session salt) is in
  `chrome.storage.session`, so a restarted worker can still reopen the tab or
  spend the pass on commit; at start the worker removes every allow rule in
  2000-2999 that no live pass accounts for. The approval record holds the host,
  the data length and a salted digest of the address, never the address: the
  address is held in the bookkeeping until the tab leaves the explanation page
  or closes (at most 5 minutes) and is found by the digest. The worker
  approves, reopens, and only then redeems the token; if the reopen fails, the
  approval goes back to pending (not consumed), and if the tab has moved on, it
  expires. Navigation approvals expire when their tab closes or leaves the
  explanation page.

## 8. Component 5: agent detection and agent mode

Agent mode is the switch that turns on the strict column of every table. It is
a person's decision; detection only proposes or auto-enables it.

| Signal | Strength | Permission | Built |
|---|---|---|---|
| The person turns it on in the side panel | definitive | none | yes (no toolbar toggle or keyboard command) |
| `navigator.webdriver === true` | strong for automation launches | none | yes (setting on by default) |
| `chrome.debugger.getTargets()` shows a tab attached by someone else | strong for CDP-via-extension agents | `debugger` (optional; **unverified** whether `getTargets` alone triggers the infobar) | no |
| A known agent extension is installed and enabled (by catalogue) | weak (installed is not acting) | `management` (optional) | no |
| Agent tab groups (named groups an agent creates) | medium | `tabGroups` (optional) | no |
| Input shape: values appearing without key events; clicks with no preceding pointer move; perfectly centred clicks | weak, behavioural | none | no |
| Running inside a browser with a built-in agent, by user agent and browser-specific APIs | medium; it says the agent is available, not acting | none | no |

Defaults: definitive and strong signals turn agent mode on and notify the
person; weak signals show a suggestion. Turning agent mode **off** is itself a
gated action (approval in extension UI), so an agent told to "disable the
LaunchSafe agent mode" cannot do it with page input. When agent mode is off,
the always-on rows still apply (OAuth consent, security settings, executable
downloads, secrets to new origins warn).

Detection is advisory. An agent that sets no flags, uses no debugger and
drives the OS is invisible to it. That is why the always-on rows exist and why
the person can declare the agent class when starting a task ("this agent
controls my whole computer"), which escalates approvals to biometric (planned;
neither the declaration nor biometric approval is built).

### 8.1 Hard lock (not built)

For tabs the person marks "agents never act here" (bank, password manager
vault, admin console), the content script inserts a tiny
`web_accessible_resources` frame of ours. Per Chromium's frame check
Chromium's frame check, another extension's `chrome.debugger` cannot attach to a tab
with that frame. This would stop agents that drive tabs through another extension's debugger on that tab entirely,
deterministically, without telling a person from an agent. It does nothing
against remote CDP, built-in agents or OS input, may stop if Chromium changes
the check, and breaks legitimate debugger extensions on that tab. Opt-in per
site, labelled, behind a flag until the spike proves it.

## 9. Component 6: log and approvals

- **Log.** Every decision is appended to an IndexedDB log: time, tab origin
  (registrable domain only by default), action class, verdict, rule ids,
  approval outcome, the hash binding (salted with the agent session's random
  salt, so a binding for a held 6-digit code cannot be matched against the
  million candidates). No page text, no field values; a page whose
  content is quarantined is logged (`event: "quarantine"`, its reason codes),
  and the start of its hidden text is stored only as its first 200 escaped
  characters, and only when the person turns on "keep evidence". Deleting
  the log leaves one `log_cleared` entry that starts the new chain. The log
  keeps at most 20,000 entries (oldest out first, the chain's anchor moving
  with them) and is read by cursor with a limit; each frame's log rows are
  budgeted, and rows over the budget are counted in one `log_throttled` row. Entries are
  hash-chained (SHA-256 via WebCrypto). The extension cannot keep a signing key
  secret from someone who controls the profile, so it does not claim signed
  logs; with the native link on, entries are also appended to the local
  firewall's signed log (Ed25519, `log verify`), section 10.
- **Approvals queue.** Pending actions expire after 5 minutes or on navigation.
  Approve, Deny, and "Approve for this site for this agent session" (per class;
  never for `oauth_consent` or `account_security`). The grant covers exactly the
  site the card names, the frame's own registrable domain, never a page-named
  form target (the card says so when the target differs, and the engine
  still judges that target, so it keeps asking), and it is saved only after the
  approval is confirmed. The queue is bounded: an identical
  pending request is coalesced into the existing one; a tab holds at most 50
  pending approvals and the queue 200; over a bound the oldest pending approval
  of the busiest tab is retired and its frame told, so a flooding tab pushes
  out only its own requests and the newest request stays visible. What the
  card shows of a field value (`maskField`): a password field, or one marked
  `current-password`, `new-password` or `one-time-code`, fully masked; a card
  security code fully masked; a card number as its last four digits; a value
  that looks like a secret hidden; a card, IBAN or national id found in a
  value as its last four digits; any other value as its first three
  characters and its length (a value of five characters or fewer as dots and
  its length). A leak hold's findings show the first four and last two
  characters (eight or fewer: dots only). So an ordinary field's first three
  characters, and a finding's first four and last two, are stored with the
  pending approval.
- **Retention.** 30 days by default, person-configurable, one-click export and
  delete. The log reads the stored period inside every purge, so a purge at
  worker start uses the person's period, not the default.

## 10. Link to the local firewall (native messaging)

Optional host `com.launchsafe.agent_firewall`, installed by the local
firewall's installer (`launchsafe-firewall install --browser chrome|chromium|edge|brave
--extension-id ID`, into that browser's per-user `NativeMessagingHosts`
directory only), allowed for our extension id only (`allowed_origins`).
Built without biometrics: `src/worker/link.ts` (connection,
mirroring, taint, approvals) and `src/worker/link-protocol.ts` (the schema);
the firewall side is its `src/runtime/native/` (its docs/browser-link.md).

The person turns the link on in the side panel ("Link to the local firewall"),
which first requests the optional `nativeMessaging` permission (section 11);
turning it off gives the permission back, and is refused while agent mode is
on (it weakens protection). With no host installed, a host that exits, or a
message either side does not accept, the link drops, the side panel's status
line says why, and the extension decides exactly as without it. Messages
(JSON, length-prefixed, 64 KB at most, each with a nonce; both sides reject
unknown types and fields):

| Message | Direction | Use |
|---|---|---|
| `hello { version, capabilities }` | both | version check; the extension lists what it enforces |
| `log.append { entry }` | ext → host | the signed log |
| `approval.request { action, binding, surface }` | ext → host | human-only approval through the firewall's queue, biometric prompt, or phone relay |
| `approval.result { binding, verdict, sig }` | host → ext | the extension accepts it only if the binding matches the pending action |
| `state.taint { session, reason }` | both | share taint: a coding session that drives the browser, and a browser session that hands content back |
| `approval.cancel { binding }` | ext → host | decided in the extension first: the firewall's queue item is closed |
| `log.ack`, `approval.queued`, `ack`, `error` | host → ext | replies; an `error` for one message is shown, not fatal |

As built:

- **Log.** Every entry is sent as it is appended; entries made while the link
  was down are sent on the next connection, after the last one the firewall
  acknowledged (at most 500). The firewall appends each as a
  `browser_decision` with our sequence number and hash, so `log verify` covers
  them. The evidence snippet (page text, opt-in) never leaves the browser, and
  a field the host's schema would refuse is dropped before sending. Bindings
  go as the log keeps them (salted per agent session). Deleting the log sends
  its "log deleted" marker, and acknowledgements count again from the new
  chain.
- **Taint.** When the agent session becomes untrusted from what this browser
  saw, its first reason is sent once per session. The firewall taints every
  coding-agent session linked to the browser (one that called a
  browser-driving MCP tool in the last 12 hours). A linked coding-agent session
  the firewall reports as untrusted makes the agent session untrusted
  (`linkedAgentTainted`); with agent mode off it is held and the next agent
  session starts untrusted. Taint from the host only ever adds; it is never
  echoed back.
- **Approvals.** Only when the firewall's hello offers `approval` (it has an
  approval passphrase). Each pending approval is filed with its fingerprint
  salted with a random value held only by this worker as the binding (never
  the unsalted fingerprint, which for a held one-time code could be matched
  against every candidate), its label (control characters removed) and site,
  never a field value or a blocked navigation's address; the person
  can approve in the firewall's queue (passphrase) or in our UI, whichever
  comes first. A result is honoured only for a binding this connection filed
  and only while that approval is still pending; it then runs exactly as an
  approval in our UI. The queue's bounds apply first: a repeated request is
  coalesced into the item already filed, and an approval retired to keep the
  queue bounded is cancelled on the firewall too. `surface` is `firewall`; the biometric surface is later
  work.

**Claude Code + Claude in Chrome.** When the agent is Claude Code driving the
browser, the strongest enforcement point is the coding firewall's own hook: the
`mcp__claude-in-chrome__*` tool calls arrive at `PreToolUse` with full
arguments (`navigate` URLs, `form_input` values, `javascript_tool` source,
`file_upload` paths). We recommend, as separate work in the firewall repo,
catalogueing those tools: page reads (`get_page_text`, `read_page`, `find`)
as `read_external` with taint, `navigate` as egress with the URL as payload,
`form_input` and `computer` typing as sends with payload, `javascript_tool` as
code execution in an untrusted context, `file_upload` as a read of the path
plus a send. The extension then covers the browser side (what the page does,
what lands in the DOM), and the two share taint over the native link.

## 11. Permissions

Install-time (as built):

| Permission | Why | Warning shown |
|---|---|---|
| host permissions `<all_urls>` with content scripts | the content guard and gate must run on every page and frame; there is no narrower way to guard arbitrary pages | "Read and change all your data on all websites" |
| `storage` | settings and link state (`storage.local`), tab state and approvals (`storage.session`); the log is in IndexedDB, which needs no permission | none |
| `declarativeNetRequest` | navigation policy | "Block content on any page" |
| `downloads` | executable download gate | "Manage your downloads" |
| `sidePanel` | approvals and status | none |
| `webNavigation` | `onErrorOccurred` detects our own blocked navigation (`ERR_BLOCKED_BY_CLIENT`) so the tab can be taken to the explanation page and offered "open it once"; `onCommitted` expires pending approvals and clears per-document quarantine; `onCreatedNavigationTarget` records the opener of a new tab | "Read your browsing history" |

`webNavigation` was reviewed for removal and kept.
Host permissions already give the content script the page URL, and
`chrome.tabs.onCreated` (`openerTabId`) and `tabs.onUpdated` need no extra
permission, so opener tracking and commit detection alone would not justify it.
The blocked-navigation page does: a declarativeNetRequest `block` surfaces to an
extension only as a failed navigation (`webNavigation.onErrorOccurred`, error
`ERR_BLOCKED_BY_CLIENT`), and the alternative, a DNR `redirect` to an extension
page, would need that page in `web_accessible_resources`, which this design
avoids. Dropping `webNavigation` would remove the
explanation page and the approve-once path for blocked navigations. The
justification is in `store/permissions-justification.md`; revisit if Chrome
offers an error signal without it.

Optional, requested at the moment of use with an explanation:
`debugger` (agent detection only; never attaches), `management` (detect agent
extensions), `tabGroups` (agent tab groups), `nativeMessaging` (firewall link).
Built so far: `nativeMessaging`, in the manifest's `optional_permissions`
(`OPTIONAL_PERMISSIONS` in `src/manifest.ts`; `manifest.test.ts` pins it),
requested from the side panel's link switch only. The warning shown is
"Communicate with cooperating native applications". The others are added with
their features.
Not requested: `tabs` (host permissions already give URLs), `webRequest`,
`cookies`, `history`, `clipboardRead`, `scripting` (static content scripts are
enough), remote code of any kind.

## 12. Privacy

- The extension makes no requests of its own; the only requests it causes are
  ones the person approves: re-downloading a held file and reopening a held
  address. No analytics, no crash reporting, no remote lists. Rule and adapter updates ship
  as extension updates. A build test (`scripts/build.test.ts`) fails if a built
  file contains `eval`, `new Function`, `fetch`, `XMLHttpRequest`, `WebSocket`,
  `EventSource` or `navigator.sendBeacon`, or an HTML page loads a remote or
  inline script; its allowlist is empty.
- Page content is processed in memory in the content script. Nothing of it
  leaves the device. The only page text ever stored is the opt-in evidence
  snippet below.

Everything the extension stores, by place. Nothing is synced or sent.

| Where | What | Lifetime |
|---|---|---|
| Memory (content script) | Page text, field values, pasted text, file names, as needed to decide; a held value while it waits for approval | The page, or until decided |
| `chrome.storage.session` | **Per-tab state**: whether the tab showed outside content or a private site, the reasons, whether a quarantine verdict applies, which tab opened it, whether it is in the agent session | Browser session (cleared on browser close) |
| `chrome.storage.session` | **Agent session**: when it started, the declared agent class, registrable domains the session's tabs showed, per-site approvals for this session | Until agent mode ends |
| `chrome.storage.session` | **Fingerprints of private strings** shown on sensitive sites (one-way hashes of emails, secrets, card and account numbers, reset links, one-time codes), at most 2,000 per session. Short one-time codes are hashed with a random per-session salt (kept beside them) so a 6-digit code cannot be guessed back from the hash. The strings themselves are never kept | Until agent mode ends |
| `chrome.storage.session` | **Approval records**: a pending approval's one-way digest of the form it covers (names, a hash of the values, the target origin), the tab and frame it is bound to, an expiry, and what the card shows: the full page URL the action came from, the control's label, a download's URL and file name, and field values masked as section 9 says (an ordinary value's first three characters and length; a leak finding's first four and last two characters). A blocked navigation's record: host, data length, salted digest of the address | 5 minutes, or until decided or the page navigates |
| `chrome.storage.session` | **Navigation pass bookkeeping**: tabs showing the explanation page with the blocked address (for an approvable block, so it can be reopened once), live one-time passes, the digest salt | Until the tab moves on or closes (address at most 5 minutes); passes 30 s |
| `chrome.storage.session` | Hosts the page scripts named as raw-IP or exfiltration-shaped, for the navigation policy | Browser session |
| `chrome.storage.local` (closed to content scripts where the browser supports it) | **Settings** and the native link's on/off state: agent mode preferences (webdriver detection), **trusted-site and sensitive-site lists** the person edits in the side panel (at most 200 each; a trusted entry cannot be a public suffix; in agent mode adding a trusted site or removing a sensitive one is refused), always-on classes, evidence and retention choices | Until changed, or uninstall |
| IndexedDB (log) | **Decision log**: time, the site's registrable domain, action class, verdict, rule ids, outcome, hash chain. Never page text, field values or full URLs | 30 days by default, person-configurable |
| IndexedDB (log) | **Optional evidence snippet**, only when the person turns on "keep evidence": the first 200 characters of hidden text that got a page quarantined, control characters escaped. This is page text | Same as the log |

- Domains in the log are a record of sites where something was held or blocked;
  the person can export it and delete it from the side panel (one click each,
  delete refused while agent mode is on), and retention prunes it.
- The native link (optional, off by default) sends only what the log, taint
  and approvals need, to the LaunchSafe firewall on the same machine: log
  entries without the evidence snippet, a taint reason code, and an approval's
  binding, label and site. The label is at most 200 characters and can come
  from the page (a button's text, for example). Never page body text, field
  values or full URLs.
- Policy and the trusted-origin list live in `chrome.storage.local`, not sync,
  by default.

## 13. Chrome Web Store considerations

- **Single purpose:** "protect people from AI browser agents being hijacked by
  web pages." Every feature serves it.
- **Broad host access** gets in-depth review; the listing and the privacy
  practices form must explain why each page is scanned and that nothing leaves
  the device. Expect longer reviews.
- **No remote code**. The engine and lexicons are bundled.
- **`debugger` stays optional** and is never used to attach, which keeps the
  default install off the most scrutinised permission and avoids the
  "debugging this browser" infobar.
- **Interference with other extensions.** The hard lock deliberately stops
  other extensions' debugger sessions on chosen tabs. It is opt-in, per site,
  disclosed in the listing, and can be dropped from the store build if review
  objects.
- **Limited Use** of user data: none is transferred; the disclosure says so.

## 14. Other browsers

| Browser | Feasibility | Notes |
|---|---|---|
| Edge | same build | Web Store or Edge Add-ons; Copilot Mode behaviour unverified |
| Brave, Vivaldi, Opera, Arc, Comet, Neon | same build via the Chrome Web Store | agent behaviour per browser in the compatibility matrix |
| Atlas | same build, minus chatgpt.com | content scripts in agent-mode tabs unverified |
| Firefox | feasible (MV3 with `browser.*`) and **stronger** on data leaks: Firefox keeps blocking `webRequest` with request bodies for all extensions | no `chrome.debugger`, no side panel (use sidebar), DNR available; few browser agents target Firefox today (its AI Window is new); v0.3 |
| Safari | feasible as a Safari Web Extension in an app wrapper (Xcode, App Store) | DNR-style content blockers, no debugger API, few agents; not planned |

## 15. Testing strategy (summary)

Engine units in Vitest under Node; the extension end to end with Playwright's bundled Chromium in a
persistent context with a fresh temporary profile; a local corpus of malicious
and benign pages served from 127.0.0.1 only; agent simulators for each input
class (untrusted script events, CDP input through Playwright, a test extension
that drives tabs with `chrome.debugger`, value setters, `DOM.setFileInputFiles`,
`Runtime.evaluate` fetch as a documented bypass); a friction corpus of saved
real pages to measure false positives. Tests never touch the person's real
browser profile or home directory, and never hit the network beyond loopback.

## 16. Open questions for the spike

1. Does `chrome.debugger.getTargets()` without `attach` show any infobar or
   warning beyond the install-time permission?
2. Does an extension frame inserted after another extension attached detach
   it, or only block new attaches? Does it hold for Comet's component agent?
3. Do content scripts run in Atlas agent-mode tabs, and can Atlas, Gemini in
   Chrome and Edge Copilot agents act on extension pages or the side panel?
4. Does `checkVisibility()` plus contrast agree with `analyzeHtml` on the
   email-guard corpus rendered as pages?
5. How often do generic `payment`/`send` heuristics fire on the friction
   corpus, and at what threshold does agent-mode friction stay tolerable?
