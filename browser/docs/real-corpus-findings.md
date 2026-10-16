# Real-page friction corpus: results and findings

Corpus: 163 static snapshots of public pages (not in the repository, because they are other people's copyrighted pages; rebuild them with `npm run capture:corpus` into `LAUNCHSAFE_BROWSER_CORPUS_DIR`, default `~/.launchsafe/browser-corpus/real`; manifest in `manifest.json`), captured
2026-10-11 by `scripts/capture-corpus.mjs` (`npm run capture:corpus`). The tests run offline from 127.0.0.1 and
execute no script from the pages; 0 requests left the machine. Run with
`node scripts/e2e.mjs test/e2e/friction-real.spec.ts` (about 5.5 minutes).

Coverage: docs 27, GitHub 8, forums 8, blogs 9, news 6, Wikipedia 10, government 13, recipes 10, SaaS pricing 14,
shops 12 (one public cart page), security writing 6, UI patterns (accordions, tabs, modals, menus,
cookie-banner vendors) 13, and other scripts: Arabic 5, Hebrew 3, Chinese 5, Japanese 4, Hindi 4, other 6
(Korean, Russian, Persian, Thai, German, Urdu). 38 URLs were skipped and are listed with the reason in the
manifest: robots.txt disallowed (Reuters, NPR, Reddit, Gymshark and IKEA carts, eBay, Target, Best Buy, Magento
demo), HTTP 403 to an automated client (Stack Overflow and Stack Exchange, OpenCart and nopCommerce demos, Etsy,
eBay), a bot wall, or too large to trim. Nothing tries to get round a refusal, so there are no Stack Overflow
pages and only one public cart page (automationteststore.com).

## Rates (agent mode off at load, then turned on)

After the fixes for FP-1 to FP-5 (below). The figures before them are kept for comparison.

| Measure | Before | Now (160 pages gated, 3 by-design excluded) | Gate |
|---|---|---|---|
| Quarantine verdicts | 7 of 163 (4.3%) | 0 | 0 |
| Flag verdicts | 9 of 163 (5.5%) | 0 | under 2% |
| Pages whose visible text changed in agent mode | 6 | 0 | 0 |
| Pages with a removal marker in agent mode | 6 | 0 | 0 |
| Pages whose viewport changed in agent mode (over 0.05% of pixels) | 1 (Rust `Vec` docs, 16.6%) | 0 (largest change 0.008%) | 0 |
| Pages that animate on their own (excluded from the pixel measure) | 4 (carousels) | 4 | n/a |
| Requests that left 127.0.0.1 | 0 | 0 | 0 |
| Private tabs, loaded with agent mode on (all 163) | 31 (19%) | 19 (11.7%) | n/a |
| Private tabs, agent mode off (all 163; e-mail addresses, by design) | 19 | 19 | n/a |

The three by-design pages, measured but left out of the raw gate by name: Simon Willison's article, quarantine
(no marker, no visible change: the removed text is alt text); OWASP LLM01, flag; Wikipedia "Prompt injection",
flag. Over all 163 pages that is 1 quarantine and 2 flags, all three on those articles. Loaded with agent mode
already on: the same verdicts and no marker page.

The raw gate ("0 quarantines, flags under 2%, agent mode changes nothing a person sees") was `test.fail()` and is
now a normal test. It leaves out exactly the three articles about prompt injection (`BY_DESIGN_EXCLUDED` in
`test/e2e/friction-real.spec.ts`, by name, with the reason): they genuinely contain injection text. The
"explained" test stays as the regression gate over all 163 pages: every non-clean page must be in
`known-findings.json` in that directory (now only those three, kind `by-design`, with their verdicts), an entry
that goes clean or changes verdict fails, and nothing new may appear. Clean: every page in Arabic, Hebrew,
Chinese, Japanese, Hindi, Korean, Russian, Persian, Thai, German and Urdu, and every docs, GitHub, news, recipe,
SaaS, government and shop page.

## Findings and fixes

Each false positive is reproduced under `test/corpus/fp-cases/`; the reproductions were `it.fails` /
`test.fail()` and are now ordinary tests, each with controls that a real attack of the same shape is still caught.

- **FP-1, 7 flags (every signed-out GitHub page, 7 of 8). Fixed.** The header "Sign up" link carries
  `ref_page=%2F%3Cuser-name%3E%2F%3Crepo-name%3E`, which the `exfil_link` template rule read as a slot for a model
  to fill. `links.test.ts`.
- **FP-2, 1 quarantine with 34 visible markers and a 16.6% pixel change (rustdoc, every page with an example).
  Fixed.** The hover-only "Run" button links to play.rust-lang.org with the code URL-encoded; the `{ }` of Rust,
  JS, CSS and JSON code read as slots, and the link, hidden until hover, became a `hidden_exfil_link` replaced by a
  marker in agent mode. `links.test.ts`.
- **FP-3, MDN's "Report a problem" footer link. Fixed.** A pre-filled GitHub issue whose `metadata` is an encoded
  `<details>` block. `links.test.ts`.
- **FP-1 to FP-3, the fix** (`src/engine/guard-scan.ts`, `exfilWhy`): a slot (`{x}`, `{{x}}`, `${x}`, `<x>`, or
  their encodings, matched on the decoded URL) counts only when it is the whole of a query or fragment value (or a
  whole line of one: `?d={user_email}`), a whole path segment or host label that names a secret
  (`/{api_key}/p.gif`), a private-data name in a short one-line query value (`?ref=/u/<user-email>`), or a
  private-data name anywhere in a hidden link to another registrable domain (the guard now passes the page's host).
  HTML tag names (`<details>`, `<summary>`) and type parameters (`Vec<T>`) are not slots, and REST placeholders in
  a path (`/orders/{order_id}`) are not secrets. Capture hosts and the hidden-image entropy rule are unchanged. The
  attack corpus (`hidden-exfil-image.html`, `hidden-exfil-link.html`) gets the same verdicts.
- **FP-4, 5 quarantines (4 MDN reference pages and MDN's `<dialog>` page; 28 of the 163 snapshots use
  `display: contents`). Fixed.** `checkVisibility()` is false for an element with no box, so everything inside a
  `display: contents` wrapper counted as hidden. The fix (`ownRendered` in `src/engine/visibility.ts`, used by
  `src/content/guard.ts`) treats such an element as transparent: only its own `visibility` (inherited by its
  children) hides it, `opacity`, `clip` and `clip-path` are ignored because the browser ignores them on a box-less
  element, and each child is judged on its own box. `fp-cases.spec.ts` with `display-contents.html`, and the
  control `display-contents-hidden.html` (a `display: none` instruction inside the wrapper and a wrapper hidden by
  `visibility` still quarantine and are removed).
- **FP-5, lower severity. Fixed.** In an agent session a 4 to 8 digit number near "code", "pin", "verify" or
  "confirm" was fingerprinted as a one-time code, so a year next to "source code" (or "Google Summer of Code 2026")
  turned the tab private. Now (`src/engine/private-data.ts`) a code needs an OTP phrase nearby (verification,
  one-time, passcode, sign-in code, "your code", "code is", 2FA and similar) or "code", "PIN" or "passcode" right
  before it; a plausible year counts only after "code is" or "code:"; numbers inside dates, decimals, prices,
  percentages and thousands groups never count. Private tabs loaded in agent mode went from 31 to 19, the same 19
  pages (e-mail addresses) as with agent mode off. `otp-years.test.ts`.

By design (3 pages, `known-findings.json` kind `by-design`): Simon Willison's prompt-injection article
(quarantine: the alt text of two tweet screenshots transcribes working injections, and alt text is read as hidden
text), OWASP LLM01 and Wikipedia "Prompt injection" (flag: visible quoted "ignore the above directions" text,
which strips nothing). The guard is not loosened for them: the raw gate leaves them out by name instead. If the
product decides pages about prompt injection must not be flagged, that is a product decision, not a bug.

## Method notes

- Verdicts come from the extension's own tab state, not a reimplementation. The reduction to a cause used the real
  guard compiled with its judgement functions wrapped to record their inputs (throwaway, not committed).
- Snapshots are rendered once with scripts on, then stored with scripts, iframes, media, `<link>`, `@font-face` and
  every non-data `url()` removed and images replaced by a 1x1 gif, so layout is close to the live page but not
  identical (fonts and images are missing). The snapshots (kept outside the repository; the counts here are from the capture dated 2026-10-11) were captured before
  `scripts/capture-corpus.mjs` kept image sizes, so an image without width and height attributes (Simon
  Willison's screenshots among them) renders at 1x1. The script now loads images while capturing (read-only
  GETs, robots.txt checked, bytes not kept) and writes each image's rendered or natural size onto the placeholder
  as width and height; the next `npm run capture:corpus` picks that up. The Simon Willison snapshot was not
  re-captured or patched: the tests may not reach the network, and the real sizes are not in the snapshot, so a
  patch would invent them. It does not change a verdict: alt text is read as hidden whatever the image's size. `<noscript>` and `<template>` content is kept, cleaned.
- E-mail addresses and phone numbers are scrubbed (the replacement address still counts as an e-mail to the leak
  guard, like the original). No page needed an account; hidden-input values are blanked.
- Pixel difference is measured on the first viewport (1100x900) with a per-channel tolerance of 8; a page that
  differs from itself 250 ms apart before agent mode is treated as animated and left out.
