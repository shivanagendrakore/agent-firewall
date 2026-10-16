# Store submission notes (internal, not for pasting)

The four files in this folder (`listing.md`, `permissions-justification.md`,
`data-usage-disclosures.md`, `privacy-policy.md`) are paste-ready. This file
holds what must not be pasted.

## Owner to-dos before submitting

- Host `privacy-policy.md` at a public URL and set its effective date (the
  policy still says "set at publication").
- Real homepage URL and privacy policy URL for the dashboard (none exist yet;
  do not invent them).
- Screenshots at 1280x800 and a 440x280 promo tile.
- The listing has not been submitted to the Chrome Web Store yet.
- Re-check the Privacy practices form's checkbox wording at submission; the
  category names in `data-usage-disclosures.md` are the ones the dashboard has
  used.
- Category: Productivity > Tools is the closest fit; if "Privacy and security"
  is offered at submission, prefer that.

## Keeping the text true

- Listing text must stay true to `docs/design.md` and `docs/threat-model.md`;
  the store treats a listing that overstates function as deceptive metadata
  (<https://developer.chrome.com/docs/webstore/program-policies/policies>).
- A manifest test pins the name and the summary (which is also the manifest
  `DESCRIPTION` in `src/manifest.ts`). The summary is 121 characters (limit
  132). "In agent mode" is in it on purpose: purchases, sends and most leaks are
  held only while agent mode is on.
- Consistency rule: the policy, the data-usage answers and the permission
  justifications are reviewed together. If code adds a network call, a storage
  field or a permission, update all three before the build is uploaded.
- Answers say Yes broadly (including Health, because a health-record site is on
  the sensitive-sites list): under-disclosing is the riskier mistake and a
  common cause of removal.
- The policy page carries the Limited Use sentence (see "Chrome Web Store User
  Data Policy" in `privacy-policy.md`); keep it. Rules:
  <https://developer.chrome.com/docs/webstore/program-policies/limited-use>;
  data FAQ:
  <https://developer.chrome.com/docs/webstore/program-policies/user-data-faq>;
  permission justifications:
  <https://developer.chrome.com/docs/webstore/cws-dashboard-privacy>.
- Roadmap wording stays out of the paste-ready files. The policy lists
  "Available" and "Not available" features; a phone approval relay is not
  available and would need a new policy version and store disclosure first.

## Words to avoid in the listing and UI

"100% protection", "prevents all prompt injection", "makes agents safe",
"unhackable", "AI-powered detection" (it is deterministic and calls no model),
"protects ChatGPT agent / Operator" (cloud agents are out of reach), any
competitor or Google or OpenAI or Anthropic trademark used as if endorsed.
Name agents only factually and only where the threat model has verified them.

## Why `webNavigation` was kept
Reviewed against least privilege: host permissions already
give the content script the page URL, and `tabs.onCreated` (`openerTabId`) and
`tabs.onUpdated` work without it, so commit and opener tracking alone would not
justify the permission. The blocked-navigation explanation does: without it
the extension would not learn that one of its own rules stopped a navigation.
Code:
`src/worker/guard-nav.ts` (`onErrorOccurred`, `onCommitted`) and
`src/worker/index.ts` (`onCommitted`, `onCreatedNavigationTarget`).

## Items to resolve before pasting

- **`webNavigation` shows the "Read your browsing history" warning.** Reviewed
  and kept (see its section). If Chrome later gives an error signal for a
  blocked navigation without it, drop the permission.
- **`downloads` warning** reads "Manage your downloads"; the build cancels held
  downloads and starts an approved one again (`downloads.download`); it never
  opens or reads files.
- The hard lock (design 8.1) needs a web-accessible frame and is not built; do
  not add it without updating this file.
