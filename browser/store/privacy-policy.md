# Privacy policy: LaunchSafe Agent Firewall for browsers

To be hosted at a public URL before the extension is submitted (the Web Store
needs a link, not a file).
Effective date: set at publication. Version: matches extension 0.0.1.

## The short version

- The extension works entirely on your device. It makes **no requests of its
  own**; the only requests it causes are ones you approve: re-downloading a
  held file and reopening a held address. There is no account, no analytics, no
  crash reporting and no remote list or code download.
- We (LaunchSafe) receive **nothing**: no page content, no browsing history, no
  usage data, no identifiers.
- It keeps a local activity log on your device for 30 days by default. You can
  export it or delete it at any time.
- We do not sell, share or transfer user data, because we do not have it.

## Who we are

LaunchSafe publishes this extension. Contact: security@launchsafe.com.

## What the extension handles, and why

The extension's one job is to stop an AI agent that is acting in your browser,
and that a web page has tried to hijack, from doing harm without your approval.
To do that it has to look at the pages you visit. All of this happens inside
your browser.

| What | How it is used | Where it lives | How long |
|---|---|---|---|
| Page content (visible and hidden text, attributes, the address's query and fragment) | Scanned in memory in the page for hidden instructions addressed to an AI agent. Not stored, not sent. | Memory only | Until the page is closed or rescanned |
| Form and keyboard activity (field values, pasted text, file names chosen for upload, controls the agent or you click) | Checked for secrets, card and ID numbers and data moving to a different site, and to hold a purchase, send, consent or similar action for your approval. Values are never written to the log; what a pending approval keeps of them is in the next row. | Memory only | Until you decide, or the page navigates |
| Approval records. For a held action: the full address of the page it came from, the control's visible label, the first 20 field names (each cut to 64 characters), a one-way hash of the values, the address the form goes to, which tab and frame it came from, and a masked preview of each field: a password field (or one marked as a current or new password or a one-time code) and a card security code fully masked; a card number as its last four digits; a value that looks like a secret hidden; a card, IBAN or ID number found in a value as its last four digits; **any other value as its first three characters and its length**. For held private data: what was found, as its first four and last two characters (eight characters or fewer: dots only). For a held download: its full download address and file name. For a blocked navigation: the destination host, how many characters of data the address carried and a salted one-way hash of the address | Bind your approval to exactly what was held, so it cannot be reused for a changed form, and show you what is waiting. | `chrome.storage.session` (memory only, readable only by the extension's own pages) | 5 minutes, or until you decide or the page navigates |
| The address of a blocked navigation you can approve | Held so the tab can be reopened once, exactly there, if you approve. It is never part of the approval record or the log, and is found by its salted hash. | `chrome.storage.session` (memory only, readable only by the extension's own pages) | Until the tab leaves the explanation page or closes, at most 5 minutes |
| Fingerprints of private strings (one-way hashes of things like one-time codes, email addresses and account numbers shown on sensitive sites; at most 2,000 per agent session, oldest first out). Short codes are hashed with a random per-session salt, kept only in session memory, so a code cannot be guessed back from its hash | Notice when such a string is typed or pasted on a different website. The originals are not kept. | `chrome.storage.session` (cleared when the browser closes) | Dropped when the agent session ends |
| Per-tab and agent-session state (whether a tab showed outside content or a sensitive site, the reasons, which tab opened which, whether agent mode is on, the sites an agent session has shown, and the per-site approvals you gave for it) | Decides how strict the checks are | `chrome.storage.session` | Browser session; the agent-session part until agent mode ends |
| Addresses of hosts a page named that look like raw IPs or data-carrying names | Lets the navigation policy block them | `chrome.storage.session` | Browser session |
| Your settings (policy, agent mode choices, the lists of sites you trust or mark sensitive, always-on classes, "keep evidence" and retention) and whether the link to the local firewall is on | Remembers your choices | `chrome.storage.local` on this device (not synced) | Until you change or remove them, or uninstall |
| Activity log (time, the site's registrable domain such as `example.com`, the kind of action, the verdict, the rule, your approval or denial, a binding hash salted per agent session so a held value cannot be guessed back from it, pages where hidden instructions were found, and when the log was deleted). The domains make it a small record of sites where something was held or blocked. | Lets you review what was held or blocked. Entries are hash-chained so edits are detectable by you. | IndexedDB on this device | 30 days by default and at most 20,000 entries (the oldest go first); you can change the period, and the period you set applies from the moment the extension starts |
| Optional evidence (only if you turn on "keep evidence"): the first 200 characters of hidden text that made a page's content quarantined, with control characters shown escaped | Shows you why a page was flagged | IndexedDB on this device | Same as the log |
| Downloads (address, file name and type, as the browser reports it) | Holds executable and installer downloads for your approval; an approved one is downloaded again from the same address | The pending approval keeps the address and file name (row above); the log keeps the site's domain and the verdict | Approval: up to 5 minutes; log: per the log |

The log never contains page text, field values or full URLs, except the opt-in
evidence above (which is page text). Hidden text on a hostile page can be anything; we show it to
you escaped and labelled as page content.

## Why the extension asks to read all websites

Hidden instructions and risky buttons can be on any site, so the scanner and the
approval gate must run on every page and frame (including payment frames). There
is no narrower way to guard arbitrary pages. The access is used only for the
checks above and nothing it reads is sent anywhere.

## What the extension never does

- It never sends data to LaunchSafe or anyone else. The only requests it causes
  are ones you approve (re-downloading a held file from the site it came from,
  reopening a held address). It does not use a remote
  server, a model, an API, a telemetry service or a remote rules feed. Rule and
  detection updates arrive only as extension updates from the Chrome Web Store.
- It does not load or run remote code.
- It does not sell data, use data for advertising, build profiles, or use data
  for anything except providing its single purpose. No human at LaunchSafe can
  see your data, because it is not collected.
- It does not read cookies, passwords stored in your browser, or your browsing
  history list. (It uses the navigation events of pages you open to apply its
  checks, and the log records the domain of a held action, so the log is
  itself a small record of sites where something was held.)

## Your controls

- **Export** the log from the extension's side panel (one click on Export, a
  JSON file saved by you to a place you choose).
- **Delete** the log from the same place (Delete log, then a confirmation).
  Delete is refused while agent mode is on, so an agent cannot erase the record
  of what it did. A deleted log keeps one entry saying when it was deleted.
  Uninstalling the extension removes all of its stored data.
- **Retention** is 30 days by default; you can shorten or lengthen it (1 to
  365 days). Shortening it is refused while agent mode is on.
- **Trusted and sensitive sites** are lists you can edit or clear in the side
  panel's settings. While agent mode is on, adding a trusted site or removing a
  sensitive one is refused.
- **Keep evidence** is off by default; with it on, the log keeps the start of
  the hidden text that got a page quarantined.
- Agent mode, and every approval, are yours to turn on or off. Agent mode also
  switches on by itself when the browser reports it is under automation; a
  setting turns that off.
- When the extension stops a navigation, the explanation page's address carries
  only the rule name, the blocked host and how many characters of data the
  address carried (never the path or query), and it appears in that tab's
  history.

## Optional features

Each is off until you turn it on.

- Available: a link to the LaunchSafe command-line firewall on the same computer
  (Chrome's native messaging, macOS and Linux only), off until you turn it on
  in the side panel, which is when the browser asks for the "communicate with
  cooperating native applications" permission. With it on, the extension
  passes its log entries (domain, action class, verdict, rule ids, event codes, a
  salted hash; up to 500 earlier entries on connect), whether its agent session
  read outside content (a taint flag), and actions waiting for your approval
  to that program on your own machine, never to the internet. The firewall can
  send back an approve or deny for a pending approval. An action waiting
  for approval is passed with the site's domain and a label of at most 200
  characters, which can come from the page (for example a button's text); for an
  upload, the label includes the chosen file names. Page
  body text, field values, full addresses and the optional evidence snippet are
  never passed.
- Not available: a phone approval relay. That would be the first feature that
  sends anything off your device, and it will not ship without a new policy
  version and a new store disclosure.

## Chrome Web Store User Data Policy

The use of information received from Chrome APIs and page content will adhere to
the Chrome Web Store User Data Policy, including the Limited Use requirements.

## Children

The extension is not directed at children and collects nothing from anyone.

## Changes

A change that affects what is handled or where it goes will be published here
with a new version and date, and, if it adds data handling, shown in the store
listing before the update ships.

## Contact

security@launchsafe.com
