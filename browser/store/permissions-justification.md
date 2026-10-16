# Permission justifications (Web Store dashboard, Privacy practices tab)

Paste the quoted text into the dashboard's matching fields.

## Single purpose statement

> LaunchSafe Agent Firewall has one purpose: to protect people from AI browser
> agents being hijacked by web pages. It scans pages for hidden instructions
> aimed at an AI agent, and holds sensitive actions until the person approves
> them in the extension's own panel: in agent mode, which the person turns on,
> purchases, sends, deletions, uploads to a new site or from a session that has
> seen private data, and data moving to a new site; with agent mode off, OAuth
> consent, account-security changes and executable downloads. Agent mode also
> switches on by itself when the browser reports it is under automation; a
> setting turns that off. Everything runs on the device. The extension makes no requests of
> its own; the only requests it causes are ones the person approves:
> re-downloading a held file and reopening a held address.

## Host permission: `<all_urls>` (also the content script match)

> The extension's content script must run on every page and every frame
> (including cross-origin payment and login iframes, and about:blank/srcdoc
> frames) at document_start. There it: (1) scans the page's text and
> attributes, in memory, for hidden instructions addressed to an AI agent, and
> in agent mode removes those it finds from the page (replacing them with a
> visible marker) and removes an instruction-carrying fragment from the address
> with history.replaceState; (2) listens, in the capture phase, for submits,
> clicks (including javascript: links, which it cancels in agent mode), Enter
> in compose boxes, file selections, drops and pastes, so a purchase, send,
> consent, upload or data leak can be paused before the page acts and approved
> by the person in the extension's side panel; while an upload is held it
> clears the file input; (3) watches what is typed and pasted into fields
> (cancelling an insertion that carries data back, or putting a field back to
> its last allowed value when the change could not be cancelled) and checks
> field values a few times a second for values set without any event. A
> hijacking page can be any site, so there is no narrower set of sites that
> gives the same protection. Page content is processed locally and is never
> transmitted; what is kept is listed in the privacy policy (masked previews
> and the page address for a pending approval, and hidden-text evidence only
> if the person turns it on).

## `storage`

> Stores the person's settings (agent mode preferences, trusted and sensitive
> site lists, policy) and whether the optional link to the local firewall is on
> in chrome.storage.local, and short-lived per-tab state, pending approvals and
> one-way fingerprints of private strings in chrome.storage.session (cleared
> when the browser closes). The activity log is kept in the extension's own
> IndexedDB. Nothing is synced or sent off the device.

## `declarativeNetRequest`

> Used for the navigation policy: always blocking background requests
> (scripts, images, fetch) to about 50 well-known request-catcher, paste and
> tunnel sites, Discord and Telegram bot addresses and cloud metadata addresses,
> even with agent mode off (those sites themselves may not work; opening one
> directly is blocked only in agent mode), and, in agent mode, blocking
> DNS-exfiltration-shaped hosts, raw IPs and a suspicious data-carrying
> navigation; the extension then shows an explanation
> page in that tab and lists the navigation in its side panel, where the person
> can let it through once (a one-time allow rule for that tab and that exact
> address, removed when the page loads or after 30 seconds). Rules are bundled
> with the extension; none are fetched. The extension does not read request
> bodies.

## `downloads`

> Used to hold downloads of executable or installer files (.exe, .msi, .dmg,
> .pkg, .sh, .bat, .ps1, .reg, .lnk, .jar, .apk and similar, disk images, and
> macro documents), always, whether or not agent mode is on: the download is
> cancelled before the file is saved under its name, and if the person approves
> it in the side panel, the extension downloads the same address again, once.
> It only observes the file name, type and source of a download the browser
> already started; it does not read file contents or the download history list.

## `sidePanel`

> The approval surface. Approve and deny decisions, the reason a page was
> flagged, and the status of agent mode are shown in the Chrome side panel or
> the extension's approval window, because it is a place web pages and page-level scripts cannot draw into or
> click. Approvals are never shown in the web page itself.

## `webNavigation`

> Used for one thing that has no substitute: when the navigation policy blocks
> a request to a known data-exfiltration destination, the browser reports it to
> the extension only as a failed navigation (`webNavigation.onErrorOccurred`,
> error ERR_BLOCKED_BY_CLIENT). The extension uses that event to show the person
> an explanation page (opened in that tab with tabs.update; when the person
> approves in the side panel, tabs.update reopens the address once). It also uses
> `onCommitted` to expire approvals that were pending for a page the person has
> left, and `onCreatedNavigationTarget` to know which tab opened which, so a tab
> opened by a flagged page keeps its caution. It reads navigation events as they
> happen; it does not read or store the browsing history list, and nothing is
> sent anywhere.

## Optional permission: `nativeMessaging`

Listed under `optional_permissions` (`OPTIONAL_PERMISSIONS` in
`src/manifest.ts`). Never granted at install: the side panel asks for it only
when the person turns on "Link to the local firewall", and gives it back when
they turn the link off.

> Optional, requested only when the person turns on the link to the LaunchSafe
> firewall installed on the same computer. The extension then sends its own
> decision log entries (domain, action class, verdict, rule ids, event codes, a
> salted hash; up to 500 earlier entries on connect; never page body text,
> field values or full addresses), a taint flag for whether its agent session
> read outside content, and held actions awaiting approval (each with the site's
> domain and a label of at most 200 characters, which can come from the page,
> such as a button's text; for an upload, the label includes the chosen file
> names), to that local program, which keeps them in its signed log and can take
> the approval. The program can send back an approve or deny for a pending
> approval. Nothing is sent over
> the network. Without the program installed, or with the link off, the
> extension works the same.

## Permissions not requested (state this if asked)

`tabs`, `webRequest`, `cookies`, `history`, `clipboardRead`, `scripting`,
`debugger`, `management`, `tabGroups`, and no optional permission other than
`nativeMessaging`. The manifest has no `web_accessible_resources` and no
`externally_connectable`.

## Remote code declaration

> No. All JavaScript is bundled in the extension package. Extension pages use
> the content security policy `default-src 'none'; script-src 'self';
> style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'none';
> object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors
> 'none'`. The extension makes no requests of its own and fetches no scripts,
> rules, lexicons or configuration; the only requests it causes are ones the
> person approves (re-downloading a held file, reopening a held address).
