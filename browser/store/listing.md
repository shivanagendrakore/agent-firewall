# Chrome Web Store listing: LaunchSafe Agent Firewall

## Name

LaunchSafe Agent Firewall for browsers

## Summary (132 characters maximum)

In agent mode, makes an AI browser agent ask you before it buys, sends, grants access or leaks data. Runs on your device.

## Category

Productivity > Tools. Language: English.

## Full description

AI agents now act inside your own browser, signed in to your mail, bank, shops
and work tools. A web page the agent reads can contain hidden instructions that
steer it: buy this, send that, approve this app, paste that code over here.
This is called indirect prompt injection.

LaunchSafe Agent Firewall does not try to guess whether the agent has been
fooled. It limits what any agent, fooled or not, can do in your browser without
you saying yes.

WHAT IT DOES

- Holds sensitive actions for your approval. In agent mode, which you turn on,
  purchases, sends and deletions are held for your approval, and so are uploads
  to a new site, or from a session that has seen private data. With agent mode
  off, it holds OAuth consent, account-security changes and executable
  downloads, and a quarantined page holds every class of action. The always-on
  holds apply to your own clicks too. You approve or deny in the extension's
  side panel or its approval window, which web pages cannot reach. An approval
  is tied to the exact form, so it cannot be reused for a changed one. You can
  also approve a class of action for one site for the rest of an agent session.
  Actions of that class on that site then proceed without asking until agent
  mode ends. Account-security changes and app-access grants are never covered
  by this.
- Watches for hidden instructions. It scans pages for text a person would not
  see but an agent can read (invisible, tiny, off-screen or encoded text,
  instructions in the link's query or fragment), marks the tab, and in agent
  mode removes the hidden text. An agent that reads the page before the
  removal can still see it.
- Guards against data leaving. It notices secrets, card and ID numbers typed,
  pasted or put in a clicked link for a different website. With agent mode off
  it warns. In agent mode it asks first. Private strings such as one-time codes
  and email addresses are tracked only while agent mode is on.
- Blocks known exfiltration destinations such as request catchers, paste sites
  and look-alike data-carrying addresses. Always blocks background requests
  (scripts, images, fetch) to about 50 well-known request-catcher, paste and
  tunnel sites, even with agent mode off. Those sites themselves may not work.
  Opening one directly is blocked only in agent mode.
- Agent mode is yours to turn on or off. It also switches on by itself when the
  browser reports it is under automation; a setting turns that off.
- Keeps a local log of what it held or blocked, which you can export or delete.

PRIVATE BY DESIGN

Everything runs on your device. The extension makes no requests of its own;
the only requests it causes are ones you approve: re-downloading a held file
and reopening a held address. No account, no analytics, no remote rules, no
model calls, no remote code. Page
content is checked in memory and is not stored or sent. The log lives only in
your browser, for 30 days by default.

WHY IT ASKS TO READ ALL WEBSITES

The checks must run on every page and frame, including payment frames, because
you cannot know in advance which page is hostile. Nothing it reads leaves your
device.

WHAT IT DOES NOT STOP (PLEASE READ)

This is a safety layer, not a guarantee. It enforces only what a browser
extension is allowed to enforce.

- It cannot see what an agent sends to its own vendor, server-side fetches,
  connectors, or anything inside a cloud browser (for example agents that run
  in their own remote virtual computer). It does nothing there.
- It does not see requests made by page script (fetch, XHR, sendBeacon,
  form.submit()) as actions, so an agent that runs its own JavaScript inside
  the page can send data directly, except to the always-blocked sites above.
  A main-world shim is planned and is not built.
- Executable downloads are cancelled after the browser has already asked the
  site for the file. Files you start yourself are held too.
- An agent that controls your whole computer can click our approval buttons,
  turn the extension off or use a different browser. A stronger approval method
  has to live outside the browser. The optional link to the LaunchSafe
  Agent Firewall on the same computer (off until you turn it on) adds a second,
  passphrase-protected place to approve held actions; it is not a lock against
  an agent that controls the whole computer.
- Automation tools that remotely control a browser with this extension loaded
  can reach its pages.
- Text hidden inside images, text a page's stylesheet generates, and anything
  inside a closed shadow root are not read.
- It has been tested only against its own test simulators, not against any
  named agent product.
- It cannot run on chrome:// pages or the Chrome Web Store, and cannot protect
  actions that are not shown in the page.
- Unusual checkouts and sites it has no specific knowledge of may be missed or
  occasionally be held when they should not be.
- Another malicious extension, malware on your computer, and approving without
  reading are out of its reach.

The extension tells you in its own panel which kinds of agent it can and cannot
cover. It will not show "protected" for one it cannot stop.

Documentation and the full threat model are public in the project repository.
Contact: security@launchsafe.com

## Support

Support email: security@launchsafe.com
