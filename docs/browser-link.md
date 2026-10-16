# The browser link

> **Status: built, not released.** The LaunchSafe browser extension (the
> Agent Firewall for browsers) is not in any store yet. Until it is, you build
> it from [`browser/`](https://github.com/shivanagendrakore/agent-firewall/blob/main/browser/README.md), load it unpacked and give its id
> to `install --browser` yourself.

The browser link connects the LaunchSafe browser extension to this firewall
over Chrome's native messaging. With it on:

- **One signed log.** The decisions the extension sends are also appended to
  the firewall's signed, hash-chained log, so `launchsafe-firewall log verify`
  covers browser decisions too (when the host cannot write an entry, it
  answers the extension with a `log_failed` error rather than recording it). The extension cannot keep a signing key secret
  from someone who controls the browser profile; the firewall's key lives in
  its own directory, which agents may not touch.
- **Shared taint.** A coding agent that drives your browser (Claude in Chrome,
  Chrome DevTools MCP, Browser MCP, Playwright MCP) is *linked* to it. When the
  extension's agent session reads outside content, every linked agent session
  becomes untrusted; when a linked agent session is untrusted, the extension's
  agent session becomes untrusted too. Taint only ever goes up.
- **Approvals in the firewall's queue.** When an approval passphrase is set,
  the extension also files each held action in the firewall's queue. A person
  can approve it there (`launchsafe-firewall queue approve <id>`, which needs
  the passphrase) or in the extension as before; whichever comes first wins.
  The extension accepts the firewall's answer only for the pending action it
  is bound to.

Messages carry no page body text, field values or full URLs. An approval
request includes a label of at most 200 characters for the held control, which
can come from the page (for example a button's text), and the site's
registrable domain.

The link works on macOS and Linux only.

## Set it up

1. Load the extension and copy its id from `chrome://extensions` (32 letters).
2. In your own terminal:

   ```bash
   launchsafe-firewall install --browser chrome --extension-id <id>
   # also: --browser chromium | edge | brave; --user-data-dir DIR for a profile started with --user-data-dir
   launchsafe-firewall doctor
   ```

3. In the extension's side panel, turn on **Link to the local firewall**. The
   browser asks for the "Communicate with cooperating native applications"
   permission once; the extension never asks for it before that.

`install --browser` writes two files and records them in
`~/.launchsafe-firewall/native-host/installs.json`:

| File | What |
|---|---|
| `<browser user data dir>/NativeMessagingHosts/com.launchsafe.agent_firewall.json` | The host manifest: `allowed_origins` names your extension's id and nothing else. macOS: `~/Library/Application Support/Google/Chrome/` (Chrome), `.../Chromium/`, `.../Microsoft Edge/`, `.../BraveSoftware/Brave-Browser/`. Linux: `~/.config/google-chrome/`, `~/.config/chromium/`, `~/.config/microsoft-edge/`, `~/.config/BraveSoftware/Brave-Browser/`. Never a system-wide directory. |
| `~/.launchsafe-firewall/native-host/launchsafe-firewall-native-host` | The launcher the manifest names (mode 700). It pins the firewall's directory and the approval key, like the hook command, and runs `launchsafe-firewall native-host`. |

Remove it with `launchsafe-firewall uninstall --browser chrome` (or `all`).
Like `uninstall`, it needs the approval passphrase when one is set. A
manifest that was edited to run something else is left in place and named.

Writing any file in a `NativeMessagingHosts` directory from an agent's tool
call is treated as a persistence change (FW-PERSISTENCE): a host manifest
names a program the browser runs. Running the launcher (or anything else in
the firewall's directory), or `launchsafe-firewall native-host`, from an
agent's tool call is FW-TAMPER: an agent cannot pose as the browser.

## Protocol

Chrome's native messaging framing: a 32-bit little-endian length, then UTF-8
JSON. The browser starts the host with the extension's origin as its argument;
the host refuses an origin no install allowed (Chrome checks
`allowed_origins` first). Messages from the browser are at most 64 KB and
must match the schema exactly (`src/runtime/native/protocol.ts`): no unknown
types, no unknown fields, bounded strings. A message that does not fit gets
an `error` and the host exits, which drops the link; the extension then keeps
deciding on its own and shows the link as down.

| Message | Direction | Use |
|---|---|---|
| `hello { nonce, version, capabilities, extension }` | browser → host | must come first; version 1. The host answers `hello { re, version, capabilities, firewall }`, with `approval` among its capabilities only when an approval passphrase is set |
| `log.append { nonce, entry }` | browser → host | appended as `browser_decision` with the extension's own sequence number and hash; answered `log.ack { re, seq }` |
| `state.taint { nonce, session, reason }` | both | browser → host: every linked agent session is tainted; host → browser: a linked agent session is untrusted (named `agent-<16 hex>`, never its id) |
| `approval.request { nonce, binding, action, surface }` | browser → host | filed in the queue (tool `browser`); answered `approval.queued { re, id }` |
| `approval.result { nonce, binding, verdict, sig }` | host → browser | `approve` only when the session file holds an approval for that item signed with the pinned approval key; anything else is `deny` |
| `approval.cancel { nonce, binding }` | browser → host | the browser decided first: the queue item is rejected. Items still waiting when the link closes are rejected too |

## Linked sessions

The hook links an agent session to the browser on each call to a tool of an
MCP server named `claude-in-chrome`, `chrome-devtools`, `browsermcp`,
`browser-mcp` or `playwright` (or a name starting with one of those and `-`
or `_`). A link lasts 12 hours after the session's last such call; a browser
taint counts for 12 hours too. The state is two append-only files in
`~/.launchsafe-firewall/browser/`; if either cannot be read, every session
that links is treated as tainted.

## Limits

- Approvals through the link use the passphrase. Phone approvals and the
  biometric prompt planned for the browser link are not wired to it yet.
- Linking is by MCP server name. An agent that drives the browser some other
  way (a shell script running Playwright, say) is not linked; the firewall's
  usual rules still apply to what it runs.
- The link is per user and per browser profile. The extension in a profile
  the install did not name cannot start the host.
