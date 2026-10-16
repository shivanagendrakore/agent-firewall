# The local dashboard (`launchsafe-firewall ui`)

A read-only web view of what the firewall knows, for the person: the morning
queue with proposed changes as a side-by-side diff, the decision log with an
explanation for every entry, the sessions and why each is or is not trusted,
the protection score, MCP pins and decoys. It runs on this machine only, for as
long as the command runs, and it never approves anything.

```sh
launchsafe-firewall ui              # prints a private address, opens it in your browser
launchsafe-firewall ui --no-open    # prints the address only
launchsafe-firewall ui --project ~/code/app   # doctor's project-level checks for that project
```

Status: 0.3.0. Zero new dependencies: Node's `http` module, server-rendered
HTML, one small script for the copy buttons, no build step.

## Screens

| Screen | Path | What it shows | Source of truth (the same code the CLI uses) |
|---|---|---|---|
| Overview | `/<token>/` | one focal point: how many actions are held for you, with one "Review queue" action (or "Nothing needs you"); one line each for protection (score and how many things to improve), the last decisions and unattended mode; recent sessions as rows (status, id, one-line reason) | `readRecords`, `doctor` + `withScore`, `recentSessions`, `listQueue`, `tailLog`, `loadPolicy` |
| Protection | `/<token>/protection` | the score, the checks to improve first (each expands to doctor's detail), passing checks behind a disclosure, where the firewall is installed | `doctor`, `readRecords` |
| Session | `/<token>/sessions/<id>` | trusted or not, everything that made it untrusted, its logged decisions | `recentSessions`, `loadState`, `tailLog` |
| Queue | `/<token>/queue` | one row per held action (100 a page, `?page=N`, oldest first): what, why in a few words, when, Review | `listQueue`, `itemSummary`, the rule's title |
| Queue item | `/<token>/queue/<id>` | title, one line of facts, the rule's sentence, the exact approve/reject/show commands, then the change as a **side-by-side diff** against the file as it is now (a unified diff on a phone) or the masked input; rules, trust sources and every reason behind a disclosure | `getQueueItem`, `proposalDiff` (shared with `queue show`), `ruleDoc` |
| Decision log | `/<token>/log` | a dense table newest first, 100 a page, a segmented filter by verdict or type, and whether `log verify` passes | a cached index of the log (`src/ui/logindex.ts`), `verifyLog` (cached) |
| Log entry | `/<token>/log/<seq>` | `explain <seq>` for that entry; the raw signed entry behind a disclosure | `explainId` |
| Pins and decoys | `/<token>/integrity` | pin changes waiting for review with the accept command, pinned servers (another agent's under its name: "Cursor · user"), planted decoys (present or missing), sessions that touched a decoy | `parsePins` (read only: a corrupt file is reported, not moved), `loadRegistry`, `recentSessions` |
| Vault | `/<token>/vault` | each stored secret as its reference (`vault://<name>`), kind, fields, store and where its value may go (its bindings, as `vault list` prints them); whether the index verifies against the approval key; the `vault add`/`vault allow` commands to run in the terminal. Never a value or a fingerprint | `loadIndex` (against the key the hook pins, else the one on disk), `bindingSummary` |
| Gateway and mail | `/<token>/guards` | the MCP servers behind the gateway (client, mode, transport); every withheld item from the one quarantine store (an MCP result by tool and server, a message by sender and subject) with its signals, status and age, never the withheld text or its preview (a person reads those with `gateway quarantine show` or `mail quarantine show` in their own terminal); paired phones by label and the relay's state, never keys or credential ids; whether `run` can sandbox agents here | `readGatewayInstall`, `listRecords`, `loadPhones`, `relayStatusLine`, doctor's `run mode` check |

Installed agents include Cursor (`install --agent cursor`) next to Claude Code,
Codex and Gemini CLI.

Paths in lists are shown relative to the project or as `~/...`, cut in the
middle when long, with the full path in the tooltip. In descriptive sentences (a
doctor detail, a trust source) a project or home path is shortened only where a
path starts (start of text, after whitespace, a quote, `=`, `:` or `(`), never
inside another path or a URL. Command and summary lines (a held action's title,
a log entry's "what") are shown exactly as written.

Every page is computed when it is requested; reloading shows the current state.
Doctor's checks are cached for 60 seconds because they start `claude --version`
and the other agents' version probes.

Design: the LaunchSafe product look (Onest, ink on a plain canvas, hairline
rows instead of boxes, a 960px column, a title and one line of facts per page,
light and dark from the OS setting). The accent (#4A64FE light,
#667EFE dark) marks only something **held or found**: pending queue items,
pending MCP pin changes, a tripped decoy. Doctor's statuses use a dot and a
word (ok, warning, failing), never colour alone. The Onest font (SIL OFL 1.1) is
embedded in the package and served by the dashboard itself.

## Threat model

The dashboard adds a listening socket to a machine where an agent runs
commands as the same user, a browser that visits untrusted pages, and text the
agent or a repository wrote. What it must not become:

1. **A way to approve, reject or widen anything without the person.** The
   firewall's human channel is the approval passphrase typed in the person's
   own terminal, which unlocks the Ed25519 approver key (docs/design.md,
   *Self-protection and the approval channel*). A web endpoint that changed the
   queue would be a new side door, reachable by anything that can send an HTTP
   request to 127.0.0.1.
2. **A way for the agent to read what it otherwise could not.** The data shown
   is what `status`, `queue`, `log`, `pins`, `canary list` and `explain`
   already print, and those read-only commands are allowed to the agent today.
   The dashboard shows no more: no keys, no approver file, no decoy values, no
   session secret fingerprints, input that was masked at enqueue.
3. **A target for a web page.** A page the person visits can make the browser
   send requests to `127.0.0.1:<port>` (cross-site requests, DNS rebinding: a
   hostname that resolves to 127.0.0.1 so the page is "same-origin" with the
   dashboard).
4. **An injection surface.** Queue reasons, summaries, proposal content, MCP
   launch lines and log entries are agent- or repository-written. Rendered as
   HTML they could run script in the dashboard's origin or make a line read
   differently from what it holds.
5. **A source of network traffic.** The firewall makes no network calls except
   `update`; the dashboard must not load fonts, scripts or images from
   anywhere.

## Security design

**Read-only, always.** The server answers `GET` and `HEAD` only; every other
method is `405` with `Allow: GET, HEAD`, and there are no CORS headers, so a
preflight never succeeds. No handler calls anything that writes the queue,
session state, pins, decoys, policy, settings or the log. The only writes the
process can cause are the caches `doctor` itself refreshes (the notification
probe, the identity and agent-scan caches), which no approval reads. So a plain
`GET /<token>/` (the Overview), `/protection` or `/guards` can refresh those
doctor caches when its 60-second cache has expired: read-only for the
firewall's decisions, not strictly write-free on disk. A test
fingerprints the firewall's authoritative files before and after requesting
every page and requires them unchanged.

**A stored value is never shown.** Every page renders with the vault's view
(names and fingerprints, read on the server and never sent): any line of
interpolated text that contains a stored value, in the clear or encoded (a
queue item's input, a log entry, a proposal), is replaced by "[hidden: this
contains the value of vault://<name>]". A vault reference in element content is
marked as one (a dashed underline and a tooltip saying it is a name, not a
value); inside attributes it stays plain escaped text, so no markup is added
where none may go. When the vault index exists but cannot be read or parsed,
nothing can be recognised, so every page says "Masking unavailable" at the top
instead of looking as safe as usual.

**Agent-written paths are read carefully.** A proposal's diff compares against
the target file as it is now, but the target is agent-written. It is read only
when it is a regular file (checked with `lstat`: never a symbolic link, device,
FIFO or socket) inside the project or the home directory, both as written and
as resolved, and not a secret file or credential store from the engine's own
lists (those say "Not shown: sensitive path"). The file is opened without
following links and without blocking, and at most 1 MB is read. The queue
item's own `cwd` is never treated as a root, for reading or for shortening
paths. A pending MCP pin change's launch line is shown with the value after a
`--token`, `--key`, `--secret` or `--password` style argument, URL query
strings and URL user info replaced by `[redacted]`. A pin name with a character
outside printable ASCII is written in the copied `pins accept` command as
`$'...'` with `\uXXXX` escapes, so a look-alike letter is visible.

**Failures stay honest and quiet.** The address is parsed before any other
check and never throws: a path is always a path on this server (`GET //` is the
same `404` as any unknown path or wrong token), and an absolute-form address
for another origin, or one that does not parse, is a `400`. A page that fails to
render is a generic `500`; the reason goes to the terminal that started `ui`,
not to the browser. The Log screen and the Overview show `log verify`'s answer
from its `ok` alone: a log that was deleted or emptied, a damaged key, or a
check that threw shows "Does not verify" (or "Check failed") with the
problems, even with no entries left. Unreadable queue files are the Overview's
focal point, ahead of held actions, since one may be an action waiting for the
person.

**Approving stays in the terminal.** Each held item and each pending pin change
shows the exact command (`launchsafe-firewall queue approve <id>`,
`queue reject <id>`, `pins accept <server>`) with a copy button (the id is the queue file's name, checked against the store's id format and quoted as one shell word, never the file's own id field); the person runs
it in their own terminal, which asks for the passphrase there. The dashboard has no passphrase field, even though signing locally would keep
the key out of the page:

- It would teach the person to type the passphrase into a web page. An agent can
  start its own server on another local port and draw a perfect copy of the
  dashboard; the terminal prompt is a place the agent cannot draw.
- The browser's process, extensions and form autofill are outside the
  firewall's control; the terminal prompt does not echo and goes nowhere else.
- A write endpoint, however guarded, is a state-changing request reachable by
  any local process that obtains the token (below).

So the dashboard is a reading aid for the review, and the decision is made where
it always was. The command shown is exactly the one the CLI prints (`queue
show`, the hook's message), so the two never disagree.

**A per-launch token in every URL.** `ui` generates 32 random bytes
(base64url, 256 bits) when it starts. Every path is under `/<token>/`; a request
without it, or with a wrong one, gets the same `404` as an unknown path
(compared in constant time). The token lives only in the process's memory and
in the line printed once to the person's terminal; it is never written to a file,
a log entry, an environment variable or a command line. Stopping `ui` (Ctrl-C,
a closed terminal, or 30 minutes without a request) makes every old address dead.

**Lifetime.** Only a request that passed the Host, Origin, method and token
checks (or a successful one-time launch) restarts the 30-minute idle clock, so a
wrong token, a rebound Host or a `405` from another local process cannot keep the
dashboard alive. `ui` is tied to the terminal that started it: it stops on
SIGINT, SIGTERM and SIGHUP, and it polls its parent process every two seconds
and stops when the parent changes (a shell killed with SIGKILL sends no hangup,
but its children are re-parented).

**Bounded pages.** The queue list is 100 held items a page. The log screens
do not parse the log per request: each log file is scanned once into a small
index (sequence, type, verdict, byte offset), cached together with the
`log verify` result and keyed by the name, device, inode, size, modification
time and change time of every file that makes up the log, plus the content
hashes of `head.json` and `anchor.json`. A same-size rewrite with the
modification time put back (`touch -r`) still moves the change time, which no
user call can set, so it misses the cache. Each cache hit also re-checks,
cheaply, that the log's last line hashes to itself and to the recorded head
(it reads `head.json` and the last 64 KB of the newest file); if that answer
changed, the index and the verification are rebuilt. A page then reads only the
lines it shows, and an append, rotation or edit rebuilds the index on the next
request. Every field a
page renders is cut to 2,000 characters with a visible "truncated" note (after
stored values are hidden on the whole text), a tool input shows at most 50 keys
or items per object with "+N more", and a block (an input, an explanation, a raw
entry) is cut at 100,000 characters. A proposal's diff shows at most 500 rows,
then "+N more lines" with the `queue show` command for the rest, and the diff
itself is not computed line by line past 2 MB of before-and-after text (it
shows as a full replacement, in `queue show` too). Tags in rows (a pin change's tool) are cut
in the middle like the rest of the row, so no screen scrolls sideways.

**Opening the browser without putting the token on a command line.** A
command line is visible to every process of the user (`ps`). So `ui` opens a
**one-time launch address** instead (`/open/<code>`, a separate 128-bit code,
valid once and for 60 seconds), which redirects to the token address. On macOS
the browser is opened by `/usr/bin/osascript` with the script on standard input
(`open location`), so even the one-time code is not in an argument list; on
Linux by `xdg-open` from `/usr/bin`, `/usr/local/bin` or `/bin` only, root-owned
and not writable by anyone else (as for `notify-send`), with the one-time
code as its argument. If the code was used already (someone raced for it), the
browser shows "This launch address was already used", which tells the person to
stop and restart. `--no-open` skips this.

On Linux the one-time code is therefore on `xdg-open`'s command line for the
moment it runs. On a machine shared with other accounts that can read process
lists (no `hidepid`), another account could race the browser for it; the
person's browser then shows "already used". Use `--no-open` on such machines
and paste the printed address yourself. (A local redirect file was considered
instead and not used: sandboxed snap and flatpak browsers often cannot read the
temporary directory, so the browser would open on an error.)

**Host, Origin and fetch-metadata checks (DNS rebinding and cross-site).** The
server listens on `127.0.0.1` only, on a random port the system picks. Before
anything else every request must have:

- `Host` exactly `127.0.0.1:<port>`. A rebinding page's requests carry its own
  hostname and are refused (`421`). `localhost` is refused too: the dashboard
  never prints it, and accepting one spelling is simpler to reason about.
- no `Origin`, or exactly `http://127.0.0.1:<port>` (`null` and other origins:
  `403`).
- no `Sec-Fetch-Site`, or `none` or `same-origin`. `cross-site` and `same-site`
  are refused (`403`); every port on 127.0.0.1 is the *same site*, so another
  local web app (including one the agent started) is refused as well.

**Content Security Policy, and headers.** Every response carries
`Content-Security-Policy: default-src 'none'; style-src 'self'; script-src
'self'; font-src 'self'; img-src 'self'; connect-src 'none'; form-action 'none';
frame-ancestors 'none'; base-uri 'none'`, plus `X-Content-Type-Options:
nosniff`, `Referrer-Policy: no-referrer` (the token never leaves in a
`Referer`), `Cache-Control: no-store`, `X-Frame-Options: DENY`,
`Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy:
same-origin` and a `Permissions-Policy` that turns off every powerful feature.
No inline script or style exists, so the policy needs no nonce or hash. Pages
contain no forms that submit anywhere and no external URLs; a test scans every
rendered page for one.

**Escaping (for HTML).** Every value is rendered through one tagged
template that escapes by default: `&`, `<`, `>`, `"` and `'` become entities, and
first C0/C1 controls, DEL, bidirectional overrides and zero-width characters
become visible `\uXXXX` escapes (the same `safeText` the terminal output uses),
so a reason cannot hide or reorder text on the review screen. Markup is only
ever the template's own literals; links are built from validated identifiers
(queue ids `[a-z0-9]`, log sequence numbers) and URL-encoded. Tests render the
classic payloads (`<script>`, `"><img src=x onerror=...>`, `</pre>`,
`javascript:` URLs, U+202E, ESC sequences) through every field an agent can
reach.

**Who may start it.** `ui` is declared state-changing in the command spec, so
the firewall denies it when the agent runs it (FW-TAMPER, like `queue approve`),
however it is reached (wrappers, `npx`, a symlink to the CLI), and the command
itself refuses to start without a real terminal or inside a coding agent's
session: Claude Code, Codex, Gemini CLI or Cursor's agent, recognised by the
variables each sets for its tools' commands (`CLAUDECODE`, `CODEX_SANDBOX`,
`GEMINI_CLI`, `CURSOR_AGENT` and the like) or by an agent CLI among the
process's ancestors. Reasons:

- The token is printed to whoever starts it. Started by the agent, the agent
  would hold the token and could also open the person's browser at a page of
  its choosing.
- It opens a listening socket and a browser window: changes to the machine,
  not reads.
- Nothing is lost: the agent can already run the read-only commands the
  dashboard draws from.

**Residual risks (stated, not solved).**

- A process running as the same user can read the browser's history, where the
  token address is stored, and can read a terminal pane that an agent is
  allowed to read (some desktop apps give the agent the person's terminal
  panel: run `ui` in a terminal the agent cannot see). What it gains is the
  read-only view: the same data the read-only commands print. It cannot approve
  anything: that needs the passphrase in the terminal, and the hook accepts only
  approvals signed with the key pinned in the hook command.
- The dashboard is as current as the moment the page was rendered; it does not
  push updates.
- Doctor's checks run in the dashboard's process with the person's
  environment, exactly as `doctor` would.

## Tests

`test/dashboard.test.ts` (in-process server on a temporary home):

- token required: no token, a wrong token, a token of the wrong length, a token
  as a query string: all `404`; the right token: `200`.
- Host and Origin: a rebinding `Host`, `localhost`, a missing `Host`, a foreign
  `Origin`, `Origin: null`, `Sec-Fetch-Site: cross-site` and `same-site` are
  refused; `none` and `same-origin` pass.
- read-only: `POST`, `PUT`, `DELETE`, `PATCH` and `OPTIONS` on every route are
  `405`, with no `Access-Control-*` header; the firewall's files are unchanged
  after every route is requested; approving through the dashboard is
  impossible (no route changes a queue item, which stays pending).
- approval only through the human channel: the item page shows the exact CLI
  command; the CLI spec marks `ui` state-changing; `launchsafe-firewall ui`
  (bare, through `npx`, behind `env`/`bash -c`) is denied for the agent; the
  handler refuses without a person at the keyboard and prints no address.
- escaping: XSS payloads in a queue item's reasons, summary, tool, trust
  sources, input, proposal target and content, an MCP server name and pending
  detail, and a log entry's fields are rendered inert.
- no external requests: the CSP header on every response, and no `http(s)://`
  or protocol-relative URL in any `src`, `href` or `url(...)` of any page or
  asset.
- an empty state (a home that does not exist) renders every screen with honest
  empty messages.
- the side-by-side diff pairs changed lines and keeps unchanged ones aligned.
- the one-time launch address works once, then not again.

`test/ui-audit.test.ts` covers the audit fixes: log verification from `ok`
alone (an emptied log, a damaged key) on the Log screen and the Overview;
boundary-only path shortening; the guarded target read (symlink, outside the
roots, sensitive path, directory); the diff row and size caps; `GET //` as an
ordinary `404` and an unparsable address as a `400`; the generic `500`; unreadable queue files as the Overview's focal point;
the agent start-up guard for Codex, Gemini CLI and Cursor; launch-line
redaction; the "Masking unavailable" note; and `\uXXXX` pin names in copied
commands.
