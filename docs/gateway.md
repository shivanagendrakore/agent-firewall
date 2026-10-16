# The MCP gateway

The gateway puts the firewall's engine in front of **any MCP client that runs
the server locally from a configuration the gateway can rewrite**,
including clients that have no hooks (Claude Desktop, VS Code), and adds what a
hook cannot do for the agents that have them: it sees every `tools/list`, pins
every tool's definition and hides changed tools; it scans every result and
withholds hidden instructions before the model sees them; and it follows the
MCP authorization rules for remote servers. Local only:
nothing listens beyond 127.0.0.1 and nothing goes to LaunchSafe. A result
larger than `gateway.responses.maxScanBytes` (4 MiB by default) is, under the
default `oversize: "deliver"`, delivered not fully scanned (the session is
tainted); set `oversize: "withhold"` to withhold it instead.

Implemented from MCP specification revision 2026-07-28 (changelog, versioning,
stdio and Streamable HTTP transports, `server/discover`, multi round-trip
requests, authorization) and tested against an in-repo stand-in server and
client; not run against captured traffic from real MCP clients or servers.

## Two transports

```
MCP client ──stdio──► launchsafe-firewall mcp wrap … -- <real server>   (one process per server)
MCP client ──HTTP───► http://127.0.0.1:8473/c/<client>/u/<server>  ──► remote MCP server
                      (launchsafe-firewall mcp serve)
```

- **stdio**: the client starts `node …/cli.js mcp wrap --client C --server NAME
  --mode M -- <command> <args…>` instead of the server. The wrapper starts the
  real server with the client's environment, relays newline-delimited JSON-RPC
  through the pipeline (16 MiB per message, nesting up to 1,000 levels, 1,000
  requests in flight), passes the server's stderr through, and exits with its
  code. A message that cannot be handled (an internal error) is answered with
  an error and not forwarded; it never ends the wrapper. If the wrapper dies,
  the client loses that server's tools; it does not fall back to an unguarded
  connection.
- **Streamable HTTP**: `launchsafe-firewall mcp serve` (person-run) binds
  127.0.0.1 only, checks `Host` and `Origin` (403, against DNS rebinding),
  requires the per-client bearer `lsgw_…` (401) and drops any other
  `Authorization` or `Cookie`. A modern request whose `MCP-Protocol-Version`,
  `Mcp-Method`, `Mcp-Name` or `Mcp-Param-*` header disagrees with the body is
  rejected with 400 and JSON-RPC `-32020` (HeaderMismatch); under a legacy
  `MCP-Protocol-Version` header, a body that declares a version, or an
  `Mcp-Method`/`Mcp-Name` header that disagrees with the body, is rejected the
  same way. A request that reuses the id of one still in flight is refused (its
  answer would otherwise be read as the other's). An upstream that resets the
  connection mid-answer, ends its stream without a complete answer, or answers
  with another id gets the request a tool error (a JSON-RPC error for other
  methods): nothing is left hanging, and a failure in one request never stops
  `mcp serve`. An upstream has 5 minutes for its whole answer (a
  `subscriptions/listen` stream has no limit); a JSON answer is cut off as soon
  as it passes 16 MiB, while it streams. Towards the
  upstream every routing header is **regenerated** from the body the gateway
  sends, never copied, and tools whose `x-mcp-header` annotations are invalid
  are excluded from `tools/list`, as the transport requires of a client.

## Modes

| Mode | Used for | What the gateway decides |
|---|---|---|
| `full` | every client, unless you choose hook mode | every `tools/call`, `resources/read`, `prompts/get` and `completion/complete`, with the same engine, rule ids, queue, log and budgets as the hooks |
| `hook` | Claude Code, Codex, Gemini CLI, Cursor with the firewall installed, when you name it (`gateway.mode: "hook"` in your own policy, or `--mode hook`) | nothing per call (the client's hook decides, so nothing is asked twice); pins and hiding, result scanning, input-request policy and the audience rules still apply |
| `auto` (default) | | `full`, unless your user or managed policy sets `gateway.mode: "hook"` |

`auto` is full mode: the gateway decides every call itself. An install record
says the firewall's hook was installed, not that it runs for this session (a
client started with its hooks switched off, or a settings file that lost
them), and in hook mode a call the hook never saw would pass undecided. With a
hook installed, full mode decides an MCP call twice (the hook, then the
gateway), so an ask may need the queue's approval as well as the client's.
Hook mode is for a person who accepts that the client's hook is the only check
per call; it still falls back to full mode when the hook's install record is
gone. A project policy cannot choose hook mode.

In both modes those four requests are forwarded with only the parameters
their method defines (the method's own fields, `_meta`, `inputResponses` and
`requestState` on `tools/call`, `resources/read` and `prompts/get`, and `task`
on `tools/call`; `completion/complete` has its own fields and `_meta` only); a parameter under any other key
was never part of the decision, so it is dropped and the drop is logged
(`gateway_protocol`, with every dropped field named in `fields`).
The same holds inside the parameters the engine does not read: `_meta` keeps
only `progressToken` (a string of at most 256 characters, or a number) and
the `io.modelcontextprotocol/` protocol version, client capabilities,
client info and related task (`{ taskId }`, a non-empty string of at most 256
characters; other fields in it are dropped); `task` (MCP's TaskMetadata) is
always forwarded when it is an object, with its `ttl` when that is a
non-negative finite number, so `task: {}` still asks for a task with the
server's default ttl; `inputResponses` keeps only answers
to input requests the gateway passed on to the client for that same call
(same tool and arguments), each with only the fields its method's result
defines (`action` and `content` for elicitation; `role`, `content`, `model`
and `stopReason` for sampling; `roots` for roots). The answers themselves are
forwarded as the client gave them, as an older client's answer to a server
request is: the input request was checked on its way in (`gateway.sampling`,
the elicitation rules).

## Sessions (full mode)

MCP shows a server no conversation boundary, so:

- stdio: all wrapped servers of one client process share one session,
  `gateway:<client>:<pid>:<start time>:<reset generation>`. An email server's taint reaches the
  same client's chat server, so the trifecta rule holds across servers. The
  session ends when the client restarts. This is stricter than per-chat.
- HTTP: one session per client. After `gateway.httpSessionIdleMinutes`
  (default 60) without a call, a clean session is renewed; one that read
  outside content or holds private data (or whose state cannot be read) is
  kept, so waiting never clears its taint.
- `launchsafe-firewall gateway reset <client>` starts a new session at once
  (a person's command: a terminal, and the approval passphrase when one is set).

`workspaceRoots` is empty for desktop clients (so a filesystem server's reads
outside `trustedReadRoots` count as outside content) unless you name roots in
`gateway.clients.<client>.workspaceRoots` (user or managed policy). Approvable
calls are **queued**: the client gets a tool error with the reason and
`launchsafe-firewall queue approve <id>`; after you approve, the same call
(same action hash) runs once when the model or you retry it, as long as the
rules that ask are still the ones you were shown and the gateway runs from the
same directory. If a rule you were not shown asks by then, or the directory
differs, the call is queued again and the error says an earlier approval was
not used and why.

Elicitation asks (`gateway.askVia: "elicitation"`) are built but apply only to
clients on the verified list, and that list is empty: a client that renders an
elicitation where the model can answer it would turn the ask into a
self-approval, so each entry needs a captured fixture first. The question's
signed request state carries the rules it named; a yes covers those, and the
call is decided again with it, so a rule that asks by the time of the answer
and was not named is queued instead. A request state without the rules (one
made before this was added) is refused.

## Phone approvals (experimental, see [phone.md](phone.md))

A wrapped server's stdio entry carries the paired phones' pin (`--phones sha256:<hex>`, written by
`mcp wrap-config`, re-pinned by `phone pair` and `phone remove`), so a client with no hook honours phone
approvals exactly as the hook path does: same verification, windows, single use and `FW-APPROVED` retry
(see `src/runtime/relay/`). `mcp serve` pins the list when it starts. Without the pin the approval
is not honoured and the call stays held for the terminal.

## tools/list pins and hiding

Every `tools/list` result is pinned in `pins/mcp.json`, the same file the hooks
use: each tool's `{description, inputSchema}` hash (the hooks' own, so a pin
made through ToolSearch agrees) and a hash of the full definition (name, title,
schemas, annotations), plus the server's reported version.

- First sight of a server pins everything; a tool whose definition carries
  hidden text or an instruction to the agent is **hidden at once**: its name,
  description, its title and the annotations' title, and every string and
  property name in its input and output schemas (property descriptions are the
  usual place for tool poisoning). The check fails closed: schemas nested more
  than 64 levels deep or holding more than 20,000 values are not walked to the
  end, so such a tool is hidden as well, with the reason in the alert and the
  log (`findings`).
- A changed title, annotations or output schema (or, for a tool a hook pinned
  by description only, the first time the gateway records its full definition)
  is checked the same way: if those fields carry hidden text or an instruction,
  the tool is hidden under **every** `toolChanges` policy and the definition is
  never pinned. A finding is a flag on the pending change, not a word in its
  text. The `x-mcp-header` walks fail closed as well: a schema nested more than
  32 levels deep is invalid and the tool is excluded from `tools/list`.
- A changed description, changed annotations, or a new tool after
  `mcpPinning.newToolGraceHours` is a pending change, and under
  `gateway.toolChanges: "hide"` (the default) the tool disappears from the
  client's list; a call to it is refused (**FW-MCP-TOOL-HELD**). Review with
  `launchsafe-firewall pins`, accept with `launchsafe-firewall pins accept
  <server>`. Under `"taint"` the tool stays visible and the session is tainted.
- A changed server version alone is reported and pending, but hides nothing
  (the definitions the model sees are compared one by one).
- Pin keys: `gw-<client>:<server>` in full mode; the agent's own key in hook
  mode (`user:github` for Claude Code), so hook and gateway share one pin.
- **Hook mode, first look at a hook's pin.** A hook pins a server from the
  tools it sees called, never from a tool list. When the gateway first lists a
  server the hook pinned, a tool the hook never saw follows the hook's own
  first-use rule instead of being hidden as new: inside the grace window, or
  when its definition was seen before, or the launch is pinned to an exact
  version with an unchanged configuration, it is pinned as a first use;
  otherwise it is a pending new tool (an alert, `pins accept` to review, the
  session tainted) and stays visible, and the client's hook decides its calls
  as it did before the wrapper. A tool that appears after that first look, or
  one whose definition carries a finding, is hidden as usual.
- **A hook's record never opens a tool.** Once the gateway has seen a server's
  tool list, a call to a tool it did not see listed is refused
  (FW-MCP-TOOL-HELD), even after the client's hook has recorded a call to it:
  the hooks' list of names holds tools seen only in calls, so only what the
  gateway saw listed counts. Hook records and gateway sightings of the same
  pending change merge and the stricter state wins: a hook's record never
  replaces the definition the gateway saw or a finding in it, so a tool listed
  with hidden text stays hidden, and its calls refused, whichever saw it first.
- **The wrapper is not a change.** Pins, the agent-safety launch analysis and
  drift see the original command: a wrapped entry is unwrapped before hashing
  (the exact installed CLI only, as for the Cursor lane's `unwrapFirewall`), and
  a local gateway URL is mapped back to the original from
  `gateway/install.json`.

## Result scanning

Every text channel the model can read goes through the shared content scanner
(`src/engine/content-scan.ts`): text blocks; embedded resources' text whatever
`mimeType` the server claims (HTML resolved); every string in
`structuredContent`; resource links' `uri`, `name`, `title` and `description`;
`resources/read` contents (their text, a `blob` whose `mimeType` is textual or
not given, decoded, and their `uri`, `name` and `title`); every string and
property name of a content block whose type the gateway does not know (images
and audio carry media and are not scanned); `prompts/get` messages; JSON-RPC **errors**
(`message` and every string in `data`); the server's **instructions** from
`initialize` and `server/discover`; every entry of `prompts/list`,
`resources/list` and `resources/templates/list`, and the other fields of those
results and of `tools/list` and `completion/complete` (a description beside the
list, `nextCursor`, anything a server adds; withheld, they are dropped and the
list is delivered); `completion/complete` values; notification text. Inside JSON (`structuredContent`, error `data`, list
entries, notifications) property names are scanned as well as values, and a
value nested more than 64 levels deep or holding more than 200,000 values is
withheld whatever `oversize` says (`too_deep_to_scan`): what the walk did not
reach was never checked.

| Verdict | When | What the client receives |
|---|---|---|
| withhold | tag characters; text spelled in a run of variation selectors (`variation_selectors`); hidden text with an agent-directed or imperative phrase; dense zero-width characters (eight or more, or four in a row) within 200 characters of an agent-directed phrase, before or after it; a data-carrying link inside hidden text; a scanner failure or time-out (`scan_failed`); JSON past the walk's limits (`too_deep_to_scan`) | a notice naming the record, the server, the tool and the signals; the text goes to `quarantine/` (30 days, 1 MiB); **FW-MCP-WITHHELD**; the session is tainted; a desktop notification. An error keeps its code and carries the notice as its message; withheld instructions are replaced by the notice; a withheld list entry is left out of the list (the rest is delivered); withheld completions become no suggestions |
| strip | hidden characters, hidden HTML or terminal control sequences without an instruction | hidden HTML removed (`[LaunchSafe Firewall removed N hidden characters]`); in text, each run of invisible characters (zero-width, direction-changing, tag characters, variation-selector runs) replaced by `⟦hidden⟧` and every terminal control sequence (ANSI escapes such as concealed text, cursor moves, erases and OSC links, titles and clipboard writes, colours too, and other C0/C1 controls; a lone carriage return becomes a line break) removed (`[LaunchSafe Firewall marked N runs of hidden characters as ⟦hidden⟧ and removed M terminal control sequences]`) |
| flag | visible text addressed to an AI assistant | the result unchanged, with a fixed note first; a taint source |
| deliver | anything else; also a result past `maxScanBytes` under the default `oversize: "deliver"` (`not_fully_scanned`: only its first part was checked, and the session is tainted) | the result |

The variation-selector and terminal checks are `src/engine/hidden.ts`, the
same code the hooks use for every other result (FW-HIDDEN-OUTPUT). Zero-width
characters follow the same count there, but not the same answer: one on its own
(or a few: fewer than eight, no run of four) is ordinary text and is delivered
as it is; a dense run is marked and delivered, and withheld only when a phrase
addressed to an AI assistant is within 200 characters of it, before or after
(every place the phrase appears counts, not only its first). The hooks do not
take a dense run out of what the agent reads (file reads and shell output are
never rewritten, and this kind is not one a rewrite covers), so they untrust
the session for every dense run, phrase or not
([design.md](design.md#what-taints-what-counts-as-sending) has the three cases
side by side). A server
whose content outsiders write (an error tracker, an issue tracker, a support
desk, outside chat, mail, the web) taints the session even when your policy
trusts it (`outsiderWritable`, [policy.md](policy.md)), and the commands its
results show are remembered for FW-OUTSIDE-COMMAND.

In full mode the hooks' post-tool step reads what the server returned, before
anything is withheld or stripped, and errors as well as results: a decoy
file's value coming back is the signal even when the client only gets the
notice, and an error from an untrusted server taints the session like a result.
A call to a hidden tool (FW-MCP-TOOL-HELD) never reaches the engine, but its
arguments still go through the decoy tripwire. Alerts written to stderr escape
control and bidi characters (a server chooses its tool names).

Secrets in results are fingerprinted as in the hooks, and masked when
`redactSecretsInOutput` is on: the gateway owns the pipe, so redaction works for
clients whose hooks cannot replace output. `gateway quarantine` lists withheld
results; `gateway quarantine show <id>` prints one for you, in your own
terminal (the firewall refuses it from an agent).

## Input requests and unknown methods

- Input requests are checked on **every** method's answer (an input-required
  result to `resources/list` or `tools/list` as much as to `tools/call`), and
  only the input-required fields go on: content or a tool list beside them is
  dropped, so nothing skips the result checks.
- **Sampling** (a server running your model on its own text) is refused for
  servers whose results are untrusted (**FW-MCP-SAMPLING**,
  `gateway.sampling: "deny_untrusted"`).
- **Elicitation** passes, labelled `[MCP server <name>]`; a URL-mode request
  from an untrusted server is turned into text, never opened.
- **Roots** pass and are logged (they reveal local paths).
- An input request is passed on only once its log entry
  (`gateway_input_request`, `passed: true`) is recorded. When the decision
  log refuses the entry and its short fallback entry, the request is refused
  (**FW-LOG-UNRECORDED**): a server's request (2025-11-25 and earlier) is
  answered with a JSON-RPC error, a 2026-07-28 input-required result ends the
  call with a refusal, and why goes to the gateway's stderr.
- Input requests are not translated between protocol eras in this release.
- **Unknown methods** are refused in both directions (**FW-MCP-METHOD**,
  `-32601`); unknown notifications are dropped and logged.

## Protocol eras

Revision 2026-07-28 is stateless (`_meta` on every request, `server/discover`);
2025-11-25 and earlier open with `initialize`. Towards the upstream the gateway
probes with `server/discover` and falls back to `initialize` on any error that
is not a recognised modern error (-32020, -32021, -32022) or on no answer,
never keyed on one code. Towards the client it accepts either: a legacy client
in front of a modern server gets its `initialize` answered by the gateway and
its requests forwarded with modern `_meta`; a modern client in front of a
legacy server gets `server/discover` answered from the server's
`InitializeResult`. Over HTTP a legacy upstream's `Mcp-Session-Id` is kept. A
modern server that supports no version the gateway knows is refused.

## Remote servers: OAuth and audience

- The gateway never passes a client's token upstream and accepts only its own
  per-client bearers (`keys/gateway-clients.json`, mode 600). It publishes no
  protected resource metadata, so no client starts an OAuth flow against it.
- `launchsafe-firewall mcp login <server>` (person-run) reads the upstream's
  RFC 9728 metadata (from its 401 or the well-known path) and checks its
  `resource` equals the canonical upstream URI; discovers the authorization
  server (RFC 8414, OpenID discovery) and records the issuer; registers by DCR
  when offered (`application_type: "native"`), else asks for a client id;
  then PKCE S256 with `resource` in both requests (RFC 8707), a loopback
  redirect, a single-use `state` and an exact-match `iss` check (RFC 9207: a
  missing `iss` is rejected when the metadata advertises it). The issuer and
  every authorization server endpoint (authorization, token, registration) must
  be `https` (plain `http` only on 127.0.0.1, `localhost` or `[::1]`), checked
  at discovery and again before a token request or a refresh. So must the MCP
  server itself, which receives the access token on every request: `mcp login`
  refuses a plain-`http` upstream off this machine, and the gateway never sends
  a login's token to one. A request to the loopback redirect without this
  login's `state` (another local process, a stale browser tab) is answered 400
  and ignored; the login goes on waiting for the real answer. Client ID
  Metadata Documents are not supported yet.
- Tokens are sent only to the upstream URL they were issued for; the gateway
  never follows a redirect, so a redirect to another origin never receives the
  token (**FW-MCP-AUTH**, logged, and a tool error). A 401 becomes a tool error
  naming `mcp login`; refresh happens in the gateway.
- Storage: in the vault when `mcp login` can sign the entry (an approval key,
  the macOS Keychain or the Secret Service, and your approval passphrase): the
  access and refresh tokens become `vault://mcp/<server>` (kind `oauth`, fields
  `access_token` and `refresh_token`, bound `mcp:<server>`), and the login's
  file in `gateway/tokens/` keeps only the issuer, resource, client id, token
  endpoint and the entry's name. The token goes only into the upstream
  `Authorization` header, never into arguments (a reference to it is
  FW-VAULT-UNSUPPORTED), and only while the signed index still binds the entry
  to that server. A refresh happens in the gateway, unattended: the new values
  go straight to the store and their fingerprints to the unsigned
  `vault/oauth-prints.json` (fingerprints only add detection; bindings never
  come from it), logged as `vault_change` `op: "refresh"`. Without an approval
  key, a usable store or the passphrase, the tokens stay in `gateway/tokens/`
  (mode 600), as before, and `mcp login` says why.
- Vault references in arguments: see "Vault substitution" below and
  [vault.md](vault.md).

## Vault substitution

The gateway owns the pipe, so it is the strongest place to put a secret into an
action: the model only ever sees `vault://<name>`.

- **Full mode:** after the engine allows a `tools/call` whose arguments carry
  references bound to that server (and tool, and argument path), the gateway
  reads each value, puts it into the arguments it sends upstream (over HTTP the
  `Mcp-Name`/`Mcp-Param-*` headers are regenerated from them), and logs a
  `vault_use` entry (reference, kind, destination `mcp:<server>:<tool>`,
  binding; never the value). A value that cannot be read denies the call; it
  is never sent with the reference in place of the value.
- **Hook mode:** the client's own hook decides, and when it allows a
  substitution it leaves a single-use grant for exactly that call (server, tool,
  hash of the arguments) in `vault/tickets/`. The gateway puts the values in
  only with a grant; a call with references and no grant is refused. A grant
  for an asked action lasts three minutes (180 s), or `vault.ticketSeconds` if that is longer.
- **On the way back:** every answer, error, notification and legacy server
  request is scrubbed before anything reads it (the content scanner, the
  quarantine store, the post-tool step, the client): the values substituted
  into calls in flight, in the clear and base64, base64url, hex, URL, base32 and
  JSON-escaped, and every fingerprinted vaulted value in the clear become the
  reference. If a value is still detectable afterwards (inside a larger encoded
  blob), the whole answer is withheld. The wrapped server's stderr is scrubbed
  line by line the same way.
- An approval given through an in-client elicitation does not cover references
  (approve in the terminal and retry).

## Installing: config rewrite

```
launchsafe-firewall mcp wrap-config --client claude-desktop --dry-run
launchsafe-firewall mcp wrap-config --client claude-desktop
launchsafe-firewall mcp unwrap-config --client claude-desktop
```

Person-run (a real terminal, not under an agent, the approval passphrase):
shows the diff, backs the file up into `backups/`, writes atomically and records
the original entries in `gateway/install.json`. The diff's lines are printed
only in an interactive terminal, with credentials masked (the entries' `env`
values and headers can hold tokens); `--dry-run` from a script prints which
servers would be wrapped and why others are left. A server whose name holds
`__` or ends in `_` is left as it is (the engine would read
`mcp__<server>__<tool>` back as another server's), and a wrapper started for
such a name refuses every call.

A `tools/list` result is checked and passed on for its first 1,000 tools; the
rest are left out and the log says so.

| Client | File | Notes |
|---|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `~/.config/Claude/…` (Linux, not confirmed) | `.mcpb` extensions and remote custom connectors are not in this file and cannot be wrapped locally |
| Claude Code | `~/.claude.json` (user and local entries) | project `.mcp.json` is repository content and is never rewritten |
| Cursor | `~/.cursor/mcp.json` | the project file is never rewritten |
| Codex | `~/.codex/config.toml` | a narrow editor changes only `command`/`args` (or `url` and auth) of `[mcp_servers.<name>]`, and refuses, printing the snippet, on comments inside the table, multi-line values, arrays of tables or dotted keys |
| Gemini CLI | `~/.gemini/settings.json` | `trust: true` is removed from wrapped entries; every URL key of an entry (`httpUrl`, `url`, `serverUrl`) points at the gateway (the upstream is `httpUrl` when present); project settings win and are never rewritten |
| VS Code | user-profile `mcp.json` (`servers`), `~/.copilot/mcp-config.json` | workspace files are never rewritten |
| ChatGPT apps, claude.ai connectors | configured in the vendor's cloud | nothing to wrap locally (needs a hosted gateway, not part of this project) |

A wrapped stdio entry runs the firewall's own code under node, with the
client's environment plus the entry's `env`, and node enables a compile cache
named by `NODE_COMPILE_CACHE` before any firewall code runs (a forged cache
entry would be code run inside the gateway). So every wrapped stdio entry sets
`NODE_COMPILE_CACHE` to `""` in its `env` (empty, which node ignores). A
value the entry itself set is moved to
`LAUNCHSAFE_FIREWALL_UPSTREAM_NODE_COMPILE_CACHE`, and the wrapper gives it
back to the server it starts as `NODE_COMPILE_CACHE`, so only the server's own
node uses it; unwrapping puts it back where it was. A value inherited from the
client's environment (not the entry) no longer reaches the server, because the
entry's empty value wins. In Codex's TOML the editor adds `NODE_COMPILE_CACHE
= ""` to a one-line `env = { … }`, under `[mcp_servers.<name>.env]`, or as a
new `env` line, and refuses an entry that sets `NODE_COMPILE_CACHE` itself or
passes it through `env_vars`. `doctor` fails ("gateway wrapper") for a wrapped
entry without it (wrapped by an earlier build, or edited since); `mcp
wrap-config` again adds it in place to an entry whose recorded hash still
matches, keeping the recorded original for unwrap, and an edited one is
reported (unwrap it and wrap it again).

An entry the client could read two ways is left as it is, with the reason: a
`command` next to a URL, URL keys that name different servers, or some URL keys
already pointing at the gateway and others not.

`launchsafe-firewall gateway status` shows what is wrapped, servers that are
not, hook-mode entries whose hook is gone, and the count of withheld results.
`gateway quarantine --json` leaves out each record's preview (the start of the
withheld text) unless it runs in an interactive terminal.

Server requests whose id starts with `lsfw-` are refused: those ids are the
gateway's own (its approval questions to the client among them), and a
server's request with one would share the client's answers with them.
Decision-log text the server or call chose (`what`, `problem`, `tool`) is
written with credentials and URL query values masked.

## Protecting the wrapped configuration

For agents the firewall hooks: a Write or Edit that removes or changes a
wrapped entry is **FW-TAMPER**; one that adds an unwrapped server is
**FW-AGENT-SETTINGS** (held as a proposal under FW-INSTRUCTIONS-HELD when the session is untrusted); a shell write to a
wrapped file is FW-TAMPER, and so is one that reaches it through its directory
(moving or removing the directory, copying or extracting over it);
`claude mcp`, `codex mcp` or `gemini mcp` naming a server the gateway wraps in
that agent's file (`remove`, or `add` over it) is FW-TAMPER (other `mcp`
subcommands stay FW-AGENT-SETTINGS), and so is the same command run through a
package runner (`npx`, `bunx`, `pnpx`, `pnpm dlx`, `yarn dlx`, `npm exec`,
`bun x`, with `@anthropic-ai/claude-code`, `@openai/codex`,
`@google/gemini-cli` or `cursor-agent`, with or without a version or
`--package`); `kill`/`pkill` of the firewall's processes,
including `mcp wrap` and `mcp serve`, is FW-TAMPER. A change made in the
desktop app itself, or by a program the firewall cannot see, is caught by
`gateway status` and by the pins (an unwrapped server never shows up under its
`gw-<client>` key).

## Policy (`gateway`)

```jsonc
"gateway": {
  "enabled": true,
  "mode": "auto",                 // "auto" (= full) | "full" | "hook" (user or managed only)
  "askVia": "queue",              // "queue" | "elicitation" (verified clients only)
  "toolChanges": "hide",          // "hide" | "taint"
  "responses": { "stripHidden": true, "withhold": "strong", "annotate": true, "maxScanBytes": 4194304, "oversize": "deliver" },
  "sampling": "deny_untrusted",   // "deny" | "deny_untrusted" | "allow"
  "unknownMethods": "deny",       // "deny" | "allow" (user or managed only)
  "httpSessionIdleMinutes": 60,
  "clients": {}                   // { "<client>": { "workspaceRoots": ["/abs/path"] } }, user or managed only
}
```

A project file may only tighten (`mode: "full"`, `askVia: "queue"`,
`toolChanges: "hide"`, the response switches on, a larger `maxScanBytes`,
`oversize: "withhold"`, `sampling` towards `"deny"`, a longer idle time).
The key belongs to policy schema version 3 (see [policy.md](policy.md))
and is still read from a version 2 file, with the same meaning.

## Honest limits

- **MCP only.** Native tools (shell, file edits, built-in web fetch) never pass
  through the gateway; the hooks cover them for the agents the firewall
  supports, and nothing covers Claude Desktop's or ChatGPT's own tools.
- **A server added directly bypasses the gateway** unless managed configuration
  forbids it. `gateway status` reports unwrapped entries; it cannot stop them.
- **Connectors called from a vendor's cloud** cannot be reached locally.
- **No conversation boundaries**: taint lasts for the client process (stdio),
  or over HTTP until `gateway reset` (a clean session is renewed after an idle
  gap; a tainted one is kept). Stricter, not looser.
- **Scanning is pattern-based**: hidden text and known agent-directed phrasings,
  not paraphrased or semantic injections, not text in images, audio or binary
  blobs. A result past `maxScanBytes` is delivered with only its first part
  checked unless `oversize` is `"withhold"`. The taint rule is what stops a
  fooled model sending data out.
- **Approval needs a retry**; elicitation asks are off until a client is
  verified.
- **A Codex HTTP wrap drops `bearer_token_env_var` and `http_headers`.** That
  breaks the server and fails closed.
- **Not built yet**: HTTP for a legacy client's standalone GET stream,
  era translation of input requests, a login item for `mcp serve`, and a
  benchmark. One Node process per wrapped stdio server.
