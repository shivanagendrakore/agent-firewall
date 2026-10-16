# The vault

The vault keeps credentials and sensitive personal or financial values (API
tokens, OAuth tokens, a card, an IBAN) in your operating system's secret store,
records where each one may go, and makes the firewall treat every stored value
as a credential in the outbound data it reads (with the limits given below).

The agent writes a **reference** such as `vault://github/token` or
`vault://bank/primary#iban` where the value would go; the firewall puts the
value in only at the moment an allowed action runs, only for destinations that
secret is bound to, and scrubs it back to the reference in everything the model
reads.

**Built:** the stores, the signed index, bindings, the commands below, the
data-loss rule for stored values (FW-VAULT-EGRESS), doctor's checks, and
substitution: through the MCP gateway (every client), and through the hooks for
shell commands where the agent can rewrite tool input (Claude Code: documented
by Claude Code, not captured live; see [limitations.md](limitations.md)). Upstream
OAuth tokens from `mcp login` live in the vault.

`launchsafe-firewall run --env NAME=vault://… -- <command>` is built with
`run` (`docs/run.md`, "Secrets by reference"): with the hook's ticket it runs
Claude Code's rewritten command (single-use, bound to the exact command, output
filtered back to the references); without one, a person's run gets a secret
only for a command it is bound to with `vault allow <name> --process`.
`vault import --from-config`, `vault unlock/lock` and the sandbox probes are
still to come.

## Commands

| Command | Who | Does |
|---|---|---|
| `vault add <name> [--kind K] [--fields a,b] [--confirm always\|never]` | you (terminal, approval passphrase) | reads each field with echo off, stores it, records its fingerprint, re-signs the index |
| `vault allow <name> --host H [--allow-in-url] [--allow-http] \| --mcp S[:tool[:arg]] \| --process "<argv>"` | you | adds a binding |
| `vault revoke <name> <n>` | you | removes binding `n` (as `vault list` numbers them) |
| `vault rotate <name>` | you | replaces every field's value and fingerprint; bindings stay |
| `vault remove <name>` | you (and a typed "yes") | deletes the values and the entry |
| `vault list [--json]` (also `vault`) | anyone, agents included | names, kinds, fields, stores, bindings; never a value or a fingerprint |

The changing commands refuse to run from a script or from inside an agent (no
terminal, or a descendant of the agent's process), and the firewall denies them
as FW-TAMPER when an agent tries. They need an approval passphrase
(`approver init`): it unlocks the key that signs the index.

Names are 1 to 4 parts of lower-case letters, digits, `_` and `-`, joined by
`/` (`github/token`, `bank/primary`). A reference is `vault://<name>` or
`vault://<name>#<field>`, and it must start on a word boundary
(`https://example.com/vault://docs` is not one).

Kinds and their default fields: `credential` and `oauth` (`value`), `card`
(`number`, `expiry`, `cvc`, `name`), `iban` (`iban`, `bic`, `holder`),
`national_id` and `personal` (`value`). Financial values are in scope.

## Where values are stored

| Store | When | Write | Protection from programs running as you |
|---|---|---|---|
| macOS Keychain | macOS | `/usr/bin/security -i`, the command on standard input, the value as `-X <hex>`: never in argv or `ps` | `--confirm always` (the default for card, iban, national_id, personal) creates the item with an empty access list (`-T ""`), which Apple documents as allowing no application without a prompt, so a read should show the keychain dialog (not observed in any test; the manual test only writes and deletes such an item). `--confirm never` (the default for credential and oauth) trusts `/usr/bin/security`, so any program running as you can read it through that tool. Never click "Always Allow" on that dialog |
| Linux Secret Service | Linux with a D-Bus session bus | `secret-tool store`, the value on standard input | none per application: once your login keyring is unlocked, any program on the session bus can read it. Run the agent in its OS sandbox (no bus socket) |
| Encrypted file (`vault/store.enc`) | Linux without a Secret Service, only with `"vault": { "fileFallback": true }` in your user policy (off by default) | AES-256-GCM per value under a random data key, wrapped with a key from scrypt over the approval passphrase | against backups and accidental reads only |

Helpers run only from fixed root-owned system paths, never through `PATH`.
`approver rotate` re-signs the index with the new key (only if it verified
against the old one) and re-wraps the file store's data key.

## The signed index

`vault/index.json` lists each secret's name, kind, fields, store, confirmation
setting, bindings and per-field fingerprints (length, two rolling hashes and a
SHA-256 prefix; never the value). It is signed with the approver key and
verified against the key the hook command pins. If the signature does not verify
(an edit on disk, a different key), no secret is bound to anything, the values
are still recognised and denied everywhere, and `doctor` fails. If the index
cannot be read at all (not JSON, not a valid index), no stored value could be
recognised, so it is not treated as "no vault". In both cases, while the vault
is on, every send and every fetch that carries data asks (FW-VAULT-INDEX), on
the hook path, through the gateway and in the library alike, until the index is
repaired; `doctor` says which it is. A change is never built on an index that
does not verify, so a forged binding cannot be laundered by the next
`vault allow`.

Bindings live only in the signed index, never in a policy file, so no repository
can bind a secret to its own host.

| Binding | Matches |
|---|---|
| `--host api.github.com` | that exact host, over https; `*.example.com` matches its subdomains (not the apex). A value inside the URL itself also needs `--allow-in-url`; plain http needs `--allow-http` |
| `--mcp linear[:create_*[:headers.token]]` | calls to that MCP server, and the tool pattern when given |
| `--process "npm publish"` | a program and arguments that `run --env` may give the secret to (`docs/run.md`); `*` only as a whole last word, never as the program |

## A stored value is always a credential (FW-VAULT-EGRESS)

Any outbound payload (a request body or URL, MCP arguments, a message) that
contains a stored value, in the clear or base64, base32, hex, URL or DNS-label
encoded, going to a destination that secret is not bound to, is **denied**. The
rule ignores `dataAllowHosts` and `sendAllowHosts`: the per-secret binding is the
narrower statement. It applies in every session, trusted or not, and is notified
like other data blocks. This covers a value that reached the agent some other
way, such as a `.env` file it read. Fields shorter than 12 characters (a CVC, an
expiry date) cannot be fingerprinted; `vault add` says which. The contents of a
file a command uploads (`curl -d @file`, `-T`, `-F`) are not read
([limitations.md](limitations.md#data-leaving-the-machine)).

A stored value also counts as a secret elsewhere: tool output that shows one
makes the session sensitive and remembers its fingerprint, and a file written
with one is a secret file (publishing it later needs you).

The keychain and keyring tools naming the firewall's service
(`security ... -s launchsafe-firewall`, `secret-tool ... service
launchsafe-firewall`, or the firewall's item label) are FW-TAMPER from inside an
agent: the store is the firewall's data. The service name is part of the
firewall's self-protection identity (`vaultServices`), and a lookup that does
not say which service it means reaches the vault's items too, so it is
FW-TAMPER as well: `security find-generic-password|delete-generic-password`
without `-s` or with a service the firewall cannot read, `security
dump-keychain -d`, `security -i` on commands it cannot see, and `secret-tool
lookup|search|clear` without a `service` attribute.

A vault block (FW-VAULT-EGRESS) sends the "Blocked" data notification, through
every agent. The dashboard's Vault tab lists names, kinds, fields, stores and
bindings, never a value, and hides any line that would show one.

## Substitution

### The rules

A reference only matters where it would leave the machine: in a request's URL
or body, a shell command that sends data, MCP arguments. Anywhere else (a file
the agent writes, a comment) it is just text: nothing is substituted and no rule
applies. Where it would leave:

| Rule | When | Outcome |
|---|---|---|
| **FW-VAULT-UNBOUND** | the reference names no stored secret (a typo, `vault://github/tokn`) or a field the secret lacks; the destination is not one the secret is bound to (for MCP: server, tool and argument path); the value would go into a URL without `--allow-in-url` (also `curl -G` with the reference in the data); a URL of the sending command that is plain http without `--allow-http`, or a local address (loopback, `localhost`, `*.localhost`, link-local, `0.0.0.0`, numeric forms) when the bound host is not itself local; the index does not verify; MCP arguments with more than 1000 references, or one nested deeper than 64 levels (they cannot all be checked, so none is substituted) | deny ("vault://github/token may only be used with host api.github.com") |
| **FW-VAULT-UNSUPPORTED** | a position the firewall cannot fill in without the agent seeing the value: a WebFetch URL or search query; single quotes, `$'…'`, backticks, a command or parameter substitution or a here-document in a shell command; a reference in a part of the command that sends nothing (`echo … > file`, an assignment, a redirection); a reference given to anything but `curl` or `wget` named as such (a shell, `env`, `timeout`, `./curl`, a path); a variable or substitution anywhere in that curl or wget command; a command that names the substitution variables (`__LSV_…`, any case), which is a read of the secret; an agent that cannot rewrite tool input; an MCP server not behind the gateway; an OAuth token anywhere but the gateway's Authorization header | deny, with the `run --env` hint |
| **FW-VAULT-OPTION** | the curl or wget command that would get the value carries an option that is not on the allowlist below (`-L`, `-v`, `--trace`, `-K`, `-x`/`--proxy`, `--resolve`, `--connect-to`, `-k`, `wget -i`, `-w '%output{…}'`, ...), `-o`/`--output`/`-O` or wget `-O`/`--output-document` to a file (anything but `-` or `/dev/null`) in a command that carries any reference, wget without `-O` (which saves a file named after the URL) in a command that carries any reference, a URL not written out as `http(s)://host/...`, or a prefix assignment other than `LANG`, `LANGUAGE`, `LC_*`, `TZ`, `NO_COLOR`, `TERM`, `COLUMNS` (`https_proxy=`, `HOSTALIASES=`, `CURL_HOME=`, `PATH=` ...) | deny, naming the option, with the `run --env` hint |
| **FW-VAULT-APPROVE** | a kind in `vault.approveKinds` (cards, IBANs, national ids, personal values); any substitution in an untrusted session (`vault.approveWhenUntrusted`); a keychain item stored with per-use confirmation in a session no one is watching (held before any keychain dialog) | approve: asked, or queued when unattended; the approval covers that exact action once |

Every other rule judges the action exactly as if the reference were text, so a
bound substitution in an untrusted session still needs FW-SEND's approval. The
question names the reference, the kind and the destination, never the value.
Values are read from the store only after the final verdict is allow (an
answered ask, or an approved retry); nothing is read for a denied or held
action. A value that cannot be read (a locked store, a missing item, the file
store, whose passphrase no unattended process has) denies the action: it is
never sent with the reference in place of the value.

### Where substitution works, per agent

| Path | Claude Code | Codex | Gemini CLI | Cursor | Claude Desktop, VS Code and other MCP clients |
|---|---|---|---|---|---|
| MCP arguments through the gateway (answers scrubbed) | yes (hook mode: the hook's grant) | yes (hook mode) | yes (hook mode) | yes (hook mode) | yes (full mode) |
| A reference in a shell command (hook rewrite) | yes: `updatedInput`, a ticketed `run` (documented by Claude Code, not captured live; see limitations.md) | refused (FW-VAULT-UNSUPPORTED): the documented input rewrite is not verified by a captured fixture | refused: same | refused: no verified input rewrite | n/a |
| Second scrub of tool output by the hook | yes (`updatedToolOutput`; not captured live) | no output replacement | no output replacement | no output replacement | the gateway rewrites answers |
| `run --env` typed by the agent | refused (FW-TAMPER: `run` is person-only); the person runs it | refused, same | refused, same | refused, same | n/a |

Each adapter states this as `supportsUpdatedInput` (true only for Claude Code);
`vault.shellRewrite: "off"` refuses the rewrite everywhere.

### The gateway

See [gateway.md](gateway.md#vault-substitution). Each MCP substitution
carries the argument path it was checked at, and the value goes in at that path
only: the same reference in another argument stays text, and a
substitution without a path (an older grant) is refused. In full mode the gateway
decides and substitutes; in hook mode the client's hook decides and leaves a
single-use grant for exactly that call, and the gateway substitutes only with
one. Every answer, error, notification and server request is scrubbed before
the scanner, the quarantine store, the post-tool step or the client sees it,
and the wrapped server's stderr is scrubbed line by line. A value still
detectable after scrubbing (inside a larger encoded blob), or an answer nested deeper than 64 levels (not scrubbed past that), withholds the whole
answer.

### The hook rewrite (Claude Code)

A Bash command such as

```sh
curl -H "Authorization: Bearer vault://github/token" https://api.github.com/user
```

is allowed (when bound) with `updatedInput`:

```sh
launchsafe-firewall run --ticket <T> --env __LSV_1=vault://github/token -- /bin/sh -c '/usr/bin/curl -q --variable %__LSV_1 --expand-header '\''Authorization: Bearer {{__LSV_1}}'\'' https://api.github.com/user'
```

(`/usr/bin/curl` stands for the absolute path the hook finds: see below.)

**The value is never an argument.** Any user on the machine can read every
process's arguments (`ps`), so neither the shell nor curl or wget is ever given
the value on its command line:

- curl imports the variable from its own environment (`--variable %__LSV_1`)
  and puts it into the option itself (`--expand-header`, `--expand-data`,
  `--expand-user`, `--expand-url`, ...: the `{{__LSV_1}}` is curl's, not the
  shell's, so the shell leaves it alone). This needs **curl 8.3 or later**; the
  hook runs `curl --version` on the curl it found and refuses an older one.
  Text around a reference that holds `{{`, or a backslash just before it, is
  refused (curl's expansion would read it).
- wget has no such expansion, so the options that carry a value (`--header`,
  `--post-data`, `--body-data`, `--user`, `--password`, `--http-user`,
  `--http-password`) move into a configuration that the shell's own `printf`
  (a builtin: no new process, no arguments) writes into a pipe, and wget reads
  it with `--config=/dev/stdin` (which also replaces `.wgetrc`):
  `printf '%s\n' "header = Authorization: Bearer ${__LSV_1}" | /usr/bin/wget --config=/dev/stdin --max-redirect=0 -qO- https://api.github.com/user`.
  A reference in a wget URL is refused (use curl). Whitespace at the ends of a
  wget value is trimmed by wget's configuration reader. To verify against your
  wget (and wget2, which some distributions install as `wget`): the
  configuration syntax and `--config` reading a pipe.

What stays: while it runs, the sender's **environment** holds the value, and
any process running as you can read another process's environment (`ps eww`
on macOS, `/proc/<pid>/environ` on Linux). That is the same exposure as the
vault's own store to a program running as you (see the end of this page);
other users on the machine cannot read it.

Only the curl or wget command that carries the references gets the values. Each such simple command is replaced, where it stands, by its own
ticketed run; everything around it (pipes, `&&` lists, redirections) stays in
the agent's shell as written and reads only the filtered output:

```sh
cd api && curl -sS -H "Authorization: Bearer vault://github/token" https://api.github.com/user > me.json | jq .name
# becomes
cd api && launchsafe-firewall run --ticket <T> --env __LSV_1=vault://github/token -- /bin/sh -c '/usr/bin/curl -q --variable %__LSV_1 -sS --expand-header '\''Authorization: Bearer {{__LSV_1}}'\'' https://api.github.com/user' > me.json | jq .name
```

- The values exist only in that one process's environment: no other command
  of the agent's (a `printenv`, a `rev`, a `git commit -m`) runs with them, and
  a command that names `__LSV_` is refused before anything runs.
- The program is named by its absolute path, found in the PATH the hook itself
  was started with (which a command of the agent cannot change) or the system
  directories; relative PATH entries are skipped. The file and its directory must
  be root-owned and not group- or world-writable (a user-owned Homebrew or
  `~/.local/bin` curl is skipped). A PATH or a `curl` script the agent set up is
  never what gets the value. Not found: denied.
- `curl -q` comes first (and wget reads only `--config=/dev/stdin`), so a
  `.curlrc` or `.wgetrc` the agent wrote cannot add trace or log options.
- Every word of that command is written out: the rewrite rebuilds it from
  literal words, so it carries no variable or substitution that could be
  computed at run time. Two sending commands get two tickets.
- wget also gets `--max-redirect=0`: it follows redirects by default and
  would resend `--header` there. curl follows none without `-L`, which is
  refused.
- The ticketed run starts the sender with only `PATH`, `HOME`, `LANG`,
  `LC_*`, `TERM` and `TZ` from the agent's shell, plus the values: nothing that
  changes routing, name resolution, TLS trust or config (the `*_proxy` family,
  `HOSTALIASES`, `RES_OPTIONS`, `SSLKEYLOGFILE`, `CURL_CA_BUNDLE`,
  `SSL_CERT_FILE`, `CURL_HOME`, `WGETRC`, `XDG_CONFIG_HOME`, `LD_*`,
  `DYLD_*`, ...) and nothing else the agent exported.
- The ticket is bound to the agent the hook ran under (the nearest of the
  hook's parent processes still alive when it is spent must be a parent of the
  `run` that spends it): another process of yours that reads the ticket off
  the agent's command line cannot spend it.

### The option allowlist

A value travels only in a request to the binding's own host, and curl or wget
never write it to disk or to the output. So a curl or wget command that carries
a reference is rewritten only when **every** option is on this list
(`src/engine/vault-options.ts`); anything else is FW-VAULT-OPTION, naming the
option. Long options are matched by their full name only (an abbreviation is
refused); curl takes no `--name=value` form, wget does. Short options may be
clustered (`-sSf`, `-XPOST`, `-qO-`).

| curl | wget | Notes |
|---|---|---|
| `-s` `--silent`, `-S` `--show-error`, `-f` `--fail`, `--fail-with-body`, `--no-progress-meter`, `--compressed` | `-q` `--quiet`, `-nv` `--no-verbose`, `--content-on-error`, `--no-config` | |
| `-i` `--include`, `--show-headers`, `-I` `--head` | `-S` `--server-response` | response headers only |
| `-X` `--request` | `--method` | a single word |
| `-H` `--header` | `--header` | may carry a reference; curl's `-H @file` is refused |
| `-d` `--data`, `--data-raw`, `--data-binary`, `--data-ascii`, `--data-urlencode`, `--json` | `--post-data`, `--body-data` | may carry a reference; `@file` is fine, a reference after `@` is refused |
| `-u` `--user` | `--user`, `--password`, `--http-user`, `--http-password` | may carry a reference |
| `-G` `--get` | | moves the data into the URL: a reference there needs `--allow-in-url` |
| `-A` `--user-agent` | `-U` `--user-agent` | |
| `-m` `--max-time`, `--connect-timeout`, `--retry` | `-T` `--timeout`, `-t` `--tries` | numbers only |
| `-o` `--output`, `-O` `--remote-name` | `-O` `--output-document` | refused whenever the command carries any vault reference, unless the target is `-` (stdout) or `/dev/null`: a saved response is not filtered, and a server that echoes the request would write the value into the file (print to stdout and redirect in the shell instead, which `run`'s filter covers); wget without `-O` is refused the same way whenever the command carries any reference, because it saves the response to a file named after the URL (`wget -qO-` and `-O /dev/null` work) |
| `-w` `--write-out` | | only `%{name}` from a fixed list of transfer variables (`http_code`, `response_code`, `http_version`, `time_*`, `size_*`, `speed_*`, `content_type`, `num_*`, `remote_ip`, `remote_port`, `scheme`, `exitcode`, `method`, `stdout`, `stderr`), `%%` and literal text; never `%output{}`, `%header{}`, `%{url}`, `%{json}` or `@file` |
| `--url` | `--max-redirect=0` | |

A reference may appear only in a header, the data, the credentials or a URL.
Every URL must be written out as `https://host[:port]/...` (or `http://` with
`--allow-http`), with no user info, no globbing in the host and no backslash,
and every URL of the command must be the bound host (a second URL is checked
too). Refused with a reason of their own: `-L`/`--location` (redirects are not
re-checked, and curl resends custom headers), `--resolve`, `--connect-to`,
`-x`/`--proxy`, `--preproxy`, `--socks*`, `--doh-url`, `--dns-servers`,
`--unix-socket`, `--interface`, `-v`, `--trace`, `--trace-ascii` (to a file or
to the output), `-K`/`--config`, `--variable`, `-k`/`--insecure`, `--next`;
wget `-i`/`--input-file`, `-e`, `-d`, `--no-check-certificate`, `-r`, `-m`.

The rewritten input carries variable names, references and tickets, never a
value. Claude Code still applies your own permission rules to it. An asked
substitution (an IBAN) returns `ask` with the same rewritten input.

### The interface for `run` (tickets)

`src/runtime/vault/tickets.ts`. The hook stores
`vault/tickets/<sha256(T)>.json` with the hash of the exact `--env` pairs and
argv (`ticketArgvHash(env, argv)`), the references, the session and an expiry
(`vault.ticketSeconds`, three minutes for an asked action), and the issuing
hook's parent processes. `run` calls
`consumeTicket(l, T, env, argv)`: the ticket is taken atomically and refused
when unknown, already used, expired, issued for another command, or spent by a
process the agent did not start (`run` then exits 77 and logs `vault_denied`).
Only the ticket's hash is on disk. Gateway grants are counted up and down
under a lock, so two hooks deciding the same call at once both count.
`readValues()` and `logUse()` in `src/runtime/vault/substitute.ts`, and
`scrubText()` in `src/engine/vault-scrub.ts` (for the streaming output filter),
are what `run` reuses.

### Output scrubbing

What the model reads is scrubbed back to the reference: by the gateway for MCP
(the substituted values and their encodings, plus every fingerprinted value),
and by PostToolUse for Claude Code (`updatedToolOutput`: every fingerprinted
value in the clear; output in which a value is still detectable is replaced by
a withheld note). Dumps are judged whole: the rows of a hex or ASCII dump
(`curl --trace -`, `--trace-ascii -`, `hexdump -C` with its double space after
the eighth byte, `xxd`) are joined before the check, so a value split over rows,
or spelled as spaced hex, is still found.
`run`'s streaming filter holds a dump's rows until the dump ends and replaces a
dump that carries a value with the withheld note; a dump without one passes
unchanged. curl's trace and verbose options are refused before anything runs
(FW-VAULT-OPTION), so this is the second line. Fields shorter than 12 characters have no fingerprint, so only
the gateway, which knows the value for the call in flight, can scrub them (as
whole tokens).

### Upstream OAuth tokens

`mcp login` stores the tokens as `vault://mcp/<server>` (kind `oauth`, bound
`mcp:<server>`) when it can sign the entry; the gateway sends them only as the
upstream `Authorization` header, and refreshes them in the store unattended
(their fingerprints in the unsigned `vault/oauth-prints.json`, which only adds
detection). See [gateway.md](gateway.md).

### SessionStart

With `vault.listInContext`, the agent is told which references exist and where
each may go, names and destinations only: "secrets are available by reference
… vault://github/token (api.github.com); vault://bank/primary#iban
(api.bank.example, needs approval)".

## Audit

Entries in the signed decision log, never a value or a fingerprint:

| Entry | Fields |
|---|---|
| `vault_change` | `op` (`add`, `allow`, `revoke`, `remove`, `rotate`, `resign` after `approver rotate`, `refresh` for an OAuth token), `name`, `kind`, a binding summary |
| `vault_use` | `session`, `ref`, `kind`, `via` (`gateway`, `hook`), `destination` (host or `mcp:<server>:<tool>`), `binding`, `action` (the action hash), `verdict` |
| `vault_denied` | `session`, `refs`, `rule` (FW-VAULT-UNBOUND, -EGRESS, -UNSUPPORTED) or `problem` (a store that could not be read, a missing grant), `destination` |
| `vault_scrub` | a gateway answer withheld because a vaulted value could not be scrubbed |

Queue items keep the references, never values; notifications are fixed text.

## Policy

| Key | Default | A project file may | User or managed only |
|---|---|---|---|
| `vault.enabled` | `true` | nothing (a repository must not switch off your vault) | set `false` |
| `vault.confirmDefault.<kind>` | `always` for card, iban, national_id, personal; `never` for credential, oauth | set `"always"` | set `"never"` |
| `vault.fileFallback` | `false` | set `false` | set `true` |
| `vault.approveKinds` | card, iban, national_id, personal | add kinds | remove kinds |
| `vault.approveWhenUntrusted` | `true` | set `true` | set `false` |
| `vault.shellRewrite` | `"auto"` | set `"off"` | either |
| `vault.ticketSeconds` | 30 | lower it (5 minimum) | raise it (up to 120) |
| `vault.listInContext` | `true` | set `false` | either |

## Doctor

`doctor` reports: whether the index verifies against your approval key; how many
secrets and bindings there are, and which secrets are bound to nothing; entries
whose store is not available on this machine; values missing from the macOS
Keychain (checked without reading them, so no dialog); the weaker stores
(Secret Service, file) and financial or personal items stored without per-use
confirmation. Not part of the protection score.

## Honest limits

- A bound host that echoes a request back can return the value; what comes
  back on the output is filtered in the clear and in the encodings above, not
  in arbitrary transformations, and a response saved to a file by curl or wget (plain wget saves one by default) is refused when the
  command carries a reference. Redirects are never followed with a value (`-L` is refused, wget
  gets `--max-redirect=0`).
- The host check is on the name: the system's own resolver decides the
  address. A bound name that resolves somewhere unexpected (your DNS, your
  `/etc/hosts`) gets the value.
- Only curl (8.3 or later) and wget get values from a shell command. For other
  programs, a person binds the secret to the command (`vault allow <name>
  --process`, best with the program's absolute path) and runs it with `run
  --env`; that run's output is not filtered.
- A value is never an argument of any process, but it is in the sender's
  environment while it runs, which any process running as you can read.
- A value over 4096 characters is not fingerprinted, so it is not recognised in
  output or in what leaves. A host binding compares the host name only: it
  ignores the port and a trailing dot.
- The file store opens only with the approval passphrase: a hook or the
  gateway (which have none) can neither read it nor write to it, so a store is
  never created under an empty passphrase.

The vault keeps secrets out of what the agent reads and limits where actions
the firewall sees can send them. It is not a hardware boundary: a program
running as you, outside the sandbox, that the firewall cannot see into can read
your keychain (on Linux always; on macOS only for secrets stored without
per-use confirmation, as Apple documents it, not observed in any test). The
Linux Secret Service store has no live test. Run the firewall with the agent's
sandbox.

## Tests

`test/vault/substitution-engine.test.ts` (the rules, the acceptance and
false-positive rows), `option-allowlist.test.ts` (every allowed option, the
refused options and destinations, ordinary pipes and redirections), `substitution-hook.test.ts` (Claude Code's rewrite,
tickets, grants, refusals for Codex and Gemini CLI, PostToolUse, SessionStart)
and `substitution-gateway.test.ts` (the in-repo fake MCP server in process and
over HTTP on 127.0.0.1: the upstream gets the value, the client and every file
under the firewall's home never do, in any encoding; OAuth tokens and their
refresh). All use the in-memory store.

`test/vault/` runs against an in-memory store behind the same interface, and
checks the real backends' argument building with a recording runner: no test
starts `/usr/bin/security` or `secret-tool`, and the default runner refuses to
while a test marker is set. `test/vault/keychain-manual.test.ts` exercises the
real macOS Keychain under a separate service name, and is skipped unless you run
it on purpose: `LAUNCHSAFE_FIREWALL_VAULT_REAL_KEYCHAIN=1 npx vitest run test/vault/keychain-manual.test.ts`.
