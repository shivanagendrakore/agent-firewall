# Command line

Generated from `src/cliargs.ts` by `scripts/gen-cli-docs.mjs`; do not edit by hand.

Every command parses its arguments against a declared spec before anything runs:

- `--help` or `-h` anywhere (before `--`) prints that command's help and exits 0 without side effects.
- An unknown flag, a missing value, a bad choice or a surplus argument exits 64 with one line on stderr and changes nothing.
- `hook` never exits 64: a malformed hook command exits 2, which blocks the tool (fail closed).
- Commands marked *changes state* are refused when an agent runs them (FW-TAMPER) and, under the test marker, refuse to write under the real home directory.

## launchsafe-firewall install

Register the firewall's hooks in an agent's settings (Claude Code, Codex, Gemini CLI, Cursor).

```
launchsafe-firewall install [--agent claude|codex|gemini|cursor] [--scope user|project|local] [--project DIR] [--no-approver]
launchsafe-firewall install --agent gemini --seatbelt PROFILE [--gemini-package DIR] [--scope user|project] [--project DIR] [--no-approver]
launchsafe-firewall install --managed [--agent claude|codex|gemini|cursor] [--lock-other-hooks] [--print]
launchsafe-firewall install --browser chrome|chromium|edge|brave --extension-id ID [--user-data-dir DIR]
```

| Option | Meaning |
|---|---|
| `--agent claude|codex|gemini|cursor` | which agent's settings (default claude) |
| `--scope user|project|local` | which settings file (Codex, Gemini CLI and Cursor: user or project) |
| `--project DIR` | the project directory (default: the current directory) |
| `--managed` | print managed settings for an administrator to deploy |
| `--lock-other-hooks` | with --managed: also set allowManagedHooksOnly |
| `--print` | with --managed: print the JSON only |
| `--no-approver` | do not offer to set an approval passphrase |
| `--seatbelt permissive-open|permissive-proxied|restrictive-open|restrictive-proxied|strict-open|strict-proxied` | with --agent gemini, macOS: also write ~/.gemini/sandbox-macos-launchsafe.sb, Gemini CLI's own PROFILE plus write access to the hook's state directories only, for gemini -s with SEATBELT_PROFILE=launchsafe (permissive-open is Gemini CLI's default) |
| `--gemini-package DIR` | with --seatbelt: Gemini CLI's package (or its bundle directory) to copy the profile from (default: found from the gemini command on PATH) |
| `--browser chrome|chromium|edge|brave` | set up the link to the LaunchSafe browser extension in this browser (a native messaging host manifest in its per-user directory) instead of agent hooks |
| `--extension-id ID` | with --browser: the LaunchSafe extension's id (32 letters, from the browser's extensions page); the only extension the link answers |
| `--user-data-dir DIR` | with --browser: a browser profile started with --user-data-dir DIR, instead of the browser's default one |

Changes state: yes

## launchsafe-firewall uninstall

Remove the firewall's hooks (needs the approval passphrase when one is set).

```
launchsafe-firewall uninstall [--agent claude|codex|gemini|cursor] [--scope user|project|local] [--project DIR] [--restore-backup [--force]] [--remove-sandbox] [--purge]
launchsafe-firewall uninstall --browser chrome|chromium|edge|brave|all
```

| Option | Meaning |
|---|---|
| `--browser chrome|chromium|edge|brave|all` | remove the browser link's host manifest for that browser (all: every one install recorded) instead of the hooks |
| `--agent claude|codex|gemini|cursor` | which agent's settings (default claude) |
| `--scope user|project|local` | which settings file (Codex, Gemini CLI and Cursor: user or project) |
| `--project DIR` | the project directory (default: the current directory) |
| `--restore-backup` | put each settings file back exactly as it was before the first install (a file install created is removed; the current file is saved as FILE.before-restore.TIMESTAMP first; settings you changed since install are listed and need a yes or --force; this also removes a sandbox profile doctor --fix added) |
| `--force` | with --restore-backup: discard settings you changed since install without asking (the file as it is now is still saved beside it first) |
| `--remove-sandbox` | also remove the sandbox profile doctor --fix installed (it is kept otherwise) |
| `--purge` | also delete the firewall's state directory |

Changes state: yes

## launchsafe-firewall doctor

Check the install and the settings files the firewall can read, and what to fix.

```
launchsafe-firewall doctor [--json] [--project DIR]
launchsafe-firewall doctor --ci [--json] [--project DIR]
launchsafe-firewall doctor --fix [--scope user|project|local] [--dry-run] [--project DIR]
launchsafe-firewall doctor --repair-state [--project DIR]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |
| `--project DIR` | the project directory (default: the current directory) |
| `--ci` | only the checks of whether the firewall's hooks are installed with the exit-2 wrapper, and of the settings files that could switch them off or reach into them (the repository's agent settings, the user's and the managed ones; command-line flags and the agents' own runtime are not seen); strict: not installed, watch mode on, or a policy error also fails; no score, no probes; exit 1 when one fails, 0 otherwise (for a CI job or a pre-commit check) |
| `--fix` | offer fixes after showing each change: Claude Code's sandbox profile from your policy (needs the approval passphrase), pinning the approval key in the hook, a package cooldown in your user config, downloading malicious-package data |
| `--scope user|project|local` | with --fix: which Claude Code settings file gets the sandbox profile (default: user) |
| `--repair-state` | rebuild a damaged install.json from the agent settings files that hold the firewall's hooks (the damaged file is kept beside it; person-run, needs the approval passphrase) |
| `--dry-run` | with --fix: print the changes and exit without writing anything or asking for the passphrase |

Changes state: no, except with --fix or --repair-state

## launchsafe-firewall update

Download the malicious-package data (OSV MAL- entries) used to check installs; the only command that downloads data without a prompt (doctor --fix offers the same download after you confirm; decisions make no network calls unless you pair a phone, which is experimental; run is a network proxy).

```
launchsafe-firewall update [--source URL|DIR] [--ecosystem LIST]
```

| Option | Meaning |
|---|---|
| `--source URL|DIR` | where to fetch <Ecosystem>/all.zip from (default: OSV's public bulk exports) |
| `--ecosystem LIST` | comma-separated ecosystems (default: npm,PyPI,crates.io,RubyGems,Go,Maven,NuGet,Packagist) |

Changes state: yes

## launchsafe-firewall status

Sessions, held actions and recent decisions.

```
launchsafe-firewall status [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall session

Stopped sessions and agents, and why (same as session list).

```
launchsafe-firewall session [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall session list

The sessions and agents that are stopped, by whom and why.

```
launchsafe-firewall session list [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall session stop

Stop a session: every later tool call it makes through the firewall is blocked (a command already running keeps running), until a person resumes it.

```
launchsafe-firewall session stop <session> [--reason TEXT]
```

| Option | Meaning |
|---|---|
| `--reason TEXT` | a note for the log and session list |

Changes state: yes

## launchsafe-firewall session resume

Resume a stopped session (needs the approval passphrase).

```
launchsafe-firewall session resume <session>
```

Changes state: yes

## launchsafe-firewall agent stop

Stop every session of an agent (claude, codex, gemini, cursor, gateway, or a local API agent id) until a person resumes it.

```
launchsafe-firewall agent stop <agentId> [--reason TEXT]
```

| Option | Meaning |
|---|---|
| `--reason TEXT` | a note for the log and session list |

Changes state: yes

## launchsafe-firewall agent resume

Resume a stopped agent (needs the approval passphrase).

```
launchsafe-firewall agent resume <agentId>
```

Changes state: yes

## launchsafe-firewall queue

Actions held for a person (same as queue list).

```
launchsafe-firewall queue [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall queue list

List held actions.

```
launchsafe-firewall queue list [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall queue show

One held action, with the diff for a proposed change.

```
launchsafe-firewall queue show <id> [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall queue review

Go through every held action (needs the approval passphrase).

```
launchsafe-firewall queue review [--i-saw-truncated]
```

| Option | Meaning |
|---|---|
| `--i-saw-truncated` | approve a held action even though parts of it were cut and are not shown (refused otherwise) |

Changes state: yes

## launchsafe-firewall queue approve

Allow held actions once (needs the approval passphrase).

```
launchsafe-firewall queue approve <id>... [--i-saw-truncated]
```

| Option | Meaning |
|---|---|
| `--i-saw-truncated` | approve a held action even though parts of it were cut and are not shown (refused otherwise) |

Changes state: yes

## launchsafe-firewall queue reject

Reject held actions.

```
launchsafe-firewall queue reject <id>...
```

Changes state: yes

## launchsafe-firewall friction

How often the firewall asked or held actions, by rule and by agent, and which actions you approved every time (same as friction report).

```
launchsafe-firewall friction [--json] [--days N]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |
| `--days N` | only the last N days (default: everything in the decision log) |

Changes state: no

## launchsafe-firewall friction report

The friction report from the decision log.

```
launchsafe-firewall friction report [--json] [--days N]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |
| `--days N` | only the last N days (default: everything in the decision log) |

Changes state: no

## launchsafe-firewall allow

Your learned choices for this project: always or never for one exact action (same as allow list).

```
launchsafe-firewall allow [--json] [--all] [--project DIR]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |
| `--all` | every project's choices |
| `--project DIR` | the project directory (default: the current directory) |

Changes state: no

## launchsafe-firewall allow list

List learned choices and the actions ready for "always in this project".

```
launchsafe-firewall allow list [--json] [--all] [--project DIR]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |
| `--all` | every project's choices |
| `--project DIR` | the project directory (default: the current directory) |

Changes state: no

## launchsafe-firewall allow add

Always allow a low-risk action you approved repeatedly, in its project only (needs the approval passphrase).

```
launchsafe-firewall allow add <code>
```

Changes state: yes

## launchsafe-firewall allow never

Never allow an asked action in its project (it is blocked from then on).

```
launchsafe-firewall allow never <code>
```

Changes state: yes

## launchsafe-firewall allow remove

Remove a learned choice (removing a "never" needs the approval passphrase).

```
launchsafe-firewall allow remove <id>
```

Changes state: yes

## launchsafe-firewall pins

MCP servers' pinned configuration, tools and descriptions, and changes waiting for review (same as pins list).

```
launchsafe-firewall pins [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall pins list

List MCP pins and pending changes.

```
launchsafe-firewall pins list [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall pins accept

Accept the pending changes of MCP servers after review (needs the approval passphrase).

```
launchsafe-firewall pins accept <server>...
```

Changes state: yes

## launchsafe-firewall scratch

Name patterns of throwaway targets whose deletion you may approve (same as scratch list).

```
launchsafe-firewall scratch [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall scratch list

The scratch-target patterns, and whether the list is signed.

```
launchsafe-firewall scratch list [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall scratch add

Declare a name pattern throwaway, e.g. app_*_test (needs the approval passphrase).

```
launchsafe-firewall scratch add <pattern>
```

Changes state: yes

## launchsafe-firewall scratch remove

Remove a scratch-target pattern (needs the approval passphrase).

```
launchsafe-firewall scratch remove <pattern>
```

Changes state: yes

## launchsafe-firewall hosts

The hosts approved for this project (same as hosts list).

```
launchsafe-firewall hosts [--project DIR] [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |
| `--project DIR` | the project directory (default: the current directory) |

Changes state: no

## launchsafe-firewall hosts list

The hosts approved for this project, and the knownHosts setting in effect.

```
launchsafe-firewall hosts list [--project DIR] [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |
| `--project DIR` | the project directory (default: the current directory) |

Changes state: no

## launchsafe-firewall hosts allow

Approve hosts for this project, so contacting them does not ask (knownHosts).

```
launchsafe-firewall hosts allow <host>... [--project DIR]
```

| Option | Meaning |
|---|---|
| `--project DIR` | the project directory (default: the current directory) |

Changes state: yes

## launchsafe-firewall hosts remove

Take hosts off this project's approved list.

```
launchsafe-firewall hosts remove <host>... [--project DIR]
```

| Option | Meaning |
|---|---|
| `--project DIR` | the project directory (default: the current directory) |

Changes state: yes

## launchsafe-firewall hosts review

The hosts knownHosts watch mode recorded for this project, proposed as its list.

```
launchsafe-firewall hosts review [--project DIR] [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |
| `--project DIR` | the project directory (default: the current directory) |

Changes state: no

## launchsafe-firewall hosts accept

Approve the hosts hosts review proposes (all of them with --all, or the ones named).

```
launchsafe-firewall hosts accept --all [--project DIR]
launchsafe-firewall hosts accept <host>... [--project DIR]
```

| Option | Meaning |
|---|---|
| `--all` | every proposed host (not the ones only run saw, nor those seen after outside content) |
| `--project DIR` | the project directory (default: the current directory) |

Changes state: yes

## launchsafe-firewall hosts reset

Empty this project's approved hosts and watch record (also replaces a damaged file).

```
launchsafe-firewall hosts reset [--project DIR]
```

| Option | Meaning |
|---|---|
| `--project DIR` | the project directory (default: the current directory) |

Changes state: yes

## launchsafe-firewall vault

Secrets the agent uses by reference, without the value being put in what it reads (same as vault list).

```
launchsafe-firewall vault [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall vault list

Stored secrets: names, kinds, fields, bindings; never a value.

```
launchsafe-firewall vault list [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall vault add

Store a secret (typed with echo off) and sign it into the vault (needs the approval passphrase).

```
launchsafe-firewall vault add <name> [--kind credential|oauth|card|iban|national_id|personal] [--fields a,b] [--confirm always|never]
```

| Option | Meaning |
|---|---|
| `--kind credential|oauth|card|iban|national_id|personal` | what it is (default credential); card, iban, national_id and personal have several fields |
| `--fields a,b` | the field names (default per kind: value; card number,expiry,cvc,name; iban iban,bic,holder) |
| `--confirm always|never` | macOS: ask in a keychain dialog on every read (default: always for card, iban, national_id, personal; never for credential, oauth) |

Changes state: yes

## launchsafe-firewall vault allow

Bind a secret to a destination (this does not approve any held action; needs the approval passphrase).

```
launchsafe-firewall vault allow <name> --host HOST [--allow-in-url] [--allow-http] | --mcp SERVER[:TOOL[:ARG]] | --process "PROGRAM ARGS..."
```

| Option | Meaning |
|---|---|
| `--host HOST` | an exact host name, or *.example.com for its subdomains |
| `--allow-in-url` | with --host: the value may also appear in the URL itself (server logs keep URLs) |
| `--allow-http` | with --host: the value may also go over plain http (the default is https only) |
| `--mcp SERVER[:TOOL[:ARG]]` | an MCP server, optionally a tool pattern and the one argument path it may appear in |
| `--process ARGV` | a command line it may be given to by "run" (a trailing * allows further arguments) |

Changes state: yes

## launchsafe-firewall vault revoke

Remove one binding of a secret, by its number in vault list (needs the approval passphrase).

```
launchsafe-firewall vault revoke <name> <n>
```

Changes state: yes

## launchsafe-firewall vault remove

Delete a secret's values and its entry (needs the approval passphrase).

```
launchsafe-firewall vault remove <name>
```

Changes state: yes

## launchsafe-firewall vault rotate

Replace a secret's values, typed with echo off (needs the approval passphrase).

```
launchsafe-firewall vault rotate <name>
```

Changes state: yes

## launchsafe-firewall mcp wrap

The stdio MCP gateway for one server (an MCP client starts this from its configuration).

```
launchsafe-firewall mcp wrap --client CLIENT --server NAME [--mode auto|full|hook] [--phones PIN] -- COMMAND [ARGS...]
```

| Option | Meaning |
|---|---|
| `--phones sha256:HEX` | the paired phones' pin (written by mcp wrap-config; phone approvals verify against it) |
| `--client claude-desktop|claude-code|cursor|codex|gemini|vscode` | which MCP client |
| `--server NAME` | the server's name in the client's configuration |
| `--mode auto|full|hook` | full: the gateway decides every call; hook: the client's firewall hook does (default auto) |

Changes state: yes

## launchsafe-firewall mcp serve

The local Streamable HTTP MCP gateway (127.0.0.1 only; person-run).

```
launchsafe-firewall mcp serve [--port N]
```

| Option | Meaning |
|---|---|
| `--port N` | the port (default 8473) |

Changes state: yes

## launchsafe-firewall mcp wrap-config

Put the gateway in front of a client's MCP servers: shows the diff, backs up, needs the approval passphrase.

```
launchsafe-firewall mcp wrap-config --client CLIENT [--server NAME,...] [--port N] [--dry-run]
```

| Option | Meaning |
|---|---|
| `--client claude-desktop|claude-code|cursor|codex|gemini|vscode` | which MCP client |
| `--server NAME,...` | only these servers |
| `--port N` | the local gateway's port for HTTP servers (default 8473) |
| `--dry-run` | print the changes and exit |

Changes state: yes

## launchsafe-firewall mcp unwrap-config

Put a client's MCP servers back as they were before wrap-config (needs the approval passphrase).

```
launchsafe-firewall mcp unwrap-config --client CLIENT [--dry-run]
```

| Option | Meaning |
|---|---|
| `--client claude-desktop|claude-code|cursor|codex|gemini|vscode` | which MCP client |
| `--dry-run` | print the changes and exit |

Changes state: yes

## launchsafe-firewall mcp login

Sign the gateway in to a wrapped HTTP server's authorization server (OAuth, person-run).

```
launchsafe-firewall mcp login <server>
```

Changes state: yes

## launchsafe-firewall gateway

MCP servers wrapped by the gateway, ones that are not, and withheld results (same as gateway status).

```
launchsafe-firewall gateway [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall gateway status

MCP servers wrapped by the gateway, ones that are not, and withheld results.

```
launchsafe-firewall gateway status [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall gateway reset

Start a new gateway session for a client now.

```
launchsafe-firewall gateway reset <client>
```

Changes state: yes

## launchsafe-firewall gateway quarantine

MCP results the gateway withheld (no text in the list; --json in your terminal adds a short escaped preview; quarantine show prints the whole text).

```
launchsafe-firewall gateway quarantine [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall gateway quarantine show

The text of one withheld result, for you in your own terminal.

```
launchsafe-firewall gateway quarantine show <id>
```

Changes state: yes

## launchsafe-firewall mail

The email guard: messages withheld from the agent (same as mail quarantine list).

```
launchsafe-firewall mail [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall mail quarantine

Messages withheld from the agent (same as mail quarantine list).

```
launchsafe-firewall mail quarantine [--all] [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |
| `--all` | also list released and discarded records |

Changes state: no

## launchsafe-firewall mail quarantine list

List withheld messages: sender, subject, signals, record id.

```
launchsafe-firewall mail quarantine list [--all] [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |
| `--all` | also list released and discarded records |

Changes state: no

## launchsafe-firewall mail quarantine show

One withheld message's record, with its hidden text escaped, for you in your own terminal.

```
launchsafe-firewall mail quarantine show <id> [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: yes

## launchsafe-firewall mail quarantine release

Deliver a withheld message to the agent next time, hidden parts stripped (needs the approval passphrase).

```
launchsafe-firewall mail quarantine release <id>
```

Changes state: yes

## launchsafe-firewall mail quarantine discard

Close a withheld message's record; it stays withheld.

```
launchsafe-firewall mail quarantine discard <id>
```

Changes state: yes

## launchsafe-firewall mail audit

Dry run of the email guard over saved mail (.eml files, mbox files or folders of them): counts only, nothing changes or leaves the machine.

```
launchsafe-firewall mail audit --path FILE|DIR [--limit N] [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print the counts as JSON (no addresses, no subjects: safe to share if you choose) |
| `--path FILE|DIR` | an .eml file, an mbox file, or a folder of them (searched recursively) |
| `--limit N` | scan at most N messages (default 5000) |

Changes state: no

## launchsafe-firewall phone

Experimental: phones paired to approve held actions (same as phone list).

```
launchsafe-firewall phone [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall phone list

Paired phones, whether the hook pins them, and the relay's state.

```
launchsafe-firewall phone list [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall phone pair

Experimental, not usable yet (the hosted relay is not available): pair a phone with a QR code so its passkey can approve or reject held actions (needs the approval passphrase and a LaunchSafe account).

```
launchsafe-firewall phone pair [--label NAME] [--no-login-item]
```

| Option | Meaning |
|---|---|
| `--label NAME` | this machine's name on the phone (default: the host name) |
| `--no-login-item` | do not install the relay daemon as a login item (run "relay run" yourself) |

Changes state: yes

## launchsafe-firewall phone remove

Unpair a phone by its label or credential id (needs the approval passphrase).

```
launchsafe-firewall phone remove <label|id>
```

Changes state: yes

## launchsafe-firewall phone unpair

Same as phone remove.

```
launchsafe-firewall phone unpair <label|id>
```

Changes state: yes

## launchsafe-firewall relay

The phone relay daemon's state (same as relay status).

```
launchsafe-firewall relay [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall relay status

The phone relay daemon: last contact, errors, items sent.

```
launchsafe-firewall relay status [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall relay run

Experimental: the phone relay daemon: sends sealed held items to your phones and applies their signed decisions (a login item after phone pair).

```
launchsafe-firewall relay run [--once]
```

| Option | Meaning |
|---|---|
| `--once` | one upload and one decision check, then exit |

Changes state: yes

## launchsafe-firewall approver

The approval passphrase (same as approver status).

```
launchsafe-firewall approver
```

Changes state: no

## launchsafe-firewall approver status

Whether an approval passphrase is set.

```
launchsafe-firewall approver status
```

Changes state: no

## launchsafe-firewall approver init

Set the approval passphrase.

```
launchsafe-firewall approver init
```

Changes state: yes

## launchsafe-firewall approver rotate

Change the approval passphrase.

```
launchsafe-firewall approver rotate
```

Changes state: yes

## launchsafe-firewall log

The signed decision log (same as log tail).

```
launchsafe-firewall log
```

Changes state: no

## launchsafe-firewall log tail

The last N decisions.

```
launchsafe-firewall log tail [N]
```

Changes state: no

## launchsafe-firewall log verify

Check the log's hash chain and signatures; with a bundle, check an exported bundle instead (needs no firewall install; exit 0 ok, 1 problems, 2 not pinned).

```
launchsafe-firewall log verify
launchsafe-firewall log verify <bundle> [--key FINGERPRINT|PEM-FILE]... [--anchor FILE]... [--no-pin] [--json]
```

| Option | Meaning |
|---|---|
| `--key FINGERPRINT|PEM-FILE` | with a bundle: a key you trust that must be among its signing keys (the sha256: fingerprint log export printed, or a PEM public key file; nothing of the file is printed) |
| `--anchor FILE` | with a bundle: anchor records (log anchor) the bundle's entries must match |
| `--no-pin` | with a bundle: accept it without --key or a matching anchor (otherwise that is UNAUTHENTICATED, exit 2) |
| `--json` | with a bundle: print the result as JSON |

Changes state: no

## launchsafe-firewall log export

Write the signed log, or a range of it, as one self-contained bundle that log verify <bundle> checks anywhere (person-run, in a terminal).

```
launchsafe-firewall log export --out FILE|- [--from SEQ|TIME] [--to SEQ|TIME]
```

| Option | Meaning |
|---|---|
| `--out FILE|-` | the bundle file to create (it must not exist yet, nor be inside the firewall's directory), or - for standard output |
| `--from SEQ|TIME` | start at this sequence number, or at the first entry at or after this time (ISO 8601: 2026-10-01 or 2026-10-01T12:00:00Z) |
| `--to SEQ|TIME` | end at this sequence number, or at the last entry at or before this time |

Changes state: yes

## launchsafe-firewall log anchor

Write the log's current head, signed, to a place you choose off the firewall's directory (a file, a git note, or a command of yours); person-run only.

```
launchsafe-firewall log anchor --file PATH
launchsafe-firewall log anchor --git-notes REPO
launchsafe-firewall log anchor --exec -- <command> [args...]
```

| Option | Meaning |
|---|---|
| `--file PATH` | append the anchor record to this file, in an existing directory outside the firewall's (not through a symbolic link) |
| `--git-notes REPO` | add the record to the git note refs/notes/launchsafe-firewall-log in this repository (push that ref yourself) |
| `--exec` | run the command after -- (no shell) with the record on its standard input, for example an upload to an object-lock bucket |

Changes state: yes

## launchsafe-firewall log rotate

Start a new log file now.

```
launchsafe-firewall log rotate
```

Changes state: yes

## launchsafe-firewall policy

The policy in effect (same as policy show).

```
launchsafe-firewall policy
```

Changes state: no

## launchsafe-firewall policy show

Print the merged policy.

```
launchsafe-firewall policy show
```

Changes state: no

## launchsafe-firewall policy validate

Check every policy file and list ignored project settings.

```
launchsafe-firewall policy validate
```

Changes state: no

## launchsafe-firewall policy init

Write a starter user policy file.

```
launchsafe-firewall policy init
```

Changes state: yes

## launchsafe-firewall policy migrate

Rewrite the user policy file in the current schema version, keeping a backup.

```
launchsafe-firewall policy migrate
```

Changes state: yes

## launchsafe-firewall rollout

The rollout mode: enforce, or watch (log what would be asked, held or blocked, and let it run); same as rollout status.

```
launchsafe-firewall rollout [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall rollout status

The rollout mode in effect, where it comes from, and what watch mode still enforces.

```
launchsafe-firewall rollout status [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall rollout watch

Turn watch mode on: every verdict is logged as usual but only the always-enforced core blocks or asks (needs the approval passphrase; logged as a signed entry).

```
launchsafe-firewall rollout watch [--days N]
```

| Option | Meaning |
|---|---|
| `--days N` | end watch mode on its own after N days (1 to 90; default 14) |

Changes state: yes

## launchsafe-firewall rollout enforce

Turn watch mode off: every verdict is enforced again (logged as a signed entry).

```
launchsafe-firewall rollout enforce
```

Changes state: yes

## launchsafe-firewall rollout report

What enforcing would have asked about, held or blocked while watch mode was on, by rule, with masked examples.

```
launchsafe-firewall rollout report [--since DATE|Nd] [--examples N] [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |
| `--since DATE|Nd` | only decisions since this date (2026-10-01) or this many days ago (7d) |
| `--examples N` | examples per rule (default 3) |

Changes state: no

## launchsafe-firewall canary

Decoy files (same as canary list).

```
launchsafe-firewall canary [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall canary list

The decoy files that are planted, and whether each is still there.

```
launchsafe-firewall canary list [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall canary plant

Plant decoy credential files (a read of one the firewall sees raises an alert; a send of their values it sees is denied).

```
launchsafe-firewall canary plant [--workspace DIR] [--home] [--kinds env,aws,ssh,gh,notes,npmrc,kube]
```

| Option | Meaning |
|---|---|
| `--workspace DIR` | the project to plant in (default: the current directory) |
| `--home` | also plant decoys in your home directory (~/.aws, ~/.ssh, ~/.config/gh); off by default |
| `--kinds LIST` | comma-separated kinds (default: env,aws in the workspace; aws,ssh,gh with --home) |

Changes state: yes

## launchsafe-firewall canary remove

Delete decoys and the exclude lines that were added for them.

```
launchsafe-firewall canary remove <id>
launchsafe-firewall canary remove --all
```

| Option | Meaning |
|---|---|
| `--all` | remove every decoy (also resets a damaged registry) |

Changes state: yes

## launchsafe-firewall scope

The task scope a session's prompt set (same as scope show).

```
launchsafe-firewall scope [<session>] [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall scope show

The task scope a session's prompt set, and your widenings (default: the most recent session).

```
launchsafe-firewall scope show [<session>] [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no

## launchsafe-firewall scope widen

Widen one session's task scope by a path, repository, host or intent (needs the approval passphrase).

```
launchsafe-firewall scope widen <session> --path P | --repo OWNER/REPO | --host HOST | --intent push|pr|publish|deploy|message|delete|install|migrate
```

| Option | Meaning |
|---|---|
| `--path P` | a file or directory (relative to the current directory) |
| `--repo OWNER/REPO` | a GitHub repository |
| `--host HOST` | a host name |
| `--intent push|pr|publish|deploy|message|delete|install|migrate` | a publish-type action the task may take |

Changes state: yes

## launchsafe-firewall caps

The spending limits: what today and a session have used, and your raises (same as caps show).

```
launchsafe-firewall caps [--session <id>] [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |
| `--session ID` | also show this session (default: the most recent one) |

Changes state: no

## launchsafe-firewall caps show

The spending limits: what today and a session have used, and your raises.

```
launchsafe-firewall caps show [--session <id>] [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |
| `--session ID` | also show this session (default: the most recent one) |

Changes state: no

## launchsafe-firewall caps raise

Raise one spending limit for a session or for today (needs the approval passphrase).

```
launchsafe-firewall caps raise toolCalls|bytesOut|identicalFailures|tokens|costUsd <amount> --session <id> | --today
```

| Option | Meaning |
|---|---|
| `--session ID` | raise this session's limit (the id the firewall's message names) |
| `--today` | raise today's limit for every session (it lapses at local midnight) |

Changes state: yes

## launchsafe-firewall caps reset

Start spending-limit counters that could not be read again (needs the approval passphrase).

```
launchsafe-firewall caps reset --session <id> | --today
```

| Option | Meaning |
|---|---|
| `--session ID` | start this session's counters again |
| `--today` | start today's counters again (every session) |

Changes state: yes

## launchsafe-firewall check

Judge one action without changing anything (reads {"tool": "...", "input": {...}, "untrusted": false, "unattended": false, "prompt": "..."} on stdin).

```
launchsafe-firewall check   < action.json
```

Changes state: no · reads standard input

## launchsafe-firewall explain

Explain a rule (FW-...), a queue item, a log entry or an agent-safety rule; with no id, same as check.

```
launchsafe-firewall explain <id> [--json]
launchsafe-firewall explain   < action.json
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: no · reads standard input

## launchsafe-firewall ui

A read-only dashboard in your browser (127.0.0.1 only, a private address printed once); approvals stay in the terminal. Only you can start it, from your own terminal.

```
launchsafe-firewall ui [--project DIR] [--no-open]
```

| Option | Meaning |
|---|---|
| `--project DIR` | the project doctor's checks look at (default: the current directory) |
| `--no-open` | print the address without opening the browser |

Changes state: yes

## launchsafe-firewall run

Start an agent (or any command) in an OS sandbox: writes limited to the workspace and a private temporary directory (plus --allow-write); network through a local proxy that admits only your policy's hosts by name (an admitted host can still receive uploads); decisions in the signed log (macOS sandbox-exec, Linux bubblewrap; limits in docs/run.md).

```
launchsafe-firewall run [--workspace DIR] [--allow-write LIST] [--send-host LIST] [--allow-localhost] [--allow-keychain] [--git-init] [--pass-env NAME]... [--allow-home-read NAME]... [--env NAME=vault://REF]... [--dry-run] [--verbose] -- <command> [args...]
launchsafe-firewall run --agent claude|codex|gemini [other run flags] -- <agent command> [args...]
launchsafe-firewall run --ticket T --env NAME=vault://REF... -- <command> [args...]
```

| Option | Meaning |
|---|---|
| `--agent claude|codex|gemini` | a preset for this coding agent: its model API as send hosts for this run, and its switches against non-essential traffic (file rules unchanged; docs/run.md) |
| `--env NAME=vault://REF` | put a vaulted secret into the command's environment as NAME (repeatable); the secret must be bound to this exact command (vault allow <name> --process "<command>") |
| `--ticket T` | a single-use ticket the firewall's hook issued for exactly this --env list and command (Claude Code's rewrite of a shell command with references); runs without the sandbox, output filtered |
| `--workspace DIR` | the directory the command may write to (default: the current directory) |
| `--allow-write LIST` | comma-separated extra directories it may write to (never the home directory, credential stores, agent settings or system directories) |
| `--send-host LIST` | comma-separated hosts it may send to for this run, without byte budgets (for example the agent's model API) |
| `--allow-localhost` | macOS: let it connect to any port on 127.0.0.1 (local test servers; every local service becomes reachable). Linux has its own loopback |
| `--allow-keychain` | macOS: let it use the keychain (denied by default, so vault items stay out of reach) |
| `--git-init` | when the workspace has no .git, run git init in it before the run starts (inside the run .git cannot be created) |
| `--pass-env NAME` | pass this variable of your environment to the command (repeatable; NAME_* for a prefix). Only a short list (PATH, HOME, the locale, the terminal) is passed otherwise, so tokens in your shell stay out |
| `--allow-home-read NAME` | leave one of ~/.config/gh, ~/.netrc, ~/.npmrc, ~/.git-credentials, ~/.docker, ~/.kube, ~/.config/gcloud, ~/.azure readable (repeatable; written as .npmrc). ~/.ssh, ~/.aws and ~/.gnupg stay unreadable |
| `--dry-run` | print the sandbox profile and the hosts, start nothing |
| `--verbose` | also print each refused connection as it happens (a full-screen agent may draw over it) |

Changes state: yes

## launchsafe-firewall serve

The local API sidecar for agents you build in any language: POST /v1/decide and the session endpoints on a unix socket in the firewall home (or 127.0.0.1).

```
launchsafe-firewall serve --api [--listen 127.0.0.1:PORT]
```

| Option | Meaning |
|---|---|
| `--api` | serve the local API (the only server in v0) |
| `--listen 127.0.0.1:PORT` | listen on this loopback address instead of <firewall home>/api.sock; any other address is refused |

Changes state: yes

## launchsafe-firewall openshell serve

The firewall as an NVIDIA OpenShell supervisor middleware (gRPC): each request a sandbox sends, after OpenShell's own policy allows it, is decided by the local API (serve --api) with the sandbox's session.

```
launchsafe-firewall openshell serve [--listen HOST:PORT] [--api-socket PATH] [--tls-cert FILE --tls-key FILE --gateway-key FILE --gateway-id ID [--audience AUD]] [--insecure]
```

| Option | Meaning |
|---|---|
| `--listen HOST:PORT` | the address the gateway and the sandbox supervisors reach (default 127.0.0.1:50051); anything but loopback needs TLS and the gateway's key, or --insecure |
| `--api-socket PATH` | the local API's unix socket (default <firewall home>/api.sock); the token is read from LAUNCHSAFE_FIREWALL_API_TOKEN |
| `--tls-cert FILE` | PEM certificate for TLS (OpenShell sends its extension token only over TLS) |
| `--tls-key FILE` | PEM private key for --tls-cert |
| `--gateway-key FILE` | the OpenShell gateway's Ed25519 public key (PEM or JWK), from its operator: every call must carry a token it signed |
| `--gateway-id ID` | the gateway's id (the token's issuer is openshell-gateway:<ID>) |
| `--audience AUD` | the token audience (default urn:openshell:extension:middleware:launchsafe-firewall) |
| `--insecure` | serve plaintext gRPC without verifying the caller (OpenShell's allow_insecure_transport; local development only) |

Changes state: yes

## launchsafe-firewall openshell policy

Print an OpenShell sandbox policy (YAML) that mirrors your firewall policy's hosts and attaches the firewall's middleware.

```
launchsafe-firewall openshell policy [--agent claude|codex|gemini] [--send-host LIST] [--middleware NAME] [--no-middleware] [--endpoint URL] [--project DIR]
```

| Option | Meaning |
|---|---|
| `--agent claude|codex|gemini` | admit this agent's model API (left out of the middleware) |
| `--send-host LIST` | comma-separated extra hosts it may send to |
| `--middleware NAME` | the middleware's registration name in the gateway's TOML (default launchsafe-firewall) |
| `--no-middleware` | only the network and file rules, without the firewall's middleware |
| `--endpoint URL` | where the gateway and sandboxes reach openshell serve (shown in the TOML comment) |
| `--project DIR` | the project directory (default: the current directory) |

Changes state: no

## launchsafe-firewall api token add

Make a new API token for an agent; it is printed once and only its SHA-256 is kept.

```
launchsafe-firewall api token add <agentId> [--traffic network] [--role decide|report|prompt ...]
```

| Option | Meaning |
|---|---|
| `--traffic network` | a network middleware's token (OpenShell's, docs/sandboxes.md): it may send context.traffic "network" for its HTTP requests, which are not counted as the agent's tool calls |
| `--role ROLE` | what the token may do: decide (decide, read sessions and approvals), report (results and inputs), prompt (prompts whose destinations and task scope apply; for the part that reads what the person typed). Repeat it or use commas. Default: decide and report |

Changes state: yes

## launchsafe-firewall api token list

The agents that have API tokens (never a token).

```
launchsafe-firewall api token list [--json]
```

| Option | Meaning |
|---|---|
| `--json` | print JSON |

Changes state: yes

## launchsafe-firewall api token revoke

Revoke every API token of an agent.

```
launchsafe-firewall api token revoke <agentId>
```

Changes state: yes

## launchsafe-firewall api tools set

Set an agent's tool registry from a JSON file (validated like the library's tool specs).

```
launchsafe-firewall api tools set <agentId> <file.json>
```

Changes state: yes

## launchsafe-firewall api tools show

Print an agent's tool registry.

```
launchsafe-firewall api tools show <agentId>
```

Changes state: yes

## launchsafe-firewall demo

Replay attack scenarios from published research and real incidents through the policy.

```
launchsafe-firewall demo
```

Changes state: no

## launchsafe-firewall version

Print the version.

```
launchsafe-firewall version
```

Changes state: no

## launchsafe-firewall help

Help for a command.

```
launchsafe-firewall help [command...]
```

Changes state: no

## launchsafe-firewall native-host

The browser link's host: the browser starts it for the LaunchSafe extension (reads native messages on stdin).

```
launchsafe-firewall native-host <origin>
```

Changes state: yes · reads standard input

## launchsafe-firewall hook

The agent hook (reads the event on stdin).

```
launchsafe-firewall hook [--agent claude|codex|gemini|cursor] [--record DIR]
```

| Option | Meaning |
|---|---|
| `--agent claude|codex|gemini|cursor` | which agent sends the event (default claude) |
| `--record DIR` | also save each raw event to DIR (only with LAUNCHSAFE_FIREWALL_RECORD=1) |

Changes state: yes · reads standard input
