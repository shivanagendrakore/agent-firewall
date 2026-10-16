# How it works

An overview of what the firewall does and why it is built this way. The short
version is in the [README](../README.md). Each part has its own page with the
details and the limits: the rules and settings in [policy.md](policy.md), the
design internals in [design.md](design.md), the attacker model in
[threat-model.md](threat-model.md), and what it does not do in
[limitations.md](limitations.md). Read the limitations before relying on it.

**The principle:** the firewall does not use a model to detect malicious
*text*. An agent can always be fooled by cleverly written content, so the
firewall does not guess intent. It watches the **actions** the agent takes and
the **data** that moves, as far as its hooks can see them, and applies fixed
rules to those outside the model. The aim is to limit what a fooled agent can
do, not to promise it can do nothing. (The email guard and the MCP gateway do
scan text for hidden instructions, with fixed patterns; they are detectors on
top of the rules, not the boundary.)

## Why a model-based filter is not enough

The well-known failure mode of AI agents is the **lethal trifecta** (Simon
Willison): an agent that at once has access to **private data**, can be reached
by **untrusted content**, and has a way to **communicate externally** can be
tricked into taking the private data and sending it to an attacker — using only
words placed in an email, a web page, a GitHub issue, a support ticket or an MCP
tool's description. The agent is working as designed; it was simply given
instructions by the wrong person.

You cannot reliably fix this by asking a model to spot the bad instruction: the
whole problem is that models follow instructions in content. The fix has to sit
**outside** the model and constrain what the agent can do. That is what this
firewall is. (See also Google DeepMind's *CaMeL*, which enforces security by
tracking control and data flow around the model rather than trusting it.)

## What it does

The firewall installs as hooks in the agent: [Claude Code's](https://code.claude.com/docs/en/hooks)
first, and also Codex, Gemini CLI and Cursor (what each supports is in
[agents/overview.md](agents/overview.md)). On every tool call the hook sees,
before it runs, the firewall:

1. **Normalizes the action** into what it does — which files it reads
   and writes, where it sends data, what code it runs — using a conservative
   shell parser and per-tool models, not string matching. What it knows it
   cannot fully understand is judged strictly rather than allowed as harmless:
   a tool it has no model for is sent to a person before it runs, in any
   session, and what it returns counts as outside content; a program whose name
   is computed, or a shell write whose target is only known at run time, needs
   a person; other code it cannot see into needs a person once the session is
   untrusted. Not every gap is known to it. The shell analysis is static, and
   some constructs are not analysed yet: a command that hides what it does
   inside one of them can run without a prompt, even in a session that has
   read outside content (listed in [limitations.md](limitations.md#shell-constructs-not-yet-analysed);
   see also [threat-model.md](threat-model.md)).
2. **Tracks the session's trust state.** A session starts *trusted* (unless the start-up scan below finds something). The first
   time the agent takes in outside content — a web fetch or search (through the
   WebFetch/WebSearch tools **or** through the shell: `curl`, `wget`, `npm view`,
   `ssh` output, a URL fetched by inline code), a result from an MCP server that
   carries outsider-written text (email, chat, issues, tickets, a browser), a
   claude.ai page, its shared database rows or its comments read through the
   desktop app's `Artifact`, `ArtifactData` and `ArtifactComments` tools, a file
   outside the workspace, a downloaded file (including one a fetch wrote with
   `>` or `tee`) — the session becomes *untrusted* and stays that way. A result
   that hides text from you can do the same (FW-HIDDEN-OUTPUT): Unicode tag
   characters or variation selectors that spell a message, or a dense run of
   zero-width characters (eight or more, or four in a row), make it untrusted
   through the hooks on every agent, while one zero-width space on its own is
   ordinary text and counts for nothing; terminal codes that conceal or
   overwrite text do the same wherever the firewall cannot rewrite the output,
   except in a program's own output in a trusted session (a test run or a
   build, with no file printed beside it), where only concealed text and OSC
   strings count, so a cursor trick there passes
   ([design.md](design.md#what-taints-what-counts-as-sending),
   [limitations.md](limitations.md#outside-content-and-hidden-text)). The
   firewall records what tainted it. Showing you something is not reading
   outside content: when the agent sends you a file (the desktop app's
   `SendUserFile`), sets a chapter marker or proposes a new session, the session
   stays trusted (reaching into a credential store still asks, and publishing a
   page to claude.ai is a send like any other). Once the session is untrusted,
   proposing a new session needs your approval, and the ask shows the whole
   prompt (the app's task chip shows only the title and summary the agent
   wrote); a session started from a prompt an untrusted session proposed starts
   untrusted, and no proposed prompt counts as you naming a destination. Files the agent wrote itself
   are not outside content: a provenance ledger remembers the hash of what each session
   wrote, so reading back notes the agent left outside the workspace keeps the
   session trusted, as long as nothing else has changed them since. The other
   way round, a file an *untrusted* session wrote stays untrusted in later
   sessions: running it, a build that runs it (`npm test` after an untrusted
   session changed `package.json` or `vitest.config.ts`, `git commit` after it
   changed `.pre-commit-config.yaml`), or an install that reads it (`npm ci`
   after it changed `package-lock.json`, `npm install` after `.npmrc`, `pip
   install -r` after the requirements file, `uv sync` after `uv.lock`), needs a
   person.
3. **Decides** allow / ask / queue / deny from a fixed rule table, and tells
   the agent. (Watch mode, a rollout setting you turn on yourself, lets the
   actions a reviewed list of rules would ask about run, and only logs them,
   for a set number of days: [policy.md](policy.md#watch-mode-rollout).) It
   restricts: an action it allows is passed on to the agent's own
   permission rules unchanged. The one exception is a command the vault
   rewrote (a curl or wget with a `vault://` reference, on Claude Code), which
   is returned with an explicit allow so the rewritten command is the one that
   runs; the person's own deny and ask rules still apply to it.

### Four core mechanisms

1. **A deterministic taint rule.** Once a session has read outside content,
   the action classes that could cause damage — sending data off the machine,
   sending a message, changing the agent's own instructions or memory, reading a
   credential store, handing private text to a third-party tool, running a build
   or task file it changed after reading that content — need a person's
   approval. Before that, normal local work is untouched. This targets the
   "external communication" leg of the lethal trifecta: once a session has read
   outside content, sends the firewall can see, and fetches to hosts you did
   not name or allow, need a person. Allowlisted and named hosts, and programs
   the hooks cannot see, are not covered.

2. **An unattended queue with batch review.** When no one is at the keyboard
   (a `claude -p` run, which includes a CI job that runs an agent with `-p`, or configured hours; a bare `CI` variable is not a trigger), an action that would ask is
   **queued** with a plain-language reason instead. You review the queue later
   with `launchsafe-firewall queue review` (one passphrase for the whole batch),
   and an approval lets that **exact** action run once.

3. **Protected memory with proposed changes.** In an untrusted session, a write
   the firewall sees (through the Write and Edit tools, a tool it models, or a
   shell command it can analyse) to the agent's instructions or memory (`CLAUDE.md`, `AGENTS.md`,
   `MEMORY.md`, `.claude/**`, and any file `CLAUDE.md` imports with `@path`,
   followed up to five imports deep) is **not applied**. It is held as a
   proposal for you to read and accept — so a poisoned web page cannot quietly
   rewrite, through the tools the firewall sees, what the agent believes in
   future sessions. The same goes for the files that make code run
   later without anyone asking: a git hook or hook-manager file (`.git/hooks`,
   a submodule's `.git/modules/<name>/hooks`, `.husky`, lefthook, pre-commit),
   an editor task that runs on its own, a dev-container lifecycle command. A
   patch applied through the shell (`git apply`, `git am`, `patch`, Codex's
   `apply_patch`) is judged file by file like the Write and Edit tools; a patch
   the firewall cannot read (piped in, or from a file the same command writes)
   needs a person once the session is untrusted. A CI change after outside content needs you
   (it is reviewed in a pull request anyway). Writes the firewall does not see
   as writes to these files (a program that writes files its command line does
   not name, a command that uses one of the shell constructs not yet analysed)
   get past all of this ([limitations.md](limitations.md)). In a trusted
   session these files stay editable, but a change made with the Write or Edit
   tool (or a patch the firewall can read) that adds a way for code to run by
   itself — a task that runs when the folder opens, a `pull_request_target`
   workflow that checks out the pull request's code, a hook that downloads and
   runs a script, a different package registry, an agent's own auto-approval
   switched on — asks first
   (`FW-AUTORUN`). A shell write to a git hook or an editor task asks too,
   because its content cannot be checked; shell writes to CI, dev-container
   and environment-hook files (`.envrc`, `.npmrc` and the like) in a trusted
   session are not checked.

4. **Self-protection, in layers.**
   - *What the agent's actions can do.* The firewall is identified by what is
     actually installed, never by what a file or folder is called: the CLI file
     the registered hook command runs, its package's `dist/`, `node_modules/` and
     `package.json`, the node binary the hook command names, and the data
     directory (`~/.launchsafe-firewall` or `LAUNCHSAFE_FIREWALL_HOME`, with its
     keys, approvals and state). Any tool call or shell command the firewall can
     analyse that writes, deletes or links over any of those, copies the data
     directory, builds the installed package from inside the agent, edits its
     hook registration or `disableAllHooks`, stops the hook process, or runs the
     CLI to change anything — by its command name, as `node <its cli.js>`,
     through `npx`/`pnpm dlx`/`bunx`/`yarn dlx`/`npm exec` of
     `@launchsafe/agent-firewall`, through a symlink whose target is its CLI
     file, or hidden behind `sudo`, `env`, `nohup`, `timeout`, `xargs`,
     `unbuffer`, `script`, `expect` or `bash -c` — is **denied** and cannot be
     approved from inside the agent. Read-only subcommands (`status`, `doctor`,
     `queue list`, `log verify`) stay allowed, and so is ordinary work that only
     shares a name: cloning or reading the firewall's source, copying its docs,
     a folder called `launchsafe-firewall-notes`. Names are compared ignoring
     case on every platform (a Linux host cannot tell whether a directory folds
     case, as WSL2's `/mnt/c` does), here and for the protected files below.
   - *What counts as an approval.* Approving a held action and uninstalling need
     an **approval passphrase** you set in your own terminal; the agent never
     sees it. It unlocks an Ed25519 key that signs each approval, and the hook
     honours only approvals that verify against the key **pinned in the hook
     command** in Claude Code's settings. So even a command the analyser cannot
     see into (a copied CLI, code that writes the session file) cannot produce an
     approval the hook accepts; a forged or unsigned approval is ignored and
     makes the session untrusted. What such a command can still do is replay
     one: by rewriting a whole session file it can remove the record of a real
     approval's use and so use a copy of that approval once more before it
     lapses (24 hours; [limitations.md](limitations.md#approvals)). The CLI additionally refuses to run these
     commands, and the ones that change the decoys, the policy file or the log
     (`canary plant`/`remove`, `policy init`/`migrate`, `log rotate`), without a
     real terminal or as a descendant of a Claude Code session. Everything the
     CLI prints, and every reason the hook gives Claude Code, shows terminal
     control characters as visible escapes (`\u001b`), so text an agent or a
     repository wrote cannot rewrite or hide lines on the approval screen.
   - *The hook registration.* A change to a Claude Code settings file (user,
     project, local or managed) is judged by the file it would produce: if the
     firewall's hook entries or their fail-closed wrapper would be removed,
     altered or moved to another matcher or event, `disableAllHooks` turned on,
     `allowManagedHooksOnly` changed, the firewall's own variables set, or the
     file left unparseable, the change is **denied**, in any session. A settings
     change made through the shell (redirect, `cp`/`mv` over the file, `tee`,
     `sed -i`, removing `.claude/`) cannot be checked that way, so it is denied;
     use the Write or Edit tool. A patch applied through the shell is judged by
     the files it would produce, and an edit tool that matches its text loosely
     (Codex's `apply_patch`, Gemini CLI's `replace`) is judged against every
     place the text could match, and as the worst case when it matches nowhere.
     Codex's and Gemini CLI's hook files are recognised wherever `CODEX_HOME` and
     `GEMINI_CLI_SYSTEM_SETTINGS_PATH` put them, and a file the install record
     registers is a settings file whatever it is called. Codex's `config.toml` is
     parsed into keys, so `features.hooks = false` written as a dotted key or an
     inline table is tampering like the `[features]` table form. A change made outside the agent mid-session is
     also blocked (`ConfigChange`). Only **managed settings** make the file
     itself unwritable to processes the firewall cannot see (see limits).

### Always on, trusted or not

Two protections never depend on trust state and can never be approved from
inside the agent:

- **Recognised credentials and sensitive personal data are denied from leaving
  for the wrong place.** An outbound payload the firewall can read that carries
  an API key, token, private key, a checksum-valid card number, an IBAN, or a
  national-ID format is **denied** unless the destination is explicitly
  allowlisted for that kind of data, or, for a credential, is the service that
  issued it (a Stripe key may go to Stripe's API). "Outbound" covers network commands,
  WebFetch URLs, web-search queries, and the arguments of every MCP tool call,
  including "read" tools such as search, docs and query. These shapes are
  recognised as written, so an encoded credential the session never read (one
  from a file pulled in with `@`, say) is not found. Secrets the session has
  already read are remembered as fingerprints and caught in the encodings
  listed in [limitations.md](limitations.md#data-leaving-the-machine) too.
  Digits inside a long hex
  token are part of that token, not a card number, so a hex-encoded secret is
  caught as a secret and not as a card; a card written against a word or a single
  letter is still a card.
  The scan has bounds (text length, encodings) and does not read the contents of
  files a command uploads (`curl -d @file`, `-T`, `-F`, `wget --post-file`);
  those are listed in [limitations.md](limitations.md) too. Published test
  values (Stripe and other processors' test cards, ISO example IBANs, specimen
  SSNs, `sk_test_` keys) are not sensitive and are let through
  (`allowTestValues`, on by default).
- **The firewall protects itself** (above).

Budgets are on by default (`budgets.enabled`), and the four byte, request, MCP
and loop limits never deny: reaching one asks a person, or holds the action
when nobody can answer. The separate behaviour-monitor limits
(`budgets.loop.stop*`) do deny, with FW-STOPPED, until a person resumes the
session. (In
`run`, where nobody can be asked, a reached budget refuses the connection; in
watch mode budgets stop nothing). Every session has an
outbound budget (once untrusted, 64 KB per host and 256 KB in total; trusted,
4 MB; addresses and uploaded files count, also to hosts in `fetchAllowHosts`,
and one call that fetches many URLs adds them all up; hosts in
`sendAllowHosts` or `budgets.exemptHosts`, and this machine itself, are not
counted), a request budget per host, a
call budget per MCP server (and 20 sends or messages through one server in 10
minutes once untrusted), and loop detection (the same command 8 times in 10
minutes with no file changed in between). Reaching one asks you once, and your
yes raises that budget for the session, counted from where you said yes;
unattended, the action is queued and a
notification says the agent seems stuck. Package installs and clones are not
counted. Limits are in the `budgets` policy key.

### Checks what the agent is armed with

When a session starts, the firewall reads the files that program the agent —
`CLAUDE.md`/`AGENTS.md`, `.claude/` settings, hooks, skills, agents and
commands, MCP server lists, Cursor/VS Code/Codex/Gemini config, agent
memory and the files `CLAUDE.md` imports, the workspace's and your own
(`~/.claude`) — and runs LaunchSafe's agent-safety rules on them (the
firewall's own copy, rule set `1.2.0-fw`, in `src/vendor/agent-safety/`). A
critical finding (hidden instructions, a hook that runs a download, a
model endpoint moved to someone else's server) makes the session start
**untrusted**, and you are told why. So does a hook or MCP server added or
changed since your last session (the firewall's own hook counts as its own only
in a settings file its install record names, pointing at the installed CLI), and
so does a workspace with more agent files than the bounded scan reads, since a
file past the limit could hide behind filler. Each MCP server is **pinned**: a
changed launch command, a changed tool description the firewall sees, or a tool
not seen before on a server whose tools could have changed (its launch is not
pinned to an exact version, or its configuration changed) marks the session
untrusted, from that call on, until you review it with
`launchsafe-firewall pins` and accept it with `launchsafe-firewall pins accept
<server>`. A tool first used on an exact-version server with an unchanged
configuration is logged as a first use, not reported as a change. The
configuration comparison also runs when a session is resumed, cleared or
compacted. The scan is static and bounded (it never runs or contacts what it
reads; a clean result is not proof a skill is benign), and a hook never sees an
MCP server's full tool list, so without the MCP gateway description pinning
covers only what Claude Code shows through its ToolSearch tool (the gateway
sees and pins every `tools/list`). Two parts of this were tested only with
synthetic fixtures, their live shape not captured: reading tool descriptions
from ToolSearch results, and the field names of the session-start messages
that tell you and the agent why a session starts untrusted.

### Decoys (canary files)

You can plant a few decoy files that look like credentials or private notes
and that no real task needs: `launchsafe-firewall canary plant` creates
`.env.backup` and `config/credentials.old.json` in the project (add `--home` for
`~/.aws/credentials.bak`, `~/.ssh/id_ed25519_old` and `~/.config/gh/hosts.yml.bak`).
Each holds a credential-shaped value that is valid with no provider and carries
the infix `LSCANARY`, so a person who finds one understands it. The files are
mode 600 and listed in `.git/info/exclude` (never `.gitignore`), so `git add -A`
does not commit them. Nothing is planted unless you run the command (or say yes
when `install` offers it, in a terminal).

If an agent **reads** one directly (`Read`, `cat`, `cp`, inline code naming it),
the read is allowed (blocking would show which file is the decoy) unless another
rule holds it (a decoy in `~/.aws` or `~/.ssh` is also a credential-store read,
which asks, or is queued when no one is there). Whatever the verdict, even when
the action is held or blocked, the session turns untrusted and sensitive, an
alert is logged and notified, and every later send in it needs you, including
search queries and MCP arguments. If a decoy's value shows up in a tool result the session is marked the
same way, and if it appears in **outbound** data the firewall reads, verbatim
or in the encodings listed in [limitations.md](limitations.md#decoys), it is
**denied** to every destination, with no allowlist (`FW-CANARY-EGRESS`); the
attempt also marks the decoy as seen and raises the alert. A push's payload is
not read, so a decoy committed with `git add -f` and pushed is not seen
leaving (`doctor` warns when git tracks a decoy). A recursive search
(`grep -r`, `rg`) that merely passes over a decoy does not trip it. List with
`canary list`, remove with `canary remove --all`. Decoys are local: no network
calls, no remote tokens.

### Task scope

Your prompt says what the task is about. The firewall records the workspace
paths, repositories and hosts it names and whether it asks to push, open a PR,
publish, deploy, send, delete or install, and uses that to **narrow** what a
fooled or unattended session may do on its own: once a session has read outside
content, a write outside the paths you named or a send to a repository or host
you did not name needs you; in an unattended run (`claude -p`, including a CI job that runs an agent with `-p`), a push, PR,
publish, deploy, message or new install the prompt never asked for is held, even
in a trusted session. An interactive trusted session is never narrowed, a prompt
that names nothing ("make it faster") narrows nothing, and the scope never
loosens a rule. Parsing is strict: no fuzzy names, nothing from pasted blocks or
quotes, no negated or questioned verbs. It runs in **log mode** by
default (`taskScope.mode: "log"`): it records what it would have asked
(`status` counts them, `explain <log seq>` shows each) and changes no decision;
set `"enforce"` to apply it. `scope show` prints a session's scope, and `scope
widen` (or saying yes after `queue approve`) widens it with your passphrase.

### Package checks

Supply-chain attacks are the incidents with confirmed real victims (Nx
"s1ngularity", a malicious MCP server on npm, backdoored PyPI releases), so
every install and package runner (`npm`/`pnpm`/`yarn`/`bun`, `npx`/`dlx`/`bunx`,
`pip`/`uv`/`uvx`/`poetry`/`pdm`/`pipx`, `cargo`, `gem`/`bundle`, `go`,
`composer`) gets three offline checks, trusted or not:

- **Known-malicious versions are denied, once you have downloaded the data**
  (FW-MALICIOUS-PACKAGE). A local snapshot of OSV's malicious-package
  advisories (`MAL-` entries) is checked for each named package, and for
  installs from a lockfile (`npm ci`, `pnpm install`, `yarn install`, `pip
  install -r`, `uv sync`, `poetry install`, `bundle install`, `cargo build`)
  for every `name@version` the lockfile pins. When only some versions are
  listed and no exact version is given, a person decides. No snapshot ships
  with the firewall: until you run `launchsafe-firewall update` (or accept
  `doctor --fix`'s offer to run it), this check denies nothing. Run `update`
  again to refresh it; `doctor` warns when the snapshot is missing or more
  than a week old.
- **Typosquats need a person** (FW-TYPOSQUAT): a name one or two letters from a
  popular package, the same with different separators or look-alike characters
  (`0`/`o`, `rn`/`m`), with a scope added or dropped, or with a `-js`/`python-`
  style affix, and not itself a known package. The name lists ship with the
  firewall; `npm run friction` replays install commands for 346 widely used
  npm and PyPI package names through the policy and fails if any of them is
  flagged.
- **`doctor` checks release-age cooldowns** (pnpm `minimumReleaseAge`, Yarn
  `npmMinimalAgeGate`, Bun `install.minimumReleaseAge`, uv `exclude-newer`) and
  `doctor --fix` can write a three-day cooldown into your **user-level** config
  after showing the diff. npm and pip have no rolling cooldown; doctor says so.

### Secrets by reference (the vault)

`launchsafe-firewall vault add <name>` stores a credential or a financial or
personal value (an API token, a card, an IBAN) in the macOS Keychain or the
Linux Secret Service (an encrypted file only if your user policy allows it),
typed with echo off, and `vault allow <name> --host <host>` binds it to where it
may go. The index of names, bindings and fingerprints is signed with your
approval key; agents may run `vault list` but never change the vault. From then
on the value is a credential wherever the firewall reads it in outbound data:
sent anywhere it is not bound to, verbatim or in the encodings listed in
[limitations.md](limitations.md#data-leaving-the-machine), it is denied
(FW-VAULT-EGRESS), whatever the allowlists say. That needs a value of 12
characters or more (a CVC or an expiry date cannot be recognised; `vault add`
says which fields), and the contents of a file a command uploads are not read.
The agent writes a `vault://` reference where the value would
go, and the firewall puts the value in only when an allowed action runs, only
for a destination the secret is bound to: through the MCP gateway (at the bound
argument), through Claude Code's hook for a curl or wget command (its own
single-use `run`, so nothing else in the command sees the value), and through
`run --env` in your own terminal; what the agent reads is scrubbed back to the
reference. On Claude Code the rewrite and the scrub rely on the hook replacing
the tool's input and output (`updatedInput`, `updatedToolOutput`), which
Claude Code documents but which were not captured live
([limitations.md](limitations.md#what-the-firewall-sees)). The vault keeps
secrets out of what the agent reads and limits where actions the firewall sees
can send them. It is not a hardware boundary: a program running as you, outside
the sandbox, that the firewall cannot see into can read your keychain (on Linux
always; on macOS only for secrets stored without per-use confirmation). Run the
firewall with the agent's sandbox. Details: [vault.md](vault.md).

### The MCP gateway

`launchsafe-firewall mcp wrap-config --client claude-desktop` (also
`claude-code`, `cursor`, `codex`, `gemini`, `vscode`) puts the firewall in front
of a client's MCP servers, after showing you the diff: local servers through a
stdio wrapper, remote ones through `launchsafe-firewall mcp serve` on
127.0.0.1. By default (`gateway.mode: "auto"`, which is full mode) the gateway
decides every tool call itself, with the same engine and rule ids as the hooks,
queueing what needs you. It does so even for a client that also has the
firewall's hook, so there a call is judged, and counted toward the budgets,
twice. Set `gateway.mode: "hook"` in your own policy to leave each call's
decision to the hook ([gateway.md](gateway.md#modes)). Either way it pins every
tool's definition from `tools/list` and **hides a changed tool, or a new one
after the first-use grace window,** until you run `pins accept` (FW-MCP-TOOL-HELD),
scans every result with fixed patterns and **withholds the hidden instructions
it finds** before the model sees them (FW-MCP-WITHHELD; hidden text without an
instruction is stripped, visible agent-directed text is annotated), refuses
sampling from untrusted servers and unknown methods, and never passes a token
anywhere but the server it was issued for. Details and limits:
[gateway.md](gateway.md).

### Hidden instructions in mail (the email guard)

Messages from MCP servers the firewall recognises as mail (by a word in the
server's or its tools' names, such as `mail`, `gmail` or `imap`, or because
you listed the server in `emailGuard.servers`) are scanned as they come back:
Unicode tag characters, CSS-hidden text (`font-size:0`, white-on-white,
off-screen, `display:none`), dense zero-width characters, hidden links that
leak data, and text addressed to an AI agent from a sender the mailbox
provider says failed authentication. Such a message is withheld and recorded
for you (`launchsafe-firewall mail quarantine`); hidden padding is stripped
from the rest; the session becomes untrusted and you get a notification
(FW-MAIL-WITHHELD). Only you can release a message, in your own terminal.
Only Claude Code's hook and the MCP gateway can keep a withheld message from
the model. Claude Code's hook does it by replacing the tool's output
(`updatedToolOutput`, documented by Claude Code but not captured live); on
Codex, Gemini CLI and Cursor the model has already read the message, so the
guard warns the agent and untrusts the session instead. A mail server wrapped
by the MCP gateway (`mcp wrap-config`) gets the same filter on the pipe, so
the withheld message never reaches any client's model. A mail server whose
name and tools' names say nothing about mail is not guarded until you list
it. On a 591-message corpus we wrote, as measured on 15 October 2026 (`npm run
mail-friction`; rerun it before a release): 0 of 435 ordinary messages
withheld, 20 of them flagged (delivered unchanged with a note telling the agent
to treat their text as data), and 156 of 156 attack fixtures withheld.
Binary attachments (PDF, DOCX, images) are not scanned, the scan is bounded
(a message it cannot fully read is withheld), the phrase lists are English
only, and moving mail out of the mailbox itself (IMAP, Microsoft 365) is not
built yet; when it is, it is a race after delivery and starts log-only.
Details: [email-guard.md](email-guard.md).

### Agents without a sandbox of their own (`run`)

`launchsafe-firewall run -- <agent>` starts any agent CLI (or script) inside
the operating system's own sandbox: `sandbox-exec` on macOS, bubblewrap on
Linux (it refuses, and says why, when neither works; `doctor` reports
readiness). The command can write only to the workspace and a private
temporary directory; the firewall's files, the project's agent settings, MCP
server lists and editor tasks, and git's hooks and config stay read-only (also
against renaming their directories, and before they exist), and the
credential directories listed in [run.md](run.md) and the firewall's keys are
unreadable; everything else your user can read stays readable to it. Its
network connections go through a proxy outside the sandbox (on 127.0.0.1; on
Linux reached through a private Unix socket) that
admits the hosts of your `fetchAllowHosts` and `sendAllowHosts` (the same list
`doctor --fix` gives Claude Code's sandbox), refuses IP addresses, metadata
endpoints, `denyHosts`, DNS answers that point back at this machine and TLS
that names a different server than the tunnel, and applies the budgets. Every
refusal and a per-host summary go to the signed log. The proxy is not the only
way out: on Linux, Unix sockets outside the directories the sandbox hides stay
reachable, and on macOS the profile is a deny list, so a system service not on
it that does network or file work for its caller is not stopped. Hosts, not
methods, are what it sees.

It is meant as the outer wall for agents the hooks cannot see (Aider,
opencode, your own scripts), but how far it has been tested is narrow: it has
not been run with Aider or opencode, the `--agent` presets (Claude Code, Codex,
Gemini CLI) were checked against the host list and the dry run without
starting the real agents, and the Linux sandbox has been exercised only in a
Docker container (Debian 12, bubblewrap 0.8) and on GitHub's Ubuntu runner. The agent's credential files stay readable inside
a run (its own directory is read-only, not hidden), so every program the run
starts can read them (Claude Code on macOS keeps its credentials in the
keychain instead, which `run` blocks unless `--allow-keychain`). The model API
hosts the agent needs are send hosts with no byte budget: an unjudged way out
for anything the agent reads. An
agent with the firewall's hooks installed has its risky actions blocked inside
`run` (its hooks cannot save their state there); give it its own sandbox
instead. Design and limits: [run.md](run.md).

```sh
launchsafe-firewall run --send-host api.anthropic.com -- aider   # the model API is a send host for this run (no byte budget)
launchsafe-firewall run --dry-run -- my-agent                     # print the profile and hosts, start nothing
```

### Approve from your phone (hosted relay not available yet)

Terminal approvals work now. Phone approvals need LaunchSafe's hosted relay and
approval app, which are not available yet, so you cannot pair a phone today.
The firewall side is built and tested against a stub relay: `launchsafe-firewall
phone pair` is designed to show a QR code, your phone to create a passkey used
only for approvals, and held actions (approval items only; proposed instruction
or memory changes stay in the terminal, which shows the diff) to reach it. The
firewall verifies the passkey signature itself against the phone pinned in the
hook command, so the relay, which only carries sealed items and signed
decisions, cannot approve anything, and neither can the agent. Approvals expire
(the item after 30 minutes, the approval after 60), decisions are single-use,
and the phone sees a sanitized summary, never secrets or raw tool input. Details:
[phone.md](phone.md).

On an internal error, risky action classes **fail closed** (blocked) and
read-only ones fail open. The hook denies a decision it has not finished
after 20 seconds by itself, but it checks that between steps, so a step that
never returns is left to the agent's own hook timeout. `install` sets that
to the agent's default: 600 seconds for Claude Code and Codex, 60 for Gemini
CLI, 30 for Cursor. When it runs out, Codex and Gemini CLI run the tool;
Claude Code's entries carry `onFailure: "block"`, which blocks from Claude
Code 2.1.295 (not verified live; `doctor` warns on older versions); Cursor's
entries are fail-closed. See [limitations.md](limitations.md).

## How it is built

- **A pure policy engine** (`src/engine`): a normalized action and the session
  state go in; a verdict with reasons comes out. No I/O. Unit tested,
  including refusal cases.
- **A conservative shell parser** that recovers quoting, ANSI-C escapes,
  substitutions, pipelines, redirections, here-documents, nested shells and
  the wrappers in its table, so a write through `tee` or `sed -i`, a program
  name spelled with escape sequences, or a command inside `bash -c` is judged
  by what it does. What it knows it cannot resolve is judged strictly. It is
  not complete: some constructs are not analysed yet and can run without a
  prompt, even after outside content (see [Shell constructs not yet
  analysed](limitations.md#shell-constructs-not-yet-analysed)).
- **A signed, hash-chained decision log** (`log verify`), with rotation that
  carries the chain across files. The signing key sits in the firewall's own
  directory, so something that can write there can rewrite the log; `log
  anchor` keeps a copy of the signed head off the machine to catch that
  ([logs.md](logs.md)).
- **Atomic, locked state** that holds up under several Claude Code sessions and
  subagents at once.

See [`design.md`](design.md), [`coverage.md`](coverage.md) (every rule mapped to OWASP LLM and Agentic Top 10, MITRE ATLAS/ATT&CK and the MCP specification, with what each item leaves uncovered), [`threat-model.md`](threat-model.md),
[`incidents.md`](incidents.md), [`policy.md`](policy.md), [`limitations.md`](limitations.md).

## No telemetry

No network calls during a decision, and nothing about you or your work ever
goes to LaunchSafe unsealed. Network use is: the `update` command you run
yourself, which downloads OSV's public malicious-package lists (a GET of each
ecosystem's export; nothing is sent); the MCP gateway relaying your MCP client's
own traffic to the servers you configured (and `mcp login`'s discovery, client
registration and sign-in with their authorization servers); `run`'s proxy,
which only carries the sandboxed agent's own connections to hosts your policy
lists and adds nothing; `log anchor --exec`, which runs the upload command you
give it; and, only if you pair a phone (the hosted relay is not available yet,
so today this does not happen), the relay daemon talking to the LaunchSafe
relay, which would carry sealed items and signed decisions (never during a
decision: the hook only queues). Some commands you start also listen for
connections on this machine: `mcp serve` and the dashboard (`ui`) on
127.0.0.1, the local API (`serve --api`) on a Unix socket or a loopback port,
and the OpenShell middleware (`openshell serve`), which without TLS any process
that reaches its port can use ([limitations.md](limitations.md#openshell-middleware)).
The policy, the session state, the approval
queue and the decision log are all local files under `~/.launchsafe-firewall`
(mode 700). There is no account, no phone-home, no analytics.
