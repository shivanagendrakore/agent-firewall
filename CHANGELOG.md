# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- MCP tools named with a reading verb followed by a noun that is also a verb (`read_message`, `get_email`, `list_messages`) are reads again. They were classed as sending a message, so after a session read outside content an agent could not read its own inbox: a live run with Claude Code and a Gmail-style server held every `read_message` with the reason "It sends a message to people". A writing verb later in the name (`search_replace`, `get_and_update_message`) still makes it a send.

## [0.3.2] - 2026-10-17

### Fixed

- The agent-file scan no longer flags a vendor skill that only decodes a file (a base64 helper whose result is never run) or that tells the model what to say to the person ("don't tell the user to ..."). Both were found in a live run with Anthropic's own google-workspace skill, and each put every session into the untrusted state. A decode still counts when something on the same line runs it, and an order to hide things from the person still counts.

## [0.3.1] - 2026-10-16

Maintenance release. The installed firewall behaves as in 0.3.0; this is the
first version published by the repository's release workflow through npm
trusted publishing, with a provenance statement.

### Changed

- The README says the npm package and the Python SDK (`launchsafe-firewall` on
  PyPI) are published; the Python SDK and browser extension READMEs name the
  security contact.
- Timing checks in the test suite allow slower shared CI runners, and two
  compile-cache tests skip under coverage (they still run in the normal test
  jobs).

## [0.3.0] - 2026-10-16

First public release.

The code was reviewed by the maintainers with AI assistance before release.
There has been no third-party audit. Known limits are in
[docs/limitations.md](docs/limitations.md). Please report problems privately
([SECURITY.md](SECURITY.md)).

### Added

#### Protecting coding agents

- **Hooks for coding agents**: Claude Code, Codex, Gemini CLI and Cursor, with
  `install`, `doctor` and `uninstall` ([usage](docs/usage.md),
  [per agent](docs/agents/overview.md)). Cursor is only partly verified (see
  [the agents overview](docs/agents/overview.md)).
- **A fixed rule table** that allows, asks, holds or denies every tool call by
  what it does, with outside content tainting the session
  ([how it works](docs/how-it-works.md), [policy](docs/policy.md)).
- **Catastrophic actions** (deleting the workspace, force-pushing over `main`,
  dropping a database, deleting cloud resources) are denied from a fixed list of
  commands in the bypass modes. The hooks were captured firing for Codex
  (`codex exec`) and Gemini CLI (yolo mode); a deny there was not captured, and
  that the agent enforces it is not verified. For Claude Code's bypass mode, one live run on 2.1.302
  denied a workspace delete. The Cursor bypass mode is not
  verified. The denials cover a fixed list of commands, not every way to do the
  damage
  ([agents](docs/agents/overview.md#bypass-and-yolo-modes),
  [limitations](docs/limitations.md)).
- **Infrastructure tools.** A preview of a teardown (`terraform plan -destroy`,
  the `tofu` and `terragrunt` forms, `pulumi preview --destroy`) is allowed like
  a plain plan, because it changes nothing. Saving a plan to a file (`-out`,
  `--save-plan`, Terragrunt's `--out-dir` and `--terragrunt-out-dir` and their
  JSON forms) is asked, because applying a saved plan carries no destroy flag;
  so is setting `TG_OUT_DIR` or `TERRAGRUNT_OUT_DIR` in a command, as for
  `TF_CLI_ARGS`. An option's value before the subcommand is not taken for the
  subcommand: `pulumi -C infra up`, `pulumi --stack prod up`,
  `terragrunt --terragrunt-working-dir infra apply`, `cdk --profile prod deploy`
  and `serverless --stage prod deploy` are judged as the changes they are, and
  `terragrunt run-all apply` is judged as an apply. `serverless --stage prod
  remove` and `pulumi up --destroy` (also after pulumi's own options) are denied
  (FW-CATASTROPHIC). `pulumi -C infra logs` and `serverless --stage prod logs`
  count as reading outside content ([agents](docs/agents/overview.md),
  [limitations](docs/limitations.md)).
- **Package registries.** A registry or index named by an option is read in the
  ways the package managers accept it: `npm --registry <url> install` and
  `publish`, `npm view --registry`, `pip --trusted-host <host> install`, uv's
  `--index=<url>`, `--default-index=<url>` and named index (`name=<url>`),
  cargo's `sparse+https` index, a scope's `--@scope:registry=<url>`, and pip's
  `-i<url>` and `-f<url>`. A new registry named that way asks (`FW-NEW-HOST`
  under `knownHosts`, `FW-FETCH` after outside content). `-i` and `-f` name an
  index only for the Python installers, npm, pnpm, yarn and bun take a value
  only for `--registry`, and a local index directory is read like a package
  given as a path ([limitations](docs/limitations.md)).
- **Shell writes with a target only known at run time** (a redirection to a
  path built from a variable) need a person (`FW-UNCLASSIFIABLE`), also when the
  same command line hands the text in quotes to a program the analyzer has no
  model for.
- **Credential and personal-data checks** on outbound data: a credential-shaped
  value is denied unless it goes to the service that issued it. Digits inside a
  long hex token are not read as a card number, so a hex-encoded secret is
  denied as a secret the session read, not as a card
  ([limitations](docs/limitations.md)). The credential scanner runs in linear
  time on hostile text (many `BEGIN PRIVATE KEY` lines, long runs of `-eyJ` or
  `${`, a JWT shape with a very long last part), cuts no private key short, and
  text shaped like a JWT in front of a Supabase service-role key does not hide
  the key ([limitations](docs/limitations.md#data-leaving-the-machine)).
- **Spending limits** per session and per day
  ([usage](docs/usage.md#spending-limits)). `budgets.stopScope: "agent"` makes a
  behaviour monitor stop cover every session of that agent
  ([policy](docs/policy.md#budgets-budgets)). Cursor's failed tool results
  (`postToolUseFailure`) are read like any output and count toward the
  identical-failures limit ([Cursor](docs/agents/cursor.md)).
- **Watch mode** for gradual rollout ([policy](docs/policy.md#watch-mode-rollout)).
- **Known hosts.** `knownHosts.builtins: false` turns off the built-in set only:
  the package registries and GitHub's code hosts stay known through the
  defaults of `fetchAllowHosts` until you set that list without them. `hosts
  list` names the built-in hosts that stay known and the list (`fetchAllowHosts`,
  `sendAllowHosts` or both) to set without them ([policy](docs/policy.md),
  [usage](docs/usage.md#known-hosts-ask-before-the-agent-contacts-a-new-website),
  [limitations](docs/limitations.md)).
- **An unattended queue and a reviewed approval flow** ([usage](docs/usage.md)).
  A stored approval is used only while every rule that asks is one the person
  was shown when they approved it, and, in the hook and the MCP gateway, only
  in the working directory and project it was given in. The engine checks this,
  so the hook, the gateway, the local API and the library all apply it; the
  action asks again, with a message that says why, and the approval is kept, not
  spent. An answer given in the client covers the rules its question named. A
  call that becomes several actions (a multi-file patch) and is held names the
  rules of the actions that would only be asked about, since one approval runs
  them all, and the approval is checked against every one of them
  ([threat model](docs/threat-model.md), [limitations](docs/limitations.md)).
  Approvals made by an earlier pre-release build are not used; the action is
  held again under a new id.
- **Unattended detection and agent-started commands.** On Linux the firewall
  reads `/proc` instead of running `ps` (absent, or without `-p`, in
  Debian-slim, Alpine and busybox images; the `/proc` reading is tested on a
  simulated `/proc` tree and on glibc Linux, not run on Alpine). A session whose agent process cannot
  be read is treated as unattended for all four agents, so an action that would
  ask is held in the queue. The check that refuses approvals, `run`, the kill
  switch's stop, the `api` commands and `openshell serve` to a process an agent
  started reads `/proc` the same way, reads each command line on one line (a
  line break in an argument becomes `?`, so `run` with a multi-line prompt is not
  taken for an agent), and refuses when a process on the way cannot be read,
  saying so ([limitations](docs/limitations.md)).
- **Tampering.** Stopping the firewall's processes by a name in another letter
  case (`pkill -i`, `killall -I` on Linux) is FW-TAMPER: the command name, the
  hook's marker variable and the relay and local API commands are compared
  ignoring case, as the CLI file's path is ([design](docs/design.md)).
- **Linux and WSL credential stores.** GNOME Keyring and KDE Wallet files, the
  host's SSH private keys, `/run/secrets` and the Docker socket are credential
  stores. A glob that could name one (`/etc/ssh/ssh_host_*`, also before the
  last part of the path or with `**`) reads it, as it does for the stores in
  the home directory (`~/.git-cred*`).
- **Recursive reads on Linux.** A recursive read, copy, archive or container
  volume of a directory above a credential store (`/etc/ssh`, `/etc`, `/run`,
  `/var/run`, `/proc`) asks as a credential read (FW-CREDENTIAL-READ), under any
  spelling and through a symlink.
- **Agent settings paths on Linux.** Claude Desktop's `~/.config/Claude` is
  matched as spelled, and Cursor's `~/.config/Cursor/User/settings.json` is
  protected like the macOS one. A write to an instruction or settings file
  leaves the record an ordinary write does: written with a credential, the file
  is a secret file, and written after outside content (once a person approves
  it), it counts as such.
- **An unsupported platform fails closed.** The package is limited to macOS and
  Linux (`"os"` in `package.json`). On Windows or any other platform the hook
  command blocks the action (exit 2) and says why, every other command but
  `help` and `version` refuses before reading or writing anything (`run`, the
  gateway and the local API included), and the Node library throws when a guard,
  a file store, a file ledger or a Node environment is created
  ([limitations](docs/limitations.md)).
- **A UTF-8 byte order mark is read, not refused.** A settings file, a lockfile
  or requirements file, or the hook's or `check`'s standard input that starts
  with one (a Windows editor's or PowerShell's) is read as if it did not.
  Install, `doctor --fix`'s sandbox step, the Codex hook-trust step and
  `install --agent gemini --seatbelt` keep the file as it was, mark included, in
  their backups, and `uninstall --restore-backup` counts the person's edits
  against the settings after the mark. A write to a settings file that starts
  with a mark is judged as an agent that drops the mark would load it, as well
  as unchanged. Policy files are still read strictly
  ([limitations](docs/limitations.md)).
- **Hidden text.** Zero-width characters in what the agent reads
  (FW-HIDDEN-OUTPUT): one zero-width space, or a few, is ordinary text and no
  finding. A dense run (eight or more, or four in a row) makes the session
  untrusted in the hooks and the library. The gateway withholds a result, and
  the email guard quarantines a message (`dense_zero_width_instruction`), when a
  dense run is within 200 characters of a phrase addressed to an AI assistant,
  counting every place the phrase appears and measuring from its nearer end on
  either side. The rule is in
  [docs/design.md](docs/design.md#what-taints-what-counts-as-sending) and pinned
  by tests and conformance vectors.

#### Building on the firewall

- **The library** for agents you build ([library](docs/library.md)) and the
  **local API** for any language ([API](docs/api.md), [contract](docs/api-v0.md)),
  with a [Python SDK](python/README.md). Runnable examples are in
  [examples/](examples/README.md).
- **A provenance ledger.** The library records what each reported tool result
  left (with `fileStore`, the hook's ledger in the same firewall home, and
  `fileLedger` for a custom store), and the local API uses it. A script an
  untrusted session wrote, or a build manifest it changed, asks for a person
  when a trusted session runs it (`FW-UNTRUSTED-CODE`, `FW-TAINTED-MANIFEST`); a
  later trusted write of the whole file clears it; and a file a trusted session
  wrote reads back without counting as outside content. A trusted session that
  reports writing the same bytes again does not make them trusted, and a call
  the guard denied (one it could not check included) or held, or whose result
  failed, vouches for nothing it left. The memory store keeps no ledger, by
  design ([library](docs/library.md#the-provenance-ledger),
  [API](docs/api.md#files-a-session-wrote)).
- **MCP gateway** ([gateway](docs/gateway.md)) and **email guard**
  ([email guard](docs/email-guard.md)). `gateway quarantine` and `mail
  quarantine` say when a record in the store is damaged, and `mail quarantine
  release` refuses a message the firewall could not read at all (it has no
  fingerprint, so there is nothing to release) and says to discard it.
- **`run`**, an OS sandbox for any program, with presets for Claude Code, Codex
  and Gemini CLI ([run](docs/run.md)). On Linux its integration tests
  have been run in a Docker container (Debian 12, bubblewrap 0.8) and on GitHub's
  Ubuntu runner (bubblewrap from apt), not on another distribution, on a
  bare-metal or virtual-machine host, or with a real agent inside. On macOS the
  maintainer loaded the profile on a Mac by hand; no CI job runs on macOS while
  the repository is private. Another `HOME` means another
  firewall data directory ([limitations](docs/limitations.md)). The approval
  commands and `run` recognise the same agent programs, including Codex's native
  release binary and Cursor's agent folder; an agent that detaches its command is
  not seen as one.
- **NVIDIA OpenShell supervisor middleware** (experimental), tested against a
  stand-in built from OpenShell's published protocol, not a real gateway
  ([sandboxes](docs/sandboxes.md)). Its requests are sent as network traffic
  (`context.traffic: "network"`), so they do not use up the agent's `toolCalls`
  limit or its agent-wide monitor
  ([local API](docs/api.md#network-middleware-traffic)). A request or WebSocket
  message to an IP address that is not on the public internet (a private
  network, link-local, multicast, a documentation or other special-purpose
  block, in any spelling, and a loopback address in the translated IPv6 form
  `::ffff:0:127.0.0.1`) is denied without being judged: reason code
  `launchsafe_deny_internal_address`, recorded as `FW-NET-REFUSED`.
- **A secret vault** with `vault://` references ([vault](docs/vault.md)).
- **A read-only local dashboard** ([dashboard](docs/dashboard.md)).
- **The browser extension and browser link** ([browser link](docs/browser-link.md)).
  The extension is built from source and is not in a browser store.

#### Evidence

- **A signed, hash-chained decision log** with offline-verifiable export and
  off-machine anchors ([logs](docs/logs.md)).
- **`demo`** replays 18 scenarios (11 public incidents, 5 attack patterns and 2
  unattended variants) through the policy in a temporary directory, installs
  nothing, and ends with a count by verdict (denied, asked or held), saying
  whether any action ran without a person. The scenarios are written by us, not
  recordings of the attacks ([usage](docs/usage.md#try-the-demo),
  [incidents](docs/incidents.md)).
- **`doctor`** reports each agent's hook timeout (Codex 600 s, Gemini CLI 60 s)
  and the hook's own 20 s deadline.
- **Documented limitations, threat model and coverage**
  ([limitations](docs/limitations.md), [threat model](docs/threat-model.md),
  [coverage](docs/coverage.md), [incidents](docs/incidents.md)).
- **602 recorded conformance vectors** in 20 files that other implementations
  can replay (`conformance/`), 12 of them for the provenance ledger
  (`prepared-ledger`).
- **Damaged files are read in linear time and reported.** A damaged session file
  is read in time linear in its size and leaves the session untrusted; the first
  ten damaged lines are listed and the rest counted
  ([design](docs/design.md#runtime-durability-and-concurrency)). A quarantine
  record with a missing or wrongly typed field, or one filed under another
  record's id, is listed as damaged and `doctor` warns
  ([threat model](docs/threat-model.md#the-firewalls-own-files-fuzzing)).

### Known limitations

The full list is in [docs/limitations.md](docs/limitations.md). In short:

- Phone approvals are experimental and not usable yet ([phone](docs/phone.md)).
- Cursor is only partly verified, and its bypass mode is not verified
  ([agents](docs/agents/overview.md)).
- The OpenShell middleware is experimental and has not been run against a real
  gateway.
- The browser extension is not in a store, and was tested with scripted stand-in
  agents, not real browser agents.
- Bypass-mode denials cover a fixed list of commands, not every way to do the
  damage, and a deny in the bypass modes was not captured for any agent.
- The signed decision log has had no third-party audit.
- Protected places are matched ignoring case on every platform, because a Linux
  host cannot tell whether a directory folds case (WSL2's `/mnt/c`, say). On a
  case-sensitive disk a look-alike path (`agents.md` or `.Claude/` in another
  directory) can be held or asked about. Matching ignoring case only adds a
  question: what counts as outside content keeps the platform's rule, so on
  Linux reading or listing such a look-alike outside the workspace still makes
  the session untrusted, and a program whose path only looks like the installed
  CLI is judged as any other program ([limitations](docs/limitations.md)).
- On a server whose `/proc` hides other users' processes (`hidepid`), the check
  for commands an agent started refuses `run`, approvals and the like over SSH,
  a `session stop` included.
- `run`'s Linux tests have been run in a Docker container (Debian 12, bubblewrap 0.8) and on GitHub's Ubuntu runner, not on other distributions or a bare-metal or virtual-machine host. On macOS the profile was loaded on a Mac by hand only; no CI job runs on macOS while the repository is private.
