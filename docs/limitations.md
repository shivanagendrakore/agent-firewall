# Limitations

This is the one list of what the firewall does not do. Each item is stated
once, plainly. The page for each part has the detail; this page has the
summary. If a claim elsewhere in the docs reads stronger than an item here,
this page is right and the other page has a bug: please report it.

The code was reviewed for security before release by the maintainers, with AI
assistance; there has been no third-party audit. The fixes are covered in the
[changelog](https://github.com/shivanagendrakore/agent-firewall/blob/main/CHANGELOG.md). Some shell-command constructs are not analysed
yet; they are listed in [Shell constructs not yet
analysed](#shell-constructs-not-yet-analysed) below. If you find another one,
please report it privately as described in [SECURITY.md](https://github.com/shivanagendrakore/agent-firewall/blob/main/SECURITY.md).

## Shell constructs not yet analysed

The shell analyser does not yet follow these. A command that uses one may run
without a prompt, including in a session that has read outside content, when
what it does is hidden inside the construct. Each is a known gap.

- **Wrapper options that rewrite the command**, for example `env -S` with
  escape sequences, and program-running wrappers that are not in the wrapper
  table.
- **A shell's `+option` flags** (`bash +x`) are read as the script file, so a
  script given on standard input is not analysed.
- **Scripts read from standard input** through `/dev/fd/0` or
  `/proc/self/fd/0`.
- **Code piped or redirected into an interpreter** (`python3`, `node` and
  similar reading the program from a pipe, `<` or a here-string).
- **Placeholder programs** in `xargs -I`, `parallel` and `find -exec`, where the
  program to run is `{}` or another placeholder filled in at run time.
- **`fd -x` and `-X`** when the option is part of a short-option cluster
  (`fd -tdx`).
- **`find -exec ... +`** when the `+` is not directly after `{}`.
- **`xargs` handing run-time paths to programs that write**, for example
  `xargs truncate`.
- **`parallel --pipe`** feeding standard input to a shell.
- **SQL piped on standard input** to a database client, and **programs started
  from inline interpreter code** (a program launched by a `-c` or `-e` string).
- **Values assigned earlier in the same command line.** A variable set at the
  start of a command is not carried into the words after it, so a verb, a
  program name or a host held in such a variable is not seen.
- **A secret environment variable reaching a request indirectly**, through a
  command substitution around the variable or from another stage of a pipeline,
  in a session that has not read outside content. Naming the variable to
  `printenv` is caught.
- **Suggested commands rebuilt at run time.** The check for running a command
  that outside content suggested compares the command's text, so the same
  command assembled from variables or command substitutions is not matched.
- **Other gaps the shell analysis leaves** (from
  [threat-model.md](threat-model.md)): `cd -P` is followed logically, not
  physically; a symlink made in the same command by a script or inline code
  (`python -c 'os.symlink(...)'`) is seen only at the next action; zsh-only
  grammar beyond the modelled cases is read as bash; arithmetic evaluation of a
  variable's contents (`(( x ))` where `x` holds `a[$(cmd)]`) is not followed;
  `echo` and `printf` are the only producers whose output piped into a shell is
  modelled (anything else is treated as opaque); a run-time path handed to a
  program outside the deleters, shells and interpreters (`xargs sed -i`,
  `xargs chmod`) is not judged as an unknown path; and proxy variables are
  followed for the network fetchers (curl, wget, httpie and similar), not for
  every program that honours them.

## What kind of tool this is

- **It is a layer, not a sandbox and not a guarantee.** The hooks decide whether
  a tool call runs. They do not contain a program that does run. Use the agent's
  own OS sandbox with it (`doctor --fix` for Claude Code, `run` for agents with
  no sandbox).
- **It cannot stop a model from being fooled.** It limits what a fooled agent
  can do. It assumes the model can be persuaded.
- **It does not defend against you, or against code that already runs on your
  machine as you.** A program running as your user, outside the agent's sandbox,
  that the firewall cannot see into, can read your files and your keychain.
- **Only approvals are bound to your passphrase.** Session state, the
  provenance ledger, pins and counters are as strong as the analyser that
  guards the files they live in. The decision log is signed with a key in the
  firewall's own directory: anyone who can write that directory can rewrite the
  log. `log verify` proves integrity against everyone else. It catches an
  edited, reordered or truncated log, and a log file deleted or emptied while
  its recorded head (or the anchor of pruned files) remains; deleting the log
  and its head together leaves what a log that was never written leaves.
  Because a head left behind by a power cut is accepted, someone who can write
  the directory and kept an older signed head can cut the log back to that
  entry, or, for a log first written by a pre-release build, back to its old
  unsigned head.
  `log anchor` answers this for the history it covers: it writes the signed
  head to a place you choose off the machine (a file, a git note, or your own
  upload command), and `log verify <bundle> --anchor` then catches a rewritten
  or cut-back history, even one with a valid chain. Entries after your latest
  anchor still have only the log's own guarantees, and nothing anchors on its
  own: you run it ([docs/logs.md](logs.md)).
- **The log keeps a bounded history.** Files rotate at 5 MiB and at most 20
  rotated files are kept; older files are pruned, leaving a signed anchor of
  where the kept chain starts. Decisions older than that are gone unless you
  exported or anchored them (`log export`, `log anchor`).
- **A full disk does not stop the agent.** Every decision is logged
  before its action runs, except on an I/O failure (below); values an agent chooses are bounded (a long tool
  name keeps its first 1,024 characters and the SHA-256 of the whole), and an
  entry the log refuses is replaced by a short fallback entry. When the log
  refuses even that (its last entry cannot be found), an allowed action is
  asked about, or blocked with no one there (FW-LOG-UNRECORDED), and an
  action that was already asked about says that it has no record. An I/O
  failure is different and kept as it was: on a full disk or a failing
  drive the decision stands (a deny is still a deny, an allow still runs) and
  the error is printed on the hook's stderr, because blocking every tool,
  including the reads needed to free space, would leave you with an agent
  that cannot help. Such a decision has no log entry. The log keeps 1 MiB
  free (`log/reserve.bin`) and gives it up when an append finds the disk full,
  so that append still lands, with a `log_disk_full` entry before it; past
  that, each event that could not be logged is counted beside the log
  (`log/unlogged.json`), the next entry that can be written is a `log_gap`
  with the count, the times and the error, and `doctor` warns about both. The
  chain itself stays intact, so `log verify` alone does not show a gap; and a
  count that could not be written at all (nothing left on the disk) is lost.
  When the log cannot be written, the hook denies sends, destructive actions
  and tampering; reads still go ahead.
- **A hook that times out can let the tool run.** The installer gives each
  hook the agent's default timeout (600 seconds for Claude Code and Codex, 60
  for Gemini CLI), and the hook denies a decision still running after 20
  seconds, checked between steps. Codex and Gemini CLI run the tool when a
  hook does not answer in time. Claude Code entries carry `onFailure: "block"`,
  which blocks on a timeout from Claude Code 2.1.295 (not verified live: the
  Claude Code version tested, 2.1.289, is older than the one that honours it,
  and no later version was captured).
  Cursor's entries are `failClosed: true`, which blocks on a timeout.
- **Browser-link log entries say which extension, not that a browser sent
  them.** The native messaging host takes the extension's origin from its
  first argument, as the browser passes it, and checks it against the origins
  an install allowed. Any local program that starts the host itself with an
  allowed origin (the agent, through a tool call the hooks did not refuse)
  can therefore have it log browser events under that extension's name. The
  host does not yet check that its parent is the browser or run a handshake
  with the extension; until it does, read browser-link entries as "a local
  program claiming to be the extension".
- **Old log files are pruned.** Past 20 archives the oldest is deleted (its
  last hash kept as the signed anchor of pruned files). Each pruned file is
  recorded as a `log_pruned` entry saying whether an export or an anchor had
  covered its entries, and `doctor` warns when one had not. `appendLog`'s
  `keepUnexported` option keeps such files instead (not yet a policy key).
  `log rotate` needs the approval passphrase when one is set.
- **Platforms: macOS and Linux, Node 22 or newer. Windows is not supported,
  and the firewall refuses to run there rather than run half-working.**
  `package.json` limits the package to `darwin` and `linux` (npm refuses to
  install it on Windows unless forced), `install` refuses, the hook command blocks every
  action with exit 2 and says why (so an agent that still has the hook in its
  settings does not run what the firewall could not judge), every other
  command except `help` and `version` refuses before it reads or writes
  anything (`run`, the gateway and the local API included), and the Node
  library throws when a guard, a file store, a file ledger or a Node
  environment is created.
  Any other platform (FreeBSD, say) is refused the same way. If an agent's
  settings still name the hook on Windows, every action it takes is blocked
  until you remove the hook from those settings or run the agent on macOS or
  Linux.
  WSL2 is Linux to the firewall: Windows-side locations (`%APPDATA%`, `C:\Program Files`) are
  not translated to their `/mnt/c` paths. A workspace on `/mnt/c` is covered for letter case, which that
  disk ignores (see [What the firewall sees](#what-the-firewall-sees)).
- **What has been verified on Linux.** The test suite has been run on Linux in
  containers and on GitHub's `ubuntu-latest` runner (Node 22). `run`'s Linux
  sandbox has been exercised live, by its integration tests, in two places: a
  Docker container (Debian 12, bubblewrap 0.8, an unprivileged user, with
  `--security-opt seccomp=unconfined --security-opt systempaths=unconfined`,
  which bubblewrap needs in a container) and that GitHub runner (bubblewrap
  from apt, with the AppArmor restriction on unprivileged user namespaces
  lifted by the CI job). It has not been run by the maintainers on a bare-metal
  or virtual-machine Linux host, on another distribution or bubblewrap
  version, or with a real agent inside it (the live tests run shell commands).
  macOS: the maintainer loaded the profile with `sandbox-exec` on a Mac by hand,
  once; there is no macOS CI run while the repository is private (those jobs run
  on public pushes and pull requests). The macOS rules not shown to block
  anything under `sandbox-exec` are listed in [run.md](run.md) (Limits).
- **A leading byte order mark is read, not refused.** A settings file, a
  lockfile, a requirements file or the hook's standard input that starts with
  a UTF-8 byte order mark (a Windows editor's or PowerShell's) is read as if it
  did not. `install` writes the settings back without it and keeps the file as
  it was, mark included, in its backup (so do `doctor --fix`'s sandbox backup,
  the backup of Codex's `config.toml` and the copy of a Gemini CLI seatbelt
  profile that `install --seatbelt` replaces), and `uninstall --restore-backup`
  counts the edits since install against the settings after the mark. The
  firewall does not check that each agent reads such a settings file the same
  way, so `doctor` can report the hooks as installed in a file that an agent
  which refuses a mark would not load. A settings write the agent makes that
  starts with a mark is judged both ways: as a file that agent would not load
  (a file that registers the firewall's hooks is still refused), and as the
  settings after the mark (a hook switch or a variable that reaches the hook
  process is found there). Policy files are still read strictly: one that
  starts with a mark is invalid.

## What the firewall sees

- **Hooks only see what the agent reports.** Files pulled into a prompt with
  `@` never pass through `PreToolUse`, so they cannot taint a session. Treat an
  `@`-included file as input you chose.
- **A tool it has no model for is held.** Coverage of exotic tools grows over
  time. Until then an unknown tool is sent to a person in any session.
- **In a trusted session it does not second-guess opaque code.** An inline
  script that computes a path and writes there is held only once the session is
  untrusted. Inline code is judged read-only only by a list of known APIs; a
  write API missing from the list is the residual risk.
- **`CDPATH` is not modelled.** A bare `cd name` is resolved against the
  current directory.
- **Symlinks are resolved as they are on disk when the hook runs**
  ([threat-model.md](threat-model.md#symlinked-aliases-of-protected-locations)).
  A link `ln` makes earlier in the same command is applied; one a script or
  an interpreter makes is seen at the next action. A path that cannot be
  resolved (a symlink loop, no permission) is judged as a protected one.
- **Protected places are matched ignoring case on every platform, so a
  look-alike can be held.** A Linux host cannot tell whether a directory folds
  case (WSL2 with the workspace on `/mnt/c`, an SMB or exFAT mount, an ext4
  directory marked case-insensitive), so `claude.md`, `.Claude/Settings.json`
  or `~/.Ssh` are judged as the protected files they would be on such a disk.
  This covers the protected files, persistence points, secret files, credential
  stores, the firewall's own directory, the agents' settings files, the files an
  instruction file imports, and the path lists in your policy (`protectedPaths`,
  `secretPaths`, `untrustedPaths`). On a case-sensitive disk, a separate file
  that only looks alike (`docs/agents.md`, `docs/memory.md`) is held as a
  proposal once the session has read outside content, and a look-alike of a
  secret or a credential store asks. A session that has read nothing outside is
  not slowed down: writes to instruction files are allowed there by default.
  What grants trust keeps the platform's rule. On Linux a directory that differs
  from the workspace only in case is outside it, so work there asks, which
  includes WSL when a Windows editor reports the workspace in other case. The
  same goes for reads: reading or listing your own agent settings, a credential
  store or the firewall's files outside the workspace does not make the session
  untrusted, but on a case-sensitive disk a look-alike (`agents.md` or
  `.Claude/` in another directory) may be someone else's file, so reading it
  makes the session untrusted, and a look-alike of a credential store or a
  secret asks as well. Likewise a program whose path only looks like the
  installed firewall's CLI is judged as any other program, not as the
  firewall's own command. On a disk that folds case under Linux, reading your
  own settings under another spelling makes the session untrusted too, and
  running the firewall's CLI under another spelling is judged as running a
  program from outside the workspace. Still
  matched by the platform's rule, so on a disk that folds case they miss a
  different spelling: decoy files, the provenance ledger, downloaded-file
  tracking, the checks for deleting the home directory or the whole workspace,
  task scope, and the paths `run` keeps read-only.
- **A glob that could name a credential store is read as reading it.**
  `cat /etc/ssh/ssh_host_*` or `cat ~/.git-cred*` asks, and so does a glob
  whose `*` or `**` could reach a store directory. A `*` is taken to name
  hidden files too, as it does with bash's `dotglob`, so `cat ~/*/package.json`
  asks because it could name a file in `~/.ssh`. Listing the same glob (`ls`,
  `stat`, `find`) is not a read.
- **Shell writes to CI files, dev-container files and env-hook files in a
  trusted session are not checked.** Only git hooks and editor tasks are
  promised. A custom `core.hooksPath` directory is not followed there.
- **Names only known at run time get no package verdict** (`npm i "$PKG"`).
- **A shell command over 256 KiB is not read.** One of more than 262,144
  characters is unclassifiable (FW-UNCLASSIFIABLE): a person decides, and
  nothing in it is analysed. Under that bound the whole command is read, in
  time that grows with its length, except for two kinds of command that grow
  faster: thousands of `cd name` steps in a row (each step reads the whole path
  the steps before it built) and hundreds of `ln` statements (each later path
  resolves through all the links made so far). Either takes seconds, not
  milliseconds, before it is decided.
- **Provenance hashes are compared when the hook runs.** A process outside the
  agent could change a file between the hook and the tool's own read.
- **Provenance does not see every writer.** A file an untrusted session wrote
  through something the firewall cannot see (an MCP tool that writes files, a
  program that writes files it was not told about) is not recorded, so it is
  not carried to later sessions; neither is a file larger than
  `provenance.maxHashBytes` (4 MB by default). A person's own edit makes the
  file theirs. The ledger is compacted to the latest entry per path, entries
  younger than 90 days and at most 100,000 paths, so older records drop out.
- **Host tools are catalogued by what they were seen to do.** A host
  application's tool catalogued as showing something to you (`SendUserFile`,
  for one) is not judged as a send. If some deployment of it also uploads what
  it shows (a remote session), that upload is not seen as one.
- **Two Claude Code behaviours the firewall relies on are documented, not
  captured live:** replacing a tool's input with `updatedInput` (the vault's
  rewritten curl and wget commands) and replacing a tool's output with
  `updatedToolOutput` (redaction, hidden-character marking, and the email
  guard keeping a withheld message from the model). If a Claude Code version
  ignored them, the vault's rewrite would not run, and the model would see the
  unredacted output and the withheld message; the taint rule still applies.
- **The first session in a workspace records receipts and taints for nothing.**
  A freshly cloned repository's hooks and MCP servers are judged by the scan
  rules, not as drift.

- **The catastrophic class is a fixed list of commands, not every way to do
  the damage** (FW-CATASTROPHIC). It reads the command the agent runs, through
  wrappers, nested shells and `npx`, but not what a script, a Makefile target,
  an npm script or a program does when it runs (`make teardown` is judged as
  running code, not as a teardown), nor the contents of a file it is handed
  (`psql -f drop.sql`, `kubectl delete -f ns.yaml`), nor a word whose value
  only exists at run time (`terraform $CMD`, `rm -rf "$(pwd)"`): a verb known only
  at run time may be allowed, not denied. A saved Terraform, OpenTofu or
  Terragrunt plan is judged where it is made, not where it is applied:
  `terraform plan -destroy -out=tf.plan` is asked (FW-DESTRUCTIVE), and so is
  a destroy preview Terragrunt saves through its plan directory (`--out-dir`,
  `--terragrunt-out-dir` and the JSON ones), because
  `terraform apply tf.plan` carries no destroy flag and the firewall cannot
  read what a plan file holds. A plan file made outside the session (by a
  person or by CI) and applied by the agent is judged as any apply is:
  allowed in a trusted session, asked after outside content. Terraform,
  OpenTofu and Terragrunt options set through the `TF_CLI_ARGS` variables,
  and Terragrunt's plan directory set through `TG_OUT_DIR` or
  `TERRAGRUNT_OUT_DIR` (and the JSON ones), outside the agent's commands (in
  the person's shell profile, or in the environment the agent was started
  with) are not read; setting one in a command is asked (FW-UNCLASSIFIABLE).
  When an option written without `=` comes right before the subcommand of
  an infrastructure tool (`pulumi --stack dev preview --destroy`), the
  firewall cannot always tell the option's value from the subcommand, so it
  counts every word as a possible subcommand: such a teardown preview is
  asked, not allowed. `git push --force` without a branch reads the branch
  checked out from `.git/HEAD`; when that cannot be read (no file access, a
  detached HEAD, a directory known only at run time) it is asked, not denied,
  and a `push.default` or upstream that sends a feature branch onto `main`
  is not followed. TRUNCATE on a local
  database, dropping one table, deleting one pod or one object stay ordinary
  destructive actions a person may approve. MCP tools are covered for SQL
  (DROP DATABASE; TRUNCATE is asked) and by name (`delete_project`,
  `delete_repository`, `delete_database`, `delete_namespace`, `drop_*`);
  other MCP delete tools stay FW-DESTRUCTIVE. See
  [agents/overview.md](agents/overview.md#bypass-and-yolo-modes) for each
  agent's bypass mode.

## Outside content and hidden text

- **The outsider-writable class is matched by name.** A server is in it when
  a word of its name, or a product name in a tool's name, says it is an error
  tracker, a forge or issue tracker, a support desk, outside chat, mail or the
  web. A server for such content named otherwise is not in the class until
  you add it (`outsiderWritable.servers`). A private tracker only your
  organisation writes to is in it until you exempt it.
- **FW-OUTSIDE-COMMAND compares text, not meaning.** It remembers commands
  that outside content showed in code, on prompt lines, as inline code or
  inside a sentence, at several granularities: each part after wrappers
  (`sudo`, `env`, `nohup`, `time`, `timeout`, `command`, `exec`, `xargs`,
  `bash -c`) are unwrapped and the program is named without its path, the
  program with its arguments in any order and without flags, each URL, each
  script or package file name, each package an install command names, and
  the set of a command's specific words. A command assembled at run time (a
  URL built from variables, a program name printed by `printf`, an alias) is
  not matched (`it.fails` tests in `test/outsider.test.ts`), and the rule
  then rests on the others (FW-FETCH, FW-INSTALL, FW-REMOTE-CODE,
  FW-UNTRUSTED-CODE). Content that only describes a command in words is not
  remembered. Only the first 512 KiB of a result, 64 command parts and 512
  fingerprints per result, and 4,096 per session are kept; past any of these
  the session is marked saturated and every risky command asks, so a long
  page cannot push a real command out. Suggestions last for the session only.
- **What the rule leaves to other rules.** A command that only fetches
  (`curl https://...` with no file kept) relies on FW-FETCH and the data
  rules, not on this one. The project's own scripts run with arguments an
  outsider chose (`npm run deploy -- --force`) are not asked about; once
  outside content changed the project's files they are FW-TAINTED-MANIFEST. A
  script the agent writes itself from outside content and then runs is
  FW-UNTRUSTED-CODE (written after taint), not this rule. Shell-like tools
  covered: Bash, Monitor and PowerShell (and the agents' shell tools, which
  the adapters map to Bash); for MCP tools and tools the firewall does not
  know, the string arguments named like a command (`command`, `cmd`,
  `script`, `shell`, `run`, ...; at most 16, four levels deep) are compared
  too, but only when the call does something risky. Both sides are compared
  without invisible characters or the gateway's ⟦hidden⟧ markers and after
  NFKC, and a result with hidden text (FW-HIDDEN-OUTPUT) or from an MCP
  server whose pin changed is remembered from, as outside content is. A
  result whose check failed in a session that already remembers commands
  marks it saturated.
- **Hidden characters in what the agent read are found, not understood.**
  Tag characters, variation selectors that spell bytes (in a run or one per
  character), invisible format and default-ignorable characters when they
  are dense (eight or more, or four in a row), direction-changing
  characters and terminal control sequences are found in
  every result the hooks or the gateway see. One zero-width space, or a few,
  is ordinary text (pasted prose has them) and is no finding: it does not
  change the session's trust. A dense run untrusts it in the hooks and the library whether
  or not a phrase is near; the gateway marks it, and withholds the result
  only when a phrase addressed to an AI assistant is within 200 characters,
  before or after the run
  ([design.md](design.md#what-taints-what-counts-as-sending)). The gateway's
  phrase check counts fewer kinds of invisible character than the hooks (the
  zero-width set, not soft hyphens or fillers) and counts two ordinary uses
  the hooks skip (a zero-width space between Thai letters, a zero-width
  non-joiner next to a space). In a program's output (a test
  run, a build, in a trusted session, with no file printed beside it) only
  concealed text and OSC strings count, so a cursor trick in a program's own
  output passes. Results past 4 MiB, or with more than 100,000 control
  sequences, are not fully checked and make the session untrusted. Claude
  Code receives MCP results and fetched pages with the characters marked;
  file reads and shell output are never rewritten, and outside MCP results
  every finding makes the session untrusted. Characters the hook never sees
  (a file pulled in with `@`, an image) are not checked. Codex, Gemini CLI and
  Cursor have shown the model the text before the hook runs: the session
  becomes untrusted and the agent is warned, nothing is removed.

- **The HTML scanner does not read every place a person cannot see.** Not
  scanned for hidden instructions: bogus comments (`<!x ...>`, `<? ...>`),
  the bodies of `<script>`, `<noframes>`, `<noembed>` and `<iframe>`, text placed
  directly in `<head>`, and the values of `<meta content>`, `data-*` and
  `aria-*` attributes. A closed `<details>` block counts as visible text.
- **Hiding by colour covers about thirty named colours and the common
  numeric forms.** Text hidden with another CSS colour name or a modern colour
  function (`hwb()`, `lab()`, `oklch()`, `color()`) is read as visible, so it
  is flagged instead of quarantined at most.
- **A terminal conceal trick split over two escape sequences is not
  detected.** Foreground and background colours set in separate sequences
  that end up equal are judged one sequence at a time.
- **Hebrew or Arabic letters next to a bidirectional override exempt it.** Two
  such letters within 16 characters are enough, which real right-to-left text
  needs and an attacker can copy.

## Data leaving the machine

- **Secret fingerprints catch the documented encodings only.** Verbatim,
  URL-encoded (once or twice), base64, base64url, base32, hex, and split across
  DNS labels are found. Reversed, case-changed, ROT13, compressed, encrypted,
  custom-alphabet, interleaved, or a few characters per request are not.
- **A card number inside a long hex token is not found, and encoded ones are
  not either.** The card check reads 13 to 19 digits (single spaces or dashes
  between them are fine) with a valid check digit and a real issuer prefix. A
  run of digits that sits in one piece of ASCII letters and digits (any other
  character ends the piece) is left alone when that piece is hex data: hex
  digits only, after an optional leading `0x`, and at least 8 of them besides
  the number (a hash, a hex-encoded value). Otherwise a hex-encoded credential
  would read as a card number by chance, and be denied under the wrong rule.
  The flip side: a card number written right against 8 or more hex digits is
  not found either. Words, field names, other letters and digits, or a single
  letter against a number do not hide it (`ref`, the `B` that starts
  magnetic-stripe data, text copied with its tags and spacing stripped), nor
  does a line break or a URL-encoded character in front of it. The
  personal-data scan reads the text as written: a card that is hex- or
  base64-encoded, split, or reversed is not found (only secrets the session has
  read are looked for in those encodings, above), and a hex dump with its bytes
  written as pairs of digits separated by spaces can still read as a card
  number. The text the phone and the watch report show is masked without this
  exception, so a card inside a hex token is hidden there.
- **The contents of uploaded files are not scanned.** A file a command sends
  (`curl -d @file`, `curl -T file`, `curl -F x=@file`, `wget --post-file`) is
  counted toward the byte budgets by its size, and the command is judged as a
  send, but the credential, personal-data and fingerprint checks read only the
  command line, not the file's contents (rules that go by the file's path, such
  as a credential-store read, still apply). After outside content the send
  still needs a person; in a trusted session that has not read credentials, a
  file of secrets with an ordinary name can be uploaded without the data rules
  catching it.
- **The data scans have bounds.** The encoded forms (base64, base32, hex, DNS
  labels) are looked for in the first 1,000,000 characters of a payload, and a
  base64 or base32 run counts only when at least 90% of what it decodes to is
  printable. A secret is fingerprinted only when it is 12 to 4,096 characters
  long. The personal-data scan reads the first 2,000,000 characters. Data past
  these bounds is not found by them. The shapes that recognise a credential by
  its form read it whole, however long, except the Supabase service-role key (a
  JWT): its header may be up to 2,048 characters and its payload up to 8,192,
  well past any real one.
- **FW-CREDENTIAL-FLOW asks about sends, not about what they carry.** After a
  session reads a credential, any send to a host you have not allowed needs
  you, in any session, until the session ends. Pushes to a git remote and
  package publishes are left to FW-SECRET-FILE-PUBLISH, which asks only when
  credentials were copied into a file earlier in the session. Only a file
  whose own name says it is not real (`.env.example`, `.env.mock`,
  `fake.pem`, `id_rsa_fixture`) is left out, checked on its real path too;
  a `.env` in a `tests` or `fixtures` folder counts, so reading one starts
  the rule.
- **curl URL globs: a `[x-y]` range in the path is judged by its first value.**
  Every `{a,b}` alternative is judged, up to 256 addresses per URL; past that,
  or with a range in the host, the command asks. A range in the path or query
  does not change the host, but only its first value is scanned as data.
- **Slow exfiltration under a budget is not seen.** Budgets bound how much can
  go to an allowed host; they do not detect it. Rotating subdomains get fresh
  per-host budgets (the total still holds). A web-search query has no host.
- **The taint rule, not pattern matching, is the main control** on sending data
  out of an untrusted session. It depends on the firewall seeing the outside
  content come in.
- **The sandbox sees hosts, not methods.** A host admitted for fetching
  (`github.com`, `registry.npmjs.org`) accepts uploads too. `doctor` labels such
  hosts. Uploads are controlled by the rules for commands the firewall can see
  (`git push`, `npm publish`, `gh`, `docker push`), not by the sandbox.
- **Hosts named in a prompt are allowed by the firewall for that session but
  not by the sandbox.** A fetch to one fails inside the sandbox until you add
  the host to `fetchAllowHosts` and run `doctor --fix` again.
- **Known hosts (`knownHosts`) see only what the hooks see.** A new host asks
  when the agent's own tool call names it. A script, test suite or other child
  process the agent starts opens connections no hook sees; only
  [`run`](run.md#known-hosts) holds those to the list. Some commands contact a
  host the firewall does not read out of them: an image's registry
  (`docker pull new.example/img`), a git remote's address in `.git/config`
  (`git push origin`), a package manager's default registry when it installs
  (`npm install`, `pip install`; a registry or index named by an option, before
  or after the command, or a package given as a URL is read), and
  CLIs with a fixed service (`vercel`, `aws`). An
  address built at run time already asks as `FW-UNCLASSIFIABLE`.
- **Known hosts learn from the tool having run.** Agents do not report who
  answered a question, so the hooks take the tool having run as your yes (as
  the budgets do). That needs a reported permission mode in which a person
  answers (`default`, `acceptEdits` or `plan`), so Codex (unless it reports
  one of them), Gemini CLI, Cursor and the MCP gateway never learn from an
  asked question; only from an action you approved in the queue. Nothing is
  learned unattended, after outside content, for a host that received data, or
  when the agent does not name its project; but an auto-approve setting or an
  allow rule that answers for you can still look like your yes. The list is per
  exact host name, not per address, and it is off by default.
- **Built-in known hosts include model APIs.** Sending your code to
  `api.openai.com` or `api.anthropic.com` does not ask as a new host while
  `knownHosts.builtins` is on.
- **`knownHosts.builtins: false` does not make the package registries ask.** It
  turns off the built-in set only. The defaults of `fetchAllowHosts` also name
  the package registries, `github.com`, GitLab and GitHub's code and content
  hosts, and a host that list names is known, so those stay known until you set
  `fetchAllowHosts` without them (which also changes `FW-FETCH`, the sandbox
  profile and `run`'s proxy, which read the same list). The firewall cannot tell
  a default entry from the same entry you wrote yourself, so it does not try.
- **Package checks are only as good as their data.** A malicious version
  published after your last `update`, or not yet in OSV, is not denied. A
  typosquat of a name outside the shipped popular lists is not flagged. The
  npm list is the hand-kept seed list: npm's search no longer ranks packages
  by popularity, so it could not be regenerated for 0.3. The
  cooldown setting covers the first days of a release; npm and pip have no
  rolling cooldown.
- **Task scope is log-only by default** (`taskScope.mode: "log"`). It records
  what it would have asked and changes no decision until you set `"enforce"`.
  Enforce mode has known friction: tests next to a named file, a path that does
  not exist yet, paths with spaces. The gateway never sees a prompt, so scope
  does not apply there.
- **Task scope is only as precise as the prompt.** A prompt that names nothing
  narrows nothing, and a broad one ("fix `src`") covers all of `src`. A pasted
  block the parser cannot recognise as pasted (no fence, no quote marks) counts
  as your words, so destinations named in it widen the scope.
- **Spending limits count what the firewall sees.** Model tokens and cost
  count only when an agent reports them through the library or the local API,
  and the cost is the agent's own figure; coding agents' hooks report no model
  usage, so token and cost limits do not apply to them. Identical failures
  count only when a result says it failed explicitly (an exit code, an MCP
  `isError`, or `failed` from the library or the API); Claude Code's shell
  results carry no exit code. Traffic from `run` and from processes the agent
  leaves running is not counted. The day is the machine's local day, so
  changing the clock or the time zone moves midnight (a day never goes
  backwards). `memoryStore()` keeps the day's counters only while the process
  runs. Bytes to install and clone hosts, loopback, `sendAllowHosts` and
  `budgets.exemptHosts`, and traffic through the `run` proxy, are not counted.
- **Identical failures can be evaded by output that changes.** Failures count
  by the error text with its numbers removed; output that changes in other ways
  each run (a random word, a temporary path) is a new failure each time. A
  second counter keyed by the action and its exit status catches that, at three
  times the limit.
- **Limits can be passed by as many calls as run at once.** The counters are
  read before a decision and written after it, so calls decided at the same
  moment (parallel tool calls, several agents) each see the same count: a limit
  can be passed by at most the number of calls in flight, and the next call is
  denied.
- **Loop detection can arrive fast for agents that cannot ask.** Eight runs of
  the same command in ten minutes asks. Polling (`gh run view`, `git fetch`)
  can hit it. On Codex, Gemini CLI and Cursor every ask is held, so 25 holds
  in ten minutes make every non-read action a loop hit, and an unattended run
  that keeps going reaches the behaviour monitor's 60 and is stopped until you
  resume it.
- **The behaviour monitor counts, it does not judge.** It stops a session that
  crosses one of four fixed counts in ten minutes (actions needing a person or
  blocked, new hosts, attempts to change configuration or the firewall, the
  same blocked action again). An agent that drifts slowly, below every limit
  and within allowed actions, is not stopped; nor is failure that spreads to
  other agents or systems the firewall does not see. The counts are per
  session: an agent that starts many short sessions resets them (`agent stop`
  covers every session of an agent, but only a person runs it).
- **The monitor can be tripped on purpose.** Outside content can steer an
  agent into blocked retries or many new hosts so that the session stops. It is
  a denial of service (the session then does nothing), not a way past a rule; a
  project may not lower a stop limit below half its default.
- **A deleted stop record un-stops silently until doctor runs.** The records
  live in the protected data directory, but something other than the agent
  (another program, a person) can delete them. `doctor` fails on a stop the
  signed log shows with no resume that is no longer in force. A monitor stop is
  also kept in the session's counters file; deleting both ends it.
- **A stop only reaches what the firewall decides.** `session stop` and
  `agent stop` block every later tool call the hooks, the gateway, the library
  with its file store or the local API send through the firewall. A command
  already running keeps running, an agent without the hook installed is not
  stopped, and the library's memory store keeps a monitor stop only for the
  life of the store (it has no person's resume; make a new store).

## Agents

- **Each agent's hooks set the ceiling.** Codex, Gemini CLI and Cursor show the
  firewall less than Claude Code does. None of the three can ask you: held
  actions wait in the queue. Codex and Gemini CLI let a tool run when a hook
  times out. Codex's hosted web search never reaches a hook. Codex cloud runs no
  local hooks. Cursor's cloud agents run only the repository's hooks, where a
  project install's paths do not exist (and, failing closed, block every
  action there). See the table in [agents/overview.md](agents/overview.md).
- **Codex runs its prompt hook only without a matcher.** Codex 0.162.1 skips a
  `UserPromptSubmit` group that has any matcher (`"*"`, `""`, `".*"`),
  silently (captured). Installs before this fix wrote `"*"`, so on Codex the
  firewall never saw a prompt: no task scope and no destinations you named.
  `doctor` fails on such an install; run `install --agent codex` again. Until a
  prompt arrives, a Codex session has no task scope (today's rules apply) and
  no named destinations (a fetch after outside content is held).
- **Unattended runs are detected from the agent's command line.** Gemini CLI
  tells its hooks nothing about `-p` or yolo mode, and Codex's `codex exec`
  and Cursor's `-p` are found the same way (Claude Code's `-p` is read from
  its own process: `CLAUDE_PID`, else the hook's parent). The firewall reads
  the command lines from `/proc` on Linux, which needs no `ps` (Debian-slim,
  Alpine and busybox images have none, or one without `-p`; reading `/proc` is
  tested on a simulated `/proc` tree and on glibc Linux, not run on Alpine), and with `ps` on
  macOS, where it falls back to `pgrep` if a seatbelt sandbox forbids `ps`
  (Gemini CLI's own `-s`). If no process can be read, the session is treated
  as unattended, for every agent: held actions wait in the queue instead of
  being asked. What it cannot see is an agent outside the hook's process view:
  in a container or sandbox with its own process namespace, with the agent
  running outside it, the walk ends at that namespace's first process and the
  session is taken as attended. Set `unattended` in the policy or
  `LAUNCHSAFE_FIREWALL_UNATTENDED=1` there.
- **Gemini CLI's own sandbox (`-s`) needs the firewall's profile.** Without
  it the hook cannot save its state there and blocks every action (one message
  says what to do). `install --agent gemini --seatbelt permissive-open` writes
  a profile that adds write access to the hook's state directories only, used
  with `SEATBELT_PROFILE=launchsafe`. The agent's commands share that sandbox,
  so the hook's state (sessions, queue, log, ledger, scan receipts) is
  protected there by the analyser alone, as without `-s`: a command the
  analyser cannot see through could reset a session's taint or counters, or
  delete log files (the signature chain shows the gap; it cannot prevent it).
  The profile cannot make those files append-only (Seatbelt has no such rule),
  and the hook has no separate helper process to write through yet. The
  policy, keys, records and vault stay read-only. Rerun the command after updating Gemini
  CLI. `mcp wrap` inside `-s` and Gemini CLI's container sandboxes were not
  tested.
- **Cursor's formats were read from source, not captured live.** So were
  Cursor's server-side tool names, its subagent events and its IDE hooks. They
  are marked in the fixtures.
- **Four behaviours of Codex and Gemini CLI were not captured.** The firewall
  assumes the riskiest reading: whether Gemini CLI fires `BeforeAgent` for a
  subagent; whether Codex reports a shell-run `apply_patch` as `Bash`; the
  exact URL extraction of Gemini's `web_fetch`; the loose matching of Codex's
  `apply_patch` and Gemini's `replace`.
- **Tab completions, typed shell input (`WriteShellStdin`), computer use and
  screen recording in Cursor carry nothing the firewall can judge.** The last
  three are held as unknown tools.
- **A hook never sees an MCP server's full tool list.** Without the gateway,
  description pinning covers only what Claude Code shows through its ToolSearch
  tool.
- **A repository can switch hooks off, unless the install is managed.** Claude
  Code's `disableAllHooks`, Codex's `[features] hooks = false` and Gemini CLI's
  `hooksConfig` are set in files a repository can ship, and in a `claude -p`
  (headless, CI) run Claude Code applies a repository's settings without the
  trust dialog. A run started with `--setting-sources` that leaves out `user`
  does not load user-level hooks at all. Only the managed install
  (`install --managed`) resists all of this; it is the recommended install. It
  does not cover flags a CI job passes. The managed installs of Claude Code,
  Codex and Cursor **have not been tested on a real machine** (the generated
  files are checked, not deployed as an administrator and run through the agent;
  Codex's needs root and Codex ignores the file in `$CODEX_HOME`), and whether Codex also needs `[hooks] managed_dir` is not
  verified ([Codex](agents/codex.md#managed-deployment)).
  `doctor` fails, naming the file and the fix, on every such setting the
  managed install does not override, including a settings file's `env` that
  sets `LAUNCHSAFE_FIREWALL_*`, a code-loading `NODE_OPTIONS`, `HOME`, `NODE_PATH`,
  `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` and similar, and
  `doctor --ci` runs only those checks, strictly (the firewall not installed,
  or watch mode on, also fails), with exit 1, for a CI job or a pre-commit
  check. Doctor reads files; it cannot see command-line flags a CI
  job passes (`--setting-sources`, `--settings`, Codex's `-c features.hooks=false`)
  or a folder Gemini CLI does not trust (`--skip-trust` skips hooks too).
  The hook command pins the firewall's data directory and `HOME` and sets
  `NODE_OPTIONS`, `NODE_PATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`,
  `NODE_COMPILE_CACHE` and the test markers empty for the hook's node, so a
  settings file's `env` (or the shell that starts the agent) cannot reach the
  firewall's code through them. The shell that runs the hook command itself
  still sees the agent's environment (`BASH_ENV`, `ENV`, `IFS`, and
  `LD_PRELOAD` for the shell); `doctor` reports a settings file that sets them,
  and an agent writing one is FW-TAMPER. A hook whose `HOME` differs from your
  user's home in the user database refuses every tool call (FW-TAMPER);
  installs from before this release do not pin it (`doctor` warns: install
  again). A managed install serves every user, so it pins no one's `HOME` and
  sets the data directory empty: the hook derives both from the user database.
- **The firewall's data directory belongs to one home, and another `HOME`
  means another directory.** A command resolves it from `LAUNCHSAFE_FIREWALL_HOME`,
  else from `HOME`, so one run under `sudo` or `su`, as another user, in a
  container, or with `HOME=` in front of it works on a different
  `.launchsafe-firewall`: its own policy, approval key, queue, sessions and
  log. An approval, `queue` or `log` command run that way does not reach the
  hook that judges your agent. To make two runs share one directory, set
  `LAUNCHSAFE_FIREWALL_HOME` to the same path in both. The installed hook
  does not follow the environment's `HOME`: it uses the directory and the
  home its command pins, and a hook run as another user, or with a `HOME`
  that is not its user's, refuses every tool call (FW-TAMPER) instead of
  judging with state that is not that user's. A managed install gives every
  user of the machine a firewall home of their own, derived from the user
  database.
- **The hook answers within its own deadline, cooperatively.** A decision not
  finished 20 s after the hook process started (configurable 1 to 25 s with
  `LAUNCHSAFE_FIREWALL_HOOK_DEADLINE_MS`) is denied by the hook itself, and every
  wait inside it (a lock: at most 2.5 s; the session-start scan; a phone hold) is
  given only the time that remains. The decision is synchronous, so the deadline
  is checked between steps: a step that never returns is left to the agent's own
  timeout, which install sets to the agent's default (600 s for Claude Code and
  Codex, 60 s for Gemini CLI, 30 s for Cursor). Claude Code blocks on a hook
  timeout only with `onFailure: "block"` (install writes it; honoured from
  Claude Code 2.1.295, `doctor` warns on older versions); Codex and Gemini CLI
  let the tool run.
- **Claude Code's `bypassPermissions` and `auto` modes are held, not asked,
  by default.** Whether a hook's `ask` reaches a person there is not verified,
  so they are in `unattendedPermissionModes` by default.
- **The agent-configuration check is strict about what it could not read.** An
  agent file over 512 KB, one that is a symbolic link leading out of its folder
  (a dotfiles link for `~/.claude/CLAUDE.md` included), and a check that stopped
  at a time, file, byte or directory cap make the session start untrusted, with
  the file or the cap named. Large repositories and dotfiles setups see this
  more often.
- **An MCP tool name split on `__` can be ambiguous.** Where the agent's event
  names the server in a field of its own (Claude Code, Cursor, Gemini CLI with
  `mcp_context`), that is the identity. Where only the joined name exists
  (Codex), a name with more than one `__` boundary is asked.
- **The firewall's own data directory is not readable by an agent without you.**
  Its keys, vault and signing material are denied; anything else there (the log,
  the queue, policy, session state) is asked as a credential store.

- **A Cursor subagent's remembered outside commands are not carried to its
  parent or back.** Taint, fingerprints and credential reads are carried;
  commands that outside content showed to the child are not, so
  FW-OUTSIDE-COMMAND stays empty for text the parent received from it.
- **Twenty protected-file or persistence writes in ten minutes stop the
  agent.** Heavy but ordinary editing of workflow files or `CLAUDE.md` can reach
  it; resuming needs the approval passphrase.
- **The browser extension cannot check an approval's signature.** The firewall
  sends it only the signature, without the id, nonce, expiry and bindings it
  covers, so the extension relies on the native-messaging channel itself.
  Sending the whole grant needs a protocol change on both sides.

## Watch mode

- **Watch mode lets some risky actions run.** Every rule outside the reviewed
  relaxable list still asks, holds or blocks ([policy.md](policy.md#watch-mode-rollout)),
  but a fooled agent can push, send a message, fetch from any host, install
  packages or start another agent while it is on, and budgets and loop
  detection stop nothing; the log shows it afterwards. It ends after 14 days
  unless `--days` says otherwise (at most 90).
- **Its records are as strong as the firewall's directory.** The grant needs
  your passphrase, but which rollout change is the latest is read from a copy
  of the signed log entry kept beside it, not by walking the log on every
  call. Someone who can write the firewall's directory and kept an older grant
  and its record could put both back, together with the list of revoked
  grants; that is the same limit as for the rest of the state.
- **The report is as good as the log.** It reads the decision log without
  checking it (run `log verify`), and an entry the log refused is not in it.
  Examples are masked by pattern: a password with no recognisable shape can
  remain in a summary.
- **A project-scope install cannot use watch mode**, and neither can a hook
  command that does not pin the approval key: the key must come from your own
  or the managed agent settings.
- **Turning it off from a script is not possible**: `rollout enforce` needs a
  person at the keyboard, like the other state-changing commands. Remove the
  grant file, or set `"enforce"` in the managed policy, to end it otherwise.

## Approvals

- **No passphrase, no approvals.** Installing without a terminal sets none.
  Held actions cannot be approved until `approver init` and a reinstall.
- **The commands that change state need a real terminal.** They refuse to run
  from a script, from an agent, or as a descendant of a Claude Code process.
  A script or CI job of yours cannot approve either.
- **A process the firewall cannot read counts as an agent.** To tell you from
  an agent, these commands, `run`, the kill switch's `session stop` and
  `agent stop`, `serve --api`, the `api` commands and `openshell serve` read
  the processes they were started from (`/proc` on Linux, `ps` elsewhere).
  When one of them cannot be read (process 1 aside, which `hidepid` may hide),
  or the chain loops or is more than 40 processes long, the command refuses
  and says it could not read them. On a Linux server whose `/proc` is mounted
  with `hidepid`, a terminal reached over SSH descends from sshd's root-owned
  process, which cannot be read, so these commands are refused there, the kill
  switch's stop included. An account in the group named by the mount's `gid=`
  option sees every process, and is not refused.
- **An agent that detaches its command is not seen as an agent.** That check
  walks up from the command to the top of the process tree. An agent's command
  that clears the agent's environment variables and detaches (it is then a
  child of process 1), or that starts in a new process namespace, reaches the top
  without meeting the agent and is read as you. It is a second line of defence:
  the approval passphrase, the hook's tamper rules and the real-terminal
  requirement still apply.
- **The phone signs what its app shows.** A passkey prompt does not show the
  item. A compromised approval web app could show one pending item and have you
  sign another. The firewall accepts only a real pending item on this machine,
  with its unused nonce, inside its time window.
- **Synced passkeys report a counter of 0.** Replay protection then rests on
  the single-use nonce and the firewall's own protection of the session file:
  a stored phone approval copied into the session (the same item id, or the
  same credential and signed nonce) is tampering and approves nothing.
- **Approvals are single-use and lapse after 24 hours.** A terminal approval
  signs a random nonce, its expiry, the rule ids it showed and the agent's
  directory and project; its use is recorded by id, and a copied approval line
  makes the session untrusted. An approval stops covering the action once a
  rule you were not shown asks about it, and, in the hook and the MCP gateway,
  when the action comes from another working directory or project than the one
  you approved it in. Both checks are made by the engine, so the hook, the
  gateway, the local API and the library all apply them. The action then asks
  again, and its message says an earlier approval was not used and why (the
  approval is kept, not spent). The local API and the library bind an approval
  to the call's `cwd` and workspace roots through its key instead. An answer
  given in the client (an elicitation, off until a client is verified) covers
  the rules its question named. A call that becomes several actions (a
  multi-file patch) is approved as a whole: the held item names the rules of
  every action that asks or is held, and the approval is checked against all
  of them. Two cases are not checked yet: an action held as a proposal (on its
  own, or as one file of a patch) names only the rules that hold it, so a rule
  that would only ask about the same action (a shell command that changes a
  git hook and also sends data, say) and starts asking after the approval does
  not stop it; and a decision names at most 16 rule entries, so a rule that
  first asks past that limit is not checked. A phone approval signs the action
  and the queue item, not the rules, the directory or the project, so it is not
  checked this way. Approvals made before this version (v1) are ignored:
  approve again. Approvals made by an earlier pre-release build are not used; the
  action is held again under a new id. The held action stays in the queue;
  the agent's next try is held again under a new id, and approving that one
  lets it run once.
  Someone who can rewrite a whole session file could still remove an approval's
  use and its original line, and so use an unused copy once before it lapses.
- **Every signed line in a session is checked each time the session is read.**
  A signature that is junk or cut short is turned away in microseconds, but a
  well-formed one (a real line copied many times, or one signed with another
  key) takes a full check, about 40 microseconds. A session file of a few
  megabytes of such lines takes one to two seconds to read with the approval
  key. Only someone who can already write the firewall's state can make one,
  the lines grant nothing they did not already grant (a forged line or a copied
  approval leaves the session untrusted), and a decision that runs past the
  hook's deadline is a deny.
- **Cut actions need an explicit approval.** The queue stores at most 200
  items of a list, 200 keys of an object, 20,000 characters of a text and 200
  parts; each cut is marked with how much is missing. `queue approve` and
  `queue review` show every stored part and refuse to approve a cut action
  unless you pass `--i-saw-truncated`. The phone shows a "Not shown here" line
  instead (it never shows the input).
- **The approval key file resists guessing only as well as the passphrase.**
  New key files use scrypt with N = 2^17 and need a passphrase of at least 14
  characters; an older file (N = 2^15) is re-encrypted the next time the
  passphrase unlocks it.
- **The phone sanitiser removes only known secret formats.** A generic password
  or a `-u user:pass` argument can pass into a summary. Summaries are fixed
  sentences and counts for most rules; Bash summaries carry more.
- **Phone approvals need LaunchSafe's hosted relay, which is not available
  yet.** Terminal approvals work now. Once the relay exists it is outside this
  repository, and with no network it will be unreachable while the terminal
  still works.

## Ordinary commands that are asked or denied

Some read-only forms of dangerous programs are denied or asked, because the
analyser judges the program and not every option:

- `fdisk -l`, `parted ... print`, `sfdisk -l`, `gdisk -l` and a plain `wipefs`
  are denied as disk-erasing commands, and `diskutil eject` and `unmount` are
  denied as disk commands.
- `systemctl` and `launchctl` read verbs such as `list-unit-files` and
  `list-timers` are treated as changing a service.
- `security find-identity` (routine for code signing) is asked as a keychain
  read, and `aws configure get` and `list` are asked as credential reads.
- `docker system prune` without `--volumes` is denied.

Use `allow add` for the cases you need, or run them yourself.

## Fewer prompts (learned project allows)

- **Narrow on purpose.** Only the low-risk rule class can become "always in
  this project", and today it holds one rule (`FW-UNKNOWN-TOOL`). Most prompts
  in practice come after outside content (`FW-SEND`, `FW-FETCH`,
  `FW-INSTALL`); those are never learnable, and taint always wins. Use
  `launchsafe-firewall friction` to see where your prompts come from.
- **An unknown tool's result makes the session untrusted.** So a learned allow
  for one applies to its first use in a session; later uses in that session are
  asked, as before.
- **The project is its directory.** Choices are keyed by the resolved project
  directory. A different repository later checked out at the same path inherits
  them; `allow list` and `allow remove` show and clear them.
- **Counting a "yes" to a prompt is inferred.** Claude Code does not report the
  answer; the firewall counts a prompt as approved when the asked tool then runs
  in that session within two hours, only in `default`, `acceptEdits` or `plan`
  mode, and not when a different decision for that action came in between. The
  count only decides when the offer appears; accepting it still needs you and
  your passphrase.
- **A damaged `learned/allows.json` applies no "always"** until it is repaired;
  "never" choices still apply from `nevers.json`. If both files are damaged, the
  "never" choices are lost until they are repaired (`doctor` reports it). Only
  something that can write the firewall's home can damage them.
- **An unsigned "never" still applies.** With no passphrase set, a "never" is
  stored unsigned; it only tightens, so it is honoured as written.
- **The library applies "never" when the host passes them or its store keeps
  them** (`fileStore` and the local API read them from the firewall's home, for
  the first workspace root; a memory store keeps none). No "always" choice ever
  applies in the library, the local API, the gateway or `check`.

## Decoys

- **Decoys only help against sweeps.** An agent that never touches a decoy is
  not caught by them, and an attacker who learns the file names can avoid them.
- **Only reads the firewall sees trip a decoy.** A recursive search that passes
  over one without printing it does not trip it unless
  `canaries.tripOnRecursive` is on; your own backup software or editor indexing
  is not an agent action and raises nothing.
- **A decoy committed with `git add -f` is not seen leaving.** A push's payload
  is not visible to the firewall; `doctor` warns when git tracks a decoy.
- **A decoy value is caught in the documented encodings only**, like any
  fingerprint (see "Data leaving the machine").

## The vault

- **It is not a hardware boundary.** A program running as you, outside the
  sandbox, that the firewall cannot see into can read the keychain: on Linux
  always, on macOS for secrets stored without per-use confirmation (`--confirm
  never`, the default for credentials), which is how Apple documents it, not
  observed in any test. The Linux Secret Service store has no live test.
- **Only `curl` and `wget` get values from a shell command.** Other programs
  need `vault allow <name> --process` and `run --env`.
- **A bound host that echoes a request back, or redirects with `curl -L`
  (which resends `-H` headers), can return the value.** What comes back is
  filtered in the documented encodings only, not after arbitrary transformation
  such as reversal.
- **A host binding compares the host name only.** It ignores the port and a
  trailing dot.
- **Fields shorter than 12 characters cannot be fingerprinted** (a CVC, an
  expiry date). `vault add` says which.
- **Not built:** `vault import --from-config` and `vault unlock` / `lock`.

- **A vault grant made for an `ask` outlives a refusal.** When a call that
  names `vault://` references is asked and you deny it, the gateway grant made
  for it stays for up to 180 seconds. A client without the hook that sends the
  same call, with the same arguments, to the same wrapped server in that time
  gets the values. The grant names the server, the tool and the arguments, not
  the session, because the gateway cannot know the hook's session.
- **The sender program must be root-owned.** `vault://` values reach only a
  `curl` or `wget` that is root-owned in root-owned, not group- or
  world-writable folders. A user-owned one (a Homebrew prefix owned by you,
  `~/.local/bin`) is refused, so on some Macs only `/usr/bin/curl` works. Run
  as root, the hook accepts root-owned programs.

## The MCP gateway

- **MCP only.** Native tools (shell, file edits, built-in web fetch) never pass
  through it. Nothing covers Claude Desktop's or ChatGPT's own tools.
- **A server added directly bypasses it** unless managed configuration forbids
  that. `gateway status` reports unwrapped entries; it cannot stop them.
- **Connectors called from a vendor's cloud** (claude.ai connectors, ChatGPT
  apps) cannot be reached locally. `.mcpb` extensions and remote custom
  connectors in Claude Desktop cannot be wrapped.
- **Scanning is pattern-based.** It finds hidden text and known agent-directed
  phrasings. It does not find paraphrased or semantic injections, or text in
  images, audio or binary blobs (a blob with a textual media type is decoded
  and scanned). A result larger than `gateway.responses.maxScanBytes` (4 MiB)
  is delivered with only its first part checked, and the session tainted,
  unless `oversize` is `"withhold"`.
- **No conversation boundaries.** Taint lasts for the client process (stdio),
  or over HTTP until `gateway reset`: after an idle gap only a clean session is
  renewed. That is stricter, never looser.
- **Full mode decides an MCP call the client's hook also decides.** `auto` is
  full mode (an install record does not prove the hook runs), so with a hook
  installed a call is judged twice and counted twice, and an ask may need the
  queue as well as the client. `gateway.mode: "hook"` in your own policy trusts
  the hook alone per call.
- **A new tool with no findings, inside the 24-hour grace window, is pinned
  silently.**
- **Approval needs a retry.** Elicitation asks are off: the list of verified
  clients is empty.
- **A Codex HTTP wrap drops `bearer_token_env_var` and `http_headers`.** That
  breaks the server and fails closed.
- **`gateway status --json` prints the upstream URLs**, including a secret in a
  query string that the client configuration already held.
- **Not built:** HTTP for a legacy client's standalone GET stream, era
  translation of input requests, a login item for `mcp serve`, `mcp pin
  --connect`. Each wrapped stdio server costs one Node process (its memory use
  has not been measured).

## The email guard

- **Mail MCP tools only.** Mail an agent reads another way (a shell command that
  prints a mailbox, a file, a vendor's cloud connector) is not split into
  messages. The taint rule still applies.
- **A server counts as mail by its name or its tools' names** (`mail`,
  `imap`, `gmail`, `outlook`, `smtp`, and the words `m365`, `o365`, `exchange`,
  `jmap`, `inbox`, `mailbox`) or by `emailGuard.servers`. A mail server named
  otherwise, with tools named otherwise, is not guarded until you list it.
  `exchange` beside a market word (`exchange-rates`) is not counted.
- **On Codex, Gemini CLI and Cursor the model has read the message** before the
  hook runs. The guard warns, records and untrusts the session. Only Claude
  Code's hook, and the gateway, keep it from the model.
- **Binary attachments are not scanned** (PDF, DOCX, images); their names are.
  Text attachments are scanned, and so is base64 attachment content in Graph
  and Gmail payloads, except that such content over 1 MiB in an attachment
  field is replaced by a placeholder instead of being read.
- **The scan is bounded.** A message over 10 MiB, nested more than 10 levels,
  or past a scanner bound (per part 4 MiB of text or 2 MiB of HTML, and a work
  budget per message and per tool result) is not fully read; on the read path
  it is withheld, and you can release it. The hook reads an event of at most
  64 MiB. A last-resort clock of 2 seconds per part can cut a scan short on an
  overloaded machine, which can only withhold more, never less
  ([email-guard.md](email-guard.md)).
- **The "mailbox path" is not built.** [email-guard.md](email-guard.md)
  describes how the detector treats mail on the mailbox path (moving mail in
  the mailbox you see). That path's code exists, but mailbox-side quarantine
  is not built (below), so those notes describe how it will behave; only the
  read path (what the agent reads) runs today.
- **The phrase lists are English only.** Hidden-text rules do not depend on
  language.
- **Template-syntax exfiltration links are not covered.** Variation-selector
  smuggling is not one of the email guard's own quarantine reasons: through
  the gateway such a result is withheld, through Claude Code's hook the
  characters are marked and the session is untrusted, and with other agents
  the session is untrusted (FW-HIDDEN-OUTPUT).
- **Sender authentication is what the provider wrote.** No signature or DNS
  check is made, and the rule looks at the top message, not forwarded ones.
- **Not built:** mailbox-side quarantine (IMAP, Microsoft 365). When it is
  built it is a race after delivery and starts log-only.

## `run`

- **It can read almost everything you can.** Only the credential directories
  listed in [run.md](run.md) and the firewall's keys are unreadable inside a
  run; every other file your user can read (other projects, documents,
  configuration with tokens in it) is readable by the program, and an
  admitted host is a way out for it.
- **Hosts, not methods.** An admitted host accepts uploads. Budgets bound how
  much; a fooled agent with an attacker's token can still push a small amount
  to an attacker's repository on an admitted host.
- **Domain fronting through a CDN.** The SNI check stops a client that names
  another server in TLS. It cannot see the encrypted `Host` header, so a CDN
  that routes on it could serve another customer's site. ECH is not handled.
- **A name in `run.privateHosts` may resolve anywhere in the private
  ranges.** The list is per name, not per address: whoever controls that
  name's DNS chooses which private address the proxy reaches.
- **No hooks means no taint tracking.** No queue, no task scope, no payload
  fingerprints (TLS is not decrypted), no decoy tripwire on reads. Keep the
  hooks on an agent that has them.
- **Agents whose hooks run as child processes (Claude Code, Codex, Gemini
  CLI, Cursor) fail closed inside `run`**, because the firewall's directory is
  read-only there. Use their own sandbox, or OpenShell with the middleware.
- **`run --agent` presets were not run with the real agents in CI.** They add
  the model API hosts and switches; sign in outside the run, and expect agents
  to complain that `~/.claude`, `~/.codex` or `~/.gemini` is read-only.
  Read-only is not unreadable: the agent's credential files there can be read
  by every program in the run, and the model API hosts are send hosts with no
  byte budget, an unjudged way out for anything the agent reads.
- **macOS uses a deny list.** A system service not on it that does network or
  file work for its caller would not be stopped. `sandbox-exec` is deprecated
  by Apple. `--allow-keychain` and `--allow-localhost` widen what the process
  can reach.
- **Linux needs unprivileged user namespaces.** Some distributions restrict
  them; `doctor` prints the error. Sockets outside the hidden directories stay
  reachable. A program that opens `/dev/tty` gets an error.
- **The read-only list for git and agent files is a list.** A module that a hook
  script imports is not followed. A repository the agent creates inside the run
  is its own. Submodule and linked-worktree commands fail inside the run.
- **Caches in your home are read-only.** `npm`, `pip` and many agents need
  `--allow-write`. `/tmp` is not writable.
- **No upstream proxy.** An existing `HTTPS_PROXY` is replaced.
- **Other local processes can use the proxy** on macOS (no credentials). It
  only reaches the policy's hosts, but they can use up the budgets.
- **If `run` is killed, an empty mount-point directory can stay behind** on
  Linux (`.mcp.json/`, for example). Remove it.
- **Budgets are per run and counted on the wire.** What stays under them is not
  seen.
- **Hosts approved for the workspace (`knownHosts`) are admitted by name.**
  Like every other admitted host, an approved host accepts uploads; the counted
  budgets bound how much. The proxy cannot ask, so a new host is refused until
  you approve it.

- **On macOS a command may write to every terminal device.** The profile
  allows writes to `/dev/tty*`, so a run can write escape sequences to your
  other terminal windows. Denying it needs the run's own terminal name and has
  not been done.
- **On macOS a process that leaves its process group can outlive the run.**
  A command that starts a background program with `setsid` and then ends the
  bridge is not always cleaned up. This has not been tested on a Mac.

## OpenShell middleware

- **Two sessions, not one.** The hooks inside an OpenShell sandbox and the
  middleware outside it keep separate session state; taint is not merged. The
  middleware's session is untrusted from the sandbox's first request and never
  sees the person's prompts.
- **The hooks' state inside the sandbox is writable by the agent's
  processes.** The hooks refuse visible writes; a program they cannot see into
  could reset them.
- **Not inspected:** the model API (left out on purpose: an unjudged,
  unbudgeted exfiltration path for anything the agent reads), WebSocket binary
  and server messages, compressed, binary or partial response bodies, `tls:
  skip` endpoints, and standard request headers with short values. Request
  bodies over 512 KiB are blocked, and compressed, binary or non-UTF-8 request
  bodies are held for a person.
- **Blocking needs `on_error: fail_closed`.** The generated policy sets it; with
  `fail_open` a middleware failure, including a redaction the service cannot
  apply to a response, lets the traffic through. Parts of a multi-unit
  response body sent before the last part are not recalled.
- **Denied hosts under an admitted wildcard** are refused only by the
  middleware; **files inside the working directory** cannot be made read-only
  by OpenShell's Landlock rules.
- **OpenShell calls its middleware API a research preview.** Tested against a
  stand-in supervisor built from its v0.1.4 protocol, not a real gateway; the
  WebSocket preflight values in particular are unconfirmed.
- **Without TLS (`--insecure`, or plaintext on loopback)** anyone who reaches
  the port, on loopback every local process, can ask in any sandbox's name and
  use up a person's approval by sending the approved request first. `serve`
  warns on every start.
- **`--no-middleware`** leaves a `denyHosts` entry under an admitted wildcard
  unenforced; the command warns.
- **Repeated refusals are counted, not each logged.** So that a sandbox
  sending the same refused request in a loop cannot flood the signed log, the
  first refusal of a kind in a time window is recorded and later ones are
  counted into the next record; past a per-sandbox number of records in the
  window, further kinds are counted together under one entry per code. The log
  shows how many, not each request.
- **Its requests are not tool calls.** They go to the local API with
  `context.traffic: "network"`: every rule, the sandbox session's budgets and
  its own behaviour monitor apply, but they do not count toward the toolCalls
  spending limit or the agent-wide monitor. Only a token made with
  `api token add <agentId> --traffic network` may send this, and only for an
  `HttpRequest`, the unreadable-request wrapper of one, or the
  `launchsafe:network-refused` record of a request the middleware refused;
  whoever holds that token can send uncounted HTTP requests and write refusal
  entries into the sandbox's log, so it belongs to the middleware alone.

## Library (`@launchsafe/agent-firewall/sdk`)

- **It does not run the checks that read a coding agent's own files:** the
  session-start scan, MCP pins, desktop notifications, subagent linkage. It has
  no email guard. Decoys work only with `fileStore`. The provenance ledger
  (what an untrusted session wrote stays untrusted in later sessions) works
  with a store that has one (`fileStore`, which the local API uses, and
  `fileLedger` for a custom store) and a guard that has file access; the
  memory store keeps none by design, so a guard on it carries nothing from one
  session to another, and a write whose result the host never reports is not
  remembered ([library](library.md#the-provenance-ledger)).
- **Approval is the host's job.** The library never approves on its own, and a
  callback that is missing, throws or times out is a no.
- **`firewallTool` covers function tools only; hosted tools, MCP-server tools and shell/apply_patch tools registered with the OpenAI Agents SDK are not wrapped.** Only the function tools you pass through `firewallTool` are checked.
- **A custom store must keep the kill switch and the spending limits.**
  `capView`, `stops` and `nevers` are required; with caps on, a store without
  `capView` denies every call, and a store whose `stops()` or `nevers()`
  throws denies every call, reads too.
- **A prompt counts only from a token with the `prompt` role.** From an agent's
  ordinary token (decide and report) `POST /v1/sessions/{session}/prompts` is
  only logged; its destinations and task scope are not applied. A token made
  with `--role prompt` applies them, so whoever holds it can name destinations
  an untrusted session may contact: give it only to the code that reads what
  the person typed, never to the agent's tool loop.
- **The local API takes the request's context on trust unless the registry
  pins it.** Without `workspaceRoots` in the agent's registry, an agent may name
  any absolute workspace root or cwd (so any file can be its "own work"); without
  `mcpServers`, a trusted MCP source it claims is judged as `unknown` (stricter),
  but a stricter claim is always taken. Approvals bind to the action, cwd and
  workspace roots together.
- **Request limits are fixed in v0** (32 in flight and 100 a second per agent,
  256 in flight in all, 100,000 new sessions per agent per server run); they
  cannot be set from the command line.
- **The remote guard trusts loopback TCP only when told to** (`allowTcp`): any
  local process can hold the port and would receive the token. The unix
  socket is checked (this user's, mode 0600), not the directory it is in.
- **An idempotent retry is replayed only briefly, and at most once, when it
  was allowed.** A deny or hold is given again for the same `Idempotency-Key`;
  an allow or ask only within 30 seconds, at most once per key, and only while
  a dry check of the same call still gives the same verdict (so no stop,
  spending limit or new "never" has intervened). After that the call is decided
  again, and counted.
- **The local API's `mcp` and `engine` formats ignore the agent's tool
  registry.** A call to a registry-declared server through the `mcp` format is
  judged by the presets, which is stricter than the library (which applies its
  tool specs' servers to every call).

- **A streaming Vercel AI tool is not recorded.** When a tool's `execute`
  returns an async iterable, the wrapper does not read its chunks, so their
  text is not scanned or fingerprinted.
- **Python SDK, Google ADK.** `firewall_callbacks` attached only to the root
  agent do not reach sub-agents or `AgentTool`s; use `FirewallPlugin` for those.
- **Python SDK, parallel approvals.** Each integration waits for approvals in a
  thread from Python's default pool. Many approvals pending at once can use all
  of it and delay other calls.
- **Gateway events in hook mode go to every session file** in the state
  directory, not only the client's, so one result's taint and fingerprints can
  reach unrelated sessions and the write costs more as sessions pile up.

## Dashboard

- **It is read-only and as current as the page was when rendered.**
- **A process running as you can read the browser history that holds the
  dashboard's private address.** It gets the read-only view only. Approvals
  stay behind the passphrase. Run `ui` in a terminal the agent cannot read.

## Browser extension

- **A held download is fetched twice.** The extension cancels an executable
  download and, when you approve it, downloads the address again. The second
  response can differ from the first (cookies, redirects, one-time URLs), and
  the log records only the first address.
- **The leak guard rescans mutating pages.** On a live feed or chat stream it
  scans every 400 ms while the page changes, which costs CPU even with agent
  mode off.
- **An approval binds the form's target, not the page's later scripts.** A
  click approval covers the form action and method at approval time; a page
  script that changes them inside the click handler is not seen again.
- More in [the extension's limits page](https://github.com/shivanagendrakore/agent-firewall/blob/main/browser/src/ui/limits.html) and
  [its README](https://github.com/shivanagendrakore/agent-firewall/blob/main/browser/README.md).

## What is tested, and what is not

- The decisions are tested: unit tests, fuzz tests, the incident replays
  (hook events we wrote to model each incident), the friction corpus and the
  mail corpus. A real model has never been talked into an attack against it in
  a test. Hook formats were captured from real agent CLIs where the per-agent
  pages say so, and those captures are replayed as fixtures; the firewall has
  not been tested against live attacks.
- Latency is measured on a developer laptop (`npm run bench`). The budget is
  p95 under 50 ms and p99 under 150 ms for the decision and the warm hook path,
  and p95 under 120 ms and p99 under 200 ms for a whole hook process (node
  start included). It is not measured on slow or loaded machines.
- The corpus counts in the docs (normal tasks, packages, mail messages) are
  the size of the corpora we wrote. A zero in them means none of those were
  interrupted, not that no ordinary task ever will be.

## Limits that matter most when you set it up

Moved here from the README. Several items restate points made above, in the context of setup.

- **Hooks are an enforcement point, not a cage.** They decide whether a tool
  runs; they do not contain a process that does run. Run the firewall
  **together with** Claude Code's OS sandbox, which limits what a command that
  *is* allowed can reach (for an agent with no sandbox of its own, start it
  with `launchsafe-firewall run`). The firewall plus the sandbox is the recommended
  setup: `doctor` scores it, and `doctor --fix` writes a sandbox profile derived
  from your policy (in your own terminal, behind the approval passphrase).
- **The sandbox sees hosts, not methods.** Its network allowlist is by host, so
  a host admitted for fetching (`registry.npmjs.org`, `github.com`, `pypi.org`)
  is reachable for uploads too. `doctor` labels those hosts *upload-capable*.
  Uploading to them is controlled by the firewall's rules for the commands it
  can see (`git push`, `npm publish`, `gh`, `docker push`), not by the sandbox;
  the sandbox is the backstop for what the firewall cannot see into (a compiled
  binary, a script that opens a socket). Hosts you name in a prompt are allowed
  by the firewall for that session but are not in the sandbox's static list: a
  fetch to one fails inside the sandbox with a network error. Add the host to
  `fetchAllowHosts` and run `doctor --fix` again.
- **Inline code is read-only only by a list of APIs.** A one-line script is
  judged a pure reader when none of the known write, process, network or
  reflection APIs of its language appear; a write API missing from those lists
  is the residual risk. It only matters for literals that name protected files,
  and those stay protected through the Write/Edit result check, the
  `ConfigChange` hook and the approval passphrase.
- **`CDPATH` is not modelled.** Within one command the firewall follows `cd`,
  subshells and `-C`-style flags, but a bare `cd name` is resolved against the
  current directory; the hook does not see the agent shell's `CDPATH`.
- **Files pulled into a prompt with `@` do not pass through `PreToolUse`** — the
  agent reads them directly. The firewall cannot see those, so it cannot taint
  on them. Treat an `@`-included file as trusted input you chose.
- **A repository's own `.claude/settings.json` can set `disableAllHooks`**, and
  in a `-p` run a repo's settings hooks load without the trust dialog. Only
  **managed settings** resist this, so the managed install
  (`install --managed --lock-other-hooks`, which also sets
  `allowManagedHooksOnly`) is the recommended one. `doctor` fails on it (and
  `doctor --ci` exits 1), naming the file and the fix.
- **It reasons about the actions it can see.** A brand-new tool is sent to a
  person. A shell construct the parser cannot resolve is usually treated as
  risky and sent to a person too, but the constructs listed under [Shell
  constructs not yet analysed](#shell-constructs-not-yet-analysed) may run
  without a prompt, and coverage of exotic tools grows over time. In a **trusted** session
  (nothing outside read yet) the firewall does not second-guess opaque code: an
  inline script that computes a path and writes there is only held once the
  session is untrusted. Self-protection does not depend on that analysis: an
  approval still needs your passphrase.
- **What the secret fingerprints catch, exactly.** A secret the session has seen
  is found again in outgoing data when it appears verbatim, URL-encoded (once or
  twice), base64 or base64url, base32 (either case), hex, or split across DNS
  labels (`abc.def.attacker.example`). It is **not** found when it is reversed,
  case-changed, ROT13'd, compressed, encrypted, re-encoded with a custom
  alphabet, interleaved with other characters, or sent a few characters at a time
  across separate requests. That is why the taint rule — not pattern matching —
  is the primary control on sending data out of an untrusted session. Slow
  exfiltration to a host that is allowed (allowlisted, or one you named) is now
  rate-limited by the per-session byte and request budgets, but it is still not
  detected byte by byte: what stays under a budget is not seen.
- **Approvals need the passphrase.** If you install without a terminal (for
  example from a script), no passphrase is set and held actions cannot be
  approved until you run `launchsafe-firewall approver init` and reinstall.
  A paired phone stands in for typing it per approval, but pairing one needs it.
- **The phone signs what its app asks it to.** A passkey prompt does not show
  the item; the approval app does. Compromised app code could show one pending
  item and have you sign another; the firewall still accepts only a real
  pending item on this machine, with its unused nonce, inside its time window.
- **Package checks are only as good as their data.** A malicious version
  published after your last `update`, or not yet reported to OSV, is not
  denied; a typosquat of a package outside the shipped popular lists is not
  flagged. The cooldown setting (`doctor --fix`) is what covers the first days
  of a new release. Names the shell only knows at run time (`npm i "$PKG"`) get
  no package verdict.
- **Each agent's hooks set the ceiling.** The engine is the same for every
  agent, but Codex, Gemini CLI and Cursor see less than Claude Code (see
  [agents/overview.md](agents/overview.md)): Codex's hosted web search never reaches a hook, none of
  the three can ask you (held actions wait in the queue), Codex and Gemini CLI
  let a tool run when a hook times out, and Cursor's cloud agents run only the
  repository's hooks.
- **Three behaviours of the other agents were not captured, so the firewall
  assumes the riskiest reading.** Gemini CLI's `web_fetch` is taken to request
  each whitespace-separated URL in its prompt whole (brackets and quotes
  included); Codex's `apply_patch` and Gemini CLI's `replace` are taken to match
  their text loosely (whitespace, punctuation, Codex's `@@` anchor, Gemini CLI's
  own correction of `old_string`), so an edit is judged against every place it
  could match and as unknown when it matches nowhere; and a Codex `apply_patch`
  run through the shell is judged as a patch whether Codex reports it as `Bash`
  or as `apply_patch`.
