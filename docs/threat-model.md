# Threat model

## What we are defending against

An AI coding agent (Claude Code first) that, in the course of normal work, takes
in content an attacker controls — a web page, a GitHub issue, a support ticket,
an email, an MCP tool's result or description, a dependency's README — and is
steered by that content into an action that harms the user: leaking private
data or credentials, destroying data, installing a backdoor, rewriting its own
instructions, or opening a path for later compromise.

The attacker's capability we assume: **they can put text (or an image) where the
agent will read it.** They cannot run code on the machine directly (that is a
different problem) and they do not control the user's prompts.

The defender's goal: **limit what a fooled agent can do.** We do not try to
keep the agent from *being* fooled — that is not reliably possible. We constrain
what any agent, fooled or not, is allowed to do.

### Across sessions

Taint is per session, but files outlive sessions. A file an untrusted session
wrote (a script, a `package.json` change, a git hook) keeps that status in the
provenance ledger while its content is unchanged: a later trusted session that
runs it, runs a build or test runner whose manifest or config-as-code it is
(`package.json`, `vitest.config.ts`, `.pre-commit-config.yaml`), or runs an
install that reads it (a lockfile, `.npmrc`/`.yarnrc*`/`bunfig.toml`/`pip.conf`,
a requirements or constraints file) needs a person (FW-UNTRUSTED-CODE,
FW-TAINTED-MANIFEST). A session cannot launder its taint into a new one: from an
untrusted session, proposing a session (`spawn_task`) needs a person who sees
the whole prompt, and a session started from such a prompt starts untrusted
(the delivery shape is an unverified assumption; the ask holds regardless). Reading such a file in a new session
taints only when it is outside the workspace, which keeps friction off ordinary
in-workspace code. Content the agent wrote from a trusted session and nobody
has changed since is not outside content wherever it lives. What this does not
cover: content an untrusted session produced through a writer the firewall
cannot see (an MCP tool that writes files, a program that writes files it was
not told about), files larger than `provenance.maxHashBytes`, and a person who
edits an untrusted-written file by hand (their edit makes it theirs). The hook,
the local API and a library guard on `fileStore` share one ledger; a library
guard on the memory store has none, so it carries nothing between sessions,
and a write whose result the host never reports is not remembered
([library](library.md#the-provenance-ledger)).

### Sideways moves (task scope)

Inside an untrusted session some action classes stay allowed because ordinary
work needs them: a write inside the workspace, for one. Content read later can
use that room to move sideways: "also update `.github/workflows`", "fix the
shared util in the other package too", "post the summary to this other repo",
or, in an unattended run, "then push and publish". The person's prompt is the
one input the attacker does not control, so the firewall records what it named
(paths, repositories, hosts, publish-type verbs) and, with `taskScope.mode:
"enforce"`, turns a move outside it into an approval: a write outside the named
paths or a send to an unnamed destination once the session is untrusted, and a
push, PR, publish, deploy, message or new install the prompt never asked for
when no one is there (even in a trusted session). The scope only narrows; the
other rules judge everything inside it. Its limits: it is only as precise as the
prompt (a prompt that names nothing narrows nothing, and a broad one like "fix
`src`" covers all of `src`); a pasted block the parser cannot recognise as
pasted (no fence, no quote marks) counts as the person's words; and it ships
in log mode, so until a person sets `enforce` it only records what it would
have asked.

## The lethal trifecta

Simon Willison's framing: an agent is dangerous when it simultaneously has
(1) access to private data, (2) exposure to untrusted content, and (3) a way to
communicate externally. Any one alone is fine; together they let an attacker
exfiltrate. Source: <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>.

The firewall targets leg (3) with a deterministic rule: **once a session has
read outside content, sends the firewall can see, and fetches to hosts you did
not name or allow, need a person** (and so do the other damaging action
classes). Allowlisted and named hosts, and programs the hooks cannot see, are
not covered. The rule is enforced on the action, not inferred from the text.

Google DeepMind's **CaMeL** (*Defeating Prompt Injections by Design*,
arXiv:2503.18813) makes the same architectural argument: achieve security
through system design around the model — tracking control and data flow and
enforcing policy when tools are called — rather than through model training.
This firewall is a pragmatic, deterministic version of that idea for coding
agents.

## Claude Code hooks (the enforcement mechanism)

Researched against the current docs at <https://code.claude.com/docs/en/hooks>
and `settings`, `managed-settings`.

- Hooks run on events including `PreToolUse`, `PostToolUse`,
  `UserPromptSubmit`, `SessionStart`, `Stop`, `SubagentStop`, `PreCompact`,
  `Notification`, `ConfigChange` and more. The firewall uses `PreToolUse` (the
  decision), `PostToolUse` (record what a tool brought in), `UserPromptSubmit`
  (record destinations the user named), `SessionStart` (housekeeping, the agent-configuration scan and the MCP pin comparison) and
  `ConfigChange` (protect its own registration mid-session).
- `PreToolUse` returns
  `hookSpecificOutput.permissionDecision` of `allow` / `deny` / `ask`. Across
  hooks the most restrictive wins, and a hook `allow` never overrides the user's
  own `deny`/`ask` rules — so the firewall can only tighten. In `-p`
  (non-interactive) mode an `ask` becomes a denial the model reads, which is why
  the firewall **queues** instead when unattended.
- Only **exit code 2** or an explicit JSON `deny` blocks a tool. Exit 1, a
  crash, a missing script (127) and a timeout all let the tool run. Therefore
  the firewall catches its own errors and the installed command is wrapped
  `... || exit 2`, so even a failure of Node itself fails closed. A timeout
  (the entry sets Claude Code's default, 600 s) is not covered by the
  wrapper. The hook denies by itself at its own deadline (20 s by default,
  checked between steps), so only a step that never returns reaches the
  timeout; the entry's `onFailure: "block"` then blocks the tool from Claude
  Code 2.1.295 (not verified live). On older versions Claude Code is documented to ignore `onFailure` and run the
  tool, so an attacker who can make one step of the firewall hang wins that
  one call. Residual, documented in [limitations.md](limitations.md).
- Matchers select tools, including MCP tools named `mcp__<server>__<tool>` and
  plugin servers `mcp__plugin_<plugin>_<server>__<tool>`. Verified against a
  live Claude Code 2.1.289 event: the `PreToolUse` input carries a top-level
  `mcp_server { name, source }` (`"project"` for a server from the repo's
  `.mcp.json`, `"dynamic"` for `--mcp-config`). The firewall trusts by
  **source**, not by name (a repository-defined server can claim any name), and
  derives the source from the config files itself when a version omits it.
- The host's own tools. The 2.1.289 binary documents `mcp_server.source`
  as `sdk | plugin | user | project | local | dynamic | managed | enterprise |
  claudeai | agent`, to be treated as an open set; `sdk` is an in-process server
  only the host application can register (a configuration file declaring
  `type: "sdk"` is rejected). The desktop app's `ccd_*` servers are such
  servers, so the firewall recognises them as host tools only with that source.
  The non-MCP host tools (`SendUserFile`, `SubagentHandback`, `Artifact`) are
  built-in names an MCP server cannot take (those are prefixed `mcp__`).
  Residual: a host tool catalogued as showing something to you that in some
  deployment also uploads it (a remote session) would not be judged as a send;
  the catalogue requires a captured event and a reviewed kind, and publishing
  is its own kind. Tools the catalogue leaves out on purpose: `SendFile`
  (to another session or machine) and `mcp__visualize__show_widget` (its HTML
  can load remote resources), which stay on the unknown/MCP path.
- Settings merge across managed / user / project / local scopes. A project's
  `disableAllHooks: true` turns off user-level hooks; only **managed settings**
  resist it, and `allowManagedHooksOnly` restricts which hooks run at all.
  Managed-settings files live at
  `/Library/Application Support/ClaudeCode/managed-settings.json` (macOS) and
  `/etc/claude-code/managed-settings.json` (Linux). `doctor` recommends this.
- The OS sandbox. Setting names verified from the settings schema in
  the Claude Code 2.1.289 binary: `sandbox` is an object (`enabled`,
  `allowUnsandboxedCommands` and `autoAllowBashIfSandboxed`, both default
  `true`, `excludedCommands`, `network.allowedDomains`/`deniedDomains`/
  `strictAllowlist`/`allowUnixSockets`/`allowLocalBinding`,
  `filesystem.allowWrite`, ...). Lists merge across scopes, so without
  `network.strictAllowlist` (honoured from user and managed settings only) a
  repository's `.claude/settings.json` can add allowed hosts, and
  `WebFetch(domain:...)` allow rules also widen the list; `doctor` names such
  hosts. The sandbox is host-level: a host admitted for fetching is reachable
  for uploads, which the firewall's own rules (git push, npm publish, gh, docker
  push) control for the commands it can see. A profile installed by
  `doctor --fix` is protected like the hook registration. Not confirmed by
  a live run: that ordinary hooks run outside the sandbox (the strings show
  sandboxing only for remote-tools project hooks); doctor probes the state
  directory instead.
- Known gaps, documented in [limitations.md](limitations.md): files included with `@` in a prompt do
  not trigger `PreToolUse`; in `-p` a repo's own settings hooks run without the
  trust dialog.

## Codex and Gemini CLI hooks

Captured live from Codex 0.162.1 and Gemini CLI 0.63.0 (method and every
observation in `docs/agents/codex.md` and `docs/agents/gemini.md`). What differs
from Claude Code, and what the firewall does about it:

- **What blocks.** Both block a tool on an explicit deny (Codex:
  `permissionDecision: "deny"`; Gemini CLI: top-level `decision: "deny"`) or on
  exit 2 **with text on stderr**. Exit 2 with empty stderr, exit 1, a crash,
  unreadable output and a timeout let the tool run. The installed command
  therefore ends `|| { echo '…' >&2; exit 2; }` (doctor accepts it as the
  fail-closed wrapper). A hook that times out (install sets the agents'
  defaults: 600 s for Codex, 60 s for Gemini CLI) still fails open. The hook
  denies by itself at its 20 s deadline, checked between steps, so only a step
  that never returns reaches the timeout: an attacker who can make one step
  of the firewall hang wins that one call. Residual, documented.
- **No ask.** Codex treats `ask` as an error and runs the tool; Gemini CLI's
  top-level `ask` hung a headless run (its interactive behaviour was not
  verified). Neither is used: an approvable action is held in the queue and
  denied with the queue command, so the person approves through the passphrase
  channel exactly as for an unattended Claude Code session.
- **Codex hook trust.** Codex silently skips a hook the person has not trusted,
  and one that changed since. A firewall that is installed but not trusted
  protects nothing, so `install` (person-run) records the trust with Codex's own
  hash and `doctor` verifies it against the hooks as written. The agent changing
  `hooks.state` is tampering (it could revoke the firewall's trust or trust its
  own hook).
- **Repository switches.** A trusted repository's `.codex/config.toml` can set
  `[features] hooks = false`; a project `.gemini/settings.json` can set
  `hooksConfig.enabled: false` or disable a hook by name. Both silently turn off
  the user's hooks (captured), like Claude Code's `disableAllHooks`. `doctor`
  fails on them; the agent writing them is FW-TAMPER (Codex's `config.toml` is
  parsed into keys, so the dotted `features.hooks = false` and the inline table
  `features = { hooks = false }` are the same switch). Only the managed layers
  resist a repository (Codex `requirements.toml` with
  `allow_managed_hooks_only`; Gemini CLI system settings in a root-owned
  directory, which still cannot stop other hooks).
- **Gemini CLI folder trust.** In an untrusted folder Gemini CLI skips every hook
  (read from its source). The firewall cannot change that; doctor says so.
- **Blind spots.** Codex's hosted web search and `tool_search` never reach a
  hook; the shell hook carries no `workdir`; neither agent can replace a
  built-in tool's output (no redaction); neither has a `ConfigChange` event, so
  settings are protected only against changes made through the agent's tools.
- **Subagents.** Both keep the parent's `session_id` on a subagent's tool calls
  (Codex adds `agent_id`), so taint is shared without linkage. A Codex
  subagent's prompt is written by the parent model and never counts as the
  person naming a destination.
- **The review fixes are agent-independent.** The pipeline around `decide()` is
  shared, so a decoy trips whatever the verdict (also when an ask becomes a held
  action, and for every part of a patch that does not run), agent-written text
  is escaped before any adapter renders it, MCP pins are compared on every
  session start and their taint applies to the revealing call, and a proposed
  prompt is never the person's (docs/design.md, "Adapters"). An unknown native
  tool is held. The session-start MCP comparison reads every installed agent's
  MCP configuration (Claude Code's files, Codex's `config.toml`, Gemini CLI's
  `settings.json`, Cursor's `mcp.json`), pinned per agent (`codex-user:<name>`):
  a changed launch line makes that agent's next session untrusted; another
  agent's session records the change without being tainted by it. A server
  launched through the firewall's own CLI (`launchsafe-firewall … -- <server>`)
  is compared on what it wraps.

## Cursor hooks

Cursor's formats were read from the shipped `cursor-agent` 2026.10.01 source and
its documentation, not captured live (docs/agents/cursor.md says what was not
verified). What that gives and does not give:

- **Decided before it runs:** every local tool through `preToolUse` (Shell,
  Read, Write with the whole new file, Delete, Grep, List, Fetch); MCP calls
  through `beforeMCPExecution`, which names the server. In the CLI the deny is
  enforced (read from source); the IDE is documented to behave the same.
- **Fails closed:** `failClosed: true` on every entry blocks on a crash, a
  non-zero exit, a timeout or no answer. The hook command has no shell wrapper,
  because Cursor's legacy transport appends the payload as a heredoc.
- **Can switch the hooks off:** any write that makes Cursor's validator reject
  `hooks.json` (one bad entry, an unknown step, a bad `version`) drops every hook
  in that file. Judged as FW-TAMPER when the file registers the firewall;
  `doctor` checks the file validates and is not a symlink.
- **Not seen:** Tab completions (the person's edits), typed shell input
  (`WriteShellStdin` carries only a length), computer use and screen recording
  (held as unknown tools); server-side tools under names not verified (held if
  unlisted). Cloud agents run only the repository's hooks, where a project
  install's local paths do not exist (fail-closed: every action blocked). Use
  Cursor's sandbox and an egress proxy for these.
- **Imported Claude Code hooks:** Cursor runs the hooks in Claude Code's
  settings with Cursor's own payload. The Claude Code hook recognises it
  (`cursor_version`) and defers to the firewall's Cursor hooks when they run for
  that step (user or enterprise file, fail-closed, valid), else decides itself.
  A project-scope Cursor install is not counted as running (untrusted
  workspaces skip it), so with only that, an event can be decided twice.

## Review findings fixed before release, and the assumptions left

These reviews were done by the maintainers with AI assistance; there has been
no third-party audit. They found places
where the engine decided a request was not network traffic, writers the
analyzer did not model, and adapter translations that judged something other
than what the agent would do. After the fixes:

- **Network.** Loopback is an IP literal in 127.0.0.0/8 (any IPv4 spelling),
  `::1`, `0.0.0.0`, `localhost` or `*.localhost`; a DNS name that starts with
  `127.` is an ordinary host. A proxy (`-x`, `--preproxy`, `--socks*`, a proxy
  variable), `--connect-to` and `--resolve` make their target a destination of
  the request; `--unix-socket` to a container engine's socket is privilege. A
  fetcher with no URL on its command line (`xargs curl`, a URL list on stdin)
  contacts an address known only at run time (FW-UNCLASSIFIABLE). A variable in
  a URL's host, or a command substitution anywhere in it, is a computed address;
  a variable only in the path or query is a send the firewall cannot size once
  the session is untrusted. Residual: proxy variables are followed for the
  network fetchers (curl, wget, httpie...), not for every program that honours
  them.
- **Patches and archives.** `git apply`, `git am`, `patch` and Codex's shell
  `apply_patch` are judged by the files their patch names, exactly like the
  Write/Edit tools; every plausible path (strip levels, `patch FILE`) is judged.
  A patch the firewall cannot read (piped, from a file the same command writes,
  one that does not parse) is an unresolvable write in an untrusted session,
  and in any session when the workspace holds agent settings. A whole-archive
  extraction (`tar x`, `unzip`) of an archive that came from outside
  (downloaded, written by the untrusted session, outside the workspace, piped)
  is an unresolvable write in an untrusted session; the repository's own
  archives extract as before.
- **Loose edit tools.** Codex's `apply_patch` and Gemini CLI's `replace` do not
  need an exact match. Their matching rules were not captured, so the engine
  over-approximates: an edit is judged at every place its text could match
  (exact occurrences, then whitespace- and punctuation-insensitive ones, which
  covers Codex's `@@` anchor) and the most severe result wins; an edit that
  matches nowhere is the worst case (FW-TAMPER for a hook settings file; an
  editor or dev-container file is judged as if the new text were added).
  Gemini CLI's own correction of `old_string` from its `instruction` cannot be
  predicted; it is covered only by the no-match worst case.
- **Gemini CLI's `web_fetch`** is taken to request each whitespace-separated URL
  whole (read from Gemini CLI's source, not captured); a URL starting inside a
  token is judged from its scheme to the token's end, so no request is judged
  on less than it sends.
- **Self-protection.** A settings layer above the recorded sandbox profile
  (local over project over user) is judged on the effective settings, and so is
  ConfigChange. Hook files are recognised by location (`CODEX_HOME`,
  `GEMINI_CLI_SYSTEM_SETTINGS_PATH`, Cursor's user and enterprise
  `hooks.json` with their real paths) and by registration, not only by name.
- **Cursor.** The Cursor adapter was built alongside these fixes; each
  one with a Cursor equivalent is carried over and tested through Cursor's own
  events. Cursor's edits carry the whole new file, so its result checks are
  exact; a write whose content the hook does not carry is the worst case.
- **Assumptions to confirm with captured events:** that Codex reports a
  shell-invoked `apply_patch` as `Bash` (the shell path now judges it either
  way); Gemini CLI's exact URL extraction; both CLIs' loose-matching rules;
  whether Gemini CLI fires `BeforeAgent` for an `invoke_agent` subagent.

## Symlinked aliases of protected locations

Testing against an installed firewall found that the installed package root was protected only by
its real path: `cd <realpath>/firewall && npm run build` was denied
(FW-TAMPER), but the same directory through `/tmp` (macOS `/tmp` is a link to
`/private/tmp`) or `npm --prefix <alias>` was not. An agent could reach the
installed runtime through any symlinked alias of it.

- **Both sides are canonical.** A target is compared as written and in its
  canonical form (realpath of the longest existing prefix plus the rest, a
  dangling link followed); the installed runtime, the firewall home, the
  agents' config directories and the protected patterns' literal prefixes are
  compared in both forms. This holds
  for tool paths, shell paths, globs (`rm -rf <alias>/dist/*`), the hook's own
  working directory, and the directory after `cd`, `pushd`, relative `cd`s and
  the programs' directory options (`npm --prefix`/`-C`, `pnpm -C`, `yarn
  --cwd`, `bun --cwd`, `make -C`, `git -C`, `env -C`).
- **Case is folded on every platform.** A Linux host cannot tell whether a
  directory folds case: WSL2 with the workspace on `/mnt/c` (NTFS), an SMB or
  exFAT mount and an ext4 directory marked case-insensitive all look like
  Linux, and there `claude.md` or `.Claude/Settings.json` is the protected file
  itself. So the lists of protected files, persistence points, secrets,
  credential stores, the firewall's own directory and the agents' settings
  files are matched ignoring case, whatever the operating system. What grants
  trust (the workspace, the scratch directory, whether reading a file outside
  the workspace reads your own agent settings rather than outside content, and
  whether a program is the firewall's own CLI) keeps the platform's rule, so
  folding case only ever adds a question.
  The price is a hold or a question about a look-alike that is a separate file
  on a case-sensitive disk (`docs/agents.md`); see
  [limitations](limitations.md).
- **Fail closed.** A path whose resolution fails for any reason but a missing
  part (a symlink loop, a directory the user may not search, a name too long)
  is treated as possibly protected: a write there is judged by the protected
  rule (checked in a trusted session, held in an untrusted one), and a build
  runner there is held for a person.
- **Links made in the same command.** `ln -s <install> x && cd x && npm run
  build` is judged with the new link applied, before it exists on disk.
- **Left:** a `cd -P` is followed logically (the stricter physical reading
  applies to programs' own directory options); a link made some other way in
  the same command (a script, `python -c 'os.symlink(...)'`) is seen only once
  it is on disk, at the next action; the OS sandbox (`doctor --fix`, `run`)
  remains the layer that sees what the shell actually does.

### The shell grammar (fuzzing)

The shell analyzer reads a command the way bash would before judging it, so
that a construct does not hide an action by being parsed differently; the
gaps left are listed under **Left:** below and in
[limitations.md](limitations.md#shell-constructs-not-yet-analysed). It models:
`((` as arithmetic only when bash reads it so (`((cmd); cmd)` is nested
subshells), functions in every form (`f()`, `function f`, `function f()`, a
`{ }` or `( )` body) defined anywhere (inside if, for, while, until, case and
subshell bodies), with each call judged as the body in the directory it runs
in; case statements, inside command substitutions too (a pattern's `)` does
not end `$( )`); brace expansion (`{rm,-rf,~}` is `rm -rf ~`); array elements;
`[[ ]]` tests with their regular expressions; and a here-document opened in a
group, read at the next newline. **Anything it cannot model exactly** (a stray
or unbalanced `(` `)` `{` `}`, `;;` outside a case, a parenthesis inside a
command such as a zsh glob qualifier, `coproc`, a computed function name, a
here-document without its body, brace expansion past 256 words, a glob in the
program's name, a glob word over 4,096 characters, more than 64 function calls
followed) makes the command unclassifiable: a person decides, never an allow
with no effects (`test/shell-grammar.test.ts` holds the table). Glob matching
is an automaton, linear in the path, with a deterministic work bound whose
overrun takes the stricter answer; a path longer than PATH_MAX is treated as
protected and secret. **Left:** zsh-only grammar beyond the cases above is
read as bash; arithmetic evaluation of a variable's contents (`(( x ))` where
`x` holds `a[$(cmd)]`) is not followed.

A second fuzzing pass found more constructs that bash or zsh runs but the
analyzer had read as a no-op (`test/shell-builtins.test.ts`): legacy `$[ ]`
arithmetic (it no longer looks like a here-document); a command substitution in
an **unquoted** here-document body; `trap 'cmd' SIG` after options; `hash -p
<path> <name>` remapping a later name; `jobs -x cmd`; `mapfile`/`readarray -C
callback`; a command substitution in an array **subscript** that bash evaluates
arithmetically even inside single quotes (`let`, `declare`/`local`/`readonly`/
`export`, `read`, `printf -v`, `unset`, `[[ -eq/-v ]]`, `test -v`); an array
assignment body `a=( $(cmd) )`; a brace-expanded program name; a shell reading
its script from a process substitution (`sh < <(...)`, `bash <(...)`); `coproc
[NAME] body`; `enable -f` loading a builtin from a shared object; and zsh's `-`
precommand modifier and `repeat N`. Each is now either modelled (the hidden
command is seen) or, where it is zsh-only grammar bash rejects (`=(...)`, glob
qualifiers, `always`, short `for`/`foreach`, short `if`), a parse error that
makes the command unclassifiable. Nesting of every grouping form, process
substitution included, is bounded, and a pathological command no longer
exhausts the stack.

A recheck tightened several of these (`test/shell-recheck.test.ts`). Some shell-command constructs are still being hardened (commands wrapped by less common wrapper programs, scripts fed to interpreters in unusual ways, and run-time paths passed to programs); see [limitations.md](limitations.md), and report any you find as described in [SECURITY.md](https://github.com/shivanagendrakore/agent-firewall/blob/main/SECURITY.md). The recheck covered:

- **Here-document continuations.** An unquoted body is read with
  backslash-newline removed, as bash does, before command substitutions are
  looked for (`$\` + newline + `(cmd)` is `$(cmd)`). A continuation onto the
  delimiter line, where shells could disagree on where the body ends, makes
  the command unclassifiable.
- **Shells reading their script from standard input.** `sh`, `bash`, `zsh`,
  `dash`, `ksh` with no script, `-s`, `-`, `/dev/stdin`, or `-c` with no code
  read standard input. A here-document or a literal here-string is analysed as
  the script; so is static text piped in (`echo`/`printf` of literal words, in
  every reading of echo's backslashes, and `cat` of a here-document). Output
  only known at run time (`cat f | sh`, `git show ... | bash`, a computed
  here-string, a group's output) and a file given with `<` (run like `sh file`,
  its contents not read) are opaque: allowed in a trusted session, asked once
  untrusted, never a plain allow. `source`/`.` of `/dev/stdin` follows the same
  rule, and of a process substitution or a computed path is opaque like `bash
  <(...)` (remote code when it is a download).
- **Wrapper options.** `xargs`, `nice` (`-N`, `--N`, `-n N`), `env`,
  `timeout`, `nohup`, `time` (bash's `time -p` too), `stdbuf`, `ionice`,
  `chrt`, `taskset`, `setsid`, `caffeinate`, `command`, `builtin`, `exec`,
  `sudo`/`doas`/`pkexec`/`run0` and the tracing wrappers each read their own
  option table (GNU, BSD and macOS forms, long-option prefixes), so the program
  they run is the one analysed. An option a wrapper does not have makes the
  program uncertain (opaque); it is never taken as the program's name.
- **Run-time paths.** A program that deletes or runs what it is given (`rm`
  and the other deleters, a shell, an interpreter, `source`) under `xargs`
  (paths appended, or at `-I`/`-J`/`-i`/`--replace`'s string), `find
  -exec`/`-execdir`/`-ok` (`{}`), `fd -x` or `parallel` (inputs from stdin,
  `::::` or `-a`) gets a path known only at run time: a recursive delete is
  decided like `rm -rf "$X"`, and running it is opaque. Executing any file whose
  path is only known at run time is opaque. Other programs keep the previous
  reading, so `find ... -print0 | xargs -0 grep ...` stays allowed.
  `parallel`'s literal `:::` inputs are analysed in place, and `parallel` with
  no command runs its inputs as commands.
- **Left:** `echo`/`printf` are the only producers whose output is modelled
  (anything else piped into a shell is opaque, not analysed); a shell's
  `-c` without code is read as reading standard input (stricter than bash,
  which refuses it); a run-time path handed to a program outside the deleters,
  shells and interpreters (`xargs sed -i`, `xargs chmod`) is not judged as an
  unknown path.

### The local API and the guard (fuzzing)

A fuzzing pass over the local API sidecar (raw HTTP on its socket and on
127.0.0.1), its five action formats, and the library's guard under random
sequences of calls, results, inputs, prompts and approvals, with the sidecar
and the library compared step by step (`test/fuzz/api-sidecar.test.ts`,
`api-formats.test.ts`, `guard-seq.test.ts`; each finding has a reproducer in
`test/fuzz/found.test.ts`), found and fixed:

- **Arguments nested too deep to judge.** An extra argument nested a few
  thousand levels deep overflowed the stack while deciding, and the failure
  policy let read-only tools through: `Read ~/.ssh/id_rsa` was allowed by the
  hook, the library and the sidecar. Arguments deeper than 256 levels are now
  refused before anything is judged, and an error the input's own shape
  causes (that refusal, a stack overflow) is a deny for every tool; the
  sidecar answers such a request with a 400.
- **Arguments past the walk's bounds.** The walk over an MCP or unknown
  tool's arguments stopped silently at depth 12 and at 2,000 strings, so a
  credential path or a credential past either bound was never judged. It now
  goes as deep as the engine judges and reads 20,000 strings; arguments it
  cannot read to the end make the call unclassifiable (a person decides).
- **Quadratic secret search.** Once a session has seen a credential, every
  argument is searched for it; one pattern backtracked over long runs without
  dots, so a 100 KB argument took seconds and a 1 MiB sidecar body minutes.
- **MCP server names in the sidecar.** A server ending in `_` ran into the
  `__` separator and was read back as another server; it is now a 400.
- **The sidecar's memory.** The decisions it remembers for `results` held
  every call's arguments, 10,000 of them, so one agent's token could grow the
  server until it was killed; they are now bounded at about 64 MiB too.
- **Quadratic prompt reading.** The pattern that drops email addresses from a
  prompt before naming its destinations backtracked the same way: a 1 MB
  prompt took minutes (a 3.7 MB Codex prompt passed the hook's timeout).
- **Extra fields in the decision log.** A field added beside an entry's
  hashed fields still verified; `log verify` now fails it (found by the
  existing log-reader fuzzer in the same pass).

The properties the fuzz tests check, which held in the runs made (fuzzing
finds bugs; it does not prove there are none): no 500, crash or hang on a
generated request; Origin and Host
refused on every spelling; no 200 for an invalid request; no token or token
hash in a reply; no agent reaching another's sessions, approvals or decisions
through any path spelling; Idempotency-Key reuse; concurrent requests on one
session; state that only gets stricter; deterministic, check-predicts-decide
verdicts; single-use approvals; no silent allow when the log refuses an entry.
A review of these fixes tightened them further (`test/fuzz/found-review.test.ts`):
one call's many URLs no longer scan the same payload once each (scans are
remembered per decision, duplicate effects are found in constant time, and past
200 destinations a call is unclassifiable); only a stack overflow, an over-long
string or the depth refusal count as the input's doing, and that deny carries
`FW-INPUT-SHAPE`, which `doctor` counts; a verdict that exists is never lowered
by a failure after it, and a read-only call goes ahead through an internal error
only if the engine alone would allow it; a tool result the scan cannot read in
full marks the session as holding private data; an ambiguous `mcp__a___b`
resolves only to a server the policy lists by its longer name, otherwise a person
decides (`doctor` warns about server names ending in `_`); the sidecar's
decision memory is per agent and a result for a forgotten decision is
`FW-RESULT-UNRECORDED`; every log verifier refuses extra fields; and a timing
fuzzer doubles the input of the engine's text scanners (it found a quadratic
blank-line check in the SQL reader), and the shell fuzzer holds every decision
to 400 ms (it found a command of 17,000 repeated words that classified each
path again; a path is now judged once per action, and long lists of different
paths, values and events no longer cost time quadratic in their length).
**Left:** the sidecar's `mcp` and `engine` formats never use the
agent's registry, so a call to a registry-declared server through the `mcp`
format is judged by presets (stricter than the library, which applies its tool
specs' servers to every call).

### The firewall's own files (fuzzing)

A fuzzing pass over the readers of the firewall's own files (session state,
the approval queue, the quarantine store, the decision log, the ledger, the
counters and the MCP pins) rewrites one or two files of a populated home with
a damaged copy (edited bytes or lines, wrong JSON types, truncation, deletion, a
directory in the file's place) and runs every reader (`test/fuzz/readers.test.ts`;
each finding has a reproducer in `test/fuzz/found.test.ts`). The properties:
no reader throws, a damaged session file leaves the session untrusted, a
changed log no longer verifies, the answer is the same twice, and the time is
bounded. It found and fixed:

- **A damaged session file of a few megabytes took seconds to read.** A file of
  hundreds of thousands of short junk lines cost a thrown parse error and an
  event for each line, and every reader read it again; a file of tens of
  thousands of distinct linked parents or agent-scan rules searched a list from
  the start for each one. Reading is now linear in the file's size: a line that
  cannot be an event is recorded without being parsed, the first ten damaged
  lines are listed and the rest counted, and the two lists have an index. The
  fail-strict answer is the same: any damaged line makes the session untrusted
  and sensitive, and every line is still read, so an event after the damage
  still counts.
- **A quarantine record with a field of the wrong type made its readers
  throw.** A record that was valid JSON but had no creation time, or one that
  was not text, broke the sort that lists the store, so the review lists, the
  held count, `doctor`'s check, the prune and the saving of a new withheld item
  all threw. Every field is now checked for its type, so a record with any
  field of the wrong kind, or one filed under another record's id, is listed as
  damaged (`doctor` warns about it) and the rest still list in order.

## Phone approvals

Who can approve from a phone ([phone.md](phone.md); the hosted relay is not available yet, so this describes the design the firewall side already enforces):

| Actor | Can it approve? | Why |
|---|---|---|
| The agent | no | it has no passkey; a hand-written `phone_approval` does not verify (corrupt, untrusted); a copy of a stored one (the same item id, or the same credential and signed nonce, even from a synced passkey whose counter stays 0) is corrupt and grants nothing; adding a key to `phones.json` breaks the pinned hash; re-pinning needs the passphrase |
| LaunchSafe's relay, a database leak, an insider | no | the relay holds no private key and never sees the pairing secret; dropping or delaying only delays; a replayed decision fails the daemon's nonce and counter checks, and a replayed stored approval fails the session's single-use checks |
| Apple's or Google's push service | no | fixed-text notifications only |
| Compromised approval web-app code | cannot approve an action that is not queued, but can mislead | it computes the challenge, so it could show item A and sign B; B must still be a real pending item on this machine with its unused nonce inside its TTL. Mitigated by the separate origin and strict CSP, the action code, approval items only, `phone.excludeRules` |
| Someone holding the unlocked phone | only with its biometric or PIN | user verification is required |
| Someone who photographs the pairing QR | no, unless they finish pairing within 10 minutes and you type yes on a mismatched label and code | |

## MCP

Researched against the MCP spec (2025-06-18), `basic/transports` and
`server/tools`. Relevant points the firewall relies on:

- A server's results and its tool **descriptions** are attacker-controllable
  when the server sits in front of outsider-written data (issues, email, chat,
  tickets, web). The spec itself warns that clients **must** treat tool
  annotations as untrusted unless the server is trusted. The firewall classes
  such servers' results as outside content (they taint).
- `notifications/tools/list_changed` lets a server change its tools after
  approval with no re-approval — the **rug pull**. The firewall does not rely on
  a point-in-time review of tool descriptions; it constrains what the resulting
  tool *calls* may do. It also **pins** each server: a
  changed launch configuration, a tool the server did not expose before (after
  a 24-hour grace window, and only when its tools could have changed: a launch
  not pinned to an exact version, or a changed configuration) and a changed
  tool description it observes in a ToolSearch result taint the session
  (FW-MCP-CHANGED), from the call that reveals the change, and wait for a
  person's `pins accept`. The configuration comparison runs on resume too. A
  first use of a tool on an exact-version, unchanged server is logged, not
  alerted (alert fatigue trains people to accept without reading). This is partial: a hook never sees `tools/list` itself, so a
  description is pinned only once Claude Code shows it through ToolSearch, and
  descriptions loaded straight into the agent's context are not seen at all.
  The MCP gateway closes that gap for wrapped servers: it sees every `tools/list`, pins every definition and hides a changed
  or new tool until reviewed (FW-MCP-TOOL-HELD), and scans every result,
  withholding hidden instructions (FW-MCP-WITHHELD). Its limits: MCP traffic
  only (native tools still rely on the hooks, and nothing covers a desktop
  app's own tools), servers added without the gateway bypass it (reported by
  `gateway status`), vendor-cloud connectors are out of reach, taint lasts for
  the client process, and scanning is pattern-based. Its own surface: a
  127.0.0.1 listener with Host/Origin checks and per-client bearers, strict
  JSON-RPC framing, unknown methods refused, upstream tokens audience-bound.
  See [gateway.md](gateway.md).

Invisible characters in what the agent reads (FW-HIDDEN-OUTPUT in the hooks
and the library, the content scan in the gateway and the email guard) are a
detector tuned to leave ordinary text alone, and the taint rule stays the
boundary. One zero-width space is no finding, because pasted text carries them
and a sentence cannot be spelled in a few; a dense run (eight or more, or four
in a row) makes the session untrusted in the hooks and the library, and the
gateway withholds it only beside a phrase addressed to an AI assistant. What
this leaves open: a message spelled in invisible characters that is split
across results below the count, or written in kinds the scan does not know
(it is pattern-based, like the rest). Details in
[design.md](design.md#what-taints-what-counts-as-sending).

## Supply chain: what the agent is armed with

A repository can arrive with a poisoned `CLAUDE.md`, a hook that runs a
download, a model endpoint moved to someone else's server, or a skill installed
from a marketplace that carries hidden instructions. The write rules
(FW-AGENT-SETTINGS, FW-INSTRUCTIONS-HELD) only see changes made during a
session; they cannot judge what is already there. At session start the firewall
runs LaunchSafe's agent-safety rules over the workspace's, the user's and the
administrator's agent files and starts the session **untrusted** on a critical
or high-confidence high finding, or when a hook, MCP server or flagged memory
changed since the last session. Files `CLAUDE.md` imports with `@path` are
scanned and write-protected like `CLAUDE.md`. Limits: the rules are static and
known-bad patterns only (a clean scan is not proof a skill is benign); the scan
is bounded (400 files, 8 MB, 300 ms). A workspace whose agent files exceed the
file or byte cap (or run out of time inside its agent trees) starts untrusted,
since filler could hide a file past the cap; a large repository that only runs
out of directories or time in the generic walk is logged, not tainted. Files a
person includes with `@` in a prompt still bypass `PreToolUse`, though agent
files among them are covered by the scan. A hook that imitates the firewall's
own command is drift unless it sits in a registered settings file and names
the installed CLI.

## Incidents turned into tests

Each public incident below is encoded in `src/scenarios.ts` as the hook events
Claude Code would emit (actions and outcomes only, no exploit payloads) and run
as a test. The full write-ups and the rule that stops each one are in
[`incidents.md`](incidents.md).

| Incident | Firewall rule / test id |
|---|---|
| EchoLeak — M365 Copilot zero-click exfiltration (CVE-2025-32711) | FW-DLP-SEEN-SECRET / FW-FETCH · INC-01 |
| GitHub MCP toxic flow — private repo leaked to a public PR (Invariant Labs) | FW-SEND · INC-02 |
| MCP tool poisoning — hidden instructions read SSH keys (Invariant Labs) | FW-CREDENTIAL-READ · INC-03 |
| MCPoison / rug pull — approved MCP config swapped (CVE-2025-54136) | FW-AGENT-SETTINGS (+ FW-MCP-CHANGED at the next session) · INC-04, catalogue MCP-028 |
| CurXecute — chat content writes an MCP config (CVE-2025-54135) | FW-INSTRUCTIONS-HELD · INC-05 |
| WhatsApp MCP — message history sent to an attacker (Invariant Labs) | FW-MESSAGE · INC-06 |
| Supabase MCP — support ticket drives SQL exfiltration (General Analysis) | FW-SEND / FW-DESTRUCTIVE · INC-07 |
| Amazon Q extension — shipped destructive prompt (AWS-2025-015) | FW-DESTROY-ROOT / FW-CATASTROPHIC / FW-DESTRUCTIVE · INC-08 |
| Nx "s1ngularity" — malicious package drives local AI CLIs to steal secrets | FW-AGENT-BYPASS / FW-CREDENTIAL-READ · INC-09 |
| Claude Code DNS exfiltration (CVE-2025-55284) | FW-DNS-EXFIL / FW-CAPTURE-HOST · INC-10 |
| Markdown-image / CamoLeak pattern (GitHub Copilot Chat; the real attack's image-proxy path is not visible to a hook) | FW-FETCH · INC-11 |
| Memory / instruction poisoning (lethal trifecta) | FW-INSTRUCTIONS-HELD · INC-12 |
| Hook/firewall tampering | FW-TAMPER · INC-13 |
| Cloud metadata credential theft | FW-METADATA · INC-14 |
| Persistence (git hooks, shell rc) after untrusted input | FW-PERSISTENCE · INC-15 |
| Download-and-run after untrusted input | FW-REMOTE-CODE · INC-16 |
| ClawHub malicious skills — a skill that runs a download (2026) | agent scan at session start · catalogue INC-29 |
| Repository config trusted too early — model endpoint override (CVE-2026-21852) | agent scan at session start · catalogue INC-30 |

## Decoy files: a detection layer

Decoys catch what the rules cannot see coming: an exotic tool, or code the shell
analyzer cannot read, sweeping through files. A direct read of a decoy is a strong
signal that the agent is doing something other than its task, so it raises an
alert and makes the session untrusted and sensitive, whether the action that
touched it was allowed, held or blocked (an unattended credential sweep and an
exfiltration attempt are the cases that matter most); the value of a decoy
leaving the machine is denied outright and alerts too. What this does **not** catch: an agent that never
touches the decoys (it only helps against sweeps), a recursive search that passes
over a decoy without printing it (no trip unless `canaries.tripOnRecursive`), a
read the firewall does not see (your own backup software or editor indexing is
not an agent action and raises nothing), and a decoy committed with `git add -f`
(a push's payload is not visible; `doctor` warns when git tracks one). Decoys are
credential-shaped but valid nowhere, so a stolen decoy gives an attacker nothing,
and an attacker who learns the file names can avoid them; the layer is cheap
extra signal, not a boundary.

## Supply chain

Malicious packages are the attack with the most confirmed victims. The
firewall's answer is deliberately offline and deterministic: a person-run
`update` fetches OSV's malicious-package advisories; installs, runners and
lockfile installs naming a listed version are denied in any session once the
person has downloaded the snapshot with `update` (none ships; by default, and
`packageIntel.malicious` can make it ask or turn it off) (FW-MALICIOUS-PACKAGE); look-alike names of popular packages need a person
(FW-TYPOSQUAT); and `doctor` recommends a release-age cooldown so a brand-new
malicious version is never fetched in its first days. What this does not cover:
versions not yet reported, packages that are vulnerable rather than malicious,
and install scripts of clean-looking packages (still FW-INSTALL once the session
is untrusted, and the OS sandbox's job once they run). Tests: `test/intel.test.ts`
(INC-26 to INC-28), `test/typosquat.test.ts`, `test/cooldown.test.ts`.

## The person's terminal and helpers

Text an agent or a repository controls (proposal content, reasons, summaries,
MCP launch lines, prompts, log entries) is shown to the person on the approval
and passphrase screens. Terminal control sequences in it could rewrite or hide
lines at the moment the person decides, so every CLI line and every hook reason
shows C0/C1 controls, DEL, bidirectional and zero-width characters as visible
`\uXXXX` escapes. The notification helper runs outside Claude Code's OS
sandbox, so it is never looked up through `PATH` (a directory the agent can
write would make agent code run as the hook): only `/usr/bin/osascript` on
macOS, and on Linux `notify-send` in `/usr/bin`, `/usr/local/bin` or `/bin`,
root-owned and not writable by anyone else. Commands that change the decoys,
the policy file or the log need a person at the keyboard, like approvals.

## The local dashboard

`launchsafe-firewall ui` adds a listening socket (127.0.0.1, random port) that
a web page or the agent could try to reach. It is read-only (GET and HEAD
only), every path needs a per-launch token printed only to the person's
terminal, Host/Origin/fetch-metadata checks refuse DNS rebinding and other
local sites, a strict CSP forbids every external resource, and approvals stay
behind the passphrase in the terminal. The agent may not start it. Full design
and residual risks: [dashboard.md](dashboard.md).

## The vault and same-user code

The vault's values live in the operating system's store, outside the agent's
reach through the firewall: the store's own tools naming the firewall's service
are FW-TAMPER, the vault's files are in the protected data directory, and its
index is signed with the approver key, so neither the agent nor a repository can
add a binding. What it does not stop: a program running as you, outside the
agent's sandbox, that the firewall cannot see into. On macOS it can read items
stored with `confirm: "never"` silently through `/usr/bin/security`; items
stored with `confirm: "always"` show the keychain dialog on every read. On Linux
any program on the session bus can read Secret Service items once the keyring
is unlocked, and the encrypted file store protects against backups only. The OS
sandbox (no bus socket, no firewall home) is what keeps sandboxed commands away
from the store. A value that reaches the agent anyway is recognised by
fingerprint in outbound data the firewall reads (the documented encodings,
values of 12 characters or more, not the contents of uploaded files) and
denied to every destination it is not bound to (FW-VAULT-EGRESS). See
[vault.md](vault.md).

The dashboard never renders a stored value: pages are rendered with the
vault's fingerprints and any line holding a value is replaced by a note naming
the secret. The vault's service name is part of the firewall's identity, and a
store lookup that does not name a service (it would match the vault's items by
account or label) is FW-TAMPER from inside an agent.

## Email and messages

Mail is outsider-written text by definition, and a person never sees what
hides in its markup. The email guard (`docs/email-guard.md`) withholds
messages with hidden, agent-directed text on the agent's read path, before the
model reads them where the hook can replace output (Claude Code; this relies
on Claude Code replacing the tool's output, which its documentation describes
but which was not captured live: if it is ignored the model sees the original
text and the taint rule still applies), and records them for the person. Assumptions and limits:

- The guard is a detector, not the boundary. The boundary stays the taint rule:
  a mail server's results make the session untrusted, so a missed message
  still cannot make the agent send data, send messages or change its own
  instructions without a person.
- On Codex, Gemini CLI and Cursor the model reads the message before the hook
  runs; the guard can only warn the agent and record. Through the MCP gateway
  (`mcp wrap-config`) the gateway runs the same filter on the pipe, so withheld
  messages never reach any client's model.
- Sender authentication is read from the provider's own top-most
  `Authentication-Results` header; a sender's forged headers sit below it.
  No signature or DNS check is made.
- Release is a person-only state change (FW-TAMPER from an agent), signed with
  the approver key when one is set; the hook honours only releases signed by
  the key pinned in its command. The quarantine store is in the protected data
  directory.
- Records keep a short escaped preview of the hidden text, never the message.

## Programs the hooks cannot see: `run`

The hooks see tool calls, so a compiled binary, a script that opens a socket,
or an agent with no hooks at all is outside their view. `launchsafe-firewall
run` puts such a program inside the operating system's sandbox (Seatbelt on
macOS, bubblewrap on Linux): writes only to the workspace and a private
temporary directory, the firewall's own files read-only, credential stores
unreadable, and the network only through a local proxy that admits the
policy's hosts and applies the budgets. What it cannot see: methods and
bodies (TLS is not decrypted), so uploads to an admitted host are bounded by
budgets, not stopped; a CDN that routes on the encrypted `Host` header; on
macOS, system services not on its deny list; on Linux, sockets reachable
through paths it does not hide, and protected files that did not exist when
the run started. Full list: [run.md](run.md).

## Out of scope

- Keeping the model from being persuaded. We assume it can be.
- Containing a process that has already been allowed to run (that is the OS
  sandbox's job; we recommend running both: `doctor --fix` sets up Claude
  Code's, and `run` starts any other agent inside one).
- Attackers with direct code execution on the machine, or who control the user's
  own prompts.
- A malicious *user* trying to exfiltrate their own data — the firewall protects
  the user, not against them.
- Running a renamed copy of the CLI. Self-protection is keyed to the
  installed runtime: a copy elsewhere under another name is not the firewall,
  and running it is not tampering by itself. That is acceptable because what a
  copy could change still needs the approval layer: approving and uninstalling
  need the passphrase, and the hook accepts only approvals signed with the key
  pinned in the hook command; the copy cannot write the data directory, the
  runtime or the settings entries without a tool call the classifier denies.
  A signed approval is also single-use and lapses: it signs a random nonce, an
  expiry (24 hours), the rule ids the person was shown and the directory and
  project the agent was in. Its use is recorded by id and an id used anywhere
  in the session never counts again; the same approval line twice (a
  byte-identical copy) makes the session untrusted and grants nothing. An
  approval no longer covers the action once a rule the person did not see asks
  about it (a session that read a credential after the approval, say), and the
  hook and the gateway do not use it for the same command run from another
  working directory or project (the agent can `cd`, and a relative command is
  another action elsewhere). The engine makes both checks on every route (the
  hook, the gateway, the local API and the library), so none can skip them; the
  local API and the library bind an approval to the call's `cwd` and workspace
  roots through the approval's key instead. An approval that is not used is
  kept, not spent, and the action asks again with a message that says why; the
  person approves the new item, which shows the rules that ask now. Older (v1)
  approval lines, which carried no nonce or expiry, are ignored after the
  upgrade. Left: someone able to rewrite the whole session file (removing both
  the approval's use and the original) can make an unused copy count once,
  until its expiry; a phone approval signs the action and the queue item but
  not the rules or the place, so it is not checked this way; an action held as
  a proposal (on its own, or as one file of a patch) names, and is checked
  against, only the rules that hold it, not one that would only ask about the
  same action; and a rule that first asks past a decision's 16 listed rule
  entries is not checked. A call that
  becomes several actions is checked against the rules of every action that
  asks or is held, all of which its held item names.

Each rule's mapping to OWASP Top 10 for LLM Applications and for Agentic Applications, MITRE ATLAS/ATT&CK and the MCP specification is in [coverage.md](coverage.md), with what each framework item leaves uncovered; `launchsafe-firewall explain <rule>` explains one rule in plain words.
