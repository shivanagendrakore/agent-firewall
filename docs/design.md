# Design

## Shape

```
  Claude Code · Codex · Gemini CLI · Cursor
      │  hook event (JSON on stdin; `hook --agent claude|codex|gemini|cursor`)
      ▼
  src/adapters/             ← one adapter per agent (parse, normalize, render: translation only)
  src/hook/claude.ts        ← runHook and the Claude Code entry (the shared pipeline is src/hook/pipeline.ts)
      │  NormalizedAction + Context + SessionState
      ▼
  src/engine/               ← pure policy engine (no I/O)
    classify.ts   action → effects (built-in tools, MCP tools, unknown tools)
    shell/        a conservative sh/bash parser + semantic analyzer
    paths.ts      path → zone / protected / secret / persistence / firewall
    network.ts    URL/host parsing, capture hosts, DNS-exfil shape, metadata
    secrets.ts    credential shapes, fingerprints (rolling hash), redaction
    pii.ts        Luhn / IBAN mod-97 / Verhoeff — cards, IBANs, national ids
    sql.ts        read / write / destroy / reaches-outside classification
    decide.ts     effects + state + policy → verdict (the rule table)
      │  Decision (verdict, reasons, rules, events)
      ▼
  src/runtime/              ← state, queue, log, policy, install (I/O, locked, atomic)
```

The engine is **agent-agnostic**. `NormalizedAction` (`{ tool, input }`) and
`Decision` are the interface; each agent is an adapter in `src/adapters/` that
translates its hook format to and from these types. No engine code changes per
agent.

The same interface serves agents a company builds itself: the library
(`src/sdk/`, `@launchsafe/agent-firewall/sdk`) calls `decide()` in-process and
keeps state in a pluggable store. See [library.md](library.md).

## Adapters

`src/adapters/types.ts` defines `AgentAdapter`:

| Member | Job |
|---|---|
| `parse(raw)` | the agent's event to an `AdapterEvent` (`pre_tool`, `post_tool`, `prompt`, `session_start`, `subagent_start/stop`, `config_change`, `ignored`); throws `AdapterParseError` on a malformed event, and a pre-tool one then exits 2 |
| `normalize(ev)` | the native call to one or more `NormalizedAction`s in the engine's vocabulary |
| `render(ev, outcome)` | the firewall's verdict and messages in the agent's output format and exit code |
| `provenance(server, …)` | where an MCP server was configured, from the agent's own config files |
| `nonInteractive(ev, env)` | why nobody can answer (claude -p, codex exec, gemini -p, yolo, or the agent's process could not be read), or null |
| `supportsAsk`, `supportsUpdatedOutput` | protocol capabilities; without ask, an approvable action is held in the queue |
| `shortCircuit(ev)` (optional) | an answer before the pipeline runs, for an event another of the firewall's hooks decides (Cursor: `preToolUse` for `MCP:<tool>` defers to `beforeMCPExecution`; a Cursor event arriving through the Claude Code hooks defers to the Cursor hooks when they run) |
| `settings`, `coverage` | where and how hooks are registered (install, doctor, managed snippet), and what the hooks can and cannot see |

The pipeline (`runHook(raw, { agent })`) is the same for every agent: parse,
then for a pre-tool event normalize, `decide()` each action and combine them
(`decideNative`): the most severe verdict wins, the reasons of the actions at
that verdict are concatenated, and the approval hash is the hash of the
**native** call, so an approved multi-file Codex patch runs once, as a whole.
A held call also lists the actions that would only be asked about (in an
attended session a proposal can hold the patch while another file only asks):
one approval runs every action, so the person sees, and the approval signs,
every rule that asks or holds, and the approval is checked against all of them.
A call that normalizes to itself (every Claude Code tool) is decided exactly as
before. Session state, queue, log, policy and identity are shared; session ids
are namespaced per agent in file names (`codex:<id>`, `gemini:<id>`,
`cursor:<id>`; Claude Code's are unchanged so existing state stays valid). Cursor
also runs the hooks in Claude Code's settings files with its own payload, so
`runHook` routes any event carrying `cursor_version` that reaches
`hook --agent claude` to the Cursor adapter (`ev.via = "claude"`).

**One place for the hook-side guarantees.** Everything the pipeline does around
`decide()` is agent-independent, so the security fixes hold
for every adapter: the tripwire's events are recorded and alerted for every
verdict, also when an ask becomes a held action for an agent without ask
(only the tripwire's events are kept then) and for every part of a call that
does not run; `say()` escapes control, bidi and zero-width characters in the
reason, system message, added context and stderr before the adapter renders
them (a redacted tool output is passed through as it was); every session
start compares the MCP pins; pin taint is applied before deciding;
`stopsDataLeaving` picks the blocks that notify; a proposed prompt is
matched before destinations and the task scope are recorded; held edits
keep `replace_all` (a Gemini `replace` with `allow_multiple`). The parts
of a multi-action call add their budget usage up under the native call's hash and their scope effects are combined. An unknown tool is approvable in any session, so each adapter maps every native tool seen in
its captures to a known one; anything else is held for a person.
`test/adapters/review-fixes.test.ts` drives each fix through Codex, Gemini CLI and Cursor.

| Agent | Adapter | Native calls that need more than a rename |
|---|---|---|
| Claude Code 2.1.289 | `claude.ts` | none |
| Codex 0.162.1 | `codex.ts` | `apply_patch` (parsed by `patch.ts`: an added file is a `Write`, an updated one a `MultiEdit` of its hunks marked `match: "loose"`, result-checked against the current file for settings, auto-run forms and auto-approval switches at every place its text could match, a delete is `rm`, a move `mv`; a patch that does not parse is one `launchsafe:unparseable` call, FW-UNCLASSIFIABLE); a shell argv array is joined with shell quoting |
| Gemini CLI 0.63.0 | `gemini.ts` | `web_fetch` (one `WebFetch` per whitespace-separated URL in its prompt, taken whole), `replace` (an `Edit` marked `match: "loose"`), `read_many_files` (a glob is a recursive read), `save_memory` (a write to `~/.gemini/GEMINI.md`) |
| Cursor (cursor-agent 2026.10.01, read from source) | `cursor.ts` | `Delete` (`rm`); an MCP call is named by `beforeMCPExecution`'s server (`preToolUse`'s `MCP:<tool>` is deferred); `Write` carries the whole new file (exact result check; without its text it is FW-UNCLASSIFIABLE); `FetchMcpResource`'s download is a write of unknown content; `beforeReadFile`'s content is recorded as the read's output; hook entries are flat and fail closed with `failClosed: true` (no shell wrapper: Cursor's legacy transport appends a heredoc) |

**Subagent linkage.** A subagent event with its own session id and its parent's
(`subagent_start` with `parentSessionId`) starts the child with the parent's
state (taint, private data, fingerprints, scope, a `linked` event); on
`subagent_stop` the child's taint, private data and fingerprints are added to
the parent. Claude Code and Codex 0.162.1 (captured) keep the parent's
`session_id` on a subagent's events, so its taint lands in the parent's state
without linkage; Codex marks them with `agent_id`, and a subagent's
`UserPromptSubmit` (written by the parent model) never sets the person's named
destinations. Gemini CLI reports no subagent events, but its subagents' tool calls carry the parent's `session_id` (captured), so taint is shared. Cursor reports a subagent's own
id (`subagent_id`, `child_conversation_id`) and its parent's conversation, so it
uses the linkage (not verified live).

**MCP pins per agent.** The session-start comparison (`src/hook/agent-checks.ts`)
reads Claude Code's MCP files and, through `src/runtime/agent-mcp.ts`, those of
every agent the firewall is installed for (Codex's `config.toml`
`[mcp_servers.*]`, Gemini CLI's `settings.json`, Cursor's `mcp.json`). Another
agent's server is pinned under that agent (`codex-user:<name>`; an MCP call's
pin source is prefixed the same way), and a change in it taints only that
agent's sessions: another agent's session records the pending change quietly, so
the owner's next session still reports it. A server launched through the
firewall's own CLI (`launchsafe-firewall … -- <server>`, or this installation's
`cli.js`) is compared on what it wraps; the firewall alone is not pinned.

The replay helpers (`src/agent-replay.ts`) translate a Claude Code-shaped event
into another agent's (Codex reads with `cat` and fetches with `curl`; Gemini CLI
has its own tools), so the incident scenarios, the friction corpus and the
catalogue rows run through every adapter (`test/adapters/replay.test.ts`).

## The decision pipeline

1. **Classify** the action into `Effect`s — concrete things it does, each with a
   class (`read_external`, `egress_send`, `write_protected`, `destructive`, …),
   a target, and flags (`taints`, `private`, `download`, `payload`, `proposal`).
   - Built-in tools (`Read`, `Write`, `Edit`, `Bash`, `WebFetch`, …) have
     explicit models.
   - MCP tools are classified by the server's trust (from policy, then presets,
     then — for a repository-defined server — forced untrusted) and the tool's
     verb (`get`/`list` → read, `create`/`send`/`delete` → send/destroy).
   - **Host tools** (`src/engine/hosttools.ts`) are the host application's
     own tools, catalogued from captured events with a reviewed kind:
     `to_user` (`SendUserFile`, `SubagentHandback`: their paths are read for the
     credential rules only, no taint, no write probe, text is not egress),
     `ui_state` (`mcp__ccd_session__mark_chapter`, `dismiss_task`,
     `mcp__ccd_host__request_keep_awake`, `Artifact` list of the person's own
     pages, pin/unpin, `ArtifactComments` watch: no effect), `spawn_session`
     (`mcp__ccd_session__spawn_task`: no effect in a trusted session; from an
     untrusted one an `agent_spawn` effect, FW-AGENT-SPAWN, whose ask carries
     the whole prompt with control characters escaped. The hook logs the
     prompt as `spawned_prompt`, hash and first 200 characters, and `status`
     shows it; every allowed or asked proposal is also recorded in
     `spawned.json` in the firewall home, and a later `UserPromptSubmit` that
     equals or contains it names no destinations and, when the proposer was
     untrusted, taints the new session. Assumption, not verified against a
     captured event: the app delivers the prompt as the new session's first
     prompt, verbatim or wrapped; the ask holds either way),
     `read_outside` (`Artifact` read and list beyond the person's own,
     `ArtifactData` get/list/query/profiles, `ArtifactComments` read: the
     result is outsider-written, so `read_external` with taint, and the request
     is an `egress_fetch` the data rules see; `ArtifactData`'s `out_dir` is a
     write) and `publish` (`Artifact` publish, `ArtifactData` writes,
     `ArtifactComments` reply/resolve: `egress_send` to claude.ai with the
     content as payload, so FW-SEND and the data rules apply). An action of a
     catalogued tool that no entry names (`Artifact` delete) is an unknown
     tool. An MCP-shaped
     host tool counts only when `mcp_server.source` is `sdk` (an in-process
     server only the host can register; Claude Code rejects `type: "sdk"` in a
     configuration file). `userOutputTools` (user or managed policy) adds
     `to_user` names; `notUserOutputTools` removes any. A tool not catalogued,
     or a renamed one, falls back to the unknown-tool path.
   - An **unknown** tool is marked `unknown` and its string arguments are scanned
     for paths and URLs, so even a tool the firewall has never seen is judged by
     where its data goes. R2: FW-UNKNOWN-TOOL asks in any session (queued when
     unattended), and the effect taints, so its result is outside content.
     `userOutputTools` declares a tool that only shows the person something.
   - A **workspace-confined filesystem server** judges its sending and
     deleting tools as writes of their path arguments, like the Write tool; its arguments still pass the data rules.
2. **Findings** record hard facts independent of state (a capture host, a
   DNS-exfil shape, a secret flow, hidden Unicode, a parse failure).
3. **Rules** (`decide.ts`) turn effects and findings into outcomes
   (`allow` / `approve` / `hold` / `deny`), most severe wins:
   - `deny` — always-on protections (data loss, self-tamper, destroy-root,
     capture host, metadata, hidden text) and, in an untrusted session, the
     worst flows (download-and-run).
   - `hold` — a change to the agent's instructions or memory, or to a git hook
     or an auto-run file, in an untrusted session; becomes a queued
     **proposal**, never applied by the agent.
   - `approve` — needs a person; becomes `ask` when someone is there, `queue`
     when not.
   - `allow` — passes through to Claude Code's own permission rules.
4. **Events** are the state changes an allowed/asked action records. They only
   ever make the session stricter (taint, sensitivity, remembered secret
   fingerprints, downloaded files, files written while untrusted). Taint never
   clears.

### What taints, what counts as sending

- **Taint** comes from any action that brings outside content back to the
  agent: WebFetch/WebSearch, a network fetch in the shell (`curl`, `wget`,
  `http`, `aria2c`, `npm view/info/search`, `ssh` output, `nc`/`socat`, a URL in
  inline code), a forge read (`gh issue view`), service logs, an MCP server whose
  results are outsider-written, a file outside the workspace, and any downloaded
  file — including stdout a fetch sends to a file with `>` or `tee`.
- **Outsider-writable sources always taint.** Error trackers and log services,
  forges and issue trackers, support desks, outside chat, mail and the web
  (`src/engine/outsider.ts`, matched on the server's name and on product names
  in a tool's name) keep untrusted results even when the policy marks the
  server `trusted`: the person may trust their own Sentry, but anyone can put
  text in a Sentry event. `outsiderWritable.alwaysTaint` (on by default; a
  project may only turn it on and add servers) and `outsiderWritable.exempt`
  (user or managed only) set it.
- **Commands outside content showed** (FW-OUTSIDE-COMMAND). PostToolUse
  records, for a result that taints, fingerprints of the commands it shows
  (riskiest first: URLs, pipes into a shell, installs, privileges, scripts)
  at several granularities: each part (split at newlines, `&&`, `||`, `;`,
  `|`, `&`, `$(`, backticks; continuations joined) after wrappers are
  unwrapped and the program is named without its path or version, the
  program with its arguments sorted and without flags, the program with a
  specific first argument, every URL and install address, every script or
  package file name, the packages install commands name, and the set of a
  part's specific words (`outside_command` events carry hashes only). A shell
  command (Bash, Monitor, PowerShell) whose parts match any of them, or which
  holds every specific word of a remembered part, or whose package requests
  name a remembered package, needs a person when it does more than read,
  write in the workspace, run the project's own code or fetch without
  keeping a file. Past 512 KiB of content, 64 parts or 512 fingerprints in a
  result, or 4,096 in a session, a saturation event makes every risky
  command ask. The comparison does not re-enter the shell parser: a command
  assembled at run time is not matched (`it.fails` tests).
- **Hidden characters and terminal codes in a result** (FW-HIDDEN-OUTPUT,
  `src/engine/hidden.ts`). Invisible characters are Unicode format characters
  and default-ignorable code points (plus the braille blank), minus their
  ordinary uses: emoji ZWJ sequences, a ZWJ or ZWNJ in a joining script, ZWSP
  in Thai, Lao, Khmer and Burmese, a leading BOM, bidirectional marks inside
  real right-to-left text, preheader padding. One such character on its own,
  or a few, is not a finding, because pasted text carries them: a result
  holds hidden ones when it has eight or more, or four in a row (see below).
  Tag characters outside RGI flags; variation selectors other than one on an emoji, a keycap or an
  ideograph (two or more spell bytes, decoded); terminal control sequences
  (SGR 8 or a foreground equal to the background, extended colours parsed so
  a grey is not "conceal"; cursor moves and erases; a carriage return or
  backspace over text; OSC/DCS/APC/PM/SOS strings, bounded to 4 KiB and ended
  by BEL or ST, otherwise only the introducer is removed; other C0/C1
  controls). The output of programs a trusted session ran, with no file
  printed beside them, counts only concealed text and OSC strings. Past 4 MiB
  or 100,000 control sequences the scan is incomplete (a finding). Claude
  Code gets MCP results and fetched pages rewritten string by string (each
  run of invisible characters becomes `⟦hidden⟧`, control sequences removed)
  when the kinds read differently to a person (this relies on Claude Code
  replacing the tool's output, which its documentation describes but which was
  not captured live; if it is ignored the model sees the original text and the
  taint rule still applies); file reads and shell output
  are never rewritten. Outside MCP results every finding taints (the host's
  use of a replaced output is not confirmed for built-in tools); everywhere,
  text smuggled in tag characters or variation selectors taints, and so does
  a dense run of invisible characters, which is not among the kinds a
  rewrite covers. The gateway
  marks and strips every MCP result, withholds text spelled in variation
  selectors, delivers colour-only output unchanged, and taints when
  `stripHidden` is off. A file write's output (the agent's own text) is not
  checked.

**Zero-width characters in a result, by route.** The routes differ in what they
can do before the model reads the text, so they answer the same three cases
differently (the hooks and the library do not look for a phrase at all). A run
is *dense* at eight or more invisible characters outside their ordinary uses,
or four in a row.

| In one result | Hooks and library | MCP gateway |
|---|---|---|
| One, or a few (fewer than eight, no run of four) | no finding; the session's trust does not change | no finding; delivered as it is |
| A dense run | FW-HIDDEN-OUTPUT: the session is untrusted and the agent warned; nothing is removed (a dense run is not a kind a rewrite covers, and file reads and shell output are never rewritten) | each run replaced by `⟦hidden⟧` and the result delivered; the characters alone do not make the session untrusted (they do when `stripHidden` is off) |
| A dense run within 200 characters of a phrase addressed to an AI assistant, before or after it | the same as a dense run alone | withheld and quarantined (FW-MCP-WITHHELD); the session is untrusted |

The 200 characters count from the nearer end of the phrase, on either side of
the run, and every place such a phrase appears counts, not only the first: a
copy far from the run does not hide the one beside it. Looking for each further
place reads its line again, and that is charged to the scan's work budget; a
text with a dense run and more than 1,000 such phrases, or one the budget
cannot pay for, counts as near without the rest being looked at. The email
guard applies the same test (`dense_zero_width_instruction`).

The hooks and the library count over the whole result (every string in it);
the gateway counts each text on its own. One character on its own is ordinary
text, and it is not a way in: spelling a sentence in invisible characters takes
dozens at the very least, far past the count. The gateway's phrase check counts
only the zero-width set (U+200B to U+200D, U+2060 to U+2064, U+FEFF, U+180E),
where the hooks count every invisible character the module knows, and the two
differ on a few ordinary uses: a zero-width space between Thai letters, or a
zero-width non-joiner next to a space, is ordinary to the hooks and counted by
the gateway's phrase check ([limitations.md](limitations.md)). What the agent
*sends* is judged more strictly: one invisible character inside a command, a
path or an address is already a finding (FW-HIDDEN-TEXT), since those have no
ordinary use for one.

## The shell parser

String-matching a command is how hook tools get bypassed. The parser
(`src/engine/shell/parse.ts`) instead recovers structure: quoting (single,
double, ANSI-C `$'...'`), command and process substitution, subshells and
groups, pipelines, redirections, here-documents, and background/sequence
operators. The analyzer (`analyze.ts`) then walks that structure:

- It resolves wrappers (`sudo`, `env`, `timeout`, `xargs`, `nohup`, …) and
  nested shells (`bash -c`, `eval`, `find -exec`) to the real program.
- It models ~150 programs (coreutils, git, package managers, cloud CLIs, db
  clients, interpreters, network tools) for what they read, write, send and run.
- It substitutes variables bound literally in the same command (`for f in *.ts`,
  `X=dist`) so ordinary loops are not flagged.
- It tracks the working directory across `cd`, `pushd`/`popd`, subshells,
  brace groups and the common directory flags (`git -C`, `make -C`, `npm
  --prefix`, `pnpm -C`, `yarn --cwd`, `cargo --manifest-path`, `env -C`, `sudo
  -D`, `docker build <context>`), so `cd ../ops && cat > notes.md` is judged as
  writing `../ops/notes.md` and `cd packages/web && npm test` checks that
  package's `package.json`. A `cd` inside `( … )`, a pipeline stage or a
  background job ends with it; one inside `{ …; }` persists. After a `cd` joined
  by `;` or `||` (it may have failed) the rest is judged under both directories
  and the worse reading wins. When the target cannot be known (`cd "$DIR"`),
  relative writes are unresolvable (a person decides) and relative reads are
  judged by their names (`.env` is still a secret), tainting only a session
  that is already untrusted.
- Inline interpreter code (`python -c`, `node -e`, `ruby -e`, `perl -e`, `php
  -r`, `deno`/`bun eval`, a here-document fed to an interpreter) is judged per
  language (`inline.ts`): code that cannot write, delete, run other programs,
  load third-party modules, reach the network or reflect (`getattr`,
  `Function(`, `send`, decoding) is a reader of the paths it names, so
  `python3 -c "print(json.load(open('~/.claude/settings.json')))"` is a read.
  Code that can do any of those gets the strict treatment: every quoted path is
  probed as a read and as a write. Interpreters without a model (`osascript`,
  `lua`, …) are always the latter.
- Anything it knows it cannot resolve — a computed command name, an
  unparseable fragment, a variable write target — produces a finding that
  sends the action to a person. **Unresolvable is treated as risky.** The
  analysis is static and not complete: the constructs listed in
  [limitations.md](limitations.md#shell-constructs-not-yet-analysed) are not
  recognised as unresolved, and a command that hides what it does inside one
  of them can run without a prompt, even after outside content.

A glob in a write target (`rm *`, `cp x ./*`) is expanded against the set of
sensitive base names, so `rm -rf *` at the workspace root is seen to touch
`CLAUDE.md` and `.claude/`.

A glob in a read target is also compared with the credential stores' places,
one path segment at a time, so `cat /etc/ssh/ssh_host_*`,
`cat /etc/ss*/ssh_host_rsa_key` and `cat ~/.git-cred*` read a credential
store. A `**` segment counts as any number of directories, as in zsh and in
bash with `globstar`. A listing (`ls`, `stat`, `find` without `-exec`) shows only
the names, so it is not a read of the store. A recursive read (`grep -r`,
`rg`, `tar`, `cp -r`, `rsync`, a container volume) of a directory that holds a
credential store asks as a credential read. Such a directory is the home
directory or one above it, `~/.config`, `~/Library`, `~/.local/share`, a store
directory itself, or any directory above a store outside the home (`/etc/ssh`
and `/etc`, `/run` and `/var/run`, `/proc`). The directory is checked under
every name that reaches it, so a symlink to `/etc/ssh` is swept as `/etc/ssh`.

## Trust state

A session's state is a fold over an append-only event log
(`~/.launchsafe-firewall/sessions/<id>.jsonl`). It is only ever built by
replaying events; there is no in-place mutation and taint is sticky. A corrupt
or unreadable line becomes a `corrupt` event that makes the session **untrusted
and sensitive** — degradation is always toward stricter.

`PostToolUse` is where taint is actually recorded (the tool has run and its
output is in hand): the result's text is scanned for secrets, which are stored
as **fingerprints** (a length + two rolling hashes + a SHA-256 prefix — never
the secret itself) so a later outbound payload can be checked for them, even
re-encoded.

### State events

A session is an append-only list of events, folded into its state. Every event
read from disk is validated field by field; a malformed one becomes `corrupt`,
which makes the session untrusted and sensitive. Signed events count only when
their Ed25519 signature verifies against the approver key pinned in the hook
command (or on disk when none is pinned); an unverifiable one is `corrupt`.

| Event | Meaning | Signed |
|---|---|---|
| `taint { source }` | the session read outside content | no |
| `sensitive { source }` | the session read private data | no |
| `fingerprint { hash }` | a secret the session saw (hash only) | no |
| `user_destinations { destinations }` | hosts and repositories the person named in a prompt | no |
| `downloaded { path }`, `tainted_write { path }`, `secret_path { path }` | files with outside content, written after taint, holding copied credentials | no |
| `credential_read { source }` | the session read a credential (a credential store, a secret file, a CLI's stored token): later sends need a person | no |
| `approval { actionHash, id, sig, nonce, exp, rules, cwd, projectDir }`, `approval_used { actionHash, id }` | a person allowed one exact action once; `nonce`, `exp`, `rules`, `cwd` and `projectDir` are signed with the rest, and a line without them is a version 1 line that is no longer honoured | yes |
| `phone_approval { actionHash, id, credentialId, m, authData, clientData, sig, exp }` | a passkey assertion from a paired phone, counted only after it is re-verified against the pinned phones (`docs/phone.md`) | yes (passkey) |
| `corrupt { detail }` | an unreadable or unverifiable line | – |
| `scope { scope }` | the task scope from the person's prompt: `{ prompt (sha256), at, paths, repos, hosts, intents, narrowed }`, each field validated (absolute paths, `github:owner/repo`, known intents, `narrowed` consistent with them) | no |
| `scope_widen { kind, value, id, sig }` | a person widened the scope; `kind` is path, repo, host or intent and `value` must be in the normalized form `scope widen` writes; signed over (session, "scope-widen", kind, value, id) | yes |
| `budget_raise { key, amount, id, sig }` | a person raised a budget (counted as allowance, see "Budgets"), or a session spending limit (`key` `cap:session:<metric>`, written by `caps raise`, see "Spending limits") | yes |
| `canary_tripped { id }`, `canary_seen { id }` | a decoy was read, written or deleted / its value seen in a tool result | no |
| `agent_scan { rules, incomplete }` | the agent-configuration scan at session start | no |
| `linked { parent }` | this session is a subagent of another | no |
| `outside_command { hash, source }` | outside content showed a command (`c:`) or named a package to install (`p:`): 32 hex characters of a SHA-256 of its canonical form, and the source; FW-OUTSIDE-COMMAND compares later commands with them | no |

`agent_scan` is written by the session-start scan (below): its presence is
the "this session was scanned" marker. `canary_tripped` and `canary_seen` are
written by the decoy files (below); their ids must match `[a-z0-9]{1,32}`.
`scope` and `scope_widen` are written by the task scope (below).

## Task scope

`UserPromptSubmit` hashes the prompt and derives a `TaskScope`
(`src/engine/scope.ts`, pure; existence checks are injected and capped at 50 per
prompt): the workspace paths it names, the repositories and hosts, the
publish-type verbs used as requests, and `narrowed` (paths or verbs found). A
continuation keeps the previous scope, a follow-up merges, anything else
replaces it; a `Task` tool's prompt never reaches this hook, so subagents (same
session) inherit the person's scope. If deriving fails nothing is recorded and
the previous scope (or none: today's rules) stays.

In `decide()`, `scopeHits()` produces FW-SCOPE hits from the effects, the state
(scope, signed widenings, taint) and whether anyone is there. The hits are added
to the verdict only when `taskScope.mode` is `"enforce"`. In every mode that
computes them, `decide()` also returns `Decision.scope = { mode, applied,
verdict, baseVerdict, changes, reasons, widen }`: the verdict with and without
the scope, computed by the same ranking and approval rule as the decision. The
hook logs it with the decision, and a held FW-SCOPE item records the widenings
`queue approve` may offer. In `"log"` mode (the default) the hit list, the
verdict, the reasons and the recorded state events are exactly those of `"off"`;
`test/scope-log-equivalence.test.ts` checks this over the friction corpus, the
friction gate's catalogue rows, the replayed incidents and the INC catalogue
rows, under a prompt that narrows the scope.

## Provenance

Taint lives in one session's event log, so on its own it has two blind spots:
content the agent wrote itself outside the workspace taints the next read of
it (friction), and a file an untrusted session wrote starts clean in the next
session (a gap). The provenance ledger (`src/runtime/ledger.ts`, files under
`~/.launchsafe-firewall/ledger/`) closes both.

- **Recording (PostToolUse).** For `Write`, `Edit`, `MultiEdit`,
  `NotebookEdit` and `Bash`, the action's write effects are re-derived and each
  file target that exists afterwards is hashed (SHA-256, at most
  `provenance.maxHashBytes`, default 4 MB; larger files get no entry). An entry
  is `{path, sha256, size, writtenAt, session, taintedAtWrite, via}`;
  directories a command created (`mkdir`) get a directory entry. Downloads
  (`curl … > f`, `wget -O`, `git clone`) are recorded with
  `taintedAtWrite: true`, `via: "download"`. Nothing is recorded for a denied
  or queued action, or a tool that failed (no file).
- **When content counts as untrusted at write.** The session was untrusted
  before the action; or the same action read outside content (`cp ~/Downloads/x
  f`); or a write target was only known at run time; or the write was partial
  and kept content that was not the agent's own. Only the `Write` tool replaces
  a whole file. For every other writer outside the workspace (`Edit`, `>>`,
  `touch`, `sed -i`, `cp` over an existing file), PreToolUse notes what was
  there (`prior.jsonl`: absent, the agent's own trusted content, an untrusted
  session's, or anything else) and PostToolUse records the result as trusted
  only when that was absent or the agent's own. Inside the workspace a partial
  write inherits the previous entry's taint.
- **Using it (PreToolUse, engine stays pure).** `Context.provenance(abs)` and
  `Context.dirProvenance(abs)` are injected by the runtime. They are only
  called for reads the engine would otherwise taint (outside the workspace, not
  a trusted root), for listings of such directories, and for executions and
  task/build manifests, so ordinary workspace reads do no ledger I/O.
  - outside read, current content matches a trusted session's entry →
    `read_local_workspace` tagged `self-authored` (no taint);
  - matches an untrusted session's entry → `read_external` "a file an untrusted
    session wrote";
  - an entry exists but the hash differs → `read_external` "a file the agent
    wrote earlier but something else changed since";
  - listing a directory a trusted session created → names only, no taint;
  - running a file, or a runner whose manifest is a file, whose current content
    an untrusted session wrote (any session) → `execute_untrusted`
    (FW-UNTRUSTED-CODE / FW-TAINTED-MANIFEST). Once the hash no longer matches,
    the person (or another tool) wrote it last and it is ordinary workspace
    code again.
  - `secret_path`, downloads in this session and third-party paths keep
    precedence over a ledger entry.
- **Storage.** `files.jsonl` and `dirs.jsonl` are append-only; the latest entry
  for a path by `writtenAt` wins. Every append and every read happens under
  `ledger/ledger.lock`, so a reader never sees a half-written line. At
  `SessionStart` (startup) the ledger is compacted when it is over 5 MB (or
  over 10 MB during a long session, on a write): the latest entry per path,
  younger than 90 days, for files that still exist, at most 100,000 paths;
  `index.json` holds the compacted map and the byte offsets it covers, and only
  the tail after them is replayed.
- **Failure.** An unreadable, malformed or truncated ledger makes every lookup
  return null: classification is as if there were no ledger (outside reads
  taint, nothing is carried between sessions), and `doctor` warns. The next
  `SessionStart` repairs it by keeping only readable entries that an untrusted
  session wrote (stricter than before, never looser). Hash I/O errors and files
  over the size limit also return null. The ledger is inside the data
  directory, so the agent writing it is FW-TAMPER.
- **Policy.** `provenance.trustSelfAuthored` (default on; a project may only
  turn it off), `provenance.carryUntrustedWrites` (default on; a project may only turn it on), `provenance.maxHashBytes` (a project may
  only lower it).
- **Routes.** The hook records in PostToolUse and looks up in PreToolUse, as
  above. The library does the same in `decide()` (the lookups, and the note
  before a partial write) and `recordResult()` (the entry), when the guard's
  store has a `ledger` and the guard has file access. `fileStore` has the
  hook's own ledger in the same firewall home, so the local API, which builds on
  it, and the hook share one ledger. The memory store has none, by design:
  nothing in it outlives the process, so a guard on it carries nothing from
  one session to the next. A result the host never reports is not recorded
  ([library](library.md#the-provenance-ledger)).

## Decoy files (canaries)

`canary plant` (person-run, so denied inside an agent like every `changesState`
command) writes decoys and `firewallHome/canaries.json`, the registry:
`{id, path (realpath), kind, token, fingerprint, plantedAt, workspace?}` plus
what `remove` needs to undo the plant (the exclude line, directories created).
The hook loads it into `ctx.canaries` (`paths`, `fingerprints`), and the engine
stays pure.

- **Read tripwire** (`effects.ts`, `readOne`): a read whose path or realpath is a
  decoy adds a `canary_read` finding and a `read_secret` effect tagged
  `canary:<id>` that taints and marks sensitive. Rule `FW-CANARY-READ` is an
  **allow**; its state events are `taint`, `sensitive` and `canary_tripped`.
  `decide()` records them (`tripwireEvents`) whatever the verdict, so a
  decoy touched by an action that another rule holds, queues or denies (a home
  decoy is also a credential-store read; `cat .env.backup | curl` is
  FW-SECRET-FLOW) still trips; the hook appends them for every verdict, writes
  a `canary` log entry and raises the `canary` desktop notification (fixed text; tests can also observe the alert through
  `HookEnv.notify`). A write
  or delete of a decoy trips the same way. Only direct reads trip; a recursive
  read does so only with `canaries.tripOnRecursive`.
- **Seen in output** (`post.ts`): a result carrying a decoy value records
  `canary_seen`, taint, sensitive and the fingerprint.
- **Egress** (`dataRules`): a payload carrying a decoy value (in the clear, base64,
  hex, URL-encoded, ... via `containsFingerprint`) is `FW-CANARY-EGRESS`, a deny
  that ignores `dataAllowHosts` and `sendAllowHosts` and applies in sessions that
  never read the decoy. The attempt also records `canary_seen`, taint and
  sensitive (the agent holds the value) and raises the alert; the block
  notifies `denied_dlp`, as FW-DLP-* and FW-SECRET-FLOW blocks do.
- **After a trip**, every `egress_send` in the session also gets `FW-CANARY-READ`
  as an `approve` hit, so it needs a person even to an allowlisted host; so do
  the arguments of a search or an MCP call. Those asks are approvable
  once (`explain` says so).
- A registry that cannot be read, or whose fingerprint does not match its value,
  is ignored (no decoys apply) and `doctor` fails with "canary registry damaged".

State events `canary_tripped { id }` and `canary_seen { id }` are unsigned.

## Always-on data-loss prevention

Independent of trust state, an outbound payload is denied if it carries:

- a credential shape going anywhere other than the service that issued it;
- a secret the session has already read (by fingerprint, in base64/hex/URL
  encoding or split across DNS labels);
- a checksum-valid card number (not digits that sit inside a long token of hex
  data), IBAN, or national-ID format,

unless the destination is explicitly allowlisted for that data kind in the
policy. These cannot be approved from inside the agent.

## Runtime: durability and concurrency

Several Claude Code sessions and subagents can run hooks at once. So:

- Every queue/log write and every read-then-write of state happens under a
  per-resource **lock file**, with a stale-lock break for crashed holders.
  Plain appends to a session file take no lock: a session file is only ever
  appended to, and each append is one `write` to an `O_APPEND` descriptor, which
  the kernel places at the end atomically with respect to other appenders, so
  concurrent appends never interleave or overwrite each other. The lock still
  serializes what needs it (using a held approval once, the budget counters),
  and a plain append changes neither what those read nor what they decide.
- Files are replaced **atomically** (write a temp file, `fsync`, `rename`); the
  log and session files are append-with-`fsync`. The one exception is the
  log's `head.json`, below.
- A **session file is read in one pass, in time that grows with its size**
  however it is damaged. Each line is one event. A line that is not a JSON
  object, is not valid JSON, or is not an event the firewall knows is a
  `corrupt` event, which makes the session untrusted and sensitive for good.
  The first ten damaged lines are listed (with their line numbers when the line
  could not be read) and the rest are counted in one last note ("N more damaged
  lines"), so a file of hundreds of thousands of damaged lines costs no event
  and no thrown error apiece (a 4 MB file took the readers seconds). Every line
  is still read: a valid event after the damage (a fingerprint, a downloaded
  path, a used approval) still counts. The lists the fold keeps whole, a
  session's linked parents and the agent scan's rule ids, are indexed by a set,
  so tens of thousands of distinct values are not searched from the start for
  each one; nothing is dropped from them, since a subagent hands its taint back
  to every parent in the list. With the approval key, each signed line
  (approval, scope widening, budget raise) is checked against a key made once
  per key, not once per line.
- The **decision log** is JSON-lines, each entry chained to the previous by
  SHA-256 and signed with a local Ed25519 key. `log verify` checks every link,
  hash, signature and sequence number, and the recorded (signed) head, so any
  edit, deletion or reordering by someone who cannot write the firewall's
  directory is detected, including a log file deleted or emptied while its head
  remains: the head is compared even when no entries remain (the signing key
  lives in that directory, so a writer there can rewrite the log, and deleting
  the log and its head together leaves nothing to detect; see
  [limitations.md](limitations.md)). A damaged
  key, anchor, head or line is reported, never a crash (signatures are read only
  from canonical base64, so junk inserted into one does not still verify).
  Rotation carries the chain across files and keeps a signed anchor when old
  files are pruned, bounding disk use.
- **Crash guarantees of the log, and why one `fsync` per decision is enough.**
  A hook call writes its decision with one `fsync` (the log entry; plus one for
  the session file when the call adds session events) before it returns, so
  before the tool runs. `head.json` (the last sequence number and hash) is then
  replaced without an `fsync`: the lock file is given the new head and renamed
  over it, which releases the lock in the same step. The argument:
  1. *Every decision whose hook returned is on disk, unless the write itself
     failed.* Its entry was fsynced first; nothing written afterwards can undo
     that. An I/O failure (a full disk, a write error) is the exception: the
     decision stands without an entry and the error is reported (item 9).
  2. *The chain never forks.* The head is a cache of the log's last entry. Under
     the lock, the next append reads the log's last complete entry (checked
     against its own hash) as well as the head, and chains from whichever is
     further on. After a power cut the head can be behind the log (its update
     had not reached the disk) or, on a file system that does not order data
     before a rename, empty; the chain then continues from the last entry on
     disk, the head is rewritten, and a `log_head_recovered` entry records that
     it happened. (Before this, a crash between the two writes left a head one
     behind, and the next append forked the chain.) Just after a rotation the
     last entry is read from the newest archive, and so it is when the new
     `decisions.jsonl` holds no complete entry yet (a crash cut its first
     write): recovery continues from the last complete entry across
     files instead of from a head the same power cut left behind.
  3. *A removed tail is still caught.* Entries are fsynced before the head is
     written, so a crash can only leave the head behind the log, never ahead. A
     head ahead of the log, or naming an entry that is not in it, is what
     removing entries from the end looks like, and `log verify` reports it as
     before. It now accepts a head that is behind and names an entry of the
     chain; a missing or unreadable head is still reported (until the next
     append rebuilds it).
  4. *The head is signed, and that survives the lock-file rename.* The content
     the lock file is given before it is renamed over `head.json` is the
     sequence number, the hash and an Ed25519 signature over
     `head:<seq>:<hash>`, so a head rewritten to match a shortened log fails on
     its signature, and a deleted or emptied `decisions.jsonl` fails because its
     head still records entries. What accepting a head that is behind gives up:
     someone who can write the firewall's directory, and kept an older signed
     `head.json`, can cut the log back to that entry and put the old head back.
     The signature proves the head was written by the firewall, not that it is
     the newest one; the cut is visible in an off-machine copy of the log, and
     nothing in the firewall's directory can prove recency against its own
     owner (docs/limitations.md).
     Stripping the signature (a downgrade to the unsigned head of pre-release
     builds) is caught too: every entry this release writes carries
     `"heads": "signed"`, and its
     signature then covers `entry:<hash>:heads-signed` instead of the hash
     bytes, so the flag cannot be removed without breaking the entry. When
     pruning drops a file whose last entry has the flag, the anchor carries it
     the same way (`anchor:<seq>:<hash>:heads-signed`). Once the walk has seen
     a flagged entry or anchor, an unsigned head fails `log verify`, whatever
     entry it names. A log written only by a pre-release build (no flag
     anywhere) still verifies with its unsigned head until its first append by
     this release. One corner: a power cut that loses every head written since
     the upgrade leaves the old unsigned head, which is then reported until the
     next append rewrites it, as a missing head is.
  5. *A cut-off line stays visible and harmless.* If a crash cuts an entry off
     mid-write (its hook never returned), the next append starts on a new line
     instead of continuing the fragment, so the following entry is intact and
     `log verify` reports only the fragment.
  6. *The last entry is always found, or nothing is appended.* The end of the
     log is read backwards in growing windows (64 KiB, doubling) until a
     complete line parses as an entry, so a long last entry does not hide it;
     lines that are not entries are passed over (`log verify` reports them).
     The search stops at 1 MiB, four times the largest event `appendLog`
     accepts (256 KiB as JSON; a larger one is refused before anything is
     written). Past that bound the append fails closed: nothing is written,
     the chain is not continued from a head that may be old, and `log verify`
     says new entries are refused until the end of the file is repaired.
  7. *A new file's name is durable.* Creating `decisions.jsonl` (the first
     entry, or the first after a rotation) and the rotation rename each fsync
     the log directory, so an fsynced entry cannot disappear with its file's
     name. That is one more `fsync` once per new file, not per decision.
  8. *What is hashed is what is written.* The event is reduced to its
     canonical JSON (sorted keys; `toJSON` is never called; a value JSON
     cannot hold is dropped or written as `null` the same way every time)
     before anything else, and that one form is measured against the 256 KiB
     cap, hashed and written, so every entry re-verifies from its line. An
     event that cannot be serialized at all (a BigInt, a cycle) is refused
     before anything is written.
  9. *Every decision has an entry, except on an I/O failure.* The firewall's own events (the
     hook's and the gateway's decisions, pins, canaries, vault use) are bounded
     before they are appended (`src/runtime/logbound.ts`): a string longer
     than 1,024 characters keeps its start, and the field's path, the SHA-256
     of the whole value and its length go into `bounded`; arrays and objects
     keep 64 items or keys, long keys are shortened with a hash suffix, and
     nesting deeper than six levels is replaced by its hash. A tool name, a
     server name, a path or a description chosen by an agent or an MCP server
     therefore cannot push an entry over the cap. If the log still refuses
     (still too large, or the last entry cannot be found), a fallback entry is
     written instead: the event's type, `fallback: true`, the session,
     verdict, rule ids, action hash and why the full entry was refused. If
     the log refuses that too, the hook turns an allow into ask (a person is
     there and the agent can ask) or deny (FW-LOG-UNRECORDED), an action
     that is already ask carries FW-LOG-UNRECORDED and its reason (so the
     person approving it knows it has no record), the gateway
     refuses a call approved in the client instead of forwarding it (and a
     server's input request, answering the server with an error), `run`'s
     proxy refuses a host's first connection whose `run_net` entry was
     refused, and an
     internal error no longer lets a read-only tool through when its cause is
     an unrecorded decision. The library (`src/sdk/guard.ts`) follows the
     same rule with any store: the bounding and the fallback entry live in
     the browser-safe `src/engine/log-bound.ts` (`src/runtime/logbound.ts`
     binds them to the log file, and the file store appends through it); an
     unrecorded allow becomes ask or deny, an unrecorded ask carries
     FW-LOG-UNRECORDED and its yes counts only if the approval entry is
     recorded, and every log failure is reported (`problems`,
     `onLogError`). An I/O failure (a full disk) is not a refusal
     and keeps its earlier behaviour: the decision stands and the error goes
     to stderr (docs/limitations.md).
  On macOS Node's `fsync` is `F_FULLFSYNC` (it also flushes the drive's cache),
  which is why each one costs milliseconds; this went from three per decision
  (entry, head, directory) to one, and from four lock and rename operations to
  two.
- Corrupt state, policy or log files are detected and surfaced by `doctor`;
  they are never silently treated as "allow". On any internal error the hook
  fails closed for risky tools and open for read-only ones.

### Hook start-up

The agent starts a new hook process for every tool call, so start-up is part
of every call's latency (`npm run bench`, end-to-end section).

- The build writes the hook's module graph as one file, `dist/hook/bundle.js`
  (`scripts/bundle-hook.mjs`, with the rolldown already in `node_modules`), and
  the `hook` command loads it instead of about 150 separate modules: one
  resolve, read and compile instead of 150. It is the same code; each module's
  `import.meta.url` is rewritten to that module's own file, so the paths the
  hook locates from it (its install directory, the CLI) are unchanged. The
  bundle is used only when it is at least as new as `dist/hook/claude.js`, so a
  `tsc` run without the bundle step never leaves an old hook in use; without a
  bundle the modules load as before. A bundle that fails to load fails the hook
  closed, like any other error.
- V8's compile cache is kept in `<firewall home>/cache/compile`, and only once
  the firewall's directory exists (the cache must not create it with looser
  permissions first). Not Node's default location, the temporary directory: the
  agent can write there, and a forged cache entry would be code run inside the
  hook. The firewall's directory is one the agent may not write. If the cache
  cannot be used (for example inside `gemini -s`, where that directory is
  read-only), the hook starts without it. Before it is used, the firewall
  home, `cache` and `cache/compile` are each checked with `lstat`: a real
  directory, not a symlink, owned by the current user, not writable by group
  or others (a missing `cache` or `cache/compile` is created mode 700). Under a
  test marker it is never enabled for a home that resolves inside the real
  home directory (from the user database, not `HOME`). Node enables a cache
  named by `NODE_COMPILE_CACHE` at start-up, before any firewall code runs, and
  a later `enableCompileCache` call cannot move it; so the installed hook
  command sets `NODE_COMPILE_CACHE=` (empty, which node ignores), and `doctor`
  fails a hook command without it until `install` is run again. The gateway's
  stdio wrapper runs the same code under node with the MCP client's
  environment and the entry's `env`, so every wrapped stdio entry sets
  `NODE_COMPILE_CACHE` empty in its `env` too; a value the entry set is passed
  to the upstream server only (docs/gateway.md), and `doctor` fails a
  wrapped entry without it until `mcp wrap-config` is run again.

## Learned project choices ("Fewer prompts")

`src/engine/learn.ts` gives every rule a risk class; only `low` is learnable
(`FW-UNKNOWN-TOOL` today), and a rule missing from the table counts as
`unverifiable`. `decide()` takes an optional `learned` view built by the hook from
`<home>/learned/allows.json` and `nevers.json` for the event's project
directory: "never" entries keyed by the action key, "always" entries keyed by
the action key and the tool's identity (an MCP tool's current pin hash from
`mcpToolIdentity()`, else `agent:<id>`; null, and so no "always", without a
current reviewed pin, for the gateway, or when the project came only from the
working directory), and the current call's identity. A "never" entry adds `FW-LEARNED-DENY` (deny) in any session. An
"always" entry turns an `approve` outcome into `allow` (`FW-LEARNED-ALLOW`)
only if, at that moment, the context is interactive (attended), every rule that fired is learnable, every effect is
`read_local_workspace`, `write_workspace`, `execute` or `unknown` (nothing
private, no download), there is no finding, the session is neither tainted
nor sensitive (nor holding fingerprints or secret paths, nor touched by a
decoy), and the policy parsed. The view only holds "always" entries whose
Ed25519 signature (approval key, over a JSON array of kind, id, project, key, identity, tool and an ISO time)
verifies against the key the hook trusts, and whose stored rules are still all
learnable. The key is SHA-256 over the tool and the canonical JSON of its input
(a Bash `description` aside).

The hook counts asks per project and key in `<home>/learned/candidates.json`
(and the queue item carries the code): a prompt is answered yes when the asked
tool's PostToolUse arrives in that session within two hours (`ask_approved`
in the log); a queue approval counts when the approved retry runs
(`FW-APPROVED`). Decision entries for asked, held and learned actions carry
`learn` (the code) and `learnable`. `launchsafe-firewall friction` reads these.
`allow add` (terminal, passphrase, signed), `allow never`, `allow remove`
(passphrase for a "never") and `queue review`'s `[p]`/`[n]` are the only
writers of `allows.json`, and each writes a `learned_choice` log entry.

## Self-protection and the approval channel

Two layers:

1. **The classifier** denies any action it can see that changes the firewall,
   identified by what is installed (`src/runtime/identity.ts`). The
   identity is built from the registered hook commands (install record plus
   managed settings that carry the marker): word 1 is the node binary, word 2
   the CLI file; the CLI's package root (nearest `package.json` named
   `@launchsafe/agent-firewall`) gives the runtime roots `dist/` and
   `node_modules/` and the file `package.json`; data roots are the firewall
   home, `~/.launchsafe-firewall`, any `LAUNCHSAFE_FIREWALL_HOME` in a hook
   command and the managed policy directories. It is cached in
   `<firewallHome>/identity.json`, keyed by the registered settings files' size,
   mtime and inode (about 0.02 ms to load; under 0.2 ms to rebuild). Without a
   hook command it falls back to the install directory narrowed to `dist/`,
   `node_modules/` and `package.json`, and `doctor` warns.
   - A path is the firewall's when it is under a data or runtime root, or is
     a runtime file, CLI file or node binary (as written or after symlinks). A
     source checkout's `src/`, `docs/`, `test/` and `.git/` are ordinary files.
   - The CLI runs when argv0 is its command name (always, so an unresolvable
     bare name fails closed) or a path whose realpath is its CLI file; when an
     interpreter (`node`, `bun`, `deno`, `tsx`, `ts-node`) runs a runtime file;
     or when a package runner (`npx`, `bunx`, `pnpm dlx`, `yarn dlx`,
     `npm exec`) runs `@launchsafe/agent-firewall` (the registry name is the
     identity of the code). Wrappers (`sudo`, `env`, `nohup`, `timeout`,
     `xargs`, `unbuffer`, `script`, `expect`, `bash -c`, inline code) are
     unwrapped first. Only read-only subcommands are allowed.
   - Any other program handed a path is judged by its own model as a read or a
     write of it: copying the runtime out is a read, copying over it is a write
     (tamper), a symlink over or to a runtime file is tamper, and copying or
     archiving the data directory is tamper because it carries the keys.
   - `kill`/`pkill`/`killall` are tamper only when they name the CLI file, its
     command name or `LAUNCHSAFE_FIREWALL_HOOK`, in any letter case (`pkill -i`
     matches a process whatever the case of the name it is given).
   - When the hook runs from a package root the agent can work in (a dev
     install from a checkout), a build runner (`npm`, `pnpm`, `yarn`, `bun`,
     `make`, `tsc`, `turbo`, …) with its working directory inside that root
     rewrites the runtime and is tamper. A packed install in its own prefix
     makes building the checkout ordinary work.
   - **Aliases.** A protected location is matched by what it is,
     not by the name that reaches it (`src/engine/canonical.ts`). Every
     comparison against the installed runtime, the firewall home, the agents'
     config directories and the project's protected files looks at the path
     as written and at its canonical form: the realpath of its longest
     existing prefix plus the remaining components (a dangling symlink on the
     way is followed to where it points). Names are compared ignoring case on
     every platform, because a Linux host cannot tell whether a directory folds
     case (WSL2's `/mnt/c`, an SMB or exFAT mount): the lists of protected
     files, persistence points, secrets, credential stores, the firewall's own
     directory and the agents' settings files use `PROTECTION_FOLDS_CASE`
     (`src/engine/canonical.ts`), while what grants trust (the workspace, the
     scratch directory, whether a read or listing outside the workspace is the
     agent's own settings or the firewall's files rather than outside content,
     `classifyAsSpelled` in `src/engine/paths.ts`, and whether a program is the
     installed CLI, whose read-only commands run unjudged) keeps the
     platform's rule, since folding there would widen. The locations
     themselves (identity roots and files, data roots, the literal prefix of
     every `~/` and absolute pattern) are compared in
     both forms too, so `/tmp` and `/private/tmp`, a user's own link to `~/.claude`
     or to the install, and an install recorded through a link all match. The
     working directory is tracked through `cd`/`pushd`/`popd` (logical, as the
     shell does) and through the programs' own directory options (`npm
     --prefix`/`-C`, `pnpm -C`/`--dir`, `yarn --cwd`, `bun --cwd`, `make -C`,
     `git -C`, `env -C`, `cargo -C`/`--manifest-path`), which the program
     resolves physically (`link/..` is the parent of where `link` points). A
     link `ln` makes earlier in the same command line is applied before it
     exists on disk. A
     path that cannot be resolved (a symlink loop, a directory the user may
     not search) is possibly protected: a write there is judged as a write to
     a protected file, and a build there is held. A decision's `rules` list is
     collapsed (identical entries once, at most three per rule with a count of
     the rest, sixteen in all); its effects keep every target.
2. **The approval key** does not depend on the classifier. `approver init` (in
   the person's own terminal) scrypt-derives a key (N = 2^17; files written
   with the older 2^15 are re-encrypted the next time the passphrase unlocks
   them) from a passphrase of at least 14 characters and uses it
   to encrypt an Ed25519 approver key. `queue approve`/`review` unlock it and
   sign the session, action hash, item id, a single-use nonce, an expiry, the
   rule ids shown and the agent's directory and project (approval message v2).
   The engine uses an approval only while every rule asking now is one of those
   shown and, in the hook and the gateway, in the same directory and project
   (`approvalRefusal` in `src/engine/state.ts`, called from `decide()` and from
   the hook's native-call decision); otherwise the action asks again and the
   approval stays unused. `install` pins the approver public key
   in the hook command in Claude Code's settings (a protected file; under
   managed settings, root-owned). The hook folds an approval into session state
   only if its signature verifies against the pinned key; an unsigned or
   forged approval becomes a `corrupt` event, so the session turns untrusted.
   The CLI also requires a real TTY and refuses to run as a descendant of a
   Claude Code process (an agent can fake a TTY with `script`, not its
   ancestry).

## MCP server provenance

Claude Code 2.1.289 sends `mcp_server: { name, source }` on `PreToolUse`
(verified against a live event; `source` is `project` for a server from the
repository's `.mcp.json`, `dynamic` for `--mcp-config`, and `user`/`local`/
`plugin`/`managed` otherwise). A server whose source is `project`, `dynamic` or
`unknown` is untrusted whatever its name, unless the user's own policy lists it
by exact name. A server in the outsider-writable class (above) is untrusted
whatever its source and its entry, unless the user's or the administrator's
policy exempts it. If a version omits the field, the hook derives the source from
the same files Claude Code reads (local and user entries in `~/.claude.json`,
the project's `.mcp.json`, `managed-mcp.json`).

## What the agent is armed with

At `SessionStart` (once per session; a resumed or compacted session keeps its
result) the hook reads the files that program the agent and runs LaunchSafe's
**agent-safety** rules on them, from LaunchSafe's own agent-safety package,
vendored at a pinned commit in
`src/vendor/agent-safety/` (Apache-2.0, see NOTICE; `node
scripts/sync-agent-safety.mjs --check` verifies the copy).

The firewall's copy **diverges from upstream** (rule set `1.2.0-fw`): the
audit fixes below are made in the vendored files, each of which says so in a
`DIVERGES FROM UPSTREAM` comment under its header, and `toml.ts` is new. The
byte comparison against the product checkout reports them as drift until
upstream takes them; the browser extension's copy of `signals.ts` must be
re-synced from this one.

- **What is read** (`src/runtime/agentfiles.ts`): the workspace's agent files
  (agent-safety's checked paths: CLAUDE.md/AGENTS.md/GEMINI.md anywhere up to
  four levels deep and in every folder above the workspace up to the git root,
  `.claude/` settings, CLAUDE.md, skills, agents, commands, rules, output
  styles, hooks and memory, the same folders of nested packages, `.agents/skills`,
  `.mcp.json`, Cursor rules, hooks and environment, VS Code, Copilot
  instructions, prompts and agents, Codex config and hooks, Gemini settings,
  commands and `context.fileName` files, Windsurf rules and workflows, dev
  containers, root `package.json` and `.env` names, and every script a hook,
  helper or MCP server names), plus the memory files a `MEMORY.md` links
  to; the user's (`~/.claude/CLAUDE.md`, `settings.json`, `agents/`,
  `commands/`, `skills/`, `hooks/`, `rules/`, `output-styles/`, the `mcpServers` of `~/.claude.json`
  global and this project's entry, and this project's auto memory under
  `~/.claude/projects/<slug>/memory/`); and the administrator's
  `managed-settings.json` and `managed-mcp.json`. Bounded: 400 files, 512 KB
  each, 8 MB in all, 1,500 directories, 300 ms of collection (150 ms for the
  inline fallback). Files are decoded as the agents read them (UTF-16 with or
  without a byte order mark, otherwise UTF-8) and split at `\n`, `\r\n`, `\r`,
  U+2028 and U+2029. Every path component is resolved: a workspace file or
  folder whose real location is outside the workspace (a symlink anywhere on
  its path) is not read and taints; a symlinked folder inside the root is
  walked once through its real path; the user's own files may point anywhere
  in the home directory. A file over 512 KB, and an `.mcp.json` that does not
  parse, taint too (fail closed). These are the firewall's own reads, not
  agent actions.
- **Analysis bounds** (vendored `analyze.ts`, `signals.ts`): every pattern has
  bounded gaps, so a line costs linear time; a line over 4 KB is checked in
  overlapping 4 KB pieces and reported (`ls-agent-long-line`, medium); the
  whole analysis has a work budget, and running out reports
  `ls-agent-analysis-incomplete` (high, taints) naming the files left
  unchecked. An agent file that does not parse as JSON/JSONC or TOML is
  `ls-agent-unparsed-file` (high, taints); the JSONC reader is iterative (no
  depth limit) and accepts comments and trailing commas, and Codex's
  `config.toml` and Gemini's command files are read by a real TOML parser.
  An agent file over 512 KB of UTF-8 is `ls-agent-oversize-file` (high, taints).
- **What the rules look at, beyond upstream 1.1.1**: injection and remote
  instructions inside code blocks (low confidence) and in quotes (low
  confidence), judged on the line joined to the one before it; quoting and
  negation judged in a window around the match; Markdown comments
  (`[//]: # (...)`) and link titles; invisible characters including variation
  selectors, soft hyphens, Hangul fillers and the Braille blank; base64 judged
  per run; commands normalised (line continuations, `cu''rl`) with two-step
  download-and-run, more pipe forms and process substitution; senders `ssh`,
  `rsync`, `sftp`, `aws s3`, `git push`; absolute home credential paths; raw
  IPs in any spelling, while private ranges are not capture endpoints;
  instructed exfiltration only when the credential source and the send are one
  step; Claude Code `permissions.allow` wildcards, `defaultMode`,
  `additionalDirectories`, approved MCP servers, plugins and marketplaces,
  `sandbox.*`, `fileSuggestion`, environment variables that preload code and
  every hook type; Gemini trust, approval mode and hooks; Codex `notify`, each
  of `approval_policy = "never"` and `danger-full-access` alone, profiles,
  hooks; VS Code terminal auto-approve maps, `chat.mcp.*` and tasks a
  folder-open task depends on; Cursor hooks and environment; dev-container
  lifecycle commands; container flags that hand an MCP server the host;
  custom registries and indexes. Findings in files kept out of git by
  convention (`.claude/settings.local.json`, `CLAUDE.local.md`) are one
  severity step lower. `ScanOptions.allowedModelHosts` names model gateways
  the person runs (not yet a policy key).
- **Findings → state** (`src/runtime/agentscan.ts`): a critical finding, or a
  high-severity one with high confidence (`agentScan.taintOn`), becomes a
  `taint` with source `agent configuration: <rule> in <file>:<line>` (plus
  `sensitive` for a credential in configuration). Everything else is logged
  (`agent_scan` log entry) and shown by `doctor`. Findings in the
  administrator's files are reported, never tainting. The firewall does not
  second-guess the vendored rules: complete subdivision flag emoji sequences
  are not hidden text, and a cloud metadata address in instruction or memory
  prose is a finding only when the line makes the agent contact it (commands,
  tasks, MCP addresses and scripts always are) — both decided upstream in
  agent-safety rules 1.1.1.
- **Drift**: the scan keeps an agent-safety receipt per scope (workspace, user,
  project memory) at `scan/receipts/<sha256(workspace)>.json` and compares it
  with the last session's (`compareReceipts`). A hook, helper, folder-open
  task or MCP server added or changed since then taints (`changed since your
  last session: ...`); a removal is logged. Memory drift taints when the
  changed memory files carry a finding (an instruction to send data out, a
  standing override, hidden text); plain growth is logged, because the agent
  writes its own memory every day and memory writes are already held once a
  session is untrusted (FW-INSTRUCTIONS-HELD). The firewall's own hook entries
  are not drift: the install command's shape, in a settings file the
  install record or managed settings registers, naming an absolute node binary
  and CLI the installed identity lists and this data directory. The same
  command in any other file, or a relative `./dist/cli.js`, is drift. Receipts
  carry the SHA-256 of each hook's and server's whole command, so a change past
  the 200 characters shown is drift too. Any file under `.claude/hooks/` or a
  skills folder added, changed or removed taints; a new finding of medium
  severity or more in a changed file (under the same rules) taints; other
  changed files are logged. The first session in a
  workspace records the receipts and taints for nothing.
- **Cache**: each scope's analysis is cached by a hash of its files' content
  (never size and modification time alone, which a file can keep while its
  content changes; content-addressed, so the user's own files are analyzed
  once for every workspace). Receipts, the cache and the last-scan summary are
  written only when they change, without fsync (a receipt lost to a power cut
  reads as missing or unreadable, never as unchanged).
- **Failure**: an analyzer exception taints ("could not be checked"); an
  unreadable receipt taints once and is rewritten. Reaching the file or byte
  cap while collecting the workspace, or running out of time inside its agent
  trees (`.claude/hooks`, `agents`, `commands`, `skills`, ...), taints, because
  the repository controls how many files it holds and a file past the cap is
  unchecked; root instruction files and hooks are collected first. The
  directory cap and a time-out in the generic walk for nested instruction files
  are logged and shown by `doctor` only (ordinary large repositories). If the first
  tool call of a session arrives without a `SessionStart` scan (an older
  client, a hook added mid-session), it runs inline; if that runs out of time,
  the session is treated as untrusted.
- **Imports**: the `@path` references in `CLAUDE.md`, `CLAUDE.local.md`,
  `AGENTS.md` and `GEMINI.md` (outside code spans and fences), and in the files
  they import, up to five hops (`src/engine/imports.ts`), are collected (inside
  the workspace, or the home for user scope) and analyzed as instruction files
  under their real display path. Writes to them are `write_protected`.
- **Output**: `SessionStart` returns `hookSpecificOutput.additionalContext`
  (for the agent) and `systemMessage` (for the person) when the session starts
  untrusted. Tested with synthetic fixtures; the field names follow Claude
  Code's documentation and were not checked against a captured event.

## MCP pins

`~/.launchsafe-firewall/pins/mcp.json` (`src/runtime/pins.ts`) remembers each
MCP server as first seen or last reviewed, keyed `<source>:<name>`:

- **Configuration**: the SHA-256 of its canonical `{ type, command, args, url,
  envKeys, headerKeys }`, its working directory, a hash of each environment
  value whose name is not a credential's, and the content of a local entry
  script it runs (`node ./server.js`), and agent-safety's pin stability of its
  launch line (a custom `--registry` or `--index-url` makes it floating and an
  unverified source). Pins made before this hash are upgraded silently while
  the older hash still matches. Pinned at first use at `SessionStart`; a server
  the repository's own `.mcp.json` names, seen for the first time, taints that
  session once (FW-MCP-CHANGED) and is pinned. When the pins file is
  unreadable it is moved aside and every configured server waits for review
  (pending, tainting) until `pins accept`, never re-pinned as a first use. The comparison runs on every
  `SessionStart` source, including resume, clear and compact (only the
  agent-safety scan is once per session). A configured server whose hash
  differs taints every session that starts with it (FW-MCP-CHANGED) and its
  results count as outside content for every call, whatever the policy says,
  until a person runs `launchsafe-firewall pins accept <server>`. A change back
  to the pinned configuration clears it.
- **Tool names**: the tools a server has been seen to expose (tool calls, and
  definitions in ToolSearch results). A new tool within `newToolGraceHours` of
  a first-use pin is added silently (servers expose tools lazily). After that,
  because a hook never sees `tools/list`, a never-called name counts as new
  only when the server's tools could have changed: its launch is not
  pinned to an exact version, or its configuration changed. A tool whose
  definition was seen in a ToolSearch result, or one on an exact-version
  server with an unchanged configuration, is pinned silently and logged as
  `first_use`. A new tool is unknown until reviewed: the session is tainted
  before the call is decided, so the call itself is judged as untrusted,
  its results count as outside content, and the decision names FW-MCP-CHANGED.
- **Descriptions**: a hook cannot see `tools/list`, but Claude Code returns
  tool definitions (name, description, input schema) as the result of its
  `ToolSearch` tool, which `PostToolUse` sees (tested with synthetic
  fixtures; the live shape of a ToolSearch result was not captured). The
  firewall pins the SHA-256 of each tool's description and
  schema from those results only (a web page cannot plant pins). A changed
  description taints the session, alerts the person (`systemMessage`) and the
  agent (`additionalContext`), and stays pending; every session that starts
  with that server is tainted until it is accepted. A description seen for the
  first time is checked with agent-safety's hidden-text, injection and
  outbound-instruction detectors.
- `pins accept` is person-only (terminal, not under Claude Code, approval
  passphrase); run from an agent it is FW-TAMPER. An unreadable pins file is
  moved aside, taints once, and `doctor` reports it.
- Not built: `mcp pin --connect` (asking a server for `tools/list` directly). It would run third-party code and make network
  calls; the MCP gateway product is the intended home for continuous
  description pinning.

## Package vetting

`src/engine/packages.ts` (pure) records what each package-manager or runner
invocation asks for: the analyzer calls `notePackageCommand()` from
`packageManager()` and the runner branch, and the notes are kept per
classification in a `WeakMap` keyed by the collector. `evaluate()` then calls
`packageRules()`, which consults `ctx.packageIntel` (the snapshot, read lazily
by `src/runtime/intel.ts`: the manifest, then one bucket per looked-up name, or
the sorted name index for a lockfile) and `ctx.lockfiles`
(`src/runtime/lockfiles.ts`: JSON or line parsers, 20 MB cap), and
`typosquatOf()` (`src/engine/typosquat.ts`, shipped lists in `src/data/`).
Ordinary commands read nothing. Findings: `malicious_package`,
`malicious_package_maybe`, `lockfile_malicious`, `typosquat_name`, and the
logged-only `intel_unreadable` and `lockfile_unreadable`.

The snapshot lives under `firewallHome/intel/`: `manifest.json` names a
generation directory holding `<eco>/<xx>.json` buckets (by the first byte of
the name's SHA-256) and `<eco>/names.idx`. `update` builds a new generation
from OSV's per-ecosystem `all.zip` (a bounded, hand-written zip reader,
`src/runtime/zip.ts`, ZIP64 included) and switches by replacing the manifest
atomically; any failure leaves the previous snapshot. An unreadable bucket or
manifest gives "unknown" (no verdict, logged) and `doctor` fails.

## Sandbox

The firewall decides what an action may do; Claude Code's OS sandbox (Seatbelt
on macOS, bubblewrap on Linux) limits what a Bash command that runs anyway can
reach: writes to the workspace, network through a proxy that admits listed
hosts. Neither is enough alone. The sandbox is host-level (a `CONNECT` shows the
host, not the method or body), so the firewall's analyzer is what tells fetch
from send for the commands it can see (`git push`, `npm publish`, `curl -d`); the
sandbox is the backstop for what it cannot see into (a compiled binary, a script
that opens a socket), which closes the documented hook-bypass gap.

- `src/engine/sandbox.ts` (pure): the setting names (from the settings schema
  inside the Claude Code 2.1.289 binary, captured in
  `test/fixtures/claude-2.1.289-sandbox-schema.json`), `profileFromPolicy()`
  (the profile and the host labels: fetch-only, send, upload-capable) and
  `sandboxViolations()` (what a change introduces that weakens a recorded
  profile).
- `src/runtime/sandbox.ts`: `readSandbox()` merges the scopes Claude Code
  merges for the `sandbox` key (managed and its drop-ins > local > project >
  user; scalars from the highest scope, lists across scopes; `strictAllowlist`
  only from user and managed, and when on the repository's domains and
  `WebFetch(domain:...)` rules drop out); doctor's four scored checks;
  `planSandboxFix()`/`runSandboxFix()`/`applySandboxFix()`; the ConfigChange
  comparison; `removeSandboxProfiles()` for uninstall. It never runs Claude Code.
- `src/runtime/score.ts`: the protection score (weights in the table below; a
  check that does not apply here, such as a cooldown without a package manager
  or the sandbox without Claude Code, is left out of the denominator).

| Check | Weight | Full points when |
|---|---|---|
| hooks installed, first, fail-closed | 25 | every hooks check ok |
| approval passphrase pinned in the hook command | 10 | pinned key matches (5 when set but not pinned) |
| managed settings register the firewall | 10 | yes |
| sandbox | 15 | `sandbox.enabled` in the effective settings |
| sandbox network | 10 | an allowlist within the policy's hosts (5 with hosts outside it) |
| sandbox escape | 5 | `allowUnsandboxedCommands` false, no unsafe `excludedCommands`, no Docker socket, nothing weakened |
| sandbox hooks | 5 | a probe write in the firewall's state directory works |
| package cooldown | 5 | configured for each detected manager |
| malicious-package data | 5 | snapshot 7 days old or less |
| canary files | 5 | at least one decoy planted, registry valid |
| decision log | 5 | verifies |

`doctor --fix` is never read-only (an agent running it is FW-TAMPER). It
checks for a terminal and that no Claude Code session started it, reads the
approval passphrase, shows the diff and asks for "yes"; then it backs up the
file into `backups/`, writes it atomically (only the `sandbox` key changes) and
records the exact `sandbox` object in `sandbox-install.json` (beside
`install.json` rather than in it, so hook records and their readers stay as
they were). An unknown sandbox key or an unreadable settings file makes it
refuse. `--dry-run` prints everything and asks nothing.

Protection (`sandbox.protectInstalledProfile`): the hook context carries
the recorded profiles (`ctx.sandboxProfiles`), and their files join
`registeredSettings`, so a shell write or removal of the file is the worst case
(denied) and a Write/Edit is judged by its result: `settingsViolations()` adds
`sandboxViolations(before, after)`, which flags only weakenings the change
introduces and that neither the recorded profile nor the current policy
covers. ConfigChange compares the file on disk with the recorded profile.
Whether ordinary hooks run outside the sandbox is indicated by the 2.1.289
strings (only remote-tools project hooks are sandboxed) but not confirmed by a
live run; doctor's probe write is the check.

## `run`: the OS sandbox for any agent

`src/engine/netgate.ts` (pure) turns the policy into the run's host list by
calling `profileFromPolicy()` (so `run` and Claude Code's sandbox admit the
same hosts), judges each proxy request and keeps the run's budgets;
`src/engine/run-profile.ts` (pure) turns one plan into a Seatbelt profile or
a bubblewrap argument list; `src/engine/tls-sni.ts` reads the ClientHello's
server name. `src/runtime/run/` holds the platform probe, the proxy, the
Linux bridge and the orchestration (log entries, signals, exit status).
Design, checks and limits: [run.md](run.md).

## Files that run code later

`PERSISTENCE_TAGGED` in `src/engine/paths.ts` gives every persistence point a
tag (`ci`, `git-hook`, `editor-task`, `devcontainer`, `env-hook`; shell
start-up files, schedulers and `~/.local/bin` stay untagged), and the write
effect carries it as `persist:<tag>` (plus `removed` for a delete), so reasons
name what kind of file it is. `src/engine/autorun.ts` checks the content a
Write or Edit leaves (the Write content, or the current file with the edits
applied; an edit to a file it cannot read is judged by what it adds), using the
vendored agent-safety `commandRisks()` line by line plus file-specific patterns:
`runOn: folderOpen`, `task.allowAutomaticTasks`, an agent's own auto-approval
(the editor-settings detector), terminal environment and profiles, program paths outside
the workspace; `pull_request_target`/`workflow_run` with a checkout of the PR
head, write permissions on an outsider trigger, a step using a secret that
contacts an unlisted host; hook bodies with any risky command; dev-container
`privileged`, host mounts and lifecycle commands; `.npmrc` registry,
`script-shell`, `node-options`, `ignore-scripts=false` (also `npm config
set`); `.gitattributes` filter, diff and merge drivers (git's built-in diff
drivers excepted); a changed nix `shellHook`. Only what the change adds counts
(the capabilities of the old content are subtracted). The result is recorded on
the effect as `autorun-checked`, `autorun:<what>` and `autorun-form`; hidden
Unicode in the change is the existing `invisible_unicode` finding (deny). A
detector failure, or a JSON settings file that does not parse, counts as
adding a capability.

`persistenceRules()` in `decide.ts`: outside the workspace, FW-PERSISTENCE in
any session. Inside it, a trusted session gets FW-AUTORUN (approve) for an
added capability, and for an unchecked shell write to a hook body or an editor
task; everything else is allowed. An untrusted session gets FW-PERSISTENCE
(approve), or FW-PERSISTENCE-HELD (hold, a proposal the hook stores with its
diff) for a tag in `persistence.holdWhenUntrusted`: hook bodies always,
`.git/config`-style git files, editor tasks and dev containers in their
auto-run forms. An untrusted write to any persistence file is a `tainted_write`,
and the runner table (`RUNNER_MANIFESTS` and the directory form
`RUNNER_MANIFEST_DIRS` in `shell/analyze.ts`) covers `git commit` for hook
managers and `.gitattributes`, `lefthook`, `act`, `gitlab-runner`,
`devcontainer`, `direnv` and `mise`, so running them afterwards is
FW-TAINTED-MANIFEST.

## Budgets

The engine stays pure: `decide()` takes an optional `budgets: BudgetView` (the
counters so far) and `src/engine/budgets.ts` computes what the action would add
(`bytes:<host>`, `bytes:*`, `req:<host>`, `mcp:<server>`, `mcpsend:<server>`)
and whether that exceeds a limit plus the person's allowance, returning the
usage and the raises in `Decision.budget`. Loop detection uses the action hash:
an action that runs or sends something and writes nothing counts toward
`loop:<hash>` (8 in a fixed 10-minute window); any write that goes ahead resets
it. `verdict:nonallow` counts asks, holds and denials.

`src/runtime/counters.ts` keeps the counters in `sessions/<id>.counters.json`
(per-key one-minute buckets for the last hour, session totals, recent loop
hashes, raised allowances, pending raises). The hook reads them before deciding
and updates them under the session's lock after the decision (allow and ask
record usage); a decision that changes nothing (most reads) takes no lock and
writes nothing, and the write is an atomic rename without fsync (a crash can
only lose the last update). An ask that exceeded a budget leaves a pending raise; when the
tool's PostToolUse arrives (the person answered yes) the raise is applied. A
queued action approved with the passphrase raises when its signed approval is
used (FW-APPROVED). Signed `budget_raise` events in the session log are counted
too; a forged one is `corrupt`. A missing file is a new session; an unreadable
one is reported to the engine as `corrupt` (an untrusted session's next egress
asks once), then replaced with fresh counters marked `resetAt`, which `doctor`
reports. `pruneSessions()` prunes the sidecar with the session. Unattended, a
held FW-LOOP action raises the `loop` notification ("held for repeating the
same failing step").

## Known hosts

`src/engine/knownhosts.ts` is pure: `contactedHosts()` reads the hosts an action
contacts from the effects the classifier already produced (egress effects with a
host, marked `send` when data goes there, plus the addresses in MCP calls'
arguments, walked with depth and size caps; a walk the caps cut short asks
with FW-UNCLASSIFIABLE in "ask" mode; no parser changes), and
`newHosts()` drops hosts with rules of their own (addresses, loopback,
metadata, capture hosts), denied hosts, the known ones (approved for the
project, the policy's `fetchAllowHosts` and `sendAllowHosts` as in effect with
their defaults, the built-in set unless `knownHosts.builtins` is false, which
does not touch the lists) and the hosts the person named in the prompt. With `knownHosts.mode`
"ask", `decide()` adds one `FW-NEW-HOST` (approve) per new host, in any session;
the rule only ever adds a question. The approved hosts reach the engine as
`ctx.knownHosts`.

`src/runtime/knownhosts.ts` keeps one file per project in
`known-hosts/<sha256 of the project's real path>.json` (approved hosts, pending
questions, the watch record), under a lock, with atomic replace. Learning works
like the budgets' raises, with more conditions. A pending question (keyed by
session and action hash) is noted only for an attended, trusted session's asked
FW-NEW-HOST in a mode where a person answers it (`default`, `acceptEdits` or
`plan`, as learned allows) or a signed queue approval being used,
and only for plain host names the action fetches from; every other decision of
the same action drops it. The tool's PostToolUse, which arrives only if it ran,
moves the hosts into the list unless the session's taint sources include
anything but this action's own. Learning and watch recording need the project
named by the agent (its event or project variable). Watch records at
PostToolUse, so only actions that ran are proposed. A damaged file counts as no
approved hosts, is reported once per hook run and by `doctor`, and is not
written over until `hosts reset`.

`run`'s proxy reads the approved hosts of its workspace (`judgeHost(...,
known)`), but whether it does follows the user and managed policy only
(`runKnownHosts()`): a project file can switch the hooks' question on, never
widen what the proxy admits. The proxy does not use the built-in set.

### The behaviour monitor and the kill switch

The monitor is FW-LOOP's second stage, not a second counter store.
`budgetRules()` also reports what the action is for the monitor
(`Decision.budget.watch`: the counted hosts, how many the session never tried,
whether it changes configuration, instructions, a file that runs code later or
the firewall), and `applyDecision()` counts it whatever the verdict: `host:<host>`
as a session total, `watch:newhost`, `watch:config` and `fail:<counter key>`
(blocks and holds) as minute buckets only, next to `verdict:nonallow`. The
loop and failure counters (FW-LOOP's same-action count, `fail:`, the
identical-failures cap) key an action by `counterKey()` (src/engine/learn.ts:
the learnKey, without cosmetic fields such as a Bash `description`, carried as
`Decision.counterKey`), so rewording the description does not reset them;
approvals and budget raises stay bound to the exact `actionHash`. After the
other rules have given a verdict, `decide()` runs `monitorCheck()`: it fires
only when this action adds to the count it crosses (counting itself), over the
minutes after the last resume (`BudgetView.window(key, 10, since)`), and then
denies the action with `FW-STOPPED` and sets `Decision.stop` (a fixed signal and
reason). The limits are `budgets.loop.stop*`, so a project may only lower them,
and not below half their default (`src/policy-budgets.ts`; a lower value is
raised to that floor and reported). Spending limits have their own project
floors (`PROJECT_CAP_FLOOR` in `src/policy-caps.ts`; see policy.md).

Spending limits and the monitor are kept apart. Both see repeated failures, but
a cap (`FW-CAP`, `FW-CAP-WARN`, src/engine/caps.ts) has its own counters and
its own way out (`caps raise`). In the monitor's counts
(`monitorCountedVerdict()`), a decision refused only by a spending limit (every
rule that gives its verdict is a cap rule) counts as allowed toward
`verdict:nonallow` and `fail:<counter key>`, in `decide()` and in the counters
alike, so a run
of cap denials never also trips a kill-switch stop that needs the approval
passphrase to resume. A cap stop is not turned into a kill-switch suspension
either: `capStopped()` only logs it, because a suspension
would outlive a person's `caps raise` and the day caps' reset at midnight.

`decide()` takes `stop: StopView` (the stop in force for the session or its
agent, and the last resume). With a stop in force it classifies the action (so
a decoy still trips) and denies it with `FW-STOPPED` before any other rule: no
budget use, no approval (a deny is never approvable), only tripwire events.

`src/runtime/stops.ts` keeps one append-only file per target
(`stops/session-<id>.jsonl`, `stops/agent-<id>.jsonl`). A stop line counts
whoever wrote it (it only tightens; the directory is inside the protected data
directory). A resume line names the stop it ends and is signed with the
approver key over `resume`, the target, its scope, the stop id, its own id and
its time (a resume's time restarts the monitor's count, to the millisecond, and
is never taken as later than now), so an agent cannot write one, an old resume
cannot end a newer stop and a resume for one session does not transfer to
another. A monitor stop is named before the counters are written and kept in
them too (`Counters.stops`, under the session lock), so a stop record that
cannot be written still stops the session; the library's guard also keeps such
a stop itself when its store cannot. File names of targets that are not plain
ids are hashed behind `~`, which a plain id cannot contain. The library and the
local API also count per agent (counters under `agent:<id>`) and stop the agent
when its sessions together cross a limit. `budgets.stopScope` sets what a
session's own monitor stop covers on every route that knows the agent:
"session" (default) or "agent", every session of the agent (the hook's adapter
id, the library's and the local API's agent id); the hook then keeps the stop's
sentinel in the agent's counters too (`recordStopSentinel`). A library guard
with no agent id (no `agent` option and a session id without `<agent>/`)
applies session scope whatever the key says, and so does network middleware
traffic. Only user or managed policy sets the key; a project file's value is
ignored and reported. The sentinels survive counters that cannot be parsed (each
well-formed one is salvaged, `salvageSentinels`) and `caps reset --session`;
only a signed resume ends a stop. A call the kill switch denies counts no
budget, but the model usage it reported still counts toward the spending
limits (`stoppedUsage()`).

Network middleware traffic (the OpenShell supervisor middleware,
src/openshell/middleware.ts) is not the agent's tool calls. Its decide requests
carry `context: middlewareDecideContext(attended)` (src/api/request.ts, which sets
`traffic: "network"`); the local API then builds the guard with
`traffic: "network"`, which keeps every rule, the sandbox session's budgets and
its own monitor, but does not count the request toward the toolCalls spending
limit (`DecideInput.countCall: false`) or toward the agent-wide counters and
their stop. The caller cannot declare this itself: the API accepts
`traffic: "network"` only from a token made with `api token add <agentId>
--traffic network` (`TokenRecord.traffic`, checked in `parseDecide()`) and only
for the middleware's shape, an engine-format `HttpRequest` or the unreadable
wrapper of one (`translateDecide()`); anything else is 400. The guard writes
`traffic: "network"` into each such signed log entry. `doctor` reports damaged records,
resumes not signed by the key, and logged stops with no logged resume that are
no longer in force (a deleted record). A line that does not parse,
names another target, or a file that cannot be read is a stop by
"unreadable" (fail closed); the person's signed resume moves such a file aside.
The hook reads the session's file and its agent's (the adapter's id; a local
API session `<agentId>/<session>`) before deciding; when the monitor fires it
appends the stop under the file's lock (idempotent), writes a `stop` entry to
the signed decision log and raises the `stopped` notification with the
signal's fixed sentence. `session stop`/`agent stop` (refused from an agent's
tool call by FW-TAMPER and from a process an agent started) and `session
resume`/`agent resume` (a person at the keyboard and the passphrase) write
`stop` and `resume` log entries. The library reads the same files through
`fileStore`; its memory store keeps monitor stops in memory.

## Spending limits

Caps (`src/engine/caps.ts`, policy `caps`) are the budgets' stopping
counterpart: `decide()` takes an optional `caps: CapView` (the session's and
today's counters and the person's raises) and an optional `usage` (model
tokens and cost the agent reported), and `capRules()` returns `FW-CAP` (deny)
at a limit and `FW-CAP-WARN` once at `warnPercent` (approve when `caps.warn` is
`ask` and someone can answer, else an allow that carries the note), plus a
`CapRecord` in `Decision.caps`: what is counted whatever the verdict (tokens,
cost: the model was used), what only when the action goes ahead (the call, the
bytes `measureUsage` gives, the byte budgets' own measure), the warnings and
the caps stopped at. A usage report that is not whole token counts (to 10^12)
and a finite cost is denied, never counted as zero. A warning is recorded as given only when the decision
shows it, so it fires once per cap value (a raised cap warns again near its new
value). A native call of several parts is counted once (`mergeCapOutcome` in
`decideNative`). Failures come from post-tool results with an explicit marker
(`capFailure`: a non-zero `exitCode`, an MCP `isError`) or the library's and the
API's `failed`; each counts under two keys per action hash, the error text with
numbers removed (`<hash>:<fingerprint>`, `capFailureFingerprint`) and its status
(`<hash>:status:exit:1`, held to `STATUS_FACTOR` (3) times the limit), the 500
most repeated kept.

The session's cap counters live in its counters file (`caps` in
`sessions/<id>.counters.json`); the day's, for every session, in
`caps/day.json` with its local calendar day, replaced atomically under its own
lock and started again when the day changes (local midnight; a later stored
day is kept, so the day never goes backwards). Damaged counters fail closed:
an unreadable day file is never overwritten, and an unreadable session file,
once the budgets start it again, keeps `capsDamagedAt`; either way `CapView`
marks the scope `damaged` and every call is denied until a person runs
`caps reset`. A day-counter write that fails denies the call. A person's raise is signed
with the approval key: a session raise is a `budget_raise` event in the session
log, a day raise a line in `caps/raises.jsonl` (signed over `day:<date>:<firewall home>`,
`cap:day:<metric>`, the amount and an id, so a line copied from another home or
day raises nothing); each raise counts once by its id, and both are `cap_raise` entries in
the decision log. `caps raise` is a state-changing command, so an agent running
it is `FW-TAMPER`, and all of these files are in the protected data directory.
A stop writes a `cap_stop` log entry through `capStopped()`, the one place a
session suspension can hook in; caps themselves only deny, so the agent's next
call meets the same limit. Unattended, a warning or a stop raises the `cap`
notification.

## The browser link

The LaunchSafe browser extension talks to the firewall over Chrome's native
messaging ([browser-link.md](browser-link.md)). `install --browser` writes a
host manifest into one browser's per-user `NativeMessagingHosts` directory,
allowed for the extension's id only, naming a launcher inside the firewall's
own directory that pins the data directory and the approval key. The host
(`src/runtime/native/`) checks the origin Chrome passes, parses every message
against a strict schema (`protocol.ts`, 64 KB frames) and exits on anything
else. Browser decisions are appended to the signed log as `browser_decision`
entries carrying the extension's own sequence number and hash. Taint is shared
through two append-only files (`link.ts`): the hook links a session on each
call to a browser-driving MCP server and applies recent browser taint to that
call; a browser taint is appended to every linked session; the host reports
tainted linked sessions back. Approvals go through the queue and come back as
`approve` only with an approval event that verifies against the pinned key.

## Failure policy (fail closed)

- Bad or unreadable hook input → exit 2 (blocks; `PreToolUse` honors it).
- Decision error → `deny` for a risky tool, `allow` for a read-only tool, except when
  the error came from the input itself: arguments nested deeper than 256 levels are
  not judged, and that refusal or a stack overflow is `deny` for every tool
  (`FW-INPUT-SHAPE`; see the fuzzing findings in threat-model.md).
- The installed command is `... || exit 2`, so a crash of Node itself blocks.
- A hook the agent stops at its own timeout is not covered by the wrapper (the
  process is killed, so `|| exit 2` never runs). The hook denies a decision
  itself at its deadline (`src/hook/deadline.ts`: 20 s by default, checked
  between steps), well inside the timeouts install writes (600 s for Claude
  Code and Codex, 60 s for Gemini CLI, 30 s for Cursor), so only a step that
  never returns reaches them. Codex and Gemini CLI then run the tool. Claude
  Code's entries carry `onFailure: "block"`, honoured from Claude Code 2.1.295
  (not verified live; the captured Claude Code, 2.1.289, is older than 2.1.295; `doctor` warns on older versions, which are documented to ignore it and run the tool).
  Cursor's entries are `failClosed: true`. See limitations.md.
- `PostToolUse` error → the session is marked untrusted rather than losing what
  the tool brought in.

## Policy precedence

Built-in safe defaults, then the administrator's managed policy and the user's
policy (either may loosen or tighten), then the project's own
`.launchsafe-firewall.json` — which may **only tighten**, because a repository is
untrusted content. See [`policy.md`](policy.md).
