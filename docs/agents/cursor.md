# Cursor

The Cursor adapter (`src/adapters/cursor.ts`) translates Cursor's hook events
(the Cursor CLI, `cursor-agent`, and the IDE's agent, local runs) to the
firewall's normalized actions and its answers back. The policy is the same
engine Claude Code uses; nothing about what is allowed differs by agent.

## How the format was verified

Read from source, **not captured live**. Codex and Gemini CLI were captured by
running them against a local mock model; Cursor's agent cannot run without a
Cursor account (`cursor-agent` exchanges an API key with Cursor's server before
anything else, then speaks Cursor's private protocol, and stores its token in the
macOS keychain), so no live event was recorded. Instead:

- The behaviour of `cursor-agent` **2026.10.01-e373342** (the build
  `cursor.com/install` served on 10 Oct 2026) was studied: how it loads hooks,
  what it writes on a hook's stdin, how it treats exit codes, output and
  `failClosed`, how it validates a hooks file, and which tool fires which step
  with which `tool_name` and `tool_input`. Only behaviour is described here.
- The result was checked against cursor.com/docs/hooks and
  cursor.com/docs/reference/third-party-hooks (fetched 10 Oct 2026).
- The fixtures (`test/fixtures/cursor-2026.10.01-src-*.json`) were reconstructed
  from that behaviour and say so in a `_fixture` field. Paths are replaced
  with `/home/user` and `/work/project`.

What was **not** verified: the IDE (its agent is documented to use the same
hooks; only the CLI's code was read), the names Cursor's server gives its own
server-side tools (web search, to-dos, plans) in `preToolUse`, and whether a
subagent's tool calls carry its `subagent_id` as their conversation. Re-capture
these when a Cursor account is available (`LAUNCHSAFE_FIREWALL_RECORD=1 launchsafe-firewall hook --agent cursor --record DIR`).

## Install

```sh
launchsafe-firewall install --agent cursor                  # ~/.cursor/hooks.json
launchsafe-firewall install --agent cursor --scope project  # <project>/.cursor/hooks.json (see below)
launchsafe-firewall doctor
```

`install` puts one entry per step first in each list, keeps every other hook,
sets `version: 1` when the file has none, saves the original under
`~/.launchsafe-firewall/backups/`, records the install (`agent: "cursor"`) and is
idempotent. `uninstall --agent cursor` removes exactly the firewall's entries
(and `version` when install added it); `--restore-backup` puts the file back as it
was (a file install created is removed), after saving the current file as
`hooks.json.before-restore.TIMESTAMP`. Cursor does not load a `hooks.json` reached
through a symlink, so install refuses one rather than write hooks that never run. Cursor reloads `hooks.json` on
save; there is nothing to trust or enable for the user file (the loader has no
trust store or hash, unlike Codex).

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      { "failClosed": true, "type": "command",
        "command": "LAUNCHSAFE_FIREWALL_HOOK=1 LAUNCHSAFE_FIREWALL_HOME='…' HOME='…' LAUNCHSAFE_FIREWALL_TEST= VITEST= NODE_COMPILE_CACHE= NODE_OPTIONS= NODE_PATH= LD_PRELOAD= DYLD_INSERT_LIBRARIES= '<node>' '<cli>' hook --agent cursor",
        "timeout": 30 }
    ],
    "postToolUse": ["…same…"], "postToolUseFailure": ["…"],
    "beforeMCPExecution": ["…"], "afterMCPExecution": ["…"],
    "beforeReadFile": ["…"], "beforeSubmitPrompt": ["…"], "sessionStart": ["…"],
    "subagentStart": ["…"], "subagentStop": ["…"]
  }
}
```

Cursor's entries are flat (no `matcher`/`hooks` group; no matcher means every
tool) and its timeouts are in seconds. `doctor` fails when the firewall's
`beforeMCPExecution` or `beforeReadFile` entry is missing or carries a matcher
(Cursor decides an MCP call only there, and `preToolUse` does not name the
server), so no MCP call or file read skips it.

**Fail-closed without a shell wrapper.** Every entry says `failClosed: true`, so
a crash, a non-zero exit other than 2, a timeout or an empty answer blocks the
step (read from source); invalid JSON blocks a permission step even without it.
That is stronger than the Codex/Gemini wrapper (it covers a timeout). The command
has **no** `|| { …; exit 2; }` wrapper on purpose: Cursor's legacy payload
transport appends a heredoc to the command (`<command> <<'CURSOR_HOOK_EOF'`),
which a trailing `{ …; }` group would take instead of node (tested). The
firewall also always answers with JSON, because with `failClosed` an empty
answer blocks.

**Project scope, with care.** Cursor runs a project's `.cursor/hooks.json` only in
a trusted workspace, and its **cloud agents run it too**, where this machine's
node and firewall paths do not exist: the hook fails, and being fail-closed it
blocks every action of a cloud agent in that repository. Prefer `--scope user`;
`doctor` warns on a project install.

**Whole-file validation.** Cursor validates `hooks.json` as a whole and loads
none of it on any error: a `version` that is not a positive integer, an unknown
step name, or one malformed entry (a non-string command, an invalid matcher
regex, a non-positive timeout, a non-boolean `failClosed`, among others). It also refuses a
`hooks.json` reached through a symlink. `doctor` checks both, and an agent write
that would break the file is FW-TAMPER (the firewall reproduces Cursor's
validator).

### Managed deployment

```sh
launchsafe-firewall install --managed --agent cursor --print | sudo tee "/Library/Application Support/Cursor/hooks.json"   # Linux: /etc/cursor/hooks.json
```

The enterprise file (MDM) and team hooks (Cursor's dashboard, Enterprise) run in
every workspace, alongside user and project hooks. Cursor merges every hook's
answer and **a deny from any of them wins**, but nothing stops other hooks from
running too (there is no equivalent of `allowManagedHooksOnly`), so `doctor`
scores this as partial.

## What the adapter maps

| Cursor step | Firewall |
|---|---|
| `preToolUse` | decision, for every local tool (its deny is enforced; `ask` is ignored by Cursor) |
| `preToolUse` for `MCP:<tool>` | deferred: it carries no server; `beforeMCPExecution` decides |
| `beforeMCPExecution` | decision for an MCP call, named `mcp__<server>__<tool>` by the server's `mcp.json` key |
| `postToolUse`, `afterMCPExecution` | taint, private data and fingerprints from the output |
| `postToolUseFailure` | a failed result (`post_tool` with `failed: true`): its error message (`error_message`) is read like a tool's output (taint, private data, fingerprints) and counts toward the identical-failures spending limit (`caps.*.identicalFailures`) for that exact action |
| `beforeReadFile` | runs after a read and before the model sees it: the content is recorded like a tool's output (decoys, secret fingerprints); always allowed (the read was decided at `preToolUse`) |
| `beforeSubmitPrompt` | destinations the person named, the task's scope |
| `sessionStart` | the session-start agent-configuration scan and MCP comparison (a resumed chat gets it before its first tool call) |
| `subagentStart` / `subagentStop` | linkage: the subagent (`subagent_id`, `child_conversation_id`) starts with the parent's state and hands its taint back |
| `beforeShellExecution`, `afterShellExecution` | understood, not registered (`preToolUse` and `postToolUse` cover the shell; registering both would decide every command twice) |
| `sessionEnd` | understood, not registered |
| `afterFileEdit`, `stop`, `preCompact`, `afterAgentResponse`, `afterAgentThought`, Tab and `workspaceOpen` steps | ignored |

| Cursor tool (as its executors report it; rows without a `cursor-2026.10.01-src-*` fixture are marked) | Judged as |
|---|---|
| `Shell { command, cwd, timeout }` | `Bash` (in `cwd` when it differs from the session's) |
| `Read { file_path }`, `ReadLints { file_path }` | `Read` |
| `Write { file_path, content }` (every edit: the whole new file) | `Write` (settings files result-checked on the exact result; a `Write` without its text is FW-UNCLASSIFIABLE, never an empty file) |
| `Delete { file_path }` | `rm -- <path>` |
| `Grep { pattern, file_path, glob, output_mode }`, `List { file_path, ignore }` | `Grep`, `LS` |
| `Glob { glob_pattern, target_directory }` (from source, no fixture) | `Glob` |
| `Fetch { url }` (and `WebFetch`) | `WebFetch` |
| `WebSearch`, `Task`, `updateTodos`/`TodoWrite`, `createPlan`, `askQuestion` (server-side; from source, no fixture; names from Cursor's docs and tool kinds, not seen in a hook event) | `WebSearch`, `Agent`, `TodoWrite`, `AskUserQuestion` |
| `ListMcpResources { server }`, `FetchMcpResource { server, uri, download_path }` (from source, no fixture) | `ListMcpResourcesTool` (outside content from an untrusted server, or when no server is named), `ReadMcpResourceTool` (+ a write of unknown content to `download_path`, judged like a shell write: FW-TAMPER for a hook settings file, a person for a git hook or editor task) |
| `WriteShellStdin { shell_id, chars_length }`, `ComputerUse { actions_count }`, `RecordScreen`, anything else (from source, no fixture) | an unknown tool: held for a person (FW-UNKNOWN-TOOL); the hook input does not say what is typed, clicked or recorded |

## Fixes carried to Cursor

Every hook fix that has a Cursor equivalent (listed in the changelog) is carried
over and tested through Cursor's own events (`test/adapters/review-fixes.test.ts`, "final-review fixes through the
Cursor adapter"):

- `Fetch` is judged on its `url` exactly as sent; Cursor's `Shell` goes
  through the fixed network and patch checks and submodule hooks.
- Cursor's edits carry the whole new file, so the result check is exact and the
  loose-matching over-approximation is not needed; a result the hook cannot
  know (a `Write` without its text, a `FetchMcpResource` download) is the worst
  case.
- `hooks.json` is recognised by location (the user's and the enterprise file,
  with their real paths, in any letter case) and by holding the firewall's
  Cursor hook, so Cursor's whole-file validation applies however the file is
  reached.
- MCP provenance looks at own keys only; a filesystem server in the user's
  `~/.cursor/mcp.json` confined to the workspace (also spelled
  `${workspaceFolder}`) keeps the session trusted and its writes are workspace
  writes. A project's `.cursor/mcp.json` is not trusted by its arguments.
- A held call that does two things (`FetchMcpResource` with a download) shows
  both parts in `queue show`.

## Output protocol (read from source)

- Permission steps (`preToolUse`, `beforeMCPExecution`, `beforeReadFile`,
  `subagentStart`) get `{"permission":"allow"}` or
  `{"permission":"deny","user_message":"…","agent_message":"…"}`; exit 0.
- `beforeSubmitPrompt` gets `{"continue":true}`; `preToolUse`, `postToolUse` and
  `sessionStart` may get `additional_context` (kept under Cursor's 10,000
  characters, past which a fail-closed `preToolUse` would block).
- Exit 2 blocks (with or without stderr). With `failClosed: true`, any other
  failure blocks too.
- No step lets the firewall ask the person (`preToolUse` and
  `beforeMCPExecution` act only on deny), so an action that needs a person is
  **held in the queue** and the agent gets the `launchsafe-firewall queue approve
  <id>` command.

## Cursor runs the Claude Code hooks too

With "Include Third-Party Plugins, Skills, and Other Configs" on (the default),
Cursor loads the hooks in `~/.claude/settings.json` and a trusted project's
`.claude/settings*.json`, maps `PreToolUse`/`PostToolUse`/`UserPromptSubmit`/
`SessionStart` to its own steps, and sends them **its own payload**
(`hook_event_name: "preToolUse"`, `tool_name: "Shell"`, `cursor_version`, …). In
v0.2 the firewall's Claude Code hook did not recognise those events and let them
through. Now `hook --agent claude` routes any event carrying `cursor_version` to
the Cursor adapter:

- when the firewall's Cursor hook runs for that step (registered, fail-closed, in
  `~/.cursor/hooks.json` or the enterprise file, in a file Cursor accepts: a plain
  file, not reached through a symlink (the file or its `.cursor` directory), and
  with no `matcher` that leaves the step's tool out), the
  imported hook says allow and records nothing, so nothing is decided or counted
  twice (Cursor merges answers; the Cursor hook's deny wins);
- otherwise it decides in full. An MCP call there has no server (`MCP:<tool>`)
  and is judged as a call to an unknown server; `doctor` recommends
  `install --agent cursor`.

## Unattended

A background agent (when the event carries `is_background_agent: true`), `cursor-agent -p`
or `--force`/`--yolo` in the process ancestry, and `approvalMode: "unrestricted"`
in `~/.cursor/cli-config.json` count as unattended (held actions wait in the
queue, and the message says nobody was there). The process ancestry is read
from `/proc` on Linux (no `ps` needed), with `ps` on macOS, and there with
`pgrep` where a sandbox forbids `ps` (`src/runtime/ancestry.ts`). If no process
can be read at all, the session is treated as unattended too; that answer is
not remembered, so the next hook reads the processes again.

## What its hooks cannot do

- **Cloud agents** run only the repository's `.cursor/hooks.json` (not the
  user's), and a project install's local paths do not exist there.
- **Tab completions** are the person's own edits; `afterTabFileEdit` only
  observes them. **Typed shell input** (`WriteShellStdin`), **computer use** and
  **screen recording** carry nothing the firewall can judge (held).
- **No `ConfigChange` step**: a change to `hooks.json` is judged when the agent
  makes it through a tool (result-checked), not when something else edits the
  file; Cursor reloads the file on save.
- Secrets in tool output are not redacted (Cursor can replace only an MCP tool's
  output).
- For what hooks cannot see, run Cursor's own sandbox (`sandbox.mode:
  "enabled"` in `cli-config.json`; `doctor` warns when it is off) and an
  egress proxy.
