# Codex

The Codex adapter (`src/adapters/codex.ts`) translates OpenAI Codex's hook
events (local runs) to the firewall's normalized actions and its answers back.
The policy is the same engine Claude Code uses. Only the CLI was captured; the
IDE extension runs the same hooks according to Codex's documentation, which
was **not verified**.

Tested with **Codex 0.162.1**. The event shapes below were captured live,
except where a note says otherwise: Codex
was installed into a temporary npm prefix and run with a throwaway `HOME` and
`CODEX_HOME` against a local mock model (a custom `model_provider` speaking the
Responses API) and a local MCP server, with a capture hook saving each event
(`test/fixtures/codex-0.162.1-*.json`). No real account or key was used. The
output protocol, the exit-code behaviour and hook trust were tested the same way.

## Install

```sh
launchsafe-firewall install --agent codex                   # $CODEX_HOME/hooks.json (default ~/.codex/hooks.json)
launchsafe-firewall install --agent codex --scope project   # <project>/.codex/hooks.json
launchsafe-firewall doctor
```

`install` puts one hook group per event first in each list (matcher `*` on the tool events only), keeps
the person's own hooks, saves the original file under
`~/.launchsafe-firewall/backups/`, records the install (`agent: "codex"`) and is
idempotent. `uninstall --agent codex` removes exactly the firewall's entries;
`--restore-backup` puts the file back as it was, after saving the current file as
`hooks.json.before-restore.TIMESTAMP`. A `hooks.json` that is a symlink into your
dotfiles is written through, and the link is kept (only to a file of yours in
your home, outside the firewall's directory, credential stores and other agents'
configuration; `--restore-backup` refuses a link into another directory: see the
[usage.md](../usage.md), "Install").

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "*", "hooks": [{ "type": "command",
        "command": "LAUNCHSAFE_FIREWALL_HOOK=1 LAUNCHSAFE_FIREWALL_HOME='…' HOME='…' LAUNCHSAFE_FIREWALL_TEST= VITEST= NODE_COMPILE_CACHE= NODE_OPTIONS= NODE_PATH= LD_PRELOAD= DYLD_INSERT_LIBRARIES= '<node>' '<cli>' hook --agent codex || { echo '…' >&2; exit 2; }",
        "timeout": 600 }] }
    ],
    "PostToolUse": ["…same…"],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "…same…", "timeout": 600 }] }],
    "SessionStart": ["…as UserPromptSubmit…"]
  }
}
```

Only the tool events get a matcher. Codex 0.162.1 **skips a `UserPromptSubmit`
group that has any matcher**, silently: `"*"`, `""`, `".*"` and `"startup"`
were all skipped, the group without one ran (`SessionStart` ran either way).
This was captured in `codex exec` with a capture hook per variant, each one
trusted (`test/fixtures/codex-0.162.1-hook-matchers.json`). Installs before
this fix wrote `"matcher": "*"` on every event, so on Codex the firewall never
saw a prompt: no task scope and no destinations the person named, in `exec` and
interactive sessions alike (the interactive case uses the same hooks but was
not captured). `doctor` fails on such a file ("Codex prompt hook"); running
`install --agent codex` again rewrites the groups and their trust.

### Hook trust (important)

Codex runs a hook from `hooks.json` only once the person has trusted it, and
**skips an untrusted hook silently** (no warning; the tool runs). A trusted hook
whose command, timeout or matcher changes is skipped the same way. Trust is
recorded in `$CODEX_HOME/config.toml`:

```toml
[hooks.state."/Users/you/.codex/hooks.json:pre_tool_use:0:0"]
trusted_hash = "sha256:…"
```

The key is the hooks file, the event, the group and the handler index; the hash
is sha256 of the hook's identity (event, matcher, command, timeout, async,
statusMessage) as compact JSON with sorted keys. The firewall reproduces
Codex's hash: it is checked against Codex's own `hooks/list` for one captured
hook (`test/adapters/install.test.ts`); other comparisons were not kept in the
repository, and `async` and `statusMessage` are not covered by that test. So
`install`, which you run yourself in a terminal to install exactly these hooks,
records their trust; your own hooks keep theirs (their entries move with them
when the firewall's group is put first). `uninstall` and `approver
init|rotate` (which re-pins the approval key in the command) update it too, and
`doctor` fails when a recorded hash no longer matches a hook as written. The
agent itself may neither grant nor revoke trust: a change to `hooks.state` is
FW-TAMPER.

You can also review the hooks in Codex with `/hooks`.

### Managed deployment

```sh
launchsafe-firewall install --managed --agent codex --lock-other-hooks --print | sudo tee /etc/codex/requirements.toml
```

`requirements.toml` carries the hooks and `allow_managed_hooks_only = true`, so
no user or project hook runs alongside them and none of them can be removed by
the user. Codex's documentation says managed hooks are trusted by policy; this
could not be tested without root (Codex ignores a `requirements.toml` in
`$CODEX_HOME`). `doctor` reports whether `/etc/codex/requirements.toml`
registers the firewall. The document also sets `[features] hooks = true`, so a
user's or project's `[features] hooks = false` cannot switch the managed hooks
off. Whether Codex additionally needs `[hooks] managed_dir` for managed hooks
is **not verified** (no root test run); if `doctor` shows the managed hooks not
running, check Codex's hooks documentation for your version.

## What the adapter maps

| Codex event | Firewall |
|---|---|
| `PreToolUse` | decision |
| `PostToolUse` | taint, private data, fingerprints from `tool_response` |
| `UserPromptSubmit` | the task scope and the destinations the person named (not for a subagent's prompt, which carries `agent_id` and is written by the parent model). `codex exec` fires it once, with the prompt given on the command line (`test/fixtures/codex-0.162.1-UserPromptSubmit-exec.json`) |
| `SessionStart` | the session-start agent-configuration scan |
| `SubagentStart` / `SubagentStop` | linkage when a parent session id is reported (0.162.1 keeps the parent's `session_id`, so nothing is needed) |
| `PermissionRequest` | ignored (the firewall decides in `PreToolUse`) |
| `SessionEnd` | understood, no action |
| any other name (`Stop`, `PreCompact`, `PostCompact`, `Interrupt` among them; **not captured**) | ignored: `parseCodex` treats an unknown event name as ignored |

| Codex tool (as the hook sees it) | Judged as |
|---|---|
| `Bash { command }` (the model's `exec_command`) | `Bash`; an argv array (older versions) is joined with shell quoting, `["bash","-lc",s]` is `s`. An input that carries both `command` and `cmd` with different values is judged as both commands (the most severe wins) |
| `apply_patch { command: "*** Begin Patch …" }` | parsed per file: an added file is a `Write`, an updated file a `MultiEdit` of its hunks (settings, auto-run and auto-approval files are result-checked against their current content), a delete `rm`, a move `mv`; the whole patch gets one verdict and one approval hash, and a held patch shows every file in `queue show`. Codex matches a chunk's context again after trimming whitespace and folding punctuation, and anchors it after its `@@` line; that was not captured, so the result is judged at every place the chunk could match (the most severe wins), and as unknown (the worst case) when it matches nowhere. A patch that does not parse is FW-UNCLASSIFIABLE. Run through the shell (`apply_patch <<'EOF'`, or the argv form), it is judged the same way |
| `mcp__<server>__<tool>` | as is; the server's source comes from `[mcp_servers.<name>]` in the user's or the project's `config.toml`. Codex names the server only inside this joined name, so a name with more than one `__` boundary is asked (FW-UNCLASSIFIABLE) unless the policy lists the longest reading's server |
| `spawn_agent`, `wait_agent`, `multi_agent_*`, `update_plan` | safe (the agent talking to itself) |
| `view_image { path }` | `Read` |
| anything else | an unknown tool: held for a person (FW-UNKNOWN-TOOL), its arguments judged, and its result treated as outside content |

## Output protocol (observed)

- `PreToolUse` blocks with
  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"…"}}`
  (the model reads "Command blocked by PreToolUse hook: …"), or exit 2 **with
  text on stderr**.
- `permissionDecision: "ask"` is unsupported: Codex logs a failure and **runs
  the tool**. The firewall never sends it; an action that needs a person is held
  in the queue and the agent gets the `launchsafe-firewall queue approve <id>`
  command.
- Exit 2 with empty stderr, exit 1, a crash, non-JSON output and a timeout all
  let the tool run. The wrapper prints a line before `exit 2`, so a failure of
  the firewall or of Node blocks; a hook that times out (600 s as installed,
  Codex's default) still fails open, which is why the firewall denies at its
  own deadline (20 s) first.
- Typing into a running command (`write_stdin`) is believed not to run
  `PreToolUse` again (not captured: no fixture); only the command that started
  the session is judged, so assume what is typed later is not seen.
- `PostToolUse` `additionalContext` reaches the model as a separate message;
  Codex cannot replace a built-in tool's output (and rejects
  `updatedMCPToolOutput`, documented as MCP-only; not captured), so secrets in output are not redacted.

## Unattended

`codex exec` forces the approval policy to `never`, and every event then says
`permission_mode: "bypassPermissions"`; the adapter treats that, `codex exec`
or `-a never` in the process ancestry, and `approval_policy = "never"` in
`config.toml` as unattended (held actions wait in the queue, and the message
says nobody was there). The process ancestry is read from `/proc` on Linux (so
an image without `ps`, such as Debian-slim or Alpine, needs none; reading `/proc` is tested on a simulated `/proc` tree and on glibc Linux, not run on Alpine), with `ps` on
macOS, and there with `pgrep` where a sandbox forbids `ps` (see
`src/runtime/ancestry.ts`). If no process can be read at all, the session is
treated as unattended: held actions wait in the queue rather than being asked.
That answer is not remembered, so the next hook reads the processes again.

Until a prompt arrives (an install with the old matcher, or a hook that
failed), the session has no task scope, so today's rules apply, and no named
destinations, so a fetch after outside content is held rather than allowed.
That is the strict side for destinations. Scope is not: with no prompt there is
nothing to narrow by, so even unattended a push is not held by FW-SCOPE (seen
on an old install). With the matcher fixed the prompt
arrives in every captured run, so no stricter fallback was added; `doctor`
catches the old install.

## What its hooks cannot do

- Codex's hosted web search and `tool_search` never reach a hook.
- Codex 0.162.1 does not send the model's `workdir` to the hook (captured):
  relative paths are judged against the session's directory. If a later
  version sends it, the adapter judges `cd <workdir> && <cmd>` (`normalizeCodex`).
- No `ConfigChange` event: a change to `hooks.json` or `config.toml` is judged
  when the agent makes it through a tool (result-checked), not when something
  else edits the file.
- A trusted project's `.codex/config.toml` with `[features] hooks = false`
  switches off every hook, the user's included (captured). `doctor` fails on it;
  the agent writing it is FW-TAMPER.
- Codex cloud tasks do not run local command hooks.
