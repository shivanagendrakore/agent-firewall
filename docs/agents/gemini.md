# Gemini CLI

The Gemini CLI adapter (`src/adapters/gemini.ts`) translates Gemini CLI's hook
events to the firewall's normalized actions and its answers back. The policy is
the same engine Claude Code uses; nothing about what is allowed differs by agent.

Tested with **Gemini CLI 0.63.0**. The hook events and the tools with a `gemini-0.63.0-*` fixture were captured live (`AfterModel` was not); the other tools in the table, and where marked behaviour, come from Gemini CLI's source or its documentation. The capture method:
Gemini CLI was installed into a temporary npm prefix and run with a throwaway
`HOME` against a local mock model that answered with scripted tool calls, and a
capture hook saved each event (`test/fixtures/gemini-0.63.0-*.json`, paths
replaced with `/home/user` and `/work/project`). No real account or key was used.

## Install

```sh
launchsafe-firewall install --agent gemini                  # ~/.gemini/settings.json ($GEMINI_CLI_HOME/.gemini/settings.json when set)
launchsafe-firewall install --agent gemini --scope project  # <project>/.gemini/settings.json
launchsafe-firewall doctor
```

`install` adds one command hook per event, first in each list, keeps every other
key and hook, sets `hooksConfig.enabled: true`, saves the original file under
`~/.launchsafe-firewall/backups/` and records the install (`agent: "gemini"`).
Running it again changes nothing. `uninstall --agent gemini` removes exactly the
firewall's entries and the `hooksConfig.enabled` flag when install was the one
that added it (install records which); `--restore-backup` puts the file back as it
was, after saving the current file as `settings.json.before-restore.TIMESTAMP`.

```json
{
  "hooksConfig": { "enabled": true },
  "hooks": {
    "BeforeTool": [
      { "matcher": "*", "hooks": [{ "name": "launchsafe-firewall", "type": "command",
        "command": "LAUNCHSAFE_FIREWALL_HOOK=1 LAUNCHSAFE_FIREWALL_HOME='…' HOME='…' … '<node>' '<cli>' hook --agent gemini || { echo '…' >&2; exit 2; }",
        "timeout": 60000 }] }
    ],
    "AfterTool": ["…same…"], "BeforeAgent": ["…"], "SessionStart": ["…"]
  }
}
```

Gemini CLI's hook timeouts are in milliseconds; install writes 60 000 (its
default), and the firewall denies at its own 20 s deadline first. Hooks need no feature flag in
0.63.0 (`hooksConfig.enabled` defaults to true; install sets it anyway).

Two things Gemini CLI does that weaken any hook, reported by `doctor`:

- **Folder trust.** In a folder Gemini CLI does not trust it skips every hook,
  the user's and the system's included (from Gemini CLI's source), so the
  firewall is not consulted there at all. Trust the folders you work in
  (in an interactive session, or with `GEMINI_CLI_TRUST_WORKSPACE=true` for
  headless runs). Seen on 18 Oct 2026 with Gemini CLI 0.64.0: a headless
  `gemini -p` in an untrusted folder refused to start ("Gemini CLI is not
  running in a trusted directory"), and `--yolo` there was overridden to the
  default approval mode. Don't use `--skip-trust` to get past it: that runs
  the agent in a folder where the firewall's hooks are skipped.
- **A repository can switch your hooks off.** A project `.gemini/settings.json`
  with `"hooksConfig": {"enabled": false}` or a `disabled` list naming the
  firewall's hook (`launchsafe-firewall`) turned off user-level hooks silently
  (captured). `doctor` fails on it; the agent writing it is FW-TAMPER.

Project hooks run the first time Gemini CLI sees them (with a warning) and are
recorded in `~/.gemini/trusted_hooks.json` (from Gemini CLI's source, not
captured); that is the session-start scan's concern (what the
agent is armed with), not the firewall's own hook.

### Managed deployment

```sh
launchsafe-firewall install --managed --agent gemini --print | sudo tee "/Library/Application Support/GeminiCli/settings.json"   # Linux: /etc/gemini-cli/settings.json
```

System settings override user and project settings, but Gemini CLI skips the
file unless its directory is owned by root (from Gemini CLI's source, not
captured); `doctor` checks the owner. `GEMINI_CLI_SYSTEM_SETTINGS_PATH` moves it. Gemini CLI has no
administrator control that stops a user from adding further hooks (there is no
equivalent of Claude Code's `allowManagedHooksOnly` or Codex's
`allow_managed_hooks_only`), so `doctor` scores this as partial.

## What the adapter maps

| Gemini CLI event | Firewall |
|---|---|
| `BeforeTool` | decision (pre-tool) |
| `AfterTool` | taint, private data and fingerprints from the output |
| `BeforeAgent` (carries the prompt) | destinations the person named |
| `SessionStart` | the session-start agent-configuration scan |
| `SessionEnd`, `AfterAgent`, `BeforeModel`, `AfterModel`, `BeforeToolSelection`, `PreCompress`, `Notification` | ignored (the firewall judges actions, not text) |

| Gemini CLI tool (input as captured; optional fields, and rows without a `gemini-0.63.0-*` fixture, are from source) | Judged as |
|---|---|
| `run_shell_command { command, description, dir_path, is_background }` | `Bash` (in `dir_path` when it is not `.`) |
| `read_file { file_path, start_line, end_line }` | `Read` |
| `read_many_files { paths / include }` (older versions; not registered in 0.63.0) | one `Read` per path; a glob is a recursive read of its base directory |
| `write_file { file_path, content }` | `Write` (result-checked for settings files) |
| `replace { file_path, old_string, new_string, instruction, allow_multiple }` | `Edit` (`allow_multiple` replaces every match). Gemini CLI matches `old_string` flexibly and can correct it from `instruction`; that was not captured, so the result is judged at every place the text could match, whitespace- and punctuation-insensitively (the most severe wins), and as unknown (the worst case: FW-TAMPER for a hook settings file) when it matches nowhere |
| `list_directory { dir_path }`, `glob { pattern, dir_path }`, `grep_search { pattern, dir_path }` (the legacy name `search_file_content` reaches the hook as such) | `LS`, `Glob`, `Grep` |
| `web_fetch { prompt }` | one `WebFetch` per URL in the prompt, taken as Gemini CLI takes it: the prompt is split on whitespace and each URL is the whole token, brackets and quotes included (read from Gemini CLI's source, not captured; a URL starting inside a token is judged from its scheme to the end of the token). The parts' budget use adds up. No URL is a parse failure (a person decides) |
| `google_web_search { query }` | `WebSearch` |
| `save_memory { fact }` (older versions; 0.63.0 has no such tool and writes memory with `write_file`/`replace`, judged as writes to a protected `GEMINI.md`) | a write to `~/.gemini/GEMINI.md`: allowed in a clean session, held as a proposal once untrusted |
| `write_todos`, `update_topic`, `invoke_agent`, `codebase_investigator`, `activate_skill`, `list_background_processes`, `read_background_output` | safe (the agent talking to itself; a subagent's own tool calls are judged one by one); the firewall's tool names are `TodoWrite`, `Agent`, `Skill` and `BashOutput` |
| `enter_plan_mode`, `exit_plan_mode`, `complete_task`, `ask_user` | safe, as `AskUserQuestion` |
| MCP tools: `mcp_<server>_<tool>` with `mcp_context { server_name, tool_name, command, args }` | `mcp__<server>__<tool>`; the server's source (system, project or user settings) decides its trust. Without `mcp_context`, a `mcp_<server>_<tool>` name is read as an unknown tool and held |
| anything else | an unknown tool: held for a person (FW-UNKNOWN-TOOL), its arguments judged, and its result treated as outside content |

## Gemini CLI's own sandbox (`gemini -s`, macOS)

What Gemini CLI 0.63.0 does (read from its sandbox launcher and captured in
sealed live runs):

- `-s` re-runs the whole CLI under `sandbox-exec` with one profile, and every
  process it starts inherits it: the firewall's hook and the agent's own tools
  run in the **same** sandbox. The hook's environment has `SANDBOX=sandbox-exec`
  and `SEATBELT_PROFILE`, and `/bin/ps` fails there.
- Its built-in profiles (`permissive-open`, the default, `permissive-proxied`,
  `restrictive-*`, `strict-*`) let a process write only the project, its
  temporary and cache directories, `~/.npm` and `~/.cache`, and never
  `~/.gemini`. With the firewall installed and nothing else, every hook fails
  to save its state, so every non-read action is blocked (captured: 5 of 5
  shell commands blocked, reads allowed). The hook now says so in one message
  naming the fix.
- `SEATBELT_PROFILE=<name>` loads `~/.gemini/sandbox-macos-<name>.sb`
  (`GEMINI_CLI_HOME` honoured), or the project's `.gemini/sandbox-macos-<name>.sb`
  only when the user's file does not exist. `tools.sandbox.allowedPaths` adds
  writable directories, but only when the sandbox is enabled from settings
  (`-s` on the command line ignores it), and it opens a whole directory.

The firewall's answer is a custom profile:

```sh
launchsafe-firewall install --agent gemini --seatbelt permissive-open
export SEATBELT_PROFILE=launchsafe   # in your shell profile
gemini -s
```

`--seatbelt BASE` writes `~/.gemini/sandbox-macos-launchsafe.sb`: Gemini CLI's
own BASE profile, copied unchanged from the installed Gemini CLI (found from
`gemini` on PATH, or `--gemini-package DIR`), plus one block that lets a
process write the hook's state directories (`sessions`, `queue`, `log`,
`locks`, `ledger`, `pins`, `quarantine`, `scan/receipts`, `scan/last`) and
nothing else. For the `strict-*` bases, which confine reads too, the block also
lets a process read the data directory, the firewall's package and node.
Install creates those directories beforehand (the data directory itself stays
read-only) and records the file; `uninstall` removes it with the last Gemini
CLI hooks, unless it was edited.

Why only those directories: whatever the profile lets the hook write, the
agent's commands can write too. Every command is still judged first (writing
the firewall's directory is FW-TAMPER), exactly as without `-s`. But a command
the analyser cannot see through can reach any file the profile opens: in a
sealed run with the whole data directory writable, inline node code with a path
built at run time was allowed and created `policy.json`. With the firewall's
profile the same command got `EPERM` for `policy.json`, `keys/`,
`install.json`, `identity.json`, `backups/`, `canaries.json`, the profile
itself and `~/.gemini/settings.json`, and could write only `sessions/` and
`queue/`. So under `-s` the policy, keys, install records, backups, vault,
decoy registry and caches have the OS's protection on top of the analyser's;
the hook's state has the analyser's alone, as everywhere. The identity cache and
the agent-scan cache stay read-only (the hook rebuilds them; a scan is not
cached between sessions there).

`doctor` reports: not set up (a fail when `tools.sandbox` or `GEMINI_SANDBOX`
starts Gemini CLI sandboxed by default), the profile missing, edited or naming
another data directory, Gemini CLI's base profile changed since it was copied
(run the install command again after updating Gemini CLI), this shell not
exporting `SEATBELT_PROFILE=launchsafe` (a project `.env` cannot override an
exported value; it can set an unexported one), and a project shipping a profile
under the firewall's name.

Not covered: `mcp wrap` started by Gemini CLI inside `-s` (the gateway's state
is not in the profile), the vault inside `-s` (references in Gemini CLI shell
commands are refused anyway), desktop notifications from inside the sandbox
(not verified), and Gemini CLI's container sandboxes (Docker, Podman: not
tested).

## Output protocol (observed)

- `BeforeTool` blocks with `{"decision": "deny", "reason": "…"}` on stdout
  (exit 0), or exit 2 **with text on stderr**.
- Exit 2 with empty stderr, any other exit code, a crash and a timeout let the
  tool run. The firewall's wrapper therefore prints a line before `exit 2`, so a
  failure of the firewall or of Node blocks. A timeout (60 s as installed)
  still fails open; the firewall denies at its own deadline (20 s) first.
- Gemini CLI's hooks cannot put a question to the person in a way the firewall
  can use, so an action that needs a person is **held in the queue** and the
  agent is told the exact `launchsafe-firewall queue approve <id>` command.

## What its hooks cannot do

- No `ConfigChange` event: a change to `settings.json` is judged only when the
  agent makes it through a tool (result-checked), not when something else edits
  the file mid-session.
- Secrets in tool output are not redacted (no output replacement for built-in tools).
- Subagents (`invoke_agent`) are not reported as sessions; their tool calls
  arrive with the parent's `session_id` (captured), so their taint is the
  session's, with no linkage needed.
- A tool call Gemini CLI rejects before the hook (a path outside the workspace,
  an unknown tool) never reaches the firewall, and never runs either.
- Unattended runs are detected from the process (`gemini -p`, `--yolo`,
  `--approval-mode yolo`); another agent starting `gemini --yolo` is also
  caught by FW-AGENT-BYPASS. Gemini CLI tells its hooks nothing about its mode
  (the event has no such field, and the hook's environment adds only
  `GEMINI_PROJECT_DIR`, `GEMINI_CWD`, `GEMINI_SESSION_ID`, `GEMINI_PLANS_DIR`
  and `CLAUDE_PROJECT_DIR`, captured), so the command line is the only
  source. Up to four ancestors are read, from `/proc` on Linux (no `ps`
  needed, so a minimal image works) and with `ps` on macOS. On macOS `/bin/ps`
  is setuid, and inside a seatbelt sandbox it fails with "Operation not
  permitted": under Gemini CLI's own `-s` and under any `sandbox-exec`
  wrapper (captured; a wrapper can hide `-p` this way, so its sessions would
  be taken as attended). There the firewall falls back to
  `pgrep`, which is not setuid: `pgrep -a -l -f gemini` lists the matching
  processes including pgrep's own ancestors, `pgrep -l -f gemini` without
  them, and the difference is the ancestors
  (`test/fixtures/gemini-0.63.0-ancestry-*.json`). When no source can be read,
  the session is treated as unattended. A result from a process that was read
  is cached per session; this one is not, so the next hook reads again.
- Gemini CLI's own sandbox (`-s`) needs the firewall's seatbelt profile; see
  the next section.
