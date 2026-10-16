# Claude Code

What `install` writes for Claude Code, and what is and is not verified. The
adapter is `src/adapters/claude.ts`; the policy is the same engine every agent
uses. Tested version: **Claude Code 2.1.289**; `onFailure: "block"` is honoured
from 2.1.295 (documented, see below).

## Install

```sh
launchsafe-firewall install                    # ~/.claude/settings.json
launchsafe-firewall install --scope project    # <project>/.claude/settings.json
launchsafe-firewall install --scope local      # <project>/.claude/settings.local.json
launchsafe-firewall install --managed --print  # the managed settings document
```

Managed settings go to `/Library/Application Support/ClaudeCode/managed-settings.json`
(macOS) or `/etc/claude-code/managed-settings.json` (Linux);
`--lock-other-hooks` adds `allowManagedHooksOnly`.

`install` registers six events: `PreToolUse`, `PostToolUse`,
`PostToolUseFailure`, `UserPromptSubmit`, `SessionStart` and `ConfigChange`
(`HOOK_EVENTS` in `src/engine/settings.ts`). The three tool events get matcher
`*`; the others have none. Each entry has:

- `timeout: 600` (seconds; the firewall answers or denies at its own 20 s
  deadline first),
- `onFailure: "block"`, so a hook that fails or times out blocks instead of
  letting the action run (honoured from Claude Code 2.1.295; `doctor` warns on
  older versions),
- a command ending in `|| exit 2`, so a crash of node itself blocks.

The command carries the same pinned prefix as the other agents
(`LAUNCHSAFE_FIREWALL_HOOK=1`, the data directory, `HOME`, test markers and
cleared Node loader variables).

## Not verified

- Live captures exist only for the MCP `PreToolUse` event
  (`test/fixtures/claude-2.1.289-pretooluse-mcp.json`), the sandbox settings
  schema (read from the binary, `claude-2.1.289-sandbox-schema.json`) and the
  desktop app's own tool events (`claude-desktop-2.1.289-*`). The other events
  follow Claude Code's hooks documentation.
- `updatedToolOutput`, `updatedInput`, `onFailure` and bypass mode are from the
  documentation, not captured ([overview.md](overview.md#not-verified)).
- No version at or after 2.1.295 was captured, so `onFailure: "block"` being
  honoured is not seen.
