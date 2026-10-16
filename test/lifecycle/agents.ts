/** What each agent's install is documented to write (docs/agents/*.md, docs/cli.md), and a realistic user file for it. */
import { CLI, MARKER, type Agent, type Lab } from "./lab.js";

type Json = Record<string, unknown>;

export interface AgentSpec {
  id: Agent;
  label: string;
  events: readonly string[];
  /** Events whose group carries a tool matcher (the group shape agents), "*" meaning every tool. */
  matched: readonly string[];
  flat: boolean;
  timeout: number;
  /** The text the installed command ends with. */
  tail: RegExp;
  /** The user's own settings file before the firewall: unrelated keys, and hooks of their own, one of them on an event the firewall also uses. */
  user(): Json;
  /** The top-level keys install adds besides `hooks` (the documented enable flags), removed before comparing with the original. */
  enableKeys: string[];
  /** Removes what install documents it adds besides the firewall's own entries. */
  stripEnable(doc: Json): Json;
}

const userGroup = (matcher: string | undefined, command: string): Json => ({ ...(matcher !== undefined ? { matcher } : {}), hooks: [{ type: "command", command, timeout: 10 }] });

export const SPECS: Record<Agent, AgentSpec> = {
  claude: {
    id: "claude",
    label: "Claude Code",
    events: ["PreToolUse", "PostToolUse", "PostToolUseFailure", "UserPromptSubmit", "SessionStart", "ConfigChange"],
    matched: ["PreToolUse", "PostToolUse", "PostToolUseFailure"],
    flat: false,
    timeout: 600,
    tail: / hook \|\| exit 2$/,
    user: () => ({
      model: "opus",
      permissions: { allow: ["Bash(ls:*)", "Read(~/notes/**)"], deny: ["Bash(rm -rf:*)"] },
      env: { EDITOR: "nvim", "WEIRD KEY": "with \"quotes\" and unicode é中" },
      hooks: {
        PreToolUse: [userGroup("Bash", "/usr/local/bin/my-bash-guard"), userGroup("Write|Edit", "/usr/local/bin/my-write-guard")],
        Stop: [userGroup(undefined, "/usr/local/bin/notify-done")],
        Notification: [userGroup(undefined, "say done")],
      },
      statusLine: { type: "command", command: "date" },
    }),
    enableKeys: [],
    stripEnable: (d) => d,
  },
  codex: {
    id: "codex",
    label: "Codex",
    events: ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"],
    // Codex 0.162.1 skips a UserPromptSubmit group with any matcher (test/fixtures/codex-0.162.1-hook-matchers.json).
    matched: ["PreToolUse", "PostToolUse"],
    flat: false,
    timeout: 600,
    tail: / hook --agent codex \|\| \{ echo 'LaunchSafe Firewall: the hook failed, so the action was blocked' >&2; exit 2; \}$/,
    user: () => ({
      hooks: {
        PreToolUse: [userGroup("shell", "/usr/local/bin/codex-guard")],
        Stop: [userGroup(undefined, "/usr/local/bin/codex-done")],
      },
    }),
    enableKeys: [],
    stripEnable: (d) => d,
  },
  gemini: {
    id: "gemini",
    label: "Gemini CLI",
    events: ["BeforeTool", "AfterTool", "BeforeAgent", "SessionStart"],
    matched: ["BeforeTool", "AfterTool"],
    flat: false,
    timeout: 60000,
    tail: / hook --agent gemini \|\| \{ echo 'LaunchSafe Firewall: the hook failed, so the action was blocked' >&2; exit 2; \}$/,
    user: () => ({
      theme: "dark",
      general: { vimMode: true, previewFeatures: false },
      mcpServers: { files: { command: "npx", args: ["-y", "some-mcp"], env: { TOKEN: "t0k" } } },
      hooks: {
        BeforeTool: [{ matcher: "run_shell_command", hooks: [{ name: "mine", type: "command", command: "/usr/local/bin/gem-guard", timeout: 5000 }] }],
        AfterAgent: [{ hooks: [{ name: "mine2", type: "command", command: "/usr/local/bin/gem-after" }] }],
      },
    }),
    enableKeys: ["hooksConfig"],
    stripEnable: (d) => {
      const c = { ...d };
      const cfg = { ...((c.hooksConfig as Json | undefined) ?? {}) };
      delete cfg.enabled;
      if (Object.keys(cfg).length === 0) delete c.hooksConfig;
      else c.hooksConfig = cfg;
      return c;
    },
  },
  cursor: {
    id: "cursor",
    label: "Cursor",
    // postToolUseFailure joined CURSOR_HOOK_EVENTS: install now registers it so a failed tool's result is read and counted.
    events: ["preToolUse", "postToolUse", "postToolUseFailure", "beforeMCPExecution", "afterMCPExecution", "beforeReadFile", "beforeSubmitPrompt", "sessionStart", "subagentStart", "subagentStop"],
    matched: [],
    flat: true,
    timeout: 30,
    tail: / hook --agent cursor$/,
    user: () => ({
      version: 1,
      hooks: {
        preToolUse: [{ command: "/usr/local/bin/cursor-guard", timeout: 10 }],
        stop: [{ command: "/usr/local/bin/cursor-stop" }],
      },
    }),
    enableKeys: [],
    stripEnable: (d) => d,
  },
};

/** The user's file exactly as an editor would leave it: 2-space JSON and a trailing newline. */
export function userText(a: Agent): string {
  return `${JSON.stringify(SPECS[a].user(), null, 2)}\n`;
}

/** The Codex config.toml the person already has (Codex's own settings and a trust record of their own hook). */
export const CODEX_TOML = 'model = "gpt-5.1"\napproval_policy = "on-request"\n\n[projects."/Users/dev/work"]\ntrust_level = "trusted"\n\n[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "docs-mcp"]\n';

/** Every firewall entry in a settings document: [event, entry]. */
export function ourEntries(doc: Json): [string, Json][] {
  const out: [string, Json][] = [];
  const hooks = (doc.hooks ?? {}) as Record<string, unknown>;
  for (const [ev, groups] of Object.entries(hooks)) {
    if (!Array.isArray(groups)) continue;
    for (const g of groups as Json[]) {
      const list = Array.isArray(g.hooks) ? (g.hooks as Json[]) : [g];
      for (const h of list) if (typeof h.command === "string" && h.command.includes(MARKER)) out.push([ev, h]);
    }
  }
  return out;
}

/** The document with every firewall entry (and a group left empty by that) removed. */
export function withoutOurs(doc: Json): Json {
  const copy = JSON.parse(JSON.stringify(doc)) as Json;
  const hooks = copy.hooks as Record<string, Json[]> | undefined;
  if (hooks === undefined) return copy;
  for (const ev of Object.keys(hooks)) {
    hooks[ev] = (hooks[ev] as Json[]).filter((g) => !(Array.isArray(g.hooks) ? (g.hooks as Json[]).some((h) => String(h.command ?? "").includes(MARKER)) : String(g.command ?? "").includes(MARKER)));
    if ((hooks[ev] as Json[]).length === 0) delete hooks[ev];
  }
  if (Object.keys(hooks).length === 0) delete copy.hooks;
  return copy;
}

export function seed(l: Lab, a: Agent, write: (p: string, c: string) => void): void {
  write(l.file(a), userText(a));
  if (a === "codex") write(`${l.home}/.codex/config.toml`, CODEX_TOML);
}

export { CLI };
