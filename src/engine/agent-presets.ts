/**
 * `run --agent claude|codex|gemini` (docs/run.md, "Agent presets") and the OpenShell policy generator
 * (docs/sandboxes.md): what each coding agent needs from the network, and nothing else. Pure data.
 *
 * Only the model API (and, for Codex and Gemini CLI, the sign-in back ends their default logins call) is
 * listed: every other host still comes from your policy's fetchAllowHosts and sendAllowHosts. The hosts are
 * exact names ("=host" in the firewall's syntax), never a wildcard, and are added as send hosts for the run
 * only (without byte budgets: the whole conversation goes to the model API on every turn). Those hosts are
 * an unjudged, unbudgeted way out: whatever the agent read can leave in a model request.
 */

export type PresetAgent = "claude" | "codex" | "gemini";

export interface AgentPreset {
  agent: PresetAgent;
  /** The agent's own name, for messages. */
  label: string;
  /** The agent's program (run notes a preset whose command is something else). */
  program: string;
  /** Hosts it sends to for its model API and sign-in (firewall syntax, exact). */
  sendHosts: readonly string[];
  /** Variables the preset sets in the child's environment (each documented by the agent). */
  env: Readonly<Record<string, string>>;
  /**
   * Where its credentials and history live. Inside run it is read-only (the firewall's hooks are registered
   * there) but not unreadable: the agent needs its credentials (~/.claude/.credentials.json on Linux; on
   * macOS Claude Code keeps them in the keychain, which run blocks unless --allow-keychain; ~/.codex/auth.json;
   * ~/.gemini/oauth_creds.json), so every program the run starts can read them too.
   */
  stateDir: string;
}

export const AGENT_PRESETS: Readonly<Record<PresetAgent, AgentPreset>> = {
  claude: {
    agent: "claude",
    label: "Claude Code",
    program: "claude",
    sendHosts: ["=api.anthropic.com"],
    // Claude Code's documented switches: no telemetry, error reporting or update checks (hosts run would refuse anyway).
    env: { CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1", DISABLE_AUTOUPDATER: "1" },
    stateDir: "~/.claude",
  },
  codex: {
    agent: "codex",
    label: "Codex CLI",
    program: "codex",
    // The OpenAI API (an API key), and ChatGPT's back end and sign-in (a ChatGPT login).
    sendHosts: ["=api.openai.com", "=chatgpt.com", "=auth.openai.com"],
    env: {},
    stateDir: "~/.codex",
  },
  gemini: {
    agent: "gemini",
    label: "Gemini CLI",
    program: "gemini",
    // The Gemini API (an API key), Code Assist (a Google login) and Google's token endpoint.
    sendHosts: ["=generativelanguage.googleapis.com", "=cloudcode-pa.googleapis.com", "=oauth2.googleapis.com"],
    env: {},
    stateDir: "~/.gemini",
  },
};

export const PRESET_AGENTS: readonly PresetAgent[] = ["claude", "codex", "gemini"];

export function isPresetAgent(s: string): s is PresetAgent {
  return (PRESET_AGENTS as readonly string[]).includes(s);
}

/** The bare host names of a preset's send hosts. */
export function presetHostNames(p: AgentPreset): string[] {
  return p.sendHosts.map((h) => h.replace(/^=/, ""));
}
