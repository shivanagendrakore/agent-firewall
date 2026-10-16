/**
 * doctor's "agent sandbox" note (not scored): which coding agents on this machine would run with no
 * sandbox at all, and what to use (docs/run.md "Agent presets", docs/sandboxes.md).
 *
 * - An agent with the firewall's hooks keeps them: inside `run` its hooks cannot save their state and fail
 *   closed, so the note points at the agent's own sandbox (Claude Code's is checked by the "sandbox" entry,
 *   Codex's sandbox_mode, Gemini CLI's -s with the firewall's seatbelt profile) or an OpenShell sandbox with
 *   the firewall's middleware, where the hooks keep judging and OpenShell is the outer wall.
 * - An agent found on PATH without the firewall's hooks has neither: `run --agent <name>` is the cage.
 *
 * Read from configuration only: doctor cannot see how an agent is started (a `--yolo` or `-s` on its
 * command line), so the note says "as configured".
 */

import { join } from "node:path";
import { geminiHome } from "../adapters/gemini.js";
import { AGENT_PRESETS, PRESET_AGENTS, type PresetAgent } from "../engine/agent-presets.js";
import type { Check } from "./doctor.js";
import { readText } from "./fsutil.js";
import { sandboxByDefault } from "./gemini-seatbelt.js";

export interface AgentSandboxInput {
  home: string;
  env: NodeJS.ProcessEnv;
  projectDir: string;
  /** Agents whose hooks the install records list. */
  hooked: ReadonlySet<string>;
  /** Claude Code's own sandbox is on (sandboxChecks reads it). */
  claudeSandboxOn: boolean;
  findBinary: (name: string) => string | null;
}

/** Codex's sandbox_mode from config.toml (CODEX_HOME honoured), or null when unset. */
export function codexSandboxMode(env: NodeJS.ProcessEnv, home: string): string | null {
  const dir = env.CODEX_HOME !== undefined && env.CODEX_HOME !== "" ? env.CODEX_HOME : join(home, ".codex");
  const t = readText(join(dir, "config.toml"));
  if (t === null) return null;
  // Top-level keys only: stop at the first table header.
  const top = t.split(/^\s*\[/m)[0] ?? "";
  const m = /^\s*sandbox_mode\s*=\s*["']([^"']+)["']/m.exec(top);
  return m === null ? null : (m[1] as string);
}

/**
 * Whether this process carries the whole environment `run` gives its child, not just LAUNCHSAFE_FIREWALL_RUN
 * (which any shell can set): the run id's form, TMPDIR in the run's own lsfw-run- directory, and every proxy
 * variable pointing at the run's proxy on 127.0.0.1. Still only the environment: a hint, never proof of a sandbox.
 */
export function looksInsideRun(env: NodeJS.ProcessEnv): boolean {
  if (!/^run-\d{14}-[0-9a-f]{8}$/.test(env.LAUNCHSAFE_FIREWALL_RUN ?? "")) return false;
  if (!/\/lsfw-run-[^/]+\/?$/.test(env.TMPDIR ?? "")) return false;
  const proxy = env.HTTPS_PROXY ?? "";
  if (!/^http:\/\/127\.0\.0\.1:\d{1,5}$/.test(proxy)) return false;
  return env.HTTP_PROXY === proxy && env.ALL_PROXY === proxy && env.https_proxy === proxy && env.http_proxy === proxy && env.NODE_USE_ENV_PROXY === "1";
}

export function agentSandboxChecks(o: AgentSandboxInput): Check[] {
  const marked = (o.env.LAUNCHSAFE_FIREWALL_RUN ?? "") !== "";
  if (marked && looksInsideRun(o.env)) return [{ name: "agent sandbox", status: "ok", detail: "this doctor appears to run inside launchsafe-firewall run (its environment says so: the run id, the run's TMPDIR and proxy)" }];
  const notes: string[] = [];
  const own: Record<PresetAgent, () => string | null> = {
    claude: () => (o.claudeSandboxOn ? null : 'Claude Code: its own sandbox is off; "launchsafe-firewall doctor --fix" turns it on from your policy and keeps the hooks working'),
    codex: () => (codexSandboxMode(o.env, o.home) === "danger-full-access" ? 'Codex: sandbox_mode = "danger-full-access" in config.toml; use "workspace-write" (Codex\'s own sandbox keeps the hooks working)' : null),
    gemini: () => {
      const settings = [join(geminiHome(o.env, o.home), "settings.json"), join(o.projectDir, ".gemini", "settings.json")];
      return sandboxByDefault(o.env, settings) === null ? "Gemini CLI: no sandbox by default; on macOS \"launchsafe-firewall install --agent gemini --seatbelt permissive-open\", then start it with SEATBELT_PROFILE=launchsafe gemini -s" : null;
    },
  };
  for (const a of PRESET_AGENTS) {
    if (o.hooked.has(a)) {
      const n = own[a]();
      if (n !== null) notes.push(`${n}, or run it in an OpenShell sandbox with the firewall's middleware (docs/sandboxes.md)`);
    } else if (o.findBinary(AGENT_PRESETS[a].program) !== null) {
      notes.push(`${AGENT_PRESETS[a].label} is installed without the firewall's hooks and runs unconfined: start it with "launchsafe-firewall run --agent ${a}" (docs/run.md)`);
    }
  }
  const ignored = marked ? " (LAUNCHSAFE_FIREWALL_RUN is set, but the rest of run's environment is not, so it was ignored)" : "";
  if (notes.length === 0) return [{ name: "agent sandbox", status: "ok", detail: `every coding agent found here has a sandbox configured (or none was found)${ignored}` }];
  return [{ name: "agent sandbox", status: "warn", detail: `as configured, these agents run with no sandbox: ${notes.join("; ")}${ignored}` }];
}
