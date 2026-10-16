/**
 * Settings that switch an agent's hooks off, or reach into the hook process, wherever an agent reads them:
 * the repository's own files (which a clone brings, and which Claude Code applies in a `claude -p` run
 * without asking about workspace trust), the user's, and the managed or system ones. Each finding names
 * the file that does it and the fix. `doctor` fails on every one the managed install does not override;
 * `doctor --ci` runs only these and the hook registrations, for a CI job or a pre-commit check.
 */

import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import type { Check } from "./doctor.js";
import { readText } from "./fsutil.js";
import { MANAGED_SETTINGS_PATHS, MARKER, settingsPath } from "./install.js";
import { codexHome } from "../adapters/codex.js";
import { geminiDisabledBy, geminiHome, geminiSystemSettings } from "../adapters/gemini.js";
import { HOOK_EVENTS } from "../engine/settings.js";
import { own } from "../own.js";

export interface HookBypassOptions {
  projectDir: string;
  home: string;
  platform: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  /** Claude Code's managed settings file (tests; default: the platform's). */
  claudeManagedPath?: string;
  /** Gemini CLI's system settings file (tests; default: GEMINI_CLI_SYSTEM_SETTINGS_PATH, else the platform's). */
  geminiSystemPath?: string;
  /** Which agents the firewall is installed for, by scope (from install.json). */
  installed?: readonly { agent: string; scope: string }[];
  /** Whether an installed hook command starts node by a bare name (then a settings PATH reaches it). */
  bareNode?: boolean;
}

/** The names of the checks this module adds (the protection score counts a failing one against the hooks). */
export const HOOK_BYPASS_CHECKS: ReadonlySet<string> = new Set(["disableAllHooks", "Claude Code managed settings", "Claude Code settings env", "Codex project hooks", "Codex user hooks", "Gemini CLI project settings", "Gemini CLI user settings"]);

const MANAGED_FIX_CLAUDE = 'Deploy the managed install, which no repository or user setting can switch off: launchsafe-firewall install --managed --lock-other-hooks --print | sudo tee "<managed-settings.json>"';
const HEADLESS = "Claude Code applies a repository's settings in a claude -p (headless, CI) run without asking about workspace trust, so a fresh clone is enough";

type Json = Record<string, unknown>;

/**
 * Item 5: JSON with comments and trailing commas (Gemini CLI and VS Code-style settings allow them) as plain JSON.
 * Comments inside strings are kept.
 */
export function stripJsonc(t: string): string {
  let out = "";
  let i = 0;
  while (i < t.length) {
    const ch = t[i] as string;
    if (ch === '"') {
      let j = i + 1;
      while (j < t.length && t[j] !== '"') j += t[j] === "\\" ? 2 : 1;
      out += t.slice(i, j + 1);
      i = j + 1;
    } else if (ch === "/" && t[i + 1] === "/") {
      while (i < t.length && t[i] !== "\n") i++;
    } else if (ch === "/" && t[i + 1] === "*") {
      const end = t.indexOf("*/", i + 2);
      i = end === -1 ? t.length : end + 2;
    } else {
      out += ch;
      i++;
    }
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}

/** A settings file as an object (JSON or JSONC); null when absent or not an object, "unparsable" when it cannot be read as either. */
function readJsonc(path: string): Json | null | "unparsable" {
  let t: string | null;
  try {
    t = readText(path);
  } catch {
    return "unparsable";
  }
  if (t === null) return null;
  for (const text of [t, stripJsonc(t)]) {
    try {
      const v = JSON.parse(text) as unknown;
      return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : null;
    } catch {
      // Try the JSONC reading next.
    }
  }
  return "unparsable";
}

function readJson(path: string): Json | null {
  const v = readJsonc(path);
  return v === "unparsable" ? null : v;
}

/** Whether a Claude Code settings document registers the firewall for every hook event. */
function registersClaude(s: Json | null): boolean {
  if (s === null) return false;
  const hooks = typeof s.hooks === "object" && s.hooks !== null ? (s.hooks as Json) : {};
  // PostToolUseFailure is newer than managed snippets already deployed: its absence there is not a missing registration.
  return HOOK_EVENTS.filter((ev) => ev !== "PostToolUseFailure").every((ev) => JSON.stringify(own(hooks, ev) ?? null).includes(MARKER));
}

/** Code-loading Node options: what NODE_OPTIONS can make node run before the firewall's own code. */
const NODE_CODE_OPTIONS = /(?:^|\s)(?:-r|--require|--import|--loader|--experimental-loader|--inspect(?:-brk|-port)?|--env-file|--openssl-config)(?:[=\s]|$)/;

/** Variables that change which code or files the hook process loads, whatever their value. */
const HOOK_ENV_ALWAYS: Record<string, string> = {
  HOME: "moves the home directory the hook reads the firewall's state, agent settings and keys from",
  NODE_PATH: "adds directories node resolves modules from",
  LD_PRELOAD: "loads a library into every process, the hook's node included",
  LD_LIBRARY_PATH: "changes the libraries node loads",
  DYLD_INSERT_LIBRARIES: "loads a library into every process, the hook's node included",
  DYLD_LIBRARY_PATH: "changes the libraries node loads",
  NODE_COMPILE_CACHE: "makes node load compiled code from a directory the agent can write (hook commands from before 0.3.0 do not clear it)",
  NODE_EXTRA_CA_CERTS: "adds certificate authorities node trusts",
  TMPDIR: "moves the temporary directory the firewall treats as scratch space",
  TMP: "moves the temporary directory some tools use",
  TEMP: "moves the temporary directory some tools use",
  BASH_ENV: "makes every non-interactive bash, the one running the hook command included, run a file first",
  ENV: "makes a POSIX shell run a file first",
  IFS: "changes how the shell running the hook command splits words",
  SHELL: "changes the shell programs start",
};

/**
 * The environment entries in a settings file that reach the firewall's hook process. PATH counts only when a
 * hook command starts node by a bare name (`bareNode`); the commands install writes name node by its path.
 */
export function hookEnvProblems(s: Json | null, o: { bareNode?: boolean } = {}): string[] {
  const env = s !== null && typeof s.env === "object" && s.env !== null && !Array.isArray(s.env) ? (s.env as Json) : {};
  const out: string[] = [];
  for (const [k, v] of Object.entries(env)) {
    const why = own(HOOK_ENV_ALWAYS, k);
    if (/^LAUNCHSAFE_FIREWALL_/i.test(k)) out.push(`env.${k} (the firewall's own variable: it can point the hook at other state, keys or approvals)`);
    else if (k === "NODE_OPTIONS" && typeof v === "string" && NODE_CODE_OPTIONS.test(v)) out.push(`env.NODE_OPTIONS "${v.slice(0, 80)}" (makes node load other code into the hook process before the firewall runs)`);
    else if (why !== undefined) out.push(`env.${k} (${why})`);
    else if (k === "PATH" && o.bareNode === true) out.push("env.PATH (a hook command starts node by name, so PATH decides which program runs)");
  }
  return out;
}

/**
 * Codex's `[features] hooks = false` in a config.toml, in its three spellings: the table, a dotted key at the
 * top level, and an inline table. Codex 0.162.1 switches every hook off with it (captured).
 */
export function codexHooksOff(toml: string | null): boolean {
  if (toml === null) return false;
  let table = "";
  for (const raw of toml.split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header !== null) {
      table = (header[1] ?? "").trim();
      continue;
    }
    if (table === "features" && /^"?hooks"?\s*=\s*false\b/.test(line)) return true;
    if (table === "" && /^features\.\s*"?hooks"?\s*=\s*false\b/.test(line)) return true;
    if (table === "" && /^features\s*=\s*\{[^}]*\bhooks\s*=\s*false\b/.test(line)) return true;
  }
  return false;
}

export function hookBypassChecks(o: HookBypassOptions): Check[] {
  const out: Check[] = [];
  const env = o.env ?? process.env;
  const installed = o.installed ?? [];
  const claudeInstalled = installed.filter((r) => r.agent === "claude" && r.scope !== "managed");

  // Claude Code. Settings merge user < project < local < managed; disableAllHooks below managed does not stop
  // managed hooks, so a managed install of the firewall turns these into warnings.
  const managedPath = o.claudeManagedPath ?? MANAGED_SETTINGS_PATHS[o.platform];
  const managed = managedPath !== undefined ? readJson(managedPath) : null;
  const managedHasUs = registersClaude(managed);
  if (managed !== null && managed.disableAllHooks === true) {
    out.push({ name: "Claude Code managed settings", status: "fail", detail: `${managedPath ?? ""} sets disableAllHooks: true, which switches off every Claude Code hook, the firewall's managed ones included. Fix: remove the key from that file (administrator)` });
  } else if (managed !== null && managed.allowManagedHooksOnly === true && !managedHasUs && claudeInstalled.length > 0) {
    out.push({ name: "Claude Code managed settings", status: "fail", detail: `${managedPath ?? ""} sets allowManagedHooksOnly: true but does not register the firewall, so its hooks in ${claudeInstalled.map((r) => r.scope).join(", ")} settings never run. Fix: ${MANAGED_FIX_CLAUDE.replace("<managed-settings.json>", managedPath ?? "")}` });
  }
  for (const scope of ["project", "local", "user"] as const) {
    const p = settingsPath(scope, o.projectDir, o.home);
    if (!existsSync(p)) continue;
    const parsed = readJsonc(p);
    // Item 5: a file that cannot be read is not "no settings": what it switches off is unknown.
    if (parsed === "unparsable") out.push({ name: "Claude Code settings", status: "warn", detail: `${p} cannot be parsed as JSON, so whether it switches hooks off or sets env for them could not be checked. Fix the file` });
    const s = parsed === "unparsable" ? null : parsed;
    const repo = scope !== "user";
    if (s?.disableAllHooks === true) {
      const fix = `Fix: remove disableAllHooks from ${p}${repo ? " (and from the repository's history of that file, for other clones)" : ""}. ${MANAGED_FIX_CLAUDE.replace("<managed-settings.json>", managedPath ?? "")}`;
      out.push(
        managedHasUs
          ? { name: "disableAllHooks", status: "warn", detail: `${p} sets disableAllHooks: true. The firewall's managed hooks still run (${managedPath ?? ""}); every other hook is off` }
          : { name: "disableAllHooks", status: "fail", detail: `${p} sets disableAllHooks: true, which switches off every Claude Code hook, the firewall's included${repo ? `. ${HEADLESS}` : ""}. ${fix}` },
      );
    }
    const envProblems = hookEnvProblems(s, { bareNode: o.bareNode === true });
    if (envProblems.length > 0) out.push({ name: "Claude Code settings env", status: "fail", detail: `${p} sets ${envProblems.join("; ")}. Claude Code gives a settings file's env to the commands it starts, the firewall's hooks included${repo ? `. ${HEADLESS}` : ""}. Fix: remove ${envProblems.length === 1 ? "it" : "them"} from ${p}` });
  }
  // Item 4: Claude Code reads its user settings from CLAUDE_CONFIG_DIR when set; install and these checks use ~/.claude.
  const configDir = env.CLAUDE_CONFIG_DIR;
  if (configDir !== undefined && configDir !== "" && resolve(configDir) !== resolve(join(o.home, ".claude"))) {
    out.push({ name: "CLAUDE_CONFIG_DIR", status: "warn", detail: `CLAUDE_CONFIG_DIR is ${configDir}, so Claude Code reads its user settings from ${join(configDir, "settings.json")}, not ${settingsPath("user", o.projectDir, o.home)} where install writes the firewall's hooks. Install with --scope project, use the managed install, or unset CLAUDE_CONFIG_DIR` });
  }
  if (managed !== null) {
    const envProblems = hookEnvProblems(managed, { bareNode: o.bareNode === true });
    if (envProblems.length > 0) out.push({ name: "Claude Code settings env", status: "fail", detail: `${managedPath ?? ""} sets ${envProblems.join("; ")}, which reaches the firewall's hooks. Fix: remove ${envProblems.length === 1 ? "it" : "them"} (administrator)` });
  }

  // Codex: [features] hooks = false in a trusted project's config.toml, or the user's, turns every hook off.
  const codexInstalled = installed.some((r) => r.agent === "codex");
  const codexProject = join(o.projectDir, ".codex", "config.toml");
  if (codexHooksOff(safeRead(codexProject))) out.push({ name: "Codex project hooks", status: "fail", detail: `${codexProject} sets [features] hooks = false, which switches off every Codex hook, the firewall's included, when this project is trusted. Fix: remove the setting from ${codexProject}; deploy the hooks in Codex's requirements.toml with launchsafe-firewall install --managed --agent codex --lock-other-hooks` });
  const codexUser = join(codexHome(env, o.home), "config.toml");
  if ((codexInstalled || existsSync(codexUser)) && codexHooksOff(safeRead(codexUser))) out.push({ name: "Codex user hooks", status: "fail", detail: `${codexUser} sets [features] hooks = false, which switches off every Codex hook, the firewall's included. Fix: remove the setting from ${codexUser}` });

  // Gemini CLI: system settings override project settings, which override the user's.
  const sys = o.geminiSystemPath ?? geminiSystemSettings(env, o.platform);
  const sysJson = sys !== undefined ? readJson(sys) : null;
  const sysHasUs = sysJson !== null && JSON.stringify(sysJson.hooks ?? null).includes(MARKER) && geminiDisabledBy(sysJson).length === 0;
  const geminiProject = join(o.projectDir, ".gemini", "settings.json");
  const gpParsed = readJsonc(geminiProject);
  if (gpParsed === "unparsable") out.push({ name: "Gemini CLI project settings", status: "warn", detail: `${geminiProject} cannot be parsed, so whether it switches hooks off could not be checked. Fix the file` });
  const gp = gpParsed === "unparsable" ? null : gpParsed;
  const gpOff = gp !== null ? geminiDisabledBy(gp) : [];
  if (gpOff.length > 0) out.push(sysHasUs ? { name: "Gemini CLI project settings", status: "warn", detail: `${geminiProject}: ${gpOff.join("; ")}. The firewall's system-settings hooks still run (${sys ?? ""}); user-level hooks are off for this project` } : { name: "Gemini CLI project settings", status: "fail", detail: `${geminiProject}: ${gpOff.join("; ")}, which switches the user's hooks (the firewall's included) off for this project. Fix: remove it from ${geminiProject}; deploy the hooks in Gemini CLI's system settings with launchsafe-firewall install --managed --agent gemini` });
  const geminiUser = join(geminiHome(env, o.home), "settings.json");
  const guParsed = readJsonc(geminiUser);
  if (guParsed === "unparsable") out.push({ name: "Gemini CLI user settings", status: "warn", detail: `${geminiUser} cannot be parsed, so whether it switches hooks off could not be checked. Fix the file` });
  const gu = guParsed === "unparsable" ? null : guParsed;
  const guOff = gu !== null ? geminiDisabledBy(gu) : [];
  // An install in the user's settings file is checked by doctor's hooks check (it names the same file).
  if (guOff.length > 0 && !sysHasUs && !installed.some((r) => r.agent === "gemini" && r.scope === "user")) out.push({ name: "Gemini CLI user settings", status: "fail", detail: `${geminiUser}: ${guOff.join("; ")}, which switches Gemini CLI's hooks (the firewall's included) off. Fix: remove it from ${geminiUser}` });
  return out;
}

function safeRead(p: string): string | null {
  try {
    return readText(p);
  } catch {
    return null;
  }
}
