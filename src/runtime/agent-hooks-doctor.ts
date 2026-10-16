/**
 * Doctor's section for each other agent (Codex, Gemini CLI, Cursor): whether
 * the agent is on this machine, whether the firewall's hooks are in its
 * settings (present, first, fail-closed, not switched off), its managed
 * deployment, its own sandbox settings, the version the adapter was tested
 * with, and what the agent's hooks cannot see.
 */

import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { adapterFor } from "../adapters/index.js";
import { codexHome, codexMatcherProblems, tomlTopLevel } from "../adapters/codex.js";
import { geminiHome, geminiSystemSettings } from "../adapters/gemini.js";
import { CURSOR_ENTERPRISE_HOOKS, cursorDisabledBy, cursorHome } from "../adapters/cursor.js";
import type { AgentAdapter } from "../adapters/types.js";
import type { Check } from "./doctor.js";
import { readText } from "./fsutil.js";
import { inspectSettings, MARKER, readRecords } from "./install.js";
import { trustStatus } from "./codex-trust.js";
import type { Layout } from "./layout.js";
import { own } from "../own.js";
import { hookEntries } from "../engine/settings.js";
import { findGeminiBundle, seatbeltChecks } from "./gemini-seatbelt.js";

export interface AgentDoctorOptions {
  home: string;
  platform: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  /** Finds an agent's binary on PATH (tests inject; the default asks the shell). */
  findBinary?: (name: string) => string | null;
  /** The agent's version (tests inject; the default runs `<bin> --version`). */
  version?: (bin: string) => string | null;
}

function onPath(name: string): string | null {
  try {
    const p = execFileSync("sh", ["-c", `command -v ${name}`], { encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"] }).trim();
    return p === "" ? null : p;
  } catch {
    return null;
  }
}

function versionOf(bin: string): string | null {
  try {
    return /(\d+\.\d+\.\d+)/.exec(execFileSync(bin, ["--version"], { encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "ignore"] }))?.[1] ?? null;
  } catch {
    return null;
  }
}

function cmp(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** M10: Cursor steps whose firewall entry carries a matcher other than "*" (or empty), so it does not see every call. */
export function cursorNarrowed(path: string): string[] {
  let doc: unknown;
  try {
    doc = JSON.parse(readText(path) ?? "null");
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const { event, entry, command } of hookEntries(doc)) {
    if (event !== "beforeMCPExecution" && event !== "beforeReadFile") continue;
    if (!command.includes(MARKER)) continue;
    const m = entry.matcher;
    if (m !== undefined && m !== "" && m !== "*" && !out.includes(event)) out.push(event);
  }
  return out;
}

/** Whether the firewall's hooks are in each settings file install recorded for this agent (present, fail-closed, not switched off, first). */
export function hookChecks(l: Layout, a: AgentAdapter, label: string): Check[] {
  const out: Check[] = [];
  let records: ReturnType<typeof readRecords> = [];
  try {
    records = readRecords(l).filter((r) => (r.agent ?? "claude") === a.id && r.scope !== "managed");
  } catch {
    return [];
  }
  for (const r of records) {
    const name = `${label} hooks (${r.scope})`;
    let st: ReturnType<typeof inspectSettings>;
    try {
      st = inspectSettings(r.path, a.settings);
    } catch {
      out.push({ name, status: "fail", detail: `${r.path} cannot be read: run launchsafe-firewall install --agent ${a.id} --scope ${r.scope}` });
      continue;
    }
    const ev = a.settings.events;
    const missing = ev.filter((e) => !own(st.events, e)?.ours);
    const open = ev.filter((e) => own(st.events, e)?.ours && !own(st.events, e)?.failClosed);
    const notFirst = ev.filter((e) => own(st.events, e)?.ours && !own(st.events, e)?.first);
    // M10: Cursor decides an MCP call only at beforeMCPExecution (preToolUse does not name the server) and hands a
    // read's content over at beforeReadFile: the firewall's entries there must exist and match every call.
    const narrowed = a.id === "cursor" ? cursorNarrowed(r.path) : [];
    if (missing.length > 0) out.push({ name, status: "fail", detail: `missing for ${missing.join(", ")} in ${r.path}: run launchsafe-firewall install --agent ${a.id} --scope ${r.scope}` });
    else if (narrowed.length > 0) out.push({ name, status: "fail", detail: `${r.path}: the firewall's ${narrowed.join(", ")} entr${narrowed.length === 1 ? "y has" : "ies have"} a matcher, so some MCP calls or file reads skip it: run launchsafe-firewall install --agent cursor --scope ${r.scope}` });
    else if (open.length > 0) out.push({ name, status: "fail", detail: `${a.settings.failClosedEntry !== undefined ? "failClosed: true" : "the fail-closed wrapper (|| exit 2)"} is missing for ${open.join(", ")}: run launchsafe-firewall install --agent ${a.id} --scope ${r.scope}` });
    else if (st.disabledBy.length > 0) out.push({ name, status: "fail", detail: `${r.path}: ${st.disabledBy.join("; ")}, so ${a.settings.label} runs no hooks: run launchsafe-firewall install --agent ${a.id} --scope ${r.scope}` });
    else if (notFirst.length > 0) out.push({ name, status: "warn", detail: `not first for ${notFirst.join(", ")} in ${r.path}; another hook runs before the firewall` });
    else out.push({ name, status: "ok", detail: `${r.path}: all ${ev.length} events, first in order, exit-2 wrapper present (an agent that runs the tool when a hook times out is not covered: docs/limitations.md)` });
  }
  return out;
}

/**
 * Codex runs a hook only once the person trusted it, and skips an untrusted or changed one silently
 * (captured, 0.162.1). install records the trust of the firewall's hooks; this checks that the recorded
 * hash still matches each hook as written (src/runtime/codex-trust.ts).
 */
function codexTrust(l: Layout, config: string | null): Check[] {
  const out: Check[] = [];
  let records: ReturnType<typeof readRecords> = [];
  try {
    records = readRecords(l).filter((r) => r.agent === "codex" && r.scope !== "managed");
  } catch {
    return [];
  }
  for (const r of records) {
    let settings: Record<string, unknown> | null = null;
    try {
      settings = JSON.parse(readText(r.path) ?? "null") as Record<string, unknown> | null;
    } catch {
      settings = null;
    }
    const st = trustStatus(config, r.path, settings);
    const bad = [...st.untrusted.map((e) => `${e} (not trusted)`), ...st.modified.map((e) => `${e} (changed since it was trusted)`)];
    if (bad.length > 0) out.push({ name: `Codex hook trust (${r.scope})`, status: "fail", detail: `Codex silently skips these firewall hooks in ${r.path}: ${bad.join(", ")}. Run launchsafe-firewall install --agent codex --scope ${r.scope} again (it records their trust), or trust them in Codex with /hooks` });
    else if (st.trusted.length > 0) out.push({ name: `Codex hook trust (${r.scope})`, status: "ok", detail: `trust recorded for ${st.trusted.join(", ")}, matching the hooks as written` });
    const matched = codexMatcherProblems(settings);
    if (matched.length > 0) out.push({ name: `Codex prompt hook (${r.scope})`, status: "fail", detail: `Codex skips a ${matched.join(" or ")} group that has a matcher, so the firewall never sees the prompt (no task scope, no destinations you named) in ${r.path}. Run launchsafe-firewall install --agent codex --scope ${r.scope} again (it writes those groups without a matcher)` });
  }
  return out;
}

function codexExtras(l: Layout, home: string, env: NodeJS.ProcessEnv, platform: NodeJS.Platform): Check[] {
  const out: Check[] = [];
  const managed = adapterFor("codex").settings.managedPaths[platform];
  const req = managed !== undefined ? readText(managed) : null;
  if (req !== null && req.includes(MARKER)) {
    if (/^\s*\[\[hooks\.(?:UserPromptSubmit|Stop)\]\]\s*\n\s*matcher\s*=/m.test(req)) out.push({ name: "Codex managed prompt hook", status: "fail", detail: `${managed} gives the firewall's UserPromptSubmit hook a matcher, which Codex skips: print the snippet again with launchsafe-firewall install --managed --agent codex --print` });
    out.push(/^\s*allow_managed_hooks_only\s*=\s*true/m.test(req) ? { name: "Codex managed hooks", status: "ok", detail: `${managed} registers the firewall and allows managed hooks only` } : { name: "Codex managed hooks", status: "warn", detail: `${managed} registers the firewall; add allow_managed_hooks_only = true so no other hook runs ahead of it` });
  } else out.push({ name: "Codex managed hooks", status: "warn", detail: `recommended: deploy the hooks in ${managed ?? "requirements.toml"} so no user or project setting can remove them: launchsafe-firewall install --managed --agent codex --lock-other-hooks` });
  const config = readText(join(codexHome(env, home), "config.toml"));
  out.push(...codexTrust(l, config));
  // A project's or the user's [features] hooks = false: src/runtime/hook-bypass.ts (doctor and doctor --ci).
  const sandbox = tomlTopLevel(config, "sandbox_mode");
  if (sandbox === "danger-full-access") out.push({ name: "Codex sandbox", status: "warn", detail: 'config.toml sets sandbox_mode = "danger-full-access": commands that run are not confined; use "workspace-write" alongside the firewall' });
  else out.push({ name: "Codex sandbox", status: "ok", detail: `sandbox_mode ${sandbox ?? "default (workspace-write in a trusted folder, read-only otherwise)"}` });
  if (config !== null && /^\s*network_access\s*=\s*true/m.test(config)) out.push({ name: "Codex network", status: "warn", detail: "config.toml turns network access on for sandboxed commands; the firewall still judges each command, but the sandbox no longer blocks the network" });
  if (tomlTopLevel(config, "approval_policy") === "never") out.push({ name: "Codex approvals", status: "warn", detail: 'config.toml sets approval_policy = "never": Codex asks nothing, so the firewall treats its sessions as unattended (held actions wait in the queue)' });
  return out;
}

function geminiExtras(l: Layout, home: string, env: NodeJS.ProcessEnv, platform: NodeJS.Platform, projectDir: string, bin: string | null): Check[] {
  const out: Check[] = [];
  // A project's hooksConfig switching the user's hooks off: src/runtime/hook-bypass.ts (doctor and doctor --ci).
  const sys = geminiSystemSettings(env, platform);
  const text = sys !== undefined ? readText(sys) : null;
  if (sys !== undefined && text !== null && text.includes(MARKER)) {
    let rootOwned = false;
    try {
      rootOwned = statSync(dirname(sys)).uid === 0;
    } catch {
      rootOwned = false;
    }
    out.push(rootOwned ? { name: "Gemini CLI system settings", status: "ok", detail: `${sys} registers the firewall; system settings override user and project settings` } : { name: "Gemini CLI system settings", status: "fail", detail: `${sys} registers the firewall, but its directory is not owned by root, so Gemini CLI skips the file ("not owned by root")` });
  } else out.push({ name: "Gemini CLI system settings", status: "warn", detail: `recommended: deploy the hooks in ${sys ?? "the system settings file"} (in a root-owned directory; overrides user and project settings): launchsafe-firewall install --managed --agent gemini` });
  out.push({ name: "Gemini CLI folder trust", status: "warn", detail: "Gemini CLI skips every hook (user and system ones too) in a folder it does not trust: trust the folders you work in" });
  out.push(...seatbeltChecks(l, { home, env, platform, projectDir, bundle: platform === "darwin" && bin !== null ? findGeminiBundle({ find: () => bin }) : null }));
  return out;
}

/**
 * Cursor (read from cursor-agent 2026.10.01): it drops a hooks.json whole on any validation error and
 * refuses one reached through a symlink; it runs a project's hooks only in a trusted workspace, and its
 * cloud agents run them where this machine's paths do not exist; the enterprise file runs everywhere.
 * It also runs the firewall's Claude Code hooks (third-party import), which defer to these.
 */
function cursorExtras(l: Layout, home: string, platform: NodeJS.Platform, projectDir: string): Check[] {
  const out: Check[] = [];
  let records: ReturnType<typeof readRecords> = [];
  try {
    records = readRecords(l);
  } catch {
    records = [];
  }
  for (const r of records.filter((x) => x.agent === "cursor" && x.scope !== "managed")) {
    try {
      if (lstatSync(r.path).isSymbolicLink()) out.push({ name: `Cursor hooks file (${r.scope})`, status: "fail", detail: `${r.path} is a symlink, and Cursor refuses to load a hooks file through one: replace it with the file itself` });
    } catch {
      // A missing file is reported by the hooks check.
    }
    if (r.scope === "project") out.push({ name: "Cursor project hooks", status: "warn", detail: `${r.path}: Cursor runs a project's hooks only in a trusted workspace, and its cloud agents run them where this machine's node and firewall do not exist (fail-closed, so every action there is blocked). Prefer launchsafe-firewall install --agent cursor --scope user` });
  }
  const project = join(projectDir, ".cursor", "hooks.json");
  try {
    const text = readText(project);
    const off = text !== null && !records.some((r) => r.path === project) ? cursorDisabledBy(JSON.parse(text) as Record<string, unknown>) : [];
    if (off.length > 0) out.push({ name: "Cursor project hooks file", status: "warn", detail: `${project}: ${off.join("; ")} (only this file's hooks are dropped; the firewall's are in another file)` });
  } catch {
    // Not JSON: Cursor reports it in its Hooks output channel.
  }
  const ent = CURSOR_ENTERPRISE_HOOKS[platform];
  const entText = ent !== undefined ? readText(ent) : null;
  if (ent !== undefined && entText !== null && entText.includes(MARKER)) out.push({ name: "Cursor enterprise hooks", status: "ok", detail: `${ent} registers the firewall; Cursor runs it in every workspace, and a deny from any hook wins` });
  else out.push({ name: "Cursor enterprise hooks", status: "warn", detail: `recommended: deploy the hooks in ${ent ?? "Cursor's enterprise hooks.json"} (MDM) so they run in every workspace: launchsafe-firewall install --managed --agent cursor` });
  try {
    const cfg = JSON.parse(readText(join(cursorHome(home), "cli-config.json")) ?? "{}") as { approvalMode?: unknown; sandbox?: { mode?: unknown } };
    if (cfg.approvalMode === "unrestricted") out.push({ name: "Cursor approvals", status: "warn", detail: 'cli-config.json sets approvalMode "unrestricted" (Run Everything): Cursor asks nothing, so the firewall treats its CLI sessions as unattended (held actions wait in the queue)' });
    if (cfg.sandbox?.mode !== "enabled") out.push({ name: "Cursor sandbox", status: "warn", detail: `cli-config.json sandbox.mode is ${typeof cfg.sandbox?.mode === "string" ? `"${cfg.sandbox.mode}"` : "not set"}: commands that run are not confined. Cursor's hooks cannot see Tab edits, a shell's typed input or computer use; turn its sandbox on (sandbox.mode "enabled") alongside the firewall` });
  } catch {
    // An unreadable config is Cursor's to report.
  }
  if (records.some((r) => (r.agent ?? "claude") === "claude" && r.scope !== "managed") && !records.some((r) => r.agent === "cursor")) out.push({ name: "Cursor and the Claude Code hooks", status: "warn", detail: "Cursor runs the firewall's Claude Code hooks too (third-party import), but only for preToolUse, postToolUse, beforeSubmitPrompt and sessionStart, and an MCP call arrives there without its server: run launchsafe-firewall install --agent cursor" });
  return out;
}

/** Doctor's checks for Codex, Gemini CLI and Cursor. An agent that is neither on this machine nor installed gets no lines. */
export function otherAgentChecks(l: Layout, o: AgentDoctorOptions & { projectDir?: string }): Check[] {
  const projectDir = o.projectDir ?? process.cwd();
  const env = o.env ?? process.env;
  const find = o.findBinary ?? onPath;
  const version = o.version ?? versionOf;
  const out: Check[] = [];
  for (const id of ["codex", "gemini", "cursor"] as const) {
    const a = adapterFor(id);
    const label = a.settings.label;
    const configDir = id === "codex" ? codexHome(env, o.home) : id === "gemini" ? geminiHome(env, o.home) : cursorHome(o.home);
    const bin = id === "cursor" ? (find("cursor-agent") ?? find("cursor")) : find(id);
    const hooks = hookChecks(l, a, label);
    const present = bin !== null || existsSync(configDir);
    if (!present && hooks.length === 0) continue;
    if (hooks.length === 0) out.push({ name: `${label} hooks`, status: "fail", detail: `${label} is on this machine (${bin ?? configDir}) but the firewall's hooks are not in its settings, so it runs unprotected: run launchsafe-firewall install --agent ${id}` });
    else out.push(...hooks);
    out.push(...(id === "codex" ? codexExtras(l, o.home, env, o.platform) : id === "gemini" ? geminiExtras(l, o.home, env, o.platform, projectDir, bin) : cursorExtras(l, o.home, o.platform, projectDir)));
    // The IDE's `cursor` command numbers its versions differently from the CLI the adapter was read from.
    const v = bin !== null && !(id === "cursor" && !/cursor-agent$/.test(bin)) ? version(bin) : null;
    if (v === null) out.push({ name: label, status: bin === null ? "warn" : "warn", detail: `${bin === null ? "not found on PATH" : "version unknown"}; the adapter was tested with ${a.testedVersion}` });
    else if (cmp(v, a.testedVersion) > 0) out.push({ name: label, status: "warn", detail: `${v} (tested with ${a.testedVersion}); newer versions were not tested, and newer hook fields or tools are not known yet. Versions older than the tested one were not tested either` });
    else out.push({ name: label, status: "ok", detail: `${v} (tested with ${a.testedVersion})` });
    const gaps = a.coverage.filter((c) => c.status !== "yes");
    out.push({ name: `${label} coverage`, status: "warn", detail: `what its hooks cannot give the firewall: ${gaps.map((c) => `${c.capability.toLowerCase()} (${c.detail})`).join("; ")}` });
  }
  return out;
}
