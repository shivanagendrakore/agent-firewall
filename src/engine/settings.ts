/**
 * Claude Code settings files are where the firewall's own hooks are
 * registered, so a change to one is judged by its result: the content the file
 * would have afterwards. A change is tampering (denied, whatever the session's
 * trust) when it would remove, alter or re-scope the firewall's hook entries
 * or their fail-closed wrapper, switch hooks off (disableAllHooks), change
 * which hooks may run (allowManagedHooksOnly), set the firewall's own
 * environment variables, or leave a registered file unparseable. A change
 * whose result cannot be computed (shell writes, copies, removals) is assumed
 * to be the worst case.
 */

import { sandboxViolations, type SandboxGuard } from "./sandbox.js";
import { stripBom } from "../bom.js";
import { own } from "../own.js";

export const MARKER = "LAUNCHSAFE_FIREWALL_HOOK=1";

/**
 * The fail-closed wrapper for agents other than Claude Code. Codex (captured, 0.162.1) blocks on exit 2
 * only when the hook also wrote to stderr: an exit 2 with empty stderr, any other exit code, and a
 * timeout let the tool run. So the wrapper always prints a line before exiting 2.
 */
export const LOUD_FAIL_CLOSED = "|| { echo 'LaunchSafe Firewall: the hook failed, so the action was blocked' >&2; exit 2; }";

/** Whether an installed hook command ends in a fail-closed wrapper (`|| exit 2`, or the loud form). */
export function isFailClosed(command: string): boolean {
  return /\|\|\s*exit 2\s*$/.test(command) || command.trimEnd().endsWith(LOUD_FAIL_CLOSED);
}
export const HOOK_EVENTS = ["PreToolUse", "PostToolUse", "PostToolUseFailure", "UserPromptSubmit", "SessionStart", "ConfigChange"] as const;

/** user/project/local settings, and the managed settings file and drop-ins. */
export function isClaudeSettingsFile(abs: string): boolean {
  return /\/\.claude\/settings(?:\.local)?\.json$/i.test(abs) || /\/managed-settings\.json$/i.test(abs) || /\/managed-settings\.d\/[^/]+\.json$/i.test(abs);
}

/**
 * The files other agents register hooks in. Codex: hooks.json (user ~/.codex or $CODEX_HOME, and a
 * project's .codex/), config.toml (which can carry hooks too) and the managed requirements.toml. Gemini
 * CLI: settings.json in ~/.gemini and a project's .gemini/, and the system settings and defaults files.
 */
export function isAgentHookSettingsFile(abs: string): boolean {
  return (
    isClaudeSettingsFile(abs) ||
    /\/\.codex\/(?:hooks\.json|config\.toml)$/i.test(abs) ||
    /\/codex\/(?:requirements|managed_config)\.toml$/i.test(abs) ||
    /\/\.gemini\/settings\.json$/i.test(abs) ||
    /\/(?:GeminiCli|gemini-cli)\/(?:settings|system-defaults)\.json$/i.test(abs) ||
    isCursorHooksFile(abs)
  );
}

/**
 * F13: a hook settings file by name, by location (the context's agent settings: $CODEX_HOME and the Gemini CLI
 * system path, which may be called anything) or because the firewall's install record registers it.
 */
export function isHookSettingsIn(ctx: { registeredSettings?: string[]; agentSettings?: string[] }, abs: string): boolean {
  if (isAgentHookSettingsFile(abs)) return true;
  // I1: case is folded on every platform (PROTECTION_FOLDS_CASE, canonical.ts), as the name patterns above already are.
  const lc = (x: string): string => x.toLowerCase();
  return [...(ctx.registeredSettings ?? []), ...(ctx.agentSettings ?? [])].some((p) => lc(p) === lc(abs));
}

/**
 * Cursor's hooks files (read from cursor-agent 2026.10.01's loader): the user's ~/.cursor/hooks.json, a
 * project's .cursor/hooks.json, the team file Cursor syncs (.cursor/managed/active-team-hooks/hooks.json)
 * and the enterprise file (/Library/Application Support/Cursor/hooks.json, /etc/cursor/hooks.json).
 */
export function isCursorHooksFile(abs: string): boolean {
  // Case-insensitive throughout (F13): on macOS's default file system "/library/application support/cursor"
  // is the same file, and a name the firewall fails to recognise would skip the result check.
  return /\/\.cursor\/(?:managed\/active-team-hooks\/)?hooks\.json$/i.test(abs) || /\/Application Support\/Cursor\/hooks\.json$/i.test(abs) || /^(?:\/private)?\/etc\/cursor\/hooks\.json$/i.test(abs);
}

/**
 * F13: a file that holds the firewall's Cursor hook is a Cursor hooks file whatever it is called (a symlinked
 * ~/.cursor written through its target, a registered copy elsewhere), so Cursor's whole-file validation is
 * applied to it too.
 */
export function holdsCursorHook(settings: unknown): boolean {
  return hookEntries(settings).some((e) => e.command.includes(MARKER) && /\bhook\s+--agent[ =]cursor\b/.test(e.command));
}

/** Whose settings a hook settings file is, for messages. */
export function agentOfSettings(abs: string): string {
  if (/\/(?:\.codex|codex)\//i.test(abs)) return "Codex";
  if (/\/(?:\.gemini|GeminiCli|gemini-cli)\//i.test(abs)) return "Gemini CLI";
  if (isCursorHooksFile(abs)) return "Cursor";
  return "Claude Code";
}

/** Settings files that may sit inside a directory (for rm -r .claude, mv .claude elsewhere). */
export function settingsFilesUnder(dir: string): string[] {
  const d = dir.replace(/\/+$/, "");
  return [`${d}/settings.json`, `${d}/settings.local.json`, `${d}/.claude/settings.json`, `${d}/.claude/settings.local.json`, `${d}/managed-settings.json`, `${d}/hooks.json`, `${d}/config.toml`, `${d}/requirements.toml`, `${d}/.codex/hooks.json`, `${d}/.codex/config.toml`, `${d}/.gemini/settings.json`, `${d}/.cursor/hooks.json`];
}

export function registersFirewall(text: string | null): boolean {
  return text !== null && text.includes(MARKER);
}

type Json = Record<string, unknown>;

/**
 * Every hook entry in a settings document, with its event: Claude Code's, Codex's and Gemini CLI's
 * groups (`{ matcher, hooks: [entry] }`) and Cursor's flat entries (`{ command, ... }` directly in the
 * event's list).
 */
export function hookEntries(settings: unknown): { event: string; entry: Json; command: string }[] {
  const out: { event: string; entry: Json; command: string }[] = [];
  const hooks = typeof settings === "object" && settings !== null ? (settings as Json).hooks : undefined;
  if (typeof hooks !== "object" || hooks === null) return out;
  for (const [event, groups] of Object.entries(hooks as Json)) {
    if (!Array.isArray(groups)) continue;
    for (const g of groups) {
      if (typeof g !== "object" || g === null) continue;
      const list = (g as Json).hooks;
      const entries = Array.isArray(list) ? list : [g];
      for (const e of entries) {
        if (typeof e !== "object" || e === null) continue;
        const c = (e as Json).command;
        out.push({ event, entry: e as Json, command: typeof c === "string" ? c : "" });
      }
    }
  }
  return out;
}

/** Cursor's hook steps (cursor-agent 2026.10.01): a hooks.json naming any other key is rejected whole. */
export const CURSOR_HOOK_STEPS: readonly string[] = ["beforeShellExecution", "beforeMCPExecution", "afterShellExecution", "afterMCPExecution", "beforeReadFile", "afterFileEdit", "beforeTabFileRead", "afterTabFileEdit", "stop", "beforeSubmitPrompt", "afterAgentResponse", "afterAgentThought", "sessionStart", "sessionEnd", "preCompact", "subagentStart", "subagentStop", "preToolUse", "postToolUse", "postToolUseFailure", "workspaceOpen"];

/**
 * Why Cursor would refuse to load a hooks.json at all (empty when it loads). Cursor validates the whole
 * file and drops every hook in it on any error: a version that is not a positive integer, an unknown
 * step name, or one malformed entry (a non-string command, an invalid matcher regex, a timeout that is
 * not a positive number, a failClosed that is not a boolean). Reproduced from cursor-agent 2026.10.01's
 * validator, so a change that breaks the file is judged as switching the firewall off.
 */
export function cursorHooksProblems(s: unknown): string[] {
  const out: string[] = [];
  if (typeof s !== "object" || s === null || Array.isArray(s)) return ["the file is not a JSON object"];
  const o = s as Json;
  if (typeof o.version !== "number" || !Number.isInteger(o.version) || o.version < 1) out.push("version is not a positive integer");
  if (typeof o.hooks !== "object" || o.hooks === null || Array.isArray(o.hooks)) return [...out, "hooks is not an object"];
  for (const [step, list] of Object.entries(o.hooks as Json)) {
    if (!CURSOR_HOOK_STEPS.includes(step)) {
      out.push(`unknown hook step ${step}`);
      continue;
    }
    if (list === undefined) continue;
    if (!Array.isArray(list)) {
      out.push(`${step} is not a list`);
      continue;
    }
    list.forEach((e, i) => {
      const where = `${step}[${i}]`;
      if (typeof e !== "object" || e === null || Array.isArray(e)) return void out.push(`${where} is not an object`);
      const h = e as Json;
      if (h.type === "prompt") {
        if (typeof h.prompt !== "string" || h.prompt.trim() === "") out.push(`${where} has no prompt`);
      } else if (h.type === "command" || h.type === undefined) {
        if (typeof h.command !== "string") out.push(`${where} has no command`);
      } else out.push(`${where} has an invalid type`);
      if (h.matcher !== undefined) {
        if (typeof h.matcher !== "string") out.push(`${where} has a matcher that is not a string`);
        else if (h.matcher !== "" && h.matcher !== "*") {
          try {
            new RegExp(h.matcher);
          } catch {
            out.push(`${where} has an invalid matcher`);
          }
        }
      }
      if (h.timeout !== undefined && (typeof h.timeout !== "number" || h.timeout <= 0)) out.push(`${where} has an invalid timeout`);
      if (h.loop_limit !== undefined && h.loop_limit !== null && (typeof h.loop_limit !== "number" || !Number.isInteger(h.loop_limit) || h.loop_limit <= 0)) out.push(`${where} has an invalid loop_limit`);
      if (h.failClosed !== undefined && typeof h.failClosed !== "boolean") out.push(`${where} has a failClosed that is not a boolean`);
    });
  }
  return out;
}

function parse(text: string): Json | null {
  try {
    const v: unknown = JSON.parse(text);
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : null;
  } catch {
    return null;
  }
}

function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  const o = v as Json;
  return `{${Object.keys(o)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(own(o, k))}`)
    .join(",")}}`;
}

/**
 * The firewall's hook groups per event, canonicalised (matcher, command, timeout, wrapper and all), for
 * every event key in the file: Claude Code's and Codex's event names, and Gemini CLI's (BeforeTool...).
 * Our entries moved under another event key (or a misspelt one) do not run there: that is a change.
 */
function ourGroups(s: Json): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const hooks = typeof s.hooks === "object" && s.hooks !== null ? (s.hooks as Json) : {};
  for (const ev of new Set([...HOOK_EVENTS, ...Object.keys(hooks)])) {
    const groups = Array.isArray(own(hooks, ev)) ? (own(hooks, ev) as unknown[]) : [];
    out.set(ev, groups.filter((g) => canonical(g).includes(MARKER)).map(canonical).sort());
  }
  return out;
}

/** Gemini CLI switches that stop the firewall's hooks from running (hooksConfig.enabled false, a disabled list naming them, tools.enableHooks false). */
function geminiHooksOff(s: Json): string[] {
  const cfg = typeof s.hooksConfig === "object" && s.hooksConfig !== null ? (s.hooksConfig as Json) : {};
  const tools = typeof s.tools === "object" && s.tools !== null ? (s.tools as Json) : {};
  const out: string[] = [];
  if (cfg.enabled === false) out.push("hooksConfig.enabled false");
  if (Array.isArray(cfg.disabled) && cfg.disabled.some((n) => typeof n === "string" && (/launchsafe/i.test(n) || n.includes(MARKER)))) out.push("hooksConfig.disabled naming the firewall's hook");
  if (tools.enableHooks === false) out.push("tools.enableHooks false");
  return out;
}

/**
 * A TOML file (Codex config.toml, requirements.toml) judged by its result: the lines that carry the
 * firewall's command must stay exactly as they are, and the keys that decide which hooks run must not
 * change. TOML is checked line by line, not parsed: anything unclear around our entries is a change.
 */
/** The [hooks.state."…"] tables of a Codex config.toml, normalized. */
function hookState(t: string): string {
  const out: string[] = [];
  let inState = false;
  for (const raw of t.split("\n")) {
    const l = raw.trim();
    if (l.startsWith("[")) inState = /^\[hooks\.state[.\]]/.test(l);
    else if (/^hooks\.state\./.test(l)) out.push(l.replace(/\s+/g, ""));
    if (inState && l !== "" && !l.startsWith("#")) out.push(l.replace(/\s+/g, ""));
  }
  return out.sort().join("\n");
}

/**
 * F11: a TOML document flattened to key paths (JSON arrays of the key parts) and canonical values, so dotted
 * keys (`features.hooks = false`), inline tables (`features = { hooks = false }`) and nested tables all give
 * the same path. Null when the text is not TOML the parser understands. A subset parser: strings (basic,
 * literal, multi-line), inline tables, arrays, tables and arrays of tables, bare scalars.
 */
export function tomlFlatten(text: string): Map<string, string> | null {
  const out = new Map<string, string>();
  const t = text.replace(/\r\n/g, "\n");
  let i = 0;
  const n = t.length;
  const fail = (): never => {
    throw new Error("toml");
  };
  const ws = (): void => {
    while (i < n && (t[i] === " " || t[i] === "\t")) i++;
  };
  const wsnl = (): void => {
    for (;;) {
      while (i < n && /[ \t\n]/.test(t[i] as string)) i++;
      if (t[i] === "#") {
        while (i < n && t[i] !== "\n") i++;
        continue;
      }
      break;
    }
  };
  const basic = (): string => {
    // t[i] === '"'
    i++;
    let v = "";
    while (i < n && t[i] !== '"') {
      if (t[i] === "\n") fail();
      if (t[i] === "\\") {
        const e = t[i + 1];
        if (e === "u" || e === "U") {
          const len = e === "u" ? 4 : 8;
          const hex = t.slice(i + 2, i + 2 + len);
          if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length !== len) fail();
          v += String.fromCodePoint(parseInt(hex, 16));
          i += 2 + len;
          continue;
        }
        const map: Record<string, string> = { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", '"': '"', "\\": "\\", e: "\u001b" };
        const m = own(map, e ?? "");
        if (m === undefined) fail();
        v += m;
        i += 2;
        continue;
      }
      v += t[i];
      i++;
    }
    if (t[i] !== '"') fail();
    i++;
    return v;
  };
  const literal = (): string => {
    i++;
    const end = t.indexOf("'", i);
    const nl = t.indexOf("\n", i);
    if (end === -1 || (nl !== -1 && nl < end)) fail();
    const v = t.slice(i, end);
    i = end + 1;
    return v;
  };
  const key = (): string[] => {
    const parts: string[] = [];
    for (;;) {
      ws();
      if (t[i] === '"') parts.push(basic());
      else if (t[i] === "'") parts.push(literal());
      else {
        const m = /^[A-Za-z0-9_-]+/.exec(t.slice(i, i + 256));
        if (m === null) fail();
        parts.push((m as RegExpExecArray)[0]);
        i += (m as RegExpExecArray)[0].length;
      }
      ws();
      if (t[i] !== ".") return parts;
      i++;
    }
  };
  const put = (path: string[], v: string): void => {
    out.set(JSON.stringify(path), v);
  };
  const value = (path: string[], depth: number): void => {
    if (depth > 32) fail();
    if (t.startsWith('"""', i) || t.startsWith("'''", i)) {
      const q = t.slice(i, i + 3);
      const end = t.indexOf(q, i + 3);
      if (end === -1) fail();
      put(path, JSON.stringify(t.slice(i + 3, end)));
      i = end + 3;
      while (t[i] === q[0]) i++;
      return;
    }
    if (t[i] === '"') return put(path, JSON.stringify(basic()));
    if (t[i] === "'") return put(path, JSON.stringify(literal()));
    if (t[i] === "{") {
      i++;
      put(path, "{}");
      ws();
      if (t[i] === "}") {
        i++;
        return;
      }
      for (;;) {
        const k = key();
        if (t[i] !== "=") fail();
        i++;
        ws();
        value([...path, ...k], depth + 1);
        ws();
        if (t[i] === ",") {
          i++;
          continue;
        }
        if (t[i] === "}") {
          i++;
          return;
        }
        fail();
      }
    }
    if (t[i] === "[") {
      i++;
      put(path, "[]");
      let k = 0;
      for (;;) {
        wsnl();
        if (t[i] === "]") {
          i++;
          return;
        }
        value([...path, String(k++)], depth + 1);
        wsnl();
        if (t[i] === ",") {
          i++;
          continue;
        }
        if (t[i] === "]") {
          i++;
          return;
        }
        fail();
      }
    }
    const m = /^(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})?|[^\s,#\]}]+)/.exec(t.slice(i, i + 256));
    if (m === null) fail();
    put(path, (m as RegExpExecArray)[0]);
    i += (m as RegExpExecArray)[0].length;
  };
  let table: string[] = [];
  const arrays = new Map<string, number>();
  try {
    for (;;) {
      wsnl();
      if (i >= n) break;
      if (t[i] === "[") {
        const arr = t[i + 1] === "[";
        i += arr ? 2 : 1;
        const k = key();
        if (arr) {
          if (!t.startsWith("]]", i)) fail();
          i += 2;
          const id = JSON.stringify(k);
          const idx = arrays.get(id) ?? 0;
          arrays.set(id, idx + 1);
          table = [...k, String(idx)];
        } else {
          if (t[i] !== "]") fail();
          i++;
          table = k;
        }
        put(table, "{}");
      } else {
        const k = key();
        if (t[i] !== "=") fail();
        i++;
        ws();
        value([...table, ...k], 0);
      }
      ws();
      if (t[i] === "#") while (i < n && t[i] !== "\n") i++;
      if (i < n && t[i] !== "\n") fail();
    }
  } catch {
    return null;
  }
  return out;
}

function tomlViolations(before: string | null, after: string, reg: boolean): string[] {
  const ours = (t: string): string => t.split("\n").filter((l) => l.includes(MARKER)).map((l) => l.trim()).sort().join("\n");
  const key = (t: string, k: string): string => t.split("\n").filter((l) => new RegExp(`^\\s*${k}\\s*=`).test(l)).map((l) => l.replace(/\s+/g, "")).join("\n");
  const b = before ?? "";
  const problems: string[] = [];
  if (reg && ours(b) !== ours(after)) problems.push(ours(after) === "" ? "it removes the firewall's hooks" : "it changes the firewall's hooks (command or fail-closed wrapper)");
  if (key(b, "allow_managed_hooks_only") !== key(after, "allow_managed_hooks_only")) problems.push("it changes allow_managed_hooks_only, which decides which hooks may run");
  if (key(b, "hooks") !== key(after, "hooks") && /^\s*hooks\s*=\s*false/m.test(after)) problems.push("it switches Codex hooks off");
  // Codex records which hooks the person trusted ([hooks.state."<file>:<event>:<group>:<handler>"]); an
  // untrusted or changed hook is skipped silently. The agent may neither revoke nor grant that trust.
  if (hookState(b) !== hookState(after)) problems.push("it changes which Codex hooks are trusted or enabled (hooks.state)");
  // F11: the same switches written as dotted keys, inline tables or nested tables, judged on the parsed keys.
  const fa = tomlFlatten(after);
  const fb = tomlFlatten(b);
  if (fa === null) {
    if (/features|hooks|allow_managed_hooks_only/.test(after) && after !== b) problems.push("the TOML cannot be parsed, and it mentions Codex's hook switches, so the change cannot be checked");
  } else {
    const pick = (m: Map<string, string> | null, test: (parts: string[]) => boolean): string =>
      m === null ? "" : [...m].filter(([k]) => test(JSON.parse(k) as string[])).map(([k, v]) => `${k}=${v}`).sort().join("\n");
    const isFeatureHooks = (p: string[]): boolean => p.length >= 2 && p[p.length - 1] === "hooks" && p[p.length - 2] === "features";
    if (pick(fa, isFeatureHooks) !== pick(fb, isFeatureHooks) && [...fa].some(([k, v]) => isFeatureHooks(JSON.parse(k) as string[]) && v === "false")) problems.push("it switches Codex hooks off (features.hooks = false)");
    const isManaged = (p: string[]): boolean => p[p.length - 1] === "allow_managed_hooks_only";
    if (pick(fa, isManaged) !== pick(fb, isManaged)) problems.push("it changes allow_managed_hooks_only, which decides which hooks may run");
    const isState = (p: string[]): boolean => p.length >= 2 && p[0] === "hooks" && p[1] === "state";
    if (pick(fa, isState) !== pick(fb, isState)) problems.push("it changes which Codex hooks are trusted or enabled (hooks.state)");
  }
  if (/LAUNCHSAFE_FIREWALL_/.test(after.replace(new RegExp(`.*${MARKER}.*`, "g"), "")) && after.replace(new RegExp(`.*${MARKER}.*`, "g"), "") !== b.replace(new RegExp(`.*${MARKER}.*`, "g"), "")) problems.push("it sets the firewall's own environment variables");
  return [...new Set(problems)];
}

/**
 * I1: variables in a settings file's `env` that reach the hook process and change what it loads or where it reads
 * its state from. Installs pin or clear them in the hook command; a write that sets one is still tampering (older
 * installs, and the shell that runs the command, see it).
 */
const HOOK_PROCESS_ENV = /^(?:HOME|NODE_OPTIONS|NODE_PATH|NODE_COMPILE_CACHE|LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|DYLD_[A-Z_]+|TMPDIR|BASH_ENV|ENV|IFS|VITEST)$/;

/** The hook-process variables `after` sets that `before` did not set to the same value. */
function hookEnvSet(before: Json, after: Json): string[] {
  const envOf = (s: Json): Json => (typeof s.env === "object" && s.env !== null && !Array.isArray(s.env) ? (s.env as Json) : {});
  const b = envOf(before);
  const a = envOf(after);
  return Object.keys(a).filter((k) => HOOK_PROCESS_ENV.test(k) && canonical(own(a, k)) !== canonical(own(b, k)));
}

function firewallEnv(s: Json): string {
  const env = typeof s.env === "object" && s.env !== null ? (s.env as Json) : {};
  return canonical(Object.fromEntries(Object.entries(env).filter(([k]) => /^LAUNCHSAFE_FIREWALL_/i.test(k))));
}

/**
 * Why changing a settings file from `before` to `after` would weaken the firewall (empty when it
 * would not). before: current content, or null if the file does not exist or could not be read.
 * after: resulting content, or null when it cannot be computed. registered: the firewall is
 * installed in this file (from its install record), even if before could not be read. sandbox: the
 * profile `doctor --fix` installed in this file (on by default), when it is protected: weakening it is
 * judged like removing the hooks.
 */
export function settingsViolations(before: string | null, after: string | null, registered: boolean, file = "", sandbox?: SandboxGuard): string[] {
  const reg = registered || registersFirewall(before);
  if (after === null) return reg ? ["the result of the change cannot be checked, and this file registers the firewall's hooks"] : ["the result of the change cannot be checked (it could switch hooks off)"];
  if (/\.toml$/i.test(file)) return tomlViolations(before, after, reg);
  let a = parse(after);
  let b = before === null ? {} : parse(before);
  const problems: string[] = [];
  if (a === null) {
    if (reg) problems.push("the file would no longer be valid JSON, so the firewall's hooks would not load");
    else if (/disableAllHooks|allowManagedHooksOnly|LAUNCHSAFE_FIREWALL_/.test(after)) problems.push("the change sets hook controls in a file that is not valid JSON");
    // A leading byte order mark: an agent that drops it (as the firewall's own readers do) loads what follows. The change
    // is judged as that agent reads the file and the result too, on top of the above (for an agent that refuses the mark).
    if (after.charCodeAt(0) !== 0xfeff) return problems;
    a = parse(stripBom(after));
    if (a === null) return problems;
    if (before !== null) b = parse(stripBom(before));
  }
  if (reg) {
    if (b === null) problems.push("the current file cannot be read as JSON, so the change cannot be compared");
    else {
      const was = ourGroups(b);
      const now = ourGroups(a);
      for (const ev of new Set([...was.keys(), ...now.keys()])) {
        const w = was.get(ev) ?? [];
        const n = now.get(ev) ?? [];
        if (w.length > 0 && canonical(w) !== canonical(n)) problems.push(n.length === 0 ? `it removes the firewall's ${ev} hook` : `it changes the firewall's ${ev} hook (command, matcher or fail-closed wrapper)`);
      }
    }
  }
  const before0 = b ?? {};
  if (a.disableAllHooks === true && before0.disableAllHooks !== true) problems.push("it sets disableAllHooks, which turns the firewall off");
  if (canonical(a.allowManagedHooksOnly) !== canonical(before0.allowManagedHooksOnly)) problems.push("it changes allowManagedHooksOnly, which decides which hooks may run");
  if (firewallEnv(a) !== firewallEnv(before0)) problems.push("it sets the firewall's own environment variables");
  for (const k of hookEnvSet(before0, a)) problems.push(`it sets env.${k}, which reaches the firewall's hook process (where it reads its state from, or what code node loads)`);
  // F13: Gemini CLI's switches are judged in any hook settings file (its system settings may be called anything).
  {
    const was = new Set(geminiHooksOff(before0));
    for (const off of geminiHooksOff(a)) if (!was.has(off)) problems.push(`it sets ${off}, which turns Gemini CLI hooks (and the firewall) off`);
  }
  if (reg && (isCursorHooksFile(file) || holdsCursorHook(before0))) {
    // Cursor drops a hooks.json whole on any validation error: breaking any entry switches ours off too.
    const was = new Set(cursorHooksProblems(before0));
    const now = cursorHooksProblems(a).filter((p) => !was.has(p));
    if (now.length > 0) problems.push(`it makes Cursor reject the whole hooks file (${now.slice(0, 2).join("; ")}), which turns the firewall's hooks off`);
  }
  if (sandbox !== undefined) {
    if (b === null) problems.push("the current file cannot be read as JSON, so the change to the sandbox profile the firewall installed cannot be compared");
    else problems.push(...sandboxViolations(b, a, sandbox));
  }
  return [...new Set(problems)];
}

/** Punctuation an edit tool may treat as equal to its ASCII form (one character for one, so offsets stay valid). */
const PUNCT: Record<string, string> = { "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-", "\u2015": "-", "\u2212": "-", "\u2018": "'", "\u2019": "'", "\u201a": "'", "\u201b": "'", "\u201c": '"', "\u201d": '"', "\u201e": '"', "\u201f": '"', "\u00a0": " ", "\u2002": " ", "\u2003": " ", "\u2007": " ", "\u2009": " ", "\u202f": " ", "\u3000": " " };
const MAX_CANDIDATES = 16;

function foldPunct(s: string): string {
  return s.replace(/[\u2010-\u2015\u2212\u2018-\u201f\u00a0\u2002\u2003\u2007\u2009\u202f\u3000]/g, (ch) => own(PUNCT, ch) ?? ch);
}

/** Every place an edit's old text may match: exact occurrences, else whitespace- and punctuation-insensitive ones. */
function matchesOf(s: string, old: string): { at: number; len: number }[] {
  const out: { at: number; len: number }[] = [];
  for (let i = s.indexOf(old); i !== -1 && out.length < MAX_CANDIDATES; i = s.indexOf(old, i + 1)) out.push({ at: i, len: old.length });
  if (out.length > 0) return out;
  const tokens = foldPunct(old).split(/\s+/).filter((t) => t !== "");
  if (tokens.length === 0) return out;
  const re = new RegExp(tokens.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("\\s*"), "g");
  for (const m of foldPunct(s).matchAll(re)) {
    out.push({ at: m.index, len: m[0].length });
    if (out.length >= MAX_CANDIDATES) break;
  }
  return out;
}

/**
 * F6: the files an edit may leave when the agent's edit tool does not need an exact match (Codex's
 * apply_patch matches context again after trimming whitespace and folding punctuation, and anchors a chunk
 * after its @@ line; Gemini CLI's replace matches whitespace-insensitively and may correct old_string;
 * `patch` applies with fuzz). Every plausible match gives one candidate, so the caller can judge each and
 * keep the most severe. Null: the old text matches nowhere, so the result is unknown (the caller assumes
 * the worst). The exact matching rules of those tools were not captured; this over-approximates them.
 */
export function looseEditResults(before: string, edits: readonly { old: string; new: string; all?: boolean }[]): string[] | null {
  let cands = [before];
  for (const e of edits) {
    const next: string[] = [];
    for (const s of cands) {
      // An empty old_string creates the file, or fills a blank one: the result is the new text.
      if (e.old === "" && s.trim() === "") { next.push(e.new); continue; }
      if (e.old === "") return null;
      const ms = matchesOf(s, e.old);
      if (ms.length === 0) return null;
      if (e.all === true) {
        let r = s;
        for (const m of [...ms].sort((a, b) => b.at - a.at)) r = r.slice(0, m.at) + e.new + r.slice(m.at + m.len);
        next.push(r);
      } else for (const m of ms) next.push(s.slice(0, m.at) + e.new + s.slice(m.at + m.len));
      if (next.length >= MAX_CANDIDATES) break;
    }
    cands = [...new Set(next)].slice(0, MAX_CANDIDATES);
  }
  return cands;
}

/** Applies Edit/MultiEdit replacements the way the tools do; an edit whose text is missing fails the whole call (no change). */
export function applyEdits(before: string, edits: readonly { old: string; new: string; all?: boolean }[]): string {
  let s = before;
  for (const e of edits) {
    if (e.old === "" && s.trim() === "") { s = e.new; continue; }
    if (e.old === "" || !s.includes(e.old)) return before;
    s = e.all === true ? s.split(e.old).join(e.new) : s.replace(e.old, () => e.new);
  }
  return s;
}
