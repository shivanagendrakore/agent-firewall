/**
 * G4: editor settings that switch on an agent's own auto-approval (the Copilot "YOLO mode" flip,
 * CVE-2025-53773: a project's .vscode/settings.json sets chat.tools.autoApprove, and every later tool
 * call runs without asking). Detection only: the verdict comes from the rules for agent settings.
 *
 * The key names are matched by shape, not from a closed list, because editors and agent extensions
 * add and rename them: a key whose last word says "auto approve", "yolo", "skip permissions",
 * "bypass permissions" or "always allow", set to a truthy value (true, a mode that bypasses asking,
 * or an object with an enabled entry). Keys the firewall has seen are listed above;
 * the shape match is the safety net for those it has not.
 */

type Json = unknown;

const KEY = /(?:auto[-_ ]?approv|yolo|skip[-_]?permission|bypass[-_]?permission|always[-_]?allow|dangerously|permission[-_]?mode)/i;
const BYPASS_MODES = /^(?:bypassPermissions|acceptEdits|auto|yolo|dontAsk|full-?auto)$/i;

/** Editor and agent settings files whose content can switch agent auto-approval on. */
export function isEditorSettingsFile(abs: string): boolean {
  return /\/\.vscode\/settings\.json$/i.test(abs) || /\.code-workspace$/i.test(abs) || /\/\.cursor\/settings\.json$/i.test(abs) || /\/\.zed\/settings\.json$/i.test(abs) || /\/(?:Code|Code - Insiders|Cursor|VSCodium|Windsurf)\/User\/settings\.json$/i.test(abs) || /\/\.windsurf\/settings\.json$/i.test(abs);
}

/** JSON with comments and trailing commas (what editors write), reduced to JSON. */
function stripJsonc(text: string): string {
  let out = "";
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string;
    if (inStr) {
      out += ch;
      if (ch === "\\") out += text[++i] ?? "";
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') {
      inStr = true;
      out += ch;
    } else if (ch === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (ch === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i++;
    } else out += ch;
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}

function truthy(v: Json): boolean {
  if (v === true) return true;
  if (typeof v === "string") return BYPASS_MODES.test(v.trim());
  if (Array.isArray(v)) return false;
  if (typeof v === "object" && v !== null) return Object.values(v).some((x) => x === true || (typeof x === "object" && x !== null && !Array.isArray(x) && (x as Record<string, unknown>).approve === true));
  return false;
}

/** A value in one spelling (object keys sorted), so equal values compare equal and a widened one does not. */
function canon(v: Json): string {
  if (Array.isArray(v)) return `[${v.map(canon).join(",")}]`;
  if (typeof v === "object" && v !== null) {
    return `{${Object.entries(v as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, x]) => `${JSON.stringify(k)}:${canon(x)}`)
      .join(",")}}`;
  }
  return JSON.stringify(v) ?? "null";
}

/** An auto-approval switch that is on: its key and the value it is set to (canonical JSON, or the raw text of an unreadable one). */
export interface AutoApproveEntry {
  key: string;
  value: string;
}

/** What a truthy value switches on, one part per allowlist member (so narrowing a list adds nothing), else the whole value. */
function parts(x: Json): string[] {
  if (typeof x === "object" && x !== null && !Array.isArray(x)) {
    const on = Object.entries(x as Record<string, unknown>).filter(([, m]) => m === true || (typeof m === "object" && m !== null && !Array.isArray(m) && (m as Record<string, unknown>).approve === true));
    if (on.length > 0) return on.map(([k, m]) => `${JSON.stringify(k)}:${canon(m)}`);
  }
  return [canon(x)];
}

function walk(v: Json, out: AutoApproveEntry[], depth: number): void {
  if (depth > 8 || typeof v !== "object" || v === null || Array.isArray(v)) return;
  for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
    if (KEY.test(k) && truthy(x)) for (const p of parts(x)) out.push({ key: k, value: p });
    else if (typeof x === "object") walk(x, out, depth + 1);
  }
}

/** The switches `text` turns on, with their values. Also reads a fragment that is not valid JSON. */
export function autoApproveEntries(text: string): AutoApproveEntry[] {
  const out: AutoApproveEntry[] = [];
  try {
    walk(JSON.parse(stripJsonc(text)) as Json, out, 0);
    return out;
  } catch {
    // A fragment (an edit's replacement text): look for `"key": value` pairs.
  }
  const re = /"([^"\n]{1,120})"\s*:\s*("(?:[^"\\\n]|\\.)*"|true|false|null|\{[^{}]*\})/g;
  for (let m = re.exec(text); m !== null; m = re.exec(text)) {
    const key = m[1] as string;
    if (!KEY.test(key)) continue;
    try {
      const parsed = JSON.parse(stripJsonc(m[2] as string)) as Json;
      if (truthy(parsed)) for (const p of parts(parsed)) out.push({ key, value: p });
    } catch {
      out.push({ key, value: m[2] as string });
    }
  }
  return out;
}

/** The auto-approval switches that `text` turns on (empty when none). Also reads a fragment that is not valid JSON. */
export function autoApproveSwitches(text: string): string[] {
  return [...new Set(autoApproveEntries(text).map((e) => e.key))];
}

/**
 * The switches `after` turns on that `before` did not already have on with the same value: a switch that
 * was on and is now set wider (an allowlist entry added or changed, acceptEdits becoming bypassPermissions)
 * counts as new. Taking an entry out of an allowlist is not.
 */
export function newAutoApproveSwitches(before: string | null, after: string): string[] {
  const had = new Set((before === null ? [] : autoApproveEntries(before)).map((e) => `${e.key}\u0000${e.value}`));
  return [...new Set(autoApproveEntries(after).filter((e) => !had.has(`${e.key}\u0000${e.value}`)).map((e) => e.key))];
}
