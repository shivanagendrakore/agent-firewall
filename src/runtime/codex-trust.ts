/**
 * Codex hook trust. Codex 0.162.1 runs a hook from hooks.json only when the
 * person has trusted it, and skips it silently otherwise (captured). Trust is
 * recorded in $CODEX_HOME/config.toml:
 *
 *   [hooks.state."<abs hooks file>:<snake_event>:<group>:<handler>"]
 *   trusted_hash = "sha256:<hex>"
 *
 * where the hash is sha256 of the compact JSON, keys sorted at every level, of
 * { event_name, matcher, hooks: [{ type, command, timeout, async, statusMessage? }] }
 * (reproduced against Codex's own hooks/list on six hooks). `install --agent
 * codex` is run by the person, in a terminal, to install exactly these hooks, so
 * it records their trust; the person's other hooks keep the trust they had (their
 * entries move with them when the firewall's group is put first). Line-based
 * TOML editing, limited to [hooks.state."<this file>:…"] tables.
 */

import { createHash } from "node:crypto";
import { MARKER } from "../engine/settings.js";
import { own } from "../own.js";

type Json = Record<string, unknown>;

/** PreToolUse -> pre_tool_use. */
export function snakeEvent(ev: string): string {
  return ev.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  const o = v as Json;
  return `{${Object.keys(o)
    .filter((k) => own(o, k) !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(own(o, k))}`)
    .join(",")}}`;
}

/** Codex's trusted_hash of one handler in one group. */
export function codexTrustHash(event: string, matcher: string | undefined, handler: Json): string {
  const h: Json = {
    type: handler.type ?? "command",
    command: handler.command,
    timeout: typeof handler.timeout === "number" ? handler.timeout : 600,
    async: handler.async === true,
    ...(typeof handler.statusMessage === "string" ? { statusMessage: handler.statusMessage } : {}),
  };
  const identity: Json = { event_name: snakeEvent(event), ...(matcher !== undefined ? { matcher } : {}), hooks: [h] };
  return `sha256:${createHash("sha256").update(canonical(identity)).digest("hex")}`;
}

interface Handler {
  key: string;
  event: string;
  group: number;
  index: number;
  matcher: string | undefined;
  handler: Json;
  ours: boolean;
}

function handlers(path: string, settings: Json | null): Handler[] {
  const out: Handler[] = [];
  const hooks = settings !== null && typeof settings.hooks === "object" && settings.hooks !== null ? (settings.hooks as Json) : {};
  for (const [ev, groups] of Object.entries(hooks)) {
    if (!Array.isArray(groups)) continue;
    groups.forEach((g, gi) => {
      const list = (g as { hooks?: unknown } | null)?.hooks;
      const matcher = typeof (g as { matcher?: unknown }).matcher === "string" ? ((g as { matcher: string }).matcher) : undefined;
      if (!Array.isArray(list)) return;
      list.forEach((h, hi) => {
        if (typeof h !== "object" || h === null) return;
        const handler = h as Json;
        out.push({ key: `${path}:${snakeEvent(ev)}:${gi}:${hi}`, event: ev, group: gi, index: hi, matcher, handler, ours: typeof handler.command === "string" && handler.command.includes(MARKER) });
      });
    });
  }
  return out;
}

/** The [hooks.state."…"] tables of a config.toml, by key, with their body lines. */
function stateTables(text: string): { key: string; start: number; end: number; body: string[] }[] {
  const lines = text.split("\n");
  const out: { key: string; start: number; end: number; body: string[] }[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*\[hooks\.state\."((?:[^"\\]|\\.)*)"\]\s*$/.exec(lines[i] ?? "");
    if (m === null) continue;
    let j = i + 1;
    while (j < lines.length && !/^\s*\[/.test(lines[j] ?? "")) j++;
    out.push({ key: (m[1] as string).replace(/\\(.)/g, "$1"), start: i, end: j, body: lines.slice(i + 1, j) });
  }
  return out;
}

function tomlKey(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/**
 * config.toml after the hooks file at `path` changed from `before` to `after`: the firewall's handlers
 * are trusted with their current hash, every other handler keeps the state it had (moved to its new
 * position), and entries for handlers that are gone are dropped. Tables for other files are untouched.
 */
export function retrust(config: string | null, path: string, before: Json | null, after: Json | null): string {
  const text = config ?? "";
  const tables = stateTables(text);
  const mine = tables.filter((t) => t.key.startsWith(`${path}:`));
  const old = new Map(mine.map((t) => [t.key, t.body]));
  const prior = handlers(path, before);
  const blocks: string[] = [];
  for (const h of handlers(path, after)) {
    if (h.ours) {
      blocks.push(`[hooks.state."${tomlKey(h.key)}"]`, `trusted_hash = "${codexTrustHash(h.event, h.matcher, h.handler)}"`, "");
      continue;
    }
    // The same handler before (same event, matcher and definition): carry its state to the new key.
    const was = prior.find((p) => !p.ours && p.event === h.event && p.matcher === h.matcher && canonical(p.handler) === canonical(h.handler));
    const body = was !== undefined ? old.get(was.key) : undefined;
    if (body !== undefined) blocks.push(`[hooks.state."${tomlKey(h.key)}"]`, ...body.filter((l) => l.trim() !== ""), "");
  }
  const drop = new Set<number>();
  for (const t of mine) for (let i = t.start; i < t.end; i++) drop.add(i);
  const kept = text.split("\n").filter((_, i) => !drop.has(i)).join("\n").replace(/\n{3,}/g, "\n\n").replace(/\s+$/, "");
  const add = blocks.join("\n").replace(/\s+$/, "");
  return `${[kept, add].filter((x) => x !== "").join("\n\n")}\n`;
}

/** Whether every firewall handler in the hooks file is trusted with its current hash in config.toml. */
export function trustStatus(config: string | null, path: string, settings: Json | null): { trusted: string[]; untrusted: string[]; modified: string[] } {
  const tables = new Map(stateTables(config ?? "").map((t) => [t.key, t.body]));
  const out = { trusted: [] as string[], untrusted: [] as string[], modified: [] as string[] };
  for (const h of handlers(path, settings).filter((x) => x.ours)) {
    const body = tables.get(h.key);
    const recorded = body?.map((l) => /^\s*trusted_hash\s*=\s*"([^"]*)"/.exec(l)?.[1]).find((x) => x !== undefined);
    if (body?.some((l) => /^\s*enabled\s*=\s*false/.test(l)) === true || recorded === undefined) out.untrusted.push(h.event);
    else if (recorded !== codexTrustHash(h.event, h.matcher, h.handler)) out.modified.push(h.event);
    else out.trusted.push(h.event);
  }
  return out;
}
