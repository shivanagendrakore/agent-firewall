/**
 * Paths as a person reads them in a list: relative to the project when inside it, `~/...` when inside
 * the home directory, and cut in the middle when still long (the full path goes in a tooltip or on the
 * detail page). Pure.
 */

export interface PathContext {
  /** Project roots to show paths relative to (as given and as resolved through symlinks). */
  projects: readonly string[];
  /** Home directories to show as `~` (as given and resolved). */
  homes: readonly string[];
}

function strip(p: string): string {
  return p.replace(/\/+$/, "");
}

/** A path relative to a project, or `~/...`, or unchanged. */
export function shortPath(path: string, c: PathContext): string {
  for (const root of c.projects.map(strip).filter((r) => r !== "")) {
    if (path === root) return ".";
    if (path.startsWith(`${root}/`)) return path.slice(root.length + 1);
  }
  for (const h of c.homes.map(strip).filter((r) => r !== "")) {
    if (path === h) return "~";
    if (path.startsWith(`${h}/`)) return `~/${path.slice(h.length + 1)}`;
  }
  return path;
}

const RE_SPECIAL = /[.*+?^${}()|[\]\\]/g;
/** What may come right before a path for it to be a path of its own (not the tail of another word or path). */
const BOUNDARY = /[\s"'`=:(]/;
/** A scheme: text after it, up to the next space, is a URL, not a path on this machine. */
const URL_LIKE = /[A-Za-z][A-Za-z0-9+.-]*:\/\//;

/**
 * Every project or home path inside a descriptive sentence, shortened the same way. A root is replaced
 * only where a path starts (the start of the text, after whitespace, a quote, `=`, `:` or `(`), never in
 * the middle of another path or inside URL-like text. Not for command or summary lines: those are shown
 * as written, so the person reads exactly what would run.
 */
export function shortenIn(text: string, c: PathContext): string {
  const roots = [...c.projects.map((r) => ({ r: `${strip(r)}/`, to: "" })), ...c.homes.map((h) => ({ r: `${strip(h)}/`, to: "~/" }))].filter((x) => x.r.length > 2).sort((a, b) => b.r.length - a.r.length);
  if (roots.length === 0) return text;
  const to = new Map<string, string>();
  for (const x of roots) if (!to.has(x.r)) to.set(x.r, x.to);
  const re = new RegExp(roots.map((x) => x.r.replace(RE_SPECIAL, "\\$&")).join("|"), "g");
  return text.replace(re, (match: string, at: number) => {
    const before = at === 0 ? "" : text.charAt(at - 1);
    if (before !== "" && !BOUNDARY.test(before)) return match;
    let start = at;
    while (start > 0 && !/\s/.test(text.charAt(start - 1))) start--;
    if (URL_LIKE.test(text.slice(start, at))) return match;
    return to.get(match) ?? match;
  });
}

/** Cuts the middle out of a long string, keeping both ends (the file name stays visible). */
export function middle(s: string, max = 56): string {
  if (s.length <= max) return s;
  const keep = max - 1;
  const tail = Math.ceil(keep * 0.6);
  return `${s.slice(0, keep - tail)}…${s.slice(s.length - tail)}`;
}
