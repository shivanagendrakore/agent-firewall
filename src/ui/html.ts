/**
 * R6 for HTML: every value the dashboard renders goes through one tagged template that escapes by
 * default. Interpolated text is first passed through safeText (C0/C1 controls, DEL, bidirectional and
 * zero-width characters become visible \uXXXX escapes, as on the terminal), then the five HTML
 * metacharacters become entities, so it is inert in element content and in quoted attributes alike.
 * Markup only ever comes from the template literals themselves (or from another `html` result).
 *
 * The vault: a reference such as `vault://github/token` is the name of a stored secret, not
 * its value; in element content it is marked as one (a `vref` span saying so). A stored value is never
 * shown: while a page renders with the vault's view (withVault), any interpolated line that contains a
 * stored value (recognised by fingerprint, in the clear or encoded) is replaced by a note naming the
 * secret, in element content and in attributes alike.
 */

import { safeText } from "../engine/terminal.js";
import { entriesIn, findRefs, formatRef, type VaultView } from "../engine/vault-ref.js";
import { own, setOwn } from "../own.js";

/** Markup that is already safe (built by `html`). Never constructed from outside text. */
export class Html {
  constructor(readonly value: string) {}
  toString(): string {
    return this.value;
  }
}

const ENTITIES: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/** Text for element content or a quoted attribute value. Never throws. */
export function esc(value: unknown): string {
  return safeText(typeof value === "string" ? value : String(value), { keepTabs: true }).replace(/[&<>"']/g, (c) => own(ENTITIES, c) as string);
}

/** The vault's view while a page renders (names and fingerprints; never a value). Set only by withVault. */
let vault: VaultView | undefined;

/** Renders a page with the vault's view, so stored values are hidden wherever they would appear. Synchronous. */
export function withVault<T>(view: VaultView | undefined, render: () => T): T {
  const before = vault;
  vault = view;
  try {
    return render();
  } finally {
    vault = before;
  }
}

/** A line that contains a stored value, as the note shown instead (null when it contains none). */
function hiddenLine(line: string): string | null {
  const found = entriesIn(line, vault);
  return found.length === 0 ? null : `[hidden: this contains the value of ${found.map((e) => formatRef(e.name)).join(", ")}]`;
}

/** Text with every line holding a stored value replaced (a value split across lines hides the whole text). */
export function hideVaultValues(text: string): string {
  if (vault === undefined || vault.entries.length === 0) return text;
  const lines = text.split("\n");
  let changed = false;
  const out = lines.map((l) => {
    const h = hiddenLine(l);
    if (h === null) return l;
    changed = true;
    return h;
  });
  if (changed) return out.join("\n");
  return hiddenLine(text) ?? text;
}

/** Escaped text with vault references marked (element content only). */
function content(s: string): string {
  const refs = findRefs(s);
  if (refs.length === 0) return esc(s);
  let out = "";
  let at = 0;
  for (const r of refs) {
    out += esc(s.slice(at, r.index));
    out += `<span class="vref" title="A vault reference: the name of a stored secret, not its value">${esc(r.text)}</span>`;
    at = r.index + r.text.length;
  }
  return out + esc(s.slice(at));
}

/** The most characters one interpolated field shows; the rest is cut with a note (DB6: a page stays small whatever the log or queue holds). */
export const MAX_FIELD = 2000;

/** `text` cut to `max` characters with a visible note saying how much is not shown. */
export function truncated(text: string, max: number): string {
  if (text.length <= max) return text;
  // Never cut between the two halves of a surrogate pair.
  let end = max;
  const code = text.charCodeAt(end - 1);
  if (code >= 0xd800 && code <= 0xdbff) end--;
  return `${text.slice(0, end)}… [truncated: ${text.length - end} more characters not shown]`;
}

function render(v: unknown, inTag: boolean): string {
  if (v instanceof Html) return v.value;
  if (v === null || v === undefined || v === false) return "";
  if (Array.isArray(v)) return v.map((x) => render(x, inTag)).join("");
  // Stored values are hidden on the whole text first, so a value longer than the cut never shows as a prefix.
  const s = truncated(hideVaultValues(typeof v === "string" ? v : String(v)), MAX_FIELD);
  return inTag ? esc(s) : content(s);
}

/** A long block (a pre): vault values hidden on the whole text, then cut to `max` and escaped. */
export function longText(text: string, max: number): Html {
  return new Html(content(truncated(hideVaultValues(text), max)));
}

/** Most keys or items shown for one object or list. */
export const MAX_FIELDS = 50;

/**
 * A tool input for display: every string cut to MAX_FIELD (after the vault's values are hidden), at most
 * MAX_FIELDS keys or items per object or list with a "+N more" entry, and a depth limit.
 */
export function boundedValue(v: unknown, depth = 0): unknown {
  if (typeof v === "string") return truncated(hideVaultValues(v), MAX_FIELD);
  if (v === null || typeof v !== "object") return v;
  if (depth >= 8) return "[nested too deep to show]";
  if (Array.isArray(v)) {
    const shown = v.slice(0, MAX_FIELDS).map((x) => boundedValue(x, depth + 1));
    return v.length > MAX_FIELDS ? [...shown, `+${v.length - MAX_FIELDS} more`] : shown;
  }
  const keys = Object.keys(v as Record<string, unknown>);
  const out: Record<string, unknown> = {};
  for (const k of keys.slice(0, MAX_FIELDS)) setOwn(out, truncated(k, 200), boundedValue(own(v as Record<string, unknown>, k), depth + 1));
  if (keys.length > MAX_FIELDS) out[`+${keys.length - MAX_FIELDS} more`] = "not shown";
  return out;
}

/** Whether template text so far ends inside a tag (an attribute value), where no markup may be added. */
function insideTag(sofar: string): boolean {
  return sofar.lastIndexOf("<") > sofar.lastIndexOf(">");
}

/** `html\`<p>${text}</p>\``: interpolations are escaped unless they are Html; arrays are concatenated. */
export function html(strings: TemplateStringsArray, ...values: unknown[]): Html {
  let out = strings[0] ?? "";
  for (let i = 0; i < values.length; i++) out += render(values[i], insideTag(out)) + (strings[i + 1] ?? "");
  return new Html(out);
}

/** Joins rendered parts. */
export function join(parts: readonly Html[], sep = ""): Html {
  return new Html(parts.map((p) => p.value).join(sep));
}
