/**
 * The leak guard's DOM-free helpers (content script), so they are unit-tested
 * in Node: the value a field would hold after an insertion, which verdicts
 * hold data back, the text a submitted form carries, and the notice copy.
 */
import type { LeakFinding } from "../engine/leak.js";
import type { Verdict } from "../engine/types.js";

/** The value after inserting `inserted` over the selection [start, end); an unknown selection appends. */
export function prospectiveValue(value: string, start: number | null, end: number | null, inserted: string): string {
  if (start === null || end === null || start < 0 || end < start || end > value.length) return value + inserted;
  return value.slice(0, start) + inserted + value.slice(end);
}

/** approve and deny hold the data back; warn and log let it through (and are reported). */
export function holdsBack(v: Verdict): boolean {
  return v === "approve" || v === "deny";
}

export function reported(v: Verdict): boolean {
  return v !== "allow";
}

/** beforeinput types that add text. Deletions and formatting never carry data out. */
export function insertsText(inputType: string): boolean {
  return inputType.startsWith("insert") && inputType !== "insertLineBreak" && inputType !== "insertParagraph" && inputType !== "insertHorizontalRule" && inputType !== "insertOrderedList" && inputType !== "insertUnorderedList";
}

/** Input types whose value is free text a person or agent could type data into. */
const TEXT_INPUT_TYPES = new Set(["", "text", "search", "email", "url", "tel", "password", "number"]);

export function isTextInputType(type: string): boolean {
  return TEXT_INPUT_TYPES.has(type.toLowerCase());
}

/** The text a submitted form carries: "name=value" per field, one per line (names give the detectors context). */
export function formText(fields: readonly { name: string; value: string }[]): string {
  return fields
    .filter((f) => f.value !== "")
    .map((f) => `${f.name}=${f.value}`)
    .join("\n");
}

/**
 * The most text the content script scans in one decision (one field value, one form, one link's query). Larger
 * values are not judged in the page at all: they are held and the worker, which rate-limits each frame, decides.
 * So a page cannot make one keystroke cost more than one bounded scan here.
 */
export const MAX_LOCAL_SCAN = 64 * 1024;

export function exceedsLocalScan(text: string): boolean {
  return text.length > MAX_LOCAL_SCAN;
}

/** The query values (and fragment) a link carries, decoded, one per line: what the leak guard judges on a link click. */
export function linkQueryText(url: URL): string {
  const out: string[] = [];
  for (const [k, v] of url.searchParams) {
    if (v !== "") out.push(`${k}=${v}`);
    else if (k !== "") out.push(k);
  }
  const frag = url.hash.replace(/^#/, "");
  if (frag !== "") {
    try {
      out.push(decodeURIComponent(frag));
    } catch {
      out.push(frag);
    }
  }
  return out.join("\n");
}

/** The in-page notice. It explains; it is never the approval (design 5.4). Finding names only, never values. */
export function noticeText(verdict: Verdict, findings: readonly LeakFinding[], destinationHost: string): string {
  const what = findings.length === 0 ? "private data" : [...new Set(findings.map((f) => (f.kind === "seen_elsewhere" ? `text shown on ${f.seenOn ?? "another site"}` : `a ${f.name}`)))].join(", ");
  if (verdict === "deny") return `LaunchSafe stopped this: it carries ${what} to ${destinationHost} from a page with hidden instructions.`;
  if (verdict === "approve") return `LaunchSafe held this back: it carries ${what} to ${destinationHost}. Approve or deny it in the LaunchSafe side panel.`;
  return `LaunchSafe: this looks like ${what} going to ${destinationHost}.`;
}
