/**
 * The side-by-side view of a proposal: the unified diff lines from proposalDiff ("  ", "- ", "+ ")
 * turned into rows of (before, after). A run of removed lines followed by a run of added lines is
 * paired line by line, so a changed line sits next to what replaces it; unchanged lines stay aligned.
 * Pure.
 */

export interface Side {
  n: number;
  text: string;
}

export interface Row {
  kind: "same" | "change" | "del" | "add";
  left: Side | null;
  right: Side | null;
}

export function sideBySide(lines: readonly string[]): Row[] {
  const rows: Row[] = [];
  let ln = 0;
  let rn = 0;
  let i = 0;
  while (i < lines.length) {
    const line = lines[i] as string;
    const tag = line.slice(0, 2);
    if (tag !== "- " && tag !== "+ ") {
      rows.push({ kind: "same", left: { n: ++ln, text: line.slice(2) }, right: { n: ++rn, text: line.slice(2) } });
      i++;
      continue;
    }
    const dels: string[] = [];
    const adds: string[] = [];
    while (i < lines.length && (lines[i] as string).startsWith("- ")) dels.push((lines[i++] as string).slice(2));
    while (i < lines.length && (lines[i] as string).startsWith("+ ")) adds.push((lines[i++] as string).slice(2));
    const n = Math.max(dels.length, adds.length);
    for (let k = 0; k < n; k++) {
      const d = dels[k];
      const a = adds[k];
      rows.push({ kind: d !== undefined && a !== undefined ? "change" : d !== undefined ? "del" : "add", left: d !== undefined ? { n: ++ln, text: d } : null, right: a !== undefined ? { n: ++rn, text: a } : null });
    }
  }
  return rows;
}
