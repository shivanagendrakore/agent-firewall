/** Whitespace-separated names to a list (keeps the data files compact and diff-friendly). */
export function names(text: string): string[] {
  return text.split(/\s+/).filter((s) => s !== "");
}
