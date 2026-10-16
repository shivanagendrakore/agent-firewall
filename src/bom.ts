/**
 * A UTF-8 byte order mark. Windows editors and PowerShell 5 put one before a file's or a pipe's text, Node's
 * "utf8" decoding keeps it as U+FEFF, and JSON.parse refuses it, so correct JSON would be rejected for three
 * invisible bytes. One leading mark is dropped where the firewall reads a file or standard input to parse it.
 */

/** `text` without one leading U+FEFF. */
export function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}
