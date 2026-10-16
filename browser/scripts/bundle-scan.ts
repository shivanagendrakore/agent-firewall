/**
 * Scans built JavaScript for the things a "makes no network requests, loads no
 * remote code" extension must not contain (docs/design.md section 12, store
 * review checklist item 1): dynamic code evaluation and every network API.
 *
 * It reads the syntax tree, so a word in a comment or a string ("fetch the
 * list") is not a finding, but a call, a `new`, a property access (`self.fetch`,
 * `navigator.sendBeacon`) or a quoted property (`self["fetch"]`) is. The scan
 * only parses text; it never runs it.
 */
import ts from "typescript";

/** Names that are findings as a bare identifier or as a property of anything. */
const BANNED = new Set(["eval", "Function", "fetch", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "importScripts", "WebTransport", "RTCPeerConnection"]);

export interface Finding {
  file: string;
  name: string;
  line: number;
}

/** One reviewed exception: a file and a name, with the reason it is safe. The list is empty on purpose. */
export interface Allowed {
  file: string;
  name: string;
  reason: string;
}

export const ALLOWLIST: readonly Allowed[] = [];

/** The names in the code that a banned word is used as, not merely mentioned. */
export function scanSource(file: string, code: string): Finding[] {
  const sf = ts.createSourceFile(file, code, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const out: Finding[] = [];
  const add = (node: ts.Node, name: string): void => {
    out.push({ file, name, line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1 });
  };
  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node) && BANNED.has(node.text)) {
      const p = node.parent;
      // A declaration or a key in an object literal / class names something of ours; it is not a use of the API.
      const declares = (ts.isPropertyAssignment(p) && p.name === node) || (ts.isMethodDeclaration(p) && p.name === node) || (ts.isPropertyDeclaration(p) && p.name === node) || (ts.isShorthandPropertyAssignment(p) && p.name === node && false);
      if (!declares) add(node, node.text);
    } else if (ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression) && BANNED.has(node.argumentExpression.text)) {
      add(node, node.argumentExpression.text);
    } else if ((ts.isCallExpression(node) || ts.isNewExpression(node)) && ts.isIdentifier(node.expression) && (node.expression.text === "setTimeout" || node.expression.text === "setInterval")) {
      // setTimeout("code") is eval by another name.
      const first = node.arguments?.[0];
      if (first !== undefined && ts.isStringLiteralLike(first)) add(node, `${node.expression.text}(string)`);
    } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      const arg = node.arguments[0];
      if (arg === undefined || !ts.isStringLiteralLike(arg) || /^(?:https?:)?\/\//i.test(arg.text)) add(node, "import()");
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

/** Findings not covered by the allowlist. */
export function disallowed(findings: readonly Finding[], allow: readonly Allowed[] = ALLOWLIST): Finding[] {
  return findings.filter((f) => !allow.some((a) => a.file === f.file && a.name === f.name));
}

/** Remote script or stylesheet references in a built HTML page. */
export function remoteReferencesInHtml(file: string, html: string): Finding[] {
  const out: Finding[] = [];
  for (const m of html.matchAll(/<(?:script|link|iframe|img|object|embed)\b[^>]*?\b(?:src|href|data)\s*=\s*["']?\s*((?:https?:)?\/\/[^"'\s>]+)/gi)) {
    out.push({ file, name: m[1] as string, line: html.slice(0, m.index).split("\n").length });
  }
  for (const m of html.matchAll(/<script\b(?![^>]*\bsrc\s*=)[^>]*>\s*\S/gi)) {
    out.push({ file, name: "inline script", line: html.slice(0, m.index).split("\n").length });
  }
  return out;
}
