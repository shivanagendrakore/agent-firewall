/**
 * Plain-language descriptions for people: what an action wanted to do, why a
 * rule stopped it (one sentence), and where the outside content came from.
 * Used by the queue and status views. Pure.
 */

import { parseMcpTool, toolWords } from "./mcp.js";
import { parseUrlLike } from "./network.js";
import { RULES } from "../rules.js";
import { own } from "../own.js";

function capitalize(s: string): string {
  return s.length === 0 ? s : s[0]!.toUpperCase() + s.slice(1);
}

function relative(path: string, cwd: string): string {
  if (cwd === "") return path;
  // A loop, not /\/+$/, whose retries are quadratic on a long run of slashes mid-string.
  let end = cwd.length;
  while (end > 0 && cwd.charCodeAt(end - 1) === 47) end--;
  const base = cwd.slice(0, end);
  return path.startsWith(`${base}/`) ? path.slice(base.length + 1) : path;
}

/** What the agent wanted to do, in one short line. */
export function summarizeAction(tool: string, input: Record<string, unknown>, cwd: string, effectDetail?: string): string {
  const str = (k: string): string => (typeof own(input, k) === "string" ? (own(input, k) as string) : "");
  switch (tool) {
    case "Write":
    case "Edit":
    case "MultiEdit":
    case "NotebookEdit": {
      const p = str("file_path") || str("notebook_path") || str("path");
      return `Change ${relative(p, cwd)}`;
    }
    case "Read":
      return `Read ${relative(str("file_path"), cwd)}`;
    case "WebFetch": {
      const u = parseUrlLike(str("url"));
      return `Fetch a page from ${u?.host ?? str("url")}`;
    }
    case "HttpRequest": {
      const u = parseUrlLike(str("url"));
      return `${(str("method") || "GET").toUpperCase().slice(0, 16)} request to ${u?.host ?? str("url")}`;
    }
    case "WebSearch":
      return `Search the web for "${str("query")}"`;
    case "Bash": {
      const cmd = str("command").trim();
      const push = /^git\s+(?:-C\s+\S+\s+)?push(?:\s+(?:-\S+\s+)*([^\s-]\S*))?/.exec(cmd);
      if (push !== null) return `Push commits to ${push[1] ?? "the default remote"}`;
      if (effectDetail !== undefined && effectDetail !== "") return capitalize(effectDetail.replace(/\s*\([^()]*\)$/, ""));
      return `Run: ${cmd}`;
    }
    default: {
      const mcp = parseMcpTool(tool);
      if (mcp !== null) {
        const words = toolWords(mcp.tool).join(" ");
        const owner = str("owner");
        const repo = str("repo");
        const where = owner !== "" && repo !== "" ? ` on ${owner}/${repo}` : str("channel") !== "" ? ` in ${str("channel")}` : str("recipient") !== "" ? ` to ${str("recipient")}` : "";
        return `${capitalize(words)} (${mcp.server})${where}`;
      }
      return effectDetail !== undefined && effectDetail !== "" ? capitalize(effectDetail) : `Use ${tool}`;
    }
  }
}

export function ruleSentence(rules: readonly string[], reasons: readonly string[]): string {
  for (const r of rules) {
    const s = own(RULES, r)?.sentence;
    if (s !== undefined) return s;
  }
  const first = (reasons[0] ?? "").split(/(?<=\.)\s/)[0] ?? "";
  return capitalize(first.replace(/^[^:]*:\s*/, ""));
}

/** Where outside content came from, phrased for "after reading ...". */
export function describeSource(source: string): string {
  const s = source.trim();
  const mcp = /^read (?:from |the result of )([\w.-]+?)\.([\w-]+)(?:\s|$)/.exec(s);
  if (mcp !== null) {
    const label = `${mcp[1]}.${mcp[2]}`;
    const server = (mcp[1] ?? "").toLowerCase();
    if (/mail|gmail|outlook|imap/.test(server)) return `an email from ${label}`;
    if (/slack|discord|teams|whatsapp|telegram|signal|chat|messages/.test(server)) return `a message from ${label}`;
    if (/github|gitlab|bitbucket|linear|jira|atlassian/.test(server)) return `content from ${label}`;
    return `results from ${label}`;
  }
  return s.replace(/^read (?:what )?/, "");
}
