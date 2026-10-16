/**
 * MCP tools: which server a tool belongs to, whether that server's results
 * are outside content, and whether a call reads, sends or destroys. Servers
 * are classed by the policy file first, then by built-in presets for the
 * well-known kinds. A server defined by the repository itself (.mcp.json,
 * Claude Code's "project" source) is never trusted on its name alone.
 */

import type { FirewallConfig, McpServerPolicy } from "../types.js";
import { own } from "../own.js";
import { globMatch } from "./glob.js";
import { isUnder, normalizeAbs } from "./paths.js";
import { forcedUntrusted } from "./outsider.js";

export interface McpTool {
  server: string;
  tool: string;
}

/** mcp__server__tool, including plugin servers (mcp__plugin_<plugin>_<server>__tool). */
export function parseMcpTool(name: string): McpTool | null {
  if (!name.startsWith("mcp__")) return null;
  const rest = name.slice(5);
  const i = rest.indexOf("__");
  if (i <= 0) return null;
  return { server: rest.slice(0, i), tool: rest.slice(i + 2) };
}

/**
 * mcp__server__tool where the separator runs into more underscores (mcp__crm___get_x): the server may end in "_"
 * (server "crm_", tool "get_x") or the tool may start with one (server "crm", tool "_get_x"). Review of FZ15: the
 * first reading put a server named "crm_" under the policy entry of "crm". The server is resolved only when the
 * longest reading names a server the policy lists by exact name; otherwise the name is ambiguous, and the caller
 * judges it with the first reading and FW-UNCLASSIFIABLE, so a person decides.
 */
export function resolveMcpTool(name: string, listed: Readonly<Record<string, unknown>>, known?: McpTool): (McpTool & { ambiguous: boolean }) | null {
  const first = parseMcpTool(name);
  if (first === null) return null;
  // I4: the agent named the server and the tool in fields of their own, and they spell this name: that is the identity.
  if (known !== undefined && known.server !== "" && known.tool !== "" && name === `mcp__${known.server}__${known.tool}`) return { ...known, ambiguous: false };
  // I4: every "__" boundary with a server before it and a tool after it is a reading. One reading: the name is clear.
  // More (mcp__a__b__c, mcp__crm___get_x): only the reading with the longest server, when the policy lists that server
  // by exact name, is taken; a shorter listed server is never chosen, since a server named "a__b" could pose as "a".
  const rest = name.slice(5);
  let longest: McpTool | null = null;
  let readings = 0;
  for (let i = rest.indexOf("__"); i !== -1; i = rest.indexOf("__", i + 1)) {
    if (i === 0 || i + 2 >= rest.length) continue;
    readings++;
    longest = { server: rest.slice(0, i), tool: rest.slice(i + 2) };
  }
  if (readings <= 1) return { ...first, ambiguous: false };
  if (longest !== null && own(listed, longest.server) !== undefined) return { ...longest, ambiguous: false };
  return { ...first, ambiguous: true };
}

const UNTRUSTED_PRIVATE = /github|gitlab|bitbucket|gitea|linear|jira|atlassian|confluence|notion|slack|discord|teams|gmail|e-?mail|mail|outlook|imap|smtp|gdrive|google|drive|calendar|whatsapp|telegram|signal|imessage|messages|sentry|intercom|zendesk|freshdesk|hubspot|salesforce|supabase|postgres|mysql|mongo|neon|planetscale|airtable|sqlite|database|db|redis|figma|asana|trello|clickup|monday|box|dropbox|onedrive|sharepoint|zoom|twitter|reddit|stripe|shopify|twilio|vercel|netlify|cloudflare|aws|gcp|azure|datadog|pagerduty|grafana|snowflake|bigquery|firebase|clerk|auth0|okta|hubspot|crm|support|ticket|helpdesk|issue/i;
const UNTRUSTED_PUBLIC = /fetch|browser|puppeteer|playwright|chrome|firefox|brave|tavily|exa|firecrawl|search|web|perplexity|context7|docs|youtube|arxiv|wikipedia|scrape|crawl|http|url|rss|news|hacker/i;
const LOCAL_TRUSTED = /^(?:sequential-?thinking|time|everything|calculator|math)$/i;

/** Servers that serve files from directories they are started with (the reference filesystem server and its kin). */
const FILESYSTEM_SERVER = /^(?:filesystem|file-?system|fs|local-?files?)$/i;

/** Whether a server's name is one of the filesystem servers' (plugin prefix ignored). */
export function isFilesystemServerName(server: string): boolean {
  return FILESYSTEM_SERVER.test(server.replace(/^plugin_[^_]+_/, ""));
}

/** The directories a filesystem server was started with and the workspace they must lie in (G6). */
export interface FsRoots {
  roots: readonly string[];
  workspace: readonly string[];
  caseInsensitive: boolean;
}

/** Whether every root the server was started with lies inside the workspace (and there is at least one). */
export function rootsInWorkspace(fs: FsRoots | undefined): boolean {
  if (fs === undefined || fs.roots.length === 0 || fs.workspace.length === 0) return false;
  return fs.roots.every((r) => fs.workspace.some((w) => isUnder(normalizeAbs(r), w, fs.caseInsensitive)));
}

/**
 * One layer's entry for a server: its exact name, else the first pattern that matches. Own entries only
 * (FB3): a server named "constructor" or "__proto__" is not listed by Object.prototype.
 */
export function matchServerEntry(servers: Readonly<Record<string, McpServerPolicy>>, server: string): McpServerPolicy | undefined {
  const exact = own(servers, server);
  if (exact !== undefined) return exact;
  for (const [pattern, p] of Object.entries(servers)) {
    if (pattern.includes("*") && globMatch(pattern, server, true)) return p;
  }
  return undefined;
}

/**
 * The policy for a server, looked up by exact name, then by pattern, then presets, then the default. A
 * server (or, given `tool`, a tool) whose content outsiders write keeps untrusted results whatever the
 * lookup said (src/engine/outsider.ts, `outsiderWritable.alwaysTaint`).
 */
export function serverPolicy(server: string, cfg: FirewallConfig, source?: string, fs?: FsRoots, tool?: string): McpServerPolicy {
  const exact = own(cfg.mcpServers, server);
  let policy: McpServerPolicy | undefined = matchServerEntry(cfg.mcpServers, server);
  if (policy === undefined) {
    // Built-in presets by the kind of system the server name suggests.
    const name = server.replace(/^plugin_[^_]+_/, "");
    if (LOCAL_TRUSTED.test(name)) policy = { results: "trusted", privateData: false };
    // G6: a filesystem server whose launch arguments confine it to the workspace reads files the
    // session could read anyway; the path rules still judge every path it is asked for. Roots that
    // are unknown, empty or outside the workspace keep the default (untrusted, private).
    else if (FILESYSTEM_SERVER.test(name) && rootsInWorkspace(fs)) policy = { results: "trusted", privateData: false };
    else if (UNTRUSTED_PRIVATE.test(name)) policy = { results: "untrusted", privateData: true };
    else if (UNTRUSTED_PUBLIC.test(name)) policy = { results: "untrusted", privateData: false };
    else policy = cfg.mcpDefault;
  }
  // A repository-defined server can claim any name; its results are outside content unless the user's
  // own policy lists it by exact name.
  if (source !== undefined && /^(?:project|dynamic|unknown)$/i.test(source) && exact === undefined) {
    policy = { ...policy, results: "untrusted" };
  }
  if (policy.results === "trusted" && forcedUntrusted(server, cfg, tool)) policy = { ...policy, results: "untrusted" };
  return policy;
}

export type ToolKind = "read" | "send" | "destroy" | "blocked";

const DESTROY_WORDS = /^(?:delete|remove|drop|destroy|purge|truncate|wipe|erase|reset|terminate|archive|revoke|ban|kick|unpublish|cancel|close_account|deactivate|disable|kill|uninstall|prune|flush|empty)$/i;
const SEND_WORDS = /^(?:create|update|edit|write|send|post|publish|push|merge|comment|reply|forward|share|invite|upload|insert|upsert|execute|exec|run|apply|deploy|set|add|put|patch|move|rename|assign|close|reopen|submit|transfer|approve|trigger|dispatch|fork|star|navigate|goto|open|click|type|fill|press|select|hover|drag|evaluate|eval|install|tag|label|react|pin|schedule|book|pay|charge|refund|transfer|mint|sign|grant|enable|start|stop|restart|resolve|assign|mention|message|dm|email|notify|call|invoke|request|import|export|sync|save|store|remember|record|log|track|link|attach|mark|complete|claim|lock|unlock|join|leave|subscribe|unsubscribe|follow|like|vote|rate|replace|clear)$/i;
const READ_WORDS = /^(?:get|list|search|read|fetch|find|describe|show|view|retrieve|lookup|count|check|status|inspect|browse|screenshot|snapshot|query|select|download|preview|info|explain|summarize|resolve_library_id|docs|diff|compare|analyze|validate|lint|test|ping|whoami|me|current|recent|history|logs?|metrics|stats|scan|recall|load|open_nodes|search_nodes|read_graph)$/i;

/** Splits a tool name into lower-case words (create_issue, createIssue, create-issue). */
export function toolWords(tool: string): string[] {
  return tool
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .split(/[_\-.\s/]+/)
    .filter((w) => w !== "")
    .map((w) => w.toLowerCase());
}

/** What a tool call does, from the policy's lists first and the tool's name second. Unknown means send. */
export function toolKind(tool: string, policy: McpServerPolicy): ToolKind {
  // Past the matcher's bounds a name is taken to be on the blocking lists and off the read list.
  const inList = (list: string[] | undefined, onLimit = true): boolean => (list ?? []).some((p) => globMatch(p, tool, true, onLimit));
  if (inList(policy.blockedTools)) return "blocked";
  if (inList(policy.destructiveTools)) return "destroy";
  if (inList(policy.sendTools)) return "send";
  if (inList(policy.readTools, false)) return "read";
  const words = toolWords(tool);
  if (words.some((w) => DESTROY_WORDS.test(w))) return "destroy";
  // "get_or_create_user", "search_and_replace": a reading verb joined to a writing one by and/or/then does both.
  const joint = words.findIndex((w) => w === "and" || w === "or" || w === "then");
  if (joint !== -1 && words.slice(joint + 1).some((w) => SEND_WORDS.test(w))) return "send";
  // The verb is usually the first word (get_issue, create_issue); some servers put it last (issue_create).
  const verb = [words[0] ?? "", words[words.length - 1] ?? ""];
  if (verb.some((w) => SEND_WORDS.test(w))) return "send";
  if (verb.some((w) => READ_WORDS.test(w))) return "read";
  if (words.some((w) => SEND_WORDS.test(w))) return "send";
  if (words.some((w) => READ_WORDS.test(w))) return "read";
  return "send";
}

/** Tools that send a message to people: email, chat, comments. */
export function isMessageTool(server: string, tool: string): boolean {
  if (/mail|slack|discord|teams|whatsapp|telegram|signal|imessage|sms|twilio|chat|messages/i.test(server)) return true;
  const words = toolWords(tool);
  if (words.some((w) => /^(?:message|messages|comment|comments|reply|replies|dm|chat|sms|mms)$/.test(w))) return true;
  // "send_email", "post_to_channel": a sending verb. An account change that mentions email
  // (update_recovery_email) is not a message to people.
  return words.some((w) => /^(?:send|post|forward|notify)$/.test(w)) && words.some((w) => /^(?:email|mail|text|to|note|notification|channel|thread|user|contact|contacts)$/.test(w) || words.length === 1);
}

/** A destination identity for "the user named this" checks: github:owner/repo, slack:#channel, or mcp:server. */
export function mcpDestination(server: string, input: Record<string, unknown>): string {
  const str = (k: string): string | undefined => {
    const v = own(input, k);
    return typeof v === "string" ? v : undefined;
  };
  const owner = str("owner") ?? str("org") ?? str("organization");
  const repo = str("repo") ?? str("repository") ?? str("repo_name");
  if (owner !== undefined && repo !== undefined) return `${server}:${owner}/${repo}`.toLowerCase();
  if (repo !== undefined && repo.includes("/")) return `${server}:${repo}`.toLowerCase();
  const channel = str("channel") ?? str("channel_id") ?? str("chat_id") ?? str("conversation");
  if (channel !== undefined) return `${server}:${channel}`.toLowerCase();
  const to = str("to") ?? str("recipient") ?? str("email") ?? str("phone") ?? str("number");
  if (to !== undefined) return `${server}:${to}`.toLowerCase();
  const project = str("project_id") ?? str("project") ?? str("projectId");
  if (project !== undefined) return `${server}:${project}`.toLowerCase();
  return `mcp:${server}`.toLowerCase();
}
