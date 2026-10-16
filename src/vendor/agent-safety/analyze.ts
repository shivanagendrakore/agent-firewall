// Vendored from LaunchSafe's agent-safety package (src/analyze.ts), Apache-2.0, at commit fc329d4314dc07a65da266a1256b1da0d17ec97c.
// Licence: Apache-2.0 (see NOTICE).
// Transform: add ".js" to relative import specifiers.
// Do not edit here: it is copied from the upstream package by
// `node scripts/sync-agent-safety.mjs` (`--check` verifies the copy).

// DIVERGES FROM UPSTREAM (firewall audit B1, B2, I1-I6, I9, I12 and minor items): a work budget and
// long-line pieces (both reported), a finding for every file that does not parse or is too large
// (UTF-8 bytes), injection rules inside code fences at low confidence, wrapped lines joined, Markdown
// comments and link titles read, line continuations joined, connected exfiltration for
// instructions, many more settings keys (Claude Code, Gemini CLI, Codex, VS Code, Cursor, dev
// containers), a real TOML parser for Codex and Gemini command files, dependsOn followed from
// folder-open tasks, \r and U+2028 line breaks, local files one step less severe, and an allowlist
// for model gateways. Upstream should take these changes.

/**
 * The agent-safety check: reads the files that program and arm coding agents
 * in a repository and reports known-bad and unsafe configuration, each with
 * the exact line as evidence, its impact and its fix.
 *
 * Static and deterministic: it never runs, installs or contacts anything a
 * file names, calls no model, and gives the same answer for the same files.
 * Pure (no Node APIs), so the runner, the public grade and the browser paste
 * checker all run this one function. A clean result means no known-bad
 * pattern was found in the files checked; it is not proof that a skill, a
 * server or an instruction file is benign.
 *
 * Bounded: lines longer than MAX_LINE are checked in overlapping pieces (and
 * reported), and the whole check stops at a work budget (and reports that),
 * so no input can make it run for long or skip a file silently.
 */
import { sha256HexSync } from "./canonical.js";
import { entriesOf, itemsOf, member, parseJsoncResult, stringOf, stringsOf, type JNode } from "./jsonc.js";
import { containerHostAccess, launchedPackage, opensWholeDisk, pinState, shellSplit } from "./launch.js";
import { agentFileKind, classifyAgentFiles, isAgentConfig, isLocalAgentFile, isMemoryIndex, type AgentFileKind } from "./paths.js";
import { RULES, type AgentRule, type RuleKey } from "./rules.js";
import {
  chunksOf,
  commandRisks,
  connectedExfiltration,
  credentialValue,
  decodeTagCharacters,
  decodeVariationSelectors,
  directsToMetadata,
  endpointVerdict,
  envPreload,
  hiddenBase64In,
  hiddenTextIn,
  injectionMatch,
  isAgentDirective,
  isCaptureUrl,
  isLocalHost,
  isMetadataHost,
  isRawIp,
  maskSecret,
  MAX_LINE,
  MEMORY_INDEX_MAX_BYTES,
  MEMORY_INDEX_MAX_LINES,
  MEMORY_TOPIC_MAX_BYTES,
  MODEL_ENDPOINT_VARS,
  outboundInstructionIn,
  permissionOffIn,
  permissionOffSaid,
  PROXY_VARS,
  REGISTRY_ENV,
  remoteInstructionsIn,
  revealInvisible,
  skipChecksIn,
  standingOverrideIn,
  tokenShapeIn,
  urlsIn,
  type CommandRisk,
} from "./signals.js";
import { parseToml } from "./toml.js";
import type { AgentFile, AgentFinding, AgentInventoryItem, AgentInventoryKind, AgentMemoryFile, AgentSeverity } from "./types.js";

export interface AgentAnalysis {
  findings: AgentFinding[];
  /** Agent configuration files read, memory included (env files and package.json are read for context and not counted). */
  filesChecked: number;
  /** Every path the check read, agent configuration or context. */
  filesRead: string[];
  /** What the files make run or connect on their own (hooks, folder-open tasks, MCP servers), flagged or not. */
  inventory: AgentInventoryItem[];
  /** The agent memory files read, by path, flagged or not: what the agent loads into later sessions and writes itself. */
  memory: AgentMemoryFile[];
  /** Units of work spent (characters run through the detectors); at most the budget plus one line. */
  work: number;
  /** Paths the work budget left unchecked (empty when every file was checked). */
  unchecked: string[];
}

export interface AnalyzeOptions {
  /** The work budget in characters run through the detectors (default MAX_WORK). */
  maxWork?: number;
  /** Model gateways the person runs themselves: a model endpoint on one of these hosts (HTTPS) is not a finding. */
  allowedModelHosts?: readonly string[];
}

/** Files larger than this (in UTF-8 bytes) are not agent configuration anyone hand-writes; they are reported, not half-read. */
export const MAX_FILE_BYTES = 512 * 1024;
/** The default work budget: several times what the largest collection the firewall reads (8 MB) costs. */
export const MAX_WORK = 64 * 1024 * 1024;

const SEVERITY_ORDER: Record<AgentSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const LOWER: Record<AgentSeverity, AgentSeverity> = { critical: "high", high: "medium", medium: "low", low: "low" };

interface AddOptions {
  severity?: AgentSeverity;
  confidence?: AgentFinding["confidence"];
  /** A sentence placed before the rule's impact: where it runs, or what was found. */
  context?: string;
  /** Text to mask in the evidence line. */
  secret?: string;
  /** Extra evidence after the line (for example decoded hidden text). */
  note?: string;
}

/** A production credential seen in the repository, by file and name only. */
interface ProductionCredential {
  file: string;
  name: string;
}

/** Masks every credential shape in a line and makes invisible characters visible. */
function safeText(text: string): string {
  let out = text;
  for (let k = 0, hit = tokenShapeIn(out); hit !== null && k < 5; k += 1, hit = tokenShapeIn(out)) out = maskSecret(out, hit.value);
  return revealInvisible(out);
}

/** UTF-8 length without building the bytes. */
export function utf8Length(text: string): number {
  let n = 0;
  for (let k = 0; k < text.length; k += 1) {
    const c = text.charCodeAt(k);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && k + 1 < text.length) {
      n += 4;
      k += 1;
    } else n += 3;
  }
  return n;
}

/** Lines as editors and agents break them: \n, \r\n, a lone \r, U+2028 and U+2029. A leading byte order mark is dropped. */
/** \r\n, \r, \n, U+2028, U+2029 (built from code points so no line separator sits in this source file). */
const LINE_BREAK = new RegExp(`\\r\\n|\\r|\\n|${String.fromCharCode(0x2028)}|${String.fromCharCode(0x2029)}`);

export function splitLines(content: string): string[] {
  return (content.charCodeAt(0) === 0xfeff ? content.slice(1) : content).split(LINE_BREAK);
}

class Budget {
  spent = 0;
  constructor(readonly max: number) {}
  /** Spends `n`; false once the budget is gone. */
  take(n: number): boolean {
    if (this.spent >= this.max) return false;
    this.spent += n;
    return true;
  }
  get over(): boolean {
    return this.spent >= this.max;
  }
}

class Collector {
  readonly findings: AgentFinding[] = [];
  readonly inventory: AgentInventoryItem[] = [];
  readonly production: ProductionCredential[] = [];
  /** Claude Code deny rules that keep the agent away from environment files. */
  deniesEnvRead = false;
  /** A sentence placed before every finding's context while one file is read (memory files say what memory is). */
  lead: string | undefined;
  private readonly seen = new Set<string>();

  constructor(
    private readonly lines: Map<string, string[]>,
    readonly budget: Budget,
    readonly allowedModelHosts: readonly string[],
  ) {}

  add(key: RuleKey, file: string, line: number, options: AddOptions = {}): void {
    const rule: AgentRule = RULES[key];
    const dedupe = `${rule.id}|${file}|${line}`;
    if (this.seen.has(dedupe)) return;
    this.seen.add(dedupe);
    let evidence = (this.lines.get(file)?.[line - 1] ?? "").slice(0, 2048).trim();
    if (options.secret !== undefined) evidence = maskSecret(evidence, options.secret);
    // Any other credential shape on the line is masked too: evidence never carries a usable secret.
    evidence = safeText(evidence);
    if (evidence.length > 300) evidence = `${evidence.slice(0, 299)}…`;
    if (options.note !== undefined) evidence = `${evidence}\n${options.note}`;
    const context = [this.lead, options.context].filter((s): s is string => s !== undefined).join(" ");
    let severity = options.severity ?? rule.severity;
    // A file kept out of git by convention is the person's own: one step less severe (never a coverage gap).
    if (rule.family !== "coverage" && isLocalAgentFile(file)) severity = LOWER[severity];
    this.findings.push({
      ruleId: rule.id,
      family: rule.family,
      title: rule.title,
      severity,
      confidence: options.confidence ?? rule.confidence,
      cwe: rule.cwe,
      findingType: rule.findingType,
      file,
      line: Math.max(1, line),
      evidence,
      impact: context === "" ? rule.impact : `${context} ${rule.impact}`,
      fix: rule.fix,
    });
  }

  /** Records something that runs or connects on its own. */
  ran(kind: AgentInventoryKind, file: string, line: number, label: string, detail: string): void {
    const whole = detail.replace(/\s+/g, " ").trim();
    let text = safeText(whole.slice(0, 2048));
    if (text.length > 200) text = `${text.slice(0, 199)}…`;
    this.inventory.push({ kind, file, line: Math.max(1, line), label, detail: text, sha256: sha256HexSync(whole) });
  }
}

const RISK_RULE: Record<Exclude<CommandRisk, "network">, RuleKey> = { remote_code: "remoteCode", exfiltration: "exfiltration", obfuscated: "obfuscated" };

/** The risks of a command of any length: checked in pieces past MAX_LINE (reported as a long line). */
function boundedRisks(out: Collector, file: string, line: number, command: string): Set<CommandRisk> {
  const risks = new Set<CommandRisk>();
  if (command.length > MAX_LINE) out.add("longLine", file, line, { context: `A command of ${command.length} characters was checked in pieces.` });
  for (const piece of chunksOf(command)) {
    out.budget.take(piece.length);
    for (const r of commandRisks(piece)) risks.add(r);
  }
  return risks;
}

/**
 * A command something runs on its own. `onOpen`: it runs when a session
 * starts or the folder opens (a plain network call is medium); otherwise a
 * plain network call is reported at low severity. Returns whether anything
 * above low was reported.
 */
function checkAutoCommand(out: Collector, file: string, line: number, command: string, context: string, onOpen: boolean): boolean {
  let found = false;
  const risks = boundedRisks(out, file, line, command);
  for (const risk of risks) {
    if (risk === "network") {
      if (onOpen) {
        out.add("networkOnOpen", file, line, { context });
        found = true;
      } else out.add("networkAutoRun", file, line, { context });
      continue;
    }
    out.add(RISK_RULE[risk], file, line, { context });
    found = true;
  }
  for (const piece of chunksOf(command)) {
    for (const { url, host } of urlsIn(piece)) {
      if (isCaptureUrl(url, host) || isRawIp(host)) {
        out.add("captureEndpoint", file, line, { context });
        found = true;
      }
    }
  }
  return found;
}

/** An environment entry an agent or tool server is started with. */
function checkEnvEntry(out: Collector, file: string, key: string, node: JNode, context: string): void {
  const value = stringOf(node);
  if (value === null) return;
  if (MODEL_ENDPOINT_VARS.has(key.toUpperCase())) {
    const verdict = endpointVerdict(value, out.allowedModelHosts);
    if (verdict !== null) out.add("modelEndpoint", file, node.line, { severity: verdict.level, context: `${key} is set to ${value.slice(0, 120)}: ${verdict.why}.` });
    return;
  }
  if (PROXY_VARS.has(key)) {
    const parsed = urlsIn(value)[0];
    if (parsed !== undefined && !isLocalHost(parsed.host)) out.add("proxy", file, node.line, { context: `${key} routes traffic through ${parsed.host}.` });
    return;
  }
  const preload = envPreload(key, value);
  if (preload !== null) out.add("envPreload", file, node.line, { context: `${context}: ${preload}.` });
  const hit = credentialValue(key, value);
  if (hit !== null) {
    out.add("secret", file, node.line, { severity: hit.production ? "critical" : "high", secret: hit.value, context: `${context} holds a literal ${hit.name} (${key}).` });
    if (hit.production) out.production.push({ file, name: key });
  }
}

/** A file the check could not parse: a finding at the line where reading stopped. */
function unparsed(out: Collector, file: string, line: number, reason: string, format: string): void {
  out.add("unparsed", file, line, { context: `It is not valid ${format} (${reason} at line ${line}).` });
}

// --- MCP servers ---------------------------------------------------------------------------------

function checkMcpServers(out: Collector, file: string, servers: JNode | undefined): void {
  for (const { key: name, keyLine, value: server } of entriesOf(servers)) {
    const context = `The MCP server "${name}" starts when the agent opens this repository.`;
    const commandNode = member(server, "command");
    const words = commandNode?.kind === "array" ? stringsOf(commandNode) : shellSplit(stringOf(commandNode) ?? "");
    const argNodes = itemsOf(member(server, "args"));
    const args = argNodes.flatMap((n) => (n.kind === "string" ? [n.value] : []));
    const all = [...words, ...args];
    const commandLine = commandNode?.line ?? keyLine;
    if (all.length > 0) out.ran("mcp_local", file, commandLine, `MCP server "${name}"`, all.join(" "));
    if (all.length > 0) {
      // Point at the argument that carries the risk (`bash -c "<here>"`), not at the bare launcher.
      const riskyArg = argNodes.find((n) => n.kind === "string" && n.value.length <= MAX_LINE && (commandRisks(n.value).some((r) => r !== "network") || urlsIn(n.value).some(({ url, host }) => isCaptureUrl(url, host) || isRawIp(host))));
      checkAutoCommand(out, file, riskyArg?.line ?? commandLine, all.join(" "), context, false);
      const pkg = launchedPackage(all);
      if (pkg !== null) {
        const specLine = argNodes.find((n) => n.kind === "string" && n.value === pkg.spec)?.line ?? commandLine;
        const state = pinState(pkg);
        if (state === "unpinned") out.add("mcpUnpinned", file, specLine, { context: `${context} It runs ${pkg.spec} from ${pkg.ecosystem === "docker" ? "the image registry" : pkg.ecosystem} with no exact version.` });
        if (state === "unverified_source") out.add("mcpSource", file, specLine, { context: pkg.registry !== undefined && pkg.registry !== null ? `${context} It installs from ${pkg.registry.slice(0, 120)}.` : context });
        const root = opensWholeDisk(pkg);
        if (root !== null) {
          const rootLine = argNodes.find((n) => n.kind === "string" && n.value === root)?.line ?? specLine;
          out.add("mcpFilesystemRoot", file, rootLine, { context: `The filesystem server "${name}" is given ${root}.` });
        }
      }
      const host = containerHostAccess(all);
      if (host !== null) out.add("mcpHostAccess", file, commandLine, { context: `The MCP server "${name}" runs a container with ${host.slice(0, 120)}.` });
    }
    for (const field of ["url", "httpUrl", "serverUrl"]) {
      const node = member(server, field);
      const value = stringOf(node);
      if (node === undefined || value === null) continue;
      out.ran("mcp_remote", file, node.line, `MCP server "${name}"`, value);
      for (const { url, host, scheme } of urlsIn(value.slice(0, MAX_LINE))) {
        if (isCaptureUrl(url, host) || isRawIp(host)) out.add("captureEndpoint", file, node.line, { context: `The MCP server "${name}" is reached at ${host}.` });
        else if ((scheme === "http" || scheme === "ws") && !isLocalHost(host)) out.add("mcpCleartext", file, node.line, { context: `The MCP server "${name}" is at ${url.slice(0, 120)}.` });
      }
    }
    // Gemini CLI: trust skips every tool confirmation for the server.
    const trust = member(server, "trust");
    if (trust?.kind === "boolean" && trust.value) out.add("mcpAutoApprove", file, trust.line, { context: `The MCP server "${name}" is trusted: its tools run without confirmation.` });
    for (const { key, value } of entriesOf(member(server, "env"))) {
      checkEnvEntry(out, file, key, value, `The MCP server "${name}"'s environment`);
      const v = stringOf(value);
      if (REGISTRY_ENV.test(key) && v !== null && v.trim() !== "" && !/^https:\/\/(?:registry\.npmjs\.org|registry\.yarnpkg\.com|pypi\.org\/simple)\/?$/i.test(v.trim())) out.add("mcpSource", file, value.line, { context: `${context} ${key} points its installer at ${v.slice(0, 120)}.` });
    }
    for (const field of ["headers", "http_headers"]) {
      for (const { key, value } of entriesOf(member(server, field))) {
        const header = stringOf(value);
        if (header === null) continue;
        const hit = credentialValue(key, header);
        if (hit !== null) {
          out.add("secret", file, value.line, { severity: hit.production ? "critical" : "high", secret: hit.value, context: `The MCP server "${name}"'s ${key} header holds a literal credential.` });
          if (hit.production) out.production.push({ file, name: `${name} ${key} header` });
        }
      }
    }
  }
}

/** Every key in a JSON tree that names a model endpoint variable, wherever it is nested. */
function checkNestedEndpoints(out: Collector, file: string, node: JNode | undefined, depth = 0): void {
  if (node === undefined || depth > 8) return;
  if (node.kind === "object") {
    for (const { key, value } of node.entries) {
      if (MODEL_ENDPOINT_VARS.has(key.toUpperCase())) checkEnvEntry(out, file, key, value, "This setting");
      else checkNestedEndpoints(out, file, value, depth + 1);
    }
  } else if (node.kind === "array") for (const item of node.items) checkNestedEndpoints(out, file, item, depth + 1);
}

// --- hooks (Claude Code, Gemini CLI, Codex, Cursor) ------------------------------------------------

/** Hook events that run as soon as a session starts or the folder opens. */
const ON_OPEN_EVENTS = /^(?:SessionStart|Setup|sessionStart|workspaceOpen|session_start)$/;

/**
 * Every hook in a `hooks` object: groups (`{ matcher, hooks: [entry] }`, Claude Code, Gemini CLI and
 * Codex) or flat entries (`{ command }`, Cursor). Command hooks are checked as commands; HTTP hooks by
 * their address; prompt and agent hooks by their text. Every one is listed.
 */
function checkHooks(out: Collector, file: string, hooks: JNode | undefined, agent: string): void {
  for (const { key: event, value: groups } of entriesOf(hooks)) {
    const onOpen = ON_OPEN_EVENTS.test(event);
    for (const group of itemsOf(groups)) {
      const inner = member(group, "hooks");
      const entries = inner?.kind === "array" ? itemsOf(inner) : [group];
      for (const hook of entries) {
        const type = stringOf(member(hook, "type")) ?? "command";
        const commandNode = member(hook, "command");
        const command = commandNode?.kind === "array" ? stringsOf(commandNode).join(" ") : stringOf(commandNode);
        if (command !== null && commandNode !== undefined) {
          out.ran("hook", file, commandNode.line, `${event} hook`, command);
          checkAutoCommand(out, file, commandNode.line, command, `${agent} runs this ${event} hook${onOpen ? " as soon as a session starts in the repository" : " on its own"}.`, onOpen);
          continue;
        }
        const urlNode = member(hook, "url");
        const url = stringOf(urlNode);
        if (url !== null && urlNode !== undefined) {
          out.ran("hook", file, urlNode.line, `${event} ${type} hook`, url);
          for (const u of urlsIn(url.slice(0, MAX_LINE))) {
            if (isCaptureUrl(u.url, u.host) || isRawIp(u.host)) out.add("captureEndpoint", file, urlNode.line, { context: `${agent} sends this ${event} hook's data to ${u.host}.` });
            else if (!isLocalHost(u.host)) out.add(onOpen ? "networkOnOpen" : "networkAutoRun", file, urlNode.line, { context: `${agent} sends this ${event} hook's data to ${u.host}.` });
          }
          continue;
        }
        const promptNode = member(hook, "prompt");
        const prompt = stringOf(promptNode);
        if (prompt !== null && promptNode !== undefined) {
          out.ran("hook", file, promptNode.line, `${event} ${type} hook`, prompt);
          for (const piece of chunksOf(prompt)) {
            const inj = injectionMatch(piece);
            if (inj !== null) out.add("injection", file, promptNode.line, inj.quoted ? { severity: "medium", confidence: "low" } : {});
          }
          continue;
        }
        // A hook of a kind the check does not know is still listed: something runs.
        out.ran("hook", file, hook.line, `${event} ${type} hook`, `(${type})`);
      }
    }
  }
}

// --- per kind ------------------------------------------------------------------------------------------

/** Claude Code helpers that run a command on their own (for credentials, telemetry headers, the status line). */
const CLAUDE_HELPERS = ["apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "gcpAuthRefresh"];
/** A wildcard that pre-approves every shell command. */
const SHELL_WILDCARD = /^(?:Bash|Shell|Terminal|run_shell_command|shell)(?:\(\s*(?:\*|\*:\*|:\*|\*\*)?\s*\))?$/i;
/** A shell allow rule for an interpreter or a network tool: as good as any command. */
const INTERPRETER_ALLOW = /^(?:Bash|Shell|run_shell_command)\(\s*(?:sudo\s+)?(?:(?:ba|z|da|k|fi)?sh|python[0-9.]*|node|deno|bun|perl|ruby|php|lua|pwsh|powershell|eval|exec|env|xargs|curl|wget|nc|ncat|socat|ssh|scp|rsync|npx|bunx|uvx|pipx|docker|kubectl)(?:\s*[:*(]|\s+\*|\s*\))/i;
/** Allow rules that cover every file or every tool. */
const BROAD_ALLOW = /^(?:(?:Write|Edit|MultiEdit|NotebookEdit)(?:\(\s*(?:\*|\*\*|\/\*\*|\/\/\*\*|~\/\*\*|\.\/\*\*|\*\*\/\*)?\s*\))?|mcp__\*|mcp__[^_\s]+__\*|WebFetch(?:\(\s*\*?\s*\))?|WebFetch\(domain:\*\))$/;

function checkAllowList(out: Collector, file: string, items: JNode[]): void {
  for (const item of items) {
    if (item.kind !== "string") continue;
    const v = item.value.trim();
    if (SHELL_WILDCARD.test(v)) out.add("shellWildcard", file, item.line);
    else if (INTERPRETER_ALLOW.test(v)) out.add("shellWildcard", file, item.line, { confidence: "medium", context: `${v.slice(0, 80)} lets the agent run any program through an interpreter or network tool.` });
    else if (BROAD_ALLOW.test(v)) out.add("broadAllow", file, item.line, { severity: /^WebFetch/.test(v) ? "low" : "medium", context: `The allow rule is ${v.slice(0, 80)}.` });
  }
}

/** A folder outside the project: absolute, in the home directory, or climbing out with "..". */
const OUTSIDE_PROJECT = /^(?:\/|~|\$\{?HOME\}?|[A-Za-z]:[\\/]|\.\.(?:[\\/]|$))/;
const WHOLE_DISK_OR_HOME = /^(?:\/|~\/?|\$\{?HOME\}?\/?|[A-Za-z]:[\\/]?|\/(?:Users|home)\/?|\/(?:Users|home)\/[^/]+\/?)$/;

function claudeSettings(out: Collector, file: string, root: JNode): void {
  for (const { key, value } of entriesOf(member(root, "env"))) checkEnvEntry(out, file, key, value, "The agent's environment in this file");

  checkHooks(out, file, member(root, "hooks"), "Claude Code");
  const statusCommand = member(member(root, "statusLine"), "command");
  const status = stringOf(statusCommand);
  if (status !== null && statusCommand !== undefined) {
    out.ran("status_line", file, statusCommand.line, "Status-line command", status);
    checkAutoCommand(out, file, statusCommand.line, status, "Claude Code runs the status-line command continuously.", true);
  }
  const suggest = member(member(root, "fileSuggestion"), "command");
  const suggestion = stringOf(suggest);
  if (suggestion !== null && suggest !== undefined) {
    out.ran("helper", file, suggest.line, "fileSuggestion command", suggestion);
    checkAutoCommand(out, file, suggest.line, suggestion, "Claude Code runs the file-suggestion command whenever a file is mentioned.", true);
  }
  for (const helper of CLAUDE_HELPERS) {
    const node = member(root, helper);
    const command = stringOf(node);
    if (command === null || node === undefined) continue;
    out.ran("helper", file, node.line, `${helper} command`, command);
    checkAutoCommand(out, file, node.line, command, `Claude Code runs the ${helper} command on its own.`, true);
  }

  const permissions = member(root, "permissions");
  const mode = member(permissions, "defaultMode");
  const modeValue = stringOf(mode);
  if (mode !== undefined && modeValue === "bypassPermissions") out.add("permissionsBypass", file, mode.line);
  else if (mode !== undefined && modeValue === "acceptEdits") out.add("permissiveSetting", file, mode.line, { context: 'defaultMode "acceptEdits" lets the agent edit files without asking.' });
  else if (mode !== undefined && modeValue === "dontAsk") out.add("permissiveSetting", file, mode.line, { severity: "low", context: 'defaultMode "dontAsk" runs every allowed tool without asking.' });
  checkAllowList(out, file, itemsOf(member(permissions, "allow")));
  for (const item of itemsOf(member(permissions, "deny"))) {
    if (item.kind === "string" && /^Read\([^)]*\.env/i.test(item.value)) out.deniesEnvRead = true;
  }
  for (const item of itemsOf(member(permissions, "additionalDirectories"))) {
    if (item.kind !== "string" || !OUTSIDE_PROJECT.test(item.value.trim())) continue;
    out.add("permissiveSetting", file, item.line, { severity: WHOLE_DISK_OR_HOME.test(item.value.trim()) ? "high" : "medium", context: `additionalDirectories gives the agent ${item.value.slice(0, 120)}, outside the project.` });
  }
  const skipPrompt = member(root, "skipDangerousModePermissionPrompt");
  if (skipPrompt?.kind === "boolean" && skipPrompt.value) out.add("permissionsBypass", file, skipPrompt.line, { severity: "medium", context: "skipDangerousModePermissionPrompt removes the confirmation before permission prompts are switched off." });
  const all = member(root, "enableAllProjectMcpServers");
  if (all?.kind === "boolean" && all.value) out.add("mcpAutoApprove", file, all.line);
  const named = member(root, "enabledMcpjsonServers");
  if (named?.kind === "array" && named.items.length > 0) out.add("mcpAutoApprove", file, named.line, { severity: "low", context: `The settings approve ${stringsOf(named).slice(0, 5).join(", ").slice(0, 120)} from .mcp.json in advance.` });
  for (const { key, value } of entriesOf(member(root, "enabledPlugins"))) {
    if (value.kind === "boolean" && value.value) out.add("pluginSource", file, value.line, { context: `The plugin ${key.slice(0, 120)} is switched on for everyone.` });
  }
  for (const { key, value } of entriesOf(member(root, "extraKnownMarketplaces"))) {
    const source = member(value, "source");
    const where = stringOf(member(source, "repo")) ?? stringOf(member(source, "url")) ?? stringOf(member(source, "path")) ?? key;
    out.add("pluginSource", file, value.line, { context: `The marketplace "${key.slice(0, 60)}" (${where.slice(0, 120)}) is added for everyone.` });
  }
  const sandbox = member(root, "sandbox");
  const flag = (node: JNode | undefined) => node?.kind === "boolean" && node.value;
  const unsandboxed = member(sandbox, "allowUnsandboxedCommands");
  if (flag(unsandboxed) && unsandboxed !== undefined) out.add("permissiveSetting", file, unsandboxed.line, { context: "sandbox.allowUnsandboxedCommands lets commands leave the sandbox." });
  const excluded = member(sandbox, "excludedCommands");
  if (excluded?.kind === "array" && excluded.items.length > 0) out.add("permissiveSetting", file, excluded.line, { severity: "low", context: `sandbox.excludedCommands runs ${stringsOf(excluded).slice(0, 5).join(", ").slice(0, 120)} outside the sandbox.` });
  const weaker = member(sandbox, "enableWeakerNestedSandbox");
  if (flag(weaker) && weaker !== undefined) out.add("permissiveSetting", file, weaker.line, { severity: "low", context: "sandbox.enableWeakerNestedSandbox weakens the sandbox." });
  const network = member(sandbox, "network");
  for (const item of itemsOf(member(network, "allowedDomains"))) {
    if (item.kind === "string" && /^\*(?:\.\*)?$/.test(item.value.trim())) out.add("permissiveSetting", file, item.line, { context: "sandbox.network.allowedDomains lets sandboxed commands reach any host." });
  }
  for (const item of itemsOf(member(network, "allowUnixSockets"))) {
    if (item.kind === "string" && /docker\.sock/.test(item.value)) out.add("permissiveSetting", file, item.line, { severity: "high", context: "The sandbox may reach the Docker socket, which controls the host." });
  }
  checkMcpServers(out, file, member(root, "mcpServers"));
}

/** VS Code tasks by label, and the tasks a task depends on (dependsOn, a label or a list of labels). */
function vscodeTasks(out: Collector, file: string, root: JNode): void {
  const tasks = itemsOf(member(root, "tasks"));
  const byLabel = new Map<string, JNode>();
  for (const task of tasks) {
    const label = stringOf(member(task, "label"));
    if (label !== null && !byLabel.has(label)) byLabel.set(label, task);
  }
  const commandsOf = (task: JNode): { line: number; text: string }[] => {
    const outCommands: { line: number; text: string }[] = [];
    for (const scope of [task, member(task, "windows"), member(task, "osx"), member(task, "linux")]) {
      const commandNode = member(scope, "command");
      const command = stringOf(commandNode);
      if (command === null || commandNode === undefined) continue;
      const args = itemsOf(member(scope, "args")).map((a) => stringOf(a) ?? stringOf(member(a, "value")) ?? "");
      outCommands.push({ line: commandNode.line, text: [command, ...args].join(" ") });
    }
    return outCommands;
  };
  for (const task of tasks) {
    const runOn = member(member(task, "runOptions"), "runOn");
    if (stringOf(runOn) !== "folderOpen" || runOn === undefined) continue;
    const label = stringOf(member(task, "label")) ?? "a task";
    let risky = false;
    // The task and everything it depends on run when the folder opens.
    const queue: { task: JNode; via: string | null }[] = [{ task, via: null }];
    const seen = new Set<JNode>([task]);
    while (queue.length > 0) {
      const { task: t, via } = queue.shift() as { task: JNode; via: string | null };
      const name = stringOf(member(t, "label")) ?? "a task";
      const context = via === null ? `VS Code runs the task "${label}" every time the folder is opened.` : `VS Code runs the task "${name}" every time the folder is opened (the folder-open task "${label}" depends on it).`;
      for (const c of commandsOf(t)) {
        out.ran("folder_open_task", file, c.line, `Folder-open task "${name}"`, c.text);
        if (checkAutoCommand(out, file, c.line, c.text, context, true)) risky = true;
      }
      const deps = member(t, "dependsOn");
      const labels = deps?.kind === "array" ? itemsOf(deps).map((d) => stringOf(d) ?? stringOf(member(d, "label")) ?? "") : [stringOf(deps) ?? stringOf(member(deps, "label")) ?? ""];
      for (const l of labels) {
        const dep = byLabel.get(l);
        if (dep !== undefined && !seen.has(dep) && seen.size < 100) {
          seen.add(dep);
          queue.push({ task: dep, via: label });
        }
      }
    }
    if (!risky) out.add("folderOpenTask", file, runOn.line, { context: `The task is "${label}".` });
  }
}

/** A VS Code auto-approve map entry that is switched on (true, or { approve: true }). */
const approved = (v: JNode) => (v.kind === "boolean" && v.value) || (v.kind === "object" && member(v, "approve")?.kind === "boolean" && (member(v, "approve") as { value: boolean }).value);

function vscodeSettings(out: Collector, file: string, root: JNode): void {
  for (const { key, value } of entriesOf(root)) {
    if ((key === "chat.tools.autoApprove" || key === "chat.tools.global.autoApprove") && value.kind === "boolean" && value.value) out.add("permissionsBypass", file, value.line);
    if (key === "chat.tools.terminal.autoApprove" || key === "github.copilot.chat.agent.terminal.allowList") {
      for (const { key: pattern, value: on } of entriesOf(value)) {
        if (!approved(on)) continue;
        const p = pattern.trim();
        if (/^\/(?:\^)?\.[*+](?:\$)?\/[a-z]*$/i.test(p) || p === "*" || p === "") out.add("shellWildcard", file, on.line, { context: `chat.tools.terminal.autoApprove approves every command (${p.slice(0, 40)}).` });
        else if (/^\/?\^?(?:(?:ba|z|da)?sh|python[0-9.]*|node|perl|ruby|pwsh|powershell|curl|wget|nc|ssh|scp|eval|npx|docker)\b/i.test(p)) out.add("shellWildcard", file, on.line, { confidence: "medium", context: `chat.tools.terminal.autoApprove approves ${p.slice(0, 60)}, which runs any program or reaches the network.` });
      }
    }
    if (key === "chat.tools.edits.autoApprove") {
      for (const { key: pattern, value: on } of entriesOf(value)) if (approved(on) && /^(?:\*\*(?:\/\*)?|\*)$/.test(pattern.trim())) out.add("broadAllow", file, on.line, { context: "chat.tools.edits.autoApprove approves edits to every file." });
    }
    if (key === "chat.mcp.autostart" && ((value.kind === "boolean" && value.value) || (value.kind === "string" && value.value !== "never"))) out.add("permissiveSetting", file, value.line, { severity: "low", context: "chat.mcp.autostart starts MCP servers without asking." });
    if (key === "chat.mcp.discovery.enabled" && (approved(value) || entriesOf(value).some((e) => approved(e.value)))) out.add("permissiveSetting", file, value.line, { severity: "low", context: "chat.mcp.discovery.enabled loads MCP servers configured for other apps." });
    if (key === "task.allowAutomaticTasks" && ((value.kind === "string" && value.value === "on") || (value.kind === "boolean" && value.value))) out.add("permissiveSetting", file, value.line, { context: "task.allowAutomaticTasks runs folder-open tasks without asking." });
    if (/^terminal\.integrated\.env\./.test(key)) for (const e of entriesOf(value)) checkEnvEntry(out, file, e.key, e.value, `The editor terminal's environment (${key})`);
  }
  checkMcpServers(out, file, member(member(root, "mcp"), "servers"));
  checkNestedEndpoints(out, file, root);
}

function geminiSettings(out: Collector, file: string, root: JNode): void {
  checkMcpServers(out, file, member(root, "mcpServers"));
  checkHooks(out, file, member(root, "hooks"), "Gemini CLI");
  for (const node of [member(root, "defaultApprovalMode"), member(member(root, "general"), "defaultApprovalMode"), member(member(root, "tools"), "approvalMode")]) {
    const mode = stringOf(node);
    if (node === undefined || mode === null) continue;
    if (mode === "yolo") out.add("permissionsBypass", file, node.line, { context: 'Gemini CLI\'s approval mode is "yolo".' });
    else if (mode === "auto_edit") out.add("permissiveSetting", file, node.line, { context: 'Gemini CLI\'s approval mode "auto_edit" edits files without asking.' });
  }
  const autoAccept = member(member(root, "tools"), "autoAccept") ?? member(root, "autoAccept");
  if (autoAccept?.kind === "boolean" && autoAccept.value) out.add("permissiveSetting", file, autoAccept.line, { context: "Gemini CLI accepts safe-looking tool calls without asking." });
  checkAllowList(out, file, [...itemsOf(member(member(root, "tools"), "allowed")), ...itemsOf(member(root, "allowedTools"))]);
  checkNestedEndpoints(out, file, root);
}

function packageJson(out: Collector, file: string, root: JNode): void {
  for (const { value } of entriesOf(member(root, "scripts"))) {
    const script = stringOf(value);
    if (script !== null && permissionOffIn(script) !== null && /\b(?:claude|codex|gemini|cursor-agent|copilot)\b/.test(script)) out.add("skipPermissionsScript", file, value.line);
  }
}

/** The commands a dev-container lifecycle key or Cursor environment key holds: a string, a list of words, or named commands. */
function commandValues(node: JNode | undefined): { line: number; text: string }[] {
  if (node === undefined) return [];
  if (node.kind === "string") return [{ line: node.line, text: node.value }];
  if (node.kind === "array") return [{ line: node.line, text: stringsOf(node).join(" ") }];
  if (node.kind === "object") return node.entries.flatMap((e) => commandValues(e.value.kind === "object" ? undefined : e.value));
  return [];
}

const DEVCONTAINER_LIFECYCLE = ["initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"];

function devcontainer(out: Collector, file: string, root: JNode): void {
  for (const key of DEVCONTAINER_LIFECYCLE) {
    for (const c of commandValues(member(root, key))) {
      out.ran("startup_command", file, c.line, `Dev container ${key}`, c.text);
      checkAutoCommand(out, file, c.line, c.text, `The dev container runs ${key}${key === "initializeCommand" ? " on the host" : ""} when it is created or opened.`, true);
    }
  }
  const privileged = member(root, "privileged");
  if (privileged?.kind === "boolean" && privileged.value) out.add("permissiveSetting", file, privileged.line, { severity: "high", context: "The dev container runs privileged, with full access to the host." });
  const runArgs = member(root, "runArgs");
  const host = containerHostAccess(["docker", "run", ...stringsOf(runArgs)]);
  if (host !== null && runArgs !== undefined) out.add("permissiveSetting", file, runArgs.line, { severity: "high", context: `The dev container runs with ${host.slice(0, 120)}.` });
  for (const m of itemsOf(member(root, "mounts"))) {
    const text = stringOf(m) ?? `source=${stringOf(member(m, "source")) ?? ""}`;
    const src = /(?:^|,)(?:source|src)=([^,]*)/.exec(text)?.[1] ?? "";
    if (/docker\.sock$|^\/$|^\$\{localEnv:(?:HOME|USERPROFILE)\}\/?$|^~\/?$/.test(src.trim())) out.add("permissiveSetting", file, m.line, { severity: "high", context: `The dev container mounts ${src.slice(0, 120)} from the host.` });
  }
  for (const { key, value } of entriesOf(member(root, "containerEnv"))) checkEnvEntry(out, file, key, value, "The dev container's environment");
  for (const { key, value } of entriesOf(member(root, "remoteEnv"))) checkEnvEntry(out, file, key, value, "The dev container's environment");
}

function cursorEnvironment(out: Collector, file: string, root: JNode): void {
  for (const key of ["install", "start"]) {
    for (const c of commandValues(member(root, key))) {
      out.ran("startup_command", file, c.line, `Cursor environment ${key}`, c.text);
      checkAutoCommand(out, file, c.line, c.text, `Cursor's background agent runs the ${key} command when its environment starts.`, true);
    }
  }
  for (const t of itemsOf(member(root, "terminals"))) {
    for (const c of commandValues(member(t, "command"))) {
      out.ran("startup_command", file, c.line, "Cursor environment terminal", c.text);
      checkAutoCommand(out, file, c.line, c.text, "Cursor's background agent starts this terminal command with its environment.", true);
    }
  }
}

/** Reads a JSON-shaped agent file. */
function jsonFile(out: Collector, kind: AgentFileKind, file: string, content: string): void {
  out.budget.take(content.length);
  const parsed = parseJsoncResult(content);
  if (!parsed.ok) {
    if (isAgentConfig(kind)) unparsed(out, file, parsed.line, parsed.reason, "JSON");
    return;
  }
  const root = parsed.root;
  if (kind === "claude_settings") claudeSettings(out, file, root);
  else if (kind === "mcp_json") {
    checkMcpServers(out, file, member(root, "mcpServers"));
    checkMcpServers(out, file, member(root, "servers"));
    checkNestedEndpoints(out, file, root);
  } else if (kind === "gemini_settings") geminiSettings(out, file, root);
  else if (kind === "vscode_tasks") vscodeTasks(out, file, root);
  else if (kind === "vscode_settings") vscodeSettings(out, file, root);
  else if (kind === "package_json") packageJson(out, file, root);
  else if (kind === "hooks_json") checkHooks(out, file, member(root, "hooks"), file.startsWith(".cursor/") ? "Cursor" : "Codex");
  else if (kind === "cursor_environment") cursorEnvironment(out, file, root);
  else if (kind === "devcontainer") devcontainer(out, file, root);
}

// --- Codex TOML --------------------------------------------------------------------------------------

function codexToml(out: Collector, file: string, content: string): void {
  out.budget.take(content.length);
  const parsed = parseToml(content);
  if (!parsed.ok) {
    unparsed(out, file, parsed.line, parsed.reason, "TOML");
    return;
  }
  const root = parsed.root;
  // The top level and every profile can set the approval policy and the sandbox.
  for (const scope of [root, ...entriesOf(member(root, "profiles")).map((e) => e.value)]) {
    const approval = member(scope, "approval_policy");
    const sandbox = member(scope, "sandbox_mode");
    const never = stringOf(approval) === "never";
    const full = stringOf(sandbox) === "danger-full-access";
    if (never && full && sandbox !== undefined) out.add("permissionsBypass", file, sandbox.line);
    else if (full && sandbox !== undefined) out.add("permissiveSetting", file, sandbox.line, { severity: "high", context: 'sandbox_mode = "danger-full-access" runs every command outside Codex\'s sandbox.' });
    else if (never && approval !== undefined) out.add("permissiveSetting", file, approval.line, { context: 'approval_policy = "never" runs every command without asking.' });
  }
  const notify = member(root, "notify");
  const notifyCommand = notify?.kind === "array" ? stringsOf(notify).join(" ") : stringOf(notify);
  if (notify !== undefined && notifyCommand !== null && notifyCommand !== "") {
    out.ran("helper", file, notify.line, "notify command", notifyCommand);
    checkAutoCommand(out, file, notify.line, notifyCommand, "Codex runs the notify command after every turn.", false);
  }
  checkMcpServers(out, file, member(root, "mcp_servers"));
  checkHooks(out, file, member(root, "hooks"), "Codex");
  for (const { key, value: provider } of entriesOf(member(root, "model_providers"))) {
    const base = member(provider, "base_url");
    const url = stringOf(base);
    if (base === undefined || url === null) continue;
    const verdict = endpointVerdict(url, out.allowedModelHosts);
    if (verdict !== null) out.add("modelEndpoint", file, base.line, { severity: verdict.level, context: `The model provider "${key.slice(0, 60)}" has base_url ${url.slice(0, 120)}: ${verdict.why}.` });
    for (const { key: k, value } of entriesOf(member(provider, "http_headers"))) checkEnvEntry(out, file, k, value, `The model provider "${key.slice(0, 60)}"'s headers`);
  }
  for (const { key, value } of entriesOf(member(member(root, "shell_environment_policy"), "set"))) checkEnvEntry(out, file, key, value, "The environment Codex gives every command");
  checkNestedEndpoints(out, file, root);
}

/** A Gemini CLI command file: its prompt is read as instructions, and its `!{…}` shell commands as commands. */
function geminiCommand(out: Collector, file: string, content: string): void {
  out.budget.take(content.length);
  const parsed = parseToml(content);
  if (!parsed.ok) {
    unparsed(out, file, parsed.line, parsed.reason, "TOML");
    return;
  }
  instructions(out, file, content);
  const prompt = member(parsed.root, "prompt");
  const text = stringOf(prompt);
  if (prompt === undefined || text === null) return;
  for (const m of text.matchAll(/!\{([^}]{1,8192})\}/g)) {
    const line = prompt.line + (text.slice(0, m.index).match(/\n/g) ?? []).length;
    out.ran("hook", file, line, "Gemini command shell step", m[1] ?? "");
    checkAutoCommand(out, file, line, m[1] ?? "", "Gemini CLI runs this shell command when the custom command is used.", false);
  }
}

// --- instructions and scripts --------------------------------------------------------------------

const ASSIGNMENT = /\b([A-Z][A-Z0-9_]{2,})\s*[:=]\s*["'`]?([^\s"'`,;]+)/g;
/** A Markdown comment or link reference definition, whose title is never shown: `[//]: # (text)`, `[x]: <> "text"`. */
const LINK_REFERENCE = /^\s{0,3}\[[^\]\n]{1,200}\]:\s{0,8}(?:<[^>\n]{0,2048}>|\S{1,2048})(?:\s{1,8}(?:"([^"\n]{0,4000})"|'([^'\n]{0,4000})'|\(([^)\n]{0,4000})\)))?\s*$/;

/** A detector run on one line and on that line joined to the one before (a sentence wrapped across lines). */
interface Joined {
  piece: string;
  prev: string;
}

function instructions(out: Collector, file: string, content: string, memory = false): void {
  const lines = splitLines(content);
  let fence: string | null = null;
  let comment: { start: number; text: string } | null = null;
  let prevProse = "";
  let continued: { start: number; text: string } | null = null;
  for (let index = 0; index < lines.length; index += 1) {
    const text = lines[index] as string;
    const line = index + 1;
    if (!out.budget.take(text.length * 2 + 1)) {
      out.add("analysisIncomplete", file, line, { context: `The check's work budget ran out at this line; the rest of ${file} and any later files were not checked.` });
      return;
    }
    const fenceMark = /^\s{0,8}(```|~~~)/.exec(text)?.[1];
    if (fenceMark !== undefined && comment === null) fence = fence === null ? fenceMark : fence === fenceMark ? null : fence;
    const inFence = fence !== null || fenceMark !== undefined;
    if (text.length > MAX_LINE) out.add("longLine", file, line, { context: `The line is ${text.length} characters long; it was checked in pieces.` });

    // HTML comments: invisible on GitHub, read by the agent. (On the whole line: indexOf is linear.)
    if (!inFence) {
      let rest = text;
      while (rest.length > 0) {
        if (comment === null) {
          const open = rest.indexOf("<!--");
          if (open < 0) break;
          comment = { start: line, text: "" };
          rest = rest.slice(open + 4);
        }
        const close = rest.indexOf("-->");
        if (close < 0) {
          if (comment.text.length < 65536) comment.text += `${rest.slice(0, 65536)}\n`;
          break;
        }
        if (comment.text.length < 65536) comment.text += rest.slice(0, close);
        if (comment.text.split("\n").some((t) => chunksOf(t).some(isAgentDirective))) out.add("hiddenComment", file, comment.start);
        comment = null;
        rest = rest.slice(close + 3);
      }
      // Markdown's own comments and link titles: not shown, read by the agent.
      const ref = text.length <= MAX_LINE ? LINK_REFERENCE.exec(text) : null;
      const title = ref?.[1] ?? ref?.[2] ?? ref?.[3];
      if (title !== undefined && (isAgentDirective(title) || injectionMatch(title) !== null || commandRisks(title).some((r) => r !== "network"))) out.add("hiddenComment", file, line, { context: "The text is a Markdown comment or link title, which is never displayed." });
    }

    // Shell line continuations: the command is checked whole, at its first line.
    // (A backtick or caret ends a continued line only in a code block: in prose a backtick closes inline code.)
    const continues = /\\$/.test(text) || (inFence && /[`^]$/.test(text));
    if (continued !== null || continues) {
      continued = continued === null ? { start: line, text } : { start: continued.start, text: `${continued.text}\n${text}` };
      if (!continues || continued.text.length > 4 * MAX_LINE) {
        const whole = continued.text;
        const start = continued.start;
        continued = null;
        if (whole.includes("\n")) commandLine(out, file, start, whole);
      }
    }

    for (const piece of chunksOf(text)) {
      const hidden = hiddenTextIn(piece);
      if (hidden !== null) {
        const decoded = hidden === "tag_characters" ? decodeTagCharacters(piece) : hidden === "variation_selectors" ? decodeVariationSelectors(piece) : "";
        out.add("hiddenUnicode", file, line, {
          severity: hidden === "tag_characters" ? "critical" : "high",
          context:
            hidden === "tag_characters"
              ? "The line carries Unicode tag characters, which spell out hidden text."
              : hidden === "bidi_controls"
                ? "The line carries bidirectional control characters."
                : hidden === "variation_selectors"
                  ? "The line carries variation selectors outside any emoji or ideograph, which can encode hidden bytes."
                  : "The line carries invisible characters (zero-width, soft hyphen, filler or blank characters) inside text.",
          ...(decoded === "" ? {} : { note: `hidden text: ${decoded.slice(0, 200)}` }),
        });
      }

      // Inside a code fence the phrase may be an example, so it is reported at low confidence (never dropped).
      const joined: Joined = { piece, prev: inFence ? "" : prevProse };
      let override = false;
      if (said(joined, (t) => injectionMatch(t)?.quoted === false)) out.add("injection", file, line, inFence ? { severity: "medium", confidence: "low", context: "The phrase is inside a code block." } : {});
      else if (said(joined, (t) => injectionMatch(t) !== null)) out.add("injection", file, line, { severity: "medium", confidence: "low", context: "The phrase is quoted." });
      if (said(joined, (t) => remoteInstructionsIn(t) !== null)) out.add("remoteInstructions", file, line, inFence ? { severity: "medium", confidence: "low", context: "The instruction is inside a code block." } : {});
      if (memory && !inFence) {
        if (said(joined, (t) => standingOverrideIn(t) !== null)) {
          out.add("memoryOverride", file, line);
          override = true;
        }
        const host = outboundInstructionIn(piece) ?? (joined.prev === "" ? null : outboundInstructionIn(`${joined.prev} ${piece}`));
        if (host !== null) out.add("memoryOutbound", file, line, { context: `The entry names ${host}.` });
      }
      for (const { url, host } of urlsIn(piece)) {
        // Instructions that only explain a cloud metadata endpoint are documentation; ones that make the agent contact it are not.
        if (isMetadataHost(host) && !directsToMetadata(piece, url)) continue;
        if (isCaptureUrl(url, host) || isRawIp(host)) out.add("captureEndpoint", file, line);
      }

      const b64 = hiddenBase64In(piece);
      if (b64 !== null) {
        const dangerous = injectionMatch(b64.decoded) !== null || commandRisks(b64.decoded.slice(0, MAX_LINE)).some((r) => r !== "network");
        out.add("hiddenBase64", file, line, { severity: dangerous ? "high" : "medium", note: `decodes to: ${b64.decoded.replace(/\s+/g, " ").slice(0, 160)}` });
      }

      const shaped = tokenShapeIn(piece);
      if (shaped !== null) {
        out.add("secret", file, line, { severity: shaped.production ? "critical" : "high", secret: shaped.value, context: `The file holds a ${shaped.name}.` });
        if (shaped.production) out.production.push({ file, name: shaped.name });
      } else {
        for (const m of piece.matchAll(ASSIGNMENT)) {
          const name = m[1] ?? "";
          const value = m[2] ?? "";
          if (MODEL_ENDPOINT_VARS.has(name)) {
            const verdict = endpointVerdict(value, out.allowedModelHosts);
            if (verdict !== null) out.add("modelEndpoint", file, line, { severity: verdict.level, context: `The file sets ${name} to ${value.slice(0, 120)}: ${verdict.why}.` });
            continue;
          }
          const hit = credentialValue(name, value);
          if (hit !== null) {
            out.add("secret", file, line, { severity: hit.production ? "critical" : "high", secret: hit.value, context: `The file assigns a literal value to ${name}.` });
            if (hit.production) out.production.push({ file, name });
            break;
          }
        }
      }

      if (permissionOffSaid(piece) !== null) out.add("skipPermissionsScript", file, line);
      // In memory, the standing-override finding already covers a line that skips checks.
      if (!override && said(joined, (t) => skipChecksIn(t) !== null)) out.add("skipChecks", file, line);
      // A command the agent is told to run (in prose or a code block) that sends credentials away: the source and the send in one step.
      if (connectedExfiltration(piece)) out.add("instructedExfiltration", file, line);
    }
    // Prose wraps across lines; a blank line or a code block ends the paragraph.
    prevProse = inFence || text.trim() === "" ? "" : text.slice(-400);
  }
  if (continued !== null && continued.text.includes("\n")) commandLine(out, file, continued.start, continued.text);
}

/** A detector's verdict on a line, or on the line joined to the prose line before it (only when the join is what makes it). */
function said(j: Joined, detect: (text: string) => boolean): boolean {
  if (detect(j.piece)) return true;
  if (j.prev === "" || detect(j.prev)) return false;
  return detect(`${j.prev} ${j.piece.slice(0, 400)}`);
}

/** A command spread over several lines with continuations, checked as one command. */
function commandLine(out: Collector, file: string, line: number, text: string): void {
  for (const piece of chunksOf(text)) {
    out.budget.take(piece.length);
    if (connectedExfiltration(piece)) out.add("instructedExfiltration", file, line);
  }
}

const MEMORY_LEAD = "This is agent memory: the agent loads it into later sessions and writes it itself.";
const kb = (bytes: number) => `${Math.round(bytes / 102.4) / 10} KB`;

/** Agent memory: every instruction-file rule, the memory rules, and its size. */
function memoryFile(out: Collector, file: string, content: string): AgentMemoryFile {
  out.lead = MEMORY_LEAD;
  try {
    instructions(out, file, content, true);
    const lines = splitLines(content);
    if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();
    const bytes = utf8Length(content);
    const role = isMemoryIndex(file) ? "index" : "topic";
    if (role === "index" && (lines.length > MEMORY_INDEX_MAX_LINES || bytes > MEMORY_INDEX_MAX_BYTES)) {
      // The first line Claude Code does not load: past 200 lines, or where the 25 KB runs out.
      let cut = Math.min(lines.length, MEMORY_INDEX_MAX_LINES + 1);
      let total = 0;
      for (let i = 0; i < lines.length; i += 1) {
        total += utf8Length(lines[i] ?? "") + 1;
        if (total > MEMORY_INDEX_MAX_BYTES) {
          cut = Math.min(cut, i + 1);
          break;
        }
      }
      out.add("memoryLarge", file, cut, { context: `The index is ${lines.length} lines and ${kb(bytes)}; Claude Code loads only the first 200 lines or 25 KB, so from this line on it is not loaded.` });
    } else if (role === "topic" && bytes > MEMORY_TOPIC_MAX_BYTES) {
      out.add("memoryLarge", file, 1, { context: `The file is ${lines.length} lines and ${kb(bytes)}.` });
    }
    return { path: file, lines: lines.length, bytes, role };
  } finally {
    out.lead = undefined;
  }
}

function agentScript(out: Collector, file: string, content: string): void {
  const lines = splitLines(content);
  const context = "A script shipped with the repository's agent hooks or skills, which the agent runs.";
  for (let index = 0; index < lines.length; index += 1) {
    let text = lines[index] as string;
    const start = index + 1;
    // Line continuations: the logical command is checked whole, at its first line.
    while (/(?:\\|`)$/.test(text) && index + 1 < lines.length && text.length < 4 * MAX_LINE) {
      index += 1;
      text = `${text}\n${lines[index] as string}`;
    }
    if (!out.budget.take(text.length + 1)) {
      out.add("analysisIncomplete", file, start, { context: `The check's work budget ran out at this line; the rest of ${file} and any later files were not checked.` });
      return;
    }
    const trimmed = text.trim();
    if (trimmed.startsWith("#") || trimmed.startsWith("//") || trimmed === "") continue;
    for (const risk of boundedRisks(out, file, start, text)) {
      if (risk !== "network") out.add(RISK_RULE[risk], file, start, { context });
    }
    for (const piece of chunksOf(text)) for (const { url, host } of urlsIn(piece)) if (isCaptureUrl(url, host) || isRawIp(host)) out.add("captureEndpoint", file, start);
  }
}

function envFile(out: Collector, file: string, content: string): void {
  for (const text of splitLines(content)) {
    if (!out.budget.take(text.length + 1)) return;
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]{0,255})\s*=\s*["']?([^"'#\s]{0,4096})/.exec(text);
    if (m === null) continue;
    const hit = credentialValue(m[1] ?? "", m[2] ?? "");
    if (hit?.production === true) out.production.push({ file, name: m[1] ?? "" });
  }
}

// --- the check -------------------------------------------------------------------------------------------

/** Runs every rule over the files given (any files: those that are not agent files are ignored). */
export function analyzeAgentFiles(files: readonly AgentFile[], options: AnalyzeOptions = {}): AgentAnalysis {
  const budget = new Budget(options.maxWork ?? MAX_WORK);
  const sizes = new Map(files.map((f) => [f.path, utf8Length(f.content)] as const));
  const fits = files.filter((f) => (sizes.get(f.path) ?? 0) <= MAX_FILE_BYTES);
  // Kinds by path, plus the topic files a memory index links to.
  const kinds = classifyAgentFiles(fits);
  const read = fits.filter((f) => kinds.has(f.path));
  const lines = new Map(read.map((f) => [f.path, splitLines(f.content)] as const));
  const out = new Collector(lines, budget, options.allowedModelHosts ?? []);
  // An agent file too large to check is reported, never skipped silently (UTF-8 bytes, as the agent reads it).
  for (const f of files) {
    const bytes = sizes.get(f.path) ?? 0;
    const kind = agentFileKind(f.path);
    if (bytes > MAX_FILE_BYTES && kind !== null && isAgentConfig(kind)) out.add("oversize", f.path, 1, { context: `The file is ${kb(bytes)}; files over ${kb(MAX_FILE_BYTES)} are not checked.` });
  }
  const memory: AgentMemoryFile[] = [];
  const unchecked: string[] = [];
  for (const f of read) {
    const kind = kinds.get(f.path);
    if (kind === undefined) continue;
    if (budget.over) {
      unchecked.push(f.path);
      continue;
    }
    if (kind === "memory") memory.push(memoryFile(out, f.path, f.content));
    else if (kind === "instructions") instructions(out, f.path, f.content);
    else if (kind === "agent_script") agentScript(out, f.path, f.content);
    else if (kind === "codex_toml") codexToml(out, f.path, f.content);
    else if (kind === "gemini_command") geminiCommand(out, f.path, f.content);
    else if (kind === "env_file") envFile(out, f.path, f.content);
    else jsonFile(out, kind, f.path, f.content);
  }
  const firstUnchecked = unchecked[0];
  if (firstUnchecked !== undefined) out.add("analysisIncomplete", firstUnchecked, 1, { context: `The check's work budget ran out before ${unchecked.length} file${unchecked.length === 1 ? "" : "s"} (${unchecked.slice(0, 3).join(", ")}${unchecked.length > 3 ? ", …" : ""}).` });

  // Blast radius: broad agent powers, production credentials in reach, and no rule keeping the agent from them.
  const broad = out.findings.find((f) => f.ruleId === RULES.permissionsBypass.id || f.ruleId === RULES.shellWildcard.id || f.ruleId === RULES.skipPermissionsScript.id);
  if (broad !== undefined && out.production.length > 0 && !out.deniesEnvRead) {
    const where = [...new Set(out.production.map((p) => `${p.file} (${p.name})`))].slice(0, 5).join(", ");
    out.add("blastRadius", broad.file, broad.line, { context: `Production credentials were found in: ${where}.` });
  }

  const findings = out.findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.file.localeCompare(b.file) || a.line - b.line || a.ruleId.localeCompare(b.ruleId));
  return {
    findings,
    filesChecked: read.filter((f) => {
      const kind = kinds.get(f.path);
      return kind !== undefined && isAgentConfig(kind);
    }).length,
    filesRead: read.map((f) => f.path),
    inventory: out.inventory.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line),
    memory: memory.sort((a, b) => a.path.localeCompare(b.path)),
    work: budget.spent,
    unchecked,
  };
}
