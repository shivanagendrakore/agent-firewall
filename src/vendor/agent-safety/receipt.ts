// Vendored from LaunchSafe's agent-safety package (src/receipt.ts), Apache-2.0, at commit fc329d4314dc07a65da266a1256b1da0d17ec97c.
// Licence: Apache-2.0 (see NOTICE).
// Transform: add ".js" to relative import specifiers.
// Do not edit here: it is copied from the upstream package by
// `node scripts/sync-agent-safety.mjs` (`--check` verifies the copy).

/**
 * The receipt: a record of one check, so a clean (or not clean) result can be
 * reproduced later. It names the rule set's version, the repository and
 * commit, every agent file read with its SHA-256 and size, the tool servers
 * and hooks the files start, the counts, and each finding by rule, severity,
 * file and line. Never a file's text and never a secret: evidence stays in
 * the result, not the receipt.
 *
 * Its digest is the SHA-256 of the canonical JSON of what the check saw and
 * found (every field but `tool_version`, `checked_at` and `digest`), so the
 * same files checked with the same rules give the same digest on any day.
 */
// DIVERGES FROM UPSTREAM (firewall audit I10): servers and hooks carry the SHA-256 of their whole
// command (the shown text stops at 200 characters), so drift sees a change past that point.
// Upstream should take this change.
import type { AgentAnalysis } from "./analyze.js";
import { canonicalJson, textBytes, webCryptoSha256, type JsonValue, type Sha256 } from "./canonical.js";
import { agentFileKind } from "./paths.js";
import { pinStability, type PinStability } from "./pin.js";
import { RULES_VERSION } from "./rules.js";
import { summarizeAgentSafety } from "./summary.js";
import type { AgentFile, AgentInventoryKind, AgentSeverity, AgentSeverityCounts } from "./types.js";

export const RECEIPT_FORMAT = "launchsafe-agent-check-receipt/1";

export interface ReceiptSource {
  host: "github";
  /** owner/name, as GitHub spells it. */
  repository: string;
  default_branch: string;
  /** The full commit SHA the files were read at. */
  commit: string;
}

export interface ReceiptFile {
  path: string;
  /** Hex SHA-256 of the file's UTF-8 text (a leading byte order mark left out). */
  sha256: string;
  bytes: number;
  /** Set on agent memory files only (from rule set 1.1.0): the agent loads them into later sessions and writes them itself. */
  memory?: true;
  /** A memory file's line count, so drift can say how much memory grew. Memory files only. */
  lines?: number;
}

export interface ReceiptServer {
  /** The name the file gives it. */
  name: string;
  file: string;
  transport: "local" | "remote";
  /** The launch line or address, credentials masked, at most 200 characters. */
  launch: string;
  /** The package or image it downloads; null for a local command or a remote address. */
  package: string | null;
  /** remote: reached over the network, nothing installed. */
  pin: PinStability | "remote";
  /** Hex SHA-256 of the whole launch line or address (from rule set 1.2.0-fw). */
  sha256?: string;
}

export interface ReceiptHook {
  kind: Exclude<AgentInventoryKind, "mcp_local" | "mcp_remote">;
  file: string;
  label: string;
  /** The command, credentials masked, at most 200 characters. */
  command: string;
  /** Hex SHA-256 of the whole command (from rule set 1.2.0-fw). */
  sha256?: string;
}

export interface ReceiptFinding {
  rule: string;
  severity: AgentSeverity;
  path: string;
  line: number;
}

export interface ReceiptSummary {
  files_checked: number;
  findings: AgentSeverityCounts;
  /** Hooks, helpers, folder-open tasks and tool servers the files start on their own. */
  runs_on_its_own: number;
}

export interface AgentCheckReceipt {
  format: typeof RECEIPT_FORMAT;
  /** What produced it (the site's tool and the package commit it vendors, or the runner). Not in the digest. */
  tool_version: string;
  rules_version: string;
  source: ReceiptSource;
  files: ReceiptFile[];
  servers: ReceiptServer[];
  hooks: ReceiptHook[];
  summary: ReceiptSummary;
  findings: ReceiptFinding[];
  /** ISO 8601. Not in the digest. */
  checked_at: string;
  /** Hex SHA-256 of the canonical content (receiptContent). */
  digest: string;
}

export interface BuildReceiptInput {
  files: readonly AgentFile[];
  analysis: AgentAnalysis;
  source: ReceiptSource;
  toolVersion: string;
  checkedAt: Date | string;
  /** Defaults to WebCrypto. */
  sha256?: Sha256;
}

const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const SERVER_LABEL = /^MCP server "(.*)"$/s;

/** The servers and hooks from the analysis's inventory, in a stable order. */
export function inventoryParts(analysis: Pick<AgentAnalysis, "inventory">): { servers: ReceiptServer[]; hooks: ReceiptHook[] } {
  const servers: ReceiptServer[] = [];
  const hooks: ReceiptHook[] = [];
  for (const item of analysis.inventory) {
    const hash = item.sha256 === undefined ? {} : { sha256: item.sha256 };
    if (item.kind === "mcp_local" || item.kind === "mcp_remote") {
      const name = SERVER_LABEL.exec(item.label)?.[1] ?? item.label;
      if (item.kind === "mcp_remote") servers.push({ name, file: item.file, transport: "remote", launch: item.detail, package: null, pin: "remote", ...hash });
      else {
        const verdict = pinStability(item.detail);
        servers.push({ name, file: item.file, transport: "local", launch: item.detail, package: verdict.package, pin: verdict.stability, ...hash });
      }
    } else hooks.push({ kind: item.kind, file: item.file, label: item.label, command: item.detail, ...hash });
  }
  servers.sort((a, b) => byText(a.file, b.file) || byText(a.name, b.name) || byText(a.transport, b.transport) || byText(a.launch, b.launch));
  hooks.sort((a, b) => byText(a.file, b.file) || byText(a.label, b.label) || byText(a.command, b.command));
  return { servers, hooks };
}

/**
 * The receipt for one check. `files` are the files the check was given (the
 * ones it does not read, and root env files, are left out: a hash of a file
 * of credentials is not something to hand around); `analysis` is
 * analyzeAgentFiles() over them.
 */
export async function buildReceipt(input: BuildReceiptInput): Promise<AgentCheckReceipt> {
  const sha256 = input.sha256 ?? webCryptoSha256;
  const read = new Set(input.analysis.filesRead);
  // Memory topic files a MEMORY.md links to have no kind by path alone, so the analysis's list says which files are memory.
  const memory = new Map(input.analysis.memory.map((m) => [m.path, m]));
  const files: ReceiptFile[] = [];
  for (const file of input.files) {
    if (!read.has(file.path) || agentFileKind(file.path) === "env_file") continue;
    const bytes = textBytes(file.content);
    const mem = memory.get(file.path);
    files.push({ path: file.path, sha256: await sha256(bytes), bytes: bytes.length, ...(mem === undefined ? {} : { memory: true as const, lines: mem.lines }) });
  }
  files.sort((a, b) => byText(a.path, b.path));
  const { servers, hooks } = inventoryParts(input.analysis);
  const summary = summarizeAgentSafety(input.analysis);
  const receipt: Omit<AgentCheckReceipt, "digest"> = {
    format: RECEIPT_FORMAT,
    tool_version: input.toolVersion,
    rules_version: RULES_VERSION,
    source: { host: "github", repository: input.source.repository, default_branch: input.source.default_branch, commit: input.source.commit },
    files,
    servers,
    hooks,
    summary: { files_checked: summary.filesChecked, findings: { ...summary.counts }, runs_on_its_own: servers.length + hooks.length },
    findings: input.analysis.findings
      .map((f) => ({ rule: f.ruleId, severity: f.severity, path: f.file, line: f.line }))
      .sort((a, b) => byText(a.path, b.path) || a.line - b.line || byText(a.rule, b.rule)),
    checked_at: typeof input.checkedAt === "string" ? input.checkedAt : input.checkedAt.toISOString(),
  };
  return { ...receipt, digest: await receiptDigest(receipt, sha256) };
}

/** What the digest covers: everything the check saw and found, nothing about when or with which build of the tool. */
export function receiptContent(receipt: Omit<AgentCheckReceipt, "digest"> | AgentCheckReceipt): JsonValue {
  return {
    format: receipt.format,
    rules_version: receipt.rules_version,
    source: { ...receipt.source },
    files: receipt.files.map((f) => ({ ...f })),
    servers: receipt.servers.map((s) => ({ ...s })),
    hooks: receipt.hooks.map((h) => ({ ...h })),
    summary: { files_checked: receipt.summary.files_checked, findings: { ...receipt.summary.findings }, runs_on_its_own: receipt.summary.runs_on_its_own },
    findings: receipt.findings.map((f) => ({ ...f })),
  };
}

/** The receipt's digest: hex SHA-256 of the canonical JSON of its content. */
export async function receiptDigest(receipt: Omit<AgentCheckReceipt, "digest"> | AgentCheckReceipt, sha256: Sha256 = webCryptoSha256): Promise<string> {
  return sha256(new TextEncoder().encode(canonicalJson(receiptContent(receipt))));
}

/** The receipt as the file a person downloads: canonical key order, two-space indent. */
export function receiptFileText(receipt: AgentCheckReceipt): string {
  return `${JSON.stringify(JSON.parse(canonicalJson(receipt as unknown as JsonValue)), null, 2)}\n`;
}

export type ParsedReceipt = { ok: true; receipt: AgentCheckReceipt } | { ok: false; problem: string };

const SEVERITIES = new Set(["critical", "high", "medium", "low"]);
const HEX64 = /^[0-9a-f]{64}$/;
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string";
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

/**
 * Reads a receipt someone pasted or uploaded, checking its shape (not its
 * digest: digestMatches does that). The problem is a sentence for the page.
 */
export function parseReceipt(text: string): ParsedReceipt {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, problem: "That isn't JSON. Paste the whole receipt file." };
  }
  if (!isObj(value)) return { ok: false, problem: "That isn't a receipt: it should be one JSON object." };
  if (value.format !== RECEIPT_FORMAT) return { ok: false, problem: `That isn't a receipt this tool reads (its format should be ${RECEIPT_FORMAT}).` };
  const bad = (what: string): ParsedReceipt => ({ ok: false, problem: `The receipt's ${what} is missing or malformed.` });
  if (!isStr(value.tool_version) || !isStr(value.rules_version) || !isStr(value.checked_at)) return bad("version or time");
  if (!isStr(value.digest) || !HEX64.test(value.digest)) return bad("digest");
  const src = value.source;
  if (!isObj(src) || src.host !== "github" || !isStr(src.repository) || !isStr(src.default_branch) || !isStr(src.commit)) return bad("source");
  const arr = (v: unknown, ok: (x: Record<string, unknown>) => boolean) => Array.isArray(v) && v.every((x) => isObj(x) && ok(x));
  if (!arr(value.files, (f) => isStr(f.path) && isStr(f.sha256) && HEX64.test(f.sha256) && isInt(f.bytes) && (f.memory === undefined || f.memory === true) && (f.lines === undefined || isInt(f.lines)))) return bad("file list");
  const hashOk = (x: Record<string, unknown>) => x.sha256 === undefined || (isStr(x.sha256) && HEX64.test(x.sha256));
  if (!arr(value.servers, (s) => isStr(s.name) && isStr(s.file) && (s.transport === "local" || s.transport === "remote") && isStr(s.launch) && (s.package === null || isStr(s.package)) && ["stable", "floating", "not_a_package", "remote"].includes(s.pin as string) && hashOk(s))) return bad("server list");
  if (!arr(value.hooks, (h) => isStr(h.kind) && isStr(h.file) && isStr(h.label) && isStr(h.command) && hashOk(h))) return bad("hook list");
  if (!arr(value.findings, (f) => isStr(f.rule) && SEVERITIES.has(f.severity as string) && isStr(f.path) && isInt(f.line))) return bad("finding list");
  const sum = value.summary;
  if (!isObj(sum) || !isInt(sum.files_checked) || !isInt(sum.runs_on_its_own) || !isObj(sum.findings) || !["critical", "high", "medium", "low"].every((k) => isInt((sum.findings as Record<string, unknown>)[k]))) return bad("summary");
  return { ok: true, receipt: value as unknown as AgentCheckReceipt };
}

/** Whether a receipt's digest is the digest of its own content (false: it was edited after it was made). */
export async function digestMatches(receipt: AgentCheckReceipt, sha256: Sha256 = webCryptoSha256): Promise<boolean> {
  return (await receiptDigest(receipt, sha256)) === receipt.digest;
}
