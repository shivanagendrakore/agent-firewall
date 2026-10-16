// Vendored from LaunchSafe's agent-safety package (src/index.ts), Apache-2.0, at commit fc329d4314dc07a65da266a1256b1da0d17ec97c.
// Licence: Apache-2.0 (see NOTICE).
// Transform: add ".js" to relative import specifiers.
// Do not edit here: it is copied from the upstream package by
// `node scripts/sync-agent-safety.mjs` (`--check` verifies the copy).

// The agent-safety check (AI-01, TE-55): browser-safe entry point. The Node file
// collector is `@launchsafe/agent-safety/node`.
// DIVERGES FROM UPSTREAM (firewall audit): exports the parsers (parseJsoncResult, jsonValueOf,
// parseToml), the analyzer's options and limits, and the helpers the firewall's collector uses.
export { analyzeAgentFiles, MAX_FILE_BYTES, MAX_WORK, splitLines, utf8Length, type AgentAnalysis, type AnalyzeOptions } from "./analyze.js";
export { agentFileKind, CHECKED_PATHS, classifyAgentFiles, isLocalAgentFile, isMemoryIndex, MAX_MEMORY_LINKS, memoryLinks, type AgentFileKind } from "./paths.js";
export { ALL_RULES, RULES, RULES_VERSION, type AgentRule } from "./rules.js";
export { canonicalJson, sha256HexSync, webCryptoSha256, type JsonValue, type Sha256 } from "./canonical.js";
export { jsonValueOf, parseJsonc, parseJsoncResult, type JNode, type JsoncResult } from "./jsonc.js";
export { parseToml, type TomlResult } from "./toml.js";
export { pinStability, type PinStability, type PinVerdict } from "./pin.js";
export {
  buildReceipt,
  digestMatches,
  inventoryParts,
  parseReceipt,
  receiptContent,
  receiptDigest,
  receiptFileText,
  RECEIPT_FORMAT,
  type AgentCheckReceipt,
  type BuildReceiptInput,
  type ParsedReceipt,
  type ReceiptFile,
  type ReceiptFinding,
  type ReceiptHook,
  type ReceiptServer,
  type ReceiptSource,
  type ReceiptSummary,
} from "./receipt.js";
export { compareReceipts, memoryDriftSentence, type HookChange, type MemoryDrift, type ReceiptDrift, type ServerChange } from "./drift.js";
export { summarizeAgentSafety } from "./summary.js";
export type {
  AgentFile,
  AgentFinding,
  AgentFindingType,
  AgentInventoryItem,
  AgentInventoryKind,
  AgentMemoryFile,
  AgentRuleFamily,
  AgentSafetySummary,
  AgentSeverity,
  AgentSeverityCounts,
} from "./types.js";
