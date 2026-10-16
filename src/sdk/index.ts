/**
 * @launchsafe/agent-firewall/sdk: the firewall's deterministic engine for an
 * agent you build yourself (docs/library.md). Dependency-free and
 * browser-safe; the file store and Ed25519 signing are in ./sdk/node.
 */

export { createGuard, guardMessage, normalizeAnswer, resolvePolicy, type Guard } from "./guard.js";
export { memoryStore, maskForStorage, type MemoryStoreOptions } from "./store.js";
export { verifyEntries, entryHash, GENESIS } from "./log.js";
// For a custom StateStore: throw LogRefused for an entry it will not take, LogUnrecorded when nothing was written.
export { LogRefused, LogUnrecorded } from "../engine/log-bound.js";
export { toAction, toolServers } from "./tools.js";
export type { ApprovalOutcome, DecisionCore, GuardPort, MaybePromise } from "./port.js";
export type {
  ApprovalAnswer,
  ApprovalHandler,
  ApprovalRequest,
  AsToolSpec,
  Authorization,
  EngineTool,
  GuardDecision,
  GuardFs,
  GuardOptions,
  GuardVerdict,
  HeldAction,
  HoldInput,
  KindToolSpec,
  LedgerNote,
  LedgerRecord,
  LogEntry,
  LogSigner,
  LogVerifyResult,
  ProvenanceLedger,
  ResultNote,
  ResultOptions,
  ModelUsage,
  CapView,
  SessionSnapshot,
  StateStore,
  ToolCall,
  ToolSpec,
  UntrustedInput,
  Counters,
  Decision,
  FirewallConfig,
  NormalizedAction,
  PolicyDoc,
  SessionState,
  StateEvent,
} from "./types.js";
