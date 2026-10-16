/**
 * Per-agent bearer tokens for the local API (docs/api.md). A token is printed once by
 * `api token add <agentId>`; only its SHA-256 is stored (api/tokens.json, mode 0600, in the firewall
 * home), so the file never holds a usable credential. A presented token is hashed and compared to every
 * stored hash in constant time.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { lstatSync, type Stats } from "node:fs";
import { dirname, join } from "node:path";
import { atomicWrite, readText, withLock } from "../runtime/fsutil.js";
import type { Layout } from "../runtime/layout.js";
import { assertAgentId, isAgentId, tokensPath } from "./files.js";

export const TOKEN_PREFIX = "lsfw_";
/** lsfw_ + 32 random bytes, base64url. */
const TOKEN_SHAPE = /^lsfw_[A-Za-z0-9_-]{43}$/;

export interface TokenRecord {
  agent: string;
  /** "sha256:<hex>" of the whole token. */
  hash: string;
  createdAt: string;
  /**
   * "network": a network middleware's token (`api token add <agentId> --traffic network`, OpenShell's
   * middleware, docs/sandboxes.md). Only such a token may send context.traffic "network", and only for the
   * middleware's own request shape (src/api/contract.ts), so an agent's ordinary token cannot declare its
   * tool calls to be network traffic and skip the toolCalls limit, the agent-wide monitor and agent stops.
   */
  traffic?: "network";
  /**
   * What the token may do (`api token add <agentId> --role ...`). Absent: DEFAULT_ROLES (decide and report), what
   * every token made before roles existed could do. "prompt" is kept apart because a prompt names the
   * destinations an untrusted session may still send to and sets the task scope: what the person typed, never
   * what the agent's own credential says the person typed (TOKEN_ROLES).
   */
  roles?: TokenRole[];
}

/**
 * - decide: POST /v1/decide, GET /v1/sessions/{s}, GET /v1/approvals/{id};
 * - report: POST /v1/sessions/{s}/results and /inputs (they can only make a session stricter; a result for a call that
 *   ran also records the files it wrote in the provenance ledger, docs/api.md "Files a session wrote"), and /prompts
 *   recorded in the log only (its destinations and task scope are not applied);
 * - prompt: POST /v1/sessions/{s}/prompts with its destinations and task scope applied: a token for the
 *   component that reads what the person typed (a chat UI), never one an agent's tool loop holds.
 */
export const TOKEN_ROLES = ["decide", "report", "prompt"] as const;
export type TokenRole = (typeof TOKEN_ROLES)[number];
export const DEFAULT_ROLES: readonly TokenRole[] = ["decide", "report"];

/** The roles a stored token has (DEFAULT_ROLES when it was made without --role). */
export function rolesOf(r: TokenRecord): readonly TokenRole[] {
  return r.roles ?? DEFAULT_ROLES;
}

/** Roles from `--role` values (each one role, or a comma-separated list). Throws on an unknown or empty one. */
export function parseRoles(values: readonly string[]): TokenRole[] {
  const out: TokenRole[] = [];
  for (const v of values) {
    for (const part of v.split(",")) {
      const r = part.trim();
      if (!(TOKEN_ROLES as readonly string[]).includes(r)) throw new Error(`--role ${JSON.stringify(r.slice(0, 40))} is not a role: use ${TOKEN_ROLES.join(", ")} (more than once, or comma-separated)`);
      if (!out.includes(r as TokenRole)) out.push(r as TokenRole);
    }
  }
  if (out.length === 0) throw new Error(`--role needs at least one of ${TOKEN_ROLES.join(", ")}`);
  return out;
}

function validRoles(v: unknown): v is TokenRole[] {
  return Array.isArray(v) && v.length > 0 && v.length <= TOKEN_ROLES.length && v.every((r) => typeof r === "string" && (TOKEN_ROLES as readonly string[]).includes(r)) && new Set(v).size === v.length;
}

interface TokenFile {
  version: 1;
  tokens: TokenRecord[];
}

function hashOf(token: string): string {
  return `sha256:${createHash("sha256").update(token, "utf8").digest("hex")}`;
}

/**
 * The token file is written 0600 by this user. A file another account owns, or one others can read or write, is
 * not trusted (the server then answers 500, never "anyone"). The directory must be this user's and not writable
 * by others, or the file could be swapped. Not checked on Windows, which has no such modes.
 */
export function assertPrivateTokenFile(l: Layout): void {
  if (process.platform === "win32" || typeof process.getuid !== "function") return;
  const uid = process.getuid();
  const p = tokensPath(l);
  let file: Stats;
  try {
    file = lstatSync(p);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return;
    throw new Error(`${p} cannot be checked`, { cause: e });
  }
  if (!file.isFile() || file.uid !== uid || (file.mode & 0o077) !== 0) throw new Error(`${p} must be a plain file owned by this user with no group or other access (chmod 600)`);
  const dir = dirname(p);
  const d = lstatSync(dir);
  if (!d.isDirectory() || d.uid !== uid || (d.mode & 0o022) !== 0) throw new Error(`${dir} must be a directory owned by this user that others cannot write to`);
}

/** The stored tokens. Throws when the file exists but is damaged (the server then answers 500, never "anyone"). */
export function readTokens(l: Layout): TokenRecord[] {
  assertPrivateTokenFile(l);
  const text = readText(tokensPath(l));
  if (text === null) return [];
  const raw = JSON.parse(text) as unknown;
  if (typeof raw !== "object" || raw === null || (raw as { version?: unknown }).version !== 1 || !Array.isArray((raw as { tokens?: unknown }).tokens)) throw new Error(`${tokensPath(l)} is damaged`);
  const out: TokenRecord[] = [];
  for (const t of (raw as TokenFile).tokens) {
    if (typeof t !== "object" || t === null || typeof t.agent !== "string" || !isAgentId(t.agent) || typeof t.hash !== "string" || !/^sha256:[0-9a-f]{64}$/.test(t.hash) || typeof t.createdAt !== "string" || (t.traffic !== undefined && t.traffic !== "network") || (t.roles !== undefined && !validRoles(t.roles))) throw new Error(`${tokensPath(l)} is damaged`);
    out.push({ agent: t.agent, hash: t.hash, createdAt: t.createdAt, ...(t.traffic === "network" ? { traffic: "network" as const } : {}), ...(t.roles !== undefined ? { roles: [...t.roles] } : {}) });
  }
  return out;
}

function write(l: Layout, tokens: TokenRecord[]): void {
  atomicWrite(tokensPath(l), `${JSON.stringify({ version: 1, tokens } satisfies TokenFile, null, 2)}\n`);
}

function lock(l: Layout): string {
  return join(l.locks, "api-tokens.lock");
}

/**
 * Adds a new token for the agent and returns it (the only time it exists outside the caller's hands).
 * `traffic` "network": the token of a network middleware (TokenRecord.traffic). `roles`: what it may do
 * (TokenRecord.roles; absent: the default, decide and report).
 */
export function addToken(l: Layout, agentId: string, now = new Date(), traffic?: "network", roles?: readonly TokenRole[]): string {
  assertAgentId(agentId);
  const why = newAgentIdProblem(l, agentId);
  if (why !== null) throw new Error(why);
  if (roles !== undefined && !validRoles([...roles])) throw new Error(`roles must be one or more of ${TOKEN_ROLES.join(", ")}, each once`);
  const token = `${TOKEN_PREFIX}${randomBytes(32).toString("base64url")}`;
  withLock(lock(l), () => write(l, [...readTokens(l), { agent: agentId, hash: hashOf(token), createdAt: now.toISOString(), ...(traffic === "network" ? { traffic } : {}), ...(roles !== undefined ? { roles: [...roles] } : {}) }]));
  return token;
}

/**
 * Removes every token of the agent. Returns how many were removed. M8: a record the file cannot vouch for (a bad
 * field) must not keep a person from revoking a token: records are matched by their agent field alone and every
 * other record, damaged or not, is written back as it was (the server goes on refusing a damaged file: 500).
 * Only a file that is not a token file at all is refused.
 */
export function revokeTokens(l: Layout, agentId: string): number {
  assertAgentId(agentId);
  return withLock(lock(l), () => {
    const text = readText(tokensPath(l));
    if (text === null) return 0;
    const raw = JSON.parse(text) as unknown;
    if (typeof raw !== "object" || raw === null || (raw as { version?: unknown }).version !== 1 || !Array.isArray((raw as { tokens?: unknown }).tokens)) throw new Error(`${tokensPath(l)} is damaged`);
    const all = (raw as { tokens: unknown[] }).tokens;
    const kept = all.filter((t) => !(typeof t === "object" && t !== null && (t as { agent?: unknown }).agent === agentId));
    if (kept.length !== all.length) atomicWrite(tokensPath(l), `${JSON.stringify({ version: 1, tokens: kept }, null, 2)}\n`);
    return all.length - kept.length;
  });
}

/**
 * M6: names an API agent may not take: the hooks' and the gateway's own agents. Their sessions, counters and stops
 * (`agent stop claude`, the monitor's agent:<id> counters) would be shared with an API agent of the same name.
 */
export const RESERVED_AGENT_IDS = ["claude", "codex", "gemini", "cursor", "gateway"] as const;

/**
 * Why a new token cannot be made for this agent id, or null: a reserved name, or one that differs only in case from
 * an agent that already has a token (on a case-insensitive file system both would share one registry file).
 */
export function newAgentIdProblem(l: Layout, agentId: string): string | null {
  const folded = agentId.toLowerCase();
  if ((RESERVED_AGENT_IDS as readonly string[]).includes(folded)) return `"${agentId}" is reserved for the firewall's own agents (${RESERVED_AGENT_IDS.join(", ")}); choose another agent id`;
  let existing: string[] = [];
  try {
    existing = readTokens(l).map((t) => t.agent);
  } catch {
    existing = [];
  }
  const clash = existing.find((a) => a !== agentId && a.toLowerCase() === folded);
  return clash !== undefined ? `"${agentId}" differs only in case from agent "${clash}", which already has a token; agent ids are compared without regard to case` : null;
}

/** The stored record of a presented token, or null. */
export function recordOfToken(records: readonly TokenRecord[], token: string): TokenRecord | null {
  if (!TOKEN_SHAPE.test(token)) return null;
  const h = Buffer.from(hashOf(token), "utf8");
  let found: TokenRecord | null = null;
  // Every record is compared, so the time taken does not say which one matched.
  for (const r of records) {
    const b = Buffer.from(r.hash, "utf8");
    if (b.length === h.length && timingSafeEqual(b, h) && found === null) found = r;
  }
  return found;
}

/** The agent a presented token belongs to, or null. */
export function agentOfToken(records: readonly TokenRecord[], token: string): string | null {
  return recordOfToken(records, token)?.agent ?? null;
}

/** The bearer token in an Authorization header, or null. */
export function bearer(header: string | undefined): string | null {
  const m = /^Bearer ([\x21-\x7e]{1,200})$/.exec(header ?? "");
  return m?.[1] ?? null;
}

/** A short, non-secret label for a stored token (the start of its hash). */
export function tokenLabel(r: TokenRecord): string {
  return r.hash.slice("sha256:".length, "sha256:".length + 12);
}
