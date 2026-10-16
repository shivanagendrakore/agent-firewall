/**
 * The human channel for changing what the firewall allows (F4).
 *
 * A person sets an approval passphrase once. It never touches disk or the
 * agent: scrypt turns it into a key that encrypts an Ed25519 "approver"
 * private key. Approving a queued action (or uninstalling) needs the
 * passphrase to unlock that key and sign the approval. The hook honours an
 * approval only if its signature verifies against the approver public key
 * pinned in the hook command in Claude Code's settings — a file the agent
 * cannot change (and, under managed settings, cannot even write).
 *
 * So an agent that copies the CLI, runs it in a pseudo-terminal, or writes
 * the session file directly still cannot produce an approval the hook will
 * accept: it does not know the passphrase.
 *
 * Nor can it reuse one (B1). Each approval signs a random single-use nonce, an
 * expiry (APPROVAL_TTL_MS), the rule ids the person was shown and where the
 * agent was (approval message v2). Its use is recorded with its id, an id used
 * anywhere in the session never counts again, a copied approval line (the same
 * id twice) makes the session untrusted, and the hook honours it only while
 * every rule asking about the action is one the person saw (I2). v1 approvals
 * (no nonce or expiry) are no longer honoured. What a copy can still do: if the
 * agent could rewrite the whole session file (the hook refuses its tool calls
 * on the firewall's data), deleting both the original and its use, an unused
 * copy counts until its expiry, once.
 */

import { createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, scryptSync, sign, verify, type KeyObject } from "node:crypto";
import { join } from "node:path";
import { AGENT_COMMAND, processLine } from "./ancestry.js";
import { atomicWrite, ensureDir, parseJsonFile, readText, withLock } from "./fsutil.js";
import type { Layout } from "./layout.js";
import { assertNotRealHome } from "./guard.js";

/** The KDF of approver files written before I4 (no `kdf` field) and of the vault's file store (derivePassphraseKey). */
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
/** I4: new approver files. 2^17 costs 128 MiB and a few hundred milliseconds per guess. */
export const APPROVER_KDF = { N: 1 << 17, r: 8, p: 1 } as const;
/** The weakest KDF an approver file may name (an older file's default) and the strongest one read (bounds memory). */
const KDF_MIN_N = 1 << 15;
const KDF_MAX_N = 1 << 20;
export const MIN_PASSPHRASE = 14;

/**
 * I4: why a new approval passphrase is too weak, or null. At least 14 characters, and not a short pattern
 * repeated (fewer than 6 different characters): the key file is only as strong as the passphrase against
 * someone who copies it.
 */
export function passphraseProblem(p: string): string | null {
  const s = p.normalize("NFKC");
  if ([...s].length < MIN_PASSPHRASE) return `it must be at least ${MIN_PASSPHRASE} characters (several words work well)`;
  if (new Set(s.toLowerCase()).size < 6) return "it repeats too few different characters";
  return null;
}

interface ApproverFile {
  version: 1;
  /** SPKI DER, base64. */
  publicKey: string;
  salt: string;
  iv: string;
  tag: string;
  /** PKCS8 DER of the private key, AES-256-GCM encrypted, base64. */
  ciphertext: string;
  createdAt: string;
  /** I4: the scrypt parameters (absent: N = 2^15, r = 8, p = 1, as before). */
  kdf?: { alg: "scrypt"; N: number; r: number; p: number };
}

type Kdf = { N: number; r: number; p: number };

function kdfOf(a: ApproverFile): Kdf {
  if (a.kdf === undefined) return { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p };
  const k = a.kdf;
  const pow2 = Number.isSafeInteger(k.N) && k.N > 0 && (k.N & (k.N - 1)) === 0;
  if (k.alg !== "scrypt" || !pow2 || k.N < KDF_MIN_N || k.N > KDF_MAX_N || k.r !== 8 || k.p !== 1) throw new Error("the approver key file is corrupt (its key derivation settings are not ones this version writes)");
  return { N: k.N, r: k.r, p: k.p };
}

/** Whether the approver file still uses the older, cheaper KDF (unlocking it once upgrades it). */
export function approverKdfWeak(l: Layout): boolean {
  const a = readApprover(l);
  return a !== null && kdfOf(a).N < APPROVER_KDF.N;
}

export function approverPath(l: Layout): string {
  return join(l.keys, "approver.json");
}

function readApprover(l: Layout): ApproverFile | null {
  const t = readText(approverPath(l));
  if (t === null) return null;
  const a = parseJsonFile(approverPath(l), t) as ApproverFile;
  if (a.version !== 1 || typeof a.publicKey !== "string" || typeof a.ciphertext !== "string") throw new Error("the approver key file is corrupt");
  return a;
}

/** The approver public key (base64 SPKI DER) from disk, or null when none is set up. */
export function approverPublicKey(l: Layout): string | null {
  return readApprover(l)?.publicKey ?? null;
}

function deriveKey(passphrase: string, salt: Buffer, kdf: Kdf = SCRYPT): Buffer {
  // scrypt needs 128 * N * r bytes; twice that leaves room.
  return scryptSync(passphrase.normalize("NFKC"), salt, 32, { N: kdf.N, r: kdf.r, p: kdf.p, maxmem: Math.max(SCRYPT.maxmem, 256 * kdf.N * kdf.r) });
}

/** The pre-I4 KDF, for another file keyed by the approval passphrase with its own salt (the vault's encrypted file store, which keeps its format). */
export function derivePassphraseKey(passphrase: string, salt: Buffer): Buffer {
  return deriveKey(passphrase, salt);
}

/** The base64 SPKI DER public key of an unlocked approver private key (what the hook pins). */
export function publicKeyOf(priv: KeyObject): string {
  return (createPublicKey(priv).export({ type: "spki", format: "der" }) as Buffer).toString("base64");
}

/** Creates the approver key. Refuses if one exists (use rotate, which needs the old passphrase). */
export function initApprover(l: Layout, passphrase: string): string {
  const weak = passphraseProblem(passphrase);
  if (weak !== null) throw new Error(`the approval passphrase is not strong enough: ${weak}`);
  assertNotRealHome(approverPath(l));
  ensureDir(l.keys);
  return withLock(join(l.keys, "approver.lock"), () => {
    if (readApprover(l) !== null) throw new Error("an approval passphrase is already set; use `launchsafe-firewall approver rotate`");
    return writeApprover(l, passphrase);
  });
}

/** Encrypts `privateKey` (a new one when absent) under the passphrase with the current KDF and writes the file. */
function writeApprover(l: Layout, passphrase: string, privateKey: KeyObject = generateKeyPairSync("ed25519").privateKey, createdAt = new Date().toISOString()): string {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", deriveKey(passphrase, salt, APPROVER_KDF), iv);
  const ct = Buffer.concat([cipher.update(privateKey.export({ type: "pkcs8", format: "der" })), cipher.final()]);
  const file: ApproverFile = {
    version: 1,
    publicKey: publicKeyOf(privateKey),
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ct.toString("base64"),
    createdAt,
    kdf: { alg: "scrypt", ...APPROVER_KDF },
  };
  atomicWrite(approverPath(l), JSON.stringify(file, null, 2), 0o600);
  return file.publicKey;
}

/** Replaces the approver key; needs the current passphrase. Returns the new public key (re-run install to pin it). */
export function rotateApprover(l: Layout, oldPassphrase: string, newPassphrase: string): string {
  const weak = passphraseProblem(newPassphrase);
  if (weak !== null) throw new Error(`the approval passphrase is not strong enough: ${weak}`);
  assertNotRealHome(approverPath(l));
  return withLock(join(l.keys, "approver.lock"), () => {
    decrypt(l, oldPassphrase);
    return writeApprover(l, newPassphrase);
  });
}

function decrypt(l: Layout, passphrase: string): { key: KeyObject; file: ApproverFile } {
  const a = readApprover(l);
  if (a === null) throw new Error("no approval passphrase is set up; run `launchsafe-firewall approver init` in your own terminal");
  const kdf = kdfOf(a);
  try {
    const d = createDecipheriv("aes-256-gcm", deriveKey(passphrase, Buffer.from(a.salt, "base64"), kdf), Buffer.from(a.iv, "base64"));
    d.setAuthTag(Buffer.from(a.tag, "base64"));
    const der = Buffer.concat([d.update(Buffer.from(a.ciphertext, "base64")), d.final()]);
    return { key: createPrivateKey({ key: der, format: "der", type: "pkcs8" }), file: a };
  } catch {
    throw new Error("wrong approval passphrase");
  }
}

/**
 * Decrypts the approver private key. Throws on a wrong passphrase (the GCM tag does not verify). I4: a file
 * still on the older KDF is re-encrypted with the current one (same key, so the pin in the hook command
 * still holds) the first time the right passphrase unlocks it; a failure to rewrite leaves it as it was.
 */
export function unlockApprover(l: Layout, passphrase: string): KeyObject {
  const { key, file } = decrypt(l, passphrase);
  if (kdfOf(file).N < APPROVER_KDF.N) {
    try {
      reencryptApprover(l, passphrase);
    } catch {
      // The key still unlocks as before; doctor keeps saying it is on the older KDF.
    }
  }
  return key;
}

/** I4: re-encrypts the approver key with the current KDF (same key pair); needs the passphrase. Returns whether it changed anything. */
export function reencryptApprover(l: Layout, passphrase: string): boolean {
  assertNotRealHome(approverPath(l));
  return withLock(join(l.keys, "approver.lock"), () => {
    const { key, file } = decrypt(l, passphrase);
    if (kdfOf(file).N >= APPROVER_KDF.N) return false;
    writeApprover(l, passphrase, key, file.createdAt);
    return true;
  });
}

/**
 * B1/I2: what a person's approval of one queued action says, all of it signed (approval message v2). `nonce`
 * makes every approval single-use on its own (two approvals never share a signed message); `exp` bounds how
 * long an unused one lasts, so a copy kept by anyone stops counting; `rules` are the rule ids the person was
 * shown, and the approval covers the action only while no other rule asks about it; `cwd` and `projectDir`
 * are where the agent was and the project the policy was judged under (the decision binds them: decide.ts).
 */
export interface ApprovalGrant {
  sessionId: string;
  actionHash: string;
  id: string;
  nonce: string;
  /** ISO time after which the approval no longer counts. */
  exp: string;
  rules: readonly string[];
  cwd: string;
  projectDir: string;
}

/** How long an approval stays usable after the person gives it (the agent must retry within this time). */
export const APPROVAL_TTL_MS = 24 * 3600 * 1000;

/** A fresh single-use nonce (128 bits, base64url). */
export function approvalNonce(): string {
  return randomBytes(16).toString("base64url");
}

/**
 * v2: a JSON array, so every field (and each rule id) is delimited unambiguously. v1 (`launchsafe-firewall/
 * approval/v1`, session, hash and id joined by newlines) carried no nonce or expiry, so a copy of a v1 line
 * could be replayed for as long as the session lived: v1 approvals are no longer honoured (store.ts reads
 * them as stale, never as tampering).
 */
export function approvalMessage(g: ApprovalGrant): Buffer {
  return Buffer.from(JSON.stringify(["launchsafe-firewall/approval/v2", g.sessionId, g.actionHash, g.id, g.nonce, g.exp, [...g.rules], g.cwd, g.projectDir]), "utf8");
}

export function signApproval(priv: KeyObject, g: ApprovalGrant): string {
  return sign(null, approvalMessage(g), priv).toString("base64");
}

/** The signer decideQueueItem takes, for an unlocked approver key. */
export function approvalSigner(priv: KeyObject): (g: ApprovalGrant) => string {
  return (g) => signApproval(priv, g);
}

/**
 * What a person-made state change signed with the approval key is: a scope widening, a budget raise (v0.2),
 * turning watch mode on, or resuming a stopped session or agent. Each kind is in its own signed message, so
 * a signature for one can never pass as another.
 */
export type StateChangeKind = "scope-widen" | "budget-raise" | "rollout-watch" | "resume";

/**
 * FZ21: the key object for a base64 SPKI public key, made once per key. Reading a session file checks every signed
 * line against the approval key, and making the key object again for each line cost about 20 microseconds: a few
 * megabytes of signed lines with junk signatures took more than a second with the key, before a signature was
 * checked. A key that cannot be read throws each time, as before (every caller then answers "not signed").
 */
let lastKey: { b64: string; key: KeyObject } | null = null;

function verifyingKey(publicKeyB64: string): KeyObject {
  if (lastKey?.b64 !== publicKeyB64) lastKey = { b64: publicKeyB64, key: createPublicKey({ key: Buffer.from(publicKeyB64, "base64"), format: "der", type: "spki" }) };
  return lastKey.key;
}

/**
 * The signed message for a person-made state change (scope widening, budget raise, watch mode, resume). M4: v2
 * is a JSON array, so a field holding a newline cannot shift the others (v1 joined them with newlines).
 */
export function stateChangeMessage(kind: StateChangeKind, sessionId: string, fields: readonly string[]): Buffer {
  return Buffer.from(JSON.stringify([`launchsafe-firewall/${kind}/v2`, sessionId, ...fields]), "utf8");
}

/** The v1 message, still verified for changes signed before v2, but only when no value holds a newline (then it is unambiguous). */
function stateChangeMessageV1(kind: StateChangeKind, sessionId: string, fields: readonly string[]): Buffer | null {
  if ([sessionId, ...fields].some((x) => x.includes("\n"))) return null;
  return Buffer.from([`launchsafe-firewall/${kind}/v1`, sessionId, ...fields].join("\n"), "utf8");
}

export function signStateChange(priv: KeyObject, kind: StateChangeKind, sessionId: string, fields: readonly string[]): string {
  return sign(null, stateChangeMessage(kind, sessionId, fields), priv).toString("base64");
}

export function verifyStateChange(publicKeyB64: string, kind: StateChangeKind, sessionId: string, fields: readonly string[], sig: string): boolean {
  try {
    const pub = verifyingKey(publicKeyB64);
    const s = Buffer.from(sig, "base64");
    if (verify(null, stateChangeMessage(kind, sessionId, fields), pub, s)) return true;
    const v1 = stateChangeMessageV1(kind, sessionId, fields);
    return v1 !== null && verify(null, v1, pub, s);
  } catch {
    return false;
  }
}

/**
 * The signed message for a learned project choice ("always" or "never" for one exact action in one project).
 * v3 (M1) also signs the rules that asked when it was chosen, so they cannot be edited into learnable ones;
 * without `rules` it is the v2 message, which older entries carry and which still verifies.
 */
export function learnedMessage(fields: { kind: "allow" | "never"; id: string; project: string; key: string; identity: string; tool: string; createdAt: string; rules?: readonly string[] }): Buffer {
  // A JSON array: every field is delimited unambiguously (a newline inside a tool name cannot shift them).
  const base = [fields.kind, fields.id, fields.project, fields.key, fields.identity, fields.tool, fields.createdAt];
  return Buffer.from(JSON.stringify(fields.rules !== undefined ? ["launchsafe-firewall/learned/v3", ...base, [...fields.rules]] : ["launchsafe-firewall/learned/v2", ...base]), "utf8");
}

export function signLearned(priv: KeyObject, fields: Parameters<typeof learnedMessage>[0]): string {
  return sign(null, learnedMessage(fields), priv).toString("base64");
}

/** Which message an entry's signature verifies as: "v3" (rules signed), "v2" (an older entry; rules not signed), or null. */
export function learnedSignature(publicKeyB64: string, fields: Parameters<typeof learnedMessage>[0], sig: string): "v3" | "v2" | null {
  try {
    const pub = verifyingKey(publicKeyB64);
    const s = Buffer.from(sig, "base64");
    if (fields.rules !== undefined && verify(null, learnedMessage(fields), pub, s)) return "v3";
    const { rules: _rules, ...v2 } = fields;
    return verify(null, learnedMessage(v2), pub, s) ? "v2" : null;
  } catch {
    return null;
  }
}

export function verifyLearned(publicKeyB64: string, fields: Parameters<typeof learnedMessage>[0], sig: string): boolean {
  return learnedSignature(publicKeyB64, fields, sig) !== null;
}

/**
 * M1: the seal over a whole set of learned choices: its generation and the digest of every entry, signed, so
 * an entry removed or added outside the CLI (a "never" deleted from both files) is visible.
 */
export function learnedSealMessage(generation: number, digest: string): Buffer {
  return Buffer.from(JSON.stringify(["launchsafe-firewall/learned-seal/v1", generation, digest]), "utf8");
}

export function verifyLearnedSeal(publicKeyB64: string, generation: number, digest: string, sig: string): boolean {
  try {
    const pub = verifyingKey(publicKeyB64);
    return verify(null, learnedSealMessage(generation, digest), pub, Buffer.from(sig, "base64"));
  } catch {
    return false;
  }
}

/** The sealer a person-run command passes to learned.ts with the unlocked key. */
export function learnedSealer(priv: KeyObject): (generation: number, digest: string) => string {
  return (generation, digest) => sign(null, learnedSealMessage(generation, digest), priv).toString("base64");
}

/**
 * Whether a v1 approval line (no nonce or expiry) carries a valid signature from this key. Such a line is no
 * longer honoured; this only tells a stale approval (made before the upgrade) from a forged one (tampering).
 */
export function verifyLegacyApproval(publicKeyB64: string, sessionId: string, actionHash: string, id: string, sig: string): boolean {
  try {
    const pub = verifyingKey(publicKeyB64);
    return verify(null, Buffer.from(`launchsafe-firewall/approval/v1\n${sessionId}\n${actionHash}\n${id}`, "utf8"), pub, Buffer.from(sig, "base64"));
  } catch {
    return false;
  }
}

export function verifyApproval(publicKeyB64: string, g: ApprovalGrant, sig: string): boolean {
  try {
    const pub = verifyingKey(publicKeyB64);
    return verify(null, approvalMessage(g), pub, Buffer.from(sig, "base64"));
  } catch {
    return false;
  }
}

// --- who is at the keyboard ------------------------------------------------------------------------

/**
 * The variables a coding agent sets for the commands its tools run: Claude Code (CLAUDECODE,
 * CLAUDE_CODE_*), Codex (CODEX_SANDBOX and CODEX_SANDBOX_NETWORK_DISABLED in its sandboxed shell,
 * CODEX_THREAD_ID), Gemini CLI (GEMINI_CLI=1 in its shell tool) and Cursor's agent (CURSOR_AGENT=1).
 * Cursor's own variables for its integrated terminal (CURSOR_TRACE_ID) are not here: the person types there too.
 */
export function agentEnv(env: NodeJS.ProcessEnv): string | null {
  if (env.CLAUDECODE === "1" || env.CLAUDE_CODE_ENTRYPOINT !== undefined || env.CLAUDE_CODE_SESSION_ID !== undefined) return "Claude Code";
  if (env.CODEX_SANDBOX !== undefined || env.CODEX_SANDBOX_NETWORK_DISABLED !== undefined || env.CODEX_THREAD_ID !== undefined) return "Codex";
  if (env.GEMINI_CLI === "1") return "Gemini CLI";
  if (env.CURSOR_AGENT === "1") return "Cursor";
  return null;
}

/** Whether a process's command line is an agent's CLI (Claude Code, Codex, Gemini CLI, Cursor's agent). */
export function agentProcess(command: string): boolean {
  return AGENT_COMMAND.test(command);
}

/**
 * Whether this process was started (directly or through any wrapper) by a coding agent's session, i.e.
 * by the agent's own tools. Defense in depth next to the passphrase: an agent can fake a TTY with
 * `script`, but it cannot make its commands stop being descendants of the agent's process.
 *
 * The walk reads /proc on Linux (slim images have no ps) and ps elsewhere. When a process on the way cannot be
 * read, or its line cannot be parsed, the answer is "an agent": a person refused here can still approve from
 * another terminal, while an agent let through here has only the passphrase left in its way. Only a PID 1 that
 * cannot be read at all ends the walk as the top of the tree.
 */
export function launchedByAgent(env: NodeJS.ProcessEnv = process.env, pid = process.pid, ps?: (pid: number) => string | null): boolean {
  return agentLaunch(env, pid, ps) !== null;
}

/**
 * Why launchedByAgent says "an agent": the agent's variables ("environment"), an agent's process on the way
 * ("process"), or a walk that could not be finished ("unknown": a process on the way could not be read, the chain
 * loops or is longer than 40); null when the person started it. The refusal says which, so a person whose process
 * table is hidden is not told an agent started the command.
 */
export function agentLaunch(env: NodeJS.ProcessEnv = process.env, pid = process.pid, ps: (pid: number) => string | null = (p) => processLine(p)): "environment" | "process" | "unknown" | null {
  if (agentEnv(env) !== null) return "environment";
  if (pid <= 1) return null;
  const seen = new Set<number>();
  let cur = pid;
  for (let i = 0; i < 40; i++) {
    // Past the top of the tree with no agent on the way: the person started it.
    if (cur < 1) return null;
    if (seen.has(cur)) return "unknown";
    seen.add(cur);
    const line = ps(cur);
    // PID 1 may be hidden from other users (hidepid); in a container, where the agent can be PID 1, it is readable.
    if (line === null) return cur !== 1 ? "unknown" : null;
    const m = /^\s*(\d+)\s+(.*)$/.exec(line);
    // A line that was read but is not "<ppid> <command>" says nothing about who started it, PID 1's included.
    if (m === null) return "unknown";
    if (cur !== pid && agentProcess(m[2] as string)) return "process";
    cur = Number(m[1]);
  }
  return "unknown";
}
