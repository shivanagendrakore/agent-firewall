/**
 * The vault's operations, for the person-run CLI: add, allow, revoke,
 * remove, rotate. Each one writes the backend and re-signs the index with
 * the unlocked approver key. Nothing here prompts or prints; values pass
 * through memory only and are never logged.
 */

import type { KeyObject } from "node:crypto";
import { fingerprint } from "../../engine/secrets.js";
import { FIELD_RE, isValidName, processBindingMatches, validHostPattern, type VaultBinding, type VaultKind } from "../../engine/vault-ref.js";
import type { Confirm, VaultPolicy } from "../../policy-vault.js";
import type { CanaryIndex } from "../../types.js";
import type { Layout } from "../layout.js";
import { accountFor, VaultBackendError, type VaultBackend } from "./backend.js";
import { updateIndex, VaultIndexError, type BackendId, type VaultEntry } from "./index.js";
import { own, setOwn } from "../../own.js";

/** The fields a kind has unless --fields says otherwise. */
export const DEFAULT_FIELDS: Record<VaultKind, readonly string[]> = {
  credential: ["value"],
  oauth: ["value"],
  card: ["number", "expiry", "cvc", "name"],
  iban: ["iban", "bic", "holder"],
  national_id: ["value"],
  personal: ["value"],
};

export const MAX_FIELDS = 8;
export const MAX_VALUE_LENGTH = 4096;

export class VaultUsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VaultUsageError";
  }
}

/** Parses --fields; throws VaultUsageError. */
export function parseFields(raw: string | undefined, kind: VaultKind): string[] {
  if (raw === undefined) return [...DEFAULT_FIELDS[kind]];
  const fields = raw.split(",").map((f) => f.trim());
  if (fields.length === 0 || fields.length > MAX_FIELDS) throw new VaultUsageError(`--fields takes 1 to ${MAX_FIELDS} field names`);
  const bad = fields.find((f) => !FIELD_RE.test(f));
  if (bad !== undefined) throw new VaultUsageError(`"${bad}" is not a field name (lower-case letters, digits and _; up to 32)`);
  if (new Set(fields).size !== fields.length) throw new VaultUsageError("--fields lists a field twice");
  return fields;
}

export function checkName(name: string): void {
  if (!isValidName(name)) throw new VaultUsageError(`"${name}" is not a vault name: 1 to 4 parts of lower-case letters, digits, _ and - (each starting with a letter or digit), joined by "/", such as github/token`);
}

/**
 * Which store a new secret goes to on this machine: the Keychain on macOS; the Secret Service on Linux,
 * else the encrypted file only when the policy allows the fallback. A reason when none can be used.
 */
export function chooseBackend(platform: NodeJS.Platform, pol: VaultPolicy, available: (id: BackendId) => { ok: boolean; reason?: string }): { id: BackendId } | { id: null; reason: string } {
  if (platform === "darwin") {
    const a = available("keychain");
    return a.ok ? { id: "keychain" } : { id: null, reason: a.reason ?? "the macOS Keychain is not available" };
  }
  if (platform === "linux") {
    const a = available("libsecret");
    if (a.ok) return { id: "libsecret" };
    if (pol.fileFallback) return { id: "file" };
    return { id: null, reason: `${a.reason ?? "no Secret Service"}. The encrypted file store protects only against backups, so it is off unless your user policy sets "vault": { "fileFallback": true }` };
  }
  return { id: null, reason: `${platform} is not supported (macOS and Linux only)` };
}

/** Per-field fingerprints of the values; fields shorter than 12 characters have none (listed in `short`). */
export function fingerprintsOf(values: Record<string, string>): { prints: Record<string, string>; short: string[] } {
  const prints: Record<string, string> = {};
  const short: string[] = [];
  for (const [f, v] of Object.entries(values)) {
    const fp = fingerprint(v);
    if (fp === null) short.push(f);
    else setOwn(prints, f, fp);
  }
  return { prints, short };
}

function checkValues(fields: readonly string[], values: Record<string, string>, canaries: CanaryIndex | undefined): void {
  for (const f of fields) {
    const v = own(values, f);
    if (v === undefined || v === "") throw new VaultUsageError(`no value was given for ${f}`);
    if (v.length > MAX_VALUE_LENGTH) throw new VaultUsageError(`the value for ${f} is longer than ${MAX_VALUE_LENGTH} characters`);
    if (/[\r\n\0]/.test(v)) throw new VaultUsageError(`the value for ${f} contains a line break or NUL`);
    // A decoy is never a vault entry: its value must stay valid nowhere.
    const fp = fingerprint(v);
    if (fp !== null && canaries?.fingerprints.has(fp) === true) throw new VaultUsageError(`the value for ${f} is the value of a decoy file you planted; decoys cannot be stored in the vault`);
  }
}

export interface AddInput {
  name: string;
  kind: VaultKind;
  fields: string[];
  values: Record<string, string>;
  confirm: Confirm;
  backend: VaultBackend;
  canaries?: CanaryIndex;
  now?: Date;
}

/** Stores the values, then adds the entry to the index. Refuses a name that exists (rotate replaces values). */
export function addSecret(l: Layout, priv: KeyObject, i: AddInput): { entry: VaultEntry; short: string[] } {
  checkName(i.name);
  checkValues(i.fields, i.values, i.canaries);
  const { prints, short } = fingerprintsOf(Object.fromEntries(i.fields.map((f) => [f, own(i.values, f) as string])));
  const now = i.now ?? new Date();
  return updateIndex(
    l,
    priv,
    (entries) => {
      if (entries.some((e) => e.name === i.name)) throw new VaultUsageError(`vault://${i.name} exists already; use "vault rotate ${i.name}" to replace its values`);
      // The backend first: an entry in the index always has its values stored.
      for (const f of i.fields) i.backend.write(accountFor(i.name, f), own(i.values, f) as string, { confirm: i.confirm });
      const entry: VaultEntry = { name: i.name, kind: i.kind, fields: [...i.fields], backend: i.backend.id, confirm: i.confirm, bindings: [], fingerprints: prints, createdAt: now.toISOString() };
      entries.push(entry);
      return { entry, short };
    },
    now,
  );
}

/**
 * Replaces every field's value and its fingerprint. When a later field cannot be written, the fields already
 * replaced keep their new values, so the index is still written with their new fingerprints (the output
 * scrub and the canary recognise what is stored now) and the error is then raised.
 */
export function rotateSecret(l: Layout, priv: KeyObject, name: string, values: Record<string, string>, backendFor: (id: BackendId) => VaultBackend, o: { canaries?: CanaryIndex; now?: Date } = {}): { entry: VaultEntry; short: string[] } {
  const now = o.now ?? new Date();
  let failure: unknown;
  const done = updateIndex(
    l,
    priv,
    (entries) => {
      const entry = entries.find((e) => e.name === name);
      if (entry === undefined) throw new VaultUsageError(`no such secret: vault://${name}`);
      checkValues(entry.fields, values, o.canaries);
      const backend = backendFor(entry.backend);
      const written: string[] = [];
      try {
        for (const f of entry.fields) {
          backend.write(accountFor(name, f), own(values, f) as string, { confirm: entry.confirm });
          written.push(f);
        }
      } catch (e) {
        failure = e;
      }
      const { prints, short } = fingerprintsOf(Object.fromEntries(written.map((f) => [f, own(values, f) as string])));
      if (failure === undefined) entry.fingerprints = prints;
      else {
        // A field not reached keeps its old value and fingerprint; a field replaced gets its new one.
        for (const f of written) delete entry.fingerprints[f];
        for (const [f, fp] of Object.entries(prints)) setOwn(entry.fingerprints, f, fp);
      }
      if (written.length > 0) entry.rotatedAt = now.toISOString();
      return { entry: { ...entry }, short };
    },
    now,
  );
  if (failure !== undefined) throw failure;
  return done;
}

/**
 * Removes the entry from the index first (so nothing refers to it), then deletes its values. Values the
 * backend could not delete are reported, not hidden.
 */
export function removeSecret(l: Layout, priv: KeyObject, name: string, backendFor: (id: BackendId) => VaultBackend, now: Date = new Date()): { entry: VaultEntry; problems: string[] } {
  const entry = updateIndex(
    l,
    priv,
    (entries) => {
      const i = entries.findIndex((e) => e.name === name);
      if (i === -1) throw new VaultUsageError(`no such secret: vault://${name}`);
      return entries.splice(i, 1)[0] as VaultEntry;
    },
    now,
  );
  const problems: string[] = [];
  let backend: VaultBackend | null = null;
  try {
    backend = backendFor(entry.backend);
  } catch (e) {
    problems.push(`could not open the ${entry.backend} store: ${(e as Error).message}`);
  }
  for (const f of backend === null ? [] : entry.fields) {
    try {
      backend?.remove(accountFor(name, f));
    } catch (e) {
      problems.push((e as Error).message);
    }
  }
  return { entry, problems };
}

/** Parses the destination flags of `vault allow` into a binding. Throws VaultUsageError. */
export function parseBinding(o: { host?: string; allowInUrl?: boolean; allowHttp?: boolean; mcp?: string; process?: string }): { binding: VaultBinding; warning?: string } {
  const given = [o.host, o.mcp, o.process].filter((x) => x !== undefined).length;
  if (given !== 1) throw new VaultUsageError("give exactly one of --host, --mcp, --process");
  if (o.allowInUrl === true && o.host === undefined) throw new VaultUsageError("--allow-in-url only applies with --host");
  if (o.allowHttp === true && o.host === undefined) throw new VaultUsageError("--allow-http only applies with --host");
  if (o.host !== undefined) {
    const host = o.host.trim().toLowerCase().replace(/\.$/, "");
    if (!validHostPattern(host)) throw new VaultUsageError(`"${o.host}" is not a host name (an exact name such as api.github.com, or *.example.com for its subdomains)`);
    const warnings = [...(o.allowInUrl === true ? ["the value may be put into the URL itself, where server logs and proxies keep it"] : []), ...(o.allowHttp === true ? ["the value may be sent over plain http, readable by anyone on the network path"] : [])];
    return { binding: { kind: "host", host, ...(o.allowInUrl === true ? { allowInUrl: true } : {}), ...(o.allowHttp === true ? { allowHttp: true } : {}) }, ...(warnings.length > 0 ? { warning: warnings.join("; ") } : {}) };
  }
  if (o.mcp !== undefined) {
    const [server, tool, arg, ...rest] = o.mcp.split(":");
    if (rest.length > 0 || server === undefined || !/^[A-Za-z0-9_.-]{1,100}$/.test(server)) throw new VaultUsageError(`--mcp takes SERVER[:TOOL[:ARG]], such as linear or linear:create_*:headers.token`);
    if (tool !== undefined && !/^[A-Za-z0-9_.*?-]{1,100}$/.test(tool)) throw new VaultUsageError(`"${tool}" is not a tool name or pattern (letters, digits, _ . - and the wildcards * ?)`);
    if (arg !== undefined && !/^[A-Za-z0-9_.[\]-]{1,200}$/.test(arg)) throw new VaultUsageError(`"${arg}" is not an argument path (such as headers.token)`);
    return { binding: { kind: "mcp", server, ...(tool !== undefined && tool !== "" ? { tool } : {}), ...(arg !== undefined && arg !== "" ? { arg } : {}) } };
  }
  const argv = (o.process ?? "").trim().split(/\s+/).filter((w) => w !== "");
  if (argv.length === 0) throw new VaultUsageError('--process takes the command line the secret may be given to, such as "npm publish"');
  if (argv[0] === "*") throw new VaultUsageError("a process binding must name the program; a bare * would give the secret to any command");
  if (argv.some((w) => /["'`$\\]/.test(w))) throw new VaultUsageError("write the command line as plain words (no quotes, $ or backslashes)");
  if (argv.slice(0, -1).includes("*") || argv.some((w) => w !== "*" && w.includes("*"))) throw new VaultUsageError('"*" is allowed only as a whole last word (any further arguments)');
  // Sanity: the pattern matches its own fixed words.
  if (!processBindingMatches(argv, argv[argv.length - 1] === "*" ? argv.slice(0, -1) : argv)) throw new VaultUsageError("that command-line pattern cannot match anything");
  const display = argv.join(" ");
  return { binding: { kind: "process", argv, display }, ...(argv[argv.length - 1] === "*" ? { warning: `"${display}" ends in *, so the secret goes to that program with any further arguments` } : {}) };
}

function sameBinding(a: VaultBinding, b: VaultBinding): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

export function allowBinding(l: Layout, priv: KeyObject, name: string, binding: VaultBinding, now: Date = new Date()): VaultEntry {
  return updateIndex(
    l,
    priv,
    (entries) => {
      const entry = entries.find((e) => e.name === name);
      if (entry === undefined) throw new VaultUsageError(`no such secret: vault://${name}`);
      if (entry.bindings.some((b) => sameBinding(b, binding))) throw new VaultUsageError("that binding exists already");
      entry.bindings.push(binding);
      return { ...entry };
    },
    now,
  );
}

/** Removes the n-th binding (1-based, as `vault list` numbers them). */
export function revokeBinding(l: Layout, priv: KeyObject, name: string, n: number, now: Date = new Date()): { entry: VaultEntry; removed: VaultBinding } {
  return updateIndex(
    l,
    priv,
    (entries) => {
      const entry = entries.find((e) => e.name === name);
      if (entry === undefined) throw new VaultUsageError(`no such secret: vault://${name}`);
      if (!Number.isInteger(n) || n < 1 || n > entry.bindings.length) throw new VaultUsageError(`vault://${name} has ${entry.bindings.length} binding(s); give a number from vault list`);
      const removed = entry.bindings.splice(n - 1, 1)[0] as VaultBinding;
      return { entry: { ...entry }, removed };
    },
    now,
  );
}

export { VaultBackendError, VaultIndexError };
