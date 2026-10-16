/**
 * The policy file: safe defaults, a versioned schema with strict validation
 * (unknown keys are errors), migrations for future versions, and the rule
 * that a project's own policy file can only make things stricter.
 */

import type { DataKind, FirewallConfig, McpServerPolicy, ProvenancePolicy } from "./types.js";
import { AGENT_SCAN_KEYS, defaultAgentScan, defaultMcpPinning, tightenAgentScanKeys, validateAgentScanKeys, type AgentScanDoc } from "./policy-agentscan.js";
import { CANARY_POLICY_KEYS, defaultCanaries, tightenCanaryKeys, validateCanaryKeys, type CanaryDoc } from "./policy-canaries.js";
import { defaultNotifications, NOTIFY_POLICY_KEYS, tightenNotifyKeys, validateNotifyKeys, type NotifyDoc } from "./policy-notify.js";
import { defaultPackageIntel, PACKAGE_POLICY_KEYS, tightenPackageKeys, validatePackageKeys, type PackageDoc } from "./policy-packages.js";
import { KNOWN_HOSTS_POLICY_KEYS, mergeKnownHosts, tightenKnownHostsKeys, validateKnownHostsKeys, type KnownHostsDoc } from "./policy-knownhosts.js";
import { RUN_POLICY_KEYS, tightenRunKeys, validateRunKeys, type RunDoc } from "./policy-run.js";
import { defaultSandbox, SANDBOX_POLICY_KEYS, tightenSandboxKeys, validateSandboxKeys, type SandboxDoc } from "./policy-sandbox.js";
import { mergeVault, tightenVaultKeys, validateVaultKeys, VAULT_POLICY_KEYS, type VaultDoc } from "./policy-vault.js";
import { GATEWAY_POLICY_KEYS, mergeGateway, tightenGatewayKeys, validateGatewayKeys, type GatewayDoc } from "./policy-gateway.js";
import { EMAIL_POLICY_KEYS, mergeEmail, tightenEmailKeys, validateEmailKeys, type EmailDoc } from "./policy-email.js";
import { mergePhone, PHONE_POLICY_KEYS, tightenPhoneKeys, validatePhoneKeys, type PhoneDoc } from "./policy-phone.js";
import { LEARNED_POLICY_KEYS, mergeLearned, tightenLearnedKeys, validateLearnedKeys, type LearnedDoc } from "./policy-learned.js";
import { defaultPersistence, mergePersistence, PERSISTENCE_POLICY_KEYS, tightenPersistenceKeys, validatePersistenceKeys, type PersistenceDoc } from "./policy-persistence.js";
import { BUDGET_POLICY_KEYS, defaultBudgets, mergeBudgets, tightenBudgetKeys, validateBudgetKeys, type BudgetDoc } from "./policy-budgets.js";
import { CAP_POLICY_KEYS, defaultCaps, mergeCaps, tightenCapKeys, validateCapKeys, type CapDoc } from "./policy-caps.js";
import { defaultTaskScope, SCOPE_POLICY_KEYS, tightenScopeKeys, validateScopeKeys, type ScopeDoc } from "./policy-scope.js";
import { ROLLOUT_POLICY_KEYS, tightenRolloutKeys, validateRolloutKeys, type RolloutDoc } from "./policy-rollout.js";
import { mergeOutsider, OUTSIDER_POLICY_KEYS, tightenOutsiderKeys, validateOutsiderKeys, type OutsiderDoc } from "./policy-outsider.js";
import { hasOwn, own, setOwn } from "./own.js";
import { matchServerEntry, parseMcpTool } from "./engine/mcp.js";
import { DEFAULT_PROTECTED_BRANCHES } from "./engine/catastrophic.js";
import { globMatch } from "./engine/glob.js";

export { defaultNotifications, MIN_NOTIFY_INTERVAL_SEC, NOTIFY_KINDS } from "./policy-notify.js";

/**
 * The schema version this firewall writes. Version 3 holds the v0.3 keys
 * (`gateway`, `emailGuard`, `vault`, `phone`). Moving the number, rather than adding keys silently to
 * version 2, is what makes an older firewall fail safe on a newer file: `migrate()` there refuses any
 * version above its own, the loader skips the file and raises a policy error (strict defaults for what
 * the file would have set, every risky action to a person), and every release since v0.1 does this.
 */
export const POLICY_VERSION = 3;
/** The oldest schema version this firewall still reads (migrated in memory). */
export const OLDEST_POLICY_VERSION = 1;

export const DEFAULT_FETCH_ALLOW_HOSTS: readonly string[] = [
  // Package registries.
  "registry.npmjs.org",
  "registry.yarnpkg.com",
  "npm.pkg.github.com",
  "pypi.org",
  "files.pythonhosted.org",
  "crates.io",
  "static.crates.io",
  "index.crates.io",
  "proxy.golang.org",
  "sum.golang.org",
  "pkg.go.dev",
  "rubygems.org",
  "repo.maven.apache.org",
  "repo1.maven.org",
  "plugins.gradle.org",
  "api.nuget.org",
  "packagist.org",
  "jsr.io",
  "deno.land",
  "registry-1.docker.io",
  "ghcr.io",
  // Source hosting (fetching code; pushing is a send and is judged separately).
  "=github.com",
  "codeload.github.com",
  "raw.githubusercontent.com",
  "objects.githubusercontent.com",
  "=gitlab.com",
  // Language and platform documentation.
  "nodejs.org",
  "developer.mozilla.org",
  "docs.python.org",
  "docs.rs",
  "doc.rust-lang.org",
  "go.dev",
  "typescriptlang.org",
  "react.dev",
  "nextjs.org",
  "docs.github.com",
  "code.claude.com",
  "docs.anthropic.com",
  "docs.claude.com",
  "modelcontextprotocol.io",
];

export function defaultConfig(): FirewallConfig {
  return {
    version: POLICY_VERSION,
    fetchAllowHosts: [...DEFAULT_FETCH_ALLOW_HOSTS],
    sendAllowHosts: [],
    denyHosts: [],
    dataAllowHosts: { credential: [], card: [], iban: [], national_id: [] },
    mcpServers: {},
    mcpDefault: { results: "untrusted", privateData: true },
    untrustedPaths: [],
    protectedPaths: [".launchsafe-firewall.json"],
    secretPaths: [],
    trustedReadRoots: ["/usr/include", "/usr/share", "/usr/lib", "/System", "/Library/Developer", "/Applications/Xcode.app", "/opt/homebrew/include", "/opt/homebrew/share"],
    untrustedWorkspace: false,
    redactSecretsInOutput: false,
    allowTestValues: true,
    allowInstructionWritesWhenTrusted: true,
    unattended: false,
    unattendedHours: [],
    // I6: bypassPermissions and auto are held, not asked, until an ask under them is verified to reach a person
    // (docs/agents/overview.md, "Bypass and yolo modes").
    unattendedPermissionModes: ["dontAsk", "bypassPermissions", "auto"],
    protectedBranches: [...DEFAULT_PROTECTED_BRANCHES],
    userOutputTools: [],
    notUserOutputTools: [],
    provenance: { trustSelfAuthored: true, carryUntrustedWrites: true, maxHashBytes: 4 * 1024 * 1024 },
    agentScan: defaultAgentScan(),
    mcpPinning: defaultMcpPinning(),
    canaries: defaultCanaries(),
    notifications: defaultNotifications(),
    taskScope: defaultTaskScope(),
    packageIntel: defaultPackageIntel(),
    sandbox: defaultSandbox(),
    persistence: defaultPersistence(),
    budgets: defaultBudgets(),
    caps: defaultCaps(),
  };
}

/** A validated policy file: any subset of the settings (nested objects may be partial too). */
export type PolicyDoc = Omit<Partial<FirewallConfig>, "provenance" | "version" | "agentScan" | "mcpPinning" | "canaries" | "notifications" | "persistence" | "budgets" | "caps" | "taskScope" | "vault" | "gateway" | "emailGuard" | "phone" | "run" | "rollout" | "knownHosts" | "learnedAllows" | "outsiderWritable"> & { provenance?: Partial<ProvenancePolicy> } & RunDoc & RolloutDoc & AgentScanDoc & CanaryDoc & NotifyDoc & PackageDoc & SandboxDoc & PersistenceDoc & BudgetDoc & CapDoc & ScopeDoc & VaultDoc & GatewayDoc & EmailDoc & PhoneDoc & KnownHostsDoc & LearnedDoc & OutsiderDoc;

export class PolicyError extends Error {
  constructor(
    readonly source: string,
    readonly problems: string[],
  ) {
    super(`${source}: ${problems.join("; ")}`);
  }
}

type Raw = Record<string, unknown>;

const STRING_LIST_KEYS = ["fetchAllowHosts", "sendAllowHosts", "denyHosts", "untrustedPaths", "protectedPaths", "secretPaths", "trustedReadRoots", "unattendedPermissionModes", "protectedBranches", "userOutputTools", "notUserOutputTools"] as const;
const BOOL_KEYS = ["untrustedWorkspace", "redactSecretsInOutput", "allowInstructionWritesWhenTrusted", "unattended", "allowTestValues"] as const;
const DATA_KINDS: readonly DataKind[] = ["credential", "card", "iban", "national_id"];
const KNOWN_KEYS = new Set<string>(["version", "$schema", "dataAllowHosts", "mcpServers", "mcpDefault", "unattendedHours", "provenance", ...AGENT_SCAN_KEYS, ...CANARY_POLICY_KEYS, ...NOTIFY_POLICY_KEYS, ...PACKAGE_POLICY_KEYS, ...SANDBOX_POLICY_KEYS, ...RUN_POLICY_KEYS, ...PERSISTENCE_POLICY_KEYS, ...BUDGET_POLICY_KEYS, ...CAP_POLICY_KEYS, ...SCOPE_POLICY_KEYS, ...VAULT_POLICY_KEYS, ...GATEWAY_POLICY_KEYS, ...EMAIL_POLICY_KEYS, ...PHONE_POLICY_KEYS, ...ROLLOUT_POLICY_KEYS, ...KNOWN_HOSTS_POLICY_KEYS, ...LEARNED_POLICY_KEYS, ...OUTSIDER_POLICY_KEYS, ...STRING_LIST_KEYS, ...BOOL_KEYS]);
const PROVENANCE_KEYS = new Set(["trustSelfAuthored", "carryUntrustedWrites", "maxHashBytes"]);
const MAX_HASH_LIMIT = 64 * 1024 * 1024;
const SERVER_KEYS = new Set(["results", "privateData", "readTools", "sendTools", "destructiveTools", "blockedTools"]);

/** Upgrades an older policy document to the current schema. Each step is a pure function. */
const MIGRATIONS: Record<number, (raw: Raw) => Raw> = {
  // 1 -> 2 (v0.2): only new keys, all with defaults, so a version 1 file means the same as version 2.
  1: (raw) => ({ ...raw, version: 2 }),
  // 2 -> 3: the v0.3 keys were already read under version 2 with the same validation and the
  // same tighten-only rules, so a version 2 file means exactly the same as version 3. Lossless by design:
  // every key, value and key order is kept; only the number changes.
  2: (raw) => ({ ...raw, version: 3 }),
};

export function migrate(raw: Raw, source: string): Raw {
  let version = raw.version;
  if (version === undefined) throw new PolicyError(source, [`missing "version" (this release reads versions ${OLDEST_POLICY_VERSION} to ${POLICY_VERSION})`]);
  if (typeof version !== "number" || !Number.isInteger(version) || version < OLDEST_POLICY_VERSION) throw new PolicyError(source, [`"version" must be a positive integer, got ${JSON.stringify(version)}`]);
  if (version > POLICY_VERSION) throw new PolicyError(source, [`policy version ${version} is newer than this firewall understands (${POLICY_VERSION}); upgrade @launchsafe/agent-firewall`]);
  let doc = raw;
  while ((version as number) < POLICY_VERSION) {
    const step = MIGRATIONS[version as number];
    if (step === undefined) throw new PolicyError(source, [`no migration from policy version ${String(version)}`]);
    doc = step(doc);
    version = doc.version;
  }
  return doc;
}

/** Item 3 (policy size): the most entries one list may hold, and the longest entry. Past them the file is an error. */
export const MAX_LIST_ENTRIES = 1000;
export const MAX_ENTRY_CHARS = 4096;

function checkStringList(v: unknown, key: string, problems: string[]): string[] | null {
  if (!Array.isArray(v) || !v.every((x) => typeof x === "string" && x.trim() !== "")) {
    problems.push(`"${key}" must be a list of non-empty strings`);
    return null;
  }
  if (v.length > MAX_LIST_ENTRIES) {
    problems.push(`"${key}" has ${v.length} entries; at most ${MAX_LIST_ENTRIES} are allowed`);
    return null;
  }
  if ((v as string[]).some((x) => x.length > MAX_ENTRY_CHARS)) {
    problems.push(`"${key}" has an entry longer than ${MAX_ENTRY_CHARS} characters`);
    return null;
  }
  // A host, tool or pattern never holds a control character; one could end a line in what is generated
  // from the policy (openshell policy's comments, for one) and start another.
  // eslint-disable-next-line no-control-regex -- control characters (and Unicode line separators) are what is refused
  const bad = (v as string[]).find((x) => /[\u0000-\u001f\u007f\u0085\u2028\u2029]/.test(x));
  if (bad !== undefined) {
    problems.push(`"${key}" has an entry with a control character (${JSON.stringify(bad.slice(0, 80))})`);
    return null;
  }
  return v as string[];
}

function checkServer(v: unknown, key: string, problems: string[]): McpServerPolicy | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    problems.push(`"${key}" must be an object`);
    return null;
  }
  const o = v as Raw;
  for (const k of Object.keys(o)) if (!SERVER_KEYS.has(k)) problems.push(`"${key}.${k}" is not a known setting (expected one of ${[...SERVER_KEYS].join(", ")})`);
  if (o.results !== "trusted" && o.results !== "untrusted") problems.push(`"${key}.results" must be "trusted" or "untrusted"`);
  if (typeof o.privateData !== "boolean") problems.push(`"${key}.privateData" must be true or false`);
  const out: McpServerPolicy = { results: o.results === "trusted" ? "trusted" : "untrusted", privateData: o.privateData !== false };
  for (const k of ["readTools", "sendTools", "destructiveTools", "blockedTools"] as const) {
    if (o[k] === undefined) continue;
    const list = checkStringList(o[k], `${key}.${k}`, problems);
    if (list !== null) out[k] = list;
  }
  return out;
}

const HHMM = /^(?:[01]\d|2[0-3]):[0-5]\d$/;

/** Validates a policy document (already parsed JSON). Returns the partial settings it contains. */
export function validatePolicy(input: unknown, source: string): PolicyDoc {
  if (typeof input !== "object" || input === null || Array.isArray(input)) throw new PolicyError(source, ["the policy must be a JSON object"]);
  const raw = migrate(input as Raw, source);
  const problems: string[] = [];
  const out: PolicyDoc = {};
  for (const k of Object.keys(raw)) if (!KNOWN_KEYS.has(k)) problems.push(`"${k}" is not a known setting`);
  for (const k of STRING_LIST_KEYS) {
    if (raw[k] === undefined) continue;
    const list = checkStringList(raw[k], k, problems);
    if (list !== null) out[k] = list;
  }
  for (const k of BOOL_KEYS) {
    if (raw[k] === undefined) continue;
    if (typeof raw[k] !== "boolean") problems.push(`"${k}" must be true or false`);
    else out[k] = raw[k] as boolean;
  }
  if (raw.dataAllowHosts !== undefined) {
    const d = raw.dataAllowHosts;
    if (typeof d !== "object" || d === null || Array.isArray(d)) problems.push('"dataAllowHosts" must be an object');
    else {
      const res = { credential: [], card: [], iban: [], national_id: [] } as Record<DataKind, string[]>;
      for (const [k, v] of Object.entries(d as Raw)) {
        if (!DATA_KINDS.includes(k as DataKind)) {
          problems.push(`"dataAllowHosts.${k}" is not a data kind (expected ${DATA_KINDS.join(", ")})`);
          continue;
        }
        const list = checkStringList(v, `dataAllowHosts.${k}`, problems);
        if (list !== null) res[k as DataKind] = list;
      }
      out.dataAllowHosts = res;
    }
  }
  if (raw.mcpServers !== undefined) {
    const m = raw.mcpServers;
    if (typeof m !== "object" || m === null || Array.isArray(m)) problems.push('"mcpServers" must be an object of server name to settings');
    else {
      const res: Record<string, McpServerPolicy> = {};
      for (const [name, v] of Object.entries(m as Raw)) {
        const sp = checkServer(v, `mcpServers.${name}`, problems);
        if (sp !== null) setOwn(res, name, sp);
      }
      out.mcpServers = res;
    }
  }
  if (raw.mcpDefault !== undefined) {
    const sp = checkServer(raw.mcpDefault, "mcpDefault", problems);
    if (sp !== null) out.mcpDefault = sp;
  }
  if (raw.unattendedHours !== undefined) {
    const h = raw.unattendedHours;
    if (!Array.isArray(h) || !h.every((x) => typeof x === "object" && x !== null && typeof (x as Raw).from === "string" && typeof (x as Raw).to === "string" && HHMM.test((x as Raw).from as string) && HHMM.test((x as Raw).to as string) && Object.keys(x as Raw).every((k) => k === "from" || k === "to"))) {
      problems.push('"unattendedHours" must be a list of { "from": "HH:MM", "to": "HH:MM" }');
    } else out.unattendedHours = h as { from: string; to: string }[];
  }
  if (raw.provenance !== undefined) {
    const pv = raw.provenance;
    if (typeof pv !== "object" || pv === null || Array.isArray(pv)) problems.push('"provenance" must be an object');
    else {
      const o = pv as Raw;
      const res: Partial<ProvenancePolicy> = {};
      for (const k of Object.keys(o)) if (!PROVENANCE_KEYS.has(k)) problems.push(`"provenance.${k}" is not a known setting (expected one of ${[...PROVENANCE_KEYS].join(", ")})`);
      for (const k of ["trustSelfAuthored", "carryUntrustedWrites"] as const) {
        if (o[k] === undefined) continue;
        if (typeof o[k] !== "boolean") problems.push(`"provenance.${k}" must be true or false`);
        else res[k] = o[k] as boolean;
      }
      if (o.maxHashBytes !== undefined) {
        const n = o.maxHashBytes;
        if (typeof n !== "number" || !Number.isInteger(n) || n < 0 || n > MAX_HASH_LIMIT) problems.push(`"provenance.maxHashBytes" must be a whole number from 0 to ${MAX_HASH_LIMIT}`);
        else res.maxHashBytes = n;
      }
      out.provenance = res;
    }
  }
  validateAgentScanKeys(raw, problems, out);
  validateCanaryKeys(raw, problems, out);
  validateNotifyKeys(raw, problems, out);
  validatePackageKeys(raw, problems, out);
  validateSandboxKeys(raw, problems, out);
  validateRunKeys(raw, problems, out);
  validatePersistenceKeys(raw, problems, out);
  validateBudgetKeys(raw, problems, out);
  validateCapKeys(raw, problems, out);
  validateScopeKeys(raw, problems, out);
  validateVaultKeys(raw, problems, out);
  validateGatewayKeys(raw, problems, out);
  validateEmailKeys(raw, problems, out);
  validatePhoneKeys(raw, problems, out);
  validateRolloutKeys(raw, problems, out);
  validateKnownHostsKeys(raw, problems, out);
  validateLearnedKeys(raw, problems, out);
  validateOutsiderKeys(raw, problems, out);
  if (problems.length > 0) throw new PolicyError(source, problems);
  return out;
}

/** The schema version a policy document declares (before migration), or null. */
export function declaredVersion(input: unknown): number | null {
  const v = typeof input === "object" && input !== null ? (input as Raw).version : undefined;
  return typeof v === "number" ? v : null;
}

/**
 * `policy migrate`'s plan for a parsed file: the document rewritten in the current schema, or null when it
 * already is. Refuses (PolicyError) a file this firewall cannot read, and checks the rewrite is lossless:
 * the original and the rewrite must validate to the same settings, so nothing is written otherwise.
 */
export function planMigration(input: unknown, source: string): { from: number; doc: Raw } | null {
  const before = validatePolicy(input, source);
  const raw = input as Raw;
  const from = raw.version as number;
  if (from === POLICY_VERSION) return null;
  const doc = migrate(raw, source);
  const after = validatePolicy(doc, source);
  if (JSON.stringify(before) !== JSON.stringify(after)) throw new PolicyError(source, [`migrating from version ${from} would change what the file means; it was left as it is`]);
  return { from, doc };
}

/** Applies the user's (or an administrator's) policy over the defaults: it may loosen or tighten anything. */
/** The protected patterns a user or managed file may add to but never take away: the project policy file itself. */
const BUILTIN_PROTECTED: readonly string[] = [".launchsafe-firewall.json"];

function withBuiltinProtected(list: readonly string[]): string[] {
  return [...new Set([...list, ...BUILTIN_PROTECTED])];
}

export function mergeTrusted(base: FirewallConfig, overDoc: PolicyDoc): FirewallConfig {
  // `rollout` is taken whole when the file sets a mode, so an empty `rollout: {}` changes nothing.
  const { rollout: _rollout, ...over } = overDoc;
  return { ...base, ...over, version: POLICY_VERSION, protectedPaths: withBuiltinProtected(over.protectedPaths ?? base.protectedPaths), dataAllowHosts: { ...base.dataAllowHosts, ...(over.dataAllowHosts ?? {}) }, mcpServers: { ...base.mcpServers, ...(over.mcpServers ?? {}) }, provenance: { ...base.provenance, ...(over.provenance ?? {}) }, agentScan: { ...base.agentScan, ...(over.agentScan ?? {}) }, mcpPinning: { ...base.mcpPinning, ...(over.mcpPinning ?? {}) }, canaries: { ...base.canaries, ...(over.canaries ?? {}) }, notifications: { ...base.notifications, ...(over.notifications ?? {}) }, packageIntel: { ...base.packageIntel, ...(over.packageIntel ?? {}) }, sandbox: { ...base.sandbox, ...(over.sandbox ?? {}) }, persistence: mergePersistence(base.persistence, over.persistence), budgets: mergeBudgets(base.budgets, over.budgets), caps: mergeCaps(base.caps, over.caps), taskScope: { ...base.taskScope, ...(over.taskScope ?? {}) }, ...(base.vault !== undefined || over.vault !== undefined ? { vault: mergeVault(base.vault, over.vault) } : {}), ...(base.gateway !== undefined || over.gateway !== undefined ? { gateway: mergeGateway(base.gateway, over.gateway) } : {}), ...(base.emailGuard !== undefined || over.emailGuard !== undefined ? { emailGuard: mergeEmail(base.emailGuard, over.emailGuard) } : {}), ...(base.phone !== undefined || over.phone !== undefined ? { phone: mergePhone(base.phone, over.phone) } : {}), ...(base.learnedAllows !== undefined || over.learnedAllows !== undefined ? { learnedAllows: mergeLearned(base.learnedAllows, over.learnedAllows) } : {}), ...(base.outsiderWritable !== undefined || over.outsiderWritable !== undefined ? { outsiderWritable: mergeOutsider(base.outsiderWritable, over.outsiderWritable) } : {}), ...(base.run !== undefined || over.run !== undefined ? { run: { ...base.run, ...over.run } } : {}), ...(overDoc.rollout?.mode !== undefined ? { rollout: { mode: overDoc.rollout.mode } } : base.rollout !== undefined ? { rollout: { ...base.rollout } } : {}), ...(base.knownHosts !== undefined || over.knownHosts !== undefined ? { knownHosts: mergeKnownHosts(base.knownHosts, over.knownHosts) } : {}) };
}

/**
 * Applies the administrator's managed policy over the user's (FM1). Every key the managed file sets wins,
 * as with `mergeTrusted`. On top of that, a managed restriction never yields to a user entry that would
 * otherwise be looked up first:
 *
 * - `mcpServers`: an exact name wins over a pattern and the first matching pattern wins, so a user entry
 *   ("corp-mail", or "*") could hide the managed entry ("corp-*") for the servers it names. Every user entry
 *   the managed file covers now starts from the managed entry and merges tighten-only (see
 *   `mergeServersUnderManaged`). A user entry for a server the managed file does not cover is unchanged.
 * - `userOutputTools`: a user-listed `mcp__<server>__<tool>` is judged as showing something to you before
 *   the server's entry is read, which would skip the managed entry's blocked tools. Unless the managed file
 *   sets `userOutputTools` itself, a user entry for a server the managed file covers is dropped.
 *
 * `base` is the configuration after the user's layer. `notes` say what of the user's file did not apply.
 */
export function mergeManaged(base: FirewallConfig, managed: PolicyDoc): { config: FirewallConfig; notes: string[] } {
  const config = mergeTrusted(base, managed);
  const notes: string[] = [];
  managedOutsider(base, managed, config, notes);
  const m = managed.mcpServers;
  if (m === undefined || Object.keys(m).length === 0) return { config, notes };
  config.mcpServers = mergeServersUnderManaged(base.mcpServers, m, notes);
  if (managed.userOutputTools === undefined) {
    config.userOutputTools = base.userOutputTools.filter((name) => {
      const t = parseMcpTool(name);
      if (t === null || matchServerEntry(m, t.server) === undefined) return true;
      notes.push(`userOutputTools.${name}: the managed policy has an entry for ${t.server}, so the user policy cannot mark its tools as only showing things to you`);
      return false;
    });
  }
  return { config, notes };
}

/**
 * The administrator's `outsiderWritable` over the user's exemptions: a user may not take out of the class a
 * server the managed file puts in it, and when the managed file turns `alwaysTaint` on without listing
 * exemptions of its own, none of the user's apply.
 */
function managedOutsider(base: FirewallConfig, managed: PolicyDoc, config: FirewallConfig, notes: string[]): void {
  const mo = managed.outsiderWritable;
  const userExempt = base.outsiderWritable?.exempt ?? [];
  if (mo === undefined || mo.exempt !== undefined || userExempt.length === 0) return;
  const servers = mo.servers ?? [];
  const covered = (e: string): boolean => servers.some((p) => (p.includes("*") ? globMatch(p, e.replace(/\*/g, ""), true) || p === e : p.toLowerCase() === e.toLowerCase()));
  // A user pattern (`corp-*`, `*`) that would also take a managed server out of the class is dropped whole: the
  // outsider check reads the exemptions before the server list, so it would win over a managed exact name.
  const covers = (e: string): boolean => servers.some((s) => (e.includes("*") ? globMatch(e, s.replace(/\*/g, ""), true) : false) || s.toLowerCase() === e.toLowerCase());
  const keep = mo.alwaysTaint === true ? [] : userExempt.filter((e) => !covered(e) && !covers(e));
  for (const e of userExempt) if (!keep.includes(e)) notes.push(`outsiderWritable.exempt ${e}: the managed policy keeps this server writable by outsiders, so the user policy's exemption is not applied`);
  config.outsiderWritable = { ...(config.outsiderWritable ?? {}), exempt: keep };
}

/**
 * The user's server entries under the managed file's (FM1). Lookup stays as `serverPolicy` does it (exact
 * name, else the first matching pattern in order), and the map is built so that lookup gives:
 *
 * - a user exact name: the managed entry for that name (exact, else first matching pattern), tightened by
 *   the user's entry;
 * - a user pattern: tightened by every managed pattern that may match the same servers. A managed `prefix*`
 *   pattern strictly inside a user `prefix*` pattern is instead emitted just before it (tightened by the
 *   user's pattern), so the user's pattern keeps its own settings for the servers the managed file does not
 *   cover;
 * - a managed exact name the user has no exact entry for: tightened by the user's matching pattern;
 * - the remaining managed entries as they are, after the user's (a server no user entry matches gets the
 *   managed entry, exactly as before).
 *
 * "Tightened" is `underManaged`: the managed entries are the base, the user's adds restrictions only.
 */
function mergeServersUnderManaged(user: Readonly<Record<string, McpServerPolicy>>, managed: Readonly<Record<string, McpServerPolicy>>, notes: string[]): Record<string, McpServerPolicy> {
  const out: Record<string, McpServerPolicy> = {};
  const mPatterns = Object.entries(managed).filter(([k]) => k.includes("*"));
  const put = (key: string, mine: McpServerPolicy, under: McpServerPolicy[], covered = true): void => {
    const merged = under.length === 0 ? mine : underManaged(under, mine, covered);
    if (under.length > 0 && loosens(mine, merged)) notes.push(`mcpServers.${key}: the managed policy covers this server; the user policy's loosening (trusted results, privateData false or readTools) is not applied`);
    setOwn(out, key, merged);
  };
  for (const [k, u] of Object.entries(user)) {
    if (!k.includes("*")) {
      const m = matchServerEntry(managed, k);
      put(k, u, m === undefined ? [] : [m]);
      continue;
    }
    const under: McpServerPolicy[] = [];
    // The managed readTools only loosen, so they are kept only when every managed pattern used covers
    // all the names this user pattern matches (the same pattern, or a broader prefix).
    let covered = true;
    for (const [mk, mp] of mPatterns) {
      if (mk !== k && !hasOwn(user, mk) && patternStrictlyInside(mk, k)) {
        if (!hasOwn(out, mk)) put(mk, u, mPatterns.filter(([ok]) => ok === mk || patternsMayOverlap(ok, mk)).map(([, op]) => op));
      } else if (mk === k || patternsMayOverlap(mk, k)) {
        under.push(mp);
        if (mk !== k && !patternStrictlyInside(k, mk)) covered = false;
      }
    }
    put(k, u, under, covered);
  }
  for (const [mk, mp] of Object.entries(managed)) {
    if (hasOwn(out, mk)) continue;
    const u = mk.includes("*") ? undefined : matchServerEntry(user, mk);
    setOwn(out, mk, u === undefined ? mp : underManaged([mp], u));
  }
  return out;
}

/**
 * The managed entries `under` with the user's entry merged over them tighten-only: tool lists are unions,
 * untrusted and private win, and `readTools` (which only loosens) is the managed file's, kept only when
 * every managed entry agrees on it and they cover every server the entry applies to (`covered`);
 * otherwise the verb-based classification applies.
 */
function underManaged(under: readonly McpServerPolicy[], mine: McpServerPolicy, covered = true): McpServerPolicy {
  let acc = under[0] as McpServerPolicy;
  for (const p of under.slice(1)) acc = stricterServer(acc, p);
  const reads = new Set(under.map((p) => JSON.stringify(p.readTools ?? null)));
  const out = stricterServer(acc, mine);
  if (!covered || reads.size > 1) delete out.readTools;
  return out;
}

/** Whether the user's entry asked for something looser than what applies. */
function loosens(mine: McpServerPolicy, merged: McpServerPolicy): boolean {
  return (mine.results === "trusted" && merged.results === "untrusted") || (!mine.privateData && merged.privateData) || (mine.readTools !== undefined && JSON.stringify(mine.readTools) !== JSON.stringify(merged.readTools));
}

/** Whether every name the `prefix*` pattern `inner` matches is matched by the `prefix*` pattern `outer`, and they differ. */
function patternStrictlyInside(inner: string, outer: string): boolean {
  const prefix = /^[^*?[\]{}]*\*$/;
  if (!prefix.test(inner) || !prefix.test(outer)) return false;
  const i = inner.slice(0, -1).toLowerCase();
  const o = outer.slice(0, -1).toLowerCase();
  return i !== o && i.startsWith(o);
}

/**
 * Applies a project's policy file. A repository is outside content, so its
 * policy may only tighten: add protected, secret and untrusted paths and
 * denied hosts, mark servers untrusted or blocked, switch strict modes on.
 * Anything that would loosen is ignored and reported.
 */
export function mergeTighten(base: FirewallConfig, over: PolicyDoc): { config: FirewallConfig; ignored: string[] } {
  const ignored: string[] = [];
  const cfg: FirewallConfig = { ...base, dataAllowHosts: { ...base.dataAllowHosts }, mcpServers: { ...base.mcpServers }, provenance: { ...base.provenance }, agentScan: { ...base.agentScan }, mcpPinning: { ...base.mcpPinning }, canaries: { ...base.canaries }, notifications: { ...base.notifications }, taskScope: { ...base.taskScope } };
  const union = (a: string[], b: string[] | undefined): string[] => [...new Set([...a, ...(b ?? [])])];
  cfg.denyHosts = union(base.denyHosts, over.denyHosts);
  cfg.protectedPaths = union(base.protectedPaths, over.protectedPaths);
  cfg.secretPaths = union(base.secretPaths, over.secretPaths);
  cfg.untrustedPaths = union(base.untrustedPaths, over.untrustedPaths);
  cfg.unattendedPermissionModes = union(base.unattendedPermissionModes, over.unattendedPermissionModes);
  // A project may protect more branches, never fewer.
  if (over.protectedBranches !== undefined) cfg.protectedBranches = union(base.protectedBranches ?? [], over.protectedBranches);
  if (over.untrustedWorkspace === true) cfg.untrustedWorkspace = true;
  if (over.redactSecretsInOutput === true) cfg.redactSecretsInOutput = true;
  if (over.unattended === true) cfg.unattended = true;
  if (over.allowInstructionWritesWhenTrusted === false) cfg.allowInstructionWritesWhenTrusted = false;
  if (over.allowTestValues === false) cfg.allowTestValues = false;
  if (over.unattendedHours !== undefined) cfg.unattendedHours = [...base.unattendedHours, ...over.unattendedHours];
  // v0.2 keys (the tighten direction of each is in docs/policy.md).
  cfg.notUserOutputTools = union(base.notUserOutputTools, over.notUserOutputTools);
  if (over.userOutputTools !== undefined && over.userOutputTools.length > 0) ignored.push("userOutputTools (a project cannot mark tools as only showing things to you)");
  const pv = over.provenance ?? {};
  if (pv.trustSelfAuthored === false) cfg.provenance.trustSelfAuthored = false;
  if (pv.trustSelfAuthored === true) ignored.push("provenance.trustSelfAuthored (a project may only turn it off)");
  if (pv.carryUntrustedWrites === true) cfg.provenance.carryUntrustedWrites = true;
  if (pv.carryUntrustedWrites === false) ignored.push("provenance.carryUntrustedWrites (a project may only turn it on)");
  if (pv.maxHashBytes !== undefined) {
    if (pv.maxHashBytes <= base.provenance.maxHashBytes) cfg.provenance.maxHashBytes = pv.maxHashBytes;
    else ignored.push("provenance.maxHashBytes (a project may only lower it)");
  }
  tightenAgentScanKeys(base, over, cfg, ignored);
  tightenCanaryKeys(over, cfg, ignored);
  tightenNotifyKeys(base, over, cfg, ignored);
  tightenPackageKeys(base, over, cfg, ignored);
  tightenSandboxKeys(base, over, cfg, ignored);
  tightenRunKeys(over, ignored);
  tightenPersistenceKeys(base, over, cfg, ignored);
  tightenBudgetKeys(base, over, cfg, ignored);
  tightenCapKeys(base, over, cfg, ignored);
  tightenScopeKeys(base, over, cfg, ignored);
  tightenVaultKeys(base, over, cfg, ignored);
  tightenGatewayKeys(base, over, cfg, ignored);
  tightenEmailKeys(base, over, cfg, ignored);
  tightenPhoneKeys(base, over, cfg, ignored);
  tightenRolloutKeys(over, cfg, ignored);
  tightenKnownHostsKeys(base, over, cfg, ignored);
  tightenLearnedKeys(base, over, cfg, ignored);
  tightenOutsiderKeys(base, over, cfg, ignored);
  for (const k of ["fetchAllowHosts", "sendAllowHosts", "trustedReadRoots"] as const) {
    if (over[k] !== undefined && over[k].length > 0) ignored.push(`${k} (a project cannot allow destinations or trusted paths)`);
  }
  if (over.dataAllowHosts !== undefined && Object.values(over.dataAllowHosts).some((l) => l.length > 0)) ignored.push("dataAllowHosts (a project cannot allow sending sensitive data)");
  if (over.untrustedWorkspace === false || over.redactSecretsInOutput === false || over.unattended === false || over.allowInstructionWritesWhenTrusted === true || over.allowTestValues === true) ignored.push("settings that switch protections off");
  if (over.mcpDefault !== undefined) {
    cfg.mcpDefault = stricterServer(base.mcpDefault, over.mcpDefault);
    if (over.mcpDefault.results === "trusted" || over.mcpDefault.readTools !== undefined || over.mcpDefault.privateData === false) ignored.push("mcpDefault loosening");
  }
  for (const [name, sp] of Object.entries(over.mcpServers ?? {})) {
    const existing = own(cfg.mcpServers, name);
    if (existing !== undefined) setOwn(cfg.mcpServers, name, stricterServer(existing, sp));
    else {
      // FB2: an exact name the earlier layers cover by a pattern starts from that pattern's entry (what
      // serverPolicy would have used), so naming the server never drops its blocked or send tools. A
      // server a project names is untrusted and private whatever the pattern says, as before.
      const inherited = name.includes("*") ? undefined : matchServerEntry(cfg.mcpServers, name);
      setOwn(cfg.mcpServers, name, stricterServer({ ...(inherited ?? {}), results: "untrusted", privateData: true }, sp));
    }
    // FB2: a project pattern also tightens every earlier entry it covers: the exact names it matches,
    // and the patterns that may match the same servers (an earlier pattern is found first).
    if (name.includes("*")) {
      for (const [k, p] of Object.entries(cfg.mcpServers)) {
        if (k === name) continue;
        if (k.includes("*") ? patternsMayOverlap(name, k) : globMatch(name, k, true)) setOwn(cfg.mcpServers, k, stricterServer(p, sp));
      }
    }
    if (sp.results === "trusted" || sp.readTools !== undefined || sp.privateData === false) ignored.push(`mcpServers.${name} loosening`);
  }
  return { config: cfg, ignored };
}

/**
 * Whether two server-name patterns may match a common name. Exact for the documented form (a prefix
 * ending in "*"); any other pair is assumed to overlap, which can only tighten more than needed.
 */
function patternsMayOverlap(a: string, b: string): boolean {
  const prefix = /^[^*?[\]{}]*\*$/;
  if (!prefix.test(a) || !prefix.test(b)) return true;
  const x = a.slice(0, -1).toLowerCase();
  const y = b.slice(0, -1).toLowerCase();
  return x.startsWith(y) || y.startsWith(x);
}

function stricterServer(a: McpServerPolicy, b: McpServerPolicy): McpServerPolicy {
  const union = (x?: string[], y?: string[]): string[] | undefined => (x === undefined && y === undefined ? undefined : [...new Set([...(x ?? []), ...(y ?? [])])]);
  const out: McpServerPolicy = { results: a.results === "untrusted" || b.results === "untrusted" ? "untrusted" : "trusted", privateData: a.privateData || b.privateData };
  const send = union(a.sendTools, b.sendTools);
  const destroy = union(a.destructiveTools, b.destructiveTools);
  const blocked = union(a.blockedTools, b.blockedTools);
  if (a.readTools !== undefined) out.readTools = a.readTools;
  if (send !== undefined) out.sendTools = send;
  if (destroy !== undefined) out.destructiveTools = destroy;
  if (blocked !== undefined) out.blockedTools = blocked;
  return out;
}

/** Whether a local time ("HH:MM") falls inside any configured unattended window (windows may cross midnight). */
export function inUnattendedHours(hours: readonly { from: string; to: string }[], now: Date): boolean {
  const minutes = now.getHours() * 60 + now.getMinutes();
  const toMin = (s: string): number => Number(s.slice(0, 2)) * 60 + Number(s.slice(3, 5));
  return hours.some(({ from, to }) => {
    const f = toMin(from);
    const t = toMin(to);
    return f <= t ? minutes >= f && minutes < t : minutes >= f || minutes < t;
  });
}
