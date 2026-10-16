/**
 * The email guard's policy key, kept apart from policy.ts so it stays one
 * module: `emailGuard`.
 *
 * | Key | Default | A project file may | User or managed only |
 * |---|---|---|---|
 * | enabled | true | set true | set false |
 * | readPath | "enforce" | move towards "enforce" | move towards "off" |
 * | mailbox | "log" | nothing (a repository must not move the person's mail) | any |
 * | servers | [] | add names | add names |
 * | pollSeconds | 15 | nothing | 5 to 600 |
 * | authservIds | [] | nothing (a repository must not declare trusted mail servers) | add |
 * | quarantineOn | all five | add | remove |
 */

import { QUARANTINE_REASONS, type QuarantineReason } from "./engine/content-scan.js";
import type { FirewallConfig } from "./types.js";

export const EMAIL_POLICY_KEYS = ["emailGuard"] as const;

export type GuardMode = "off" | "log" | "enforce";

export interface EmailGuardPolicy {
  enabled: boolean;
  /** The agent's read path (hooks today, the MCP gateway later): withhold and strip. */
  readPath: GuardMode;
  /** Local mailbox moves (not in this build); it starts in log mode. */
  mailbox: GuardMode;
  /** Extra MCP server names treated as mail (added to the built-in name match). */
  servers: string[];
  /** E2's Microsoft Graph delegated polling interval. */
  pollSeconds: number;
  /** Extra trusted Authentication-Results authserv-ids. */
  authservIds: string[];
  quarantineOn: QuarantineReason[];
}

export interface EmailDoc {
  emailGuard?: Partial<EmailGuardPolicy>;
}

export function defaultEmailGuard(): EmailGuardPolicy {
  return { enabled: true, readPath: "enforce", mailbox: "log", servers: [], pollSeconds: 15, authservIds: [], quarantineOn: [...QUARANTINE_REASONS] };
}

/** The email guard policy in effect (defaults for anything a policy file did not set). */
export function emailGuardPolicy(cfg: Pick<FirewallConfig, "emailGuard">): EmailGuardPolicy {
  const d = defaultEmailGuard();
  const e = cfg.emailGuard ?? {};
  return {
    enabled: e.enabled ?? d.enabled,
    readPath: e.readPath ?? d.readPath,
    mailbox: e.mailbox ?? d.mailbox,
    servers: e.servers ?? d.servers,
    pollSeconds: e.pollSeconds ?? d.pollSeconds,
    authservIds: e.authservIds ?? d.authservIds,
    quarantineOn: e.quarantineOn ?? d.quarantineOn,
  };
}

/** MCP servers whose names say they serve mail (the preset match), anywhere in the name. */
const MAIL_SERVER = /mail|imap|gmail|outlook|smtp|e-?mail/i;

/**
 * Mail words matched as whole words of the name (split at punctuation, digits-to-letters stay together,
 * and camelCase): `m365`, `o365`, `jmap`, `inbox`, `mailbox` (`mailbox` is also caught by `mail` above).
 */
const MAIL_WORDS: ReadonlySet<string> = new Set(["m365", "o365", "jmap", "inbox", "mailbox"]);

/**
 * `exchange` is a mail word only without a word that makes it a market: `exchange-rates`,
 * `crypto-exchange`, `stock-exchange-api` are not mail; `exchange`, `ms-exchange`, `exchange-online` are.
 */
const MARKET_WORDS: ReadonlySet<string> = new Set(["rate", "rates", "currency", "currencies", "fx", "forex", "crypto", "coin", "coins", "bitcoin", "stock", "stocks", "price", "prices", "market", "markets", "trade", "trading", "token", "tokens", "dex", "cex", "swap", "money"]);

/** The words of a server or tool name: split at anything but letters and digits, and at camelCase humps. */
export function nameWords(name: string): string[] {
  return name
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((w) => w !== "");
}

/** Whether a server or tool name says mail (without the policy's `servers` list). */
export function mailName(name: string): boolean {
  if (MAIL_SERVER.test(name)) return true;
  const words = nameWords(name);
  if (words.some((w) => MAIL_WORDS.has(w))) return true;
  return words.includes("exchange") && !words.some((w) => MARKET_WORDS.has(w));
}

/**
 * Whether the guard treats a server's results as mail: its name says mail, it is listed in
 * `emailGuard.servers`, or the tool's own name says mail (a server named for its vendor, such as
 * `microsoft` with an `outlook_list_messages` tool).
 */
export function isMailServer(server: string, policy: Pick<EmailGuardPolicy, "servers">, tool?: string): boolean {
  const name = server.replace(/^plugin_[^_]+_/, "");
  return mailName(name) || policy.servers.includes(server) || policy.servers.includes(name) || (tool !== undefined && tool !== "" && mailName(tool));
}

const KEYS = ["enabled", "readPath", "mailbox", "servers", "pollSeconds", "authservIds", "quarantineOn"] as const;
const MODES: readonly GuardMode[] = ["off", "log", "enforce"];
const RANK: Record<GuardMode, number> = { off: 0, log: 1, enforce: 2 };

type Raw = Record<string, unknown>;

const stringList = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string" && x.trim() !== "" && x.length <= 253);

/** Validates the key of a (migrated) policy document into `out`. */
export function validateEmailKeys(raw: Raw, problems: string[], out: EmailDoc): void {
  if (raw.emailGuard === undefined) return;
  const v = raw.emailGuard;
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    problems.push('"emailGuard" must be an object');
    return;
  }
  const o = v as Raw;
  const res: Partial<EmailGuardPolicy> = {};
  for (const k of Object.keys(o)) if (!(KEYS as readonly string[]).includes(k)) problems.push(`"emailGuard.${k}" is not a known setting (expected one of ${KEYS.join(", ")})`);
  if (o.enabled !== undefined) {
    if (typeof o.enabled === "boolean") res.enabled = o.enabled;
    else problems.push('"emailGuard.enabled" must be true or false');
  }
  for (const k of ["readPath", "mailbox"] as const) {
    if (o[k] === undefined) continue;
    if (typeof o[k] === "string" && (MODES as readonly string[]).includes(o[k])) res[k] = o[k] as GuardMode;
    else problems.push(`"emailGuard.${k}" must be one of ${MODES.join(", ")}`);
  }
  for (const k of ["servers", "authservIds"] as const) {
    if (o[k] === undefined) continue;
    if (stringList(o[k])) res[k] = [...new Set(o[k])];
    else problems.push(`"emailGuard.${k}" must be a list of names`);
  }
  if (o.pollSeconds !== undefined) {
    if (typeof o.pollSeconds === "number" && Number.isInteger(o.pollSeconds) && o.pollSeconds >= 5 && o.pollSeconds <= 600) res.pollSeconds = o.pollSeconds;
    else problems.push('"emailGuard.pollSeconds" must be a whole number of seconds from 5 to 600');
  }
  if (o.quarantineOn !== undefined) {
    if (Array.isArray(o.quarantineOn) && o.quarantineOn.every((x) => typeof x === "string" && (QUARANTINE_REASONS as readonly string[]).includes(x))) res.quarantineOn = [...new Set(o.quarantineOn as QuarantineReason[])];
    else problems.push(`"emailGuard.quarantineOn" must be a list of: ${QUARANTINE_REASONS.join(", ")}`);
  }
  out.emailGuard = res;
}

/** The user's (or an administrator's) `emailGuard` over the layer below: anything goes. */
export function mergeEmail(base: FirewallConfig["emailGuard"], over: EmailDoc["emailGuard"]): FirewallConfig["emailGuard"] {
  if (base === undefined && over === undefined) return undefined;
  return { ...(base ?? {}), ...(over ?? {}) };
}

/** Applies a project file's `emailGuard`: tightening only; anything looser is listed in `ignored`. */
export function tightenEmailKeys(base: FirewallConfig, over: EmailDoc, cfg: FirewallConfig, ignored: string[]): void {
  const e = over.emailGuard;
  if (e === undefined) return;
  const cur = emailGuardPolicy(base);
  const next: Partial<EmailGuardPolicy> = { ...(base.emailGuard ?? {}) };
  if (e.enabled === true) next.enabled = true;
  if (e.enabled === false) ignored.push("emailGuard.enabled (a repository must not switch off the email guard)");
  if (e.readPath !== undefined) {
    if (RANK[e.readPath] >= RANK[cur.readPath]) next.readPath = e.readPath;
    else ignored.push("emailGuard.readPath (a project may only move it towards enforce)");
  }
  if (e.mailbox !== undefined) ignored.push("emailGuard.mailbox (a repository must not move your mail)");
  if (e.servers !== undefined) next.servers = [...new Set([...cur.servers, ...e.servers])];
  if (e.pollSeconds !== undefined) ignored.push("emailGuard.pollSeconds (user or managed policy only)");
  if (e.authservIds !== undefined && e.authservIds.length > 0) ignored.push("emailGuard.authservIds (a repository must not declare trusted mail servers)");
  if (e.quarantineOn !== undefined) {
    next.quarantineOn = [...new Set([...cur.quarantineOn, ...e.quarantineOn])];
  }
  cfg.emailGuard = next;
}
