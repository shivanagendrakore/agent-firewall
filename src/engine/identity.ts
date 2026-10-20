/**
 * F-c: the firewall's own identity, as the engine sees it. Self-protection is keyed to what is
 * actually installed (the CLI file a registered hook command runs, its package's dist/ and
 * node_modules/, the node binary, the data directory), never to what a file or folder is called.
 * Pure: the identity is built by the runtime (src/runtime/identity.ts) and passed in the Context.
 */

import type { Context, FirewallIdentity } from "../types.js";
import { PROTECTION_FOLDS_CASE, withCanonical } from "./canonical.js";

/** The CLI's documented command name. A bare word with this name is always the CLI (fail closed). */
export const FIREWALL_BIN = "launchsafe-firewall";
/** The package's registry name: the identity of the code when run through npx/dlx/bunx/npm exec. */
export const FIREWALL_PACKAGE_NAME = "@launchsafe/agent-firewall";

/** The service the vault's values are stored under in the macOS Keychain and the Secret Service. */
export const FIREWALL_VAULT_SERVICE = "launchsafe-firewall";

/** The firewall's managed config locations (all platforms). */
export const FIREWALL_MANAGED_DIRS: readonly string[] = ["/Library/Application Support/LaunchSafeFirewall", "/etc/launchsafe-firewall"];

function trimSlash(p: string): string {
  if (p.length <= 1) return p;
  // A loop, not /\/+$/, whose retries are quadratic on a long run of slashes mid-string.
  let end = p.length;
  while (end > 0 && p.charCodeAt(end - 1) === 47) end--;
  return p.slice(0, end);
}

/**
 * The identity used when none was built (tests, the engine used as a library): the deprecated
 * install directory narrowed to what runs (dist/, node_modules/, package.json).
 */
export function fallbackIdentity(installDir: string, dataRoots: readonly string[] = []): FirewallIdentity {
  const d = trimSlash(installDir);
  const has = d !== "";
  return {
    cliFiles: has ? [`${d}/dist/cli.js`] : [],
    runtimeRoots: has ? [`${d}/dist`, `${d}/node_modules`] : [],
    runtimeFiles: has ? [`${d}/package.json`] : [],
    packageRoots: has ? [d] : [],
    nodeBinaries: [],
    dataRoots: [...dataRoots],
    binNames: [FIREWALL_BIN],
    source: "fallback-install-dir",
  };
}

const cache = new WeakMap<Context, FirewallIdentity>();

/** The identity for a context, with the data roots the context always implies added. Cached per context. */
export function identityOf(ctx: Context): FirewallIdentity {
  const hit = cache.get(ctx);
  if (hit !== undefined) return hit;
  const base = ctx.identity ?? fallbackIdentity(ctx.firewallInstallDir);
  // SELF-016: every location in both forms, as recorded and canonical, so an alias of either matches.
  const both = (xs: readonly string[]): string[] => [...new Set(withCanonical(xs.filter((d) => d !== "").map(trimSlash), ctx))];
  const dataRoots = both([...base.dataRoots, ctx.firewallHome, `${ctx.home}/.launchsafe-firewall`, ...FIREWALL_MANAGED_DIRS]);
  const binNames = [...new Set([FIREWALL_BIN, ...base.binNames])];
  const vaultServices = [...new Set([FIREWALL_VAULT_SERVICE, ...(base.vaultServices ?? [])])];
  const id: FirewallIdentity = {
    ...base,
    cliFiles: both(base.cliFiles),
    runtimeRoots: both(base.runtimeRoots),
    runtimeFiles: both(base.runtimeFiles),
    packageRoots: both(base.packageRoots),
    nodeBinaries: both(base.nodeBinaries),
    dataRoots,
    binNames,
    vaultServices,
  };
  cache.set(ctx, id);
  return id;
}

function under(path: string, root: string, ci: boolean): boolean {
  const a = ci ? path.toLowerCase() : path;
  const r = trimSlash(ci ? root.toLowerCase() : root);
  if (r === "" || r === "/") return false;
  return a === r || a.startsWith(`${r}/`);
}

function same(a: string, b: string, ci: boolean): boolean {
  return ci ? a.toLowerCase() === b.toLowerCase() : a === b;
}

export type FirewallPart = "data" | "runtime" | "cli" | "node";

/**
 * Which part of the installed firewall an absolute, normalized path is, or null for an ordinary file. `ci` folds
 * case: PROTECTION_FOLDS_CASE (I1) for every check that refuses or asks; the checks that grant trust because a path
 * is the firewall's (classifyAsSpelled in paths.ts, a read-only command of the CLI in shell/analyze.ts) pass the
 * platform's rule.
 */
export function firewallPart(abs: string, ctx: Context, ci: boolean = PROTECTION_FOLDS_CASE): FirewallPart | null {
  const id = identityOf(ctx);
  if (id.dataRoots.some((r) => under(abs, r, ci))) return "data";
  if (id.cliFiles.some((f) => same(abs, f, ci))) return "cli";
  if (id.runtimeRoots.some((r) => under(abs, r, ci)) || id.runtimeFiles.some((f) => same(abs, f, ci))) return "runtime";
  if (id.nodeBinaries.some((f) => same(abs, f, ci))) return "node";
  return null;
}

/**
 * I2: what a path inside the firewall's data directory holds. "key": the signing and approval keys, the relay device
 * key (keys/), the vault (vault/) and any log-*.pem: never read by an agent. "data": anything else there (the log,
 * the queue, session state, policy): a read asks, as a credential store's does. Null outside it. `ci` as for firewallPart.
 */
export function firewallDataKind(abs: string, ctx: Context, ci: boolean = PROTECTION_FOLDS_CASE): "key" | "data" | null {
  const root = identityOf(ctx).dataRoots.find((r) => under(abs, r, ci));
  if (root === undefined) return null;
  const rel = abs.slice(trimSlash(root).length + 1);
  const r = ci ? rel.toLowerCase() : rel;
  if (/^(?:keys|vault)(?:\/|$)/.test(r) || /(?:^|\/)log-[^/]*\.pem$/.test(r) || /(?:^|\/)relay-device\.json$/.test(r)) return "key";
  return "data";
}

/**
 * Whether an absolute path is inside one of the installed firewall's package roots (a build there rewrites
 * the runtime). The caller passes each form of the path (as written, canonical): SELF-016.
 */
export function inPackageRoot(abs: string, ctx: Context): string | null {
  const ci = PROTECTION_FOLDS_CASE;
  return identityOf(ctx).packageRoots.find((r) => under(abs, r, ci)) ?? null;
}

/** A bare word that names the CLI: its documented name (optionally with a version, as npx accepts) or a known alias. */
export function isBinName(word: string, ctx: Context): boolean {
  if (/^launchsafe-firewall(?:\.js)?(?:@[\w.^~<>=*-]+)?$/.test(word)) return true;
  return identityOf(ctx).binNames.includes(word);
}

/** The package's registry identity, with an optional version, or as a --package/-p value. */
export function isPackageIdentity(word: string): boolean {
  return /^(?:--package=|-p=)?@launchsafe\/agent-firewall(?:@[\w.^~<>=*-]+)?$/.test(word);
}
