/**
 * Installs the browser link (docs/browser-link.md): a native messaging host manifest in one browser's
 * per-user NativeMessagingHosts directory, allowed for the LaunchSafe extension's id only, naming a small
 * launcher script inside the firewall's own directory. Never a system-wide location, never the registry.
 *
 * A record of every manifest written (install record: <home>/native-host/installs.json) lets uninstall remove
 * exactly what install added, lets doctor check it, and gives the host the origins it may answer (Chrome
 * checks allowed_origins; the host checks again).
 */

import { createHash } from "node:crypto";
import { lstatSync, readFileSync, statSync, unlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { atomicWrite, readText } from "../fsutil.js";
import { installDir, type Layout } from "../layout.js";
import { assertNotRealHome } from "../guard.js";
import { approverPublicKey } from "../approver.js";
import { CLEAR_COMPILE_CACHE, CLEAR_LOADER_ENV } from "../install.js";
import { HOST_NAME, isExtensionId } from "./protocol.js";

export const BROWSERS = ["chrome", "chromium", "edge", "brave"] as const;
export type Browser = (typeof BROWSERS)[number];

const LABELS: Record<Browser, string> = { chrome: "Google Chrome", chromium: "Chromium", edge: "Microsoft Edge", brave: "Brave" };

/** Each browser's per-user directory for host manifests (its default profile's user data directory + NativeMessagingHosts). */
const USER_DIRS: Record<"darwin" | "linux", Record<Browser, readonly string[]>> = {
  darwin: {
    chrome: ["Library", "Application Support", "Google", "Chrome"],
    chromium: ["Library", "Application Support", "Chromium"],
    edge: ["Library", "Application Support", "Microsoft Edge"],
    brave: ["Library", "Application Support", "BraveSoftware", "Brave-Browser"],
  },
  linux: {
    chrome: [".config", "google-chrome"],
    chromium: [".config", "chromium"],
    edge: [".config", "microsoft-edge"],
    brave: [".config", "BraveSoftware", "Brave-Browser"],
  },
};

export function browserLabel(b: Browser): string {
  return LABELS[b];
}

/**
 * Where a browser looks for this host's manifest. `userDataDir` (a browser started with --user-data-dir)
 * takes the place of the browser's default directory: Chromium reads <user data dir>/NativeMessagingHosts.
 */
export function hostManifestDir(browser: Browser, o: { home?: string; platform?: NodeJS.Platform; userDataDir?: string } = {}): string {
  if (o.userDataDir !== undefined) return join(resolve(o.userDataDir), "NativeMessagingHosts");
  const platform = o.platform ?? process.platform;
  if (platform !== "darwin" && platform !== "linux") throw new Error(`the browser link supports macOS and Linux only (this is ${platform})`);
  return join(o.home ?? homedir(), ...USER_DIRS[platform][browser], "NativeMessagingHosts");
}

export function hostManifestPath(dir: string): string {
  return join(dir, `${HOST_NAME}.json`);
}

/** The launcher Chrome runs: inside the firewall's own directory (mode 700), which agents may not write. */
export function launcherPath(l: Layout): string {
  return join(l.home, "native-host", "launchsafe-firewall-native-host");
}

function recordPath(l: Layout): string {
  return join(l.home, "native-host", "installs.json");
}

export interface HostInstall {
  browser: Browser;
  manifest: string;
  extensionIds: string[];
  /** sha256 of the manifest as written, so doctor and uninstall can tell an edited file. */
  sha256: string;
  installedAt: string;
}

function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

function shq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Every recorded install. A damaged record reads as an error, never as "nothing installed". */
export function readHostInstalls(l: Layout): HostInstall[] {
  const t = readText(recordPath(l));
  if (t === null) return [];
  const v = JSON.parse(t) as unknown;
  if (!Array.isArray(v) || !v.every(isInstall)) throw new Error(`${recordPath(l)} is damaged`);
  return v;
}

function isInstall(x: unknown): x is HostInstall {
  if (typeof x !== "object" || x === null) return false;
  const r = x as Record<string, unknown>;
  return (BROWSERS as readonly unknown[]).includes(r.browser) && typeof r.manifest === "string" && Array.isArray(r.extensionIds) && r.extensionIds.every((i) => typeof i === "string" && isExtensionId(i)) && typeof r.sha256 === "string" && typeof r.installedAt === "string";
}

/** The origins the host answers: every extension id an install allowed. */
export function allowedOrigins(l: Layout): string[] {
  return [...new Set(readHostInstalls(l).flatMap((r) => r.extensionIds.map((id) => `chrome-extension://${id}/`)))];
}

/**
 * The launcher: the data directory and the approval key are pinned in it, as in the hook command, so the
 * host trusts the approval key that was on disk at install and Chrome's environment cannot move the home.
 * NODE_COMPILE_CACHE and the loader variables are cleared for the same reason as the hook's (install.ts CLEAR_COMPILE_CACHE, CLEAR_LOADER_ENV).
 */
export function launcherScript(l: Layout, nodePath = process.execPath, cli = join(installDir(), "dist", "cli.js")): string {
  let approver = "";
  try {
    const pub = approverPublicKey(l);
    if (pub !== null) approver = `LAUNCHSAFE_FIREWALL_APPROVER=${shq(pub)} `;
  } catch {
    // A damaged approver file: no pin, so the host offers no approvals; doctor reports the file.
  }
  return [
    "#!/bin/sh",
    "# Written by `launchsafe-firewall install --browser`: the LaunchSafe browser extension's link to the firewall.",
    "# The browser starts this with the extension's origin as its argument. Remove it with `launchsafe-firewall uninstall --browser`.",
    `LAUNCHSAFE_FIREWALL_HOME=${shq(l.home)} ${approver}${CLEAR_COMPILE_CACHE}${CLEAR_LOADER_ENV}exec ${shq(nodePath)} ${shq(cli)} native-host "$@"`,
    "",
  ].join("\n");
}

export function hostManifest(launcher: string, extensionIds: readonly string[]): string {
  return `${JSON.stringify({ name: HOST_NAME, description: "LaunchSafe Agent Firewall: the browser extension's link to the local firewall", path: launcher, type: "stdio", allowed_origins: extensionIds.map((id) => `chrome-extension://${id}/`) }, null, 2)}\n`;
}

export interface InstallHostResult {
  manifest: string;
  launcher: string;
  changed: boolean;
}

/**
 * Writes the launcher and one browser's host manifest, and records them. Refuses an extension id that is
 * not 32 letters a to p, and (under a test marker) any path in the real home directory.
 */
export function installHost(l: Layout, browser: Browser, extensionIds: readonly string[], o: { home?: string; platform?: NodeJS.Platform; userDataDir?: string; nodePath?: string; cli?: string } = {}): InstallHostResult {
  if (extensionIds.length === 0) throw new Error("the browser link needs the extension's id (--extension-id): copy it from the browser's extensions page (32 letters)");
  for (const id of extensionIds) if (!isExtensionId(id)) throw new Error(`"${id.slice(0, 64)}" is not an extension id (32 letters from a to p)`);
  const dir = hostManifestDir(browser, o);
  const manifest = hostManifestPath(dir);
  const launcher = launcherPath(l);
  assertNotRealHome(manifest);
  assertNotRealHome(l.home);
  // A manifest some other program put under this name is not overwritten silently.
  const existing = readText(manifest);
  const records = readHostInstalls(l);
  const mine = records.find((r) => r.manifest === manifest);
  if (existing !== null && (mine === undefined || sha256(existing) !== mine.sha256) && !isOurManifest(existing, launcher)) throw new Error(`${manifest} exists and was not written by this firewall; move it away first`);
  const script = launcherScript(l, o.nodePath, o.cli);
  const scriptChanged = readText(launcher) !== script;
  if (scriptChanged) atomicWrite(launcher, script, 0o700);
  const ids = [...new Set(extensionIds)].sort();
  const text = hostManifest(launcher, ids);
  const changed = existing !== text;
  if (changed) atomicWrite(manifest, text, 0o644);
  const next = [...records.filter((r) => r.manifest !== manifest), { browser, manifest, extensionIds: ids, sha256: sha256(text), installedAt: mine !== undefined && !changed ? mine.installedAt : new Date().toISOString() }];
  atomicWrite(recordPath(l), `${JSON.stringify(next, null, 2)}\n`);
  return { manifest, launcher, changed: changed || scriptChanged };
}

/** Whether a manifest is this host's, pointing at this firewall's launcher. */
function isOurManifest(text: string, launcher: string): boolean {
  try {
    const m = JSON.parse(text) as Record<string, unknown>;
    return m.name === HOST_NAME && m.path === launcher;
  } catch {
    return false;
  }
}

export interface UninstallHostResult {
  manifest: string;
  action: "removed" | "left-edited" | "already-gone";
}

/** Removes the recorded manifests for one browser (or every browser), and the launcher once none is left. */
export function uninstallHost(l: Layout, browser?: Browser): UninstallHostResult[] {
  assertNotRealHome(l.home);
  const records = readHostInstalls(l);
  const out: UninstallHostResult[] = [];
  const keep: HostInstall[] = [];
  for (const r of records) {
    if (browser !== undefined && r.browser !== browser) {
      keep.push(r);
      continue;
    }
    assertNotRealHome(r.manifest);
    const text = readText(r.manifest);
    if (text === null) out.push({ manifest: r.manifest, action: "already-gone" });
    else if (sha256(text) !== r.sha256 && !isOurManifest(text, launcherPath(l))) out.push({ manifest: r.manifest, action: "left-edited" });
    else {
      unlinkSync(r.manifest);
      out.push({ manifest: r.manifest, action: "removed" });
    }
  }
  atomicWrite(recordPath(l), `${JSON.stringify(keep, null, 2)}\n`);
  if (keep.length === 0 && readText(launcherPath(l)) !== null) unlinkSync(launcherPath(l));
  return out;
}

export interface LinkCheck {
  name: string;
  status: "ok" | "warn" | "fail";
  detail: string;
}

/** doctor: each recorded manifest is in place, unedited, allowed for its ids only, and its launcher runs this firewall. */
export function browserLinkChecks(l: Layout): LinkCheck[] {
  let records: HostInstall[];
  try {
    records = readHostInstalls(l);
  } catch (e) {
    return [{ name: "browser link", status: "fail", detail: (e as Error).message }];
  }
  if (records.length === 0) return [{ name: "browser link", status: "ok", detail: "not set up (optional): launchsafe-firewall install --browser chrome --extension-id ID" }];
  const launcher = launcherPath(l);
  const out: LinkCheck[] = [];
  let launcherProblem: string | null = null;
  const st = lstatSync(launcher, { throwIfNoEntry: false });
  if (st === undefined) launcherProblem = `${launcher} is missing: run launchsafe-firewall install --browser again`;
  else if (!st.isFile() || st.isSymbolicLink()) launcherProblem = `${launcher} is not a regular file`;
  else if ((st.mode & 0o100) === 0) launcherProblem = `${launcher} is not executable`;
  else if ((st.mode & 0o022) !== 0) launcherProblem = `${launcher} can be changed by other users`;
  else {
    const text = readFileSync(launcher, "utf8");
    const node = /exec '((?:[^']|'\\'')*)' /.exec(text)?.[1]?.replace(/'\\''/g, "'");
    if (node === undefined || statSync(node, { throwIfNoEntry: false }) === undefined) launcherProblem = `${launcher} names a node binary that no longer exists: run launchsafe-firewall install --browser again`;
  }
  for (const r of records) {
    const name = `browser link (${r.browser})`;
    const text = readText(r.manifest);
    if (text === null) {
      out.push({ name, status: "fail", detail: `${r.manifest} is missing: run launchsafe-firewall install --browser ${r.browser} --extension-id ${r.extensionIds[0] ?? "ID"}` });
      continue;
    }
    let m: Record<string, unknown> = {};
    try {
      m = JSON.parse(text) as Record<string, unknown>;
    } catch {
      out.push({ name, status: "fail", detail: `${r.manifest} is not valid JSON` });
      continue;
    }
    const origins = Array.isArray(m.allowed_origins) ? m.allowed_origins : [];
    const expected = r.extensionIds.map((id) => `chrome-extension://${id}/`);
    if (m.name !== HOST_NAME || m.type !== "stdio" || m.path !== launcher) out.push({ name, status: "fail", detail: `${r.manifest} does not run this firewall's launcher (${launcher})` });
    else if (origins.length !== expected.length || !expected.every((o) => origins.includes(o))) out.push({ name, status: "fail", detail: `${r.manifest} allows other extensions than the one installed (${expected.join(", ")})` });
    else if (launcherProblem !== null) out.push({ name, status: "fail", detail: launcherProblem });
    else out.push({ name, status: "ok", detail: `${r.manifest}: allowed for ${r.extensionIds.join(", ")} only` });
  }
  return out;
}
