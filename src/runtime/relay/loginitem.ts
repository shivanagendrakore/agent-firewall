/**
 * The relay daemon as a login item: a launchd agent on
 * macOS, a systemd user unit on Linux, written by `phone pair` (unless
 * --no-login-item) and removed by `phone remove` when the last phone goes.
 * The service names contain "launchsafe-firewall", so an agent that tries to
 * stop or unload it is caught by the firewall's own tamper rule.
 *
 * Every command goes through an injected runner, so tests check the files
 * and the commands without touching launchd or systemd.
 */

import { existsSync, unlinkSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { atomicWrite, ensureDir } from "../fsutil.js";
import { assertNotRealHome } from "../guard.js";
import { firewallHome, installDir, type Layout } from "../layout.js";

export const LAUNCHD_LABEL = "com.launchsafe-firewall.relay";
export const SYSTEMD_UNIT = "launchsafe-firewall-relay.service";

export type Runner = (cmd: string, args: readonly string[]) => { status: number; stderr: string };

export interface LoginItemDeps {
  platform: NodeJS.Platform;
  home?: string;
  run: Runner;
  uid?: number;
  nodePath?: string;
  cli?: string;
}

export function loginItemPath(platform: NodeJS.Platform, home = homedir()): string | null {
  if (platform === "darwin") return join(home, "Library", "LaunchAgents", `${LAUNCHD_LABEL}.plist`);
  if (platform === "linux") return join(home, ".config", "systemd", "user", SYSTEMD_UNIT);
  return null;
}

function xml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function homeEnv(l: Layout): Record<string, string> {
  return l.home === firewallHome({}) ? {} : { LAUNCHSAFE_FIREWALL_HOME: l.home };
}

export function launchdPlist(l: Layout, nodePath: string, cli: string): string {
  const env = homeEnv(l);
  const envXml = Object.keys(env).length === 0 ? "" : `  <key>EnvironmentVariables</key>\n  <dict>\n${Object.entries(env).map(([k, v]) => `    <key>${xml(k)}</key>\n    <string>${xml(v)}</string>`).join("\n")}\n  </dict>\n`;
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${xml(nodePath)}</string>
    <string>${xml(cli)}</string>
    <string>relay</string>
    <string>run</string>
  </array>
${envXml}  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>30</integer>
  <key>StandardErrorPath</key>
  <string>${xml(join(l.home, "relay", "daemon.log"))}</string>
</dict>
</plist>
`;
}

function sdQuote(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export function systemdUnit(l: Layout, nodePath: string, cli: string): string {
  const env = Object.entries(homeEnv(l)).map(([k, v]) => `Environment=${sdQuote(`${k}=${v}`)}\n`).join("");
  return `[Unit]
Description=LaunchSafe Firewall phone relay (sealed queue items out, signed phone decisions in)

[Service]
ExecStart=${sdQuote(nodePath)} ${sdQuote(cli)} relay run
${env}Restart=always
RestartSec=30

[Install]
WantedBy=default.target
`;
}

export interface LoginItemResult {
  path: string | null;
  ok: boolean;
  detail: string;
}

/** Writes and starts the login item. A failure is reported, never thrown: pairing itself already succeeded. */
export function installLoginItem(l: Layout, d: LoginItemDeps): LoginItemResult {
  const path = loginItemPath(d.platform, d.home);
  if (path === null) return { path, ok: false, detail: `no login item on ${d.platform}; run "launchsafe-firewall relay run" yourself` };
  assertNotRealHome(path);
  const nodePath = d.nodePath ?? process.execPath;
  const cli = d.cli ?? join(installDir(), "dist", "cli.js");
  ensureDir(dirname(path));
  if (d.platform === "darwin") {
    atomicWrite(path, launchdPlist(l, nodePath, cli), 0o644);
    const domain = `gui/${d.uid ?? userInfo().uid}`;
    d.run("launchctl", ["bootout", `${domain}/${LAUNCHD_LABEL}`]);
    const r = d.run("launchctl", ["bootstrap", domain, path]);
    return r.status === 0 ? { path, ok: true, detail: `launchd agent ${LAUNCHD_LABEL} started` } : { path, ok: false, detail: `launchctl bootstrap failed (${r.stderr.trim().slice(0, 200)}); run "launchsafe-firewall relay run" yourself` };
  }
  atomicWrite(path, systemdUnit(l, nodePath, cli), 0o644);
  d.run("systemctl", ["--user", "daemon-reload"]);
  const r = d.run("systemctl", ["--user", "enable", "--now", SYSTEMD_UNIT]);
  return r.status === 0 ? { path, ok: true, detail: `systemd user unit ${SYSTEMD_UNIT} enabled` } : { path, ok: false, detail: `systemctl --user enable failed (${r.stderr.trim().slice(0, 200)}); run "launchsafe-firewall relay run" yourself` };
}

export function removeLoginItem(d: LoginItemDeps): LoginItemResult {
  const path = loginItemPath(d.platform, d.home);
  if (path === null || !existsSync(path)) return { path, ok: true, detail: "no login item was installed" };
  assertNotRealHome(path);
  if (d.platform === "darwin") d.run("launchctl", ["bootout", `gui/${d.uid ?? userInfo().uid}/${LAUNCHD_LABEL}`]);
  else d.run("systemctl", ["--user", "disable", "--now", SYSTEMD_UNIT]);
  try {
    unlinkSync(path);
  } catch {
    // Gone already.
  }
  return { path, ok: true, detail: "login item removed" };
}

export function loginItemInstalled(platform: NodeJS.Platform, home = homedir()): boolean {
  const p = loginItemPath(platform, home);
  return p !== null && existsSync(p);
}
