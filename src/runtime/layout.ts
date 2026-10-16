/**
 * Where the firewall keeps its files. One private directory per user
 * (~/.launchsafe-firewall, mode 700); the agent may never write inside it.
 */

import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function firewallHome(env: NodeJS.ProcessEnv = process.env): string {
  const override = env.LAUNCHSAFE_FIREWALL_HOME;
  return override !== undefined && override !== "" ? resolve(override) : join(homedir(), ".launchsafe-firewall");
}

/** The installed package root (two levels above this file in dist/runtime/). */
export function installDir(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
}

export interface Layout {
  home: string;
  policy: string;
  sessions: string;
  queue: string;
  log: string;
  keys: string;
  backups: string;
  locks: string;
  /** The kill switch's records (runtime/stops.ts). */
  stops: string;
}

export function layout(home = firewallHome()): Layout {
  return {
    home,
    policy: join(home, "policy.json"),
    sessions: join(home, "sessions"),
    queue: join(home, "queue"),
    log: join(home, "log"),
    keys: join(home, "keys"),
    backups: join(home, "backups"),
    locks: join(home, "locks"),
    stops: join(home, "stops"),
  };
}

/** A file-system-safe name for a session id that came from outside. */
export function safeId(id: string): string {
  return /^[A-Za-z0-9_-]{1,100}$/.test(id) ? id : `h-${createHash("sha256").update(id).digest("hex").slice(0, 32)}`;
}

export const MANAGED_POLICY_PATHS: Record<string, string> = {
  darwin: "/Library/Application Support/LaunchSafeFirewall/policy.json",
  linux: "/etc/launchsafe-firewall/policy.json",
};

export const PROJECT_POLICY_FILE = ".launchsafe-firewall.json";
