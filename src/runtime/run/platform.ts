/**
 * v0.3 `run`: which operating-system sandbox this machine has, and whether it
 * works here. macOS: /usr/bin/sandbox-exec. Linux: bubblewrap, only from a
 * root-owned system directory (never found through PATH, which an agent may
 * be able to write; the rule notify.ts uses for notify-send). Each is probed
 * with a trivial command, so a nested sandbox or disabled user namespaces are
 * reported before a run, with the tool's own error.
 */

import { spawnSync } from "node:child_process";
import { isTrustedSystemFile } from "../notify.js";

export type RunPlatform = { kind: "seatbelt"; path: string; detail: string } | { kind: "bwrap"; path: string; detail: string } | { kind: "none"; reason: string; hint: string };

export const SANDBOX_EXEC = "/usr/bin/sandbox-exec";
export const BWRAP_CANDIDATES: readonly string[] = ["/usr/bin/bwrap", "/usr/local/bin/bwrap", "/bin/bwrap"];

export interface DetectDeps {
  platform?: NodeJS.Platform;
  /** Root-owned, not writable by others (tests inject). */
  trusted?: (path: string) => boolean;
  /** Runs the probe; returns the exit status and standard error. */
  probe?: (path: string, args: readonly string[]) => { status: number | null; stderr: string };
}

function realProbe(path: string, args: readonly string[]): { status: number | null; stderr: string } {
  const r = spawnSync(path, args, { encoding: "utf8", timeout: 5000, stdio: ["ignore", "ignore", "pipe"] });
  return { status: r.status, stderr: (r.stderr ?? (r.error?.message ?? "")).trim() };
}

const firstLine = (s: string): string => s.split("\n").find((x) => x.trim() !== "")?.trim().slice(0, 200) ?? "";

export function detectRunPlatform(d: DetectDeps = {}): RunPlatform {
  const platform = d.platform ?? process.platform;
  const trusted = d.trusted ?? isTrustedSystemFile;
  const probe = d.probe ?? realProbe;
  if (platform === "darwin") {
    if (!trusted(SANDBOX_EXEC)) return { kind: "none", reason: `${SANDBOX_EXEC} is missing or not a root-owned system file`, hint: "run needs macOS's built-in sandbox-exec; it ships with every macOS release" };
    const r = probe(SANDBOX_EXEC, ["-p", "(version 1)(allow default)", "/usr/bin/true"]);
    if (r.status !== 0) {
      const err = firstLine(r.stderr);
      return { kind: "none", reason: `sandbox-exec cannot apply a profile here${err !== "" ? ` (${err})` : ""}`, hint: /Operation not permitted|sandbox_apply/i.test(err) ? "this process is already inside a sandbox (an agent's or an app's); start run from your own terminal" : "check that sandbox-exec works: sandbox-exec -p '(version 1)(allow default)' /usr/bin/true" };
    }
    return { kind: "seatbelt", path: SANDBOX_EXEC, detail: "macOS sandbox-exec (Seatbelt)" };
  }
  if (platform === "linux") {
    const path = BWRAP_CANDIDATES.find((p) => trusted(p));
    if (path === undefined) return { kind: "none", reason: "bubblewrap (bwrap) is not installed in /usr/bin, /usr/local/bin or /bin as a root-owned file", hint: "install it with your package manager (apt install bubblewrap, dnf install bubblewrap, pacman -S bubblewrap)" };
    const r = probe(path, ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-net", "--unshare-pid", "--die-with-parent", "--new-session", "/bin/true"]);
    if (r.status !== 0) {
      const err = firstLine(r.stderr);
      return { kind: "none", reason: `bubblewrap cannot create a sandbox here${err !== "" ? ` (${err})` : ""}`, hint: "bubblewrap needs unprivileged user namespaces: on Ubuntu 24.04 and later the AppArmor setting kernel.apparmor_restrict_unprivileged_userns blocks them unless bwrap has a profile; in a container the maintainers ran it with seccomp and systempaths unconfined (see docs/run.md)" };
    }
    return { kind: "bwrap", path, detail: `bubblewrap (${path})` };
  }
  return { kind: "none", reason: `${platform} has no sandbox run supports`, hint: "run supports macOS (sandbox-exec) and Linux (bubblewrap)" };
}

/** Whether `run` would refuse a sandbox here, for doctor (no process is started beyond the probe). */
export function runReadiness(detect: () => RunPlatform = () => detectRunPlatform()): { ok: boolean; detail: string } {
  const sb = detect();
  if (sb.kind === "none") return { ok: false, detail: `launchsafe-firewall run cannot sandbox agents here: ${sb.reason}. ${sb.hint}` };
  return { ok: true, detail: `${sb.detail} works: "launchsafe-firewall run -- <agent>" limits an agent's writes to the workspace and routes an agent's network through a proxy that admits only your policy's hosts (docs/run.md, Limits)` };
}

