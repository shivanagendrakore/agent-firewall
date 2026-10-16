/**
 * The package doctor checks: how fresh and intact the malicious-package snapshot
 * is, and whether the project's package managers refuse brand-new versions.
 * Check names are stable ("malicious-package data", "package cooldown") so the
 * doctor score can weight them.
 */

import { packageIntelPolicy } from "../engine/packages.js";
import type { FirewallConfig } from "../types.js";
import { cooldownStatus, type CooldownEnv } from "./cooldown.js";
import type { Check } from "./doctor.js";
import { inspectIntel } from "./intel.js";

/** After this many days doctor warns; past maxSnapshotAgeDays it fails (the data is still used). */
export const SNAPSHOT_WARN_DAYS = 7;

export function intelCheck(firewallHome: string, cfg: FirewallConfig, now: Date = new Date()): Check {
  const name = "malicious-package data";
  const i = inspectIntel(firewallHome, now);
  if (i.state === "none") return { name, status: "warn", detail: 'none yet: installs are not checked against known malicious packages. In your own terminal run "launchsafe-firewall update" (the firewall\'s only network use); typosquat checks work without it' };
  if (i.state === "damaged") return { name, status: "fail", detail: `intel damaged, run "launchsafe-firewall update": ${i.problems.slice(0, 3).join("; ")}` };
  const m = i.manifest;
  const age = i.ageDays ?? 0;
  const total = m?.sources.reduce((a, s) => a + s.entries, 0) ?? 0;
  const ecos = m?.sources.map((s) => s.eco).join(", ") ?? "";
  const max = packageIntelPolicy(cfg).maxSnapshotAgeDays;
  const summary = `${total} listed package name(s) across ${ecos}, fetched ${m?.fetchedAt.slice(0, 10) ?? "?"} (${age} day${age === 1 ? "" : "s"} ago)`;
  if (age > max) return { name, status: "fail", detail: `${summary}: older than packageIntel.maxSnapshotAgeDays (${max}); still used, but run "launchsafe-firewall update"` };
  if (age > SNAPSHOT_WARN_DAYS) return { name, status: "warn", detail: `${summary}: run "launchsafe-firewall update" weekly` };
  return { name, status: "ok", detail: summary };
}

export function cooldownCheck(projectDir: string, e: CooldownEnv): Check {
  const name = "package cooldown";
  const st = cooldownStatus(projectDir, e);
  if (st.length === 0) return { name, status: "ok", detail: "no package manager detected in this project" };
  const missing = st.filter((s) => s.state === "missing");
  const unavailable = st.filter((s) => s.state === "unavailable");
  const configured = st.filter((s) => s.state === "configured");
  const parts = [
    ...configured.map((s) => `${s.manager}: ${s.detail}`),
    ...missing.map((s) => `${s.manager}: ${s.detail} (doctor --fix can set 3 days in your user config)`),
    ...unavailable.map((s) => `${s.manager}: ${s.detail}`),
  ];
  if (missing.length === 0 && unavailable.length === 0) return { name, status: "ok", detail: parts.join("; ") };
  return { name, status: "warn", detail: `new package versions are installed as soon as they are published, before a malicious one can be found and pulled. ${parts.join("; ")}` };
}

export function packageChecks(firewallHome: string, projectDir: string, cfg: FirewallConfig, e: CooldownEnv, now: Date = new Date()): Check[] {
  return [intelCheck(firewallHome, cfg, now), cooldownCheck(projectDir, e)];
}
