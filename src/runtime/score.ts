/**
 * The protection score. Each check that matters for protection has
 * a weight; the score is the points earned over the weights of the checks
 * that apply on this machine, out of 100. It is informational: exit codes
 * still come from fail statuses only.
 */

import type { Check } from "./doctor.js";
import { HOOK_BYPASS_CHECKS } from "./hook-bypass.js";

/** Weights for checks other modules own, by stable check name. The sandbox checks carry their own. */
const WEIGHTS: readonly { match: (c: Check) => boolean; weight: number; points: (c: Check) => number; applies?: (c: Check) => boolean }[] = [
  { match: (c) => c.name === "approval passphrase", weight: 10, points: (c) => (c.status === "ok" ? 10 : /set, but not pinned/.test(c.detail) ? 5 : 0) },
  { match: (c) => c.name === "managed settings", weight: 10, points: (c) => (c.status === "ok" ? 10 : 0) },
  { match: (c) => c.name === "package cooldown", weight: 5, points: (c) => (c.status === "ok" ? 5 : 0), applies: (c) => !/^no package manager detected/.test(c.detail) },
  { match: (c) => c.name === "malicious-package data", weight: 5, points: (c) => (c.status === "ok" ? 5 : 0) },
  { match: (c) => c.name === "canary files" || c.name === "canary registry", weight: 5, points: (c) => (c.status === "ok" ? 5 : 0) },
  { match: (c) => c.name === "decision log", weight: 5, points: (c) => (c.status === "ok" ? 5 : 0) },
];

const HOOKS_WEIGHT = 25;

/**
 * Attaches weight and points to the checks (one entry per scored item), adds a zero-point entry for
 * decoys when none are planted (and canaries are on), and appends the "protection score" entry.
 */
export function withScore(checks: Check[], o: { canariesEnabled: boolean }): Check[] {
  const out = checks.map((c) => ({ ...c }));
  // Hooks: one item, full points only when every hooks check is ok.
  // Every agent's hooks checks count ("hooks (user)" for Claude Code, "Codex hooks (user)", ...), and a hook command
  // whose node is gone blocks everything.
  const hooks = out.filter((c) => c.name === "hooks" || /^(?:[A-Za-z ]+ )?hooks(?: \(|$)/.test(c.name) || c.name === "hook node");
  if (hooks.length > 0) {
    const first = hooks[0] as Check;
    first.weight = HOOKS_WEIGHT;
    // A setting that switches the hooks off (or reaches into them) is worth as much as hooks that are missing.
    first.points = hooks.every((c) => c.status === "ok") && !out.some((c) => HOOK_BYPASS_CHECKS.has(c.name) && c.status === "fail") ? HOOKS_WEIGHT : 0;
  }
  const scored = new Set<number>();
  for (const w of WEIGHTS) {
    const i = out.findIndex((c, k) => !scored.has(k) && w.match(c));
    if (i === -1) continue;
    const c = out[i] as Check;
    scored.add(i);
    if (c.weight !== undefined || (w.applies !== undefined && !w.applies(c))) continue;
    c.weight = w.weight;
    c.points = w.points(c);
  }
  if (o.canariesEnabled && !out.some((c) => c.name === "canary files" || c.name === "canary registry")) {
    out.push({ name: "canary files", status: "ok", detail: 'none planted (optional): "launchsafe-firewall canary plant" puts decoy credentials in the workspace; an agent that reads one raises an alert', weight: 5, points: 0 });
  }
  const weight = out.reduce((a, c) => a + (c.weight ?? 0), 0);
  const points = out.reduce((a, c) => a + (c.points ?? 0), 0);
  const score = weight === 0 ? 0 : Math.round((points / weight) * 100);
  out.push({ name: "protection score", status: "ok", detail: `${score}/100 (${points} of ${weight} points from the checks that apply on this machine)`, score });
  return out;
}

/** The text block doctor prints under the checks: the score and each check's contribution. */
export function scoreLines(checks: readonly Check[]): string[] {
  const total = checks.find((c) => c.name === "protection score");
  const rows = checks.filter((c) => c.weight !== undefined);
  const width = Math.max(...rows.map((c) => c.name.length), 10);
  return [`Setup score: ${total?.score ?? 0}/100 (how many of the firewall's recommended settings are in place; not a measure of safety)`, ...rows.map((c) => `  ${c.name.padEnd(width)}  ${String(c.points ?? 0).padStart(2)}/${String(c.weight).padEnd(2)}${(c.points ?? 0) < (c.weight ?? 0) ? `  ${firstSentence(c.detail)}` : ""}`)];
}

function firstSentence(s: string): string {
  const cut = s.split(/(?<=[.:;])\s/)[0] ?? s;
  return cut.length > 110 ? `${cut.slice(0, 107)}...` : cut;
}
