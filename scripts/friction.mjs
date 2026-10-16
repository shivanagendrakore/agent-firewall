/**
 * Friction report: how often the firewall would interrupt normal work. Runs
 * every known-good case trusted and untrusted; a normal task that is not
 * allowed is a regression. Release gate. Build first: npm run friction.
 */
import { decide } from "../dist/engine/decide.js";
import { emptyState, foldEvents } from "../dist/engine/state.js";
import { defaultConfig } from "../dist/policy.js";
import { ALWAYS_FINE, TRUSTED_ONLY, TOOL_CASES, V02_FINE, PACKAGES_FINE } from "../dist/corpus.js";
import { frictionRows, runRow } from "../dist/catalogue.js";
import { applyDecision, budgetView, emptyCounters } from "../dist/runtime/counters.js";
import { applyCapRecord, emptyCapCounts, emptyDaily, warningShown } from "../dist/engine/caps.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const HOME = "/Users/dev", WS = "/Users/dev/proj";
const ctx = { cwd: WS, workspaceRoots: [WS], home: HOME, scratchRoots: ["/tmp", "/private/tmp"], firewallHome: HOME + "/.launchsafe-firewall", firewallInstallDir: "/opt/lsfw", interactive: true, caseInsensitive: true };
const cfg = defaultConfig();
const tainted = foldEvents([{ type: "taint", source: "read a web page" }]);
const fill = (v) => (typeof v === "string" ? v.replaceAll("{WS}", WS) : typeof v === "object" && v ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x)])) : v);
const v = (tool, input, state) => decide({ action: { tool, input }, state, config: cfg, ctx }).verdict;

const rows = [];
for (const c of ALWAYS_FINE) rows.push({ g: "always", c, t: v("Bash", { command: c }, emptyState()), u: v("Bash", { command: c }, tainted) });
for (const c of TRUSTED_ONLY) rows.push({ g: "trusted-only", c, t: v("Bash", { command: c }, emptyState()), u: v("Bash", { command: c }, tainted) });
for (const c of TOOL_CASES) rows.push({ g: "tool", c: c.tool, t: v(c.tool, fill(c.input), emptyState()), u: v(c.tool, fill(c.input), tainted) });

for (const c of V02_FINE) rows.push({ g: "v02", c, t: v("Bash", { command: c }, emptyState()), u: v("Bash", { command: c }, tainted) });
// R16: widely used packages are not typosquats (installing is ordinary work in a trusted session; untrusted asks by design).
const pkgRows = [...PACKAGES_FINE.npm.map((n) => `npm install ${n}`), ...PACKAGES_FINE.PyPI.map((n) => `pip install ${n}`)].map((c) => ({ g: "pkg", c, t: v("Bash", { command: c }, emptyState()), u: "allow" }));
const g = (n) => rows.filter((r) => r.g === n);
const ok = (rs, k) => rs.filter((r) => r[k] === "allow").length;
const pct = (n, d) => `${((100 * n) / d).toFixed(1)}%`;
const always = g("always"), tools = g("tool"), to = g("trusted-only");
const L = [];
L.push("LaunchSafe Firewall - friction report\n");
L.push(`Normal tasks that must never interrupt (${always.length} shell + ${tools.length} tool = ${always.length + tools.length}):`);
L.push(`  trusted session:   ${ok(always, "t") + ok(tools, "t")}/${always.length + tools.length} allowed (${pct(ok(always, "t") + ok(tools, "t"), always.length + tools.length)})`);
L.push(`  untrusted session: ${ok(always, "u") + ok(tools, "u")}/${always.length + tools.length} allowed (${pct(ok(always, "u") + ok(tools, "u"), always.length + tools.length)})`);
L.push("");
L.push(`Network / install / deploy (${to.length}) - meant to need a person once untrusted:`);
L.push(`  trusted: ${ok(to, "t")}/${to.length} allowed    untrusted: ${ok(to, "u")}/${to.length} allowed, ${to.length - ok(to, "u")} ask/queue by design`);
L.push("");
const v02 = g("v02");
L.push(`v0.2 false-positive cases (${v02.length}): trusted ${ok(v02, "t")}/${v02.length}, untrusted ${ok(v02, "u")}/${v02.length} allowed`);
L.push("");
L.push(`Widely used packages installed in a trusted session (${pkgRows.length}): ${pkgRows.filter((r) => r.t === "allow").length}/${pkgRows.length} allowed`);
L.push("");
const bad = [...always, ...tools, ...v02, ...pkgRows].filter((r) => r.t !== "allow" || r.u !== "allow");
if (bad.length === 0) L.push("No normal task is interrupted, trusted or untrusted.");
else { L.push("UNEXPECTED interruptions:"); for (const r of bad) L.push(`  ${r.c}  (trusted ${r.t}, untrusted ${r.u})`); }

// The same normal work as one long session with budgets and spending limits on at their defaults:
// every normal task five times over, two seconds apart, trusted and then untrusted, with the counters
// kept in memory (one day's spending-limit counters shared by both sessions, as on one machine).
const budgetBad = [];
const daily = emptyDaily(new Date(2026, 9, 10, 9, 0, 0));
for (const [label, st] of [["trusted", emptyState()], ["untrusted", tainted]]) {
  const counters = emptyCounters();
  let clock = Date.UTC(2026, 9, 10, 9, 0, 0);
  const work = [...ALWAYS_FINE.map((c) => ["Bash", { command: c }]), ...TOOL_CASES.map((c) => [c.tool, fill(c.input)]), ...V02_FINE.map((c) => ["Bash", { command: c }])];
  for (let pass = 0; pass < 5; pass++) {
    for (const [tool, input] of work) {
      const now = new Date((clock += 2000));
      const d = decide({ action: { tool, input }, state: st, config: cfg, ctx, budgets: budgetView(counters, false, st, now), caps: { sessionId: label, session: counters.caps ?? emptyCapCounts(), day: daily, raise: () => 0 } });
      applyDecision(counters, d, now);
      if (d.caps !== undefined) applyCapRecord(daily, d.caps, d.verdict === "allow" || d.verdict === "ask", warningShown(d.rules), "day");
      if (d.verdict === "allow" && d.rules.some((r) => r.startsWith("FW-CAP"))) budgetBad.push({ c: `${tool} ${JSON.stringify(input).slice(0, 80)} (${label}, pass ${pass + 1}: spending limit ${d.verdict} ${d.rules.join(",")})` });
      if (d.verdict !== "allow") budgetBad.push({ c: `${tool} ${JSON.stringify(input).slice(0, 80)} (${label}, pass ${pass + 1}: ${d.verdict} ${d.rules.join(",")})` });
    }
  }
}
L.push("");
L.push(budgetBad.length === 0 ? "Budgets and spending limits at their defaults over a long session (every normal task 5 times, trusted and untrusted): no interruption." : "UNEXPECTED budget interruptions:");
for (const r of budgetBad.slice(0, 20)) L.push(`  ${r.c}`);
bad.push(...budgetBad);

// v0.2 scenario catalogue: every runnable row whose expected decision is "allow", through the real hook
// in a throwaway tree (its own home, workspace and scratch; the real home is never read or written).
const parent = mkdtempSync(join(tmpdir(), "lsfw-friction-"));
const cat = frictionRows().map(({ row, state }) => ({ row, state, run: runRow(row, state, { parent }) }));
rmSync(parent, { recursive: true, force: true });
const catBad = cat.filter((x) => x.run.steps.some((s) => s.verdict !== "allow"));
L.push("");
L.push(`Scenario catalogue rows expected to be allowed (${cat.length} row-states): ${cat.length - catBad.length}/${cat.length} allowed`);
for (const x of catBad) L.push(`  INTERRUPTED ${x.row.id} [${x.state}] ${x.row.task}: ${x.run.steps.map((s) => s.verdict).join(", ")}`);
bad.push(...catBad);
console.log(L.join("\n"));
process.exit(bad.length === 0 ? 0 : 1);
