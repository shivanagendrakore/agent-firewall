/**
 * End-to-end hook latency: what one tool call really costs. Each sample spawns the installed hook
 * command (the exact `sh -c` line `install` writes: node start, module loading, the hook, durable
 * writes) with the event on stdin, per adapter, in an untrusted session with remembered secrets.
 * The in-process numbers in bench.mjs measure a warm runHook and leave out node start and imports.
 *
 * Budget, on a quiet machine: p95 < 120 ms, p99 < 200 ms per adapter.
 *
 *   node scripts/bench-e2e.mjs [--dist DIR] [--n N] [--json]
 *
 * --dist runs another build (for before/after comparisons). Temp homes only; no network.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, realpathSync } from "node:fs";
import { tmpdir, loadavg } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const E2E_BUDGET = { p95: 120, p99: 200 };

const patch = "*** Begin Patch\n*** Add File: src/new.ts\n+export const n = 1;\n*** Update File: src/index.ts\n@@\n-export const a = 1;\n+export const a = 2;\n*** Add File: docs/notes.md\n+notes\n*** End Patch\n";
const secrets = "AWS_SECRET_ACCESS_KEY=AKIA1A2B3C4D5E6F7G8H\n".repeat(20);

/** Per adapter: the event that makes the session untrusted, and the PreToolUse-shaped call measured. */
const ADAPTERS = {
  claude: {
    taint: (sid, ws) => ({ hook_event_name: "PostToolUse", session_id: sid, cwd: ws, tool_name: "WebFetch", tool_input: { url: "https://x.example.com" }, tool_response: secrets }),
    call: (sid, ws) => ({ hook_event_name: "PreToolUse", session_id: sid, cwd: ws, permission_mode: "default", tool_name: "Bash", tool_input: { command: "git status && git diff --staged | head -100" } }),
  },
  codex: {
    taint: (sid, ws) => ({ hook_event_name: "PostToolUse", session_id: sid, cwd: ws, tool_name: "Bash", tool_input: { command: "curl -sS https://x.example.com" }, tool_response: secrets }),
    call: (sid, ws) => ({ hook_event_name: "PreToolUse", session_id: sid, cwd: ws, permission_mode: "default", tool_name: "apply_patch", tool_input: { command: patch } }),
  },
  gemini: {
    taint: (sid, ws) => ({ hook_event_name: "AfterTool", session_id: sid, cwd: ws, tool_name: "web_fetch", tool_input: { prompt: "read https://x.example.com" }, tool_response: { llmContent: secrets } }),
    call: (sid, ws) => ({ hook_event_name: "BeforeTool", session_id: sid, cwd: ws, tool_name: "run_shell_command", tool_input: { command: "git status && git diff --staged | head -100", dir_path: "." } }),
  },
};

function pct(sorted, p) {
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}

/** Runs the end-to-end bench against the build in `dist`; returns per-adapter percentiles (ms). */
export async function benchE2E({ dist = fileURLToPath(new URL("../dist", import.meta.url)), n = 60, warm = 5 } = {}) {
  dist = resolve(dist);
  const { hookCommand } = await import(pathToFileURL(join(dist, "runtime", "install.js")).href);
  const { layout } = await import(pathToFileURL(join(dist, "runtime", "layout.js")).href);
  const root = realpathSync(mkdtempSync(join(tmpdir(), "lsfw-bench-e2e-")));
  const results = {};
  try {
    for (const [agent, ev] of Object.entries(ADAPTERS)) {
      const home = join(root, agent), ws = join(home, "proj");
      mkdirSync(ws, { recursive: true });
      const l = layout(join(home, ".launchsafe-firewall"));
      const cmd = hookCommand(l, process.execPath, join(dist, "cli.js"), agent);
      // HOME is the temp home and the test marker is set: nothing can reach the real home.
      const env = { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: home, TMPDIR: tmpdir(), LAUNCHSAFE_FIREWALL_TEST: "1", CLAUDE_PROJECT_DIR: ws, GEMINI_PROJECT_DIR: ws };
      const send = (obj) => {
        const t0 = process.hrtime.bigint();
        const r = spawnSync("/bin/sh", ["-c", cmd], { input: JSON.stringify(obj), env, cwd: ws, encoding: "utf8" });
        const ms = Number(process.hrtime.bigint() - t0) / 1e6;
        if (r.status !== 0) throw new Error(`${agent} hook exited ${r.status}: ${r.stderr}`);
        return ms;
      };
      const samples = [];
      for (let i = 0; i < n + warm; i++) {
        // A fresh session every 20 calls keeps state at a realistic size.
        const sid = `${agent}-${i - (i % 20)}`;
        if (i % 20 === 0) send(ev.taint(sid, ws));
        const ms = send(ev.call(sid, ws));
        if (i >= warm) samples.push(ms);
      }
      samples.sort((a, b) => a - b);
      results[agent] = { n: samples.length, p50: pct(samples, 50), p95: pct(samples, 95), p99: pct(samples, 99), min: samples[0], max: samples[samples.length - 1] };
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  return results;
}

export function e2eWithinBudget(results) {
  return Object.values(results).every((r) => r.p95 < E2E_BUDGET.p95 && r.p99 < E2E_BUDGET.p99);
}

export function formatE2E(results) {
  const f = (x) => x.toFixed(1).padStart(6);
  const lines = [`End to end, one hook process per call (the installed sh -c command; ${Object.values(results)[0]?.n ?? 0} calls per adapter):`];
  for (const [agent, r] of Object.entries(results)) lines.push(`  ${agent.padEnd(7)} p50 ${f(r.p50)} ms   p95 ${f(r.p95)} ms   p99 ${f(r.p99)} ms   min ${f(r.min)} ms   max ${f(r.max)} ms`);
  lines.push(e2eWithinBudget(results) ? `  end to end within budget (p95 < ${E2E_BUDGET.p95} ms, p99 < ${E2E_BUDGET.p99} ms)` : "  END TO END OVER BUDGET");
  return lines.join("\n");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const args = process.argv.slice(2);
  const arg = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
  const before = loadavg().map((x) => x.toFixed(2)).join(" ");
  const res = await benchE2E({ ...(arg("--dist") ? { dist: arg("--dist") } : {}), ...(arg("--n") ? { n: Number(arg("--n")) } : {}) });
  const after = loadavg().map((x) => x.toFixed(2)).join(" ");
  if (args.includes("--json")) console.log(JSON.stringify({ load: [before, after], results: res }));
  else console.log(`${formatE2E(res)}\n  load ${before} / ${after}`);
  process.exitCode = e2eWithinBudget(res) ? 0 : 1;
}
