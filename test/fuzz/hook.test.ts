/**
 * Fuzz: the hook pipeline for each adapter (Claude Code, Codex, Gemini CLI, Cursor), through runHook() as the
 * CLI calls it. Properties: never throws and always prints a valid decision (exit 0 with JSON or nothing, or
 * exit 2 with a reason); fails closed (unreadable input blocks; a dangerous command is never allowed however
 * much noise surrounds it, and a pre-tool event whose command is missing or the wrong type is never allowed);
 * bounded time; deterministic.
 */
import { afterAll, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { verdictFor } from "../../src/agent-replay.js";
import { runHook, type HookEnv } from "../../src/hook/claude.js";
import { layout, type Layout } from "../../src/runtime/layout.js";
import { AGENT_IDS, type AgentId, type HookIO } from "../../src/adapters/types.js";
import { testRoot } from "../helpers.js";
import { DANGEROUS_SHELL, fixtureEvents } from "./corpus.js";
import { allowLongRuns, noStarRuns, budget, corruptText, firstDiff, fuzz, iters, mutateJsonN, mutateStringN, timed, type Json } from "./gen.js";

allowLongRuns();

const HOOK_BUDGET_MS = budget(2000);
/** Seconds each hook target may run in the default configuration: every decision writes state files, so a slow disk bounds it. */
const HOOK_CAP_S = 5;

interface Env {
  root: string;
  ws: string;
  home: string;
  l: Layout;
  h: (agent: AgentId) => HookEnv;
}

/** A throwaway firewall home and workspace. */
function newEnv(): Env {
  const root = realpathSync(mkdtempSync(join(testRoot(), "lsfw-fuzz-")));
  const home = join(root, "home");
  const ws = join(home, "proj");
  mkdirSync(ws, { recursive: true });
  const l = layout(join(home, ".launchsafe-firewall"));
  return { root, home, ws, l, h: (agent) => ({ env: agent === "claude" ? { CLAUDE_PROJECT_DIR: ws } : {}, layout: l, agent, home, scratchRoots: [join(root, "scratch")], detectNonInteractive: () => false, notifyDeps: { spawn: () => undefined } }) };
}

const envs: Env[] = [];
function fresh(): Env {
  const e = newEnv();
  envs.push(e);
  return e;
}
afterAll(() => {
  for (const e of envs) rmSync(e.root, { recursive: true, force: true });
});

/** One environment per agent, replaced every 100 iterations (a long queue and session directory slow every decision). */
function envFor(i: number, pool: Map<string, Env>, key: string): Env {
  const k = `${key}:${Math.floor(i / 100)}`;
  let e = pool.get(k);
  if (e === undefined) {
    for (const [old, env] of pool) if (old.startsWith(`${key}:`)) {
      rmSync(env.root, { recursive: true, force: true });
      pool.delete(old);
    }
    e = fresh();
    pool.set(k, e);
  }
  return e;
}

// --- seeds ---------------------------------------------------------------------------------------------

const PREFIX: Record<AgentId, string> = { claude: "claude", codex: "codex-", gemini: "gemini-", cursor: "cursor-" };

/** The agent's own fixtures: every event kind it sends, as captured. */
function seedsFor(agent: AgentId): Json[] {
  const out = fixtureEvents(PREFIX[agent]).map((f) => f.event as Json);
  // Claude Code's non-pre-tool shapes are small enough to write out; the fixtures only hold the MCP ones.
  if (agent === "claude") {
    out.push(
      { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "npm test" }, session_id: "s", cwd: "/work" },
      { hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: { url: "https://example.com" }, tool_response: "text", session_id: "s", cwd: "/work" },
      { hook_event_name: "UserPromptSubmit", prompt: "fix the failing test in src/a.ts", session_id: "s", cwd: "/work" },
      { hook_event_name: "SessionStart", source: "startup", session_id: "s", cwd: "/work" },
      { hook_event_name: "ConfigChange", source: "user_settings", session_id: "s", cwd: "/work" },
      { hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: "/work/a.ts", content: "x" }, session_id: "s", cwd: "/work" },
    );
  }
  return out;
}

/** Where a shell command sits in the agent's pre-tool event, and the event to start from. */
const SHELL_SEED: Record<AgentId, Json> = {
  claude: { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "" }, session_id: "s", cwd: "/work", permission_mode: "default" },
  codex: { session_id: "s", turn_id: "t", cwd: "/work", hook_event_name: "PreToolUse", model: "m", permission_mode: "default", tool_name: "Bash", tool_input: { command: "" }, tool_use_id: "c1" },
  gemini: { session_id: "s", cwd: "/work", hook_event_name: "BeforeTool", timestamp: "2026-10-10T16:27:54.368Z", tool_name: "run_shell_command", tool_input: { command: "", description: "d", dir_path: "." } },
  cursor: { conversation_id: "c0ffee", generation_id: "g", model: "default", tool_name: "Shell", tool_input: { command: "", cwd: "/work" }, tool_use_id: "t", cwd: "/work", session_id: "c0ffee", hook_event_name: "preToolUse", workspace_roots: ["/work"] },
};

function shellEvent(agent: AgentId, command: string, session: string): Json {
  const e = structuredClone(SHELL_SEED[agent]);
  (e.tool_input as Json).command = command;
  e.session_id = session;
  if (agent === "cursor") e.conversation_id = session;
  return e;
}

/** The paths a "noise" mutation must leave alone: what makes the event this event. */
const RELEVANT = new Set(["hook_event_name", "tool_name", "tool_input"]);
const protectedPath = (p: readonly (string | number)[]): boolean => p.length === 0 || (p.length === 1 && RELEVANT.has(p[0] as string)) || (p.length === 2 && p[0] === "tool_input" && p[1] === "command");

// --- checks --------------------------------------------------------------------------------------------

function describeIo(io: HookIO): string {
  return `exit=${io.exitCode} stdout=${JSON.stringify(io.stdout.slice(0, 200))} stderr=${JSON.stringify(io.stderr.slice(0, 200))}`;
}

const VERDICTS = new Set(["allow", "ask", "queue", "deny"]);

/** The decision an output means, or throws why it is not a valid one. Exit 2 is a block. */
function decisionOf(agent: AgentId, io: HookIO): string {
  if (typeof io.stdout !== "string" || typeof io.stderr !== "string" || !Number.isInteger(io.exitCode)) throw new Error(`malformed result ${describeIo(io)}`);
  if (io.exitCode !== 0 && io.exitCode !== 2) throw new Error(`exit code ${io.exitCode} is neither 0 nor 2 ${describeIo(io)}`);
  if (io.exitCode === 2) {
    if (io.stderr.trim() === "" && io.stdout.trim() === "") throw new Error(`a block with no reason ${describeIo(io)}`);
    return "deny";
  }
  if (io.stdout.trim() !== "") {
    try {
      JSON.parse(io.stdout);
    } catch {
      throw new Error(`exit 0 with stdout that is not JSON ${describeIo(io)}`);
    }
  }
  const v = verdictFor(agent, io).verdict;
  if (!VERDICTS.has(v)) throw new Error(`no decision in the output ${describeIo(io)}`);
  return v;
}

function run(agent: AgentId, e: Env, raw: string): { io: HookIO; ms: number } {
  const { value, ms } = timed(() => runHook(raw, e.h(agent)), HOOK_BUDGET_MS);
  return { io: value, ms };
}

function show(raw: string): string {
  return raw.length > 300 ? `${JSON.stringify(raw.slice(0, 300))}...(${raw.length} chars)` : JSON.stringify(raw);
}

/** JSON text without the star runs of FZ11 (a hung decision cannot be interrupted by a time budget). */
const stringify = (v: unknown): string => noStarRuns(JSON.stringify(v) ?? "null");

// --- tests ---------------------------------------------------------------------------------------------

describe("fuzz: hook pipeline", () => {
  it("the dangerous seeds are blocked by every adapter to begin with", () => {
    const e = fresh();
    for (const agent of AGENT_IDS) {
      for (const c of DANGEROUS_SHELL) {
        const io = runHook(stringify(shellEvent(agent, c, `base-${agent}`)), e.h(agent));
        expect(decisionOf(agent, io), `${agent}: ${c} ${describeIo(io)}`).not.toBe("allow");
      }
    }
  });

  for (const agent of AGENT_IDS) {
    describe(agent, () => {
      const seeds = seedsFor(agent);
      const pool = new Map<string, Env>();

      it("never throws, always prints a valid decision, within the time budget; unreadable input blocks", () => {
        let i = 0;
        fuzz(`hook:${agent}:robust`, iters(10), (r, seed) => {
          const e = envFor(i++, pool, "robust");
          const base = structuredClone(r.pick(seeds));
          base.session_id = `fz${seed}`;
          let raw: string;
          let parsesAsObject = true;
          switch (r.int(10)) {
            case 0:
            case 1:
              raw = corruptText(r, stringify(base));
              break;
            case 2:
              raw = mutateStringN(r, r.pick(["", "{}", "[]", "null", "garbage", stringify(base)]), 4);
              break;
            default:
              raw = stringify(mutateJsonN(r, base, 4));
          }
          try {
            const v: unknown = JSON.parse(raw);
            parsesAsObject = typeof v === "object" && v !== null && !Array.isArray(v);
          } catch {
            parsesAsObject = false;
          }
          let result: { io: HookIO; ms: number };
          try {
            result = run(agent, e, raw);
          } catch (err) {
            throw new Error(`threw ${(err as Error).message.slice(0, 120)}: ${show(raw)}`, { cause: err });
          }
          if (result.ms > HOOK_BUDGET_MS) throw new Error(`slow (${Math.round(result.ms)} ms > ${HOOK_BUDGET_MS}): ${show(raw)}`);
          let d: string;
          try {
            d = decisionOf(agent, result.io);
          } catch (err) {
            throw new Error(`${(err as Error).message}: ${show(raw)}`, { cause: err });
          }
          if (!parsesAsObject && (result.io.exitCode !== 2 || result.io.stdout !== "")) throw new Error(`unreadable input did not block (${d}) ${describeIo(result.io)}: ${show(raw)}`);
        }, { capSec: HOOK_CAP_S });
      });

      it("a dangerous command is never allowed, whatever else the event carries", () => {
        let i = 0;
        fuzz(`hook:${agent}:dangerous-noise`, iters(10), (r, seed) => {
          const e = envFor(i++, pool, "noise");
          const command = r.pick(DANGEROUS_SHELL);
          const ev = mutateJsonN(r, shellEvent(agent, command, `fz${seed}`), 3, protectedPath);
          const raw = stringify(ev);
          const { io, ms } = run(agent, e, raw);
          if (ms > HOOK_BUDGET_MS) throw new Error(`slow (${Math.round(ms)} ms): ${show(raw)}`);
          const d = decisionOf(agent, io);
          if (d === "allow") throw new Error(`allowed ${JSON.stringify(command)} ${describeIo(io)}: ${show(raw)}`);
        }, { capSec: HOOK_CAP_S });
      });

      it("a shell call whose command is missing or not a string is never allowed", () => {
        let i = 0;
        fuzz(`hook:${agent}:bad-command`, iters(10), (r, seed) => {
          const e = envFor(i++, pool, "badcmd");
          const ev = shellEvent(agent, "echo hi", `fz${seed}`);
          const bad = r.pick<unknown>([undefined, null, 0, 1, true, [], ["rm", "-rf", "~"], {}, { command: "rm -rf ~" }, [{ a: 1 }]]);
          const input = ev.tool_input as Json;
          if (bad === undefined) delete input.command;
          else input.command = bad;
          const raw = stringify(ev);
          const { io } = run(agent, e, raw);
          const d = decisionOf(agent, io);
          if (d === "allow") throw new Error(`allowed a shell call with command=${stringify(bad)} ${describeIo(io)}: ${show(raw)}`);
        }, { capSec: HOOK_CAP_S });
      });

      it("is deterministic: the same event gets the same decision", () => {
        let i = 0;
        fuzz(`hook:${agent}:deterministic`, iters(20), (r, seed) => {
          const a = envFor(i, pool, "detA");
          const b = envFor(i++, pool, "detB");
          const base = r.bool() ? structuredClone(r.pick(seeds)) : shellEvent(agent, mutateStringN(r, r.pick(DANGEROUS_SHELL), 3), "x");
          base.session_id = `fz${seed}`;
          const raw = stringify(mutateJsonN(r, base, 2));
          const d1 = run(agent, a, raw).io;
          const d2 = run(agent, b, raw).io;
          const roots = [a.root, b.root];
          const norm = (io: HookIO): string => `${io.exitCode}|${decisionOf(agent, io)}|${verdictFor(agent, io).reason.split(roots[0] as string).join("ROOT").split(roots[1] as string).join("ROOT").replace(/queue approve [a-z0-9]+/g, "queue approve ID").replace(/allow (add|never|remove) [a-z0-9]+/g, "allow $1 ID").replace(/\b[a-z0-9]{8}\b/g, "ID")}`;
          if (norm(d1) !== norm(d2)) throw new Error(`not deterministic (${firstDiff(norm(d1), norm(d2))}): ${show(raw)}`);
        }, { capSec: HOOK_CAP_S });
      });
    });
  }

  it("the hook entry point is not reachable by prototype-pollution keys", () => {
    const e = fresh();
    for (const agent of AGENT_IDS) {
      const io = runHook('{"__proto__":{"hook_event_name":"x"},"constructor":{"prototype":{"tool_name":"Bash"}},"hook_event_name":"PreToolUse"}', e.h(agent));
      decisionOf(agent, io);
      expect(({} as Record<string, unknown>).tool_name).toBeUndefined();
    }
  });
});

