/**
 * Runs the scenario catalogue (src/catalogue-scenarios.ts) through the real
 * hook, as Claude Code would send the events, in a throwaway directory tree
 * that has its own home, workspace, sibling folder and scratch directory. The
 * runner never reads or writes the real home: the home directory and scratch
 * roots are injected into the hook's context.
 */

import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CATALOGUE, type CatalogueRow, type CatStep, type Expectation, type RowState } from "./catalogue-scenarios.js";
import { asAgentEvent, expectedFor, verdictFor } from "./agent-replay.js";
import { adapterFor } from "./adapters/index.js";
import { runHook, trustedApproverKey, type HookEnv } from "./hook/claude.js";
import { approvalSigner, initApprover, unlockApprover } from "./runtime/approver.js";
import { plantCanaries } from "./runtime/canaries.js";
import { intelDir, writeEcosystem } from "./runtime/intel.js";
import { ecoDir, type Ecosystem, type IntelEntry } from "./engine/packages.js";
import { install } from "./runtime/install.js";
import { applySandboxFix, planSandboxFix } from "./runtime/sandbox.js";
import { defaultConfig, POLICY_VERSION } from "./policy.js";
import { layout, type Layout } from "./runtime/layout.js";
import { tailLog } from "./runtime/log.js";
import { decideQueueItem, listQueue, loadState } from "./runtime/store.js";
import { atomicWrite } from "./runtime/fsutil.js";
import { PROJECT_POLICY_FILE } from "./runtime/layout.js";
import type { Verdict } from "./types.js";
import { VERSION } from "./version.js";

/**
 * The feature and gap tags that are built. A row tagged with one not listed here is reported as
 * todo; each tag is added when its feature lands.
 */
export const BUILT_ITEMS: ReadonlySet<string> = new Set<string>(["F-a", "3", "7", "F-f", "F-b", "F-c", "F-d", "F-e", "G1", "G2", "G3", "G4", "G5", "G6", "10", "9", "4", "1", "5", "6", "2", "8"]);

export function runnable(row: Pick<CatalogueRow, "item" | "skip">): boolean {
  return row.skip === undefined && (row.item === undefined || BUILT_ITEMS.has(row.item));
}

// --- synthetic data values (shapes the detectors recognise; not real credentials or people) ---------

function luhnComplete(prefix: string): string {
  for (let d = 0; d <= 9; d++) {
    const s = prefix + d;
    let sum = 0;
    for (let i = 0; i < s.length; i++) {
      let n = Number(s[s.length - 1 - i]);
      if (i % 2 === 1) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
    }
    if (sum % 10 === 0) return s;
  }
  return `${prefix}0`;
}

function ibanComplete(country: string, bban: string): string {
  const moved = `${bban}${country}00`;
  let rem = 0;
  for (const ch of moved) {
    const v = ch >= "A" && ch <= "Z" ? String(ch.charCodeAt(0) - 55) : ch;
    for (const d of v) rem = (rem * 10 + Number(d)) % 97;
  }
  return `${country}${String(98 - rem).padStart(2, "0")}${bban}`;
}

const VD = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1], [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]];
const VP = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1], [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]];
const VINV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

function verhoeffComplete(digits: string): string {
  let c = 0;
  const rev = `${digits}0`.split("").reverse();
  for (let i = 1; i < rev.length; i++) c = (VD[c] as number[])[(VP[i % 8] as number[])[Number(rev[i])] as number] as number;
  return `${digits}${VINV[c]}`;
}

// The fake secrets are assembled at load from parts, so the compiled file holds no complete secret-shaped
// literal for a third-party secret scanner to flag in the published package. The values are unchanged.
const assemble = (...parts: string[]): string => parts.join("");

const SEEN = assemble("sk_live_", "9fQ2xLm7Rt4Vb8Nc3Kp6Wd1Z");
const b64url = (s: string): string => Buffer.from(s).toString("base64url");

export const TOKENS: Record<string, string> = {
  PAN: luhnComplete("453201511283036"),
  IBAN: ibanComplete("DE", "370400440532013981"),
  AWS_KEY: assemble("AKIA", "Q3EGRZ7H2KXN5TYW"),
  SLACK_TOKEN: assemble("xoxb-", "4827364519-", "Hq8Lr2Vt6Np0Ws4Ky9Bz3Dm"),
  NPM_TOKEN: assemble("npm_", "Rk3Vq8Lt2Wp7Yz5Nc9Hm4Bx6Fd1Gs0Jq2TeA"),
  JWT_SERVICE: `eyJhbGciOiJIUzI1NiJ9.${b64url('{"iss":"supabase","role":"service_role","ref":"abcd"}')}.Qm9vdGhzaWduYXR1cmVfeHl6`,
  PG_URL: "postgres://app:Hk7s9Qw2Lp@db.corp-internal.net:5432/app",
  NATID: (() => {
    const d = verhoeffComplete("23456789012");
    return `${d.slice(0, 4)} ${d.slice(4, 8)} ${d.slice(8)}`;
  })(),
  SEEN,
  SEEN_B64: Buffer.from(SEEN).toString("base64"),
  SEEN_HEX_A: Buffer.from(SEEN).toString("hex").slice(0, 34),
  SEEN_HEX_B: Buffer.from(SEEN).toString("hex").slice(34),
  HEXLABEL: "7f3a9c2e41b8d6075e1f4a9c3b2d8e6f",
  BLOB200: Buffer.from(Array.from({ length: 150 }, (_, i) => (i * 37 + 11) % 256)).toString("base64url").slice(0, 200),
  TAGS: "page\u{E0068}\u{E0069}",
  LONGTEXT: "export function reconcileLedger(entries, accounts) { const totals = new Map(); for (const e of entries) { totals.set(e.account, (totals.get(e.account) ?? 0) + e.amount); } return accounts.map((a) => ({ ...a, balance: totals.get(a.id) ?? 0 })); } // internal billing code",
  SK_TEST: assemble("sk_te", "st_4eC39HqLyjWD", "arjtT1zdp7dc"),
  // Replaced by the value of a decoy planted in the row's own tree (Tree.canary); this stays only for a row that plants none.
  CANARY: "lsfw-canary-not-planted",
};

export interface Tree {
  root: string;
  home: string;
  ws: string;
  other: string;
  scratch: string;
  fwPkg: string;
  l: Layout;
  /** The value of a decoy planted in this tree (rows that name {CANARY}). */
  canary?: string;
}

/** The firewall package root (the directory holding dist/ and package.json). */
export function packageRoot(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..");
}

export function fill(v: unknown, t: Tree): unknown {
  if (typeof v === "string") {
    let s = (t.canary === undefined ? v : v.replaceAll("{CANARY}", t.canary)).replaceAll("{WS}", t.ws).replaceAll("{H}", t.home).replaceAll("{O}", t.other).replaceAll("{TMP}", t.scratch).replaceAll("{FW_PKG}", t.fwPkg);
    for (const [k, val] of Object.entries(TOKENS)) s = s.replaceAll(`{${k}}`, val);
    return s;
  }
  if (Array.isArray(v)) return v.map((x) => fill(x, t));
  if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x, t)]));
  return v;
}

/**
 * The malicious-package snapshot the package rows judge against, written into the row's own
 * firewall home the way `update` lays it out. Test data only: it lists exactly the names and versions
 * the catalogue rows name, so those rows can check the decision path. It is not a claim about any
 * real package or version (the real list comes from OSV at `update` time).
 */
const CATALOGUE_INTEL: Partial<Record<Ecosystem, Record<string, IntelEntry>>> = {
  npm: {
    "listed-package": { all: true, versions: [], ranges: [], ids: ["MAL-0000-catalogue-1"] },
    "listed-build-tool": { all: false, versions: ["1.0.0"], ranges: [], ids: ["MAL-0000-catalogue-2"] },
    "postmark-mcp": { all: false, versions: ["1.0.16"], ranges: [], ids: ["MAL-0000-catalogue-3"] },
  },
  PyPI: {
    "listed-package": { all: true, versions: [], ranges: [], ids: ["MAL-0000-catalogue-4"] },
    litellm: { all: false, versions: ["1.0.0"], ranges: [], ids: ["MAL-0000-catalogue-5"] },
  },
};

function writeCatalogueIntel(l: Layout): void {
  const gen = "g-catalogue";
  const sources = Object.entries(CATALOGUE_INTEL).map(([eco, names]) => {
    const map = new Map(Object.entries(names ?? {}));
    const buckets = writeEcosystem(join(intelDir(l.home), gen, ecoDir(eco as Ecosystem)), map);
    return { eco, url: "catalogue", sha256: "0".repeat(64), entries: map.size, buckets };
  });
  atomicWrite(join(intelDir(l.home), "manifest.json"), JSON.stringify({ format: 1, fetchedAt: new Date().toISOString(), dir: gen, sources }));
}

const PKG_JSON = '{"name":"proj","version":"1.0.0","scripts":{"test":"vitest run","build":"tsc","dev":"vite","lint":"eslint ."}}\n';

const DEFAULT_FILES: Record<string, string> = {
  "{WS}/README.md": "# proj\n",
  "{WS}/package.json": PKG_JSON,
  "{WS}/.env": `STRIPE_SECRET_KEY=${SEEN}\n`,
  "{WS}/CLAUDE.md": "# proj\n",
  "{WS}/.github/workflows/ci.yml": "jobs:\n  test:\n    strategy:\n      matrix:\n        node: [20]\n",
  "{WS}/build.rs": "fn main() {}\n",
  "{WS}/build.gradle.kts": "plugins {}\n",
  "{WS}/packages/web/package.json": PKG_JSON,
  "{WS}/packages/api/src/x.ts": "a\n",
  "{WS}/src/app.py": "x = 1\n",
  "{WS}/src/a.ts": "export const a = 1;\n",
  "{WS}/analysis.ipynb": "{}\n",
};

/** A fresh tree: {H}/Developer/proj is the workspace, {H}/Developer/ops a sibling outside it. */
export function makeTree(parent = tmpdir()): Tree {
  const root = realpathSync(mkdtempSync(join(parent, "lsfw-cat-")));
  const home = join(root, "home");
  const t: Tree = { root, home, ws: join(home, "Developer", "proj"), other: join(home, "Developer", "ops"), scratch: join(root, "scratch"), fwPkg: packageRoot(), l: layout(join(home, ".launchsafe-firewall")) };
  for (const d of [t.ws, t.other, t.scratch]) mkdirSync(d, { recursive: true });
  return t;
}

function writeFiles(t: Tree, files: Record<string, string>): void {
  for (const [p, content] of Object.entries(files)) {
    const abs = fill(p, t) as string;
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, fill(content, t) as string);
  }
}

/** What the tool would have done to the disk, so later steps see it (Write/Edit, and Bash `apply`). */
function applyStep(step: CatStep, t: Tree): void {
  const input = fill(step.input, t) as Record<string, unknown>;
  if (step.tool === "Write" && typeof input.file_path === "string") writeFiles(t, { [input.file_path]: String(input.content ?? "") });
  if (step.tool === "Edit" && typeof input.file_path === "string") {
    let before = "";
    try {
      before = readFileSync(input.file_path, "utf8");
    } catch {
      before = "";
    }
    const old = String(input.old_string ?? "");
    if (old !== "" && before.includes(old)) writeFileSync(input.file_path, before.replace(old, String(input.new_string ?? "")));
  }
  if (step.apply !== undefined) writeFiles(t, step.apply);
}

export interface StepOutcome {
  tool: string;
  verdict: Verdict;
  rules: string[];
  reason: string;
}

export interface RowRun {
  row: string;
  state: RowState;
  steps: StepOutcome[];
  problems: string[];
  passed: boolean;
}

const PASSPHRASE = "catalogue harness passphrase";

function expectedVerdict(e: Expectation, unattended: boolean): Verdict {
  if (e.startsWith("allow")) return "allow";
  if (e === "ask") return unattended ? "queue" : "ask";
  return e as Verdict;
}

/** Runs one row in one starting state, in its own tree. */
export function runRow(row: CatalogueRow, state: RowState, opts: { parent?: string; keep?: boolean } = {}): RowRun {
  const t = makeTree(opts.parent);
  const unattended = state === "UA-T" || state === "UA-U";
  const tainted = state === "U" || state === "U+S" || state === "UA-U";
  const problems: string[] = [];
  const outcomes: StepOutcome[] = [];
  try {
    writeFiles(t, { ...DEFAULT_FILES, ...(row.files ?? {}) });
    if (row.installed === true) install(t.l, "user", t.ws, VERSION, { home: t.home });
    if (row.sandboxProfile === true) applySandboxFix(t.l, planSandboxFix(t.l, t.ws, defaultConfig(), { scope: "user", home: t.home, platform: process.platform, claudeVersion: null, managedPath: join(t.root, "no-managed-settings.json") }));
    if (row.item === "4") writeCatalogueIntel(t.l);
    // A row that names {CANARY} gets a real decoy planted by the person in its tree.
    if (JSON.stringify(row).includes("{CANARY}")) t.canary = plantCanaries(t.l, { workspace: t.ws, homeDir: t.home, kinds: ["env"] }).planted[0]?.token;
    atomicWrite(t.l.policy, JSON.stringify({ version: POLICY_VERSION, ...((fill(row.policy ?? {}, t) as Record<string, unknown>) ?? {}) }));
    if (row.projectPolicy !== undefined) atomicWrite(join(t.ws, PROJECT_POLICY_FILE), JSON.stringify({ version: POLICY_VERSION, ...row.projectPolicy }));
    // The harness also runs outside vitest (npm run friction): a stand-in spawner so a held row never shows a real desktop notification.
    const agent = row.agent ?? "claude";
    const h: HookEnv = { env: { CLAUDE_PROJECT_DIR: t.ws }, layout: t.l, agent, home: t.home, scratchRoots: [t.scratch], detectNonInteractive: () => unattended, notifyDeps: { spawn: () => undefined } };
    const sid = (s?: string): string => `cat-${row.id}-${state}-${s ?? "main"}`.replace(/[^A-Za-z0-9_-]/g, "_");
    const send = (event: Record<string, unknown>, session?: string, cwd?: string): ReturnType<typeof runHook> =>
      runHook(JSON.stringify(asAgentEvent(agent, { session_id: sid(session), cwd: cwd ?? t.ws, permission_mode: "default", ...(fill(event, t) as Record<string, unknown>) })), h);
    if (row.prompt !== undefined) send({ hook_event_name: "UserPromptSubmit", prompt: row.prompt });
    if (tainted) send({ hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: { url: "https://blog.example.org/post", prompt: "read" }, tool_response: "(outside content placeholder)" });
    if (state === "U+S") send({ hook_event_name: "PostToolUse", tool_name: "Read", tool_input: { file_path: "{WS}/.env" }, tool_response: `STRIPE_SECRET_KEY=${SEEN}\n` });
    let lastQueued: string | null = null;
    row.steps.forEach((step, i) => {
      if (step.tool === "__approve_last__") {
        if (lastQueued === null) {
          problems.push(`step ${i}: nothing was queued to approve`);
          return;
        }
        try {
          initApprover(t.l, PASSPHRASE);
        } catch {
          // Already set up in this tree.
        }
        const priv = unlockApprover(t.l, PASSPHRASE);
        decideQueueItem(t.l, lastQueued, "approved", approvalSigner(priv));
        return;
      }
      // A subagent with its own session id starting and stopping (linked to the main session).
      if (step.tool === "__subagent_start__" || step.tool === "__subagent_stop__") {
        send({ hook_event_name: step.tool === "__subagent_start__" ? "SubagentStart" : "SubagentStop", parent_session_id: sid() }, step.session);
        return;
      }
      const last = i === row.steps.length - 1;
      const judged = last || step.expect !== undefined;
      const cwd = step.cwd === undefined ? undefined : (fill(step.cwd, t) as string);
      const event: Record<string, unknown> = { hook_event_name: "PreToolUse", tool_name: step.tool, tool_input: step.input };
      if (step.tool.startsWith("mcp__")) event.mcp_server = { source: step.mcpSource ?? "user" };
      const before = tailLog(t.l, 1)[0]?.seq ?? -1;
      const res = send(event, step.session, cwd);
      const { verdict, reason } = verdictFor(agent, res);
      // The decision entry (a decoy alert or other notes may be logged after it).
      const entry = tailLog(t.l, 10).filter((e) => e.seq > before && e.event.type === "decision").at(-1);
      const rules = entry !== undefined && Array.isArray(entry.event.rules) ? (entry.event.rules as string[]) : [];
      outcomes.push({ tool: step.tool, verdict, rules, reason });
      if (verdict === "queue") lastQueued = listQueue(t.l).items.filter((q) => q.status === "pending").at(-1)?.id ?? null;
      // A person answers "yes" to an ask; the tool then runs and its PostToolUse arrives.
      if (verdict === "allow" || verdict === "ask") {
        applyStep(step, t);
        const post: Record<string, unknown> = { hook_event_name: "PostToolUse", tool_name: step.tool, tool_input: step.input, tool_response: step.post ?? "(tool output placeholder)" };
        if (step.tool.startsWith("mcp__")) post.mcp_server = { source: step.mcpSource ?? "user" };
        send(post, step.session, cwd);
      }
      if (!judged) return;
      const exp = step.expect ?? row.expect;
      const want = expectedFor(agent, expectedVerdict(exp, unattended), adapterFor(agent).supportsAsk);
      const label = `step ${i} (${step.tool})`;
      if (verdict !== want) problems.push(`${label}: expected ${want}, got ${verdict} [${rules.join(",")}] ${reason.split("\n").slice(0, 3).join(" / ")}`);
      const rule = step.expect !== undefined ? step.rule : row.rule;
      if (rule !== undefined && verdict === want && !rule.split("|").some((r) => rules.includes(r))) problems.push(`${label}: expected rule ${rule}, got [${rules.join(",")}]`);
      if (last && exp.startsWith("allow") && verdict === "allow") {
        const st = loadState(t.l, sid(step.session), trustedApproverKey(t.l, {}));
        if (exp.includes("taint") && !st.tainted) problems.push(`${label}: expected the session to become untrusted`);
        if (!exp.includes("taint") && !tainted && st.tainted && step.session === undefined) problems.push(`${label}: the session became untrusted (${st.taintSources.join("; ")})`);
        if (exp.includes("+S") && !st.sensitive) problems.push(`${label}: expected the session to become sensitive`);
      }
    });
  } catch (e) {
    problems.push(`harness error: ${(e as Error).stack ?? String(e)}`);
  } finally {
    if (opts.keep !== true) rmSync(t.root, { recursive: true, force: true });
  }
  return { row: row.id, state, steps: outcomes, problems, passed: problems.length === 0 };
}

/** Every runnable row and state whose expectation is allowed: the catalogue's part of the friction gate. */
export function frictionRows(): { row: CatalogueRow; state: RowState }[] {
  return CATALOGUE.filter((r) => runnable(r) && r.expect.startsWith("allow") && r.steps.every((s) => s.expect === undefined || s.expect.startsWith("allow"))).flatMap((r) => r.states.map((state) => ({ row: r, state })));
}
