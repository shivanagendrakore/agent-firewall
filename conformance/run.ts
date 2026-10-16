/**
 * Runs a conformance vector against the in-process library (createGuard with a memory store) and returns
 * what each step gave, in the vectors' `expect` shape. generate.ts records it; test/conformance.test.ts
 * checks the recorded vectors against it.
 *
 * The reference environment (docs/api-v0.md leaves it to the host; the vectors fix it): home /home/agent,
 * no scratch directories, the default policy, no file-system access (paths are judged as text), no
 * vault, no package-intel snapshot, a fixed clock, the memory store.
 *
 * A vector with `setup` runs in the prepared environment instead (setup.ts): a temporary tree with the
 * setup's files, decoys and policy, and the file access the sidecar gives with fileAccess on (the hook's
 * nodeEnvironment over that tree, the policy loaded from its firewall home and workspace, the decoy registry),
 * pinned so the host it runs on does not change a verdict: paths compare case-sensitively, and the variables that
 * move agents' settings files elsewhere (PINNED_UNSET) are unset while a vector runs.
 *
 * Both environments: the calls are one agent's (REFERENCE.agent), as the API's sessions are `<agentId>/<session>`,
 * so the per-agent counts (the behaviour monitor, budgets.stopScope "agent") are kept as the sidecar keeps them.
 */

import { BadRequest, parseDecide } from "../src/api/request.js";
import { loadCanaryIndex } from "../src/runtime/canaries.js";
import { loadPolicy } from "../src/runtime/config.js";
import { createGuard, memoryStore, type Guard, type GuardDecision, type GuardOptions, type StateStore } from "../src/sdk/index.js";
import { fileLedger, nodeEnvironment } from "../src/sdk/node.js";
import { dispose, prepare, substitute, type Prepared, type Setup } from "./setup.js";
import { translateDecide, translateInput, translatePrompt, translateRegistry, translateResult, type Registry } from "./translate.js";

export type StepKind = "decide" | "result" | "input" | "prompt" | "approve";
/** Which of the agent's tokens sends the step: its ordinary one, or its network middleware's (`api token add --traffic network`). */
export type Token = "agent" | "network";

export interface Expect {
  verdict?: "allow" | "ask" | "hold" | "deny";
  /** The exact set of rule ids (sorted). */
  ruleIds?: string[];
  sessionUntrusted?: boolean;
  holdsPrivateData?: boolean;
  /** A result step: the output with credentials masked, when the engine masked something. */
  redacted?: string;
  /** The request is refused as a bad request (HTTP status). */
  error?: 400;
}

export interface Step {
  kind: StepKind;
  /** Default "agent". "network": sent with the agent's network-middleware token (the only one that may send context.traffic "network"). */
  token?: Token;
  /** The request body in the contract's shape. Non-decide steps carry `session` in the body (it is the URL path in the API). "@step:N" as a decisionId means the decision of step N. */
  request: Record<string, unknown>;
  expect: Expect;
  /**
   * Only where the two routes differ by design: what the HTTP API answers (its request limits refuse the body before
   * the engine sees it, where the library judges the call). Runners that talk to the API compare with this instead of
   * `expect`. Recorded from src/api/request.ts, never written by hand; only ever on a vector's last step.
   */
  expectApi?: Expect;
}

export interface Vector {
  id: string;
  description: string;
  /** Where the case comes from (a corpus, an incident, the contract), for people. Not read by a runner. */
  source?: string;
  /**
   * Set when the vector pins a choice the contract leaves to the implementation: why. Another implementation may
   * answer differently and still conform; its runner reports such a difference instead of failing.
   */
  implementationSpecific?: string;
  agentTools: Registry;
  /** Prepared before the steps (setup.ts); its presence switches the vector to the prepared environment. */
  setup?: Setup;
  steps: Step[];
}

/** The reference values: the agent's home, the clock, and the agent every call is from (the API's token's agent). */
export const REFERENCE = { home: "/home/agent", now: "2026-10-12T12:00:00.000Z", agent: "conf" } as const;

/**
 * Unset while a vector runs (pinEnvironment): each moves an agent's settings files, which the engine protects, to
 * wherever it points on the machine running the vectors.
 */
export const PINNED_UNSET = ["CLAUDE_CONFIG_DIR", "CODEX_HOME", "GEMINI_CLI_HOME", "GEMINI_CLI_SYSTEM_SETTINGS_PATH"] as const;

/** Unsets PINNED_UNSET in this process; returns the function that puts them back. */
export function pinEnvironment(): () => void {
  const saved = new Map<string, string>();
  for (const k of PINNED_UNSET) {
    const v = process.env[k];
    if (v !== undefined) saved.set(k, v);
    delete process.env[k];
  }
  return () => {
    for (const [k, v] of saved) process.env[k] = v;
  };
}

const STEP_REF = /^@step:(\d+)$/;

/** What the library gave for each step, and, where the HTTP API answers otherwise by design, what it answers. */
export interface Outcome {
  expects: Expect[];
  /** Per step: the API's answer where it differs (src/api/request.ts refuses the body), else undefined. */
  api: (Expect | undefined)[];
}

/** Runs the vector's steps in order; throws on a vector that is not well formed. */
export function runVector(v: Vector): Expect[] {
  return runVectorRoutes(v).expects;
}

/** runVector, plus the steps the HTTP API refuses where the library judges (Step.expectApi). */
export function runVectorRoutes(v: Vector): Outcome {
  const restore = pinEnvironment();
  try {
    if (v.setup === undefined) return runSteps(v, undefined);
    const p = prepare(v.setup);
    try {
      return runSteps({ ...v, steps: substitute(v.steps, p) }, p);
    } finally {
      dispose(p);
    }
  } finally {
    restore();
  }
}

/** The guard options a prepared tree gives: what the sidecar's ApiCore builds with fileAccess on, case-sensitive. */
function preparedOptions(p: Prepared, roots: string[]): Pick<GuardOptions, "workspace" | "cwd" | "home" | "scratch" | "caseInsensitive" | "fs" | "settingsFiles" | "installDir" | "packageIntel" | "lockfiles" | "policy" | "policyError"> {
  const loaded = loadPolicy(p.l, roots);
  const policy = loaded.config;
  // A policy that does not load is judged as the sidecar and the hook judge it: the layers that loaded, and
  // FW-POLICY-ERROR on every risky call (the policy-error-* vectors set one up on purpose).
  return { ...nodeEnvironment({ workspace: roots, home: p.home, scratch: [], firewallHome: p.firewallHome, policy }), caseInsensitive: false, policy, ...(loaded.error !== undefined ? { policyError: loaded.error } : {}) };
}

/** Whether the HTTP API refuses a decide body the contract's translation accepts (its own limits: src/api/request.ts). */
function apiRefuses(request: unknown, names: readonly string[], token: Token | undefined): boolean {
  try {
    parseDecide(request, names, { networkTraffic: token === "network" });
    return false;
  } catch (e) {
    if (e instanceof BadRequest) return true;
    throw e;
  }
}

function runSteps(v: Vector, p: Prepared | undefined): Outcome {
  const reg = translateRegistry(v.agentTools);
  if (!reg.ok) throw new Error(`${v.id}: registry: ${reg.detail}`);
  const names = Object.keys(reg.tools);
  let store: StateStore = memoryStore();
  if (p !== undefined) {
    // The decoy registry as the file store reads it (with the same symlink resolution, case-sensitive as pinned).
    const env = nodeEnvironment({ home: p.home, scratch: [], firewallHome: p.firewallHome });
    const canaries = loadCanaryIndex(p.l, false, env.fs?.realpath);
    // The provenance ledger as the file store has it, in the tree's firewall home: what one session wrote reaches the
    // next (the sidecar's guards have it through fileStore). The reference environment has none: no file access.
    store = { ...memoryStore(canaries !== undefined ? { canaries } : {}), ledger: fileLedger({ home: p.firewallHome }) };
  }
  const decisions = new Map<number, { guard: Guard; decision: GuardDecision }>();
  const guards = new Map<string, Guard>();
  const now = (): Date => new Date(REFERENCE.now);
  const api: (Expect | undefined)[] = v.steps.map(() => undefined);

  const guardFor = (session: string, o: { registry: boolean; attended: boolean; workspace: string[]; cwd?: string | undefined; traffic?: "network" }): Guard => {
    const key = JSON.stringify([session, o]);
    const have = guards.get(key);
    if (have !== undefined) return have;
    const env: GuardOptions = p === undefined ? { home: REFERENCE.home, workspace: o.workspace } : preparedOptions(p, o.workspace);
    const cwd = o.cwd ?? env.cwd;
    // Approvals hold only in the context they were given for (cwd and workspace), as the sidecar binds them.
    const opts: GuardOptions = { ...env, session, agent: REFERENCE.agent, bindApprovalsToContext: true, store, now, attended: o.attended, ...(cwd !== undefined ? { cwd } : {}), ...(o.registry ? { tools: reg.tools } : {}), ...(o.traffic !== undefined ? { traffic: o.traffic } : {}) };
    const g = createGuard(opts);
    guards.set(key, g);
    return g;
  };
  const decisionOf = (ref: unknown, i: number): { guard: Guard; decision: GuardDecision } => {
    const m = typeof ref === "string" ? STEP_REF.exec(ref) : null;
    const d = m === null ? undefined : decisions.get(Number(m[1]));
    if (d === undefined) throw new Error(`${v.id} step ${i}: decisionId must be "@step:N" naming an earlier decide step`);
    return d;
  };
  const flags = (g: Guard): Pick<Expect, "sessionUntrusted" | "holdsPrivateData"> => {
    const s = g.state();
    return { sessionUntrusted: s.untrusted, holdsPrivateData: s.holdsPrivateData };
  };

  const expects = v.steps.map((step, i): Expect => {
    if (step.token !== undefined && step.token !== "agent" && step.token !== "network") throw new Error(`${v.id} step ${i}: token must be "agent" or "network"`);
    switch (step.kind) {
      case "decide": {
        const t = translateDecide(step.request, names);
        if (!t.ok) return { error: t.status };
        // The contract: context.traffic "network" is accepted only from a network middleware's token (docs/api-v0.md).
        if (t.traffic === "network" && step.token !== "network") return { error: 400 };
        if (apiRefuses(step.request, names, step.token)) api[i] = { error: 400 };
        const g = guardFor(t.session, { registry: t.useRegistry, attended: t.attended, workspace: t.workspace, cwd: t.cwd, ...(t.traffic === "network" ? { traffic: "network" as const } : {}) });
        const d = t.dryRun ? g.check(t.call) : g.decide(t.call);
        decisions.set(i, { guard: g, decision: d });
        // A dry run records nothing, and what the session object of its response shows is left open by the contract.
        return { verdict: d.verdict, ruleIds: [...new Set(d.rules)].sort(), ...(t.dryRun ? {} : flags(g)) };
      }
      case "result": {
        const t = translateResult(step.request);
        if (!t.ok) return { error: t.status };
        const { guard, decision } = decisionOf(t.decisionId, i);
        const note = guard.recordResult(decision.call, t.output, t.failed !== undefined ? { failed: t.failed } : {});
        return { ...flags(guard), ...(note.redacted !== undefined ? { redacted: note.redacted } : {}) };
      }
      case "input": {
        const t = translateInput(step.request);
        if (!t.ok) return { error: t.status };
        const g = guardFor(t.session, { registry: false, attended: true, workspace: [] });
        g.reportInput({ source: t.source, content: t.content, ...(t.private !== undefined ? { private: t.private } : {}) });
        return flags(g);
      }
      case "prompt": {
        const t = translatePrompt(step.request);
        if (!t.ok) return { error: t.status };
        const g = guardFor(t.session, { registry: false, attended: true, workspace: [] });
        g.recordPrompt(t.text);
        return flags(g);
      }
      case "approve": {
        // A person's answer to a hold, outside the agent's API (in the sidecar: the firewall's queue). Only holds:
        // the library keeps no queue item for an ask, so what a yes to an ask does is not pinned (see the README).
        const { guard, decision } = decisionOf(step.request.decisionId, i);
        if (decision.verdict !== "hold" || decision.held === undefined) throw new Error(`${v.id} step ${i}: only a hold can be approved`);
        guard.approve(decision.held.id, { by: "conformance" });
        return {};
      }
    }
  });
  return { expects, api };
}
