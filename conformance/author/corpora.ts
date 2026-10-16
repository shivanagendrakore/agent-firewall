/**
 * Vectors drawn from the repository's corpora, in the engine format: the friction corpus (src/corpus.ts),
 * the incident scenarios (src/scenarios.ts) and the scenario catalogue (src/catalogue-scenarios.ts). Their
 * strings are engine input only; nothing here (or anywhere) runs one.
 */

import { ALWAYS_FINE, TOOL_CASES, TRUSTED_ONLY, V02_FINE } from "../../src/corpus.js";
import { TOKENS } from "../../src/catalogue.js";
import { CATALOGUE, type CatStep, type RowState } from "../../src/catalogue-scenarios.js";
import { SCENARIOS } from "../../src/scenarios.js";
import { ctxOf, eng, HOME, NO_TOOLS, NPM_TOKEN, OUTSIDE, PRIVATE, prm, res, SLACK_BOT, STRIPE_LIVE, taintEngine, vec, WS, type Skeleton, type SkStep } from "./kit.js";

const fillPlain = (v: unknown): unknown => {
  if (typeof v === "string") return v.replaceAll("{WS}", WS).replaceAll("{HOME}", HOME).replaceAll("{H}", HOME).replaceAll("{TMP}", "/tmp/scratch").replaceAll("{O}", "/srv/other");
  if (Array.isArray(v)) return v.map(fillPlain);
  if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fillPlain(x)]));
  return v;
};
/** The catalogue's tokens, with the credential-shaped ones the vectors carry re-minted with the LSFWCONF marker. */
const CONF_TOKENS: Record<string, string> = { ...TOKENS, SEEN: STRIPE_LIVE, SLACK_TOKEN: SLACK_BOT, NPM_TOKEN };
const fillTokens = (v: unknown): unknown => {
  if (typeof v === "string") return v.replace(/\{([A-Z0-9_]+)\}/g, (m, n: string) => CONF_TOKENS[n] ?? m);
  if (Array.isArray(v)) return v.map(fillTokens);
  if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fillTokens(x)]));
  return v;
};
const fill = (v: unknown): Record<string, unknown> => fillTokens(fillPlain(v)) as Record<string, unknown>;

/** Evenly spaced picks, so a sample covers the whole list. */
const pick = <T>(xs: readonly T[], n: number): T[] => (xs.length <= n ? [...xs] : Array.from({ length: n }, (_, i) => xs[Math.floor((i * xs.length) / n)] as T));

export function friction(): Skeleton[] {
  const out: Skeleton[] = [];
  const fine = pick([...ALWAYS_FINE], 10);
  fine.forEach((c, i) => out.push(vec(`friction-fine-trusted-${String(i + 1).padStart(2, "0")}`, `Normal work in a trusted session: ${c.slice(0, 50)}`, "src/corpus.ts ALWAYS_FINE", NO_TOOLS, [eng("Bash", { command: c })])));
  pick([...ALWAYS_FINE], 3).forEach((c, i) => out.push(vec(`friction-fine-untrusted-${String(i + 1).padStart(2, "0")}`, `Normal work after reading outside content: ${c.slice(0, 50)}`, "src/corpus.ts ALWAYS_FINE", NO_TOOLS, [...taintEngine(0), eng("Bash", { command: c })])));
  pick([...V02_FINE], 5).forEach((c, i) => {
    // A command that changes into $TMPDIR is fine only where the host names its scratch directories; the reference
    // environment has none, so it is its own vector below, described as what it shows there.
    if (c.includes("$TMPDIR")) return;
    out.push(vec(`friction-v02-${String(i + 1).padStart(2, "0")}`, `Read-only inline script or cd chain: ${c.slice(0, 50)}`, "src/corpus.ts V02_FINE", NO_TOOLS, [eng("Bash", { command: c })]));
  });
  out.push(vec("friction-tmpdir-without-scratch", "A cd into $TMPDIR, then writes there, with no scratch directories named: the target cannot be resolved, so a person is asked", "src/corpus.ts V02_FINE (fine where the host names its scratch directories)", NO_TOOLS, [eng("Bash", { command: "cd $TMPDIR && mkdir -p x && cd x && touch y" })]));
  pick([...TRUSTED_ONLY], 8).forEach((c, i) => {
    const n = String(i + 1).padStart(2, "0");
    out.push(vec(`friction-needs-person-trusted-${n}`, `Fine when trusted: ${c.slice(0, 50)}`, "src/corpus.ts TRUSTED_ONLY", NO_TOOLS, [eng("Bash", { command: c })]));
    out.push(vec(`friction-needs-person-untrusted-${n}`, `After outside content, a person is needed: ${c.slice(0, 50)}`, "src/corpus.ts TRUSTED_ONLY", NO_TOOLS, [...taintEngine(0), eng("Bash", { command: c })]));
  });
  pick([...TRUSTED_ONLY], 3).forEach((c, i) => out.push(vec(`friction-needs-person-unattended-${i + 1}`, `Unattended after outside content, held for a person: ${c.slice(0, 50)}`, "src/corpus.ts TRUSTED_ONLY", NO_TOOLS, [...taintEngine(0, ctxOf(true)), eng("Bash", { command: c }, ctxOf(true))])));
  TOOL_CASES.forEach((c, i) => out.push(vec(`friction-tool-${String(i + 1).padStart(2, "0")}-${c.tool.toLowerCase()}`, `Ordinary ${c.tool} call`, "src/corpus.ts TOOL_CASES", NO_TOOLS, [eng(c.tool, fill(c.input))])));
  return out;
}

export function incidents(): Skeleton[] {
  return SCENARIOS.map((s) => {
    const ctx = ctxOf(s.unattended);
    const steps: SkStep[] = [];
    for (const st of s.steps) {
      const ev = fill(st.event);
      const name = ev.hook_event_name;
      if (name === "UserPromptSubmit") steps.push(prm(String(ev.prompt ?? "")));
      else if (name === "PreToolUse") steps.push(eng(String(ev.tool_name), ev.tool_input as Record<string, unknown>, ctx));
      else {
        // A PostToolUse follows the PreToolUse of the same call.
        const idx = steps.map((x, i) => ({ x, i })).reverse().find(({ x }) => x.kind === "decide" && (x.request.action as { tool?: string; input?: unknown }).tool === ev.tool_name && JSON.stringify((x.request.action as { input?: unknown }).input) === JSON.stringify(ev.tool_input))?.i;
        if (idx === undefined) throw new Error(`${s.id}: a PostToolUse without its PreToolUse`);
        steps.push(res(idx, ev.tool_response));
      }
    }
    return vec(`incident-${s.id.toLowerCase()}`, s.title, `src/scenarios.ts ${s.id}; ${s.source}`, NO_TOOLS, steps);
  });
}

const STATE_OK: Record<RowState, boolean> = { T: true, U: true, "U+S": true, "UA-T": true, "UA-U": true };

/** Catalogue rows that need nothing but a session: no files, policy, installed hooks, package intel, other agents or sessions. */
export function catalogue(max: number): Skeleton[] {
  const rows = CATALOGUE.filter(
    (r) =>
      r.skip === undefined &&
      r.files === undefined &&
      r.policy === undefined &&
      r.projectPolicy === undefined &&
      r.installed !== true &&
      r.sandboxProfile !== true &&
      r.agent === undefined &&
      r.item !== "4" &&
      r.steps.every((s: CatStep) => s.apply === undefined && s.session === undefined && s.cwd === undefined && !s.tool.startsWith("__")) &&
      !/\{(CANARY|FW_PKG|SEEN_[A-Z0-9]+)\}/.test(JSON.stringify(r)),
  );
  const all: Skeleton[] = [];
  for (const r of rows) {
    for (const state of r.states) {
      if (!STATE_OK[state]) continue;
      const unattended = state === "UA-T" || state === "UA-U";
      const ctx = ctxOf(unattended);
      const steps: SkStep[] = [];
      if (r.prompt !== undefined) steps.push(prm(r.prompt));
      if (state === "U" || state === "U+S" || state === "UA-U") steps.push(...taintEngine(steps.length, ctx));
      if (state === "U+S") {
        const at = steps.length;
        steps.push(eng("Read", { file_path: `${WS}/.env` }, ctx), res(at, `STRIPE_SECRET_KEY=${CONF_TOKENS.SEEN ?? ""}\n`));
      }
      r.steps.forEach((st, i) => {
        const at = steps.length;
        const input = fill(st.input);
        steps.push(eng(st.tool, input, ctx));
        if (i < r.steps.length - 1) steps.push(res(at, fillTokens(st.post ?? "(tool output placeholder)")));
      });
      all.push(vec(`catalogue-${r.id.toLowerCase()}-${state.toLowerCase().replace("+", "")}`, `${r.task} (${state})`, `src/catalogue-scenarios.ts ${r.id}`, NO_TOOLS, steps));
    }
  }
  return pick(all, max);
}

export { OUTSIDE, PRIVATE };
