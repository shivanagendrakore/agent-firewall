/**
 * `scratch`: the scratch-target allowlist (src/runtime/scratch.ts). `scratch add` and `scratch remove` change
 * what the firewall lets a person approve, so they run only for a person: an interactive terminal that is
 * not under an agent, and the approval passphrase, which signs the list. `scratch` and `scratch list` are
 * read-only. Terminal and input come in through ScratchCliDeps so tests run the real handlers.
 */

import type { Parsed } from "./cliargs.js";
import type { Layout } from "./runtime/layout.js";

type Ok = Extract<Parsed, { kind: "ok" }>;

export interface ScratchCliDeps {
  out: (s: string) => void;
  err: (s: string) => void;
  humanAtKeyboard: () => Promise<boolean>;
  readSecret: (prompt: string) => Promise<string>;
}

async function trustedKey(l: Layout): Promise<string | null> {
  const { approverPublicKey } = await import("./runtime/approver.js");
  try {
    return approverPublicKey(l);
  } catch {
    return null;
  }
}

export async function scratchList(p: Ok, l: Layout, d: ScratchCliDeps): Promise<number> {
  const { loadScratch } = await import("./runtime/scratch.js");
  const st = loadScratch(l, await trustedKey(l));
  if (st.state === "corrupt") {
    d.err(`${st.error}. Run "launchsafe-firewall doctor".`);
    return 1;
  }
  const patterns = st.state === "absent" ? [] : st.file.patterns;
  if (p.flags.get("--json") === true) {
    d.out(JSON.stringify({ signed: st.state !== "unsigned", ...(st.state === "unsigned" ? { problem: st.reason } : {}), patterns }, null, 2));
    return st.state === "unsigned" ? 1 : 0;
  }
  if (st.state === "unsigned") d.err(`WARNING: ${st.reason}. None of these patterns is used until this is resolved.`);
  if (patterns.length === 0) d.out('No scratch targets. Add one in your own terminal: launchsafe-firewall scratch add "app_*_test"');
  else for (const x of patterns) d.out(x);
  return st.state === "unsigned" ? 1 : 0;
}

async function change(p: Ok, l: Layout, d: ScratchCliDeps, op: "add" | "remove"): Promise<number> {
  const { validScratchPattern } = await import("./engine/catastrophic.js");
  const { unlockApprover, approverPublicKey } = await import("./runtime/approver.js");
  const { updateScratch } = await import("./runtime/scratch.js");
  const pattern = p.positionals[0] as string;
  if (op === "add" && !validScratchPattern(pattern)) {
    d.err(`launchsafe-firewall scratch add: "${pattern.slice(0, 100)}" is not a pattern: use letters, digits, _ . - and *, with at least three characters that are not * (for example app_*_test, *-pr-*, preview-*).`);
    return 64;
  }
  if (!(await d.humanAtKeyboard())) return 1;
  if (approverPublicKey(l) === null) {
    d.err('The scratch-target list is signed with your approval key, and no approval passphrase is set. In your own terminal run "launchsafe-firewall approver init" first.');
    return 1;
  }
  let priv;
  try {
    priv = unlockApprover(l, await d.readSecret("Approval passphrase: "));
  } catch (e) {
    d.err(`${(e as Error).message}. Nothing was changed.`);
    return 1;
  }
  try {
    let changed = false;
    updateScratch(l, priv, (list) => {
      const at = list.indexOf(pattern);
      if (op === "add" && at === -1) {
        list.push(pattern);
        changed = true;
      } else if (op === "remove" && at !== -1) {
        list.splice(at, 1);
        changed = true;
      }
    });
    d.out(changed ? `${op === "add" ? "Added" : "Removed"} ${pattern}.` : `${pattern} was ${op === "add" ? "already listed" : "not listed"}; nothing changed.`);
    return 0;
  } catch (e) {
    d.err((e as Error).message);
    return 1;
  }
}

export const SCRATCH_HANDLERS: Record<string, (p: Ok, l: Layout, d: ScratchCliDeps) => Promise<number>> = {
  scratch: scratchList,
  "scratch list": scratchList,
  "scratch add": (p, l, d) => change(p, l, d, "add"),
  "scratch remove": (p, l, d) => change(p, l, d, "remove"),
};
