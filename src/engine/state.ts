/**
 * Session state is a fold over an append-only list of events. Nothing is ever
 * removed: once a session is untrusted it stays untrusted. A corrupt event
 * makes the session untrusted and sensitive, never more permissive.
 */

import type { SessionState, StateEvent } from "../types.js";
import { normalizeWiden, parseTaskScope } from "./scope.js";
import { own } from "../own.js";
import { MAX_SUGGESTIONS_PER_SESSION, SATURATED } from "./outsider.js";

const MAX_SOURCES = 20;

export function emptyState(): SessionState {
  return {
    tainted: false,
    taintSources: [],
    sensitive: false,
    sensitiveSources: [],
    fingerprints: new Set(),
    userDestinations: new Set(),
    downloaded: new Set(),
    taintedWrites: new Set(),
    secretPaths: new Set(),
    credentialReads: [],
    approvals: new Map(),
    proposalApprovals: new Set(),
    scope: null,
    scopeWidenings: [],
    budgetRaises: [],
    canaryTripped: new Set(),
    canarySeen: new Set(),
    agentScanned: false,
    agentScanRules: [],
    agentScanIncomplete: false,
    linkedParents: [],
  };
}

function pushBounded(list: string[], v: string): void {
  if (list.includes(v)) return;
  list.push(v);
  if (list.length > MAX_SOURCES) list.shift();
}

// A list that keeps every distinct value (nothing is dropped, since a parent left out would never be told what its
// subagent read) cannot be searched with includes() once per event: a session file of tens of thousands of
// distinct values took seconds to fold. Each such list has a set of its members beside it, built when first needed.
const members = new WeakMap<string[], Set<string>>();

function addDistinct(list: string[], v: string): void {
  let seen = members.get(list);
  if (seen === undefined) {
    seen = new Set(list);
    members.set(list, seen);
  }
  if (seen.has(v)) return;
  seen.add(v);
  list.push(v);
}

export function applyEvent(s: SessionState, e: StateEvent): void {
  switch (e.type) {
    case "taint":
      s.tainted = true;
      pushBounded(s.taintSources, e.source);
      return;
    case "sensitive":
      s.sensitive = true;
      pushBounded(s.sensitiveSources, e.source);
      return;
    case "fingerprint":
      s.fingerprints.add(e.hash);
      return;
    case "user_destinations":
      for (const d of e.destinations) s.userDestinations.add(d.toLowerCase());
      return;
    case "downloaded":
      s.downloaded.add(e.path);
      return;
    case "tainted_write":
      s.taintedWrites.add(e.path);
      return;
    case "secret_path":
      s.secretPaths.add(e.path);
      return;
    case "credential_read":
      pushBounded((s.credentialReads ??= []), e.source);
      return;
    case "approval":
      s.approvals.set(e.actionHash, e.id);
      // V37: the latest approval for a hash decides whether it covers a proposal hold.
      if (e.proposal === true) (s.proposalApprovals ??= new Set()).add(e.actionHash);
      else s.proposalApprovals?.delete(e.actionHash);
      // I2: what it was signed for, when it says (v2).
      if (e.rules !== undefined || e.exp !== undefined) {
        (s.approvalGrants ??= new Map()).set(e.actionHash, { id: e.id, ...(e.rules !== undefined ? { rules: [...e.rules] } : {}), ...(e.exp !== undefined ? { exp: e.exp } : {}), ...(e.cwd !== undefined ? { cwd: e.cwd } : {}), ...(e.projectDir !== undefined ? { projectDir: e.projectDir } : {}) });
      } else s.approvalGrants?.delete(e.actionHash);
      return;
    case "approval_used":
      s.approvals.delete(e.actionHash);
      s.proposalApprovals?.delete(e.actionHash);
      s.approvalGrants?.delete(e.actionHash);
      return;
    case "phone_approval":
      // Only an event loadState() verified against the pinned phones (and found unexpired) counts.
      // Phones approve approval items only (proposals stay in the terminal): never a proposal hold.
      if (e.verified === true) {
        s.approvals.set(e.actionHash, e.id);
        s.proposalApprovals?.delete(e.actionHash);
        s.approvalGrants?.delete(e.actionHash);
      }
      return;
    case "scope":
      s.scope = e.scope;
      return;
    case "scope_widen":
      s.scopeWidenings.push({ kind: e.kind, value: e.value, id: e.id });
      return;
    case "budget_raise":
      s.budgetRaises.push({ key: e.key, amount: e.amount, id: e.id });
      return;
    case "canary_tripped":
      s.canaryTripped.add(e.id);
      return;
    case "canary_seen":
      s.canarySeen.add(e.id);
      return;
    case "agent_scan":
      s.agentScanned = true;
      for (const r of e.rules) addDistinct(s.agentScanRules, r);
      s.agentScanIncomplete = s.agentScanIncomplete || e.incomplete;
      return;
    case "linked":
      addDistinct(s.linkedParents, e.parent);
      return;
    case "outside_command": {
      const m = (s.outsideCommands ??= new Map());
      // The first source is kept; past the cap, older fingerprints stay and new ones are not added.
      if (m.has(e.hash)) return;
      // Past the cap the session is saturated (every risky command asks), so nothing is lost by not storing more.
      if (m.size >= MAX_SUGGESTIONS_PER_SESSION && e.hash !== SATURATED) {
        if (!m.has(SATURATED)) m.set(SATURATED, e.source);
        return;
      }
      m.set(e.hash, e.source);
      if (e.tokens !== undefined && e.tokens.length > 0) (s.outsideTokenSets ??= []).push([e.tokens, e.source]);
      return;
    }
    case "corrupt":
      s.tainted = true;
      s.sensitive = true;
      pushBounded(s.taintSources, `unreadable session state (${e.detail})`);
      pushBounded(s.sensitiveSources, "unreadable session state");
      return;
  }
}

export function foldEvents(events: Iterable<StateEvent>): SessionState {
  const s = emptyState();
  for (const e of screenApprovals([...events])) applyEvent(s, e);
  return s;
}

const isApproval = (e: StateEvent): e is Extract<StateEvent, { type: "approval" | "phone_approval" }> => e.type === "approval" || e.type === "phone_approval";

/**
 * B1: approvals are single-use by their id, wherever the lines sit. An approval whose id an "approval_used"
 * names anywhere in the session (before or after it) never counts again, and an approval id that appears
 * twice is a copied line: each copy becomes "corrupt" (the session is untrusted), so appending a byte-identical
 * copy of a used approval re-grants nothing. Older "approval_used" lines without an id still cancel the
 * approvals of their action that come before them, as they always did.
 */
export function screenApprovals(events: readonly StateEvent[]): StateEvent[] {
  const count = new Map<string, number>();
  const used = new Set<string>();
  for (const e of events) {
    if (isApproval(e)) count.set(e.id, (count.get(e.id) ?? 0) + 1);
    else if (e.type === "approval_used" && e.id !== undefined) used.add(e.id);
  }
  return events.flatMap((e): StateEvent[] => {
    if (!isApproval(e)) return [e];
    if ((count.get(e.id) ?? 0) > 1) return [{ type: "corrupt", detail: `approval ${e.id} appears more than once in the session file (a copied approval)` }];
    return used.has(e.id) ? [] : [e];
  });
}

/**
 * Whether the approval `approvalId` for `actionHash` is still unused in these events (in file order): it is
 * there exactly once, no "approval_used" anywhere names its id, and no older id-less "approval_used" for that
 * action follows it. Signatures are checked by whoever read the approval; this only answers "has another
 * process used it since".
 */
export function approvalUnused(events: readonly StateEvent[], actionHash: string, approvalId: string): boolean {
  let at = -1;
  let copies = 0;
  events.forEach((e, i) => {
    if (isApproval(e) && e.id === approvalId) {
      copies++;
      if (e.actionHash === actionHash) at = i;
    }
  });
  if (at === -1 || copies !== 1) return false;
  if (events.some((e) => e.type === "approval_used" && e.id === approvalId)) return false;
  return !events.slice(at + 1).some((e) => e.type === "approval_used" && e.actionHash === actionHash);
}

/**
 * I2: whether the approval held for `actionHash` covers a decision naming `rules`: every rule asking now
 * (other than the approval's own FW-APPROVED) is one the person was shown when they approved. An approval
 * that records no rules (the library's memory store) covers as before.
 */
export function approvalCoversRules(state: SessionState, actionHash: string, rules: readonly string[]): boolean {
  const g = state.approvalGrants?.get(actionHash);
  if (g === undefined || g.rules === undefined) return true;
  const shown = new Set(g.rules);
  return rules.every((r) => r === "FW-APPROVED" || shown.has(r));
}

/** Where a route decides: the working directory and the project directory an approval must have been given for. */
export interface ApprovalPlace {
  cwd?: string;
  projectDir?: string;
}

/**
 * I2/I9: why the approval held for `actionHash` does not apply to a decision naming `rules` here, in plain
 * words, or null when it does. Two things end it: a rule asking now that the person was not shown when
 * approving (approvalCoversRules), and a working directory or project other than the one it was signed for.
 * `where` is what the route knows: the hook and the gateway state both (the agent can `cd`, so the same
 * relative command is another action elsewhere); the library and the local API bind an approval to the
 * caller's context through its key instead (approvalKey in decide.ts) and pass nothing. A grant that records
 * no place (an answer given in the client) is judged on its rules only, and an approval that records no grant
 * at all (the memory store's, a phone's) is not refused here.
 */
export function approvalRefusal(state: SessionState, actionHash: string, rules: readonly string[], where?: ApprovalPlace): string | null {
  const g = state.approvalGrants?.get(actionHash);
  if (g === undefined) return null;
  if (!approvalCoversRules(state, actionHash, rules)) {
    const shown = new Set(g.rules);
    const extra = [...new Set(rules)].filter((r) => r !== "FW-APPROVED" && !shown.has(r));
    const names = extra.slice(0, 3).join(", ") + (extra.length > 3 ? ` and ${extra.length - 3} more` : "");
    return `${names} ${extra.length === 1 ? "now asks" : "now ask"} about it too, which you were not shown when you approved it`;
  }
  const other = (signed: string | undefined, here: string | undefined): boolean => signed !== undefined && here !== undefined && signed !== here;
  if (where !== undefined && (other(g.cwd, where.cwd) || other(g.projectDir, where.projectDir))) return "you approved it for another working directory or project";
  return null;
}

/** The action whose approval these decision events use, if any. */
export function usedApproval(events: readonly StateEvent[]): string | undefined {
  const e = events.find((x) => x.type === "approval_used");
  return e?.type === "approval_used" ? e.actionHash : undefined;
}

const EVENT_TYPES = new Set(["taint", "sensitive", "fingerprint", "user_destinations", "downloaded", "tainted_write", "secret_path", "credential_read", "approval", "approval_used", "phone_approval", "corrupt", "scope", "scope_widen", "budget_raise", "canary_tripped", "canary_seen", "agent_scan", "linked", "outside_command"]);

/** Events that must carry a valid approver signature (checked in loadState, like approvals). */
export const SIGNED_EVENT_TYPES: ReadonlySet<string> = new Set(["approval", "scope_widen", "budget_raise", "phone_approval"]);

/** Validates an event read from disk. Anything malformed becomes a "corrupt" event. */
export function parseEvent(raw: unknown): StateEvent {
  if (typeof raw !== "object" || raw === null) return { type: "corrupt", detail: "not an object" };
  const o = raw as Record<string, unknown>;
  const t = o.type;
  if (typeof t !== "string" || !EVENT_TYPES.has(t)) return { type: "corrupt", detail: `unknown event type ${String(t)}` };
  const str = (k: string): string | null => (typeof own(o, k) === "string" ? (own(o, k) as string) : null);
  switch (t) {
    case "taint":
    case "sensitive":
    case "credential_read": {
      const source = str("source");
      return source === null ? { type: "corrupt", detail: `${t} without source` } : { type: t, source };
    }
    case "fingerprint": {
      const hash = str("hash");
      return hash === null ? { type: "corrupt", detail: "fingerprint without hash" } : { type: t, hash };
    }
    case "user_destinations": {
      const d = o.destinations;
      return Array.isArray(d) && d.every((x) => typeof x === "string") ? { type: t, destinations: d as string[] } : { type: "corrupt", detail: "bad destinations" };
    }
    case "downloaded":
    case "secret_path":
    case "tainted_write": {
      const path = str("path");
      return path === null ? { type: "corrupt", detail: `${t} without path` } : { type: t, path };
    }
    case "approval": {
      const h = str("actionHash");
      const id = str("id");
      const sig = str("sig");
      if (h === null || id === null) return { type: "corrupt", detail: "bad approval" };
      const base: Extract<StateEvent, { type: "approval" }> = sig === null ? { type: t, actionHash: h, id } : { type: t, actionHash: h, id, sig };
      // v2 fields: all or none, each well formed (they are signed; loadState checks the signature over them).
      const v2 = ["nonce", "exp", "rules", "cwd", "projectDir"].filter((k) => own(o, k) !== undefined);
      if (v2.length === 0) return base;
      const nonce = str("nonce");
      const exp = str("exp");
      const cwd = str("cwd");
      const projectDir = str("projectDir");
      const rules = own(o, "rules");
      if (v2.length !== 5 || nonce === null || nonce === "" || exp === null || cwd === null || projectDir === null || !Array.isArray(rules) || rules.length > 64 || !rules.every((r) => typeof r === "string")) return { type: "corrupt", detail: "bad approval" };
      return { ...base, nonce, exp, rules: rules as string[], cwd, projectDir };
    }
    case "phone_approval": {
      // Field by field, as for the other signed events; `verified` is never taken from disk.
      const f = ["actionHash", "id", "credentialId", "m", "authData", "clientData", "sig", "exp"].map(str);
      if (f.some((x) => x === null || x === "")) return { type: "corrupt", detail: "bad phone_approval" };
      const [actionHash, id, credentialId, m, authData, clientData, sig, exp] = f as string[];
      return { type: t, actionHash: actionHash as string, id: id as string, credentialId: credentialId as string, m: m as string, authData: authData as string, clientData: clientData as string, sig: sig as string, exp: exp as string };
    }
    case "approval_used": {
      const h = str("actionHash");
      const id = own(o, "id");
      if (h === null || (id !== undefined && typeof id !== "string")) return { type: "corrupt", detail: "bad approval_used" };
      return typeof id === "string" ? { type: t, actionHash: h, id } : { type: t, actionHash: h };
    }
    case "scope": {
      const scope = parseTaskScope(o.scope);
      return scope === null ? { type: "corrupt", detail: "bad scope" } : { type: t, scope };
    }
    case "scope_widen": {
      const kind = str("kind");
      const value = str("value");
      const id = str("id");
      const sig = str("sig");
      // The kind and value must be ones `scope widen` can produce (normalized), or the line was not written by it.
      const valid = kind !== null && value !== null && normalizeWiden(kind, value)?.value === value;
      return !valid || id === null || sig === null ? { type: "corrupt", detail: "bad scope_widen" } : { type: t, kind, value, id, sig };
    }
    case "budget_raise": {
      const key = str("key");
      const id = str("id");
      const sig = str("sig");
      const amount = o.amount;
      return key === null || id === null || sig === null || typeof amount !== "number" || !Number.isFinite(amount) || amount < 0 ? { type: "corrupt", detail: "bad budget_raise" } : { type: t, key, amount, id, sig };
    }
    case "canary_tripped":
    case "canary_seen": {
      const id = str("id");
      return id === null || !/^[a-z0-9]{1,32}$/.test(id) ? { type: "corrupt", detail: `bad ${t}` } : { type: t, id };
    }
    case "agent_scan": {
      const rules = o.rules;
      const incomplete = o.incomplete;
      return Array.isArray(rules) && rules.every((x) => typeof x === "string") && typeof incomplete === "boolean" ? { type: t, rules: rules as string[], incomplete } : { type: "corrupt", detail: "bad agent_scan" };
    }
    case "linked": {
      const parent = str("parent");
      return parent === null ? { type: "corrupt", detail: "linked without parent" } : { type: t, parent };
    }
    case "outside_command": {
      const hash = str("hash");
      const source = str("source");
      const tokens = o.tokens;
      const tokensOk = tokens === undefined || (Array.isArray(tokens) && tokens.length <= 12 && tokens.every((x) => typeof x === "string" && /^[0-9a-f]{16}$/.test(x)));
      if (hash === null || !(/^[cpuskat]:[0-9a-f]{32}$/.test(hash) || hash === SATURATED) || source === null || source.length > 200 || !tokensOk) return { type: "corrupt", detail: "bad outside_command" };
      return Array.isArray(tokens) && tokens.length > 0 ? { type: t, hash, source, tokens: tokens as string[] } : { type: t, hash, source };
    }
    default:
      return { type: "corrupt", detail: str("detail") ?? "corrupt" };
  }
}
