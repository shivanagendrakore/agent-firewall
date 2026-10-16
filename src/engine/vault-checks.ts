/**
 * The vault's decision rules (see docs/vault.md). Pure: names,
 * kinds, bindings and fingerprints come from the VaultView, never a value.
 *
 * - A reference only matters where it would leave the machine: in an egress
 *   effect's payload or URL. Anywhere else (the text of a Write, a comment)
 *   it is just text: no tag, no rule, no substitution.
 * - FW-VAULT-UNBOUND (deny): a reference that names no secret (a typo), or a
 *   destination the secret is not bound to, or a value in a URL without
 *   allowInUrl, or an index that is not signed by the person's key.
 * - FW-VAULT-UNSUPPORTED (deny): a position the firewall cannot substitute
 *   safely (WebFetch, WebSearch, single quotes, a computed word, an agent
 *   that cannot rewrite tool input, an MCP server not behind the gateway).
 * - FW-VAULT-APPROVE (approve): a kind whose every use needs a person (cards, IBANs, national ids, personal data), any use in an untrusted
 *   session, and a keychain item with per-use confirmation in a session no
 *   one is watching (queued before any keychain dialog).
 *
 * Every other rule still judges the action exactly as if the reference were
 * text: the vault never loosens anything.
 */

import type { Context, Effect, FirewallConfig, NormalizedAction, SessionState, VaultDecision, VaultSubstitution } from "../types.js";
import { vaultPolicy } from "../policy-vault.js";
import { classifyAction } from "./classify.js";
import { parseMcpTool } from "./mcp.js";
import { allCommands, parseShell } from "./shell/parse.js";
import { bindingSummary, findRefs, formatRef, hostBindingMatches, REF_PATHS_DEPTH, REF_PATHS_MAX, refPathsChecked, resolveRef, toolMatches, type VaultBinding, type VaultView, type VaultViewEntry } from "./vault-ref.js";
import { isLocalHost } from "./vault-options.js";
import { planShellRewrite, shellQuote, type ShellPart } from "./vault-shell.js";
import type { RuleHit } from "./decide.js";
import { memoLast } from "./payload-memo.js";

export const RULE_UNBOUND = "FW-VAULT-UNBOUND";
export const RULE_UNSUPPORTED = "FW-VAULT-UNSUPPORTED";
export const RULE_APPROVE = "FW-VAULT-APPROVE";
export const RULE_OPTION = "FW-VAULT-OPTION";

// run is person-only (an agent may not start it: FW-TAMPER), so the hint names what the user runs in their own terminal.
const RUN_HINT = 'To give a secret to a command, the user can run it in their own terminal as: launchsafe-firewall run --env NAME=vault://<name> -- <command> (the command reads $NAME; the secret must be bound to that command with vault allow <name> --process), or use an MCP server behind the gateway';

function isEgress(e: Effect): boolean {
  return e.cls === "egress_send" || e.cls === "egress_fetch";
}

// One scan per payload, however many effects carry it (src/engine/payload-memo.ts; decide() resets them).
const payloadRefs = memoLast((payload: string) => findRefs(payload));
const targetRefs = memoLast((target: string) => findRefs(target));

function hasRef(e: Effect, text: string): boolean {
  return payloadRefs(e.payload ?? "").some((r) => r.text === text) || targetRefs(e.target).some((r) => r.text === text);
}

/** Where a secret may go, for the refusal message ("may only be used with ..."). */
function boundTo(entry: VaultViewEntry): string {
  const usable = entry.bindings.filter((b) => b.kind !== "process");
  return usable.length === 0 ? "nothing yet (bind it in your own terminal: launchsafe-firewall vault allow)" : usable.map(bindingSummary).join(", ");
}

/**
 * Simple commands of a shell command that carry a reference but would not send it anywhere (echo, tee,
 * printf): the rewrite would put the value where the agent can read it. Also a reference in an
 * assignment, a redirection or a here-document.
 */
function nonSendingPart(command: string, ctx: Context, cfg: FirewallConfig, state: SessionState): string | null {
  const script = parseShell(command);
  for (const sc of allCommands(script)) {
    if (sc.assigns.some((a) => findRefs(a.value.text).length > 0)) return "a variable assignment";
    if (sc.redirects.some((r) => (r.target !== null && findRefs(r.target.text).length > 0) || (r.heredoc !== undefined && findRefs(r.heredoc.body).length > 0))) return "a redirection";
    if (!sc.words.some((w) => findRefs(w.text).length > 0)) continue;
    // curl and wget (as planned by the rewrite) send by definition; their destinations are checked against the binding.
    const w0 = sc.words[0];
    if (w0 !== undefined && !w0.quoted && !w0.dynamic && (w0.text === "curl" || w0.text === "wget")) continue;
    const alone = sc.words.map((w) => shellQuote(w.text)).join(" ");
    const c = classifyAction({ tool: "Bash", input: { command: alone } }, ctx, cfg, state);
    if (!c.effects.some(isEgress)) return `"${sc.words[0]?.text ?? ""}", which sends nothing off the machine`;
  }
  return null;
}

/**
 * The vault's hits for one action, and the substitutions it would make. Undefined when the action carries
 * no reference in a position that leaves the machine (then nothing about the decision changes).
 */
export function vaultRules(action: NormalizedAction, effects: readonly Effect[], state: SessionState, cfg: FirewallConfig, ctx: Context, hits: RuleHit[]): VaultDecision | undefined {
  const walked = refPathsChecked(action.input);
  if (!walked.complete) {
    // V17: past the caps a reference could sit where no binding was checked; refuse the whole action.
    hits.push({ rule: RULE_UNBOUND, outcome: "deny", reason: `the input carries more than ${REF_PATHS_MAX} vault references or nests them deeper than ${REF_PATHS_DEPTH} levels, so the firewall cannot check where each one would go` });
    const refs = [...new Set(walked.paths.map((r) => r.ref.text))].slice(0, 10);
    return { refs, substitute: [] };
  }
  const all = walked.paths;
  if (all.length === 0) return undefined;
  const egress = effects.filter(isEgress);
  let leaving = all.filter((r) => egress.some((e) => hasRef(e, r.ref.text)));
  if (leaving.length === 0 && action.tool === "Bash" && typeof action.input.command === "string") {
    // A reference in the arguments of curl or wget always matters, even where the analyzer sees no egress
    // (wget -i reads its URLs from a file; a loopback URL is not egress to it): the allowlist and the
    // destination check still decide, so the reference is never let through unchecked.
    const plan = planShellRewrite(action.input.command);
    const inSender = plan.ok ? plan.parts.flatMap((p) => p.vars.map((v) => v.ref.text)) : plan.rule === "option" && plan.ref !== undefined ? [plan.ref] : [];
    leaving = all.filter((r) => inSender.includes(r.ref.text));
  }
  if (leaving.length === 0) return undefined;
  const refs = [...new Set(leaving.map((r) => r.ref.text))];
  const out: VaultDecision = { refs, substitute: [] };
  const pol = vaultPolicy(cfg);
  const view = ctx.vault;
  for (const e of egress) {
    for (const r of refs) if (hasRef(e, r)) e.tags = [...(e.tags ?? []), `vault:${r.slice("vault://".length)}`];
  }
  if (!pol.enabled || view === undefined) {
    hits.push({ rule: RULE_UNBOUND, outcome: "deny", reason: `${refs.slice(0, 3).join(", ")}: no such secret (${pol.enabled ? "the vault is empty" : "the vault is switched off"}), so the reference would go out as text` });
    return out;
  }
  if (!view.signed) {
    hits.push({ rule: RULE_UNBOUND, outcome: "deny", reason: `${refs.slice(0, 3).join(", ")}: ${view.damaged !== undefined && view.entries.length === 0 ? "the vault index cannot be read" : "the vault index is not signed by your approval key"}, so no secret may be used anywhere (launchsafe-firewall doctor)` });
    return out;
  }
  const unknown = (text: string, why: string): void => void hits.push({ rule: RULE_UNBOUND, outcome: "deny", reason: `${text}: ${why}` });
  const mcp = parseMcpTool(action.tool);
  if (mcp !== null) {
    if (!(ctx.vaultPaths?.gatewayServers ?? []).includes(mcp.server)) {
      hits.push({ rule: RULE_UNSUPPORTED, outcome: "deny", reason: `MCP server ${mcp.server} is not behind the firewall's gateway, so nothing can put the value of ${refs.slice(0, 3).join(", ")} in and the reference would go out as text; wrap it in your own terminal (launchsafe-firewall mcp wrap-config)` });
      return out;
    }
    for (const { ref, path } of leaving) {
      const res = resolveRef(ref, view);
      if (!res.ok) {
        unknown(ref.text, res.reason);
        continue;
      }
      if (oauthOnly(res.entry, ref.text, hits)) continue;
      const b = res.entry.bindings.find((x): x is Extract<VaultBinding, { kind: "mcp" }> => x.kind === "mcp" && x.server === mcp.server && toolMatches(x.tool, mcp.tool) && (x.arg === undefined || x.arg === path));
      if (b === undefined) {
        unknown(ref.text, `${formatRef(res.entry.name)} may only be used with ${boundTo(res.entry)}, not as ${path === "" ? "the arguments" : `argument ${path}`} of ${mcp.server}:${mcp.tool}`);
        continue;
      }
      out.substitute.push({ ref: ref.text, name: res.entry.name, field: res.field, kind: res.entry.kind, via: "gateway", destination: `mcp:${mcp.server}:${mcp.tool}`, binding: bindingSummary(b), path });
    }
  } else if (action.tool === "Bash" && typeof action.input.command === "string") {
    const command = action.input.command;
    for (const text of refs) {
      const ref = findRefs(text)[0];
      if (ref === undefined) continue;
      const res = resolveRef(ref, view);
      if (!res.ok) {
        unknown(text, res.reason);
        continue;
      }
      if (oauthOnly(res.entry, text, hits)) continue;
      for (const e of egress.filter((x) => hasRef(x, text))) {
        const inUrl = findRefs(e.target).some((x) => x.text === text);
        const b = res.entry.bindings.find((x): x is Extract<VaultBinding, { kind: "host" }> => x.kind === "host" && e.host !== undefined && hostBindingMatches(x.host, e.host) && (!inUrl || x.allowInUrl === true));
        if (b === undefined) {
          const urlNote = inUrl && res.entry.bindings.some((x) => x.kind === "host" && e.host !== undefined && hostBindingMatches(x.host, e.host)) ? " (inside the URL itself, which needs --allow-in-url: URLs end up in server logs and proxies)" : "";
          unknown(text, `${formatRef(res.entry.name)} may only be used with ${boundTo(res.entry)}, not ${e.host ?? e.target}${urlNote}`);
          continue;
        }
        if (!out.substitute.some((s) => s.ref === text && s.destination === e.host)) out.substitute.push({ ref: text, name: res.entry.name, field: res.field, kind: res.entry.kind, via: "hook", destination: e.host ?? e.target, binding: bindingSummary(b) });
      }
    }
    const plan = planShellRewrite(command);
    if (!plan.ok) hits.push({ rule: plan.rule === "option" ? RULE_OPTION : RULE_UNSUPPORTED, outcome: "deny", reason: `${plan.ref ?? refs[0]} cannot be put into this command: ${plan.why}. ${RUN_HINT}` });
    else {
      for (const part of plan.parts) destinationProblems(part, view, hits, out);
      const part = nonSendingPart(command, ctx, cfg, state);
      if (part !== null) hits.push({ rule: RULE_UNSUPPORTED, outcome: "deny", reason: `${refs.slice(0, 3).join(", ")} appears in ${part}: the value would be put where the agent could read it. ${RUN_HINT}` });
      else if (ctx.vaultPaths?.shellRewrite !== true) hits.push({ rule: RULE_UNSUPPORTED, outcome: "deny", reason: `this agent cannot have its command rewritten by the firewall (only agents verified to rewrite tool input can, and vault.shellRewrite must not be "off"), so ${refs.slice(0, 3).join(", ")} would go out as text. ${RUN_HINT}` });
    }
  } else {
    hits.push({ rule: RULE_UNSUPPORTED, outcome: "deny", reason: `the firewall never puts a vault value into ${action.tool} (${refs.slice(0, 3).join(", ")}): its request is not one it can fill in and keep out of the model's view. ${RUN_HINT}` });
  }
  approvals(out.substitute, state, ctx, pol, hits);
  return out;
}

/**
 * Every URL of a sending command that gets a value must be the secret's bound host, exactly (or a subdomain
 * of a "*." binding), over https unless that binding says --allow-http, never a local address unless the
 * bound host is itself local, and with the reference in the URL only under --allow-in-url. Checked per part
 * on the URLs the allowlist parsed, so a second URL, -G or a name the analyzer read differently cannot slip by.
 */
function destinationProblems(part: ShellPart, view: VaultView, hits: RuleHit[], out: VaultDecision): void {
  for (const v of part.vars) {
    const res = resolveRef(v.ref, view);
    if (!res.ok || res.entry.kind === "oauth") continue;
    const hosts = res.entry.bindings.filter((b): b is Extract<VaultBinding, { kind: "host" }> => b.kind === "host");
    for (const u of part.urls) {
      const matching = hosts.filter((b) => hostBindingMatches(b.host, u.host));
      let why: string | null = null;
      if (matching.length === 0) why = `${formatRef(res.entry.name)} may only be used with ${boundTo(res.entry)}, not ${u.host}`;
      else if (isLocalHost(u.host) && !matching.some((b) => isLocalHost(b.host.replace(/^\*\./, "x.")))) why = `${u.host} is a local address and the bound host is not`;
      else if (u.scheme !== "https" && !matching.some((b) => b.allowHttp === true)) why = `${u.text.slice(0, 80)} is plain http; ${formatRef(res.entry.name)} goes only over https to ${u.host} (bind it with --allow-http to allow http)`;
      else if (u.hasRef && !matching.some((b) => b.allowInUrl === true && (u.scheme === "https" || b.allowHttp === true))) why = `${formatRef(res.entry.name)} would be inside the URL itself, which needs --allow-in-url (URLs end up in server logs and proxies)`;
      if (why === null) {
        // A URL the analyzer did not count as egress (a loopback host bound on purpose) still gets its substitution.
        const b = matching[0] as Extract<VaultBinding, { kind: "host" }>;
        if (!out.substitute.some((s) => s.ref === v.ref.text)) out.substitute.push({ ref: v.ref.text, name: res.entry.name, field: res.field, kind: res.entry.kind, via: "hook", destination: u.host, binding: bindingSummary(b) });
        continue;
      }
      // Once this reference is refused (here, or by the binding check on the analyzer's effects), once is enough.
      if (hits.some((h) => h.rule === RULE_UNBOUND && h.reason.startsWith(`${v.ref.text}:`))) continue;
      hits.push({ rule: RULE_UNBOUND, outcome: "deny", reason: `${v.ref.text}: ${why}` });
    }
  }
}

/** An upstream OAuth token (`mcp login`) goes only into the gateway's Authorization header, never into arguments or commands. */
function oauthOnly(entry: VaultViewEntry, text: string, hits: RuleHit[]): boolean {
  if (entry.kind !== "oauth") return false;
  hits.push({ rule: RULE_UNSUPPORTED, outcome: "deny", reason: `${text} is an OAuth token; the gateway sends it only as the Authorization header to the server it was issued for, never in arguments or commands` });
  return true;
}

function approvals(subs: readonly VaultSubstitution[], state: SessionState, ctx: Context, pol: ReturnType<typeof vaultPolicy>, hits: RuleHit[]): void {
  const seen = new Set<string>();
  for (const s of subs) {
    if (seen.has(s.ref)) continue;
    seen.add(s.ref);
    const entry = ctx.vault?.entries.find((e) => e.name === s.name);
    if (pol.approveKinds.includes(s.kind as VaultViewEntry["kind"])) {
      hits.push({ rule: RULE_APPROVE, outcome: "approve", reason: `${s.ref} is a ${s.kind.replace("_", " ")} value; every use needs you (going to ${s.destination})` });
    } else if (entry?.confirm === "always" && !ctx.interactive) {
      hits.push({ rule: RULE_APPROVE, outcome: "approve", reason: `${s.ref} is stored with per-use keychain confirmation and no one is here to answer the dialog, so it is held before the keychain is asked (going to ${s.destination})` });
    } else if (state.tainted && pol.approveWhenUntrusted) {
      hits.push({ rule: RULE_APPROVE, outcome: "approve", reason: `this session has read outside content, so using ${s.ref} needs you (going to ${s.destination})` });
    }
  }
}
