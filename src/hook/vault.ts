/**
 * The hooks' half of vault substitution (hook rewrite and
 * gateway substitution in hook mode; see docs/vault.md). Called by runPreTool only after the
 * final verdict is allow (or an ask the person will answer):
 *
 * - a shell command's references are rewritten into environment variables of
 *   a ticketed `launchsafe-firewall run`, returned as updatedInput (agents
 *   verified to rewrite input only; the engine denies the rest). The value
 *   never appears: only variable names, the references and a single-use
 *   ticket bound to the exact command.
 * - an MCP call's references are left to the gateway, which owns the pipe:
 *   the hook leaves a single-use grant for that exact call.
 *
 * And on the way back (PostToolUse): every vaulted value the output still
 * shows is replaced by its reference where the agent can replace output.
 */

import { spawnSync } from "node:child_process";
import { accessSync, constants, existsSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { isRootProtectedFile } from "../runtime/notify.js";
import { parseMcpTool } from "../engine/mcp.js";
import { resultText } from "../engine/post.js";
import { planShellRewrite, shellQuote } from "../engine/vault-shell.js";
import { scrubText } from "../engine/vault-scrub.js";
import type { VaultView } from "../engine/vault-ref.js";
import type { Decision, NormalizedAction } from "../types.js";
import type { Layout } from "../runtime/layout.js";
import { vaultPolicy, type VaultPolicy } from "../policy-vault.js";
import type { FirewallConfig } from "../types.js";
import { formatRef } from "../engine/vault-ref.js";
import { approverPublicKey } from "../runtime/approver.js";
import { loadIndex } from "../runtime/vault/index.js";
import { readGatewayInstall } from "../gateway/install.js";
import { issueGrant, issueTicket, type AncestorInput } from "../runtime/vault/tickets.js";
import { logUse } from "../runtime/vault/substitute.js";

/**
 * How long a ticket or grant for an asked action lasts: the person may take a while to answer, but not ten
 * minutes (I8: an unspent ticket is an authorization lying around). An expired one is refused; the agent
 * runs the command again and the person answers again.
 */
export const ASK_SECONDS = 180;

/** The command that runs this firewall: the node binary and the CLI file next to this module (dist/cli.js), else the bin name. */
export function selfArgv(): string[] {
  const cli = fileURLToPath(new URL("../cli.js", import.meta.url));
  return existsSync(cli) ? [process.execPath, cli] : ["launchsafe-firewall"];
}

/** MCP servers the gateway wraps (any client): the only ones a reference can reach as a value. */
export function wrappedServers(l: Layout): string[] {
  try {
    return [...new Set(readGatewayInstall(l).entries.map((e) => e.server))];
  } catch {
    return [];
  }
}

/** Where curl and wget are looked for when the hook's own PATH does not say (system directories only). */
export const DEFAULT_SENDER_PATH = "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin:/home/linuxbrew/.linuxbrew/bin";

/**
 * The absolute path of the program a value goes to, from the hook's own PATH (what the agent was started
 * with, which a command of the agent cannot change) or the system directories; relative PATH entries are
 * skipped. A candidate must be a trusted system file (root-owned, not group- or world-writable, in a
 * root-owned directory, after symlinks): the value is passed in that program's environment, so a `curl`
 * in a directory the agent can write (~/.local/bin, a user-owned Homebrew prefix, node_modules/.bin) must
 * never be chosen. A user-owned curl is skipped and the search goes on to the next directory. Null when
 * not found.
 */
export function resolveSender(program: string, path: string | undefined): string | null {
  // Under the test suite a caller must say where to look: the system curl must never reach the network.
  if (path === undefined && process.env.LAUNCHSAFE_FIREWALL_TEST === "1") return null;
  for (const dir of (path ?? DEFAULT_SENDER_PATH).split(":")) {
    if (!isAbsolute(dir)) continue;
    const p = join(dir, program);
    try {
      const st = statSync(p);
      if (st.isFile() && isRootProtectedFile(p)) {
        accessSync(p, constants.X_OK);
        return p;
      }
    } catch {
      // Not here.
    }
  }
  return null;
}

/** curl's version from `curl --version` ("curl 8.7.1 (...)"), or null when it cannot be read. */
export function senderVersion(exe: string): number[] | null {
  try {
    const r = spawnSync(exe, ["--version"], { encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"], env: { PATH: "/usr/bin:/bin" } });
    const m = /^curl (\d+)\.(\d+)(?:\.(\d+))?/.exec(r.stdout ?? "");
    return m === null ? null : [Number(m[1]), Number(m[2]), Number(m[3] ?? 0)];
  } catch {
    return null;
  }
}

/** Whether version `v` is at least `min` (component by component). */
export function atLeast(v: readonly number[], min: readonly number[]): boolean {
  for (let i = 0; i < min.length; i++) {
    const a = v[i] ?? 0;
    const b = min[i] ?? 0;
    if (a !== b) return a > b;
  }
  return true;
}

export interface Prepared {
  updatedInput?: Record<string, unknown>;
}

/**
 * Prepares an allowed (or asked) decision's substitutions. Throws when a ticket or grant cannot be written:
 * the caller then denies, so a reference never goes out where a value was meant to be.
 */
export function prepareSubstitution(l: Layout, o: { action: NormalizedAction; d: Decision; session: string; pol: VaultPolicy; self?: string[]; now?: Date; logExtra?: Record<string, unknown>; senderPath?: string; resolveSender?: typeof resolveSender; senderVersion?: typeof senderVersion; ancestors?: readonly AncestorInput[] }): Prepared {
  const subs = o.d.vault?.substitute ?? [];
  if (subs.length === 0 || (o.d.verdict !== "allow" && o.d.verdict !== "ask")) return {};
  const seconds = o.d.verdict === "ask" ? Math.max(ASK_SECONDS, o.pol.ticketSeconds) : o.pol.ticketSeconds;
  const out: Prepared = {};
  const viaHook = subs.filter((s) => s.via === "hook");
  if (viaHook.length > 0 && typeof o.action.input.command === "string") {
    const command = o.action.input.command;
    const plan = planShellRewrite(command);
    if (!plan.ok) throw new Error(`the command cannot be rewritten (${plan.why})`);
    if (plan.parts.length === 0) throw new Error("the command has no reference to put a value in");
    // V1: each curl/wget command that carries references becomes its own ticketed run, so only that one
    // process gets the values; the rest of the command runs as written in the agent's shell, without them.
    let rewritten = "";
    let at = 0;
    for (const part of plan.parts) {
      const env = part.vars.map((v) => [v.name, v.ref.text] as const);
      const exe = (o.resolveSender ?? resolveSender)(part.program, o.senderPath);
      if (exe === null) throw new Error(`${part.program} was not found in a system directory`);
      // B2: curl takes the value from its environment (--variable, --expand-*), which needs curl 8.3 or later;
      // an older curl would need the value on its command line, where every user can read it: refused.
      if (part.program === "curl") {
        const v = (o.senderVersion ?? senderVersion)(exe);
        if (v === null || !atLeast(v, [8, 3])) throw new Error(`${exe} is ${v === null ? "a curl whose version could not be read" : `curl ${v.join(".")}`}; a vault value goes only to curl 8.3 or later, which reads it from its environment instead of its command line`);
      }
      // curl -q first: a .curlrc the agent wrote cannot add trace or log options. wget reads only the
      // configuration the shell's printf feeds it (--config=/dev/stdin: no .wgetrc), which holds the
      // value-carrying options. wget follows redirects by default and resends --header there, so it gets
      // --max-redirect=0 (curl follows none without -L, which is refused).
      const inner =
        part.program === "curl"
          ? [part.assigns, shellQuote(exe), "-q", part.args].filter((x) => x !== "").join(" ")
          : `${part.feed === "" ? "printf ''" : part.feed} | ${[part.assigns, shellQuote(exe), "--config=/dev/stdin", "--max-redirect=0", part.args].filter((x) => x !== "").join(" ")}`;
      const argv = ["/bin/sh", "-c", inner];
      const mine = viaHook.filter((s) => part.vars.some((v) => v.ref.text === s.ref));
      const ticket = issueTicket(l, { env, argv, session: o.session, substitute: mine, seconds, ...(o.now !== undefined ? { now: o.now } : {}), ...(o.ancestors !== undefined ? { ancestors: o.ancestors } : {}) });
      const full = [...(o.self ?? selfArgv()), "run", "--ticket", ticket, ...env.flatMap(([n, r]) => ["--env", `${n}=${r}`]), "--", ...argv];
      rewritten += command.slice(at, part.start) + full.map(shellQuote).join(" ") + (part.redirects === "" ? "" : ` ${part.redirects}`);
      at = part.end;
    }
    rewritten += command.slice(at);
    out.updatedInput = { ...o.action.input, command: rewritten };
    for (const s of viaHook) logUse(l, s, { session: o.session, action: o.d.actionHash, verdict: o.d.verdict, ...(o.logExtra !== undefined ? { extra: o.logExtra } : {}) });
  }
  const viaGateway = subs.filter((s) => s.via === "gateway");
  const mcp = parseMcpTool(o.action.tool);
  if (viaGateway.length > 0 && mcp !== null) {
    issueGrant(l, { server: mcp.server, tool: mcp.tool, args: o.action.input, session: o.session, substitute: viaGateway, seconds, ...(o.now !== undefined ? { now: o.now } : {}) });
  }
  return out;
}

export const WITHHELD_OUTPUT = "LaunchSafe Firewall withheld this output: it carried a value stored in the vault in a form that could not be replaced by its reference.";

/** The tool output with every vaulted value replaced by its reference; undefined when nothing needed it. */
export function scrubOutput(result: unknown, base: string | undefined, view: VaultView | undefined): string | undefined {
  if (view === undefined || view.entries.length === 0) return undefined;
  const s = scrubText(base ?? resultText(result), [], view);
  if (s.leftover) return WITHHELD_OUTPUT;
  return s.count > 0 ? s.value : undefined;
}

/**
 * SessionStart (vault.listInContext): which references exist and where each may go, so the agent writes
 * the reference where the value would go. Names and bound destinations only; nothing when the index does
 * not verify or holds nothing usable.
 */
export function vaultContext(l: Layout, cfg: FirewallConfig, env: NodeJS.ProcessEnv): string | null {
  const pol = vaultPolicy(cfg);
  if (!pol.enabled || !pol.listInContext) return null;
  let key: string | null = env.LAUNCHSAFE_FIREWALL_APPROVER !== undefined && env.LAUNCHSAFE_FIREWALL_APPROVER !== "" ? env.LAUNCHSAFE_FIREWALL_APPROVER : null;
  if (key === null) {
    try {
      key = approverPublicKey(l);
    } catch {
      key = null;
    }
  }
  const st = loadIndex(l, key);
  if (st.state !== "ok") return null;
  const items = st.index.entries
    .filter((e) => e.kind !== "oauth")
    .flatMap((e) => {
      const where = e.bindings.filter((b) => b.kind !== "process").map((b) => (b.kind === "host" ? b.host : `MCP ${b.server}${b.tool !== undefined ? ` ${b.tool}` : ""}`));
      if (where.length === 0) return [];
      const refs = e.fields.length === 1 ? [formatRef(e.name)] : e.fields.map((f) => formatRef(e.name, f));
      const approve = pol.approveKinds.includes(e.kind) ? ", needs approval" : "";
      return refs.map((r) => `${r} (${where.join(", ")}${approve})`);
    })
    .slice(0, 20);
  if (items.length === 0) return null;
  return `LaunchSafe Firewall: secrets are available by reference; write the reference where the value would go, in a shell command (double quotes or plain words, not single quotes) or in MCP arguments, and never ask for the value: ${items.join("; ")}.`;
}
