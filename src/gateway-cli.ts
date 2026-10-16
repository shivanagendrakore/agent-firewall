/**
 * The MCP gateway's commands (docs/gateway.md).
 *
 * - `mcp wrap` (started by an MCP client from its configuration) and `mcp
 *   serve` (person-run) are the gateway itself;
 * - `mcp wrap-config` / `mcp unwrap-config` rewrite a client's configuration:
 *   person-run (terminal, not under an agent, approval passphrase), with the
 *   diff shown first and a backup;
 * - `gateway reset` starts a new session for a client (person-run);
 * - `gateway status` and `gateway quarantine` list what is wrapped and what
 *   was withheld (read-only); `gateway quarantine show` prints withheld text,
 *   so it is person-only (an agent must never read it back).
 *
 * Terminal and stores come in through GatewayCliDeps so tests run the real
 * handlers in temporary homes.
 */

import { homedir } from "node:os";
import { join } from "node:path";
import type { Parsed } from "./cliargs.js";
import type { Layout } from "./runtime/layout.js";
import { installDir } from "./runtime/layout.js";
import { safeText } from "./engine/terminal.js";
import { isClient, type ClientId } from "./gateway/install.js";

type Ok = Extract<Parsed, { kind: "ok" }>;

export interface GatewayCliDeps {
  out: (s: string) => void;
  err: (s: string) => void;
  humanAtKeyboard: () => Promise<boolean>;
  readSecret: (prompt: string) => Promise<string>;
  ask: (prompt: string) => Promise<string>;
  env: NodeJS.ProcessEnv;
  cwd: string;
  platform: NodeJS.Platform;
  home: string;
  /** The node binary and CLI file written into wrapped entries (default: this process and this installation). */
  node?: string;
  cli?: string;
  /** Whether a terminal is attached (no message; default: stdin and stdout are TTYs). What is shown only to a person. */
  interactive?: () => boolean;
}

function interactive(d: GatewayCliDeps): boolean {
  return d.interactive?.() ?? (process.stdin.isTTY === true && process.stdout.isTTY === true);
}

/**
 * A configuration diff as printed: credentials masked always, and the lines themselves only in an interactive
 * terminal. The entries carry env values and headers (tokens an agent's script must never read back).
 */
async function shownDiff(d: GatewayCliDeps, diff: string): Promise<string> {
  if (!interactive(d)) return "  (the lines that change are shown only in an interactive terminal: the entries' env values and headers can hold credentials)";
  const { redactSecrets } = await import("./engine/secrets.js");
  return redactSecrets(diff).text;
}

/** The approval passphrase, when one is set (a person's command needs it then; without a key, the terminal check is all). */
async function passphraseIfSet(l: Layout, d: GatewayCliDeps): Promise<boolean> {
  const { approverPublicKey } = await import("./runtime/approver.js");
  let key: string | null;
  try {
    key = approverPublicKey(l);
  } catch {
    key = "unreadable";
  }
  return key === null ? true : passphraseOk(l, d);
}

const EXIT_USAGE = 64;
const flag = (p: Ok, n: string): boolean => p.flags.get(n) === true;
const opt = (p: Ok, n: string): string | undefined => {
  const v = p.flags.get(n);
  return typeof v === "string" ? v : undefined;
};

function clientOf(p: Ok, d: GatewayCliDeps, cmd: string): ClientId | null {
  const c = opt(p, "--client") ?? p.positionals[0];
  if (c === undefined || !isClient(c)) {
    d.err(`launchsafe-firewall ${cmd}: name a client with --client (claude-desktop, claude-code, cursor, codex, gemini, vscode)`);
    return null;
  }
  return c;
}

async function passphraseOk(l: Layout, d: GatewayCliDeps): Promise<boolean> {
  const { unlockApprover } = await import("./runtime/approver.js");
  try {
    unlockApprover(l, await d.readSecret("Approval passphrase: "));
    return true;
  } catch (e) {
    d.err(`The approval passphrase is needed for this (${(e as Error).message}). Set one with: launchsafe-firewall approver init`);
    return false;
  }
}

/** `mcp wrap … -- <command> <args…>`: the stdio gateway for one server. */
export async function mcpWrap(p: Ok, l: Layout, d: GatewayCliDeps): Promise<number> {
  const client = clientOf(p, d, "mcp wrap");
  const server = opt(p, "--server");
  if (client === null || server === undefined || p.positionals.length === 0) {
    d.err("launchsafe-firewall mcp wrap: usage: mcp wrap --client C --server NAME [--mode auto|full|hook] -- COMMAND [ARGS...]");
    return EXIT_USAGE;
  }
  const { runWrap } = await import("./gateway/stdio.js");
  const { PIN_RE } = await import("./runtime/relay/phones.js");
  const phones = opt(p, "--phones");
  const phonesPin = phones !== undefined && PIN_RE.test(phones) ? phones : undefined;
  if (phones !== undefined && phonesPin === undefined) d.err("launchsafe-firewall mcp wrap: the --phones pin is malformed, so phone approvals are refused here (terminal approvals still work).");
  const [command, ...args] = p.positionals as [string, ...string[]];
  return runWrap({ l, env: d.env, client, server, mode: (opt(p, "--mode") as "auto" | "full" | "hook" | undefined) ?? "auto", command, args, cwd: d.cwd, ...(phonesPin !== undefined ? { phonesPin } : {}), stdin: process.stdin, stdout: process.stdout, stderr: process.stderr, home: d.home });
}

/** `mcp serve`: the local Streamable HTTP gateway (127.0.0.1 only). */
export async function mcpServe(p: Ok, l: Layout, d: GatewayCliDeps): Promise<number> {
  if (!(await d.humanAtKeyboard())) return 1;
  const { startGatewayServer } = await import("./gateway/http.js");
  const { DEFAULT_PORT } = await import("./gateway/clients.js");
  const port = Number(opt(p, "--port") ?? DEFAULT_PORT);
  // The HTTP gateway has no wrapper command to carry the pin; it pins the paired phones' list as it is
  // when the person starts it (a phone paired or removed later needs a restart), unless the environment says.
  const { phonesPinOf } = await import("./runtime/relay/phones.js");
  const pin = d.env.LAUNCHSAFE_FIREWALL_PHONES !== undefined && d.env.LAUNCHSAFE_FIREWALL_PHONES !== "" ? null : phonesPinOf(l);
  const s = await startGatewayServer({ l, env: pin !== null ? { ...d.env, LAUNCHSAFE_FIREWALL_PHONES: pin } : d.env, port, cwd: d.cwd, home: d.home, diag: (x) => d.err(x) });
  // V14: one request's failure must not end the process (Node's default for an unhandled rejection), which
  // would take down every wrapped HTTP server and start each client on a fresh, untainted session. Requests
  // fail closed on their own (src/gateway/http.ts); this only reports what still slipped through.
  const guard = (e: unknown): void => d.err(`LaunchSafe Firewall gateway: an internal error was caught: ${safeText(e instanceof Error ? e.message : String(e))}`);
  process.on("unhandledRejection", guard);
  d.out(`LaunchSafe Firewall MCP gateway listening on http://127.0.0.1:${s.port} (this machine only). Press Ctrl-C to stop.`);
  await new Promise<void>((resolve) => {
    const stop = (): void => void s.close().then(resolve);
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
  process.off("unhandledRejection", guard);
  return 0;
}

/** `mcp wrap-config --client C [--server NAME…] [--dry-run] [--port N]`. */
export async function mcpWrapConfig(p: Ok, l: Layout, d: GatewayCliDeps): Promise<number> {
  const client = clientOf(p, d, "mcp wrap-config");
  if (client === null) return EXIT_USAGE;
  const { planWrap, applyPlan, lineDiff, linkTarget, DEFAULT_PORT } = await import("./gateway/clients.js");
  const servers = opt(p, "--server")?.split(",").map((s) => s.trim()).filter((s) => s !== "");
  const plans = planWrap({ l, client, node: d.node ?? process.execPath, cli: d.cli ?? join(installDir(), "dist", "cli.js"), port: Number(opt(p, "--port") ?? DEFAULT_PORT), ...(servers !== undefined ? { servers } : {}) }, { home: d.home, platform: d.platform, env: d.env });
  let refused = false;
  let todo = 0;
  for (const plan of plans) {
    for (const n of plan.file.notes) d.out(`Note: ${n}`);
    if (plan.before === null) {
      d.out(`${plan.file.path}: not found, nothing to wrap.`);
      continue;
    }
    if (plan.refused !== undefined) {
      refused = true;
      d.err(`${plan.file.path}: ${plan.refused.why}.`);
      if (plan.refused.snippet !== "") d.out(plan.refused.snippet);
      continue;
    }
    for (const s of plan.skipped) d.out(`${plan.file.path}: "${s.server}" left as it is (${s.why}).`);
    if (plan.after === null) continue;
    todo++;
    if (plan.wrapped.length > 0) d.out(`${plan.file.path}: wraps ${plan.wrapped.map((w) => `"${w.server}" (${w.mode} mode)`).join(", ")}:`);
    if (plan.fixed.length > 0) d.out(`${plan.file.path}: sets NODE_COMPILE_CACHE empty for the gateway in ${plan.fixed.map((f) => `"${f.server}"`).join(", ")} (wrapped before this was done; the server keeps its own value):`);
    d.out(await shownDiff(d, lineDiff(plan.before, plan.after)));
  }
  if (refused) return 1;
  if (todo === 0 || flag(p, "--dry-run")) return 0;
  if (!(await d.humanAtKeyboard())) return 1;
  if (!(await passphraseOk(l, d))) return 1;
  for (const plan of plans) {
    const link = plan.after !== null ? linkTarget(plan.file.path) : null;
    const backup = applyPlan(l, plan);
    if (link !== null) d.out(`${plan.file.path} is a symbolic link to ${link}: the change was written to that file and the link was kept.`);
    if (backup !== null) d.out(`Wrote ${plan.file.path} (backup: ${backup}). Restart ${client} to start its servers through the gateway.`);
  }
  if (plans.some((x) => x.wrapped.some((w) => w.upstream.kind === "http"))) d.out("HTTP servers now point at the local gateway: start it with launchsafe-firewall mcp serve.");
  return 0;
}

/** `mcp unwrap-config --client C [--dry-run]`: every recorded entry back to its original. */
export async function mcpUnwrapConfig(p: Ok, l: Layout, d: GatewayCliDeps): Promise<number> {
  const client = clientOf(p, d, "mcp unwrap-config");
  if (client === null) return EXIT_USAGE;
  const { planUnwrap, applyUnwrap, lineDiff, linkTarget } = await import("./gateway/clients.js");
  const plans = planUnwrap(l, client);
  if (plans.length === 0) {
    d.out(`Nothing of ${client} is wrapped.`);
    return 0;
  }
  for (const plan of plans) {
    for (const n of plan.notes) d.out(`Note: ${n}`);
    if (plan.refused !== undefined) {
      d.err(`${plan.file}: ${plan.refused.why}.`);
      if (plan.refused.snippet !== "") d.out(plan.refused.snippet);
      return 1;
    }
    if (plan.before !== null && plan.after !== null) d.out(`${plan.file}:\n${await shownDiff(d, lineDiff(plan.before, plan.after))}`);
  }
  if (flag(p, "--dry-run")) return 0;
  if (!(await d.humanAtKeyboard())) return 1;
  if (!(await passphraseOk(l, d))) return 1;
  for (const plan of plans) {
    const link = plan.after !== null ? linkTarget(plan.file) : null;
    const backup = applyUnwrap(l, plan);
    if (link !== null) d.out(`${plan.file} is a symbolic link to ${link}: the change was written to that file and the link was kept.`);
    d.out(`Restored ${plan.file}${backup !== null ? ` (backup: ${backup})` : ""}.`);
    for (const x of plan.savedPaths ?? []) d.out(`Saved the original of an entry you had edited: ${x}`);
  }
  return 0;
}

/** `gateway` / `gateway status`: what is wrapped, what is not, and what was withheld. Read-only. */
export async function gatewayStatus(p: Ok, l: Layout, d: GatewayCliDeps): Promise<number> {
  const { readGatewayInstall, hookInstalledFor, CLIENTS } = await import("./gateway/install.js");
  const { unwrappedServers } = await import("./gateway/clients.js");
  const { listRecords } = await import("./runtime/quarantine.js");
  let entries: import("./gateway/install.js").GatewayEntry[] = [];
  let problem: string | null = null;
  try {
    entries = readGatewayInstall(l).entries;
  } catch (e) {
    problem = (e as Error).message;
  }
  const cli = d.cli ?? join(installDir(), "dist", "cli.js");
  const unwrapped = CLIENTS.flatMap((c) => unwrappedServers({ l, client: c, cli, node: d.node ?? process.execPath }, { home: d.home, platform: d.platform, env: d.env }).map((u) => ({ client: c, ...u })));
  const withheld = listRecords(l).records.filter((r) => r.kind === "mcp_result");
  const warnings = entries.filter((e) => e.mode === "hook" && !hookInstalledFor(l, e.client)).map((e) => `"${e.server}" of ${e.client} was wrapped in hook mode but the firewall's hook for ${e.client} is not installed: it runs in full mode`);
  if (flag(p, "--json")) {
    d.out(JSON.stringify({ wrapped: entries.map((e) => ({ client: e.client, server: e.server, file: e.file, mode: e.mode, upstream: e.upstream.kind === "http" ? { kind: "http", url: e.upstream.url } : { kind: "stdio", command: e.upstream.command } })), unwrapped, withheld: withheld.length, warnings, ...(problem !== null ? { problem } : {}) }, null, 2));
    return 0;
  }
  if (problem !== null) d.err(`gateway/install.json is unreadable: ${problem}. Run "launchsafe-firewall doctor".`);
  d.out(entries.length === 0 ? "No MCP server is wrapped. Wrap a client's servers with: launchsafe-firewall mcp wrap-config --client <client>" : "Wrapped MCP servers:");
  for (const e of entries) d.out(`  ${e.client}  ${e.server}  ${e.mode} mode  ${e.upstream.kind === "http" ? e.upstream.url : e.upstream.command}`);
  for (const u of unwrapped) d.out(`Not wrapped: ${u.client} server "${u.server}" in ${u.file}`);
  for (const w of warnings) d.out(`Warning: ${w}`);
  d.out(`Results withheld so far: ${withheld.length}${withheld.length > 0 ? " (launchsafe-firewall gateway quarantine)" : ""}`);
  return 0;
}

/** `gateway reset <client>`: a new session for the client at once (person-run). */
export async function gatewayReset(p: Ok, l: Layout, d: GatewayCliDeps): Promise<number> {
  const client = clientOf(p, d, "gateway reset");
  if (client === null) return EXIT_USAGE;
  if (!(await d.humanAtKeyboard())) return 1;
  // A reset leaves a tainted session behind, so it is the approval passphrase's when one is set.
  if (!(await passphraseIfSet(l, d))) return 1;
  const { resetSession } = await import("./gateway/install.js");
  resetSession(l, client);
  d.out(`The next MCP call from ${client} starts a new gateway session (trusted until it reads outside content).`);
  return 0;
}

/** `gateway quarantine`: withheld results (metadata and an escaped preview; never the withheld text). */
export async function gatewayQuarantine(p: Ok, l: Layout, d: GatewayCliDeps): Promise<number> {
  const { listRecords } = await import("./runtime/quarantine.js");
  const { records, corrupt } = listRecords(l);
  const recs = records.filter((r) => r.kind === "mcp_result");
  // A damaged record cannot be told apart from a mail one: say so, as `mail quarantine` does (on stderr, so --json stays JSON).
  if (corrupt.length > 0) d.err(`Unreadable quarantine records: ${corrupt.join(", ")} (launchsafe-firewall doctor)`);
  if (flag(p, "--json")) {
    // The preview is the start of the withheld text: only for a person at a terminal, never for a script or an agent.
    const tty = interactive(d);
    d.out(JSON.stringify(recs.map(({ body: _body, preview, ...r }) => (tty ? { ...r, preview } : r)), null, 2));
    return 0;
  }
  if (recs.length === 0) d.out("Nothing withheld.");
  for (const r of recs) d.out(`${r.id}  ${r.createdAt.slice(0, 19)}  ${r.client ?? "?"}/${r.server ?? "?"}  ${r.tool ?? ""}  ${r.signals.join(", ")}  ${r.size} bytes`);
  return 0;
}

/** `gateway quarantine show <id>`: the withheld text, for a person in their own terminal only. */
export async function gatewayQuarantineShow(p: Ok, l: Layout, d: GatewayCliDeps): Promise<number> {
  if (!(await d.humanAtKeyboard())) return 1;
  const { escapeForTerminal, getRecord } = await import("./runtime/quarantine.js");
  let r: import("./runtime/quarantine.js").QuarantineRecord | null;
  try {
    r = getRecord(l, p.positionals[0] ?? "");
  } catch (e) {
    d.err(`launchsafe-firewall gateway quarantine show: the record cannot be read: ${(e as Error).message}`);
    return 1;
  }
  if (r === null || r.kind !== "mcp_result") {
    d.err(`launchsafe-firewall gateway quarantine show: no record ${p.positionals[0] ?? ""}`);
    return EXIT_USAGE;
  }
  d.out(`${r.id}: withheld from ${r.server ?? "?"} (${r.tool ?? ""}) for ${r.signals.join(", ")}. Invisible characters are shown escaped. Do not paste it into an agent.\n`);
  d.out(r.body !== undefined ? escapeForTerminal(r.body) : r.preview);
  return 0;
}

/** `mcp login <server>`: the gateway as an OAuth client of a wrapped HTTP server's authorization server. */
export async function mcpLogin(p: Ok, l: Layout, d: GatewayCliDeps): Promise<number> {
  if (!(await d.humanAtKeyboard())) return 1;
  const { loginInteractive } = await import("./gateway/oauth.js");
  return loginInteractive(l, p.positionals[0] ?? "", { out: d.out, err: d.err, readSecret: d.readSecret, ask: d.ask, env: d.env });
}

export const GATEWAY_HANDLERS: Record<string, (p: Ok, l: Layout, d: GatewayCliDeps) => Promise<number>> = {
  "mcp wrap": mcpWrap,
  "mcp serve": mcpServe,
  "mcp wrap-config": mcpWrapConfig,
  "mcp unwrap-config": mcpUnwrapConfig,
  "mcp login": mcpLogin,
  gateway: gatewayStatus,
  "gateway status": gatewayStatus,
  "gateway reset": gatewayReset,
  "gateway quarantine": gatewayQuarantine,
  "gateway quarantine show": gatewayQuarantineShow,
};

export const defaultHome = (): string => homedir();
