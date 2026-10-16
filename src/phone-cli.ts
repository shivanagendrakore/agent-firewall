/**
 * The phone-approval commands (docs/phone.md). `phone pair`
 * and `phone remove` change who may approve, so they run only for a person:
 * an interactive terminal not under an agent, and the approval passphrase
 * (the firewall's engine also refuses them from inside an agent). `phone
 * list` and `relay status` are read-only. `relay run` is the daemon a login
 * item starts; an agent starting it is refused like any changing command.
 *
 * Every dependency that touches the terminal, the network or the service
 * manager comes in through PhoneCliDeps, so tests run the real handlers
 * against a stub relay on 127.0.0.1 with scripted input.
 */

import { hostname } from "node:os";
import type { Parsed } from "./cliargs.js";
import type { Layout } from "./runtime/layout.js";
import type { RelayClient } from "./runtime/relay/client.js";
import type { Runner } from "./runtime/relay/loginitem.js";

type Ok = Extract<Parsed, { kind: "ok" }>;

export interface PhoneCliDeps {
  out: (s: string) => void;
  err: (s: string) => void;
  /** Writes a line unescaped (the QR code's colour codes). */
  raw: (s: string) => void;
  ansi: boolean;
  humanAtKeyboard: () => Promise<boolean>;
  readSecret: (prompt: string) => Promise<string>;
  ask: (prompt: string) => Promise<string>;
  /** The relay client for an API base (tests: one pointing at the stub relay). */
  client: (base: string, l: Layout) => RelayClient;
  run: Runner;
  platform: NodeJS.Platform;
  home?: string;
  sleep: (ms: number) => Promise<void>;
  now?: () => Date;
  /** relay run: stops the daemon (SIGINT/SIGTERM in the CLI; tests abort it). */
  signal?: AbortSignal;
  /** relay run: the daemon's timings (tests shorten them). */
  daemon?: { syncEveryMs?: number; waitSeconds?: number };
  /** phone pair: how long to wait and how often to ask the relay (tests shorten them). */
  pairing?: { pollMs?: number; timeoutMs?: number };
}

function flag(p: Ok, name: string): boolean {
  return p.flags.get(name) === true;
}

function opt(p: Ok, name: string): string | undefined {
  const v = p.flags.get(name);
  return typeof v === "string" ? v : undefined;
}

/** The person check and the approval passphrase. */
async function unlock(l: Layout, d: PhoneCliDeps): Promise<boolean> {
  const { approverPublicKey, unlockApprover } = await import("./runtime/approver.js");
  const { assertNotRealHome } = await import("./runtime/guard.js");
  assertNotRealHome(l.keys);
  if (!(await d.humanAtKeyboard())) return false;
  if (approverPublicKey(l) === null) {
    d.err('Phone approvals stand in for your approval passphrase, and none is set. In your own terminal run "launchsafe-firewall approver init" first.');
    return false;
  }
  try {
    unlockApprover(l, await d.readSecret("Approval passphrase: "));
    return true;
  } catch (e) {
    d.err(`${(e as Error).message}. Nothing was changed.`);
    return false;
  }
}

/** Re-pins every installed hook command (the approver key and the phones' list) and says what happened. */
async function repinLines(l: Layout): Promise<string[]> {
  const { repinApprover, readRecords } = await import("./runtime/install.js");
  const { adapterFor } = await import("./adapters/index.js");
  let recorded = 0;
  try {
    recorded = readRecords(l).length;
  } catch {
    recorded = 0;
  }
  const lines: string[] = [];
  if (recorded === 0) lines.push('The firewall is not installed yet: "launchsafe-firewall install" will pin the paired phones in the hook.');
  else {
    const r = repinApprover(l, (id) => adapterFor(id).settings);
    lines.push(r.updated.length > 0 ? `The hook now pins the paired phones in ${r.updated.join(", ")}.` : "The hook already pins the paired phones.");
    for (const k of r.skipped) lines.push(`Could not update ${k.path} (${k.reason}); run "launchsafe-firewall install" for that file, or phone approvals stay refused there.`);
  }
  // Item P: the gateway's wrapped servers carry the same pin (clients with no hook decide through them).
  const { repinGatewayEntries } = await import("./gateway/clients.js");
  const { phonesPinOf } = await import("./runtime/relay/phones.js");
  let pin: string | null = null;
  try {
    pin = phonesPinOf(l);
  } catch {
    pin = null;
  }
  try {
    const g = repinGatewayEntries(l, pin);
    if (g.updated.length > 0) lines.push(`Wrapped MCP servers now carry the pin in ${g.updated.join(", ")}; restart those clients. (A server run by "mcp serve" reads it when "mcp serve" starts.)`);
    for (const k of g.skipped) lines.push(`Could not update MCP server "${k.server}" in ${k.path} (${k.reason}); phone approvals are not honoured for it until it is wrapped again.`);
  } catch (e) {
    if (e instanceof Error && e.name === "RealHomeRefused") throw e;
    lines.push(`Could not update the gateway's wrapped servers (${(e as Error).message}); phone approvals are not honoured for them.`);
  }
  return lines;
}

async function relayOrigin(l: Layout): Promise<{ origin: string; enabled: boolean }> {
  const { loadPolicy } = await import("./runtime/config.js");
  const { phonePolicy } = await import("./policy-phone.js");
  // User and managed policy only: a repository cannot choose the relay.
  const p = phonePolicy(loadPolicy(l, []).config);
  return { origin: p.relayOrigin, enabled: p.enabled };
}

export async function phoneList(p: Ok, l: Layout, d: PhoneCliDeps): Promise<number> {
  const { loadPhones } = await import("./runtime/relay/phones.js");
  const { installedPhonePin } = await import("./runtime/relay/daemon.js");
  const { readRelayState } = await import("./runtime/relay/files.js");
  const s = loadPhones(l);
  if (s.state === "corrupt") {
    d.err(`${s.error}. Every phone approval is refused until it is fixed; run "launchsafe-firewall doctor".`);
    return 1;
  }
  const phones = s.state === "ok" ? s.file.phones : [];
  const installed = installedPhonePin(l);
  const pinned = s.state === "ok" && phones.length > 0 && installed.pin === s.hash;
  const st = readRelayState(l);
  if (flag(p, "--json")) {
    d.out(JSON.stringify({ pinned, phones: phones.map((x) => ({ label: x.label, credentialId: x.credentialId, alg: x.alg, origin: x.origin, pairedAt: x.pairedAt })), relay: { lastContactAt: st.lastContactAt ?? null, unreachableSince: st.unreachableSince ?? null, revoked: st.revoked ?? null } }, null, 2));
    return 0;
  }
  if (phones.length === 0) {
    d.out("No phone is paired. Phone approvals are experimental and need LaunchSafe's hosted relay, which is not available yet; approve in your terminal with launchsafe-firewall queue approve <id>.");
    return 0;
  }
  for (const x of phones) d.out(`${x.label}  ${x.credentialId.slice(0, 12)}  ${x.alg === -7 ? "ES256" : x.alg === -257 ? "RS256" : "EdDSA"}  ${x.origin}  paired ${x.pairedAt.slice(0, 10)}`);
  d.out(pinned ? "\nThe hook command pins these phones." : `\nWARNING: ${installed.pin === null ? (installed.reason ?? "the hook command does not pin them") : "keys/phones.json does not match the pin in the hook command"}: phone approvals are refused. Run "launchsafe-firewall doctor".`);
  if (st.revoked !== undefined) d.out("This machine was unpaired in the LaunchSafe app: pair again to receive phone decisions.");
  else if (st.unreachableSince !== undefined) d.out(`Phone relay unreachable since ${st.unreachableSince.slice(0, 16).replace("T", " ")}.`);
  return 0;
}

export async function phonePair(p: Ok, l: Layout, d: PhoneCliDeps): Promise<number> {
  const { pairPhone } = await import("./runtime/relay/pair.js");
  const { appendLog } = await import("./runtime/log.js");
  const { updateRelayState } = await import("./runtime/relay/files.js");
  const { installLoginItem } = await import("./runtime/relay/loginitem.js");
  const { safeLine } = await import("./engine/terminal.js");
  if (!(await unlock(l, d))) return 1;
  const { origin, enabled } = await relayOrigin(l);
  if (!enabled) {
    d.err("Phone approvals are switched off in your policy (phone.enabled is false).");
    return 1;
  }
  const label = safeLine(opt(p, "--label") ?? hostname().replace(/\.local$/, "")).slice(0, 64) || "this computer";
  d.out(`Pairing a phone through ${origin}. The phone creates a passkey just for approvals; LaunchSafe's relay only carries sealed items and signed decisions, and cannot approve anything.\n`);
  let r;
  try {
    r = await pairPhone({ l, client: d.client(origin, l), origin, machineLabel: label, out: d.out, raw: d.raw, ansi: d.ansi, confirm: async (q) => (await d.ask(q)).trim().toLowerCase() === "yes", sleep: d.sleep, ...(d.now !== undefined ? { now: d.now } : {}), ...(d.pairing?.pollMs !== undefined ? { pollMs: d.pairing.pollMs } : {}), ...(d.pairing?.timeoutMs !== undefined ? { timeoutMs: d.pairing.timeoutMs } : {}) });
  } catch (e) {
    if (e instanceof Error && e.name === "RealHomeRefused") throw e;
    d.err(`launchsafe-firewall phone pair: ${(e as Error).message}. Nothing was written.`);
    return 1;
  }
  if (!r.ok) {
    d.err(`Pairing stopped: ${r.reason}`);
    return 1;
  }
  updateRelayState(l, (s) => {
    const { revoked: _r, ...rest } = s;
    return rest;
  });
  appendLog(l, { type: "phone_paired", phone: r.phone.label, credential: r.phone.credentialId.slice(0, 16), alg: r.phone.alg, origin: r.phone.origin });
  d.out(`\nPaired "${r.phone.label}".`);
  for (const line of await repinLines(l)) d.out(line);
  if (!flag(p, "--no-login-item")) {
    const li = installLoginItem(l, { platform: d.platform, run: d.run, ...(d.home !== undefined ? { home: d.home } : {}) });
    d.out(li.ok ? `The relay daemon runs as a login item (${li.detail}).` : `The relay daemon is not running: ${li.detail}.`);
  } else d.out('Run the relay daemon yourself: launchsafe-firewall relay run');
  d.out('Held actions now also reach this phone (approval items only; proposed changes stay in the terminal). On an iPhone, add the approval app to your Home Screen to get notifications. Check with "launchsafe-firewall doctor".');
  return 0;
}

export async function phoneRemove(p: Ok, l: Layout, d: PhoneCliDeps): Promise<number> {
  const { loadPhones, writePhones } = await import("./runtime/relay/phones.js");
  const { appendLog } = await import("./runtime/log.js");
  const { removeLoginItem } = await import("./runtime/relay/loginitem.js");
  const s = loadPhones(l);
  const want = p.positionals[0] as string;
  if (s.state !== "ok" || s.file.phones.length === 0) {
    d.err(s.state === "corrupt" ? `${s.error}.` : "No phone is paired.");
    return 1;
  }
  const byLabel = s.file.phones.filter((x) => x.label === want);
  const byId = want.length >= 8 ? s.file.phones.filter((x) => x.credentialId.startsWith(want)) : [];
  const match = byLabel.length > 0 ? byLabel : byId;
  if (match.length !== 1) {
    d.err(match.length === 0 ? `No paired phone is called "${want}". Run: launchsafe-firewall phone list` : `Several phones are called "${want}": give the credential id from "launchsafe-firewall phone list".`);
    return 1;
  }
  const gone = match[0] as (typeof match)[number];
  if (!(await unlock(l, d))) return 1;
  const left = s.file.phones.filter((x) => x.credentialId !== gone.credentialId);
  writePhones(l, left);
  appendLog(l, { type: "phone_removed", phone: gone.label, credential: gone.credentialId.slice(0, 16) });
  d.out(`Removed "${gone.label}". Its decisions are no longer accepted.`);
  for (const line of await repinLines(l)) d.out(line);
  if (left.length === 0) {
    const li = removeLoginItem({ platform: d.platform, run: d.run, ...(d.home !== undefined ? { home: d.home } : {}) });
    if (li.path !== null && li.detail !== "no login item was installed") d.out(`No phone is left: the relay daemon's ${li.detail}.`);
  }
  d.out("Also remove it in the LaunchSafe app to stop its notifications.");
  return 0;
}

export async function relayStatus(p: Ok, l: Layout, d: PhoneCliDeps): Promise<number> {
  const { readRelayState, listOutbox } = await import("./runtime/relay/files.js");
  const { readDevice } = await import("./runtime/relay/keys.js");
  const st = readRelayState(l);
  let device = null;
  try {
    device = readDevice(l);
  } catch {
    device = null;
  }
  const out = listOutbox(l);
  const open = out.filter((r) => r.withdrawn === undefined).length;
  const data = { registered: device?.token !== undefined, relay: device?.relayOrigin ?? null, machine: device?.label ?? null, lastContactAt: st.lastContactAt ?? null, unreachableSince: st.unreachableSince ?? null, lastError: st.lastError ?? null, revoked: st.revoked ?? null, daemonHeartbeat: st.loopAt ?? null, itemsOnPhones: open, fairUse: st.fairUse ?? null };
  if (flag(p, "--json")) {
    d.out(JSON.stringify(data, null, 2));
    return 0;
  }
  if (!data.registered) {
    d.out("No phone is paired, so the relay is not used (no network).");
    return 0;
  }
  d.out(`Relay: ${data.relay ?? "?"} (this machine: ${data.machine ?? "?"})`);
  d.out(data.revoked !== null ? "This machine was unpaired in the LaunchSafe app." : data.unreachableSince !== null ? `Unreachable since ${data.unreachableSince.slice(0, 16).replace("T", " ")}: ${data.lastError ?? ""}` : `Last contact: ${data.lastContactAt?.slice(0, 16).replace("T", " ") ?? "never"}`);
  d.out(`Daemon heartbeat: ${data.daemonHeartbeat?.slice(0, 19).replace("T", " ") ?? "never"}; items on the phones: ${open}`);
  if (data.fairUse !== null) d.out(`Fair use: ${data.fairUse.message}`);
  return 0;
}

export async function relayRun(p: Ok, l: Layout, d: PhoneCliDeps): Promise<number> {
  const { readDevice } = await import("./runtime/relay/keys.js");
  const { runDaemon, syncOutbox, pollOnce } = await import("./runtime/relay/daemon.js");
  const { assertNotRealHome } = await import("./runtime/guard.js");
  assertNotRealHome(l.home);
  const device = readDevice(l);
  if (device?.token === undefined || device.relayOrigin === undefined) {
    d.err('No phone is paired: run "launchsafe-firewall phone pair" in your own terminal.');
    return 1;
  }
  const client = d.client(device.relayOrigin, l);
  const deps = { l, client, ...(d.now !== undefined ? { now: d.now } : {}), say: d.err };
  if (flag(p, "--once")) {
    const s = await syncOutbox(deps);
    const r = await pollOnce(deps, 0);
    d.out(`Sent ${s.uploaded} item(s), withdrew ${s.withdrawn}; ${r.applied} decision(s) applied, ${r.refused} refused.${s.skipped !== undefined ? ` (${s.skipped})` : ""}`);
    return 0;
  }
  const ac = new AbortController();
  const signal = d.signal ?? ac.signal;
  const onSignal = (): void => ac.abort();
  if (d.signal === undefined) {
    process.once("SIGINT", onSignal);
    process.once("SIGTERM", onSignal);
  }
  try {
    const why = await runDaemon(deps, { signal, ...(d.daemon?.syncEveryMs !== undefined ? { syncEveryMs: d.daemon.syncEveryMs } : {}), ...(d.daemon?.waitSeconds !== undefined ? { waitSeconds: d.daemon.waitSeconds } : {}) });
    if (why === "revoked") {
      d.err('This machine was unpaired in the LaunchSafe app. Pair again with "launchsafe-firewall phone pair".');
      return 1;
    }
    return 0;
  } finally {
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
  }
}

export const PHONE_HANDLERS: Record<string, (p: Ok, l: Layout, d: PhoneCliDeps) => Promise<number>> = {
  phone: phoneList,
  "phone list": phoneList,
  "phone pair": phonePair,
  "phone remove": phoneRemove,
  "phone unpair": phoneRemove,
  relay: relayStatus,
  "relay status": relayStatus,
  "relay run": relayRun,
};
