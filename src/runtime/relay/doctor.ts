/**
 * Doctor's phone-approval checks. Nothing is checked (and nothing changes)
 * until a phone is paired. Then: the paired phones' list matches the pin in
 * every installed hook command, the relay registration is live (not revoked
 * in the app, reachable, within fair use, items sealable), the daemon is
 * running, the wall clock did not jump back, and the hold the policy asks
 * for fits each installed agent's hook timeout. Not part of the protection
 * score: phone approvals add a channel, they do not add protection.
 */

import { phonePolicy } from "../../policy-phone.js";
import type { AgentId } from "../../adapters/types.js";
import type { FirewallConfig } from "../../types.js";
import type { Check } from "../doctor.js";
import { readRecords } from "../install.js";
import type { Layout } from "../layout.js";
import { wrappedPhonePins } from "../../gateway/clients.js";
import { installedPhonePin } from "./daemon.js";
import { readRelayState } from "./files.js";
import { holdCapSeconds, hookTimeoutSeconds } from "./hold.js";
import { readDevice } from "./keys.js";
import { loadPhones } from "./phones.js";

export interface PhoneDoctorOptions {
  now?: Date;
  /** Whether a process id is alive (tests pass a fake). */
  alive?: (pid: number) => boolean;
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

export function phoneChecks(l: Layout, cfg: Pick<FirewallConfig, "phone">, o: PhoneDoctorOptions = {}): Check[] {
  const now = o.now ?? new Date();
  const phones = loadPhones(l);
  let device: ReturnType<typeof readDevice> = null;
  let deviceError: string | null = null;
  try {
    device = readDevice(l);
  } catch (e) {
    deviceError = (e as Error).message;
  }
  const installed = installedPhonePin(l);
  if (phones.state === "absent" && installed.pin === null && device?.token === undefined && deviceError === null) return [];
  const checks: Check[] = [];
  const pol = phonePolicy(cfg);
  // The pin.
  if (phones.state === "corrupt") checks.push({ name: "phone pin", status: "fail", detail: `${phones.error}: every phone approval is refused (terminal approvals still work)` });
  else if (phones.state === "absent" || phones.file.phones.length === 0) checks.push(installed.pin !== null ? { name: "phone pin", status: "fail", detail: "the hook command pins paired phones but keys/phones.json is missing or empty: every phone approval is refused" } : { name: "phone pin", status: "ok", detail: "no phone is paired" });
  else if (installed.pin === null) checks.push({ name: "phone pin", status: "fail", detail: `${phones.file.phones.length} phone(s) in keys/phones.json, but ${installed.reason ?? "the hook command does not pin them"}: phone approvals are refused. Run "launchsafe-firewall install" again (or phone pair) in your own terminal` });
  else if (installed.pin !== phones.hash) checks.push({ name: "phone pin", status: "fail", detail: "keys/phones.json does not match the pin in the hook command (changed without phone pair or phone remove): every phone approval is refused" });
  else checks.push({ name: "phone pin", status: "ok", detail: `${phones.file.phones.length} phone(s) paired and pinned: ${phones.file.phones.map((p) => p.label).join(", ")}` });
  // Item P: a wrapped MCP server that does not carry the list's pin ignores phone approvals (the terminal decides).
  if (phones.state === "ok" && phones.file.phones.length > 0) {
    const w = wrappedPhonePins(l);
    const behind = w.pins.filter((x) => x !== phones.hash).length;
    if (behind > 0) checks.push({ name: "phone pin (gateway)", status: "warn", detail: `${behind} wrapped MCP server(s) do not carry the paired phones' pin, so phone approvals are not honoured for them (the terminal still decides). Run "launchsafe-firewall mcp unwrap-config --client <client>" and "mcp wrap-config" again` });
  }
  if (!pol.enabled) checks.push({ name: "phone approvals", status: "warn", detail: "switched off by phone.enabled: phone decisions are ignored" });
  // The relay registration and the daemon.
  const st = readRelayState(l);
  if (deviceError !== null) checks.push({ name: "phone relay", status: "fail", detail: deviceError });
  else if (st.revoked !== undefined) checks.push({ name: "phone relay", status: "fail", detail: `this machine was unpaired in the LaunchSafe app (${st.revoked.slice(0, 16).replace("T", " ")}): pair again with "launchsafe-firewall phone pair"` });
  else if (device?.token === undefined || device.deviceId === undefined) checks.push({ name: "phone relay", status: "fail", detail: 'this machine has no relay registration: run "launchsafe-firewall phone pair" in your own terminal' });
  else if (st.sealError !== undefined) checks.push({ name: "phone relay", status: "fail", detail: `items are not sent to the phone: ${st.sealError.message}` });
  else if (st.unreachableSince !== undefined) checks.push({ name: "phone relay", status: "warn", detail: `phone relay unreachable since ${st.unreachableSince.slice(0, 16).replace("T", " ")} (${st.lastError ?? "no answer"}); terminal approvals are unaffected` });
  else if (st.fairUse !== undefined && now.getTime() - Date.parse(st.fairUse.at) < 86400000) checks.push({ name: "phone relay", status: "warn", detail: `the relay refused items under its fair-use limits: ${st.fairUse.message}` });
  else checks.push({ name: "phone relay", status: "ok", detail: st.lastContactAt !== undefined ? `${device.relayOrigin ?? pol.relayOrigin}, last contact ${st.lastContactAt.slice(0, 16).replace("T", " ")}` : `${device.relayOrigin ?? pol.relayOrigin}, not contacted yet` });
  const alive = o.alive ?? processAlive;
  const beat = st.loopAt !== undefined ? now.getTime() - Date.parse(st.loopAt) : Infinity;
  if (st.pid !== undefined && alive(st.pid) && beat < 120_000) checks.push({ name: "phone relay daemon", status: "ok", detail: `running (pid ${st.pid})` });
  else checks.push({ name: "phone relay daemon", status: "fail", detail: 'phone relay daemon not running: phone approvals cannot arrive. It is a login item after phone pair; or run "launchsafe-firewall relay run" in your own terminal' });
  if (st.clockBackwards !== undefined && now.getTime() - Date.parse(st.clockBackwards.at) < 86400000) checks.push({ name: "phone clock", status: "warn", detail: `the clock moved back ${st.clockBackwards.minutes} minutes; approval windows were longer by that much` });
  // The hold must fit every installed agent's hook timeout.
  if (pol.holdSeconds > 0) {
    let agents: AgentId[] = [];
    try {
      agents = [...new Set(readRecords(l).map((r) => r.agent ?? "claude"))];
    } catch {
      agents = ["claude"];
    }
    const over = agents.filter((a) => pol.holdSeconds > holdCapSeconds(a));
    checks.push(over.length === 0 ? { name: "phone hold", status: "ok", detail: `calls wait up to ${pol.holdSeconds} s for the phone` } : { name: "phone hold", status: "warn", detail: over.map((a) => `phone.holdSeconds ${pol.holdSeconds} is capped at ${holdCapSeconds(a)} s for ${a} (hook timeout ${hookTimeoutSeconds(a)} s${a === "codex" || a === "gemini" ? `; ${a} lets the call run when a hook times out` : ""})`).join("; ") });
  }
  return checks;
}
