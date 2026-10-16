/**
 * Phone approvals, pairing (docs/phone.md): P1 full pairing with the stub relay, P2 a relay that swaps the
 * phone's passkey, P3 pairing from inside an agent or without a terminal, and the other ways it stops
 * with nothing written (no "yes", a wrong passphrase, an answer for another site).
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { bash, explain } from "../helpers.js";
import { doctor } from "../../src/runtime/doctor.js";
import { installedHookCommands } from "../../src/runtime/install.js";
import { readDevice } from "../../src/runtime/relay/keys.js";
import { loginItemPath } from "../../src/runtime/relay/loginitem.js";
import { loadPhones, phonesPath } from "../../src/runtime/relay/phones.js";
import { comparisonCode } from "../../src/runtime/relay/protocol.js";
import { tailLog } from "../../src/runtime/log.js";
import { machine, pairWith, TestPhone } from "./harness.js";

describe("phone pair", () => {
  it("P1: pairs through the relay: phones.json written, every hook command re-pinned, login item installed, doctor ok", async () => {
    const m = await machine();
    const s = loadPhones(m.l);
    expect(s.state).toBe("ok");
    if (s.state !== "ok") return;
    expect(s.file.phones).toHaveLength(1);
    expect(s.file.phones[0]).toMatchObject({ label: "Pixel", alg: -7, rpId: "approve.launchsafe.com", origin: "https://approve.launchsafe.com", credentialId: m.phone.credentialId });
    expect((readFileSync(phonesPath(m.l)).length > 0)).toBe(true);
    const cmds = installedHookCommands(m.l).commands;
    expect(cmds.length).toBeGreaterThan(0);
    for (const c of cmds) expect(c.command).toContain(`LAUNCHSAFE_FIREWALL_PHONES='${s.hash}'`);
    // The approver pin is kept, and the phones pin follows it.
    for (const c of cmds) expect(c.command).toMatch(/LAUNCHSAFE_FIREWALL_APPROVER='[^']+' LAUNCHSAFE_FIREWALL_PHONES='sha256:[0-9a-f]{64}' /);
    const dev = readDevice(m.l);
    expect(dev?.deviceId).toBeDefined();
    expect(dev?.token).toMatch(/^tok_/);
    // The daemon as a launchd agent, through the (fake) service manager.
    expect(existsSync(loginItemPath("darwin", m.home) as string)).toBe(true);
    expect(m.runs.some((r) => r.cmd === "launchctl" && r.args[0] === "bootstrap")).toBe(true);
    expect(readFileSync(loginItemPath("darwin", m.home) as string, "utf8")).toContain("<string>relay</string>\n    <string>run</string>");
    const checks = doctor(m.l, m.ws, { home: m.home });
    expect(checks.find((c) => c.name === "phone pin")).toMatchObject({ status: "ok" });
    expect(tailLog(m.l, 5).some((e) => e.event.type === "phone_paired")).toBe(true);
    await m.relay.close();
  });

  it("P1: the comparison code and the label are shown before the person types yes", async () => {
    const m = await machine({ pair: false });
    const r = await pairWith(m, m.phone);
    expect(r.status).toBe(0);
    const link = /https:\/\/approve\.launchsafe\.com\/firewall\/pair#\S+/.exec(r.stdout)?.[0] as string;
    const secret = Buffer.from(new URLSearchParams(link.split("#")[1]).get("s") as string, "base64url");
    const code = comparisonCode(secret, Buffer.from(readDevice(m.l)?.signPub ?? "", "base64url"));
    expect(r.stdout).toContain(`Comparison code: ${code}`);
    expect(code).toMatch(/^[A-Z2-7]{4}-[A-Z2-7]{4}$/);
    await m.relay.close();
  });

  it("P2: a relay that swaps in its own passkey key is caught by the MAC: refused, nothing written", async () => {
    const m = await machine({ pair: false });
    const attacker = new TestPhone("attacker");
    m.relay.tamperAnswer = (a) => ({ ...a, publicKey: Buffer.from(attacker.auth.cose).toString("base64url") });
    const r = await pairWith(m, m.phone);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/MAC/);
    expect(existsSync(phonesPath(m.l))).toBe(false);
    for (const c of installedHookCommands(m.l).commands) expect(c.command).not.toContain("LAUNCHSAFE_FIREWALL_PHONES");
    expect(readDevice(m.l)?.token).toBeUndefined();
    await m.relay.close();
  });

  it("P2: a whole answer replaced by the relay (its own passkey and ECDH key, its own MAC) is refused", async () => {
    const m = await machine({ pair: false });
    const attacker = new TestPhone("attacker");
    m.relay.tamperAnswer = (a) => ({ ...a, credentialId: attacker.credentialId, phoneEcdhPub: Buffer.from(attacker.ecdhRaw).toString("base64url") });
    const r = await pairWith(m, m.phone);
    expect(r.status).toBe(1);
    expect(existsSync(phonesPath(m.l))).toBe(false);
    await m.relay.close();
  });

  it("a passkey created on another origin (the main app) is refused", async () => {
    const m = await machine({ pair: false });
    const r = await pairWith(m, new TestPhone("Pixel", "ES256", false, "https://app.launchsafe.com", "approve.launchsafe.com"));
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/origin/);
    expect(existsSync(phonesPath(m.l))).toBe(false);
    await m.relay.close();
  });

  it("without yes, nothing is written and the relay is not confirmed", async () => {
    const m = await machine({ pair: false });
    const r = await pairWith(m, m.phone, { answers: ["no"] });
    expect(r.status).toBe(1);
    expect(existsSync(phonesPath(m.l))).toBe(false);
    expect(m.relay.devices).toHaveLength(0);
    await m.relay.close();
  });

  it("a wrong passphrase stops before anything reaches the relay", async () => {
    const m = await machine({ pair: false });
    const r = await m.cli(["phone", "pair"], { secrets: ["wrong passphrase!"] });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/wrong approval passphrase/);
    expect(m.relay.requests).toHaveLength(0);
    await m.relay.close();
  });

  it("P3: from inside an agent or without a terminal, phone pair is refused before anything happens", async () => {
    const m = await machine({ pair: false });
    const r = await m.cli(["phone", "pair"], { human: false });
    expect(r.status).toBe(1);
    expect(m.relay.requests).toHaveLength(0);
    expect(existsSync(join(m.l.keys, "relay-device.json"))).toBe(false);
    await m.relay.close();
  });

  it("P3: an agent's tool call running phone pair, phone remove or relay run is FW-TAMPER; phone list is not", () => {
    for (const c of ["launchsafe-firewall phone pair", "launchsafe-firewall phone remove Pixel", "launchsafe-firewall phone unpair Pixel", "launchsafe-firewall relay run", "npx launchsafe-firewall phone pair --label x"]) {
      const d = bash(c);
      expect(d.verdict, `${c}: ${explain(d)}`).toBe("deny");
      expect(d.rules, c).toContain("FW-TAMPER");
    }
    for (const c of ["launchsafe-firewall phone list", "launchsafe-firewall phone", "launchsafe-firewall relay status --json", "launchsafe-firewall phone pair --help"]) expect(bash(c).verdict, c).toBe("allow");
  });

  it("an agent stopping the relay daemon (kill, launchctl, systemctl) is FW-TAMPER", () => {
    for (const c of ['pkill -f "relay run"', "pkill -f launchsafe-firewall", "launchctl bootout gui/501/com.launchsafe-firewall.relay", "systemctl --user stop launchsafe-firewall-relay.service", "launchctl unload ~/Library/LaunchAgents/com.launchsafe-firewall.relay.plist"]) {
      const d = bash(c);
      expect(d.rules, `${c}: ${explain(d)}`).toContain("FW-TAMPER");
    }
    expect(bash("launchctl list").verdict).toBe("allow");
  });

  it("a second phone joins the same device registration, and both are pinned", async () => {
    const m = await machine();
    const second = new TestPhone("iPad", "EdDSA");
    const r = await pairWith(m, second);
    expect(r.status, r.stderr).toBe(0);
    expect(m.relay.devices).toHaveLength(1);
    const s = loadPhones(m.l);
    expect(s.state === "ok" && s.file.phones.map((p) => p.label)).toEqual(["Pixel", "iPad"]);
    for (const c of installedHookCommands(m.l).commands) expect(c.command).toContain(s.state === "ok" ? s.hash : "x");
    await m.relay.close();
  });

  it("phone remove drops the phone, re-pins, and removes the login item with the last phone", async () => {
    const m = await machine();
    const before = m.pin();
    const r = await m.cli(["phone", "remove", "Pixel"]);
    expect(r.status, r.stderr).toBe(0);
    expect(m.pin()).toBeNull();
    expect(before).not.toBeNull();
    for (const c of installedHookCommands(m.l).commands) expect(c.command).not.toContain("LAUNCHSAFE_FIREWALL_PHONES");
    expect(existsSync(loginItemPath("darwin", m.home) as string)).toBe(false);
    expect(m.runs.some((x) => x.cmd === "launchctl" && x.args[0] === "bootout")).toBe(true);
    const list = await m.cli(["phone", "list"]);
    expect(list.stdout).toMatch(/No phone is paired/);
    await m.relay.close();
  });

  it("phone list shows the paired phones and whether the hook pins them, without a passphrase", async () => {
    const m = await machine();
    const r = await m.cli(["phone", "list", "--json"], { secrets: [] });
    const j = JSON.parse(r.stdout) as { pinned: boolean; phones: { label: string }[] };
    expect(j.pinned).toBe(true);
    expect(j.phones.map((p) => p.label)).toEqual(["Pixel"]);
    await m.relay.close();
  });
});
