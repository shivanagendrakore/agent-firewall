/**
 * Test only: a paired machine in a temporary home, a stub relay on
 * 127.0.0.1, and a phone (a software authenticator plus the phone web app's
 * crypto, in Node) that scans the QR link, reads sealed items and signs
 * decisions exactly as the web app would.
 */
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdirSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { main } from "../../src/climain.js";
import { runHook, type HookEnv } from "../../src/hook/claude.js";
import { initApprover } from "../../src/runtime/approver.js";
import { install } from "../../src/runtime/install.js";
import { layout, type Layout } from "../../src/runtime/layout.js";
import { HttpRelayClient } from "../../src/runtime/relay/client.js";
import { installedPhonePin, type DaemonDeps } from "../../src/runtime/relay/daemon.js";
import { readDevice } from "../../src/runtime/relay/keys.js";
import { pairingMac, registrationChallenge, DECISION_TYPE, type DecisionMessage, type PairingAnswer, type PhoneItem, type RelayDecision, type SealedItem } from "../../src/runtime/relay/protocol.js";
import { displayHash, openSealed, rawP256 } from "../../src/runtime/relay/seal.js";
import { canonicalJson, sha256 } from "../../src/runtime/relay/util.js";
import { appendEvents, listQueue, type QueueItem } from "../../src/runtime/store.js";
import type { PhoneCliDeps } from "../../src/phone-cli.js";
import { VERSION } from "../../src/version.js";
import { testRoot } from "../helpers.js";
import { SoftAuthenticator, type Alg } from "./softauth.js";
import { startStubRelay, type StubRelay } from "./stub-relay.js";

export const PASS = "correct horse battery";
export const ORIGIN = "https://approve.launchsafe.com";
export const RP_ID = "approve.launchsafe.com";

const b64u = (b: Uint8Array): string => Buffer.from(b).toString("base64url");

export class TestPhone {
  readonly auth: SoftAuthenticator;
  readonly ecdhPriv: KeyObject;
  readonly ecdhRaw: Buffer;
  deviceSpki: Buffer | null = null;
  deviceId: string | null = null;
  constructor(
    readonly label = "Pixel",
    alg: Alg = "ES256",
    synced = false,
    readonly origin = ORIGIN,
    readonly rpId = RP_ID,
  ) {
    this.auth = new SoftAuthenticator(alg, synced);
    const k = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.ecdhPriv = k.privateKey;
    this.ecdhRaw = rawP256(k.publicKey);
  }

  /** Scans the pairing link: creates the approval passkey and MACs the answer with the secret from the fragment. */
  answer(link: string, deviceSpki: Buffer): { pairingId: string; answer: PairingAnswer; mac: string } {
    const frag = new URLSearchParams(link.slice(link.indexOf("#") + 1));
    const pairingId = frag.get("p") as string;
    const secret = Buffer.from(frag.get("s") as string, "base64url");
    const fp = frag.get("f") as string;
    if (sha256(deviceSpki).toString("hex").slice(0, 16) !== fp) throw new Error("fingerprint mismatch");
    this.deviceSpki = deviceSpki;
    const reg = this.auth.register({ rpId: this.rpId, origin: this.origin, challenge: registrationChallenge(pairingId, fp) });
    const answer: PairingAnswer = { credentialId: b64u(this.auth.credentialId), publicKey: b64u(this.auth.cose), attestationObject: b64u(reg.attestationObject), clientDataJSON: b64u(reg.clientDataJSON), phoneEcdhPub: b64u(this.ecdhRaw), label: this.label };
    return { pairingId, answer, mac: pairingMac(secret, answer, pairingId, deviceSpki) };
  }

  get credentialId(): string {
    return b64u(this.auth.credentialId);
  }

  /** The items the relay holds for this phone, opened (device signature checked first). */
  inbox(relay: StubRelay): { ref: string; item: PhoneItem; sealed: SealedItem }[] {
    return relay.items
      .filter((x) => x.credentialId === this.credentialId)
      .map((x) => {
        const sealed = JSON.parse(Buffer.from(x.sealed, "base64url").toString("utf8")) as SealedItem;
        return { ref: x.itemRef, sealed, item: openSealed(sealed, { phoneEcdhPriv: this.ecdhPriv, phoneEcdhPubRaw: this.ecdhRaw, deviceSpki: this.deviceSpki as Buffer, deviceId: this.deviceId ?? x.deviceId, itemRef: x.itemRef }) };
      });
  }

  /** Signs a decision as the approval screen does: challenge = SHA-256(canonicalJson(M)). */
  decide(entry: { ref: string; item: PhoneItem }, decision: "approve" | "reject", o: { issuedAt?: Date; uv?: boolean; origin?: string; counter?: number; m?: Partial<DecisionMessage>; display?: string } = {}): Omit<RelayDecision, "id"> {
    const it = entry.item;
    const msg: DecisionMessage = { v: 1, type: DECISION_TYPE, deviceId: it.deviceId, itemId: it.itemId, sessionTag: it.sessionTag, actionHash: it.actionHash, decision, displayHash: o.display ?? displayHash(it), nonce: it.nonce, issuedAt: (o.issuedAt ?? new Date()).toISOString(), ...(o.m ?? {}) };
    const m = canonicalJson(msg);
    const a = this.auth.assert({ rpId: this.rpId, origin: o.origin ?? this.origin, challenge: sha256(m), ...(o.uv !== undefined ? { uv: o.uv } : {}), ...(o.counter !== undefined ? { counter: o.counter } : {}) });
    return { itemRef: entry.ref, credentialId: this.credentialId, m, authenticatorData: b64u(a.authenticatorData), clientDataJSON: b64u(a.clientDataJSON), signature: b64u(a.signature) };
  }
}

export interface Machine {
  l: Layout;
  home: string;
  ws: string;
  relay: StubRelay;
  phone: TestPhone;
  approver: string;
  runs: { cmd: string; args: readonly string[] }[];
  /** The hook environment (pins as the installed hook command carries them). */
  hookEnv: (over?: Partial<HookEnv>) => HookEnv;
  daemon: (over?: Partial<DaemonDeps>) => DaemonDeps;
  cli: (args: string[], o?: { answers?: string[]; secrets?: string[]; human?: boolean; deps?: Partial<PhoneCliDeps> }) => Promise<{ status: number; stdout: string; stderr: string }>;
  pin: () => string | null;
}

export function phoneDeps(m: { relay: StubRelay; home: string; runs: { cmd: string; args: readonly string[] }[] }, secrets: string[], answers: string[], human = true): Partial<PhoneCliDeps> {
  return {
    humanAtKeyboard: () => Promise.resolve(human),
    readSecret: () => Promise.resolve(secrets.shift() ?? ""),
    ask: () => Promise.resolve(answers.shift() ?? ""),
    client: (_base, l) => new HttpRelayClient({ base: m.relay.url, device: () => readDevice(l) ?? (() => { throw new Error("no device"); })() }),
    run: (cmd, args) => {
      m.runs.push({ cmd, args });
      return { status: 0, stderr: "" };
    },
    platform: "darwin",
    home: m.home,
    ansi: false,
    sleep: (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 5))),
    pairing: { pollMs: 5, timeoutMs: 10000 },
  };
}

/** A machine with the firewall installed (Claude Code, user scope, temp home) and an approval passphrase. */
export async function machine(o: { alg?: Alg; synced?: boolean; label?: string; pair?: boolean; phoneOrigin?: string } = {}): Promise<Machine> {
  const root = mkdtempSync(join(testRoot(), "phone-"));
  const home = join(root, "home");
  const ws = join(root, "ws");
  mkdirSync(ws, { recursive: true });
  const l = layout(join(home, ".launchsafe-firewall"));
  const approver = initApprover(l, PASS);
  install(l, "user", ws, VERSION, { home });
  const relay = await startStubRelay();
  const phone = new TestPhone(o.label ?? "Pixel", o.alg ?? "ES256", o.synced ?? false, o.phoneOrigin ?? ORIGIN);
  const runs: { cmd: string; args: readonly string[] }[] = [];
  const m: Machine = {
    l,
    home,
    ws,
    relay,
    phone,
    approver,
    runs,
    pin: () => installedPhonePin(l).pin,
    hookEnv: (over = {}) => ({ env: { CLAUDE_PROJECT_DIR: ws, LAUNCHSAFE_FIREWALL_APPROVER: approver, ...(m.pin() !== null ? { LAUNCHSAFE_FIREWALL_PHONES: m.pin() as string } : {}) }, layout: l, home, detectNonInteractive: () => true, notifyDeps: { platform: "darwin", spawn: () => undefined, executable: () => true }, ...over }),
    daemon: (over = {}) => ({ l, client: new HttpRelayClient({ base: relay.url, device: () => readDevice(l) ?? (() => { throw new Error("no device"); })() }), ...over }),
    async cli(args, c = {}) {
      let stdout = "";
      let stderr = "";
      const status = await main(args, l, { write: (fd, s) => (fd === 1 ? (stdout += s) : (stderr += s)), humanAtKeyboard: () => Promise.resolve(c.human ?? true), phone: { ...phoneDeps(m, [...(c.secrets ?? [PASS])], [...(c.answers ?? ["yes"])], c.human ?? true), ...(c.deps ?? {}) } });
      return { status, stdout, stderr };
    },
  };
  if (o.pair !== false) {
    const r = await pairWith(m, m.phone);
    if (r.status !== 0) throw new Error(`pairing failed: ${r.stderr}`);
  }
  return m;
}

/** Runs `phone pair` and plays the phone: waits for the link in the output, then claims the pairing on the relay. */
export async function pairWith(m: Machine, phone: TestPhone, o: { answers?: string[]; beforeClaim?: () => void; args?: string[] } = {}): Promise<{ status: number; stdout: string; stderr: string }> {
  let stdout = "";
  let stderr = "";
  let done = false;
  const run = main(["phone", "pair", ...(o.args ?? [])], m.l, {
    write: (fd, s) => (fd === 1 ? (stdout += s) : (stderr += s)),
    humanAtKeyboard: () => Promise.resolve(true),
    phone: phoneDeps(m, [PASS], o.answers ?? ["yes"]),
  }).then((status) => {
    done = true;
    return status;
  });
  for (let i = 0; i < 2000 && !done; i++) {
    const link = /https:\/\/approve\.launchsafe\.com\/firewall\/pair#\S+/.exec(stdout)?.[0];
    if (link !== undefined) {
      const dev = readDevice(m.l);
      const a = phone.answer(link, Buffer.from(dev?.signPub ?? "", "base64url"));
      o.beforeClaim?.();
      m.relay.claim(a.pairingId, a.answer, a.mac);
      break;
    }
    await new Promise((r) => setTimeout(r, 2));
  }
  const status = await run;
  if (status === 0) {
    phone.deviceId = readDevice(m.l)?.deviceId ?? null;
  }
  return { status, stdout, stderr };
}

/** An unattended, untrusted session asks to push: FW-SEND, held in the queue. Returns the queue item. */
export function queueSend(m: Machine, session = "s1", command = "git push origin main", over: Partial<HookEnv> = {}): { item: QueueItem; out: string } {
  appendEvents(m.l, session, [{ type: "taint", source: "read the web page https://example.com/issue" }]);
  const r = runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: session, cwd: m.ws, permission_mode: "default", tool_name: "Bash", tool_input: { command } }), m.hookEnv(over));
  const item = listQueue(m.l).items.filter((i) => i.status === "pending" && i.sessionId === session).pop();
  if (item === undefined) throw new Error(`nothing was queued: ${r.stdout} ${r.stderr}`);
  return { item, out: r.stdout };
}

/** The hook's answer to the same call again (the agent's retry). */
export function retry(m: Machine, session = "s1", command = "git push origin main", over: Partial<HookEnv> = {}): { d: string | undefined; reason: string; raw: ReturnType<typeof runHook> } {
  const r = runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: session, cwd: m.ws, permission_mode: "default", tool_name: "Bash", tool_input: { command } }), m.hookEnv(over));
  const o = r.stdout.trim() === "" ? {} : (JSON.parse(r.stdout) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } });
  return { d: o.hookSpecificOutput?.permissionDecision ?? (r.exitCode === 0 && r.stdout.trim() === "" ? "allow" : undefined), reason: o.hookSpecificOutput?.permissionDecisionReason ?? "", raw: r };
}
