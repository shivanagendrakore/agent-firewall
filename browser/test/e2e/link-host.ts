/**
 * A stand-in for the local firewall's native messaging host, for the link e2e test. It speaks the link
 * protocol (design 10; src/worker/link-protocol.ts), records every message the extension sends to a file,
 * and answers as the firewall would. It is registered only in the test's temporary browser profile
 * (<user data dir>/NativeMessagingHosts), never in the person's own browser or home directory.
 */
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const HOST_JS = String.raw`
import { appendFileSync, readFileSync } from "node:fs";
const [record, control, origin] = process.argv.slice(2);
const cfg = JSON.parse(readFileSync(control, "utf8"));
appendFileSync(record, JSON.stringify({ type: "_started", origin }) + "\n");
let buf = Buffer.alloc(0);
let seq = 0;
let n = 0;
const nonce = () => "host-" + String(++n).padStart(8, "0");
function send(m) {
  const b = Buffer.from(JSON.stringify(m), "utf8");
  const h = Buffer.alloc(4);
  h.writeUInt32LE(b.length, 0);
  process.stdout.write(Buffer.concat([h, b]));
}
process.stdin.on("data", (c) => {
  buf = Buffer.concat([buf, c]);
  while (buf.length >= 4) {
    const len = buf.readUInt32LE(0);
    if (buf.length < 4 + len) return;
    const m = JSON.parse(buf.subarray(4, 4 + len).toString("utf8"));
    buf = buf.subarray(4 + len);
    appendFileSync(record, JSON.stringify(m) + "\n");
    if (m.type === "hello") {
      send({ type: "hello", re: m.nonce, version: 1, capabilities: cfg.capabilities, firewall: "0.3.0" });
      if (cfg.agentTaint) send({ type: "state.taint", nonce: nonce(), session: "agent-0123456789abcdef", reason: "agent_session_untrusted" });
    } else if (m.type === "log.append") send({ type: "log.ack", re: m.nonce, seq: ++seq });
    else if (m.type === "state.taint" || m.type === "approval.cancel") send({ type: "ack", re: m.nonce });
    else if (m.type === "approval.request") {
      send({ type: "approval.queued", re: m.nonce, id: "abcd2345" });
      if (cfg.approve) setTimeout(() => send({ type: "approval.result", nonce: nonce(), binding: m.binding, verdict: "approve", sig: "c2ln" }), 200);
    }
  }
});
process.stdin.on("end", () => process.exit(0));
`;

export interface TestHostOptions {
  capabilities: ("log" | "taint" | "approval")[];
  /** Report a tainted linked agent session right after the hello. */
  agentTaint: boolean;
  /** Answer every approval request with approve (as a person approving in the firewall's queue). */
  approve: boolean;
}

export interface TestHost {
  launcher: string;
  record: string;
  /** Every message the extension sent, in order (plus a first `_started` line with the origin Chrome passed). */
  messages(): Record<string, unknown>[];
}

/** Writes the stand-in host into `dir` (a temp folder) and returns its launcher. */
export function writeTestHost(dir: string, o: TestHostOptions): TestHost {
  mkdirSync(dir, { recursive: true });
  const script = join(dir, "host.mjs");
  const control = join(dir, "control.json");
  const record = join(dir, "record.jsonl");
  const launcher = join(dir, "launchsafe-test-host");
  writeFileSync(script, HOST_JS);
  writeFileSync(control, JSON.stringify(o));
  writeFileSync(record, "");
  const q = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;
  writeFileSync(launcher, `#!/bin/sh\nexec ${q(process.execPath)} ${q(script)} ${q(record)} ${q(control)} "$@"\n`);
  chmodSync(launcher, 0o755);
  return {
    launcher,
    record,
    messages: () =>
      readFileSync(record, "utf8")
        .split("\n")
        .filter((l) => l !== "")
        .map((l) => JSON.parse(l) as Record<string, unknown>),
  };
}

/** Registers the host for one extension in a temporary browser profile only. */
export function registerInProfile(profile: string, extensionId: string, launcher: string): string {
  if (!/^[a-p]{32}$/.test(extensionId)) throw new Error("not an extension id");
  const dir = join(profile, "NativeMessagingHosts");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, "com.launchsafe.agent_firewall.json");
  writeFileSync(path, JSON.stringify({ name: "com.launchsafe.agent_firewall", description: "LaunchSafe test host", path: launcher, type: "stdio", allowed_origins: [`chrome-extension://${extensionId}/`] }));
  return path;
}
