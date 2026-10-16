/**
 * The browser link end to end through the built CLI, in a temporary home: install --browser writes the
 * manifest in the browser's per-user directory; the launcher it names, fed native messaging frames the
 * way the browser sends them, puts browser decisions into the log that `log verify` checks; doctor reports
 * the link; the hook links a session that drives the browser and gives it the browser's taint.
 */

import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runHook } from "../../src/hook/claude.js";
import { layout } from "../../src/runtime/layout.js";
import { recordBrowserTaint } from "../../src/runtime/native/link.js";
import { loadState } from "../../src/runtime/store.js";
import { bash, spawnCli, spawnCliBytes, spawnLauncherBytes, tempHome } from "../helpers.js";

const ID = "d".repeat(32);
const ORIGIN = `chrome-extension://${ID}/`;

function frame(v: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(v), "utf8");
  const head = Buffer.alloc(4);
  head.writeUInt32LE(body.length, 0);
  return Buffer.concat([head, body]);
}

function frames(out: Buffer): Record<string, unknown>[] {
  const res: Record<string, unknown>[] = [];
  let at = 0;
  while (at + 4 <= out.length) {
    const n = out.readUInt32LE(at);
    res.push(JSON.parse(out.subarray(at + 4, at + 4 + n).toString("utf8")) as Record<string, unknown>);
    at += 4 + n;
  }
  return res;
}

const hello = { type: "hello", nonce: "hello-001", version: 1, capabilities: ["gate"], extension: "0.0.1" };
const entry = { seq: 0, hash: "1".repeat(64), prevHash: "0".repeat(64), at: 1760000000000, site: "shop.test", actionClass: "payment", verdict: "approve", rules: ["gate.payment"] };

describe("install --browser and the launcher it writes", () => {
  it("installs, serves the browser, and log verify covers the browser's decisions", () => {
    const home = tempHome();
    const r = spawnCli(["install", "--browser", "chrome", "--extension-id", ID], { home });
    expect(r.stderr).toBe("");
    expect(r.status).toBe(0);
    const dir = process.platform === "darwin" ? join(home, "Library", "Application Support", "Google", "Chrome", "NativeMessagingHosts") : join(home, ".config", "google-chrome", "NativeMessagingHosts");
    const manifest = JSON.parse(readFileSync(join(dir, "com.launchsafe.agent_firewall.json"), "utf8")) as { path: string; allowed_origins: string[] };
    expect(manifest.allowed_origins).toEqual([ORIGIN]);
    expect(existsSync(join(home, ".claude", "settings.json"))).toBe(false);

    const served = spawnLauncherBytes(manifest.path, [ORIGIN], { home, input: Buffer.concat([frame(hello), frame({ type: "log.append", nonce: "log-00001", entry })]) });
    expect(served.stderr).toBe("");
    expect(served.status).toBe(0);
    expect(frames(served.stdout).map((m) => m.type)).toEqual(["hello", "log.ack"]);

    const v = spawnCli(["log", "verify"], { home });
    expect(v.status).toBe(0);
    expect(spawnCli(["log", "tail", "10"], { home }).stdout).toContain('"type":"browser_decision"');

    const d = JSON.parse(spawnCli(["doctor", "--json"], { home }).stdout) as { name: string; status: string }[];
    expect(d.find((c) => c.name === "browser link (chrome)")).toMatchObject({ status: "ok" });
  });

  it("the host refuses an extension the install did not allow, and fails closed on a bad frame", () => {
    const home = tempHome();
    expect(spawnCli(["install", "--browser", "chrome", "--extension-id", ID], { home }).status).toBe(0);
    const other = spawnCliBytes(["native-host", `chrome-extension://${"e".repeat(32)}/`], { home, input: frame(hello) });
    expect(other.status).toBe(1);
    expect(frames(other.stdout)).toEqual([{ type: "error", code: "refused", message: expect.stringContaining("not allowed") }]);
    const bad = spawnCliBytes(["native-host", ORIGIN], { home, input: Buffer.concat([frame(hello), frame({ type: "run", nonce: "x-0000001" })]) });
    expect(bad.status).toBe(1);
    expect(frames(bad.stdout).map((m) => m.type)).toEqual(["hello", "error"]);
  });

  it("refuses --browser with agent options, and the browser options without --browser", () => {
    expect(spawnCli(["install", "--browser", "chrome", "--extension-id", ID, "--agent", "claude"]).status).toBe(64);
    expect(spawnCli(["install", "--extension-id", ID]).status).toBe(64);
    expect(spawnCli(["install", "--browser", "safari", "--extension-id", ID]).status).toBe(64);
    expect(spawnCli(["install", "--browser", "chrome", "--extension-id", "nope"]).status).toBe(1);
    expect(spawnCli(["uninstall", "--browser", "chrome", "--purge"]).status).toBe(64);
  });

  it("an agent may not start the host (it changes the log and taint)", () => {
    const r = spawnCli(["native-host", "--help"]);
    expect(r.stdout).toContain("refuses it when an agent runs it");
  });
});

describe("the hook links a session that drives the browser", () => {
  it("a Claude in Chrome call after a browser taint makes the session untrusted for that very call", () => {
    const root = mkdtempSync(join(tmpdir(), "lsfw-hooklink-"));
    try {
      const l = layout(join(root, "home"));
      recordBrowserTaint(l, "ext-1", "quarantine_verdict");
      const r = runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s-browser", cwd: root, permission_mode: "default", tool_name: "mcp__claude-in-chrome__navigate", tool_input: { url: "https://shop.test/" } }), { env: { CLAUDE_PROJECT_DIR: root }, layout: l, detectNonInteractive: () => false });
      expect(r.exitCode).toBe(0);
      const st = loadState(l, "s-browser");
      expect(st.tainted).toBe(true);
      expect(st.taintSources).toContain("the linked browser session read outside content (quarantine_verdict)");
      // A call to another MCP server does not link or taint.
      runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s-other", cwd: root, permission_mode: "default", tool_name: "mcp__github__get_issue", tool_input: { n: 1 } }), { env: { CLAUDE_PROJECT_DIR: root }, layout: l, detectNonInteractive: () => false });
      expect(loadState(l, "s-other").taintSources.some((s) => s.includes("browser"))).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("an agent cannot pose as the browser", () => {
  it("running the launcher (or anything in the firewall's data directory) is tampering, however it is started", () => {
    const launcher = "/Users/dev/.launchsafe-firewall/native-host/launchsafe-firewall-native-host";
    for (const c of [`${launcher} chrome-extension://${ID}/`, `sh ${launcher} x`, "~/.launchsafe-firewall/native-host/launchsafe-firewall-native-host x", `bash -c '${launcher} x'`, "launchsafe-firewall native-host x"]) {
      const d = bash(c);
      expect(d.verdict, c).toBe("deny");
      expect(d.rules, c).toContain("FW-TAMPER");
    }
    expect(bash("sh ./build.sh").verdict).toBe("allow");
  });

  it("writing a native messaging host manifest is a persistence change", () => {
    const d = bash(`echo '{}' > '/Users/dev/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.launchsafe.agent_firewall.json'`);
    expect(d.rules).toContain("FW-PERSISTENCE");
    expect(d.verdict).not.toBe("allow");
  });
});
