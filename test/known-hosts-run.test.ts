/**
 * Known hosts under `run`: the proxy admits the hosts a person approved for the workspace, from the same
 * per-project list the hooks learn into, so scripts and child processes the hooks cannot see reach the
 * approved hosts and no others. Upstream connections go to a local server through the test-only dial.
 */
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer, request, type Server } from "node:http";
import { connect, type Socket } from "node:net";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { judgeHost, RunBudgets, runNetPolicy } from "../src/engine/netgate.js";
import { runHook, type HookEnv } from "../src/hook/claude.js";
import { defaultConfig } from "../src/policy.js";
import { allowHosts, approvedHosts, knownHostsFile } from "../src/runtime/knownhosts.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { startProxy, type ProxyEvent, type RunningProxy } from "../src/runtime/run/proxy.js";
import { knownHostsReader, RUN_WATCH_CAP, runKnownHosts, runWatchBuffer } from "../src/runtime/run/run.js";
import type { FirewallConfig } from "../src/types.js";
import { tempHome, testRoot } from "./helpers.js";

const ASK: Partial<FirewallConfig> = { knownHosts: { mode: "ask" } };

describe("judgeHost with the workspace's approved hosts", () => {
  const pol = (over: Partial<FirewallConfig> = {}) => runNetPolicy({ ...defaultConfig(), fetchAllowHosts: ["listed.test"], denyHosts: ["denied.test"], ...over }).policy;

  it("an approved host is admitted (fetch-only, marked known); an unapproved one is refused with the command that approves it", () => {
    const p = pol(ASK);
    expect(p.knownHosts).toBe(true);
    expect(judgeHost(p, "approved.test", 443, ["approved.test"])).toMatchObject({ verdict: "allow", kind: "fetch-only", known: true });
    const no = judgeHost(p, "other.test", 443, ["approved.test"]);
    expect(no).toMatchObject({ verdict: "deny", why: "not-listed" });
    expect(no.reason).toMatch(/launchsafe-firewall hosts allow other\.test/);
    // Exact names only.
    expect(judgeHost(p, "sub.approved.test", 443, ["approved.test"]).verdict).toBe("deny");
  });

  it("every refusal above the list still wins: denyHosts, metadata, raw IPs, loopback, capture hosts, ports", () => {
    const p = pol(ASK);
    const known = ["denied.test", "169.254.169.254", "203.0.113.9", "localhost", "x.ngrok.io", "approved.test"];
    expect(judgeHost(p, "denied.test", 443, known).why).toBe("denied-host");
    expect(judgeHost(p, "169.254.169.254", 80, known).why).toBe("metadata");
    expect(judgeHost(p, "203.0.113.9", 443, known).why).toBe("raw-ip");
    expect(judgeHost(p, "localhost", 443, known).why).toBe("loopback");
    expect(judgeHost(p, "x.ngrok.io", 443, known).why).toBe("capture");
    expect(judgeHost(p, "approved.test", 22, known).why).toBe("port");
  });

  it("with knownHosts off the list is not consulted", () => {
    const p = pol();
    expect(p.knownHosts).toBe(false);
    expect(judgeHost(p, "approved.test", 443, ["approved.test"]).verdict).toBe("deny");
    expect(judgeHost(p, "approved.test", 443, ["approved.test"]).reason).not.toMatch(/hosts allow/);
  });

  it("approved hosts are counted under the budgets for other hosts (never exempt)", () => {
    const b = new RunBudgets(pol(ASK));
    expect(b.tier("approved.test")).toBe("other");
  });
});

let web: Server;
let webPort = 0;
beforeAll(async () => {
  web = createServer((q, r) => r.end(`web ${q.headers.host ?? ""}`));
  await new Promise<void>((r) => web.listen(0, "127.0.0.1", () => r()));
  webPort = (web.address() as { port: number }).port;
});
afterAll(() => {
  web.close();
});

const dial = (): Promise<Socket> =>
  new Promise((res, rej) => {
    const s = connect(webPort, "127.0.0.1", () => res(s));
    s.on("error", rej);
  });

function get(p: RunningProxy, url: string): Promise<{ status: number; body: string }> {
  return new Promise((res, rej) => {
    const q = request({ host: "127.0.0.1", port: p.port as number, method: "GET", path: url, headers: { host: new URL(url).host } }, (r) => {
      let b = "";
      r.on("data", (c: Buffer) => (b += c.toString()));
      r.on("end", () => res({ status: r.statusCode ?? 0, body: b }));
    });
    q.on("error", rej);
    q.end();
  });
}

let home: string, ws: string, l: Layout, clock: number;
beforeEach(() => {
  home = tempHome("knownhosts-run-home-");
  ws = mkdtempSync(join(testRoot(), "knownhosts-run-ws-"));
  l = layout(join(home, ".launchsafe-firewall"));
  clock = Date.UTC(2026, 9, 13, 9, 0, 0);
  mkdirSync(l.home, { recursive: true });
  writeFileSync(l.policy, JSON.stringify({ version: 3, knownHosts: { mode: "ask" } }));
});

function hookEnv(): HookEnv {
  return { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, home, scratchRoots: [join(home, "tmp")], now: new Date(clock), detectNonInteractive: () => false, notifyDeps: { spawn: () => undefined, platform: "darwin", executable: () => true, now: () => clock } };
}

describe("the proxy uses the same per-project list as the hooks", () => {
  it("a host the person approved through the agent's hook is admitted for every process in the run; others are refused", async () => {
    // The hook path: FW-NEW-HOST asked, the person said yes, the tool ran (PostToolUse).
    const input = { url: "http://approved.test/docs", prompt: "read" };
    const preOut = runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: "r1", cwd: ws, permission_mode: "default", tool_name: "WebFetch", tool_input: input }), hookEnv());
    expect(preOut.stdout).toMatch(/FW-NEW-HOST/);
    runHook(JSON.stringify({ hook_event_name: "PostToolUse", session_id: "r1", cwd: ws, tool_name: "WebFetch", tool_input: input, tool_response: "ok" }), hookEnv());
    expect(approvedHosts(l, ws)).toEqual(["approved.test"]);

    const { policy } = runNetPolicy({ ...defaultConfig(), ...ASK, fetchAllowHosts: [] });
    const events: ProxyEvent[] = [];
    let now = clock;
    const p = await startProxy({ policy, budgets: new RunBudgets(policy), listen: { host: "127.0.0.1" }, onEvent: (e) => events.push(e), dial, knownHosts: knownHostsReader(l, ws, () => now) });
    try {
      const ok = await get(p, "http://approved.test/x");
      expect(ok.status).toBe(200);
      expect(events.find((e) => e.type === "net" && e.verdict === "allow")).toMatchObject({ host: "approved.test", known: true });
      const no = await get(p, "http://later.test/x");
      expect(no.status).toBe(403);
      expect(no.body).toMatch(/hosts allow later\.test/);
      // Approved in another terminal while the run lasts: admitted once the reader looks again.
      allowHosts(l, ws, ["later.test"], "cli", new Date(clock));
      expect((await get(p, "http://later.test/x")).status).toBe(403);
      now += 1500;
      expect((await get(p, "http://later.test/x")).status).toBe(200);
    } finally {
      await p.close();
    }
  });

  it("another workspace's approvals do not reach this run", async () => {
    const other = mkdtempSync(join(testRoot(), "knownhosts-run-other-"));
    allowHosts(l, other, ["approved.test"], "cli", new Date(clock));
    const { policy } = runNetPolicy({ ...defaultConfig(), ...ASK, fetchAllowHosts: [] });
    const p = await startProxy({ policy, budgets: new RunBudgets(policy), listen: { host: "127.0.0.1" }, onEvent: () => undefined, dial, knownHosts: knownHostsReader(l, ws) });
    try {
      expect((await get(p, "http://approved.test/x")).status).toBe(403);
    } finally {
      await p.close();
    }
  });

  it("the reader reads the list at most once a second and treats an unreadable file as no approved hosts", () => {
    let now = 0;
    const read = knownHostsReader(l, ws, () => now);
    expect(read()).toEqual([]);
    allowHosts(l, ws, ["a.test"], "cli", new Date(clock));
    expect(read()).toEqual([]);
    now = 1000;
    expect(read()).toEqual(["a.test"]);
    writeFileSync(knownHostsFile(l, ws), "damaged");
    now = 2000;
    expect(read()).toEqual([]);
  });
});

describe("review fixes for run", () => {
  const pol = (over: Partial<FirewallConfig> = {}) => runNetPolicy({ ...defaultConfig(), fetchAllowHosts: [], ...over }).policy;

  it("judgeHost: case and a trailing dot do not matter, on either side; a subdomain is another host", () => {
    const p = pol(ASK);
    expect(judgeHost(p, "APPROVED.TEST.", 443, ["approved.test"]).verdict).toBe("allow");
    expect(judgeHost(p, "approved.test", 443, ["Approved.Test."]).verdict).toBe("allow");
    expect(judgeHost(p, "www.approved.test", 443, ["approved.test"]).verdict).toBe("deny");
    expect(judgeHost(p, "approved.test.evil.example", 443, ["approved.test"]).verdict).toBe("deny");
  });

  it("an approved host that accepts uploads is admitted and labelled so", () => {
    const j = judgeHost(pol(ASK), "bitbucket.org", 443, ["bitbucket.org"]);
    expect(j).toMatchObject({ verdict: "allow", known: true, uploadCapable: true });
    expect(j.reason).toMatch(/accepts uploads/);
  });

  it("a repository's policy switching knownHosts on does not change what the proxy admits", () => {
    const managed = join(home, "no-managed-policy.json");
    writeFileSync(l.policy, JSON.stringify({ version: 3 }));
    writeFileSync(join(ws, ".launchsafe-firewall.json"), JSON.stringify({ version: 3, knownHosts: { mode: "ask" } }));
    expect(runKnownHosts(l, process.platform, managed).mode).toBe("off");
    allowHosts(l, ws, ["approved.test"], "cli", new Date(clock));
    const cfg = { ...defaultConfig(), knownHosts: { mode: "ask" as const }, fetchAllowHosts: [] };
    const p = runNetPolicy(cfg, { knownHostsFrom: { knownHosts: runKnownHosts(l, process.platform, managed) } }).policy;
    expect(p.knownHosts).toBe(false);
    expect(judgeHost(p, "approved.test", 443, approvedHosts(l, ws)).verdict).toBe("deny");
    // The user's own policy switches it on.
    writeFileSync(l.policy, JSON.stringify({ version: 3, knownHosts: { mode: "ask" } }));
    expect(runKnownHosts(l, process.platform, managed).mode).toBe("ask");
  });

  it("watch under run: hosts are batched in memory, capped per run, and written on flush", () => {
    const writes: string[][] = [];
    const buf = runWatchBuffer((h) => writes.push(h), () => undefined, 3_600_000);
    for (let i = 0; i < RUN_WATCH_CAP + 50; i++) buf.add(`h${i}.example.dev`);
    buf.add("h0.example.dev");
    expect(writes).toEqual([]);
    expect(buf.size()).toBe(RUN_WATCH_CAP);
    buf.close();
    expect(writes).toHaveLength(1);
    expect(writes[0]).toHaveLength(RUN_WATCH_CAP);
    buf.close();
    expect(writes).toHaveLength(1);
  });

  it("a failing write is reported, not thrown", () => {
    const warned: string[] = [];
    const buf = runWatchBuffer(() => {
      throw new Error("disk full");
    }, (m) => warned.push(m), 3_600_000);
    buf.add("a.example.dev");
    buf.close();
    expect(warned.join("")).toMatch(/disk full/);
  });
});
