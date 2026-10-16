/**
 * The Python SDK (python/ in this repository) against the REAL sidecar: the sidecar runs in this process
 * over a throwaway firewall home, on a unix socket and on 127.0.0.1, and test/api/e2e_python_guard.py runs
 * with the SDK's own venv (python -I -B: no user site, no bytecode written) and prints one JSON result.
 * While the Python guard waits on a hold, this test approves it in the firewall's queue, as a person would.
 *
 * The venv is LAUNCHSAFE_FIREWALL_PY_VENV, else python/.venv in this repository (python/README.md says how to
 * make it); the suite skips (saying why) when it is not there. The program runs no command: every shell string
 * in it is data for the engine.
 */

import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ApiServer } from "../../src/api/server.js";
import { approvalSigner, initApprover, unlockApprover } from "../../src/runtime/approver.js";
import { verifyLog } from "../../src/runtime/log.js";
import { decideQueueItem, listQueue } from "../../src/runtime/store.js";
import { agent, apiTree, removeApiTree, startServer, type ApiTree } from "./harness.js";

const here = dirname(fileURLToPath(import.meta.url));
const venv = process.env.LAUNCHSAFE_FIREWALL_PY_VENV || resolve(here, "../../python/.venv");
const python = join(venv, "bin", "python");
const program = join(here, "e2e_python_guard.py");
const PASS = "correct horse battery staple";
const skip = existsSync(python) ? false : `the Python SDK's venv is not at ${venv} (set LAUNCHSAFE_FIREWALL_PY_VENV)`;

interface Summary {
  allowed: boolean;
  verdict: string;
  rules: string[];
  decisionId: string | null;
  approval: { id: string; status: string } | null;
  error: string | null;
  untrusted: boolean | null;
}

/** The program, asynchronously: the sidecar answers it from this same process meanwhile. */
function runPython(args: string[]): Promise<Record<string, unknown>> {
  return new Promise((resolvePromise, reject) => {
    const env = { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: process.env.HOME ?? "/tmp", LANG: "C.UTF-8" };
    execFile(python, ["-I", "-B", program, ...args], { env, timeout: 60_000, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err !== null) return reject(new Error(`python failed: ${err.message}\n${stderr}`));
      const last = stdout.trim().split("\n").pop() ?? "";
      try {
        resolvePromise(JSON.parse(last) as Record<string, unknown>);
      } catch {
        reject(new Error(`python printed no JSON:\n${stdout}\n${stderr}`));
      }
    });
  });
}

describe.skipIf(skip !== false)(`the Python SDK against the real sidecar${skip !== false ? ` (skipped: ${skip})` : ""}`, () => {
  let t: ApiTree;
  let sock: ApiServer;
  let tcp: ApiServer;
  let token: string;
  let live: Record<string, unknown>;
  let down: Record<string, Record<string, Summary & { recorded?: boolean; queued?: boolean }>>;
  let approvedId = "";

  beforeAll(async () => {
    t = apiTree();
    initApprover(t.l, PASS);
    token = agent(t, "py-bot");
    sock = await startServer(t);
    tcp = await startServer(t, { listen: { host: "127.0.0.1", port: 0 } });
    const base = `http://127.0.0.1:${tcp.port as number}`;
    // A person at the terminal: approves the held delete_account once the Python guard is waiting on it.
    let stop = false;
    const person = (async () => {
      while (!stop) {
        const it = listQueue(t.l).items.find((x) => x.status === "pending" && x.sessionId === "py-bot/py-hold");
        if (it !== undefined) {
          const priv = unlockApprover(t.l, PASS);
          decideQueueItem(t.l, it.id, "approved", approvalSigner(priv));
          approvedId = it.id;
          return;
        }
        await new Promise((r) => setTimeout(r, 20));
      }
    })();
    try {
      live = await runPython(["live", sock.socket as string, base, token]);
    } finally {
      stop = true;
      await person;
    }
    await sock.close();
    await tcp.close();
    down = (await runPython(["down", sock.socket as string, base, token])) as typeof down;
  }, 120_000);

  afterAll(async () => {
    await sock?.close();
    await tcp?.close();
    if (t !== undefined) removeApiTree(t);
  });

  const s = (k: string): Summary => live[k] as Summary;

  it("health over the socket", () => {
    expect(live.health).toEqual({ ok: true, engine: expect.any(String) });
  });

  it("allow: a trusted read, and its result recorded under the decision", () => {
    expect(s("allow")).toMatchObject({ allowed: true, verdict: "allow", rules: [], decisionId: expect.stringMatching(/^dec_/), error: null });
    expect(live.allow).toMatchObject({ resultRecorded: true, resultError: null });
  });

  it("hold, approved in the firewall's queue, is allowed once; the next identical call is held again", () => {
    const h = live.hold as { approvedRetry: Summary; secondRetry: Summary };
    expect(approvedId).not.toBe("");
    expect(h.approvedRetry).toMatchObject({ allowed: true, verdict: "allow", rules: ["FW-APPROVED"] });
    expect(h.secondRetry).toMatchObject({ allowed: false, verdict: "hold", approval: { status: "pending" } });
    expect(h.secondRetry.approval?.id).not.toBe(approvedId);
  });

  it("an attended ask has no queue item and is not allowed", () => {
    expect(s("ask")).toMatchObject({ allowed: false, verdict: "ask", approval: null });
  });

  it("deny", () => {
    expect(s("deny")).toMatchObject({ allowed: false, verdict: "deny" });
    expect(s("deny").rules.length).toBeGreaterThan(0);
  });

  it("the five formats: a mapped shell tool is judged as the engine's Bash in native, openai.chat and anthropic", () => {
    const f = live.formats as Record<string, Summary>;
    const eng = f.engine as Summary;
    expect(eng.verdict).toBe("deny");
    for (const k of ["native", "openai.chat", "anthropic"]) {
      expect(f[k], k).toMatchObject({ allowed: false, verdict: "deny", rules: eng.rules });
    }
    expect(f.mcp?.decisionId).toMatch(/^dec_/);
    expect(["ask", "deny"]).toContain(f.mcp?.verdict);
    expect(f.anthropicRead).toMatchObject({ allowed: true, verdict: "allow" });
  });

  it("reports taint the session, and the next send is a person's decision", () => {
    const x = live.taint as { before: Summary; after: Summary; inputRecorded: boolean; promptRecorded: boolean; state: { untrusted: boolean; untrustedBecause: string[]; holdsPrivateData: boolean } };
    expect(x.inputRecorded).toBe(true);
    expect(x.promptRecorded).toBe(true);
    expect(x.after).toMatchObject({ allowed: false, untrusted: true });
    expect(["ask", "hold"]).toContain(x.after.verdict);
    expect(x.state).toMatchObject({ untrusted: true, holdsPrivateData: true });
    expect(x.state.untrustedBecause).toContain("a support ticket");
  });

  it("the same over 127.0.0.1", () => {
    expect(s("tcp")).toMatchObject({ allowed: true, verdict: "allow" });
  });

  it("everything the Python SDK did is in the signed log", () => {
    expect(verifyLog(t.l)).toMatchObject({ ok: true });
  });

  it("fail closed once the server is stopped, on the socket and on TCP", () => {
    for (const k of ["socket", "tcp"]) {
      const d = down[k] as Record<string, Summary & { recorded?: boolean; queued?: boolean }>;
      expect(d.read, k).toMatchObject({ allowed: true, verdict: "allow", decisionId: null });
      expect(d.read?.error, k).toBeTruthy();
      for (const c of ["send", "untrustedRead", "engineRead", "strictRead"]) expect(d[c], `${k} ${c}`).toMatchObject({ allowed: false, verdict: "deny", rules: ["FW-UNAVAILABLE"], decisionId: null });
      expect(d.report, k).toMatchObject({ recorded: false, queued: true });
    }
  });
});
