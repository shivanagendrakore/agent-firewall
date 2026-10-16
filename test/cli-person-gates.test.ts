/**
 * Commands that weaken what the firewall records or watches need the approval passphrase when one is set
 * (log rotate can prune log files; canary remove takes a tripwire away), and update never fetches the
 * malicious-package lists over plain HTTP from another host. Temporary homes only; no network.
 */

import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { main } from "../src/climain.js";
import { initApprover } from "../src/runtime/approver.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { appendLog } from "../src/runtime/log.js";

process.env.LAUNCHSAFE_FIREWALL_TEST = "1";

const PASS = "correct horse battery";
let root: string;
let l: Layout;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-gate-"));
  l = layout(join(root, "home"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

async function cli(args: string[], secret = PASS): Promise<{ status: number; out: string }> {
  let out = "";
  let status: number;
  try {
    status = await main(args, l, { write: (_fd, s) => void (out += s), humanAtKeyboard: () => Promise.resolve(true), readSecret: () => Promise.resolve(secret) });
  } catch (e) {
    out += (e as Error).message;
    status = 1;
  }
  return { status, out };
}

describe("log rotate", () => {
  it("needs the approval passphrase when one is set", async () => {
    initApprover(l, PASS);
    appendLog(l, { type: "decision", n: 1 });
    const bad = await cli(["log", "rotate"], "not the passphrase");
    expect(bad.status).not.toBe(0);
    expect(readdirSync(l.log).some((n) => /^decisions-\d{8}\.jsonl$/.test(n))).toBe(false);
    expect((await cli(["log", "rotate"])).status).toBe(0);
    expect(readdirSync(l.log).some((n) => /^decisions-\d{8}\.jsonl$/.test(n))).toBe(true);
  });
});

describe("canary remove", () => {
  it("needs the approval passphrase when one is set", async () => {
    initApprover(l, PASS);
    const bad = await cli(["canary", "remove", "--all"], "not the passphrase");
    expect(bad.status).not.toBe(0);
    expect(bad.out).toMatch(/wrong approval passphrase/);
  });
});

describe("update --source", () => {
  it("refuses plain http:// to another host", async () => {
    const r = await cli(["update", "--source", "http://mirror.example.com/osv"]);
    expect(r.status).toBe(64);
    expect(r.out).toMatch(/must be https:\/\//);
    expect(existsSync(join(l.home, "intel"))).toBe(false);
  });
});
