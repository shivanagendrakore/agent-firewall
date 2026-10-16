/**
 * Review r7, item 5: standard input is bounded once, by the CLI's reader (runHook has no bound of its own), and a
 * command fails closed on input past it: the hook blocks the action (exit 2) and check does not judge (exit 1).
 */
import { closeSync, mkdirSync, mkdtempSync, openSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { main } from "../src/climain.js";
import { layout } from "../src/runtime/layout.js";
import { testRoot } from "./helpers.js";

describe("the CLI on oversized standard input (r7, item 5)", () => {
  const big = (): { fd: number; close: () => void } => {
    const dir = mkdtempSync(join(testRoot(), "stdin-r7-"));
    const file = join(dir, "in.json");
    writeFileSync(file, JSON.stringify({ tool: "Bash", input: { command: "x".repeat(4000) } }));
    const fd = openSync(file, "r");
    return { fd, close: () => closeSync(fd) };
  };
  const home = () => {
    const h = join(mkdtempSync(join(testRoot(), "home-r7-")), ".launchsafe-firewall");
    mkdirSync(h, { recursive: true });
    return layout(h);
  };

  it("the hook command blocks the action (exit 2) when the event is larger than the bound", async () => {
    const f = big();
    const errs: string[] = [];
    try {
      const code = await main(["hook"], home(), { stdin: { fd: f.fd, max: 1024 }, write: (fd, s) => void (fd === 2 && errs.push(s)) });
      expect(code).toBe(2);
    } finally {
      f.close();
    }
    expect(errs.join("")).toContain("could not read the hook input and blocked the action: the input on standard input is larger than");
  });

  it("check exits 1 without judging when the request is larger than the bound", async () => {
    const f = big();
    const errs: string[] = [];
    const outs: string[] = [];
    try {
      const code = await main(["check"], home(), { stdin: { fd: f.fd, max: 1024 }, write: (fd, s) => void (fd === 2 ? errs.push(s) : outs.push(s)) });
      expect(code).toBe(1);
    } finally {
      f.close();
    }
    expect(errs.join("")).toContain("did not judge the request: the input on standard input is larger than");
    expect(outs.join("")).toBe("");
  });
});
