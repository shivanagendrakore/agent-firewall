/**
 * Several processes writing the same session state, queue and log at once, as
 * when several Claude Code sessions and subagents run hooks together. No lost
 * updates, no torn lines, and the log chain stays valid.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { layout } from "../src/runtime/layout.js";
import { listQueue, readEvents } from "../src/runtime/store.js";
import { verifyLog } from "../src/runtime/log.js";
import { tempHome, testEnv } from "./helpers.js";

let root: string;
let l: ReturnType<typeof layout>;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-cc-"));
  l = layout(join(root, "home"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const WORKER = `
import { layout } from "./dist/runtime/layout.js";
import { appendEvents, enqueue } from "./dist/runtime/store.js";
import { appendLog, loadKey } from "./dist/runtime/log.js";
const home = process.argv[2];
const w = Number(process.argv[3]);
const l = layout(home);
loadKey(l);
for (let i = 0; i < 20; i++) {
  appendEvents(l, "shared", [{ type: "downloaded", path: "/w/" + w + "-" + i }]);
  enqueue(l, { sessionId: "shared", cwd: "/w", tool: "Bash", input: { command: "c" + w + "-" + i }, actionHash: "h-" + w + "-" + i, rules: ["R"], reasons: ["r"], kind: "approval" });
  appendLog(l, { type: "decision", worker: w, i });
}
`;

describe("parallel processes (10 x 20 operations)", () => {
  it("no lost or torn updates; log chain valid", () => {
    const procs: ReturnType<typeof execFileSync>[] = [];
    const children = [];
    for (let w = 0; w < 10; w++) {
      children.push(
        new Promise<void>((resolve, reject) => {
          const { spawn } = require("node:child_process") as typeof import("node:child_process");
          const p = spawn(process.execPath, ["--input-type=module", "-", l.home, String(w)], { cwd: join(import.meta.dirname, ".."), stdio: ["pipe", "ignore", "inherit"], env: testEnv(tempHome("cc-")) });
          p.stdin.end(WORKER);
          p.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`worker ${w} exited ${code}`))));
        }),
      );
    }
    return Promise.all(children).then(() => {
      void procs;
      const events = readEvents(l, "shared");
      expect(events.filter((e) => e.type === "downloaded").length).toBe(200);
      expect(events.some((e) => e.type === "corrupt")).toBe(false);
      expect(listQueue(l).items.length).toBe(200);
      expect(listQueue(l).corrupt.length).toBe(0);
      const v = verifyLog(l);
      expect(v.ok, v.problems.join("; ")).toBe(true);
      expect(v.entries).toBe(200);
    });
  }, 60000);
});
