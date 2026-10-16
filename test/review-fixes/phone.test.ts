/**
 * Review of the phone fixes V21, V37, V38. PH1 and PH2 failed before the fix (project-dir policy lookup,
 * fail-closed on a broken policy); PH3 covers an item with no recorded project.
 */
import { describe, expect, it } from "vitest";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { runHook } from "../../src/hook/claude.js";
import { PROJECT_POLICY_FILE } from "../../src/runtime/layout.js";
import { pollOnce, syncOutbox } from "../../src/runtime/relay/daemon.js";
import { appendEvents, getQueueItem, listQueue } from "../../src/runtime/store.js";
import { machine, queueSend, type Machine } from "../phone/harness.js";

/** Queues a held `git push` from `cwd` (the project stays m.ws through CLAUDE_PROJECT_DIR) and seals it to the phone. */
async function sentFrom(m: Machine, cwd: string) {
  appendEvents(m.l, "s1", [{ type: "taint", source: "read the web page https://example.com/issue" }]);
  runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s1", cwd, permission_mode: "default", tool_name: "Bash", tool_input: { command: "git push origin main" } }), m.hookEnv());
  const item = listQueue(m.l).items.filter((i) => i.status === "pending").pop();
  if (item === undefined) throw new Error("nothing was queued");
  await syncOutbox(m.daemon());
  const entry = m.phone.inbox(m.relay).find((e) => e.item.itemId === item.id);
  if (entry === undefined) throw new Error("the item did not reach the phone");
  return { item, entry };
}

describe("phone fixes review", () => {
  it("control: a project policy excluding the rule after sending refuses the decision (cwd = project dir)", async () => {
    const m = await machine();
    try {
      const { item, entry } = await sentFrom(m, m.ws);
      writeFileSync(join(m.ws, PROJECT_POLICY_FILE), JSON.stringify({ version: 2, phone: { excludeRules: ["FW-SEND"] } }));
      m.relay.addDecision(m.phone.decide(entry, "approve"));
      expect((await pollOnce(m.daemon(), 0)).applied).toBe(0);
      expect(getQueueItem(m.l, item.id)?.status).toBe("pending");
    } finally {
      await m.relay.close();
    }
  });

  it("PH1 V21: the project's tightened phone policy applies when the agent's cwd is a subdirectory of the project", async () => {
    const m = await machine();
    try {
      const sub = join(m.ws, "src");
      mkdirSync(sub, { recursive: true });
      // The hook judged this call under m.ws's policy (CLAUDE_PROJECT_DIR); the queue item records cwd = m.ws/src.
      const { item, entry } = await sentFrom(m, sub);
      writeFileSync(join(m.ws, PROJECT_POLICY_FILE), JSON.stringify({ version: 2, phone: { excludeRules: ["FW-SEND"] } }));
      m.relay.addDecision(m.phone.decide(entry, "approve"));
      await pollOnce(m.daemon(), 0);
      // Expected: refused, still pending. Actual: approved by the phone (the daemon reads m.ws/src's policy, which has none).
      expect(getQueueItem(m.l, item.id)?.status).toBe("pending");
    } finally {
      await m.relay.close();
    }
  });

  it("PH2 V21: an unreadable policy at decision time does not let a phone decision through (the fix's stated fail-closed)", async () => {
    const m = await machine();
    try {
      const { item } = queueSend(m);
      await syncOutbox(m.daemon());
      const entry = m.phone.inbox(m.relay).find((e) => e.item.itemId === item.id);
      if (entry === undefined) throw new Error("the item did not reach the phone");
      // The person tightens the policy but leaves a syntax error: loadPolicy returns defaults (phone on, no exclusions) plus an error, which the daemon ignores.
      writeFileSync(m.l.policy, '{ "version": 2, "phone": { "enabled": false }, }');
      m.relay.addDecision(m.phone.decide(entry, "approve"));
      await pollOnce(m.daemon(), 0);
      expect(getQueueItem(m.l, item.id)?.status).toBe("pending");
    } finally {
      await m.relay.close();
    }
  });

  it("PH3: an older item with no recorded project directory is never sent to the phone and a decision for it is refused", async () => {
    const m = await machine();
    try {
      const { item, entry } = await sentFrom(m, m.ws);
      // Strip the project directory as an item queued by an older version would lack it.
      const file = join(m.l.queue, `${item.id}.json`);
      const j = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
      delete j.projectDir;
      writeFileSync(file, JSON.stringify(j));
      m.relay.addDecision(m.phone.decide(entry, "approve"));
      expect((await pollOnce(m.daemon(), 0)).applied).toBe(0);
      expect(getQueueItem(m.l, item.id)?.status).toBe("pending");
    } finally {
      await m.relay.close();
    }
  });
});
