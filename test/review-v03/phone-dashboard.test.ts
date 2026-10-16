/**
 * Review v0.3, lane "nothing approvable can be approved by an agent, a relay, a notification or the
 * dashboard": phone approvals (relay daemon and hook) and the read-only dashboard. Each case was an it.fails in the review, kept as a regression test; it asserts
 * the promised behaviour and passes now the findings are fixed.
 */
import { describe, expect, it } from "vitest";
import { writeFileSync } from "node:fs";
import { getQueueItem, appendEvents, listQueue } from "../../src/runtime/store.js";
import { runHook } from "../../src/hook/claude.js";
import { pollOnce, runDaemon, syncOutbox } from "../../src/runtime/relay/daemon.js";
import { trustedKeys } from "../../src/hook/claude.js";
import { loadState } from "../../src/runtime/store.js";
import { machine, queueSend, retry, type Machine } from "../phone/harness.js";

async function sendAndRead(m: Machine, session = "s1", command = "git push origin main") {
  const { item } = queueSend(m, session, command);
  await syncOutbox(m.daemon());
  const entry = m.phone.inbox(m.relay).find((e) => e.item.itemId === item.id);
  if (entry === undefined) throw new Error("the item did not reach the phone");
  return { id: item.id, entry };
}

describe("phone approvals (review v0.3)", () => {
  it("V21 phone (PD1): excludeRules added after an item was sent", async () => {
    const m = await machine();
    try {
      const { id, entry } = await sendAndRead(m);
      // The person now keeps FW-SEND terminal-only (docs/phone.md: a project or the user may add rules).
      writeFileSync(m.l.policy, JSON.stringify({ version: 2, phone: { excludeRules: ["FW-SEND"] } }));
      m.relay.addDecision(m.phone.decide(entry, "approve"));
      const r = await pollOnce(m.daemon(), 0);
      expect(r.applied).toBe(0);
      expect(getQueueItem(m.l, id)?.status).toBe("pending");
      expect(retry(m).d).not.toBe("allow");
    } finally {
      await m.relay.close();
    }
  });

  it("V21 phone (PD2): approvable [] after an item was sent", async () => {
    const m = await machine();
    try {
      const { id, entry } = await sendAndRead(m);
      writeFileSync(m.l.policy, JSON.stringify({ version: 2, phone: { approvable: [] } }));
      m.relay.addDecision(m.phone.decide(entry, "approve"));
      const r = await pollOnce(m.daemon(), 0);
      expect(r.applied).toBe(0);
      expect(getQueueItem(m.l, id)?.status).toBe("pending");
    } finally {
      await m.relay.close();
    }
  });

  it("V37 phone (PD3): settings change approved while trusted runs as an untrusted-session proposal", async () => {
    const m = await machine();
    try {
      const write = (session: string) => runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: session, cwd: m.ws, permission_mode: "default", tool_name: "Write", tool_input: { file_path: `${m.ws}/.claude/settings.json`, content: '{"hooks":{}}\n' } }), m.hookEnv());
      // Control: in a session that read outside content, this write is held as a proposal, not an approval item.
      appendEvents(m.l, "s10", [{ type: "taint", source: "read the web page https://example.com/issue" }]);
      write("s10");
      expect(listQueue(m.l).items.find((i) => i.sessionId === "s10")?.kind).toBe("proposal");
      const first = write("s9");
      const item = listQueue(m.l).items.find((i) => i.sessionId === "s9" && i.status === "pending");
      expect(item, first.stdout).toBeDefined();
      expect(item?.kind).toBe("approval");
      await syncOutbox(m.daemon());
      const entry = m.phone.inbox(m.relay).find((e) => e.item.itemId === item?.id);
      expect(entry).toBeDefined();
      m.relay.addDecision(m.phone.decide(entry!, "approve"));
      expect((await pollOnce(m.daemon(), 0)).applied).toBe(1);
      // The session now reads outside content: the same write is a proposal (terminal-only).
      appendEvents(m.l, "s9", [{ type: "taint", source: "read the web page https://example.com/issue" }]);
      const again = write("s9");
      expect(again.stdout).not.toBe("");
      expect(again.stdout).not.toMatch(/"allow"/);
      expect(listQueue(m.l).items.some((i) => i.sessionId === "s9" && i.kind === "proposal")).toBe(true);
    } finally {
      await m.relay.close();
    }
  });

  it("V38 phone (PD4): a relay 401 turns past, legitimate phone approvals into tampering", async () => {
    const m = await machine();
    try {
      const { entry } = await sendAndRead(m);
      m.relay.addDecision(m.phone.decide(entry, "approve"));
      expect((await pollOnce(m.daemon(), 0)).applied).toBe(1);
      expect(retry(m).d).toBe("allow");
      expect(loadState(m.l, "s1", trustedKeys(m.l, m.hookEnv().env)).taintSources.filter((x) => /phone approval/.test(x))).toEqual([]);
      // The relay (anyone answering at its address) says 401: the daemon resets the registration and stops.
      m.relay.revokeAll();
      expect(await runDaemon(m.daemon({ sleep: async () => void (await new Promise((x) => setTimeout(x, 1))) }), { signal: new AbortController().signal, waitSeconds: 0 })).toBe("revoked");
      const st = loadState(m.l, "s1", trustedKeys(m.l, m.hookEnv().env));
      expect(st.taintSources.filter((x) => /phone approval/.test(x))).toEqual([]);
    } finally {
      await m.relay.close();
    }
  });
});
