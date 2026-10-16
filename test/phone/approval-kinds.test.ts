/**
 * V37: which approvals let through a change held as a proposal. An approval given on a proposal (in the
 * terminal, with its diff) applies the held change; an approval given on an approval item (while the
 * session was trusted, in the terminal or on a phone) covers only an "approve" outcome, never the same
 * change once the session is untrusted and it is held as a proposal. Whether the item was a proposal comes
 * from the queue, never from the session file.
 */
import { describe, expect, it } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { runHook } from "../../src/hook/claude.js";
import { approvalSigner, unlockApprover } from "../../src/runtime/approver.js";
import { appendEvents, decideQueueItem, listQueue, sessionFile } from "../../src/runtime/store.js";
import { machine, PASS, type Machine } from "./harness.js";

const TAINT = { type: "taint" as const, source: "read the web page https://example.com/issue" };

function write(m: Machine, session: string) {
  return runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: session, cwd: m.ws, permission_mode: "default", tool_name: "Write", tool_input: { file_path: `${m.ws}/.claude/settings.json`, content: '{"hooks":{}}\n' } }), m.hookEnv());
}

function approve(m: Machine, session: string) {
  const item = listQueue(m.l).items.find((i) => i.sessionId === session && i.status === "pending");
  if (item === undefined) throw new Error("nothing pending");
  const priv = unlockApprover(m.l, PASS);
  decideQueueItem(m.l, item.id, "approved", approvalSigner(priv));
  return item;
}

describe("approvals and proposal holds (V37)", () => {
  it("a proposal approved in the terminal is applied on retry", async () => {
    const m = await machine({ pair: false });
    try {
      appendEvents(m.l, "p1", [TAINT]);
      write(m, "p1");
      expect(approve(m, "p1").kind).toBe("proposal");
      const again = write(m, "p1");
      expect(again.stdout).not.toMatch(/"deny"|"ask"/);
      expect(listQueue(m.l).items.filter((i) => i.sessionId === "p1" && i.status === "pending")).toEqual([]);
    } finally {
      await m.relay.close();
    }
  });

  it("an approval item approved with the passphrase does not apply the change once it is held as a proposal", async () => {
    const m = await machine({ pair: false });
    try {
      write(m, "p2");
      expect(approve(m, "p2").kind).toBe("approval");
      appendEvents(m.l, "p2", [TAINT]);
      const again = write(m, "p2");
      expect(again.stdout).not.toBe("");
      expect(listQueue(m.l).items.some((i) => i.sessionId === "p2" && i.kind === "proposal" && i.status === "pending")).toBe(true);
    } finally {
      await m.relay.close();
    }
  });

  it("a `proposal` flag written into the session file is not believed", async () => {
    const m = await machine({ pair: false });
    try {
      write(m, "p3");
      approve(m, "p3");
      const f = sessionFile(m.l, "p3");
      writeFileSync(f, readFileSync(f, "utf8").replace(/"type":"approval",/, '"type":"approval","proposal":true,'));
      expect(readFileSync(f, "utf8")).toMatch(/"proposal":true/);
      appendEvents(m.l, "p3", [TAINT]);
      write(m, "p3");
      expect(listQueue(m.l).items.some((i) => i.sessionId === "p3" && i.kind === "proposal" && i.status === "pending")).toBe(true);
    } finally {
      await m.relay.close();
    }
  });
});
