/**
 * fileStore(): a guard's state in the runtime's own files. Held actions are the CLI's queue items, an
 * approval made through the CLI's channel (signed with the approver key) is honoured, an unsigned
 * approval is not, the log is the runtime's signed log, and the store refuses the real home while a
 * test marker is set.
 */

import { userInfo } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { approvalSigner, initApprover, unlockApprover } from "../../src/runtime/approver.js";
import { verifyLog } from "../../src/runtime/log.js";
import { appendEvents, decideQueueItem, listQueue } from "../../src/runtime/store.js";
import { createNodeGuard, fileLedger, fileStore } from "../../src/sdk/node.js";
import { makeTree, removeTree, type Tree } from "./harness.js";

const SEND = { tool: "send_email", input: { to: "someone@else.example", body: "numbers" } };
const PASS = "correct horse battery staple";

describe("fileStore", () => {
  let t: Tree;
  beforeEach(() => {
    t = makeTree();
  });
  afterEach(() => removeTree(t));

  function guard(o: { approver?: boolean } = {}) {
    const g = createNodeGuard({
      session: "file-s",
      workspace: t.ws,
      home: t.home,
      scratch: [t.scratch],
      attended: false,
      tools: { send_email: { kind: "send" }, read_ticket: { kind: "read" } },
      store: fileStore({ home: t.l.home, ...(o.approver === true ? { approver: { passphrase: PASS } } : {}) }),
    });
    g.recordResult({ tool: "read_ticket", input: { id: "1" } }, "a ticket someone wrote");
    return g;
  }

  it("a held action is a queue item the CLI lists, and the CLI's signed approval lets it run once", () => {
    initApprover(t.l, PASS);
    const g = guard();
    const d = g.decide(SEND);
    expect(d.verdict).toBe("hold");
    const items = listQueue(t.l).items;
    expect(items.map((i) => [i.id, i.sessionId, i.tool, i.status])).toEqual([[d.held?.id, "file-s", "send_email", "pending"]]);
    // What `launchsafe-firewall queue approve <id>` does, with the passphrase.
    const priv = unlockApprover(t.l, PASS);
    decideQueueItem(t.l, d.held?.id ?? "", "approved", approvalSigner(priv));
    expect(g.decide(SEND).rules).toEqual(["FW-APPROVED"]);
    expect(g.decide(SEND).verdict).toBe("hold");
  });

  it("guard.approve needs the approver key; with it, the approval is signed and honoured", () => {
    initApprover(t.l, PASS);
    const plain = guard();
    const d = plain.decide(SEND);
    expect(() => plain.approve(d.held?.id ?? "")).toThrow(/needs the approver key.*queue approve/);
    const signed = guard({ approver: true });
    signed.approve(d.held?.id ?? "", { by: "alice" });
    expect(signed.decide(SEND).verdict).toBe("allow");
  });

  it("an unsigned approval written into the session file is ignored and makes the session untrusted", () => {
    const g = guard();
    const d = g.decide(SEND);
    appendEvents(t.l, "file-s", [{ type: "approval", actionHash: d.actionHash, id: "forged" }]);
    expect(g.decide(SEND).verdict).toBe("hold");
    expect(g.state().untrustedBecause.join()).toMatch(/not signed/);
  });

  it("the log is the runtime's signed log (launchsafe-firewall log verify)", () => {
    const g = guard();
    g.decide(SEND);
    expect(verifyLog(t.l)).toMatchObject({ ok: true });
    expect(g.verifyLog()).toMatchObject({ ok: true, signed: true });
    expect(g.log().map((e) => e.event.type)).toEqual(["result", "decision"]);
  });

  it("refuses the real home while a test marker is set", () => {
    expect(() => fileStore({ home: join(userInfo().homedir, ".launchsafe-firewall") })).toThrow(/real home/);
  });

  it("fileLedger (the ledger for a custom store) refuses the real home too", () => {
    expect(() => fileLedger({ home: join(userInfo().homedir, ".launchsafe-firewall") })).toThrow(/real home/);
  });
});
