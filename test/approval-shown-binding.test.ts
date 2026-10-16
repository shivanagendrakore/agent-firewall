/** What the person was shown is what gets signed: an item changed between the screen and the passphrase is refused. */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { layout } from "../src/runtime/layout.js";
import { decideQueueItem, enqueue, getQueueItem, shownBinding } from "../src/runtime/store.js";
import { approvalSigner, initApprover, unlockApprover } from "../src/runtime/approver.js";
import { safeLine } from "../src/engine/terminal.js";

let root: string;
let l: ReturnType<typeof layout>;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-shown-"));
  l = layout(join(root, "home"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const base = { sessionId: "s", cwd: "/w", tool: "Bash", input: { command: "x" }, actionHash: "h1", rules: ["R"], reasons: ["why"], kind: "approval" as const };

function signer(): ReturnType<typeof approvalSigner> {
  initApprover(l, "correct horse battery");
  return approvalSigner(unlockApprover(l, "correct horse battery"));
}

describe("approval is bound to what was shown", () => {
  it("approves an item that is unchanged since it was shown", () => {
    const item = enqueue(l, base);
    const shown = shownBinding(getQueueItem(l, item.id) as NonNullable<ReturnType<typeof getQueueItem>>);
    expect(decideQueueItem(l, item.id, "approved", signer(), { shown }).status).toBe("approved");
  });
  it.each([
    ["actionHash", (o: Record<string, unknown>) => ({ ...o, actionHash: "evil" })],
    ["rules", (o: Record<string, unknown>) => ({ ...o, rules: [] })],
    ["cwd", (o: Record<string, unknown>) => ({ ...o, cwd: "/elsewhere" })],
    ["projectDir", (o: Record<string, unknown>) => ({ ...o, projectDir: "/elsewhere" })],
  ])("refuses when the item's %s changed after it was shown", (_n, change) => {
    const item = enqueue(l, base);
    const shown = shownBinding(getQueueItem(l, item.id) as NonNullable<ReturnType<typeof getQueueItem>>);
    const file = join(l.queue, `${item.id}.json`);
    writeFileSync(file, JSON.stringify(change(JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>)));
    expect(() => decideQueueItem(l, item.id, "approved", signer(), { shown })).toThrow(/changed after it was shown/);
    expect(getQueueItem(l, item.id)?.status).toBe("pending");
  });
});

describe("approval screen text is one line", () => {
  it("safeLine removes newlines from a tool name or reason", () => {
    expect(safeLine("Bash\n  - fake reason: safe")).not.toContain("\n");
  });
});
