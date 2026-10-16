/**
 * Can simulator B (another extension with chrome.debugger) reach the approval
 * surfaces? Acceptance: "The B simulator cannot attach to the side
 * panel or approval window". Threat model assumption 2. Each refusal message
 * is recorded as a test annotation, so the run's output is the record.
 */
import { DEBUGGER_AGENT_DIR, debuggerAgent, debuggerAgentWorker } from "../agents/sim-b.js";
import { expect, test } from "./fixtures.js";
import { openPanelInTab, simClick, tabIdFor, waitForCard } from "./gate-helpers.js";

test.use({ extraExtensions: [DEBUGGER_AGENT_DIR] });

async function tryIt(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return "ATTACHED";
  } catch (e) {
    return e instanceof Error ? e.message.replace(/^.*?Error: /s, "").split("\n")[0] ?? "" : String(e);
  }
}

test("B attaches to a web page but not to the side panel, the approval window, or the extension's other pages and worker", async ({ context, corpus, extensionId }) => {
  const agent = debuggerAgent(await debuggerAgentWorker(context));
  // Our panel page in an ordinary tab, so the agent's tabs API can see it (the real side panel is not a tab at all).
  const panel = await openPanelInTab(context, extensionId);
  const limits = await context.newPage();
  await limits.goto(`chrome-extension://${extensionId}/limits.html`);

  // Control: the agent can drive an ordinary page, and its click is held (always-on class), which opens the approval window.
  const page = await context.newPage();
  await page.goto(corpus.url("accounts.test", "/actions/password.html"));
  const pageTab = await tabIdFor(agent, page);
  expect(await tryIt(() => agent.attach(pageTab))).toBe("ATTACHED");
  await simClick("B", page, "#change", { agent, tabId: pageTab });
  await waitForCard(panel);
  await expect.poll(async () => (await agent.findTabs(`chrome-extension://${extensionId}/approval.html`)).length, { timeout: 10_000 }).toBe(1);

  const record: Record<string, string> = {};
  for (const name of ["sidepanel.html", "approval.html", "limits.html"]) {
    const tabs = await agent.findTabs(`chrome-extension://${extensionId}/${name}`);
    expect(tabs.length, `${name} is open and visible to the agent's tabs API`).toBeGreaterThan(0);
    record[`attach(tabId) ${name}`] = await tryIt(() => agent.attach(tabs[0]?.id as number));
  }
  // By target id, the path for targets the agent did not open itself (getTargets lists them).
  const ours = (await agent.targets()).filter((t) => t.url.startsWith(`chrome-extension://${extensionId}/`));
  expect(ours.length).toBeGreaterThan(0);
  for (const t of ours) record[`attach(targetId) ${t.type} ${new URL(t.url).pathname}`] = await tryIt(() => agent.attachTarget(t.id));

  for (const [what, result] of Object.entries(record)) test.info().annotations.push({ type: "B reach", description: `${what}: ${result}` });
  for (const [what, result] of Object.entries(record)) expect(result, what).not.toBe("ATTACHED");

  // Nor can it message our worker from its own extension: approve the pending request by id, as if it knew it.
  const pendingId = (await panel.evaluate(() => chrome.runtime.sendMessage({ type: "ui.approvals" })) as { approvals: { approvalId: string }[] }).approvals[0]?.approvalId;
  expect(typeof pendingId).toBe("string");
  const bWorker = await debuggerAgentWorker(context);
  const external = await bWorker.evaluate(
    ([ext, id]) => chrome.runtime.sendMessage(ext as string, { type: "ui.approve", approvalId: id }).then((r: unknown) => `replied: ${JSON.stringify(r)}`, (e: Error) => `refused: ${e.message}`),
    [extensionId, pendingId] as const,
  );
  test.info().annotations.push({ type: "B reach", description: `runtime.sendMessage(ourId, ui.approve): ${external}` });
  expect(external.startsWith("refused")).toBe(true);
  expect((await panel.evaluate(() => chrome.runtime.sendMessage({ type: "ui.approvals" })) as { approvals: unknown[] }).approvals).toHaveLength(1);

  // And from the page it can attach to, page script has no channel to our worker (no externally_connectable).
  expect(await agent.evaluate(pageTab, "typeof (globalThis.chrome && chrome.runtime && chrome.runtime.sendMessage)")).toBe("undefined");
  await agent.detach(pageTab);
});
