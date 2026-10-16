// Simulator B (test only): an extension that drives tabs with chrome.debugger,
// the input path of Claude in Chrome and Comet's agent. Loaded only by the e2e
// harness next to the extension under test, in a temporary profile. Never
// installed anywhere else.
//
// test/agents/sim-b.ts calls these through the worker's global `agent` object
// (Playwright worker.evaluate). Input goes through CDP Input.* (trusted
// events), file inputs through DOM.setFileInputFiles, and page script through
// Runtime.evaluate (the B' path).

const PROTOCOL = "1.3";

function send(target, method, params = {}) {
  return chrome.debugger.sendCommand(target, method, params);
}

async function nodeFor(tabId, selector) {
  const target = { tabId };
  const { root } = await send(target, "DOM.getDocument", { depth: 0 });
  const { nodeId } = await send(target, "DOM.querySelector", { nodeId: root.nodeId, selector });
  if (!nodeId) throw new Error(`debugger agent: no element for ${selector}`);
  return nodeId;
}

/** The centre of an element in CSS pixels, from the box model (no page script). */
async function centreOf(tabId, selector) {
  const target = { tabId };
  const nodeId = await nodeFor(tabId, selector);
  await send(target, "DOM.scrollIntoViewIfNeeded", { nodeId }).catch(() => undefined);
  const { model } = await send(target, "DOM.getBoxModel", { nodeId });
  const q = model.content;
  return { x: (q[0] + q[2] + q[4] + q[6]) / 4, y: (q[1] + q[3] + q[5] + q[7]) / 4 };
}

async function click(tabId, x, y) {
  const target = { tabId };
  await send(target, "Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
  await send(target, "Input.dispatchMouseEvent", { type: "mousePressed", x, y, button: "left", clickCount: 1 });
  await send(target, "Input.dispatchMouseEvent", { type: "mouseReleased", x, y, button: "left", clickCount: 1 });
}

const KEYS = {
  Enter: { key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" },
};

self.agent = {
  async attach(tabId) {
    await chrome.debugger.attach({ tabId }, PROTOCOL);
    await send({ tabId }, "DOM.enable");
  },
  /** Attach by target id (from getTargets): the path an agent would use for a page it did not open. */
  async attachTarget(targetId) {
    await chrome.debugger.attach({ targetId }, PROTOCOL);
  },
  async detach(tabId) {
    await chrome.debugger.detach({ tabId }).catch(() => undefined);
  },
  async detachTarget(targetId) {
    await chrome.debugger.detach({ targetId }).catch(() => undefined);
  },
  /** Every target the debugger API lists (url, type, attached, extensionId). */
  async targets() {
    return chrome.debugger.getTargets();
  },
  /** Tabs whose URL starts with the prefix (the agent has the tabs permission). */
  async findTabs(urlPrefix) {
    const tabs = await chrome.tabs.query({});
    return tabs.filter((t) => (t.url ?? t.pendingUrl ?? "").startsWith(urlPrefix)).map((t) => ({ id: t.id, url: t.url ?? t.pendingUrl, windowId: t.windowId }));
  },
  click,
  async clickSelector(tabId, selector) {
    const { x, y } = await centreOf(tabId, selector);
    await click(tabId, x, y);
  },
  async focusSelector(tabId, selector) {
    const nodeId = await nodeFor(tabId, selector);
    await send({ tabId }, "DOM.focus", { nodeId });
  },
  async insertText(tabId, text) {
    await send({ tabId }, "Input.insertText", { text });
  },
  async pressKey(tabId, name, modifiers = 0) {
    const k = KEYS[name];
    if (!k) throw new Error(`debugger agent: unknown key ${name}`);
    await send({ tabId }, "Input.dispatchKeyEvent", { type: "keyDown", modifiers, ...k });
    await send({ tabId }, "Input.dispatchKeyEvent", { type: "keyUp", modifiers, key: k.key, code: k.code, windowsVirtualKeyCode: k.windowsVirtualKeyCode });
  },
  async setFileInputFiles(tabId, selector, paths) {
    const nodeId = await nodeFor(tabId, selector);
    await send({ tabId }, "DOM.setFileInputFiles", { nodeId, files: paths });
  },
  async evaluate(tabId, expression) {
    const r = await send({ tabId }, "Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(`debugger agent: evaluate threw: ${r.exceptionDetails.text}`);
    return r.result ? r.result.value : undefined;
  },
};
