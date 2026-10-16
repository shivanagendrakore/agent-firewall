import { describe, expect, it } from "vitest";
import { LIMITS, isGateUiBroadcast, parseContentMessage, parseGateContentMessage, parseGateUiMessage, parseGateWorkerMessage, parseUiMessage, parseWorkerMessage } from "./messages.js";

describe("gate/approvals messages", () => {
  it("content: only the bare posture request", () => {
    expect(parseGateContentMessage({ type: "gate.posture" })).toEqual({ type: "gate.posture" });
    for (const m of [null, "gate.posture", { type: "gate.posture", agentMode: false }, { type: "action.check" }, { type: "ui.approvals" }]) expect(parseGateContentMessage(m)).toBeNull();
  });

  it("worker: a posture with both booleans, nothing else", () => {
    expect(parseGateWorkerMessage({ type: "gate.posture", posture: { agentMode: true, quarantined: false } })).toEqual({ type: "gate.posture", posture: { agentMode: true, quarantined: false } });
    for (const m of [{ type: "gate.posture" }, { type: "gate.posture", posture: { agentMode: "yes", quarantined: false } }, { type: "gate.posture", posture: { agentMode: true } }, { type: "approval.granted", approvalId: "a", token: "t" }]) {
      expect(parseGateWorkerMessage(m)).toBeNull();
    }
  });

  it("UI: approvals state and approve-for-site, with a bounded id", () => {
    expect(parseGateUiMessage({ type: "ui.approvals" })).toEqual({ type: "ui.approvals" });
    expect(parseGateUiMessage({ type: "ui.approveForSite", approvalId: "a1" })).toEqual({ type: "ui.approveForSite", approvalId: "a1" });
    for (const m of [{ type: "ui.approveForSite", approvalId: "" }, { type: "ui.approveForSite", approvalId: 3 }, { type: "ui.approveForSite", approvalId: "x".repeat(LIMITS.token + 1) }, { type: "ui.approve", approvalId: "a" }]) {
      expect(parseGateUiMessage(m)).toBeNull();
    }
  });

  it("the sections do not overlap: a gate message is not a foundation message, and the reverse", () => {
    expect(parseContentMessage({ type: "gate.posture" })).toBeNull();
    expect(parseUiMessage({ type: "ui.approveForSite", approvalId: "a" })).toBeNull();
    expect(parseWorkerMessage({ type: "gate.posture", posture: { agentMode: true, quarantined: true } })).toBeNull();
    expect(parseGateUiMessage({ type: "ui.state" })).toBeNull();
  });

  it("recognises only the exact UI broadcast", () => {
    expect(isGateUiBroadcast({ type: "ui.changed" })).toBe(true);
    expect(isGateUiBroadcast({ type: "ui.change" })).toBe(false);
    expect(isGateUiBroadcast("ui.changed")).toBe(false);
  });
});
