/**
 * An approval given in the client (elicitation) restates the call the gateway held: the re-decision counts its
 * usage once and is not counted a second time toward the behaviour monitor's repeat (loop) tracking.
 */
import { describe, expect, it } from "vitest";
import { readCounters } from "../../src/runtime/counters.js";
import { gw, newHome, textOf, writePolicy } from "./harness.js";

describe("gateway: an in-client approval is counted once", () => {
  it("the held call and its approved re-decision are one call for loop tracking", () => {
    const { l, home } = newHome();
    writePolicy(l, { gateway: { askVia: "elicitation" } });
    const now = new Date("2026-10-10T10:00:00Z");
    const opts = { l, home, session: "cnt", clientInfo: { name: "verified-client", version: "1" }, clientCaps: { elicitation: {} }, core: { verifiedElicitationClients: ["verified-client"], now: () => now } };
    const mail = gw({ ...opts, server: "gmail", cfg: { era: "modern", tools: [{ name: "get_message", description: "Read.", inputSchema: { type: "object" } }] } });
    mail.call("tools/list");
    mail.call("tools/call", { name: "get_message", arguments: { id: "1" } });
    const slack = gw({ ...opts, server: "slack", cfg: { era: "modern", tools: [{ name: "post_message", description: "Post.", inputSchema: { type: "object" } }] } });
    slack.call("tools/list");
    const args = { name: "post_message", arguments: { channel: "#c", text: "s" } };
    const ask = slack.call("tools/call", args);
    expect(ask.result?.resultType).toBe("input_required");
    const before = readCounters(l, "gateway:cnt").counters.last.reduce((n, x) => n + x.count, 0);
    expect(before).toBeGreaterThan(0);
    const ok = slack.call("tools/call", { ...args, requestState: ask.result?.requestState, inputResponses: { launchsafe_approval: { action: "accept", content: {} } } });
    expect(textOf(ok)).toBe("ok post_message");
    // The approved re-decision did not count the same call again.
    expect(readCounters(l, "gateway:cnt").counters.last.reduce((n, x) => n + x.count, 0)).toBe(before);
  });
});
