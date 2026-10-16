/**
 * Person-made state changes signed with the approval key (src/runtime/approver.ts): a signature for one kind
 * never verifies as another kind, another session or other fields; and fields cannot be shifted across the
 * message's separators (a newline inside one field must not turn into two fields). Keys are generated here.
 */
import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { signApproval, signStateChange, stateChangeMessage, verifyApproval, verifyStateChange, type ApprovalGrant, type StateChangeKind } from "../src/runtime/approver.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const PUB = publicKey.export({ format: "der", type: "spki" }).toString("base64");
const KINDS: StateChangeKind[] = ["scope-widen", "budget-raise", "rollout-watch", "resume"];

describe("state-change signatures", () => {
  it("verify for the kind, session and fields they were made for", () => {
    for (const kind of KINDS) {
      const sig = signStateChange(privateKey, kind, "s1", ["cap:session:toolCalls", "10", "r1"]);
      expect(verifyStateChange(PUB, kind, "s1", ["cap:session:toolCalls", "10", "r1"], sig), kind).toBe(true);
    }
  });

  it("a signature for one kind never verifies as another", () => {
    const fields = ["cap:session:toolCalls", "10", "r1"];
    for (const kind of KINDS) {
      const sig = signStateChange(privateKey, kind, "s1", fields);
      for (const other of KINDS.filter((k) => k !== kind)) expect(verifyStateChange(PUB, other, "s1", fields, sig), `${kind} as ${other}`).toBe(false);
    }
  });

  it("nor for another session, other fields, or another key", () => {
    const sig = signStateChange(privateKey, "budget-raise", "s1", ["cap:session:toolCalls", "10", "r1"]);
    expect(verifyStateChange(PUB, "budget-raise", "s2", ["cap:session:toolCalls", "10", "r1"], sig)).toBe(false);
    expect(verifyStateChange(PUB, "budget-raise", "s1", ["cap:session:toolCalls", "100", "r1"], sig)).toBe(false);
    expect(verifyStateChange(PUB, "budget-raise", "s1", ["cap:session:toolCalls", "10"], sig)).toBe(false);
    const other = generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).toString("base64");
    expect(verifyStateChange(other, "budget-raise", "s1", ["cap:session:toolCalls", "10", "r1"], sig)).toBe(false);
    expect(verifyStateChange(PUB, "budget-raise", "s1", ["cap:session:toolCalls", "10", "r1"], "not base64 at all")).toBe(false);
    expect(verifyStateChange("garbage", "budget-raise", "s1", ["cap:session:toolCalls", "10", "r1"], sig)).toBe(false);
  });

  // BUG (state-change field shift): stateChangeMessage joins the session id and the fields with "\n", so
  // ["a", "b"] and ["a\nb"] (or a session id ending in "\nX" and a field list starting with "X") are the same
  // signed message, and a signature made for one verifies for the other. learnedMessage avoids this with a
  // JSON array. Owned by the engine fixer; remove `.fails` when stateChangeMessage delimits its fields.
  it("a newline inside a field cannot shift the fields: a signature for [a, b] does not verify for [a\\nb]", () => {
    expect(stateChangeMessage("scope-widen", "s1", ["/Users/dev/proj", "/Users/dev/other"]).equals(stateChangeMessage("scope-widen", "s1", ["/Users/dev/proj\n/Users/dev/other"]))).toBe(false);
    const sig = signStateChange(privateKey, "scope-widen", "s1", ["/Users/dev/proj", "/Users/dev/other"]);
    expect(verifyStateChange(PUB, "scope-widen", "s1", ["/Users/dev/proj\n/Users/dev/other"], sig)).toBe(false);
  });
  it("a newline in the session id cannot move a field into it", () => {
    const sig = signStateChange(privateKey, "resume", "s1\nagent:claude", ["2026-10-14T00:00:00Z"]);
    expect(verifyStateChange(PUB, "resume", "s1", ["agent:claude", "2026-10-14T00:00:00Z"], sig)).toBe(false);
  });
  it("FZ21: each check uses the key it is given when checks with different keys alternate (the key object is made once per key, not per line)", () => {
    const theirs = generateKeyPairSync("ed25519");
    const OTHER = theirs.publicKey.export({ format: "der", type: "spki" }).toString("base64");
    const fields = ["cap:session:toolCalls", "10", "r1"];
    const byMe = signStateChange(privateKey, "budget-raise", "s1", fields);
    const byThem = signStateChange(theirs.privateKey, "budget-raise", "s1", fields);
    const checks: [string, string][] = [[PUB, byMe], [PUB, byThem], [OTHER, byMe], [OTHER, byThem], [PUB, byMe], ["garbage", byMe], [PUB, byMe], [OTHER, byThem]];
    expect(checks.map(([key, sig]) => verifyStateChange(key, "budget-raise", "s1", fields, sig))).toEqual([true, false, false, true, true, false, true, true]);
    const g: ApprovalGrant = { sessionId: "s1", actionHash: "h", id: "a1", nonce: "n1", exp: "2026-10-15T07:00:00.000Z", rules: ["FW-SEND"], cwd: "/w", projectDir: "/w" };
    const approved = signApproval(privateKey, g);
    expect([PUB, OTHER, PUB, "garbage", OTHER].map((key) => verifyApproval(key, g, approved))).toEqual([true, false, true, false, false]);
  });
});
