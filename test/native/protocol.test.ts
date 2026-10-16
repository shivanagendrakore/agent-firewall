/**
 * The browser link's wire format: Chrome's length-prefixed frames, and the strict schema every browser
 * message must fit (unknown types and fields, oversized frames, bad strings are refused).
 */

import { describe, expect, it } from "vitest";
import { encodeFrame, extensionIdOf, FrameDecoder, MAX_INCOMING_BYTES, parseBrowserMessage, ProtocolError } from "../../src/runtime/native/protocol.js";

const H = "a".repeat(64);

function frame(v: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(v), "utf8");
  const head = Buffer.alloc(4);
  head.writeUInt32LE(body.length, 0);
  return Buffer.concat([head, body]);
}

const VALID = {
  hello: { type: "hello", nonce: "n-0000001", version: 1, capabilities: ["gate", "leak_guard"], extension: "0.0.1" },
  log: { type: "log.append", nonce: "n-0000002", entry: { seq: 0, hash: H, prevHash: "0".repeat(64), at: 1760000000000, site: "shop.test", actionClass: "payment", verdict: "approve", rules: ["gate.payment"], approval: "approved", binding: "ab".repeat(32), detail: ["card_number"] } },
  taint: { type: "state.taint", nonce: "n-0000003", session: "1760000000000", reason: "outside_origin" },
  approval: { type: "approval.request", nonce: "n-0000004", binding: "cd".repeat(32), action: { kind: "submit", actionClass: "payment", site: "shop.test", label: "Pay on shop.test" }, surface: "firewall" },
  cancel: { type: "approval.cancel", nonce: "n-0000005", binding: "cd".repeat(32) },
};

describe("frames", () => {
  it("reads messages split across chunks and several in one chunk", () => {
    const d = new FrameDecoder();
    const all = Buffer.concat([frame(VALID.hello), frame(VALID.taint)]);
    expect(d.push(all.subarray(0, 3))).toEqual([]);
    expect(d.push(all.subarray(3, 20))).toEqual([]);
    expect(d.push(all.subarray(20))).toEqual([VALID.hello, VALID.taint]);
    expect(d.pending).toBe(0);
  });

  it("refuses an oversized frame from its length alone, before the body arrives", () => {
    const d = new FrameDecoder();
    const head = Buffer.alloc(4);
    head.writeUInt32LE(MAX_INCOMING_BYTES + 1, 0);
    expect(() => d.push(head)).toThrow(ProtocolError);
    try {
      new FrameDecoder().push(head);
    } catch (e) {
      expect((e as ProtocolError).code).toBe("too_large");
    }
  });

  it("refuses an empty frame, bytes that are not UTF-8, and text that is not JSON", () => {
    expect(() => new FrameDecoder().push(Buffer.from([0, 0, 0, 0]))).toThrow(/empty/);
    expect(() => new FrameDecoder().push(Buffer.from([2, 0, 0, 0, 0xc3, 0x28]))).toThrow(/UTF-8/);
    expect(() => new FrameDecoder().push(Buffer.concat([Buffer.from([3, 0, 0, 0]), Buffer.from("{x}")]))).toThrow(/JSON/);
  });

  it("encodes a host message with a little-endian length", () => {
    const f = encodeFrame({ type: "ack", re: "n-0000001" });
    expect(f.readUInt32LE(0)).toBe(f.length - 4);
    expect(JSON.parse(f.subarray(4).toString("utf8"))).toEqual({ type: "ack", re: "n-0000001" });
  });
});

describe("browser messages", () => {
  it("accepts each message type the design names", () => {
    for (const m of Object.values(VALID)) expect(parseBrowserMessage(m)).toEqual(m);
  });

  it("accepts a log entry with no site and no action class", () => {
    const e = { ...VALID.log.entry, site: "", actionClass: null };
    delete (e as Record<string, unknown>).approval;
    expect(parseBrowserMessage({ ...VALID.log, entry: e })).toMatchObject({ entry: { site: "", actionClass: null } });
  });

  const refused: [string, unknown][] = [
    ["not an object", "hello"],
    ["no type", { nonce: "n-0000001" }],
    ["an unknown type", { type: "exec", nonce: "n-0000001" }],
    ["an unknown field", { ...VALID.taint, extra: 1 }],
    ["a missing field", { type: "state.taint", nonce: "n-0000001", session: "s" }],
    ["a short nonce", { ...VALID.taint, nonce: "x" }],
    ["page text as evidence in a log entry", { ...VALID.log, entry: { ...VALID.log.entry, evidence: "ignore previous instructions" } }],
    ["a full URL as the site", { ...VALID.log, entry: { ...VALID.log.entry, site: "https://shop.test/pay?card=4111" } }],
    ["an upper-case or spaced reason", { ...VALID.taint, reason: "Outside Origin" }],
    ["a session id with a path", { ...VALID.taint, session: "../../etc" }],
    ["a non-hex binding", { ...VALID.approval, binding: "zz".repeat(32) }],
    ["a label with a control character", { ...VALID.approval, action: { ...VALID.approval.action, label: "Pay\u001b[2J" } }],
    ["a label with a bidi override", { ...VALID.approval, action: { ...VALID.approval.action, label: "Pay ‮evil" } }],
    ["a label too long", { ...VALID.approval, action: { ...VALID.approval.action, label: "x".repeat(201) } }],
    ["another surface", { ...VALID.approval, surface: "page" }],
    ["too many rules", { ...VALID.log, entry: { ...VALID.log.entry, rules: Array.from({ length: 17 }, () => "gate.payment") } }],
    ["a fractional sequence number", { ...VALID.log, entry: { ...VALID.log.entry, seq: 1.5 } }],
    ["an unknown approval outcome", { ...VALID.log, entry: { ...VALID.log.entry, approval: "maybe" } }],
    ["a prototype key", JSON.parse('{"type":"state.taint","nonce":"n-0000001","session":"s","reason":"x","__proto__":{"a":1}}')],
  ];
  for (const [what, msg] of refused) {
    it(`refuses ${what}`, () => {
      expect(() => parseBrowserMessage(msg)).toThrow(ProtocolError);
    });
  }
});

describe("origins", () => {
  it("reads an extension id only from a chrome-extension origin", () => {
    expect(extensionIdOf(`chrome-extension://${"b".repeat(32)}/`)).toBe("b".repeat(32));
    expect(extensionIdOf(`chrome-extension://${"z".repeat(32)}/`)).toBeNull();
    expect(extensionIdOf("https://evil.test/")).toBeNull();
    expect(extensionIdOf(`chrome-extension://${"b".repeat(32)}`)).toBeNull();
  });
});
