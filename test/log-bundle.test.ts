/**
 * Exported decision-log bundles (docs/logs.md): a round trip verifies with the standalone verifier, and every
 * kind of tampering fails it: truncation, reordering, edits, a removed middle entry, a swapped key, a bundle
 * from another install, keys used outside their range, and an edited manifest.
 */
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { canonicalJson as engineCanonical } from "../src/engine/decide.js";
import { exportLog, ExportRefused } from "../src/logbundle/export.js";
import { BUNDLE_FORMAT, canonicalJson, cliMain, endorseMessage, entryHash, entryMessage, fingerprint, GENESIS, headerMessage, verifyBundle, type BundleHeader, type BundleKey, type BundleManifest } from "../src/logbundle/verify.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { appendLog, loadKey, rotateNow, verifyLog, type LogEntry } from "../src/runtime/log.js";

let root: string;
let l: Layout;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-bundle-"));
  l = layout(join(root, "home"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

function fill(lay: Layout, n: number, type = "decision"): void {
  for (let i = 1; i <= n; i++) appendLog(lay, { type, tool: "Bash", verdict: i % 3 === 0 ? "deny" : "allow", n: i });
}

function fp(lay: Layout): string {
  const k = loadKey(lay, false);
  if (k === null) throw new Error("no key");
  return fingerprint(k.pub);
}

const lines = (t: string): string[] => t.split("\n").filter((x) => x !== "");
const join_ = (ls: readonly string[]): string => `${ls.join("\n")}\n`;
const header = (t: string): BundleHeader => JSON.parse(lines(t)[0] as string) as BundleHeader;

/** Re-signs a bundle's header (and optionally its entries) with another key, as someone with that key would. */
function resign(text: string, priv: KeyObject, pub: KeyObject, o: { entries?: boolean } = {}): string {
  const ls = lines(text);
  const h = header(text);
  const id = fingerprint(pub);
  const keys: BundleKey[] = [{ ...(h.keys[0] as BundleKey), id, spki: pub.export({ type: "spki", format: "der" }).toString("base64") }];
  let entries = ls.slice(1);
  if (o.entries === true) entries = entries.map((x) => {
    const e = JSON.parse(x) as LogEntry;
    return JSON.stringify({ ...e, sig: sign(null, entryMessage(e.hash, e.heads), priv).toString("base64") });
  });
  const manifest: BundleManifest = { ...h.manifest, signer: id, logHead: null, toEnd: false };
  const hd: BundleHeader = { ...h, manifest, keys, sig: sign(null, headerMessage(manifest, keys), priv).toString("base64") };
  return join_([JSON.stringify(hd), ...entries]);
}

describe("canonicalJson in the standalone verifier", () => {
  it("is the engine's, byte for byte", () => {
    const samples: unknown[] = [null, 1, -0.5, 1e21, "x y", [], {}, { b: 1, a: [2, { d: null, c: "é" }] }, JSON.parse('{"__proto__":{"x":1},"constructor":2}'), { u: undefined, n: null }, [undefined, 1]];
    for (const s of samples) expect(canonicalJson(s)).toBe(engineCanonical(s));
  });
});

describe("log export and the standalone verifier", () => {
  it("round trip: the whole log exports and verifies, pinned to the install's key", () => {
    fill(l, 12);
    const r = exportLog(l);
    expect(r.manifest).toMatchObject({ entries: 12, firstSeq: 1, lastSeq: 12, fromStart: true, toEnd: true, startPrev: GENESIS, eventTypes: { decision: 12 } });
    expect(r.fingerprint).toBe(fp(l));
    const v = verifyBundle(r.text, { keys: [r.fingerprint] });
    expect(v).toMatchObject({ ok: true, entries: 12, firstSeq: 1, lastSeq: 12, pinned: true, signer: r.fingerprint });
    expect(v.problems).toEqual([]);
    // The entries are carried exactly as the log holds them.
    const logLines = readFileSync(join(l.log, "decisions.jsonl"), "utf8").split("\n").filter((x) => x !== "");
    expect(lines(r.text).slice(1).map((x) => JSON.parse(x) as unknown)).toEqual(logLines.map((x) => JSON.parse(x) as unknown));
    // Unpinned it is intact but unauthenticated (exit 2), unless --no-pin accepts that.
    const u = verifyBundle(r.text);
    expect(u).toMatchObject({ ok: false, status: "unauthenticated", intact: true, authenticated: false });
    expect(u.notes.join(" ")).toContain("not pinned");
    expect(verifyBundle(r.text, { allowUnpinned: true })).toMatchObject({ ok: true, status: "ok", authenticated: false });
  });

  it("a PEM public key pins it as well as the fingerprint", () => {
    fill(l, 3);
    const k = loadKey(l, false);
    const pem = k?.pub.export({ type: "spki", format: "pem" }) as string;
    expect(verifyBundle(exportLog(l).text, { keys: [pem] })).toMatchObject({ ok: true, pinned: true });
  });

  it("the standalone entry point verifies a bundle file and exits 1 on tampering", () => {
    fill(l, 4);
    const r = exportLog(l);
    const file = join(root, "b.jsonl");
    writeFileSync(file, r.text);
    let said = "";
    expect(cliMain([file, "--key", r.fingerprint], (s) => void (said += s))).toBe(0);
    expect(said).toContain("OK: 4 entries");
    writeFileSync(file, join_(lines(r.text).slice(0, -1)));
    said = "";
    expect(cliMain([file], (s) => void (said += s))).toBe(1);
    expect(said).toContain("PROBLEMS");
    writeFileSync(file, r.text);
    said = "";
    expect(cliMain([file], (s) => void (said += s))).toBe(2);
    expect(said).toContain("UNAUTHENTICATED");
    expect(cliMain([file, "--no-pin"], () => undefined)).toBe(0);
  });

  it("ranges by sequence and by time verify; a range that ends early carries no head", () => {
    fill(l, 10);
    const r = exportLog(l, { from: "3", to: "7" });
    expect(r.manifest).toMatchObject({ entries: 5, firstSeq: 3, lastSeq: 7, fromStart: false, toEnd: false, logHead: null, prunedAnchor: null });
    expect(verifyBundle(r.text, { keys: [r.fingerprint] }).ok).toBe(true);
    const tail = exportLog(l, { from: "8" });
    expect(tail.manifest).toMatchObject({ firstSeq: 8, lastSeq: 10, toEnd: true });
    expect(verifyBundle(tail.text, { keys: [tail.fingerprint] }).ok).toBe(true);
    const all = exportLog(l, { from: "2000-01-01T00:00:00Z", to: "2999-01-01" });
    expect(all.manifest.entries).toBe(10);
    expect(() => exportLog(l, { from: "11" })).toThrow(ExportRefused);
    for (const bad of ["yesterday-ish", "2026-10", "2026-10-01T12:00", "2026-10-01 12:00Z", "+002026-10-01", "1e3", "99999999999999999999"]) expect(() => exportLog(l, { from: bad }), bad).toThrow(ExportRefused);
    // Digits alone are a sequence number, never a year.
    expect(() => exportLog(l, { from: "2026" })).toThrow(/no entries in that range/);
    expect(exportLog(l, { to: "2999-01-01T00:00:00+02:00" }).manifest.entries).toBe(10);
  });

  it("exports a rotated and pruned log from the anchor of its pruned files", () => {
    for (let i = 0; i < 4; i++) {
      fill(l, 3);
      rotateNow(l, 2);
    }
    fill(l, 2);
    expect(verifyLog(l).ok).toBe(true);
    const r = exportLog(l);
    expect(r.manifest.prunedAnchor).not.toBeNull();
    expect(r.manifest.firstSeq).toBe((r.manifest.prunedAnchor?.seq ?? 0) + 1);
    expect(verifyBundle(r.text, { keys: [r.fingerprint] })).toMatchObject({ ok: true });
  });

  it("refuses a log that does not verify, and an empty one", () => {
    expect(() => exportLog(l)).toThrow(ExportRefused);
    fill(l, 3);
    const f = join(l.log, "decisions.jsonl");
    writeFileSync(f, readFileSync(f, "utf8").replace('"n":2', '"n":20'));
    expect(() => exportLog(l)).toThrow(/does not verify/);
  });

  describe("tampering fails", () => {
    let text: string;
    let key: string;
    beforeEach(() => {
      fill(l, 8);
      const r = exportLog(l);
      text = r.text;
      key = r.fingerprint;
      expect(verifyBundle(text, { keys: [key] }).ok).toBe(true);
    });
    const fails = (t: string, re: RegExp): void => {
      const v = verifyBundle(t, { keys: [key] });
      expect(v.ok).toBe(false);
      expect(v.problems.join("\n")).toMatch(re);
    };

    it("truncation: the last entries removed", () => {
      fails(join_(lines(text).slice(0, -2)), /manifest says 8 entries, the bundle holds 6/);
    });
    it("truncation: cut mid-line", () => {
      fails(text.slice(0, text.length - 40), /not valid JSON/);
    });
    it("reordering two entries", () => {
      const ls = lines(text);
      [ls[3], ls[4]] = [ls[4] as string, ls[3] as string];
      fails(join_(ls), /entries missing or reordered/);
    });
    it("an edited entry", () => {
      const ls = lines(text);
      ls[2] = (ls[2] as string).replace('"verdict":"allow"', '"verdict":"deny"');
      fails(join_(ls), /content does not match its hash/);
    });
    it("an edited entry with its hash recomputed", () => {
      const ls = lines(text);
      const e = JSON.parse(ls[2] as string) as LogEntry;
      const event = { ...e.event, verdict: "deny" };
      ls[2] = JSON.stringify({ ...e, event, hash: entryHash(e.prev, e.seq, e.ts, event) });
      fails(join_(ls), /bad signature|does not link/);
    });
    it("a removed middle entry", () => {
      const ls = lines(text);
      ls.splice(4, 1);
      fails(join_(ls), /entries missing or reordered|does not link/);
    });
    it("a duplicated entry", () => {
      const ls = lines(text);
      ls.splice(4, 0, ls[4] as string);
      fails(join_(ls), /entries missing or reordered/);
    });
    it("a line added at the end", () => {
      fails(`${text}{"note":"added"}\n`, /not a log entry/);
    });
    it("an edited manifest (the counts)", () => {
      const ls = lines(text);
      const h = header(text);
      ls[0] = JSON.stringify({ ...h, manifest: { ...h.manifest, entries: 7, eventTypes: { decision: 7 } } });
      fails(join_(ls.slice(0, -1)), /header \(manifest and keys\) has a bad signature/);
    });
    it("a swapped key (another public key in the header, fingerprint updated)", () => {
      const other = generateKeyPairSync("ed25519").publicKey;
      const h = header(text);
      const keys = [{ ...(h.keys[0] as BundleKey), id: fingerprint(other), spki: other.export({ type: "spki", format: "der" }).toString("base64") }];
      const ls = lines(text);
      ls[0] = JSON.stringify({ ...h, keys, manifest: { ...h.manifest, signer: fingerprint(other) } });
      const v = verifyBundle(join_(ls));
      expect(v.ok).toBe(false);
      expect(v.problems.join("\n")).toMatch(/bad signature/);
    });
    it("a swapped key (the fingerprint left as it was)", () => {
      const other = generateKeyPairSync("ed25519").publicKey;
      const h = header(text);
      const ls = lines(text);
      ls[0] = JSON.stringify({ ...h, keys: [{ ...(h.keys[0] as BundleKey), spki: other.export({ type: "spki", format: "der" }).toString("base64") }] });
      fails(join_(ls), /the key was swapped/);
    });
    it("a bundle re-signed throughout with another key: consistent, but not the pinned key", () => {
      const k = generateKeyPairSync("ed25519");
      const forged = resign(text, k.privateKey, k.publicKey, { entries: true });
      expect(verifyBundle(forged)).toMatchObject({ intact: true, status: "unauthenticated" });
      fails(forged, /not by the pinned key/);
    });
    it("a signature with junk inserted", () => {
      const ls = lines(text);
      const e = JSON.parse(ls[1] as string) as LogEntry;
      ls[1] = JSON.stringify({ ...e, sig: `${e.sig.slice(0, 10)}!!${e.sig.slice(10)}` });
      fails(join_(ls), /bad signature/);
    });
    it("a head cut short: the bundle claims the log's end but stops before the head", () => {
      const ls = lines(text);
      const h = header(text);
      expect(h.manifest.logHead?.seq).toBe(8);
      // Even with the manifest fixed up, its signature no longer holds.
      ls[0] = JSON.stringify({ ...h, manifest: { ...h.manifest, entries: 7, lastSeq: 7, lastHash: (JSON.parse(ls[7] as string) as LogEntry).hash } });
      fails(join_(ls.slice(0, -1)), /bad signature|before the log's head/);
    });
    it("a wrong format version is refused, not guessed at", () => {
      const ls = lines(text);
      ls[0] = JSON.stringify({ ...header(text), version: 2 });
      fails(join_(ls), /format version 2/);
    });
  });

  it("a bundle from another install fails against this install's key", () => {
    fill(l, 5);
    const mine = fp(l);
    const other = layout(join(root, "other-home"));
    fill(other, 5);
    const theirs = exportLog(other);
    expect(verifyBundle(theirs.text).intact).toBe(true);
    const v = verifyBundle(theirs.text, { keys: [mine] });
    expect(v.ok).toBe(false);
    expect(v.problems.join("\n")).toContain("another install's log");
    // The public key file of this install pins the same way.
    const pem = readFileSync(join(l.keys, "log-ed25519.pub.pem"), "utf8");
    expect(verifyBundle(theirs.text, { keys: [pem] }).ok).toBe(false);
  });
});

describe("key validity over time", () => {
  /** A bundle of six entries: 1-3 signed by k1, 4-6 by k2, with k2 endorsed by k1 unless told otherwise. */
  function twoKeys(o: { endorse?: boolean; k2From?: number; signFiveWith1?: boolean } = {}): { text: string; k1: string; k2: string } {
    const k1 = generateKeyPairSync("ed25519");
    const k2 = generateKeyPairSync("ed25519");
    const entries: LogEntry[] = [];
    let prev = GENESIS;
    for (let seq = 1; seq <= 6; seq++) {
      const ts = new Date(Date.UTC(2026, 9, 1, 0, 0, seq)).toISOString();
      const event = { type: "decision", n: seq };
      const hash = entryHash(prev, seq, ts, event);
      const priv = seq <= 3 || (o.signFiveWith1 === true && seq === 5) ? k1.privateKey : k2.privateKey;
      entries.push({ seq, ts, prev, event, hash, sig: sign(null, entryMessage(hash, "signed"), priv).toString("base64"), heads: "signed" });
      prev = hash;
    }
    const id1 = fingerprint(k1.publicKey);
    const id2 = fingerprint(k2.publicKey);
    const from2 = o.k2From ?? 4;
    const keys: BundleKey[] = [
      { id: id1, alg: "ed25519", spki: k1.publicKey.export({ type: "spki", format: "der" }).toString("base64"), fromSeq: 1, toSeq: 3 },
      { id: id2, alg: "ed25519", spki: k2.publicKey.export({ type: "spki", format: "der" }).toString("base64"), fromSeq: from2, toSeq: 6, ...(o.endorse === false ? {} : { endorsement: sign(null, endorseMessage(id2, from2), k1.privateKey).toString("base64") }) },
    ];
    const manifest: BundleManifest = { createdAt: "2026-10-13T00:00:00.000Z", createdBy: "test", signer: id2, requested: { from: null, to: null }, fromStart: true, toEnd: false, entries: 6, firstSeq: 1, lastSeq: 6, firstHash: (entries[0] as LogEntry).hash, lastHash: prev, startPrev: GENESIS, eventTypes: { decision: 6 }, logHead: null, prunedAnchor: null };
    const h: BundleHeader = { format: BUNDLE_FORMAT, version: 1, manifest, keys, sig: sign(null, headerMessage(manifest, keys), k2.privateKey).toString("base64") };
    return { text: join_([JSON.stringify(h), ...entries.map((e) => JSON.stringify(e))]), k1: id1, k2: id2 };
  }

  it("a key handed over to the next, with the old key's endorsement, verifies; either key pins it", () => {
    const b = twoKeys();
    expect(verifyBundle(b.text, { keys: [b.k1] })).toMatchObject({ ok: true, pinned: true });
    expect(verifyBundle(b.text, { keys: [b.k2] })).toMatchObject({ ok: true, pinned: true });
  });
  it("a later key without the earlier key's endorsement fails", () => {
    expect(verifyBundle(twoKeys({ endorse: false }).text).problems.join("\n")).toMatch(/not endorsed by key 1/);
  });
  it("overlapping validity ranges fail", () => {
    expect(verifyBundle(twoKeys({ k2From: 3 }).text).problems.join("\n")).toMatch(/must not overlap or leave a gap/);
  });
  it("an entry signed by a key outside that key's range fails", () => {
    expect(verifyBundle(twoKeys({ signFiveWith1: true }).text).problems.join("\n")).toMatch(/line 6: bad signature/);
  });
});
