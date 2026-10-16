/**
 * The conformance vectors' `setup` (conformance/setup.ts): the tree it prepares, the paths it refuses (a
 * vector can never write outside its temporary tree), the placeholders, and the decoy registry and policy
 * file it writes, read back the way the firewall reads them.
 */

import { existsSync, readFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { decoy } from "../conformance/author/kit.js";
import { checkSetup, dispose, prepare, substitute, treePath, type Setup } from "../conformance/setup.js";
import { loadCanaryIndex } from "../src/runtime/canaries.js";
import { loadPolicy } from "../src/runtime/config.js";
import { openIntel } from "../src/runtime/intel.js";

const TOKEN = "LSCANARY0123456789abcdef0123456789abcdef";

function withTree<T>(setup: Setup, fn: (p: ReturnType<typeof prepare>) => T): T {
  const p = prepare(setup);
  try {
    return fn(p);
  } finally {
    dispose(p);
  }
}

describe("conformance setup: the prepared tree", () => {
  it("creates workspace, home and firewall home under a new temporary directory, and removes it", () => {
    const p = prepare({});
    expect(p.root.startsWith(realpathSync(tmpdir()))).toBe(true);
    for (const d of [p.workspace, p.home, p.firewallHome]) expect(existsSync(d)).toBe(true);
    dispose(p);
    expect(existsSync(p.root)).toBe(false);
  });

  it("writes files under workspace/ and home/, with the placeholders replaced in their contents", () => {
    withTree({ files: { "workspace/a/b.txt": "in {{workspace}}", "home/.config/x": "home {{home}}" } }, (p) => {
      expect(readFileSync(join(p.workspace, "a", "b.txt"), "utf8")).toBe(`in ${p.workspace}`);
      expect(readFileSync(join(p.home, ".config", "x"), "utf8")).toBe(`home ${p.home}`);
    });
  });

  it("refuses every path that would leave the tree, before writing anything", () => {
    for (const bad of ["../x", "workspace/../../x", "workspace/a/../../../x", "/etc/passwd", "etc/passwd", "workspace", "workspace/", "home//x", "home/./x", "firewall/policy.json", "workspace\\..\\x", "home/x\u0000y"]) {
      expect(() => prepare({ files: { [bad]: "x" } }), bad).toThrow(/setup path/);
    }
    expect(() => prepare({ decoys: [decoy("a", "../outside", "env", TOKEN)] })).toThrow(/setup path/);
  });

  it("refuses unknown keys and malformed values", () => {
    expect(() => checkSetup({ commands: ["x"] })).toThrow(/not a setup key/);
    expect(() => checkSetup({ files: { "workspace/a": 1 } })).toThrow(/text/);
    expect(() => checkSetup({ decoys: [{ id: "A!", path: "home/x", kind: "env", token: TOKEN, fingerprint: "x" }] })).toThrow(/decoy.id/);
    expect(() => checkSetup({ decoys: [{ id: "a", path: "home/x", kind: "env", token: "no-infix-value-here", fingerprint: "x" }] })).toThrow(/malformed/);
    expect(() => checkSetup({ packages: { Hackage: {} } })).toThrow(/not an ecosystem/);
    expect(() => checkSetup({ policy: { version: 3, budgets: {} }, budgets: {} })).toThrow(/not both/);
    expect(() => checkSetup([])).toThrow(/object/);
  });

  it("registers decoys as the firewall reads them, and writes the decoy file", () => {
    withTree({ decoys: [decoy("d1", "home/.aws/credentials.bak", "aws", TOKEN)] }, (p) => {
      expect(readFileSync(join(p.home, ".aws", "credentials.bak"), "utf8")).toBe(`${TOKEN}\n`);
      const idx = loadCanaryIndex(p.l, false);
      expect(idx?.byPath.get(join(p.home, ".aws", "credentials.bak"))).toBe("d1");
      expect(idx?.fingerprints.size).toBe(1);
    });
  });

  it("writes the user's policy with budgets merged and placeholders replaced, and it loads", () => {
    withTree({ policy: { version: 3, untrustedPaths: ["{{workspace}}/vendor/**"] }, budgets: { trusted: { bytesTotal: 10 } } }, (p) => {
      const loaded = loadPolicy(p.l, [p.workspace]);
      expect(loaded.error).toBeUndefined();
      expect(loaded.config.untrustedPaths).toEqual([`${p.workspace}/vendor/**`]);
      expect(loaded.config.budgets?.trusted.bytesTotal).toBe(10);
    });
  });

  it("writes a package snapshot the firewall reads", () => {
    withTree({ packages: { npm: { "bad-placeholder": { all: true, ids: ["MAL-0"] } } } }, (p) => {
      const intel = openIntel(p.firewallHome);
      expect(intel.lookup("npm", "bad-placeholder")).toMatchObject({ kind: "listed", entry: { all: true } });
      expect(intel.lookup("npm", "fine-placeholder")).toEqual({ kind: "clean" });
      expect(intel.lookup("PyPI", "bad-placeholder")).toEqual({ kind: "none" });
    });
  });

  it("substitutes the placeholders in every string of a request, at any depth", () => {
    withTree({}, (p) => {
      const out = substitute({ a: ["{{workspace}}/x", { b: "cat {{home}}/.y" }], n: 1, t: true, o: "{{other}}" }, p);
      expect(out).toEqual({ a: [`${p.workspace}/x`, { b: `cat ${p.home}/.y` }], n: 1, t: true, o: "{{other}}" });
    });
  });

  it("treePath keeps a path inside its area", () => {
    withTree({}, (p) => {
      expect(treePath(p, "workspace/src/a.ts")).toBe(join(p.workspace, "src", "a.ts"));
      expect(() => treePath(p, "home/../workspace/a")).toThrow();
    });
  });
});
