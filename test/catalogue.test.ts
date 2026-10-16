/**
 * The v0.2 scenario catalogue (scenarios.md, 270 rows) run through the real hook in a throwaway tree.
 * Rows whose item is not built yet are todo, so the suite reports progress; rows that cannot be
 * automated say why. The INST rows (commands a person runs) are in test/catalogue-inst.test.ts.
 */
import { describe, expect, it } from "vitest";
import { CATALOGUE, INST, type Category } from "../src/catalogue-scenarios.js";
import { runnable, runRow } from "../src/catalogue.js";
import { testRoot } from "./helpers.js";

describe("catalogue shape", () => {
  it("has the 270 rows of scenarios.md, with unique ids", () => {
    const ids = [...CATALOGUE.map((r) => r.id), ...INST.map((r) => r.id)];
    expect(ids.length).toBe(270);
    expect(new Set(ids).size).toBe(270);
    const count = (c: Category): number => CATALOGUE.filter((r) => r.category === c).length;
    expect({ DEV: count("DEV"), GIT: count("GIT"), PKG: count("PKG"), DOC: count("DOC"), MCP: count("MCP"), MEM: count("MEM"), CRED: count("CRED"), UNAT: count("UNAT"), MULTI: count("MULTI"), INC: count("INC"), SELF: count("SELF"), INST: INST.length }).toEqual({ DEV: 54, GIT: 18, PKG: 17, DOC: 12, MCP: 30, MEM: 14, CRED: 29, UNAT: 12, MULTI: 8, INC: 44, SELF: 16, INST: 16 });
  });
});

const categories = [...new Set(CATALOGUE.map((r) => r.category))];
for (const cat of categories) {
  describe(`catalogue ${cat}`, () => {
    for (const r of CATALOGUE.filter((x) => x.category === cat)) {
      for (const state of r.states) {
        const name = `${r.id} [${state}] ${r.task} -> ${r.expect}${r.rule !== undefined ? ` ${r.rule}` : ""}`;
        if (r.skip !== undefined) it.skip(`${name} (${r.skip})`, () => undefined);
        else if (!runnable(r)) it.todo(`${name} (item ${r.item ?? ""})`);
        else
          it(name, () => {
            const res = runRow(r, state, { parent: testRoot() });
            expect(res.problems, res.problems.join("\n")).toEqual([]);
          });
      }
    }
  });
}
