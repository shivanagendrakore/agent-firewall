/**
 * The email guard's false-positive corpus and attack recall, the
 * same gate as `npm run mail-friction` (EFP11 and the measured false-positive
 * plan). Every content fixture is measured as four messages
 * (MIME alternative, single-part with legacy charsets, forwarded, structured
 * JSON), plus the email guard's own fixtures. The rates are printed.
 */
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanMail } from "../../src/engine/mail/detect.js";
import { buildMailCorpus } from "../../src/mail-corpus.js";
import { REPO } from "../helpers.js";

const corpus = buildMailCorpus(join(REPO, "test", "fixtures", "content"), join(REPO, "test", "fixtures", "mail"));
const results = corpus.map((m) => ({ m, r: scanMail(m.input) }));
const GATED = ["template", "newsletter", "multilingual", "mailing_list", "calendar", "ham"];

describe("mail corpus", () => {
  it("prints the rates per group and recall per family", () => {
    const rows = GATED.map((g) => {
      const rs = results.filter((x) => x.m.group === g).map((x) => x.r.verdict);
      const n = (v: string) => rs.filter((x) => x === v).length;
      return { group: g, messages: rs.length, withheld: n("quarantine"), neutralize: n("neutralize"), flag: n("flag"), deliver: n("deliver") };
    });
    console.log("mail corpus (false positives):");
    console.table(rows);
    const attacks = results.filter((x) => x.m.group === "attack");
    console.table([...new Set(attacks.map((x) => x.m.family))].sort().map((f) => ({ family: f, recalled: attacks.filter((x) => x.m.family === f && x.r.verdict === "quarantine").length, of: attacks.filter((x) => x.m.family === f).length })));
    expect(corpus.length).toBeGreaterThan(500);
  });
  it("EFP11: no template, newsletter, multilingual, mailing-list, calendar or ordinary message is withheld", () => {
    const fp = results.filter((x) => GATED.includes(x.m.group) && x.r.verdict === "quarantine").map((x) => `${x.m.id}: ${x.r.reasons.join(",")}`);
    expect(fp).toEqual([]);
  });
  it("newsletters quoting injection phrases are flagged at most", () => {
    for (const { m, r } of results.filter((x) => x.m.group === "newsletter")) expect(["flag", "neutralize", "deliver"], m.id).toContain(r.verdict);
  });
  it("pinned verdicts hold in every shape", () => {
    const off = results.filter((x) => x.m.expect !== undefined && x.m.group !== "attack" && x.r.verdict !== x.m.expect).map((x) => `${x.m.id}: expected ${x.m.expect}, got ${x.r.verdict}`);
    expect(off).toEqual([]);
  });
  it("attack recall is 100% in every family and shape", () => {
    const missed = results.filter((x) => x.m.group === "attack" && x.r.verdict !== "quarantine").map((x) => `${x.m.id} (${x.m.family}): ${x.r.verdict}`);
    expect(missed).toEqual([]);
    expect(results.filter((x) => x.m.group === "attack").length).toBeGreaterThanOrEqual(60);
  });
});
