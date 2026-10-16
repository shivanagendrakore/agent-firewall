/**
 * The email guard's false-positive gate. Release gate, next to `npm run friction`.
 * Build first: npm run mail-friction.
 *
 * Fails (exit 1) when any template, newsletter, multilingual, mailing-list,
 * calendar or ordinary message is withheld, when a message pinned to a verdict
 * gets another, or when any attack fixture is not withheld (recall). Also runs
 * the corpus through the read-path filter as mail tool results of 20 messages
 * each (Microsoft Graph's `{ value: [...] }` shape, as MCP text), so the
 * splitter is measured too: exactly the attack messages must become stubs.
 *
 * Prints the rates; the neutralize rate is reported, not a false positive (the
 * person still sees everything; only hidden text is stripped for the agent).
 */
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildMailCorpus } from "../dist/mail-corpus.js";
import { readMessage, scanMail } from "../dist/engine/mail/detect.js";
import { filterMailResult } from "../dist/engine/mail/filter.js";

const repo = join(fileURLToPath(import.meta.url), "..", "..");
const corpus = buildMailCorpus(join(repo, "test", "fixtures", "content"), join(repo, "test", "fixtures", "mail"));
const GATED = new Set(["template", "newsletter", "multilingual", "mailing_list", "calendar", "ham"]);

const rows = [];
const problems = [];
let slowest = 0;
const started = performance.now();
for (const m of corpus) {
  const t = performance.now();
  const r = scanMail(m.input);
  slowest = Math.max(slowest, performance.now() - t);
  rows.push({ m, r });
  if (GATED.has(m.group) && r.verdict === "quarantine") problems.push(`false positive: ${m.id} (${m.group}) withheld by ${r.reasons.join(", ")}`);
  if (m.group === "attack" && r.verdict !== "quarantine") problems.push(`missed attack: ${m.id} (${m.family}) got ${r.verdict}`);
  if (m.expect !== undefined && m.group !== "attack" && r.verdict !== m.expect) problems.push(`pinned verdict: ${m.id} expected ${m.expect}, got ${r.verdict}`);
}
const elapsed = performance.now() - started;

const L = ["LaunchSafe Firewall - email guard friction report", ""];
L.push(`${corpus.length} messages (${new Set(corpus.map((m) => m.id.replace(/\/[^/]*$/, ""))).size} distinct bodies; each content fixture as MIME alternative, single-part, forwarded and structured JSON).`, "");
L.push("group          messages  withheld  neutralize      flag   deliver");
for (const g of ["template", "newsletter", "multilingual", "mailing_list", "calendar", "ham"]) {
  const rs = rows.filter((x) => x.m.group === g);
  const n = (v) => rs.filter((x) => x.r.verdict === v).length;
  L.push(`${g.padEnd(14)} ${String(rs.length).padStart(8)}  ${String(n("quarantine")).padStart(8)}  ${String(n("neutralize")).padStart(10)}  ${String(n("flag")).padStart(8)}  ${String(n("deliver")).padStart(8)}`);
}
const ham = rows.filter((x) => GATED.has(x.m.group));
const fp = ham.filter((x) => x.r.verdict === "quarantine").length;
L.push("", `False-positive (withheld) rate: ${fp}/${ham.length} (${((100 * fp) / Math.max(1, ham.length)).toFixed(2)}%)`);
L.push(`Neutralize rate (hidden text stripped, reported only): ${ham.filter((x) => x.r.verdict === "neutralize").length}/${ham.length}`);
L.push(`Flag rate (visible text addressed to an AI, delivered with a note): ${ham.filter((x) => x.r.verdict === "flag").length}/${ham.length}`);

L.push("", "Attack recall by family:");
const attacks = rows.filter((x) => x.m.group === "attack");
for (const f of [...new Set(attacks.map((x) => x.m.family))].sort()) {
  const rs = attacks.filter((x) => x.m.family === f);
  L.push(`  ${String(f).padEnd(16)} ${rs.filter((x) => x.r.verdict === "quarantine").length}/${rs.length}`);
}
L.push(`  ${"total".padEnd(16)} ${attacks.filter((x) => x.r.verdict === "quarantine").length}/${attacks.length}`);
L.push("  Known misses (outside the deterministic rules, not in the corpus): paraphrased instructions that use no lexicon phrase, instructions in languages other than English, text inside images and attachment contents (PDF, DOCX), visible instructions from a sender whose provider reports authentication as passing.");

// The splitter: the corpus as mail tool results of 20 messages each.
let stubs = 0;
let expected = 0;
let results = 0;
for (let i = 0; i < corpus.length; i += 20) {
  const batch = corpus.slice(i, i + 20);
  const value = batch.map((m) => (typeof m.input === "string" ? { id: m.id, raw: m.input } : m.input));
  const out = filterMailResult([{ type: "text", text: JSON.stringify({ value }) }], { mode: "enforce", record: () => "q-gate" });
  results++;
  expected += new Set(batch.filter((m) => m.group === "attack").map((m) => m.id)).size;
  stubs += out.withheld.length;
  if (!out.split) problems.push(`splitter: batch ${results} was not read as messages`);
  const bySha = new Map(value.map((v, k) => [readMessage(v).sha256, batch[k]]));
  for (const w of out.withheld) {
    const m = bySha.get(w.scan.sha256);
    if (m === undefined || m.group !== "attack") problems.push(`splitter false positive: ${m?.id ?? "an unknown part of the result"} withheld inside a tool result`);
  }
}
if (stubs !== expected) problems.push(`splitter: ${stubs} messages withheld in ${results} tool results, expected ${expected}`);
L.push("", `Splitter: ${results} tool results of up to 20 messages; ${stubs} withheld, ${expected} attack messages in them.`);
L.push("", `Scan time: ${(elapsed / corpus.length).toFixed(2)} ms per message on average, slowest ${slowest.toFixed(1)} ms (informational, not a benchmark).`);

L.push("");
if (problems.length === 0) L.push("No ordinary message is withheld, and every attack fixture is.");
else {
  L.push("FAILED:");
  for (const p of problems) L.push(`  ${p}`);
}
console.log(L.join("\n"));
process.exit(problems.length === 0 ? 0 : 1);
