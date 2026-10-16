/**
 * Generates docs/cli.md from the CLI's declared
 * command specs (src/cliargs.ts), so the documented options cannot drift from
 * what the parser accepts. `--check` exits 1 when a file is out of date (CI).
 * Build first: npm run build.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { COMMANDS, PROGRAM } from "../dist/cliargs.js";

const check = process.argv.includes("--check");

function flagArg(f) {
  return f.kind === "bool" ? "" : f.kind === "enum" ? ` ${f.values.join("|")}` : f.kind === "string" ? ` ${f.placeholder}` : ` ${f.placeholder ?? "N"}`;
}

const lines = [
  "# Command line",
  "",
  "Generated from `src/cliargs.ts` by `scripts/gen-cli-docs.mjs`; do not edit by hand.",
  "",
  "Every command parses its arguments against a declared spec before anything runs:",
  "",
  "- `--help` or `-h` anywhere (before `--`) prints that command's help and exits 0 without side effects.",
  "- An unknown flag, a missing value, a bad choice or a surplus argument exits 64 with one line on stderr and changes nothing.",
  "- `hook` never exits 64: a malformed hook command exits 2, which blocks the tool (fail closed).",
  "- Commands marked *changes state* are refused when an agent runs them (FW-TAMPER) and, under the test marker, refuse to write under the real home directory.",
  "",
];
for (const s of COMMANDS) {
  lines.push(`## ${PROGRAM} ${s.path.join(" ")}`, "", s.summary.charAt(0).toUpperCase() + s.summary.slice(1) + ".", "", "```", ...s.usage.split("\n").map((u) => `${PROGRAM} ${u}`), "```", "");
  const flags = Object.entries(s.flags);
  if (flags.length > 0) {
    lines.push("| Option | Meaning |", "|---|---|");
    for (const [n, f] of flags) lines.push(`| \`${n}${flagArg(f)}\` | ${f.help ?? ""} |`);
    lines.push("");
  }
  // `doctor` only reads unless --fix or --repair-state is given; its flag stays false so agents may still run the read-only checks.
  const changes = s.changesState ? "yes" : s.path.join(" ") === "doctor" ? "no, except with --fix or --repair-state" : "no";
  lines.push(`Changes state: ${changes}${s.stdin ? " · reads standard input" : ""}`, "");
}
const cliMd = `${lines.join("\n").trimEnd()}\n`;


const files = [["docs/cli.md", cliMd]];
let stale = 0;
for (const [path, content] of files) {
  let current = "";
  try {
    current = readFileSync(path, "utf8");
  } catch {
    current = "";
  }
  if (current === content) continue;
  if (check) {
    console.error(`${path} is out of date: run npm run gen:docs`);
    stale++;
  } else writeFileSync(path, content);
}
process.exit(stale === 0 ? 0 : 1);
