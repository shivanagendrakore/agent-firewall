/**
 * The vendored firewall scanners (src/vendor/firewall/) stay byte-identical to the firewall's own files. In
 * the Agent Firewall repository the firewall's src/ is one folder up, so each copy, minus the header
 * scripts/sync-firewall.mjs writes, is compared with the file its header names in ../src; an extract's
 * declarations must appear there verbatim. A scanner changed at the root without a re-sync fails here:
 * commit the change, then run `npm run sync:firewall`. Outside the repository there is nothing to compare
 * with, and each test is skipped with that reason (`npm run check:vendor` still checks the headers).
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { FIREWALL_COMMIT } from "../../src/vendor/firewall-commit.js";

const BROWSER = resolve(import.meta.dirname, "..", "..");
const FIREWALL = resolve(BROWSER, "..");
const VENDOR = join(BROWSER, "src", "vendor", "firewall");

/** Whether browser/ sits in the agent-firewall repository: the root is the firewall package, with its src/. */
function firewallBeside(): boolean {
  try {
    const pkg = JSON.parse(readFileSync(join(FIREWALL, "package.json"), "utf8")) as { name?: unknown };
    return pkg.name === "@launchsafe/agent-firewall" && statSync(join(FIREWALL, "src")).isDirectory();
  } catch {
    return false;
  }
}

const NOT_IN_REPO = !firewallBeside();
const SKIP_REASON =
  "../src is not the Agent Firewall's src/ (browser/ is outside the agent-firewall repository), so there is nothing to compare with; npm run check:vendor still checks the headers";

const FIRST_LINE = /^\/\/ Vendored from the LaunchSafe Agent Firewall \((src\/[^)]+)\), Apache-2\.0, at commit ([0-9a-f]{40})\.\n/;
const HEADER_END = "// `node scripts/sync-firewall.mjs` (`--check` verifies the copy).\n\n";
const EXTRACT = /^\/\/ Extract: only (.+?), verbatim;/m;

interface Copy {
  /** The firewall path the header names, e.g. src/engine/content-scan.ts. */
  source: string;
  commit: string;
  /** The declarations an extract holds; null for a whole-file copy. */
  extract: string[] | null;
  /** Everything after the header. */
  body: string;
}

function filesUnder(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? filesUnder(p) : [p];
  });
}

/** Every vendored file, as a path under src/vendor/firewall/. */
const vendoredFiles = (): string[] => filesUnder(VENDOR).map((p) => relative(VENDOR, p).split("\\").join("/")).sort();

function parse(file: string): Copy {
  const text = readFileSync(join(VENDOR, file), "utf8");
  const first = FIRST_LINE.exec(text);
  const end = text.indexOf(HEADER_END);
  if (first === null || end === -1) throw new Error(`src/vendor/firewall/${file} has no sync-firewall header`);
  const [, source = "", commit = ""] = first;
  const names = EXTRACT.exec(text.slice(0, end))?.[1];
  return { source, commit, extract: names === undefined ? null : names.split(", "), body: text.slice(end + HEADER_END.length) };
}

/** The first line where the two texts differ, for a readable failure; null when they are identical. */
function firstDifference(vendored: string, upstream: string): string | null {
  if (vendored === upstream) return null;
  const a = vendored.split("\n");
  const b = upstream.split("\n");
  let i = 0;
  while (a[i] === b[i]) i++;
  return `first difference at line ${i + 1} of the firewall's file: vendored ${JSON.stringify(a[i] ?? "<end of file>")}, firewall ${JSON.stringify(b[i] ?? "<end of file>")}`;
}

/** The declared name of one extracted declaration (`export type NAME`, `export interface NAME`, ...). */
const declaredName = (declaration: string): string | undefined => /^export (?:type|interface|const|function) (\w+)/.exec(declaration)?.[1];

const FILES = vendoredFiles();

describe("vendored firewall scanners are byte-identical to ../src", () => {
  it("vendors the scanners at all", () => {
    expect(FILES).toContain("engine/content-scan.ts");
    expect(FILES).toContain("engine/content-html.ts");
  });

  it.for(FILES)("src/vendor/firewall/%s", (file, ctx) => {
    ctx.skip(NOT_IN_REPO, SKIP_REASON);
    const copy = parse(file);
    expect(copy.commit, "the header names the commit in src/vendor/firewall-commit.ts").toBe(FIREWALL_COMMIT);
    const upstreamPath = join(FIREWALL, copy.source);
    expect(existsSync(upstreamPath), `${copy.source} is gone from the firewall; update scripts/sync-firewall.mjs`).toBe(true);
    const upstream = readFileSync(upstreamPath, "utf8");
    const resync = `commit the change to ../${copy.source}, then run npm run sync:firewall`;

    if (copy.extract === null) {
      expect(firstDifference(copy.body, upstream), `src/vendor/firewall/${file} differs from ../${copy.source}; ${resync}`).toBeNull();
      return;
    }
    const declarations = copy.body.replace(/\n$/, "").split(/\n\n(?=export )/);
    expect(declarations.map(declaredName), "the extract holds exactly the declarations its header names").toEqual(copy.extract);
    for (const d of declarations) {
      const present = upstream.startsWith(`${d}\n`) || upstream.includes(`\n${d}\n`);
      expect(present, `${declaredName(d) ?? "a declaration"} in src/vendor/firewall/${file} is no longer verbatim in ../${copy.source}; ${resync}`).toBe(true);
    }
  });
});
