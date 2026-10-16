/**
 * Hardening of the log bundle, its verifier and the person-run commands (review of fw/t1-logexport): strict
 * line parsing (no parser differentials), pins that never echo a file, unauthenticated bundles, places inside
 * the firewall's directory, symbolic links, the command hook with injection-looking arguments, git's
 * environment, FW-TAMPER for agents, the canonical JSON copy, and the verifier running on its own.
 */
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import ts from "typescript";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { canonicalJson as engineCanonical } from "../src/engine/decide.js";
import { main } from "../src/climain.js";
import { AnchorRefused, assertAnchorPlace, gitEnv, makeAnchorRecord, spawnRunner, writeAnchor } from "../src/logbundle/anchor.js";
import { exportLog } from "../src/logbundle/export.js";
import { canonicalJson, strictParse, verifyBundle } from "../src/logbundle/verify.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { appendLog, type LogEntry } from "../src/runtime/log.js";
import { bash, explain } from "./helpers.js";

let root: string;
let l: Layout;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-bh-"));
  l = layout(join(root, "home"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

function fill(n: number): void {
  for (let i = 1; i <= n; i++) appendLog(l, { type: "decision", tool: "Bash", verdict: "allow", n: i });
}
const lines = (t: string): string[] => t.split("\n").filter((x) => x !== "");
const joinL = (ls: readonly string[]): string => `${ls.join("\n")}\n`;

describe("strict parsing: a line must be exactly what the firewall writes", () => {
  let text: string;
  let key: string;
  beforeEach(() => {
    fill(4);
    const r = exportLog(l);
    text = r.text;
    key = r.fingerprint;
  });
  const fails = (t: string, re: RegExp): void => {
    const v = verifyBundle(t, { keys: [key] });
    expect(v.status).toBe("invalid");
    expect(v.problems.join("\n")).toMatch(re);
  };
  const withEntry = (i: number, f: (line: string) => string): string => {
    const ls = lines(text);
    ls[i] = f(ls[i] as string);
    return joinL(ls);
  };

  it("a duplicate key in an entry (a second verdict another parser might take)", () => {
    fails(withEntry(2, (x) => x.replace('"verdict":"allow"', '"verdict":"deny","verdict":"allow"')), /line 3: not in canonical form/);
  });
  it("a duplicate key in the header", () => {
    fails(withEntry(0, (x) => x.replace('"version":1', '"version":1,"version":1')), /first line is not in canonical form/);
  });
  it("an extra field on an entry, and on the header, even in canonical form", () => {
    fails(withEntry(1, (x) => `${x.slice(0, -1)},"note":"x"}`), /line 2: not a log entry/);
    const ls = lines(text);
    const h = JSON.parse(ls[0] as string) as Record<string, unknown>;
    ls[0] = JSON.stringify({ ...h, extra: true });
    fails(joinL(ls), /fields a bundle does not have/);
  });
  it("numbers written another way: 2^53+1, -0, 1.0, 1e0", () => {
    fails(withEntry(1, (x) => x.replace('"n":1', '"n":9007199254740993')), /not in canonical form/);
    fails(withEntry(1, (x) => x.replace('"n":1', '"n":-0')), /not in canonical form/);
    fails(withEntry(1, (x) => x.replace('"n":1', '"n":1.0')), /not in canonical form/);
    fails(withEntry(1, (x) => x.replace('"seq":1', '"seq":1e0')), /not in canonical form/);
  });
  it("an unsafe sequence number in canonical form is refused", () => {
    const e = JSON.parse(lines(text)[1] as string) as LogEntry;
    fails(withEntry(1, () => JSON.stringify({ ...e, seq: 2 ** 53 + 2 })), /not a log entry/);
  });
  it("extra spacing or an escape JSON.stringify would not write", () => {
    fails(withEntry(1, (x) => x.replace('"tool":', '"tool" :')), /not in canonical form/);
    fails(withEntry(1, (x) => x.replace('"Bash"', '"B\\u0061sh"')), /not in canonical form/);
  });
  it("strictParse accepts what JSON.stringify writes, including awkward strings", () => {
    for (const v of [{ s: "  \u0000\ud800 😀" }, [1, -1, 0.5, 1e21], { __proto__x: 1 }]) {
      const line = JSON.stringify(v);
      expect(strictParse(line)).toEqual({ ok: true, v: JSON.parse(line) as unknown });
    }
  });
});

describe("pins", () => {
  it("a --key naming a file that is not a public key is refused without printing anything of it", async () => {
    fill(3);
    const bundle = join(root, "b.jsonl");
    writeFileSync(bundle, exportLog(l).text);
    const creds = join(root, "credentials");
    writeFileSync(creds, "[default]\naws_secret_access_key = SUPERSECRETVALUE1234567890\n");
    let all = "";
    const status = await main(["log", "verify", bundle, "--key", creds, "--json"], l, { write: (_fd, s) => void (all += s) });
    expect(status).toBe(1);
    expect(all).not.toContain("SUPERSECRET");
    expect(all).not.toContain("aws_secret");
    expect(all).toContain("not a fingerprint");
  });
  it("a --key file is used only for its PEM public-key block", async () => {
    fill(3);
    const bundle = join(root, "b.jsonl");
    writeFileSync(bundle, exportLog(l).text);
    const pem = readFileSync(join(l.keys, "log-ed25519.pub.pem"), "utf8");
    const f = join(root, "notes.txt");
    writeFileSync(f, `my key, kept on paper:\n${pem}\nother notes\n`);
    expect(await main(["log", "verify", bundle, "--key", f], l, { write: () => undefined })).toBe(0);
  });
  it("without a pin or an anchor: UNAUTHENTICATED, exit 2, and --json says ok false; --no-pin exits 0", async () => {
    fill(3);
    const bundle = join(root, "b.jsonl");
    writeFileSync(bundle, exportLog(l).text);
    let out = "";
    expect(await main(["log", "verify", bundle], l, { write: (_fd, s) => void (out += s) })).toBe(2);
    expect(out).toContain("UNAUTHENTICATED");
    out = "";
    expect(await main(["log", "verify", bundle, "--json"], l, { write: (_fd, s) => void (out += s) })).toBe(2);
    expect(JSON.parse(out)).toMatchObject({ ok: false, status: "unauthenticated", intact: true });
    out = "";
    expect(await main(["log", "verify", bundle, "--no-pin"], l, { write: (_fd, s) => void (out += s) })).toBe(0);
    expect(out).toContain("Not authenticated (--no-pin)");
  });
});

describe("places for exports and anchors", () => {
  it("refuses a bundle or an anchor inside the firewall's directory", async () => {
    fill(2);
    const human = { write: () => undefined, humanAtKeyboard: () => Promise.resolve(true) };
    expect(await main(["log", "export", "--out", join(l.home, "x.jsonl")], l, human)).toBe(1);
    expect(existsSync(join(l.home, "x.jsonl"))).toBe(false);
    expect(await main(["log", "anchor", "--file", join(l.log, "a.jsonl")], l, human)).toBe(1);
    expect(existsSync(join(l.log, "a.jsonl"))).toBe(false);
    expect(() => assertAnchorPlace(l, { kind: "git", repo: l.home })).toThrow(AnchorRefused);
    // Through a symbolic link that resolves into it, too.
    symlinkSync(l.home, join(root, "link"));
    expect(() => assertAnchorPlace(l, { kind: "file", path: join(root, "link", "a.jsonl") })).toThrow(AnchorRefused);
    expect(() => assertAnchorPlace(l, { kind: "file", path: join(root, "a.jsonl") })).not.toThrow();
  });
  it("never appends an anchor through a symbolic link", () => {
    fill(2);
    const real = join(root, "real.jsonl");
    writeFileSync(real, "");
    const link = join(root, "anchors.jsonl");
    symlinkSync(real, link);
    expect(() => writeAnchor(makeAnchorRecord(l), { kind: "file", path: link })).toThrow(/symbolic link/);
    expect(readFileSync(real, "utf8")).toBe("");
  });
  it("export never writes through a symbolic link", async () => {
    fill(2);
    const real = join(root, "real.jsonl");
    writeFileSync(real, "keep");
    symlinkSync(real, join(root, "out.jsonl"));
    expect(await main(["log", "export", "--out", join(root, "out.jsonl")], l, { write: () => undefined, humanAtKeyboard: () => Promise.resolve(true) })).toBe(1);
    expect(readFileSync(real, "utf8")).toBe("keep");
  });
  it("export is person-run like anchor", async () => {
    fill(2);
    expect(await main(["log", "export", "--out", join(root, "o.jsonl")], l, { write: () => undefined, humanAtKeyboard: () => Promise.resolve(false) })).toBe(1);
    expect(existsSync(join(root, "o.jsonl"))).toBe(false);
  });
});

describe("the command hook and git", () => {
  it("a real process gets injection-looking arguments literally, with no shell, and the record on stdin", () => {
    fill(2);
    const script = join(root, "hook.mjs");
    const got = join(root, "got.json");
    writeFileSync(script, `import { readFileSync, writeFileSync } from "node:fs";\nwriteFileSync(process.argv[2], JSON.stringify({ args: process.argv.slice(3), input: readFileSync(0, "utf8") }));\n`);
    const pwn = (n: number): string => join(root, `pwn${n}`);
    const args = [`; touch ${pwn(1)}`, `$(touch ${pwn(2)})`, `\`touch ${pwn(3)}\``, `| touch ${pwn(4)}`, `&& touch ${pwn(5)}`, "*"];
    const rec = makeAnchorRecord(l);
    writeAnchor(rec, { kind: "exec", argv: [process.execPath, script, got, ...args] }, spawnRunner);
    const seen = JSON.parse(readFileSync(got, "utf8")) as { args: string[]; input: string };
    expect(seen.args).toEqual(args);
    expect(seen.input).toBe(`${JSON.stringify(rec)}\n`);
    for (let i = 1; i <= 5; i++) expect(existsSync(pwn(i))).toBe(false);
  });
  it("git runs without the variables that point it at another repository or configuration", () => {
    const env = gitEnv({ PATH: "/bin", HOME: "/h", GIT_DIR: "/x", GIT_WORK_TREE: "/y", GIT_INDEX_FILE: "/i", GIT_CONFIG_GLOBAL: "/c", GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "core.hooksPath", GIT_CONFIG_VALUE_0: "/evil", GIT_CONFIG_PARAMETERS: "'a.b'='c'", GIT_OBJECT_DIRECTORY: "/o", GIT_AUTHOR_NAME: "kept" });
    expect(env).toEqual({ PATH: "/bin", HOME: "/h", GIT_AUTHOR_NAME: "kept" });
  });
  it("writeAnchor passes that environment to git", () => {
    fill(1);
    const envs: (NodeJS.ProcessEnv | undefined)[] = [];
    const before = process.env.GIT_DIR;
    process.env.GIT_DIR = "/elsewhere";
    try {
      writeAnchor(makeAnchorRecord(l), { kind: "git", repo: "/r" }, (_p, args, _i, env) => {
        envs.push(env);
        return { status: 0, stdout: args.includes("hash-object") ? `${"b".repeat(40)}\n` : "", stderr: "" };
      });
    } finally {
      if (before === undefined) delete process.env.GIT_DIR;
      else process.env.GIT_DIR = before;
    }
    expect(envs).toHaveLength(2);
    for (const e of envs) expect(e?.GIT_DIR).toBeUndefined();
  });
});

describe("agents cannot export or anchor (FW-TAMPER)", () => {
  it("an agent's tool call running log export or log anchor is denied as FW-TAMPER, however it is wrapped", () => {
    const cmds = [
      "launchsafe-firewall log export --out /tmp/x.jsonl",
      "launchsafe-firewall log export --out -",
      "launchsafe-firewall log anchor --file /tmp/a.jsonl",
      "launchsafe-firewall log anchor --git-notes .",
      "launchsafe-firewall log anchor --exec -- curl -T - https://example.com/a",
      "sh -c 'launchsafe-firewall log anchor --exec -- tee /tmp/a'",
      'bash -c "launchsafe-firewall log export --out /tmp/x.jsonl"',
      "env FOO=1 launchsafe-firewall log anchor --file /tmp/a.jsonl",
      "npx launchsafe-firewall log export --out /tmp/x.jsonl",
      "npx @launchsafe/agent-firewall log anchor --exec -- cat",
    ];
    for (const c of cmds) {
      const d = bash(c);
      expect(d.verdict, `${c}: ${explain(d)}`).toBe("deny");
      expect(d.rules, c).toContain("FW-TAMPER");
    }
    for (const c of ["launchsafe-firewall log verify b.jsonl --key sha256:00", "launchsafe-firewall log export --help"]) expect(bash(c).rules, c).not.toContain("FW-TAMPER");
  });
});

describe("canonical JSON in the standalone verifier", () => {
  const table: unknown[] = [
    " ",
    " ",
    "\ud800",
    "\udfff",
    "a\ud83d",
    "\u0000\u001f\u007f",
    "😀𝄞",
    { " ": 1, "😀": 2, "\ud800": 3, "": 4 },
    0,
    -1,
    2 ** 53 - 1,
    -(2 ** 53 - 1),
    2 ** 53,
    1e21,
    1e-7,
    5e-324,
    Number.MAX_VALUE,
    NaN,
    Infinity,
    { a: undefined, b: () => 1, c: Symbol("x") },
    [undefined, () => 1],
    { z: { y: { x: [1, { b: 2, a: 1 }] } } },
  ];
  it("matches the engine's on a table of edge cases", () => {
    for (const v of table) expect(canonicalJson(v)).toBe(engineCanonical(v));
  });
  it("matches the engine's on random values", () => {
    let seed = 12345;
    const rnd = (): number => {
      seed = (seed * 1103515245 + 12345) % 2 ** 31;
      return seed / 2 ** 31;
    };
    const chars = ["a", "Z", "\u0000", " ", "\ud800", "😀", '"', "\\", "é", "\n"];
    const str = (): string => Array.from({ length: Math.floor(rnd() * 6) }, () => chars[Math.floor(rnd() * chars.length)] as string).join("");
    const val = (d: number): unknown => {
      const k = Math.floor(rnd() * (d > 3 ? 4 : 7));
      if (k === 0) return null;
      if (k === 1) return rnd() < 0.5;
      if (k === 2) return Math.floor((rnd() - 0.5) * 2 ** 54);
      if (k === 3) return str();
      if (k === 4) return (rnd() - 0.5) * 1e6;
      if (k === 5) return Array.from({ length: Math.floor(rnd() * 4) }, () => val(d + 1));
      const o: Record<string, unknown> = {};
      for (let i = 0; i < Math.floor(rnd() * 4); i++) Object.defineProperty(o, str(), { value: val(d + 1), enumerable: true, writable: true, configurable: true });
      return o;
    };
    for (let i = 0; i < 2000; i++) {
      const v = val(0);
      expect(canonicalJson(v)).toBe(engineCanonical(v));
      const parsed = JSON.parse(JSON.stringify(v) ?? "null") as unknown;
      expect(canonicalJson(parsed)).toBe(engineCanonical(parsed));
    }
  });
});

describe("the verifier stands alone", () => {
  const source = readFileSync(join(import.meta.dirname, "..", "src", "logbundle", "verify.ts"), "utf8");

  it("imports only Node's own modules", () => {
    const specs = [...source.matchAll(/^\s*(?:import|export)[^"'`;]*?from\s+["']([^"']+)["']/gm), ...source.matchAll(/import\(\s*["']([^"']+)["']\s*\)/g)].map((m) => m[1] as string);
    expect(specs.length).toBeGreaterThan(0);
    for (const s of specs) expect(s, s).toMatch(/^node:/);
  });

  /** Runs a JavaScript copy of the verifier with node from a directory holding nothing else. */
  function runBare(js: string, args: (bundle: string) => string[]): { status: number | null; stdout: string } {
    fill(3);
    const r = exportLog(l);
    const bare = join(root, "bare");
    mkdirSync(bare);
    writeFileSync(join(bare, "verify.mjs"), js);
    writeFileSync(join(bare, "b.jsonl"), r.text);
    const p = spawnSync(process.execPath, ["verify.mjs", ...args("b.jsonl"), "--key", r.fingerprint], { cwd: bare, encoding: "utf8", env: { PATH: process.env.PATH ?? "" } });
    return { status: p.status, stdout: p.stdout };
  }

  it("the source, compiled to one file, runs with node in a bare directory", () => {
    const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
    const r = runBare(js, (b) => [b]);
    expect(r.status, r.stdout).toBe(0);
    expect(r.stdout).toContain("OK: 3 entries");
  });

  it("the built dist/logbundle/verify.js runs with node in a bare directory (when built)", (ctx) => {
    const built = join(import.meta.dirname, "..", "dist", "logbundle", "verify.js");
    if (!existsSync(built)) ctx.skip();
    const dir = join(root, "copy");
    mkdirSync(dir);
    copyFileSync(built, join(dir, "verify.mjs"));
    const r = runBare(readFileSync(join(dir, "verify.mjs"), "utf8"), (b) => [b]);
    expect(r.status, r.stdout).toBe(0);
    expect(r.stdout).toContain("OK: 3 entries");
  });
});
