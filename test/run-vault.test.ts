/**
 * `run --env NAME=vault://…` (the vault and run together): Claude Code's shell substitution end to end
 * (the hook rewrites the command into a ticketed run, run spends the ticket, the child gets the value, the
 * agent reads only the reference), the refusals (replay, another command, no binding), and the output
 * filter. Values live only in an in-memory store; the "curl" the command runs is a script in a temporary
 * directory, so nothing reaches the network.
 */
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { main } from "../src/climain.js";
import { fingerprint } from "../src/engine/secrets.js";
import type { VaultView } from "../src/engine/vault-ref.js";
import { runHook, type HookEnv } from "../src/hook/claude.js";
import { initApprover, unlockApprover } from "../src/runtime/approver.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { tailLog } from "../src/runtime/log.js";
import { OutputScrubber, parseEnvPairs, resolveRunEnv, WITHHELD_SEGMENT } from "../src/runtime/run/vault-env.js";
import { addSecret, allowBinding } from "../src/runtime/vault/store.js";
import { issueTicket } from "../src/runtime/vault/tickets.js";
import { skipWithoutExec, testRoot } from "./helpers.js";
import { fakeBackend, TOKEN, type FakeStore } from "./vault/fake.js";

const PASS = "correct horse battery";
const CURL = 'curl -H "Authorization: Bearer vault://github/token" https://api.github.com/user';

interface H {
  root: string;
  l: Layout;
  ws: string;
  store: FakeStore;
  env: HookEnv;
  /** Outside the tree that is searched for values: the fake curl and what it received. */
  bin: string;
  capture: string;
}

function setup(): H {
  const root = mkdtempSync(join(testRoot(), "run-vault-"));
  const l = layout(join(root, "home"));
  const ws = join(root, "ws");
  mkdirSync(ws, { recursive: true });
  const pub = initApprover(l, PASS);
  const priv = unlockApprover(l, PASS);
  const store = fakeBackend();
  addSecret(l, priv, { name: "github/token", kind: "credential", fields: ["value"], values: { value: TOKEN }, confirm: "never", backend: store });
  allowBinding(l, priv, "github/token", { kind: "host", host: "api.github.com" });
  const outside = mkdtempSync(join(testRoot(), "run-vault-bin-"));
  const bin = join(outside, "bin");
  mkdirSync(bin);
  // Prints what it was given (so run's filter has a value to replace) and saves it where the test can see that the value arrived.
  // The rewrite runs curl as `<absolute path> -q ...` (no config file); the -q is recorded, then skipped.
  // B2: the value is in its environment (curl --variable imports it), never in its arguments; the stand-in
  // records both (the capture path is written in: the ticketed sender's environment is an allowlist, I6).
  const capture = join(outside, "capture.txt");
  writeFileSync(join(bin, "curl"), `#!/bin/sh\n[ "$1" = --version ] && { echo "curl 8.7.1 (stand-in)"; exit 0; }\nprintf '%s\\n' "$@" > '${capture}'\nprintf 'ENV:%s\\n' "$__LSV_1" >> '${capture}'\necho "> Authorization: Bearer $__LSV_1"\necho "< 200"\n`);
  chmodSync(join(bin, "curl"), 0o755);
  // The hook looks for curl only in the stand-in's directory: when the stand-in cannot run (a noexec test root),
  // the rewrite is refused rather than naming the system curl, which would try the network.
  return { root, l, ws, store, bin, capture: join(outside, "capture.txt"), env: { env: { CLAUDE_PROJECT_DIR: ws, LAUNCHSAFE_FIREWALL_APPROVER: pub, PATH: bin }, layout: l, detectNonInteractive: () => false, selfArgv: ["launchsafe-firewall"], resolveSender: (prog) => (existsSync(join(bin, prog)) ? join(bin, prog) : null), notifyDeps: { platform: "darwin", spawn: () => undefined, executable: () => true } } };
}

function rewrite(h: H, command: string, session = "s1"): string {
  const r = runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: session, cwd: h.ws, permission_mode: "default", tool_name: "Bash", tool_input: { command } }), h.env);
  const o = JSON.parse(r.stdout || "{}") as { hookSpecificOutput?: { permissionDecision?: string; updatedInput?: { command?: string } } };
  expect(o.hookSpecificOutput?.permissionDecision).toBe("allow");
  return o.hookSpecificOutput?.updatedInput?.command ?? "";
}

/** The rewritten command's words, unquoted as /bin/sh would (it only uses single quotes). */
function words(cmd: string): string[] {
  const out: string[] = [];
  for (const m of cmd.matchAll(/'((?:[^']|'\\'')*)'|(\S+)/g)) out.push(m[1] !== undefined ? m[1].replace(/'\\''/g, "'") : (m[2] as string));
  return out;
}

async function run(h: H, argv: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  let stdout = "";
  let stderr = "";
  const code = await main(argv, h.l, {
    write: (fd, s) => {
      if (fd === 1) stdout += s;
      else stderr += s;
    },
    humanAtKeyboard: async () => true,
    run: { backendFor: () => h.store, env: { PATH: `${h.bin}:/usr/bin:/bin`, LSFW_CAPTURE: h.capture } },
  });
  return { code, stdout, stderr };
}

function everything(dir: string): string {
  let out = "";
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    out += statSync(p).isDirectory() ? everything(p) : readFileSync(p, "utf8");
  }
  return out;
}

describe("Claude Code's shell substitution, end to end", () => {
  it("the hook's ticketed run puts the value in the child's environment; the agent reads only the reference; no value in any file", async (ctx) => {
    skipWithoutExec(ctx);
    const h = setup();
    const cmd = rewrite(h, CURL);
    const w = words(cmd);
    expect(w[0]).toBe("launchsafe-firewall");
    expect(cmd).not.toContain(TOKEN);
    const r = await run(h, w.slice(1));
    expect(r.code, r.stderr).toBe(0);
    // The upstream (the fake curl) got the value in its environment, and never as an argument (B2)...
    const captured = readFileSync(h.capture, "utf8").split("\n");
    expect(captured).toContain(`ENV:${TOKEN}`);
    expect(captured.filter((x) => !x.startsWith("ENV:")).join("\n")).not.toContain(TOKEN);
    expect(captured).toContain("Authorization: Bearer {{__LSV_1}}");
    // V1: curl is named by its absolute path from the hook's PATH, with -q first (no .curlrc).
    expect(cmd).toContain(`${join(h.bin, "curl")} -q --variable %__LSV_1 --expand-header`);
    expect(captured[0]).toBe("-q");
    // ...and what the agent reads has the reference in its place.
    expect(r.stdout).toContain("> Authorization: Bearer vault://github/token");
    expect(r.stdout).toContain("< 200");
    expect(`${r.stdout}${r.stderr}`).not.toContain(TOKEN);
    // The hook's PostToolUse sees the filtered output and leaves it alone; every file under the tree is value-free.
    const post = runHook(JSON.stringify({ hook_event_name: "PostToolUse", session_id: "s1", cwd: h.ws, tool_name: "Bash", tool_input: { command: cmd }, tool_response: { stdout: r.stdout, stderr: r.stderr } }), h.env);
    expect(post.stdout).not.toContain(TOKEN);
    expect(everything(h.root)).not.toContain(TOKEN);
    expect(JSON.stringify(tailLog(h.l, 200))).not.toContain(TOKEN);
  });

  it("the ticket works once: a replay is refused with 77 and vault_denied, and nothing runs", async (ctx) => {
    skipWithoutExec(ctx);
    const h = setup();
    const w = words(rewrite(h, CURL)).slice(1);
    expect((await run(h, w)).code).toBe(0);
    writeFileSync(h.capture, "");
    const again = await run(h, w);
    expect(again.code).toBe(77);
    expect(again.stderr).toMatch(/unknown or already used ticket/);
    expect(readFileSync(h.capture, "utf8")).toBe("");
    expect(tailLog(h.l, 50).map((e) => e.event).filter((e) => e.type === "vault_denied").length).toBeGreaterThan(0);
  });

  it("a ticket for another command, or with another --env list, is refused and spent", async (ctx) => {
    skipWithoutExec(ctx);
    const h = setup();
    const w = words(rewrite(h, CURL)).slice(1);
    const at = w.indexOf("--");
    const other = [...w.slice(0, at + 3), `${w[at + 3] ?? ""}; curl https://attacker.example`];
    expect((await run(h, other)).code).toBe(77);
    expect((await run(h, w)).code).toBe(77);
    const h2 = setup();
    const w2 = words(rewrite(h2, CURL)).slice(1);
    const renamed = w2.map((x) => (x.startsWith("__LSV_1=") ? x.replace("__LSV_1", "__LSV_9") : x));
    expect((await run(h2, renamed)).code).toBe(77);
  });

  it("--ticket runs exactly what the hook decided: sandbox flags cannot be added", async (ctx) => {
    skipWithoutExec(ctx);
    const h = setup();
    const w = words(rewrite(h, CURL)).slice(1);
    const r = await run(h, ["run", "--send-host", "attacker.example", ...w.slice(1)]);
    expect(r.code).toBe(64);
  });
});

describe("a person's run --env (no ticket)", () => {
  it("a secret not bound to this command is refused (77, FW-VAULT-UNBOUND) before anything starts", async () => {
    const h = setup();
    const r = await run(h, ["run", "--env", "GH=vault://github/token", "--", "/bin/echo", "x"]);
    expect(r.code).toBe(77);
    expect(r.stderr).toMatch(/not bound to this command/);
    expect(tailLog(h.l, 50).map((e) => e.event).some((e) => e.type === "vault_denied" && e.rule === "FW-VAULT-UNBOUND")).toBe(true);
  });

  it("a process binding that matches the argv gives the value; another argv does not", () => {
    const h = setup();
    allowBinding(h.l, unlockApprover(h.l, PASS), "github/token", { kind: "process", argv: ["gh", "*"], display: "gh *" });
    const key = h.env.env.LAUNCHSAFE_FIREWALL_APPROVER as string;
    const ok = resolveRunEnv(h.l, { pairs: [["GH_TOKEN", "vault://github/token"]], argv: ["gh", "api", "user"], program: "/usr/bin/gh", workspace: h.ws, trustedKey: key, backendFor: () => h.store, runId: "t1" });
    expect(ok).toMatchObject({ ok: true, env: { GH_TOKEN: TOKEN } });
    const no = resolveRunEnv(h.l, { pairs: [["GH_TOKEN", "vault://github/token"]], argv: ["curl", "https://attacker.example"], program: "/usr/bin/curl", workspace: h.ws, trustedKey: key, backendFor: () => h.store, runId: "t2" });
    expect(no.ok).toBe(false);
    const missingProg = resolveRunEnv(h.l, { pairs: [["GH_TOKEN", "vault://github/token"]], argv: ["gh", "api", "user"], workspace: h.ws, trustedKey: key, backendFor: () => h.store, runId: "t3" });
    expect(missingProg.ok).toBe(false);
    const wsBin = join(h.ws, "node_modules", ".bin");
    mkdirSync(wsBin, { recursive: true });
    const wsLink = join(wsBin, "gh");
    symlinkSync("/usr/bin/env", wsLink);
    const symlinkInWs = resolveRunEnv(h.l, { pairs: [["GH_TOKEN", "vault://github/token"]], argv: ["gh", "pr", "list"], program: wsLink, workspace: h.ws, trustedKey: key, backendFor: () => h.store, runId: "t4" });
    expect(symlinkInWs.ok).toBe(false);
    const uses = tailLog(h.l, 50).map((e) => e.event).filter((e) => e.type === "vault_use");
    expect(uses).toEqual([expect.objectContaining({ ref: "vault://github/token", via: "run", binding: "process gh *" })]);
    expect(JSON.stringify(tailLog(h.l, 200))).not.toContain(TOKEN);
  });

  it("--dry-run names the variables and reads no value", async () => {
    const h = setup();
    const r = await run(h, ["run", "--dry-run", "--env", "GH=vault://github/token", "--", "/bin/echo", "x"]);
    expect(r.stdout).toContain("Would set GH from vault://github/token");
    expect(r.stdout).not.toContain(TOKEN);
  });
});

describe("parseEnvPairs and the output filter", () => {
  it("names and references are checked; a literal secret, a reserved name or a duplicate is refused", () => {
    expect(parseEnvPairs(["A=vault://github/token", "B=vault://bank/primary#iban"])).toEqual({ ok: true, pairs: [["A", "vault://github/token"], ["B", "vault://bank/primary#iban"]] });
    for (const bad of [["A=ghp_literal"], ["1A=vault://x"], ["PATH=vault://x"], ["HTTPS_PROXY=vault://x"], ["LAUNCHSAFE_FIREWALL_HOME=vault://x"], ["A=vault://x", "A=vault://y"], ["A"]]) expect(parseEnvPairs(bad).ok, bad.join(" ")).toBe(false);
  });

  it("a value split across chunks, or base64-encoded, is still replaced", () => {
    const known = [{ value: TOKEN, ref: "vault://github/token" }];
    const s = new OutputScrubber(known);
    const text = `token=${TOKEN}\nb64=${Buffer.from(TOKEN).toString("base64")}\n`;
    let out = "";
    for (let i = 0; i < text.length; i += 7) out += s.push(Buffer.from(text.slice(i, i + 7)));
    out += s.end();
    expect(out).toBe("token=vault://github/token\nb64=vault://github/token\n");
  });

  it("a ticket never starts with \"-\" (the parser would take it for a flag after --ticket)", () => {
    const h = setup();
    for (let i = 0; i < 300; i++) expect(issueTicket(h.l, { env: [], argv: ["true"], session: "s", substitute: [], seconds: 5 })).toMatch(/^[A-Za-z0-9_][A-Za-z0-9_-]{21}$/);
    // 300 tickets are 300 durable file writes: about 15s on an idle Mac, and past the default under load.
  }, 120_000);

  it("no values: output passes unchanged", () => {
    const s = new OutputScrubber([]);
    expect(s.push("hello ") + s.push(Buffer.from("world")) + s.end()).toBe("hello world");
    expect(WITHHELD_SEGMENT).not.toContain("vault://");
  });
  it("V16: a dump (curl --trace -, --trace-ascii) is judged whole across rows and chunks; a value in it is withheld, a dump without one passes", () => {
    const known = [{ ref: "vault://github/token", value: TOKEN }];
    const hexRows = (data: string): string => {
      const buf = Buffer.from(data, "utf8");
      let out = `=> Send header, ${buf.length} bytes\n`;
      for (let i = 0; i < buf.length; i += 16) {
        const row = buf.subarray(i, i + 16);
        out += `${i.toString(16).padStart(4, "0")}: ${[...row].map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ")} ${[...row].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("")}\n`;
      }
      return out;
    };
    const header = `GET /user HTTP/1.1\r\nAuthorization: Bearer ${TOKEN}\r\n\r\n`;
    const ascii = `== Info: connected\n=> Send header, 80 bytes\n0000: GET /user HTTP/1.1\n0014: Authorization: Bearer ${TOKEN.slice(0, 10)}\n0040: ${TOKEN.slice(10)}\n<= Recv header\n`;
    for (const dump of [hexRows(header), ascii]) {
      // One byte at a time: the worst split there is.
      const f = new OutputScrubber(known);
      let out = "";
      for (const ch of dump) out += f.push(ch);
      out += f.end();
      expect(out).toContain(WITHHELD_SEGMENT);
      expect(out.replace(/[^0-9a-f]/g, "")).not.toContain(Buffer.from(TOKEN).toString("hex"));
      expect(out).not.toContain(TOKEN.slice(10));
    }
    const benign = hexRows("GET /user HTTP/1.1\r\nAccept: */*\r\n\r\n");
    const f = new OutputScrubber(known);
    expect(f.push(benign) + f.end()).toBe(benign);
  });

  it("holds enough to recognise a view entry's value written percent-encoded, one character at a time", () => {
    const OTHER = "glpat-999999999999999999999999999999999999";
    const view: VaultView = {
      signed: true,
      entries: [{ name: "gitlab/token", kind: "credential", fields: ["value"], confirm: "never", bindings: [{ kind: "host", host: "gitlab.com" }], fingerprints: { value: fingerprint(OTHER) as string } }],
    };
    const pct = Array.from(Buffer.from(OTHER), (b) => `%${b.toString(16).padStart(2, "0")}`).join("");
    const f = new OutputScrubber([], view);
    let out = "";
    for (const ch of `x=${pct}\n`) out += f.push(ch);
    out += f.end();
    expect(out).not.toContain(pct);
  });

  it("holds chunk-split hexdump -C rows and scrubs or withholds view entries and misaligned encodings", async (ctx) => {
    const OTHER = "glpat-999999999999999999999999999999999999";
    const known = [{ ref: "vault://github/token", value: TOKEN }];
    const view: VaultView = {
      signed: true,
      entries: [
        { name: "github/token", kind: "credential", fields: ["value"], confirm: "never", bindings: [{ kind: "host", host: "api.github.com" }], fingerprints: { value: fingerprint(TOKEN) as string } },
        { name: "gitlab/token", kind: "credential", fields: ["value"], confirm: "never", bindings: [{ kind: "host", host: "gitlab.com" }], fingerprints: { value: fingerprint(OTHER) as string } },
      ],
    };
    const hexdumpC = (data: string): string => {
      const buf = Buffer.from(data, "utf8");
      const rows: string[] = [];
      for (let i = 0; i < buf.length; i += 16) {
        const row = [...buf.subarray(i, i + 16)];
        const hex = row.map((b) => b.toString(16).padStart(2, "0"));
        const left = hex.slice(0, 8).join(" ");
        const right = hex.slice(8).join(" ");
        const cols = `${left}${right === "" ? "" : `  ${right}`}`.padEnd(49, " ");
        const txt = row.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
        rows.push(`${i.toString(16).padStart(8, "0")}  ${cols}|${txt}|`);
      }
      rows.push(`${buf.length.toString(16).padStart(8, "0")}\n`);
      return rows.join("\n");
    };
    const dump = hexdumpC(`Authorization: Bearer ${TOKEN}\n`);
    const f = new OutputScrubber(known, view);
    let dumpOut = "";
    for (const ch of dump) dumpOut += f.push(ch);
    dumpOut += f.end();
    expect(dumpOut).toContain(WITHHELD_SEGMENT);
    expect(dumpOut.replace(/[^0-9a-f]/g, "")).not.toContain(Buffer.from(TOKEN).toString("hex"));

    // Another vaulted secret in the clear is scrubbed to its reference via view.
    const sOther = new OutputScrubber(known, view);
    expect(sOther.push(`other=${OTHER}\n`) + sOther.end()).toBe("other=vault://gitlab/token\n");

    // A secret embedded in a larger base64 blob (shifted byte alignment) is caught via view and withheld.
    const misalignedB64 = Buffer.from(`x:${TOKEN}`).toString("base64");
    const sBlob = new OutputScrubber(known, view);
    const blobOut = sBlob.push(`{"blob":"${misalignedB64}"}\n`) + sBlob.end();
    expect(blobOut).toBe(WITHHELD_SEGMENT);
    expect(blobOut).not.toContain(misalignedB64);

    // End-to-end ticketed run passes the loaded VaultView into OutputScrubber.
    skipWithoutExec(ctx);
    const h = setup();
    addSecret(h.l, unlockApprover(h.l, PASS), { name: "gitlab/token", kind: "credential", fields: ["value"], values: { value: OTHER }, confirm: "never", backend: h.store });
    writeFileSync(join(h.bin, "curl"), `#!/bin/sh\n[ "$1" = --version ] && { echo "curl 8.7.1 (stand-in)"; exit 0; }\necho "other=${OTHER}"\n`);
    chmodSync(join(h.bin, "curl"), 0o755);
    const w = words(rewrite(h, CURL)).slice(1);
    const r = await run(h, w);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("other=vault://gitlab/token");
    expect(r.stdout).not.toContain(OTHER);
  });
});
