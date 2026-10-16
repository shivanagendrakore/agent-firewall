/**
 * The vault audit's fixes: B2 (the value is never an argument of the shell, curl or wget), I6 (the ticketed
 * sender's environment), I7 (process bindings and the resolved program), I8 (tickets bound to the agent),
 * the ticket sweep race and the file store under an empty passphrase. Values come from the in-memory store;
 * the "curl" and "wget" are scripts in a temporary directory that print what they were given.
 */
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { defaultConfig } from "../../src/policy.js";
import { vaultPolicy } from "../../src/policy-vault.js";
import { planShellRewrite } from "../../src/engine/vault-shell.js";
import { ASK_SECONDS, atLeast, prepareSubstitution, resolveSender } from "../../src/hook/vault.js";
import { layout } from "../../src/runtime/layout.js";
import { processBindingFor, ticketBaseEnv } from "../../src/runtime/run/vault-env.js";
import { fileBackend, storePath } from "../../src/runtime/vault/file.js";
import { ancestry, consumeTicket, issueTicket, lineageProblem, ticketsDir, type ProcessParent } from "../../src/runtime/vault/tickets.js";
import { skipWithoutExec, testRoot } from "../helpers.js";
import { fingerprint } from "../../src/engine/secrets.js";
import { initApprover, publicKeyOf, unlockApprover } from "../../src/runtime/approver.js";
import { substituteJson } from "../../src/runtime/vault/substitute.js";
import { loadIndex } from "../../src/runtime/vault/index.js";
import { addSecret, rotateSecret } from "../../src/runtime/vault/store.js";
import { fakeBackend, TOKEN } from "./fake.js";

const REF = "vault://github/token";

/** The ticketed run's argv for one command, as the hook builds it. */
function rewrite(command: string, o: { version?: number[] | null; exe?: string } = {}): { argv: string[]; env: [string, string][] } {
  const l = layout(join(mkdtempSync(join(testRoot(), "vault-audit-")), "home"));
  const d = { verdict: "allow", actionHash: "h", vault: { refs: [REF], substitute: [{ ref: REF, name: "github/token", field: "value", kind: "credential", via: "hook", destination: "api.github.com", binding: "host api.github.com" }] } };
  const out = prepareSubstitution(l, {
    action: { tool: "Bash", input: { command } } as never,
    d: d as never,
    session: "s",
    pol: vaultPolicy(defaultConfig()),
    self: ["launchsafe-firewall"],
    resolveSender: (p) => o.exe ?? `/opt/bin/${p}`,
    senderVersion: () => (o.version === undefined ? [8, 7, 1] : o.version),
    ancestors: [],
  });
  const cmd = String(out.updatedInput?.command ?? "");
  const words: string[] = [];
  for (const m of cmd.matchAll(/'((?:[^']|'\\'')*)'|(\S+)/g)) words.push(m[1] !== undefined ? m[1].replace(/'\\''/g, "'") : (m[2] as string));
  const env: [string, string][] = [];
  words.forEach((w, i) => {
    if (w === "--env") {
      const [n, ...r] = (words[i + 1] as string).split("=");
      env.push([n as string, r.join("=")]);
    }
  });
  return { argv: words.slice(words.indexOf("--") + 1), env };
}

describe("B2: the value never becomes an argument", () => {
  it("curl: --variable and --expand-*, no shell expansion of the value anywhere in the inner command", () => {
    const { argv } = rewrite(`curl -sS -H "Authorization: Bearer ${REF}" -d "t=${REF}" https://api.github.com/user`);
    expect(argv.slice(0, 2)).toEqual(["/bin/sh", "-c"]);
    const inner = argv[2] as string;
    expect(inner).toContain("/opt/bin/curl -q --variable %__LSV_1");
    expect(inner).toContain("--expand-header 'Authorization: Bearer {{__LSV_1}}'");
    expect(inner).toContain("--expand-data 't={{__LSV_1}}'");
    expect(inner).not.toMatch(/\$\{?__LSV/);
  });
  it("curl: a reference in the URL becomes --expand-url, before a --", () => {
    const p = planShellRewrite(`curl -s -- "https://api.github.com/x?t=${REF}"`);
    expect(p.ok && p.parts[0]?.args).toBe("--variable %__LSV_1 -s --expand-url 'https://api.github.com/x?t={{__LSV_1}}' --");
  });
  it("curl: literal {{ next to a reference, or a curl older than 8.3, is refused", () => {
    expect(planShellRewrite(`curl -H "X: {{a}} ${REF}" https://api.github.com/`).ok).toBe(false);
    expect(() => rewrite(`curl -H "A: ${REF}" https://api.github.com/`, { version: [8, 2, 1] })).toThrow(/8\.3 or later/);
    expect(() => rewrite(`curl -H "A: ${REF}" https://api.github.com/`, { version: null })).toThrow(/could not be read/);
    expect(atLeast([8, 3, 0], [8, 3])).toBe(true);
    expect(atLeast([7, 88], [8, 3])).toBe(false);
  });
  it("wget: the value-carrying options are fed by the shell's printf to --config=/dev/stdin; a reference in a wget URL is refused", () => {
    const { argv } = rewrite(`wget -qO- --header="Authorization: Bearer ${REF}" https://api.github.com/user`);
    const inner = argv[2] as string;
    expect(inner).toMatch(/^printf '%s\\n' "header = Authorization: Bearer \$\{__LSV_1\}" \| \/opt\/bin\/wget --config=\/dev\/stdin --max-redirect=0 -qO- https:\/\/api\.github\.com\/user$/);
    expect(planShellRewrite(`wget -O - "https://api.github.com/x?t=${REF}"`)).toMatchObject({ ok: false, why: expect.stringMatching(/use curl/) });
  });
  it("run as /bin/sh would: the sender's arguments never hold the value (stand-in curl and wget print theirs)", (ctx) => {
    skipWithoutExec(ctx);
    const bin = join(mkdtempSync(join(testRoot(), "vault-audit-bin-")), "bin");
    mkdirSync(bin);
    writeFileSync(join(bin, "curl"), '#!/bin/sh\nprintf "ARG:%s\\n" "$@"\n');
    writeFileSync(join(bin, "wget"), '#!/bin/sh\nprintf "ARG:%s\\n" "$@"\nwhile IFS= read -r line; do printf "CONF:%s\\n" "$line"; done\n');
    chmodSync(join(bin, "curl"), 0o755);
    chmodSync(join(bin, "wget"), 0o755);
    for (const [cmd, exe] of [[`curl -sS -H "Authorization: Bearer ${REF}" https://api.github.com/user`, join(bin, "curl")], [`wget -qO- --header="Authorization: Bearer ${REF}" https://api.github.com/user`, join(bin, "wget")]] as const) {
      const { argv, env } = rewrite(cmd, { exe });
      const out = execFileSync(argv[0] as string, argv.slice(1), { encoding: "utf8", env: { PATH: "/usr/bin:/bin", [env[0]?.[0] as string]: TOKEN } });
      const args = out.split("\n").filter((x) => x.startsWith("ARG:"));
      expect(args.length, cmd).toBeGreaterThan(0);
      expect(args.join("\n"), cmd).not.toContain(TOKEN);
      if (cmd.startsWith("wget")) expect(out).toContain(`CONF:header = Authorization: Bearer ${TOKEN}`);
    }
  });
});

describe("I6: the ticketed sender's environment is an allowlist", () => {
  it("PATH, HOME, LANG, LC_*, TERM, TZ only", () => {
    const e = ticketBaseEnv({ PATH: "/usr/bin", HOME: "/h", LANG: "C", LC_ALL: "C", TERM: "xterm", TZ: "UTC", GITHUB_TOKEN: "x", HTTPS_PROXY: "http://p", BASH_ENV: "/tmp/x", NODE_OPTIONS: "--require x", CURL_HOME: "/x" });
    expect(Object.keys(e).sort()).toEqual(["HOME", "LANG", "LC_ALL", "PATH", "TERM", "TZ"]);
  });
});

describe("I7: process bindings and the program run starts", () => {
  it("an absolute binding matches only that file; a relative one never; a bare name never inside the workspace", () => {
    expect(processBindingFor(["/usr/bin/env", "*"], { argv: ["env", "x"], program: "/usr/bin/env" })).toBe(true);
    expect(processBindingFor(["/usr/bin/env", "*"], { argv: ["env"], program: "/tmp/env" })).toBe(false);
    expect(processBindingFor(["./deploy"], { argv: ["./deploy"], program: "/w/deploy" })).toBe(false);
    expect(processBindingFor(["gh", "*"], { argv: ["gh", "api"], program: "/usr/bin/gh", workspace: "/w" })).toBe(true);
    expect(processBindingFor(["gh", "*"], { argv: ["gh", "api"], program: "/w/node_modules/.bin/gh", workspace: "/w" })).toBe(false);
    expect(processBindingFor(["gh", "*"], { argv: ["/tmp/gh", "api"], program: "/tmp/gh", workspace: "/w" })).toBe(false);
  });
  it("a bare-name binding refuses an unresolved program or a workspace symlink to an outside binary", () => {
    expect(processBindingFor(["gh", "*"], { argv: ["gh", "api"], workspace: "/w" })).toBe(false);
    const ws = mkdtempSync(join(testRoot(), "vault-audit-ws-"));
    const binDir = join(ws, "node_modules", ".bin");
    mkdirSync(binDir, { recursive: true });
    const link = join(binDir, "gh");
    symlinkSync("/usr/bin/env", link);
    expect(processBindingFor(["gh", "*"], { argv: ["gh", "pr", "list"], program: link, workspace: ws })).toBe(false);
  });
});

describe("I8: a ticket is bound to the agent the hook ran under", () => {
  it("the nearest living ancestor of the hook must be an ancestor of the spender", () => {
    const alive = (p: number): boolean => p !== 300;
    expect(lineageProblem([300, 200, 100], { ancestors: [900, 800, 200, 100], alive })).toBeNull();
    expect(lineageProblem([300, 200, 100], { ancestors: [900, 800, 100], alive })).toMatch(/not started by the agent/);
    expect(lineageProblem([300], { ancestors: [900], alive })).toMatch(/gone/);
    expect(lineageProblem([200], { ancestors: null, alive })).toMatch(/could not be read/);
    expect(lineageProblem([], { ancestors: [900], alive })).toMatch(/could not be read/);
    expect(lineageProblem(undefined, { ancestors: [900], alive })).toMatch(/could not be read/);
  });
  it("fails closed on empty ancestry, checks (pid, start) against PID reuse, and bounds ancestry at the coding agent", () => {
    const table = new Map<number, ProcessParent>([
      [700, { ppid: 600, start: "t700", cmd: "node /opt/lsfw/dist/cli.js hook" }],
      [600, { ppid: 500, start: "t600", cmd: "/bin/sh -c launchsafe-firewall hook" }],
      [500, { ppid: 400, start: "t500", cmd: "node /opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js" }],
      [400, { ppid: 300, start: "t400", cmd: "-zsh" }],
      [300, { ppid: 200, start: "t300", cmd: "tmux: server" }],
      [200, { ppid: 1, start: "t200", cmd: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal" }],
    ]);
    const issuedAncestors = ancestry(700, () => table);
    expect(issuedAncestors).toEqual([
      { pid: 600, start: "t600" },
      { pid: 500, start: "t500" },
    ]);
    expect(ancestry(700, () => null)).toBeNull();

    // Legitimate run under the same live coding agent (wrapper shell 600 exited, agent 500 alive with start t500).
    expect(
      lineageProblem(issuedAncestors!, {
        ancestors: [
          { pid: 900, start: "t900" },
          { pid: 850, start: "t850" },
          { pid: 500, start: "t500" },
        ],
        alive: (pid, start) => pid === 500 && start === "t500",
      }),
    ).toBeNull();

    // Agent 500 exited while a 180s ask ticket was unspent; shell 400 and tmux 300 are still alive in the session.
    expect(
      lineageProblem(issuedAncestors!, {
        ancestors: [
          { pid: 950, start: "t950" },
          { pid: 400, start: "t400" },
          { pid: 300, start: "t300" },
        ],
        alive: (pid) => pid === 400 || pid === 300 || pid === 200,
      }),
    ).toMatch(/gone/);

    // PID 500 was reused by another process with a different start time.
    expect(
      lineageProblem(issuedAncestors!, {
        ancestors: [
          { pid: 950, start: "t950" },
          { pid: 500, start: "t500-reused" },
        ],
        alive: (pid, start) => pid === 500 && start === "t500-reused",
      }),
    ).toMatch(/gone/);
    expect(
      lineageProblem(issuedAncestors!, {
        ancestors: [
          { pid: 950, start: "t950" },
          { pid: 500, start: "t500-reused" },
        ],
        alive: () => true,
      }),
    ).toMatch(/not started by the agent/);

    // consumeTicket fails closed when the ticket's ancestors could not be read ([]).
    const l = layout(join(mkdtempSync(join(testRoot(), "vault-audit-")), "home"));
    const env: [string, string][] = [["__LSV_1", REF]];
    const argv = ["/bin/sh", "-c", "x"];
    const tEmpty = issueTicket(l, { env, argv, session: "s", substitute: [], seconds: 30, ancestors: [] });
    expect(consumeTicket(l, tEmpty, env, argv)).toEqual({
      ok: false,
      why: "the processes above the hook could not be read, so the ticket's agent cannot be confirmed",
    });
  });
  it("consumeTicket refuses a spender outside the agent's tree, and the ticket is spent", () => {
    const l = layout(join(mkdtempSync(join(testRoot(), "vault-audit-")), "home"));
    const env: [string, string][] = [["__LSV_1", REF]];
    const argv = ["/bin/sh", "-c", "x"];
    const t = issueTicket(l, { env, argv, session: "s", substitute: [], seconds: 30, ancestors: [process.pid] });
    expect(consumeTicket(l, t, env, argv, new Date(), () => ({ ancestors: [1234567], alive: () => true }))).toEqual({ ok: false, why: "this run was not started by the agent the ticket was issued to" });
    expect(consumeTicket(l, t, env, argv).ok).toBe(false);
    const t2 = issueTicket(l, { env, argv, session: "s", substitute: [], seconds: 30, ancestors: [process.pid] });
    expect(consumeTicket(l, t2, env, argv).ok).toBe(true);
  });
  it("an asked action's ticket lasts three minutes, not ten", () => {
    expect(ASK_SECONDS).toBe(180);
  });
});

describe("minor: the ticket sweep and the file store", () => {
  it("a sweep leaves another process's freshly taken ticket alone", () => {
    const l = layout(join(mkdtempSync(join(testRoot(), "vault-audit-")), "home"));
    mkdirSync(ticketsDir(l), { recursive: true });
    const taken = join(ticketsDir(l), "abc.json.taken.0011223344ff");
    writeFileSync(taken, JSON.stringify({ kind: "run", expires: Date.now() + 30000 }));
    issueTicket(l, { env: [], argv: ["x"], session: "s", substitute: [], seconds: 30, ancestors: [] }); // writes, and sweeps
    expect(existsSync(taken)).toBe(true);
    expect(readdirSync(ticketsDir(l)).filter((n) => n.endsWith(".json"))).toHaveLength(1);
  });
  it("the file store opened with an empty passphrase neither writes nor reads, and no store is created", () => {
    const l = layout(join(mkdtempSync(join(testRoot(), "vault-audit-")), "home"));
    const locked = fileBackend(l, "");
    expect(() => locked.write("a/value", "secret-value-123", { confirm: "never" })).toThrow(/locked/);
    expect(existsSync(storePath(l))).toBe(false);
    const open = fileBackend(l, "correct horse");
    open.write("a/value", "secret-value-123", { confirm: "never" });
    expect(() => fileBackend(l, "").read("a/value")).toThrow(/locked/);
    expect(open.read("a/value")).toBe("secret-value-123");
  });
});

describe("the sender is found only among trusted system files", () => {
  it("a user-owned curl in a PATH directory is never chosen", () => {
    const dir = mkdtempSync(join(testRoot(), "vault-sender-"));
    writeFileSync(join(dir, "curl"), "#!/bin/sh\necho 'curl 8.9.0'\n");
    chmodSync(join(dir, "curl"), 0o755);
    expect(resolveSender("curl", dir)).toBeNull();
    expect(resolveSender("curl", `${dir}:${dir}`)).toBeNull();
  });
});

describe("rotate keeps the index true when a later field cannot be written", () => {
  it("the fields already replaced get their new fingerprints, and the error is raised", () => {
    const l = layout(join(mkdtempSync(join(testRoot(), "vault-rotate-")), "home"));
    const pass = "correct horse battery";
    initApprover(l, pass);
    const priv = unlockApprover(l, pass);
    const store = fakeBackend();
    const A1 = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B1 = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const A2 = "ghp_cccccccccccccccccccccccccccccccccccc";
    const B2 = "ghp_dddddddddddddddddddddddddddddddddddd";
    addSecret(l, priv, { name: "app/keys", kind: "credential", fields: ["id", "secret"], values: { id: A1, secret: B1 }, confirm: "never", backend: store });
    const real = store.write.bind(store);
    store.write = (account, value, o) => {
      if (account.endsWith(":secret")) throw new Error("the store refused the second field");
      real(account, value, o);
    };
    expect(() => rotateSecret(l, priv, "app/keys", { id: A2, secret: B2 }, () => store)).toThrow(/refused the second field/);
    const st = loadIndex(l, publicKeyOf(priv));
    const e = st.state === "ok" ? st.index.entries[0] : undefined;
    expect(store.values.get("app/keys:id")?.value).toBe(A2);
    expect(e?.fingerprints.id).toBe(fingerprint(A2));
    expect(e?.fingerprints.secret).toBe(fingerprint(B1));
  });
});

describe("substitution is a single pass over whole references", () => {
  it("a value that contains another reference is not expanded again, and glued text is not a reference", () => {
    const values = [
      { ref: "vault://a/one", value: "x-vault://b/two-y" },
      { ref: "vault://b/two", value: "SECOND" },
    ];
    expect(substituteJson({ v: "k=vault://a/one" }, values)).toEqual({ v: "k=x-vault://b/two-y" });
    expect(substituteJson({ v: "vault://b/two and vault://b/two2 and xvault://b/two" }, values)).toEqual({ v: "SECOND and vault://b/two2 and xvault://b/two" });
  });
});
