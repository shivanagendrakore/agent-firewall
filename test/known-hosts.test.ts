/**
 * Known hosts (knownHosts, FW-NEW-HOST): "ask before the agent contacts a website it has never contacted in
 * this project". The engine rule, the policy's tighten-only rules for a project file, the per-project list
 * in the firewall's own directory through the real hook (ask once, the yes is learned; never while
 * tainted; watch mode and its review), the CLI, and the friction corpus.
 */
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { ALWAYS_FINE, PACKAGES_FINE, TOOL_CASES, TRUSTED_ONLY, V02_FINE } from "../src/corpus.js";
import { BUILTIN_KNOWN_HOSTS, builtinsKnownThroughLists, contactedHosts, isKnownHost, knownHostRules, learnableHost } from "../src/engine/knownhosts.js";
import type { RuleHit } from "../src/engine/decide.js";
import { runHook, type HookEnv } from "../src/hook/claude.js";
import { main } from "../src/climain.js";
import { knownHostsPolicy } from "../src/policy-knownhosts.js";
import { defaultConfig, mergeTighten, mergeTrusted, PolicyError, validatePolicy } from "../src/policy.js";
import { approvalSigner, initApprover, unlockApprover } from "../src/runtime/approver.js";
import { allowHosts, approvedHosts, confirmPending, KNOWN_HOSTS_LOCK, knownHostsChecks, knownHostsFile, notePending, proposals, readKnownHosts, recordSeen } from "../src/runtime/knownhosts.js";
import { layout, type Layout } from "../src/runtime/layout.js";
import { decideQueueItem, listQueue } from "../src/runtime/store.js";
import type { FirewallConfig } from "../src/types.js";
import { bash, ctx, explain, HOME, REPO, run, state, tempHome, testEnv, testRoot, WS } from "./helpers.js";

const ASK = { knownHosts: { mode: "ask" as const } };

describe("FW-NEW-HOST in the engine", () => {
  it("off by default: a new host changes nothing", () => {
    expect(run("WebFetch", { url: "https://new.example.dev/guide", prompt: "p" }).verdict).toBe("allow");
    expect(bash("curl https://new.example.dev/x").verdict).toBe("allow");
    expect(knownHostsPolicy(defaultConfig()).mode).toBe("off");
  });

  it("a new host asks, through a web fetch tool, a shell network command and an MCP fetch-like tool", () => {
    const w = run("WebFetch", { url: "https://new.example.dev/guide", prompt: "p" }, { config: ASK });
    expect(w.verdict, explain(w)).toBe("ask");
    expect(w.rules).toEqual(["FW-NEW-HOST"]);
    expect(w.reasons[0]).toMatch(/this project has never contacted new\.example\.dev before\. If you allow it, new\.example\.dev is added to this project's known hosts/);
    for (const c of ["curl https://new.example.dev/x", "wget https://new.example.dev/f", "git clone https://new.example.dev/r.git", "ssh new.example.dev ls", "http GET new.example.dev"]) {
      const d = bash(c, { config: ASK });
      expect(d.verdict, `${c}: ${explain(d)}`).toBe("ask");
      expect(d.rules, c).toContain("FW-NEW-HOST");
    }
    const m = run("mcp__fetch__fetch", { url: "https://new.example.dev/x" }, { config: ASK });
    expect(m.rules, explain(m)).toContain("FW-NEW-HOST");
  });

  it("an approved host passes; approval is per exact host", () => {
    const known = { ctx: { knownHosts: { approved: ["new.example.dev"] } }, config: ASK };
    expect(run("WebFetch", { url: "https://new.example.dev/guide", prompt: "p" }, known).verdict).toBe("allow");
    expect(bash("curl https://new.example.dev/x", known).verdict).toBe("allow");
    expect(run("mcp__fetch__fetch", { url: "https://new.example.dev/x" }, known).rules).not.toContain("FW-NEW-HOST");
    expect(bash("curl https://other.new.example.dev/x", known).rules).toContain("FW-NEW-HOST");
  });

  it("the person's own host lists and the built-in hosts are known; builtins: false turns only the built-in set off", () => {
    expect(bash("curl https://api.anthropic.com/v1/models", { config: ASK }).verdict).toBe("allow");
    expect(bash("npm install lodash", { config: ASK }).verdict).toBe("allow");
    expect(bash("curl https://api.github.com/repos/acme/app", { config: ASK }).verdict).toBe("allow");
    const off = { knownHosts: { mode: "ask" as const, builtins: false } };
    expect(bash("curl https://api.anthropic.com/v1/models", { config: off }).rules).toContain("FW-NEW-HOST");
    // docs.python.org is in the default fetchAllowHosts: the person's list, not the built-in set.
    expect(bash("curl https://docs.python.org/3/", { config: off }).verdict).toBe("allow");
    expect(bash("curl https://corp.example/x", { config: { ...ASK, sendAllowHosts: ["corp.example"] } }).verdict).toBe("allow");
  });

  it("builtins: false removes every built-in host that no list names; the default fetchAllowHosts is a list, so the registries and GitHub's code hosts stay known until it is set", () => {
    const off = { knownHosts: { mode: "ask" as const, builtins: false } };
    // A strict start: builtins off and a fetchAllowHosts of the person's own that leaves the registries out.
    const strict = { ...off, fetchAllowHosts: ["docs.python.org"], sendAllowHosts: [] as string[] };
    // Every built-in host, with no list naming it: known while the set is on, not once it is off.
    for (const p of BUILTIN_KNOWN_HOSTS) {
      const h = p.replace(/^=/, "");
      expect(isKnownHost(h, { ...defaultConfig(), ...ASK, fetchAllowHosts: [] }, []), `${h} with the set on`).toBe(true);
      expect(isKnownHost(h, { ...defaultConfig(), ...strict }, []), `${h} with the set off and no list naming it`).toBe(false);
    }
    // The reported case: with only builtins off, the default fetchAllowHosts still names the registries (documented).
    expect(run("WebFetch", { url: "https://registry.npmjs.org/lodash", prompt: "p" }, { config: off }).rules).not.toContain("FW-NEW-HOST");
    for (const url of ["https://pypi.org/simple/requests/", "https://crates.io/api/v1/crates/serde", "https://github.com/acme/app", "https://gitlab.com/acme/app", "https://codeload.github.com/acme/app/tar.gz/main"]) {
      expect(bash(`curl ${url}`, { config: off }).rules, `${url} (default list)`).not.toContain("FW-NEW-HOST");
    }
    // The built-in hosts no default list names ask as soon as the set is off.
    for (const url of ["https://api.anthropic.com/v1/models", "https://api.openai.com/v1/models", "https://api.github.com/repos/acme/app", "https://formulae.brew.sh/api/formula.json", "https://bitbucket.org/acme/app"]) {
      expect(bash(`curl ${url}`, { config: ASK }).rules, `${url} (set on)`).not.toContain("FW-NEW-HOST");
      expect(bash(`curl ${url}`, { config: off }).rules, `${url} (set off)`).toContain("FW-NEW-HOST");
    }
    // With a list of the person's own that leaves them out, the registries ask too: every way the agent names one.
    expect(run("WebFetch", { url: "https://registry.npmjs.org/lodash", prompt: "p" }, { config: strict }).rules).toContain("FW-NEW-HOST");
    expect(bash("npm view lodash", { config: strict }).rules).toContain("FW-NEW-HOST");
    for (const url of ["https://registry.npmjs.org/lodash", "https://pypi.org/simple/requests/", "https://crates.io/api/v1/crates/serde", "https://github.com/acme/app", "https://gitlab.com/acme/app", "https://codeload.github.com/acme/app/tar.gz/main"]) {
      const d = bash(`curl ${url}`, { config: strict });
      expect(d.verdict, `${url}: ${explain(d)}`).toBe("ask");
      expect(d.rules, url).toContain("FW-NEW-HOST");
      expect(bash(`curl ${url}`, { config: ASK }).rules, `${url} (set on)`).not.toContain("FW-NEW-HOST");
    }
    // A host the person's own lists name stays known with the set off, built-in or not.
    expect(bash("curl https://registry.npmjs.org/lodash", { config: { ...strict, fetchAllowHosts: ["registry.npmjs.org"] } }).rules).not.toContain("FW-NEW-HOST");
    expect(bash("curl https://api.openai.com/v1/models", { config: { ...strict, sendAllowHosts: ["api.openai.com"] } }).rules).not.toContain("FW-NEW-HOST");
    // A host the person approved for this project passes whatever the lists say.
    expect(bash("curl https://registry.npmjs.org/lodash", { config: strict, ctx: { knownHosts: { approved: ["registry.npmjs.org"] } } }).rules).not.toContain("FW-NEW-HOST");
  });

  it("builtinsKnownThroughLists names the built-in hosts a list still covers: the registries and GitHub's code hosts by default, none for a list that leaves them out", () => {
    const kept = builtinsKnownThroughLists(defaultConfig());
    expect(kept).toEqual(expect.arrayContaining(["registry.npmjs.org", "pypi.org", "crates.io", "codeload.github.com", "=github.com", "=gitlab.com", "raw.githubusercontent.com"]));
    for (const h of ["api.anthropic.com", "api.openai.com", "api.github.com", "formulae.brew.sh", "=claude.ai", "=bitbucket.org", "generativelanguage.googleapis.com", "api2.cursor.sh"]) expect(kept, h).not.toContain(h);
    // Nothing is listed twice, and what is listed is built in.
    expect(new Set(kept).size).toBe(kept.length);
    for (const h of kept) expect(BUILTIN_KNOWN_HOSTS, h).toContain(h);
    expect(builtinsKnownThroughLists({ fetchAllowHosts: ["docs.python.org"], sendAllowHosts: [] })).toEqual([]);
    expect(builtinsKnownThroughLists({ fetchAllowHosts: [], sendAllowHosts: ["api.openai.com"] })).toEqual(["api.openai.com"]);
  });

  it("builtinsKnownThroughLists reports exactly the built-in hosts isKnownHost still knows with builtins off", () => {
    const lists: Pick<FirewallConfig, "fetchAllowHosts" | "sendAllowHosts">[] = [
      { fetchAllowHosts: defaultConfig().fetchAllowHosts, sendAllowHosts: [] },
      { fetchAllowHosts: ["docs.python.org"], sendAllowHosts: [] },
      { fetchAllowHosts: ["=registry.npmjs.org", "*.github.com"], sendAllowHosts: ["api.openai.com"] },
      { fetchAllowHosts: ["github.com"], sendAllowHosts: [] },
      { fetchAllowHosts: [], sendAllowHosts: ["crates.io", "=claude.ai"] },
    ];
    for (const cfg of lists) {
      const kept = builtinsKnownThroughLists(cfg);
      for (const p of BUILTIN_KNOWN_HOSTS) {
        const known = isKnownHost(p.replace(/^=/, ""), { ...defaultConfig(), ...cfg, knownHosts: { mode: "ask", builtins: false } }, []);
        expect(kept.includes(p), `${p} with ${JSON.stringify(cfg)}`).toBe(known);
      }
    }
    // A list that covers part of the set: one exact entry, and GitHub's subdomains but not github.com itself.
    expect(builtinsKnownThroughLists({ fetchAllowHosts: ["=registry.npmjs.org", "*.github.com"], sendAllowHosts: [] })).toEqual(["registry.npmjs.org", "npm.pkg.github.com", "codeload.github.com", "api.github.com"]);
  });

  // docs/limitations.md: a package manager's default registry is not read as a contact, but a registry named by
  // option or a package given as a URL is. These pin the second half, in every spelling the installers accept.
  it("a package command that names its registry or index asks about that host as new: by option, in every spelling and every time, or a package given as a URL", () => {
    const cases: [string, string[]][] = [
      ["npm install --registry https://npm.new.example.dev lodash", ["npm.new.example.dev"]],
      ["npm install --registry=https://npm.new.example.dev lodash", ["npm.new.example.dev"]],
      ["npm install --@acme:registry=https://npm.new.example.dev @acme/ui", ["npm.new.example.dev"]],
      // Without "=", npm reads the scope's option as a switch and the URL as a package to fetch: contacted either way.
      ["npm install --@acme:registry https://npm.new.example.dev @acme/ui", ["npm.new.example.dev"]],
      ["pnpm add --@acme:registry=https://npm.new.example.dev @acme/ui", ["npm.new.example.dev"]],
      ["pip install -i https://pypi.new.example.dev/simple requests", ["pypi.new.example.dev"]],
      ["pip install -ihttps://pypi.new.example.dev/simple requests", ["pypi.new.example.dev"]],
      ["pip install --index-url https://pypi.new.example.dev/simple requests", ["pypi.new.example.dev"]],
      ["pip install --index-url=https://pypi.new.example.dev/simple requests", ["pypi.new.example.dev"]],
      ["pip install --extra-index-url=https://pypi.new.example.dev/simple requests", ["pypi.new.example.dev"]],
      // Every index option counts, not only the first one given.
      ["pip install -i https://pypi.new.example.dev/simple --extra-index-url https://extra.new.example.dev/simple requests", ["pypi.new.example.dev", "extra.new.example.dev"]],
      ["pip install --find-links https://wheels.new.example.dev/ requests", ["wheels.new.example.dev"]],
      ["pip install --find-links=https://wheels.new.example.dev/ requests", ["wheels.new.example.dev"]],
      ["pip install -fhttps://wheels.new.example.dev/ requests", ["wheels.new.example.dev"]],
      ["pip install --trusted-host pypi.new.example.dev requests", ["pypi.new.example.dev"]],
      ["uv add --index=https://pypi.new.example.dev/simple requests", ["pypi.new.example.dev"]],
      ["uv add --default-index=https://pypi.new.example.dev/simple requests", ["pypi.new.example.dev"]],
      // uv's named index: name=URL.
      ["uv add --index internal=https://pypi.new.example.dev/simple requests", ["pypi.new.example.dev"]],
      ["uv add --index=internal=https://pypi.new.example.dev/simple requests", ["pypi.new.example.dev"]],
      ["cargo install --index sparse+https://index.new.example.dev/ ripgrep", ["index.new.example.dev"]],
      ["gem install --source https://gems.new.example.dev rails", ["gems.new.example.dev"]],
      ["npm install https://new.example.dev/pkg.tgz", ["new.example.dev"]],
      ["pip install git+https://new.example.dev/acme/tool.git", ["new.example.dev"]],
      // Not an install: the registry a metadata command asks is the one named.
      ["npm view lodash --registry https://npm.new.example.dev", ["npm.new.example.dev"]],
    ];
    for (const [cmd, hosts] of cases) {
      const d = bash(cmd, { config: ASK });
      expect(d.verdict, `${cmd}: ${explain(d)}`).toBe("ask");
      expect(d.rules, cmd).toContain("FW-NEW-HOST");
      for (const host of hosts) expect(d.reasons.join(" "), cmd).toContain(`this project has never contacted ${host} before`);
      // Approved for this project, the same command does not ask about them.
      expect(bash(cmd, { config: ASK, ctx: { knownHosts: { approved: hosts } } }).rules, `${cmd} (approved)`).not.toContain("FW-NEW-HOST");
    }
  });

  it("a registry option before the command does not hide it: the install and the publish are seen, and so is the registry", () => {
    for (const cmd of ["npm --registry https://npm.new.example.dev install lodash", "pnpm --registry https://npm.new.example.dev add lodash", "yarn --registry https://npm.new.example.dev add lodash"]) {
      const d = bash(cmd, { config: ASK });
      expect(d.effects.some((e) => e.cls === "execute" && (e.tags ?? []).includes("install")), `${cmd}: ${explain(d)}`).toBe(true);
      expect(d.effects.some((e) => e.cls === "egress_fetch" && e.host === "npm.new.example.dev"), cmd).toBe(true);
      expect(d.rules, cmd).toContain("FW-NEW-HOST");
    }
    // The package goes to the named registry: a send, judged as the same publish with the option after the command.
    for (const tainted of [false, true]) {
      const before = bash("npm --registry https://npm.new.example.dev publish", { tainted });
      const after = bash("npm publish --registry https://npm.new.example.dev", { tainted });
      expect(before.effects.some((e) => e.cls === "egress_send" && e.host === "npm.new.example.dev"), explain(before)).toBe(true);
      expect([before.verdict, before.rules], explain(before)).toEqual([after.verdict, after.rules]);
    }
    // After outside content, that send asks.
    const p = bash("npm --registry https://npm.new.example.dev publish", { tainted: true });
    expect(p.verdict, explain(p)).not.toBe("allow");
  });

  it("a registry read and pip's --trusted-host named before the command are seen too", () => {
    // A metadata read asks the named registry, and what it brings back is written by package authors: outside content.
    const v = bash("npm --registry https://npm.new.example.dev view lodash", { config: ASK });
    expect(v.effects.some((e) => e.cls === "egress_fetch" && e.host === "npm.new.example.dev"), explain(v)).toBe(true);
    expect(v.effects.some((e) => e.cls === "read_external" && e.taints === true), explain(v)).toBe(true);
    expect(v.rules, explain(v)).toContain("FW-NEW-HOST");
    // pip's one index option that goes before the command (a general option) takes a value too.
    const t = bash("pip --trusted-host pypi.new.example.dev install requests", { config: ASK });
    expect(t.effects.some((e) => e.cls === "execute" && (e.tags ?? []).includes("install")), explain(t)).toBe(true);
    expect(t.rules, explain(t)).toContain("FW-NEW-HOST");
    expect(t.reasons.join(" ")).toContain("this project has never contacted pypi.new.example.dev before");
  });

  // npm reads an option it does not know, and a scope's --@scope:registry without "=", as a switch, and pnpm, yarn
  // and bun find their command the same way: of the index options, they take a value only for --registry.
  const NPM_SWITCHES = ["--source", "--index", "--index-url", "--extra-index-url", "--default-index", "--find-links", "--trusted-host", "--@acme:registry"];

  it("npm, pnpm, yarn and bun: an index option other than --registry before the command is a switch, and the install after it is seen", () => {
    for (const [tool, verb] of [["npm", "install"], ["pnpm", "add"], ["yarn", "add"], ["bun", "add"]] as const) {
      for (const tainted of [false, true]) {
        const plain = bash(`${tool} ${verb} evil-pkg`, { tainted });
        for (const flag of NPM_SWITCHES) {
          // The same install of evil-pkg, judged the same way: after outside content, FW-INSTALL.
          const cmd = `${tool} ${flag} ${verb} evil-pkg`;
          const d = bash(cmd, { tainted });
          expect(d.effects.some((e) => e.cls === "execute" && (e.tags ?? []).includes("install") && e.detail.includes("evil-pkg")), `${cmd}: ${explain(d)}`).toBe(true);
          expect([d.verdict, d.rules], `${cmd}: ${explain(d)}`).toEqual([plain.verdict, plain.rules]);
          if (tainted) expect(d.rules, cmd).toContain("FW-INSTALL");
        }
      }
    }
  });

  it("npm, pnpm and yarn: a publish after such a switch is still a publish, a send to the registry", () => {
    // FW-SECRET-FILE-PUBLISH judges it in any session once credentials were copied into a file, FW-SEND after outside content.
    const copied = [{ type: "secret_path" as const, path: `${WS}/dist/.env` }];
    for (const [cmd, tool] of [["npm --index publish", "npm"], ["npm --@acme:registry publish", "npm"], ["npm --source publish", "npm"], ["pnpm --index-url publish", "pnpm"], ["yarn --find-links publish", "yarn"]] as const) {
      for (const o of [{ events: copied }, { tainted: true }]) {
        const plain = bash(`${tool} publish`, o);
        const d = bash(cmd, o);
        expect(d.effects.some((e) => e.cls === "egress_send" && e.destination === `${tool}:registry`), `${cmd}: ${explain(d)}`).toBe(true);
        expect([d.verdict, d.rules], `${cmd}: ${explain(d)}`).toEqual([plain.verdict, plain.rules]);
      }
      expect(bash(cmd, { events: copied }).rules, cmd).toContain("FW-SECRET-FILE-PUBLISH");
    }
  });

  it("npm, pnpm, yarn and bun: a package name with a dot in it after such a switch is a package, not a registry host", () => {
    for (const cmd of ["npm install --index lodash.merge", "pnpm add --source chart.js", "yarn add --find-links socket.io", "bun add --index-url lodash.merge"]) {
      const d = bash(cmd, { config: ASK });
      expect(d.rules, `${cmd}: ${explain(d)}`).not.toContain("FW-NEW-HOST");
      expect(d.effects.filter((e) => e.cls === "egress_fetch" || e.cls === "egress_send").map((e) => e.host), cmd).toEqual([]);
      expect(d.effects.some((e) => e.cls === "execute" && (e.tags ?? []).includes("install")), cmd).toBe(true);
    }
  });

  it("a local index or wheel directory is read like a package given as a path, not contacted", () => {
    for (const cmd of ["pip install --find-links ./wheels requests", "pip install --find-links=./wheels requests", "pip install -f ./wheels requests"]) {
      const d = bash(cmd, { config: ASK });
      expect(d.effects.some((e) => e.cls.startsWith("read") && e.target === `${WS}/wheels`), `${cmd}: ${explain(d)}`).toBe(true);
      expect(d.effects.filter((e) => e.cls === "egress_fetch" || e.cls === "egress_send"), cmd).toEqual([]);
    }
  });

  it("-f and -i name an index only for the Python installers: npm's -f (force) and pnpm's -i (interactive) are followed by a package, not a host", () => {
    for (const cmd of ["npm install -f socket.io", "yarn add -f chart.js", "pnpm update -i lodash.merge", "apt-get install -f python3.11"]) {
      const d = bash(cmd, { config: ASK });
      expect(d.rules, `${cmd}: ${explain(d)}`).not.toContain("FW-NEW-HOST");
      expect(d.effects.filter((e) => e.cls === "egress_fetch" || e.cls === "egress_send").map((e) => e.host), cmd).toEqual([]);
      // Still an install of that package.
      expect(d.effects.some((e) => e.cls === "execute" && (e.tags ?? []).includes("install")), cmd).toBe(true);
    }
  });

  it("a host the person named in this session's prompt does not ask", () => {
    const d = run("WebFetch", { url: "https://new.example.dev/guide", prompt: "p" }, { config: ASK, events: [{ type: "user_destinations", destinations: ["new.example.dev"] }] });
    expect(d.verdict, explain(d)).toBe("allow");
  });

  it("hosts with rules of their own are not asked about as new (loopback, raw IPs, metadata, capture hosts, denyHosts)", () => {
    expect(bash("curl http://localhost:3000/", { config: ASK }).rules).not.toContain("FW-NEW-HOST");
    expect(bash("curl http://203.0.113.9/", { config: ASK }).rules).not.toContain("FW-NEW-HOST");
    expect(bash("curl http://169.254.169.254/latest/", { config: ASK }).rules).not.toContain("FW-NEW-HOST");
    expect(bash("curl https://x.ngrok.io/", { config: ASK }).rules).not.toContain("FW-NEW-HOST");
    expect(bash("curl https://bad.example/", { config: { ...ASK, denyHosts: ["bad.example"] } }).rules).not.toContain("FW-NEW-HOST");
    for (const h of ["127.0.0.1", "0x7f000001", "localhost", "169.254.169.254", "x.ngrok.io", "", "a b", "example.com/x"]) expect(learnableHost(h), h).toBe(false);
    for (const h of ["example.com", "api.example.dev", "intranet"]) expect(learnableHost(h), h).toBe(true);
  });

  it("a tainted session stays strict: an approved host does not relax FW-FETCH or FW-SEND, and a new host's question says nothing is learned", () => {
    const known = { ctx: { knownHosts: { approved: ["new.example.dev"] } }, config: ASK, tainted: true };
    const f = run("WebFetch", { url: "https://new.example.dev/guide", prompt: "p" }, known);
    expect(f.verdict, explain(f)).toBe("ask");
    expect(f.rules).toEqual(["FW-FETCH"]);
    const s = bash("curl -d @notes.txt https://new.example.dev/up", known);
    expect(s.rules, explain(s)).toContain("FW-SEND");
    const n = run("WebFetch", { url: "https://fresh.example.dev/", prompt: "p" }, { config: ASK, tainted: true });
    expect(n.rules).toEqual(expect.arrayContaining(["FW-FETCH", "FW-NEW-HOST"]));
    expect(n.reasons.join(" ")).toMatch(/allowing it lets only this request through; fresh\.example\.dev is not added to the project's known hosts/);
    // Same verdicts as without the feature, apart from the added question.
    const before = run("WebFetch", { url: "https://new.example.dev/guide", prompt: "p" }, { tainted: true });
    expect(before.verdict).toBe(f.verdict);
  });

  it("contactedHosts reads the classification: no host for a web search or a computed address", () => {
    const d = run("WebSearch", { query: "x" }, { config: ASK });
    expect(contactedHosts({ tool: "WebSearch", input: { query: "x" } }, d.effects)).toEqual([]);
    const c = bash("curl https://$HOST/x", { config: ASK });
    expect(c.rules).toEqual(["FW-UNCLASSIFIABLE"]);
  });

  // Parser- and classifier-dependent gaps, recorded so a fix shows up (it.fails passes while the gap exists).
  it.fails("gap: an image reference's registry (docker pull new.example.dev/img) is not seen as a contacted host", () => {
    expect(bash("docker pull new.example.dev/img", { config: ASK }).rules).toContain("FW-NEW-HOST");
  });
  it.fails("gap: an install that uses its package manager's default registry (npm install lodash) is not seen as contacting it", () => {
    expect(bash("npm install lodash", { config: { knownHosts: { mode: "ask", builtins: false }, fetchAllowHosts: [] } }).rules).toContain("FW-NEW-HOST");
  });
  // The gap above, stated exactly, so the it.fails passes for that reason and no other (it.fails also passes when
  // its body throws). Delete both when the default registry is read as a contact.
  it("the recorded gap: npm install with the default registry is an install and no contact, so even a strict list does not ask", () => {
    const d = bash("npm install lodash", { config: { knownHosts: { mode: "ask", builtins: false }, fetchAllowHosts: [] } });
    expect(d.effects.filter((e) => e.cls === "egress_fetch" || e.cls === "egress_send").map((e) => e.host), explain(d)).toEqual([]);
    expect(d.effects.some((e) => e.cls === "execute" && (e.tags ?? []).includes("install")), explain(d)).toBe(true);
    expect(d.rules).not.toContain("FW-NEW-HOST");
  });
  it.fails("gap: a git remote named in .git/config (git push origin) is not resolved to its host", () => {
    expect(bash("git push origin main", { config: ASK, ctx: { readFile: (p) => (p.endsWith("/.git/config") ? '[remote "origin"]\n\turl = https://new.example.dev/r.git\n' : null) } }).rules).toContain("FW-NEW-HOST");
  });
});

describe("knownHosts policy: a repository may only tighten, and can never add a host", () => {
  it("validation: modes, builtins, watchDays; a host list is not a setting", () => {
    expect(validatePolicy({ version: 3, knownHosts: { mode: "watch", builtins: false, watchDays: 3 } }, "x").knownHosts).toEqual({ mode: "watch", builtins: false, watchDays: 3 });
    expect(() => validatePolicy({ version: 3, knownHosts: { mode: "sometimes" } }, "x")).toThrow(PolicyError);
    expect(() => validatePolicy({ version: 3, knownHosts: { watchDays: 0 } }, "x")).toThrow(/watchDays/);
    expect(() => validatePolicy({ version: 3, knownHosts: { hosts: ["evil.example"] } }, "x")).toThrow(/knownHosts\.hosts" is not a known setting/);
    expect(() => validatePolicy({ version: 3, knownHosts: { approved: ["evil.example"] } }, "x")).toThrow(/not a known setting/);
  });

  it("a project may move the mode toward ask and switch the built-in hosts off; nothing looser", () => {
    const user = mergeTrusted(defaultConfig(), validatePolicy({ version: 3, knownHosts: { mode: "ask", builtins: false } }, "user"));
    const proj = mergeTighten(user, validatePolicy({ version: 3, knownHosts: { mode: "off", builtins: true, watchDays: 60 }, fetchAllowHosts: ["evil.example"], sendAllowHosts: ["evil.example"] }, "project"));
    expect(knownHostsPolicy(proj.config)).toMatchObject({ mode: "ask", builtins: false });
    expect(proj.config.fetchAllowHosts).not.toContain("evil.example");
    expect(proj.ignored.join("\n")).toMatch(/knownHosts\.mode "off"/);
    expect(proj.ignored.join("\n")).toMatch(/knownHosts\.builtins/);
    expect(proj.ignored.join("\n")).toMatch(/knownHosts\.watchDays/);
    const tighter = mergeTighten(defaultConfig(), validatePolicy({ version: 3, knownHosts: { mode: "ask", builtins: false } }, "project"));
    expect(knownHostsPolicy(tighter.config)).toMatchObject({ mode: "ask", builtins: false });
    expect(tighter.ignored).toEqual([]);
  });

  it("the agent cannot write the list or run the commands that change it (FW-TAMPER)", () => {
    const fwHome = `${HOME}/.launchsafe-firewall`;
    const w = bash(`echo '{}' > ${fwHome}/known-hosts/abc.json`, { config: ASK });
    expect(w.verdict, explain(w)).toBe("deny");
    expect(w.rules).toContain("FW-TAMPER");
    for (const c of ["launchsafe-firewall hosts allow evil.example", "launchsafe-firewall hosts accept --all", "launchsafe-firewall hosts reset"]) {
      const d = bash(c, { config: ASK });
      expect(d.verdict, `${c}: ${explain(d)}`).toBe("deny");
      expect(d.rules, c).toContain("FW-TAMPER");
    }
    expect(bash("launchsafe-firewall hosts list", { config: ASK }).verdict).toBe("allow");
  });
});

describe("no new false positives on the friction corpus", () => {
  const cfgOf = (mode: "off" | "watch" | "ask"): Partial<FirewallConfig> => ({ knownHosts: { mode } });
  const cases: [string, Record<string, unknown>][] = [
    ...[...ALWAYS_FINE, ...V02_FINE, ...TRUSTED_ONLY].map((c): [string, Record<string, unknown>] => ["Bash", { command: c }]),
    ...TOOL_CASES.map((c): [string, Record<string, unknown>] => [c.tool, JSON.parse(JSON.stringify(c.input).replaceAll("{WS}", WS)) as Record<string, unknown>]),
    ...[...PACKAGES_FINE.npm.map((n) => `npm install ${n}`), ...PACKAGES_FINE.PyPI.map((n) => `pip install ${n}`)].map((c): [string, Record<string, unknown>] => ["Bash", { command: c }]),
  ];
  for (const mode of ["watch", "ask"] as const) {
    it(`mode ${mode}: every corpus case has the same verdict and rules as with the feature off, trusted and untrusted`, () => {
      const diff: string[] = [];
      for (const [tool, input] of cases) {
        for (const tainted of [false, true]) {
          const a = run(tool, input, { tainted });
          const b = run(tool, input, { tainted, config: cfgOf(mode) });
          if (a.verdict !== b.verdict || a.rules.join() !== b.rules.join()) diff.push(`${tool} ${JSON.stringify(input).slice(0, 80)} (${tainted ? "untrusted" : "trusted"}): ${a.verdict} -> ${b.verdict} ${b.rules.join(",")}`);
        }
      }
      expect(diff).toEqual([]);
    });
  }
  it("the built-in set covers the hosts the corpus's installs and API calls use", () => {
    for (const h of ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "github.com", "api.github.com", "crates.io", "api.anthropic.com"]) expect(BUILTIN_KNOWN_HOSTS.some((p) => p.replace(/^=/, "") === h), h).toBe(true);
  });
});

// --- through the real hook, in a temporary home ---------------------------------------------------------

let home: string, ws: string, l: Layout, clock: number, seq = 0;

beforeEach(() => {
  noProject = false;
  home = tempHome("knownhosts-home-");
  ws = mkdtempSync(join(testRoot(), "knownhosts-ws-"));
  l = layout(join(home, ".launchsafe-firewall"));
  clock = Date.UTC(2026, 9, 13, 9, 0, 0);
});

const session = (): string => `kh${++seq}`;

function userPolicy(doc: Record<string, unknown>): void {
  mkdirSync(l.home, { recursive: true });
  writeFileSync(l.policy, JSON.stringify({ version: 3, ...doc }));
}

let noProject = false;

function env(unattended = false): HookEnv {
  return { env: noProject ? {} : { CLAUDE_PROJECT_DIR: ws }, layout: l, home, scratchRoots: [join(home, "tmp")], now: new Date(clock), detectNonInteractive: () => unattended, notifyDeps: { spawn: () => undefined, platform: "darwin", executable: () => true, now: () => clock } };
}

function verdictOf(out: string): string {
  if (out.trim() === "") return "allow";
  const o = JSON.parse(out) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
  const dec = o.hookSpecificOutput?.permissionDecision;
  if (dec === "ask") return "ask";
  if (dec === "deny") return /held this for review/.test(o.hookSpecificOutput?.permissionDecisionReason ?? "") ? "queue" : "deny";
  return "allow";
}

function pre(s: string, tool: string, input: Record<string, unknown>, unattended = false, mode = "default"): { verdict: string; reason: string } {
  const r = runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: s, cwd: ws, permission_mode: mode, tool_name: tool, tool_input: input }), env(unattended));
  const reason = r.stdout.trim() === "" ? "" : ((JSON.parse(r.stdout) as { hookSpecificOutput?: { permissionDecisionReason?: string } }).hookSpecificOutput?.permissionDecisionReason ?? "");
  return { verdict: verdictOf(r.stdout), reason };
}

function post(s: string, tool: string, input: Record<string, unknown>, response: unknown = "ok"): string {
  return runHook(JSON.stringify({ hook_event_name: "PostToolUse", session_id: s, cwd: ws, tool_name: tool, tool_input: input, tool_response: response }), env()).stderr;
}

/** A tool call that runs when allowed or asked (the person says yes): PreToolUse, then PostToolUse. */
function call(s: string, tool: string, input: Record<string, unknown>): string {
  const r = pre(s, tool, input);
  if (r.verdict === "allow" || r.verdict === "ask") post(s, tool, input);
  return r.verdict;
}

const fetchNew = (host = "new.example.dev"): Record<string, unknown> => ({ url: `https://${host}/guide`, prompt: "summarize" });

function taint(s: string): void {
  // Reading a page on an approved-by-default host taints without asking.
  post(s, "WebFetch", { url: "https://github.com/acme/app/issues/1", prompt: "read" }, "outside content");
}

describe("the hook: ask once, learn the yes, per project", () => {
  it("a new host asks; once the person says yes (the tool ran) it is learned, and the next contact passes", () => {
    userPolicy({ knownHosts: { mode: "ask" } });
    const s = session();
    const first = pre(s, "WebFetch", fetchNew());
    expect(first.verdict).toBe("ask");
    expect(first.reason).toMatch(/FW-NEW-HOST/);
    expect(first.reason).toMatch(/If you allow it, new\.example\.dev is added to this project's known hosts/);
    expect(approvedHosts(l, ws)).toEqual([]);
    const note = post(s, "WebFetch", fetchNew());
    expect(note).toMatch(/added new\.example\.dev to this project's known hosts/);
    expect(approvedHosts(l, ws)).toEqual(["new.example.dev"]);
    expect(readKnownHosts(l, ws).file.approved[0]?.via).toBe("asked");
    expect(readFileSync(join(l.log, "decisions.jsonl"), "utf8")).toMatch(/known_hosts_added/);
    // A new session in the same project: known (the shell's curl too).
    const s2 = session();
    // (Each in a fresh session: what a fetch returns is outside content, so it taints the session it ran in.)
    expect(pre(s2, "WebFetch", fetchNew()).verdict).toBe("allow");
    expect(pre(session(), "Bash", { command: "curl https://new.example.dev/x" }).verdict).toBe("allow");
    // Another project: not known there.
    const other = mkdtempSync(join(testRoot(), "knownhosts-other-"));
    expect(approvedHosts(l, other)).toEqual([]);
  });

  it("a question the person declined (no PostToolUse) teaches nothing", () => {
    userPolicy({ knownHosts: { mode: "ask" } });
    const s = session();
    expect(pre(s, "WebFetch", fetchNew()).verdict).toBe("ask");
    expect(pre(s, "WebFetch", fetchNew()).verdict).toBe("ask");
    // A PostToolUse for a different action does not confirm it.
    post(s, "WebFetch", fetchNew("other.example.dev"));
    expect(approvedHosts(l, ws)).toEqual([]);
    // An hour later the unanswered question has expired: a PostToolUse then teaches nothing.
    clock += 61 * 60 * 1000;
    post(s, "WebFetch", fetchNew());
    expect(approvedHosts(l, ws)).toEqual([]);
  });

  it("a tainted session stays strict: its yes lets one request through and learns nothing", () => {
    userPolicy({ knownHosts: { mode: "ask" } });
    const s = session();
    taint(s);
    const r = pre(s, "WebFetch", fetchNew());
    expect(r.verdict).toBe("ask");
    expect(r.reason).toMatch(/FW-FETCH/);
    expect(r.reason).toMatch(/is not added to the project's known hosts/);
    post(s, "WebFetch", fetchNew());
    expect(approvedHosts(l, ws)).toEqual([]);
    expect(readKnownHosts(l, ws).file.pending).toEqual([]);
    expect(pre(session(), "WebFetch", fetchNew()).verdict).toBe("ask");
  });

  it("a tainted session's queue approval learns nothing; a trusted one's does", () => {
    userPolicy({ knownHosts: { mode: "ask" } });
    initApprover(l, "known hosts test passphrase");
    const priv = unlockApprover(l, "known hosts test passphrase");
    const approveAll = (): void => {
      for (const item of listQueue(l).items.filter((q) => q.status === "pending")) decideQueueItem(l, item.id, "approved", approvalSigner(priv));
    };
    const t = session();
    taint(t);
    expect(pre(t, "WebFetch", fetchNew("tainted.example.dev"), true).verdict).toBe("queue");
    approveAll();
    expect(pre(t, "WebFetch", fetchNew("tainted.example.dev"), true).verdict).toBe("allow");
    post(t, "WebFetch", fetchNew("tainted.example.dev"));
    expect(approvedHosts(l, ws)).toEqual([]);
    const s = session();
    expect(pre(s, "WebFetch", fetchNew(), true).verdict).toBe("queue");
    approveAll();
    expect(pre(s, "WebFetch", fetchNew(), true).verdict).toBe("allow");
    post(s, "WebFetch", fetchNew());
    expect(readKnownHosts(l, ws).file.approved).toMatchObject([{ host: "new.example.dev", via: "queue" }]);
  });

  it("a repository cannot pre-approve hosts: its policy and any file it ships are not the list", () => {
    userPolicy({ knownHosts: { mode: "ask" } });
    writeFileSync(join(ws, ".launchsafe-firewall.json"), JSON.stringify({ version: 3, fetchAllowHosts: ["new.example.dev"], sendAllowHosts: ["new.example.dev"], knownHosts: { mode: "ask" } }));
    // A copy of what the list file looks like, planted in the repository where a careless reader might look.
    const planted = join(ws, ".launchsafe-firewall", "known-hosts");
    mkdirSync(planted, { recursive: true });
    writeFileSync(join(planted, knownHostsFile(l, ws).split("/").pop() as string), JSON.stringify({ version: 1, project: ws, approved: [{ host: "new.example.dev", at: new Date(clock).toISOString(), via: "cli" }], pending: [] }));
    const r = pre(session(), "WebFetch", fetchNew());
    expect(r.verdict).toBe("ask");
    expect(r.reason).toMatch(/FW-NEW-HOST/);
    // A repository's policy cannot turn the question off either.
    writeFileSync(join(ws, ".launchsafe-firewall.json"), JSON.stringify({ version: 3, knownHosts: { mode: "off" } }));
    expect(pre(session(), "WebFetch", fetchNew()).verdict).toBe("ask");
  });

  it("a damaged list fails closed: no host counts as approved, and the file is left for the person", () => {
    userPolicy({ knownHosts: { mode: "ask" } });
    allowHosts(l, ws, ["new.example.dev"], "cli", new Date(clock));
    expect(pre(session(), "WebFetch", fetchNew()).verdict).toBe("allow");
    writeFileSync(knownHostsFile(l, ws), "{ not json");
    const s = session();
    expect(pre(s, "WebFetch", fetchNew()).verdict).toBe("ask");
    post(s, "WebFetch", fetchNew());
    expect(readFileSync(knownHostsFile(l, ws), "utf8")).toBe("{ not json");
  });

  it("the list file holds only learnable hosts: a forged entry for an IP address makes the whole file damaged", () => {
    mkdirSync(join(l.home, "known-hosts"), { recursive: true });
    writeFileSync(knownHostsFile(l, ws), JSON.stringify({ version: 1, project: readKnownHosts(l, ws).file.project, approved: [{ host: "169.254.169.254", at: "x", via: "cli" }], pending: [] }));
    expect(readKnownHosts(l, ws).damaged).toBe(true);
    expect(approvedHosts(l, ws)).toEqual([]);
  });

  it("pending questions keep only learnable hosts, are per session and action, and expire", () => {
    const now = new Date(clock);
    notePending(l, ws, { session: "a", hash: "h1", hosts: ["new.example.dev", "127.0.0.1", "x.ngrok.io"], via: "asked" }, now);
    expect(confirmPending(l, ws, "b", "h1", now)).toEqual([]);
    expect(confirmPending(l, ws, "a", "h2", now)).toEqual([]);
    expect(confirmPending(l, ws, "a", "h1", now)).toEqual(["new.example.dev"]);
    expect(confirmPending(l, ws, "a", "h1", now)).toEqual([]);
  });
});

describe("watch mode: record, then propose a list", () => {
  it("nothing asks; contacted hosts are recorded, tainted ones apart; review proposes; accept --all approves; then ask mode passes them", async () => {
    userPolicy({ knownHosts: { mode: "watch", watchDays: 3 } });
    const s = session();
    // What a fetch returns taints the session it ran in, so each trusted contact gets a fresh session.
    expect(call(s, "Bash", { command: "curl https://api.example.dev/v1" })).toBe("allow");
    expect(call(session(), "Bash", { command: "curl https://api.example.dev/v2" })).toBe("allow");
    expect(call(session(), "WebFetch", fetchNew())).toBe("allow");
    // Data sent to a host: recorded, listed apart, not in --all.
    expect(call(session(), "Bash", { command: "curl -d x=1 https://upload.example.dev/in" })).toBe("allow");
    const t = session();
    taint(t);
    call(t, "Bash", { command: "curl https://attacker.example/x" });
    const f = readKnownHosts(l, ws).file;
    const p = proposals(f);
    expect(p.proposed.map((x) => x.host)).toEqual(["api.example.dev", "new.example.dev"]);
    expect(p.taintedOnly.map((x) => x.host)).toEqual(["attacker.example"]);
    expect(p.sentTo.map((x) => x.host)).toEqual(["upload.example.dev"]);
    expect(f.approved).toEqual([]);

    const out: string[] = [];
    const cli = (args: string[], person = true): Promise<number> => main(args, l, { write: (_fd, x) => void out.push(x), humanAtKeyboard: () => Promise.resolve(person) });
    expect(await cli(["hosts", "review", "--project", ws])).toBe(0);
    expect(out.join("")).toMatch(/Proposed \(2\)/);
    expect(out.join("")).toMatch(/Not proposed \(1\)[^\n]*outside content/);
    expect(await cli(["hosts", "accept", "--all", "--project", ws], false)).toBe(1);
    expect(approvedHosts(l, ws)).toEqual([]);
    expect(await cli(["hosts", "accept", "--all", "--project", ws])).toBe(0);
    expect(approvedHosts(l, ws).sort()).toEqual(["api.example.dev", "new.example.dev"]);
    // Neither the tainted-only host nor the one that received data is accepted by --all.
    expect(approvedHosts(l, ws)).not.toContain("attacker.example");
    expect(approvedHosts(l, ws)).not.toContain("upload.example.dev");

    userPolicy({ knownHosts: { mode: "ask" } });
    expect(pre(session(), "WebFetch", fetchNew()).verdict).toBe("allow");
    expect(pre(session(), "Bash", { command: "curl https://attacker.example/x" }).verdict).toBe("ask");
  });

  it("an action that did not run (declined, so no PostToolUse) is never recorded", () => {
    userPolicy({ knownHosts: { mode: "watch" } });
    expect(pre(session(), "WebFetch", fetchNew("declined.example.dev")).verdict).toBe("allow");
    expect(readKnownHosts(l, ws).file.watch).toBeUndefined();
    call(session(), "WebFetch", fetchNew("ran.example.dev"));
    expect(proposals(readKnownHosts(l, ws).file).proposed.map((x) => x.host)).toEqual(["ran.example.dev"]);
  });

  it("the watch ends after watchDays: nothing more is recorded", () => {
    const start = new Date(clock);
    expect(recordSeen(l, ws, [{ host: "a.example.dev", tainted: false }], "hook", 2, start)).toBe(true);
    expect(recordSeen(l, ws, [{ host: "b.example.dev", tainted: false }], "hook", 2, new Date(clock + 3 * 86400000))).toBe(false);
    expect(proposals(readKnownHosts(l, ws).file).proposed.map((x) => x.host)).toEqual(["a.example.dev"]);
  });
});

describe("hosts commands", () => {
  it("allow needs a person, refuses hosts that can never be approved, list shows the mode", async () => {
    const out: string[] = [];
    const cli = (args: string[], person = true): Promise<number> => main(args, l, { write: (_fd, x) => void out.push(x), humanAtKeyboard: () => Promise.resolve(person) });
    expect(await cli(["hosts", "allow", "docs.example.dev", "--project", ws], false)).toBe(1);
    expect(existsSync(knownHostsFile(l, ws))).toBe(false);
    expect(await cli(["hosts", "allow", "docs.example.dev", "169.254.169.254", "--project", ws])).toBe(1);
    expect(approvedHosts(l, ws)).toEqual(["docs.example.dev"]);
    expect(out.join("")).toMatch(/Not added: 169\.254\.169\.254/);
    expect(out.join("")).toMatch(/knownHosts\.mode is "off"/);
    out.length = 0;
    expect(await cli(["hosts", "list", "--project", ws])).toBe(0);
    expect(out.join("")).toMatch(/docs\.example\.dev/);
    expect(await cli(["hosts", "remove", "docs.example.dev", "--project", ws])).toBe(0);
    expect(approvedHosts(l, ws)).toEqual([]);
    expect(await cli(["hosts", "accept", "--project", ws])).toBe(64);
  });

  it("list says which built-in hosts stay known when builtins is off, because a list names them, and says nothing when no list does", async () => {
    const out: string[] = [];
    const cli = (args: string[]): Promise<number> => main(args, l, { write: (_fd, x) => void out.push(x), humanAtKeyboard: () => Promise.resolve(true) });
    const text = async (...args: string[]): Promise<string> => {
      out.length = 0;
      expect(await cli(["hosts", "list", ...args, "--project", ws])).toBe(0);
      return out.join("");
    };
    const json = async (): Promise<{ builtins: boolean; builtinHosts: string[]; builtinHostsKnownThroughLists: string[] }> => JSON.parse(await text("--json")) as { builtins: boolean; builtinHosts: string[]; builtinHostsKnownThroughLists: string[] };

    // Built in and on: the set is listed in full, and nothing is said to stay known through a list.
    userPolicy({ knownHosts: { mode: "ask" } });
    expect(await text()).not.toMatch(/Built-in hosts are off/);
    expect(await text()).toMatch(/turns off only these/);
    expect((await json()).builtinHosts).toEqual([...BUILTIN_KNOWN_HOSTS]);
    expect((await json()).builtinHostsKnownThroughLists).toEqual([]);

    // Off, with the default fetchAllowHosts: the registries and GitHub's code hosts are still known, and the answer says so.
    userPolicy({ knownHosts: { mode: "ask", builtins: false } });
    const off = await text();
    expect(off).toMatch(/Built-in hosts off\./);
    expect(off).toMatch(/Built-in hosts are off, but \d+ of them are still known because fetchAllowHosts or sendAllowHosts names them: [^\n]*registry\.npmjs\.org/);
    expect(off).toMatch(/set fetchAllowHosts without them/);
    const j = await json();
    expect(j.builtins).toBe(false);
    expect(j.builtinHosts).toEqual([]);
    expect(j.builtinHostsKnownThroughLists).toEqual(expect.arrayContaining(["registry.npmjs.org", "pypi.org", "=github.com"]));
    expect(j.builtinHostsKnownThroughLists).not.toContain("api.anthropic.com");

    // Off, with a fetchAllowHosts that leaves them out: every built-in host asks, and nothing is said to stay known.
    userPolicy({ knownHosts: { mode: "ask", builtins: false }, fetchAllowHosts: ["docs.python.org"] });
    expect(await text()).not.toMatch(/still known/);
    expect((await json()).builtinHostsKnownThroughLists).toEqual([]);
  });

  /** `hosts list` for ws through the real CLI: its text, or its parsed --json. */
  const list = async (...args: string[]): Promise<string> => {
    const out: string[] = [];
    expect(await main(["hosts", "list", ...args, "--project", ws], l, { write: (_fd, x) => void out.push(x), humanAtKeyboard: () => Promise.resolve(true) })).toBe(0);
    return out.join("");
  };
  const listJson = async (): Promise<{ builtins: boolean; builtinHosts: string[]; builtinHostsKnownThroughLists: string[] }> => JSON.parse(await list("--json")) as { builtins: boolean; builtinHosts: string[]; builtinHostsKnownThroughLists: string[] };

  it("list reports the built-in hosts still known when the project file, not the user policy, turns the set off", async () => {
    userPolicy({ knownHosts: { mode: "ask" } });
    expect((await listJson()).builtins).toBe(true);
    writeFileSync(join(ws, ".launchsafe-firewall.json"), JSON.stringify({ version: 3, knownHosts: { builtins: false } }));
    const j = await listJson();
    expect(j.builtins).toBe(false);
    expect(j.builtinHosts).toEqual([]);
    expect(j.builtinHostsKnownThroughLists).toEqual(builtinsKnownThroughLists(defaultConfig()));
    expect(j.builtinHostsKnownThroughLists).toEqual(expect.arrayContaining(["registry.npmjs.org", "=github.com"]));
    expect(j.builtinHostsKnownThroughLists).not.toContain("api.anthropic.com");
    expect(await list()).toMatch(/Built-in hosts are off, but \d+ of them are still known/);
  });

  it("list names a short kept list in full without an exact entry's '=', counts a long one, and its advice names the list that keeps them", async () => {
    userPolicy({ knownHosts: { mode: "ask", builtins: false }, fetchAllowHosts: ["=github.com", "registry.npmjs.org"], sendAllowHosts: ["api.openai.com"] });
    const both = await list();
    expect(both).toContain("Built-in hosts are off, but 3 of them are still known because fetchAllowHosts or sendAllowHosts names them: registry.npmjs.org, github.com, api.openai.com. To be asked about those too, set fetchAllowHosts and sendAllowHosts without them.");
    expect(both).not.toMatch(/=github\.com/);
    expect(both).not.toMatch(/ more\./);
    expect(both).toMatch(/fetchAllowHosts \(2\) and sendAllowHosts \(1\) from your policy \(a list you have not set keeps its defaults\)\./);
    expect((await listJson()).builtinHostsKnownThroughLists).toEqual(["registry.npmjs.org", "=github.com", "api.openai.com"]);

    // Only sendAllowHosts keeps one: setting fetchAllowHosts again would not make it ask, so the advice names sendAllowHosts.
    userPolicy({ knownHosts: { mode: "ask", builtins: false }, fetchAllowHosts: ["docs.python.org"], sendAllowHosts: ["api.openai.com"] });
    expect(await list()).toContain("Built-in hosts are off, but 1 of them is still known because fetchAllowHosts or sendAllowHosts names them: api.openai.com. To be asked about those too, set sendAllowHosts without them.");

    // The default fetchAllowHosts keeps more than six: the first six are named and the rest counted.
    userPolicy({ knownHosts: { mode: "ask", builtins: false } });
    const all = builtinsKnownThroughLists(defaultConfig()).map((h) => h.replace(/^=/, ""));
    expect(all.length).toBeGreaterThan(6);
    expect(await list()).toContain(`names them: ${all.slice(0, 6).join(", ")}, and ${all.length - 6} more. To be asked about those too, set fetchAllowHosts without them.`);
  });
});

describe("review fixes: nothing is learned without a trusted, attended yes", () => {
  it("stale pending then taint: a question declined while trusted is dropped by the tainted re-ask, and its yes teaches nothing", () => {
    userPolicy({ knownHosts: { mode: "ask" } });
    const s = session();
    expect(pre(s, "WebFetch", fetchNew()).verdict).toBe("ask");
    expect(readKnownHosts(l, ws).file.pending).toHaveLength(1);
    // Declined (no PostToolUse). Then the session reads outside content, and the identical call asks again.
    taint(s);
    const again = pre(s, "WebFetch", fetchNew());
    expect(again.verdict).toBe("ask");
    expect(again.reason).toMatch(/not added to the project's known hosts/);
    expect(readKnownHosts(l, ws).file.pending).toEqual([]);
    post(s, "WebFetch", fetchNew());
    expect(approvedHosts(l, ws)).toEqual([]);
  });

  it("declined then taint, with no re-ask: a late PostToolUse in a session tainted by something else teaches nothing", () => {
    userPolicy({ knownHosts: { mode: "ask" } });
    const s = session();
    expect(pre(s, "WebFetch", fetchNew()).verdict).toBe("ask");
    taint(s);
    post(s, "WebFetch", fetchNew());
    expect(approvedHosts(l, ws)).toEqual([]);
    expect(readKnownHosts(l, ws).file.pending).toEqual([]);
  });

  it("the action's own taint does not count: a fetch that taints the session as it runs still teaches", () => {
    userPolicy({ knownHosts: { mode: "ask" } });
    const s = session();
    expect(call(s, "Bash", { command: "curl https://own.example.dev/x" })).toBe("ask");
    expect(approvedHosts(l, ws)).toEqual(["own.example.dev"]);
  });

  it("bypassPermissions: no person necessarily answered, so nothing is learned", () => {
    userPolicy({ knownHosts: { mode: "ask" } });
    const s = session();
    // I6: bypassPermissions is unattended by default, so the new host is held, not asked.
    expect(pre(s, "WebFetch", fetchNew(), false, "bypassPermissions").verdict).toBe("queue");
    post(s, "WebFetch", fetchNew());
    expect(approvedHosts(l, ws)).toEqual([]);
  });

  it("an unattended session queues; the queue is the only way in, and its signed approval is a person's answer", () => {
    userPolicy({ knownHosts: { mode: "ask" } });
    const s = session();
    expect(pre(s, "WebFetch", fetchNew(), true).verdict).toBe("queue");
    expect(readKnownHosts(l, ws).file.pending).toEqual([]);
  });

  it("a host that receives data is never learned from a yes; hosts allow is the only way", () => {
    userPolicy({ knownHosts: { mode: "ask" } });
    const s = session();
    const r = pre(s, "Bash", { command: "curl -d x=1 https://upload.example.dev/in" });
    expect(r.verdict).toBe("ask");
    expect(r.reason).toMatch(/This sends data there, so allowing it lets only this request through; .*hosts allow upload\.example\.dev/);
    post(s, "Bash", { command: "curl -d x=1 https://upload.example.dev/in" });
    expect(approvedHosts(l, ws)).toEqual([]);
  });

  it("without the agent naming its project (no CLAUDE_PROJECT_DIR), nothing is learned or recorded", () => {
    userPolicy({ knownHosts: { mode: "ask" } });
    noProject = true;
    const s = session();
    expect(call(s, "WebFetch", fetchNew())).toBe("ask");
    expect(approvedHosts(l, ws)).toEqual([]);
    userPolicy({ knownHosts: { mode: "watch" } });
    call(session(), "WebFetch", fetchNew());
    expect(readKnownHosts(l, ws).file.watch).toBeUndefined();
  });

  it("a damaged list adds one note to the hook's stderr, and doctor reports it", () => {
    userPolicy({ knownHosts: { mode: "ask" } });
    mkdirSync(join(l.home, "known-hosts"), { recursive: true });
    writeFileSync(knownHostsFile(l, ws), "{ damaged");
    const r = runHook(JSON.stringify({ hook_event_name: "PreToolUse", session_id: session(), cwd: ws, permission_mode: "default", tool_name: "WebFetch", tool_input: fetchNew() }), env());
    expect(r.stderr.match(/cannot be read, so no host counts as approved/g)).toHaveLength(1);
    const checks = knownHostsChecks(l);
    expect(checks).toHaveLength(1);
    expect(checks[0]?.detail).toMatch(/cannot be read/);
  });
});

describe("review fixes: what counts as a contact", () => {
  it("a host that is not a plain name still asks, and says it cannot be remembered", () => {
    // A non-ASCII name in a URL arrives as punycode (a plain name); one the classifier passes through as it is does not.
    const hits: RuleHit[] = [];
    const cfg = { ...defaultConfig(), knownHosts: { mode: "ask" as const } };
    knownHostRules({ tool: "WebFetch", input: {} }, [{ cls: "egress_fetch", target: "x", host: "bücher.example", detail: "contact bücher.example" }], state(), cfg, ctx(), hits);
    expect(hits.map((h) => h.rule)).toEqual(["FW-NEW-HOST"]);
    expect(hits[0]?.reason).toMatch(/"bücher\.example".*not a plain host name, so the firewall cannot remember it/);
    expect(run("WebFetch", { url: "https://bücher.example/guide", prompt: "p" }, { config: ASK }).rules).toContain("FW-NEW-HOST");
    expect(learnableHost("bücher.example")).toBe(false);
    expect(learnableHost(`${"a".repeat(60)}.${"b".repeat(60)}.${"c".repeat(60)}.${"d".repeat(60)}.example`)).toBe(false);
  });

  it("MCP arguments are walked: nested URLs and bare hosts under address keys are contacts; other text is not", () => {
    const nested = run("mcp__browser__navigate", { options: { target: [{ url: "https://deep.example.dev/x" }] } }, { config: ASK });
    expect(nested.rules, explain(nested)).toContain("FW-NEW-HOST");
    expect(nested.reasons.join(" ")).toMatch(/deep\.example\.dev/);
    const bare = run("mcp__probe__check", { host: "bare.example.dev" }, { config: ASK });
    expect(bare.rules, explain(bare)).toContain("FW-NEW-HOST");
    const endpoint = run("mcp__probe__check", { config: { endpoint: "bare2.example.dev:8443/v1" } }, { config: ASK });
    expect(endpoint.reasons.join(" ")).toMatch(/bare2\.example\.dev/);
    const note = run("mcp__notes__read_note", { title: "see example.dev for details" }, { config: ASK });
    expect(note.rules).not.toContain("FW-NEW-HOST");
    // The walk's own caps (the classifier may still find an address on its own).
    let deep: Record<string, unknown> = { url: "https://toodeep.example.dev/" };
    for (let i = 0; i < 10; i++) deep = { x: deep };
    expect(contactedHosts({ tool: "mcp__probe__check", input: deep }, [])).toEqual([]);
    expect(contactedHosts({ tool: "mcp__probe__check", input: { x: { y: { url: "https://ok.example.dev/" } } } }, []).map((c) => c.host)).toEqual(["ok.example.dev"]);
    expect(contactedHosts({ tool: "mcp__probe__check", input: { url: `https://${"a".repeat(5000)}.example/` } }, [])).toEqual([]);
  });
});

describe("review fixes: the list file under concurrent writers", () => {
  it("a stale lock is broken; a live one makes a writer wait and then fail without touching the file", () => {
    const lock = `${knownHostsFile(l, ws)}.lock`;
    mkdirSync(join(l.home, "known-hosts"), { recursive: true });
    writeFileSync(lock, "");
    const old = new Date(clock - 3600_000);
    utimesSync(lock, old, old);
    expect(allowHosts(l, ws, ["a.example.dev"], "cli", new Date(clock)).added).toEqual(["a.example.dev"]);
    writeFileSync(lock, "");
    const saved = { ...KNOWN_HOSTS_LOCK };
    KNOWN_HOSTS_LOCK.timeoutMs = 150;
    try {
      expect(() => allowHosts(l, ws, ["b.example.dev"], "cli", new Date(clock))).toThrow(/timed out/);
    } finally {
      Object.assign(KNOWN_HOSTS_LOCK, saved);
      rmSync(lock, { force: true });
    }
    expect(approvedHosts(l, ws)).toEqual(["a.example.dev"]);
  });

  it("four processes writing at once lose no host", async () => {
    const WORKER = `
import { allowHosts } from "./dist/runtime/knownhosts.js";
import { layout } from "./dist/runtime/layout.js";
const [home, project, w] = process.argv.slice(2);
const l = layout(home);
for (let i = 0; i < 25; i++) allowHosts(l, project, ["w" + w + "-" + i + ".example.dev"], "cli", new Date());
`;
    await Promise.all(
      [0, 1, 2, 3].map(
        (w) =>
          new Promise<void>((resolve, reject) => {
            const p = spawn(process.execPath, ["--input-type=module", "-", l.home, ws, String(w)], { cwd: REPO, stdio: ["pipe", "ignore", "inherit"], env: testEnv(tempHome("kh-cc-")) });
            p.stdin.end(WORKER);
            p.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`worker ${w} exited ${code}`))));
          }),
      ),
    );
    expect(approvedHosts(l, ws)).toHaveLength(100);
    expect(readKnownHosts(l, ws).damaged).toBe(false);
  }, 60000);
});
