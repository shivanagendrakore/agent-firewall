/**
 * An unsupported platform fails closed and says so. macOS and Linux are the supported platforms; Windows is not
 * (docs/limitations.md): the hook command blocks the action (exit 2) with the reason, every other command refuses
 * before it reads or writes anything, the Node library throws when it is created, and package.json says
 * macOS and Linux only. The platform is injected (main()'s `platform` option, the library's `platform` option);
 * nothing here sets process.platform.
 */
import { closeSync, existsSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { COMMANDS, parseCommandLine } from "../src/cliargs.js";
import { HANDLERS, main } from "../src/climain.js";
import { assertSupportedPlatform, platformSupported, unsupportedPlatformMessage } from "../src/runtime/platform.js";
import { layout } from "../src/runtime/layout.js";
import * as sdkCore from "../src/sdk/index.js";
import * as sdkNode from "../src/sdk/node.js";
import { createNodeGuard, fileLedger, fileStore, nodeEnvironment } from "../src/sdk/node.js";
import * as sdkRemote from "../src/sdk/remote.js";
import * as sdkRemoteHttp from "../src/sdk/remote-http.js";
import { VERSION } from "../src/version.js";
import { REPO, tempHome } from "./helpers.js";

const UNSUPPORTED: NodeJS.Platform[] = ["win32", "freebsd", "openbsd", "aix", "sunos", "android", "cygwin"];

describe("which platforms are supported", () => {
  it.each(["darwin", "linux"] as const)("%s is supported", (p) => {
    expect(platformSupported(p)).toBe(true);
    expect(() => assertSupportedPlatform(p)).not.toThrow();
  });

  it.each(UNSUPPORTED)("%s is not: the check refuses it and names what is supported", (p) => {
    expect(platformSupported(p)).toBe(false);
    expect(() => assertSupportedPlatform(p)).toThrow(/macOS and Linux only/);
    expect(unsupportedPlatformMessage(p)).toContain(p === "win32" ? "Windows (win32)" : p);
  });

  it("the default is the platform this process runs on", () => {
    expect(platformSupported()).toBe(process.platform === "darwin" || process.platform === "linux");
  });
});

describe("the CLI on an unsupported platform", () => {
  let home: string;
  let stdinFd: number | null;
  const outs: string[] = [];
  const errs: string[] = [];
  const write = (fd: 1 | 2, s: string): void => void (fd === 1 ? outs : errs).push(s);
  const real: Record<string, (typeof HANDLERS)[string]> = { ...HANDLERS };
  const ran: string[] = [];

  /** A benign hook event on standard input: one the firewall allows on a supported platform. */
  const event = (): { fd: number } => {
    const ws = join(home, "ws");
    const file = join(home, "event.json");
    writeFileSync(file, JSON.stringify({ hook_event_name: "PreToolUse", session_id: "pg1", cwd: ws, permission_mode: "default", tool_name: "Read", tool_input: { file_path: join(ws, "a.ts") } }));
    stdinFd = openSync(file, "r");
    return { fd: stdinFd };
  };

  beforeEach(() => {
    home = tempHome("platform-gate-");
    outs.length = 0;
    errs.length = 0;
    ran.length = 0;
    stdinFd = null;
    // Handlers are replaced by stubs that only record they were called: a gate that failed to stop a command would run nothing real here.
    for (const key of Object.keys(HANDLERS)) {
      HANDLERS[key] = (): Promise<number> => {
        ran.push(key);
        return Promise.resolve(0);
      };
    }
  });
  afterEach(() => {
    Object.assign(HANDLERS, real);
    if (stdinFd !== null) closeSync(stdinFd);
  });

  const fw = (): string => join(home, ".launchsafe-firewall");

  it("the hook command blocks the action (exit 2) on Windows, says why, and reads and writes nothing", async () => {
    const code = await main(["hook"], layout(fw()), { platform: "win32", stdin: event(), write });
    expect(code).toBe(2);
    expect(ran).toEqual([]);
    expect(outs.join("")).toBe("");
    const said = errs.join("");
    expect(said).toContain("Windows (win32) is not supported");
    expect(said).toContain("macOS and Linux only");
    expect(said).toContain("blocked");
    expect(existsSync(fw())).toBe(false);
  });

  it.each(["claude", "codex", "gemini", "cursor"])("the hook command for %s blocks on Windows the same way", async (agent) => {
    const code = await main(["hook", "--agent", agent], layout(fw()), { platform: "win32", stdin: event(), write });
    expect(code).toBe(2);
    expect(ran).toEqual([]);
    expect(errs.join("")).toContain("Windows (win32) is not supported");
  });

  it.each(UNSUPPORTED)("the hook command blocks on %s (every platform that is not macOS or Linux)", async (platform) => {
    const code = await main(["hook"], layout(fw()), { platform, stdin: event(), write });
    expect(code).toBe(2);
    expect(ran).toEqual([]);
  });

  it.each(["darwin", "linux"] as const)("the same hook command is handed to the hook on %s", async (platform) => {
    const code = await main(["hook"], layout(fw()), { platform, stdin: event(), write });
    expect(code).toBe(0);
    expect(ran).toEqual(["hook"]);
    expect(errs.join("")).toBe("");
  });

  it("a hook command with a bad argument still blocks (exit 2), as it did before the platform check", async () => {
    const code = await main(["hook", "--no-such-flag"], layout(fw()), { platform: "win32", write });
    expect(code).toBe(2);
    expect(ran).toEqual([]);
  });

  it("every command but help and version is refused on Windows before its handler runs: exit 1, the reason on standard error, nothing on standard output, nothing created", async () => {
    const checked: string[] = [];
    for (const spec of COMMANDS) {
      const key = spec.path.join(" ");
      const argv = [...spec.path, ...Array.from({ length: spec.positionals.min }, () => (spec.positionals.int === true ? "1" : "x"))];
      if (parseCommandLine(argv).kind !== "ok") continue;
      ran.length = 0;
      outs.length = 0;
      errs.length = 0;
      const code = await main(argv, layout(fw()), { platform: "win32", write });
      if (key === "help" || key === "version") {
        expect(ran, key).toEqual([key]);
        expect(code, key).toBe(0);
        continue;
      }
      checked.push(key);
      expect(ran, key).toEqual([]);
      expect(code, key).toBe(key === "hook" ? 2 : 1);
      expect(errs.join(""), key).toContain("macOS and Linux only");
      expect(outs.join(""), key).toBe("");
    }
    // The commands the issue names, and most of the table: a spec that could not be parsed from its path alone is not skipped silently.
    for (const key of ["install", "uninstall", "doctor", "status", "run", "serve", "mcp wrap", "mcp serve", "gateway status", "openshell serve", "queue approve", "check"]) expect(checked, key).toContain(key);
    expect(checked.length).toBeGreaterThan(COMMANDS.length * 0.8);
    expect(existsSync(fw())).toBe(false);
  });

  it("run, the gateway and the local API say they are not supported, not that something else failed", async () => {
    for (const argv of [["run", "--", "true"], ["mcp", "wrap", "--client", "cursor", "--server", "s", "--", "true"], ["serve"]]) {
      errs.length = 0;
      expect(await main(argv, layout(fw()), { platform: "win32", write }), argv.join(" ")).toBe(1);
      expect(errs.join(""), argv.join(" ")).toMatch(/Windows \(win32\) is not supported.*This command did not run/);
    }
    expect(ran).toEqual([]);
  });

  it("help and version still work on Windows, so a person can see what the firewall is and why it refuses", async () => {
    for (const argv of [["--version"], ["-v"], ["version"], ["help"], ["--help"], ["hook", "--help"], ["install", "--help"]]) {
      outs.length = 0;
      expect(await main(argv, layout(fw()), { platform: "win32", write }), argv.join(" ")).toBe(0);
    }
    expect(ran).toEqual(["version", "version", "version", "help"]);
  });

  it("with the real handlers: the version is printed on Windows, and a command is refused without touching the firewall's directory", async () => {
    Object.assign(HANDLERS, real);
    expect(await main(["version"], layout(fw()), { platform: "win32", write })).toBe(0);
    expect(outs.join("")).toContain(VERSION);
    outs.length = 0;
    expect(await main(["status"], layout(fw()), { platform: "win32", write })).toBe(1);
    expect(outs.join("")).toBe("");
    expect(existsSync(fw())).toBe(false);
  });

  it("the platform option does not outlast the call: the next call sees the platform this process runs on", async () => {
    await main(["status"], layout(fw()), { platform: "win32", write });
    expect(ran).toEqual([]);
    expect(await main(["status"], layout(fw()), { write })).toBe(0);
    expect(ran).toEqual(["status"]);
  });
});

describe("the Node library on an unsupported platform", () => {
  it.each(UNSUPPORTED)("createNodeGuard, fileStore and nodeEnvironment throw on %s, before they create anything", (platform) => {
    const fw = join(tempHome("platform-sdk-"), ".launchsafe-firewall");
    expect(() => createNodeGuard({ platform })).toThrow(/macOS and Linux only/);
    expect(() => createNodeGuard({ platform, persist: "file", firewallHome: fw })).toThrow(/macOS and Linux only/);
    expect(() => fileStore({ home: fw, platform })).toThrow(/macOS and Linux only/);
    expect(() => nodeEnvironment({ platform })).toThrow(/macOS and Linux only/);
    expect(existsSync(fw)).toBe(false);
  });

  it("a store the caller gives does not get around the check", () => {
    const fw = join(tempHome("platform-sdk-"), ".launchsafe-firewall");
    const store = fileStore({ home: fw, platform: "linux" });
    expect(() => createNodeGuard({ platform: "win32", store })).toThrow(/Windows \(win32\) is not supported/);
  });

  it.each(["darwin", "linux"] as const)("they work on %s", (platform) => {
    const fw = join(tempHome("platform-sdk-"), ".launchsafe-firewall");
    expect(() => fileStore({ home: fw, platform })).not.toThrow();
    expect(() => nodeEnvironment({ platform })).not.toThrow();
    expect(() => createNodeGuard({ platform, persist: "file", firewallHome: fw })).not.toThrow();
  });

  it.each(UNSUPPORTED)("fileLedger, which reads and writes the firewall home's ledger, throws on %s before it touches the home", (platform) => {
    const fw = join(tempHome("platform-sdk-"), ".launchsafe-firewall");
    expect(() => fileLedger({ home: fw, platform })).toThrow(/macOS and Linux only/);
    expect(existsSync(fw)).toBe(false);
  });

  it.each(["darwin", "linux"] as const)("fileLedger works on %s", (platform) => {
    const fw = join(tempHome("platform-sdk-"), ".launchsafe-firewall");
    const ledger = fileLedger({ home: fw, platform });
    // Nothing has been recorded in this home yet: the file is unknown, not refused.
    expect(ledger.file(join(fw, "..", "nothing-written.ts"), 1024, false)).toBeNull();
  });

  /** One call per function src/sdk/node.ts adds that reads or writes the disk, made as on Windows. */
  const ON_WINDOWS: Record<string, (fw: string) => unknown> = {
    createNodeGuard: (fw) => createNodeGuard({ platform: "win32", persist: "file", firewallHome: fw }),
    fileLedger: (fw) => fileLedger({ home: fw, platform: "win32" }),
    fileStore: (fw) => fileStore({ home: fw, platform: "win32" }),
    nodeEnvironment: (fw) => nodeEnvironment({ platform: "win32", firewallHome: fw }),
  };
  /** What src/sdk/node.ts adds that touches nothing on disk: a signer holds its key in memory. */
  const IN_MEMORY = ["ed25519Signer"];

  it("every function the Node entry adds is either refused on Windows here or named as touching nothing on disk, so a new one cannot go unchecked", () => {
    // The browser-safe entry and the remote guard are re-exported; they hold no file access and have no platform check by design.
    const shared = new Set([...Object.keys(sdkCore), ...Object.keys(sdkRemote), ...Object.keys(sdkRemoteHttp)]);
    const added = Object.entries(sdkNode)
      .filter(([k, v]) => typeof v === "function" && !shared.has(k))
      .map(([k]) => k)
      .sort();
    expect(added).toEqual([...Object.keys(ON_WINDOWS), ...IN_MEMORY].sort());
    for (const [name, call] of Object.entries(ON_WINDOWS)) {
      const fw = join(tempHome("platform-sdk-"), ".launchsafe-firewall");
      expect(() => call(fw), name).toThrow(/Windows \(win32\) is not supported/);
      expect(existsSync(fw), name).toBe(false);
    }
  });
});

describe("package.json", () => {
  const pkg = JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")) as { os?: unknown; engines?: unknown };
  const lock = JSON.parse(readFileSync(join(REPO, "package-lock.json"), "utf8")) as { packages: Record<string, { os?: unknown }> };

  it("limits the package to macOS and Linux, so npm refuses to install it on Windows", () => {
    expect(pkg.os).toEqual(["darwin", "linux"]);
  });

  it("the lockfile's root entry says the same, so npm install does not rewrite it", () => {
    expect(lock.packages[""]?.os).toEqual(pkg.os);
  });
});
