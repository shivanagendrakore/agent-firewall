/**
 * The hook command loads dist/hook/bundle.js (scripts/bundle-hook.mjs) instead of ~150 separate modules.
 * These check that the bundle is the hook that runs, that it decides like the modules do (including the
 * paths it locates from its own file: the install directory it protects), that an old bundle is never
 * used, and that the compile cache lives in the firewall's data directory.
 */
import { describe, it, expect } from "vitest";
import { cpSync, existsSync, mkdirSync, readdirSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPO, spawnCli, tempHome, UNDER_COVERAGE } from "./helpers.js";

/** A copy of the built package somewhere else, so its install directory is not this repository. */
function copyPackage(): string {
  const pkg = join(tempHome("pkg-"), "agent-firewall");
  mkdirSync(pkg, { recursive: true });
  cpSync(join(REPO, "dist"), join(pkg, "dist"), { recursive: true, preserveTimestamps: true });
  cpSync(join(REPO, "package.json"), join(pkg, "package.json"));
  return pkg;
}

/** A node --import file that prints the dist modules the process loaded, one per line, to stderr. */
function tracer(): string {
  const f = join(tempHome("trace-"), "trace.mjs");
  writeFileSync(f, `import module from "node:module";\nconst seen = [];\nmodule.registerHooks({ load(url, ctx, next) { if (url.includes("/dist/")) seen.push(url.replace(/.*\\/dist\\//, "")); return next(url, ctx); } });\nprocess.on("exit", () => process.stderr.write("LOADED " + seen.join(" ") + "\\n"));\n`);
  return f;
}

function hookCall(pkg: string, home: string, tool: string, input: Record<string, unknown>, trace?: string, extraEnv: Record<string, string | undefined> = {}) {
  const ws = join(home, "proj");
  mkdirSync(ws, { recursive: true });
  const event = JSON.stringify({ hook_event_name: "PreToolUse", session_id: "b1", cwd: ws, permission_mode: "default", tool_name: tool, tool_input: input });
  const r = spawnCli(["hook"], { home, cli: join(pkg, "dist", "cli.js"), input: event, cwd: ws, env: { CLAUDE_PROJECT_DIR: ws, ...extraEnv }, ...(trace !== undefined ? { nodeArgs: ["--import", trace] } : {}) });
  const loaded = /LOADED (.*)/.exec(r.stderr)?.[1]?.split(" ") ?? [];
  return { r, loaded };
}

describe("hook bundle", () => {
  it("is built, newer than the modules it was made from, and exports what hook/claude.js exports", async () => {
    const bundle = join(REPO, "dist", "hook", "bundle.js");
    expect(existsSync(bundle)).toBe(true);
    expect(statSync(bundle).mtimeMs).toBeGreaterThanOrEqual(statSync(join(REPO, "dist", "hook", "claude.js")).mtimeMs);
    const a = (await import(join(REPO, "dist", "hook", "claude.js"))) as Record<string, unknown>;
    const b = (await import(bundle)) as Record<string, unknown>;
    expect(Object.keys(b).sort()).toEqual(Object.keys(a).sort());
  });

  it("is what the hook command loads, and it protects its own install directory", () => {
    const pkg = copyPackage();
    const home = tempHome();
    const { r, loaded } = hookCall(pkg, home, "Write", { file_path: join(pkg, "dist", "hook", "bundle.js"), content: "export {}" }, tracer());
    expect(loaded).toContain("hook/bundle.js");
    expect(loaded).not.toContain("hook/claude.js");
    expect(loaded.length).toBeLessThan(15);
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
    // An ordinary workspace command is allowed through the bundle as through the modules.
    const ok = hookCall(pkg, home, "Bash", { command: "git status" });
    expect(ok.r.status).toBe(0);
    expect(ok.r.stdout).not.toContain('"deny"');
  });

  it("an old bundle (tsc ran after it) is not used: the modules load instead", () => {
    const pkg = copyPackage();
    const bundle = join(pkg, "dist", "hook", "bundle.js");
    const old = new Date(statSync(join(pkg, "dist", "hook", "claude.js")).mtimeMs - 60_000);
    utimesSync(bundle, old, old);
    const home = tempHome();
    const { r, loaded } = hookCall(pkg, home, "Write", { file_path: join(pkg, "dist", "cli.js"), content: "x" }, tracer());
    expect(loaded).toContain("hook/claude.js");
    expect(loaded).not.toContain("hook/bundle.js");
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
  });

  it("a bundle that fails to load fails the hook closed", () => {
    const pkg = copyPackage();
    writeFileSync(join(pkg, "dist", "hook", "bundle.js"), "throw new Error('broken bundle');\n");
    const { r } = hookCall(pkg, tempHome(), "Bash", { command: "git status" });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("broken bundle");
  });

  it.skipIf(UNDER_COVERAGE)("keeps the compile cache in the firewall's data directory, only once that directory exists", () => {
    const pkg = copyPackage();
    const home = tempHome();
    const fw = join(home, ".launchsafe-firewall");
    // The first call creates the firewall's directory (mode 700) itself; the cache does not create it.
    // Node keeps no compile cache while NODE_V8_COVERAGE is set (npm run coverage sets it for child processes).
    const noCoverage = { NODE_V8_COVERAGE: undefined };
    hookCall(pkg, home, "Bash", { command: "git status" }, undefined, noCoverage);
    expect(statSync(fw).mode & 0o777).toBe(0o700);
    hookCall(pkg, home, "Bash", { command: "git status" }, undefined, noCoverage);
    const cache = join(fw, "cache", "compile");
    expect(existsSync(cache)).toBe(true);
    expect(readdirSync(cache).length).toBeGreaterThan(0);
  });
});
