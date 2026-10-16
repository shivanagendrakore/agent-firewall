/**
 * v0.3 `run`: the sandbox profile (pure) and the TLS server-name parser the proxy uses. The profile
 * is checked as text and argument lists here; test/run-sandbox.test.ts runs it.
 */
import { describe, expect, it } from "vitest";
import { BRIDGE_MARKER, bwrapArgs, bwrapMissing, filePlaceholder, guardedAncestors, HOME_UNREADABLE, sandboxExecArgs, seatbeltProfile, WORKSPACE_PROTECTED, writePathProblem, type RunPlan } from "../src/engine/run-profile.js";
import { buildClientHello, parseClientHello } from "../src/engine/tls-sni.js";

const plan = (over: Partial<RunPlan> = {}): RunPlan => ({
  platform: "darwin",
  workspace: "/Users/dev/proj",
  runTmp: "/private/var/folders/x/T/lsfw-run-1",
  writable: ["/Users/dev/proj", "/private/var/folders/x/T/lsfw-run-1"],
  readOnly: ["/Users/dev/.launchsafe-firewall", "/Users/dev/proj/.git/hooks"],
  unreadable: ["/Users/dev/.launchsafe-firewall/keys", "/Users/dev/.ssh"],
  socketDirs: ["/Users/dev/proj", "/private/var/folders/x/T/lsfw-run-1"],
  proxyPort: 51234,
  allowLocalhost: false,
  allowKeychain: false,
  ...over,
});

describe("seatbeltProfile", () => {
  it("passes every path as a parameter, never in the profile text", () => {
    const { text, params } = seatbeltProfile(plan());
    expect(text).not.toContain("/Users/dev");
    expect(params).toContainEqual(["W0", "/Users/dev/proj"]);
    expect(params).toContainEqual(["R1", "/Users/dev/proj/.git/hooks"]);
    expect(params).toContainEqual(["U1", "/Users/dev/.ssh"]);
  });
  it("network: deny all, then the proxy port and local binding only", () => {
    const { text } = seatbeltProfile(plan());
    expect(text).toContain("(deny network*)");
    expect(text).toContain('(allow network-outbound (remote ip "localhost:51234"))');
    expect(text).not.toContain('(remote ip "localhost:*")');
    expect(seatbeltProfile(plan({ allowLocalhost: true })).text).toContain('(allow network-outbound (remote ip "localhost:*"))');
  });
  it("writes: denied, then allowed for the writable params, then read-only paths denied last (last match wins)", () => {
    const { text } = seatbeltProfile(plan());
    const deny = text.indexOf("(deny file-write*)\n");
    const allow = text.indexOf('(allow file-write* (subpath (param "W0"))');
    const ro = text.indexOf('(deny file-write* (subpath (param "R0"))');
    expect(deny).toBeGreaterThan(-1);
    expect(allow).toBeGreaterThan(deny);
    expect(ro).toBeGreaterThan(allow);
    expect(text).toContain('(deny file-read* file-write* (subpath (param "U0")) (subpath (param "U1")))');
  });
  it("signals, Apple Events and the services that act outside the sandbox; keychain only without the flag", () => {
    const { text } = seatbeltProfile(plan());
    expect(text).toContain("(deny signal)\n(allow signal (target same-sandbox))");
    expect(text).toContain("(deny appleevent-send)");
    expect(text).toContain('(global-name "com.apple.coreservices.launchservicesd")');
    expect(text).toContain('(global-name "com.apple.SecurityServer")');
    expect(seatbeltProfile(plan({ allowKeychain: true })).text).not.toContain("SecurityServer");
  });
  it("V3: the directories leading to a protected path inside a writable one are denied as literals, after the read-only rules", () => {
    const { text, params } = seatbeltProfile(plan({ readOnly: ["/Users/dev/.launchsafe-firewall", "/Users/dev/proj/.git/hooks", "/Users/dev/proj/.claude/settings.json"] }));
    const lits = params.filter(([k]) => k.startsWith("A")).map(([, v]) => v);
    expect(lits.sort()).toEqual(["/Users/dev/proj", "/Users/dev/proj/.claude", "/Users/dev/proj/.git"]);
    expect(text.indexOf('(deny file-write* (literal (param "A0"))')).toBeGreaterThan(text.indexOf('(deny file-write* (subpath (param "R0"))'));
    expect(guardedAncestors(["/a/b/c/d"], ["/a/b"], false).sort()).toEqual(["/a/b", "/a/b/c"]);
    expect(guardedAncestors(["/x/y"], ["/a"], false)).toEqual([]);
  });
  it("refuses a bad port or a path with a line break", () => {
    expect(() => seatbeltProfile(plan({ proxyPort: 0 }))).toThrow(/port/);
    expect(() => seatbeltProfile(plan({ writable: ["/a\n(allow default)"] }))).toThrow(/line break/);
  });
  it("sandbox-exec arguments: -D pairs, -p, then -- and the command", () => {
    const a = sandboxExecArgs(plan(), ["/usr/bin/env", "-i"]);
    expect(a[0]).toBe("-D");
    expect(a[1]).toBe("W0=/Users/dev/proj");
    const p = a.indexOf("-p");
    expect(a.slice(p + 2)).toEqual(["--", "/usr/bin/env", "-i"]);
  });
});

describe("bwrapArgs", () => {
  const exists = (p: string): "dir" | "file" | null => (p.endsWith("/.ssh") || p.endsWith("/keys") || p === "/home/dev/proj" || p === "/home/dev/proj/.git" || p === "/home/dev/proj/.git/hooks" || p.includes("lsfw-run") || p.endsWith(".launchsafe-firewall") ? "dir" : p.endsWith("approver.json") ? "file" : null);
  const lp = plan({ platform: "linux", workspace: "/home/dev/proj", runTmp: "/tmp/lsfw-run-1", writable: ["/home/dev/proj", "/tmp/lsfw-run-1"], readOnly: ["/home/dev/.launchsafe-firewall", "/home/dev/proj/.git/hooks", "/home/dev/proj/.claude/settings.json"], unreadable: ["/home/dev/.launchsafe-firewall/keys", "/home/dev/.launchsafe-firewall/keys/approver.json", "/home/dev/.ssh", "/home/dev/.aws"], proxyPort: 3128 });
  const args = bwrapArgs(lp, { socketDir: "/tmp/lsfw-sock-1", insideSocketDir: "/run/lsfw", socketName: "proxy.sock", nodePath: "/usr/bin/node", bridgeSource: "BRIDGE", exists, cwd: "/home/dev/proj" }, ["aider", "--yes"]);
  const at = (...seq: string[]): number => args.findIndex((_, i) => seq.every((s, j) => args[i + j] === s));
  it("isolates the network, pids and the session, and dies with run", () => {
    for (const f of ["--unshare-net", "--unshare-pid", "--new-session", "--die-with-parent"]) expect(args).toContain(f);
  });
  it("root read-only, then private /tmp and /run, then writable binds, then read-only binds, then hidden paths", () => {
    const root = at("--ro-bind", "/", "/");
    const tmp = at("--tmpfs", "/tmp");
    const run = at("--tmpfs", "/run");
    const ws = at("--bind", "/home/dev/proj", "/home/dev/proj");
    const fw = at("--ro-bind", "/home/dev/.launchsafe-firewall", "/home/dev/.launchsafe-firewall");
    const ssh = at("--tmpfs", "/home/dev/.ssh");
    expect(root).toBeGreaterThan(-1);
    expect(tmp).toBeGreaterThan(root);
    expect(run).toBeGreaterThan(root);
    expect(ws).toBeGreaterThan(tmp);
    expect(fw).toBeGreaterThan(ws);
    expect(ssh).toBeGreaterThan(fw);
    expect(at("--ro-bind", "/dev/null", "/home/dev/.launchsafe-firewall/keys/approver.json")).toBeGreaterThan(fw);
  });
  it("a missing unreadable path needs nothing; a missing protected file under a missing directory gets an empty read-only tmpfs there, with no stand-in file inside (V7)", () => {
    expect(args).not.toContain("/home/dev/.aws");
    const t = at("--tmpfs", "/home/dev/proj/.claude", "--remount-ro", "/home/dev/proj/.claude");
    expect(t).toBeGreaterThan(at("--bind", "/home/dev/proj", "/home/dev/proj"));
    expect(t).toBeLessThan(args.indexOf("--chdir"));
    expect(args).not.toContain("/home/dev/proj/.claude/settings.json");
  });
  it("V3: each existing directory on the way to a protected path is a mount point of its own (rename and rmdir get EBUSY), bound writable, after the workspace and before the read-only binds on top", () => {
    const g = at("--bind", "/home/dev/proj/.git", "/home/dev/proj/.git");
    expect(g).toBeGreaterThan(at("--bind", "/home/dev/proj", "/home/dev/proj"));
    expect(g).toBeLessThan(at("--ro-bind", "/home/dev/proj/.git/hooks", "/home/dev/proj/.git/hooks"));
    expect(args.filter((s) => s === "/home/dev/proj").length).toBe(2 + 1); // its own bind, and --chdir
    expect(args).not.toContain("/home/dev"); // above the writable directories: the root is read-only already
  });
  it("V3: the guarded directories are bound shallow first; missing ones and files are left to bwrapMissing", () => {
    const have = new Map<string, "dir" | "file">([["/w", "dir"], ["/tmp/r", "dir"], ["/w/sub", "dir"], ["/w/sub/.git", "dir"], ["/w/sub/.git/hooks", "dir"], ["/w/.claude", "dir"], ["/w/.claude/settings.json", "file"], ["/w/wt", "dir"], ["/w/wt/.git", "file"]]);
    const p2 = plan({ platform: "linux", workspace: "/w", runTmp: "/tmp/r", writable: ["/w", "/tmp/r"], readOnly: ["/w/sub/.git/hooks", "/w/.claude/settings.json", "/w/.codex/config.toml", "/w/wt/.git/hooks"], unreadable: [] });
    const a2 = bwrapArgs(p2, { socketDir: "/tmp/s", insideSocketDir: "/run/lsfw", socketName: "proxy.sock", nodePath: "/usr/bin/node", bridgeSource: "B", exists: (p) => have.get(p) ?? null, cwd: "/w" }, ["sh"]);
    const binds = a2.flatMap((s, i) => (s === "--bind" ? [a2[i + 1] as string] : []));
    expect(binds).toEqual(["/w", "/tmp/r", "/w/.claude", "/w/sub", "/w/wt", "/w/sub/.git"]);
    expect(a2.join(" ")).toContain("--tmpfs /w/.codex"); // .codex is missing: bwrapMissing's tmpfs
    expect(binds).not.toContain("/w/.codex");
    expect(binds).not.toContain("/w/wt/.git");
  });
  it("binds the proxy socket directory read-only and starts the bridge with the marker, socket, port and command", () => {
    expect(at("--ro-bind", "/tmp/lsfw-sock-1", "/run/lsfw")).toBeGreaterThan(-1);
    const dd = args.indexOf("--");
    expect(args.slice(dd)).toEqual(["--", "/usr/bin/node", "-e", "BRIDGE", BRIDGE_MARKER, "/run/lsfw/proxy.sock", "3128", "--", "aider", "--yes"]);
    expect(args).toContain("--chdir");
  });
});

describe("bwrapMissing (V7: protected paths that do not exist yet, without creating files in the repository)", () => {
  const ws = "/home/dev/proj";
  const have = new Map<string, "dir" | "file">([[ws, "dir"], ["/tmp/r", "dir"], [`${ws}/.git`, "dir"], [`${ws}/.git/hooks`, "dir"], [`${ws}/.claude`, "dir"], [`${ws}/wt`, "dir"], [`${ws}/wt/.git`, "file"]]);
  const exists = (p: string): "dir" | "file" | null => have.get(p) ?? null;
  const lp = plan({ platform: "linux", workspace: ws, runTmp: "/tmp/r", writable: [ws, "/tmp/r"], readOnly: [`${ws}/.git/hooks`, `${ws}/.git/modules`, `${ws}/.claude/settings.local.json`, `${ws}/.cursor/hooks.json`, `${ws}/.cursor/mcp.json`, `${ws}/.mcp.json`, `${ws}/wt/.git/hooks`, "/home/dev/.launchsafe-firewall/missing"], unreadable: [] });
  const m = bwrapMissing(lp, exists);
  const at = (...seq: string[]): number => m.args.findIndex((_, i) => seq.every((x, j) => m.args[i + j] === x));
  it("existing paths are left to the plain read-only binds", () => {
    expect(m.args).not.toContain(`${ws}/.git/hooks`);
  });
  it("a missing file in an existing agent configuration directory: the directory is bound read-only whole (nothing created)", () => {
    expect(at("--ro-bind", `${ws}/.claude`, `${ws}/.claude`)).toBeGreaterThan(-1);
    expect(m.created).not.toContain(`${ws}/.claude`);
    expect(m.created).not.toContain(`${ws}/.claude/settings.local.json`);
  });
  it("a missing agent configuration directory: one empty read-only tmpfs, no stand-in files inside it (git add . would commit them), the mount point listed for removal", () => {
    expect(at("--tmpfs", `${ws}/.cursor`, "--remount-ro", `${ws}/.cursor`)).toBeGreaterThan(-1);
    expect(m.args.filter((x) => x === `${ws}/.cursor`).length).toBe(2);
    expect(m.args.some((x) => x.startsWith(`${ws}/.cursor/`))).toBe(false);
    expect(m.created).toContain(`${ws}/.cursor`);
    expect(m.files).toEqual([]);
  });
  it("a missing path at the top of the workspace or in .git: an empty read-only tmpfs on the path itself (its mount point is an empty directory)", () => {
    for (const p of [`${ws}/.mcp.json`, `${ws}/.git/modules`]) {
      expect(at("--tmpfs", p, "--remount-ro", p)).toBeGreaterThan(-1);
      expect(m.created).toContain(p);
    }
  });
  it("an existing file on the way (a linked worktree's .git file) is bound read-only so it cannot become a directory", () => {
    expect(at("--ro-bind", `${ws}/wt/.git`, `${ws}/wt/.git`)).toBeGreaterThan(-1);
    expect(m.args).not.toContain(`${ws}/wt/.git/hooks`);
  });
  it("paths outside every writable directory need nothing (the root is read-only)", () => {
    expect(m.args.join(" ")).not.toContain(".launchsafe-firewall");
  });
  it("a missing file git reads in an existing git directory gets a file stand-in, not a directory (git dies on one, and on an empty commondir)", () => {
    const have2 = new Map<string, "dir" | "file">([[ws, "dir"], ["/tmp/r", "dir"], [`${ws}/.git`, "dir"], [`${ws}/sub`, "dir"], [`${ws}/sub/.git`, "dir"]]);
    const p2 = plan({ platform: "linux", workspace: ws, runTmp: "/tmp/r", writable: [ws, "/tmp/r"], readOnly: [`${ws}/.git/commondir`, `${ws}/.git/config.worktree`, `${ws}/sub/.git/commondir`, `${ws}/sub/.git/config`, `${ws}/.git/hooks`, `${ws}/.mcp.json`], unreadable: [] });
    const m2 = bwrapMissing(p2, (p) => have2.get(p) ?? null);
    expect(m2.files).toEqual([
      { path: `${ws}/.git/commondir`, content: ".\n" },
      { path: `${ws}/.git/config.worktree`, content: "" },
      { path: `${ws}/sub/.git/commondir`, content: ".\n" },
      { path: `${ws}/sub/.git/config`, content: "" },
    ]);
    const j = m2.args.join(" ");
    for (const f of m2.files) {
      expect(j).toContain(`--ro-bind ${f.path} ${f.path}`);
      expect(j).not.toContain(`--tmpfs ${f.path}`);
      expect(m2.created).toContain(f.path);
    }
    // Directories and files git does not read keep the empty-directory mount point.
    expect(j).toContain(`--tmpfs ${ws}/.git/hooks --remount-ro ${ws}/.git/hooks`);
    expect(j).toContain(`--tmpfs ${ws}/.mcp.json --remount-ro ${ws}/.mcp.json`);
  });
  it("RN7: a missing protected directory inside an agent directory (.claude/skills) gets an empty read-only mount on itself, not the whole .claude; nothing is mounted below a directory bound read-only", () => {
    const base = new Map<string, "dir" | "file">([[ws, "dir"], ["/tmp/r", "dir"], [`${ws}/.claude`, "dir"], [`${ws}/.claude/settings.json`, "file"], [`${ws}/.claude/settings.local.json`, "file"]]);
    const ro = [`${ws}/.claude/settings.json`, `${ws}/.claude/settings.local.json`, `${ws}/.claude/skills`, `${ws}/.claude/agents`, `${ws}/.claude/commands`];
    const p3 = plan({ platform: "linux", workspace: ws, runTmp: "/tmp/r", writable: [ws, "/tmp/r"], readOnly: ro, unreadable: [] });
    const m3 = bwrapMissing(p3, (p) => base.get(p) ?? null);
    for (const d of ["skills", "agents", "commands"]) expect(m3.args.join(" ")).toContain(`--tmpfs ${ws}/.claude/${d} --remount-ro ${ws}/.claude/${d}`);
    expect(m3.args).not.toContain("--ro-bind");
    // settings.local.json missing: .claude is bound read-only whole, and no mount points are made inside it.
    base.delete(`${ws}/.claude/settings.local.json`);
    const m4 = bwrapMissing(p3, (p) => base.get(p) ?? null);
    expect(m4.args).toEqual(["--ro-bind", `${ws}/.claude`, `${ws}/.claude`]);
    expect(m4.created).toEqual([]);
    // An existing protected directory (bound read-only by bwrapArgs) has nothing mounted below it either.
    const p5 = plan({ platform: "linux", workspace: ws, runTmp: "/tmp/r", writable: [ws, "/tmp/r"], readOnly: [`${ws}/.husky`, `${ws}/.husky/pre-commit.sh`], unreadable: [] });
    expect(bwrapMissing(p5, (p) => (p === ws || p === "/tmp/r" || p === `${ws}/.husky` ? "dir" : null)).args).toEqual([]);
  });
  it("filePlaceholder: only commondir, config and config.worktree directly inside a .git directory", () => {
    expect(filePlaceholder("/w/.git/commondir")).toBe(".\n");
    expect(filePlaceholder("/w/a/.git/config")).toBe("");
    expect(filePlaceholder("/w/.git/config.worktree")).toBe("");
    for (const p of ["/w/commondir", "/w/.git/hooks", "/w/.git/worktrees/x/commondir", "/w/.mcp.json", "/w/.git/toString", "/w/.git/constructor"]) expect(filePlaceholder(p), p).toBeNull();
  });
});

describe("writePathProblem (--allow-write and the workspace)", () => {
  const H = "/Users/dev";
  const prot = ["/Users/dev/.launchsafe-firewall", "/opt/fw"];
  const no = (p: string): string | null => writePathProblem(p, H, prot, true);
  it("refuses the disk root, system directories, the home directory and above", () => {
    for (const p of ["/", "/Users", "/etc", "/usr/local", "/System/Library", "/Library/LaunchDaemons", "/opt/homebrew/bin", "/private/etc", "/var", H, `${H}/`]) expect(no(p), p).not.toBeNull();
  });
  it("refuses credential stores, shell start-up files, agent settings and the firewall's directory", () => {
    for (const p of [".ssh", ".aws/x", ".gnupg", ".claude", ".claude/projects", ".codex", ".gemini/tmp", ".cursor", ".launchsafe-firewall", ".zshrc", ".config", ".config/gh", ".local/bin", "Library", "Library/LaunchAgents", ".npmrc", ".gitconfig"]) expect(no(`${H}/${p}`), p).not.toBeNull();
  });
  it("allows ordinary directories, caches and a /tmp", () => {
    for (const p of [`${H}/proj`, `${H}/.npm`, `${H}/.cache/pip`, `${H}/.config/goose`, `${H}/Library/Caches/pip`, "/tmp", "/private/tmp", "/Volumes/work/repo"]) expect(no(p), p).toBeNull();
  });
  it("a directory inside a protected path is refused; one containing it is allowed (read-only wins)", () => {
    expect(no("/opt/fw/dist")).not.toBeNull();
    expect(writePathProblem("/opt", H, ["/opt/fw"], true)).not.toBeNull(); // /opt itself is top-level
    expect(writePathProblem("/srv/x", H, ["/srv/x/fw"], false)).toBeNull();
  });
  it("case-insensitive on macOS only", () => {
    expect(writePathProblem("/users/dev/.SSH", H, [], true)).not.toBeNull();
    expect(writePathProblem("/home/dev/.SSH", "/home/dev", [], false)).toBeNull();
  });
  it("lists are the documented ones", () => {
    expect(WORKSPACE_PROTECTED).toContain(".git/hooks");
    // git takes the config and the hooks from the directory .git/commondir names.
    expect(WORKSPACE_PROTECTED).toContain(".git/commondir");
    expect(WORKSPACE_PROTECTED).toContain(".launchsafe-firewall.json");
    expect(HOME_UNREADABLE).toEqual([".ssh", ".aws", ".gnupg"]);
  });
});

describe("parseClientHello (SNI)", () => {
  it("reads the server name", () => {
    expect(parseClientHello(buildClientHello("github.com"))).toEqual({ state: "tls", sni: "github.com" });
    expect(parseClientHello(buildClientHello("GitHub.COM."))).toEqual({ state: "tls", sni: "github.com" });
  });
  it("no server name", () => {
    expect(parseClientHello(buildClientHello(null))).toEqual({ state: "tls", sni: null });
  });
  it("needs more bytes until the record (and the handshake) is complete", () => {
    const h = buildClientHello("registry.npmjs.org");
    for (let i = 0; i < h.length; i++) expect(parseClientHello(h.subarray(0, i)).state, String(i)).toBe("need-more");
  });
  it("a ClientHello split over two records", () => {
    const h = buildClientHello("pypi.org");
    const hs = h.subarray(5);
    const cut = 20;
    const rec = (b: Buffer): Buffer => Buffer.concat([Buffer.from([0x16, 0x03, 0x01, b.length >> 8, b.length & 255]), b]);
    const two = Buffer.concat([rec(hs.subarray(0, cut)), rec(hs.subarray(cut))]);
    expect(parseClientHello(two)).toEqual({ state: "tls", sni: "pypi.org" });
    expect(parseClientHello(two.subarray(0, 5 + cut + 3)).state).toBe("need-more");
  });
  it("not TLS: plain HTTP, SSH banners, junk, a non-ClientHello handshake", () => {
    expect(parseClientHello(Buffer.from("GET / HTTP/1.1\r\n\r\n")).state).toBe("not-tls");
    expect(parseClientHello(Buffer.from("SSH-2.0-OpenSSH\r\n")).state).toBe("not-tls");
    expect(parseClientHello(Buffer.from([0x16, 0x02, 0, 0, 1, 0])).state).toBe("not-tls");
    const h = Buffer.from(buildClientHello("a.example"));
    h[5] = 0x02;
    expect(parseClientHello(h).state).toBe("not-tls");
  });
  it("truncated inner lengths are malformed, not a crash", () => {
    const h = Buffer.from(buildClientHello("a.example"));
    // Claim a longer extension block than the handshake holds.
    const extLenAt = 5 + 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1;
    h[extLenAt] = 0xff;
    expect(parseClientHello(h).state).toBe("not-tls");
  });
});
