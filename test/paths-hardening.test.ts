/**
 * Path-classification hardening: bracket globs, more sensitive base names, the bare agent directories, `~+` and `~-`,
 * more credential stores (also under another user's home), more secret shapes, the editors' user-level settings,
 * imports reached through a symlinked directory, a dangling link read from its real directory, the case fold's Kelvin
 * sign, the byte helpers' Node parity, and the lock's inode checks.
 *
 * Paths and commands are data; the only files touched are in a temporary directory.
 */
import { existsSync, mkdirSync, realpathSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { base64Decode, hexToLatin1, utf8Decode } from "../src/engine/bytes.js";
import { globMatch } from "../src/engine/glob.js";
import { isImportedInstruction } from "../src/engine/imports.js";
import { classifyPath, resolvePath, underUnknownCwd } from "../src/engine/paths.js";
import { defaultConfig } from "../src/policy.js";
import { linkTargetProblem, withLock, withLockReplacing } from "../src/runtime/fsutil.js";
import { realpathStrict } from "../src/runtime/realpath.js";
import { ctx, HOME, tempHome, WS } from "./helpers.js";

const c = ctx();
const cfg = defaultConfig();
const info = (p: string, cc = c) => classifyPath(resolvePath(p, cc)!, cc, cfg);

describe("a bracket glob names the sensitive file it expands to", () => {
  it.each([`${WS}/CLAUDE.m[d]`, `${WS}/AGENTS.m[d]`, `${WS}/.[c]laude`, `${WS}/.mcp.js[o]n`, `${HOME}/.zsh[r]c`])("%s is protected or a persistence point", (p) => {
    const i = info(p);
    expect(i.protected || i.persistence, p).toBe(true);
  });
  it("controls: a bracket glob that names nothing sensitive is ordinary", () => {
    for (const p of [`${WS}/READ[M]E.md`, `${WS}/src/file[0-9].ts`]) {
      const i = info(p);
      expect(i.protected || i.persistence || i.secret || i.credentialStore, p).toBe(false);
    }
  });
});

describe("a glob reaches the sensitive names that were missing from the list", () => {
  it("shell start-up files, the home's other persistence points, agent directories and credential files", () => {
    expect(info(`${HOME}/.zpro*`).persistence).toBe(true);
    expect(info(`${HOME}/.zshe*`).persistence).toBe(true);
    expect(info(`${HOME}/.bash_pro*`).persistence).toBe(true);
    expect(info(`${WS}/.gitmod*`).persistence).toBe(true);
    for (const g of [".kiro*", ".codex*", ".gemini*", ".windsurf*", ".continue*", ".roomo*", "opencode.js*", ".aider.conf.y*"]) expect(info(`${WS}/${g}`).protected, g).toBe(true);
    expect(info(`${HOME}/.net*`).credentialStore).toBe(true);
    expect(info(`${WS}/.pgp*`).secret).toBe(true);
  });
});

describe("the bare agent directories are protected, not only what is inside them", () => {
  it.each([".codex", ".gemini", ".windsurf", ".kiro", ".continue", ".junie", ".opencode", ".roo", ".amazonq"])("%s", (d) => {
    expect(info(`${WS}/${d}`).protected).toBe(true);
    expect(info(`${HOME}/${d}`).protected).toBe(true);
    expect(info(`${WS}/${d}/x.json`).protected).toBe(true);
  });
  it("controls: a name that only starts the same is an ordinary file", () => {
    for (const d of [".kiros", ".codexes", "kiro", ".roof"]) expect(info(`${WS}/${d}`).protected, d).toBe(false);
  });
});

describe("`~+` is the working directory and `~-` is unknown", () => {
  it("~+ resolves to the cwd, exactly", () => {
    const r = resolvePath("~+/CLAUDE.md", c)!;
    expect(r.abs).toBe(`${WS}/CLAUDE.md`);
    expect(r.exact).toBe(true);
    expect(resolvePath("~+", c)!.abs).toBe(WS);
    expect(info("~+/CLAUDE.md").protected).toBe(true);
  });
  it("~- is an unknown directory: inexact, under the unknown cwd", () => {
    const r = resolvePath("~-/CLAUDE.md", c)!;
    expect(r.exact).toBe(false);
    expect(underUnknownCwd(r.abs)).toBe(true);
  });
  it("controls: ~ and ~user are unchanged", () => {
    expect(resolvePath("~/x", c)!.abs).toBe(`${HOME}/x`);
    expect(resolvePath("~bob/x", c)!.exact).toBe(false);
  });
});

describe("more credential stores", () => {
  it.each([
    `${HOME}/.dockercfg`,
    `${HOME}/.databrickscfg`,
    `${HOME}/.oci/config`,
    `${HOME}/.config/glab-cli/config.yml`,
    `${HOME}/.pulumi/credentials.json`,
    `${HOME}/.config/pulumi/credentials.json`,
    `${HOME}/.config/sops/age/keys.txt`,
    `${HOME}/.bundle/config`,
    `${HOME}/.config/pypoetry/auth.toml`,
    `${HOME}/.local/share/opencode/auth.json`,
    `${HOME}/Library/Application Support/Slack/Cookies`,
    `${HOME}/.config/discord/Local Storage/x`,
  ])("%s", (p) => expect(info(p).credentialStore).toBe(true));

  it.each(["/root/.ssh/id_ed25519", "/home/bob/.aws/credentials", "/Users/eve/.kube/config", "/home/bob/.config/gcloud/credentials.db", "/root/.netrc", "/home/bob/.git-credentials", "/Users/eve/.docker/config.json"])("another user's %s", (p) => {
    expect(info(p).credentialStore).toBe(true);
  });
  it("controls: another user's public key and known_hosts, and a project's own folders, are not stores", () => {
    for (const p of ["/home/bob/.ssh/id_ed25519.pub", "/home/bob/.ssh/known_hosts", "/root/.ssh/known_hosts"]) expect(info(p).credentialStore, p).toBe(false);
    for (const p of [`${WS}/.oci/config`, `${WS}/.bundle/config`, `${WS}/.docker/Dockerfile`, `${WS}/sub/.pulumi/x.json`]) expect(info(p).credentialStore, p).toBe(false);
  });
});

describe("more secret shapes", () => {
  it.each([
    "service_account_prod.json",
    "id_rsa.bak",
    "keys/id_rsa.old",
    "keys/id_ed25519.backup",
    "keys/id_ecdsa.1",
    "AuthKey_ABC123.p8",
    "putty.ppk",
    ".pgpass",
    ".dockercfg",
    ".docker/config.json",
    "application_default_credentials.json",
    "prod.tfvars.json",
  ])("%s is a secret in the workspace", (name) => {
    const i = info(`${WS}/${name}`);
    expect(i.secret, name).toBe(true);
    expect(i.zone).toBe("workspace");
    // In the workspace it is readable (the session turns sensitive), not a credential store.
    expect(i.credentialStore, name).toBe(false);
  });
  it("controls: public keys and ordinary project files are not secrets", () => {
    for (const name of ["id_rsa.pub", "id_ed25519.pub", "package.json", "service.json", "src/keys.ts", ".docker/Dockerfile", "app.tfvars.example", "tsconfig.json"]) expect(info(`${WS}/${name}`).secret, name).toBe(false);
  });
});

describe("the editors' user-level settings are protected", () => {
  it.each([
    `${HOME}/.config/Code - Insiders/User/tasks.json`,
    `${HOME}/Library/Application Support/VSCodium/User/settings.json`,
    `${HOME}/Library/Application Support/Cursor/User/tasks.json`,
    `${HOME}/.config/Cursor/User/mcp.json`,
    `${HOME}/.config/Windsurf/User/mcp.json`,
    `${HOME}/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`,
    `${HOME}/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json`,
    `${HOME}/.config/Code/User/settings.json`,
  ])("%s", (p) => expect(info(p).protected).toBe(true));
  it("controls: the rest of the user directory is not claimed", () => {
    for (const p of [`${HOME}/.config/Code/User/keybindings.json`, `${HOME}/.config/Code/User/globalStorage/other.ext/settings/x.json`, `${HOME}/.config/Codeish/User/tasks.json`]) expect(info(p).protected, p).toBe(false);
  });
});

describe("an imported instruction file is found through a symlinked directory", () => {
  // `${WS}/link` leads to `${WS}/notes`.
  const real = (p: string): string => (p === `${WS}/link` || p.startsWith(`${WS}/link/`) ? `${WS}/notes${p.slice(`${WS}/link`.length)}` : p);
  const imports = (ref: string) => ctx({ realpath: real, readFile: (p: string) => (p === `${WS}/CLAUDE.md` ? `Rules: @${ref}\n` : null) });

  it("a write through the alias reaches the file the import names", () => {
    expect(isImportedInstruction(imports("notes/rules.md"), `${WS}/link/rules.md`)).toBe(true);
  });
  it("an import spelled through the alias covers the real path", () => {
    expect(isImportedInstruction(imports("link/rules.md"), `${WS}/notes/rules.md`)).toBe(true);
  });
  it("controls: the plain spelling still matches; another file does not", () => {
    expect(isImportedInstruction(imports("notes/rules.md"), `${WS}/notes/rules.md`)).toBe(true);
    expect(isImportedInstruction(imports("notes/rules.md"), `${WS}/link/other.md`)).toBe(false);
    expect(isImportedInstruction(imports("notes/rules.md"), `${WS}/src/a.ts`)).toBe(false);
  });
});

describe("a dangling symlink's relative target is read from the link's real directory", () => {
  it("resolves ../out beside the real directory, not beside the alias", () => {
    const root = realpathSync(tempHome("rp-"));
    mkdirSync(join(root, "real", "sub"), { recursive: true });
    symlinkSync(join(root, "real", "sub"), join(root, "a"));
    symlinkSync("../out", join(root, "real", "sub", "l"));
    expect(realpathStrict(join(root, "a", "l"))).toBe(join(root, "real", "out"));
  });
  it("an absolute target and a plain dangling link are unchanged", () => {
    const root = realpathSync(tempHome("rp-"));
    symlinkSync(join(root, "gone", "f"), join(root, "abs"));
    symlinkSync("rel-gone", join(root, "rel"));
    expect(realpathStrict(join(root, "abs"))).toBe(join(root, "gone", "f"));
    expect(realpathStrict(join(root, "rel"))).toBe(join(root, "rel-gone"));
  });
});

describe("the glob matcher's case fold", () => {
  it("the Kelvin sign is a k when case is folded, and only then", () => {
    expect(globMatch("/tmp/kube", "/tmp/Kube", true)).toBe(true);
    expect(globMatch("/tmp/Kube", "/tmp/kube", true)).toBe(true);
    expect(globMatch("/tmp/kube", "/tmp/Kube", false)).toBe(false);
  });
  it("controls: ordinary folding and different letters", () => {
    expect(globMatch("**/CLAUDE.md", "/w/claude.MD", true)).toBe(true);
    expect(globMatch("**/CLAUDE.md", "/w/claude.MD", false)).toBe(false);
    expect(globMatch("/tmp/kube", "/tmp/jube", true)).toBe(false);
  });
  it("a protected name spelled with a Kelvin sign is still protected", () => {
    expect(info(`${HOME}/.Kube/config`).credentialStore).toBe(true);
  });
});

describe("the byte helpers match Node", () => {
  it("utf8Decode keeps a leading byte order mark, as Buffer does", () => {
    const bytes = Uint8Array.from([0xef, 0xbb, 0xbf, 0x41]);
    expect(utf8Decode(bytes)).toBe(Buffer.from(bytes).toString("utf8"));
    expect(utf8Decode(bytes).charCodeAt(0)).toBe(0xfeff);
  });
  it("hexToLatin1 stops at the first pair that is not two hex digits", () => {
    for (const hex of ["4142", "411g", "41zz42", "4a4B", "g1", "4 1", "41+1", ""]) expect(hexToLatin1(hex), hex).toBe(Buffer.from(hex, "hex").toString("latin1"));
    expect(hexToLatin1("411g")).toBe("A");
  });
  it("base64Decode is unchanged", () => {
    expect(Buffer.from(base64Decode("aGVsbG8=")).toString("utf8")).toBe("hello");
  });
});

describe("linkTargetProblem refuses more credential files", () => {
  it("~/.kube, ~/.netrc, ~/.npmrc and ~/.git-credentials", () => {
    const home = realpathSync(tempHome("lt-"));
    const env = { ...process.env, LAUNCHSAFE_FIREWALL_HOME: join(home, ".launchsafe-firewall"), CLAUDE_CONFIG_DIR: "", CODEX_HOME: "", GEMINI_CLI_HOME: "" };
    const link = join(home, ".claude", "settings.json");
    for (const p of [".kube/config", ".netrc", ".npmrc", ".git-credentials"]) expect(linkTargetProblem(link, join(home, p), { home, env }), p).toMatch(/credential store/);
    expect(linkTargetProblem(link, join(home, "dotfiles", "settings.json"), { home, env })).toBeNull();
  });
});

describe("locks", () => {
  it("a stale lock is broken and the lock is taken", () => {
    const dir = realpathSync(tempHome("lock-"));
    const lock = join(dir, "x.lock");
    writeFileSync(lock, "999999999 0");
    const old = new Date(Date.now() - 3_600_000);
    utimesSync(lock, old, old);
    expect(withLock(lock, () => "ran", { staleMs: 1000, timeoutMs: 2000 })).toBe("ran");
    expect(existsSync(lock)).toBe(false);
  });
  it("withLockReplacing: a throwing callback releases its own lock and rethrows", () => {
    const dir = realpathSync(tempHome("lock-"));
    const lock = join(dir, "y.lock");
    expect(() =>
      withLockReplacing(lock, join(dir, "target"), () => {
        throw new Error("boom");
      }),
    ).toThrow("boom");
    expect(existsSync(lock)).toBe(false);
  });
  it("withLockReplacing: the lock file becomes the target with the new content", () => {
    const dir = realpathSync(tempHome("lock-"));
    const lock = join(dir, "z.lock");
    const target = join(dir, "target");
    expect(withLockReplacing(lock, target, () => ({ result: 7, content: "new" }))).toBe(7);
    expect(existsSync(lock)).toBe(false);
    expect(existsSync(target)).toBe(true);
  });
});
