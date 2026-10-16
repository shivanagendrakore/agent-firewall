// Vendored from LaunchSafe's agent-safety package (src/launch.ts), Apache-2.0, at commit fc329d4314dc07a65da266a1256b1da0d17ec97c.
// Licence: Apache-2.0 (see NOTICE).
// Transform: add ".js" to relative import specifiers.
// Do not edit here: it is copied from the upstream package by
// `node scripts/sync-agent-safety.mjs` (`--check` verifies the copy).

// DIVERGES FROM UPSTREAM (firewall audit I11 and minor items): a custom registry or index flag makes a
// package an unverified source; PEP 440 exact versions (==2024.1, uvx pkg@1.2) count as pinned while
// npm's pkg@1.2 (a range) does not; docker flags that hand the container the host are reported.
// Upstream should take these changes.

/**
 * How an MCP server is launched: which package runner, which package, and
 * whether its version is pinned. Pure, so each launcher shape has a test.
 */

/** Splits a command line into words (quotes respected, no expansion). */
export function shellSplit(command: string): string[] {
  const out: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  let has = false;
  for (const ch of command) {
    if (quote !== null) {
      if (ch === quote) quote = null;
      else current += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      has = true;
    } else if (/\s/.test(ch)) {
      if (has || current !== "") out.push(current);
      current = "";
      has = false;
    } else current += ch;
  }
  if (has || current !== "") out.push(current);
  return out;
}

export type Ecosystem = "npm" | "pypi" | "docker";

export interface LaunchedPackage {
  ecosystem: Ecosystem;
  /** The package (or image) spec as written. */
  spec: string;
  /** The words after the package: its own arguments. */
  rest: string[];
  /** A registry or package index the launcher was pointed at (--registry, --index-url, …), or null for the public one. */
  registry?: string | null;
}

/** Launcher flags that install from somewhere other than the public registry. */
const REGISTRY_FLAGS = new Set(["--registry", "--index", "--index-url", "-i", "--extra-index-url", "--default-index", "--find-links", "-f"]);

/** The registry or index a launcher's flags (before the package) point it at, or null. */
function registryOf(words: readonly string[]): string | null {
  for (let k = 0; k < words.length; k += 1) {
    const w = words[k] ?? "";
    const eq = w.indexOf("=");
    const flag = eq > 0 ? w.slice(0, eq) : w;
    if (!REGISTRY_FLAGS.has(flag)) continue;
    const value = eq > 0 ? w.slice(eq + 1) : (words[k + 1] ?? "");
    if (value !== "" && !/^https:\/\/(?:registry\.npmjs\.org|registry\.yarnpkg\.com|pypi\.org\/simple)\/?$/i.test(value)) return value;
  }
  return null;
}

/** Flags that take a value, per launcher, so the value is not mistaken for the package. */
const NPX_VALUE_FLAGS = new Set(["--registry", "--cache", "--userconfig", "-c", "--call", "--node-options", "--workspace", "-w"]);
const UVX_VALUE_FLAGS = new Set(["-i", "-f", "--find-links", "--pip-args", "--with", "--with-requirements", "--with-editable", "--python", "-p", "--index", "--index-url", "--extra-index-url", "--default-index", "--constraint", "-c", "--override", "--directory", "--project", "--cache-dir", "--config-file", "--env-file"]);
const DOCKER_VALUE_FLAGS = new Set(["-e", "--env", "-v", "--volume", "--name", "--network", "--net", "-p", "--publish", "--mount", "--env-file", "-w", "--workdir", "-u", "--user", "--entrypoint", "--label", "-l", "--platform", "--add-host", "--cap-add", "--cap-drop", "--memory", "-m", "--cpus", "--hostname", "-h", "--pull", "--security-opt", "--device", "--ulimit", "--tmpfs"]);

function firstPositional(words: string[], valueFlags: Set<string>): number {
  for (let k = 0; k < words.length; k += 1) {
    const w = words[k] ?? "";
    if (w === "--") return k + 1 < words.length ? k + 1 : -1;
    if (w.startsWith("-")) {
      if (!w.includes("=") && valueFlags.has(w)) k += 1;
      continue;
    }
    return k;
  }
  return -1;
}

/**
 * The package a launcher installs and runs, from the server's command and
 * arguments as one word list. Null for anything that is not a package runner
 * (a local script, a binary on PATH): those are the repository's own code.
 */
export function launchedPackage(words: string[]): LaunchedPackage | null {
  // Windows wraps launchers in `cmd /c`.
  let w = words.map((x) => x.trim()).filter((x) => x !== "");
  if (/^cmd(?:\.exe)?$/i.test(w[0] ?? "") && /^\/c$/i.test(w[1] ?? "")) w = w.slice(2);
  const head = (w[0] ?? "").replace(/^.*[\\/]/, "").replace(/\.(?:cmd|exe)$/i, "").toLowerCase();
  let after: string[];
  let ecosystem: Ecosystem;
  if (head === "npx" || head === "bunx" || head === "pnpx") {
    ecosystem = "npm";
    after = w.slice(1);
  } else if ((head === "pnpm" || head === "yarn" || head === "bun") && (w[1] === "dlx" || w[1] === "x")) {
    ecosystem = "npm";
    after = w.slice(2);
  } else if (head === "npm" && (w[1] === "exec" || w[1] === "x")) {
    ecosystem = "npm";
    after = w.slice(2);
  } else if (head === "uvx" || (head === "uv" && w[1] === "tool" && w[2] === "run")) {
    ecosystem = "pypi";
    after = head === "uvx" ? w.slice(1) : w.slice(3);
  } else if (head === "pipx" && w[1] === "run") {
    ecosystem = "pypi";
    after = w.slice(2);
  } else if ((head === "docker" || head === "podman") && w[1] === "run") {
    ecosystem = "docker";
    after = w.slice(2);
  } else return null;

  // Only the launcher's own flags (before the package) say where it installs from; the server's arguments do not.
  if (ecosystem === "npm") {
    // `npx -p pkg cmd` / `--package=pkg`: the package is the flag's value.
    for (let k = 0; k < after.length; k += 1) {
      const word = after[k] ?? "";
      if ((word === "-p" || word === "--package") && after[k + 1] !== undefined) return { ecosystem, spec: after[k + 1] ?? "", rest: after.slice(k + 2), registry: registryOf(after.slice(0, k)) };
      if (word.startsWith("--package=")) return { ecosystem, spec: word.slice("--package=".length), rest: after.slice(k + 1), registry: registryOf(after.slice(0, k)) };
    }
    const at = firstPositional(after, NPX_VALUE_FLAGS);
    return at < 0 ? null : { ecosystem, spec: after[at] ?? "", rest: after.slice(at + 1), registry: registryOf(after.slice(0, at)) };
  }
  if (ecosystem === "pypi") {
    const flagsUntil = (k: number) => registryOf(after.slice(0, k));
    for (let k = 0; k < after.length; k += 1) {
      const word = after[k] ?? "";
      if ((word === "--from" || word === "--spec") && after[k + 1] !== undefined) {
        const at = firstPositional(after.slice(k + 2), UVX_VALUE_FLAGS);
        return { ecosystem, spec: after[k + 1] ?? "", rest: after.slice(k + 2), registry: flagsUntil(at < 0 ? after.length : k + 2 + at) };
      }
      if (word.startsWith("--from=") || word.startsWith("--spec=")) {
        const at = firstPositional(after.slice(k + 1), UVX_VALUE_FLAGS);
        return { ecosystem, spec: word.slice(word.indexOf("=") + 1), rest: after.slice(k + 1), registry: flagsUntil(at < 0 ? after.length : k + 1 + at) };
      }
    }
    const at = firstPositional(after, UVX_VALUE_FLAGS);
    return at < 0 ? null : { ecosystem, spec: after[at] ?? "", rest: after.slice(at + 1), registry: flagsUntil(at) };
  }
  const at = firstPositional(after, DOCKER_VALUE_FLAGS);
  return at < 0 ? null : { ecosystem, spec: after[at] ?? "", rest: after.slice(at + 1) };
}

export type PinState = "pinned" | "unpinned" | "unverified_source";

const EXACT_VERSION = /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
/** A PEP 440 version with no wildcard: `==2024.1`, `==1.4.2rc1`, `==2.0.post1` name one release. */
const PEP440_EXACT = /^v?\d+(?:\.\d+)*(?:(?:a|b|rc|alpha|beta|c)\d*)?(?:\.?post\d*)?(?:\.?dev\d*)?(?:\+[a-z0-9.]+)?$/i;

/** The exact Python version a spec names (`pkg==1.2`, `pkg===1.2`, uv's `pkg@1.2`), or null. */
export function pypiExactVersion(spec: string): string | null {
  if (/@\s*(?:git\+|https?:|file:)/i.test(spec) || /[<>~^*!,]/.test(spec.replace(/^[^=@]*/, ""))) return null;
  const m = /(?:===|==|@)\s*([^,;\s]+)$/.exec(spec);
  return m !== null && PEP440_EXACT.test(m[1] ?? "") ? (m[1] ?? null) : null;
}

/** Whether a launched package is pinned to one exact release. */
export function pinState(pkg: LaunchedPackage): PinState {
  const spec = pkg.spec;
  if (/^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:\/\/|file:)/i.test(spec) || /\.(?:tgz|tar\.gz|whl|zip)$/i.test(spec)) return "unverified_source";
  // A registry or index the repository chose serves whatever it likes under any version.
  if (pkg.registry !== undefined && pkg.registry !== null) return "unverified_source";
  if (pkg.ecosystem === "npm") {
    // `user/repo` with no scope is a GitHub shorthand: it runs whatever the default branch holds.
    if (!spec.startsWith("@") && /^[^@/\s]+\/[^@\s]+$/.test(spec)) return "unverified_source";
    const at = spec.lastIndexOf("@");
    if (at <= 0) return "unpinned";
    // npm: 1.2 is a range (1.2.x); only a full version is one release.
    return EXACT_VERSION.test(spec.slice(at + 1)) ? "pinned" : "unpinned";
  }
  if (pkg.ecosystem === "pypi") return pypiExactVersion(spec) !== null ? "pinned" : "unpinned";
  if (spec.includes("@sha256:")) return "pinned";
  const tag = /:([^/:]+)$/.exec(spec)?.[1];
  // A named tag other than latest is a deliberate choice; a missing tag or :latest moves on its own.
  return tag === undefined || tag === "latest" ? "unpinned" : "pinned";
}

/**
 * What a `docker run` / `podman run` launch hands the container from the host: privileged mode, the
 * host's process, network or IPC namespace, added capabilities that break isolation, or a mount of
 * the whole disk, the home directory or the Docker socket. Null when none.
 */
export function containerHostAccess(words: readonly string[]): string | null {
  let w = words.map((x) => x.trim()).filter((x) => x !== "");
  if (/^cmd(?:\.exe)?$/i.test(w[0] ?? "") && /^\/c$/i.test(w[1] ?? "")) w = w.slice(2);
  const head = (w[0] ?? "").replace(/^.*[\\/]/, "").replace(/\.exe$/i, "").toLowerCase();
  if ((head !== "docker" && head !== "podman") || w[1] !== "run") return null;
  const hostMount = (src: string) => {
    const s = src.replace(/^["']|["']$/g, "").replace(/[\\/]+$/, "");
    return s === "" || s === "/" || s === "~" || /^\$\{?(?:HOME|env:HOME|USERPROFILE)\}?$/.test(s) || /^\/(?:Users|home|root|etc|var\/run\/docker\.sock|run\/docker\.sock)$/.test(s) || /docker\.sock$/.test(s) || /^[A-Za-z]:$/.test(s) || /^[A-Za-z]:\\Users$/i.test(s);
  };
  for (let k = 2; k < w.length; k += 1) {
    const a = w[k] as string;
    if (!a.startsWith("-")) {
      // Past the image: the rest are the server's own arguments.
      if (k > 2 && DOCKER_VALUE_FLAGS.has(w[k - 1] as string)) continue;
      break;
    }
    if (a === "--privileged" || a === "--privileged=true") return "--privileged";
    const [flag, inline] = a.includes("=") ? [a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1)] : [a, undefined];
    const value = inline ?? (w[k + 1] ?? "");
    if ((flag === "--pid" || flag === "--network" || flag === "--net" || flag === "--ipc" || flag === "--uts" || flag === "--userns") && value === "host") return `${flag}=host`;
    if (flag === "--cap-add" && /^(?:ALL|SYS_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|NET_ADMIN)$/i.test(value)) return `--cap-add=${value}`;
    if (flag === "--security-opt" && /(?:apparmor|seccomp|label)[=:](?:unconfined|disable)/i.test(value)) return `--security-opt ${value}`;
    if ((flag === "-v" || flag === "--volume") && hostMount(value.split(":")[0] ?? "")) return `${flag} ${value}`;
    if (flag === "--mount" && /(?:^|,)(?:source|src)=([^,]*)/.test(value) && hostMount(/(?:^|,)(?:source|src)=([^,]*)/.exec(value)?.[1] ?? "")) return `--mount ${value}`;
  }
  return null;
}

/** Whether a filesystem server's arguments open the whole disk or home directory. */
export function opensWholeDisk(pkg: LaunchedPackage): string | null {
  if (!/server-filesystem|mcp-filesystem|filesystem-mcp/i.test(pkg.spec)) return null;
  for (const arg of pkg.rest) {
    const a = arg.trim() === "/" ? "/" : arg.trim().replace(/[\\/]+$/, "");
    if (a === "/" || a === "~" || a === "$HOME" || a === "${HOME}" || a === "${env:HOME}" || a === "${userHome}" || /^[A-Za-z]:$/.test(a) || a === "/Users" || a === "/home" || /^[A-Za-z]:\\Users$/i.test(a)) {
      return arg;
    }
  }
  return null;
}
