// Vendored from LaunchSafe's agent-safety package (src/pin.ts), Apache-2.0, at commit fc329d4314dc07a65da266a1256b1da0d17ec97c.
// Licence: Apache-2.0 (see NOTICE).
// Transform: add ".js" to relative import specifiers.
// Do not edit here: it is copied from the upstream package by
// `node scripts/sync-agent-safety.mjs` (`--check` verifies the copy).

/**
 * Whether a tool server's launch line names one fixed release (stable) or a
 * target that can move under it (floating), for receipts and drift. Stricter
 * than the mcpUnpinned rule on purpose: a receipt says what would run again
 * tomorrow, and an image tag can be pointed at another image.
 */
// DIVERGES FROM UPSTREAM (firewall audit I11, minor version forms): a package from a custom registry
// or index floats, and PEP 440 exact versions (==2024.1) are stable. Upstream should take this.
import { launchedPackage, pypiExactVersion, shellSplit } from "./launch.js";

export type PinStability = "stable" | "floating" | "not_a_package";

export interface PinVerdict {
  stability: PinStability;
  /** The package, image or source as written; null for a local command. */
  package: string | null;
  /** Why, in plain words. */
  reason: string;
}

const EXACT_VERSION = /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const COMMIT = /^[0-9a-f]{7,40}$/i;

/** The ref after `#` or the last `@` of a git source, if any. */
function gitRef(spec: string): string | null {
  const hash = spec.indexOf("#");
  if (hash >= 0) return spec.slice(hash + 1).replace(/^commit=/, "") || null;
  // git+https://host/repo.git@ref (pip, uv): the @ after the path.
  const m = /^(?:git\+)?[a-z]+:\/\/[^/]+\/.+@([^@/]+)$/i.exec(spec);
  return m?.[1] ?? null;
}

/**
 * The launch line's pin: `npx -y pkg@1.4.2`, `uvx pkg==1.4.2`, an image
 * digest or a git source at a commit are stable; `latest`, a branch, a range
 * (`^1`, `~1`), an image tag or no version at all float. A line that runs no
 * package (a local script, a binary on PATH) is the repository's own code.
 */
export function pinStability(launch: string): PinVerdict {
  const pkg = launchedPackage(shellSplit(launch));
  if (pkg === null) return { stability: "not_a_package", package: null, reason: "It runs a local command, not a downloaded package." };
  const spec = pkg.spec;
  const stable = (reason: string): PinVerdict => ({ stability: "stable", package: spec, reason });
  const floating = (reason: string): PinVerdict => ({ stability: "floating", package: spec, reason });

  const isGit = /^(?:git\+|git:|github:|gitlab:|bitbucket:)/i.test(spec) || (pkg.ecosystem === "npm" && !spec.startsWith("@") && /^[^@/\s:]+\/[^@\s]+$/.test(spec.split("#")[0] ?? ""));
  if (isGit) {
    const ref = gitRef(spec);
    return ref !== null && COMMIT.test(ref) ? stable("It names a git commit.") : floating(ref === null ? "It runs whatever the repository's default branch holds." : `It follows the git ref "${ref}", which can move.`);
  }
  if (/^(?:https?:|file:)/i.test(spec) || /\.(?:tgz|tar\.gz|whl|zip)$/i.test(spec)) return floating("It downloads a file from an address whose contents can change.");
  if (pkg.registry !== undefined && pkg.registry !== null) return floating(`It installs from ${pkg.registry.slice(0, 80)}, a registry the configuration chose, which can serve anything under any version.`);

  if (pkg.ecosystem === "npm") {
    const at = spec.lastIndexOf("@");
    const version = at > 0 ? spec.slice(at + 1) : "";
    if (EXACT_VERSION.test(version)) return stable(`It names the exact version ${version}.`);
    return floating(version === "" ? "It names no version, so the newest release runs." : `It names "${version}", which can move to a newer release.`);
  }
  if (pkg.ecosystem === "pypi") {
    const exact = pypiExactVersion(spec);
    if (exact !== null) return stable(`It names the exact version ${exact}.`);
    const m = /(?:==|@)([^,;\s]+)$/.exec(spec);
    const version = m?.[1] ?? "";
    return floating(version === "" ? "It names no version, so the newest release runs." : `It names "${version}", which can move to a newer release.`);
  }
  if (spec.includes("@sha256:")) return stable("It names an image digest.");
  const tag = /:([^/:@]+)$/.exec(spec)?.[1];
  return floating(tag === undefined ? "It names no image tag, so latest runs." : `It names the image tag "${tag}", which can be moved to another image.`);
}
