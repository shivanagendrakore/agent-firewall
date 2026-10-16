/**
 * Opens the dashboard's one-time launch address in the person's browser. The address is never put on
 * a command line where it can be avoided (every process of the user can read argument lists with ps):
 * on macOS /usr/bin/osascript reads `open location` from standard input; on Linux xdg-open runs only
 * from a fixed root-owned system path (never PATH, R11) and gets the one-time code as its argument, which
 * stops working after its first use. That argument is a stated residual risk (docs/dashboard.md): on a
 * Linux machine shared with other accounts that can read process lists, another account could race the
 * browser for the code during the moment xdg-open runs; the browser then shows "already used", and
 * `--no-open` avoids it altogether. A redirect file was not used instead because sandboxed (snap, flatpak)
 * browsers often cannot read the temporary directory. Under the test marker nothing is started.
 */

import { spawn } from "node:child_process";
import { testMarker } from "../runtime/guard.js";
import { isTrustedSystemFile } from "../runtime/notify.js";

export const XDG_OPEN_PATHS: readonly string[] = ["/usr/bin/xdg-open", "/usr/local/bin/xdg-open", "/bin/xdg-open"];

/** What would be run to open `url`, or a reason it cannot be. Exported for tests. */
export function openCommand(url: string, platform: NodeJS.Platform, trusted: (p: string) => boolean = isTrustedSystemFile): { cmd: string; args: string[]; stdin?: string } | { error: string } {
  // Only the address the dashboard built: no quote, backslash or space can reach the script.
  if (!/^http:\/\/127\.0\.0\.1:\d{1,5}\/open\/[A-Za-z0-9_-]+$/.test(url)) return { error: "not a dashboard launch address" };
  if (platform === "darwin") return { cmd: "/usr/bin/osascript", args: ["-"], stdin: `open location "${url}"\n` };
  if (platform === "linux") {
    const tool = XDG_OPEN_PATHS.find((p) => trusted(p));
    return tool === undefined ? { error: `xdg-open is not installed in ${XDG_OPEN_PATHS.join(", ")} (or is writable by someone other than root)` } : { cmd: tool, args: [url] };
  }
  return { error: `${platform} is not supported` };
}

/** Starts the browser; resolves with null on success or the reason it could not. */
export function openBrowser(url: string, platform: NodeJS.Platform = process.platform): Promise<string | null> {
  const c = openCommand(url, platform);
  if ("error" in c) return Promise.resolve(c.error);
  if (testMarker(process.env)) return Promise.resolve("not started under the test marker");
  return new Promise((resolveOpen) => {
    const child = spawn(c.cmd, c.args, { stdio: [c.stdin !== undefined ? "pipe" : "ignore", "ignore", "ignore"], detached: false });
    child.on("error", (e) => resolveOpen(e.message));
    child.on("exit", (code) => resolveOpen(code === 0 ? null : `${c.cmd} exited with ${String(code)}`));
    if (c.stdin !== undefined) child.stdin?.end(c.stdin);
  });
}
