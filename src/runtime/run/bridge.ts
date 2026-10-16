/**
 * v0.3 `run` on Linux: the bridge that runs first inside bubblewrap's network
 * namespace. The namespace has its own loopback and no route out, so the
 * proxy (outside) is reachable only through its Unix socket, bound read-only
 * into the sandbox. The bridge listens on 127.0.0.1:<port> inside, forwards
 * each connection to that socket, then starts the command and passes signals
 * and the exit status through. It is a string run with `node -e`, so it needs
 * no file on disk and no build step; only Node's own modules.
 *
 * Arguments: <marker> <socket path> <port> -- <command> [args...]
 */

export const BRIDGE_SOURCE = String.raw`"use strict";
const net = require("node:net");
const { spawn } = require("node:child_process");
const { constants } = require("node:os");
const a = process.argv.slice(1);
const sock = a[1];
const port = Number(a[2]);
const cmd = a[3] === "--" ? a.slice(4) : a.slice(3);
const fail = (code, msg) => { process.stderr.write("launchsafe-firewall run: " + msg + "\n"); process.exit(code); };
if (!sock || !Number.isInteger(port) || cmd.length === 0) fail(64, "the sandbox bridge was started without a socket, a port or a command");
const srv = net.createServer((c) => {
  const u = net.connect(sock);
  c.on("error", () => u.destroy());
  u.on("error", () => c.destroy());
  c.pipe(u).pipe(c);
});
srv.on("error", (e) => fail(70, "the sandbox bridge could not listen on 127.0.0.1:" + port + " (" + e.message + ")"));
srv.listen(port, "127.0.0.1", () => {
  const child = spawn(cmd[0], cmd.slice(1), { stdio: "inherit" });
  for (const s of ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGWINCH", "SIGUSR1", "SIGUSR2"]) process.on(s, () => { try { child.kill(s); } catch { /* gone */ } });
  child.on("error", (e) => fail(e.code === "ENOENT" ? 127 : 126, "cannot start " + cmd[0] + ": " + e.message));
  child.on("exit", (code, signal) => process.exit(code !== null ? code : 128 + (constants.signals[signal] || 0)));
});
`;

/**
 * macOS Seatbelt runner: starts the command inside the sandbox and, when it exits, sends SIGKILL to every
 * remaining process in the same sandbox (`(allow signal (target same-sandbox))` in engine/run-profile.ts
 * restricts `kill(-1, SIGKILL)` to processes of this sandbox run, including background processes that
 * ignored SIGHUP under `/usr/bin/script` or called `setpgid` / `setsid`). Arguments: <marker> <status file> -- <command>.
 * The kill can take this process down as well, so the exit status is written to the status file first.
 */
export const SEATBELT_BRIDGE_SOURCE = String.raw`"use strict";
const { spawn } = require("node:child_process");
const { constants } = require("node:os");
const a = process.argv.slice(1);
const sep = a.indexOf("--");
const cmd = sep >= 0 ? a.slice(sep + 1) : a.slice(1);
const statusFile = sep >= 2 ? a[1] : "";
const fail = (code, msg) => { process.stderr.write("launchsafe-firewall run: " + msg + "\n"); process.exit(code); };
if (cmd.length === 0) fail(64, "the sandbox bridge was started without a command");
const child = spawn(cmd[0], cmd.slice(1), { stdio: "inherit" });
const tty = Boolean(process.stdin.isTTY || process.stdout.isTTY || process.stderr.isTTY);
for (const s of ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGWINCH", "SIGUSR1", "SIGUSR2"]) {
  process.on(s, () => {
    if (tty && (s === "SIGINT" || s === "SIGQUIT" || s === "SIGWINCH")) return;
    try { child.kill(s); } catch { /* gone */ }
  });
}
child.on("error", (e) => fail(e.code === "ENOENT" ? 127 : 126, "cannot start " + cmd[0] + ": " + e.message));
child.on("exit", (code, signal) => {
  const status = code !== null ? code : 128 + (constants.signals[signal] || 0);
  // On macOS kill(-1) can reach this process too (it is in the sandbox it clears), and a process killed
  // by SIGKILL has no exit status of its own. The status goes to a file first; run reads it when it sees 137.
  if (statusFile) { try { require("node:fs").writeFileSync(statusFile, String(status)); } catch { /* run reports the signal */ } }
  const buf = new Int32Array(new SharedArrayBuffer(4));
  for (let i = 0; i < 50; i++) {
    try {
      process.kill(-1, "SIGKILL");
      Atomics.wait(buf, 0, 0, 5);
    } catch {
      break;
    }
  }
  process.exit(status);
});
`;

