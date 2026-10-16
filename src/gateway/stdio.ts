/**
 * `launchsafe-firewall mcp wrap --client <c> --server <name> [--mode auto|full|hook] -- <command> <args…>`
 * (stdio transport). The client starts this instead of the real
 * server; it starts the real server with the client's environment, relays
 * newline-delimited JSON-RPC both ways through the gateway pipeline, and passes
 * the server's stderr to its own. When the server exits, the wrapper exits
 * with its code. When the wrapper dies, the client loses the server: its tools
 * disappear rather than run unguarded (fail closed).
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { homedir } from "node:os";
import type { Readable, Writable } from "node:stream";
import { loadPolicy } from "../runtime/config.js";
import { rootsFromArgs } from "../runtime/context.js";
import type { Layout } from "../runtime/layout.js";
import { realpathLoose } from "../runtime/realpath.js";
import { gatewayPolicy } from "../policy-gateway.js";
import { readGatewayInstall, resolveMode, upstreamEnv, type ClientId, type GatewayEntry } from "./install.js";
import { errorResponse, frame, INTERNAL_ERROR, LineFramer, type Message } from "./jsonrpc.js";
import { GatewayCore, type CoreOptions } from "./pipeline.js";
import { stdioSession } from "./session.js";

export interface WrapOptions {
  l: Layout;
  env: NodeJS.ProcessEnv;
  client: ClientId;
  server: string;
  mode: "auto" | "full" | "hook";
  command: string;
  args: string[];
  cwd: string;
  stdin: Readable;
  stdout: Writable;
  stderr: Writable;
  home?: string;
  /** The paired phones' pin from the wrapper's own arguments (`--phones`), the counterpart of the hook command's. */
  phonesPin?: string;
  /** Tests: the parent process's start time, and anything else the core takes. */
  sessionStart?: string;
  core?: Partial<CoreOptions>;
}

/** The pin key's source: `gw-<client>` in full mode; in hook mode the agent's own, so hook and gateway share one pin. */
export function pinSourceFor(client: ClientId, mode: "full" | "hook", entry: GatewayEntry | undefined): string {
  if (mode === "full") return `gw-${client}`;
  if (client === "claude-code") return entry?.scope === "local" ? "local" : entry?.scope === "managed" ? "managed" : "user";
  return `${client}-user`;
}

/** Everything the pipeline needs for one wrapped server, from the install record and the policy. */
export function coreOptionsFor(o: { l: Layout; env: NodeJS.ProcessEnv; client: ClientId; server: string; mode: "auto" | "full" | "hook"; cwd: string; home?: string; args?: string[]; phonesPin?: string; transport: "stdio" | "http" }): { options: Omit<CoreOptions, "session">; warning: string | null } {
  let entry: GatewayEntry | undefined;
  try {
    entry = readGatewayInstall(o.l).entries.find((e) => e.client === o.client && e.server === o.server);
  } catch {
    entry = undefined;
  }
  const gp = gatewayPolicy(loadPolicy(o.l, [o.cwd]).config);
  // I4: "auto" (the wrapper's default) follows the policy, whose own "auto" is full mode; hook mode only by name.
  const { mode, warning } = resolveMode(o.l, o.client, o.mode === "auto" ? gp.mode : o.mode);
  // Policy mode "full" wins over the entry's; "hook" only where the hook is really installed.
  const effective: "full" | "hook" = gp.mode === "full" ? "full" : mode;
  const roots = (gp.clients[o.client]?.workspaceRoots ?? []).flatMap((r) => [r, realpathLoose(r)]);
  // A server the person wrapped from their own configuration is "user"; one with no record is unknown (untrusted).
  const source = entry === undefined ? "unknown" : "user";
  const home = o.home ?? homedir();
  const mcpRoots = source === "user" && o.args !== undefined ? rootsFromArgs(o.args, o.cwd, home) : undefined;
  return {
    options: {
      l: o.l,
      // The pipeline's own environment only (the server child gets the client's, as before): a pin from the
      // wrapper's arguments is the hook command's LAUNCHSAFE_FIREWALL_PHONES, so phone approvals are honoured alike.
      env: o.phonesPin !== undefined ? { ...o.env, LAUNCHSAFE_FIREWALL_PHONES: o.phonesPin } : o.env,
      client: o.client,
      server: o.server,
      mode: effective,
      source,
      pinSource: pinSourceFor(o.client, effective, entry),
      cwd: o.cwd,
      workspaceRoots: [...new Set(roots)],
      ...(mcpRoots !== undefined ? { mcpRoots } : {}),
      transport: o.transport,
      ...(o.home !== undefined ? { home: o.home } : {}),
    },
    warning,
  };
}

/** Runs the wrapper until the server exits; resolves with the exit code. */
export function runWrap(o: WrapOptions): Promise<number> {
  const diag = (s: string): void => void o.stderr.write(s.endsWith("\n") ? s : `${s}\n`);
  const { options, warning } = coreOptionsFor({ l: o.l, env: o.env, client: o.client, server: o.server, mode: o.mode, cwd: o.cwd, args: o.args, transport: "stdio", ...(o.phonesPin !== undefined ? { phonesPin: o.phonesPin } : {}), ...(o.home !== undefined ? { home: o.home } : {}) });
  if (warning !== null) diag(`LaunchSafe Firewall gateway: ${warning}. Run "launchsafe-firewall doctor".`);
  return new Promise((resolveExit) => {
    let child: ChildProcessWithoutNullStreams;
    try {
      // LG4: the server gets the entry's own NODE_COMPILE_CACHE back; the empty one was for the firewall's node.
      child = spawn(o.command, o.args, { cwd: o.cwd, env: upstreamEnv(o.env), stdio: ["pipe", "pipe", "pipe"] });
    } catch (e) {
      diag(`LaunchSafe Firewall gateway: could not start ${o.command}: ${(e as Error).message}`);
      resolveExit(127);
      return;
    }
    let closed = false;
    // FZ3: a message that cannot be written out (frame throws) is not sent; a response the client waits for
    // becomes an error, so nothing half-written or unchecked goes either way and the request is still answered.
    const framed = (m: Message): string | null => {
      try {
        return frame(m);
      } catch (e) {
        diag(`LaunchSafe Firewall gateway: a message could not be written (${(e as Error).message}); it was not sent.`);
        return null;
      }
    };
    const toClient = (m: Message): void => {
      const line = framed(m);
      if (line !== null) void o.stdout.write(line);
      else if ("id" in m && m.id !== undefined && m.id !== null && !("method" in m)) void o.stdout.write(frame(errorResponse(m.id, INTERNAL_ERROR, "LaunchSafe Firewall gateway: the answer could not be written; it was withheld")));
    };
    const toUpstream = (m: Message): void => {
      if (closed || !child.stdin.writable) return;
      const line = framed(m);
      if (line !== null) child.stdin.write(line);
      else if ("method" in m && "id" in m && m.id !== undefined) toClient(errorResponse(m.id, INTERNAL_ERROR, "LaunchSafe Firewall gateway: the request could not be written; it was not sent"));
    };
    // FZ3: nothing from either stream may throw out of a data handler (it would end the process).
    const safely = (fn: () => void): void => {
      try {
        fn();
      } catch (e) {
        diag(`LaunchSafe Firewall gateway: an internal error was caught (${(e as Error).message}); nothing was forwarded.`);
      }
    };
    const core = new GatewayCore({ ...options, session: () => stdioSession(o.l, o.client, o.sessionStart !== undefined ? { start: o.sessionStart } : {}), diag, onUpstreamAbuse: () => {
      diag("LaunchSafe Firewall gateway: the server broke the protocol 10 times in a minute; closing it.");
      child.kill();
    }, ...(o.core ?? {}) }, { client: toClient, upstream: toUpstream });
    const fromClient = new LineFramer((line) => core.clientText(line), () => diag("LaunchSafe Firewall gateway: dropped a client message larger than 16 MiB"));
    const fromServer = new LineFramer((line) => core.upstreamText(line), () => core.upstreamOversize());
    o.stdin.setEncoding("utf8");
    child.stdout.setEncoding("utf8");
    o.stdin.on("data", (c: string) => safely(() => fromClient.push(c)));
    o.stdin.on("end", () => child.stdin.end());
    // A server that exits or closes its input while a message is being written (EPIPE) must not crash the wrapper:
    // it is diagnosed and the wrapper closes the server (the client loses it, as when it exits).
    const broken = (what: string) => (e: Error): void => {
      diag(`LaunchSafe Firewall gateway: the ${what} of ${o.command} failed (${e.message}); closing it.`);
      closed = true;
      child.kill();
    };
    child.stdin.on("error", broken("input"));
    child.stdout.on("error", broken("output"));
    child.stdout.on("data", (c: string) => safely(() => fromServer.push(c)));
    // The server may log the arguments it received; whole lines are scrubbed of vaulted values.
    let errBuf = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (c: string) => safely(() => {
      errBuf += c;
      const cut = errBuf.lastIndexOf("\n");
      if (cut === -1 && errBuf.length < 65536) return;
      const lines = cut === -1 ? errBuf : errBuf.slice(0, cut + 1);
      errBuf = cut === -1 ? "" : errBuf.slice(cut + 1);
      o.stderr.write(core.scrubDiagnostic(lines));
    }));
    child.stderr.on("end", () => safely(() => {
      if (errBuf !== "") o.stderr.write(core.scrubDiagnostic(errBuf));
      errBuf = "";
    }));
    child.on("error", (e) => {
      diag(`LaunchSafe Firewall gateway: ${o.command}: ${e.message}`);
      closed = true;
      resolveExit(127);
    });
    child.on("close", (code, signal) => {
      closed = true;
      resolveExit(code ?? (signal !== null ? 1 : 0));
    });
  });
}
