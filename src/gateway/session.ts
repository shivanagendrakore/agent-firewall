/**
 * Which firewall session an MCP message belongs to (the session model). MCP shows a server no conversation boundary, so:
 *
 * - stdio: every server a client starts is a child of the client process, so
 *   all wrapped servers of one client process share one session,
 *   `<client>:<ppid>:<start time of ppid>`; an email server's taint reaches the
 *   same client's chat server, and the trifecta rule holds across servers.
 * - HTTP: the per-client bearer identifies the client; a new session starts
 *   after `gateway.httpSessionIdleMinutes` without a call, but only when the
 *   old one is clean (I5: a tainted session is kept until `gateway reset`).
 *
 * `gateway reset <client>` adds a new generation, which starts a new session
 * at once. The pipeline namespaces the id (`gateway:<id>`).
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { systemTool, type ProcessProbe } from "../runtime/ancestry.js";
import type { Layout } from "../runtime/layout.js";
import { resetGeneration } from "./install.js";
import { loadState } from "../runtime/store.js";

/**
 * The start time of a process: field 22 (starttime) of `/proc/<pid>/stat` on Linux, else `ps -o lstart=`
 * (digits and letters only); "unknown" when neither can tell. It only names the session.
 */
export function processStart(pid: number, o: ProcessProbe = {}): string {
  if (!Number.isInteger(pid) || pid < 1) return "unknown";
  if ((o.platform ?? process.platform) === "linux") {
    try {
      const stat = readFileSync(join(o.procRoot ?? "/proc", String(pid), "stat"), "utf8");
      const close = stat.lastIndexOf(")");
      if (close < 0) return "unknown";
      // proc(5): the fields after "(comm)" start at field 3 (state), so field 22 is index 19.
      const start = stat.slice(close + 1).trim().split(/\s+/)[19];
      return start !== undefined && /^\d+$/.test(start) ? start : "unknown";
    } catch {
      return "unknown";
    }
  }
  try {
    const args = ["-o", "lstart=", "-p", String(pid)];
    const out = o.exec !== undefined ? o.exec("ps", args) : execFileSync(systemTool("ps"), args, { encoding: "utf8", timeout: 1000, stdio: ["ignore", "pipe", "ignore"] });
    const t = out.trim().replace(/[^A-Za-z0-9]+/g, "");
    return t === "" ? "unknown" : t;
  } catch {
    return "unknown";
  }
}

export interface StdioSessionOptions {
  ppid?: number;
  /** Tests: the parent's start time. */
  start?: string;
}

export function stdioSession(l: Layout, client: string, o: StdioSessionOptions = {}): string {
  const ppid = o.ppid ?? process.ppid;
  return `${client}:${ppid}:${o.start ?? processStart(ppid)}:${resetGeneration(l, client)}`;
}

/**
 * HTTP sessions: one per client, renewed after an idle gap. I5: only a clean session is renewed. One that read
 * outside content or holds private data (or whose state cannot be read) is kept across the gap, so waiting an
 * hour never clears its taint; only `gateway reset <client>` (a person's command) starts a new one then.
 */
export class HttpSessions {
  private readonly current = new Map<string, { id: string; last: number }>();
  constructor(
    private readonly l: Layout,
    private readonly idleMinutes: () => number,
  ) {}

  /** Whether the gateway session `id` may be left behind: it is clean (neither untrusted nor holding private data). */
  private clean(id: string): boolean {
    try {
      const s = loadState(this.l, `gateway:${id}`);
      return !s.tainted && !s.sensitive;
    } catch {
      return false;
    }
  }

  sessionFor(client: string, now = Date.now()): string {
    const gen = resetGeneration(this.l, client);
    const cur = this.current.get(client);
    const idle = this.idleMinutes() * 60_000;
    if (cur !== undefined && cur.id.endsWith(`:${gen}`) && (now - cur.last <= idle || !this.clean(cur.id))) {
      cur.last = now;
      return cur.id;
    }
    const id = `${client}:http:${now}:${gen}`;
    this.current.set(client, { id, last: now });
    return id;
  }
}
