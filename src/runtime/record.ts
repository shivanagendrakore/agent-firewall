/**
 * `hook --record DIR`: saves each raw hook event to DIR, to capture live
 * fixtures of tool names and payload shapes (the method F10 used for
 * mcp_server.source). Only when the person sets LAUNCHSAFE_FIREWALL_RECORD=1,
 * or under the test marker, and never into the real home during tests.
 */

import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import { atomicWrite } from "./fsutil.js";
import { assertNotRealHome, testMarker } from "./guard.js";

export function recordEvent(dir: string, raw: string, env: NodeJS.ProcessEnv): string | null {
  if (env.LAUNCHSAFE_FIREWALL_RECORD !== "1" && !testMarker(env)) throw new Error("--record needs LAUNCHSAFE_FIREWALL_RECORD=1");
  const target = resolve(dir);
  assertNotRealHome(target, env);
  let name = "event";
  try {
    const o = JSON.parse(raw) as { hook_event_name?: unknown; tool_name?: unknown };
    name = [o.hook_event_name, o.tool_name].filter((x): x is string => typeof x === "string").join("-").replace(/[^A-Za-z0-9_.-]/g, "_") || "event";
  } catch {
    name = "unparsed";
  }
  const file = join(target, `${Date.now()}-${name}-${createHash("sha256").update(raw).digest("hex").slice(0, 8)}.json`);
  atomicWrite(file, raw);
  return file;
}
