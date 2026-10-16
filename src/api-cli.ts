/**
 * The local API's commands (docs/api.md): `serve --api`, `api token add|list|revoke` and
 * `api tools set|show`. They are a person's: the engine refuses them from an agent's tool call (FW-TAMPER,
 * changesState in cliargs.ts), and here a process started inside a coding agent's session is refused too. No
 * terminal is required (a service manager or a provisioning script may run them), as for `run`.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Parsed } from "./cliargs.js";
import { isAgentId } from "./api/files.js";
import { readRegistry, writeRegistry } from "./api/registry.js";
import { parseListen, startApiServer } from "./api/server.js";
import { addToken, newAgentIdProblem, parseRoles, readTokens, revokeTokens, rolesOf, tokenLabel, type TokenRole } from "./api/tokens.js";
import type { Layout } from "./runtime/layout.js";
import { appendLog } from "./runtime/log.js";

type Ok = Extract<Parsed, { kind: "ok" }>;

export interface ApiCliDeps {
  out: (s: string) => void;
  err: (s: string) => void;
  /**
   * False when an agent started this process, or a process it was started from cannot be read (the command is
   * refused). It prints why: `refusal` for an agent.
   */
  notAgent: (refusal: string) => Promise<boolean>;
  cwd: string;
  env: NodeJS.ProcessEnv;
  /** Tests: resolves once the server is up, with a function that stops it (instead of waiting for a signal). */
  onListening?: (stop: () => void, address: string) => void;
  /** A person at an interactive terminal (prints why when not). Default: refuse. */
  humanAtKeyboard?: () => Promise<boolean>;
  /** Reads the approval passphrase without echo. */
  readSecret?: (prompt: string) => Promise<string>;
}

/**
 * A token or a registry decides what an agent may claim (a network middleware's token skips the agent's counts;
 * a registry pins its sources and roots), so making one needs a person at a terminal, and the approval passphrase
 * when one is set: a script or an agent that only reached the person's shell cannot mint them.
 */
async function personWithPassphrase(l: Layout, d: ApiCliDeps, what: string): Promise<boolean> {
  if (!(await person(d, what))) return false;
  if (d.humanAtKeyboard === undefined || !(await d.humanAtKeyboard())) {
    if (d.humanAtKeyboard === undefined) d.err(`launchsafe-firewall ${what} runs only in an interactive terminal (a person at the keyboard).`);
    return false;
  }
  const { approverPublicKey, unlockApprover } = await import("./runtime/approver.js");
  let key: string | null;
  try {
    key = approverPublicKey(l);
  } catch {
    key = "unreadable";
  }
  if (key === null) return true;
  try {
    unlockApprover(l, await (d.readSecret ?? (() => Promise.reject(new Error("no terminal to read it from"))))("Approval passphrase: "));
    return true;
  } catch (e) {
    d.err(`launchsafe-firewall ${what}: the approval passphrase is needed for this (${(e as Error).message}).`);
    return false;
  }
}

type Handler = (p: Ok, l: Layout, d: ApiCliDeps) => Promise<number>;

const USAGE = 64;

function person(d: ApiCliDeps, what: string): Promise<boolean> {
  return d.notAgent(`launchsafe-firewall ${what} was started from inside an agent session. Run it from your own terminal or script; an agent may not manage the firewall's API.`);
}

function agentArg(p: Ok, d: ApiCliDeps): string | null {
  const a = p.positionals[0] as string;
  if (isAgentId(a)) return a;
  d.err(`launchsafe-firewall: "${a.slice(0, 80)}" is not a valid agent id (1 to 64 letters, digits, "_", "-" or ".", starting with a letter or digit).`);
  return null;
}

/** A record of what a person did to the API, in the signed log (never a token). */
function record(l: Layout, event: Record<string, unknown>): void {
  try {
    appendLog(l, { type: "api", ...event });
  } catch {
    // The change is made; the log's own problem is reported by log verify.
  }
}

export const API_HANDLERS: Record<string, Handler> = {
  async serve(p, l, d) {
    if (p.flags.get("--api") !== true) {
      d.err('launchsafe-firewall serve: say what to serve: "serve --api" (the only server in v0). Run "launchsafe-firewall serve --help".');
      return USAGE;
    }
    if (!(await person(d, "serve --api"))) return 1;
    const listenRaw = p.flags.get("--listen");
    let listen: ReturnType<typeof parseListen> | undefined;
    if (typeof listenRaw === "string") {
      try {
        listen = parseListen(listenRaw);
      } catch (e) {
        d.err(`launchsafe-firewall serve: ${(e as Error).message}`);
        return USAGE;
      }
    }
    const s = await startApiServer({ l, env: d.env, ...(listen !== undefined ? { listen } : {}), diag: d.err });
    record(l, { event: "server_started", address: s.address });
    d.out(`LaunchSafe Firewall API listening on ${s.address}`);
    if (readTokens(l).length === 0) d.out('No agent has a token yet: run "launchsafe-firewall api token add <agentId>" in your own terminal.');
    d.out("Press Ctrl-C to stop.");
    await new Promise<void>((done) => {
      const stop = (): void => {
        process.removeListener("SIGINT", stop);
        process.removeListener("SIGTERM", stop);
        done();
      };
      if (d.onListening !== undefined) d.onListening(stop, s.address);
      else {
        process.once("SIGINT", stop);
        process.once("SIGTERM", stop);
      }
    });
    await s.close();
    record(l, { event: "server_stopped", address: s.address });
    return 0;
  },
  async "api token add"(p, l, d) {
    const agent = agentArg(p, d);
    if (agent === null) return USAGE;
    const taken = newAgentIdProblem(l, agent);
    if (taken !== null) {
      d.err(`launchsafe-firewall api token add: ${taken}.`);
      return USAGE;
    }
    if (!(await personWithPassphrase(l, d, "api token add"))) return 1;
    const network = p.flags.get("--traffic") === "network";
    const given = p.lists?.get("--role");
    let roles: TokenRole[] | undefined;
    try {
      roles = given !== undefined ? parseRoles(given) : undefined;
    } catch (e) {
      d.err(`launchsafe-firewall api token add: ${(e as Error).message}`);
      return USAGE;
    }
    const token = addToken(l, agent, new Date(), network ? "network" : undefined, roles);
    record(l, { event: "token_added", agent, ...(network ? { traffic: "network" } : {}), ...(roles !== undefined ? { roles } : {}) });
    const who = network ? "the network middleware of agent" : "agent";
    const promptOnly = roles !== undefined && roles.length === 1 && roles[0] === "prompt";
    d.out(`A new API token for ${who} ${agent}${roles !== undefined ? ` (roles: ${roles.join(", ")})` : ""} (shown only this once; the firewall keeps only its SHA-256):\n\n  ${token}\n\nGive it to ${network ? "the middleware (openshell serve, in LAUNCHSAFE_FIREWALL_API_TOKEN)" : promptOnly ? "the part of your application that reads what the person types (never the agent's tool loop)" : "that agent's process"} as its bearer token. Do not paste it into an agent's chat.`);
    return 0;
  },
  async "api token list"(p, l, d) {
    if (!(await person(d, "api token list"))) return 1;
    const t = readTokens(l);
    if (p.flags.get("--json") === true) {
      d.out(JSON.stringify(t.map((r) => ({ agent: r.agent, createdAt: r.createdAt, id: tokenLabel(r), ...(r.traffic !== undefined ? { traffic: r.traffic } : {}), roles: rolesOf(r) })), null, 2));
      return 0;
    }
    if (t.length === 0) d.out("No API tokens.");
    for (const r of t) d.out(`${r.agent}  token ${tokenLabel(r)}…  created ${r.createdAt.slice(0, 19).replace("T", " ")}  roles ${rolesOf(r).join(",")}${r.traffic === "network" ? "  (network middleware)" : ""}`);
    return 0;
  },
  async "api token revoke"(p, l, d) {
    const agent = agentArg(p, d);
    if (agent === null) return USAGE;
    if (!(await person(d, "api token revoke"))) return 1;
    const n = revokeTokens(l, agent);
    if (n === 0) {
      d.err(`Agent ${agent} has no API token.`);
      return 1;
    }
    record(l, { event: "token_revoked", agent, count: n });
    d.out(`Revoked ${n} token${n === 1 ? "" : "s"} of agent ${agent}. A running server refuses ${n === 1 ? "it" : "them"} from the next request.`);
    return 0;
  },
  async "api tools set"(p, l, d) {
    const agent = agentArg(p, d);
    if (agent === null) return USAGE;
    if (!(await personWithPassphrase(l, d, "api tools set"))) return 1;
    const file = resolve(d.cwd, p.positionals[1] as string);
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(file, "utf8"));
    } catch (e) {
      d.err(`launchsafe-firewall api tools set: cannot read ${file} as JSON: ${(e as Error).message}`);
      return 1;
    }
    let n: number;
    try {
      n = Object.keys(writeRegistry(l, agent, raw).tools).length;
    } catch (e) {
      d.err(`launchsafe-firewall api tools set: ${file}: ${(e as Error).message}. Nothing was changed.`);
      return 1;
    }
    record(l, { event: "tools_set", agent, tools: n });
    d.out(`Set the tool registry of agent ${agent}: ${n} tool${n === 1 ? "" : "s"}. A running server uses it from the next request.`);
    return 0;
  },
  async "api tools show"(p, l, d) {
    const agent = agentArg(p, d);
    if (agent === null) return USAGE;
    if (!(await person(d, "api tools show"))) return 1;
    const r = readRegistry(l, agent);
    if (r === null) {
      d.err(`Agent ${agent} has no tool registry (its native calls are judged by the engine's own tool names; any other tool is FW-UNKNOWN-TOOL).`);
      return 1;
    }
    d.out(JSON.stringify(r, null, 2));
    return 0;
  },
};
