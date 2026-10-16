/**
 * `openshell serve` and `openshell policy` (docs/sandboxes.md). `serve` is a person's command (an agent may
 * not choose what judges its own traffic: FW-TAMPER from a tool call, refused inside an agent session here);
 * `policy` only prints.
 *
 * `serve` listens on loopback by default. OpenShell's supervisors run in their own containers or pods, so a
 * real deployment listens on an address they reach: that needs TLS and the gateway's public key (every call
 * then carries a token the gateway signed, naming the sandbox), or `--insecure`, which OpenShell itself calls
 * `allow_insecure_transport` and which is for local development only.
 */

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { Parsed } from "./cliargs.js";
import { isPresetAgent } from "./engine/agent-presets.js";
import { startGrpcServer } from "./openshell/grpc.js";
import { loadPublicKeys, type JwtConfig } from "./openshell/jwt.js";
import { apiClient, middlewareService, type DecisionClient } from "./openshell/middleware.js";
import { openShellPolicy } from "./openshell/policy.js";
import { loadPolicy } from "./runtime/config.js";
import type { Layout } from "./runtime/layout.js";
import { appendLog } from "./runtime/log.js";

type Ok = Extract<Parsed, { kind: "ok" }>;

export interface OpenShellCliDeps {
  out: (s: string) => void;
  err: (s: string) => void;
  /**
   * False when an agent started this process, or a process it was started from cannot be read (serve is
   * refused). It prints why: `refusal` for an agent.
   */
  notAgent: (refusal: string) => Promise<boolean>;
  cwd: string;
  env: NodeJS.ProcessEnv;
  /** Tests: a stand-in for the local API. */
  client?: DecisionClient;
  /** Tests: called once the server listens, with a function that stops it. */
  onListening?: (stop: () => void, address: string) => void;
}

type Handler = (p: Ok, l: Layout, d: OpenShellCliDeps) => Promise<number>;

const USAGE = 64;
export const TOKEN_ENV = "LAUNCHSAFE_FIREWALL_API_TOKEN";
export const DEFAULT_LISTEN = { host: "127.0.0.1", port: 50051 };

function opt(p: Ok, name: string): string | undefined {
  const v = p.flags.get(name);
  return typeof v === "string" ? v : undefined;
}

/** HOST:PORT, [v6]:PORT. */
export function parseHostPort(s: string): { host: string; port: number } {
  const m = /^(?:\[([0-9a-fA-F:.]+)\]|([A-Za-z0-9.-]+)):(\d{1,5})$/.exec(s.trim());
  const port = m === null ? NaN : Number(m[3]);
  if (m === null || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`--listen ${s.slice(0, 80)}: expected HOST:PORT`);
  return { host: (m[1] ?? m[2]) as string, port };
}

export function isLoopbackHost(h: string): boolean {
  return h === "localhost" || h === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

export const OPENSHELL_HANDLERS: Record<string, Handler> = {
  async "openshell serve"(p, l, d) {
    if (!(await d.notAgent("launchsafe-firewall openshell serve was started from inside an agent session. Run it from your own terminal or a service manager; an agent may not choose what judges its own traffic."))) return 1;
    let listen = DEFAULT_LISTEN;
    try {
      const raw = opt(p, "--listen");
      if (raw !== undefined) listen = parseHostPort(raw);
    } catch (e) {
      d.err(`launchsafe-firewall openshell serve: ${(e as Error).message}`);
      return USAGE;
    }
    const insecure = p.flags.get("--insecure") === true;
    const cert = opt(p, "--tls-cert");
    const key = opt(p, "--tls-key");
    const gwKey = opt(p, "--gateway-key");
    const gwId = opt(p, "--gateway-id");
    const secureParts = [cert, key, gwKey, gwId].filter((x) => x !== undefined).length;
    if (secureParts !== 0 && secureParts !== 4) {
      d.err("launchsafe-firewall openshell serve: --tls-cert, --tls-key, --gateway-key and --gateway-id go together (OpenShell sends its token only over TLS, and the token is what proves which sandbox is asking).");
      return USAGE;
    }
    if (secureParts === 4 && insecure) {
      d.err("launchsafe-firewall openshell serve: --insecure cannot be combined with TLS and the gateway's key.");
      return USAGE;
    }
    if (secureParts === 0 && !insecure && !isLoopbackHost(listen.host)) {
      d.err(`launchsafe-firewall openshell serve: refusing to listen on ${listen.host} without TLS and the gateway's key: anyone who reaches the port could ask in a sandbox's name. Pass --tls-cert, --tls-key, --gateway-key and --gateway-id, or --insecure for local development.`);
      return USAGE;
    }
    let tls: { cert: Buffer; key: Buffer } | undefined;
    let jwt: JwtConfig | undefined;
    if (secureParts === 4) {
      try {
        tls = { cert: readFileSync(resolve(d.cwd, cert as string)), key: readFileSync(resolve(d.cwd, key as string)) };
        jwt = { publicKey: loadPublicKeys(readFileSync(resolve(d.cwd, gwKey as string), "utf8")), gatewayId: gwId as string, audience: opt(p, "--audience") ?? "urn:openshell:extension:middleware:launchsafe-firewall" };
      } catch (e) {
        d.err(`launchsafe-firewall openshell serve: ${(e as Error).message}`);
        return 1;
      }
    }
    let client = d.client;
    if (client === undefined) {
      const token = d.env[TOKEN_ENV];
      if (token === undefined || token.trim() === "") {
        d.err(`launchsafe-firewall openshell serve: set ${TOKEN_ENV} to the middleware's API token (launchsafe-firewall api token add openshell --traffic network), and start the local API with launchsafe-firewall serve --api.`);
        return 1;
      }
      client = apiClient({ target: { socketPath: resolve(d.cwd, opt(p, "--api-socket") ?? join(l.home, "api.sock")) }, token: token.trim() });
    }
    const svc = middlewareService({ client, ...(jwt !== undefined ? { jwt, expectedAudience: jwt.audience } : {}) });
    let server: Awaited<ReturnType<typeof startGrpcServer>>;
    try {
      server = await startGrpcServer({ host: listen.host, port: listen.port, ...(tls !== undefined ? { tls } : {}), maxMessageBytes: svc.maxMessageBytes, unary: svc.unary, streams: svc.streams, authorize: svc.authorize, onError: (e, path) => d.err(`launchsafe-firewall openshell serve: ${path}: ${e.message}`) });
    } catch (e) {
      d.err(`launchsafe-firewall openshell serve: cannot listen on ${listen.host}:${listen.port}: ${(e as Error).message}`);
      return 1;
    }
    const mode = jwt !== undefined ? "TLS, gateway tokens verified" : "plaintext, callers not verified";
    try {
      appendLog(l, { type: "openshell", event: "server_started", address: server.address, mode });
    } catch {
      // log verify reports the log's own problem.
    }
    d.out(`LaunchSafe Firewall OpenShell middleware listening on ${server.address} (${mode}).`);
    if (jwt === undefined) {
      d.out("Register it in the gateway's TOML with allow_insecure_transport = true (local development only; docs/sandboxes.md).");
      d.err(plaintextWarning(server.address, isLoopbackHost(listen.host)));
    }
    d.out("Press Ctrl-C to stop.");
    await new Promise<void>((done) => {
      const stop = (): void => {
        process.removeListener("SIGINT", stop);
        process.removeListener("SIGTERM", stop);
        done();
      };
      if (d.onListening !== undefined) d.onListening(stop, server.address);
      else {
        process.once("SIGINT", stop);
        process.once("SIGTERM", stop);
      }
    });
    await server.close();
    try {
      appendLog(l, { type: "openshell", event: "server_stopped", address: server.address });
    } catch {
      // As above.
    }
    return 0;
  },
  async "openshell policy"(p, l, d) {
    const agent = opt(p, "--agent");
    if (agent !== undefined && !isPresetAgent(agent)) return USAGE;
    const project = resolve(d.cwd, opt(p, "--project") ?? ".");
    const pol = loadPolicy(l, [project]);
    if (pol.error !== undefined) d.err(`launchsafe-firewall openshell policy: your policy is invalid (${pol.error}); the strict defaults are used.`);
    const sendHosts = (opt(p, "--send-host") ?? "").split(",").map((x) => x.trim()).filter((x) => x !== "");
    const r = openShellPolicy(pol.config, { ...(agent !== undefined ? { agent } : {}), sendHosts, middleware: p.flags.get("--no-middleware") === true ? null : (opt(p, "--middleware") ?? "launchsafe-firewall"), ...(opt(p, "--endpoint") !== undefined ? { endpoint: opt(p, "--endpoint") as string } : {}) });
    if (r.problems.length > 0) {
      d.err(`launchsafe-firewall openshell policy: ${r.problems.join("; ")}`);
      return 1;
    }
    for (const w of r.warnings) d.err(`launchsafe-firewall openshell policy: WARNING: ${w}.`);
    d.out(r.yaml.trimEnd());
    return 0;
  },
};

/**
 * Said on standard error every time the service starts without verifying callers. Without the gateway's
 * signed tokens (which OpenShell sends only over TLS) the service cannot tell the supervisor from any other
 * caller that reaches the port: on loopback, every process on this machine, including programs an agent
 * runs outside a sandbox. OpenShell v0.1.4's documented middleware registration shows no setting for a
 * shared-secret header this service could require instead.
 */
export function plaintextWarning(address: string, loopback: boolean): string {
  const who = loopback ? "every process on this machine (an agent's tool calls outside a sandbox among them)" : "anyone who reaches this address";
  return [
    `launchsafe-firewall openshell serve: WARNING: plaintext, callers not verified (${address}).`,
    `  ${who} can ask for decisions in any sandbox's name, add taint and outside content to its session,`,
    "  and use up a person's approval: after a queue approve, the identical request passes once, for whoever sends it first.",
    "  Use TLS with the gateway's key (--tls-cert, --tls-key, --gateway-key, --gateway-id) for anything but local development.",
  ].join("\n");
}
