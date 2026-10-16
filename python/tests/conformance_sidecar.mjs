// The real sidecar for tests/test_conformance.py: one fresh firewall home, agent and server per vector, set up
// exactly as test/api/conformance-sidecar.test.ts sets it up (the reference environment, or a vector's prepared
// tree from conformance/setup.ts). It imports the compiled firewall from dist-conformance/ (`npx tsc -p
// tsconfig.conformance.json` at the repository root) and runs no command: every string in a vector is data.
//
// Protocol: one JSON object per line on stdin, one JSON answer per line on stdout.
//   {"op":"start","vector":{...}}  -> {"ok":true,"socket":"...","token":"...","networkToken":"...","steps":[...]}
//                                     (the agent's token and its network middleware's; steps with the setup's
//                                     {{workspace}} and {{home}} replaced; stops the previous vector)
//   {"op":"approve","id":"..."}    -> {"ok":true}  a person approves that queue item, as `queue approve` does
//   {"op":"stop"}                  -> {"ok":true}  closes the server and removes its trees
// A failure answers {"ok":false,"error":"..."}. End of stdin stops everything and exits.
//
// Usage: node conformance_sidecar.mjs <repository>/dist-conformance

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

const dist = process.argv[2];
if (dist === undefined) {
  process.stderr.write("usage: node conformance_sidecar.mjs <dist-conformance>\n");
  process.exit(2);
}
const load = (rel) => import(pathToFileURL(join(dist, rel)).href);
const [{ REFERENCE, PINNED_UNSET }, setup, { addToken }, { serverNameProblem, trustedSource, writeRegistry }, { startApiServer }, approver, { decideQueueItem }, { layout }] = await Promise.all([
  load("conformance/run.js"),
  load("conformance/setup.js"),
  load("src/api/tokens.js"),
  load("src/api/registry.js"),
  load("src/api/server.js"),
  load("src/runtime/approver.js"),
  load("src/runtime/store.js"),
  load("src/runtime/layout.js"),
]);

const PASS = "conformance passphrase";
const AGENT = REFERENCE.agent;
// The prepared environment's pins: variables that move agents' settings files are unset (conformance/README.md).
for (const k of PINNED_UNSET) delete process.env[k];
let cur = null;

async function stop() {
  const c = cur;
  cur = null;
  if (c === null) return;
  try {
    await c.server.close();
  } finally {
    rmSync(c.sockDir, { recursive: true, force: true });
    rmSync(c.root, { recursive: true, force: true });
    if (c.prepared !== undefined) setup.dispose(c.prepared);
  }
}

async function start(vector) {
  await stop();
  // A short directory for the socket (a unix socket path is limited to about 100 bytes).
  const sockDir = mkdtempSync("/tmp/lsfwpy-");
  const root = mkdtempSync(join(tmpdir(), "lsfwpy-state-"));
  let prepared;
  try {
    prepared = vector.setup !== undefined ? setup.prepare(vector.setup) : undefined;
    const steps = prepared !== undefined ? setup.substitute(vector.steps, prepared) : vector.steps;
    const l = prepared?.l ?? layout(join(root, "state"));
    if (steps.some((s) => s.kind === "approve")) approver.initApprover(l, PASS);
    // As test/api/conformance-sidecar.test.ts: the sidecar honours a trusted MCP source only for a server the person
    // registered, and the vectors' sources stand for the person's configuration, so their servers are registered.
    const mcpServers = {};
    for (const s of steps) {
      const a = s.kind === "decide" ? s.request?.action : undefined;
      const server = a?.mcp?.server;
      const source = a?.mcp?.source;
      if (a?.format === "mcp" && typeof server === "string" && typeof source === "string" && trustedSource(source) && serverNameProblem(server) === null && /^[A-Za-z][A-Za-z0-9_-]{0,31}$/.test(source) && !Object.hasOwn(mcpServers, server)) mcpServers[server] = { source };
    }
    writeRegistry(l, AGENT, Object.keys(mcpServers).length > 0 ? { ...vector.agentTools, mcpServers } : vector.agentTools);
    // The vectors' prompts are the person's: tokens with the prompt role.
    const roles = ["decide", "report", "prompt"];
    const token = addToken(l, AGENT, new Date(REFERENCE.now), undefined, roles);
    // The agent's network middleware's token, for steps with "token": "network" (context.traffic "network").
    const networkToken = addToken(l, AGENT, new Date(REFERENCE.now), "network", roles);
    const server = await startApiServer({
      l,
      env: {},
      home: prepared?.home ?? REFERENCE.home,
      scratch: [],
      fileAccess: prepared !== undefined,
      now: () => new Date(REFERENCE.now),
      socket: join(sockDir, "api.sock"),
    });
    cur = { server, prepared, sockDir, root, l };
    return { socket: server.socket, token, networkToken, steps };
  } catch (e) {
    rmSync(sockDir, { recursive: true, force: true });
    rmSync(root, { recursive: true, force: true });
    if (prepared !== undefined) setup.dispose(prepared);
    throw e;
  }
}

function approve(id) {
  if (cur === null) throw new Error("no vector is running");
  const priv = approver.unlockApprover(cur.l, PASS);
  decideQueueItem(cur.l, id, "approved", (sid, h, x) => approver.signApproval(priv, sid, h, x));
  return {};
}

async function handle(msg) {
  if (msg.op === "start") return await start(msg.vector);
  if (msg.op === "approve") return approve(String(msg.id));
  if (msg.op === "stop") {
    await stop();
    return {};
  }
  throw new Error(`unknown op ${JSON.stringify(msg.op)}`);
}

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  if (line.trim() === "") continue;
  let answer;
  try {
    answer = { ok: true, ...(await handle(JSON.parse(line))) };
  } catch (e) {
    answer = { ok: false, error: e instanceof Error ? (e.stack ?? e.message) : String(e) };
  }
  process.stdout.write(`${JSON.stringify(answer)}\n`);
}
await stop();
