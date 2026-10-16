/**
 * Network traffic: a network middleware (an outer sandbox's supervisor, docs/sandboxes.md) asks about the HTTP
 * requests it sees leave, with the agent's network token (`api token add <agentId> --traffic network`) and
 * `context.traffic: "network"`, in the engine's vocabulary (HttpRequest, or its record of a request it refused).
 * Only that token may send such traffic, and only in that shape: everything else is a 400. That network traffic
 * is not counted toward the toolCalls spending limit is in prepared-caps (it needs a policy).
 */

import { NETWORK_REFUSED_TOOL, UNPARSEABLE_TOOL } from "../../src/engine/classify.js";
import { ctxOf, eng, http, NO_TOOLS, reg, res, taintEngine, vec, withNet, type Skeleton, type SkStep } from "./kit.js";

const NET = { ...ctxOf(false), traffic: "network" as const };

/** The middleware's record of a request it refused before asking (a loopback target here). */
const refused = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({ method: "GET", url: "http://127.0.0.1:8080/admin", code: "loopback", reason: "the target is this machine", ...extra });

export function networkTraffic(): Skeleton[] {
  const out: Skeleton[] = [];
  const add = (id: string, description: string, steps: SkStep[]): void => void out.push(vec(`network-${id}`, description, "docs/api-v0.md, context.traffic; src/api/request.ts", NO_TOOLS, steps));

  add("get-trusted", "A middleware's GET of a documentation page in a trusted session", [http("GET", "https://docs.example.org/guide")]);
  add("response-taints", "A middleware's GET, then an install by the agent: the response was outside content", [http("GET", "https://docs.example.org/guide"), eng("Bash", { command: "npm install lodash" })]);
  add("post-after-taint", "A middleware's POST with a body after the agent read outside content", [...taintEngine(0), http("POST", "https://upload.example.net/in", "report=1")]);
  add("post-after-taint-unattended", "A middleware's POST with a body after outside content, with no person there", [...taintEngine(0, ctxOf(true)), http("POST", "https://upload.example.net/in", "report=1", ctxOf(true))]);
  add("metadata", "A middleware's request to the cloud metadata service", [http("GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/")]);
  add("unparseable-wrapper", "A middleware's request whose body it could not read", [withNet(eng(UNPARSEABLE_TOOL, { tool: "HttpRequest", reason: "the body is compressed with an unknown encoding" }, NET))]);

  // FW-NET-REFUSED: the middleware's record of a request it refused is always denied (and only it may send one).
  add("refused", "A middleware's record of a request to this machine it refused", [withNet(eng(NETWORK_REFUSED_TOOL, refused(), NET))]);
  add("refused-unattended", "A middleware's record of a refused request, with no person there", [withNet(eng(NETWORK_REFUSED_TOOL, refused(), { ...NET, attended: false }))]);
  add("refused-host-header", "A middleware's record of a request whose Host header named another target", [withNet(eng(NETWORK_REFUSED_TOOL, refused({ url: "https://docs.example.org/", code: "host-mismatch", reason: "the Host header names another target" }), NET))]);

  // What only the network token may send, in what shape (400 otherwise).
  add("400-agent-token", "Network traffic sent with the agent's ordinary token", [eng("HttpRequest", { method: "GET", url: "https://docs.example.org/guide" }, NET)]);
  add("400-refused-agent-token", "A refused-request record sent with the agent's ordinary token", [eng(NETWORK_REFUSED_TOOL, refused(), NET)]);
  add("400-refused-not-network", "A refused-request record sent with the network token but not as network traffic", [withNet(eng(NETWORK_REFUSED_TOOL, refused()))]);
  add("400-refused-agent-plain", "A refused-request record sent by the agent as an ordinary tool call", [eng(NETWORK_REFUSED_TOOL, refused())]);
  add("400-tool-bash", "Network traffic whose tool is Bash", [withNet(eng("Bash", { command: "curl https://docs.example.org/guide" }, NET))]);
  add("400-tool-webfetch", "Network traffic whose tool is WebFetch", [withNet(eng("WebFetch", { url: "https://docs.example.org/guide", prompt: "read" }, NET))]);
  add("400-unparseable-other-tool", "Network traffic wrapping an unreadable call of another tool", [withNet(eng(UNPARSEABLE_TOOL, { tool: "Bash", reason: "x" }, NET))]);
  out.push(vec("network-400-format-native", "Network traffic in the native format", "docs/api-v0.md, context.traffic", reg({ http_get: { as: "HttpRequest", map: { url: "$.url" } } }), [withNet({ kind: "decide", request: { session: "run-1", action: { format: "native", tool: "http_get", input: { url: "https://docs.example.org/guide" } }, context: NET } })]));
  add("400-format-mcp", "Network traffic in the mcp format", [withNet({ kind: "decide", request: { session: "run-1", action: { format: "mcp", tool: "fetch", input: { url: "https://docs.example.org/guide" }, mcp: { server: "web", source: "user" } }, context: NET } })]);

  // The network token may still send ordinary tool calls; they are judged as the agent's own.
  add("token-tool-call", "An ordinary tool call sent with the network token", [withNet(eng("Bash", { command: "ls -la" }))]);
  add("token-result", "A middleware's GET and its response recorded with the network token", [http("GET", "https://docs.example.org/guide"), withNet(res(0, "(page)")), eng("Bash", { command: "npm install lodash" })]);
  return out;
}
