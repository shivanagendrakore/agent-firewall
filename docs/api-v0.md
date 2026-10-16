# Firewall API v0: the local sidecar contract

Status: the v0 contract, 12 Oct 2026; updated the same day with the decisions
the sidecar, the conformance vectors and the Python SDK settled, and on 14 Oct
with token roles, registry pins, limits, network traffic and what the vectors
pin. It is what the
sidecar (`launchsafe-firewall serve --api`, in `src/api/`) and the Python SDK
([`python/`](https://github.com/shivanagendrakore/agent-firewall/blob/main/python/README.md)) implement. For v0, this page is the contract.

## Transport and authentication

- `serve --api` listens on a unix socket at `<firewall home>/api.sock` (mode
  0600) by default, or on `--listen 127.0.0.1:<port>`. Never a non-loopback
  address (refused at start).
- TCP listener hardening, as the MCP gateway's: `Host` must be
  `127.0.0.1:<port>` or `localhost:<port>`. The Host check is the TCP
  listener's only: over the unix socket clients send `Host: localhost` with no
  port (httpx does), and DNS rebinding cannot reach a socket. On both, a
  request with an `Origin` header is refused (403), and `Cookie` is ignored.
- Every `/v1` call except `GET /v1/health` needs `Authorization: Bearer <token>`.
  Tokens are per agent: `launchsafe-firewall api token add <agentId>` prints a
  new token once and stores only its SHA-256 in the firewall home;
  `api token list` and `api token revoke <agentId>` manage them. These are
  person-run commands; from an agent's tool call they are FW-TAMPER.
- Token roles (`api token add <agentId> --role R`, repeatable or
  comma-separated): `decide` (`POST /v1/decide`, `GET /v1/sessions/{s}`,
  `GET /v1/approvals/{id}`), `report` (`results` and `inputs`), `prompt`
  (`prompts`, applied). A token made without `--role` has `decide` and
  `report`. A request to an endpoint the token's roles do not cover is 403,
  except `prompts`: from a token with `report` but not `prompt` it is answered
  `{ "recorded": true, "applied": false, "detail": "…" }` and only its hash is
  logged, because a prompt widens what an untrusted session may do and must come
  from the part of the application that reads what the person typed.
- A network middleware's token (`api token add <agentId> --traffic network`) is
  the only one that may send `context.traffic: "network"` (below).
- Session ids from the caller are namespaced by agent server-side
  (`<agentId>/<session>`), so one agent cannot read or taint another's session.
  A session id is 1 to 200 letters, digits, `.`, `_`, `-`, `:` or `/`; anything
  else is 400. In a URL it is one percent-encoded path segment (`run/42` is
  `run%2F42`), decoded before the check.
- Request bodies are JSON, at most 1 MiB (413 over that). Unknown fields: 400.

## Tool registry

A remote caller cannot pass a JavaScript mapper, so tool specs are data. In v0
they are set only by a person:
`launchsafe-firewall api tools set <agentId> <file.json>` (and `api tools show
<agentId>`). There is no HTTP endpoint for it in v0: an agent credential can
never change its own tool specs.

```jsonc
{
  "tools": {
    "search_docs":    { "kind": "read", "results": "untrusted" },
    "get_customer":   { "kind": "read", "results": "trusted", "privateData": true },
    "send_email":     { "kind": "send" },
    "delete_account": { "kind": "destroy" },
    "run_shell":      { "as": "Bash", "map": { "command": "$.cmd" } },
    "http_get":       { "as": "WebFetch", "map": { "url": "$.url" } }
  }
}
```

`kind` and `as` mean exactly what they mean in the TypeScript library's tool
specs (`src/sdk/tools.ts`). `map` is a flat object of engine field to a
JSONPath of the form `$.a.b` (dot paths only in v0). A tool with no spec is
FW-UNKNOWN-TOOL (ask; its result taints), as in the library. In the `native`,
`openai.chat` and `anthropic` formats this holds for every name the registry
does not list, an engine tool's name (`Bash`) included; the engine and mcp
formats never use the registry. The sidecar also accepts the library's
`server` on a `kind` spec (tools of one server share `results` and
`privateData`).

The registry may also pin what a decide request's context claims, since that
context is the agent's own word:

```jsonc
{
  "tools": { "...": "..." },
  "mcpServers": { "crm": { "source": "user" }, "repo-tools": { "source": "project" } },
  "workspaceRoots": ["/srv/app"]
}
```

- `mcpServers.<server>.source`: where the person configured that server. A
  listed server is judged with this source; a request claiming a source the
  engine trusts (`user`, `sdk`, …) for a server listed with an untrusted one
  (`project`, `dynamic`, `unknown`) is 403 `forbidden-context`. A server **not**
  listed is never judged as a trusted source's on the agent's word: a claimed
  trusted source is judged as `unknown`, and the decision's `problems` says so.
- `workspaceRoots`: every `context.workspace` root and `context.cwd` must be one
  of these or inside one, else 403 `forbidden-context`. Without it any absolute
  path is accepted.

## Endpoints

| Method and path | Body | Returns |
|---|---|---|
| `GET /v1/health` | none | `{ "ok": true, "engine": { "version": "…" } }` |
| `POST /v1/decide` | decide request | decision |
| `POST /v1/sessions/{session}/results` | `{ "decisionId", "output", "failed"?: bool }` | `{ "recorded": true, "output"?: redacted string }` |
| `POST /v1/sessions/{session}/inputs` | `{ "source", "content", "private"?: bool }` | `{ "recorded": true }` |
| `POST /v1/sessions/{session}/prompts` | `{ "text" }` | `{ "recorded": true }`; `"applied": false` and a `detail` from a token without the `prompt` role |
| `GET /v1/sessions/{session}` | none | the `session` object of a decision |
| `GET /v1/approvals/{id}` | none | `{ "id", "status": "pending" \| "approved" \| "denied" \| "expired" }` |

`POST /v1/decide` honours `Idempotency-Key`: a retry with the same key and body
returns the same decision and writes no second log entry (a deny or hold always;
an allow or ask once, only within 30 seconds, and only while a dry check of the
call still gives the same verdict with no stop or spending limit; a dry run is
checked afresh; see api.md); the same key with a
different body is 400. Keys are per agent and remembered while the server runs.
A replayed hold carries its approval's status as it is now (`pending`,
`approved` or `denied`), not as it was. The session endpoints accept the header
and ignore it.

Limits, per agent: 32 requests in flight and 100 a second (bursts of 300); past
them, 429 `rate-limited` with `Retry-After`, while other agents are still
answered. Each agent may open 100,000 new sessions while the server runs (429
`too-many-sessions` past it). Past 256 requests in flight on the whole server,
every request is 503 `overloaded` with `Retry-After` (not a refusal: retry).

`inputs` and `prompts` on a session with no decision yet create the session
(a retrieved document at the start of a run); `GET /v1/sessions/{session}` for
a session never seen is 404. `results` needs a `decisionId` this server
returned for that session (404 otherwise). For a decision the server has
forgotten (memory bounds, per agent), the output is recorded as untrusted input
holding private data and the answer carries `"rule": "FW-RESULT-UNRECORDED"`. There is no `?wait=` long poll in
v0: poll `GET /v1/approvals/{id}`.

### Decide request

```jsonc
{
  "session": "run-42",
  "action": {
    "format": "native",            // native | engine | openai.chat | anthropic | mcp
    "tool": "send_email",          // native and engine: the tool name
    "input": { "to": "x@y.com" },  // native and engine: the arguments
    "callId": "call_abc",          // optional, kept in the log
    "mcp": { "server": "gmail", "source": "user" },  // format mcp only
    "raw": null                    // openai.chat: one tool_call object; anthropic: one tool_use block
  },
  "context": {
    "attended": true,              // false: ask becomes hold; missing: true
    "workspace": ["/srv/app"],     // optional
    "cwd": "/srv/app",             // optional
    "traffic": "tool"              // optional: "network" for a network middleware's request (api.md)
  },
  "dryRun": false,                 // true: preview only, records nothing
  "usage": {                       // optional: the model usage behind this call
    "inputTokens": 1200,           // whole numbers from 0
    "outputTokens": 300,
    "costUsd": 0.0045              // the agent's own estimate, US dollars
  }
}
```

- `usage` (optional, every field optional, unknown fields 400) counts toward
  the token and cost spending limits (policy `caps`). The firewall never calls
  a model and keeps no prices; it adds up what the agent reports. A dry run
  records nothing.
- `failed` on a result (optional, a boolean) says the tool failed: it counts
  toward the identical-failures spending limit of that exact call, by the
  error in `output`. Without it, only an explicit marker in `output` counts (a
  non-zero `exitCode`, an MCP result's `isError`).

- `engine`: `tool` and `input` are already in the engine's vocabulary (`Bash`,
  `Read`, `WebFetch`, …).
- `native`: `tool` is looked up in the agent's registry.
- `openai.chat`: `raw` is `{ "id", "type": "function", "function": { "name",
  "arguments": "<json string>" } }`; then as `native`. `arguments` must parse
  to a JSON object (400 otherwise).
- `anthropic`: `raw` is `{ "type": "tool_use", "id", "name", "input" }`; then as
  `native`.
- For `openai.chat` and `anthropic` the action is `format`, `raw` and optionally
  `callId` (default: `raw.id`); `tool` and `input` are not sent (400 if they
  are). "Unknown fields: 400" applies to the request envelope (`action`,
  `context`, `mcp` and the top level); inside `raw`, the framework's own block,
  only the keys above are read and any other key is ignored.
- `mcp`: `tool` is the MCP tool name, `mcp.server` the server name; the engine
  sees `mcp__<server>__<tool>`. A server name may not contain `__` or end with
  `_` (it would run into the separator and be read back as another server): 400.
- In every format, a tool's arguments nested deeper than 256 levels are 400 (the
  engine does not judge them; 256 levels are judged). The in-process library has
  no request to refuse, so it denies such a call (`FW-INPUT-SHAPE`); the
  conformance vectors record both answers (a step's `expectApi`).
- `context.traffic: "network"` is a network middleware's request on the agent's
  behalf (an outer sandbox's supervisor). It is accepted only from the agent's
  network token (`api token add <agentId> --traffic network`), only in the
  `engine` format, and only for `HttpRequest`, the `launchsafe:unparseable`
  wrapper of one, or `launchsafe:network-refused` (the middleware's record of a
  request it refused, always denied with `FW-NET-REFUSED`); anything else is
  400, as is `launchsafe:network-refused` without network traffic. Such a request
  is judged like the agent's own but is not a tool call: it is not counted toward
  the `toolCalls` spending limit, the agent-wide behaviour monitor or agent
  stops. The network token may also send ordinary tool calls.

### Decision

```jsonc
{
  "decisionId": "dec_…",
  "verdict": "allow",              // allow | ask | hold | deny
  "rules": [ { "id": "FW-SEND", "outcome": "approve", "reason": "…" } ],
  "message": "LaunchSafe Firewall: …",
  "actionHash": "sha256:…",
  "session": {
    "untrusted": false, "untrustedBecause": [],
    "holdsPrivateData": false, "privateBecause": []
  },
  "approval": { "id": "…", "status": "pending" },   // only for hold
  "engine": { "version": "0.3.0" },
  "log": { "seq": 12, "hash": "sha256:…" }
}
```

Each rule's `outcome` is the engine's (`approve`, `hold`, `deny`, or `allow`
for `FW-APPROVED`). A decision may also carry `problems` (what went wrong
recording it; the verdict already accounts for it).

An `allow` carries no rules except `FW-APPROVED` and two notes that never stop
the call: `FW-CANARY-READ` (a planted decoy was touched; allowed so the decoy
does not give itself away, and the session becomes untrusted) and `FW-CAP-WARN`
(a spending limit is near; an `ask` when a person can answer and policy
`caps.warn` is `"ask"`, else a note on the allow).

The `session` object of an `ask` already shows the call's effects (outside
content read, private data held), because an ask goes ahead once the host's
person says yes; a `hold` or `deny` records none of them (a hold's effects are
recorded when the approved retry runs).

The results response's `output` is the tool output with every credential masked
as its first four characters followed by `…[redacted by LaunchSafe Firewall]`
(U+2026, then that text); the rest of the output is unchanged, and `output` is
left out when nothing was masked or policy `redactSecretsInOutput` is off.

`hold` creates an item in the firewall's existing queue, so `launchsafe-firewall
queue list`, terminal approvals and phone approvals work unchanged. After a
person approves, the agent retries the identical call (same session, same
action, and the same `context.cwd` and `context.workspace`: an approval holds
only in the context it was given for) and gets `allow` once; the approval is
single use. The retry is the
identical decide body with a new `Idempotency-Key` (the old key would return the
first answer), and it is a new decision. `ask`, as in the library, creates no
queue item and has no `approval`: a person the host's own UI reaches answers it,
and a retry is decided afresh (still `ask`). With no one there
(`attended: false`) the same call is a `hold`. `GET /v1/approvals/{id}` reports
`pending`, `approved` or `denied` (rejected); queue items do not expire in v0,
so `expired` is not returned yet.

`dryRun: true` returns a decision with a `decisionId` (not usable for
`results`) and leaves out `log` and `approval`; nothing is recorded.

A decision the log refuses to record is `FW-LOG-UNRECORDED`, as in the library:
an allow becomes `ask` with a person there and `deny` without.

## Errors

`application/problem+json`: `{ "type", "title", "status", "detail" }`. 400 bad
request (unknown field, unknown format, bad JSON, a bad session id, an
Idempotency-Key reused with another body), 401 no, bad or revoked token, 403
`forbidden` (Origin or Host refused, or a token whose roles do not cover the
endpoint), 403 `forbidden-context` (a context the registry does not allow: an
MCP source looser than the registered one, a root or cwd outside
`workspaceRoots`), 404 unknown session, decision, approval or path, 405 wrong
method, 413 too large, 429 `rate-limited` or `too-many-sessions` (with
`Retry-After` for the rate limits), 500 (also a damaged token file or registry:
never an open door; the body names no internals), 503 `overloaded` (with
`Retry-After`). A policy file that does not load is not an error: the layers
that loaded apply, every risky call carries `FW-POLICY-ERROR`, and every
decision's `problems` says why. The conformance vectors (conformance/README.md) pin the 400s
only; the other statuses are tested separately.

## Fail-closed (SDK side)

The SDK turns every failure into a decision, never an exception the integrator
can forget:

| Failure | Read-only tool (registry kind `read`, results trusted, no private data) | Anything else |
|---|---|---|
| unreachable, timeout (default 250 ms), 503 (TypeScript and Python) | `allow` (configurable to `deny`: `failOpenReads: false` in TypeScript, `fail_open_reads=False` in Python) | `deny`, rule `FW-UNAVAILABLE` |
| 500 or any other 5xx (TypeScript and Python: the sidecar took the request and failed on it) | `deny` | `deny`, rule `FW-UNAVAILABLE` |
| 429 | as for unreachable | `deny`, `FW-RATE-LIMITED`; no tight retry loop |
| 400, 401, 403, 404 | `deny` | `deny`, rule `FW-API-ERROR` |

## Not in v0

Hosted and self-hosted service, JWS approval tokens, central policy bundles,
data classes, `openai.responses` and `gemini` formats, the Go SDK, configurable
rate limits.

## Reference client behaviour

Choices the contract leaves to the client (host-UI approvals, `native` versus
`engine` tool names, malformed answers, 429, retries) are described in
[api.md](api.md#how-the-typescript-remote-guard-handles-the-cases-v0-leaves-open).
