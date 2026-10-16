# The local API: the firewall for agents you build in any language

`launchsafe-firewall serve --api` runs the firewall as a small local server, so an agent written in
Python, Go or anything else asks it before each tool call, the way the [library](library.md) does
in-process for TypeScript. The server is the library over the firewall's own files: the same engine,
the same session state, the same signed log (`log verify`) and the same queue (`queue list`, terminal
approvals, and phone approvals, which are experimental: see [phone.md](phone.md)). The wire contract is
[api-v0.md](api-v0.md); this page is how to run it, and where it differs from v0 (token roles, the
registry's pins, request limits) it says so.

```
  your agent (any language) ──HTTP over <firewall home>/api.sock──▶ serve --api
      POST /v1/decide                                                 │ createGuard() per request
      POST /v1/sessions/{s}/results|inputs|prompts                    │ the firewall home's files:
      GET  /v1/sessions/{s} · /v1/approvals/{id}                      ▼ sessions, queue, signed log
```

## Set it up (a person, in their own terminal)

```sh
launchsafe-firewall api token add support-bot          # prints a token once: give it to that agent's process
launchsafe-firewall api tools set support-bot tools.json
launchsafe-firewall serve --api                         # listens on ~/.launchsafe-firewall/api.sock (mode 0600)
```

All of these are a person's commands. From an agent's tool call they are blocked (`FW-TAMPER`), as are
stopping the server (`pkill -f "serve --api"`) and writing anything under the firewall home (the socket,
`api/tokens.json`, `api/tools/`). A process started inside a coding agent's session (Claude Code, Codex, Gemini CLI or Cursor) is refused too.
`serve --api`, `api token list`, `api token revoke` and `api tools show` need no terminal, so a service
manager or a provisioning script may run them. `api token add` and `api tools set` make what an agent may
claim (a network middleware's token skips the agent's counts; a registry pins its sources and roots), so
they run only in an interactive terminal, and ask for the approval passphrase when one is set.

| Command | What it does |
|---|---|
| `serve --api [--listen 127.0.0.1:PORT]` | Runs the server. Default: the unix socket `<firewall home>/api.sock`, created mode 0600. `--listen` takes `127.0.0.1:<port>` or `localhost:<port>` only; any other address is refused before anything listens. Start and stop are recorded in the signed log. |
| `api token add <agentId> [--traffic network] [--role R ...]` | A new bearer token for the agent, printed once. Only its SHA-256 is stored (`api/tokens.json`, 0600). An agent may have several. `--traffic network` makes a network middleware's token (see "Network middleware traffic"); `--role` sets what it may do (see "Token roles"). |
| `api token list [--json]` | The agents with tokens, each token's roles and the start of its hash. Never a token. |
| `api token revoke <agentId>` | Revokes every token of the agent; a running server refuses them from the next request. It works even when another record in the file is damaged (that record is left as it was). |
| `api tools set <agentId> <file.json>` | The agent's tool registry (below). Validated before anything is written; a running server uses it from the next request. |
| `api tools show <agentId>` | Prints the stored registry. |

An agent id is 1 to 64 letters, digits, `_`, `-` or `.`, starting with a letter or a digit. Ids are
compared without regard to case: a token is not made for `Bot` while `bot` has one. `claude`, `codex`,
`gemini`, `cursor` and `gateway` are reserved for the firewall's own agents (their sessions, counters and
`agent stop` would be shared).

### Token roles

| Role | Endpoints |
|---|---|
| `decide` | `POST /v1/decide`, `GET /v1/sessions/{s}`, `GET /v1/approvals/{id}` |
| `report` | `POST /v1/sessions/{s}/results` and `/inputs` (they can only make a session stricter; a result for a call that ran also records the files it wrote, see "Files a session wrote"); `/prompts` is logged only |
| `prompt` | `POST /v1/sessions/{s}/prompts`, applied |

A token made without `--role` (every token made before roles existed) has `decide` and `report`. A
prompt names the destinations an untrusted session may still send to and sets the task scope, so it
counts only when it comes from a token made for what the person typed: `api token add <agentId> --role
prompt`, held by the part of your application that reads the person's input, never by the agent's tool
loop. From a token without the role, a prompt is answered `{"recorded": true, "applied": false, "detail":
...}` and only its hash is logged (`applied: false`). A request to an endpoint the token's roles do not
cover is 403. `--role` may be repeated or comma-separated (`--role decide,report,prompt` for one token
that does everything, as the in-process library does). The TypeScript remote guard sends prompts with
`promptToken` when given.

## The tool registry

The library's tool specs as data (an agent credential can never change them; there is no endpoint
for it):

```json
{
  "tools": {
    "search_docs":    { "kind": "read", "results": "untrusted" },
    "get_customer":   { "kind": "read", "results": "trusted", "privateData": true },
    "lookup_status":  { "kind": "read", "results": "trusted", "privateData": false },
    "send_email":     { "kind": "send" },
    "delete_account": { "kind": "destroy" },
    "run_shell":      { "as": "Bash", "map": { "command": "$.cmd" } },
    "http_get":       { "as": "WebFetch", "map": { "url": "$.url" } }
  }
}
```

`kind`, `results`, `privateData` and `server` mean what they mean in the library
([library.md](library.md#your-tools-in-the-engines-vocabulary)). `as` names an engine tool; `map` builds
its input from the call's arguments with dot paths (`$.a.b`), and leaves out a field whose path is
missing. Any other key, a bracket or filter path, or two tools of one server that disagree is an error.
In the `native`, `openai.chat` and `anthropic` formats, a tool the registry does not list is
`FW-UNKNOWN-TOOL` (ask, and its result makes the session untrusted).

A decide request's context is the agent's own word, so the registry can also pin it:

```json
{
  "tools": { "...": "..." },
  "mcpServers": { "crm": { "source": "user" }, "repo-tools": { "source": "project" } },
  "workspaceRoots": ["/srv/app"]
}
```

- `mcpServers`: where each MCP server the agent uses was configured, as you know it. A server listed
  here is judged with your source; a request that claims a source the engine trusts (`user`, `sdk`, ...)
  for a server you listed as untrusted (`project`, `dynamic`, `unknown`) is 403. A server **not** listed
  is never judged as a trusted source's on the agent's word: a claimed `user` (or any trusted source) is
  judged as `unknown` (its results are outside content unless your policy names the server), and the
  decision's `problems` says so. A server name may not hold `__` or end in `_`.
- `workspaceRoots`: every `context.workspace` root and `context.cwd` must be one of these or inside one,
  else 403 (without it, any absolute path is accepted, as before).

## Calling it

Every `/v1` call except `GET /v1/health` sends `Authorization: Bearer <token>`. Sessions are the
agent's own: `run-42` of one agent is never another agent's `run-42`.

```sh
SOCK=~/.launchsafe-firewall/api.sock
TOKEN=lsfw_...   # from api token add

curl --unix-socket $SOCK http://localhost/v1/health

curl --unix-socket $SOCK http://localhost/v1/decide \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"session":"run-42","action":{"format":"native","tool":"send_email","input":{"to":"ana@example.com","body":"hi"}}}'

# What the tool returned (after an allow): keeps the session's taint true.
curl --unix-socket $SOCK http://localhost/v1/sessions/run-42/results \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"decisionId":"dec_...","output":"..."}'

# Outside content that reached the agent without a tool call, and what the person typed.
curl --unix-socket $SOCK http://localhost/v1/sessions/run-42/inputs \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"source":"a support ticket","content":"...","private":true}'
curl --unix-socket $SOCK http://localhost/v1/sessions/run-42/prompts \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"text":"email the summary to ana@example.com"}'

curl --unix-socket $SOCK http://localhost/v1/sessions/run-42 -H "Authorization: Bearer $TOKEN"
```

To have spending limits (policy `caps`, [usage.md](usage.md#spending-limits)) cover model spend, send
the usage behind each call with it: `"usage": {"inputTokens": 1200, "outputTokens": 300, "costUsd": 0.0045}`
in the decide request (the cost is your own estimate; the firewall keeps no prices). Send `"failed": true`
with a result when the tool failed, so the same failure again and again stops at the identical-failures
limit. At a limit the decision is `deny` with rule `FW-CAP` and what the person can do.

The decision is `allow`, `ask`, `hold` or `deny`, with the rule ids, one message for the model and the
person, the session's trust state and the signed log entry. The formats (`native`, `engine`,
`openai.chat`, `anthropic`, `mcp`), every field and every error are in [api-v0.md](api-v0.md). The
[Python SDK](https://github.com/shivanagendrakore/agent-firewall/blob/main/python/README.md) speaks this API and turns every failure into a decision.

### Approvals

A `hold` is an item in the firewall's queue, shown by `launchsafe-firewall queue list` and approved
there (`queue approve <id>`, with the approval passphrase) or on a paired phone (experimental, see
[phone.md](phone.md)). Poll `GET /v1/approvals/{id}`; once it is `approved`, send the identical decide
request again (with a new `Idempotency-Key` if you use one) and it is allowed once. A retry with the
hold's own key gets the hold again, with `approval.status` as it is now (`approved` once a person
approved it), which tells you to retry with a new key. An `ask` creates no queue item: it is for a
person your own UI reaches, and with `context.attended: false` the same call is a `hold` instead.

The approval binds to the action **and** to the request's `context.cwd` and `context.workspace`: the
same call sent with another cwd or other roots is decided afresh (a relative path or a command means
other files in another directory), so retry exactly as it was held. It also covers only the rules the
person was shown: if another rule asks by the time of the retry (the session read a credential in
between, say), the retry is a `hold` again with a new queue item, its `message` says an earlier
approval was not used and why, and the earlier approval stays unused.

### Files a session wrote

Taint belongs to one session, but files outlive sessions. The server keeps the hook's provenance
ledger in its firewall home (`ledger/`, [design](design.md#provenance)): when you report the result of a
call that ran (a `Write`, an `Edit`, a shell command that writes), the files it left are hashed and
remembered with whether that session was untrusted. A different session that later runs such a
file, or a build whose manifest it is, is asked about it (`FW-UNTRUSTED-CODE`, `FW-TAINTED-MANIFEST`)
while the file still holds what the untrusted session left; a later trusted write of the whole file
with new content ends that (a report of the same bytes does not: what an untrusted session left stays
untrusted, whoever reports writing it again), and a change by anything else makes it ordinary code again. A file a trusted session wrote
reads back from outside the workspace without counting as outside content. The hook and the server
share the ledger when they share a firewall home.

- Report a result for every call that ran, with the files already on disk. A write whose result is
  never reported is not remembered. A result for a decision the server denied or held records nothing
  in the ledger (that call did not run), and a result is taken as true: the server cannot see
  what the tool did. A caller holding a `report` token can therefore make a file with new content
  count as a trusted session's; keep that role away from the agent's own process.
- It needs the server's file access (the default; `fileAccess: false` in the TypeScript `startApiServer`
  turns it off, and then nothing is read or written). The conformance vectors that need it say so
  (`implementationSpecific`).

### Network middleware traffic

A network middleware that asks about HTTP requests on an agent's behalf (the OpenShell supervisor
middleware, [sandboxes.md](sandboxes.md)) sends `"context": {"attended": ..., "traffic": "network"}`
(`middlewareDecideContext()` in `src/api/request.ts`). Such a request is not one of the agent's tool calls:

- **Skipped:** it does not count toward the `toolCalls` spending limit, and not toward the agent-wide
  behaviour monitor's counters (kept under `agent:<id>`) or the agent-wide stop they can trigger. A
  monitor stop it causes stays with the sandbox's session, even with `budgets.stopScope: "agent"`.
- **Still applies:** every rule (host lists, credentials leaving, the session's trust), the session's own
  budgets and behaviour monitor, the other spending limits (`bytesOut` and the rest), any stop already in
  force for the session or the agent, the queue and the signed log.

`traffic` is `"tool"` (the default) or `"network"`; any other value is 400. Leave it out for the agent's
own tool calls. Because network traffic skips those counts, the API does not take the caller's word for
it: `"network"` is accepted only

- from a token made for the middleware with
  `launchsafe-firewall api token add <agentId> --traffic network` (stored with the token, shown by
  `api token list`), and
- for the middleware's own request shape: `format: "engine"` with tool `HttpRequest`, the
  unreadable-request wrapper (`launchsafe:unparseable` whose `input.tool` is `HttpRequest`), or
  `launchsafe:network-refused`, the middleware's record of a request it refused before asking (a
  loopback or other non-public address target, a `Host` or pseudo-header naming another target),
  always denied under `FW-NET-REFUSED`.

Anything else with `"network"` (an ordinary agent token, or a `Bash` call from the middleware's token) is
400. So is `launchsafe:network-refused` without `"network"`, in any format: only the middleware may record
a refusal, so an agent cannot write refusal entries into its own log. The signed log entry of a network
request carries `"traffic": "network"`.

## Hardening

- The socket is mode 0600 in the firewall's private home. `--listen` binds 127.0.0.1 only.
- On TCP, `Host` must be `127.0.0.1:<port>` or `localhost:<port>` (DNS rebinding). On both, any request
  with an `Origin` header is refused (403): no web page can call it. Cookies are never read.
- Bodies are JSON of at most 1 MiB (413). An unknown field is 400 (inside `raw`, the framework's own
  block, only the documented keys are read).
- `Idempotency-Key` on decide: a retry with the same key and body gets the first answer and writes no
  second log entry, within limits so that a remembered answer never outlives a change. A `deny` or a
  `hold` is always given again, even after the hold is approved: retry with a new key after an
  approval. An `allow` or an `ask` is given again once, only within 30 seconds of the first answer
  (`IDEMPOTENT_ALLOW_MS`, a retry of an answer lost in flight), and only while a dry check of the same
  call still gives the same verdict for the same action with no `FW-STOPPED` or `FW-CAP` (so outside
  content read since, a new "never" or a changed policy is never answered with the old allow).
  Otherwise the call is decided again, logged and counted as a new one, and that answer becomes the
  key's, but a key has one replay in all: once it has been decided again, every later request with it
  is decided, logged and counted afresh (a `deny` or a `hold` among those answers is still given again).
  The request is read first, so a token without `--traffic network` that repeats a network
  middleware's key and body gets its own 400, never the remembered answer. A dry run
  (`dryRun: true`) is never given again (each is checked afresh), but its key is bound to its body
  like any other: the same key with another body is 400.
- Fail-closed: session state that cannot be read makes the session untrusted and holding private data;
  a decision the log could not record is `FW-LOG-UNRECORDED` (never an allow); a damaged token file or
  registry is a 500, never an open door, and its body names no path or parse error (the server's
  stderr does). A policy file that cannot be loaded is `FW-POLICY-ERROR` on every risky call (ask, as on
  the hook path), and every decision's `problems` says why.
- Limits: an agent may have 32 requests in flight and send 100 a second (300 in a burst); past them it
  gets 429 with `Retry-After`, and other agents are still answered. Past 256 requests in flight on the
  whole server, every request gets 503 with `Retry-After`. Each agent may open 100,000 new sessions while
  the server runs (429 past it; a new session starts clean, so this bounds how often an agent can leave
  a tainted one behind).
- Decision-log text (`what`) is written with credentials and URL query values masked.

## Verified together

On 12 Oct 2026 both SDKs were run end to end against this sidecar (the real server, engine, queue and
signed log in a throwaway firewall home), over the unix socket and over `127.0.0.1`:

- Sidecar and TypeScript remote guard: `@launchsafe/agent-firewall` 0.3.0, Node 24.21, with the Vercel AI
  SDK (`ai` 7.0.137) integration (`test/api/e2e-remote-guard.test.ts`).
- Python SDK: `launchsafe-firewall` 0.1.0 ([`python/`](https://github.com/shivanagendrakore/agent-firewall/blob/main/python/README.md)), Python 3.14.8, httpx
  0.28.1 (`test/api/e2e-python.test.ts`, which uses the venv named by `LAUNCHSAFE_FIREWALL_PY_VENV`, else
  `python/.venv`, and skips when it is missing).

Covered: allow, ask, deny, a hold approved in the queue and its single-use retry, all five formats, results,
inputs and prompts tainting the session, a revoked token, one agent unable to see another's session, and
the fail-closed table once the server is stopped. One difference between the SDKs: for an attended `ask`
(no queue item), the TypeScript guard's `authorize()` queues the call as a hold of the same action and
waits for the queue's approval; the Python `Guard` returns the ask unanswered (`allowed` false) for the
host's own person, and can queue it and wait with `wait_for_approval`.

## Limits in v0

- Decisions are remembered in memory, per agent, for `results` and idempotent retries (each agent's
  last 10,000, and at most about 64 MiB of their arguments: the oldest go first; idempotency keys are
  bounded the same way, 10,000 entries and about 64 MiB per agent). A `results` call
  for a decision the server has forgotten is recorded the strictest way (untrusted input holding
  private data) and answered with `"rule": "FW-RESULT-UNRECORDED"`; after a restart, `results` for
  an earlier decision is 404.
- One server per firewall home. A unix socket path must be under about 100 bytes; with a long
  `LAUNCHSAFE_FIREWALL_HOME`, use `--listen`.
- Not in v0: a hosted or self-hosted service, approval tokens, central policy, data classes,
  configurable rate limits, a `?wait=` long poll (see [api-v0.md](api-v0.md#not-in-v0)).

Latency, measured on a development Mac over the unix socket (every decision is fsynced to the log):
decide p50 about 7 ms and p95 about 8 ms for an allowed read, about 19 and 25 ms for a send that asks
(`test/api/bench.test.ts` prints them; it does not gate on them).

## How the TypeScript remote guard handles the cases v0 leaves open

`createRemoteGuard()` (`src/sdk/remote.ts`) is the reference client. Where the
v0 contract leaves a choice, it does this, and another client should match it:

- **A host UI's answer is not recorded.** v0 has no endpoint for an approval
  given in a framework's own prompt (and an agent credential must never
  approve). A framework's "no" is a no; its "yes" is necessary but not enough,
  and the guard then waits for the queue's approval.
- **Tool names under `native`.** The guard sends `native` by default; choose
  `format: "engine"` for Claude Code tool names.
- **`permissionMode` is not in the v0 context** (unknown fields are 400). A
  call whose mode is in `unattendedPermissionModes` is sent with
  `attended: false` instead.
- **`mcp.source`** is always sent, as `"unknown"` when the call does not say.
- **Fail closed on a broken answer.** A 2xx that is not JSON, not the contract's
  shape or larger than 2 MiB, and every other non-2xx below 500 except 429
  (413 included), is denied with `FW-API-ERROR`, even for reads.
- **Read-only means the contract's definition.** Only a `tools` spec with
  `kind: "read"`, `results: "trusted"` and `privateData: false` is read-only, so
  an engine-format `Read` is denied when the sidecar is down. Such a read goes
  ahead (unless `failOpenReads: false`) only when the sidecar could not answer:
  unreachable, timed out, 429 or 503. A 500 (or any other 5xx) means the sidecar
  took the request and failed on it, which a crafted request can cause, so it
  denies reads too (`FW-UNAVAILABLE`).
- **The transport is checked.** The unix socket is used only when it is a
  socket owned by this user with mode 0600 (else `FW-API-ERROR`, and the token
  is never sent). Loopback TCP (`baseUrl`) proves nothing about who answers
  (any local process may hold the port first, and it would receive the token),
  so it needs `allowTcp: true`.
- **Prompts** go with `promptToken` when given (a token with the `prompt`
  role); with the agent's own token they are only logged.
- **429.** The guard sends nothing for at least 1 s after a 429 (longer with
  `Retry-After`); calls in that window get `FW-RATE-LIMITED` locally.
- **Idempotency.** A key is sent on every POST and reused when a failed report
  is resent. `/v1/decide` itself is never retried.
- **Results without a decision.** `recordResult(call, output)` remembers the
  allowed decision by call id (else tool and input). With none, the output goes
  to `/inputs` as untrusted input, which can only make the session stricter.
- **Reports that fail.** A failed `/inputs` or `/prompts` is kept (up to 100)
  and sent before the next decision; decisions fail closed until it is. A 4xx on
  one, or more than 100, fails the guard closed for good.
- **Approval wait.** The guard polls the approval every second (`approvalPollMs`).
  A 404 ends the wait as pending with the error; it is never approved.
- **`ask` or `hold` without an `approval`.** To wait on the queue for an ask, the
  guard decides the identical call again with `attended: false`, which the
  server holds, and waits on that item. A hold without an approval is a
  malformed answer (`FW-API-ERROR`).
- **Session ids** are 1 to 200 characters and percent-encoded in paths.

## Errors

Every error is `application/problem+json` (`type`, `title`, `status`, `detail`); `type` is this page with
the error's name as the anchor.

### bad-request

400: the request is not what the contract allows (a missing or mistyped field, a path that is not valid
percent-encoding, a bad `Idempotency-Key`). `detail` names the problem.

### bad-json

400: the body is not valid JSON.

### unknown-field

400: a field the contract does not define (outside `raw`, where only the documented keys are read).

### unknown-format

400: `action.format` is not `native`, `engine`, `openai.chat`, `anthropic` or `mcp`.

### idempotency-key-reused

400: this `Idempotency-Key` was used with a different body.

### unauthorized

401: no bearer token, or one that is unknown or revoked.

### forbidden

403: a request with an `Origin` header (a web page), a wrong `Host` on TCP, or a token whose roles do not
cover the endpoint (see "Token roles").

### forbidden-context

403: the request claims a context the agent's registry does not allow: an MCP source looser than the
registered one, or a workspace root or cwd outside `workspaceRoots`.

### not-found

404: no such endpoint, session, decision or approval for this agent.

### method-not-allowed

405: the endpoint takes the other method (GET or POST).

### too-large

413: the body is larger than 1 MiB.

### rate-limited

429 with `Retry-After`: the agent is over its request limits (see "Hardening"). Decide nothing until then.

### too-many-sessions

429: the agent opened as many new sessions as it may while the server runs; reuse a session.

### internal

500: the server could not handle the request (a damaged token file or registry among the causes). The
body names no internals; the server's stderr says why. Both the TypeScript remote guard and the Python SDK fail closed on it, reads included (rule `FW-UNAVAILABLE`); only a 503 lets read-only tools through.

### overloaded

503 with `Retry-After`: the server has too many requests in flight. Not a refusal: retry later.
