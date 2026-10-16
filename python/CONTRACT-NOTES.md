# Contract notes: where docs/api-v0.md left a choice open

The Python SDK is part of the [Agent Firewall repository](../README.md), beside the sidecar it
talks to (`launchsafe-firewall serve --api`, [docs/api.md](../docs/api.md)). The wire contract is
[docs/api-v0.md](../docs/api-v0.md). These notes record what the SDK does where the contract is silent
or ambiguous, so the sidecar can match it, or the contract can be changed and the SDK with it. Numbered
for reference; each says what the sidecar needs to do for the SDK to work, and where the contract has
since settled the point.

## Transport

1. **Default socket.** `<firewall home>/api.sock`, with the firewall home as
   [`firewallHome()`](../src/runtime/layout.ts): `$LAUNCHSAFE_FIREWALL_HOME` made absolute (relative
   to the working directory), an empty value counting as unset, else `~/.launchsafe-firewall`.
2. **Host header on the unix socket.** httpx sends `Host: localhost` (no port) over the socket. The
   Host check must apply only to the TCP listener, or accept that header on the socket. The contract
   says the Host check is the TCP listener's only.
3. **Health without a token.** The SDK sends no `Authorization` on `GET /v1/health`.
4. **Timeouts.** 250 ms for decide and 2 s for everything else, applied both by httpx per phase
   (connect, read, write, pool) and as one total deadline for the call. `AsyncClient` cancels the call
   at the deadline; `Client` reads the body chunk by chunk and gives up past the deadline, and never
   uses an answer that completed after it. (A blocking client cannot interrupt a single stalled phase,
   so its worst case is the deadline plus one phase.) A late answer is a timeout: never an allow for a
   non-read tool.
4a. **Socket ownership.** Before any call on the unix socket (and so before the token is sent), the
   client checks that the socket is owned by the calling user and has no group or other permission
   bits, as the sidecar creates it (0600). Anything else is `FirewallUntrustedSocket`, which the guard
   treats like an API error (deny, reads included). Messages never name the socket's path, because
   deny messages reach the model.
5. **No `?wait=` long poll** (v0 has none). `wait_for_approval`
   polls `GET /v1/approvals/{id}` from 250 ms, times 1.5, up to 2 s between polls.

## Requests

6. **Raw formats carry `callId`, not `tool`/`input`.** For `openai.chat` and `anthropic` the SDK
   sends `format`, `raw` and `callId` (the raw block's id). The sidecar must accept `callId`
   beside `raw` and must not require `tool`/`input` for those formats.
7. **What is in `raw`.** `openai.chat`: exactly `{ "id", "type": "function", "function": { "name",
   "arguments" } }` (arguments kept as the model's string, even when it is not JSON). `anthropic`:
   exactly `{ "type": "tool_use", "id", "name", "input" }`; other keys of the SDK's block (such as
   `caller`) are dropped. The contract refuses unknown fields in the request envelope but ignores
   them inside `raw`; the SDK sends only these keys either way.
8. **`context` is left out when empty, and `dryRun` when false.** `Guard` sends `attended: true` by
   default (as `createGuard`); `Guard(attended=None)` leaves it out, and the contract's default for a
   missing `attended` is true.
9. **Session ids are one path segment, percent-encoded** (`run/42` is sent as `run%2F42`). The
   sidecar must decode it as one segment, and not split on an encoded slash. The contract allows 1 to
   200 letters, digits, `.`, `_`, `-`, `:` and `/`, checked after decoding; the SDK does not check a
   caller's id (the sidecar answers 400). The SDK's default session id is `sdk-` and 24 hex characters.
10. **`content` (inputs) and `output` (results) are any JSON value**, sent as given: a string, or an
    object for structured tool output. Values that are not JSON are sent as their `repr()` text.
11. **Size.** A report's content is measured as the bytes that are sent: compact JSON in UTF-8 (a
    character outside ASCII counts 2 to 4 bytes, a quote, backslash or control character 2 to 6 once
    escaped). Over 512 KiB, it is sent as text cut to the longest prefix that, with a marker, fits in
    512 KiB, so the body stays well under the 1 MiB limit. If the sidecar still answers 413 (a
    smaller limit), the report is sent once more cut to 64 KiB, with a new `Idempotency-Key`; only a
    second 413 makes it a refused report (the guard then denies every later non-read call). A lone
    surrogate, which UTF-8 cannot carry, is sent as its JSON escape (`\ud800`). Decide bodies are not
    cut: a 413 there is a deny.
12. **`Idempotency-Key` on every POST**, not only decide. A report kept for retry is sent again with
    the same key. The sidecar may ignore the header on the session endpoints; it must not reject it.
13. **Approved, then the identical call again with a new key.** After an approval the SDK sends the
    same decide body with a fresh `Idempotency-Key` (the old key would return the cached ask). The
    sidecar must treat that as a new decision (the single-use allow), not as a key conflict.

## Responses

14. **Required decision fields.** The SDK requires `decisionId`, `verdict` (one of the four),
    `rules` (a list of `{ id, outcome?, reason? }`), `message`, `actionHash` and `session` (with
    `untrusted`, `untrustedBecause`, `holdsPrivateData`, `privateBecause`). `approval`, `engine` and
    `log` are optional, so a **dry run** may leave out `log` (and `approval`) but should still send a
    `decisionId`. Unknown fields are ignored and kept, so the sidecar can add fields freely.
15. **`ask`/`hold` without `approval`** is accepted (the call is simply not allowed and there is
    nothing to wait for). With an approval, `status` must be one of the four states. The sidecar queues
    only holds, never asks. With `wait_for_approval=True` the guard decides the identical ask again with
    `attended: false` (a hold of the same action, with an approval id), waits on that item, and decides
    the call once more; there, a recorded hold with no `approval` is an `FW-API-ERROR` (as in the
    TypeScript guard). Without the option it stays accepted.
16. **Reports on a session with no decision yet.** The SDK may send inputs and prompts before the
    first decide (a retrieved document at the start of a run). The sidecar creates the session then,
    as the contract says, and does not answer 404: a 404 on a report is treated as a refusal, and
    the guard denies every later non-read call. `GET /v1/sessions/{session}` for a session never seen may 404 (only
    `guard.state()` raises then).
17. **Redacted `output` is a string.** A non-string `output` in the results response is a protocol
    error.
18. **Problem documents.** `status` in the body is optional to the SDK; `title`/`detail` are shown in
    the deny message (escaped, cut to 120 characters). A body that is not JSON is accepted on error
    statuses.

## Fail-closed choices beyond the table

19. **Malformed answers deny everything**, read-only tools included, as `FW-API-ERROR`: a 200 that is
    not JSON, lacks a required field, has an unknown verdict, or any other 2xx or a 3xx (redirects
    are not followed). The table does not list this case; treating it like a 4xx is the stricter
    reading.
20. **413 and any other 4xx** (405, 409, 422) deny like 400.
21. **429.** `Retry-After` in seconds is honoured (an HTTP date is ignored); during the pause (default
    1 s, at most 60 s) the guard answers from the table without calling the sidecar, so there is no
    retry loop.
22. **Which tools are read-only is decided client-side**, from a local copy of the tool specs the
    integrator passes as `tools` (the registry file's `"tools"` object), because v0 has no way for
    an agent to read its registry. If the copy and the sidecar's registry differ, only the
    fail-open decision follows the copy; every real decision is the sidecar's. Engine-format and MCP
    calls are never read-only to the SDK. Suggestion for v1: a read-only `GET /v1/tools` for the
    agent's own specs, or a `toolsVersion` in `health`, so the SDK can check its copy.
23. **Fail-open reads are not recorded.** They have no `decisionId` to record a result against; the
    contract's read-only tools have trusted results and no private data, so there is nothing to
    taint.
24. **Undelivered reports** (sidecar away, 5xx, 429) are kept, up to 1,000, and sent in order before
    the next decision; if that fails, the decision fails closed. A refused report (4xx), or more
    than 1,000 kept, makes the guard deny every later non-read call (`FW-API-ERROR`, "start a new
    session"), because the session's state may be missing taint. A read-only call still asks the
    sidecar, also when the refusal came from the flush before that very call.
24a. **A dry run cannot be recorded against.** `check()` returns an `Authorization` marked
    `dry_run`; `record_result()` refuses it with a `ValueError` before sending anything, so a
    programming mistake never reaches the sidecar as a refused report (which would lose the state).
24b. **`context.traffic`** is sent only when the guard is made with `traffic=` ("tool" or
    "network").
25. **Prompts are not kept for retry.** A lost prompt only makes later decisions stricter (fewer
    named destinations), so `record_prompt` reports the failure and moves on.

## Integrations

26. **Approvals stay in the firewall.** None of the six integrations uses the framework's own approval
    (for example `needs_approval` in the Agents SDK, `interrupt()` in LangGraph): in v0 an agent credential can
    never approve, so a host-side yes could not reach the sidecar. With `approval_timeout` the guard
    waits on the firewall's queue instead. If a host-side approval channel is wanted later, the
    contract needs an endpoint (or signed token) for it.
27. **Agents SDK pre-approval guardrails.** With `pre_approval_tool_input_guardrails` on, the input
    guardrail runs before the SDK's own approval prompt and again before the tool, so the call is
    decided twice and logged twice.
