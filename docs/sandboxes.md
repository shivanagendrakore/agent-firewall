# Sandboxes: the firewall decides, a sandbox contains

The firewall's hooks decide whether each action an agent proposes may run, with
what the session has read in mind. They cannot contain a program that does run
(a compiled binary, a script that opens a socket), and they see nothing of an
agent that has no hooks. A sandbox is the other half: a hard boundary on files
and network that holds whatever the program is. Use both. This page is how.

| You run | The checkpoint (hooks, session taint) | The cage | Where |
|---|---|---|---|
| Claude Code, Codex or Gemini CLI on your machine | the firewall's hooks | the agent's own sandbox: `doctor --fix` writes Claude Code's from your policy; Codex `sandbox_mode = "workspace-write"`; Gemini CLI `-s` with `install --agent gemini --seatbelt` | [usage.md](usage.md), [agents/](agents/) |
| An agent without hooks (Aider, opencode, goose, a script), or a hooked agent you want caged without its hooks | none (run sees connections, not tool calls) | `launchsafe-firewall run`, or `run --agent claude\|codex\|gemini` | [run.md](run.md) |
| Any agent, with its hooks, in NVIDIA OpenShell | the hooks inside the sandbox, **and** the firewall's middleware outside it, which judges every outbound request with the sandbox's session | OpenShell: Landlock, seccomp, a network fence, a supervisor that sees every connection | this page |
| Any agent in another outer sandbox (a container, a VM) | the hooks inside | that sandbox, with an egress allowlist mirrored from your policy | [below](#any-other-outer-sandbox) |

`doctor` says which of your agents would run with no sandbox at all ("agent
sandbox"): an agent on your PATH without the firewall's hooks gets `run --agent
<name>`; one with the hooks gets its own sandbox or OpenShell, because inside
`run` its hooks cannot save their state and block every risky action (run.md,
"Hooks inside run cannot write state").

## NVIDIA OpenShell

[OpenShell](https://github.com/NVIDIA/OpenShell) (Apache-2.0) runs each agent in
a deny-by-default sandbox: Landlock limits files, seccomp hands every TCP
connection and DNS query to a **supervisor** on the trusted side, and the
workload has no other network path. The supervisor checks each request against
the sandbox's YAML policy (hosts, ports, methods and paths; REST, GraphQL, MCP
and JSON-RPC bodies), injects provider credentials only on the way out (the
agent never holds the key), and logs in OCSF. A **policy prover** checks
proposed network rules and holds new reach for human review. What follows is
from OpenShell's public documentation and repository for v0.1.4, read on 13
October 2026.

### What OpenShell lets another program decide

| Extension point | What it can do | Used here |
|---|---|---|
| **Supervisor middleware** (gRPC, `proto/supervisor_middleware.proto`) | Called by the supervisor *after* the network policy allows a request and *before* credentials are injected: allow, deny or change an HTTP request; inspect, change or block an HTTP response before the sandbox receives it; allow, deny or replace each WebSocket text message the sandbox sends. Selected per destination host in the sandbox policy (`network_middlewares`), in order, each entry with its own `on_error` (the generated policy sets `fail_closed`). | Yes: `launchsafe-firewall openshell serve` |
| Gateway interceptors | Govern control-plane operations (policy updates, sandbox creation). | No |
| Compute and credential drivers, isolation backends | Where sandboxes run and where secrets live. | No |

So there is a decision callback, and the firewall implements it. OpenShell marks
the middleware API a **research preview**: its contract may change between
releases, and protocol negotiation refuses an incompatible service at gateway
start. There is no OpenShell hook for file or process events: those stay with
OpenShell's own policy and the agent's hooks.

### How the middleware decides

```
  sandbox (agent + its hooks)            OpenShell supervisor                  your machine
  ───────────────────────────            ────────────────────                  ────────────
  curl -X POST paste.example ─TCP─▶ network policy: host listed?  ──gRPC──▶ openshell serve
                                     middleware: ask               ◀────────  │ POST /v1/decide
                                     inject credentials, connect             │ { engine HttpRequest,
                                                                              ▼   session = sandbox id }
                                                                         serve --api (engine, session
                                                                         state, queue, signed log)
```

- **Each request** becomes the engine tool `HttpRequest` (URL, method, body) in
  the session named by the sandbox's id (`<agentId>/<sandbox id>` in the API's
  namespacing; a policy entry's `config.session` puts several sandboxes in one
  session). A request with a body, or with a method other than GET, HEAD or
  OPTIONS, is a send; every request reads outside content (its response), so
  the session is untrusted from its first request, as it would be after a
  WebFetch. The scheme, host and method must be present (no request is taken
  for a GET by default), and a known field with the wrong protobuf wire type,
  another phase, or a sandbox or session id with an empty, `.` or `..` part is
  a malformed message.
- **Headers count as data.** Every request header value is added to what the
  engine scans, except a value that fits its header's bounded shape (listed
  under "Headers not scanned" in the limits below). `Authorization`, `Cookie`,
  `Referer`, `Origin`, `X-Api-Key` and any custom header are always added, and
  so is a standard header whose value does not fit its shape (a key in the
  `User-Agent`, a token in a MIME subtype or a `charset`, data in a language
  tag), a header sent twice, and every header once the values left out add up
  to more than 2 KiB. So a GET that carries such a header is judged as a send,
  and a credential in a header is caught like one in a body. A header that
  changes on every retry (a fresh signature, a trace id in a custom header)
  makes the retry a different request, so an approval does not match it.
- **A `Host` header must name the target.** A `Host` (or `:authority`) naming
  another host than the one the request goes to is denied
  (`launchsafe_deny_host_mismatch`), never judged by the target alone. So is a
  `:scheme`, `:method` or `:path` pseudo-header that does not restate the
  target OpenShell hands over (its scheme, method, path and query), and any
  other pseudo-header but `:protocol: websocket`
  (`launchsafe_deny_target_mismatch`): OpenShell sends the target and the
  header list separately, and pseudo-headers are left out of the scan only
  because they must restate the target. The `:path` value is compared after
  the same normalisation on both sides: percent-escapes of unreserved
  characters (letters, digits, `-`, `.`, `_`, `~`) decoded, other escapes in
  upper case, and a bare `?` with no query dropped; a `:path` with a fragment
  (`#`) never matches. This is how OpenShell is expected to build its target
  from the request line; it has not been confirmed against a real gateway, so
  a gateway that normalises differently makes ordinary requests show up as
  `launchsafe_deny_target_mismatch` (a false refusal, never a pass).
- **Bodies the service cannot read are held.** A request body that is
  compressed (`Content-Encoding` other than `identity`), binary by its
  `Content-Type` (`application/octet-stream`, images, archives, protobuf, ...)
  or not UTF-8 text is never judged as if it were empty: the host lists are
  checked with a placeholder (a deny stays a deny), and otherwise the request is
  held as an action the firewall cannot read, bound to the body's SHA-256, so a
  person's approval lets exactly those bytes through once.
- **Loopback targets** (`localhost`, `*.localhost`, `127.0.0.0/8`, `::1`,
  `0.0.0.0`, an address written as one integer) are denied
  (`launchsafe_deny_loopback`) without being judged.
- **Targets that are not on the public internet** are denied
  (`launchsafe_deny_internal_address`) without being judged: an IP address of a
  private network (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, fec0::/10)
  or of a block no public host lives in (link-local, multicast and reserved,
  the documentation and benchmarking blocks and the IETF protocol-assignment
  block), in the spellings the loopback check reads (short, hex and octal
  IPv4, IPv4 inside IPv6). These are the classes `run`'s DNS check refuses
  ([run.md](run.md)). The middleware sees the name OpenShell resolves, not the
  address it resolves to, so this refuses an address a sandbox policy names,
  never a name that resolves to one. A cloud metadata address is left to the
  engine, which denies it under `FW-METADATA`. The generated policy never lists
  an IP address. A policy you write that must let a sandbox reach a private
  address can leave it out of the entry's middleware hosts, and then the
  firewall does not judge that traffic at all.
- **Refusals are logged.** A request denied for its `Host`, a pseudo-header,
  a loopback target or an address that is not on the public internet is
  recorded through the API as a decision of its own
  (rule `FW-NET-REFUSED`, with the reason code and why), so a domain-fronting
  attempt leaves an entry in the firewall's signed log and the decision id is
  in OpenShell's metadata. The URL and the reason (which quotes the offending
  `Host` or pseudo-header value, cut to 200 characters) are recorded with
  credentials masked, and masked before they are cut, so a credential across
  the cut is never left half visible: credential-shaped values (keeping their
  first four characters), assignment-style ones in a query or header value
  (`?password=…`, `&access_token=…`, `/x/password=…`: a path's `/`
  separates like `?` and `&`; eight characters or more, or any length for a
  key named `password`, `passwd`, `secret` or `token`, alone or as the last
  word of the name, such as `db_password`; such a key's value is masked
  whole: a quoted one to its closing quote, a backslash-escaped quote inside
  it not counting, and an unquoted one to the next `&` or whitespace, or
  its end, through anything else in it: `/`, `?`, `#`, `,`, `;`, quotes and
  `}` included, so a quote or brace right after such a value is masked with
  it), and userinfo
  (`https://user:pass@host`, up to the last `@` of the authority, so a
  password holding an `@` is masked whole, and anything before the last `@`
  of a `Host` value). A NUL character in the quoted text is recorded as
  U+FFFD. Identical refusals are recorded once a minute: the ones in between
  are counted, and the count is in the next refusal recorded for them (a count
  still pending when the middleware stops is lost). Identical means the same
  sandbox, reason code and target host and, for a `Host` or pseudo-header
  mismatch, the same offending value (normalised: a `Host` value in lower
  case without brackets or a trailing dot, a `:path` as it is compared, other
  pseudo-headers trimmed and in lower case; the key holds a short hash of it),
  so `evil2.example` and `evil3.example` fronted onto one target are recorded
  one by one. The minute is measured on a monotonic clock, so a change to the
  system time neither reopens nor stretches it. A sandbox past 32 recorded
  refusals in any 60 seconds (a sliding window, so two minutes back to back
  never record 64 around their boundary) has its refusals of further kinds (new hosts or new
  offending values) counted together under one entry per reason code, so an
  agent in a loop cannot flood the log. If the API cannot record a refusal
  (unreachable, or it refuses the request), the request is still denied,
  without the entry; the middleware counts the failure, reports it on standard
  error (once per reason code a minute, the next report saying how many were
  not reported), and gives the throttle back its place, so the next identical
  refusal tries to record again and its count includes the one that failed
  and any counted while it was being recorded. Any other
  failure while refusing ends in the same deny, reported the same way.
- **The verdict:** `allow` passes. `ask`, `hold` and `deny` block the request:
  OpenShell answers the sandbox with its `middleware_denied` error and logs the
  reason code (such as `launchsafe_hold_fw_send` or
  `launchsafe_deny_fw_dlp_credential`) and the rule ids as findings. Whether
  the agent sees the reason code depends on OpenShell's error, not on the
  firewall. Nobody watches the network, so the generated policy sets
  `attended: false` and an ask is a **hold**: an item in the firewall's queue
  (`queue list`, `queue approve <id>`, phone approvals). After a person
  approves, the identical request passes once.
- **Responses:** the body goes to the session as that request's result, so
  secrets and private data in it count, and a value the firewall redacts (such
  as a vaulted secret) is redacted in what the agent receives. The service can
  rewrite a body only when it arrived as one unit of UTF-8 text and the
  redacted text fits in 512 KiB; when the firewall redacted something and it
  cannot rewrite the body (several units, not UTF-8, too large), the stream
  fails, so with `on_error: fail_closed` the response is not delivered, never
  delivered unredacted. Units of a multi-unit body before the last one are
  passed as they arrive, so a redaction found only at the end cannot recall
  them; OpenShell sends a whole body (the mode the service asks for) up to its
  `max_payload_bytes`. A response whose request the service has no record of
  (an empty or unknown request id, or one evicted from the last 10,000) gets a
  fresh read decision for its address, so it is still redacted; when that read
  is not allowed, the response is not delivered. A clean body is never
  rewritten. A response the service does not read (compressed or binary by its
  headers, partial, no-transform) is recorded as unread outside content.
- **WebSocket text messages** the sandbox sends are judged like request bodies.
  The values the service reads from OpenShell's WebSocket preflight (the
  inspect mode it answers with, the field numbers) come from the protocol file
  and have not been confirmed against a real gateway. The preflight, as the
  service reads it, carries the context, the target and the config, and no
  handshake headers, so the service checks no `Host` and scans no header
  there. The handshake itself is the HTTP upgrade request: OpenShell's
  documentation says a middleware with the HTTP request binding (this one
  advertises it) inspects the upgrade request, where the `Host` check, the
  pseudo-header check and the header scan above apply. A message to a
  loopback target, or to an address that is not on the public internet, is
  denied and recorded like a request to one.
- **A failure blocks only with `on_error: fail_closed`.** The local API down, a
  bad token, a malformed message, a body over 512 KiB, a redaction that cannot
  be applied: the service answers with a gRPC error, which OpenShell treats as
  a middleware failure. With `on_error: fail_closed`, which the generated
  policy sets on every entry, the traffic does not go out (or, for a response,
  does not come in). An entry you write yourself with `fail_open` lets it
  through.
- **Limits on the gRPC server:** at most 100 concurrent streams per connection,
  a connection idle for 15 minutes is closed, a call idle for 10 minutes ends
  with `DEADLINE_EXCEEDED` (a WebSocket session's stream lasts as long as the
  WebSocket), and one call may send at most 64 MiB and 100,000 messages.
- Every decision is in the firewall's signed log (`log tail`, `log verify`),
  tagged with the API agent and decision id; OpenShell's OCSF log has the
  reason code and rule ids.

### Set it up

On the machine that runs the OpenShell gateway, in your own terminal:

```sh
# 1. The local API, and a token for the middleware.
launchsafe-firewall api token add openshell --traffic network   # prints the token once
launchsafe-firewall serve --api                       # leave running

# 2. The middleware. Supervisors run in their own containers, so it must listen
#    on an address they reach. With TLS and the gateway's public key, every call
#    carries a token the gateway signed, naming the sandbox:
export LAUNCHSAFE_FIREWALL_API_TOKEN=lsfw_...
launchsafe-firewall openshell serve --listen 0.0.0.0:50051 \
  --tls-cert fw.pem --tls-key fw-key.pem \
  --gateway-key gateway-ed25519.pub.pem --gateway-id <gateway id>
#    For local development only (OpenShell's allow_insecure_transport):
#    launchsafe-firewall openshell serve --listen 0.0.0.0:50051 --insecure

# 3. The sandbox policy, mirrored from your firewall policy.
launchsafe-firewall openshell policy --agent claude --endpoint https://<host>:50051 > policy.yaml
```

Make the middleware's token with `--traffic network`. Its HTTP requests are
then judged as network traffic, which does not use up the agent's toolCalls
limit or its agent-wide monitor (api.md, "Network middleware traffic"). A token
made without it is an ordinary agent token, and the local API refuses the
middleware's requests from it (400, which fails closed). Give the middleware
its own token: never hand a `--traffic network` token to an agent.

Then register the service in the gateway's TOML (the generated policy prints
this block at its top), restart the gateway, and create the sandbox:

```toml
[[openshell.supervisor.middleware]]
name = "launchsafe-firewall"
grpc_endpoint = "https://<host>:50051"     # or http://host.openshell.internal:50051 with allow_insecure_transport = true
tls_ca_cert_path = "/path/to/ca.pem"
max_payload_bytes = 524288
timeout = "500ms"
```

```sh
openshell sandbox create --policy policy.yaml
```

Inside the sandbox image, install the firewall and its hooks for the agent
(`launchsafe-firewall install --agent claude`), so tool calls are judged there
too; attach the model API key as an OpenShell provider rather than putting it
in the sandbox.

`openshell serve` refuses a non-loopback address without TLS and the gateway's
key unless you pass `--insecure`, and the four TLS flags go together. Without
TLS it prints a warning on every start, on loopback too: it cannot tell the
supervisor from any other caller that reaches the port (see `--insecure`
below). The `--gateway-key` file may hold several keys (PEM blocks one after
another, or a JWK Set), so the old and the new key are both accepted during a
rotation; a token is
refused when it is valid for more than an hour (`exp` minus `iat`, or `exp`
minus now). With tokens verified, an evaluation is answered only for the sandbox the token names
(`caller_kind: supervisor`, `sandbox_id`), and the gateway's own token may only
describe the service and validate config. Like `serve --api`, it is a person's
command: from an agent's tool call it is `FW-TAMPER`, and it is refused inside an
agent session.

### The generated policy

`openshell policy` uses `profileFromPolicy()`, the derivation behind `run` and
`doctor --fix`, so OpenShell admits the same hosts: IP addresses, loopback,
metadata and capture hosts and `denyHosts` are never listed.

- `sendAllowHosts` and `--send-host`: `access: full`.
- `fetchAllowHosts`: `access: read-only` (GET, HEAD, OPTIONS), except code hosts
  and registries (`github.com`, `registry.npmjs.org`, ...), where fetching itself
  uses POST (git's smart HTTP): `full`, with uploads judged by the middleware.
- A firewall pattern `x` (the host and its subdomains) becomes `x` and `**.x`;
  a wildcard with fewer than three labels is left out (OpenShell refuses it),
  with a comment.
- `--agent claude|codex|gemini` admits that agent's model API (the same exact
  hosts as `run --agent`) and leaves it **out of the middleware**: the whole
  conversation goes there every turn. That makes it an unjudged, unbudgeted way
  out: anything the agent reads can leave in a model request, and nothing
  counts the bytes. The policy says so in a comment.
- `network_middlewares` attaches the firewall to every other listed host, 32
  hosts per entry (OpenShell's limit), at most 10 entries.
- Every value printed into the policy, comments included, is JSON-quoted, and
  a host with a control character (in the firewall policy, which refuses it
  already, or in `--send-host`) stops the command before anything is printed.
- `--no-middleware` with a `denyHosts` entry under an admitted wildcard prints
  a warning on standard error and a `WARNING` comment in the policy: without
  the middleware nothing refuses that host.
- Every rule has `binaries: [{ path: "/**" }]` (any program in the sandbox).
  Narrow it to the agent and the tools it needs.
- `filesystem_policy`: the working directory and `/tmp` writable, `/usr`,
  `/lib`, `/etc` readable. Add what your image needs.

### What is shared, and what is not

Shared, because the middleware asks the same local API:

- the policy (host lists, `denyHosts`, `dataAllowHosts`, vault bindings, decoys),
  the engine and its rule ids;
- the queue and approvals, and the signed log of the firewall home `serve --api`
  uses.

Not shared in this release:

- **Session state between the hooks inside and the middleware outside.** The
  hooks in the sandbox keep their own sessions in the firewall home inside the
  image; the middleware keeps one per sandbox on your machine. Taint is not
  merged. The middleware's session is the conservative one: it is untrusted
  from the sandbox's first request, and it never sees the person's prompts, so
  hosts you name in a prompt do not widen it.
- **The hooks' state inside the sandbox is writable by the agent's processes**
  (it lives in the same sandbox, as with Gemini CLI's `-s`). The hooks refuse
  visible writes to it (`FW-TAMPER`); a program they cannot see into could reset
  them. The middleware's session is outside, out of reach.
- **The model API** is admitted but not judged or counted (left out of the
  middleware): an exfiltration path for anything the agent read. OpenShell's
  provider keeps the key out of the sandbox; nothing here limits what is sent
  with it.
- **What OpenShell does not hand to middleware:** WebSocket binary messages and
  messages from the server, bodies of compressed, partial or no-transform
  responses (recorded as unread, not inspected), and endpoints with `tls: skip`.
  A request body over 512 KiB is a middleware failure: blocked with
  `fail_closed`.
- **Headers not scanned:** bounded shapes, not a guarantee of no data. Only
  these values, each when it fits exactly, the header is sent once, and all of
  them together stay under 2 KiB:
  `Content-Length` of digits; a `Content-Type` or `Accept` media type from a
  closed list of registered types (`application/json`, `text/html`,
  `image/png`, ...), a wildcard (`*/*`, `text/*`), or a type and an alphabetic
  subtype of at most 24 letters, dots and dashes with a registered suffix
  (`application/vnd.api+json`), with only a `charset` from the list below and
  a `q` value; `Accept-Charset` and `charset` values from a closed list
  (`utf-8`, `utf-16`, `utf-16le`, `utf-16be`, `us-ascii`,
  `iso-8859-1` to `iso-8859-15`, `windows-1250` to `windows-1258`);
  `Accept-Language` tags of a 2 or 3 letter language with at most a 2 letter
  region, the numeric region `419` or a 4 letter script, with `q` values, and
  `Accept-Language` and `Accept-Charset` lists of at most 10 items; the enumerated
  values of `Accept-Encoding`, `Content-Encoding`, `Connection`,
  `Keep-Alive`, `TE`, `Transfer-Encoding`, `Upgrade`, `Cache-Control`,
  `Pragma`, `Expect`, `DNT`, `Upgrade-Insecure-Requests` and `Sec-Fetch-*`;
  an HTTP date in `If-Modified-Since` and `If-Unmodified-Since`; a byte
  `Range`; `Sec-WebSocket-Version` digits and `permessage-deflate`
  extensions; a `Sec-WebSocket-Key` of exactly 24 base64 characters ending
  in `==` (16 random bytes by the protocol, so at most 16 bytes of the
  client's choosing); a `User-Agent` of at most 256 characters made of
  product tokens (a name of letters, a version of digits and dots with at most
  12 digits) and comments of plain words, version numbers of at most 2 digits
  per part and a fixed set of platform names (`X11`, `x86_64`, `Win64`,
  `rv:128.0`), with at most 40 digits in the whole value; and a `Host` or
  `:authority` naming the target. Pseudo-headers are not scanned because they
  must restate the target (above). Anything else (a digit in a subtype, a
  token as a charset, a key in a `User-Agent` word, a `User-Agent` with a URL
  or JSON in it, digits split over many `User-Agent` products past 40, a long
  language list) is scanned, and its GET is judged as a send. **Residual
  channels:** these shapes bound what a header can carry; they do not close
  it. A `User-Agent` can still carry words of letters of the agent's choosing
  (up to its 256 characters) and up to 40 digits, a language list up to 10
  short tags, a suffixed subtype up to 24 letters, and `Sec-WebSocket-Key` 16
  random-looking bytes the client picks; together they stay under 2 KiB per
  request. A secret in a recognised format is caught wherever it is (it does
  not fit these shapes); data the agent encodes into letters is not. Response headers are read only for
  their `Content-Encoding` and `Content-Type`.
- **Denied hosts under an admitted wildcard** (`gist.github.com` under
  `github.com`): OpenShell's network rules cannot subtract a host; only the
  middleware refuses it. The policy names each such host in a comment.
- **File rules.** Landlock cannot make a path inside the writable working
  directory read-only, so `.git/hooks`, `.claude/settings.json` and the other
  files `run` protects stay writable there. The hooks still judge the agent's
  own writes to them.
- **run's byte budgets** are a feature of run's proxy; the middleware applies
  the engine's rules per request.
- **Without TLS (`--insecure`, and plaintext on loopback):** callers are not
  verified. Anyone who reaches the port (on loopback, every process on the
  machine, including an agent's tool calls outside a sandbox) can ask for
  decisions in any sandbox's name, add taint and outside content to its
  session, and use up a person's approval: after `queue approve`, the identical
  request passes once, for whoever sends it first. `serve` warns on every start.
  Local development only.

**What was tested:** the middleware against a stand-in supervisor that speaks
the protocol from OpenShell's `proto/supervisor_middleware.proto` (v0.1.4) over
real HTTP/2 gRPC, with the real local API, engine, queue and signed log
(`test/openshell/`). It has not been run against a real OpenShell gateway in
CI; a field rename in a future OpenShell release is caught at gateway start by
protocol negotiation, not silently.

## Any other outer sandbox

A container, a VM, gVisor or Firecracker has no callback the firewall can
answer. Run the agent inside with its hooks installed, and give the sandbox an
egress allowlist from your policy: `launchsafe-firewall openshell policy
--no-middleware` prints the host list in one place to copy from, and
`launchsafe-firewall run --dry-run` prints the same list. Shared: the policy
when you copy it. Not shared: everything that happens afterwards (the outer
sandbox does not ask the firewall anything). A `denyHosts` entry under an
admitted wildcard is enforced by nothing there; `--no-middleware` warns about
each one.

## Platforms

- **macOS (`run`):** `sandbox-exec` (Seatbelt) confines file writes, network,
  signals, Apple Events and named system services (LaunchServices, the
  pasteboard, the keychain, name resolution, preference writes), and denies
  hard links, launchd jobs, other processes' information and task ports and the
  `TIOCSTI` ioctl (the name-resolution, preference-write, hard-link, launchd,
  process-info, task-port and TIOCSTI rules are generated and tested as
  profile text only; to be verified on a Mac, [run.md](run.md) Limits). The profile starts from "allow"
  and denies those, so a system service not on the list that does work for its
  caller is not stopped; Claude Code's own profile starts from "deny" and is
  stricter. `sandbox-exec` is deprecated by Apple (it still works on macOS 26).
- **Gemini CLI's `-s` with the firewall's profile:** whatever the profile lets
  the hook write, the agent's own commands can write too, since they share the
  sandbox: the hook's session state (trust, counters, mode), its queue, its
  log, the provenance ledger, MCP pins, the quarantine and the scan receipts. A
  command that edits session state can undo a session's taint or reset its
  counters, and one that deletes log files leaves a gap the log's signature
  chain shows (`log verify`) but cannot prevent. The firewall judges every
  command (writing its directory is FW-TAMPER), so the profile's protection of
  that state is the analyser's, exactly as without `-s`; the policy, keys,
  install records, backups and vault stay read-only.
- **Linux (`run`):** bubblewrap needs **unprivileged user namespaces**. Ubuntu
  24.04 restricts them through AppArmor
  (`kernel.apparmor_restrict_unprivileged_userns`), some hardened kernels turn
  them off, and inside a Docker container bubblewrap needs `--security-opt
  seccomp=unconfined --security-opt systempaths=unconfined`. `doctor` probes
  and prints bubblewrap's error.
- **OpenShell** sandboxes Linux workloads (Docker, Podman, Kubernetes or a
  MicroVM); `openshell serve` runs wherever the firewall runs (macOS or Linux),
  as long as the gateway and the supervisors reach it.
