# Conformance vectors for the Agent Firewall API

A language-neutral test set: the in-process library and the API sidecar (`serve --api`) are both checked
against the same JSON files, so they cannot give different verdicts, and the [Python SDK](../python/README.md)
runs them through its client against the real sidecar. The contract is
[docs/api-v0.md](../docs/api-v0.md). Every expected value was recorded by running the real engine through
`createGuard` (never written by hand); the vectors are data, and no string in them is ever run as a command.

## Files

| Path | What |
|---|---|
| `vectors/*.json` | Each file is a JSON array of vectors (602 in all). The groups: `engine-friction`, `engine-incidents`, `engine-catalogue` (drawn from `src/corpus.ts`, `src/scenarios.ts`, `src/catalogue-scenarios.ts`), `format-native`, `format-openai-chat`, `format-anthropic`, `format-mcp`, `format-details`, `families` (send and egress, secrets leaving, destroy, unknown tools, instructions and persistence, private data, attended vs unattended, approvals, sessions, workspace), `rules` (rule by rule, each with the twins that must not fire it: catastrophic actions by kind, hidden text and hidden output, input shape, credential flow, raw IPs, secrets and personal data leaving, metadata, download-and-run, agent settings and instructions, obfuscation, privilege, agent spawning, outside writes, send arguments, data-carrying addresses, secret variables, untrusted code, symlinks, commands outside content showed), `network-traffic` (a network middleware's requests and refusals, and the 400s for the wrong token, format or tool), `invalid-requests` (400s, and the `raw` keys that are ignored); and the 149 vectors with a `setup` (see "The prepared environment"): `prepared-decoys` (decoy reads and decoy values leaving), `prepared-files` (instruction imports, auto-run edits, patch files, upload sizes, secret files), `prepared-policy` (the user's and the project's policy: hosts, credentials, unattended, untrusted paths, MCP servers, protected paths and branches, task scope, output masking, suggested commands), `prepared-budgets` (request, byte, MCP-call and loop budgets, and the behaviour monitor's limits and stop scope), `prepared-caps` (spending limits: tool calls, tokens, cost, identical failures, the warning, network traffic not counted), `prepared-hosts` (known hosts, `knownHosts.mode` ask, and what `knownHosts.builtins` false leaves known), `prepared-packages` (the malicious-package snapshot, lockfiles, typosquats), `prepared-ledger` (files one session wrote and another runs or reads: a script, a build manifest, a note outside the workspace; they need a persistent provenance ledger in the firewall home). Every character outside ASCII is written as a `\uXXXX` escape (UTF-16), so hidden characters show in a diff. |
| `translate.ts` | The contract's request shapes to library calls (`translateDecide`, `translateRegistry`, `translateResult`, `translateInput`, `translatePrompt`). Pure and browser-safe; the sidecar can import it. |
| `run.ts` | Runs a vector against the library and returns the actual results in the `expect` shape. |
| `setup.ts` | Prepares a vector's `setup` in a temporary tree (and removes it); both TypeScript runners use it. |
| `author/` | The sources of the vectors (the requests only). |
| `generate.ts` | Runs `author/` through `run.ts` and writes `vectors/*.json` with the recorded results. |
| `../test/conformance.test.ts` | Checks every recorded vector against the library, the vector set's coverage, and the translation. |
| `../test/api/conformance-sidecar.test.ts` | Checks every recorded vector against the real sidecar over its unix socket. |
| `../test/conformance-setup.test.ts` | The setup's tree, the paths it refuses, the placeholders, and the files it writes. |
| `../python/tests/test_conformance.py` | Every recorded vector through the Python SDK's `Client` against the real sidecar (see below). |

## The vector format

```jsonc
{
  "id": "native-read-then-send-asks",
  "description": "...",
  "source": "where the case comes from (people only)",
  "agentTools": { "tools": { "search_docs": { "kind": "read", "results": "untrusted" }, ... } },  // the registry, contract shape
  "setup": { "files": { ... }, "decoys": [ ... ], "policy": { ... }, "budgets": { ... }, "packages": { ... } },  // optional
  "steps": [
    { "kind": "decide", "request": { /* POST /v1/decide body */ }, "expect": { "verdict": "allow", "ruleIds": [], "sessionUntrusted": false, "holdsPrivateData": false } },
    { "kind": "result", "request": { "session": "run-1", "decisionId": "@step:0", "output": "..." }, "expect": { "sessionUntrusted": true, "holdsPrivateData": false } },
    { "kind": "decide", "token": "network", "request": { /* context.traffic "network" */ }, "expect": { ... } }
  ],
  "implementationSpecific": "why"   // optional, see below
}
```

A step's optional `token` says which of the agent's two tokens sends it: `"agent"` (the default, `api token add
<agentId>`) or `"network"` (its network middleware's, `api token add <agentId> --traffic network`). Only the network
token may send `context.traffic: "network"`; a runner holds both tokens for the one agent and sends each step with
its own. In the library (`run.ts`) the network token is the host saying the request is a middleware's
(`GuardOptions.traffic`), and `context.traffic: "network"` without it is the same 400.

`implementationSpecific`, when present, says why the vector pins a choice the contract leaves to the implementation
(today: `policy-deny-host-no-workspace`, which project policy applies to a call naming no workspace, and nine of the
twelve `prepared-ledger` vectors, whose outcome depends on a persistent provenance ledger: what an earlier session
wrote, kept between sessions). Another implementation may answer differently there and still conform: its runner
reports the difference instead of failing. One with no persistent ledger answers those nine as a fresh session would.

One vector is one agent with one tool registry and a fresh firewall state (no earlier sessions, no approvals).
A vector without `setup` runs in the reference environment; one with `setup` runs in the prepared environment.
Steps run in order. The step kinds:

| kind | request | what an implementation does |
|---|---|---|
| `decide` | the decide request body (`session`, `action`, `context`, `dryRun`) | `POST /v1/decide` |
| `result` | `{ session, decisionId, output }` | `POST /v1/sessions/{session}/results` |
| `input` | `{ session, source, content, private? }` | `POST /v1/sessions/{session}/inputs` |
| `prompt` | `{ session, text }` | `POST /v1/sessions/{session}/prompts` |
| `approve` | `{ session, decisionId }` | a person approves the hold that step made: not an agent API call. The sidecar runs the firewall's own approval (`queue approve`) on the item the decision returned; the library calls `guard.approve(heldId)`. Only holds are approved (see "Not pinned"). |

In `result`, `input` and `prompt` requests the session is in the body (in the API it is the URL path).
`"@step:N"` as a `decisionId` means the `decisionId` the decision of step N returned; replace it before sending.

`expect` is the whole of what is compared:

- `verdict`: `allow`, `ask`, `hold` or `deny`.
- `ruleIds`: the exact set of rule ids in the decision (compare as sets; the file keeps them sorted). An allow has none except `FW-APPROVED` for a held call a person approved.
- `sessionUntrusted`, `holdsPrivateData`: the `session` object of the decision (for a `decide`), or the session after the step (for the other kinds). Left out for a `dryRun` decision, because the contract does not say what a preview's `session` object shows.
- `redacted`: on a `result` step, the output with credentials masked, when the policy masks them (`redactSecretsInOutput`; `policy-redact-output*` have it). In the API it is the `output` field of the results response. The mask keeps a credential's first four characters and replaces the rest with `…[redacted by LaunchSafe Firewall]` (U+2026, then that text), every occurrence of each credential, the rest of the output unchanged; `redacted` is left out when nothing was masked.
- `error: 400`: the request must be refused as a bad request, and nothing reaches the engine. These are the `invalid-*` and `network-400-*` vectors. They come from `translate.ts` (the contract's request rules) and the token rule above, not the engine.

`expectApi`, on a step that has it, replaces `expect` for a runner that talks to the HTTP API. It records the one
place the routes differ by design: the API refuses a body its own limits reject before the engine sees it (arguments
nested deeper than 256 levels: 400), where the library judges the call (deny, `FW-INPUT-SHAPE`). It is recorded from
`src/api/request.ts`, never by hand, and is only ever on a vector's last step (`rule-input-shape-depth-257*`).

Nothing else is compared: not `decisionId`, `message`, `actionHash`, `log`, `approval` ids or reasons.

Reading the recorded values:

- An `allow` carries no rule ids except `FW-APPROVED` (a held call a person approved) and two notes that never
  stop a call: `FW-CANARY-READ` (a decoy was touched: allowed on purpose, so the decoy does not give itself away; the
  session becomes untrusted) and `FW-CAP-WARN` (a spending limit is near, noted when no one can be asked or the policy
  says `caps.warn: "note"`; with a person there it is an `ask`).
- An `ask` and a `hold` differ in what the session object shows: an `ask` is assumed to go ahead once the host's
  person says yes, so its effects (outside content read, private data, a credential read) are already in the
  decision's `session`; a `hold` (and a `deny`) records none until a person approves and the identical retry runs.
  Compare `secret-read-credentials-unattended` (hold, session unchanged) with an attended credentials read (ask,
  `holdsPrivateData` true).

## The reference environment

The contract leaves the host's environment to the host; the vectors fix it, so an implementation under test
must be configured the same way:

- the default policy (no policy file, no project policy), no vault, no package-intel snapshot, the memory store;
- the agent's home directory is `/home/agent`, there are no scratch directories, the clock is 2026-10-12T12:00:00Z;
- every call is from one agent, `conf` (the API namespaces its sessions as `conf/<session>`; the library is told the
  agent), so the per-agent counts (the behaviour monitor, `budgets.stopScope: "agent"`) are the same on both routes;
- **no file-system access**: no realpath, no file reads, no file sizes. Paths are judged as text. The paths in the vectors (`/srv/app`, `/home/agent`) do not exist; run the sidecar where it would not find them, or without file context;
- every request carries `context.workspace` (usually `["/srv/app"]`) and `cwd` as the vector says; unset means no workspace and `/`;
- `attended` defaults to true; `false` turns an ask into a hold;
- no decoy files are planted (vectors with a `setup` plant them; see below).

## The prepared environment (`setup`)

A vector with a `setup` object needs files, decoys, a policy, budgets or a package snapshot in place before its
first step. The runner prepares them in a fresh temporary tree, runs the steps with file access over that tree,
and removes the tree afterwards. Nothing in a setup is ever run: file contents are written as data, and every path
stays inside the tree.

The tree, under one new temporary directory (use its realpath, so symlinked temp directories do not differ):

| Directory | What | Placeholder |
|---|---|---|
| `workspace/` | the agent's project | `{{workspace}}` |
| `home/` | the agent's home directory (`~`) | `{{home}}` |
| `firewall/` | the firewall home (`LAUNCHSAFE_FIREWALL_HOME`) | none: a vector never names it |

Before the steps, replace `{{workspace}}` and `{{home}}` with those absolute paths in every string of every
step's request (at any depth), in the contents of `setup.files`, and in `setup.policy` and `setup.budgets`.
Requests in prepared vectors name the workspace as `"context": { "workspace": ["{{workspace}}"], "cwd": "{{workspace}}" }`.

`setup` has only these keys (any other key is an error; all are optional):

| Key | Shape | What the runner does |
|---|---|---|
| `files` | `{ "<area>/<path>": "<text>" }` | Writes each file (creating its directories). `<area>` is `workspace` or `home`; the path is relative, `/`-separated, with no empty, `.` or `..` segment and no backslash or NUL. Anything else is refused before anything is written. A project policy is a file here: `workspace/.launchsafe-firewall.json`. |
| `decoys` | `[{ "id", "path", "kind", "token", "fingerprint" }]` | Registers each decoy as `canary plant` does: `firewall/canaries.json` is `{ "version": 1, "canaries": [ { "id", "path": <absolute path in the tree>, "kind", "token", "fingerprint", "plantedAt": "2026-10-12T11:00:00.000Z", "workspace": <the workspace path, for a workspace decoy> } ] }`. `path` follows the `files` rules. The decoy file holds `files[path]` when given, else the token and a newline. `id` is `[a-z0-9]{1,32}`, `kind` one of env, aws, ssh, gh, notes, npmrc, kube, `token` contains `LSCANARY`. `fingerprint` is recorded in the vector (the engine's fingerprint of the token), so a runner copies it and never computes it. |
| `policy` | a policy document (docs/policy.md, with `version`) | Written as the user's policy file, `firewall/policy.json`. A policy that does not load is judged as every route judges it: the layers that loaded apply and every risky call carries FW-POLICY-ERROR (`policy-error-*` set one up on purpose). |
| `budgets` | the policy's `budgets` object | Merged into `firewall/policy.json` as its `budgets` key (with `{"version": 3}` when there is no `policy`). Not allowed when `policy` has `budgets` too. |
| `packages` | `{ "<ecosystem>": { "<name>": { "all"?, "versions"?, "ranges"?, "ids"? } } }` | Writes the malicious-package snapshot `launchsafe-firewall update` writes, covering exactly the ecosystems named (npm, PyPI, crates.io, RubyGems, Go, Maven, NuGet, Packagist): `firewall/intel/manifest.json` `{ "format": 1, "fetchedAt": "2026-10-12T12:00:00.000Z", "dir": "g-conformance", "sources": [...] }` and the bucket files and name index under `firewall/intel/g-conformance/<ecosystem, lower case>/` (layout in `src/runtime/intel.ts`; names normalised as `normalizeName` in `src/engine/packages.ts` does). Missing lists are empty; `all` defaults to false. |

The prepared environment differs from the reference one only in what the setup and the file system give:

- the engine has file access over the tree, as the hook has: symlinks resolved, file contents and sizes read,
  lockfiles, the decoy registry, the package snapshot (the sidecar's `fileAccess`, the library's
  `nodeEnvironment()` with `scratch: []`);
- the agent's home is `{{home}}`, there are no scratch directories, and the clock is still 2026-10-12T12:00:00Z;
- pinned, so the machine running the vectors does not change a verdict: paths compare case-sensitively (as on
  Linux; `run.ts` sets it, and the sidecar and Python runs in CI are on Linux; on macOS the sidecar compares without
  case and a case-dependent vector could differ there), and `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `GEMINI_CLI_HOME` and
  `GEMINI_CLI_SYSTEM_SETTINGS_PATH` are unset (each moves an agent's protected settings files out of the tree;
  `run.ts`'s `pinEnvironment()`, used by all three runners);
- the policy is what the firewall home's `policy.json` and each request's workspace `.launchsafe-firewall.json`
  give (user layer, then the project layer, tighten-only), read for every request;
- the firewall home keeps the provenance ledger (`firewall/ledger/`, empty at the start), so what one of the
  vector's sessions reported writing is known to its later sessions, as the hook and the sidecar know it
  (`prepared-ledger`);
- `prompt` and `input` requests carry no workspace (the API has none for them), so a task scope sees only what a
  prompt says without the workspace (intents and hosts, not workspace paths).

How each runner applies it:

- **library** (`run.ts`): `prepare()` builds the tree; each guard gets `nodeEnvironment()` over it, the policy from
  `loadPolicy()` of the tree's firewall home and the request's workspace, and a memory store holding the decoy
  index read from the registry, with `fileLedger()` over the tree's firewall home as its provenance ledger (the
  memory store keeps none).
- **sidecar** (`test/api/conformance-sidecar.test.ts`): the same `prepare()`; the server starts with the tree's
  firewall home as its home directory layout, `home: {{home}}`, `scratch: []` and `fileAccess: true`, and the
  vector's registry and both tokens (the agent's and its network middleware's) are set in that firewall home. Its
  guards get the provenance ledger through `fileStore`, in that same firewall home.
- **Python SDK** (`python/tests/test_conformance.py`): pytest starts `python/tests/conformance_sidecar.mjs`, a
  Node driver that imports the compiled firewall from `dist-conformance/` and, per vector, does what the sidecar
  runner does (the same `prepare()`, registry, tokens and server options) and returns the substituted steps. Every
  step goes through the SDK's typed calls (`usage` on decide and `failed` on a result included), with a second
  client for the network token; a body they cannot express (the 400 cases, and `context.traffic: "network"`, which
  an agent's SDK has no field for) goes as is through the same client. Every vector runs, those with a `setup`
  included. To run it: `npm ci && npx tsc -p
  tsconfig.conformance.json` at the root, then pytest in `python/` (it skips, saying why, without the build or
  Node; `LAUNCHSAFE_FIREWALL_CONFORMANCE=require` makes that a failure).
- **Other runners**: a runner that talks to a sidecar prepares the same tree, starts the sidecar with
  `LAUNCHSAFE_FIREWALL_HOME=<tree>/firewall`, the home directory `<tree>/home` and file access on (which keeps the
  provenance ledger in that firewall home), and substitutes the placeholders.

A shared fixture (one file of setup trees that vectors `extends`) was considered and left out: every runner, and
every outside consumer, would have to resolve a second file, and a vector would no longer be self-contained. The
repeated project files cost only file size.

## How `native`, `openai.chat`, `anthropic` and `mcp` are translated

Exactly as the contract says, in `translate.ts`:

- **native**: the tool is looked up in the registry. `kind` (and `results`, `privateData`) is a library `KindToolSpec`; `as` is an `AsToolSpec`; `map` becomes the input function, which builds the engine input from only the mapped fields (`$.a.b`, dots only; a missing source field is left out). No `map`: the arguments pass unchanged. A tool the registry does not list is FW-UNKNOWN-TOOL.
- **engine**: `tool` and `input` as given, the registry is not applied.
- **openai.chat**: `raw.function.arguments` is JSON-parsed (must be an object), `raw.id` is the call id, then as native.
- **anthropic**: `raw.input` and `raw.id`, then as native.
- **mcp**: the engine sees `mcp__<server>__<tool>`, judged with `mcp.source` as the configuration source (omitted: "unknown"). The registry is not applied.
- A request with an unknown field anywhere, a field that does not belong to the format, or a body the format does not describe is a 400.

## Running against the library

```
npm ci
npx vitest run test/conformance.test.ts        # every vector, plus the set's coverage and the translation
npm run conformance:generate                    # re-record vectors/*.json from author/ (review the diff)
npm run conformance:check                       # fail if vectors/*.json are not what the generator writes now
```

A change to a verdict or a rule id fails `test/conformance.test.ts` until the vectors are regenerated and the
diff is reviewed: that diff is the record of an intended behaviour change. Add a case by adding a skeleton in
`author/` (requests only) and regenerating.

## How another implementation consumes them

1. Read every `vectors/*.json`. For each vector, start from clean state, load `agentTools` as the agent's registry (`launchsafe-firewall api tools set <agent> <file>`, or the SDK's test hook), in the reference environment above.
2. For each step, send the request with the token the step names (the sidecar: over HTTP, one session namespace per vector; the Python SDK: through its client) and compare the response with `expect` as described (`expectApi` instead, where present, for an HTTP API). For an `approve` step, approve the hold of the referenced decision out of band, then continue.
3. The Python SDK and the sidecar can import nothing from here; they read the JSON (the Python test's Node driver uses the compiled `setup.ts` only to prepare trees). The sidecar (TypeScript) may import `translate.ts` so it reads requests the way the vectors do.
4. Fail-closed behaviour (timeouts, 5xx, 429), idempotency keys, authentication (401), Origin and Host checks (403), unknown sessions, decisions and paths (404), wrong methods (405), bodies over 1 MiB (413), TCP hardening and the other transport rules of the contract are out of scope for the vectors; they are separate tests. The vectors' only status is 400.

## Rule coverage

`test/conformance.test.ts` checks that every rule id in `src/rules.ts` is recorded by at least one vector, or is on
its exemption list with the reason. The exemptions: the API's and the SDK's transport answers (FW-UNAVAILABLE,
FW-RATE-LIMITED, FW-API-ERROR, FW-RESULT-UNRECORDED), a log store that refuses to record (FW-LOG-UNRECORDED), rules needing state a person signs (FW-LEARNED-*, FW-MCP-CHANGED,
FW-VAULT-*), the MCP gateway's and the mail guard's own rules (FW-MCP-TOOL-HELD, FW-MCP-WITHHELD, FW-MCP-SAMPLING,
FW-MCP-METHOD, FW-MCP-AUTH, FW-MAIL-WITHHELD), and FW-HIDDEN-OUTPUT, which no library or API decision carries (its
effect, the session made untrusted by hidden characters in a result, is pinned by `rule-hidden-output-*`).

## Not pinned (found while building the vectors)

- A yes to an `ask`. The contract says an ask creates a queue item and, once a person approves, the identical retry is allowed once. The library has no queue item for an ask: its approval callback answers it, and a retry is decided afresh (still an ask). Vectors approve holds only, until the two agree.
- `decide` with `dryRun`: what the `session` object shows (before or after the call).

## Not covered yet

- Task-scope paths: a `prompt` request carries no workspace, so a prompt naming a workspace directory never
  narrows the scope through the API (intents and hosts do; `policy-task-scope-*`). The scope's path rule (FW-SCOPE
  on a write outside the named paths) is not reachable until prompts can name their workspace.
- The vault (FW-VAULT-*): its index must be signed with the approver key, and a vector cannot carry a signature
  without a key in the vectors. Not in `setup` yet.
- The untrusted MCP-send budget (`budgets.untrusted.mcpSends10m`): in the case tried, a send that was asked about
  (FW-MESSAGE) and never answered was not counted, so a second send showed no FW-BUDGET-MCP. No vector pins it
  until it is settled which is intended. (Hosts in `sendAllowHosts` are exempt from budgets by design.)
- Symlinks already on disk, agent settings and hooks registered elsewhere on the machine, the sandbox profiles and
  the install directory: `setup.files` writes regular files only, and the rest lies outside the tree. (FW-SYMLINK
  is covered by commands that make a link: `rule-symlink-*`.)
- `Idempotency-Key`, `GET` endpoints and error codes other than 400.
- The shell constructs listed in docs/limitations.md: known gaps, not pinned.
