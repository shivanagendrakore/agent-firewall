# The library: the firewall inside your own agent

Status: part of 0.3.0, the first public release.

The hook path (`launchsafe-firewall hook --agent claude|codex|gemini|cursor`) puts the
firewall in front of someone else's coding agent. Companies that build their
own agents need the same engine in-process: their agent loop calls a tool, the
firewall decides first, and the agent's own UI asks the person when a person
has to say yes. This document is the design of that library.

```
  your agent loop (Vercel AI SDK · OpenAI Agents SDK · Claude Agent SDK · LangGraph · your own)
      │  a tool call { tool, input } · untrusted content · the person's prompt
      ▼
  @launchsafe/agent-firewall/sdk          src/sdk/            createGuard()
      │  tool mapping (your tools → the engine's vocabulary)
      │  NormalizedAction + Context + SessionState            (the same types as the hook)
      ▼
  src/engine/  decide()  (pure, unchanged)
      │  Decision
      ▼
  StateStore   memoryStore() (default, browser-safe) · fileStore() (Node, the runtime's files)
  DecisionLog  hash-chained, signed when a signer is given (fileStore: the runtime's Ed25519 key)
```

## Principles

1. **One engine.** The library calls the same `decide()` with the same
   `NormalizedAction`, `Context` and `SessionState` the hook builds. No rule
   lives in the library or in an integration. The friction corpus and the
   incident corpus, replayed through the library, give the same verdicts and
   rule ids as the hook path (`test/sdk/parity.test.ts`), and so do the
   cases fixed after the pre-release review. `nodeEnvironment()` gives the
   engine the context the hook builds: file contents and real paths, file
   sizes (uploads count toward the budgets) and the protected settings
   files (the install record, the sandbox profile `doctor --fix` installed and
   the agents' own settings by location), through `fs.size` and
   `settingsFiles`.
2. **The library never approves on its own.** `deny` is never approvable and
   never reaches the approval callback. `ask` is allowed only when the host's
   approval callback (or the framework's own approval protocol, for the
   integrations) returns an explicit yes. `hold` is never allowed now; it is
   stored for review and runs only after the host calls `guard.approve(id)` and
   the agent tries the exact same call again (once). No callback, a callback
   that throws, times out or returns anything but `true` / `{ approved: true }`
   is a no.
3. **Dependency-free core, browser-safe.** `@launchsafe/agent-firewall/sdk`
   and the engine it imports use no Node module and no Node global (the engine's
   SHA-256 and byte decoding moved to `src/engine/bytes.ts`, pure TypeScript,
   tested equal to `node:crypto` and `Buffer`). The import graph is checked by
   `test/sdk/browser-safe.test.ts`. Everything that touches the file system is
   in `@launchsafe/agent-firewall/sdk/node`. That entry supports macOS and
   Linux: `createNodeGuard()`, `fileStore()`, `fileLedger()` and
   `nodeEnvironment()` throw on any other platform (Windows included) when
   called, before they create anything, so a guard that looks protected is
   never made where the firewall has not been written or tested to work. The
   browser-safe entry has no platform check. Each of the four takes a
   `platform` option, default `process.platform`, so a test can simulate one.
4. **Integrations are thin.** Each is one small file that translates a
   framework's official interception point to `guard.decide()` /
   `guard.recordResult()` and the framework's approval protocol to
   `guard.approveAsked()`. They import the framework for types only, except
   LangGraph, whose human-in-the-loop primitive (`interrupt`) and `ToolNode`
   are runtime functions (optional peer dependencies).

## API

```ts
import { createGuard } from "@launchsafe/agent-firewall/sdk";

const guard = createGuard({
  workspace: "/srv/app",                    // roots whose files are the agent's own work (optional)
  policy: { sendAllowHosts: ["api.example.com"] },   // the policy file's schema (docs/policy.md), merged over the defaults;
                                            // a whole FirewallConfig is accepted too, validated just as strictly (an unknown key anywhere throws)
  tools: {                                  // your tools, in the engine's vocabulary (below)
    search_docs: { kind: "read", results: "untrusted", privateData: false },
    get_customer: { kind: "read", results: "trusted", privateData: true },
    send_email: { kind: "send" },
    delete_account: { kind: "destroy" },
    run_shell: { as: "Bash", input: (a) => ({ command: String(a.cmd) }) },
  },
  onApproval: async (req) => ui.confirm(req.message),   // your person; return true / { approved: true, by }
});

guard.recordPrompt(userText);               // what the person typed: hosts and repos they named, the task scope
guard.reportInput({ source: "email from x@y.com", content: body });   // untrusted content outside a tool call

const call = { tool: "send_email", input: { to, body } };
const a = await guard.authorize(call);      // decide, then your approval for an ask: { allowed, decision }
if (a.allowed) guard.recordResult(call, await sendEmail(to, body));    // what the tool brought in
// a.decision: { verdict: "allow" | "ask" | "hold" | "deny", rules, reasons, message, held?, actionHash, engine }

guard.pending();                            // held actions waiting for review
guard.approve(heldId, { by: "alice" });     // a person approved one: the same call is allowed once
guard.log();  guard.verifyLog();            // the decision log, hash-chained and signed
```

| Member | Hook equivalent | Records |
|---|---|---|
| `check(call)` | none (a preview) | nothing |
| `decide(call)` | PreToolUse | the decision's state events (taint, private data, approvals used; tripwire events only when not allowed), a held item for `hold`, budget counters, a log entry |
| `authorize(call)` | PreToolUse + the person answering an `ask` | as `decide`, plus the host's answer (log entry, budget raise on yes) |
| `requestApproval(decision)` | Claude Code asking the person | puts one of this guard's asks to `onApproval`, records the answer |
| `approveAsked(decision, answer)` | the person answering Claude Code's dialog | the answer; used by integrations whose framework asked the person (only an unanswered ask this guard handed out, for the same action, counts) |
| `recordResult(call, output, { failed }?)` | PostToolUse | taint from what the tool was, taint and a warning when the output hides text (FW-HIDDEN-OUTPUT: tag characters, text in variation selectors, a dense run of zero-width characters, terminal tricks; one zero-width space is ordinary and no finding), credential fingerprints, decoy values seen; a redacted copy when `redactSecretsInOutput`; with `failed: true` (or an explicit marker in the output), one more identical failure for the spending limits |
| `reportInput(input)` | none (content outside a tool call) | taint (and private data when `private: true`), fingerprints |
| `recordPrompt(text)` | UserPromptSubmit | the destinations the person named, the task scope |
| `approve(id)` / `reject(id)` | `launchsafe-firewall queue approve/reject` | the person's decision on a held item |
| `pending()`, `state()`, `log()`, `verifyLog()` | `queue list`, `status`, `log tail`, `log verify` | nothing |

### Verdicts

The engine's `queue` is called `hold` in the library (it is what a host shows:
"held for review").

| Verdict | Meaning | What the host does |
|---|---|---|
| `allow` | proceeds | run the tool, then `recordResult` |
| `ask` | a person must say yes first (`attended: true`) | `authorize()` calls `onApproval`; integrations use the framework's approval UI |
| `hold` | needs a person who is not there now (`attended: false`), or a change to the agent's instructions or memory that is only ever a proposal | do not run; show `guard.pending()` for review; `approve(id)` lets the same call run once |
| `deny` | never allowed, not even with approval (credentials leaving, decoy values, hidden text, root deletes...) | do not run; give the message to the model |

`attended` (default `true`) is the hook's `interactive`: whether a person can
answer now. A batch or scheduled agent sets `attended: false`, and every `ask`
becomes `hold`. So does a call whose `permissionMode` is one of the policy's
`unattendedPermissionModes` (default `dontAsk`, `bypassPermissions` and `auto`), the policy's `unattended`, and
its unattended hours, as in the hook.

### Your tools in the engine's vocabulary

The engine knows the coding-agent tools (Bash, Read, Write, Edit, WebFetch,
WebSearch...) and MCP tools (`mcp__server__tool`). A host's own tools are
mapped to one of these, so no rule is written twice:

- `{ as: "Bash" | "Read" | "Write" | "Edit" | "WebFetch" | ..., input?: (args) => engineInput }`:
  the tool *is* one the engine models; `input` translates the arguments.
- `{ kind: "read" | "send" | "destroy" | "blocked", results?, privateData?, server? }`:
  the tool is judged like an MCP tool of server `server` (default: the tool's
  own name). It becomes `mcp__<server>__<tool>`, and the server gets an exact
  policy entry (`results`, default `"untrusted"`; `privateData`, default `true`,
  the engine's `mcpDefault`; the tool in `readTools` / `sendTools` /
  `destructiveTools` / `blockedTools`). Destinations, message tools, SQL
  arguments and the data rules work as for any MCP server.
- A tool without a spec is passed to the engine under its own name: coding-agent
  tool names and `mcp__` names are classified as usual (an `mcp__` tool from a
  configuration source the host does not state is `"unknown"`, i.e. untrusted,
  as in the hook), and any other name is FW-UNKNOWN-TOOL (asks, and its result
  is outside content).

### Spending limits

The policy's `caps` ([usage.md](usage.md#spending-limits)) apply to the guard
as to the hook: tool calls, data sent and identical failures, per session and
per day, warned once at 80% (`FW-CAP-WARN`, an `ask` when `attended`, else a
note) and denied at the limit (`FW-CAP`). Give a call the model usage behind it
and the token and cost limits count it too:

```ts
guard.decide({ tool: "send_email", input, usage: { inputTokens: 1200, outputTokens: 300, costUsd: 0.0045 } });
guard.recordResult(call, error, { failed: true }); // the tool failed: counts toward identicalFailures
```

The cost is your own estimate; the library calls no model and keeps no
prices. `memoryStore()` keeps the day's counters in the process (all its
sessions; a new local day starts from zero) and cannot raise a limit: set the
limits you want in the guard's `policy`. `fileStore()` shares the firewall
home's counters with the hook, survives restarts, and honours raises a person
signs with `launchsafe-firewall caps raise`. A custom `StateStore` opts in with
`capView`, `recordCaps`, `recordFailure` and `capStopped` (optional; without
`capView` caps are not checked).

### State stores

`StateStore` is the guard's memory: session events, budget counters, held
items and the decision log. Every method is synchronous (decisions are).

- `memoryStore()` (default): plain maps in the process; browser-safe. A
  person-made change (an approval) enters only through `settle()`, which
  `guard.approve()` calls; one appended any other way is treated as tampering
  (the session becomes untrusted). Several guards may share one store; each guard is one session
  (`session` option, default a random id) and sees only its own events.
- `fileStore({ home })` (`/sdk/node`): the runtime's own files under a
  firewall home (`sessions/`, `queue/`, `log/`, `ledger/`), through the same functions the
  hook uses (`loadState`, `appendEvents`, `enqueue`, `decideQueueItem`,
  the bounded `appendLog`). Held items appear in `launchsafe-firewall queue list` with
  `LAUNCHSAFE_FIREWALL_HOME=<home>`, approvals made there with the passphrase
  are honoured, and `log verify` checks the log. Approvals in the file store
  must be signed with the approver key: `guard.approve()` works when the store
  is given an `approver` (the unlocked key, or `{ passphrase }` to unlock it),
  and otherwise throws and names the CLI command. An approval event written
  into a session file without that signature is ignored and makes the session
  untrusted, as in the hook. The store never writes under
  the real home while a test marker is set (the runtime's guard).
- A log event (`appendLog`) is at most 256 KiB as JSON; a larger one throws
  and nothing is written (log a summary or a hash of large data). The guard
  bounds its own events first, as the hook does (strings to 1,024 characters
  with the SHA-256 and length of the whole in `bounded`, arrays and objects to
  64 items), and the file store appends through the same bounded path. A
  custom store that will not take an entry throws `LogRefused` (exported; any
  error named `LogRefused` counts): the guard then writes the short fallback
  entry (type, verdict, rule ids, action hash, why). A store that throws
  `LogUnrecorded`, or refuses the fallback entry too, has recorded nothing;
  see "The decision log" below for what the guard does then.
- A held approval is used once, atomically: when a decision uses one, the guard
  calls the store's `consumeApproval(session, actionHash, approvalId)`, which
  records the use only if nothing used that approval since the session was
  loaded (the file store re-reads the session file under its lock, so two
  processes, or a guard and a hook, cannot both run one approval). If it was
  used already, the guard decides again without it. A custom `StateStore`
  should implement it the same way (a transaction or a conditional write);
  without it the guard appends the decision's events as before.
- An approval made in the file store (the CLI's, signed) covers only the rules
  the person was shown: if another rule asks by the time the call is retried,
  the decision is a `hold` again (a new held item), its `message` says an
  earlier approval was not used and why, and the earlier approval stays
  unused. An approval that records no rules (the memory store's) covers as
  before.

A state store serves one process. For a chat app whose approval arrives in a
later request (AI SDK, Agents SDK interruptions, LangGraph resumes), keep the
guard's session id and give every request's guard the same store (a file
store, or your own `StateStore` over your database).

### The provenance ledger

Taint belongs to one session, but files outlive sessions: a script an
untrusted session wrote is plain workspace code to a different, trusted session
that runs it. The hook closes this with the provenance ledger (`ledger/` in the
firewall home, [design](design.md#provenance)). The library does the same when
its store has a `ledger` and the guard has file access (`nodeEnvironment()`, or
the local API with file access on, which is the default):

- **Where it exists.** `fileStore()` has one, the hook's own in the same
  firewall home, so a file written under the hook and one written under a
  guard know each other; `createNodeGuard({ persist: "file" })` and the local
  API have it through `fileStore`. `fileLedger({ home })` (`/sdk/node`) gives a
  custom store the same ledger: `{ ...myStore, ledger: fileLedger({ home }) }`.
- **Where it does not, by design.** `memoryStore()` keeps none: nothing in it
  outlives the process, so what one session wrote reaches no other session. A
  guard on it still catches a script its own session wrote after reading
  outside content (the session's own events), and nothing more. A guard with
  no file access (no `fs` option) never reads or writes the ledger either: it
  hashes real files.
- **What it records.** When `recordResult()` reports a call that ran (Write,
  Edit, MultiEdit, NotebookEdit or a shell command), each file the call left is
  hashed and remembered, with whether the session was untrusted at the time.
  Report a result only for a call that ran: a write whose result is never
  reported is not remembered, and a result reported for a call that did not run
  would record whatever is on disk as that session's (the guard and the local
  API record nothing trusted for decisions they denied or held, for this
  reason). A file larger than
  `provenance.maxHashBytes`, or one an MCP tool wrote, is not recorded.
- **What it changes.** In a later session, running such a file, or a build whose
  manifest it is, asks for a person (FW-UNTRUSTED-CODE, FW-TAINTED-MANIFEST)
  while its content is still what the untrusted session left. A later trusted
  `Write` of the whole file with new content ends that; the same bytes written
  again, or a trusted edit of part of it, does not; a change by anything else
  makes it ordinary code again. A call the guard denied (one it could not check
  included) or held, or one whose result says it failed, vouches for nothing it
  left: what it wrote is recorded only when the session was untrusted, and then
  as untrusted. A file a trusted session wrote reads back from outside the
  workspace without counting as outside content.
- **When it fails.** A ledger never stops a call. A lookup that fails is
  "unknown" (the v0.1 classification, never looser); a note or an entry that
  cannot be written is lost and told to `onLogError` (a failed note is also in
  the decision's `problems`).

### The vault

The guard reads the vault the way the hook does, for every call: the view
(names, kinds, bindings and fingerprints from the signed index, never a value)
comes from the `vault` option, else from the store (`fileStore` reads the
firewall home's index and verifies it against the approver key; the memory
store has none). With a vault, an argument that carries a vaulted value to a
destination that secret is not bound to is denied `FW-VAULT-EGRESS` on every
integration, exactly as on the hook path, and a vaulted value in a tool result
(or in `reportInput`) makes the session hold private data. The library does not
rewrite arguments, so a `vault://` reference that would need substituting is
refused as on an agent the hook cannot rewrite. `vault.enabled: false` in the
policy turns all of this off.

### The decision log

Each entry is `{ seq, ts, prev, event, hash, sig }`, chained by
`sha256(prev, seq, ts, canonical event)` exactly like the runtime log
(`src/runtime/log.ts`). The memory store signs `hash` with the `signer` it is
given (`ed25519Signer()` from `/sdk/node`, or any `{ sign(bytes): base64 }`,
e.g. WebCrypto behind a sync facade); without a signer the chain still proves
order and integrity but `sig` is empty, and `verifyLog()` says so (`signed:
false`). `createNodeGuard()` (`/sdk/node`: `createGuard` with the Node
environment filled in) signs with a new Ed25519 key per process unless given a
`signer`. The file
store signs with the runtime's local Ed25519 key. Entries: `decision`,
`approval` (asked and held; who, and whether yes), `input`, `prompt`
(hash and length only), `result`.

No decision is carried out without a log entry, as on the hook path. When the
store refuses a decision's entry and its fallback entry, an allow becomes
`ask` when a person can answer (`attended` and no unattended mode) and `deny`
otherwise, with rule `FW-LOG-UNRECORDED` first; an `ask` gets the rule too,
and a yes to it counts only if the approval's own entry is recorded
(`authorize` and `approveAsked` return `approved: false` with a note
otherwise). A read-only tool is let through an internal error only when the
failure entry was recorded, and never when the error came from the call itself
(arguments nested deeper than 256 levels, which the engine does not judge, or a
stack overflow): that is a `deny`. Log failures are never swallowed: each one is in
the decision's `problems` and is passed to the `onLogError` option (default
`console.warn`). Any other error from the store's `appendLog` (an I/O failure)
is reported the same way and the decision stands, as the hook's does on a
full disk (docs/limitations.md).

### What an ask records

As in the hook, `decide()` records an allowed or asked call's state events at
decision time (reading outside content taints the session before the tool
runs, so a parallel call cannot race past it). An ask the person then declines
has still recorded them: stricter, never looser. A held or denied call records
only its tripwire events (a touched decoy).

## Remote guard

`createRemoteGuard()` (in `@launchsafe/agent-firewall/sdk/node`) has the same
surface, but the decision is made by the local API sidecar
(`launchsafe-firewall serve --api`, [api-v0.md](api-v0.md)) instead of in your
process. Your agent then shares the coding-agent hooks' session state, approval
queue and decision log: a held action shows up in `launchsafe-firewall queue
list`, and an approval made in the terminal or on the phone (experimental, see
[phone.md](phone.md)) counts.

```ts
import { createRemoteGuard } from "@launchsafe/agent-firewall/sdk/node";

const guard = createRemoteGuard({
  // socketPath defaults to <firewall home>/api.sock (used only when it is this user's, mode 0600);
  // or baseUrl: "http://127.0.0.1:<port>" with allowTcp: true (nothing proves who answers on a port)
  token: process.env.LAUNCHSAFE_FIREWALL_TOKEN,   // launchsafe-firewall api token add <agentId>
  promptToken: process.env.LAUNCHSAFE_FIREWALL_PROMPT_TOKEN, // optional: --role prompt, for recordPrompt
  session: runId,
  timeoutMs: 250,              // per request; a timeout is never an allow
  failOpenReads: true,         // see the table below
  tools: {                     // client-side only: which tools are read-only when the sidecar cannot answer
    search_docs: { kind: "read", results: "trusted", privateData: false },
    send_email: { kind: "send" },
  },
  onPending: (d) => ui.show(`Approve ${d.approval?.id} in LaunchSafe`),
});

const a = await guard.authorize(call);     // never throws
if (a.allowed) await guard.recordResult(call, await run(call), a.retry ?? a.decision);
```

Every method returns a promise. `check`, `decide`, `authorize`, `recordResult`,
`reportInput` and `recordPrompt` never throw; `state()` and `health()` reject
with a `RemoteHttpError`. There is no `approve`, `reject`, `pending`, `log` or
`verifyLog`: an agent credential can never approve, and the queue and log
belong to the person (`launchsafe-firewall queue`, `log`).

The sidecar judges by the tool registry a person set
(`launchsafe-firewall api tools set <agentId> <file.json>`), never by the
guard's `tools`. A tool declared in `tools` is sent as `native`; an `mcp__`
tool as `mcp` (with `mcpSource`, else `"unknown"`); anything else as the
`format` option (default `native`; set `"engine"` for Claude Code tool names,
as with the Claude Agent SDK integration). A call whose `permissionMode` is in
`unattendedPermissionModes` (default `dontAsk`, `bypassPermissions` and `auto`) is sent with `attended: false`.

**Fail closed.** The contract's table is code:

| Failure | Read-only tool (`kind: "read"`, `results: "trusted"`, `privateData: false` in `tools`) | Anything else |
|---|---|---|
| unreachable, timeout, 503 (overloaded) | `allow` (`failOpenReads: false`: `deny`) | `deny`, `FW-UNAVAILABLE` |
| 500 or any other 5xx (the sidecar took the request and failed on it) | `deny` | `deny`, `FW-UNAVAILABLE` |
| 429 | as for 503; no request until `Retry-After` (at least 1 s) has passed | `deny`, `FW-RATE-LIMITED` |
| 400, 401, 403, 404, 413, any other non-2xx; an answer that is not JSON, not the contract's shape or larger than `maxResponseBytes` (2 MiB); a socket that is not this user's or not mode 0600 | `deny` | `deny`, `FW-API-ERROR` |

Such a decision has `decisionId: null` and a `failure` saying why. A request
body over 1 MiB is never sent (`FW-API-ERROR`); an input, prompt or output
over it is cut to fit and the result says so. Each POST carries a fresh
`Idempotency-Key`.

**Approvals.** A `hold` is an item in the firewall's queue; an `ask` is not
(the contract leaves it to the host's person). For an ask, `authorize()` puts
it in the queue by deciding the identical call again with `attended: false`
(a hold of the same action, told to `onPending` with its approval id), waits
(polling `GET /v1/approvals/{id}`, up to `approvalTimeoutMs`, default 5
minutes) for a person to approve it there, then decides the identical call
again, which the sidecar allows once; the retry is `a.retry`. A hold is not waited on: tell the model it is held, and the same
call is allowed once after approval. `waitForApproval(idOrDecision)` waits on
any item. In the integrations, the framework's own approval UI answering no is
a no; answering yes is necessary but not sufficient, because only the queue's
approval lets the call run (`approveAsked` and `requestApproval` then wait for
it as `authorize` does).

**Reports.** `reportInput` and `recordPrompt` that cannot be sent are kept (up
to 100, with their idempotency keys) and sent before the next decision; until
they are, decisions fail closed (as unreachable), so the sidecar's session is
never looser than what the agent saw. A report the sidecar refuses (4xx) makes
the guard fail closed for good. `recordResult` sends the id of the decision the
call ran under (passed in, or remembered by call id, else by tool and input);
with none (decided while the sidecar was down), the output is reported as
untrusted input instead. The v0 contract returns no secret count, so
`secretsSeen` is always 0; `becameUntrusted` comes from the session read after
recording.

The four integrations take either guard (`GuardPort`): `vercelFirewall`,
`firewallTool`, `claudeAgentFirewall` and `firewallToolNode` await every call.

## What the library does not do (and the hook does)

These read the coding agent's own files and have no meaning for an embedded
agent; they are not run by the library (the engine's rules that depend on them
see "nothing known", the same as a fresh hook session):

- the agent-configuration scan at session start (CLAUDE.md, MCP lists...), MCP
  pins and tool-description pinning (an embedded agent declares its tools in
  code);
- decoy files, unless the host uses `fileStore`, whose decoy registry the Node
  environment loads;
- the provenance ledger (files the agent wrote itself) unless the store has
  one: `fileStore` does, `memoryStore` does not, and a guard with no file
  access never uses one (see "The provenance ledger");
- desktop notifications (the `onHold` callback is the host's equivalent);
- subagent linkage (create one guard per agent; share a store and pass taint
  with `reportInput` when one agent's output becomes another's input);
- the email guard: the library has none (mail an embedded agent reads is not
  scanned as messages).

## Integrations

Each lives in `src/sdk/integrations/` and is exported as a subpath. Every one
blocks a held or denied call before the tool's code runs, passes an allowed
call through untouched, and records what an executed tool returned.

| Framework (version tested) | Interception point | allow | ask | hold / deny |
|---|---|---|---|---|
| Vercel AI SDK `ai` 7.0 | `toolApproval` (generateText/streamText/ToolLoopAgent), `vercelFirewall(guard).tools(...)` around each tool's `execute` (decisions kept for it and approvals marked used are bounded: 10,000 and 100,000, the oldest go first) | `not-applicable` | `user-approval` with the reason; on the next call the AI SDK re-validates approved calls through the same function, which records the person's yes (`tool-approval-response` in the messages) | `denied` with the reason; `execute` refuses as a second line |
| OpenAI Agents SDK `@openai/agents-core` 0.20 | `firewallTool(guard, options)`: `needsApproval`, a tool input guardrail and a tool output guardrail on each function tool | guardrail `allow` | `needsApproval` is true and the ask is recorded, the run stops with an interruption, the host calls `state.approve()`; the input guardrail lets it run only for the call that was shown (the firewall's own single-use record: same call id, tool and arguments) and records the yes | guardrail `rejectContent` with the reason (never an interruption: nothing to approve) |
| Claude Agent SDK `@anthropic-ai/claude-agent-sdk` 0.3 | `hooks` (PreToolUse, PostToolUse, PostToolUseFailure, UserPromptSubmit) and `canUseTool` | no output (Claude Code's own permission rules still apply) | PreToolUse answers `ask`, Claude Code calls `canUseTool`, which calls the host's approval and records it | PreToolUse answers `deny` with the reason |
| LangGraph JS `@langchain/langgraph` 1.4 | `firewallToolNode(guard, tools)`: a drop-in for `ToolNode` | runs the tool | `interrupt()` with the request; the host resumes with `Command({ resume: { approved: true, by } })`; each answer binds to the call it was shown for | a `ToolMessage` with the reason (status `error`); the tool is not called |

The engine understands Claude Code's tool names natively, so the Claude Agent
SDK integration needs no tool mapping; the others use the guard's `tools`.

Tests use each framework's real package and types (dev dependencies) and drive
a real run where the framework has a test model (AI SDK `MockLanguageModelV4`,
Agents SDK `ScriptedModel`, LangGraph without a model); the Claude Agent SDK
needs the Claude Code process and a model, so its callbacks are called with
inputs typed by the SDK's own `PreToolUseHookInput` / `CanUseTool` types.

### Framework details that matter

- **Vercel AI SDK.** The approval answer is read the way the AI SDK reads it:
  the `tool-approval-response` in the last `tool` message whose request (in an
  assistant message) names this tool call. The yes binds to the exact call the
  firewall judged: when the history comes back with that tool call's input
  changed, the changed call is decided afresh and never inherits the approval
  (an ask is refused, a deny stays a deny), and `execute` refuses an input whose
  action hash differs from the decided one. An approval is single use: once a
  yes for a tool call has been granted, the same response resent later (before
  or after the call ran) is decided as never asked, so an ask is refused. Setting
  `experimental_toolApprovalSecret` makes the AI SDK bind each approval to its
  call with an HMAC as well; recommended (it also covers an approval sent to a
  fresh instance that never saw the request).
- **OpenAI Agents SDK.** Input guardrails normally run after the approval. With
  `toolExecution.preApprovalInputGuardrails` they also run before the
  interruption; the guardrail then lets the approval request through, and
  checks the answer when the person has given it.
  The SDK's own approval state is not the firewall's approval:
  `state.approve(item, { alwaysApprove: true })` stores a yes for every later
  call of that tool, whatever its arguments. The firewall therefore records, in
  `needsApproval`, each ask it is about to show the person (the decision is
  logged and the budget counters move then, as the hook logs an ask when it is
  raised, so a refusal, which never reaches the guardrail, is still recorded),
  and the input guardrail lets an ask run only for that record: the same call
  id, tool and arguments, once. A later call the SDK considers approved but the
  person was never shown is refused with the reason. The record lives in the
  `firewallTool` instance, so an interruption must be resumed in the process
  that raised it (a resume elsewhere is refused: safe, never looser).
  With `redactSecretsInOutput`, the output guardrail replaces a result that
  carried credentials with the masked copy (`rejectContent`), so the model
  sees what the hook would show Claude Code.
  `firewallTool` covers function tools only;
  hosted tools, MCP-server tools and shell/apply_patch tools registered with the OpenAI Agents SDK are not wrapped (the firewall does not see them).
  A function tool that throws is recorded as a failed result (it counts toward
  the identical-failures limit) and the error is rethrown.
- **Claude Agent SDK.** `canUseTool` is only called for calls Claude Code asks
  about; the hooks are what see every call, so both are required. An approval
  binds to the exact tool input the PreToolUse hook judged. The hook input's
  `permission_mode` is passed to the guard (`ToolCall.permissionMode`): a mode
  in the policy's `unattendedPermissionModes` (default `dontAsk`, `bypassPermissions` and `auto`) means no one
  can answer, so an ask becomes a held action and PreToolUse answers `deny`, as
  on the hook path. If the guard throws while deciding, PreToolUse answers
  `deny` with the reason rather than rejecting (Claude Code treats a hook error
  as non-blocking).
- **LangGraph.** A node runs again from the start when the graph resumes, so the
  node previews (records nothing), interrupts once per ask in call order, and
  decides and records only when every answer is in. LangGraph hands resume
  values back by interrupt index, not by call, so the node remembers, per
  paused node run (thread and checkpoint namespace), which call each index was
  raised for (call id, tool name and action hash; the interrupt value carries
  `actionHash`). An answer counts only for that call: when the set of asks
  changed while the graph was paused (the session read outside content, so a
  call that was allowed now asks), the answer is not moved to another call and
  that call is asked again; an answer this process never saw raised (a resume
  in another process) is not applied either, and the call is asked again. A
  turn whose tool calls share an id is refused whole: every call gets an error
  `ToolMessage` and nothing runs. A tool that returns a `Command` works as in
  `ToolNode` (the node returns ToolNode's list of updates and Commands), and
  the `ToolMessage`s the Command carries are recorded (taint, credentials). With
  `redactSecretsInOutput`, a recorded `ToolMessage`'s content is replaced by the
  masked copy before the model sees it.

## Verification

| Claim | Test |
|---|---|
| Same verdicts and rule ids as the hook path: friction corpus (690 cases: 172 normal tasks trusted and untrusted, 346 package installs) and every step of the 18 incident scenarios, with the memory store and the file store; 14 cases fixed after the pre-release review, trusted and untrusted | `test/sdk/parity.test.ts` |
| Never approves on its own (no callback, a throw, a timeout, any answer but an explicit yes; deny and hold never reach the callback; a forged or replayed answer; an approval slipped into the store) | `test/sdk/guard.test.ts` |
| State isolation between guards (one store, several sessions; separate stores) | `test/sdk/guard.test.ts` |
| No network (fetch and sockets throw for the whole file) | `test/sdk/guard.test.ts`, every integration test |
| Browser-safe core (import graph; type-checks with the DOM library and no Node types) | `test/sdk/browser-safe.test.ts` |
| Engine bytes equal to `node:crypto` / `Buffer` | `test/sdk/bytes.test.ts` |
| File store: CLI queue, signed approvals, runtime log, real-home guard | `test/sdk/file-store.test.ts` |
| The provenance ledger across sessions: a script an untrusted session wrote is asked about in a different, trusted session, one a trusted session wrote is not, a later trusted write clears it, a result vouches for nothing when its call failed or was denied (one the guard could not check, or whose arguments are nested too deep to judge, included) or held (in the library an untrusted session's is still recorded, as untrusted; the local API records nothing for a denied or held decision), the hook and the library share it, the memory store and a guard with no file access carry nothing, and a failing ledger never stops a call; the same through the local API | `test/sdk/ledger.test.ts`, `test/api/ledger.test.ts` |
| Each integration blocks a held and a denied call, passes an allowed one, runs an ask only after the person's yes | `test/sdk/{vercel-ai,openai-agents,claude-agent-sdk,langgraph}.test.ts` |
| Examples type-check against the built package and run offline | `test/sdk/examples.test.ts` |
| Remote guard: every method, every fail-closed row, idempotency keys, approval waits, resent reports, over a unix socket and 127.0.0.1; the Vercel AI SDK integration end to end | `test/sdk/remote.test.ts`, `test/sdk/remote-integration.test.ts` |
| Remote guard and the Python SDK against the real sidecar (engine, queue, signed log): allow, ask, hold approved in the queue, deny, every format, taint from reports, revoked tokens, agent isolation, fail-closed after the server stops; one Vercel AI SDK run | `test/api/e2e-remote-guard.test.ts`, `test/api/e2e-python.test.ts` |
| Enforcement parity of the OpenAI Agents, Claude Agent SDK and LangGraph adapters with the hook path through each framework's real entry point: verdicts and rule ids, single-use approvals bound to the call shown (no blanket `alwaysApprove`, resume answers bound by call), refused asks logged, `dontAsk` holds, a throwing guard denies, redacted output, `Command` results, duplicate ids, the vault | `test/review-fixes/sdk-adapters.test.ts` |

## Files

| File | Job |
|---|---|
| `src/sdk/index.ts` | the public, browser-safe surface |
| `src/sdk/guard.ts` | `createGuard`: the pipeline (decide, record, approve) |
| `src/sdk/tools.ts` | tool specs to engine actions and server policies |
| `src/sdk/store.ts` | `StateStore`, `memoryStore()` |
| `src/sdk/log.ts` | the chained log and its verification |
| `src/sdk/types.ts` | public types |
| `src/sdk/node.ts` | `fileStore`, `fileLedger`, `ed25519Signer`, `nodeEnvironment`, `createNodeGuard`, and the remote guard's exports |
| `src/sdk/port.ts` | `GuardPort`: what integrations need from a guard (in-process or remote) |
| `src/sdk/remote.ts`, `remote-http.ts`, `remote-types.ts` | `createRemoteGuard`: the sidecar client, its transport and types |
| `src/sdk/integrations/*.ts` | one per framework |
| `src/engine/bytes.ts` | SHA-256 and byte decoding without Node (used by the engine) |
| `src/engine/counters.ts` | budget counters, pure (moved from `src/runtime/counters.ts`, which re-exports them) |
| `examples/sdk/*` | one runnable example per integration and one plain loop |
