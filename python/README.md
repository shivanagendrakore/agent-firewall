# launchsafe-firewall

The Python SDK for the [LaunchSafe Agent Firewall](https://github.com/shivanagendrakore/agent-firewall/blob/main/README.md)'s local API sidecar
(`launchsafe-firewall serve --api`). Before a tool call that goes through the SDK (an integration
below, or your own `guard.authorize()`), the agent asks the firewall, which answers `allow`, `ask`,
`hold` or `deny`. The firewall tracks the session's state (taint, private data, secrets seen) from the
results and inputs the SDK reports back, so it is only as complete as those reports. A call that does
not pass through the SDK (a tool the integration cannot see, code that skips the guard) is not checked:
the SDK is a gate in your agent's own process, not a sandbox.

The SDK lives in the `python/` folder of the Agent Firewall repository, beside the firewall and the
sidecar it talks to. The firewall itself is installed as the root README describes; how to run the
sidecar is in [docs/api.md](https://github.com/shivanagendrakore/agent-firewall/blob/main/docs/api.md), and the wire contract is
[docs/api-v0.md](https://github.com/shivanagendrakore/agent-firewall/blob/main/docs/api-v0.md).

> **Status: pre-release.** Not yet published to PyPI: the `pip install launchsafe-firewall` commands
> below work after release. Until then, install from a checkout of the repository
> (`pip install ./python`).

- One runtime dependency: `httpx`. Python 3.10 or later, tested on 3.10 and 3.13 in CI (3.14 by hand) (the `pydantic-ai` extra needs 3.11 or later), on macOS and Linux only (Windows is not supported).
- Talks only to the sidecar you point it at: the unix socket `<firewall home>/api.sock` by default,
  or a loopback `base_url`. No telemetry.
- Fails closed: `guard.authorize()` never raises. Every failure becomes a decision (table below).
  What does raise is outside that promise: the format helpers `from_openai_tool_call`,
  `from_anthropic_tool_use` and `from_mcp_call` raise `ValueError` (or `TypeError` for something that
  is not a mapping) for a malformed block before `authorize()` is reached
  (catch it and treat the call as not allowed); `guard.state()` raises a `FirewallError` (it is a
  query, not a decision); and `guard.record_result()` raises `ValueError` when given the result of
  `check()` (a dry run, never recorded).

## Install

This installs only the SDK. The firewall and its `launchsafe-firewall` command (the sidecar the SDK talks to) come from npm, as the [root README](https://github.com/shivanagendrakore/agent-firewall/blob/main/README.md) describes. Python 3.10 or later on macOS or Linux; the `pydantic-ai` extra needs Python 3.11 or later.

```sh
pip install launchsafe-firewall                    # core
pip install 'launchsafe-firewall[openai-agents]'   # + OpenAI Agents SDK integration
pip install 'launchsafe-firewall[langgraph]'       # + LangGraph integration
pip install 'launchsafe-firewall[claude-agent-sdk]'  # + Claude Agent SDK integration
pip install 'launchsafe-firewall[pydantic-ai]'     # + Pydantic AI integration
pip install 'launchsafe-firewall[google-adk]'      # + Google ADK integration
pip install 'launchsafe-firewall[crewai]'          # + CrewAI integration
```

CrewAI's releases declare Python 3.10 to 3.13, so pip does not install the `crewai` extra on 3.14.

A person sets the sidecar up (these are person-run commands; from an agent's tool call they are
blocked as FW-TAMPER):

```sh
launchsafe-firewall serve --api                        # listens on ~/.launchsafe-firewall/api.sock
launchsafe-firewall api token add my-agent             # prints the agent's token once
launchsafe-firewall api tools set my-agent tools.json  # the agent's tool specs
```

The `tools.json` the examples use is [examples/tools.json](https://github.com/shivanagendrakore/agent-firewall/blob/main/python/examples/tools.json) (`lookup_order` and `send_email`, as each example defines in its `TOOLS`; the Claude Agent SDK example uses the built-in tools and needs none).

### Tokens and roles

`api token add` makes a token with the `decide` and `report` roles, which is what `authorize`, `record_result` and `report_input` need. `guard.record_prompt()` takes effect only with a token made with `--role prompt`, held by the code that reads what the person typed, not by the agent's tool loop. With a token that has the `report` role but not `prompt`, the sidecar logs a hash of the prompt and answers `applied: false` (the returned outcome has `recorded=True, applied=False` and the sidecar's `detail`); the prompt is not applied (a token without the `report` role gets a 403, and the outcome is `recorded=False, applied=False` with the error). The guard uses one token, so to send real prompts give that code its own `Guard` with the prompt token. See the roles table in [docs/api.md](https://github.com/shivanagendrakore/agent-firewall/blob/main/docs/api.md).

## Quickstart

```python
import json
from launchsafe_firewall import Guard

specs = json.load(open("tools.json"))["tools"]  # the same file the person registered
with Guard(session="run-42", tools=specs) as guard:  # token from LAUNCHSAFE_FIREWALL_TOKEN
    auth = guard.authorize("send_email", {"to": "ana@example.com", "body": "hi"}, call_id="call_1")
    if auth.allowed:
        output = send_email(to="ana@example.com", body="hi")
        note = guard.record_result(auth, output)
        output = note.output or output  # the redacted copy, when the sidecar sent one
    else:
        output = auth.message  # give the model the reason instead
```

A tool the firewall's policy asks about (a send tool usually is) comes back with `allowed=False` and verdict `ask`: it was not done. With `wait_for_approval=True` (and `approval_timeout=`) the guard queues it for a person and waits; with `attended=False` the sidecar answers a hold instead of an ask. In both cases the call runs only once a person approves it in the firewall.

`AsyncGuard` is the same API with `await`. `Guard(Client(base_url="http://127.0.0.1:8787"))`
uses a TCP listener instead of the socket; `Client(socket_path=...)` another socket.

Also on the guard:

- `guard.report_input(source, content, private=None)`: untrusted content that reached the agent
  outside a tool call (a retrieved document, an email in the prompt).
- `guard.record_prompt(text)`: what the person typed (never model or tool text).
- `guard.check(tool, input)`: what `authorize` would say now; records nothing.
- `guard.state()`: the session snapshot.
- Spending limits (the firewall's policy `caps`): pass
  `usage=ModelUsage(input_tokens=..., output_tokens=..., cost_usd=...)` to `authorize` so the
  token and cost limits count the model usage behind a call (the cost is your own estimate), and
  `guard.record_result(auth, output, failed=True)` when the tool failed, so the same failure again
  and again stops at the identical-failures limit. At a limit the decision is `deny` with rule
  `FW-CAP`.
- `approval_timeout=` (on the guard or per call): seconds to wait for a person to answer a `hold` in
  the firewall's queue (terminal, phone). When they approve, the guard sends the identical call
  again and it is allowed once. The default, 0, does not wait: the call is not allowed and
  `auth.approval` names the queue item.
- `wait_for_approval=True` (opt-in, `Guard` and `AsyncGuard`): also wait for an `ask`. The sidecar
  queues only holds, so an ask has no approval id; the guard sends the identical call again with
  `context.attended = false`, the sidecar answers `hold` for the same action with an approval id,
  and the guard polls that queue item (with backoff, `approval_timeout` seconds, 300 when unset;
  `approval_timeout=0` on a call means do not wait). When a person approves it, the identical call is
  decided once more (new `Idempotency-Key`) and is allowed once. A no, an expiry, a timeout, a retry
  that is not an allow for the same action, or a hold that comes back with no approval id is not
  allowed (the last is `FW-API-ERROR`), with the reason in `auth.message`. A framework's own
  approval prompt is necessary but not enough: only the queue's approval lets the call run. Like
  the TypeScript guard, a plain `hold` is waited on only through `approval_timeout`.
- `max_wait=` (per call): a cap on any wait for a person in that call, for hosts that give up on a
  callback after a set time; the Claude Agent SDK integration uses it.
- `traffic="network"` (on the guard): sends `context.traffic` for a network middleware's requests
  (its token must be made with `--traffic network`); left out, the sidecar counts them as tool calls.
- Threads: a blocking `Guard` used from an async framework decides in `asyncio.to_thread`, so each
  call waiting for a person holds one thread of the event loop's default executor (by default
  `min(32, cpus + 4)`) for up to `approval_timeout`. With many parallel waits, use an `AsyncGuard`,
  or give the loop a bigger executor (`loop.set_default_executor(ThreadPoolExecutor(n))`).

### Tool calls in other formats

```python
from launchsafe_firewall import from_openai_tool_call, from_anthropic_tool_use, from_mcp_call, engine

guard.authorize(from_openai_tool_call(message.tool_calls[0]))  # OpenAI chat completions
guard.authorize(from_anthropic_tool_use(block))  # Anthropic tool_use block
guard.authorize(from_mcp_call("gmail", params, source="user"))  # MCP tools/call params
guard.authorize(engine("WebFetch", {"url": "https://example.com"}))  # the engine's own vocabulary
```

The native block is sent as it is, so the sidecar maps it and an approval binds to that call.

## Fail-closed

`authorize()` turns every failure into a decision; nothing is raised for the integrator to forget.

| Failure | Read-only tool | Anything else |
|---|---|---|
| unreachable, no socket, timeout (250 ms), connection dropped, 503 | `allow` (`fail_open_reads=False`: `deny`) | `deny`, rule `FW-UNAVAILABLE` |
| any other 5xx (500, 502, 504, ...: the sidecar took the request and failed on it) | `deny`, `FW-UNAVAILABLE` | `deny`, rule `FW-UNAVAILABLE` |
| 429 | as the first row; then no call to the sidecar for `Retry-After` seconds (default 1, at most 60) | `deny`, `FW-RATE-LIMITED` |
| 400, 401, 403, 404, 413, any other 4xx | `deny`, `FW-API-ERROR` | `deny`, `FW-API-ERROR` |
| malformed answer (not JSON, missing field, unknown verdict) | `deny`, `FW-API-ERROR` | `deny`, `FW-API-ERROR` |
| an earlier report was refused | asks the sidecar as usual | `deny`, `FW-API-ERROR` ("start a new session") |

The 250 ms decide timeout is short on purpose. To raise it: `Guard(Client(decide_timeout=1.0))`. A timeout is a deny for every tool except a read-only one.

When a read-only call fails open, the decision comes from the local `tools` copy, so keep it identical to the file the person registered with the sidecar. A call that fails open is not recorded by the firewall: the sidecar never saw it.

A **read-only tool** is the contract's: in `tools`, `kind: "read"`, `results: "trusted"` and
`privateData: false` (it defaults to true, so it must be explicit). Engine-format and MCP calls are
never read-only to the SDK, because it cannot see how the sidecar classifies them. Without `tools`,
nothing fails open.

**Reports do not raise either** (except `record_result` given a `check()` result, above). A result or
input that cannot be delivered because the sidecar is away is kept in memory (up to 1,000 reports, each cut to at most 512 KiB, so up to about 500 MiB in the worst case) and sent, in order,
before the next decision; if that send still fails, the decision fails closed. One the sidecar refuses
(a 4xx) cannot be sent again, so the guard denies every later non-read call: the session's state may
be incomplete. A read-only call still asks the sidecar, also when it was the one whose flush hit the
refusal. Content over 512 KiB, measured as the UTF-8 JSON bytes that are sent (a multibyte or escaped
character counts for its bytes), is cut, with a marker, so it fits the sidecar's 1 MiB limit (its
source still taints the session); a report the sidecar still refuses as too large (413) is sent once
more cut to 64 KiB before it counts as refused.

The client checks the socket before it sends the token: a socket owned by another user, or open to
other users (the sidecar makes it 0600), is refused (`FirewallUntrustedSocket`, a deny for every
tool, reads included). Error messages that reach the model never name the socket's path. Every
call has a total deadline equal to its timeout (250 ms for decide), not only httpx's per-phase ones:
a sidecar that trickles its answer is given up on, and an answer that completes late is not used.

## Integrations

### OpenAI Agents SDK

```python
from agents import Agent, Runner
from launchsafe_firewall import AsyncGuard
from launchsafe_firewall.integrations.openai_agents import firewall_tools

async with AsyncGuard(tools=specs) as guard:
    agent = Agent(name="support", tools=firewall_tools(guard, [lookup_order, send_email]))
    await Runner.run(agent, "...")
```

Each `FunctionTool` gets a tool input guardrail (authorize; a call not allowed is rejected with the
firewall's message, the tool never runs) and a tool output guardrail (record the result; the model
gets the redacted copy). Hosted tools (web search, file search, code interpreter) run at OpenAI and
cannot be gated: `firewall_tools` refuses them rather than passing them through. A blocking `Guard`
works too.

For an agent with handoffs or agents used as tools, `firewall_agent(guard, agent)` gates the whole
graph: the agent's tools, its handoff agents (an `Agent`, or a `Handoff` made by `handoff()`), the
agent behind each `as_tool()` tool, and theirs in turn. It changes those agents in place (a handoff
and an `as_tool()` tool keep their own agent object, so a copy would leave the one that runs
ungated), and checks the whole graph before changing anything. Its limits:

- An agent with `mcp_servers` is refused (`TypeError`): the SDK lists MCP tools at run time, outside
  the guardrails. `allow_mcp_servers=True` accepts it, and those tools then run unchecked.
- Refused too: hosted tools anywhere in the graph, a custom `Handoff` whose agent the SDK does not
  expose, and an `as_tool()` tool whose agent is not exposed.
- Tools added to an agent afterwards are not gated; call `firewall_agent` again.
- A tool that raised is recorded with `failed=True` (the gated copy's failure formatter notes it, then
  formats the error as the tool's own default or custom one does). A tool with
  `failure_error_function=None` ends the run with nothing recorded.

### LangGraph

```python
from launchsafe_firewall import Guard
from launchsafe_firewall.integrations.langgraph import firewall_tool_node

graph.add_node("tools", firewall_tool_node(guard, [lookup_order, send_email]))  # instead of ToolNode
```

Built on `ToolNode`'s `wrap_tool_call` / `awrap_tool_call`. A call not allowed gets an error
`ToolMessage` with the firewall's message; an allowed call's result is recorded. Both `invoke` and
`ainvoke` are gated with either guard (an `AsyncGuard` refuses a blocking `invoke`). Approvals are
given in the firewall, not with `interrupt()`: an agent credential can never approve. A tool that
raises, or returns a `ToolMessage` with status "error", is recorded with `failed=True`. A tool that
returns a `Command`: when it carries only this call's `ToolMessage`, the redacted copy replaces that
message's content; anything more (other messages, state keys, a goto) is recorded as a structured
record, and if the sidecar masks something in it the Command is not delivered (the model gets an
error `ToolMessage`), because it cannot be masked in place.

### Claude Agent SDK

```python
from claude_agent_sdk import ClaudeAgentOptions, query
from launchsafe_firewall import AsyncGuard
from launchsafe_firewall.integrations.claude_agent_sdk import claude_agent_firewall

async with AsyncGuard(tools=specs) as guard:
    fw = claude_agent_firewall(guard)  # fallback=your_can_use_tool for prompts the firewall did not raise
    options = ClaudeAgentOptions(hooks=fw.hooks, can_use_tool=fw.can_use_tool)
    async for message in query(prompt="...", options=options):
        ...
```

A `PreToolUse` hook authorizes every tool call (built-in, MCP, sub-agent); a call not allowed is denied
with the firewall's message, so the tool never runs. Hooks also fire under `bypassPermissions`. A
`PostToolUse` hook records the result (and returns a redacted copy), `UserPromptSubmit` records the
person's prompt. `can_use_tool` never approves on its own: it hands the prompt to your `fallback`, or
refuses. Calls reach the sidecar in the engine's tool vocabulary (`Bash`, `WebFetch`, ...), MCP tools as
MCP calls. A `PostToolUseFailure` hook records a tool that failed with `failed=True`.

Every hook's `HookMatcher` carries `timeout` (`hook_timeout=`, default 600 s). Without it Claude Code
gives a hook 60 s, and a hook it times out is non-blocking: the tool would run undecided. A wait for
a person in the firewall's queue is cut to `hook_timeout - 30` s; an approval still pending then is
denied with "still pending ... retry", and the model can try the call again once a person answers.

### Pydantic AI

```python
from pydantic_ai import Agent
from launchsafe_firewall.integrations.pydantic_ai import LaunchSafeFirewall

# List the firewall first among your capabilities.
# The model string is a placeholder: "anthropic:" models need `pip install "pydantic-ai-slim[anthropic]"`.
agent = Agent("anthropic:claude-sonnet-5-5", tools=[lookup_order, send_email], capabilities=[LaunchSafeFirewall(guard)])
```

A capability whose `wrap_tool_execute` authorizes each call before the tool function (function tools,
toolsets and MCP alike): a call not allowed returns the firewall's message to the model as the tool's
result, and an allowed call's result is recorded (the model gets the redacted copy). Deferred
(`external`) tools and provider-side native tools (web search, code execution) cannot be gated, so the
capability raises `UserError` rather than let them through. Pydantic AI's own approval flow is left as
you set it; firewall approvals happen in the firewall. A tool that raises is recorded with
`failed=True`.

**Not gated: output tools and output functions.** Output tools are the framework's own and fire no
tool hooks. An output function (a function given as `output_type`, or inside `ToolOutput` and the
other output markers) runs with the model's arguments in output processing, outside every tool hook,
so the firewall never sees it. `check_output_functions(agent)` refuses an agent that has one
(`allow=True` only warns); prefer output types, or make the function a tool.

### Google ADK

```python
from google.adk.apps import App
from launchsafe_firewall import AsyncGuard
from launchsafe_firewall.integrations.google_adk import FirewallPlugin

async with AsyncGuard(tools=specs) as guard:
    app = App(name="support", root_agent=agent, plugins=[FirewallPlugin(guard)])
```

A plugin's `before_tool_callback` / `after_tool_callback` run for every agent under the runner
(sub-agents and `AgentTool` runs included). A call not allowed is answered with
`{"error": <the firewall's message>}`, so the model reads why and the tool never runs; an allowed call's
result is recorded, and the model gets the redacted copy; a tool that raises is recorded with
`failed=True` (`on_tool_error_callback`). For one agent without a runner, use
`firewall_callbacks(guard)` and pass `.before_agent`, `.before`, `.after` and `.on_error` as the
agent's `before_agent_callback`, `before_tool_callback`, `after_tool_callback` and
`on_tool_error_callback`. Tools that run at the model provider (`google_search`, grounding) and every
`code_executor` (built-in or local: ADK runs the model's code without a tool callback) never reach
tool callbacks: the plugin, and the callbacks' `before_agent`, refuse to start a run that has one,
looking into sub-agents and the agents behind `AgentTool`s too (`unsupported_tools(agent)` lists
them); the tool callback refuses each call of such an agent as well. `allow_code_executor=True` (on
the plugin or the callbacks) accepts an executor you trust to be contained. A blocking `Guard` works
too.

### CrewAI

```python
from launchsafe_firewall import Guard
from launchsafe_firewall.integrations.crewai import install_firewall

with Guard(tools=specs) as guard:
    uninstall = install_firewall(guard)  # after any hooks of your own
    crew.kickoff()
    uninstall()
```

Registers CrewAI's global `before_tool_call` / `after_tool_call` hooks. A call not allowed is aborted
(`HookAborted`), and the model is given the firewall's message instead of CrewAI's generic "blocked by
hook" text. CrewAI swallows any other exception a hook raises and runs the tool; these hooks turn every
error into an abort so a failing hook never lets a call through. Hooks are synchronous (also under
`kickoff_async`), so a blocking `Guard` is required. Register tools in the sidecar under the names
CrewAI gives the model (lowercase, underscores). Each call is decided and recorded on its own (two
parallel calls of one tool never share a decision) and carries a `callId` (`crewai-<hex>`), as
CrewAI's hooks give none. A tool that raised, or returned a `ToolFailure`, is recorded with
`failed=True`.

Runnable examples with stub tools: [examples/](https://github.com/shivanagendrakore/agent-firewall/tree/main/python/examples/).

## The raw client

`Client` / `AsyncClient` implement every v0 call (`health`, `decide`, `record_result`,
`report_input`, `record_prompt`, `get_session`, `get_approval`, `wait_for_approval`) and raise
`FirewallError` subclasses: `FirewallUnavailable` / `FirewallTimeout`, `FirewallServerError` (5xx),
`FirewallRateLimited` (429, `retry_after`), `FirewallAPIError` (other 4xx, with the RFC 9457
`problem`), `FirewallProtocolError`. Every `decide` carries an `Idempotency-Key` (a fresh one unless
you pass `idempotency_key=`). `base_url` must be a loopback `http://` origin; the token must be
printable ASCII. Environment proxies are never used.

| Setting | Default |
|---|---|
| socket | `$LAUNCHSAFE_FIREWALL_HOME/api.sock`, else `~/.launchsafe-firewall/api.sock` |
| token | `token=`, else `$LAUNCHSAFE_FIREWALL_TOKEN` |
| decide timeout | 250 ms (each phase, and the whole call) |
| other calls | 2 s (likewise) |

The token has surrounding whitespace (a trailing newline from a file) stripped.

Where the contract left a choice open, [CONTRACT-NOTES.md](https://github.com/shivanagendrakore/agent-firewall/blob/main/python/CONTRACT-NOTES.md) says what this SDK
does.

## Development

Run these from the `python/` folder of the repository. Google ADK and CrewAI do not install together,
so the tests use two environments (both are git-ignored):

```sh
cd python

# 1. everything except CrewAI: ADK, Claude Agent SDK, Pydantic AI, OpenAI Agents SDK, LangGraph
python3 -m venv .venv
.venv/bin/pip install -e '.[dev,openai-agents,langgraph,claude-agent-sdk,pydantic-ai,google-adk]'
.venv/bin/pytest                    # the CrewAI test module is skipped here
.venv/bin/mypy --exclude crewai     # strict; the CrewAI files need their own environment
.venv/bin/ruff check . && .venv/bin/ruff format --check .

# 2. CrewAI (on Python 3.14, uv installs it; pip refuses, see Install)
python3 -m venv .venv-crewai
uv pip install --python .venv-crewai/bin/python -e '.[dev,crewai]'
.venv-crewai/bin/pytest tests/test_crewai.py
.venv-crewai/bin/mypy src/launchsafe_firewall/integrations/crewai.py tests/test_crewai.py examples/crewai_example.py
```

On Python 3.10 to 3.13, `.venv-crewai/bin/pip install -e '.[dev,crewai]'` works in place of `uv`.

The tests run a fake sidecar in-process on a real unix socket and on 127.0.0.1; they make no other
network calls and run no commands.

`tests/test_conformance.py` is the exception: it runs every [conformance vector](https://github.com/shivanagendrakore/agent-firewall/blob/main/conformance/README.md)
through `Client` against the real sidecar, which a small Node driver (`tests/conformance_sidecar.mjs`) starts
per vector. It needs Node 22+ and the compiled firewall (`npm ci && npx tsc -p tsconfig.conformance.json` at
the repository root) and skips, saying why, without them.

Licence: Apache-2.0.
