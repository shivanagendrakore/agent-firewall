<div align="center">

# LaunchSafe Agent Firewall

**The firewall for AI agents.** Each tool call a running hook reports is checked before it runs, outside the model.

[![CI](https://github.com/shivanagendrakore/agent-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/shivanagendrakore/agent-firewall/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/@launchsafe/agent-firewall.svg)](https://www.npmjs.com/package/@launchsafe/agent-firewall)

</div>

An agent that can read your private data, reads content someone else wrote (a
web page, an issue, an email, an MCP tool result) and can send data out can be
told by that content to leak the data. A model-based filter can be talked
around. This firewall does not use a model to detect malicious text. It runs in
the agent's hooks, tracks what the session has read and what each action would
do, and applies fixed rules outside the model. (The email guard and the MCP
gateway also scan text with fixed patterns, as detectors on top of the rules,
not as the boundary.) Zero runtime dependencies, Node 22+,
macOS and Linux (Windows is not supported, and the firewall refuses to run
there), no telemetry.

## Works with

- **Coding agents**, through their hooks: Claude Code, Codex, Gemini CLI, Cursor (Cursor's hook formats were read from its source and documentation, not captured live).
- **Agents you build** with the OpenAI Agents SDK, Claude Agent SDK, LangGraph or the Vercel AI SDK, through the [library](docs/library.md); in any other language, through the [local API](docs/api.md), with a [Python SDK](python/README.md). Runnable examples: [examples/sdk/](examples/sdk/).
- **MCP servers an app starts or connects to from this machine**, through the [MCP gateway](docs/gateway.md), when the gateway can rewrite the app's MCP configuration. Not `.mcpb` extensions, Claude Desktop's remote custom connectors, connectors called from a vendor's cloud, or a server added to the app directly, which bypasses the gateway ([the limits](docs/limitations.md#the-mcp-gateway)).
- **Agents that read email through a mail MCP server**, through the [email guard](docs/email-guard.md). A server counts as mail by its name or its tools' names, or when you list it; only Claude Code's hook and the gateway can keep a withheld message from the model ([the limits](docs/limitations.md#the-email-guard)).
- **Programs and agents without hooks**, through the [`run` sandbox](docs/run.md): an OS sandbox with a network proxy, but no taint tracking. On Linux its tests have been run in a Docker container (Debian 12, bubblewrap 0.8) and on GitHub's Ubuntu runner, not on other distributions or a bare-metal host; on macOS the profile was loaded by `sandbox-exec` on a Mac by hand, not in CI. The `run --agent claude|codex|gemini` presets have not been run with the real agents, the agent's credentials stay readable inside the run, and an agent with the firewall's hooks installed has its hooks fail closed there, which blocks every action that needs the firewall's state (remove the hooks, or use the agent's own sandbox) ([the limits](docs/limitations.md#run)).
- **Agents in NVIDIA OpenShell sandboxes** (experimental), through the firewall's [supervisor middleware](docs/sandboxes.md): OpenShell is the cage, and the firewall judges each request OpenShell hands it. Tested against a stand-in supervisor built from OpenShell's published protocol, not a real gateway; the model API, WebSocket binary and server messages, and `tls: skip` endpoints are not inspected ([the limits](docs/limitations.md#openshell-middleware)).
- **Browser agents**, through the [browser extension](browser/README.md) (built, not released yet; tested with scripted stand-in agents, not real browser agents).

It protects an agent where the agent touches your machine, your tools or your data. An assistant that runs entirely on its vendor's servers is not covered, except for the local MCP servers it reaches that you wrap with the gateway; nothing covers its own tools.

## What it looks like

Ordinary work passes silently. After the session has read a web page, a push
needs you. With nobody there to answer, it is held. A live key in a request
body is denied unless it goes to the service that issued it.

```
ASK   LaunchSafe Firewall: push commits to the git remote "origin". (rule FW-SEND)
HOLD  To allow this exact action once, run: launchsafe-firewall queue approve jvztcgrr
DENY  ... would carry a credential (Stripe live secret key) to a destination that did not issue it (rule FW-DLP-CREDENTIAL)
```

`launchsafe-firewall demo` replays modelled action sequences from 11 public
incidents and 5 well-known attack patterns (18 scenarios) through the policy in
a temporary directory and installs nothing. In this build all 34 harmful
actions in them reached deny, ask or queue (13 denied, 13 asked, 8 held in the
queue); none ran without a person, and the demo's last line gives these counts.
An asked action runs if you say yes. The scenarios are the hook events we wrote
to model each attack, not recordings of the attacks
([incidents](docs/incidents.md)).

## Quick start

Install the package globally (Node 22 or newer). Do not run it with `npx` or a
shell alias: the hooks need a stable path to the CLI.

```sh
npm install -g @launchsafe/agent-firewall
launchsafe-firewall install   # sets an approval passphrase, registers the hooks
launchsafe-firewall update    # downloads the malicious-package lists (the only command that downloads data without a prompt; `doctor --fix` offers the same download after you confirm)
launchsafe-firewall doctor    # checks the install and the settings files it can read
```

To build from a checkout instead, see [CONTRIBUTING.md](CONTRIBUTING.md). No malicious-package data ships with the firewall: until you run
`update`, known-malicious versions are not denied (`doctor` warns). Run it
weekly; a version listed after your last `update` is not denied either.

Run `install` in your own terminal and type the passphrase only there, never
into an agent. Add `--agent codex|gemini|cursor` for the other agents. Then use
your agent as usual.

Teams should use the managed install (needs administrator rights):
`install --managed --lock-other-hooks` prints Claude Code's managed settings
for an administrator to deploy (add `--agent codex|gemini|cursor` for the
others; [how](docs/usage.md#install)). For Claude Code, no repository's or
user's settings file can then switch the hooks off.
None of the managed installs (Claude Code's, Codex's, Cursor's) has been tested
on a real machine: the files are generated and checked, but not deployed as an
administrator and run through the agent (it needs root; see
[Codex](docs/agents/codex.md#managed-deployment)).
For Gemini CLI and Cursor it is a system-level install without a lock on other
hooks, and Gemini CLI still skips hooks in a folder it does not trust. A
command-line flag a CI job passes is not covered. See the
[agents table](docs/agents/overview.md).

To roll out gradually, `rollout watch` logs what would have been asked or held
and lets it run, for a reviewed list of rules: sends, messages and fetches
after outside content, outside writes, installs, opaque code, starting another
agent, the task scope, unknown tools, bare IP addresses, misspelt package
names, the budgets, loop detection and policy errors. While it is on, a fooled agent can push,
send a message, fetch from any host, install packages or start another agent
([limitations](docs/limitations.md#watch-mode)). Credential and personal-data
denials, self-protection, destructive and catastrophic actions stay enforced,
and so do new-host checks when `knownHosts` is on (it is off by default). See
[policy.md](docs/policy.md#watch-mode-rollout).

- **Approve** a held action in your terminal: `launchsafe-firewall queue review`,
  or `queue approve <id>` for one item. Approval needs the passphrase and lets
  that exact action run once.
- **Explain** a rule in plain words: `launchsafe-firewall explain FW-SEND`.
- **Uninstall**: `launchsafe-firewall uninstall` (add `--restore-backup` to put
  the settings file back as it was, `--purge` to delete the firewall's state).

## Features

- **Allow, ask, hold or deny before each tool call a running hook reports.**
  Each action is judged mostly by what it does (files, network, code), read
  with a conservative shell parser; some rules also match fixed lists of
  commands and names. Some shell constructs are not analysed yet and can run
  without a prompt, even after outside content
  ([the list](docs/limitations.md#shell-constructs-not-yet-analysed)). Unknown
  tools go to a person.
- **Outside content taints the session.** After a web page, email or MCP
  result is read, a send or fetch the firewall can see needs a person unless
  the destination is allowlisted or you named it; so do changes to the agent's
  instructions and running changed build files. Programs the hooks cannot see
  are not covered.
- **Credentials and personal data.** A recognised credential shape in outbound
  data, as written, is denied unless it goes to the service that issued it. A
  secret the session has read is also found in common encodings; an encoded
  credential it never read is not, and the contents of an uploaded file are not
  scanned ([limitations](docs/limitations.md#data-leaving-the-machine)).
  Reading `~/.ssh`, `~/.aws` and similar needs you.
- **Catastrophic actions.** Deleting the workspace, force-pushing over `main`,
  dropping a database or deleting cloud resources is denied from a fixed list of
  commands, also in Codex's `codex exec` and Gemini CLI's yolo mode (their
  hooks were captured firing in those modes; that the agent enforces the deny
  there was not captured) and in Claude Code's bypass mode (from its
  documentation, not captured); whether Cursor's hooks run in its bypass mode
  is unverified. Not
  every way to do the damage
  ([per agent](docs/agents/overview.md#bypass-and-yolo-modes)).
- **Self-protection.** Changes the firewall can see to its own hooks, its files
  and the approval key are denied, and cannot be approved from inside the
  agent. Approvals are signed with a key unlocked by your passphrase. Other
  state (sessions, counters, the provenance ledger) is only as strong as the
  analyser that guards it
  ([limitations](docs/limitations.md#what-kind-of-tool-this-is)).
- **A signed, hash-chained log** of decisions, verifiable offline
  ([logs](docs/logs.md)); an entry the file system fails to write (a full disk,
  an I/O error) is reported, not recorded. The signing key is in the
  firewall's own directory, so something that can write there can rewrite the
  log; anchor it off the machine (`log anchor`) to catch that. Plus spending
  limits (token and cost limits only where the library or the local API
  reports model usage) and an unattended queue for runs with nobody present.
- **More:** a secret vault, an MCP gateway, an email guard, decoy files, package
  checks (known-malicious versions once you have run `update`), and `run`, an
  OS sandbox for agents without hooks.

## Supported agents

| Agent | Blocks a command before it runs | Asks you in its own prompt | Install |
|---|:---:|:---:|---|
| Claude Code | ✓ | ✓* | `launchsafe-firewall install` |
| Codex | ✓ | — (held in the queue) | `launchsafe-firewall install --agent codex` |
| Gemini CLI | ✓ | — (held in the queue) | `launchsafe-firewall install --agent gemini` |
| Cursor | ✓* | — (held in the queue) | `launchsafe-firewall install --agent cursor` |
| Your own agent | ✓ | ✓ (you supply the prompt) | `@launchsafe/agent-firewall/sdk` |

\* Claude Code: asking in its bypass mode (`bypassPermissions`) was not
verified. Claude Code: only the MCP `PreToolUse` event, the sandbox schema and
the desktop app's tool events were captured live; the other hook events follow
its documentation. Cursor: its hook formats were read from its source and
documentation, not captured live.

Exceptions to "blocks before it runs": the hook itself denies a decision still
running after 20 seconds, but it checks the time between steps, so a step that
never returns is left to the agent's hook timeout, which install sets to each
agent's default. Codex (600 seconds) and Gemini CLI (60 seconds) then run
the tool. Claude Code (600 seconds) blocks only through the `onFailure:
"block"` install writes, which it honours from 2.1.295 (not verified live: the Claude Code version tested, 2.1.289, is
older than that, and no later version was captured); older versions are documented to ignore it and run the tool. Cursor (30 seconds) blocks, per Cursor's source; not run against the real
agent. Codex's hosted web
search never reaches a hook, and Codex cloud runs no local hooks; Cursor's
cloud agents run only the repository's hooks. Each agent's hooks see a
different amount. See [docs/agents/overview.md](docs/agents/overview.md) for
the full table.

## How it works

The firewall installs as hooks in the agent. On every tool call it turns the
action into what it actually does, checks the session's trust state, and
decides from a fixed rule table. A session starts trusted. It becomes untrusted
the first time the agent reads outside content, and from then on the damaging
action classes it can see need a person. It restricts: an action it accepts
goes on to the agent's own permission rules (a vault-rewritten command is the
one exception, see [How it works](docs/how-it-works.md)). On an internal error,
risky actions fail closed; a hook that times out fails open on Codex and Gemini
CLI, and on Claude Code unless it honours `onFailure: "block"` (above). Read
[How it works](docs/how-it-works.md), [design](docs/design.md) and
[limitations](docs/limitations.md) for the detail.

No telemetry. [How it works](docs/how-it-works.md#no-telemetry) lists the
firewall's network use. The servers you start yourself (`serve --api`, `ui`,
`mcp serve`, `openshell serve`) listen for connections (`openshell serve`
without TLS answers any process that reaches its port), and
`log anchor --exec` runs an upload command of your own.

## What is in this repository

| Path | What | Package |
|---|---|---|
| `/` (the root) | The firewall: the CLI and agent hooks, the library, the MCP gateway, the email guard and the local API | `@launchsafe/agent-firewall` on npm |
| [`browser/`](browser/README.md) | The browser extension (Manifest V3) for browser agents, which can [link to the firewall](docs/browser-link.md) | Chrome extension |
| [`python/`](python/README.md) | The Python SDK for the local API, with plug-ins for the OpenAI Agents SDK, LangGraph, Claude Agent SDK, Pydantic AI, Google ADK and CrewAI | `launchsafe-firewall` on PyPI |

Each part has its own package file, tests and release. The npm package and
the Python SDK are published; the browser extension is not yet.

## Documentation

Full docs: [docs.launchsafe.com/agent-firewall](https://docs.launchsafe.com/agent-firewall).

- [Using the firewall](docs/usage.md): install, first run, approving, uninstall
- [Limitations](docs/limitations.md): what it does not do. Read this first.
- [How it works](docs/how-it-works.md) and [design](docs/design.md)
- [Policy](docs/policy.md) and [command line](docs/cli.md)
- [Decision log](docs/logs.md): export, offline verify, off-machine anchors
- [Vault](docs/vault.md), [MCP gateway](docs/gateway.md),
  [email guard](docs/email-guard.md), [`run`](docs/run.md),
  [sandboxes and OpenShell](docs/sandboxes.md)
- [Phone approvals](docs/phone.md) (experimental, not usable yet) and
  [dashboard](docs/dashboard.md)
- [Browser link](docs/browser-link.md) to the LaunchSafe browser extension (not released yet)
- [Library for your own agent](docs/library.md) and the [local API](docs/api.md)
  (`serve --api`) for agents in any language
- Per agent: [Claude Code](docs/agents/claude.md), [Codex](docs/agents/codex.md), [Gemini CLI](docs/agents/gemini.md),
  [Cursor](docs/agents/cursor.md)
- [Threat model](docs/threat-model.md), [coverage](docs/coverage.md),
  [incidents](docs/incidents.md)

## Security

This is a layer, not a sandbox and not a guarantee. The code was reviewed for
security by the maintainers, with AI assistance; there has been no third-party
audit, and it has not been tested against live attacks. Run it together with
the agent's OS sandbox. The [threat model](docs/threat-model.md) and
[limitations](docs/limitations.md) list what it covers and what it does not.

To report a bypass, email security@launchsafe.com privately instead of opening
a public issue. See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the test
setup and the checks every change passes (`npm run typecheck`, `lint`, `test`,
`check:docs`; `browser/` and `python/` have their own). Please follow the
[code of conduct](CODE_OF_CONDUCT.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Secret-detection patterns and the agent-safety rules and analyzer were copied and adapted from LaunchSafe's private product repository, whose copyright holder (LaunchSafe) licenses them here under Apache-2.0; the file list is in NOTICE. `browser/src/engine/psl-data.ts` is derived from the Public Suffix List (MPL-2.0).
