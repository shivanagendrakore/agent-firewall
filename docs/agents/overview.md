# Supported agents

Capability table and per-agent notes. Details per agent are in
[claude.md](claude.md), [codex.md](codex.md), [gemini.md](gemini.md) and
[cursor.md](cursor.md).

One engine, one policy, one queue and one log; an adapter per agent
(`src/adapters/`) translates its hook events. The Codex and Gemini CLI
formats were captured live from the installed CLI (Codex 0.162.1, Gemini CLI
0.63.0), with a fixture set for each. For Claude Code (2.1.289) the repository
holds only live captures of the MCP `PreToolUse` event, the sandbox settings
schema and the desktop app's own tool events (`test/fixtures/claude-*`). The other
hook events were not captured; they follow Claude Code's hooks documentation.
Cursor's could not be captured without a Cursor account: its formats were
reconstructed from the behaviour of `cursor-agent` 2026.10.01 and checked
against Cursor's hooks documentation (the fixtures say so). `doctor` prints the
gaps from this table.

| Capability | Claude Code | Codex | Gemini CLI | Cursor |
|---|---|---|---|---|
| Block a shell command before it runs | yes | yes | yes | yes (`preToolUse` on `Shell`) |
| File writes seen with content | yes | yes (`apply_patch` parsed per file, one verdict per patch) | yes | yes in the CLI (`preToolUse` before `Write`, with the whole new file, and `Delete`; read from source); the IDE is documented the same, **not verified** |
| File reads seen (taint from outside files) | yes | through the shell only (Codex has no read tool) | yes | yes (`preToolUse` on `Read` decides; `beforeReadFile` hands over the content) |
| Web fetch and search seen | yes | curl yes; **hosted web search not visible** | yes (every URL in `web_fetch`) | `Fetch` yes; server-side tools (web search) **under unverified names** (an unlisted name is held) |
| MCP calls seen, trusted by configuration source | yes | yes | yes | yes (`beforeMCPExecution` names the server; `preToolUse` does not) |
| Tool output seen (taint, fingerprints) | yes, with redaction | yes, no redaction | yes, no redaction | yes, no redaction |
| Asks you | yes | **no**: held in the queue with the approve command | **no**: held in the queue | **no**: held in the queue (`preToolUse` ignores `ask`) |
| Fails closed | yes, except a timeout, unless `onFailure: "block"` (Claude Code 2.1.295+; install writes it, `doctor` warns on older versions); `\|\| exit 2` covers a crash | yes, except a hook timeout (the wrapper prints, because Codex ignores a silent exit 2) | same as Codex | yes, including a timeout (`failClosed: true` on every entry; per Cursor's source, not run against the real agent) |
| Hook timeout install writes | 600 s (Claude Code's documented default) | 600 s (Codex's default, checked in a hash test) | 60 000 ms (Gemini CLI's documented default) | 30 s |
| Settings the agent can rewrite mid-session protected | yes (result-checked + ConfigChange) | result-checked writes, incl. hook trust | result-checked writes | result-checked writes, incl. Cursor's validation of the whole file |
| A repository can switch the hooks off | `disableAllHooks` (doctor fails) | `[features] hooks = false` (doctor fails) | `hooksConfig` (doctor fails); untrusted folders skip all hooks | no switch; one invalid entry makes Cursor drop that whole `hooks.json` (doctor fails, the agent doing it is FW-TAMPER); project hooks only in a trusted workspace |
| Managed deployment the user cannot disable (none of these four tested on a real machine) | managed settings + `allowManagedHooksOnly` | `requirements.toml` + `allow_managed_hooks_only` | system settings (no lock on other hooks) | enterprise `hooks.json` (MDM) or team hooks; a deny from any hook wins, no lock on other hooks |
| Subagents | shared session id | shared session id | shared session id | linked by `subagentStart`/`subagentStop` (**not verified live**) |
| Cloud runs | no | **Codex cloud runs no local hooks** | no | **only the repository's `.cursor/hooks.json`** |

```sh
launchsafe-firewall install --agent codex     # ~/.codex/hooks.json, and records the hooks' trust (Codex skips untrusted hooks silently)
launchsafe-firewall install --agent gemini    # ~/.gemini/settings.json
launchsafe-firewall install --agent cursor    # ~/.cursor/hooks.json (fail-closed entries; Cursor reloads it on save)
```

The same engine decides for all four; what each agent's hook protocol lets
the firewall do differs (table above). For example, in every agent decoys
trip whatever the verdict, unknown tools are held, a proposed prompt is never
the person's, agent-written text is escaped before it is shown, and MCP
servers are compared with their pins on every session start.

Every hook answers within its own deadline (20 s from the hook process's
start by default; `LAUNCHSAFE_FIREWALL_HOOK_DEADLINE_MS`, 1 to 25 s): a
decision not finished by then is a deny the hook writes itself, well before
the agent's timeout, so a slow disk or a held lock never becomes a timeout
an agent may treat as "run it". The deadline is checked between steps and
bounds every wait (locks, the configuration scan, a phone hold); a step that
never returns is left to the agent's timeout (see
[limitations](../limitations.md)).

An MCP tool is identified by the server and tool the event names in fields of
their own where the agent provides them (Claude Code's top-level
`mcp_server.name`, Cursor's `mcp_server_name`, Gemini CLI's `mcp_context`).
Where only the joined name exists (Codex), a name with more than one `__`
boundary (`mcp__a__b__c`) can be read as more than one server and is asked
(FW-UNCLASSIFIABLE), unless the policy lists the longest reading's server by
exact name. Every native tool the agents were seen (or, for Cursor, read) using maps
to a tool the firewall knows, so ordinary work is not interrupted; a tool it does
not know is held for you. The session-start MCP comparison reads every installed
agent's MCP configuration (Claude Code's files, Codex's `config.toml`, Gemini
CLI's `settings.json`, Cursor's `mcp.json`), keyed per agent: a changed launch
line makes that agent's next session untrusted until you accept it.

**What Cursor's hooks cannot give the firewall.** Tab completions (your own
edits), the characters typed into a running shell (`WriteShellStdin`), computer
use and screen recording carry nothing the firewall can judge; the last three
are held as unknown tools. Cursor's cloud agents run only the repository's own
hooks, where a project install's local paths do not exist (and, failing closed,
block every action there): install for Cursor with `--scope user`, and use
Cursor's sandbox (`sandbox.mode: "enabled"`) and an egress proxy for what hooks
cannot see. Cursor also runs the firewall's Claude Code hooks (its third-party
import, on by default); the firewall recognises Cursor's events there and defers
to its own Cursor hooks when they run, so nothing is decided twice.

## Bypass and yolo modes

Every agent has a mode that skips its own permission prompts: Claude Code's
`bypassPermissions` (`--dangerously-skip-permissions`), Codex's
`--dangerously-bypass-approvals-and-sandbox` / `--yolo` and `codex exec`
(approval policy `never`), Gemini CLI's `--yolo` / `--approval-mode yolo`, and
Cursor's `--force` / `--yolo` or "Run Everything". The firewall's protection in
those modes depends on two questions per agent: does its hook still run, and is
the hook's deny still enforced. What is known, and where it comes from:

| Agent | Hook runs in bypass mode | Deny enforced | Ask in bypass mode | Source |
|---|---|---|---|---|
| Claude Code | **yes** | **yes** | not relied on (see below) | Claude Code hooks reference (code.claude.com/docs/en/hooks, read 13 Oct 2026): `permission_mode` is a hook input whose values include `"bypassPermissions"`, and `"deny"` prevents the tool call; the documentation describes bypass mode as skipping permission prompts, not hooks, and hooks run unless switched off (`disableAllHooks`, which `doctor` fails on). The captures are from 2.1.289. Bypass mode was run live once on Claude Code 2.1.302 (`rm -rf` of the workspace under `--dangerously-skip-permissions`): the hook denied it with FW-CATASTROPHIC and the workspace was untouched. |
| Codex | **yes** (captured) | yes (the agent honours a deny: captured outside this mode; not captured in it) | never sent (Codex runs a tool on `ask`) | Codex 0.162.1 captured live: under `codex exec` every event carries `permission_mode: "bypassPermissions"` and `PreToolUse` fired (`test/fixtures/codex-0.162.1-PreToolUse-Bash.json`); deny blocks ([codex.md](codex.md)). The `--dangerously-bypass-approvals-and-sandbox` flag sets the same approval policy but was not captured on its own. A hook timeout (600 s as installed) fails open; the firewall's own deadline denies long before it. |
| Gemini CLI | **yes** (a capture hook ran) | yes (the agent honours a deny: captured outside this mode; not captured in it) | not supported (held in the queue) | Gemini CLI 0.63.0 captured live with `--approval-mode yolo`: a capture hook on `BeforeAgent` ran (`test/fixtures/gemini-0.63.0-ancestry-ps.json`, `-ancestry-seatbelt.json`), not the firewall's hook; `BeforeTool`'s `{"decision":"deny"}` blocks ([gemini.md](gemini.md)). A hook timeout fails open. |
| Cursor | **not verified** | yes, where the hook runs | ignored by Cursor (held in the queue) | Inferred from `cursor-agent` 2026.10.01's behaviour, not run: `preToolUse` is the decision point for every local tool and its deny is enforced ([cursor.md](cursor.md)). Neither that reading nor cursor.com/docs/hooks (read 13 Oct 2026) says whether hooks run under `--force` or "Run Everything", and no such run was captured. The firewall entries are `failClosed`. |

What the firewall does about it:

- **The catastrophic class is denied, never asked** (FW-CATASTROPHIC, with
  FW-DESTROY-ROOT): deleting the home directory, the root, the whole
  workspace or a repository's `.git`; force-pushing over or deleting a
  protected branch (`main`, `master`, `trunk` always, and the policy's
  `protectedBranches`: by default `production`, `prod`, `develop`,
  `release/*`), including a force push that names no branch while one of
  them is checked out; `git push --mirror` and `git reflog expire
  --expire=now --all`; dropping a database (DROP DATABASE or SCHEMA,
  `dropdb`, `mysqladmin drop`, `dropDatabase()`, FLUSHALL, and TRUNCATE on a
  remote database named on the command line); deleting buckets, volumes,
  clusters, namespaces, custom resource definitions, projects, accounts,
  repositories, KMS keys and DNS zones with aws, gcloud, gsutil, bq, az,
  kubectl/oc, eksctl, doctl, gh, terraform/tofu/terragrunt/pulumi/cdk
  destroy, sam, serverless, railway, fly, vercel, supabase, heroku, netlify,
  neon, PlanetScale and Turso; `docker volume prune`, `docker system prune`
  and `docker compose down -v`; and MCP tools named `delete_project`,
  `delete_repository`, `delete_database`, `delete_namespace` or `drop_*`.
  A deny is the one answer every agent enforces in every mode where its hook
  runs, so this does not depend on how an agent treats `ask`. No permission
  mode, policy file (user, managed or project), approval or library callback
  turns it into a question (`test/hard-block.test.ts`, which runs each
  agent's own event format in its bypass mode). The message says why and what
  to do instead; a person who means it runs the command in their own
  terminal.
- **Everyday teardown stays approvable.** A targeted teardown (`terraform
  destroy -target=...`, `pulumi destroy --target`), one named Docker volume,
  a filtered `aws s3 rm --recursive --exclude/--include`, `find ... -name
  ... -delete`, and a command whose verb or branch is known only at run time
  (`terraform $CMD`) are FW-DESTRUCTIVE: asked, or held. A throwaway
  database, namespace, app or bucket whose name matches a pattern you
  declared with `launchsafe-firewall scratch add` (signed with your approval
  key, user level only; see [policy.md](../policy.md#scratch-targets)) is
  asked too.
- **A preview of a teardown is allowed.** `terraform plan -destroy` (also
  `tofu` and `terragrunt`, and `pulumi preview --destroy`) changes nothing and
  is the preview the denial message sends you to, so it is judged as a plain
  plan is. Saving it to a file (`-out=FILE`, `--save-plan`, Terragrunt's
  `--out-dir`) is FW-DESTRUCTIVE:
  asked, or held, because the plan file destroys everything when it is applied
  and `terraform apply FILE` carries no destroy flag for the firewall to see.
  `apply -destroy`, `destroy` and their `-auto-approve` forms stay denied.
- **Everything else that needs a person** is asked (Claude Code) or held in
  the queue (the other three, and any session the firewall finds unattended).
  Codex, Gemini CLI and Cursor in their bypass modes are detected as unattended
  ([codex.md](codex.md), [gemini.md](gemini.md), [cursor.md](cursor.md)). So is
  any session of the four whose agent process cannot be read at all (on Linux
  the firewall reads `/proc`, so a missing `ps` is not that case): not knowing
  is taken as nobody being there ([limitations.md](../limitations.md)).
  Claude Code's `bypassPermissions` and `auto` are unattended by default
  (`unattendedPermissionModes` is `["dontAsk", "bypassPermissions", "auto"]`):
  whether a hook's `ask` reaches a person in those modes is **not verified**,
  so such actions are held in the queue with the approve command instead of
  asked. This stays until an ask under them is captured reaching a person.
- **Where the hook does not run, nothing in it applies:** hooks switched off by
  a repository (`doctor` fails), a hook that times out on Codex or Gemini CLI
  (or on Claude Code before 2.1.295, which is documented to ignore `onFailure: "block"`),
  cloud runs. Use the agent's own sandbox and the firewall's `run` there.

## Not verified

What these notes rely on that no capture or test run shows:

- Claude Code honouring `onFailure: "block"` (documented for 2.1.295 and later;
  the captures are 2.1.289, older than the version that honours it, and no
  later version was captured).
- That Claude Code before 2.1.295 accepts the `onFailure` field and ignores it
  (the documentation says so; no capture of an older or newer version shows it).
- Whether a hook's `ask` reaches a person under Claude Code's
  `bypassPermissions` or `auto` (so both are held by default).
- That Codex (`codex exec`) and Gemini CLI (yolo mode) enforce a hook's deny in
  those modes: the hooks were captured firing there, a deny was captured only
  outside them.
- Cursor's hooks under `--force` / "Run Everything", and its subagent events.
- Whether Codex needs `[hooks] managed_dir` besides `requirements.toml` for
  managed hooks ([codex.md](codex.md)).
- Gemini CLI's `mcp_context.tool_name` in every version (older events name the
  tool only in the joined name, which is then judged by the `__` rule above).
