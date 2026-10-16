# `launchsafe-firewall run`: an agent inside the OS sandbox

```sh
launchsafe-firewall run -- aider --model sonnet
launchsafe-firewall run --send-host api.anthropic.com -- my-agent
launchsafe-firewall run --dry-run -- opencode      # print the sandbox and the host list, run nothing
```

`run` starts any command (an agent CLI, a script, a build) inside the
operating system's own sandbox: on macOS `sandbox-exec` (Seatbelt), on Linux
bubblewrap. The command can write only to the workspace and a private
temporary directory, cannot change the firewall's own files, and reaches the
network only through a small proxy on 127.0.0.1 that `run` starts and that
admits the hosts your firewall policy lists. Every refusal, the first
connection to each host and a summary at the end go to the firewall's signed
decision log.

It is for agents that have **no built-in sandbox** and often no hooks either
(Aider, opencode, goose, home-made scripts). For Claude Code use its own
sandbox (`doctor --fix` writes the profile from the same policy); Codex,
Gemini CLI and Cursor have sandboxes of their own too.

For a coding agent, `run --agent claude|codex|gemini` sets the run up for it
(see [Agent presets](#agent-presets)). To keep an agent's hooks judging every
action *and* have a hard outer wall, use the agent's own sandbox or an OpenShell
sandbox with the firewall's middleware ([sandboxes.md](sandboxes.md)).

## Why it exists

The hooks decide whether a tool runs; they cannot contain a program that does
run, and they see nothing at all for an agent that has no hooks. The threat
model's gap is exactly that: a compiled binary, a script that opens a socket,
or a whole agent the firewall cannot see into. `run` closes the part of that
gap the operating system can enforce: where the process may write and which
hosts it may reach, whatever the program is.

## Design

```
  you ── launchsafe-firewall run -- <agent> ──────────────────────────────┐
           │ 1. policy → hosts (profileFromPolicy, the same derivation     │
           │    doctor --fix uses for Claude Code's sandbox)               │
           │ 2. proxy on 127.0.0.1:<port>  (Linux: a private Unix socket)  │
           │ 3. sandbox profile → sandbox-exec / bwrap → <agent>           │
           ▼                                                               │
   ┌──────── sandbox ─────────┐        ┌──── proxy (outside) ────┐         │
   │ <agent>                   │ CONNECT│ host on the list?       │ signed  │
   │  HTTPS_PROXY=127.0.0.1:P ─┼───────►│ DNS answer not internal?│──► log  │
   │  writes: workspace, $TMPDIR│       │ TLS SNI = that host?    │         │
   │  no other network, no DNS │        │ budgets                 │──► host │
   └───────────────────────────┘        └─────────────────────────┘         │
```

### The host list (shared with Claude Code's sandbox)

`run` does not have a policy of its own. It calls `profileFromPolicy()`
(`src/engine/sandbox.ts`), the function that turns the policy into Claude Code's
`sandbox.network.allowedDomains` for `doctor --fix`, so both sandboxes admit
exactly the same hosts:

- `fetchAllowHosts` and `sendAllowHosts`, in the sandbox's syntax (`"=x"` only
  that host, `"*.x"` its subdomains, `"x"` both);
- never a raw IP address (any spelling), loopback, a cloud metadata endpoint, a
  capture or tunnel host, anything in `denyHosts`, or a wildcard that would cover
  a metadata name or IP addresses, even when listed;
- `denyHosts` win over every allowed pattern;
- hosts you named in a prompt are not added (they are per session and `run`
  has no session).

`--send-host LIST` adds hosts for this run only, as send hosts (for example
the agent's model API, which every agent needs and no default lists). The same
exclusions apply: an IP address, loopback, a metadata or capture host, or a host
in `denyHosts` is refused and `run` does not start.

### Known hosts

The hooks see the agent's tool calls, not what a program those calls start
does: a test suite, a build script, a package's install script or any other
child process opens its own connections, and no hook sees them. A hook-only
setup therefore cannot hold child processes to the per-project known-hosts
list ([usage.md](usage.md#known-hosts-ask-before-the-agent-contacts-a-new-website)).
`run` narrows that gap: every process in the sandbox, whatever started it, can
reach the network only through the proxy, which admits only the hosts below.

With `knownHosts.mode` set to `"ask"` or `"watch"` in your user or managed
policy (a repository's `.launchsafe-firewall.json` cannot switch this on for
`run`: there it would widen what the proxy admits), the proxy also admits the
hosts approved for the workspace, from the same list the hooks learn into
(`~/.launchsafe-firewall/known-hosts/`). The hooks add a host there only from
a fetch a person said yes to; a host the agent sent data to gets there only by
your own `hosts allow` or `hosts accept <host>`. It reads the list again at most
once a second, so a host you approve while the run lasts (a yes in the agent's
own prompt, or `launchsafe-firewall hosts allow <host>` in another terminal) is
admitted from then on. An approved host is admitted only by its exact name,
after every refusal above the list in the table below (port, address form,
metadata, capture hosts, `denyHosts`), and as a fetch-only host under the
counted budgets. "Fetch-only" is a label: like every admitted host, it accepts
uploads too (the proxy sees hosts, not methods), and a registry or code host
among them is labelled upload-capable in the log and the dry run. The proxy cannot ask: a host that is neither listed nor
approved is refused, and the refusal names the command that approves it. With
`"watch"`, the hosts refused that way are recorded for `hosts review`, listed
apart from what the hooks saw, since `run` cannot tell what the program had
read; they are collected in memory and written in batches (every 30 seconds
and at the end), at most 200 per run. The built-in known hosts are not added to the proxy's list: they include
model APIs that receive your code by design, so pass `--send-host` for the one
your agent uses. `run --dry-run` prints the approved hosts with the rest.

### The proxy (`src/runtime/run/proxy.ts`)

Node's `http` server, outside the sandbox, on 127.0.0.1 and a random port (on
Linux on a Unix socket in a private directory, bridged into the sandbox; see
below). The child's environment points every proxy variable at it
(`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and the lower-case forms;
`NODE_USE_ENV_PROXY=1` for Node's own `fetch`, which honours it only on Node 22.21+ or 24.5+); `NO_PROXY` keeps loopback
traffic local. A program that ignores the variables simply cannot connect: the
sandbox admits no other address.

For each `CONNECT host:port` (HTTPS) or absolute-form `GET http://host/...`
(plain HTTP), in order:

| Check | Refused when | Logged as |
|---|---|---|
| port | not 443 or 80 | `why: "port"` |
| address form | a raw IP address or loopback | `FW-RAW-IP` / `why: "loopback"` |
| metadata | a cloud metadata endpoint | `FW-METADATA` |
| capture hosts | a request catcher or tunnel service | `FW-CAPTURE-HOST` |
| `denyHosts` | listed | `why: "denied-host"` |
| the list | not admitted by the derived host list or `--send-host`, nor approved for the workspace (knownHosts, see above) | `why: "not-listed"` |
| DNS | any answer of the proxy's own lookup is private (10/8, 172.16/12, 192.168/16), carrier-grade NAT (100.64/10), unique local (fc00::/7), site-local (fec0::/10), loopback, link-local, unspecified, multicast, a metadata address, or a special-purpose block that is not the public internet (192.0.0.0/24, the documentation blocks 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32, the benchmarking 198.18.0.0/15), in IPv4, IPv6, IPv4-mapped or NAT64 (64:ff9b::/96) form (DNS rebinding). Every answer is checked, and the proxy connects to the address it checked, never a second lookup. A private answer is admitted only for a name in `run.privateHosts` (user or managed policy), a loopback answer only with `--allow-localhost` on macOS; link-local, metadata, unspecified and multicast answers never | `why: "resolves-internal"` |
| TLS name | the client's TLS ClientHello names a different server (SNI) than the CONNECT line, or port 443 carries something that is not TLS | `why: "sni-mismatch"` / `"not-tls"` |
| Host header | plain HTTP only (absolute form, and requests read inside a CONNECT to port 80): the `Host` header names a different server or port than the admitted URL; the upstream always gets the admitted host as `Host` | `why: "bad-host"` |
| budgets | see below | `FW-BUDGET-BYTES` / `FW-BUDGET-REQUESTS` |

A refused request gets `403` with one plain line that says why and which
policy key to change, so the agent (and you, reading its output) can tell a
firewall refusal from a network failure. A CONNECT to port 80 that carries
HTTP is read request by request, like absolute form (so the Host check, the
budgets and the tunnel's own target apply to every request inside it); bytes on
port 80 that are not HTTP are refused. An HTTP upgrade (a WebSocket, `ws://`)
is admitted with the same checks as a request (the tunnel's target, the list,
budgets, the `Host` header) and then relayed both ways, with the bytes the
client sends counted against the budgets. Only the upgrade request itself is
sent on at first; bytes the client queues behind it (a pipelined second request
with another `Host`) are held, and relayed only once the server has answered
`101`. Any other answer is passed on and the connection closed. The proxy never decrypts TLS: it sees
the host name, the port and the SNI, never the path, the method or the body.

### Budgets in run mode

The hooks' budgets ask a person when one is reached. In `run` nobody can be
asked in the middle of a connection, and the firewall cannot see what the agent
read, so the run is treated like an **untrusted** session from the start and a
reached budget **refuses** (fail closed) instead of asking:

| Destination | Upload bytes (client to server) | Connections and requests |
|---|---|---|
| hosts in `sendAllowHosts`, `--send-host` or `budgets.exemptHosts` | not counted | not counted |
| package registries and code hosts (the hooks' install and clone list: `registry.npmjs.org`, `pypi.org`, `github.com`, ...) | `budgets.trusted.bytesTotal` together (4 MB) | `budgets.trusted.requestsPerHost10m` per host (300) |
| every other listed host | `budgets.untrusted.bytesPerHost` each (64 KB) and `budgets.untrusted.bytesTotal` together (256 KB) | `budgets.untrusted.requestsPerHost10m` per host (40) |

The middle row exists because the proxy cannot tell an install from an upload:
with the untrusted numbers every `npm install` would stop at 64 KB of request
headers, and with no limit a fooled agent could push your code to its own
repository on `github.com` without bound. Bytes are counted on the wire (TLS
records and headers included), so they are an upper bound of what was sent. A
CONNECT tunnel counts as one request however many HTTP requests travel inside
it. Once a budget is reached, new connections to that host (or, for a total,
to every counted host) are refused for the rest of the run, and a tunnel that
crosses the limit is closed. `budgets.enabled: false` switches them off. To
raise one for an agent you trust, change the `budgets` key in your user policy
or add the host to `sendAllowHosts`.

### The sandbox profile

Both platforms get the same rules from one plan (`src/engine/run-profile.ts`,
pure):

- **Writes:** the workspace (the current directory, or `--workspace DIR`) and a
  private temporary directory created for the run (`TMPDIR` points at it; it
  is removed afterwards), plus `--allow-write LIST`. `--allow-write` refuses the
  disk root, system directories, the home directory or anything above it,
  credential stores, shell start-up files, `~/.config` and `~/Library`
  themselves, the agents' own configuration directories (`~/.claude`,
  `~/.codex`, `~/.gemini`, `~/.cursor`, where the firewall's hooks are
  registered), other places that start programs later (`~/.config/nvim`,
  `~/.config/zsh`, `~/.vim`, `~/.emacs.d`, `~/.tmux`, `~/.config/environment.d`,
  `~/.local/share/applications`, `~/.cargo/bin`, `~/go/bin`, `~/.npm-global`,
  VS Code's `User` settings directory) and the firewall's data directory.
  Every `--allow-write` directory gets the same read-only paths as the
  workspace (the list below, and nested repositories' rules), not only the
  workspace: a repository you pass there keeps its `.git/hooks`, `.git/config`
  and `.envrc` read-only too. `/tmp` is not writable by
  default: other programs' sockets and files live there (tmux, X11, editors'
  servers). A directory that holds Unix sockets is refused on Linux, where the
  command could connect to them through the bind (a tmux socket types into your
  terminal); on macOS, where the profile lets it connect only inside the
  workspace and the run's directory, `run` notes them (it could still delete or
  replace them). Give a tool that ignores `TMPDIR` a directory of its own
  instead of `/tmp`.
- **Read-only, always,** even when they sit inside a writable directory, and
  whether they exist yet or not: the firewall's data directory
  (`~/.launchsafe-firewall` or `LAUNCHSAFE_FIREWALL_HOME`), its installed
  package, the settings files its install record names, and in the workspace
  everything that starts a program later, outside the sandbox:
  - agent settings: `.claude/settings.json`, `.claude/settings.local.json`,
    `.codex/` whole, `.gemini/settings.json`, `.gemini/extensions/` and
    `.gemini/commands/` whole (extensions bring MCP servers and hooks, commands
    are prompts Gemini CLI runs), `.cursor/hooks.json`, and `.envrc` (direnv
    runs it when you next `cd` into the project); and Claude Code's `.claude/skills/`,
    `.claude/agents/` and `.claude/commands/` whole (skills and subagents can
    declare hooks in their frontmatter), and `.claude/hooks/` whole (where hook
    scripts live, protected before any exists);
  - MCP server lists, editor tasks and settings, dev containers: `.mcp.json`,
    `.cursor/mcp.json`, `.vscode/tasks.json` (a folder-open task),
    `.vscode/settings.json` (it names interpreters and shells the editor
    starts) and `.devcontainer/` whole (`initializeCommand` runs on your
    machine); `.vscode/launch.json`, `.idea/` whole and the `*.code-workspace`
    files at the top (those that exist; a new one can still be created);
  - hook managers and task runners: `.pre-commit-config.yaml`, `lefthook.yml`
    and `.lefthook.yml` (also `.yaml`), `mise.toml` and `.mise.toml`;
  - git: `.git/hooks`, `.git/config` and `.git/config.worktree`
    (`core.hooksPath`, `core.fsmonitor`, filters and `!` aliases run programs),
    `.git/commondir` (git takes the config and the hooks from the directory it
    names), `.git/modules` and `.git/worktrees` (submodules' and linked
    worktrees' own hooks, config and pointer files such as their `commondir`
    and `gitdir`), `.husky`, and a `.git` file (a linked worktree's or
    submodule's pointer to its git directory). `.git/objects/info/alternates`
    stays writable: it only borrows objects (which the run can write into
    `.git/objects` anyway) and never names config or hooks;
  - what the workspace names itself (`src/runtime/run/code-paths.ts`): the
    directory `core.hooksPath` points to, files the git config names (an
    fsmonitor script, an `[include]`d config), read from `.git/config`,
    `.git/config.worktree`, your global git config (`~/.gitconfig`,
    `~/.config/git/config`: a relative `core.hooksPath` there is relative to
    the workspace) and every file they include, `[includeIf]` too, whatever its
    condition; nested repositories'
    `.git/hooks`, `.git/config` and `.git/commondir` (or their `.git` file),
    and the script files
    the agent settings above run as hooks, MCP servers or tasks (the files a
    command names inside the workspace, with `$CLAUDE_PROJECT_DIR`,
    `$CURSOR_PROJECT_DIR`, `$GEMINI_PROJECT_DIR` and `${workspaceFolder}`
    expanded), also when such a file does not exist yet, as long as the command
    names it as a program (`scripts/guard.sh`, `./bin/check`: a script
    extension, a leading `./`, or a path with a `/` as the first word of the
    command or of a part after `;`, `&&` or `|`, such as
    `"$CLAUDE_PROJECT_DIR"/.claude/hooks/guard` or `tools/lint`; each MCP
    server argument counts as its own command), so the agent cannot create a missing hook
    script that runs in your next session. Its directory cannot be created in
    the run either. `run` names these scripts when it starts, with the
    settings file that runs each; when the agent must change one (build output
    an MCP server you are developing runs), add its path to
    `run.allowWritePaths` in your user policy ([policy.md](policy.md)): a
    project policy cannot, and no entry ever exempts git's own files (any
    path with a `.git` component, whichever settings file also names it);
  - the project policy `.launchsafe-firewall.json`.

  Each path is protected as written and with symlinks resolved, so neither the
  link nor its target can be changed. **The directories that lead to a
  protected path cannot be moved, removed or replaced** (`.git`, `.claude`,
  `.cursor`, `.codex`, `.gemini`, `.vscode`, `.husky`, the workspace itself,
  and the directories above a nested repository or a hook script, on both
  platforms): renaming `.git` away and putting a prepared copy with an
  executable `hooks/pre-commit` or a `core.fsmonitor` config in its place,
  writing `hooks/pre-commit` and renaming it back, or putting a symlink or a
  prepared directory where a missing `.claude` would be, is refused. Their
  contents stay writable (git works as usual). Such a directory that does not
  exist yet cannot be created inside the run either (create `.claude/`
  yourself first if the agent needs to write there). Hard links: on Linux every
  protected path is a mount of its own, and the kernel refuses a hard link
  across mounts (`EXDEV`); on macOS the profile denies creating hard links at
  all (`(deny file-link)`; to be verified on a Mac, see Limits), since Seatbelt
  judges a write by the name it uses and a link would give a protected file a
  writable name.
- **Unreadable:** the firewall's keys and vault directories, `~/.ssh`,
  `~/.aws` and `~/.gnupg`, always; and by default the other places tokens
  live: `~/.config/gh`, `~/.netrc`, `~/.npmrc`, `~/.git-credentials`,
  `~/.docker`, `~/.kube`, `~/.config/gcloud` and `~/.azure`. A command that
  needs one gets it with `--allow-home-read NAME` (`--allow-home-read .npmrc`
  for `npm publish`; repeatable). On Linux Docker Desktop's sockets
  (`~/.docker/run`, `~/.docker/desktop`) stay hidden even then.
- **Environment:** the command gets a short list of your variables (`PATH`,
  `HOME`, `USER`, `SHELL`, the terminal's, the locale's `LANG`/`LC_*`, `TZ`,
  editor and pager, the XDG directories, the toolchains' locations such as
  `JAVA_HOME` or `CARGO_HOME`, and TLS trust settings such as
  `NODE_EXTRA_CA_CERTS`), plus run's own. Everything else stays out, so a
  `GITHUB_TOKEN` or `AWS_SECRET_ACCESS_KEY` exported in your shell does not
  reach the command unless you pass it: `--pass-env NAME` (repeatable;
  `NAME_*` for a prefix). `--agent` passes that agent's own key variables
  (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` and the like).
  `SSH_AUTH_SOCK`, the D-Bus address and proxy variables are dropped even
  when named.
- **Network:** nothing but the proxy. On Linux the sandbox has no network at
  all (its own namespace), so no DNS either. On macOS the profile denies the
  network and the name-resolution service (`mDNSResponder`, which sends DNS
  queries on behalf of the process outside the sandbox), so a lookup fails
  instead of leaving as a DNS query; that this covers every lookup path is to
  be verified on a Mac (see Limits), so treat "no DNS" as Linux-verified only.
  Use `127.0.0.1`, not `localhost`, for local servers on macOS. On
  macOS loopback is the host's, so connecting to other local ports is refused
  unless you pass `--allow-localhost` (local test servers need it; every
  service listening on your machine's 127.0.0.1 becomes reachable). On Linux
  the sandbox has its own loopback: local test servers work, the host's
  services stay unreachable, and the flag changes nothing.
- **Unix sockets:** only inside the workspace and the run's temporary
  directory. A socket elsewhere (tmux, ssh-agent, Docker, the D-Bus session
  bus) is a way out of any sandbox: it lets the process ask something outside
  to act for it.
- **Processes:** a sandboxed process cannot signal processes outside the
  sandbox (so it cannot stop the proxy). On macOS it also cannot submit launchd
  jobs (which would run outside the sandbox and outlive the run) or inspect or
  take over processes outside it (their arguments and environment, their task
  port); when `run` has no terminal the command gets a process group of its
  own, which `run` kills when the command exits, before it removes the run's
  directory.

**macOS (`/usr/bin/sandbox-exec`).** A Seatbelt profile with every path passed
as a `-D` parameter (no quoting of paths into the profile text): network denied
except `localhost:<proxy port>` and local binding; file writes denied except the
plan's directories, with the read-only paths denied last (Seatbelt's last
matching rule wins); reads denied for the unreadable paths; Unix sockets only
under the workspace and the run directory; `signal` only within the same
sandbox; Apple Events denied; and the system services that would act for the
process outside the sandbox denied by name: LaunchServices (`open` of a URL or
an application), the background URL-session daemon, the pasteboard and, unless
`--allow-keychain`, the keychain (so a vault item stored with `confirm: never`
is out of reach too), name resolution (`mDNSResponder`) and preference writes
(`cfprefsd`, which writes `~/Library/Preferences` for its caller). Hard links,
launchd jobs, other processes' information and task ports, and the `TIOCSTI`
ioctl are denied too. Whenever `run` could reach a terminal (standard input,
output or error is one, or it has a controlling terminal at all, which a
program can open as `/dev/tty`), the command runs under `/usr/bin/script` with
a pseudo-terminal of its own, so a keystroke the sandboxed program pushes into
its terminal (`TIOCSTI`) stays inside it and is never typed into your shell
after it exits. The rules added in this release (the `TIOCSTI`, hard-link,
launchd, process and name-resolution denials, and `script` with redirected
standard input) are checked by the tests as profile text; the profile as a
whole was loaded by `sandbox-exec` on a Mac by the maintainer, by hand, once,
but nothing shows that each new rule blocks what it is meant to (Limits).

**Linux (bubblewrap).** `bwrap` is used only from `/usr/bin`, `/usr/local/bin`
or `/bin`, root-owned and not writable by others (never through `PATH`).
`--ro-bind / /`, fresh `/dev`, `/proc`, a private `/tmp` and `/run` (hiding the
host's sockets, including the D-Bus session bus that holds the Secret Service),
binds of the writable directories, then each existing directory on the way to
a protected path (`.git`, `.claude`, a nested repository's directory and the
ones above it) bound onto itself, then read-only binds of the protected paths
over them, and an empty tmpfs or `/dev/null` over the unreadable ones. The
self-binds are what keep `.git` in place: the kernel refuses to rename or
remove a mount point (`EBUSY`), but a directory that merely holds one, such as
`.git` with a read-only `.git/hooks` inside, can be renamed freely. A
consequence: a rename from outside such a directory into it (`mv notes.txt
.claude/`, `git mv` across a nested repository's directory) crosses a mount and
fails with `EXDEV`; `mv` falls back to copying, most programs do the same.
The other flags: `--unshare-net` (its own network namespace: no route out, its
own loopback), `--unshare-pid`, `--new-session` (no controlling terminal, so
`TIOCSTI` cannot reach yours) and `--die-with-parent`.

**Protected paths that do not exist yet (Linux).** bubblewrap can mount only on
a path that exists, and `run` does not create files in your repository to make
one. Instead:

- when the protected file's directory is missing too (`.cursor/mcp.json`
  without `.cursor`), that directory gets an empty read-only tmpfs: the agent
  sees an empty, read-only `.cursor/`, and nothing can be created below it.
  There are no stand-in files inside it, so `git add .` in the run commits only
  the agent's own changes (empty directories are invisible to git);
- when the file is missing from an existing agent configuration directory
  (`.claude/settings.local.json` in an existing `.claude/`; also `.codex`,
  `.gemini`, `.cursor`, `.vscode`), that whole directory is bound read-only and
  nothing is created;
- a file git reads inside a git directory (`.git/commondir`,
  `.git/config.worktree`, a nested repository's `.git/config`) gets a **file**
  stand-in, because git refuses a directory there ("Is a directory") and an
  empty `commondir` too ("failed to read"): `run` writes it before the sandbox
  starts with the content git assumes when the file is absent (`.`, the git
  directory itself, for `commondir`; nothing for a config) and binds it
  read-only onto itself, so git inside and outside the run behaves as without
  it (git never lists what is inside `.git`, so it is never committed);
- a missing protected directory inside an agent configuration directory
  (`.claude/skills` in an existing `.claude/`) gets an empty read-only tmpfs on
  itself, so the rest of `.claude/` stays writable; nothing is mounted below a
  directory that is read-only already;
- anywhere else (`.mcp.json` at the top of the workspace, `.git/modules`,
  `.git/hooks`, `.husky`), the path itself gets an empty read-only tmpfs: inside
  the run it is an empty directory nothing can be written into;
- an existing file on the way (a linked worktree's `.git` file) is bound
  read-only, so it cannot be replaced by a directory.

The mount points of the first and fourth cases are **empty directories** that
bubblewrap creates on disk while the run lasts (git ignores empty
directories), and those of the third are the file stand-ins. `run` removes
each one when the last run using it ends (a stand-in only while it still holds
exactly the stand-in's content), and never while another run in the same
workspace still uses it (removing a mount point from outside would detach the
protection inside that run); the users are recorded per path in a private
directory inside the firewall's own directory (`~/.launchsafe-firewall/run-mounts`,
mode 0700: read-only inside every run, and never writable through
`--allow-write`), one claim per run holding its pid, the process's start time,
its command line and the run's id. A project policy that exists
is bound read-only like the other protected files, so every run and hook in
the workspace reads the real file. Only when there is none does the run keep
an empty directory at `.launchsafe-firewall.json` (or `.mcp.json`, ...):
readers of policy and agent files (the policy loader, the hooks) take such a
directory as the file's absence **only with proof that a live run holds it**:
a claim in the registry above, which must be a 0700 directory you own (not a
link), by a process that is still running, started at the time the claim
records, with the same command line, and that command line is this
firewall's `run` (its `dist/cli.js`, also through the `launchsafe-firewall`
link, followed by `run`); or, inside a run, where the run's own process is in
another pid namespace and cannot be checked, a claim in that registry recorded
by this very run (the id in `LAUNCHSAFE_FIREWALL_RUN`) on a path that is a
read-only mount point in the run's mount namespace (`/proc/self/mountinfo`).
The filesystem a directory lies on is never proof: on a Linux host whose `/tmp`
is a tmpfs, an empty directory there is not a run's mount point unless a run
claimed it. Any other directory there is an error
that fails closed (strict defaults, every risky action to a person), and so is
a claim that cannot be checked (a pid reused by another program, a process
whose start time or command line cannot be read). A hook that sees another
firewall directory (`LAUNCHSAFE_FIREWALL_HOME`) than the run's cannot see its
registry and fails closed too. If `run` itself is killed, an
empty directory or a stand-in can stay behind (`.mcp.json/`, or
`.git/commondir` holding `.`, which git reads as no `commondir`); remove it. A
protected path reached through a symlink inside the workspace (`.claude ->
../shared`) cannot be protected on Linux, because bubblewrap mounts on the
target and the link itself could be replaced: `run` refuses to start and says
which link.

Inside, a small Node bridge listens on
127.0.0.1:<port> in the namespace and forwards each connection to the proxy's
Unix socket, then starts the command and passes signals and the exit status
through.

### Who may start it

`run` is started by a person. It is declared as changing state, so the hooks
deny it as FW-TAMPER when an agent they watch tries to start it, and the CLI
refuses when it runs inside a coding agent's session (Claude Code, Codex, Gemini CLI or Cursor), or when a process it was
started from cannot be read ([limitations](limitations.md#approvals)). It
does not require a terminal, so a script or CI job you wrote can use it.
Nothing inside the sandbox can change the policy, the log or the firewall's
files.

### What is logged

Signed, hash-chained entries in the decision log (`log tail`, `log verify`):

- `run_start`: the run id, the program's name and its argument count (never
  the arguments: prompts and keys are often passed there), the workspace, the
  platform, the number of hosts and the run's flags;
- `run_net`: the first allowed connection to each host (`known: true` when it
  was admitted as a host approved for the workspace), and every refusal (up
  to 20 per host and reason; the rest are counted in `run_end`);
- `run_budget`: a budget reached (rule, key, limit, amount);
- `run_end`: the exit status, the duration, and per host the connections,
  bytes up and down and refusals.

Entries are bounded as the hook's are (a long host name keeps its first 1,024
characters and the SHA-256 of the whole) and fall back to a short entry when
the log refuses the full one. A host's first connection is made only once its
`run_net` entry is recorded: when the log refuses the entry and the fallback
entry, the connection is refused (403, FW-LOG-UNRECORDED) and the next one
tries again. An I/O failure (a full disk) is printed and the connection
stands (docs/limitations.md).

At the end `run` prints the refusals to standard error. With `--verbose` it
also prints each refusal as it happens (a full-screen agent may draw over it).

## Secrets by reference (`--env`)

`run --env NAME=vault://<name>[#field] -- <command>` puts a vaulted secret in
the command's environment as `NAME`. Two ways in, and only these:

- **A person's run** (no ticket): every reference must name a secret bound to
  this exact argv with `vault allow <name> --process "<argv>"` (a trailing `*`
  allows further arguments). Anything else exits 77, logs `vault_denied`
  (FW-VAULT-UNBOUND) and starts nothing. `--dry-run` names the variables and
  reads no value. `run` resolves the program once, to an absolute path, and
  checks the binding against that file and starts that file: a binding written
  with an absolute path (`vault allow <name> --process "/opt/homebrew/bin/gh *"`,
  the safer form) matches only that file; one written with a bare name (`gh *`)
  matches the name as typed, and never a program found inside the workspace (a
  `gh` the agent left in `node_modules/.bin` or another workspace directory on
  your `PATH`); a relative path (`./deploy`) never matches. The values go into
  the sandboxed child's environment only;
  run's own variables (proxy, `TMPDIR`, `LAUNCHSAFE_FIREWALL_*`) cannot be
  replaced, and `PATH`, `HOME`, `LD_*`, `DYLD_*`, `NODE_OPTIONS` are refused as
  names. The command's output is **not** filtered in a person's run: it reaches
  your terminal as the command prints it, so a bound command that prints its
  token shows it to you (and to whatever reads your terminal's scrollback).
- **The hook's ticket** (`--ticket T`): Claude Code's rewrite of a shell
  command with references (`docs/vault.md`, "Hook rewrite"). The ticket is
  single-use, expires (with the policy's `ticketSeconds`; three minutes for an
  action you are asked about), and is bound to the exact `--env` list and argv
  (`consumeTicket()`) and to the agent the hook ran under: the nearest of the
  hook's parent processes still alive when the ticket is spent must be a
  parent of the `run` that spends it, so another process of yours that read
  the ticket off the agent's command line cannot use it. A replay, another
  command, another list or another process exits 77.
  This path runs the command as the hook decided it, in the agent's own shell:
  no person check (the hook's decision is the authorization) and no sandbox
  (which would change what was decided); sandbox flags cannot be added. The
  sender starts with only `PATH`, `HOME`, `LANG`, `LC_*`, `TERM` and `TZ` from
  the agent's environment, plus the values. The
  child's output is filtered back to the references (every value and its
  encodings, also across chunks) before the agent reads it; PostToolUse scrubs
  again.

An agent typing `launchsafe-firewall run` itself is FW-TAMPER either way: an
agent may not start its own sandbox or pick its own secrets.

## Agent presets

```sh
launchsafe-firewall run --agent claude -- claude
launchsafe-firewall run --agent codex -- codex --full-auto
launchsafe-firewall run --agent gemini --dry-run -- gemini
```

`--agent` adds what that agent needs to reach its model, and nothing else:

| Agent | Send hosts for this run (exact names, no byte budget) | Environment |
|---|---|---|
| `claude` (Claude Code) | `api.anthropic.com` | `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, `DISABLE_AUTOUPDATER=1` (no telemetry, error reports or update checks, which run would refuse anyway) |
| `codex` (Codex CLI) | `api.openai.com`, `chatgpt.com`, `auth.openai.com` (an API key, or a ChatGPT login) | none |
| `gemini` (Gemini CLI) | `generativelanguage.googleapis.com`, `cloudcode-pa.googleapis.com`, `oauth2.googleapis.com` (an API key, or a Google login) | none |

Your `--send-host` and `--env` values are added too (an `--env` of the same name
wins over the preset's; run's own variables win over both). Everything else is
run as described above, unchanged: the same writable directories, the same
read-only and unreadable paths, the same proxy checks and budgets for every
other host, the same refusals. The dry run names the preset. The command after
`--` is still required; when it is not the agent's program (or `npx`, `node`,
`bunx`, `pnpx` starting it), run says so and starts it anyway.

What to expect, honestly:

- **Sign in outside the run first.** A login flow opens a browser and may call
  hosts the preset does not list; the agent's credentials and history live in
  `~/.claude`, `~/.codex` or `~/.gemini`, which are read-only inside the run
  (the firewall's hooks and the agents' settings live there). An agent that
  cannot write its history prints an error or carries on without it; a token
  refresh that needs another host is refused with run's 403 line, and
  `--send-host` adds it. Caches need `--allow-write` as for any program.
- **The credentials are readable, not protected.** Read-only means the run
  cannot change them; it does not hide them. The agent needs them
  (`~/.claude/.credentials.json` on Linux; on macOS Claude Code keeps them in
  the keychain, which run blocks unless `--allow-keychain`;
  `~/.codex/auth.json`; `~/.gemini/oauth_creds.json`), so every program the
  run starts can read them too.
- **The model API is an unjudged, unbudgeted way out.** The preset's hosts are
  send hosts with no byte budget, and run sees connections, not what they
  carry: anything the agent reads, its credentials included, can leave in a
  request to them. The dry run says so.
- **An agent with the firewall's hooks installed** runs them inside the run,
  where they cannot save their state: every risky action is blocked, and run
  warns. For that agent use its own sandbox, or OpenShell with the middleware
  ([sandboxes.md](sandboxes.md)). `doctor` tells you which agent needs what
  ("agent sandbox").
- The presets were checked against run's host derivation and dry run in CI;
  the real agents were not started inside run there.

## Limits (read these)

- **Hosts, not methods.** Like Claude Code's sandbox, `run` sees host names.
  A host admitted for fetching (`github.com`, `registry.npmjs.org`) accepts
  uploads too; the budgets bound how much, but a fooled agent with an
  attacker's token can still push a small amount of your code to an attacker's
  repository on an admitted host. Keep `sendAllowHosts` short and treat
  upload-capable hosts as such (`doctor` labels them).
- **Domain fronting through a CDN.** The SNI check stops a client that opens
  a tunnel to an admitted host and then names another server in TLS. It cannot
  see the HTTP `Host` header inside TLS (in plain HTTP it does, and refuses a
  `Host` that names another server), so a CDN that routes on that header
  could still serve another customer's site through an admitted host's
  address. Most large CDNs now refuse mismatched names; not all do. A
  ClientHello that hides the name it really wants is refused: Encrypted Client
  Hello (extension `0xfe0d`) and the older encrypted SNI (`0xffce`), whose
  outer name is only the provider's, and a ClientHello with two `server_name`
  extensions or two names in one. A client that uses ECH falls back to plain
  TLS when the server lets it, or fails. Fronting through the HTTP `Host`
  header inside an admitted TLS connection remains.
- **No hooks means no taint tracking.** In `run` the firewall sees connections,
  not tool calls: no proposals, no queue, no task scope, no secret
  fingerprints in payloads (TLS is not decrypted), no decoy tripwire on reads.
  An agent that has hooks should keep them; `run` is the outer wall.
- **Hooks inside `run` cannot write state.** An agent whose firewall hooks run
  as its own child processes (Claude Code, Codex, Gemini CLI, Cursor) runs them
  inside the sandbox, where the firewall's directory is read-only: every risky
  action then fails closed. `run` warns when it sees such an agent with the hooks
  installed. Use that agent's own sandbox instead, OpenShell with the firewall's
  middleware ([sandboxes.md](sandboxes.md)), or `run` without the hooks.
- **macOS: a deny list for system services.** The Seatbelt profile starts from
  "allow" and denies network, writes, the unreadable paths, signals, Apple
  Events and the services named above. A system service not on that list that
  performs network or file work for its caller would not be stopped. Claude
  Code's own macOS sandbox starts from "deny" with an allow list, which is
  stricter. `sandbox-exec` is also deprecated by Apple (it still works on
  macOS 26 and Apple's own tools use the same engine).
- **macOS: the keychain flag and local ports.** `--allow-keychain` gives the
  sandboxed process the keychain, so `confirm: never` vault items become
  readable through `/usr/bin/security`. `--allow-localhost` exposes every
  service on 127.0.0.1 (databases, local model servers, other agents' MCP
  servers).
- **Linux: bubblewrap needs unprivileged user namespaces.** Some distributions
  restrict them (Ubuntu 24.04's AppArmor setting, hardened kernels); `doctor`
  runs a probe and prints bubblewrap's error. A Unix socket is reachable from
  another network namespace and through a read-only mount, so what hides
  sockets is where they are: `/run` (and `/var/run`, `$XDG_RUNTIME_DIR`, the
  system Docker and Podman sockets, the D-Bus session bus) is an empty tmpfs,
  `/tmp` is private, `~/.docker` is unreadable by default and Docker Desktop's
  `~/.docker/run` and `~/.docker/desktop` always are. A socket somewhere else
  under your home or in a directory you pass to `--allow-write` (refused when
  it holds one when the run starts, not when one appears later) stays
  reachable; `run` cannot know every such path.
  **What has been verified:** the live integration tests have run on Linux in
  two places: inside a Docker container (Debian 12, bubblewrap 0.8, an
  unprivileged user, with `--security-opt seccomp=unconfined --security-opt
  systempaths=unconfined`, which bubblewrap needs in a container to work at
  all), and on GitHub's `ubuntu-latest` runner (bubblewrap from apt, with the
  AppArmor restriction on unprivileged user namespaces lifted by the CI job).
  Not verified by the maintainers: a bare-metal or virtual-machine Linux host,
  any other distribution or bubblewrap version, or a real agent running inside
  the sandbox (the live tests run shell commands). The integration tests run
  wherever `bwrap` can create a sandbox. On macOS the maintainer loaded the
  profile with `sandbox-exec` on a Mac by hand (once); no CI job runs on macOS
  while the repository is private.
- **Linux: no controlling terminal.** `--new-session` is what keeps `TIOCSTI`
  out of your terminal, and it also means a program that opens `/dev/tty` for
  a prompt gets an error. Interactive agents that read their standard input
  work.
- **What the run keeps read-only for git and agents is a list.** Files that a
  hook script loads (a module it imports) are not followed: keep hook scripts
  self-contained or outside the workspace. A command's script is found only
  when the command names it as a path from the workspace (not after a `cd`). A
  repository the agent creates inside the run (`git init` in a subdirectory, a
  `.git` file pointing at a directory it wrote) is its own: check it before you
  run git there. Submodule and linked-worktree git directories are read-only as
  a whole, so `git submodule update` and `git worktree add` (and commits inside
  a submodule) fail inside the run; do them outside.
- **git commands that change `.git/config`, and `git init`, run outside
  `run`.** `.git/config` is read-only (its `core.fsmonitor`,
  `core.hooksPath`, filters and aliases run programs), so `git config`,
  `git remote add`, `git push -u`, `git branch --set-upstream-to` and
  `git checkout --track` fail inside the run with git's own message, `could
  not write config file <workspace>/.git/config` (`Operation not permitted`
  on macOS, `Device or resource busy` on Linux, where the file is a mount
  point; or `could not lock config file`). In a
  workspace that is not a repository yet, `.git` itself cannot be created, so
  `git init` fails (`.git: Operation not permitted` on macOS, `Read-only file
  system` on Linux): an agent that could create `.git` could prepare its hooks
  and config too. `run` prints a one-line note about this when it starts. Run
  those commands outside `run`, or start `run --git-init`, which runs
  `git init` in a workspace without `.git` (as you, outside the sandbox)
  before the run starts.
- **Caches and agent state in your home are read-only.** `npm`, `pip` and many
  agents write caches or history under your home. They fail, fall back, or
  need `--allow-write ~/.npm` (for example). A tool that ignores `TMPDIR` and
  insists on `/tmp` needs a setting of its own pointed at a directory you
  create for it: `/tmp` holds other programs' sockets, and `--allow-write /tmp`
  is refused on Linux for that reason.
- **Your environment is filtered; your files are not all hidden.** Only the
  base list of variables (and `--pass-env`) reaches the command, and the
  credential stores above are unreadable, but other files under your home stay
  readable (a project's `.env`, a tool's token file in a place not on the list).
  Pass `--allow-home-read` and `--pass-env` only for what the command needs.
- **Instruction files persist.** Files that steer an agent next time
  (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursor/rules`, a README the agent
  reads first) are ordinary workspace files: the command can rewrite them, and
  the next agent session, inside or outside `run`, reads what it wrote. They
  are not code, so `run` does not lock them; review changes to them like any
  other change before the next session (the firewall's hooks scan them at
  session start).
- **Runners in agent settings.** A hook, MCP server or task started through a
  runner (`npm run`, `npx`, `make`, `python -m`, `uv run`,
  `node_modules/.bin/...`) runs code from files `run` cannot keep read-only
  (`package.json` scripts, a `Makefile`, installed packages); a change made
  there inside the run runs later, outside it. `run` warns when it starts in
  such a workspace; prefer settings that name a script file.
- **macOS: rules to verify on a Mac.** The `TIOCSTI` ioctl denial, the
  hard-link denial (`file-link`), `job-creation`, `process-info*` and
  `mach-priv-task-port` for other processes, the `mDNSResponder` and
  `cfprefsd` denials, and `/usr/bin/script` with redirected standard input are
  generated and checked as profile text by the tests, including in CI, which
  runs on Linux (the macOS CI jobs are off while the repository is private).
  The maintainer ran the profile on a Mac by hand, once, and `sandbox-exec`
  parsed it; no test shows that each of these rules blocks what it is meant to
  block (for example that the `mDNSResponder` denial covers every lookup
  path). A rule `sandbox-exec` cannot parse stops every run (nothing starts),
  it never weakens one.
- **No upstream proxy.** A proxy you already use (`HTTPS_PROXY` in your
  environment) is replaced, and `run`'s proxy connects directly. Corporate
  proxies are not chained in this release.
- **Other local processes can use the proxy.** On macOS it listens on
  127.0.0.1 without credentials (many tools do not support proxy credentials).
  It only reaches the hosts your policy lists, so this changes nothing about
  where data can go; it can use up the run's budgets.
- **Budgets are per run** and counted on the wire; what stays under them is
  not seen.
- **Vault values reach only the child's environment.** `run --env
  NAME=vault://...` is built (see "Secrets by reference" above and
  [vault.md](vault.md)): values go into the child's environment, never its
  arguments. In a ticketed run (the hook's) the output is filtered back to the
  references, dumps included; a program that transforms a value before
  printing it (reverses it, say) is outside the filter, which is why a ticketed
  run is only ever a single curl or wget command. A person's run is not
  filtered at all (see above) and needs a process binding. Any process running
  as you can read a running process's environment (`ps eww` on macOS,
  `/proc/<pid>/environ` on Linux), so while the command runs, its values are as
  exposed to your other programs as the vault's own store is.
