# Policy

The policy is a single JSON file. The firewall ships with safe defaults, so a
policy file is optional — you write one only to allow something the defaults
block, to tell it which MCP servers are trusted, or to tighten further.

- **User / machine policy:** `~/.launchsafe-firewall/policy.json`. Create a
  starting one with `launchsafe-firewall policy init`.
- **Administrator policy:** a managed file at
  `/Library/Application Support/LaunchSafeFirewall/policy.json` (macOS) or
  `/etc/launchsafe-firewall/policy.json` (Linux). Applies over the user policy.
- **Project policy:** `.launchsafe-firewall.json` at a workspace root. **May only
  tighten** — see below.

Check what is in effect: `launchsafe-firewall policy show`. Validate a file:
`launchsafe-firewall policy validate`.

**What no policy changes.** The always-on denies (FW-CATASTROPHIC, FW-DESTROY-ROOT,
FW-TAMPER and the others marked "deny" in `launchsafe-firewall explain`) have no
switch that turns them into a question: not a user, administrator or project
file, not an approval, and not a permission mode. For the permission modes, the
hooks were captured firing in Codex's `codex exec` and in Gemini CLI's yolo
mode; Claude Code's bypass mode is read from its documentation, not captured;
it is not verified for Cursor (`docs/agents/`). The exceptions
are the keys that say what such a rule covers or whether it runs, listed with
each key below: for example `protectedBranches` adds branches FW-CATASTROPHIC
protects, `sandbox.protectInstalledProfile: false` stops treating a weakened
sandbox profile as FW-TAMPER, `vault.enabled: false` turns FW-VAULT-EGRESS off,
`budgets.enabled: false` switches off the FW-STOPPED monitor, `caps.enabled`
controls FW-CAP, `gateway.enabled` covers the gateway rules,
`packageIntel.malicious` and `canaries.enabled` change or switch off their
rules (those that switch a rule off are user or managed policy only; a project
file cannot), and `dataAllowHosts` names destinations the data rules
allow. Two things make a matching action an ordinary destructive ask instead: a
targeted form (`terraform destroy -target=...`) and your signed scratch-target
list (below).
FW-CREDENTIAL-FLOW (a send after the session read credentials) follows
`sendAllowHosts` and `dataAllowHosts.credential` for the hosts you trust,
and treats an MCP server your own policy marks `"results": "trusted"` (or
lists as `mcp:<server>` in either list) as allowed.

## Schema (version 3)

Every policy sets `"version"`. The current schema is version 3. Every key is
validated strictly: an unknown key, at the top level or inside any object
(`gateway.responses`, `vault.confirmDefault`, `mcpServers.<name>`, ...), is an
error, and so is a value of the wrong type or out of range.

This release reads versions 1, 2 and 3. Versions 1 and 2 were written by
pre-release builds.

- **Version 1 and 2 files keep working, unchanged.** Version 3 only added keys
  (`gateway`, `emailGuard`, `vault`, `phone`), all with defaults, so an older
  file means exactly what it would mean as version 3. It is migrated in memory
  and `policy validate` says a migration is available.
- **`launchsafe-firewall policy migrate`** rewrites your user file as version 3.
  It is lossless: every key, value and key order is kept and only the number
  changes, and it checks that the old and new file validate to the same
  settings before writing. The original bytes are first saved next to it as
  `policy.json.v2.bak` (`.v2.2.bak` and so on if a backup already exists; an
  earlier backup is never replaced). An invalid file, or one newer than the
  firewall, is refused and nothing is written. Like `policy init`, it needs you
  at the keyboard (an agent running it gets FW-TAMPER).
- **Managed and project files** are not rewritten by `policy migrate`: their
  owners change `"version": 2` to `3` (nothing else changes).

**A schema version newer than the firewall's is refused.** This firewall reads
a version 4 file as invalid ("policy version 4 is newer than this firewall
understands (3); upgrade @launchsafe/agent-firewall") and handles it like any
invalid file (see "Invalid policy fails safe" below): it is not applied, so its
keys keep what the layers below it, or the built-in defaults, set; every other layer that parsed still applies (a
newer managed file also drops the user's layer); and the policy error sends
every action other than a read to a person (FW-POLICY-ERROR) until the firewall
is upgraded or the file is changed back.

```jsonc
{
  "version": 3,

  // Hosts that may be FETCHED from even in an untrusted session (GET-like).
  // Suffix match on a dot boundary: "github.com" also matches "api.github.com";
  // "=github.com" matches only that host; "*.github.com" only subdomains.
  // Setting this REPLACES the built-in list, so include the defaults you want.
  "fetchAllowHosts": ["registry.npmjs.org", "github.com", "..."],

  // Hosts that may be SENT to (POST/upload/push) even in an untrusted session.
  // Empty by default on purpose.
  "sendAllowHosts": [],

  // Hosts denied in every contact the firewall can see (tool calls and the shell
  // commands it reads), and refused by run's proxy and the sandbox profile
  // doctor --fix writes. A program the hooks cannot see, outside those
  // sandboxes, is not stopped from reaching them.
  "denyHosts": [],

  // Destinations allowed to RECEIVE a kind of sensitive data that is otherwise
  // never sent. Only these override the always-on data-loss rules. Entries are
  // hosts, or "mcp:<server>" for an MCP server (its tool arguments).
  "dataAllowHosts": {
    "credential": [],     // e.g. your own secret manager's host, or "mcp:vault"
    "card": [],           // e.g. your payment processor
    "iban": [],
    "national_id": []
  },

  // Published test values are not sensitive data: payment processors' test
  // cards (4242 4242 4242 4242, 5555 5555 5555 4444, ...), ISO example IBANs
  // (DE89 3704 0044 0532 0130 00, ...), specimen SSNs (078-05-1120, ...) and
  // keys marked as test keys (sk_test_..., sk-test-...). Exact published values
  // only; a real number is still detected by its checksum. A project policy can
  // only turn this off.
  "allowTestValues": true,

  // MCP servers, by the server name (the middle of mcp__<server>__<tool>).
  // An exact name, or a pattern ending in "*". Only the entries written here
  // count: a server named "constructor", "toString" or "__proto__" is an
  // unlisted server like any other (never a built-in property of the map).
  "mcpServers": {
    "my-internal-tools": { "results": "trusted", "privateData": false },
    "github":            { "results": "untrusted", "privateData": true,
                            "blockedTools": ["delete_repo"] }
  },
  // A user-configured server named filesystem or fs, started with directories that are all inside
  // the workspace, is trusted without an entry here (its roots are read from its launch arguments).
  // The policy for a server not listed:
  "mcpDefault": { "results": "untrusted", "privateData": true },

  // Extra path globs (in addition to the built-ins). The first three are matched ignoring case, on every
  // platform (a Linux host cannot tell whether a directory folds case); trustedReadRoots keeps the platform's rule:
  "untrustedPaths": [],   // reading these taints the session
  "protectedPaths": [],   // writing these needs a person / is held
  "secretPaths": [],      // these are credential files
  // absolute roots outside the workspace safe to read. Default: /usr/include, /usr/share, /usr/lib, /System,
  // /Library/Developer, /Applications/Xcode.app, /opt/homebrew/include, /opt/homebrew/share.
  // A list you set REPLACES these, so include the defaults you want.
  "trustedReadRoots": [],

  // Modes:
  "untrustedWorkspace": false,   // treat the whole checkout as outside content (reviewing someone else's repo)
  // Mask secrets in tool output before the model sees them. Only Claude Code can replace a tool's output (Codex and
  // Gemini CLI cannot; Cursor only an MCP tool's). This relies on Claude Code replacing the tool's output, which its
  // documentation describes but which was not captured live; if it is ignored the model sees the original text
  // and the taint rule still applies.
  "redactSecretsInOutput": false,
  "allowInstructionWritesWhenTrusted": true, // false = even a trusted session must confirm instruction writes
  "unattended": false,           // always queue instead of ask
  "unattendedHours": [{ "from": "22:00", "to": "07:00" }], // example (default []): local hours with no one at the keyboard
  // Claude Code permission modes where no one answers. bypassPermissions and auto are held (not asked) because an ask
  // there is not verified to reach a person. A list you set REPLACES this one, so keep the modes you want held.
  "unattendedPermissionModes": ["dontAsk", "bypassPermissions", "auto"],
  "protectedBranches": ["production", "prod", "develop", "release/*"], // besides main, master, trunk (always): force pushes and deletes are FW-CATASTROPHIC

  // Tools (exact names) that only show something to you, so they never taint the
  // session or count as sending: added to the built-in host-tool catalogue.
  "userOutputTools": [],
  // Tool names that must never be treated that way (a project may add these).
  "notUserOutputTools": [],
  // The provenance ledger: files the agent wrote itself.
  "provenance": {
    "trustSelfAuthored": true,     // reading a file whose content is exactly what a trusted session wrote does not taint
    "carryUntrustedWrites": true,  // files an untrusted session wrote stay untrusted in later sessions (running them, or a manifest)
    "maxHashBytes": 4194304        // larger files are not tracked: reading one outside the workspace taints, and one an untrusted session wrote is not carried to later sessions
  },
  // The session-start scan of what the agent is armed with (agent-safety rules).
  "agentScan": {
    "enabled": true,      // false: no scan (MCP configuration pins still work)
    "taintOn": "high",    // "high": critical, or high severity with high confidence; "critical": critical only; "never": log only
    "userScope": true     // also scan ~/.claude (instructions, settings, agents, commands, skills), ~/.claude.json servers and the project's auto memory
  },
  // MCP pins (configuration, tool names, observed tool descriptions).
  "mcpPinning": {
    "enabled": true,
    "newToolGraceHours": 24,  // tools a server exposes this soon after its first-use pin are added without an alert
    "taintOnChange": true     // false: changes are recorded for review but do not taint
  },
  // Decoy files planted with `canary plant` (see "Decoys" in docs/how-it-works.md).
  "canaries": {
    "enabled": true,         // false switches the registry, tripwire and egress check off. User or managed policy only
    "tripOnRecursive": false,// true: a recursive read (grep -r, rg --no-ignore, tar) whose scope holds a decoy trips it too
    "offerAtInstall": true,  // `install` offers workspace decoys as a yes/no prompt (terminal only)
    "homeDecoys": false      // the install offer also covers ~/.aws, ~/.ssh, ~/.config/gh; `canary plant --home` is the explicit way
  },
  // Desktop notifications for held and blocked actions (see below).
  "notifications": {
    "enabled": true,
    "on": ["queued", "proposal", "denied_dlp", "canary", "loop", "agent_config", "mcp_changed", "mcp_withheld", "mail_quarantined", "stopped", "cap"],
    "onlyWhenUnattended": false,   // true = only when the session is unattended
    "minIntervalSec": 120          // at most one per kind per interval; suppressed ones are counted into the next
  },
  // Per-task scope from your prompt (see "Task scope" below).
  "taskScope": {
    "mode": "log",             // "off" | "log" (compute and log what it would ask; no decision changes) | "enforce"
    "unattendedIntents": true  // the intent rules (push, PR, publish, deploy, message, install) also apply to unattended trusted sessions
  },
  // Sources anyone outside your organisation can write (see "Outsider-writable sources" below).
  "outsiderWritable": {
    "alwaysTaint": true,       // results from an error tracker, issue tracker, support desk, outside chat, mail or the web taint even when you trust the server
    "servers": [],             // more server names or patterns in the class, e.g. ["corp-tickets*"]
    "exempt": [],              // server names or patterns taken out of the class (user or managed policy only)
    "commands": "ask"          // FW-OUTSIDE-COMMAND: running a command such content showed needs you; "off" (user or managed only)
  },
  // Package checks (installs and package runners), trusted or not.
  "packageIntel": {
    "malicious": "deny",       // a version listed as malicious: "deny" | "approve" | "off"
    "typosquat": "approve",    // a look-alike of a popular name: "approve" | "off"
    "lockfiles": true,         // check what an install from a lockfile would fetch
    "maxSnapshotAgeDays": 30   // past this, doctor fails (the data is still used)
  },
  // Claude Code's OS sandbox profile, written by `doctor --fix`.
  "sandbox": {
    "protectInstalledProfile": true, // weakening the profile doctor --fix installed is FW-TAMPER
    "strictAllowlist": true,         // the profile sets network.strictAllowlist: hosts outside the list are refused, not prompted
    "safeExcludedCommands": []       // excludedCommands entries doctor does not count as an unsandboxed escape
  },
  // `run`: paths whose agent-run scripts stay writable inside the sandbox (user or managed policy only).
  "run": {
    "allowWritePaths": [],         // e.g. ["dist"] when .mcp.json runs node dist/index.js and the agent rebuilds it
    "privateHosts": []             // e.g. ["corp.example"]: admitted names whose DNS answers may be private addresses
  },
  // Ask before the agent contacts a host this project has never contacted (FW-NEW-HOST; docs/usage.md).
  // The approved hosts themselves live in ~/.launchsafe-firewall/known-hosts/, never in a policy file.
  "knownHosts": {
    "mode": "off",      // "off" | "watch" (record hosts for watchDays, propose a list: hosts review) | "ask"
    "builtins": true,   // the built-in set (registries, GitHub, the agents' model APIs) counts as known; false turns off that set only, hosts fetchAllowHosts names stay known
    "watchDays": 7      // 1 to 90
  },
  // Files that make code run later (CI, git hooks, editor tasks, dev containers, environment hooks).
  "persistence": {
    "trustedContentChecks": true,   // a trusted session's change that adds a code-running capability asks (FW-AUTORUN); false = no such check
    "holdWhenUntrusted": ["git-hook", "editor-task", "devcontainer"]  // an untrusted session's change is held as a proposal (FW-PERSISTENCE-HELD)
  },
  // Fewer prompts (docs/usage.md): offering "always in this project" for a low-risk action you approved
  // repeatedly. The choices themselves are never in a policy file (launchsafe-firewall allow list).
  "learnedAllows": {
    "enabled": true,      // false: nothing is offered and no "always" choice applies ("never" choices still do)
    "proposeAfter": 3     // approvals of the same action in a project before the offer (2 to 100)
  },
  // Per-session budgets. Reaching one asks a person, or is held when nobody can answer; it never denies outright. The loop group's stop* limits are the
  // behaviour monitor's: crossing one stops the session until a person resumes it.
  "budgets": {
    "enabled": true,
    "untrusted": { "bytesPerHost": 65536, "bytesTotal": 262144, "requestsPerHost10m": 40, "mcpCalls10m": 200, "mcpSends10m": 20 },
    "trusted":   { "bytesTotal": 4194304, "requestsPerHost10m": 300, "mcpCalls10m": 200 },
    "loop":      { "sameAction10m": 8, "nonAllow10m": 25,     // FW-LOOP: the next action needs a person
                   "stopNonAllow10m": 60, "stopNewHosts10m": 40, "stopConfigTouches10m": 20, "stopSameFailure10m": 20 },  // the behaviour monitor: the session stops (FW-STOPPED)
    "exemptHosts": [],  // added to the built-in install and clone exemptions; user or managed policy only
    "stopScope": "session"  // what a monitor stop stops: "session", or "agent" (every session of that agent)
  },
  // Spending limits per session and per day. Reaching one denies the action (FW-CAP); null = no limit.
  "caps": {
    "enabled": true,
    "warnPercent": 80,   // warn once at this share of a limit (FW-CAP-WARN)
    "warn": "ask",       // "ask": the warning asks you when someone can answer; "note": noted only
    "session": { "toolCalls": 5000,  "bytesOut": 67108864,  "identicalFailures": 10, "tokens": null, "costUsd": null },
    "day":     { "toolCalls": 20000, "bytesOut": 268435456, "identicalFailures": 25, "tokens": null, "costUsd": null }
  }
}
```

### Version 2 keys: defaults and what a project file may do

| Key | Default | Tightening (a project may) | Loosening (user or managed policy only) |
|---|---|---|---|
| `userOutputTools` | `[]` | – (entries in a project file are ignored and reported) | add tool names |
| `notUserOutputTools` | `[]` | add tool names | – |
| `provenance.trustSelfAuthored` | `true` | set `false` (every outside read taints, even of files the agent wrote) | set `true` |
| `provenance.carryUntrustedWrites` | `true` | set `true` | set `false` |
| `provenance.maxHashBytes` | `4194304` | lower it | raise it (up to 64 MiB) |
| `agentScan.enabled` | `true` | set `true` | set `false` |
| `agentScan.taintOn` | `"high"` | move towards `"high"` (`"never"` < `"critical"` < `"high"`) | move towards `"never"` |
| `agentScan.userScope` | `true` | set `true` | set `false` |
| `mcpPinning.enabled` | `true` | set `true` | set `false` |
| `mcpPinning.newToolGraceHours` | `24` | lower it | raise it (up to 720) |
| `mcpPinning.taintOnChange` | `true` | set `true` | set `false` |
| `canaries.enabled` | `true` | set `true` | set `false` |
| `canaries.tripOnRecursive` | `false` | set `true` | set `false` |
| `canaries.offerAtInstall` | `true` | – (read only from user and managed policy; ignored and reported) | set either way |
| `canaries.homeDecoys` | `false` | – (read only from user and managed policy; ignored and reported) | set either way |
| `notifications.enabled` | `true` | set `true` | set `false` |
| `notifications.on` | all eleven kinds | add kinds | remove kinds |
| `notifications.onlyWhenUnattended` | `false` | – (ignored and reported) | set either way |
| `notifications.minIntervalSec` | `120` | – (ignored and reported) | set it (10 to 86400) |
| `packageIntel.malicious` | `"deny"` | move towards `"deny"` (`"off"` < `"approve"` < `"deny"`) | move towards `"off"` |
| `packageIntel.typosquat` | `"approve"` | set `"approve"` | set `"off"` |
| `packageIntel.lockfiles` | `true` | set `true` | set `false` |
| `packageIntel.maxSnapshotAgeDays` | `30` | lower it | raise it (up to 3650) |
| `sandbox.protectInstalledProfile` | `true` | set `true` | set `false` |
| `sandbox.strictAllowlist` | `true` | set `true` | set `false` |
| `sandbox.safeExcludedCommands` | `[]` | – (entries in a project file are ignored and reported) | add command patterns |
| `persistence.trustedContentChecks` | `true` | set `true` | set `false` |
| `persistence.holdWhenUntrusted` | `["git-hook", "editor-task", "devcontainer"]` | add tags (`ci`, `env-hook`) | remove tags |
| `budgets.enabled` | `true` | set `true` | set `false` |
| `budgets.untrusted.*`, `budgets.trusted.*`, `budgets.loop.*` | see above | lower a limit | raise a limit (whole numbers from 1) |
| `budgets.exemptHosts` | `[]` | – (ignored and reported) | add hosts |
| `budgets.stopScope` | `"session"` | – (ignored and reported) | set `"agent"` or `"session"` |
| `caps.enabled` | `true` | set `true` | set `false` |
| `caps.session.*`, `caps.day.*` | see above | lower a limit, or set one that is `null` | raise a limit, or set it to `null` (no limit) |
| `caps.warnPercent` | `80` | lower it | raise it (1 to 99) |
| `caps.warn` | `"ask"` | set `"ask"` | set `"note"` |
| `taskScope.mode` | `"log"` | move towards `"enforce"` (`"off"` < `"log"` < `"enforce"`) | move towards `"off"` |
| `taskScope.unattendedIntents` | `true` | set `true` | set `false` |
| `rollout.mode` | `"enforce"` | set `"enforce"` | `"watch"`: only through `rollout watch` (user policy, with a signed grant) or a managed file; see [Watch mode](#watch-mode-rollout) |
| `knownHosts.mode` | `"off"` | move towards `"ask"` (`"off"` < `"watch"` < `"ask"`) | move towards `"off"` |
| `knownHosts.builtins` | `true` | set `false` | set `true` |
| `knownHosts.watchDays` | `7` | – (ignored and reported) | set it (1 to 90) |

`knownHosts.builtins`. The built-in set is the list of common development
hosts in `src/engine/knownhosts.ts`: the package registries, the code hosts
(GitHub, GitLab, Bitbucket), GitHub's API and content hosts, Homebrew's index and
the model APIs of the supported agents. Setting `builtins` to `false` turns off
that set and nothing else. A host that `fetchAllowHosts` or `sendAllowHosts`
names is known either way, and the defaults of `fetchAllowHosts` already name
the package registries and the GitHub, GitLab and documentation hosts. So with
`builtins: false` and no `fetchAllowHosts` of your own, those stay known, and
only Bitbucket, `api.github.com`, Homebrew's index and the model APIs ask. To be
asked about the registries too, set `fetchAllowHosts` yourself without them (a
list you set replaces the defaults, see
[Lists replace](#lists-replace-they-do-not-append)). That list also decides
`FW-FETCH` after outside content, the sandbox profile `doctor --fix` writes and
the hosts `run`'s proxy admits, so taking a host out of it changes those too.
`launchsafe-firewall hosts list` names the built-in hosts that stay known.

`userOutputTools` and `notUserOutputTools`. The built-in catalogue
(`src/engine/hosttools.ts`) holds the host tools captured from Claude Code
2.1.289 events: `SendUserFile` and `SubagentHandback` (show something to you),
`mcp__ccd_session__mark_chapter`, `mcp__ccd_session__dismiss_task` and
`mcp__ccd_host__request_keep_awake` (app UI only), `mcp__ccd_session__spawn_task`
(proposes a session; its prompt is logged), and `Artifact` publishing (a send to
claude.ai, never "to you"). The `mcp__` ones count only when Claude Code reports
the server's source as `sdk`. A name in `userOutputTools` is treated as showing
something to you: any path in its arguments is read for the credential rules
only (sharing `~/.aws/credentials` still asks; a workspace `.env` still marks
the session sensitive) and nothing taints. A name in `notUserOutputTools` is
never a host tool, including catalogued ones, and is judged as an unknown or
MCP tool. `doctor` warns when Claude Code is newer than the catalogue.

### Files that run code later (`persistence`)

The persistence paths carry a tag: `ci` (GitHub, GitLab, CircleCI, Buildkite,
Drone, Woodpecker, Travis, AppVeyor, Cloud Build, CodeBuild, Codemagic, Bitrise,
Tekton, Jenkins, Azure Pipelines, local action definitions, Dependabot and
Renovate), `git-hook` (`.git/hooks`, `.husky`, `.githooks`, lefthook,
pre-commit, `.git/config`, `.git/info/attributes`, and the same files of a
submodule's git directory `.git/modules/<name>/` and of linked worktrees
`.git/worktrees/<name>/config`), `editor-task` (`.vscode`
tasks, settings, launch and extensions, `.idea`, `.zed`, `.fleet`,
`*.code-workspace`, project-local `.nvim.lua`, `.exrc`, `.vimrc`),
`devcontainer` (`.devcontainer`, `devbox.json`, `.gitpod.yml`, `.replit`) and
`env-hook` (`.envrc`, mise, `.npmrc`, `.yarnrc`, `.yarnrc.yml`,
`.pnpmfile.cjs`). `.gitattributes` and `flake.nix`/`shell.nix` are judged by
their content when written with the Write or Edit tools (a filter, diff or merge
driver; a changed `shellHook`); a shell write to them cannot be checked, so it
asks when the session is untrusted, and `nix-shell`/`nix develop` after an
untrusted change to them asks (FW-TAINTED-MANIFEST). `.tool-versions` and
`.nvmrc` only pin versions and are not persistence points.

The content checks read files the way their tools do: a git config file is
parsed by key (a key on its section line, `[section "sub"]` headers, comments),
and any setting that makes git run a program or read another file counts
(`core.hooksPath`, `core.pager`, `core.editor`, `core.fsmonitor`,
`core.sshCommand`, filters, diff and merge drivers, credential helpers,
`include.path`/`includeIf.*.path`, an alias starting with `!`). JSON and JSONC
files (editor tasks and settings, dev containers, `devbox.json`) are read with
comments removed and escapes decoded, so `"run\u004fn"` is `runOn`; devbox's
`shell.init_hook` is a lifecycle command. A workflow's triggers are read from
its `on:` key (a permission called `issues: write` is not an `issues` trigger),
a head ref used only in a `concurrency` group checks nothing out, and
`github.event['pull_request']['head']` is the same as the dotted form. `.yarnrc`
`yarn-path` is checked like `.yarnrc.yml`'s `yarnPath`. `npm config set` (and
pnpm's) writes the user's `~/.npmrc` unless `--location=project` is given, and
`yarn config set` may write `~/.yarnrc` or the project's `.yarnrc.yml`: every
file it may write is judged, with the value taken as written (`node-options
"--require x"`).

With `trustedContentChecks` on, a trusted session's Write or Edit inside the
workspace is allowed unless the content it leaves adds a code-running capability
(FW-AUTORUN; `launchsafe-firewall explain FW-AUTORUN` lists them). A shell write
to a git hook or an editor task cannot be checked and asks. With it off, trusted
sessions get no such content check. `holdWhenUntrusted` names the tags whose changes an
untrusted session makes are held as proposals: hook bodies always, editor tasks
and dev containers only in their auto-run forms (a `folderOpen` task, a
lifecycle command); other changes to them ask (FW-PERSISTENCE). A project may
add tags and add paths through `protectedPaths`; it may not remove either.

### Budgets (`budgets`)

Counters per session (`sessions/<id>.counters.json`, inside the data directory).
Bytes are the payload that leaves (the URL for a GET, the command line or body
for a send, the arguments of an MCP call, plus the size of a file it uploads:
`curl -T`, `-d @file`, `-F x=@file`, `wget --post-file`) and count for
allowlisted hosts too. A send whose destination has no host name (a package
registry, a git remote, a cloud CLI) is counted under that destination, and a
registry named on the command line (`npm publish --registry URL`) under its host.
One native call that becomes several actions (a Gemini `web_fetch` with many
URLs, a multi-file patch) is judged part by part against the counters plus what
the earlier parts add, so together they reach a budget as the same requests made
one by one would.
Not counted: registries and source hosts reached by a package manager or git
(`registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `crates.io`,
`proxy.golang.org`, `github.com` for clones, `codeload.github.com`, `ghcr.io`
and similar), loopback (an IP literal in 127.0.0.0/8, `::1`, `0.0.0.0`,
`localhost` and `*.localhost`; a DNS name such as `127.0.0.1.example.com` is an
ordinary host), the hosts in `sendAllowHosts`, and `exemptHosts`. A request sent
through a proxy (`curl -x`, `--preproxy`, `--socks5`, an `https_proxy=` or
`ALL_PROXY=` variable) or redirected with `--connect-to`/`--resolve` counts
for, and is judged against, the host it really reaches.
`requestsPerHost10m`, `mcpCalls10m`, `mcpSends10m` (sends and messages through
one MCP server, untrusted sessions only) and the `loop` limits are per 10
minutes; the byte limits are per session. `loop.sameAction10m` counts the same
action with no file written in between (an edit resets it);
`loop.nonAllow10m` counts actions that asked, were held or were blocked.
Approving an action that reached a budget (answering the prompt, or `queue
approve`) raises that budget for the session by the same amount again, counted
from where you approved it: when usage was already past the limit (bytes sent
while the session was still trusted), one yes is enough until another full
budget has been used. Approving a multi-part call raises each budget it
exceeded once. When the counters file cannot be read, the next action that
sends data in an untrusted session asks once, then counting starts again; reads
in between leave the file as it is. Each group may be given in part; the other
limits keep their defaults. A project may only lower limits.

The behaviour monitor uses the same counters with higher limits, per 10
minutes, and stops the session instead of asking (`FW-STOPPED`, see
[usage.md, "Stopping an agent"](usage.md#stopping-an-agent)):
`loop.stopNonAllow10m` (60 actions that asked, were held or were blocked),
`loop.stopNewHosts10m` (40 hosts the session had never tried before; the
exempt hosts above are not counted), `loop.stopConfigTouches10m` (20 attempts
to change the agent's settings, instructions or memory, a file that runs code
later, or the firewall) and `loop.stopSameFailure10m` (20 blocks or holds of
exactly the same action). It counts attempts, whatever their verdict, and only
on an action that adds to the count it crosses, so a read never stops a
session. An approval never raises these limits; only a person's resume ends a
stop, and the monitor counts again from the resume. A project may lower them
and may not raise them or switch budgets off; your own or the managed policy
may raise them, or set `budgets.enabled: false`, which switches the monitor off
with the budgets.

`budgets.stopScope` says what a behaviour monitor stop stops. `"session"` (the
default) stops only the session that crossed the limit. `"agent"` stops every
session of that agent: the hook's agent (`claude`, `codex`, ...), or the agent
id for the library and the local API. The stop holds until a person runs
`agent resume` (see [usage.md, "Stopping an agent"](usage.md#stopping-an-agent)),
so starting a new session does not get round it. Only your own or the managed
policy sets it: an agent-wide stop also stops the agent's sessions in your
other repositories, so a repository's content could use a project-file
`"agent"` to stop your other work. A project file's `stopScope`, either value,
is ignored and reported as a policy warning. Network middleware
traffic (the OpenShell middleware, [api.md](api.md)) keeps its stops to the
sandbox's session whatever this key says.

### Spending limits (`caps`)

Limits that stop the agent, per session and per day (every session of this
firewall home; the day is the local calendar day and starts again at local
midnight). Where a budget asks you, a cap denies the action (`FW-CAP`) with
what to do. `toolCalls` counts each tool call that goes ahead (allowed, or
asked); `bytesOut` counts data sent off the machine as the byte budgets count
it; `identicalFailures` is how often one exact action failed with the same
error (numbers in the error are ignored); `tokens` and `costUsd` count the
model usage an agent reports with a call through the library or the local API
(`usage`), and the firewall never calls a model or prices one. A limit is a
whole number from 1 (`costUsd`: US dollars above 0), or `null` for no limit;
each group may be given in part. At `warnPercent` of a limit the firewall
warns once (`FW-CAP-WARN`): it asks you when `warn` is `"ask"` and someone can
answer, else it notes it in the decision and lets the action go ahead. A
person raises a limit for now with `launchsafe-firewall caps raise` (signed
with the approval key, in the decision log); see
[usage.md](usage.md#spending-limits). A project may only lower limits, set a
limit where there was none, warn earlier or ask instead of noting, and never
below a floor (`toolCalls` 100, `bytesOut` 65536, `identicalFailures` 3,
`tokens` 10000, `costUsd` 0.1): a repository is untrusted content, and a project
file that set every limit to 1 would stop your agent at its first call. A value
under the floor is raised to it (or to your own lower limit) and reported. A
project can still make limits tighter than you would like within those floors;
`policy show` lists what it changed.

### Task scope (`taskScope`)

Each prompt you type sets the session's task scope: the workspace paths it names
(a named file adds its directory, unless that is the workspace root), the GitHub
repositories and hosts it names, and the publish-type verbs it uses as a request
(push, open a PR, publish or release, deploy or ship, send/post/email/message,
delete/remove/drop, install or "add the dependency", migrate; and the command
words `git push`, `gh pr create`, `npm publish`, `vercel deploy`, `npm install
<name>` and the like, when they open a request: "run npm publish", not "the CI
step that runs npm publish fails"). Only values the scope can store are kept: a
host that is not a DNS name (`api_server`, `*.example.com`) is dropped, and at
most 50 paths. With `mode: "enforce"`, FW-SCOPE then asks (or holds, when no one
is there) for:

| Action | When | Outcome |
|---|---|---|
| a write inside the workspace outside every named path (build outputs `dist/ build/ coverage/ .next/ target/` and caches, lockfiles and scratch are never narrowed) | untrusted, or unattended | approve |
| a send to a repository or host the prompt did not name (and not on `sendAllowHosts`); the workspace's own remote is not "another" destination | untrusted | approve (FW-SEND fires too; FW-SCOPE adds the reason) |
| a push, PR, publish, deploy or message the prompt did not ask for (a PR covers pushing its branch); deploys include `vercel`, `vercel --prod` and the deploy CLIs run through `npx` (`npx vercel|netlify|wrangler deploy`), publishes include `twine upload`, and a POST to a chat webhook (Slack, Teams, Google Chat) is a message | unattended, even trusted (`unattendedIntents`) | approve, so held |
| a new package install the prompt did not ask for (restoring declared dependencies, `npm ci`, `npm install`, `pip install -r`, is not) | unattended, even trusted (`unattendedIntents`) | approve, so held |
| a destructive action without a delete verb | any | approve (FW-DESTRUCTIVE fires too; FW-SCOPE adds the reason) |

An interactive trusted session is never narrowed. A prompt that names no path
and no verb ("make it faster") narrows nothing. The scope never loosens: an
action inside it is judged by every other rule exactly as before, and a hold
rule (FW-INSTRUCTIONS-HELD) still wins.

Parsing is strict on purpose, because whatever it finds is something the session
may then do without FW-SCOPE asking: no fuzzy names ("the auth module" names
nothing), only paths that exist inside the workspace, nothing from fenced code
blocks, quoted lines (`> ...`) or quoted strings (pasted logs, issues and emails
are someone else's words), and no verb that is negated ("don't push"), asked
about ("should I deploy?"), used as a noun ("the deploy script fails", "push
notifications"), the subject of a description ("Release workflow fails", "Push
to talk is broken", "git push was rejected") or not in the position of a
request. A path is named as written, as Claude Code's `@src/foo.ts` mention, or
as `src/foo.ts:42`. A continuation ("yes", "continue", a slash command) keeps
the scope; a follow-up that starts like one ("yes, and push", "also update the
docs") keeps what it does not name and adds the verbs it uses; any other prompt
replaces it ("Next.js build fails ..." and "Good morning ..." are new tasks). A subagent's `Task` prompt is
not your prompt and never sets the scope. The prompt text is stored only as a
sha256 hash.

`mode: "log"` (the default) computes the same and
writes it to the decision log (`scope: { mode, verdict, changes, reasons }`)
without changing any decision; `status` shows "N actions would have been asked
by task scope" and `explain <log seq>` shows it per decision. Widening takes your
approval passphrase: approving a FW-SCOPE item with `queue approve`/`review`
offers to widen the scope for that session by what the action needed, and
`launchsafe-firewall scope widen <session> --path P | --repo R | --host H |
--intent I` does it directly (a host is a DNS name or an IPv4 address; only a
widening this command accepts is offered) (`scope show [<session>]` prints the scope). A
widening is a signed `scope_widen` event; an unsigned or forged one makes the
session untrusted and is ignored.

### Watch mode (`rollout`)

Watch mode is for rolling the firewall out to a team: it decides every action
as in enforce mode and writes the verdict to the signed decision log. When only
rules from a reviewed list (below) would ask or hold, it lets the action run
instead; every other rule stays enforced, so credential and personal-data
denials, self-protection, destructive actions and the others listed below still
block or ask. After a week
or two, `launchsafe-firewall rollout report` shows what enforcing would have
done, by rule, so you can tune the policy (allow a host, trust a server) before
you switch to enforce.

```sh
launchsafe-firewall rollout watch            # in your own terminal; asks for the approval passphrase; 14 days unless --days N
launchsafe-firewall rollout report            # what would have been asked, held or blocked, by rule
launchsafe-firewall rollout enforce           # back to enforcing
launchsafe-firewall rollout status            # the mode in effect and where it comes from
```

**What watch mode relaxes, and what it never does.** Only these rules, reviewed
one by one, let an action run in watch mode instead of asking or holding it
(`WATCH_RELAXABLE_RULES` in `src/policy-rollout.ts`): `FW-SEND`, `FW-MESSAGE`,
`FW-SEND-ARGS`, `FW-FETCH`, `FW-FETCH-DATA`, `FW-OUTSIDE-WRITE`, `FW-INSTALL`,
`FW-OPAQUE-CODE`, `FW-AGENT-SPAWN`, `FW-SCOPE`, `FW-RAW-IP`, `FW-UNKNOWN-TOOL`,
`FW-TYPOSQUAT`, `FW-BUDGET-BYTES`, `FW-BUDGET-REQUESTS`, `FW-BUDGET-MCP`,
`FW-LOOP` and `FW-POLICY-ERROR` (which cannot arise in watch mode, see below).
So in watch mode the byte, request and MCP budgets and loop detection do not
stop anything; they are only logged. Every other rule stays enforced, among
them every rule a person can never approve, and any rule added later until it
is reviewed (a test fails when a rule that cannot be approved is put on the
relaxable list). That includes:

| Group | Rules (examples) |
|---|---|
| Data leaving | `FW-DLP-CREDENTIAL`, `FW-DLP-SEEN-SECRET`, `FW-DLP-PERSONAL`, `FW-SECRET-FLOW`, `FW-SECRET-VARIABLE`, `FW-SECRET-FILE-PUBLISH`, `FW-CREDENTIAL-READ`, `FW-CREDENTIAL-FLOW`, `FW-NEW-HOST`, `FW-METADATA`, `FW-CAPTURE-HOST`, `FW-DNS-EXFIL`, the `FW-VAULT-*` rules |
| Decoys | `FW-CANARY-EGRESS`, `FW-CANARY-READ` (after a decoy was touched, every send asks) |
| Self-protection and the agent's own configuration | `FW-TAMPER`, `FW-AGENT-BYPASS`, `FW-AGENT-SETTINGS`, `FW-INSTRUCTIONS`, `FW-INSTRUCTIONS-HELD`, `FW-PERSISTENCE`, `FW-PERSISTENCE-HELD`, `FW-AUTORUN`, `FW-SYMLINK`, `FW-HIDDEN-TEXT`, `FW-LOG-UNRECORDED`, `FW-RESULT-UNRECORDED` |
| Outside content | `FW-OUTSIDE-COMMAND` (a command outside content suggested), `FW-HIDDEN-OUTPUT` |
| Destructive and code-running actions | `FW-CATASTROPHIC`, `FW-DESTROY-ROOT`, `FW-DESTRUCTIVE`, `FW-MALICIOUS-PACKAGE`, `FW-REMOTE-CODE`, `FW-OBFUSCATED`, `FW-UNTRUSTED-CODE`, `FW-TAINTED-MANIFEST`, `FW-UNCLASSIFIABLE`, `FW-PRIVILEGE`, `FW-BLOCKED-TOOL`, `FW-INPUT-SHAPE` |
| Stops and limits | `FW-STOPPED` (the kill switch and the behaviour monitor's stop), `FW-CAP` and `FW-CAP-WARN` (spending limits), `FW-LEARNED-DENY` (your "never") |

`launchsafe-firewall rollout status` prints the full list. When an enforced
rule fires, the action gets that rule's verdict (an ask, a hold, a block);
when only relaxable rules fire, it runs. Everything else is unchanged in watch
mode: taint, private data and secret fingerprints are recorded as for an
allowed action (so the enforced rules see the whole session), decoy alerts
fire, budgets count, and a decision the log cannot record is still asked about
or blocked. A watched action is not queued, so there is nothing to approve.
Each decision made in watch mode carries `"rollout": "watch"` in the log, and
one that enforcing would have asked about, held or blocked carries
`"watch": { "verdict", "rules" }`.

**Who can turn it on.** Watch mode loosens the firewall, so:

- **You, with the approval passphrase.** `rollout watch [--days N]` runs only in
  a real terminal and never as a descendant of an agent, and asks for the
  approval passphrase. It writes a grant signed with the approval key
  (`~/.launchsafe-firewall/rollout.json`, ending after `--days`, 14 by default,
  at most 90), a signed `rollout` entry in the decision log (with a copy as
  the latest rollout change, `rollout-head.json`), and
  `"rollout": { "mode": "watch" }` in your user policy (the file as it was is
  kept as `policy.json.before-rollout-*.bak`). If the policy file cannot be
  written, the grant is taken back and a signed revocation is logged. It then
  checks that watch mode is really in effect and exits 1 with the reason if
  not. The hook honours the user policy's `"watch"` only when all of these
  hold: the grant verifies against the approval key pinned in a hook command
  in your own agent settings (`~/.claude/settings.json`, Codex's, Gemini
  CLI's, Cursor's user files) or the managed ones, naming this firewall home,
  and the hook process was given that same key by its command (a key that
  only reached it through the environment, such as a repository's settings
  `env`, or the key file on disk, does not count; neither does a pin in a
  project-scope install); the latest rollout change is this grant's `watch`;
  the grant was not revoked and has not ended; and every policy file loaded
  without errors. Anything else leaves the firewall enforcing, and `doctor`
  and `rollout status` say why. Without an approval passphrase there is no
  watch mode.
- **An administrator, in the managed policy** (`"rollout": { "mode": "watch" }`),
  with no grant: the agent cannot write that file. A managed
  `"mode": "enforce"` wins over any user grant, and `rollout watch` refuses.
  The hooks log a `rollout_seen` entry the first time they see the mode in
  effect change without a command (a managed change, a grant that ended, a
  policy error).
- **Never a project file.** A repository's `.launchsafe-firewall.json` asking
  for `"watch"` is ignored and reported (`policy validate`, `doctor`); its
  `"enforce"` is a tightening and turns a person's watch mode off for that
  workspace.
- **Never an agent's tool call.** `rollout watch` and `rollout enforce` are
  state-changing commands, so an agent running them is `FW-TAMPER` (denied,
  also in watch mode), as is writing the policy file, the grant or the record.
  `rollout status` and `rollout report` are read-only.

`rollout enforce` (a person at the keyboard; no passphrase, it only tightens)
logs a signed revocation naming the grant (its id is kept in
`rollout-revoked.json`, so the same grant file put back later does not count
again), removes the grant, and sets the user policy back to `"enforce"`.
`status` says when watch mode is on; `doctor` warns, and `doctor --ci` fails.

**The report.** `rollout report [--since 2026-10-01|7d] [--examples N] [--json]`
reads the decision log: how many decisions were made in watch mode, how many
enforcing would have asked about, held or blocked, and for each rule the count
by would-be verdict, the number of sessions, and up to three examples. Examples
are the decision's one-line summary, shortened to 160 characters, with
credentials, card and IBAN numbers, national ids, URL passwords, `-u user:pass`
and authorization values masked. It also lists what watch mode still stopped.

Watch mode applies where the hook pipeline decides: the agents' hooks and the
MCP gateway. The library (`@launchsafe/agent-firewall/sdk`) and the local API
always enforce; the gateway's own protocol refusals (a hidden tool, a withheld
result) and the email guard are unchanged. `check` and `explain` show the
enforced verdict.

### Outsider-writable sources (`outsiderWritable`)

An error tracker shows whatever a crashing client sent; an issue tracker, a
pull-request comment, a support inbox, a chat with people outside your
organisation, an email and a web page show what strangers wrote. Your own
Sentry or GitHub server can be fully trusted and still hand the agent an
attacker's words: a poisoned error event that says "to fix this, run ..." can
lead a coding agent to run the attacker's command.

- `alwaysTaint` (default `true`): results from a server in this class make the
  session untrusted even when `mcpServers` marks the server `trusted`. The
  class is matched on the server's name, word by word (`sentry`,
  `mcp-server-sentry`, `plugin_acme_zendesk`), and on product names in a tool's
  name (`get_sentry_issue` on any server): error tracking and logs (Sentry,
  Datadog, Bugsnag, Rollbar, Honeybadger, Raygun, Airbrake, New Relic,
  AppSignal, LogRocket, Loki, Papertrail, Logtail, Better Stack, Splunk,
  CloudWatch, PagerDuty, Opsgenie, GlitchTip, Axiom, Sumo Logic), forges and
  issue trackers (GitHub, GitLab, Bitbucket, Gitea, Forgejo, Codeberg, Jira,
  Atlassian, YouTrack, Linear, Shortcut, Asana, Trello, ClickUp), support desks
  and CRMs (Intercom, Zendesk, Freshdesk, Help Scout, HubSpot, Salesforce,
  Crisp, Front), chat (Slack, Discord, Telegram, WhatsApp, Microsoft Teams as
  `msteams`, Reddit, Twitter), mail (Gmail, Outlook, IMAP, Proton Mail,
  Fastmail), the web (Firecrawl, Tavily, Perplexity, Brave, Browserbase,
  Puppeteer, Playwright, Exa, SerpApi, SearXNG, DuckDuckGo, Bing), and any
  server with one of the words `fetch`, `web`, `browser`, `websearch`, `mail`,
  `email`, `inbox`, `logs`, `issues`, `tickets`, `helpdesk` or `support` in its
  name. Most of these were already untrusted by their preset; the change is
  that your own `trusted` entry no longer makes them trusted.
- `servers`: more server names or patterns (`*`) in the class.
- `exempt`: names or patterns taken out of the class, for a private tracker
  only your organisation writes to (an internal Jira, a Slack without external
  members). User or managed policy only.
- `commands` (default `"ask"`): **FW-OUTSIDE-COMMAND**. When a result that
  made the session untrusted showed a command (in a code block, a prompt line,
  inline code, or written in a sentence such as "then run git clone ..."), the
  firewall remembers a fingerprint of it (a hash, never the text), and of the
  package names its install commands name. Running that command later, word
  for word or nearly (quotes, spacing, `sudo`, prompt markers, case and quiet
  flags such as `-y` and `-fsSL` aside), or installing one of those packages
  with any package manager of the same ecosystem, needs you; with no one
  there it is held. Commands that only read, write inside the workspace, run
  the project's own scripts or fetch without keeping a file are left to the
  other rules, so "run `npm test`" in an issue does not make `npm test` ask.
  `"off"` switches the rule off (user or managed policy only).

| Key | Default | A project file may | User or managed only |
|---|---|---|---|
| `outsiderWritable.alwaysTaint` | `true` | set `true` | set `false` |
| `outsiderWritable.servers` | `[]` | add names or patterns | add or remove |
| `outsiderWritable.exempt` | `[]` | – (ignored and reported) | add names or patterns |
| `outsiderWritable.commands` | `"ask"` | set `"ask"` | set `"off"` |

The key belongs to policy schema version 3 and is also read from a version 2
file, with the same meaning. In the administrator's file, `outsiderWritable.alwaysTaint: true` (without an
`exempt` list of its own) cancels the user's exemptions, and the
administrator's `servers` cancel the user's exemptions for those servers.

### Package checks (`packageIntel`)

Each key may be set on its own; the others keep their defaults. The malicious
check needs the local snapshot (`launchsafe-firewall update`); without it the
check is skipped and `doctor` warns. A version listed in a range the firewall
cannot compare, or an install without an exact version of a partly-listed
package, asks a person (`malicious` never turns into "allow" by itself). A
project file may only tighten: `malicious` towards `deny`, `typosquat` towards
`approve`, `lockfiles` to `true`, and a lower `maxSnapshotAgeDays`; anything
else is ignored and reported.

### The vault (`vault`)

See [vault.md](vault.md). Bindings are never a policy setting: they live in
the vault's signed index.

| Key | Default | A project file may | User or managed only |
|---|---|---|---|
| `vault.enabled` | `true` | nothing (a repository must not switch off your vault) | set `false`: no vault view is built and FW-VAULT-EGRESS does not apply |
| `vault.confirmDefault.<kind>` | `"always"` for `card`, `iban`, `national_id`, `personal`; `"never"` for `credential`, `oauth` | set `"always"` | set `"never"` |
| `vault.fileFallback` | `false` | set `false` | set `true` |
| `vault.approveKinds` | `["card", "iban", "national_id", "personal"]` (every use of a financial or personal value needs you) | add kinds (`credential`, `oauth`) | remove kinds |
| `vault.approveWhenUntrusted` | `true` (any substitution in an untrusted session needs you) | set `true` | set `false` |
| `vault.shellRewrite` | `"auto"` (rewrite a shell command's references into a ticketed `run` for agents verified to rewrite tool input: Claude Code) | set `"off"` | either |
| `vault.ticketSeconds` | 30 | lower it (5 minimum) | raise it (up to 120) |
| `vault.listInContext` | `true` (SessionStart names the references and where each may go) | set `false` | either |

The keys belong to schema version 3 and are still read
from a version 2 file, with the same meaning.

### The MCP gateway (`gateway`)

See [gateway.md](gateway.md). By default changed tools are hidden and risky calls are
queued (no in-client asks).

| Key | Default | A project file may | User or managed only |
|---|---|---|---|
| `gateway.enabled` | `true` | nothing | set `false` |
| `gateway.mode` | `"auto"` | set `"full"` | any |
| `gateway.askVia` | `"queue"` | set `"queue"` | set `"elicitation"` (verified clients only) |
| `gateway.toolChanges` | `"hide"` | set `"hide"` | set `"taint"` |
| `gateway.responses.stripHidden` / `annotate` | `true` | set `true` | set `false` |
| `gateway.responses.withhold` | `"strong"` | set `"strong"` | set `"never"` |
| `gateway.responses.maxScanBytes` | 4 MiB | raise it (up to 64 MiB) | lower it |
| `gateway.responses.oversize` | `"deliver"` | set `"withhold"` | either |
| `gateway.sampling` | `"deny_untrusted"` | move towards `"deny"` | either way |
| `gateway.unknownMethods` | `"deny"` | – | set `"allow"` |
| `gateway.httpSessionIdleMinutes` | 60 | raise it | lower it (5 to 1440) |
| `gateway.clients.<client>.workspaceRoots` | `[]` | – (ignored, reported) | add absolute roots |

Schema version 3, and still read from a version 2 file, like `vault`.

### The email guard (`emailGuard`)

See [email-guard.md](email-guard.md). The quarantine rule names are the shared
content scanner's (`tag_chars`, `hidden_instruction`,
`dense_zero_width_instruction`, `hidden_exfil_link`, `auth_fail_instruction`).

| Key | Default | A project file may | User or managed only |
|---|---|---|---|
| `emailGuard.enabled` | `true` | set `true` | set `false` |
| `emailGuard.readPath` | `"enforce"` (`"off"`, `"log"`, `"enforce"`) | move towards `"enforce"` | move towards `"off"` |
| `emailGuard.mailbox` | `"log"` (for the mailbox guard, not built yet) | nothing (a repository must not move your mail) | any |
| `emailGuard.servers` | `[]`: extra MCP server names treated as mail | add names | add names |
| `emailGuard.pollSeconds` | `15` (Graph delegated polling, not built yet) | nothing | 5 to 600 |
| `emailGuard.authservIds` | `[]`: extra trusted `Authentication-Results` authserv-ids | nothing (a repository must not declare trusted mail servers) | add |
| `emailGuard.quarantineOn` | all five rules | add | remove (a removed rule degrades to strip or flag) |

Like `vault`, the key belongs to schema version 3 and is still read from a
version 2 file.

### The sandbox profile (`sandbox`, and how the host lists feed it)

`doctor --fix` writes Claude Code's `sandbox` settings key (and nothing else)
from this policy:

- `network.allowedDomains` is `fetchAllowHosts` plus `sendAllowHosts`, converted
  to the sandbox's syntax: `"=github.com"` becomes `github.com`, a bare
  `"crates.io"` (the host and its subdomains) becomes `crates.io` and
  `*.crates.io`, `"*.x"` stays `*.x`. Raw IP addresses (in any spelling: octal,
  hex, fewer than four parts), loopback, cloud metadata endpoints, capture and
  tunnel hosts and anything in `denyHosts` are never added, even when listed, and
  neither is a wildcard that would cover a metadata name (`*.google.internal`)
  or IP addresses (a numeric last label).
- `network.deniedDomains` is `denyHosts` (Claude Code blocks those even when an
  allowed wildcard matches them).
- `enabled: true`, `allowUnsandboxedCommands: false` and
  `autoAllowBashIfSandboxed: false` (Claude Code's defaults for the last two are
  `true`), `excludedCommands: []`, `network.allowLocalBinding: true` (local dev
  servers), `network.allowUnixSockets: []` (the Docker socket is deliberately
  not allowed), and `network.strictAllowlist: true` at user scope when
  `sandbox.strictAllowlist` is on (Claude Code ignores it in project and local
  settings, so it is not written there).
- Settings already in the file that weaken the sandbox are removed, and the plan
  says so: `network.allowAllUnixSockets`, own proxy ports,
  `filesystem.disabled`, `enableWeakerNestedSandbox`,
  `enableWeakerNetworkIsolation`, `allowAppleEvents`, `ignoreViolations`, and
  `filesystem.allowWrite` entries that open the disk, the home directory or a
  credential store (`doctor` scores those as a way out of the sandbox).

The sandbox sees hosts, not methods: `doctor` labels each host **fetch-only**
(from `fetchAllowHosts` only) or **send** (in `sendAllowHosts`), and
**upload-capable** when it accepts uploads over HTTPS even when it is only used
for fetching (GitHub, GitLab, the npm registry, PyPI, GHCR, Docker Hub, ...).
`sendAllowHosts` is empty by default, so the default profile holds only fetch
hosts. Hosts named in a prompt (per session) are never added. To reach another
host from inside the sandbox, add it to `fetchAllowHosts` and run
`doctor --fix` again; the regenerated profile replaces the lists.

`protectInstalledProfile`: once a profile is installed, an agent change
that weakens it is FW-TAMPER (deny) in any session: switching the sandbox off,
`allowUnsandboxedCommands` or `autoAllowBashIfSandboxed` back on, adding to
`excludedCommands`, `allowUnixSockets`, `allowMachLookup` or
`filesystem.allowWrite`, adding a host (or a `WebFetch(domain:...)` allow rule)
outside this policy, turning off the strict allowlist, `allowAllUnixSockets`,
an own proxy port, `filesystem.disabled`, the `enableWeaker...` and
`allowAppleEvents` switches, `filesystem.allowRead`, a different `bwrapPath`,
`socatPath`, `ripgrep` or `ignoreViolations`, removing denied entries, adding a
sandbox key this version does not know, or removing the `sandbox` key. Claude
Code takes the sandbox's settings from several layers (local over project over
user; lists merge), so a change to another layer is judged on the settings that
would take effect: a project or local settings file that switches the sandbox
off or adds `excludedCommands` over a user-level profile is FW-TAMPER too, and
ConfigChange checks the layers above the recorded file the same way (with a
strict allowlist, a project's hosts and `WebFetch` rules do not count, as in
Claude Code). Only what the change itself introduces counts: for ConfigChange,
the `WebFetch(domain:...)` rules the file held when the profile was recorded are
yours, not the change's. Narrowing is an ordinary settings change
(FW-AGENT-SETTINGS). With `false`, every such change is an ordinary settings
change.

`launchsafe-firewall run` (docs/run.md) uses the same derivation for its
proxy: the hosts above, plus the run's `--send-host` entries. Its budgets are
the `budgets` key's: the untrusted numbers for listed hosts, the trusted total
shared by package registries and code hosts, nothing counted for
`sendAllowHosts`, `--send-host` and `exemptHosts`; a reached budget refuses
instead of asking (nobody can be asked mid-connection).

### `run` (`run.allowWritePaths`, `run.privateHosts`)

`launchsafe-firewall run` keeps the scripts the workspace's agent settings run
(hooks, MCP servers, editor tasks) read-only, because the agent could otherwise
replace a program your next session starts outside the sandbox. When that is
build output the agent must rebuild (an MCP server you are developing, started
as `node dist/index.js`), list the path, relative to the workspace or
absolute: `"run": { "allowWritePaths": ["dist"] }`. It exempts only scripts
named by agent settings, never the fixed list (agent settings, git's files,
the project policy) or the firewall's files. Git's files are judged by what
they are, not by who names them: any path with a `.git` component (a nested
repository's or submodule's `.git` pointer file, its `config`, `hooks`,
`commondir`) stays read-only even when `.mcp.json` or a hook also names it and
an entry covers its directory. `run` names the exempted
paths when it starts. Only user or managed policy may set it: in a project
file it is ignored (and listed by `policy validate`).

`run`'s proxy refuses to connect when an admitted name resolves to a private
address (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, and their
IPv4-mapped forms), so a public name cannot be pointed at your company network
or home router (DNS rebinding). A company host that really lives there is
listed in `run.privateHosts`, in the `fetchAllowHosts` syntax
(`"corp.example"`, `"=git.corp.example"`, `"*.corp.example"`):
`"run": { "privateHosts": ["corp.example"] }`. The host must still be admitted
by `fetchAllowHosts` or `sendAllowHosts`; the key only widens which answers
count. Loopback answers need `--allow-localhost` (macOS); link-local, metadata,
unspecified and multicast answers are never admitted. Only user or managed
policy may set it: in a project file it is ignored.

### MCP server settings

- `results`: `"trusted"` (results do not taint) or `"untrusted"` (results are
  outside content). A server Claude Code reports as **project**-defined is forced
  untrusted whatever its name — a repository must not be able to mark its own
  server trusted. A server whose content outsiders write (an error tracker, an
  issue tracker, a support desk, outside chat, mail, the web) stays untrusted
  even when marked `"trusted"`, unless `outsiderWritable` exempts it (see
  "Outsider-writable sources").
- `privateData`: whether reading from this server counts as reading private data.
- `readTools` / `sendTools` / `destructiveTools` / `blockedTools`: override the
  verb-based classification for specific tools (glob patterns allowed).
  `blockedTools` are never callable.

Within one file, a server's exact name wins over a pattern, and the first
matching pattern wins over later ones. A project file's entries only add
restrictions to what the user and managed files give a server: an exact
name a project lists starts from the entry the earlier layers would have used
for it (the exact entry, else the first matching pattern) and merges
tighten-only — `blockedTools`, `sendTools` and `destructiveTools` are unions,
`results: "untrusted"` and `privateData: true` win, and a server a project
names is always untrusted and private. A project pattern also tightens every
earlier exact entry it matches and every earlier pattern that can match the same
servers (two `prefix*` patterns are compared exactly; any other pair is assumed
to overlap, which can only tighten more than needed).

The administrator's entries hold under the user's. Because an exact name
wins over a pattern, and an earlier pattern over a later one, a user entry
(`"corp-mail"`, or a catch-all `"*"`) would otherwise hide the managed file's
`"corp-*"` for the servers it names. So every user entry the managed file covers
starts from the managed entry and merges tighten-only, the same way a project
entry does: `blockedTools`, `sendTools` and `destructiveTools` are unions,
`results: "untrusted"` and `privateData: true` win, and the managed file's
`readTools` are kept while the user's are not added (a user's `readTools` cannot
turn an administrator's send tool into a read). Field by field:

| User entry | Managed entry used |
|---|---|
| an exact name | the managed entry for that name (exact, else its first matching pattern) |
| a pattern | every managed pattern that can match the same servers; a managed `prefix*` strictly inside a user `prefix*` (`"corp-mail*"` inside `"corp-*"`) is applied only to its own servers, so the user's pattern keeps its settings for the rest |
| none, for a name the managed file lists exactly | the managed entry, with the user's matching pattern merged over it tighten-only |
| any, for a server the managed file does not cover | none: the user's entry applies exactly as before |

The managed file's `readTools` are kept only when the managed patterns used
agree on them and cover every server the entry applies to; otherwise the tools
are classified by their names. `policy validate` notes each user entry whose
loosening (trusted results, `privateData: false`, `readTools`) did not apply.

### Phone approvals (`phone`)

See [phone.md](phone.md) (experimental).

| Key | Default | A project file may | User or managed only |
|---|---|---|---|
| `phone.enabled` | `true` | set `false` | set `true` |
| `phone.itemTtlMinutes` | 30 | lower it | raise it (up to 720) |
| `phone.useWithinMinutes` | 60 | lower it | raise it (up to 1440) |
| `phone.clockSkewMinutes` | 10 | lower it | raise it (up to 30) |
| `phone.requireUserVerification` | `true` | – | – (cannot be `false` in this release) |
| `phone.approvable` | `["approval"]` | remove kinds | – (proposals stay in the terminal) |
| `phone.excludeRules` | `[]` | add rules | add or remove |
| `phone.holdSeconds` | 0 | lower it | raise it (capped at the agent's hook timeout minus 10 s) |
| `phone.relayOrigin` | `"https://approve.launchsafe.com"` | – | change it |

Like the vault's, these keys belong to schema version 3 and are still read
from a version 2 file.

### Learned project allows (`learnedAllows`)

See "Fewer prompts" in [usage.md](usage.md#fewer-prompts). The key only
governs the offer and whether "always" choices apply; the choices are signed
and kept in the firewall's home, never in a policy file. Any other field under
`learnedAllows` (a list of allows, say) is an error, so a repository's
`.launchsafe-firewall.json` that tries to carry one is invalid and grants
nothing.

| Key | Default | A project file may | User or managed only |
|---|---|---|---|
| `learnedAllows.enabled` | `true` | set `false` | set `true` |
| `learnedAllows.proposeAfter` | 3 | raise it | lower it (down to 2; up to 100) |

## Desktop notifications

A local native notification (macOS `osascript`, Linux `notify-send` with a
graphical session) tells you when something is waiting. It informs and never
approves: it has no buttons, and approving needs `launchsafe-firewall queue
review` in your terminal with your passphrase. The text is a fixed sentence plus
a count; tool input, paths, URLs and the agent's words never reach it.

- `enabled`: master switch. On by default (coalesced, fixed text).
- `on`: the kinds that notify. `queued` (an action held for review), `proposal`
  (a held change to the agent's instructions), `denied_dlp` (a credential or
  personal data blocked from leaving), and the kinds later items raise:
  `canary`, `loop`, `agent_config`, `mcp_changed`, `mcp_withheld` (the gateway
  withheld an MCP result), `mail_quarantined` (the email guard withheld a
  message), `stopped` (the behaviour monitor stopped a session; the text
  names which of its four fixed reasons it was) and `cap` (a spending limit
  was reached, or nearly reached).
- `onlyWhenUnattended`: when true, an attended session never notifies.
- `minIntervalSec` (10 to 86400, default 120): at most one notification per
  kind in this time; events in between are counted into the next one.
  `denied_dlp`, `canary` and `stopped` skip this but never fire more than once per 10 s.

Keys you leave out take these defaults. The rate-limit state is
`~/.launchsafe-firewall/notify.json` (inside the protected directory). If the
helper cannot start, the decision is unaffected and one `notify_failed` entry a
day is written to the decision log.

## Scratch targets

Deleting a whole database, namespace, app or bucket is FW-CATASTROPHIC:
denied, whatever the session. When some of those are throwaway (a test
database, a per-pull-request preview), declare their names in your own
terminal:

```sh
launchsafe-firewall scratch add 'app_*_test'   # needs the approval passphrase
launchsafe-firewall scratch add '*-pr-*'
launchsafe-firewall scratch list
launchsafe-firewall scratch remove '*-pr-*'
```

A delete whose every target matches a pattern is then asked (or held), like
any other destructive action, instead of denied: `dropdb app_test`,
`DROP DATABASE IF EXISTS app_test`, `kubectl delete ns preview-42`,
`fly apps destroy web-pr-17`. Patterns use `*` only and need at least three
other characters. The list is not part of any policy file: it lives in the
firewall's home (`scratch-targets.json`, which the agent may not write) and
is signed with your approval key, so a project file or an agent cannot add to
it, and a list that does not verify is ignored. A name known only at run time
(`dropdb $DB`), a quoted SQL name, and accounts, projects, clusters, database
servers, the workspace and protected branches are never scratch.

## A project may only tighten

A `.launchsafe-firewall.json` in a repository is attacker-reachable content, so
it is applied with **tighten-only** semantics: it may add to `denyHosts`,
`protectedPaths`, `secretPaths`, `untrustedPaths`, `protectedBranches`; mark a server untrusted or
block tools; switch on `untrustedWorkspace`, `redactSecretsInOutput`,
`unattended`, or `allowInstructionWritesWhenTrusted: false`; and move the
version 2 and version 3 keys only in the tightening direction of their tables
above (the same rules whichever schema version each file declares, so a version
2 project file under a version 3 user file, or the other way round, tightens
exactly as it would at one version; a project
cannot switch decoy detection off: `canaries.enabled: false` is ignored and
reported; `offerAtInstall` and `homeDecoys` are only read from user and managed
policy; it may turn `notifications` on and add kinds to `notifications.on`,
never switch them off or make them quieter; it may only make the
`packageIntel` checks stricter; it may switch `sandbox.protectInstalledProfile`
and `sandbox.strictAllowlist` on, never off, and never mark commands safe to run
outside the sandbox; it may set `rollout.mode` to `"enforce"`, never to
`"watch"`; it may switch `knownHosts` towards `"ask"` and its
built-in hosts off, and can never add a known host: there is no policy key for
one, and the list is kept in the firewall's own directory; it may switch
`learnedAllows` off or raise `learnedAllows.proposeAfter`, and can never hold a
learned allow; it may add outsider-writable servers and turn
`outsiderWritable.alwaysTaint` and `commands` on, never exempt a server).
Anything that would **loosen** the policy (allowing a destination, trusting a server, adding a
trusted read root) is **ignored and reported** by `doctor` and `policy validate`.

## The administrator's file over the user's

The managed file is applied after the user's, so every key it sets wins (a
list it sets replaces the user's; inside `budgets`, `gateway`, `vault` and the
other objects, each field it sets wins). A user file could still relax a
managed restriction only where its own setting is read before the managed one,
in another entry or another key. These cases are closed:

- **`mcpServers`**: a user's exact name or pattern no longer hides a managed
  entry (see "MCP server settings" above).
- **`userOutputTools`**: a tool in it is judged as showing something to you
  before its MCP server's entry is read, so a user listing
  `mcp__corp-mail__send_all` would have skipped the administrator's
  `blockedTools` and `results: "untrusted"` for it. Unless the managed file sets
  `userOutputTools` itself, a user entry naming a tool of a server the managed
  file has an entry for is dropped (and noted by `policy validate`).

These are left as they are, because the managed file can close them by setting
the key itself, or the user's setting is not loosening anything the
administrator wrote:

- **`mcpDefault`**: the managed default is for servers no file lists. A user
  entry for a server the managed file does not list (including a user `"*"`)
  applies as written; an administrator who wants every server judged their way
  lists them, or a `"*"` entry, in `mcpServers`.
- **`sendAllowHosts` and `budgets.exemptHosts`**: hosts the user lists are not
  counted against the managed budgets. Set those keys in the managed file
  (`[]` to allow none) to fix them.
- **`fetchAllowHosts`, `sendAllowHosts` and `sandbox.safeExcludedCommands`** feed
  the sandbox profile that `sandbox.protectInstalledProfile` protects; a managed
  file that sets them decides what the profile may allow.
- **`dataAllowHosts`** (including `"mcp:<server>"` entries) overrides the data
  rules, not an MCP server's entry; a managed `dataAllowHosts` replaces all four
  kinds.
- **`trustedReadRoots`** never outranks `secretPaths` or `untrustedPaths` (a
  secret or untrusted file under a trusted root is still judged as one), and a
  host in **`denyHosts`** is denied (FW-CAPTURE-HOST) whatever allow list also
  names it, so neither needs a change.

## Lists replace, they do not append

When you set a list key (for example `fetchAllowHosts`) in a user or managed
policy, it **replaces** the built-in list for that key — it does not extend it.
Run `launchsafe-firewall policy show` to see the effective defaults and copy the
ones you want to keep. (Across non-managed scopes the arrays merge; see the
precedence rules in `src/policy.ts`.)

## Invalid policy fails safe

If the user or managed policy file is unreadable or invalid, the broken file is
not applied (its keys keep what the other layers, else the built-in defaults, set;
the built-in defaults are not the strictest possible settings) and a "policy error" sends every
risky action to a person, so a broken file never silently opens things up.
Every other layer that parsed still applies: a broken user file keeps the
administrator's managed policy (its `denyHosts`, blocked tools and server
entries stay hard denies) and the project's tightening. A broken managed file
also drops the user's layer, which could otherwise open what the administrator
closed. A file whose `"version"` is newer than the firewall understands is
treated the same way (see the schema section above). `doctor` and
`policy validate` report the exact problem.
