/**
 * The command line, declared once. Every subcommand parses its arguments
 * against a spec before anything runs: `--help`/`-h` anywhere prints that
 * command's help, and an unknown flag, a missing value, a bad enum value or a
 * surplus argument is a usage error. Nothing here does I/O, so the engine may
 * use the same table to tell which firewall invocations are read-only.
 */

import { VERSION } from "./version.js";
import { own } from "./own.js";

export type FlagSpec =
  | { kind: "bool"; help?: string }
  | { kind: "string"; placeholder: string; help?: string; /** May be given more than once (every value is in Ok.lists). */ repeat?: boolean }
  | { kind: "enum"; values: readonly string[]; help?: string }
  | { kind: "int"; min?: number; max?: number; placeholder?: string; help?: string };

export interface CommandSpec {
  path: readonly string[];
  /** One line for the top-level help. */
  summary: string;
  /** The usage line(s), without the program name. */
  usage: string;
  flags: Record<string, FlagSpec>;
  /** Short aliases ("-j": "--json"); "-h" for --help is always recognised. */
  short?: Record<string, string>;
  positionals: { min: number; max: number | null; names: readonly string[]; int?: boolean };
  /** Changes the machine or the firewall's state: refused for agents and guarded in tests. */
  changesState: boolean;
  /** Reads from standard input. */
  stdin?: boolean;
  /** Hidden from the top-level help (still documented in docs/cli.md). */
  hidden?: boolean;
}

export type Parsed =
  | { kind: "ok"; spec: CommandSpec; flags: Map<string, string | true>; positionals: string[]; /** Every value of a repeatable flag, in order. */ lists?: Map<string, string[]> }
  | { kind: "help"; spec: CommandSpec | null }
  | { kind: "error"; message: string; spec: CommandSpec | null };

export const PROGRAM = "launchsafe-firewall";

const json: Record<string, FlagSpec> = { "--json": { kind: "bool", help: "print JSON" } };
const scope: FlagSpec = { kind: "enum", values: ["user", "project", "local"], help: "which settings file (Codex, Gemini CLI and Cursor: user or project)" };
const agent: FlagSpec = { kind: "enum", values: ["claude", "codex", "gemini", "cursor"], help: "which agent's settings (default claude)" };
const browser: FlagSpec = { kind: "enum", values: ["chrome", "chromium", "edge", "brave"], help: "set up the link to the LaunchSafe browser extension in this browser (a native messaging host manifest in its per-user directory) instead of agent hooks" };
const project: FlagSpec = { kind: "string", placeholder: "DIR", help: "the project directory (default: the current directory)" };
const none = { min: 0, max: 0, names: [] as readonly string[] };
const sawTruncated: FlagSpec = { kind: "bool", help: "approve a held action even though parts of it were cut and are not shown (refused otherwise)" };

export const COMMANDS: readonly CommandSpec[] = [
  {
    path: ["install"],
    summary: "register the firewall's hooks in an agent's settings (Claude Code, Codex, Gemini CLI, Cursor)",
    usage: "install [--agent claude|codex|gemini|cursor] [--scope user|project|local] [--project DIR] [--no-approver]\ninstall --agent gemini --seatbelt PROFILE [--gemini-package DIR] [--scope user|project] [--project DIR] [--no-approver]\ninstall --managed [--agent claude|codex|gemini|cursor] [--lock-other-hooks] [--print]\ninstall --browser chrome|chromium|edge|brave --extension-id ID [--user-data-dir DIR]",
    flags: {
      "--agent": agent,
      "--scope": scope,
      "--project": project,
      "--managed": { kind: "bool", help: "print managed settings for an administrator to deploy" },
      "--lock-other-hooks": { kind: "bool", help: "with --managed: also set allowManagedHooksOnly" },
      "--print": { kind: "bool", help: "with --managed: print the JSON only" },
      "--no-approver": { kind: "bool", help: "do not offer to set an approval passphrase" },
      "--seatbelt": { kind: "enum", values: ["permissive-open", "permissive-proxied", "restrictive-open", "restrictive-proxied", "strict-open", "strict-proxied"], help: "with --agent gemini, macOS: also write ~/.gemini/sandbox-macos-launchsafe.sb, Gemini CLI's own PROFILE plus write access to the hook's state directories only, for gemini -s with SEATBELT_PROFILE=launchsafe (permissive-open is Gemini CLI's default)" },
      "--gemini-package": { kind: "string", placeholder: "DIR", help: "with --seatbelt: Gemini CLI's package (or its bundle directory) to copy the profile from (default: found from the gemini command on PATH)" },
      "--browser": browser,
      "--extension-id": { kind: "string", placeholder: "ID", repeat: true, help: "with --browser: the LaunchSafe extension's id (32 letters, from the browser's extensions page); the only extension the link answers" },
      "--user-data-dir": { kind: "string", placeholder: "DIR", help: "with --browser: a browser profile started with --user-data-dir DIR, instead of the browser's default one" },
    },
    positionals: none,
    changesState: true,
  },
  {
    path: ["uninstall"],
    summary: "remove the firewall's hooks (needs the approval passphrase when one is set)",
    usage: "uninstall [--agent claude|codex|gemini|cursor] [--scope user|project|local] [--project DIR] [--restore-backup [--force]] [--remove-sandbox] [--purge]\nuninstall --browser chrome|chromium|edge|brave|all",
    flags: { "--browser": { kind: "enum", values: ["chrome", "chromium", "edge", "brave", "all"], help: "remove the browser link's host manifest for that browser (all: every one install recorded) instead of the hooks" }, "--agent": agent, "--scope": scope, "--project": project, "--restore-backup": { kind: "bool", help: "put each settings file back exactly as it was before the first install (a file install created is removed; the current file is saved as FILE.before-restore.TIMESTAMP first; settings you changed since install are listed and need a yes or --force; this also removes a sandbox profile doctor --fix added)" }, "--force": { kind: "bool", help: "with --restore-backup: discard settings you changed since install without asking (the file as it is now is still saved beside it first)" }, "--remove-sandbox": { kind: "bool", help: "also remove the sandbox profile doctor --fix installed (it is kept otherwise)" }, "--purge": { kind: "bool", help: "also delete the firewall's state directory" } },
    positionals: none,
    changesState: true,
  },
  {
    path: ["doctor"],
    summary: "check the install and the settings files the firewall can read, and what to fix",
    usage: "doctor [--json] [--project DIR]\ndoctor --ci [--json] [--project DIR]\ndoctor --fix [--scope user|project|local] [--dry-run] [--project DIR]\ndoctor --repair-state [--project DIR]",
    flags: {
      ...json,
      "--project": project,
      "--ci": { kind: "bool", help: "only the checks of whether the firewall's hooks are installed with the exit-2 wrapper, and of the settings files that could switch them off or reach into them (the repository's agent settings, the user's and the managed ones; command-line flags and the agents' own runtime are not seen); strict: not installed, watch mode on, or a policy error also fails; no score, no probes; exit 1 when one fails, 0 otherwise (for a CI job or a pre-commit check)" },
      "--fix": { kind: "bool", help: "offer fixes after showing each change: Claude Code's sandbox profile from your policy (needs the approval passphrase), pinning the approval key in the hook, a package cooldown in your user config, downloading malicious-package data" },
      "--scope": { kind: "enum", values: ["user", "project", "local"], help: "with --fix: which Claude Code settings file gets the sandbox profile (default: user)" },
      "--repair-state": { kind: "bool", help: "rebuild a damaged install.json from the agent settings files that hold the firewall's hooks (the damaged file is kept beside it; person-run, needs the approval passphrase)" },
      "--dry-run": { kind: "bool", help: "with --fix: print the changes and exit without writing anything or asking for the passphrase" },
    },
    positionals: none,
    changesState: false,
  },
  {
    path: ["update"],
    summary: "download the malicious-package data (OSV MAL- entries) used to check installs; the only command that downloads data without a prompt (doctor --fix offers the same download after you confirm; decisions make no network calls unless you pair a phone, which is experimental; run is a network proxy)",
    usage: "update [--source URL|DIR] [--ecosystem LIST]",
    flags: { "--source": { kind: "string", placeholder: "URL|DIR", help: "where to fetch <Ecosystem>/all.zip from (default: OSV's public bulk exports)" }, "--ecosystem": { kind: "string", placeholder: "LIST", help: "comma-separated ecosystems (default: npm,PyPI,crates.io,RubyGems,Go,Maven,NuGet,Packagist)" } },
    positionals: none,
    changesState: true,
  },
  { path: ["status"], summary: "sessions, held actions and recent decisions", usage: "status [--json]", flags: json, positionals: none, changesState: false },
  { path: ["session"], summary: "stopped sessions and agents, and why (same as session list)", usage: "session [--json]", flags: json, positionals: none, changesState: false },
  { path: ["session", "list"], summary: "the sessions and agents that are stopped, by whom and why", usage: "session list [--json]", flags: json, positionals: none, changesState: false },
  { path: ["session", "stop"], summary: "stop a session: every later tool call it makes through the firewall is blocked (a command already running keeps running), until a person resumes it", usage: "session stop <session> [--reason TEXT]", flags: { "--reason": { kind: "string", placeholder: "TEXT", help: "a note for the log and session list" } }, positionals: { min: 1, max: 1, names: ["session"] }, changesState: true },
  { path: ["session", "resume"], summary: "resume a stopped session (needs the approval passphrase)", usage: "session resume <session>", flags: {}, positionals: { min: 1, max: 1, names: ["session"] }, changesState: true },
  { path: ["agent", "stop"], summary: "stop every session of an agent (claude, codex, gemini, cursor, gateway, or a local API agent id) until a person resumes it", usage: "agent stop <agentId> [--reason TEXT]", flags: { "--reason": { kind: "string", placeholder: "TEXT", help: "a note for the log and session list" } }, positionals: { min: 1, max: 1, names: ["agentId"] }, changesState: true },
  { path: ["agent", "resume"], summary: "resume a stopped agent (needs the approval passphrase)", usage: "agent resume <agentId>", flags: {}, positionals: { min: 1, max: 1, names: ["agentId"] }, changesState: true },
  { path: ["queue"], summary: "actions held for a person (same as queue list)", usage: "queue [--json]", flags: json, positionals: none, changesState: false },
  { path: ["queue", "list"], summary: "list held actions", usage: "queue list [--json]", flags: json, positionals: none, changesState: false },
  { path: ["queue", "show"], summary: "one held action, with the diff for a proposed change", usage: "queue show <id> [--json]", flags: json, positionals: { min: 1, max: 1, names: ["id"] }, changesState: false },
  { path: ["queue", "review"], summary: "go through every held action (needs the approval passphrase)", usage: "queue review [--i-saw-truncated]", flags: { "--i-saw-truncated": sawTruncated }, positionals: none, changesState: true },
  { path: ["queue", "approve"], summary: "allow held actions once (needs the approval passphrase)", usage: "queue approve <id>... [--i-saw-truncated]", flags: { "--i-saw-truncated": sawTruncated }, positionals: { min: 1, max: null, names: ["id"] }, changesState: true },
  { path: ["queue", "reject"], summary: "reject held actions", usage: "queue reject <id>...", flags: {}, positionals: { min: 1, max: null, names: ["id"] }, changesState: true },
  // Fewer prompts (docs/usage.md): what the firewall asked, and the person's learned choices per project.
  { path: ["friction"], summary: "how often the firewall asked or held actions, by rule and by agent, and which actions you approved every time (same as friction report)", usage: "friction [--json] [--days N]", flags: { ...json, "--days": { kind: "int", min: 1, max: 3650, placeholder: "N", help: "only the last N days (default: everything in the decision log)" } }, positionals: none, changesState: false },
  { path: ["friction", "report"], summary: "the friction report from the decision log", usage: "friction report [--json] [--days N]", flags: { ...json, "--days": { kind: "int", min: 1, max: 3650, placeholder: "N", help: "only the last N days (default: everything in the decision log)" } }, positionals: none, changesState: false },
  { path: ["allow"], summary: "your learned choices for this project: always or never for one exact action (same as allow list)", usage: "allow [--json] [--all] [--project DIR]", flags: { ...json, "--all": { kind: "bool", help: "every project's choices" }, "--project": project }, positionals: none, changesState: false },
  { path: ["allow", "list"], summary: "list learned choices and the actions ready for \"always in this project\"", usage: "allow list [--json] [--all] [--project DIR]", flags: { ...json, "--all": { kind: "bool", help: "every project's choices" }, "--project": project }, positionals: none, changesState: false },
  { path: ["allow", "add"], summary: "always allow a low-risk action you approved repeatedly, in its project only (needs the approval passphrase)", usage: "allow add <code>", flags: {}, positionals: { min: 1, max: 1, names: ["code"] }, changesState: true },
  { path: ["allow", "never"], summary: "never allow an asked action in its project (it is blocked from then on)", usage: "allow never <code>", flags: {}, positionals: { min: 1, max: 1, names: ["code"] }, changesState: true },
  { path: ["allow", "remove"], summary: "remove a learned choice (removing a \"never\" needs the approval passphrase)", usage: "allow remove <id>", flags: {}, positionals: { min: 1, max: 1, names: ["id"] }, changesState: true },
  { path: ["pins"], summary: "MCP servers' pinned configuration, tools and descriptions, and changes waiting for review (same as pins list)", usage: "pins [--json]", flags: json, positionals: none, changesState: false },
  { path: ["pins", "list"], summary: "list MCP pins and pending changes", usage: "pins list [--json]", flags: json, positionals: none, changesState: false },
  { path: ["pins", "accept"], summary: "accept the pending changes of MCP servers after review (needs the approval passphrase)", usage: "pins accept <server>...", flags: {}, positionals: { min: 1, max: null, names: ["server"] }, changesState: true },
  // Scratch targets: name patterns a person declares throwaway, so deleting such a database, namespace, app or bucket is asked instead of denied.
  { path: ["scratch"], summary: "name patterns of throwaway targets whose deletion you may approve (same as scratch list)", usage: "scratch [--json]", flags: json, positionals: none, changesState: false },
  { path: ["scratch", "list"], summary: "the scratch-target patterns, and whether the list is signed", usage: "scratch list [--json]", flags: json, positionals: none, changesState: false },
  { path: ["scratch", "add"], summary: "declare a name pattern throwaway, e.g. app_*_test (needs the approval passphrase)", usage: "scratch add <pattern>", flags: {}, positionals: { min: 1, max: 1, names: ["pattern"] }, changesState: true },
  { path: ["scratch", "remove"], summary: "remove a scratch-target pattern (needs the approval passphrase)", usage: "scratch remove <pattern>", flags: {}, positionals: { min: 1, max: 1, names: ["pattern"] }, changesState: true },
  // Known hosts (knownHosts): the hosts a person approved per project. Changes need a person at the keyboard; reading is for anyone.
  { path: ["hosts"], summary: "the hosts approved for this project (same as hosts list)", usage: "hosts [--project DIR] [--json]", flags: { ...json, "--project": project }, positionals: none, changesState: false },
  { path: ["hosts", "list"], summary: "the hosts approved for this project, and the knownHosts setting in effect", usage: "hosts list [--project DIR] [--json]", flags: { ...json, "--project": project }, positionals: none, changesState: false },
  { path: ["hosts", "allow"], summary: "approve hosts for this project, so contacting them does not ask (knownHosts)", usage: "hosts allow <host>... [--project DIR]", flags: { "--project": project }, positionals: { min: 1, max: null, names: ["host"] }, changesState: true },
  { path: ["hosts", "remove"], summary: "take hosts off this project's approved list", usage: "hosts remove <host>... [--project DIR]", flags: { "--project": project }, positionals: { min: 1, max: null, names: ["host"] }, changesState: true },
  { path: ["hosts", "review"], summary: "the hosts knownHosts watch mode recorded for this project, proposed as its list", usage: "hosts review [--project DIR] [--json]", flags: { ...json, "--project": project }, positionals: none, changesState: false },
  { path: ["hosts", "accept"], summary: "approve the hosts hosts review proposes (all of them with --all, or the ones named)", usage: "hosts accept --all [--project DIR]\nhosts accept <host>... [--project DIR]", flags: { "--all": { kind: "bool", help: "every proposed host (not the ones only run saw, nor those seen after outside content)" }, "--project": project }, positionals: { min: 0, max: null, names: ["host"] }, changesState: true },
  { path: ["hosts", "reset"], summary: "empty this project's approved hosts and watch record (also replaces a damaged file)", usage: "hosts reset [--project DIR]", flags: { "--project": project }, positionals: none, changesState: true },
  // The vault. Every state-changing command needs a person (terminal, approval passphrase); list is read-only, agents included.
  { path: ["vault"], summary: "secrets the agent uses by reference, without the value being put in what it reads (same as vault list)", usage: "vault [--json]", flags: json, positionals: none, changesState: false },
  { path: ["vault", "list"], summary: "stored secrets: names, kinds, fields, bindings; never a value", usage: "vault list [--json]", flags: json, positionals: none, changesState: false },
  {
    path: ["vault", "add"],
    summary: "store a secret (typed with echo off) and sign it into the vault (needs the approval passphrase)",
    usage: "vault add <name> [--kind credential|oauth|card|iban|national_id|personal] [--fields a,b] [--confirm always|never]",
    flags: {
      "--kind": { kind: "enum", values: ["credential", "oauth", "card", "iban", "national_id", "personal"], help: "what it is (default credential); card, iban, national_id and personal have several fields" },
      "--fields": { kind: "string", placeholder: "a,b", help: "the field names (default per kind: value; card number,expiry,cvc,name; iban iban,bic,holder)" },
      "--confirm": { kind: "enum", values: ["always", "never"], help: "macOS: ask in a keychain dialog on every read (default: always for card, iban, national_id, personal; never for credential, oauth)" },
    },
    positionals: { min: 1, max: 1, names: ["name"] },
    changesState: true,
  },
  {
    path: ["vault", "allow"],
    summary: "bind a secret to a destination (this does not approve any held action; needs the approval passphrase)",
    usage: 'vault allow <name> --host HOST [--allow-in-url] [--allow-http] | --mcp SERVER[:TOOL[:ARG]] | --process "PROGRAM ARGS..."',
    flags: {
      "--host": { kind: "string", placeholder: "HOST", help: "an exact host name, or *.example.com for its subdomains" },
      "--allow-in-url": { kind: "bool", help: "with --host: the value may also appear in the URL itself (server logs keep URLs)" },
      "--allow-http": { kind: "bool", help: "with --host: the value may also go over plain http (the default is https only)" },
      "--mcp": { kind: "string", placeholder: "SERVER[:TOOL[:ARG]]", help: "an MCP server, optionally a tool pattern and the one argument path it may appear in" },
      "--process": { kind: "string", placeholder: "ARGV", help: 'a command line it may be given to by "run" (a trailing * allows further arguments)' },
    },
    positionals: { min: 1, max: 1, names: ["name"] },
    changesState: true,
  },
  { path: ["vault", "revoke"], summary: "remove one binding of a secret, by its number in vault list (needs the approval passphrase)", usage: "vault revoke <name> <n>", flags: {}, positionals: { min: 2, max: 2, names: ["name", "n"] }, changesState: true },
  { path: ["vault", "remove"], summary: "delete a secret's values and its entry (needs the approval passphrase)", usage: "vault remove <name>", flags: {}, positionals: { min: 1, max: 1, names: ["name"] }, changesState: true },
  { path: ["vault", "rotate"], summary: "replace a secret's values, typed with echo off (needs the approval passphrase)", usage: "vault rotate <name>", flags: {}, positionals: { min: 1, max: 1, names: ["name"] }, changesState: true },
  // The MCP gateway (docs/gateway.md). wrap and serve are the gateway itself; the config rewrites, login and reset need a person.
  {
    path: ["mcp", "wrap"],
    summary: "the stdio MCP gateway for one server (an MCP client starts this from its configuration)",
    usage: "mcp wrap --client CLIENT --server NAME [--mode auto|full|hook] [--phones PIN] -- COMMAND [ARGS...]",
    flags: { "--phones": { kind: "string", placeholder: "sha256:HEX", help: "the paired phones' pin (written by mcp wrap-config; phone approvals verify against it)" }, "--client": { kind: "enum", values: ["claude-desktop", "claude-code", "cursor", "codex", "gemini", "vscode"], help: "which MCP client" }, "--server": { kind: "string", placeholder: "NAME", help: "the server's name in the client's configuration" }, "--mode": { kind: "enum", values: ["auto", "full", "hook"], help: "full: the gateway decides every call; hook: the client's firewall hook does (default auto)" } },
    positionals: { min: 1, max: null, names: ["command"] },
    changesState: true,
    hidden: true,
  },
  { path: ["mcp", "serve"], summary: "the local Streamable HTTP MCP gateway (127.0.0.1 only; person-run)", usage: "mcp serve [--port N]", flags: { "--port": { kind: "int", min: 1024, max: 65535, placeholder: "N", help: "the port (default 8473)" } }, positionals: none, changesState: true },
  {
    path: ["mcp", "wrap-config"],
    summary: "put the gateway in front of a client's MCP servers: shows the diff, backs up, needs the approval passphrase",
    usage: "mcp wrap-config --client CLIENT [--server NAME,...] [--port N] [--dry-run]",
    flags: { "--client": { kind: "enum", values: ["claude-desktop", "claude-code", "cursor", "codex", "gemini", "vscode"], help: "which MCP client" }, "--server": { kind: "string", placeholder: "NAME,...", help: "only these servers" }, "--port": { kind: "int", min: 1024, max: 65535, placeholder: "N", help: "the local gateway's port for HTTP servers (default 8473)" }, "--dry-run": { kind: "bool", help: "print the changes and exit" } },
    positionals: none,
    changesState: true,
  },
  { path: ["mcp", "unwrap-config"], summary: "put a client's MCP servers back as they were before wrap-config (needs the approval passphrase)", usage: "mcp unwrap-config --client CLIENT [--dry-run]", flags: { "--client": { kind: "enum", values: ["claude-desktop", "claude-code", "cursor", "codex", "gemini", "vscode"], help: "which MCP client" }, "--dry-run": { kind: "bool", help: "print the changes and exit" } }, positionals: none, changesState: true },
  { path: ["mcp", "login"], summary: "sign the gateway in to a wrapped HTTP server's authorization server (OAuth, person-run)", usage: "mcp login <server>", flags: {}, positionals: { min: 1, max: 1, names: ["server"] }, changesState: true },
  { path: ["gateway"], summary: "MCP servers wrapped by the gateway, ones that are not, and withheld results (same as gateway status)", usage: "gateway [--json]", flags: json, positionals: none, changesState: false },
  { path: ["gateway", "status"], summary: "MCP servers wrapped by the gateway, ones that are not, and withheld results", usage: "gateway status [--json]", flags: json, positionals: none, changesState: false },
  { path: ["gateway", "reset"], summary: "start a new gateway session for a client now", usage: "gateway reset <client>", flags: {}, positionals: { min: 1, max: 1, names: ["client"] }, changesState: true },
  { path: ["gateway", "quarantine"], summary: "MCP results the gateway withheld (no text in the list; --json in your terminal adds a short escaped preview; quarantine show prints the whole text)", usage: "gateway quarantine [--json]", flags: json, positionals: none, changesState: false },
  { path: ["gateway", "quarantine", "show"], summary: "the text of one withheld result, for you in your own terminal", usage: "gateway quarantine show <id>", flags: {}, positionals: { min: 1, max: 1, names: ["id"] }, changesState: true },
  // The email guard's review list. Reading it is for anyone; releasing or discarding needs a person (terminal, approval passphrase for release).
  { path: ["mail"], summary: "the email guard: messages withheld from the agent (same as mail quarantine list)", usage: "mail [--json]", flags: json, positionals: none, changesState: false },
  { path: ["mail", "quarantine"], summary: "messages withheld from the agent (same as mail quarantine list)", usage: "mail quarantine [--all] [--json]", flags: { ...json, "--all": { kind: "bool", help: "also list released and discarded records" } }, positionals: none, changesState: false },
  { path: ["mail", "quarantine", "list"], summary: "list withheld messages: sender, subject, signals, record id", usage: "mail quarantine list [--all] [--json]", flags: { ...json, "--all": { kind: "bool", help: "also list released and discarded records" } }, positionals: none, changesState: false },
  // It prints the sender, subject, Message-ID and hidden text of a withheld message: for a person only, like release
  // (an agent running it would read what was withheld from it).
  { path: ["mail", "quarantine", "show"], summary: "one withheld message's record, with its hidden text escaped, for you in your own terminal", usage: "mail quarantine show <id> [--json]", flags: json, positionals: { min: 1, max: 1, names: ["id"] }, changesState: true },
  { path: ["mail", "quarantine", "release"], summary: "deliver a withheld message to the agent next time, hidden parts stripped (needs the approval passphrase)", usage: "mail quarantine release <id>", flags: {}, positionals: { min: 1, max: 1, names: ["id"] }, changesState: true },
  { path: ["mail", "quarantine", "discard"], summary: "close a withheld message's record; it stays withheld", usage: "mail quarantine discard <id>", flags: {}, positionals: { min: 1, max: 1, names: ["id"] }, changesState: true },
  {
    path: ["mail", "audit"],
    summary: "dry run of the email guard over saved mail (.eml files, mbox files or folders of them): counts only, nothing changes or leaves the machine",
    usage: "mail audit --path FILE|DIR [--limit N] [--json]",
    flags: { "--json": { kind: "bool", help: "print the counts as JSON (no addresses, no subjects: safe to share if you choose)" }, "--path": { kind: "string", placeholder: "FILE|DIR", help: "an .eml file, an mbox file, or a folder of them (searched recursively)" }, "--limit": { kind: "int", min: 1, max: 1000000, placeholder: "N", help: "scan at most N messages (default 5000)" } },
    positionals: none,
    changesState: false,
  },
  // Phone approvals. Pairing and removal need a person (terminal, approval passphrase); list and status are read-only.
  { path: ["phone"], summary: "experimental: phones paired to approve held actions (same as phone list)", usage: "phone [--json]", flags: json, positionals: none, changesState: false },
  { path: ["phone", "list"], summary: "paired phones, whether the hook pins them, and the relay's state", usage: "phone list [--json]", flags: json, positionals: none, changesState: false },
  {
    path: ["phone", "pair"],
    summary: "experimental, not usable yet (the hosted relay is not available): pair a phone with a QR code so its passkey can approve or reject held actions (needs the approval passphrase and a LaunchSafe account)",
    usage: "phone pair [--label NAME] [--no-login-item]",
    flags: { "--label": { kind: "string", placeholder: "NAME", help: "this machine's name on the phone (default: the host name)" }, "--no-login-item": { kind: "bool", help: 'do not install the relay daemon as a login item (run "relay run" yourself)' } },
    positionals: none,
    changesState: true,
  },
  { path: ["phone", "remove"], summary: "unpair a phone by its label or credential id (needs the approval passphrase)", usage: "phone remove <label|id>", flags: {}, positionals: { min: 1, max: 1, names: ["label|id"] }, changesState: true },
  { path: ["phone", "unpair"], summary: "same as phone remove", usage: "phone unpair <label|id>", flags: {}, positionals: { min: 1, max: 1, names: ["label|id"] }, changesState: true },
  { path: ["relay"], summary: "the phone relay daemon's state (same as relay status)", usage: "relay [--json]", flags: json, positionals: none, changesState: false },
  { path: ["relay", "status"], summary: "the phone relay daemon: last contact, errors, items sent", usage: "relay status [--json]", flags: json, positionals: none, changesState: false },
  {
    path: ["relay", "run"],
    summary: "experimental: the phone relay daemon: sends sealed held items to your phones and applies their signed decisions (a login item after phone pair)",
    usage: "relay run [--once]",
    flags: { "--once": { kind: "bool", help: "one upload and one decision check, then exit" } },
    positionals: none,
    changesState: true,
  },
  { path: ["approver"], summary: "the approval passphrase (same as approver status)", usage: "approver", flags: {}, positionals: none, changesState: false },
  { path: ["approver", "status"], summary: "whether an approval passphrase is set", usage: "approver status", flags: {}, positionals: none, changesState: false },
  { path: ["approver", "init"], summary: "set the approval passphrase", usage: "approver init", flags: {}, positionals: none, changesState: true },
  { path: ["approver", "rotate"], summary: "change the approval passphrase", usage: "approver rotate", flags: {}, positionals: none, changesState: true },
  { path: ["log"], summary: "the signed decision log (same as log tail)", usage: "log", flags: {}, positionals: none, changesState: false },
  { path: ["log", "tail"], summary: "the last N decisions", usage: "log tail [N]", flags: {}, positionals: { min: 0, max: 1, names: ["N"], int: true }, changesState: false },
  {
    path: ["log", "verify"],
    summary: "check the log's hash chain and signatures; with a bundle, check an exported bundle instead (needs no firewall install; exit 0 ok, 1 problems, 2 not pinned)",
    usage: "log verify\nlog verify <bundle> [--key FINGERPRINT|PEM-FILE]... [--anchor FILE]... [--no-pin] [--json]",
    flags: {
      "--key": { kind: "string", placeholder: "FINGERPRINT|PEM-FILE", repeat: true, help: "with a bundle: a key you trust that must be among its signing keys (the sha256: fingerprint log export printed, or a PEM public key file; nothing of the file is printed)" },
      "--anchor": { kind: "string", placeholder: "FILE", repeat: true, help: "with a bundle: anchor records (log anchor) the bundle's entries must match" },
      "--no-pin": { kind: "bool", help: "with a bundle: accept it without --key or a matching anchor (otherwise that is UNAUTHENTICATED, exit 2)" },
      "--json": { kind: "bool", help: "with a bundle: print the result as JSON" },
    },
    positionals: { min: 0, max: 1, names: ["bundle"] },
    changesState: false,
  },
  {
    path: ["log", "export"],
    summary: "write the signed log, or a range of it, as one self-contained bundle that log verify <bundle> checks anywhere (person-run, in a terminal)",
    usage: "log export --out FILE|- [--from SEQ|TIME] [--to SEQ|TIME]",
    flags: {
      "--out": { kind: "string", placeholder: "FILE|-", help: "the bundle file to create (it must not exist yet, nor be inside the firewall's directory), or - for standard output" },
      "--from": { kind: "string", placeholder: "SEQ|TIME", help: "start at this sequence number, or at the first entry at or after this time (ISO 8601: 2026-10-01 or 2026-10-01T12:00:00Z)" },
      "--to": { kind: "string", placeholder: "SEQ|TIME", help: "end at this sequence number, or at the last entry at or before this time" },
    },
    positionals: none,
    changesState: true,
  },
  {
    path: ["log", "anchor"],
    summary: "write the log's current head, signed, to a place you choose off the firewall's directory (a file, a git note, or a command of yours); person-run only",
    usage: "log anchor --file PATH\nlog anchor --git-notes REPO\nlog anchor --exec -- <command> [args...]",
    flags: {
      "--file": { kind: "string", placeholder: "PATH", help: "append the anchor record to this file, in an existing directory outside the firewall's (not through a symbolic link)" },
      "--git-notes": { kind: "string", placeholder: "REPO", help: "add the record to the git note refs/notes/launchsafe-firewall-log in this repository (push that ref yourself)" },
      "--exec": { kind: "bool", help: "run the command after -- (no shell) with the record on its standard input, for example an upload to an object-lock bucket" },
    },
    positionals: { min: 0, max: null, names: ["command"] },
    changesState: true,
  },
  { path: ["log", "rotate"], summary: "start a new log file now", usage: "log rotate", flags: {}, positionals: none, changesState: true },
  { path: ["policy"], summary: "the policy in effect (same as policy show)", usage: "policy", flags: {}, positionals: none, changesState: false },
  { path: ["policy", "show"], summary: "print the merged policy", usage: "policy show", flags: {}, positionals: none, changesState: false },
  { path: ["policy", "validate"], summary: "check every policy file and list ignored project settings", usage: "policy validate", flags: {}, positionals: none, changesState: false },
  { path: ["policy", "init"], summary: "write a starter user policy file", usage: "policy init", flags: {}, positionals: none, changesState: true },
  { path: ["policy", "migrate"], summary: "rewrite the user policy file in the current schema version, keeping a backup", usage: "policy migrate", flags: {}, positionals: none, changesState: true },
  // Watch-only rollout (docs/policy.md#watch-mode). Turning watch on is a loosening: a person, the approval passphrase, a signed log entry.
  { path: ["rollout"], summary: "the rollout mode: enforce, or watch (log what would be asked, held or blocked, and let it run); same as rollout status", usage: "rollout [--json]", flags: json, positionals: none, changesState: false },
  { path: ["rollout", "status"], summary: "the rollout mode in effect, where it comes from, and what watch mode still enforces", usage: "rollout status [--json]", flags: json, positionals: none, changesState: false },
  {
    path: ["rollout", "watch"],
    summary: "turn watch mode on: every verdict is logged as usual but only the always-enforced core blocks or asks (needs the approval passphrase; logged as a signed entry)",
    usage: "rollout watch [--days N]",
    flags: { "--days": { kind: "int", min: 1, max: 90, placeholder: "N", help: "end watch mode on its own after N days (1 to 90; default 14)" } },
    positionals: none,
    changesState: true,
  },
  { path: ["rollout", "enforce"], summary: "turn watch mode off: every verdict is enforced again (logged as a signed entry)", usage: "rollout enforce", flags: {}, positionals: none, changesState: true },
  {
    path: ["rollout", "report"],
    summary: "what enforcing would have asked about, held or blocked while watch mode was on, by rule, with masked examples",
    usage: "rollout report [--since DATE|Nd] [--examples N] [--json]",
    flags: { ...json, "--since": { kind: "string", placeholder: "DATE|Nd", help: "only decisions since this date (2026-10-01) or this many days ago (7d)" }, "--examples": { kind: "int", min: 0, max: 20, placeholder: "N", help: "examples per rule (default 3)" } },
    positionals: none,
    changesState: false,
  },
  { path: ["canary"], summary: "decoy files (same as canary list)", usage: "canary [--json]", flags: json, positionals: none, changesState: false },
  { path: ["canary", "list"], summary: "the decoy files that are planted, and whether each is still there", usage: "canary list [--json]", flags: json, positionals: none, changesState: false },
  {
    path: ["canary", "plant"],
    summary: "plant decoy credential files (a read of one the firewall sees raises an alert; a send of their values it sees is denied)",
    usage: "canary plant [--workspace DIR] [--home] [--kinds env,aws,ssh,gh,notes,npmrc,kube]",
    flags: {
      "--workspace": { kind: "string", placeholder: "DIR", help: "the project to plant in (default: the current directory)" },
      "--home": { kind: "bool", help: "also plant decoys in your home directory (~/.aws, ~/.ssh, ~/.config/gh); off by default" },
      "--kinds": { kind: "string", placeholder: "LIST", help: "comma-separated kinds (default: env,aws in the workspace; aws,ssh,gh with --home)" },
    },
    positionals: none,
    changesState: true,
  },
  {
    path: ["canary", "remove"],
    summary: "delete decoys and the exclude lines that were added for them",
    usage: "canary remove <id>\ncanary remove --all",
    flags: { "--all": { kind: "bool", help: "remove every decoy (also resets a damaged registry)" } },
    positionals: { min: 0, max: 1, names: ["id"] },
    changesState: true,
  },
  { path: ["scope"], summary: "the task scope a session's prompt set (same as scope show)", usage: "scope [<session>] [--json]", flags: json, positionals: { min: 0, max: 1, names: ["session"] }, changesState: false },
  { path: ["scope", "show"], summary: "the task scope a session's prompt set, and your widenings (default: the most recent session)", usage: "scope show [<session>] [--json]", flags: json, positionals: { min: 0, max: 1, names: ["session"] }, changesState: false },
  {
    path: ["scope", "widen"],
    summary: "widen one session's task scope by a path, repository, host or intent (needs the approval passphrase)",
    usage: "scope widen <session> --path P | --repo OWNER/REPO | --host HOST | --intent push|pr|publish|deploy|message|delete|install|migrate",
    flags: {
      "--path": { kind: "string", placeholder: "P", help: "a file or directory (relative to the current directory)" },
      "--repo": { kind: "string", placeholder: "OWNER/REPO", help: "a GitHub repository" },
      "--host": { kind: "string", placeholder: "HOST", help: "a host name" },
      "--intent": { kind: "enum", values: ["push", "pr", "publish", "deploy", "message", "delete", "install", "migrate"], help: "a publish-type action the task may take" },
    },
    positionals: { min: 1, max: 1, names: ["session"] },
    changesState: true,
  },
  { path: ["caps"], summary: "the spending limits: what today and a session have used, and your raises (same as caps show)", usage: "caps [--session <id>] [--json]", flags: { ...json, "--session": { kind: "string", placeholder: "ID", help: "also show this session (default: the most recent one)" } }, positionals: { min: 0, max: 0, names: [] }, changesState: false },
  { path: ["caps", "show"], summary: "the spending limits: what today and a session have used, and your raises", usage: "caps show [--session <id>] [--json]", flags: { ...json, "--session": { kind: "string", placeholder: "ID", help: "also show this session (default: the most recent one)" } }, positionals: { min: 0, max: 0, names: [] }, changesState: false },
  {
    path: ["caps", "raise"],
    summary: "raise one spending limit for a session or for today (needs the approval passphrase)",
    usage: "caps raise toolCalls|bytesOut|identicalFailures|tokens|costUsd <amount> --session <id> | --today",
    flags: {
      "--session": { kind: "string", placeholder: "ID", help: "raise this session's limit (the id the firewall's message names)" },
      "--today": { kind: "bool", help: "raise today's limit for every session (it lapses at local midnight)" },
    },
    positionals: { min: 2, max: 2, names: ["metric", "amount"] },
    changesState: true,
  },
  {
    path: ["caps", "reset"],
    summary: "start spending-limit counters that could not be read again (needs the approval passphrase)",
    usage: "caps reset --session <id> | --today",
    flags: {
      "--session": { kind: "string", placeholder: "ID", help: "start this session's counters again" },
      "--today": { kind: "bool", help: "start today's counters again (every session)" },
    },
    positionals: { min: 0, max: 0, names: [] },
    changesState: true,
  },
  {
    path: ["check"],
    summary: 'judge one action without changing anything (reads {"tool": "...", "input": {...}, "untrusted": false, "unattended": false, "prompt": "..."} on stdin)',
    usage: "check   < action.json",
    flags: {},
    positionals: none,
    changesState: false,
    stdin: true,
  },
  {
    path: ["explain"],
    summary: "explain a rule (FW-...), a queue item, a log entry or an agent-safety rule; with no id, same as check",
    usage: "explain <id> [--json]\nexplain   < action.json",
    flags: json,
    positionals: { min: 0, max: 1, names: ["id"] },
    changesState: false,
    stdin: true,
  },
  {
    path: ["ui"],
    summary: "a read-only dashboard in your browser (127.0.0.1 only, a private address printed once); approvals stay in the terminal. Only you can start it, from your own terminal",
    usage: "ui [--project DIR] [--no-open]",
    flags: { "--project": { kind: "string", placeholder: "DIR", help: "the project doctor's checks look at (default: the current directory)" }, "--no-open": { kind: "bool", help: "print the address without opening the browser" } },
    positionals: none,
    // Person-only (docs/dashboard.md): it prints the access token to whoever starts it and opens a
    // listening socket and a browser window, so an agent may not start it, like the changing commands.
    changesState: true,
  },
  {
    path: ["run"],
    summary: "start an agent (or any command) in an OS sandbox: writes limited to the workspace and a private temporary directory (plus --allow-write); network through a local proxy that admits only your policy's hosts by name (an admitted host can still receive uploads); decisions in the signed log (macOS sandbox-exec, Linux bubblewrap; limits in docs/run.md)",
    usage: "run [--workspace DIR] [--allow-write LIST] [--send-host LIST] [--allow-localhost] [--allow-keychain] [--git-init] [--pass-env NAME]... [--allow-home-read NAME]... [--env NAME=vault://REF]... [--dry-run] [--verbose] -- <command> [args...]\nrun --agent claude|codex|gemini [other run flags] -- <agent command> [args...]\nrun --ticket T --env NAME=vault://REF... -- <command> [args...]",
    flags: {
      "--agent": { kind: "enum", values: ["claude", "codex", "gemini"], help: "a preset for this coding agent: its model API as send hosts for this run, and its switches against non-essential traffic (file rules unchanged; docs/run.md)" },
      "--env": { kind: "string", placeholder: "NAME=vault://REF", repeat: true, help: "put a vaulted secret into the command's environment as NAME (repeatable); the secret must be bound to this exact command (vault allow <name> --process \"<command>\")" },
      "--ticket": { kind: "string", placeholder: "T", help: "a single-use ticket the firewall's hook issued for exactly this --env list and command (Claude Code's rewrite of a shell command with references); runs without the sandbox, output filtered" },
      "--workspace": { kind: "string", placeholder: "DIR", help: "the directory the command may write to (default: the current directory)" },
      "--allow-write": { kind: "string", placeholder: "LIST", help: "comma-separated extra directories it may write to (never the home directory, credential stores, agent settings or system directories)" },
      "--send-host": { kind: "string", placeholder: "LIST", help: "comma-separated hosts it may send to for this run, without byte budgets (for example the agent's model API)" },
      "--allow-localhost": { kind: "bool", help: "macOS: let it connect to any port on 127.0.0.1 (local test servers; every local service becomes reachable). Linux has its own loopback" },
      "--allow-keychain": { kind: "bool", help: "macOS: let it use the keychain (denied by default, so vault items stay out of reach)" },
      "--git-init": { kind: "bool", help: "when the workspace has no .git, run git init in it before the run starts (inside the run .git cannot be created)" },
      "--pass-env": { kind: "string", placeholder: "NAME", repeat: true, help: "pass this variable of your environment to the command (repeatable; NAME_* for a prefix). Only a short list (PATH, HOME, the locale, the terminal) is passed otherwise, so tokens in your shell stay out" },
      "--allow-home-read": { kind: "string", placeholder: "NAME", repeat: true, help: "leave one of ~/.config/gh, ~/.netrc, ~/.npmrc, ~/.git-credentials, ~/.docker, ~/.kube, ~/.config/gcloud, ~/.azure readable (repeatable; written as .npmrc). ~/.ssh, ~/.aws and ~/.gnupg stay unreadable" },
      "--dry-run": { kind: "bool", help: "print the sandbox profile and the hosts, start nothing" },
      "--verbose": { kind: "bool", help: "also print each refused connection as it happens (a full-screen agent may draw over it)" },
    },
    positionals: { min: 1, max: null, names: ["command"] },
    // Started by a person (docs/run.md): an agent the hooks watch may not start it, like the changing commands.
    changesState: true,
  },
  // The local API sidecar (docs/api.md). Starting it and managing its tokens and tool registries are a person's
  // commands: an agent's tool call running any of them is FW-TAMPER (changesState), like relay run.
  {
    path: ["serve"],
    summary: "the local API sidecar for agents you build in any language: POST /v1/decide and the session endpoints on a unix socket in the firewall home (or 127.0.0.1)",
    usage: "serve --api [--listen 127.0.0.1:PORT]",
    flags: { "--api": { kind: "bool", help: "serve the local API (the only server in v0)" }, "--listen": { kind: "string", placeholder: "127.0.0.1:PORT", help: "listen on this loopback address instead of <firewall home>/api.sock; any other address is refused" } },
    positionals: none,
    changesState: true,
  },
  // NVIDIA OpenShell (docs/sandboxes.md): the firewall as a supervisor middleware, and a policy mirroring its hosts.
  {
    path: ["openshell", "serve"],
    summary: "the firewall as an NVIDIA OpenShell supervisor middleware (gRPC): each request a sandbox sends, after OpenShell's own policy allows it, is decided by the local API (serve --api) with the sandbox's session",
    usage: "openshell serve [--listen HOST:PORT] [--api-socket PATH] [--tls-cert FILE --tls-key FILE --gateway-key FILE --gateway-id ID [--audience AUD]] [--insecure]",
    flags: {
      "--listen": { kind: "string", placeholder: "HOST:PORT", help: "the address the gateway and the sandbox supervisors reach (default 127.0.0.1:50051); anything but loopback needs TLS and the gateway's key, or --insecure" },
      "--api-socket": { kind: "string", placeholder: "PATH", help: "the local API's unix socket (default <firewall home>/api.sock); the token is read from LAUNCHSAFE_FIREWALL_API_TOKEN" },
      "--tls-cert": { kind: "string", placeholder: "FILE", help: "PEM certificate for TLS (OpenShell sends its extension token only over TLS)" },
      "--tls-key": { kind: "string", placeholder: "FILE", help: "PEM private key for --tls-cert" },
      "--gateway-key": { kind: "string", placeholder: "FILE", help: "the OpenShell gateway's Ed25519 public key (PEM or JWK), from its operator: every call must carry a token it signed" },
      "--gateway-id": { kind: "string", placeholder: "ID", help: "the gateway's id (the token's issuer is openshell-gateway:<ID>)" },
      "--audience": { kind: "string", placeholder: "AUD", help: "the token audience (default urn:openshell:extension:middleware:launchsafe-firewall)" },
      "--insecure": { kind: "bool", help: "serve plaintext gRPC without verifying the caller (OpenShell's allow_insecure_transport; local development only)" },
    },
    positionals: none,
    changesState: true,
  },
  {
    path: ["openshell", "policy"],
    summary: "print an OpenShell sandbox policy (YAML) that mirrors your firewall policy's hosts and attaches the firewall's middleware",
    usage: "openshell policy [--agent claude|codex|gemini] [--send-host LIST] [--middleware NAME] [--no-middleware] [--endpoint URL] [--project DIR]",
    flags: {
      "--agent": { kind: "enum", values: ["claude", "codex", "gemini"], help: "admit this agent's model API (left out of the middleware)" },
      "--send-host": { kind: "string", placeholder: "LIST", help: "comma-separated extra hosts it may send to" },
      "--middleware": { kind: "string", placeholder: "NAME", help: "the middleware's registration name in the gateway's TOML (default launchsafe-firewall)" },
      "--no-middleware": { kind: "bool", help: "only the network and file rules, without the firewall's middleware" },
      "--endpoint": { kind: "string", placeholder: "URL", help: "where the gateway and sandboxes reach openshell serve (shown in the TOML comment)" },
      "--project": project,
    },
    positionals: none,
    changesState: false,
  },
  { path: ["api", "token", "add"], summary: "make a new API token for an agent; it is printed once and only its SHA-256 is kept", usage: "api token add <agentId> [--traffic network] [--role decide|report|prompt ...]", flags: { "--traffic": { kind: "enum", values: ["network"], help: "a network middleware's token (OpenShell's, docs/sandboxes.md): it may send context.traffic \"network\" for its HTTP requests, which are not counted as the agent's tool calls" }, "--role": { kind: "string", placeholder: "ROLE", repeat: true, help: "what the token may do: decide (decide, read sessions and approvals), report (results and inputs), prompt (prompts whose destinations and task scope apply; for the part that reads what the person typed). Repeat it or use commas. Default: decide and report" } }, positionals: { min: 1, max: 1, names: ["agentId"] }, changesState: true },
  { path: ["api", "token", "list"], summary: "the agents that have API tokens (never a token)", usage: "api token list [--json]", flags: json, positionals: none, changesState: true },
  { path: ["api", "token", "revoke"], summary: "revoke every API token of an agent", usage: "api token revoke <agentId>", flags: {}, positionals: { min: 1, max: 1, names: ["agentId"] }, changesState: true },
  { path: ["api", "tools", "set"], summary: "set an agent's tool registry from a JSON file (validated like the library's tool specs)", usage: "api tools set <agentId> <file.json>", flags: {}, positionals: { min: 2, max: 2, names: ["agentId", "file.json"] }, changesState: true },
  { path: ["api", "tools", "show"], summary: "print an agent's tool registry", usage: "api tools show <agentId>", flags: {}, positionals: { min: 1, max: 1, names: ["agentId"] }, changesState: true },
  { path: ["demo"], summary: "replay attack scenarios from published research and real incidents through the policy", usage: "demo", flags: {}, positionals: none, changesState: false },
  { path: ["version"], summary: "print the version", usage: "version", flags: {}, positionals: none, changesState: false },
  { path: ["help"], summary: "help for a command", usage: "help [command...]", flags: {}, positionals: { min: 0, max: null, names: ["command"] }, changesState: false },
  {
    path: ["native-host"],
    summary: "the browser link's host: the browser starts it for the LaunchSafe extension (reads native messages on stdin)",
    usage: "native-host <origin>",
    flags: {},
    positionals: { min: 0, max: 1, names: ["origin"] },
    // Started by the browser through the launcher install wrote: an agent may not start it (it writes the log and taint).
    changesState: true,
    stdin: true,
    hidden: true,
  },
  {
    path: ["hook"],
    summary: "the agent hook (reads the event on stdin)",
    usage: "hook [--agent claude|codex|gemini|cursor] [--record DIR]",
    flags: { "--agent": { kind: "enum", values: ["claude", "codex", "gemini", "cursor"], help: "which agent sends the event (default claude)" }, "--record": { kind: "string", placeholder: "DIR", help: "also save each raw event to DIR (only with LAUNCHSAFE_FIREWALL_RECORD=1)" } },
    positionals: none,
    changesState: true,
    stdin: true,
  },
];

const HELP_FLAGS = new Set(["--help", "-h"]);

/** The spec whose path is the longest prefix of the leading words. */
function matchSpec(argv: readonly string[]): CommandSpec | null {
  let best: CommandSpec | null = null;
  for (const s of COMMANDS) {
    if (s.path.length > argv.length) continue;
    if (!s.path.every((p, i) => argv[i] === p)) continue;
    if (best === null || s.path.length > best.path.length) best = s;
  }
  return best;
}

/** Parses a command line (the words after the program name) against COMMANDS. Pure. */
export function parseCommandLine(argv: readonly string[]): Parsed {
  const dashdash = argv.indexOf("--");
  const head = dashdash === -1 ? argv : argv.slice(0, dashdash);
  const spec = matchSpec(argv);
  // --help wins over everything, wherever it is before "--".
  if (head.some((a) => HELP_FLAGS.has(a))) return { kind: "help", spec };
  if (argv.length === 0) return { kind: "help", spec: null };
  if (argv.length === 1 && (argv[0] === "--version" || argv[0] === "-v")) return parseCommandLine(["version"]);
  if (spec === null) return { kind: "error", message: `unknown command "${argv[0] ?? ""}"`, spec: null };
  const flags = new Map<string, string | true>();
  const lists = new Map<string, string[]>();
  const positionals: string[] = [];
  const rest = argv.slice(spec.path.length);
  const short = spec.short ?? {};
  let endOfFlags = false;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i] as string;
    if (!endOfFlags && a === "--") {
      endOfFlags = true;
      continue;
    }
    if (!endOfFlags && a.startsWith("-") && a !== "-") {
      const eq = a.indexOf("=");
      const rawName = eq === -1 ? a : a.slice(0, eq);
      const name = own(short, rawName) ?? rawName;
      const f = own(spec.flags, name);
      if (f === undefined) return { kind: "error", message: `unknown flag ${rawName}`, spec };
      if (flags.has(name) && !(f.kind === "string" && f.repeat === true)) return { kind: "error", message: `${name} given more than once`, spec };
      if (f.kind === "bool") {
        if (eq !== -1) return { kind: "error", message: `${name} does not take a value`, spec };
        flags.set(name, true);
        continue;
      }
      let value: string | undefined;
      if (eq !== -1) value = a.slice(eq + 1);
      else {
        value = rest[i + 1];
        if (value === undefined || (value.startsWith("-") && value !== "-")) return { kind: "error", message: `${name} needs a value`, spec };
        i++;
      }
      if (value === "") return { kind: "error", message: `${name} needs a value`, spec };
      if (f.kind === "enum" && !f.values.includes(value)) return { kind: "error", message: `${name} must be one of ${f.values.join(", ")}`, spec };
      if (f.kind === "int") {
        const n = Number(value);
        if (!/^-?\d+$/.test(value) || (f.min !== undefined && n < f.min) || (f.max !== undefined && n > f.max)) return { kind: "error", message: `${name} must be a whole number${f.min !== undefined ? ` from ${f.min}` : ""}${f.max !== undefined ? ` to ${f.max}` : ""}`, spec };
      }
      flags.set(name, value);
      if (f.kind === "string" && f.repeat === true) lists.set(name, [...(lists.get(name) ?? []), value]);
      continue;
    }
    positionals.push(a);
  }
  const p = spec.positionals;
  const label = p.names[0] ?? "argument";
  if (positionals.length < p.min) return { kind: "error", message: p.max === null ? `needs at least one ${label}` : `needs ${p.names.slice(0, p.min).map((n) => `<${n}>`).join(" ")}`, spec };
  if (p.max !== null && positionals.length > p.max) return { kind: "error", message: `unexpected argument "${positionals[p.max] ?? ""}"`, spec };
  if (p.int === true && positionals.some((x) => !/^\d+$/.test(x))) return { kind: "error", message: `<${label}> must be a whole number`, spec };
  return { kind: "ok", spec, flags, positionals, ...(lists.size > 0 ? { lists } : {}) };
}

function flagLine(name: string, f: FlagSpec): string {
  const arg = f.kind === "bool" ? "" : f.kind === "enum" ? ` ${f.values.join("|")}` : f.kind === "string" ? ` ${f.placeholder}` : ` ${f.placeholder ?? "N"}`;
  return `  ${`${name}${arg}`.padEnd(32)} ${f.help ?? ""}`.trimEnd();
}

/** The help text for one command, or the top-level help when spec is null. */
export function helpText(spec: CommandSpec | null): string {
  if (spec === null) {
    const lines = [`${PROGRAM} ${VERSION}: the firewall for AI agents`, "", "Usage:"];
    for (const s of COMMANDS) {
      if (s.hidden === true) continue;
      for (const u of s.usage.split("\n")) lines.push(`  ${PROGRAM} ${u}`);
    }
    lines.push("", `Run "${PROGRAM} <command> --help" for one command's options.`, "", "No telemetry. Decisions make no network calls unless you pair a phone (experimental).");
    return lines.join("\n");
  }
  const lines = [`${PROGRAM} ${spec.path.join(" ")}: ${spec.summary}`, "", "Usage:"];
  for (const u of spec.usage.split("\n")) lines.push(`  ${PROGRAM} ${u}`);
  const fl = Object.entries(spec.flags);
  lines.push("", "Options:");
  for (const [n, f] of fl) lines.push(flagLine(n, f));
  lines.push(flagLine("-h, --help", { kind: "bool", help: "show this help and exit (changes nothing)" }));
  const subs = COMMANDS.filter((s) => s.path.length === spec.path.length + 1 && spec.path.every((p, i) => s.path[i] === p));
  if (subs.length > 0) {
    lines.push("", "Subcommands:");
    for (const s of subs) lines.push(`  ${(s.path[s.path.length - 1] as string).padEnd(32)} ${s.summary}`);
  }
  if (spec.changesState) lines.push("", "This command changes the firewall or your settings, or is for you only, so the firewall refuses it when an agent runs it.");
  return lines.join("\n");
}

/** The usage error line the CLI prints (exit 64). */
export function usageError(p: Extract<Parsed, { kind: "error" }>): string {
  const path = p.spec === null ? "" : ` ${p.spec.path.join(" ")}`;
  return `${PROGRAM}${path}: ${p.message}. Run "${PROGRAM}${path} --help".`;
}

/**
 * Whether running the firewall's CLI with these arguments (the words after the program) cannot change
 * anything. Derived from COMMANDS, so a new subcommand is state-changing unless declared otherwise.
 * Any --help/-h makes it read-only (help has no side effects). A usage error is read-only only for a
 * read-only command; "doctor --fix" is never read-only.
 */
export function isReadOnlyInvocation(words: readonly string[]): boolean {
  const p = parseCommandLine(words);
  if (p.kind === "help") return true;
  const dashdash = words.indexOf("--");
  const head = dashdash === -1 ? words : words.slice(0, dashdash);
  if (p.spec === null || p.spec.changesState) return false;
  if (p.spec.path[0] === "doctor" && head.some((w) => w === "--fix" || w.startsWith("--fix=") || w === "--repair-state")) return false;
  return true;
}
