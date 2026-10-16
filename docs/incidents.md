# Public incidents and the rules that answer them

Each entry is a published attack on an AI agent, or (INC-12 to INC-16) a
well-known attack pattern. For each we give a short, neutral summary (no
exploit payloads), the firewall rule that denies, holds or puts to you the
**action** the attack depends on, and the test id. INC-01 to INC-16 are
modelled in `src/scenarios.ts` (18 scenarios: INC-02 and INC-08 each have an
unattended variant) as the hook events we expect Claude Code to emit for the
attack's actions, written by us from the public write-ups (they are not
recordings of the attacks), and run in `test/scenarios.test.ts`. INC-21, INC-29, INC-30 and INC-31 are
catalogue scenarios: rows of the firewall's coverage catalogue, modelled on
public reports (only INC-21 links its source here; the others are described
from reports we have not linked, so treat them as scenarios, not citations),
and the three
package-vetting incidents run in `test/intel.test.ts`. Run the first 16
yourself: `launchsafe-firewall demo`. For
any rule named below, `launchsafe-firewall explain <rule>` (for example
`launchsafe-firewall explain FW-SEND`) explains what it stops, when it applies,
whether you can approve it and which incidents it answers.

The common thread: in every case the agent was *fooled* by content. The
firewall does not try to un-fool it. It gates the damaging action the attack
depends on, when that action goes through a tool the firewall can see. A
variant that reaches the same goal through an action outside the rules (an
allowlisted host, a program the hooks cannot see) is not covered; see
[limitations.md](limitations.md).

---

## INC-01 — EchoLeak (M365 Copilot, zero-click) — CVE-2025-32711

**What happened.** A crafted email caused Microsoft 365 Copilot to take private
data from the user's tenant and leak it through an auto-fetched image URL, with
no user interaction. (Aim Security.)
Source: <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711>

**What stops it.** The session is untrusted after reading the email and the
private file. Fetching a URL to a host the user never named is sent to a person
(**FW-FETCH**); if the URL carries a secret the session has seen, it is denied
outright (**FW-DLP-SEEN-SECRET**), including when the secret is base64/hex/URL
encoded. Test **INC-01** (FW-FETCH) and catalogue row **INC-01** (FW-DLP-SEEN-SECRET).

## INC-02 — GitHub MCP toxic agent flow (Invariant Labs, 2025)

**What happened.** A malicious issue in a public repo steers the agent into
reading a private repo and opening a public pull request containing the private
contents.
Source: <https://invariantlabs.ai/blog/mcp-github-vulnerability>

**What stops it.** Reading issues from a forge taints the session. Creating the
public PR is an external send and needs a person (**FW-SEND**); unattended it is
queued. Test **INC-02** / **INC-02b**.

## INC-03 — MCP tool poisoning (Invariant Labs, 2025)

**What happened.** Hidden instructions in a tool's description tell the agent to
read `~/.ssh` keys and pass them as a tool argument.
Source: <https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks>

**What stops it.** Reading a credential store is always sent to a person, in any
session (**FW-CREDENTIAL-READ**) — no ordinary coding task reads `~/.ssh` or
`~/.aws`. Test **INC-03**.

## INC-04 — MCPoison / rug pull (Check Point) — CVE-2025-54136

**What happened.** An already-approved MCP configuration is silently swapped for
a different command, gaining persistent code execution on each run.
Source: <https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison>

**What stops it.** Writing `.mcp.json`, `.cursor/mcp.json` or `.claude/settings`
is an agent-settings change and needs a person even in a trusted session
(**FW-AGENT-SETTINGS**), because those files can make code run in every future
session. Test **INC-04**. A swap made outside the agent (a `git pull`, another
tool) is caught at the next session start: the server's configuration no longer
matches its pin, so the session starts untrusted and the server's results count
as outside content until you run `launchsafe-firewall pins accept <server>`
(**FW-MCP-CHANGED**; catalogue row **MCP-028**). A changed tool
*description* the firewall sees in a ToolSearch result is treated the same way.

## INC-05 — CurXecute (Aim Security) — CVE-2025-54135

**What happened.** Content from a chat/MCP server leads the agent to create an
MCP config file, which triggers code execution.
Source: <https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison>

**What stops it.** After the untrusted chat content, writing an agent-settings
file is held as a proposal, never applied (**FW-INSTRUCTIONS-HELD**). Test
**INC-05**.

## INC-06 — WhatsApp MCP exfiltration (Invariant Labs, 2025)

**What happened.** Tool poisoning plus unrestricted messaging lets an attacker
have the agent send the user's message history to the attacker's number, looking
like a normal message.
Source: <https://invariantlabs.ai/blog/whatsapp-mcp-exploited>

**What stops it.** After reading message history (untrusted, private), sending a
message to a recipient the user never named needs a person (**FW-MESSAGE**).
Test **INC-06**.

## INC-07 — Supabase MCP lethal trifecta (General Analysis, 2025)

**What happened.** A support ticket contains instructions; the agent, holding a
service-role database connection, reads a private table and writes its contents
back into a ticket the attacker can read.
Source: <https://simonwillison.net/2025/Jul/06/supabase-mcp-lethal-trifecta/>

**What stops it.** The firewall classifies the SQL by what it does. Writing data
back out through the MCP server after untrusted input needs a person
(**FW-SEND**); a destructive statement is caught separately
(**FW-DESTRUCTIVE**). Test **INC-07**.

## INC-08 — Amazon Q extension destructive prompt (AWS, 2025) — AWS-2025-015

**What happened.** A prompt injected into a shipped extension instructed the
agent to delete the user's home directory and tear down cloud resources.
Source: <https://aws.amazon.com/security/security-bulletins/AWS-2025-015/>

**What stops it.** `rm -rf ~` / `rm -rf /` is denied outright
(**FW-DESTROY-ROOT**). Deleting a bucket (`s3 rb --force`) is denied too
(**FW-CATASTROPHIC**), also in the bypass modes of Claude Code, Codex and
Gemini CLI; this was not verified for Cursor. Other cloud deletions
(`aws ... terminate-instances`, `iam delete-user`) are destructive and need a
person (**FW-DESTRUCTIVE**); unattended they are queued. Tests **INC-08** /
**INC-08b**.

## INC-09 — Nx "s1ngularity" supply-chain attack (2025)

**What happened.** A malicious npm package's postinstall script launched local
AI CLIs (Claude, Gemini, q) with their safety switched off to inventory the file
system and exfiltrate credentials; over 6,700 repos were exposed.
Sources: <https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c>,
<https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware>

**What stops it.** Starting another coding agent with its safety flags disabled
(`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`) is denied
outright (**FW-AGENT-BYPASS**). Reading wallet/credential stores is queued
(**FW-CREDENTIAL-READ**). Test **INC-09**. Once the compromised
versions are in OSV's malicious-package data, installing them — directly or
from a lockfile that pins them — is denied (**FW-MALICIOUS-PACKAGE**). Test
**INC-27** in `test/intel.test.ts`.

## INC-10 — Claude Code DNS exfiltration — CVE-2025-55284

**What happened.** Prompt injection in analyzed code used auto-approved
utilities (`ping`, `nslookup`, `dig`) to encode secrets into subdomains of
outbound DNS lookups. (Reported by Embrace The Red; the link below is a
third-party write-up on jmason.ie, not the original.)
Source: <https://jmason.ie/2025/08/25/161304a.html>

**What stops it.** A host name built from local data — a long or high-entropy
label in front of a domain — is denied (**FW-DNS-EXFIL**), and known
data-capture/interactsh hosts are denied (**FW-CAPTURE-HOST**). Test **INC-10**.

## INC-11 — Markdown-image / CamoLeak pattern (GitHub Copilot Chat, 2025)

**What happened.** Hidden instructions in a PR made Copilot encode discovered
secrets as a sequence of image requests, reconstructing them from which image
URLs were fetched.
Source: <https://legitsecurity.com/blog/camoleak-critical-github-copilot-vulnerability-leaks-private-source-code>

**What stops it.** After reading the untrusted PR, fetching URLs on a host the
user never named needs a person (**FW-FETCH**); a URL that carries data in its
path or query asks (**FW-FETCH-DATA**; catalogue row **INC-11**). Test **INC-11** asserts FW-FETCH. This answers the pattern, not the real attack's path: the real
attack went through GitHub's own image proxy, which a hook cannot see, so only
the agent's own fetch of a URL on a host nobody named is stopped.

## INC-12 — Memory / instruction poisoning

**What happened.** A poisoned web page persuades the agent to rewrite its own
long-term memory or `CLAUDE.md`, changing its behavior in later sessions.
Source (framing): <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>

**What stops it.** After reading the page, any write to agent memory or
instructions is held as a proposal and never applied by the agent
(**FW-INSTRUCTIONS-HELD**). Test **INC-12**.

## INC-13 — Hook / firewall tampering

**What happened.** An injected instruction tries to disable the security hooks
or remove the firewall so later actions go unchecked.

**What stops it.** Changes to the firewall or its hook settings through
actions the firewall can see are denied (**FW-TAMPER**): `disableAllHooks`,
deleting `~/.launchsafe-firewall`, editing its config, or `launchsafe-firewall
uninstall`/`queue approve` from inside the agent. A program the analyzer cannot
see into could still write those files; approvals stay safe because they must
be signed with the key your passphrase unlocks. Managed settings make the
registration impossible for a repository or user setting to remove. Test
**INC-13**.

## INC-14 — Cloud metadata credential theft

**What happened.** The agent is directed to the instance metadata service
(169.254.169.254), which hands out the machine's cloud credentials.

**What stops it.** A request the firewall can see to a known metadata endpoint
is denied (**FW-METADATA**). A program the hooks cannot see that makes the
request itself is not covered (`run`'s proxy refuses metadata endpoints for
the programs it starts). Test **INC-14**.

## INC-15 — Persistence

**What happened.** After untrusted input, the agent is steered into writing a
git hook or a shell start-up line that will run code later without anyone asking.

**What stops it.** Writes to persistence points (git hooks, CI workflows, editor
tasks, dev containers, environment hooks, shell rc files, launch agents, cron)
need a person (**FW-PERSISTENCE**); after outside content, a git hook is never
written by the agent at all but kept as a proposal (**FW-PERSISTENCE-HELD**).
In a trusted session, a change that adds a way for code to run
by itself asks (**FW-AUTORUN**). Test **INC-15**.

## INC-16 — Download-and-run

**What happened.** After untrusted input, the agent pipes a downloaded script
straight into a shell.

**What stops it.** A download piped into an interpreter is denied in an
untrusted session and asked in a trusted one (**FW-REMOTE-CODE**). Test **INC-16**.

## INC-21 — Copilot settings flip to auto-approve (CVE-2025-53773)

**What happened.** Injected instructions made the agent edit the project's
`.vscode/settings.json` to switch on its own auto-approval of tool calls, after
which every later command ran without asking.
Source: <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53773>

**What stops it.** A change to editor settings that switches on an agent's
auto-approval asks even in a trusted session (**FW-AUTORUN**, with
**FW-AGENT-SETTINGS**) and is held as a proposal (**FW-INSTRUCTIONS-HELD**) in an untrusted one. Catalogue row **INC-21**.

## INC-31 — Git-hook escape (catalogue scenario; reported 2026)

**What happened.** After reading a file from a repository, the agent wrote a
git hook, which then ran outside the agent's own controls on the next checkout.

**What stops it.** A git hook written by an untrusted session is held as a
proposal and never applied by the agent (**FW-PERSISTENCE-HELD**);
a shell write to a hook in a trusted session asks, because its content cannot
be checked (**FW-AUTORUN**). Catalogue row **INC-31**.

## INC-29 — Malicious marketplace skills (catalogue scenario; reported for ClawHub, 2026)

**What happened.** Skills published to a public marketplace carried scripts
that downloaded and ran code once the agent used the skill.

**What stops it.** The session-start scan runs LaunchSafe's
agent-safety rules over `.claude/skills/` (the workspace's and
`~/.claude/skills/`): a skill script that pipes a download into a shell is a
critical finding (`ls-agent-auto-run-remote-code`), so the session starts
untrusted and the damaging action classes need a person. Catalogue row **INC-29**.

## INC-30 — Repository configuration trusted too early (catalogue scenario; reported for Claude Code as CVE-2026-21852)

**What happened.** A repository's `.claude/settings.json` moved the model
endpoint to an attacker's server, so prompts and code were sent there.

**What stops it.** The session-start scan flags a model endpoint moved to
another host (`ls-agent-model-endpoint-override`, high severity, high
confidence) and the session starts untrusted. Catalogue row **INC-30**. (The
firewall cannot stop Claude Code itself from using the endpoint; it makes sure
the session cannot also send data or change settings without a person.)

---

## Package-vetting incidents

These run in `test/intel.test.ts` against a fixture snapshot with invented
package names (the real names and versions come from OSV at `update` time).

- **INC-26 — a malicious MCP server on npm (postmark-mcp pattern, 2025).** A
  package published as an MCP server turned malicious in a later version; it is
  usually launched with `npx`. A listed version run through a package runner is
  denied (**FW-MALICIOUS-PACKAGE**).
- **INC-27 — a compromised build-tool version in a lockfile (Nx pattern).** `npm
  ci` from a lockfile that pins a listed version is denied before anything
  installs (**FW-MALICIOUS-PACKAGE**, finding `lockfile_malicious`).
- **INC-28 — a backdoored PyPI release (LiteLLM pattern, 2026).** `pip install
  <name>==<listed version>` is denied; a later, unlisted version is allowed
  (**FW-MALICIOUS-PACKAGE**).
