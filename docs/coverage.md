# Coverage: what the firewall does and does not cover

<!-- Generated from src/rules.ts and src/frameworks.ts by scripts/gen-coverage.mjs (npm run gen:docs); do not edit by hand. CI runs npm run check:docs. -->

This maps every rule the firewall emits to four public frameworks, and states,
for each framework item, whether the firewall covers it, covers it partly, or
does not cover it. Each rule's mapping lives with the rule in `src/rules.ts`;
the items, their verification, the coverage claimed and the gaps live in
`src/frameworks.ts`. This page and the machine-readable [`coverage.json`](coverage.json)
are generated from both. `test/coverage-mapping.test.ts` fails if a rule id in
the code has no mapping, if a mapping names a rule or an item that does not
exist, or if this page and the JSON disagree. `launchsafe-firewall explain <rule>`
shows one rule's mapping.

How to read the status:

- **covered**: the firewall deterministically gates the agent-side attack path
  the item describes. The "gap" column still lists what remains.
- **partly**: some of the item's attack paths are gated; the gap says which are not.
- **not covered**: no rule in effect addresses it. We say so rather than
  stretch a rule to fit.

A rule that "maps" to an item reduces risk on one path of it; it does not make
the item go away. The firewall governs a coding agent's actions through hooks. It
does not stop a model being fooled, and it is not a sandbox. Where the honest
mitigation is a sandbox, managed settings or a planned item, the table says so.
Planned rules (roadmap items, not in the code yet) are listed at the end with
their intended mapping and are not counted.

## Summary

| Framework | covered | partly | not covered |
|---|---|---|---|
| OWASP Top 10 for LLM Applications (2025) | 0 | 6 | 4 |
| OWASP Top 10 for Agentic Applications | 0 | 8 | 2 |
| MITRE ATLAS (agent-relevant techniques) | 0 | 17 | 3 |
| MCP specification security requirements | 0 | 9 | 5 |

Rule count: 79 rules emitted by the engine, plus the `FW-APPROVED` marker (Approved once by a person; it is not a control and maps to nothing), the `FW-LEARNED-ALLOW` marker (Always allowed in this project by your choice; it is not a control and maps to nothing); 0 planned.

## Verification status

Checked on 2026-10-09 against primary sources.

| Source | Status | Notes |
|---|---|---|
| OWASP Top 10 for LLM Applications (2025) | verified | All ten ids and names read from the official page. Source: https://genai.owasp.org/llm-top-10/ |
| OWASP Top 10 for Agentic Applications | verified (names); descriptions from the OWASP announcement | ASI01 to ASI10 ids and names read from the OWASP announcement post. The resource page https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ lists no items in its text and the PDF was not read. Source: https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/ |
| MITRE ATLAS (agent-relevant techniques) | verified against MITRE's published data, not the atlas.mitre.org pages | atlas.mitre.org technique pages returned 404 to the fetch tool. The data file carries a notice that it is deprecated in favour of newer data in the same repository; ids and names were checked in that file, so a rename in a later release would not be seen. Source: https://github.com/mitre-atlas/atlas-data (dist/ATLAS.yaml, version 5.6.0) |
| MITRE ATT&CK (supplementary) | verified except T1562.001 | Titles of T1048, T1071.004, T1552, T1059, T1027, T1485, T1548, T1546, T1053, T1195.001, T1030 and T1105 were read from attack.mitre.org. T1562.001 could not be fetched and is unverified. Source: https://attack.mitre.org/techniques/ |
| MCP specification security requirements | verified | Requirement wording read from both pages. The security best practices page now serves the 2025-11-25 text, which cross-references the 2025-11-25 authorization spec; the tools page is 2025-06-18. Requirement levels (MUST, SHOULD) are as on those pages. Source: https://modelcontextprotocol.io/specification/2025-06-18/server/tools and /basic/security_best_practices |

**Could not be verified:**

- An ATLAS technique for triggers hidden in multimodal inputs was considered but not found in ATLAS data 5.6.0, so none is used (AML.T0068 LLM Prompt Obfuscation is used for FW-HIDDEN-TEXT instead).
- ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools): the page could not be fetched, so its id and title were not checked against attack.mitre.org.
- OWASP Agentic Top 10 item descriptions beyond the names (taken from the announcement post, not the full PDF).

## OWASP Top 10 for LLM Applications (2025)

| Item | Status | Rules | Gap | Mitigation |
|---|---|---|---|---|
| **LLM01:2025** Prompt Injection | partly | `FW-SEND`, `FW-MESSAGE`, `FW-SEND-ARGS`, `FW-FETCH`, `FW-NEW-HOST`, `FW-INSTRUCTIONS-HELD`, `FW-INSTRUCTIONS`, `FW-HIDDEN-TEXT`, `FW-RESULT-UNRECORDED`, `FW-MCP-CHANGED`, `FW-OUTSIDE-COMMAND`, `FW-HIDDEN-OUTPUT`, `FW-MCP-TOOL-HELD`, `FW-MCP-WITHHELD`, `FW-MCP-SAMPLING`, `FW-MAIL-WITHHELD` | The firewall does not stop a model being fooled. It limits what a fooled agent may do after reading outside content. An injected instruction that only asks for an action inside the allowed envelope (an edit in the workspace, a misleading answer to the user) is not stopped. | Run the agent in an OS sandbox; deploy managed settings; review diffs before merging. |
| **LLM02:2025** Sensitive Information Disclosure | partly | `FW-SEND`, `FW-MESSAGE`, `FW-SEND-ARGS`, `FW-FETCH`, `FW-FETCH-DATA`, `FW-NEW-HOST`, `FW-DLP-CREDENTIAL`, `FW-DLP-SEEN-SECRET`, `FW-DLP-PERSONAL`, `FW-CREDENTIAL-READ`, `FW-SECRET-FLOW`, `FW-SECRET-VARIABLE`, `FW-METADATA`, `FW-CREDENTIAL-FLOW`, `FW-SECRET-FILE-PUBLISH`, `FW-CAPTURE-HOST`, `FW-DNS-EXFIL`, `FW-RAW-IP`, `FW-NET-REFUSED`, `FW-BUDGET-BYTES`, `FW-BUDGET-REQUESTS`, `FW-BUDGET-MCP`, `FW-CANARY-READ`, `FW-CANARY-EGRESS`, `FW-VAULT-EGRESS`, `FW-VAULT-UNBOUND`, `FW-VAULT-INDEX`, `FW-VAULT-UNSUPPORTED`, `FW-VAULT-OPTION`, `FW-VAULT-APPROVE`, `FW-MCP-AUTH` | Covers disclosure through the agent's own tool actions (network sends, fetches, messages, DNS, credential reads). Does not cover what the model provider sees in the prompt, leaks into the chat transcript, or data sent to a host the policy allows. | Keep secrets out of the working tree; use a sandbox with network egress rules; review allow-host lists (sendAllowHosts, dataAllowHosts). |
| **LLM03:2025** Supply Chain | partly | `FW-AGENT-SETTINGS`, `FW-INSTALL`, `FW-MCP-CHANGED`, `FW-MALICIOUS-PACKAGE`, `FW-TYPOSQUAT`, `FW-MCP-TOOL-HELD` | Checks every install and package runner offline: a version listed in the local OSV malicious-package snapshot (downloaded by the person with update; none ships) is denied by default (packageIntel.malicious can make it ask or turn it off), including versions a lockfile install would fetch (FW-MALICIOUS-PACKAGE), and a look-alike of a popular name needs a person (FW-TYPOSQUAT). Also gates installs after outside content and changes to agent and MCP configuration, and pins each MCP server (FW-MCP-CHANGED). Does not catch a malicious package not yet listed, a snapshot the person has not downloaded (none ships) or refreshed, or a malicious model. | Run launchsafe-firewall update regularly; set a release-age cooldown (doctor --fix); pin and lock dependencies; use managed settings to allow-list MCP servers. |
| **LLM04:2025** Data and Model Poisoning | not covered | none | Out of scope: training, fine-tuning and embedding-store poisoning are outside a coding-agent firewall. (Changes to the agent's own instruction and memory files after outside content are held as proposals; that is mapped under LLM01 and ASI06, not here.) | Control training and RAG data at the pipeline; review instruction-file changes in code review. |
| **LLM05:2025** Improper Output Handling | partly | `FW-REMOTE-CODE`, `FW-OBFUSCATED`, `FW-UNTRUSTED-CODE`, `FW-TAINTED-MANIFEST`, `FW-OPAQUE-CODE`, `FW-UNCLASSIFIABLE`, `FW-OUTSIDE-COMMAND` | Covers the agent executing code the model or an outsider supplied on the developer's machine (downloaded scripts, decoded payloads, build files changed after outside content, opaque code). Does not cover output rendered by a downstream web application (XSS, injection into other systems). | Validate and encode model output in the application that consumes it; sandbox code execution. |
| **LLM06:2025** Excessive Agency | partly | `FW-SEND`, `FW-MESSAGE`, `FW-SEND-ARGS`, `FW-NEW-HOST`, `FW-CREDENTIAL-READ`, `FW-SECRET-FLOW`, `FW-AGENT-SETTINGS`, `FW-PERSISTENCE`, `FW-OUTSIDE-WRITE`, `FW-DESTRUCTIVE`, `FW-CATASTROPHIC`, `FW-DESTROY-ROOT`, `FW-PRIVILEGE`, `FW-SYMLINK`, `FW-REMOTE-CODE`, `FW-OBFUSCATED`, `FW-UNTRUSTED-CODE`, `FW-TAINTED-MANIFEST`, `FW-INSTALL`, `FW-OPAQUE-CODE`, `FW-UNCLASSIFIABLE`, `FW-AGENT-BYPASS`, `FW-AGENT-SPAWN`, `FW-TAMPER`, `FW-POLICY-ERROR`, `FW-UNKNOWN-TOOL`, `FW-NET-REFUSED`, `FW-BLOCKED-TOOL`, `FW-LEARNED-DENY`, `FW-LOG-UNRECORDED`, `FW-UNAVAILABLE`, `FW-RATE-LIMITED`, `FW-API-ERROR`, `FW-SCOPE`, `FW-AUTORUN`, `FW-PERSISTENCE-HELD`, `FW-STOPPED`, `FW-VAULT-EGRESS`, `FW-VAULT-UNBOUND`, `FW-VAULT-OPTION`, `FW-VAULT-APPROVE`, `FW-OUTSIDE-COMMAND`, `FW-MCP-SAMPLING` | The firewall's core job: every tool call the hooks see is classified and gated by effect, with approval required for send, destructive, persistence, privilege, agent-settings and code-execution classes, and denial for the worst. Remaining gap: shell analysis is static, so code it cannot see into is judged strictly but not understood, and programs the agent starts act unseen; it limits autonomy per action but does not reduce the permissions the agent's tools hold; and only agents with hook support are covered (Claude Code first). | Give the agent least-privilege credentials; use a sandbox for process, file-system and network isolation. |
| **LLM07:2025** System Prompt Leakage | not covered | none | Out of scope: the firewall governs actions, not what the model says about its own prompt. (Credential-shaped content leaving the machine is covered under LLM02.) | Do not put secrets in system prompts; treat the system prompt as public. |
| **LLM08:2025** Vector and Embedding Weaknesses | not covered | none | Out of scope: no vector store or embedding pipeline is in the firewall's path. | Access control and tenant isolation in the vector store; validate documents before embedding. |
| **LLM09:2025** Misinformation | not covered | none | Out of scope: the firewall cannot judge whether the model's claims or generated code are correct. | Tests, code review, and grounding the model in trusted sources. |
| **LLM10:2025** Unbounded Consumption | partly | `FW-INPUT-SHAPE`, `FW-RATE-LIMITED`, `FW-BUDGET-BYTES`, `FW-BUDGET-REQUESTS`, `FW-BUDGET-MCP`, `FW-LOOP`, `FW-STOPPED`, `FW-CAP`, `FW-CAP-WARN` | Per-session budgets make volume visible: outbound bytes per host and in total, requests per host and calls per MCP server in 10 minutes, and loop detection (the same action 8 times with no write in between, or 25 non-allowed verdicts in 10 minutes) turn the next action into an approval. Spending limits (FW-CAP) stop the agent at a cap per session and per day on tool calls, data sent and identical failures, and on model tokens and cost an agent reports through the local API or the library. Remaining gap: coding agents' hooks report no model usage, so their token and cost caps do not apply. | Provider-side spend limits and rate limits; agent turn and budget limits in the agent's own settings. |

## OWASP Top 10 for Agentic Applications

| Item | Status | Rules | Gap | Mitigation |
|---|---|---|---|---|
| **ASI01** Agent Goal Hijack | partly | `FW-SEND`, `FW-MESSAGE`, `FW-SEND-ARGS`, `FW-FETCH`, `FW-NEW-HOST`, `FW-HIDDEN-TEXT`, `FW-SCOPE`, `FW-CANARY-READ`, `FW-CANARY-EGRESS`, `FW-OUTSIDE-COMMAND`, `FW-HIDDEN-OUTPUT`, `FW-MCP-WITHHELD`, `FW-MCP-SAMPLING`, `FW-MAIL-WITHHELD` | Same gap as LLM01: the hijack itself is not prevented; the damaging actions it depends on (exfiltration, destructive, persistence, instruction rewrite) are gated. A hijack that stays inside permitted actions is not stopped. | Sandbox; managed settings; human review of the agent's output. |
| **ASI02** Tool Misuse | partly | `FW-SEND`, `FW-MESSAGE`, `FW-SEND-ARGS`, `FW-FETCH`, `FW-FETCH-DATA`, `FW-NEW-HOST`, `FW-CAPTURE-HOST`, `FW-DNS-EXFIL`, `FW-RAW-IP`, `FW-OUTSIDE-WRITE`, `FW-DESTRUCTIVE`, `FW-CATASTROPHIC`, `FW-DESTROY-ROOT`, `FW-SYMLINK`, `FW-AGENT-BYPASS`, `FW-UNKNOWN-TOOL`, `FW-NET-REFUSED`, `FW-BLOCKED-TOOL`, `FW-LEARNED-DENY`, `FW-SCOPE`, `FW-MCP-METHOD` | MCP tools are classified by their name and arguments (a verb in the tool name decides read, send or destroy) plus the effects of paths, URLs, SQL and shell commands; a tool whose name misdescribes it can be misclassified. A legitimate tool bent to a harmful use is still gated: sends, fetches, destructive commands, writes outside the project, unknown tools. Remaining gap: misuse within an allowed envelope (an allowed host, an in-project edit), and shell effects the static analysis does not model (see docs/limitations.md). | Narrow allow-lists; sandbox; scoped credentials. |
| **ASI03** Identity and Privilege Abuse | partly | `FW-DLP-CREDENTIAL`, `FW-DLP-SEEN-SECRET`, `FW-DLP-PERSONAL`, `FW-CREDENTIAL-READ`, `FW-SECRET-FLOW`, `FW-SECRET-VARIABLE`, `FW-METADATA`, `FW-CREDENTIAL-FLOW`, `FW-SECRET-FILE-PUBLISH`, `FW-PRIVILEGE`, `FW-VAULT-EGRESS`, `FW-VAULT-UNBOUND`, `FW-VAULT-INDEX`, `FW-VAULT-UNSUPPORTED`, `FW-VAULT-OPTION`, `FW-VAULT-APPROVE`, `FW-MCP-AUTH` | Gates credential-store reads, credentials sent to a service that did not issue them, metadata endpoints and elevated privileges. There is no agent identity, per-agent credential or token-scope management in the firewall. | Per-agent scoped, short-lived credentials; secret manager; sandbox that does not mount credential stores. |
| **ASI04** Agentic Supply Chain Vulnerabilities | partly | `FW-AGENT-SETTINGS`, `FW-INSTALL`, `FW-MCP-CHANGED`, `FW-MALICIOUS-PACKAGE`, `FW-TYPOSQUAT`, `FW-MCP-TOOL-HELD` | Once the person has downloaded the malicious-package snapshot with update (none ships), denies by default installs of versions listed as malicious (packageIntel.malicious can make it ask or turn it off), and asks before a look-alike of a popular package (FW-MALICIOUS-PACKAGE, FW-TYPOSQUAT), gates changes to agent and MCP configuration and installs after outside content, and pins each MCP server: a changed launch command, a tool added after the grace window or a changed description it sees makes the session untrusted (FW-MCP-CHANGED). A hook never sees a server's full tool list, so description pinning covers only what Claude Code shows through ToolSearch. Plugins, unlisted malicious packages and a snapshot the person has not downloaded or refreshed are not vetted. | Allow-list MCP servers and plugins with managed settings; pin versions; use a package-reputation scanner. |
| **ASI05** Unexpected Code Execution | partly | `FW-AGENT-SETTINGS`, `FW-PERSISTENCE`, `FW-REMOTE-CODE`, `FW-OBFUSCATED`, `FW-UNTRUSTED-CODE`, `FW-TAINTED-MANIFEST`, `FW-INSTALL`, `FW-OPAQUE-CODE`, `FW-UNCLASSIFIABLE`, `FW-AUTORUN`, `FW-PERSISTENCE-HELD`, `FW-OUTSIDE-COMMAND` | Gates download-and-run, code from outside the project, obfuscated and opaque code, installs and build files changed after outside content. Shell analysis is static: code the firewall cannot see into is sent to a person (or denied), not understood. | Sandbox or container for execution; managed settings. |
| **ASI06** Memory and Context Poisoning | partly | `FW-INSTRUCTIONS-HELD`, `FW-INSTRUCTIONS`, `FW-MCP-CHANGED`, `FW-MCP-TOOL-HELD`, `FW-MCP-WITHHELD` | Covers the agent's file-based instructions and memory (CLAUDE.md, AGENTS.md, memory, rules) and agent settings: after outside content, writes are held as proposals. Does not cover vector or database memory, or memory managed by a third-party MCP server. | Review instruction-file changes; scope and expire memory in the memory system itself. |
| **ASI07** Insecure Inter-Agent Communication | not covered | none | Not covered: the firewall has no authentication or integrity check on messages between agents. (Starting another coding agent after outside content needs a person; that is mapped under ASI10, FW-AGENT-SPAWN.) | Authenticated agent-to-agent channels in the multi-agent framework; do not let agents act on each other's output unchecked. |
| **ASI08** Cascading Failures | partly | `FW-RATE-LIMITED`, `FW-BUDGET-MCP`, `FW-LOOP`, `FW-STOPPED`, `FW-CAP-WARN` | Loop detection and MCP-call budgets catch retry storms and one-message-per-contact fan-out inside one session; unattended, the run is held with a notification. The behaviour monitor stops a session that crosses its limits (non-allowed verdicts, new hosts, configuration changes, repeated identical failures) and a person can stop a session or every session of an agent (FW-STOPPED). Remaining gap: no model of failures propagating across agents or systems beyond what one machine's firewall sees. | Circuit breakers, rate limits and blast-radius limits in the orchestration layer. |
| **ASI09** Human-Agent Trust Exploitation | not covered | none | The firewall's approvals are written in plain words from the action itself, not from the agent's explanation, which helps, but nothing stops a person approving a harmful action out of trust. | User training; keep approval requests rare and specific; require a second reviewer for sensitive actions. |
| **ASI10** Rogue Agents | partly | `FW-AGENT-BYPASS`, `FW-AGENT-SPAWN`, `FW-TAMPER`, `FW-LOG-UNRECORDED`, `FW-UNAVAILABLE`, `FW-API-ERROR`, `FW-LOOP`, `FW-STOPPED` | Denies tampering with the firewall and hooks, and starting another agent with its safety switched off; spawning needs a person. A kill switch (session stop, agent stop) and a deterministic behaviour monitor (counters per session: non-allowed verdicts, new hosts, configuration changes, repeated identical failures) stop a session until a person resumes it with the approval passphrase. Remaining gap: the monitor counts behaviour, it does not judge intent: an agent that drifts slowly, below every limit and within allowed actions, is not stopped; and an agent the firewall does not see (no hook, no gateway, no API) cannot be stopped by it. | Managed settings make the hook unremovable; sandbox; monitoring and revocation at the platform level. |

## MITRE ATLAS (agent-relevant techniques)

| Item | Status | Rules | Gap | Mitigation |
|---|---|---|---|---|
| **AML.T0051** LLM Prompt Injection | partly | `FW-SEND`, `FW-MESSAGE`, `FW-SEND-ARGS`, `FW-HIDDEN-TEXT`, `FW-OUTSIDE-COMMAND`, `FW-HIDDEN-OUTPUT`, `FW-MCP-WITHHELD`, `FW-MCP-SAMPLING`, `FW-MAIL-WITHHELD` | As LLM01: consequences gated, injection not prevented (includes AML.T0051.001 Indirect). | Sandbox; managed settings. |
| **AML.T0053** AI Agent Tool Invocation | partly | `FW-REMOTE-CODE`, `FW-OBFUSCATED`, `FW-UNTRUSTED-CODE`, `FW-TAINTED-MANIFEST`, `FW-OPAQUE-CODE`, `FW-UNCLASSIFIABLE`, `FW-AGENT-BYPASS`, `FW-AGENT-SPAWN`, `FW-UNKNOWN-TOOL`, `FW-BLOCKED-TOOL`, `FW-OUTSIDE-COMMAND` | Tool invocations are gated by effect after outside content. Invocations that are within policy are allowed. | Least-privilege tool configuration; sandbox. |
| **AML.T0057** LLM Data Leakage | partly | `FW-SEND-ARGS`, `FW-FETCH-DATA`, `FW-DLP-CREDENTIAL`, `FW-DLP-SEEN-SECRET`, `FW-DLP-PERSONAL`, `FW-CANARY-EGRESS`, `FW-VAULT-EGRESS`, `FW-VAULT-UNBOUND`, `FW-VAULT-INDEX`, `FW-VAULT-UNSUPPORTED`, `FW-VAULT-OPTION` | Covers leakage through agent actions; not leakage through the model's replies. | Keep secrets out of the context; output filtering. |
| **AML.T0086** Exfiltration via AI Agent Tool Invocation | partly | `FW-SEND`, `FW-MESSAGE`, `FW-SEND-ARGS`, `FW-FETCH`, `FW-NEW-HOST`, `FW-CANARY-EGRESS` | Sends, fetches, messages, MCP writes and SQL write-backs the firewall can see after outside content need a person; recognised credentials and previously seen secrets are denied from leaving. Gap: an allowed or named host, an approved action, the contents of files a command uploads (not scanned), and programs the hooks cannot see. | Egress allow-list at the network layer; sandbox. |
| **AML.T0025** Exfiltration via Cyber Means | partly | `FW-FETCH`, `FW-FETCH-DATA`, `FW-NEW-HOST`, `FW-DLP-SEEN-SECRET`, `FW-SECRET-FLOW`, `FW-CREDENTIAL-FLOW`, `FW-SECRET-FILE-PUBLISH`, `FW-CAPTURE-HOST`, `FW-DNS-EXFIL`, `FW-RAW-IP`, `FW-VAULT-EGRESS` | Covers the agent's own network actions, DNS-label encoding, capture hosts and bare IPs. Does not see traffic from processes the agent starts and then leaves running. | Network egress controls; sandbox. |
| **AML.T0055** Unsecured Credentials | partly | `FW-CREDENTIAL-READ`, `FW-SECRET-FLOW`, `FW-SECRET-VARIABLE`, `FW-METADATA`, `FW-CREDENTIAL-FLOW`, `FW-SECRET-FILE-PUBLISH` | Gates agent reads of credential stores and secret files and the use of secret environment variables. Does not remove credentials that sit unprotected on disk. | Secret manager; remove long-lived credentials from developer machines. |
| **AML.T0083** Credentials from AI Agent Configuration | partly | `FW-CREDENTIAL-READ` | Credential-store patterns include the agent's own credentials file (for example ~/.claude/.credentials.json); other agent configuration that embeds tokens depends on the secret patterns. | Keep tokens out of agent configuration files; use environment-scoped secrets. |
| **AML.T0098** AI Agent Tool Credential Harvesting | partly | `FW-DLP-CREDENTIAL`, `FW-CREDENTIAL-READ` | Reads of credential stores and secret flows are gated. Tokens a tool legitimately holds in its own process are out of reach. | Scoped, short-lived tool credentials. |
| **AML.T0080** AI Agent Context Poisoning | partly | `FW-INSTRUCTIONS-HELD`, `FW-INSTRUCTIONS`, `FW-MCP-CHANGED` | Includes AML.T0080.000 Memory. File-based instructions and memory are held after outside content; other memory stores are not covered. | Review instruction-file changes; memory hygiene in the memory system. |
| **AML.T0081** Modify AI Agent Configuration | partly | `FW-INSTRUCTIONS-HELD`, `FW-INSTRUCTIONS`, `FW-AGENT-SETTINGS`, `FW-TAMPER` | Changes to .mcp.json, agent settings and hook registration through actions the firewall can see need a person even when trusted; tampering with the firewall is denied. A write from code the shell analysis cannot see into (a script, inline code that builds the path) is not recognised as such; Claude Code's ConfigChange event and managed settings are the backstop. | Managed settings make the registration unremovable. |
| **AML.T0101** Data Destruction via AI Agent Tool Invocation | partly | `FW-DESTRUCTIVE`, `FW-CATASTROPHIC`, `FW-DESTROY-ROOT` | Destructive commands, cloud deletions and destructive SQL the firewall recognises need a person; wiping root or home is denied. Destruction from a fixed list of commands, not every way to do it: a script or program that deletes is judged as running code, not as a deletion. | Backups; scoped credentials; sandbox. |
| **AML.T0104** Publish Poisoned AI Agent Tool | partly | `FW-MCP-CHANGED` | A resource-development technique performed by an attacker on a registry. The firewall cannot see publication; it notices only a pinned MCP server whose launch command or tool descriptions change (FW-MCP-CHANGED). | Allow-list MCP servers and plugins; review sources before installing. |
| **AML.T0109** AI Supply Chain Rug Pull | partly | `FW-AGENT-SETTINGS`, `FW-MCP-CHANGED`, `FW-MCP-TOOL-HELD` | Swapping an approved MCP configuration is gated (the CVE-2025-54136 pattern), and a pinned server whose launch command, tool names or observed tool descriptions change makes the session untrusted (FW-MCP-CHANGED). Tools a server reveals only to the model, never through ToolSearch, are not seen. | Pin server versions; allow-list servers; managed settings. |
| **AML.T0110** AI Agent Tool Poisoning | partly | `FW-MCP-CHANGED`, `FW-MCP-TOOL-HELD` | A pinned server whose tool description changes, or a tool added later, is held or makes the session untrusted (FW-MCP-CHANGED, FW-MCP-TOOL-HELD). A poisoned description present from the start is not detected as such; the firewall constrains the resulting actions. | Review tool descriptions; allow-list servers. |
| **AML.T0010** AI Supply Chain Compromise | partly | `FW-INSTALL`, `FW-MALICIOUS-PACKAGE`, `FW-TYPOSQUAT` | Package installs after outside content need a person; versions listed in the local OSV malicious-package snapshot are denied by default, lockfile installs included, and typosquats ask. The snapshot is downloaded by the person with update (none ships), and packageIntel.malicious can make a listed version ask or turn the check off. A compromise not yet listed, listed after the last update, or checked before the snapshot was downloaded is not caught. | Run launchsafe-firewall update regularly; release-age cooldowns (doctor --fix); pin and lock dependencies. |
| **AML.T0068** LLM Prompt Obfuscation | partly | `FW-HIDDEN-TEXT`, `FW-HIDDEN-OUTPUT` | Invisible and hidden text in tool inputs is denied; obfuscation inside content the agent reads is not detected. | Normalise untrusted input before it reaches the model. |
| **AML.T0093** Prompt Infiltration via Public-Facing Application | not covered | none | The entry vector: the firewall assumes the attacker can place text where the agent reads it (see the threat model) and gates the consequences. | Limit what untrusted sources the agent reads; use a separate low-privilege agent for untrusted content. |
| **AML.T0054** LLM Jailbreak | not covered | none | Model-level behaviour; out of scope. | Model and provider guardrails. |
| **AML.T0056** Extract LLM System Prompt | not covered | none | Out of scope (see LLM07). | Treat the system prompt as public. |
| **AML.T0034** Cost Harvesting | partly | `FW-CAP`, `FW-CAP-WARN` | Includes AML.T0034.002 Agentic Resource Consumption. Spending limits (FW-CAP) stop an agent at a cap on tool calls, data sent and identical failures per session and per day, and on model tokens and cost when the agent reports them through the local API or the library. Coding agents' hooks report no model usage, so their model spend is not capped, and reported cost is the agent's own figure. | Provider spend limits. |

## MCP specification security requirements

| Item | Status | Rules | Gap | Mitigation |
|---|---|---|---|---|
| **MCP-TOOLS-HITL** Tools: a human in the loop with the ability to deny tool invocations (server/tools, User Interaction Model, SHOULD) | partly | `FW-SEND`, `FW-MESSAGE`, `FW-SEND-ARGS`, `FW-FETCH`, `FW-FETCH-DATA`, `FW-NEW-HOST`, `FW-REMOTE-CODE`, `FW-OBFUSCATED`, `FW-UNTRUSTED-CODE`, `FW-TAINTED-MANIFEST`, `FW-OPAQUE-CODE`, `FW-UNCLASSIFIABLE`, `FW-UNKNOWN-TOOL`, `FW-BLOCKED-TOOL`, `FW-LEARNED-DENY`, `FW-SCOPE`, `FW-VAULT-APPROVE`, `FW-OUTSIDE-COMMAND` | Risky tool calls are held for a person who can approve or reject (ask, or a queue when no one is there); the rest are allowed. Applies only to agents that run the hook. | Managed settings so the hook cannot be removed. |
| **MCP-TOOLS-CONFIRM** Tools: clients SHOULD prompt for confirmation on sensitive operations and show tool inputs before calling (server/tools, Security Considerations) | partly | `FW-SEND`, `FW-MESSAGE`, `FW-SEND-ARGS` | Prompts appear for the sensitive classes, in plain words and with the exact action. Calls the policy allows are not shown to the user first. | Agent-side permission prompts for everything else. |
| **MCP-ANNOTATIONS-UNTRUSTED** Tools: clients MUST consider tool annotations untrusted unless from trusted servers (server/tools, Tool) | partly | `FW-MCP-CHANGED`, `FW-MCP-TOOL-HELD` | Annotations are never trusted: the gateway reads descriptions and annotations only to pin them and hide a changed or new tool, and a server's trust comes from its source in config, not from its claims. But the hooks classify an MCP tool by its name and arguments (a verb in the tool name decides read, send or destroy) plus the effects of what it touches, so a tool whose name misdescribes it can be misclassified. | List a server's read, send and destructive tools by name in your policy (mcpServers.<server>); allow-list servers with managed settings. |
| **MCP-TOOLS-RESULTS** Tools: clients SHOULD validate tool results before passing them to the LLM (server/tools, Security Considerations) | partly | `FW-HIDDEN-OUTPUT`, `FW-MCP-WITHHELD` | Through the MCP gateway, every result is scanned: hidden text aimed at the agent is withheld into quarantine (FW-MCP-WITHHELD), other hidden text is stripped, and visible agent-directed text is annotated. The scan is pattern-based (not paraphrased or semantic injections, not text in images). Without the gateway, results are recorded as outside content, which taints the session and tightens later actions. | Wrap MCP servers with launchsafe-firewall mcp wrap-config; the taint rule stays the primary control. |
| **MCP-LIST-CHANGED** Tools: notifications/tools/list_changed (rug pull); server/tools, List Changed Notification | partly | `FW-MCP-CHANGED`, `FW-MCP-TOOL-HELD` | A pinned server that exposes a new tool after the grace window makes the session untrusted until you accept it (FW-MCP-CHANGED). The hook does not receive list_changed notifications; it sees new tools when they are called or shown through ToolSearch. Through the MCP gateway every tools/list is pinned, and a changed or new tool is hidden until reviewed (FW-MCP-TOOL-HELD). | Pin versions; managed-settings allow-list of servers. |
| **MCP-LOCAL-SERVER** Security best practices: Local MCP Server Compromise (consent before executing startup commands, sandboxing) | partly | `FW-AGENT-SETTINGS`, `FW-MCP-CHANGED` | Writing a config that launches a server needs a person. The firewall does not sandbox the server or highlight dangerous patterns inside its startup command beyond the normal shell analysis. | Run servers in a sandbox or container with minimal file-system and network access. |
| **MCP-SSRF** Security best practices: Server-Side Request Forgery (private ranges, metadata endpoints, redirects) | partly | `FW-METADATA`, `FW-RAW-IP` | The agent's own requests to metadata endpoints and bare IPs are denied. The MCP client's OAuth-discovery fetches are not routed through the hook. | Egress proxy for MCP clients; block private ranges at the network layer. |
| **MCP-TOKEN-PASSTHROUGH** Security best practices: Token Passthrough (servers MUST NOT accept tokens not issued to them) | partly | `FW-DLP-CREDENTIAL`, `FW-DLP-SEEN-SECRET`, `FW-SECRET-VARIABLE`, `FW-VAULT-EGRESS`, `FW-VAULT-UNBOUND`, `FW-MCP-AUTH` | A server-side requirement. The firewall stops the agent carrying a credential to a destination that did not issue it, which is the client-side half; the MCP gateway never forwards a client's Authorization header and sends an upstream token only to the origin of the resource it was issued for (FW-MCP-AUTH). | Server operators validate token audience. |
| **MCP-CONFUSED-DEPUTY** Security best practices: Confused Deputy Problem (OAuth proxy servers MUST implement per-client consent) | not covered | none | A requirement on OAuth proxy servers; nothing in an agent hook can enforce it. | Use only servers that implement it; allow-list servers. |
| **MCP-SESSION-HIJACKING** Security best practices: Session Hijacking | not covered | none | Server-side transport requirement. | Server operators: non-deterministic session ids, verify every request. |
| **MCP-OAUTH-URL** Security best practices: OAuth Authorization URL Validation | not covered | none | A client-implementation requirement on URL schemes and how URLs are opened. | Use an MCP client that validates schemes. |
| **MCP-STDIO-PROXY** Security best practices: stdio Transport Security in Proxy Scenarios | partly | `FW-MCP-METHOD` | The MCP gateway is itself a proxy: it frames stdio strictly (one bounded message per line), refuses unknown methods both ways (FW-MCP-METHOD), binds its HTTP listener to 127.0.0.1 with Origin and Host checks and a per-client bearer, and validates header-body agreement. It does not sandbox the wrapped server. | Run servers in a sandbox or container. |
| **MCP-SCOPE** Security best practices: Scope Minimization | not covered | none | Token scopes are granted outside the agent's tool calls; the firewall does not inspect them. | Request narrow scopes; avoid omnibus tokens. |
| **MCP-SERVER-DUTIES** Tools: servers MUST validate inputs, apply access control, rate limit, sanitise outputs (server/tools, Security Considerations) | not covered | none | Server obligations; the firewall is client-side. | Choose servers that meet them; managed-settings allow-list. |

## Rule index

Every rule in effect, with its mappings. ATT&CK ids are supplementary (ATLAS has no agent-specific technique for these) and are not counted above.

| Rule | What it stops | OWASP LLM | OWASP Agentic | ATLAS | ATT&CK | MCP |
|---|---|---|---|---|---|---|
| `FW-SEND` | Sending data out after reading outside content | LLM01, LLM02, LLM06 | ASI01, ASI02 | AML.T0086, AML.T0051 | - | MCP-TOOLS-HITL, MCP-TOOLS-CONFIRM |
| `FW-MESSAGE` | Sending a message to people after reading outside content | LLM01, LLM02, LLM06 | ASI01, ASI02 | AML.T0086, AML.T0051 | - | MCP-TOOLS-HITL, MCP-TOOLS-CONFIRM |
| `FW-SEND-ARGS` | Sending tool arguments to an outside service while holding private data | LLM01, LLM02, LLM06 | ASI01, ASI02 | AML.T0086, AML.T0051, AML.T0057 | - | MCP-TOOLS-HITL, MCP-TOOLS-CONFIRM |
| `FW-FETCH` | Contacting a destination you did not name after reading outside content | LLM01, LLM02 | ASI01, ASI02 | AML.T0086, AML.T0025 | - | MCP-TOOLS-HITL |
| `FW-FETCH-DATA` | An address that can carry data out | LLM02 | ASI02 | AML.T0025, AML.T0057 | T1048 | MCP-TOOLS-HITL |
| `FW-NEW-HOST` | Contacting a host this project has never contacted | LLM01, LLM02, LLM06 | ASI01, ASI02 | AML.T0086, AML.T0025 | - | MCP-TOOLS-HITL |
| `FW-DLP-CREDENTIAL` | A credential leaving for a destination that did not issue it | LLM02 | ASI03 | AML.T0057, AML.T0098 | T1048 | MCP-TOKEN-PASSTHROUGH |
| `FW-DLP-SEEN-SECRET` | A secret this session read, leaving the machine | LLM02 | ASI03 | AML.T0057, AML.T0025 | T1048 | MCP-TOKEN-PASSTHROUGH |
| `FW-DLP-PERSONAL` | Personal or financial data leaving the machine | LLM02 | ASI03 | AML.T0057 | T1048 | - |
| `FW-CREDENTIAL-READ` | Reading a credential store | LLM02, LLM06 | ASI03 | AML.T0055, AML.T0083, AML.T0098 | T1552 | - |
| `FW-SECRET-FLOW` | Reading a secret and contacting the network in one command | LLM02, LLM06 | ASI03 | AML.T0055, AML.T0025 | T1552, T1048 | - |
| `FW-SECRET-VARIABLE` | A secret environment variable sent to a service that did not issue it | LLM02 | ASI03 | AML.T0055 | T1552 | MCP-TOKEN-PASSTHROUGH |
| `FW-METADATA` | Asking the cloud metadata service for credentials | LLM02 | ASI03 | AML.T0055 | T1552 | MCP-SSRF |
| `FW-CREDENTIAL-FLOW` | Sending data out after reading credentials | LLM02 | ASI03 | AML.T0055, AML.T0025 | T1552, T1048 | - |
| `FW-SECRET-FILE-PUBLISH` | Publishing after credentials were copied into a file | LLM02 | ASI03 | AML.T0055, AML.T0025 | T1552 | - |
| `FW-CAPTURE-HOST` | A data-capture, tunnelling or denied host | LLM02 | ASI02 | AML.T0025 | T1048 | - |
| `FW-DNS-EXFIL` | A host name built to carry data | LLM02 | ASI02 | AML.T0025 | T1048, T1071.004 | - |
| `FW-RAW-IP` | Contacting a bare IP address | LLM02 | ASI02 | AML.T0025 | T1048 | MCP-SSRF |
| `FW-INSTRUCTIONS-HELD` | Changing the agent's instructions or memory after outside content | LLM01 | ASI06 | AML.T0080, AML.T0081 | - | - |
| `FW-INSTRUCTIONS` | Changing the agent's instructions or memory (strict mode) | LLM01 | ASI06 | AML.T0080, AML.T0081 | - | - |
| `FW-AGENT-SETTINGS` | Changing settings that make code run in every session | LLM03, LLM06 | ASI04, ASI05 | AML.T0081, AML.T0109 | - | MCP-LOCAL-SERVER |
| `FW-PERSISTENCE` | Writing something that runs code later on its own | LLM06 | ASI05 | - | T1546, T1053 | - |
| `FW-OUTSIDE-WRITE` | Writing outside the project after outside content | LLM06 | ASI02 | - | - | - |
| `FW-DESTRUCTIVE` | Destroying data or infrastructure | LLM06 | ASI02 | AML.T0101 | T1485 | - |
| `FW-CATASTROPHIC` | An action that cannot be undone | LLM06 | ASI02 | AML.T0101 | T1485 | - |
| `FW-DESTROY-ROOT` | Erasing the home directory, the disk or the root | LLM06 | ASI02 | AML.T0101 | T1485 | - |
| `FW-PRIVILEGE` | Running with elevated privileges | LLM06 | ASI03 | - | T1548 | - |
| `FW-SYMLINK` | A link to a protected file | LLM06 | ASI02 | - | - | - |
| `FW-REMOTE-CODE` | Downloading code and running it directly | LLM05, LLM06 | ASI05 | AML.T0053 | T1059, T1105 | MCP-TOOLS-HITL |
| `FW-OBFUSCATED` | Decoding hidden text and running it | LLM05, LLM06 | ASI05 | AML.T0053 | T1059, T1027 | MCP-TOOLS-HITL |
| `FW-UNTRUSTED-CODE` | Running code that came from outside the project | LLM05, LLM06 | ASI05 | AML.T0053 | T1059 | MCP-TOOLS-HITL |
| `FW-TAINTED-MANIFEST` | Running a build or task file changed after outside content | LLM05, LLM06 | ASI05 | AML.T0053 | T1059 | MCP-TOOLS-HITL |
| `FW-INSTALL` | Downloading and running packages after outside content | LLM03, LLM06 | ASI04, ASI05 | AML.T0010 | T1195.001 | - |
| `FW-OPAQUE-CODE` | Running code the firewall cannot see into, after outside content | LLM05, LLM06 | ASI05 | AML.T0053 | T1059 | MCP-TOOLS-HITL |
| `FW-UNCLASSIFIABLE` | Part of the action is only known at run time | LLM05, LLM06 | ASI05 | AML.T0053 | T1059 | MCP-TOOLS-HITL |
| `FW-AGENT-BYPASS` | Starting a coding agent with its safety switched off | LLM06 | ASI02, ASI10 | AML.T0053 | - | - |
| `FW-AGENT-SPAWN` | Starting another coding agent after outside content | LLM06 | ASI10 | AML.T0053 | - | - |
| `FW-TAMPER` | Changing the firewall itself | LLM06 | ASI10 | AML.T0081 | T1562.001 | - |
| `FW-POLICY-ERROR` | The policy file is invalid | LLM06 | - | - | - | - |
| `FW-HIDDEN-TEXT` | Invisible characters in a path, address or command | LLM01 | ASI01 | AML.T0051, AML.T0068 | - | - |
| `FW-UNKNOWN-TOOL` | A tool the firewall does not know | LLM06 | ASI02 | AML.T0053 | - | MCP-TOOLS-HITL |
| `FW-NET-REFUSED` | A network request the sandbox middleware refused | LLM02, LLM06 | ASI02 | - | T1048 | - |
| `FW-BLOCKED-TOOL` | A tool the policy blocks | LLM06 | ASI02 | AML.T0053 | - | MCP-TOOLS-HITL |
| `FW-APPROVED` | Approved once by a person | - | - | - | - | - |
| `FW-LEARNED-ALLOW` | Always allowed in this project by your choice | - | - | - | - | - |
| `FW-LEARNED-DENY` | Never allowed in this project by your choice | LLM06 | ASI02 | - | - | MCP-TOOLS-HITL |
| `FW-LOG-UNRECORDED` | An action the decision log could not record | LLM06 | ASI10 | - | T1562.001 | - |
| `FW-INPUT-SHAPE` | A tool call whose input cannot be judged | LLM10 | - | - | - | - |
| `FW-RESULT-UNRECORDED` | A tool result whose decision was forgotten | LLM01 | - | - | - | - |
| `FW-UNAVAILABLE` | The firewall API could not be reached | LLM06 | ASI10 | - | - | - |
| `FW-RATE-LIMITED` | The firewall API asked the agent to slow down | LLM06, LLM10 | ASI08 | - | - | - |
| `FW-API-ERROR` | The firewall API refused the request | LLM06 | ASI10 | - | - | - |
| `FW-SCOPE` | Acting outside the task you gave | LLM06 | ASI01, ASI02 | - | - | MCP-TOOLS-HITL |
| `FW-MCP-CHANGED` | An MCP server changed since it was pinned | LLM03, LLM01 | ASI04, ASI06 | AML.T0109, AML.T0110, AML.T0104, AML.T0080 | - | MCP-LIST-CHANGED, MCP-ANNOTATIONS-UNTRUSTED, MCP-LOCAL-SERVER |
| `FW-MALICIOUS-PACKAGE` | A package version listed as malicious | LLM03 | ASI04 | AML.T0010 | T1195.001 | - |
| `FW-TYPOSQUAT` | A misspelt popular package | LLM03 | ASI04 | AML.T0010 | T1195.001 | - |
| `FW-AUTORUN` | A change that makes code run automatically | LLM06 | ASI05 | - | T1546, T1053 | - |
| `FW-PERSISTENCE-HELD` | A git hook or auto-run file held as a proposal | LLM06 | ASI05 | - | T1546, T1053 | - |
| `FW-BUDGET-BYTES` | Outbound data budget reached | LLM10, LLM02 | - | - | T1030 | - |
| `FW-BUDGET-REQUESTS` | Outbound request budget reached | LLM10, LLM02 | - | - | T1030 | - |
| `FW-BUDGET-MCP` | MCP call budget reached | LLM10, LLM02 | ASI08 | - | T1030 | - |
| `FW-LOOP` | The agent seems stuck | LLM10 | ASI08, ASI10 | - | - | - |
| `FW-STOPPED` | The session or agent is stopped | LLM06, LLM10 | ASI08, ASI10 | - | - | - |
| `FW-CAP` | Spending limit reached | LLM10 | - | AML.T0034 | - | - |
| `FW-CAP-WARN` | Spending limit nearly reached | LLM10 | ASI08 | AML.T0034 | - | - |
| `FW-CANARY-READ` | A decoy file was touched | LLM02 | ASI01 | - | - | - |
| `FW-CANARY-EGRESS` | A decoy value leaving the machine | LLM02 | ASI01 | AML.T0086, AML.T0057 | - | - |
| `FW-VAULT-EGRESS` | A vaulted secret leaving for a destination it is not bound to | LLM02, LLM06 | ASI03 | AML.T0057, AML.T0025 | T1048 | MCP-TOKEN-PASSTHROUGH |
| `FW-VAULT-UNBOUND` | A vault reference that names no secret, or goes where its secret is not bound | LLM02, LLM06 | ASI03 | AML.T0057 | T1048 | MCP-TOKEN-PASSTHROUGH |
| `FW-VAULT-INDEX` | Sending while the vault index cannot be trusted | LLM02 | ASI03 | AML.T0057 | T1048 | - |
| `FW-VAULT-UNSUPPORTED` | A vault reference where the firewall cannot put the value in safely | LLM02 | ASI03 | AML.T0057 | - | - |
| `FW-VAULT-OPTION` | A vault value given to curl or wget with an option off the allowlist | LLM02, LLM06 | ASI03 | AML.T0057 | T1048 | - |
| `FW-VAULT-APPROVE` | Using a financial or personal value from the vault | LLM02, LLM06 | ASI03 | - | - | MCP-TOOLS-HITL |
| `FW-OUTSIDE-COMMAND` | Running a command that outside content suggested | LLM01, LLM05, LLM06 | ASI01, ASI05 | AML.T0051, AML.T0053 | T1059 | MCP-TOOLS-HITL |
| `FW-HIDDEN-OUTPUT` | Invisible characters or terminal tricks in what the agent read | LLM01 | ASI01 | AML.T0051, AML.T0068 | - | MCP-TOOLS-RESULTS |
| `FW-MCP-TOOL-HELD` | A changed or new MCP tool, hidden until reviewed | LLM03, LLM01 | ASI04, ASI06 | AML.T0109, AML.T0110 | - | MCP-LIST-CHANGED, MCP-ANNOTATIONS-UNTRUSTED |
| `FW-MCP-WITHHELD` | An MCP result carrying hidden instructions, withheld | LLM01 | ASI01, ASI06 | AML.T0051 | - | MCP-TOOLS-RESULTS |
| `FW-MCP-SAMPLING` | An MCP server asking to run your model | LLM01, LLM06 | ASI01 | AML.T0051 | - | - |
| `FW-MCP-METHOD` | An MCP method the gateway does not know | - | ASI02 | - | - | MCP-STDIO-PROXY |
| `FW-MCP-AUTH` | An upstream token kept to its own server | LLM02 | ASI03 | - | - | MCP-TOKEN-PASSTHROUGH |
| `FW-MAIL-WITHHELD` | A mail message with hidden instructions for the agent withheld | LLM01 | ASI01 | AML.T0051 | - | - |

## Planned rules (not in the code yet, so not counted)

| Rule | Roadmap item | What it will stop | OWASP LLM | OWASP Agentic | ATLAS | ATT&CK | MCP |
|---|---|---|---|---|---|---|---|

When one ships, its status in `src/rules.ts` becomes active and the items it maps to are re-assessed in `src/frameworks.ts` (the generator refuses an item that gains a rule without a coverage claim).

## What no mapping fixes

- A fooled agent working inside its allowed envelope. Use an OS sandbox.
- A repository that disables the hook. Use managed settings (`launchsafe-firewall install --managed`; see [usage.md](usage.md)).
- Agents without hook support. Claude Code, Codex, Gemini CLI and Cursor are covered through their hooks; agents built with the OpenAI Agents SDK, Claude Agent SDK, LangGraph or the Vercel AI SDK through the library (`docs/library.md`). Other agents are not covered.
- Anything the model provider, the MCP server or the package registry does on its own side.

See also [`threat-model.md`](threat-model.md) and [`incidents.md`](incidents.md).
