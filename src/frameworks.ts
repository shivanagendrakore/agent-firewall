/**
 * The frameworks the rule catalogue maps to, and what the firewall does not
 * cover in each: item ids and names as verified (see VERIFICATION), the
 * coverage the firewall claims when at least one active rule maps to an item,
 * the honest gap and the mitigation. Which rules map to an item is not stored
 * here: it is derived from each rule's mapping in src/rules.ts, so the two
 * cannot disagree. An item no active rule maps to is "not covered".
 * scripts/gen-coverage.mjs turns this and src/rules.ts into docs/coverage.md
 * and docs/coverage.json. Pure data.
 */

import { own } from "./own.js";

export type MappingField = "owaspLlm" | "owaspAgentic" | "atlas" | "mcpSpec";

export interface FrameworkItem {
  id: string;
  name: string;
  /** What the firewall claims when an active rule maps here; absent for items nothing is meant to cover. */
  claim?: "covered" | "partly";
  gap: string;
  mitigation: string;
}

export interface Framework {
  field: MappingField;
  /** The key in docs/coverage.json. */
  key: string;
  title: string;
  items: FrameworkItem[];
}

export const VERIFICATION = {
  "checkedOn": "2026-10-09",
  "owaspLlm2025": {
    "status": "verified",
    "source": "https://genai.owasp.org/llm-top-10/",
    "note": "All ten ids and names read from the official page."
  },
  "owaspAgentic2026": {
    "status": "verified (names); descriptions from the OWASP announcement",
    "source": "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/",
    "note": "ASI01 to ASI10 ids and names read from the OWASP announcement post. The resource page https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ lists no items in its text and the PDF was not read."
  },
  "mitreAtlas": {
    "status": "verified against MITRE's published data, not the atlas.mitre.org pages",
    "source": "https://github.com/mitre-atlas/atlas-data (dist/ATLAS.yaml, version 5.6.0)",
    "note": "atlas.mitre.org technique pages returned 404 to the fetch tool. The data file carries a notice that it is deprecated in favour of newer data in the same repository; ids and names were checked in that file, so a rename in a later release would not be seen."
  },
  "attack": {
    "status": "verified except T1562.001",
    "source": "https://attack.mitre.org/techniques/",
    "note": "Titles of T1048, T1071.004, T1552, T1059, T1027, T1485, T1548, T1546, T1053, T1195.001, T1030 and T1105 were read from attack.mitre.org. T1562.001 could not be fetched and is unverified."
  },
  "mcpSpec": {
    "status": "verified",
    "source": "https://modelcontextprotocol.io/specification/2025-06-18/server/tools and /basic/security_best_practices",
    "note": "Requirement wording read from both pages. The security best practices page now serves the 2025-11-25 text, which cross-references the 2025-11-25 authorization spec; the tools page is 2025-06-18. Requirement levels (MUST, SHOULD) are as on those pages."
  },
  "unverified": [
    "An ATLAS technique for triggers hidden in multimodal inputs was considered but not found in ATLAS data 5.6.0, so none is used (AML.T0068 LLM Prompt Obfuscation is used for FW-HIDDEN-TEXT instead).",
    "ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools): the page could not be fetched, so its id and title were not checked against attack.mitre.org.",
    "OWASP Agentic Top 10 item descriptions beyond the names (taken from the announcement post, not the full PDF)."
  ]
} as const;

export const FRAMEWORKS: Framework[] = [
  {
    field: "owaspLlm",
    key: "owaspLlm2025",
    title: "OWASP Top 10 for LLM Applications (2025)",
    items: [
      { id: "LLM01:2025", name: "Prompt Injection", claim: "partly", gap: "The firewall does not stop a model being fooled. It limits what a fooled agent may do after reading outside content. An injected instruction that only asks for an action inside the allowed envelope (an edit in the workspace, a misleading answer to the user) is not stopped.", mitigation: "Run the agent in an OS sandbox; deploy managed settings; review diffs before merging." },
      { id: "LLM02:2025", name: "Sensitive Information Disclosure", claim: "partly", gap: "Covers disclosure through the agent's own tool actions (network sends, fetches, messages, DNS, credential reads). Does not cover what the model provider sees in the prompt, leaks into the chat transcript, or data sent to a host the policy allows.", mitigation: "Keep secrets out of the working tree; use a sandbox with network egress rules; review allow-host lists (sendAllowHosts, dataAllowHosts)." },
      { id: "LLM03:2025", name: "Supply Chain", claim: "partly", gap: "Checks every install and package runner offline: a version listed in the local OSV malicious-package snapshot (downloaded by the person with update; none ships) is denied by default (packageIntel.malicious can make it ask or turn it off), including versions a lockfile install would fetch (FW-MALICIOUS-PACKAGE), and a look-alike of a popular name needs a person (FW-TYPOSQUAT). Also gates installs after outside content and changes to agent and MCP configuration, and pins each MCP server (FW-MCP-CHANGED). Does not catch a malicious package not yet listed, a snapshot the person has not downloaded (none ships) or refreshed, or a malicious model.", mitigation: "Run launchsafe-firewall update regularly; set a release-age cooldown (doctor --fix); pin and lock dependencies; use managed settings to allow-list MCP servers." },
      { id: "LLM04:2025", name: "Data and Model Poisoning", gap: "Out of scope: training, fine-tuning and embedding-store poisoning are outside a coding-agent firewall. (Changes to the agent's own instruction and memory files after outside content are held as proposals; that is mapped under LLM01 and ASI06, not here.)", mitigation: "Control training and RAG data at the pipeline; review instruction-file changes in code review." },
      { id: "LLM05:2025", name: "Improper Output Handling", claim: "partly", gap: "Covers the agent executing code the model or an outsider supplied on the developer's machine (downloaded scripts, decoded payloads, build files changed after outside content, opaque code). Does not cover output rendered by a downstream web application (XSS, injection into other systems).", mitigation: "Validate and encode model output in the application that consumes it; sandbox code execution." },
      { id: "LLM06:2025", name: "Excessive Agency", claim: "partly", gap: "The firewall's core job: every tool call the hooks see is classified and gated by effect, with approval required for send, destructive, persistence, privilege, agent-settings and code-execution classes, and denial for the worst. Remaining gap: shell analysis is static, so code it cannot see into is judged strictly but not understood, and programs the agent starts act unseen; it limits autonomy per action but does not reduce the permissions the agent's tools hold; and only agents with hook support are covered (Claude Code first).", mitigation: "Give the agent least-privilege credentials; use a sandbox for process, file-system and network isolation." },
      { id: "LLM07:2025", name: "System Prompt Leakage", gap: "Out of scope: the firewall governs actions, not what the model says about its own prompt. (Credential-shaped content leaving the machine is covered under LLM02.)", mitigation: "Do not put secrets in system prompts; treat the system prompt as public." },
      { id: "LLM08:2025", name: "Vector and Embedding Weaknesses", gap: "Out of scope: no vector store or embedding pipeline is in the firewall's path.", mitigation: "Access control and tenant isolation in the vector store; validate documents before embedding." },
      { id: "LLM09:2025", name: "Misinformation", gap: "Out of scope: the firewall cannot judge whether the model's claims or generated code are correct.", mitigation: "Tests, code review, and grounding the model in trusted sources." },
      { id: "LLM10:2025", name: "Unbounded Consumption", claim: "partly", gap: "Per-session budgets make volume visible: outbound bytes per host and in total, requests per host and calls per MCP server in 10 minutes, and loop detection (the same action 8 times with no write in between, or 25 non-allowed verdicts in 10 minutes) turn the next action into an approval. Spending limits (FW-CAP) stop the agent at a cap per session and per day on tool calls, data sent and identical failures, and on model tokens and cost an agent reports through the local API or the library. Remaining gap: coding agents' hooks report no model usage, so their token and cost caps do not apply.", mitigation: "Provider-side spend limits and rate limits; agent turn and budget limits in the agent's own settings." },
    ],
  },
  {
    field: "owaspAgentic",
    key: "owaspAgentic2026",
    title: "OWASP Top 10 for Agentic Applications",
    items: [
      { id: "ASI01", name: "Agent Goal Hijack", claim: "partly", gap: "Same gap as LLM01: the hijack itself is not prevented; the damaging actions it depends on (exfiltration, destructive, persistence, instruction rewrite) are gated. A hijack that stays inside permitted actions is not stopped.", mitigation: "Sandbox; managed settings; human review of the agent's output." },
      { id: "ASI02", name: "Tool Misuse", claim: "partly", gap: "MCP tools are classified by their name and arguments (a verb in the tool name decides read, send or destroy) plus the effects of paths, URLs, SQL and shell commands; a tool whose name misdescribes it can be misclassified. A legitimate tool bent to a harmful use is still gated: sends, fetches, destructive commands, writes outside the project, unknown tools. Remaining gap: misuse within an allowed envelope (an allowed host, an in-project edit), and shell effects the static analysis does not model (see docs/limitations.md).", mitigation: "Narrow allow-lists; sandbox; scoped credentials." },
      { id: "ASI03", name: "Identity and Privilege Abuse", claim: "partly", gap: "Gates credential-store reads, credentials sent to a service that did not issue them, metadata endpoints and elevated privileges. There is no agent identity, per-agent credential or token-scope management in the firewall.", mitigation: "Per-agent scoped, short-lived credentials; secret manager; sandbox that does not mount credential stores." },
      { id: "ASI04", name: "Agentic Supply Chain Vulnerabilities", claim: "partly", gap: "Once the person has downloaded the malicious-package snapshot with update (none ships), denies by default installs of versions listed as malicious (packageIntel.malicious can make it ask or turn it off), and asks before a look-alike of a popular package (FW-MALICIOUS-PACKAGE, FW-TYPOSQUAT), gates changes to agent and MCP configuration and installs after outside content, and pins each MCP server: a changed launch command, a tool added after the grace window or a changed description it sees makes the session untrusted (FW-MCP-CHANGED). A hook never sees a server's full tool list, so description pinning covers only what Claude Code shows through ToolSearch. Plugins, unlisted malicious packages and a snapshot the person has not downloaded or refreshed are not vetted.", mitigation: "Allow-list MCP servers and plugins with managed settings; pin versions; use a package-reputation scanner." },
      { id: "ASI05", name: "Unexpected Code Execution", claim: "partly", gap: "Gates download-and-run, code from outside the project, obfuscated and opaque code, installs and build files changed after outside content. Shell analysis is static: code the firewall cannot see into is sent to a person (or denied), not understood.", mitigation: "Sandbox or container for execution; managed settings." },
      { id: "ASI06", name: "Memory and Context Poisoning", claim: "partly", gap: "Covers the agent's file-based instructions and memory (CLAUDE.md, AGENTS.md, memory, rules) and agent settings: after outside content, writes are held as proposals. Does not cover vector or database memory, or memory managed by a third-party MCP server.", mitigation: "Review instruction-file changes; scope and expire memory in the memory system itself." },
      { id: "ASI07", name: "Insecure Inter-Agent Communication", gap: "Not covered: the firewall has no authentication or integrity check on messages between agents. (Starting another coding agent after outside content needs a person; that is mapped under ASI10, FW-AGENT-SPAWN.)", mitigation: "Authenticated agent-to-agent channels in the multi-agent framework; do not let agents act on each other's output unchecked." },
      { id: "ASI08", name: "Cascading Failures", claim: "partly", gap: "Loop detection and MCP-call budgets catch retry storms and one-message-per-contact fan-out inside one session; unattended, the run is held with a notification. The behaviour monitor stops a session that crosses its limits (non-allowed verdicts, new hosts, configuration changes, repeated identical failures) and a person can stop a session or every session of an agent (FW-STOPPED). Remaining gap: no model of failures propagating across agents or systems beyond what one machine's firewall sees.", mitigation: "Circuit breakers, rate limits and blast-radius limits in the orchestration layer." },
      { id: "ASI09", name: "Human-Agent Trust Exploitation", gap: "The firewall's approvals are written in plain words from the action itself, not from the agent's explanation, which helps, but nothing stops a person approving a harmful action out of trust.", mitigation: "User training; keep approval requests rare and specific; require a second reviewer for sensitive actions." },
      { id: "ASI10", name: "Rogue Agents", claim: "partly", gap: "Denies tampering with the firewall and hooks, and starting another agent with its safety switched off; spawning needs a person. A kill switch (session stop, agent stop) and a deterministic behaviour monitor (counters per session: non-allowed verdicts, new hosts, configuration changes, repeated identical failures) stop a session until a person resumes it with the approval passphrase. Remaining gap: the monitor counts behaviour, it does not judge intent: an agent that drifts slowly, below every limit and within allowed actions, is not stopped; and an agent the firewall does not see (no hook, no gateway, no API) cannot be stopped by it.", mitigation: "Managed settings make the hook unremovable; sandbox; monitoring and revocation at the platform level." },
    ],
  },
  {
    field: "atlas",
    key: "mitreAtlas",
    title: "MITRE ATLAS (agent-relevant techniques)",
    items: [
      { id: "AML.T0051", name: "LLM Prompt Injection", claim: "partly", gap: "As LLM01: consequences gated, injection not prevented (includes AML.T0051.001 Indirect).", mitigation: "Sandbox; managed settings." },
      { id: "AML.T0053", name: "AI Agent Tool Invocation", claim: "partly", gap: "Tool invocations are gated by effect after outside content. Invocations that are within policy are allowed.", mitigation: "Least-privilege tool configuration; sandbox." },
      { id: "AML.T0057", name: "LLM Data Leakage", claim: "partly", gap: "Covers leakage through agent actions; not leakage through the model's replies.", mitigation: "Keep secrets out of the context; output filtering." },
      { id: "AML.T0086", name: "Exfiltration via AI Agent Tool Invocation", claim: "partly", gap: "Sends, fetches, messages, MCP writes and SQL write-backs the firewall can see after outside content need a person; recognised credentials and previously seen secrets are denied from leaving. Gap: an allowed or named host, an approved action, the contents of files a command uploads (not scanned), and programs the hooks cannot see.", mitigation: "Egress allow-list at the network layer; sandbox." },
      { id: "AML.T0025", name: "Exfiltration via Cyber Means", claim: "partly", gap: "Covers the agent's own network actions, DNS-label encoding, capture hosts and bare IPs. Does not see traffic from processes the agent starts and then leaves running.", mitigation: "Network egress controls; sandbox." },
      { id: "AML.T0055", name: "Unsecured Credentials", claim: "partly", gap: "Gates agent reads of credential stores and secret files and the use of secret environment variables. Does not remove credentials that sit unprotected on disk.", mitigation: "Secret manager; remove long-lived credentials from developer machines." },
      { id: "AML.T0083", name: "Credentials from AI Agent Configuration", claim: "partly", gap: "Credential-store patterns include the agent's own credentials file (for example ~/.claude/.credentials.json); other agent configuration that embeds tokens depends on the secret patterns.", mitigation: "Keep tokens out of agent configuration files; use environment-scoped secrets." },
      { id: "AML.T0098", name: "AI Agent Tool Credential Harvesting", claim: "partly", gap: "Reads of credential stores and secret flows are gated. Tokens a tool legitimately holds in its own process are out of reach.", mitigation: "Scoped, short-lived tool credentials." },
      { id: "AML.T0080", name: "AI Agent Context Poisoning", claim: "partly", gap: "Includes AML.T0080.000 Memory. File-based instructions and memory are held after outside content; other memory stores are not covered.", mitigation: "Review instruction-file changes; memory hygiene in the memory system." },
      { id: "AML.T0081", name: "Modify AI Agent Configuration", claim: "partly", gap: "Changes to .mcp.json, agent settings and hook registration through actions the firewall can see need a person even when trusted; tampering with the firewall is denied. A write from code the shell analysis cannot see into (a script, inline code that builds the path) is not recognised as such; Claude Code's ConfigChange event and managed settings are the backstop.", mitigation: "Managed settings make the registration unremovable." },
      { id: "AML.T0101", name: "Data Destruction via AI Agent Tool Invocation", claim: "partly", gap: "Destructive commands, cloud deletions and destructive SQL the firewall recognises need a person; wiping root or home is denied. Destruction from a fixed list of commands, not every way to do it: a script or program that deletes is judged as running code, not as a deletion.", mitigation: "Backups; scoped credentials; sandbox." },
      { id: "AML.T0104", name: "Publish Poisoned AI Agent Tool", claim: "partly", gap: "A resource-development technique performed by an attacker on a registry. The firewall cannot see publication; it notices only a pinned MCP server whose launch command or tool descriptions change (FW-MCP-CHANGED).", mitigation: "Allow-list MCP servers and plugins; review sources before installing." },
      { id: "AML.T0109", name: "AI Supply Chain Rug Pull", claim: "partly", gap: "Swapping an approved MCP configuration is gated (the CVE-2025-54136 pattern), and a pinned server whose launch command, tool names or observed tool descriptions change makes the session untrusted (FW-MCP-CHANGED). Tools a server reveals only to the model, never through ToolSearch, are not seen.", mitigation: "Pin server versions; allow-list servers; managed settings." },
      { id: "AML.T0110", name: "AI Agent Tool Poisoning", claim: "partly", gap: "A pinned server whose tool description changes, or a tool added later, is held or makes the session untrusted (FW-MCP-CHANGED, FW-MCP-TOOL-HELD). A poisoned description present from the start is not detected as such; the firewall constrains the resulting actions.", mitigation: "Review tool descriptions; allow-list servers." },
      { id: "AML.T0010", name: "AI Supply Chain Compromise", claim: "partly", gap: "Package installs after outside content need a person; versions listed in the local OSV malicious-package snapshot are denied by default, lockfile installs included, and typosquats ask. The snapshot is downloaded by the person with update (none ships), and packageIntel.malicious can make a listed version ask or turn the check off. A compromise not yet listed, listed after the last update, or checked before the snapshot was downloaded is not caught.", mitigation: "Run launchsafe-firewall update regularly; release-age cooldowns (doctor --fix); pin and lock dependencies." },
      { id: "AML.T0068", name: "LLM Prompt Obfuscation", claim: "partly", gap: "Invisible and hidden text in tool inputs is denied; obfuscation inside content the agent reads is not detected.", mitigation: "Normalise untrusted input before it reaches the model." },
      { id: "AML.T0093", name: "Prompt Infiltration via Public-Facing Application", gap: "The entry vector: the firewall assumes the attacker can place text where the agent reads it (see the threat model) and gates the consequences.", mitigation: "Limit what untrusted sources the agent reads; use a separate low-privilege agent for untrusted content." },
      { id: "AML.T0054", name: "LLM Jailbreak", gap: "Model-level behaviour; out of scope.", mitigation: "Model and provider guardrails." },
      { id: "AML.T0056", name: "Extract LLM System Prompt", gap: "Out of scope (see LLM07).", mitigation: "Treat the system prompt as public." },
      { id: "AML.T0034", name: "Cost Harvesting", claim: "partly", gap: "Includes AML.T0034.002 Agentic Resource Consumption. Spending limits (FW-CAP) stop an agent at a cap on tool calls, data sent and identical failures per session and per day, and on model tokens and cost when the agent reports them through the local API or the library. Coding agents' hooks report no model usage, so their model spend is not capped, and reported cost is the agent's own figure.", mitigation: "Provider spend limits." },
    ],
  },
  {
    field: "mcpSpec",
    key: "mcpSpec",
    title: "MCP specification security requirements",
    items: [
      { id: "MCP-TOOLS-HITL", name: "Tools: a human in the loop with the ability to deny tool invocations (server/tools, User Interaction Model, SHOULD)", claim: "partly", gap: "Risky tool calls are held for a person who can approve or reject (ask, or a queue when no one is there); the rest are allowed. Applies only to agents that run the hook.", mitigation: "Managed settings so the hook cannot be removed." },
      { id: "MCP-TOOLS-CONFIRM", name: "Tools: clients SHOULD prompt for confirmation on sensitive operations and show tool inputs before calling (server/tools, Security Considerations)", claim: "partly", gap: "Prompts appear for the sensitive classes, in plain words and with the exact action. Calls the policy allows are not shown to the user first.", mitigation: "Agent-side permission prompts for everything else." },
      { id: "MCP-ANNOTATIONS-UNTRUSTED", name: "Tools: clients MUST consider tool annotations untrusted unless from trusted servers (server/tools, Tool)", claim: "partly", gap: "Annotations are never trusted: the gateway reads descriptions and annotations only to pin them and hide a changed or new tool, and a server's trust comes from its source in config, not from its claims. But the hooks classify an MCP tool by its name and arguments (a verb in the tool name decides read, send or destroy) plus the effects of what it touches, so a tool whose name misdescribes it can be misclassified.", mitigation: "List a server's read, send and destructive tools by name in your policy (mcpServers.<server>); allow-list servers with managed settings." },
      { id: "MCP-TOOLS-RESULTS", name: "Tools: clients SHOULD validate tool results before passing them to the LLM (server/tools, Security Considerations)", claim: "partly", gap: "Through the MCP gateway, every result is scanned: hidden text aimed at the agent is withheld into quarantine (FW-MCP-WITHHELD), other hidden text is stripped, and visible agent-directed text is annotated. The scan is pattern-based (not paraphrased or semantic injections, not text in images). Without the gateway, results are recorded as outside content, which taints the session and tightens later actions.", mitigation: "Wrap MCP servers with launchsafe-firewall mcp wrap-config; the taint rule stays the primary control." },
      { id: "MCP-LIST-CHANGED", name: "Tools: notifications/tools/list_changed (rug pull); server/tools, List Changed Notification", claim: "partly", gap: "A pinned server that exposes a new tool after the grace window makes the session untrusted until you accept it (FW-MCP-CHANGED). The hook does not receive list_changed notifications; it sees new tools when they are called or shown through ToolSearch. Through the MCP gateway every tools/list is pinned, and a changed or new tool is hidden until reviewed (FW-MCP-TOOL-HELD).", mitigation: "Pin versions; managed-settings allow-list of servers." },
      { id: "MCP-LOCAL-SERVER", name: "Security best practices: Local MCP Server Compromise (consent before executing startup commands, sandboxing)", claim: "partly", gap: "Writing a config that launches a server needs a person. The firewall does not sandbox the server or highlight dangerous patterns inside its startup command beyond the normal shell analysis.", mitigation: "Run servers in a sandbox or container with minimal file-system and network access." },
      { id: "MCP-SSRF", name: "Security best practices: Server-Side Request Forgery (private ranges, metadata endpoints, redirects)", claim: "partly", gap: "The agent's own requests to metadata endpoints and bare IPs are denied. The MCP client's OAuth-discovery fetches are not routed through the hook.", mitigation: "Egress proxy for MCP clients; block private ranges at the network layer." },
      { id: "MCP-TOKEN-PASSTHROUGH", name: "Security best practices: Token Passthrough (servers MUST NOT accept tokens not issued to them)", claim: "partly", gap: "A server-side requirement. The firewall stops the agent carrying a credential to a destination that did not issue it, which is the client-side half; the MCP gateway never forwards a client's Authorization header and sends an upstream token only to the origin of the resource it was issued for (FW-MCP-AUTH).", mitigation: "Server operators validate token audience." },
      { id: "MCP-CONFUSED-DEPUTY", name: "Security best practices: Confused Deputy Problem (OAuth proxy servers MUST implement per-client consent)", gap: "A requirement on OAuth proxy servers; nothing in an agent hook can enforce it.", mitigation: "Use only servers that implement it; allow-list servers." },
      { id: "MCP-SESSION-HIJACKING", name: "Security best practices: Session Hijacking", gap: "Server-side transport requirement.", mitigation: "Server operators: non-deterministic session ids, verify every request." },
      { id: "MCP-OAUTH-URL", name: "Security best practices: OAuth Authorization URL Validation", gap: "A client-implementation requirement on URL schemes and how URLs are opened.", mitigation: "Use an MCP client that validates schemes." },
      { id: "MCP-STDIO-PROXY", name: "Security best practices: stdio Transport Security in Proxy Scenarios", claim: "partly", gap: "The MCP gateway is itself a proxy: it frames stdio strictly (one bounded message per line), refuses unknown methods both ways (FW-MCP-METHOD), binds its HTTP listener to 127.0.0.1 with Origin and Host checks and a per-client bearer, and validates header-body agreement. It does not sandbox the wrapped server.", mitigation: "Run servers in a sandbox or container." },
      { id: "MCP-SCOPE", name: "Security best practices: Scope Minimization", gap: "Token scopes are granted outside the agent's tool calls; the firewall does not inspect them.", mitigation: "Request narrow scopes; avoid omnibus tokens." },
      { id: "MCP-SERVER-DUTIES", name: "Tools: servers MUST validate inputs, apply access control, rate limit, sanitise outputs (server/tools, Security Considerations)", gap: "Server obligations; the firewall is client-side.", mitigation: "Choose servers that meet them; managed-settings allow-list." },
    ],
  },
];

/** ATT&CK techniques the rules name (supplementary: used where ATLAS has no agent-specific technique; not counted in coverage). */
export const ATTACK: Record<string, string> = {
  T1027: "Obfuscated Files or Information",
  T1030: "Data Transfer Size Limits",
  T1048: "Exfiltration Over Alternative Protocol",
  T1053: "Scheduled Task/Job",
  T1059: "Command and Scripting Interpreter",
  "T1071.004": "Application Layer Protocol: DNS",
  T1105: "Ingress Tool Transfer",
  "T1195.001": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
  T1485: "Data Destruction",
  T1546: "Event Triggered Execution",
  T1548: "Abuse Elevation Control Mechanism",
  T1552: "Unsecured Credentials",
  "T1562.001": "Impair Defenses: Disable or Modify Tools",
};

/** An item's name by id, in any framework (or the ATT&CK table). */
export function frameworkName(id: string): string | null {
  for (const f of FRAMEWORKS) for (const i of f.items) if (i.id === id) return i.name;
  return own(ATTACK, id) ?? null;
}
