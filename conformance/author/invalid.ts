/** Requests the contract refuses as a bad request (400): they never reach the engine. Recorded by translate.ts. */

import { NO_TOOLS, reg, SESSION, vec, type Skeleton, type SkStep } from "./kit.js";

const bad = (request: Record<string, unknown>, kind: SkStep["kind"] = "decide"): SkStep => ({ kind, request });
const ok = { format: "native", tool: "search_docs", input: { q: "x" } };

export function invalid(): Skeleton[] {
  const R = reg({ search_docs: { kind: "read" } });
  const out: Skeleton[] = [];
  const add = (id: string, description: string, step: SkStep): void => void out.push(vec(`invalid-${id}`, description, "docs/api-v0.md, errors", R, [step]));
  add("unknown-top-level-field", "An unknown field in the body", bad({ session: SESSION, action: ok, extra: 1 }));
  add("unknown-action-field", "An unknown field in action", bad({ session: SESSION, action: { ...ok, extra: 1 } }));
  add("unknown-context-field", "An unknown field in context", bad({ session: SESSION, action: ok, context: { attended: true, user: "x" } }));
  add("unknown-format", "A format v0 does not have", bad({ session: SESSION, action: { format: "openai.responses", raw: {} } }));
  add("missing-format", "No format", bad({ session: SESSION, action: { tool: "search_docs", input: {} } }));
  add("missing-session", "No session", bad({ action: ok }));
  add("empty-session", "An empty session", bad({ session: "", action: ok }));
  add("native-missing-tool", "native without a tool", bad({ session: SESSION, action: { format: "native", input: {} } }));
  add("native-missing-input", "native without input", bad({ session: SESSION, action: { format: "native", tool: "search_docs" } }));
  add("native-input-not-object", "native with input that is not an object", bad({ session: SESSION, action: { format: "native", tool: "search_docs", input: "q" } }));
  add("native-with-raw", "native with a raw field", bad({ session: SESSION, action: { ...ok, raw: {} } }));
  add("openai-arguments-not-json", "openai.chat with arguments that are not JSON", bad({ session: SESSION, action: { format: "openai.chat", raw: { id: "c", type: "function", function: { name: "search_docs", arguments: "{q:" } } } }));
  add("openai-arguments-array", "openai.chat with arguments that are a JSON array", bad({ session: SESSION, action: { format: "openai.chat", raw: { id: "c", type: "function", function: { name: "search_docs", arguments: "[1]" } } } }));
  add("openai-arguments-object-not-string", "openai.chat with arguments given as an object", bad({ session: SESSION, action: { format: "openai.chat", raw: { id: "c", type: "function", function: { name: "search_docs", arguments: { q: "x" } } } } }));
  add("openai-wrong-type", "openai.chat whose raw type is not function", bad({ session: SESSION, action: { format: "openai.chat", raw: { id: "c", type: "custom", function: { name: "search_docs", arguments: "{}" } } } }));
  add("openai-with-tool-field", "openai.chat with a tool field beside raw", bad({ session: SESSION, action: { format: "openai.chat", tool: "search_docs", raw: { id: "c", type: "function", function: { name: "search_docs", arguments: "{}" } } } }));
  add("anthropic-wrong-type", "anthropic whose raw type is not tool_use", bad({ session: SESSION, action: { format: "anthropic", raw: { type: "text", id: "t", name: "search_docs", input: {} } } }));
  add("anthropic-missing-raw", "anthropic without raw", bad({ session: SESSION, action: { format: "anthropic" } }));
  add("mcp-missing-server", "mcp without mcp.server", bad({ session: SESSION, action: { format: "mcp", tool: "list_issues", input: {}, mcp: { source: "user" } } }));
  add("mcp-missing-mcp", "mcp without the mcp object", bad({ session: SESSION, action: { format: "mcp", tool: "list_issues", input: {} } }));
  add("mcp-object-on-native", "An mcp object on a native action", bad({ session: SESSION, action: { ...ok, mcp: { server: "x" } } }));
  add("attended-not-boolean", "attended as a string", bad({ session: SESSION, action: ok, context: { attended: "yes" } }));
  add("workspace-not-array", "workspace as a string", bad({ session: SESSION, action: ok, context: { workspace: "/srv/app" } }));
  add("dry-run-not-boolean", "dryRun as a string", bad({ session: SESSION, action: ok, dryRun: "true" }));
  add("result-missing-output", "A result without output", bad({ session: SESSION, decisionId: "@step:0" }, "result"));
  add("result-unknown-field", "A result with an unknown field", bad({ session: SESSION, decisionId: "@step:0", output: "x", extra: 1 }, "result"));
  add("input-missing-source", "An input without a source", bad({ session: SESSION, content: "x" }, "input"));
  add("input-private-not-boolean", "An input whose private is a string", bad({ session: SESSION, source: "s", content: "x", private: "yes" }, "input"));
  add("prompt-missing-text", "A prompt without text", bad({ session: SESSION }, "prompt"));
  add("prompt-text-not-string", "A prompt whose text is a number", bad({ session: SESSION, text: 5 }, "prompt"));

  // Types and closed objects.
  add("session-not-string", "A session that is a number", bad({ session: 5, action: ok }));
  add("call-id-not-string", "An action.callId that is a number", bad({ session: SESSION, action: { ...ok, callId: 5 } }));
  add("cwd-not-string", "A context.cwd that is a number", bad({ session: SESSION, action: ok, context: { cwd: 5 } }));
  add("traffic-unknown", "A context.traffic that is neither tool nor network", bad({ session: SESSION, action: ok, context: { traffic: "browser" } }));
  add("mcp-source-not-string", "An mcp.source that is a number", bad({ session: SESSION, action: { format: "mcp", tool: "list_issues", input: {}, mcp: { server: "github", source: 5 } } }));
  add("mcp-unknown-key", "An unknown field in action.mcp", bad({ session: SESSION, action: { format: "mcp", tool: "list_issues", input: {}, mcp: { server: "github", trust: "full" } } }));
  add("native-empty-tool", "native with an empty tool name", bad({ session: SESSION, action: { format: "native", tool: "", input: {} } }));
  add("engine-empty-tool", "engine with an empty tool name", bad({ session: SESSION, action: { format: "engine", tool: "", input: {} } }));
  add("anthropic-empty-name", "anthropic whose tool_use name is empty", bad({ session: SESSION, action: { format: "anthropic", raw: { type: "tool_use", id: "t", name: "", input: {} } } }));
  add("body-array", "A decide body that is a JSON array", bad([{ session: SESSION, action: ok }] as unknown as Record<string, unknown>));
  add("body-null", "A decide body that is JSON null", bad(null as unknown as Record<string, unknown>));

  // usage: an object of whole token counts and a finite cost.
  add("usage-not-object", "A usage that is a string", bad({ session: SESSION, action: ok, usage: "600 tokens" }));
  add("usage-unknown-key", "A usage with an unknown field", bad({ session: SESSION, action: ok, usage: { tokens: 600 } }));
  add("usage-negative", "A usage with a negative token count", bad({ session: SESSION, action: ok, usage: { inputTokens: -1 } }));
  add("usage-fraction", "A usage with a fractional token count", bad({ session: SESSION, action: ok, usage: { outputTokens: 1.5 } }));
  add("usage-cost-string", "A usage whose cost is a string", bad({ session: SESSION, action: ok, usage: { costUsd: "0.01" } }));

  // The session endpoints.
  out.push(vec("invalid-result-failed-not-boolean", "A result whose failed is a string", "docs/api-v0.md, errors", R, [{ kind: "decide", request: { session: SESSION, action: ok } }, bad({ session: SESSION, decisionId: "@step:0", output: "x", failed: "yes" }, "result")]));
  add("input-unknown-field", "An input with an unknown field", bad({ session: SESSION, source: "s", content: "x", trusted: true }, "input"));
  add("input-missing-content", "An input without content", bad({ session: SESSION, source: "s" }, "input"));
  add("prompt-unknown-field", "A prompt with an unknown field", bad({ session: SESSION, text: "hello", from: "user" }, "prompt"));

  // Inside `raw` only the documented keys are read: other keys a framework adds are ignored, not refused.
  const ignored = (id: string, description: string, action: Record<string, unknown>): void => void out.push(vec(`raw-${id}`, description, "docs/api-v0.md, decide request (raw)", R, [{ kind: "decide", request: { session: SESSION, action } }]));
  ignored("anthropic-extra-keys-ignored", "anthropic: a tool_use block with keys the contract does not read (cache_control, caller) is accepted", { format: "anthropic", raw: { type: "tool_use", id: "toolu_1", name: "search_docs", input: { q: "x" }, cache_control: { type: "ephemeral" }, caller: { type: "direct" } } });
  ignored("openai-extra-keys-ignored", "openai.chat: a tool_call with keys the contract does not read is accepted", { format: "openai.chat", raw: { id: "call_1", type: "function", index: 0, function: { name: "search_docs", arguments: '{"q":"x"}', strict: true } } });
  void NO_TOOLS;
  return out;
}
