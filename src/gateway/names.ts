/**
 * MCP server names, checked alike by the gateway (wrap-config, the wrapper) and the local API (the registry, decide
 * requests): the engine reads a call's server back from mcp__<server>__<tool>, so a name that holds "__" or ends in
 * "_" would be read as another server, and its calls judged under that server's policy (FZ15).
 */

/** Why an MCP server name cannot be used, or null. */
export function serverNameProblem(name: string): string | null {
  // eslint-disable-next-line no-control-regex -- refusing control characters is the point
  if (name === "" || name.length > 200 || /[\u0000-\u001f\u007f-\u009f]/.test(name)) return "must be 1 to 200 characters without control characters";
  if (name.includes("__")) return 'cannot contain "__" (the separator in mcp__<server>__<tool>)';
  if (name.endsWith("_")) return 'cannot end with "_" (it would run into the "__" separator in mcp__<server>__<tool>)';
  return null;
}
