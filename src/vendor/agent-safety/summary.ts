// Vendored from LaunchSafe's agent-safety package (src/summary.ts), Apache-2.0, at commit fc329d4314dc07a65da266a1256b1da0d17ec97c.
// Licence: Apache-2.0 (see NOTICE).
// Transform: add ".js" to relative import specifiers.
// Do not edit here: it is copied from the upstream package by
// `node scripts/sync-agent-safety.mjs` (`--check` verifies the copy).

import type { AgentAnalysis } from "./analyze.js";
import type { AgentSafetySummary } from "./types.js";

/**
 * Counts only, for the public grade: how many agent files were read and how
 * many issues of each severity were found. Never a file, a rule or a line:
 * that detail is the signed-in reveal.
 */
export function summarizeAgentSafety(analysis: Pick<AgentAnalysis, "findings" | "filesChecked">): AgentSafetySummary {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of analysis.findings) counts[finding.severity] += 1;
  return { filesChecked: analysis.filesChecked, counts };
}
