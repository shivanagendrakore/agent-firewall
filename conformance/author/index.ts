import { catalogue, friction, incidents } from "./corpora.js";
import { families } from "./families.js";
import { formatDetails, mcpFormat, registryFormats } from "./formats.js";
import { invalid } from "./invalid.js";
import { preparedLedger } from "./ledger.js";
import { networkTraffic } from "./network.js";
import { preparedBudgets, preparedCaps, preparedDecoys, preparedFiles, preparedHosts, preparedPackages, preparedPolicy } from "./prepared.js";
import { ruleFamilies } from "./rules.js";
import type { Skeleton } from "./kit.js";

/** Vector files, by name: each is a JSON array of vectors. */
export function groups(): Record<string, Skeleton[]> {
  const registry = registryFormats();
  return {
    "engine-friction": friction(),
    "engine-incidents": incidents(),
    "engine-catalogue": catalogue(25),
    "format-native": registry.filter((v) => v.id.startsWith("native-")),
    "format-openai-chat": registry.filter((v) => v.id.startsWith("openai-")),
    "format-anthropic": registry.filter((v) => v.id.startsWith("anthropic-")),
    "format-details": formatDetails(),
    "format-mcp": mcpFormat(),
    "families": families(),
    "rules": ruleFamilies(),
    "network-traffic": networkTraffic(),
    "invalid-requests": invalid(),
    "prepared-decoys": preparedDecoys(),
    "prepared-files": preparedFiles(),
    "prepared-policy": preparedPolicy(),
    "prepared-budgets": preparedBudgets(),
    "prepared-caps": preparedCaps(),
    "prepared-hosts": preparedHosts(),
    "prepared-ledger": preparedLedger(),
    "prepared-packages": preparedPackages(),
  };
}
