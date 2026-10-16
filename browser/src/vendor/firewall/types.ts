// Vendored from the LaunchSafe Agent Firewall (src/types.ts), Apache-2.0, at commit 5145f69e102584ff11ae342cd2349c4ee76974f3.
// Licence: Apache-2.0 (see NOTICE).
// Extract: only DataKind, verbatim; the rest of src/types.ts is the firewall's policy model and is not needed.
// Do not edit here: it is copied from the firewall repository by
// `node scripts/sync-firewall.mjs` (`--check` verifies the copy).

export type DataKind = "credential" | "card" | "iban" | "national_id";
