/**
 * Codex's `apply_patch` parser lives in the engine (src/engine/codex-patch.ts): the shell analyzer judges
 * `apply_patch` run through the shell (F2), and the engine stays free of adapters so the library (src/sdk/)
 * remains browser-safe. Re-exported here for the Codex adapter.
 */
export * from "../engine/codex-patch.js";
