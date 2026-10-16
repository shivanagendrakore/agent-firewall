/**
 * The person's settings (design 9, 8, 5.3) in chrome.storage.local: log
 * retention, "keep evidence", webdriver detection, the agent-mode-off gating
 * of the always-on classes, and the trusted and sensitive site lists. Not
 * synced (design 12).
 *
 * While agent mode is on, changes that weaken protection are refused (turning
 * an always-on row or detection off, keeping the log for less time, trusting a
 * new site, taking a site off the sensitive list): an agent that reaches
 * extension UI should not be able to switch checks off mid-task. Agent mode
 * itself is turned off only through its gated approval.
 */
import { isPublicSuffix } from "../engine/domain.js";
import { ALWAYS_ON_CLASSES, DEFAULT_POLICY, type Policy } from "../engine/types.js";
import type { Settings, SettingsPatch } from "../shared/messages.js";
import { normalizeSitePattern, RETENTION_DAYS_MAX, RETENTION_DAYS_MIN, SITE_LIST_MAX } from "../shared/messages.js";
import type { KeyValueArea } from "./state.js";

export const SETTINGS_KEY = "ls.settings";

export const DEFAULT_SETTINGS: Settings = Object.freeze({
  retentionDays: 30,
  keepEvidence: false,
  detectWebdriver: true,
  alwaysOn: Object.freeze({ ...DEFAULT_POLICY.alwaysOn }),
  trustedHosts: Object.freeze([]),
  privateHosts: Object.freeze([]),
}) as unknown as Settings;

/**
 * A stored or patched site list, cleaned: valid patterns only, deduplicated, bounded. A trusted entry that
 * names a whole public suffix ("com", "*.github.io") would trust sites with no common owner, so it is dropped.
 */
export function cleanSiteList(x: unknown, trusted: boolean): string[] {
  if (!Array.isArray(x)) return [];
  const out = new Set<string>();
  for (const v of x) {
    if (typeof v !== "string") continue;
    const p = normalizeSitePattern(v);
    if (p === null) continue;
    const base = p.replace(/^=|^\*\./, "");
    if (trusted && (!base.includes(".") || isPublicSuffix(base))) continue;
    out.add(p);
    if (out.size >= SITE_LIST_MAX) break;
  }
  return [...out];
}

/** A stored value, repaired field by field: anything malformed falls back to the default (the strict choice). */
export function normalizeSettings(x: unknown): Settings {
  const o = typeof x === "object" && x !== null ? (x as Record<string, unknown>) : {};
  const days = o.retentionDays;
  const ao = typeof o.alwaysOn === "object" && o.alwaysOn !== null ? (o.alwaysOn as Record<string, unknown>) : {};
  const alwaysOn = { ...DEFAULT_SETTINGS.alwaysOn };
  for (const c of ALWAYS_ON_CLASSES) if (typeof ao[c] === "boolean") alwaysOn[c] = ao[c] as boolean;
  return {
    retentionDays: typeof days === "number" && Number.isInteger(days) && days >= RETENTION_DAYS_MIN && days <= RETENTION_DAYS_MAX ? days : DEFAULT_SETTINGS.retentionDays,
    keepEvidence: typeof o.keepEvidence === "boolean" ? o.keepEvidence : DEFAULT_SETTINGS.keepEvidence,
    detectWebdriver: typeof o.detectWebdriver === "boolean" ? o.detectWebdriver : DEFAULT_SETTINGS.detectWebdriver,
    alwaysOn,
    trustedHosts: cleanSiteList(o.trustedHosts, true),
    privateHosts: cleanSiteList(o.privateHosts, false),
  };
}

/** The changes in `patch` that would weaken protection relative to `current`. */
export function weakeningChanges(current: Settings, patch: SettingsPatch): string[] {
  const out: string[] = [];
  if (patch.detectWebdriver === false && current.detectWebdriver) out.push("detectWebdriver");
  if (patch.retentionDays !== undefined && patch.retentionDays < current.retentionDays) out.push("retentionDays");
  for (const c of ALWAYS_ON_CLASSES) if (patch.alwaysOn?.[c] === false && current.alwaysOn[c]) out.push(`alwaysOn.${c}`);
  // Trusting a site the list did not have, or dropping a sensitive one, loosens what counts as outside or private.
  if (patch.trustedHosts !== undefined && cleanSiteList(patch.trustedHosts, true).some((h) => !current.trustedHosts.includes(h))) out.push("trustedHosts");
  if (patch.privateHosts !== undefined) {
    const next = cleanSiteList(patch.privateHosts, false);
    if (current.privateHosts.some((h) => !next.includes(h))) out.push("privateHosts");
  }
  return out;
}

/** Applies a patch. With agent mode on, weakening changes are dropped and named in `refused`. */
export function applySettingsPatch(current: Settings, patch: SettingsPatch, agentMode: boolean): { settings: Settings; refused: string[] } {
  const refused = agentMode ? weakeningChanges(current, patch) : [];
  const next: Settings = { ...current, alwaysOn: { ...current.alwaysOn } };
  if (patch.retentionDays !== undefined && !refused.includes("retentionDays")) next.retentionDays = patch.retentionDays;
  if (patch.keepEvidence !== undefined) next.keepEvidence = patch.keepEvidence;
  if (patch.detectWebdriver !== undefined && !refused.includes("detectWebdriver")) next.detectWebdriver = patch.detectWebdriver;
  for (const c of ALWAYS_ON_CLASSES) {
    const v = patch.alwaysOn?.[c];
    if (v !== undefined && !refused.includes(`alwaysOn.${c}`)) next.alwaysOn[c] = v;
  }
  if (patch.trustedHosts !== undefined && !refused.includes("trustedHosts")) next.trustedHosts = cleanSiteList(patch.trustedHosts, true);
  if (patch.privateHosts !== undefined && !refused.includes("privateHosts")) next.privateHosts = cleanSiteList(patch.privateHosts, false);
  return { settings: normalizeSettings(next), refused };
}

/** The engine policy with the person's always-on choices and site lists (added to the base policy's). */
export function policyWith(settings: Settings, base: Policy = DEFAULT_POLICY): Policy {
  return {
    ...base,
    alwaysOn: { ...settings.alwaysOn },
    trustedHosts: [...new Set([...base.trustedHosts, ...settings.trustedHosts])],
    privateHosts: [...new Set([...base.privateHosts, ...settings.privateHosts])],
  };
}

/**
 * The log's retention period, read from the stored settings at the moment of each purge (RR8): a worker that
 * starts and purges before anything else has loaded still purges with the person's period, never the default.
 */
export function retentionFrom(store: SettingsStore): () => Promise<number> {
  return async () => (await store.load()).retentionDays * 24 * 60 * 60 * 1000;
}

export interface SettingsStore {
  load(): Promise<Settings>;
  save(s: Settings): Promise<void>;
}

export function createSettingsStore(area: KeyValueArea): SettingsStore {
  return {
    async load() {
      return normalizeSettings((await area.get(SETTINGS_KEY))[SETTINGS_KEY]);
    },
    async save(s) {
      await area.set({ [SETTINGS_KEY]: normalizeSettings(s) });
    },
  };
}
