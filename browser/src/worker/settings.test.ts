import { describe, expect, it } from "vitest";
import { applySettingsPatch, createSettingsStore, DEFAULT_SETTINGS, normalizeSettings, policyWith, SETTINGS_KEY, weakeningChanges } from "./settings.js";
import type { KeyValueArea } from "./state.js";

function memoryArea(): KeyValueArea & { data: Map<string, unknown> } {
  const data = new Map<string, unknown>();
  return {
    data,
    get: async (k) => (data.has(k) ? { [k]: structuredClone(data.get(k)) } : {}),
    set: async (items) => {
      for (const [k, v] of Object.entries(items)) data.set(k, structuredClone(v));
    },
  };
}

describe("settings", () => {
  it("defaults: 30-day retention, detection on, every always-on row on, no evidence", () => {
    expect(DEFAULT_SETTINGS).toEqual({ retentionDays: 30, keepEvidence: false, detectWebdriver: true, alwaysOn: { oauth_consent: true, account_security: true, download_exec: true }, trustedHosts: [], privateHosts: [] });
  });
  it("repairs malformed stored values to the defaults, field by field", () => {
    expect(normalizeSettings(null)).toEqual(DEFAULT_SETTINGS);
    expect(normalizeSettings({ retentionDays: 0, keepEvidence: "yes", alwaysOn: { oauth_consent: false, bogus: true } })).toEqual({ ...DEFAULT_SETTINGS, alwaysOn: { ...DEFAULT_SETTINGS.alwaysOn, oauth_consent: false } });
    expect(normalizeSettings({ retentionDays: 9999 }).retentionDays).toBe(30);
  });
  it("names weakening changes", () => {
    expect(weakeningChanges(DEFAULT_SETTINGS, { detectWebdriver: false, retentionDays: 7, alwaysOn: { oauth_consent: false } })).toEqual(["detectWebdriver", "retentionDays", "alwaysOn.oauth_consent"]);
    expect(weakeningChanges(DEFAULT_SETTINGS, { retentionDays: 90, keepEvidence: true })).toEqual([]);
  });
  it("with agent mode off, applies every change", () => {
    const r = applySettingsPatch(DEFAULT_SETTINGS, { detectWebdriver: false, alwaysOn: { download_exec: false } }, false);
    expect(r.refused).toEqual([]);
    expect(r.settings.detectWebdriver).toBe(false);
    expect(r.settings.alwaysOn.download_exec).toBe(false);
  });
  it("with agent mode on, refuses weakening changes and applies the rest", () => {
    const r = applySettingsPatch(DEFAULT_SETTINGS, { detectWebdriver: false, retentionDays: 5, keepEvidence: true, alwaysOn: { account_security: false } }, true);
    expect(r.refused.sort()).toEqual(["alwaysOn.account_security", "detectWebdriver", "retentionDays"]);
    expect(r.settings).toEqual({ ...DEFAULT_SETTINGS, keepEvidence: true });
  });
  it("with agent mode on, strengthening changes go through", () => {
    const weak = { ...DEFAULT_SETTINGS, detectWebdriver: false, alwaysOn: { ...DEFAULT_SETTINGS.alwaysOn, oauth_consent: false } };
    const r = applySettingsPatch(weak, { detectWebdriver: true, alwaysOn: { oauth_consent: true } }, true);
    expect(r.refused).toEqual([]);
    expect(r.settings).toEqual(DEFAULT_SETTINGS);
  });
  it("the policy takes the always-on choices", () => {
    expect(policyWith({ ...DEFAULT_SETTINGS, alwaysOn: { oauth_consent: false, account_security: true, download_exec: true } }).alwaysOn.oauth_consent).toBe(false);
  });
  it("persists through the store", async () => {
    const area = memoryArea();
    const store = createSettingsStore(area);
    expect(await store.load()).toEqual(DEFAULT_SETTINGS);
    await store.save({ ...DEFAULT_SETTINGS, retentionDays: 60 });
    expect((area.data.get(SETTINGS_KEY) as { retentionDays: number }).retentionDays).toBe(60);
    expect((await store.load()).retentionDays).toBe(60);
  });
});

describe("RR9: the trusted and sensitive site lists", () => {
  it("are cleaned: valid patterns only, no duplicates, and no trusted public suffix", () => {
    const s = normalizeSettings({ trustedHosts: ["Intranet.Example", "intranet.example", "com", "*.github.io", "bad host", 5], privateHosts: ["bank.example", "=vault.example"] });
    expect(s.trustedHosts).toEqual(["intranet.example"]);
    expect(s.privateHosts).toEqual(["bank.example", "=vault.example"]);
  });
  it("in agent mode, trusting a new site and dropping a sensitive one are refused; the opposite changes apply", () => {
    const cur = { ...DEFAULT_SETTINGS, trustedHosts: ["a.example"], privateHosts: ["bank.example"] };
    expect(weakeningChanges(cur, { trustedHosts: ["a.example", "b.example"] })).toEqual(["trustedHosts"]);
    expect(weakeningChanges(cur, { privateHosts: [] })).toEqual(["privateHosts"]);
    const r = applySettingsPatch(cur, { trustedHosts: [], privateHosts: ["bank.example", "health.example"] }, true);
    expect(r.refused).toEqual([]);
    expect(r.settings).toMatchObject({ trustedHosts: [], privateHosts: ["bank.example", "health.example"] });
  });
  it("feed the engine policy on top of the base policy", () => {
    const p = policyWith({ ...DEFAULT_SETTINGS, trustedHosts: ["a.example"], privateHosts: ["bank.example"] });
    expect(p.trustedHosts).toEqual(["a.example"]);
    expect(p.privateHosts).toEqual(["bank.example"]);
  });
});
