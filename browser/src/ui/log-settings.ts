/**
 * The side panel's settings and decision log view (leak lane).
 * A separate component: sidepanel.ts mounts it below the approvals, which the
 * gate lane owns. Every string from storage is set with textContent.
 *
 * The agent-mode switch is not here: there is one, in sidepanel.ts, and turning
 * it off is an approval card (cards.ts) that needs a trusted, armed pointer press.
 *
 * - Settings: webdriver detection, the always-on rows, keep evidence,
 *   retention, and the trusted and sensitive site lists (one pattern per line).
 *   The worker refuses weakening changes while agent mode is on.
 * - Log: verify, the newest entries, export (a JSON file saved from this page)
 *   and delete (refused while agent mode is on).
 */
import { ALWAYS_ON_CLASSES, type AlwaysOnClass } from "../engine/types.js";
import { sendToWorker } from "../shared/bridge.js";
import { normalizeSitePattern, SITE_LIST_MAX, type Settings, type SettingsPatch } from "../shared/messages.js";
import { ALWAYS_ON_LABELS, entryLine, exportFileName, refusedLine, verifyLine } from "./log-view.js";

const SHOWN_ENTRIES = 50;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}, text?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  if (text !== undefined) e.textContent = text;
  return e;
}

/**
 * Runs `fn` only for a click that follows a trusted pointer down on the same
 * button: synthetic clicks, keyboard activation and clicks from other pages
 * do nothing.
 */
export function onFreshPointerClick(button: HTMLElement, fn: () => void): void {
  let armed = false;
  button.addEventListener("pointerdown", (e) => {
    armed = e.isTrusted && e.button === 0;
  });
  button.addEventListener("pointerleave", () => (armed = false));
  button.addEventListener("click", (e) => {
    const ok = armed && e.isTrusted && e.detail > 0;
    armed = false;
    if (ok) fn();
  });
}

export interface LogSettingsView {
  /** Re-reads settings and the log (the side panel calls it on the worker's ui.changed broadcast). */
  refresh(): void;
}

export function mountLogSettings(container: HTMLElement): LogSettingsView {
  // ---- settings ----
  const setSec = el("section", { id: "ls-settings", "aria-labelledby": "ls-settings-h" });
  const setH = el("h2", { id: "ls-settings-h", class: "ls-h" }, "Settings");
  const detect = el("input", { id: "ls-detect-webdriver", type: "checkbox" });
  const detectLabel = el("label", { for: "ls-detect-webdriver" }, " Turn agent mode on when the browser is under automation (navigator.webdriver)");
  detectLabel.prepend(detect);
  const alwaysHead = el("p", { class: "muted" }, "With agent mode off, these still wait for your approval:");
  const alwaysBoxes = new Map<AlwaysOnClass, HTMLInputElement>();
  const alwaysList = el("div");
  for (const c of ALWAYS_ON_CLASSES) {
    const box = el("input", { id: `ls-always-${c}`, type: "checkbox" });
    const label = el("label", { for: `ls-always-${c}` }, ` ${ALWAYS_ON_LABELS[c]}`);
    label.prepend(box);
    alwaysBoxes.set(c, box);
    const row = el("div");
    row.append(label);
    alwaysList.append(row);
  }
  const evidence = el("input", { id: "ls-keep-evidence", type: "checkbox" });
  const evidenceLabel = el("label", { for: "ls-keep-evidence" }, " Keep evidence (the first 200 characters of hidden text that triggered a block)");
  evidenceLabel.prepend(evidence);
  const retention = el("input", { id: "ls-retention", type: "number", min: "1", max: "365", step: "1" });
  const retentionLabel = el("label", { for: "ls-retention" }, "Keep the log for (days) ");
  retentionLabel.append(retention);
  const siteList = (id: string, label: string, help: string): { box: HTMLTextAreaElement; save: HTMLButtonElement; wrap: HTMLDivElement } => {
    const wrap = el("div", { class: "ls-sites" });
    const lab = el("label", { for: id }, label);
    const box = el("textarea", { id, rows: "3", spellcheck: "false", autocomplete: "off", placeholder: "example.com\n*.example.org" });
    const note = el("p", { class: "muted" }, help);
    const save = el("button", { id: `${id}-save`, type: "button" }, "Save list");
    wrap.append(lab, box, note, save);
    return { box, save, wrap };
  };
  const trusted = siteList("ls-trusted-hosts", "Trusted sites", "Pages from these sites do not make a tab untrusted. One per line: example.com covers its subdomains, =host.example.com only that host. Adding one is refused while agent mode is on.");
  const sensitive = siteList("ls-private-hosts", "Sensitive sites", "Added to the built-in list (mail, banks, cloud consoles). Removing one is refused while agent mode is on.");
  const setMsg = el("p", { id: "ls-settings-msg", class: "muted", role: "status" });
  const row = (child: HTMLElement): HTMLDivElement => {
    const d = el("div");
    d.append(child);
    return d;
  };
  setSec.append(setH, row(detectLabel), alwaysHead, alwaysList, row(evidenceLabel), row(retentionLabel), trusted.wrap, sensitive.wrap, setMsg);

  // ---- log ----
  const logSec = el("section", { id: "ls-log", "aria-labelledby": "ls-log-h" });
  const logH = el("h2", { id: "ls-log-h", class: "ls-h" }, "Decision log");
  const logNote = el("p", { class: "muted" }, "Kept on this device only. Entries name the site and the rule, never page text or what was typed. The chain shows edits made outside the extension; someone who controls this browser profile can still rewrite all of it.");
  const verify = el("p", { id: "ls-log-verify", role: "status" });
  const buttons = el("div");
  const verifyBtn = el("button", { id: "ls-log-verify-btn", type: "button" }, "Verify");
  const exportBtn = el("button", { id: "ls-log-export", type: "button" }, "Export");
  const deleteBtn = el("button", { id: "ls-log-delete", type: "button" }, "Delete log");
  const deleteConfirm = el("button", { id: "ls-log-delete-confirm", type: "button", hidden: "" }, "Confirm: delete every entry");
  buttons.append(verifyBtn, exportBtn, deleteBtn, deleteConfirm);
  const logMsg = el("p", { id: "ls-log-msg", class: "muted", role: "status" });
  const list = el("ol", { id: "ls-log-entries", reversed: "" });
  logSec.append(logH, logNote, verify, buttons, logMsg, list);

  container.append(setSec, logSec);

  // ---- behaviour ----
  // ---- behaviour ----

  const renderSettings = (s: Settings): void => {
    detect.checked = s.detectWebdriver;
    evidence.checked = s.keepEvidence;
    retention.value = String(s.retentionDays);
    for (const [c, box] of alwaysBoxes) box.checked = s.alwaysOn[c];
    trusted.box.value = s.trustedHosts.join("\n");
    sensitive.box.value = s.privateHosts.join("\n");
  };

  const refreshLog = async (): Promise<void> => {
    const [v, l] = await Promise.all([sendToWorker({ type: "ui.log.verify" }), sendToWorker({ type: "ui.log.list", limit: SHOWN_ENTRIES })]);
    verify.textContent = verifyLine(v);
    list.replaceChildren(...[...l.entries].reverse().map((e) => el("li", {}, entryLine(e))));
  };

  const refresh = async (): Promise<void> => {
    const settings = await sendToWorker({ type: "ui.settings.get" });
    renderSettings(settings.settings);
    await refreshLog();
  };

  const patch = async (p: SettingsPatch): Promise<void> => {
    const r = await sendToWorker({ type: "ui.settings.set", patch: p });
    renderSettings(r.settings);
    setMsg.textContent = refusedLine(r.refused ?? []);
    await refreshLog();
  };

  detect.addEventListener("change", () => void patch({ detectWebdriver: detect.checked }));
  evidence.addEventListener("change", () => void patch({ keepEvidence: evidence.checked }));
  retention.addEventListener("change", () => {
    const n = Number(retention.value);
    if (Number.isInteger(n) && n >= 1 && n <= 365) void patch({ retentionDays: n });
  });
  for (const [c, box] of alwaysBoxes) box.addEventListener("change", () => void patch({ alwaysOn: { [c]: box.checked } }));
  const linesOf = (box: HTMLTextAreaElement): string[] => box.value.split(/[\s,]+/).map((x) => x.trim()).filter((x) => x !== "");
  const saveList = (key: "trustedHosts" | "privateHosts", box: HTMLTextAreaElement): void => {
    const raw = linesOf(box);
    const valid = raw.map(normalizeSitePattern).filter((x): x is string => x !== null);
    if (valid.length !== raw.length || valid.length > SITE_LIST_MAX) {
      setMsg.textContent = `Not saved: each line must be a site such as example.com (at most ${SITE_LIST_MAX}).`;
      return;
    }
    void patch({ [key]: valid });
  };
  trusted.save.addEventListener("click", () => saveList("trustedHosts", trusted.box));
  sensitive.save.addEventListener("click", () => saveList("privateHosts", sensitive.box));

  verifyBtn.addEventListener("click", () => void refreshLog());
  exportBtn.addEventListener("click", () => {
    void (async () => {
      const { json } = await sendToWorker({ type: "ui.log.export" });
      const url = URL.createObjectURL(new Blob([json], { type: "application/json" }));
      const a = el("a", { href: url, download: exportFileName(Date.now()) });
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
      logMsg.textContent = "Exported.";
    })();
  });
  deleteBtn.addEventListener("click", () => {
    deleteConfirm.hidden = false;
  });
  onFreshPointerClick(deleteConfirm, () => {
    void (async () => {
      const r = await sendToWorker({ type: "ui.log.clear" });
      deleteConfirm.hidden = true;
      logMsg.textContent = r.ok ? "The log is deleted." : "Not deleted: agent mode is on. Turn it off first.";
      await refreshLog();
    })();
  });

  const safeRefresh = (): void => {
    refresh().catch(() => {
      logMsg.textContent = "The extension's worker is not responding. Reload the extension.";
    });
  };
  safeRefresh();
  return { refresh: safeRefresh };
}
