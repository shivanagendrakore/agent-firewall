/**
 * Shared pieces of the site adapters: reading what the content script
 * measured (label, page URL, form fields) and the label patterns several
 * adapters use. Pure; no DOM.
 */
import { normalizeLabel } from "./classify.js";
import type { ActionClass, FieldInfo, NormalizedAction } from "./types.js";

export type InPage = Exclude<NormalizedAction, { kind: "navigate" | "download" }>;
export type Hit = { actionClass: ActionClass; signal: string } | null;

export function inPage(a: NormalizedAction): a is InPage {
  return a.kind !== "navigate" && a.kind !== "download";
}

/** The control's label without bidi and zero-width marks, whitespace collapsed (classify.normalizeLabel). */
export function normalLabel(a: NormalizedAction): string {
  return normalizeLabel(a.kind === "activate" ? a.label : a.kind === "submit" ? (a.label ?? "") : "");
}

export function pageParts(a: InPage): { path: string; hash: string; host: string; search: string } {
  try {
    const u = new URL(a.context.pageUrl);
    return { path: u.pathname, hash: u.hash, host: u.hostname.toLowerCase(), search: u.search };
  } catch {
    return { path: "", hash: "", host: "", search: "" };
  }
}

/** A control a person uses to commit a change on a settings page (not navigation like "Back" or "Learn more"). */
export const COMMIT_LABEL = /^(?:save|save changes|update|change|change password|update password|confirm|continue|next|done|turn on|turn off|enable|disable|add|create|generate|generate token|generate new token|regenerate|remove|revoke|delete|sign out|verify|submit|set|set up|yes|ok|proceed|apply|register)\b/i;

/** Activations that mean "send now" in a mail or chat compose, with the shortcut hint some sites add. */
export const SEND_NOW = /^send\b(?!\s+(?:feedback|to\s+back|later\b))/i;

export function isCommit(a: InPage, label: string): boolean {
  return a.kind === "submit" || (a.kind === "activate" && COMMIT_LABEL.test(label));
}

/** The fields around the control, or none. */
export function fieldsAround(a: InPage): readonly FieldInfo[] {
  return a.kind === "submit" ? a.form.fields : (a.context.formFields ?? []);
}

/** True when any field around the control has a name or label matching the pattern. */
export function hasField(a: InPage, pattern: RegExp): boolean {
  return fieldsAround(a).some((f) => pattern.test(f.label ?? "") || pattern.test(f.name));
}

/** A keyboard send (Enter or Ctrl+Enter in a composer): the gate reports it as role "shortcut". */
export function isShortcut(a: InPage): boolean {
  return a.kind === "activate" && a.role === "shortcut";
}

/** The composer around the control has a message body. */
export function inComposer(a: InPage): boolean {
  return a.context.compose?.hasBody === true;
}

/** The target URL's path of a form submit, or "". */
export function targetPath(a: InPage): string {
  if (a.kind !== "submit") return "";
  try {
    return new URL(a.form.targetUrl, a.context.pageUrl).pathname;
  } catch {
    return "";
  }
}
