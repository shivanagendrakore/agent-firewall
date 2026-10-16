/**
 * Action fingerprints (design 5.3): the hash an approval binds to.
 *
 * (frame origin, action kind, action class, element path, field names, a
 * digest of the field values, the form's target origin and method). The digest
 * also covers what the field values alone do not: the full target URL of a
 * submit, upload or link (path and query, BR8b), and an activated control's
 * label and role, and a form control's form action and method (BR8a; a compose surface's body is already in its fields).
 * Any change to what would be submitted or clicked changes the fingerprint, so
 * an approval cannot be reused for a changed form or a retargeted control. Field values enter only as a
 * digest; the snapshot itself holds no values and is safe to keep in
 * chrome.storage.session and to show (masked) in the UI.
 */
import { sha256Hex } from "../vendor/firewall/engine/bytes.js";
import { originOf } from "./domain.js";
import type { ActionClass, ActionKind, FieldInfo, NormalizedAction } from "./types.js";

/** What an approval is bound to. Tab and frame are bound separately from the fingerprint (bindings.ts). */
export interface ActionSnapshot {
  tabId: number;
  frameId: number;
  frameOrigin: string;
  kind: ActionKind;
  actionClass: ActionClass | null;
  elementPath: string;
  /** Field names in document order. */
  fieldNames: string[];
  /** SHA-256 over the (name, value) pairs; "" when the action has no fields. */
  valuesDigest: string;
  /** The origin a submit or upload goes to; "" when it has none. */
  targetOrigin: string;
  method: string;
}

/**
 * What a stored snapshot keeps of the field names: the first few, cut short. The fingerprint (computed from the
 * full list before storing) is the binding; the names only label an approval whose metadata is missing, and a page
 * can send up to 500 of them, so keeping them all would let one form fill the session storage.
 */
export const STORED_FIELD_NAMES = 20;
export const STORED_FIELD_NAME_CHARS = 64;
export function storedFieldNames(names: readonly string[]): string[] {
  return names.slice(0, STORED_FIELD_NAMES).map((n) => n.slice(0, STORED_FIELD_NAME_CHARS));
}

/** Length-prefixed, so ("ab","c") and ("a","bc") never collide. */
function framed(parts: readonly string[]): string {
  return parts.map((p) => `${p.length}:${p}`).join("|");
}

export function valuesDigest(fields: readonly FieldInfo[]): string {
  if (fields.length === 0) return "";
  return sha256Hex(framed(fields.flatMap((f) => [f.name, f.type, f.value ?? ""])));
}

/**
 * Binding-only entries appended to the digest, after the real fields. Their
 * type ("binding") is not one the browser reports for a field, so a page
 * cannot forge a field that stands in for one.
 */
function bound(name: string, value: string): FieldInfo {
  return { name: `\u0000${name}`, type: "binding", value };
}

function digestWith(fields: readonly FieldInfo[], extra: readonly FieldInfo[]): string {
  return valuesDigest([...fields, ...extra]);
}

/**
 * The snapshot of an in-page action. Navigations and downloads are approved by
 * the worker against their URL, not replayed by the content script, so they
 * have no snapshot here.
 */
export function snapshotOf(action: Exclude<NormalizedAction, { kind: "navigate" | "download" }>, actionClass: ActionClass | null): ActionSnapshot {
  const base = { tabId: action.frame.tabId, frameId: action.frame.frameId, frameOrigin: action.frame.origin, kind: action.kind, actionClass, elementPath: action.elementPath };
  switch (action.kind) {
    case "submit":
      return { ...base, fieldNames: action.form.fields.map((f) => f.name), valuesDigest: digestWith(action.form.fields, [bound("target", action.form.targetUrl)]), targetOrigin: originOf(action.form.targetUrl) ?? "", method: action.form.method.toUpperCase() };
    case "activate": {
      const fields = action.context.formFields ?? [];
      const control = [bound("label", action.label), bound("role", action.role), bound("tag", action.tag), bound("href", action.href ?? ""), bound("compose", action.context.compose === undefined ? "" : `${action.context.compose.hasRecipient ? 1 : 0}${action.context.compose.hasBody ? 1 : 0}`), bound("formtarget", action.context.formTarget?.url ?? ""), bound("formmethod", action.context.formTarget?.method ?? "")];
      return { ...base, fieldNames: fields.map((f) => f.name), valuesDigest: digestWith(fields, control), targetOrigin: action.href !== undefined ? (originOf(action.href) ?? "") : action.context.formTarget !== undefined ? (originOf(action.context.formTarget.url) ?? "") : "", method: action.context.formTarget?.method.toUpperCase() ?? "" };
    }
    case "upload": {
      const files: FieldInfo[] = action.files.map((f, i) => ({ name: `file${i}`, type: "file", value: `${f.name}\u0000${f.size}\u0000${f.type}` }));
      return { ...base, fieldNames: files.map((f) => f.name), valuesDigest: digestWith(files, [bound("target", action.targetUrl ?? "")]), targetOrigin: action.targetUrl !== undefined ? (originOf(action.targetUrl) ?? "") : "", method: "" };
    }
    case "paste":
      return { ...base, fieldNames: ["paste"], valuesDigest: valuesDigest([{ name: "paste", type: "text", value: action.text }]), targetOrigin: "", method: "" };
    case "type":
      return { ...base, fieldNames: [action.field.name], valuesDigest: valuesDigest([{ ...action.field, value: action.value }]), targetOrigin: "", method: "" };
  }
}

/** The fingerprint of a snapshot: what must be identical for an approval to apply. */
export function actionFingerprint(s: ActionSnapshot): string {
  return sha256Hex(framed([s.frameOrigin, s.kind, s.actionClass ?? "", s.elementPath, framed(s.fieldNames), s.valuesDigest, s.targetOrigin, s.method]));
}

/**
 * The fingerprint as the decision log keeps it: salted with the agent session's random salt, so a binding for
 * a held 6-digit code read out of the log or an export cannot be matched against the million candidate codes
 * (RR11). The unsalted fingerprint stays in memory-only session storage with the approval it binds.
 */
export function saltedFingerprint(s: ActionSnapshot, salt: string): string {
  return sha256Hex(framed(["launchsafe-binding", salt, actionFingerprint(s)]));
}
