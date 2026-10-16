/**
 * The `outsiderWritable` policy key (src/engine/outsider.ts): which sources
 * outsiders can write, whether their results always taint, and whether a
 * command they showed needs a person before it runs. A project file may only
 * tighten: turn `alwaysTaint` on, add servers, set `commands` to "ask". It
 * cannot exempt a server or switch the rule off.
 */
import type { OutsiderWritablePolicy } from "./engine/outsider.js";
import type { FirewallConfig } from "./types.js";

export { DEFAULT_OUTSIDER_WRITABLE, outsiderPolicy } from "./engine/outsider.js";

export const OUTSIDER_POLICY_KEYS = ["outsiderWritable"] as const;

export interface OutsiderDoc {
  outsiderWritable?: Partial<OutsiderWritablePolicy>;
}

type Raw = Record<string, unknown>;

const KEYS = ["alwaysTaint", "servers", "exempt", "commands"];

function stringList(v: unknown, key: string, problems: string[]): string[] | null {
  if (!Array.isArray(v) || !v.every((x) => typeof x === "string" && x.trim() !== "" && x.length <= 200)) {
    problems.push(`"outsiderWritable.${key}" must be a list of non-empty server names or patterns (at most 200 characters each)`);
    return null;
  }
  return v as string[];
}

/** Validates `outsiderWritable` of a (migrated) policy document into `out`. Unknown sub-keys and bad values are errors. */
export function validateOutsiderKeys(raw: Raw, problems: string[], out: OutsiderDoc): void {
  if (raw.outsiderWritable === undefined) return;
  const o = raw.outsiderWritable;
  if (typeof o !== "object" || o === null || Array.isArray(o)) {
    problems.push('"outsiderWritable" must be an object');
    return;
  }
  const res: Partial<OutsiderWritablePolicy> = {};
  for (const [k, v] of Object.entries(o as Raw)) {
    if (k === "alwaysTaint") {
      if (typeof v !== "boolean") problems.push('"outsiderWritable.alwaysTaint" must be true or false');
      else res.alwaysTaint = v;
    } else if (k === "servers" || k === "exempt") {
      const list = stringList(v, k, problems);
      if (list !== null) res[k] = list;
    } else if (k === "commands") {
      if (v !== "ask" && v !== "off") problems.push('"outsiderWritable.commands" must be "ask" or "off"');
      else res.commands = v;
    } else problems.push(`"outsiderWritable.${k}" is not a known setting (expected one of ${KEYS.join(", ")})`);
  }
  out.outsiderWritable = res;
}

/** The user's or the administrator's layer over the one below: every key it sets wins. */
export function mergeOutsider(base: Partial<OutsiderWritablePolicy> | undefined, over: Partial<OutsiderWritablePolicy> | undefined): Partial<OutsiderWritablePolicy> {
  return { ...(base ?? {}), ...(over ?? {}) };
}

/** Applies a project file's `outsiderWritable`: stricter only; loosening is listed in `ignored`. */
export function tightenOutsiderKeys(base: FirewallConfig, over: OutsiderDoc, cfg: FirewallConfig, ignored: string[]): void {
  const o = over.outsiderWritable;
  if (o === undefined) return;
  const current: Partial<OutsiderWritablePolicy> = { ...(base.outsiderWritable ?? {}) };
  if (o.alwaysTaint === true) current.alwaysTaint = true;
  if (o.alwaysTaint === false) ignored.push("outsiderWritable.alwaysTaint (a project may only turn it on)");
  if (o.servers !== undefined) current.servers = [...new Set([...(current.servers ?? []), ...o.servers])];
  if (o.exempt !== undefined && o.exempt.length > 0) ignored.push("outsiderWritable.exempt (a project cannot take a server out of the outsider-writable class)");
  if (o.commands === "ask") current.commands = "ask";
  if (o.commands === "off") ignored.push('outsiderWritable.commands "off" (a project may only set "ask")');
  cfg.outsiderWritable = current;
}
