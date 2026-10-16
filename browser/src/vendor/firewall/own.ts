// Vendored from the LaunchSafe Agent Firewall (src/own.ts), Apache-2.0, at commit 09968d171ebeda828fc07ce6c843170341f28fd0.
// Licence: Apache-2.0 (see NOTICE).
// Do not edit here: it is copied from the firewall repository by
// `node scripts/sync-firewall.mjs` (`--check` verifies the copy).

/**
 * Own-property lookups for maps keyed by names from outside: MCP server and tool names, hosts, agent
 * and client names, vault entries, pins, sessions, package and tag names (FB3).
 *
 * A plain object answers `map["constructor"]`, `map["toString"]` or `map["__proto__"]` from
 * Object.prototype, so a server or tool that picks such a name would be judged by a built-in function
 * instead of by "not listed". A write of `map["__proto__"] = v` changes the object's prototype instead
 * of adding an entry. Every read and write through a computed string key on such a map goes through
 * these helpers; the `local/own-keys` lint rule (eslint.config.mjs) keeps it that way.
 */

/** The value stored under `key` itself, never one inherited from the prototype. */
export function own<T>(map: Readonly<Record<string, T>> | undefined | null, key: string): T | undefined {
  return map != null && Object.hasOwn(map, key) ? map[key] : undefined;
}

/** Whether `key` is an entry of the map itself. */
export function hasOwn(map: object | undefined | null, key: string): boolean {
  return map != null && Object.hasOwn(map, key);
}

/** Stores `value` under `key` as an own entry, even for "__proto__" (never changes the prototype). */
export function setOwn<T>(map: Record<string, T>, key: string, value: NoInfer<T>): void {
  Object.defineProperty(map, key, { value, writable: true, enumerable: true, configurable: true });
}

/** An empty map with no prototype, for names from outside. */
export function ownMap<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}
