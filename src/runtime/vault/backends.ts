/**
 * Opens a vault backend by id. The CLI passes the approval passphrase the
 * person typed for the command (the file store needs it); tests inject their
 * own factory instead and never reach this one's real stores.
 */

import type { Layout } from "../layout.js";
import type { Runner, VaultBackend } from "./backend.js";
import { fileBackend } from "./file.js";
import type { BackendId } from "./index.js";
import { keychainBackend } from "./keychain.js";
import { libsecretBackend } from "./libsecret.js";

export interface OpenOptions {
  passphrase: string;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  runner?: Runner;
}

export type BackendFactory = (id: BackendId, l: Layout, o: OpenOptions) => VaultBackend;

export const openBackend: BackendFactory = (id, l, o) => {
  const common = { ...(o.runner !== undefined ? { runner: o.runner } : {}), ...(o.platform !== undefined ? { platform: o.platform } : {}) };
  if (id === "keychain") return keychainBackend(common);
  if (id === "libsecret") return libsecretBackend({ ...common, ...(o.env !== undefined ? { env: o.env } : {}) });
  return fileBackend(l, o.passphrase);
};

/** Whether a backend can be used here, without a passphrase (the file store always can). */
export function backendAvailable(id: BackendId, o: { platform?: NodeJS.Platform; env?: NodeJS.ProcessEnv } = {}): { ok: boolean; reason?: string } {
  if (id === "keychain") return keychainBackend(o).available();
  if (id === "libsecret") return libsecretBackend(o).available();
  return { ok: true };
}
