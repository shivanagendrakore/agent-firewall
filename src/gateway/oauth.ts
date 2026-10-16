/**
 * The gateway as an OAuth client of upstream authorization servers
 * (OAuth and audience rules; MCP 2026-07-28
 * basic/authorization):
 *
 * - the upstream's protected resource metadata (RFC 9728) is read from its
 *   401 `WWW-Authenticate: Bearer resource_metadata="…"` or the well-known
 *   path, and its `resource` must equal the canonical upstream URI;
 * - the authorization server's metadata (RFC 8414, then OpenID discovery)
 *   gives the issuer, which is recorded;
 * - registration: dynamic client registration when offered (deprecated in
 *   2026-07-28 but still the common case), else a client id the person
 *   pastes. Client ID Metadata Documents need a document at a LaunchSafe URL
 *   (not set up yet), so they are not offered yet;
 * - PKCE S256, `resource` = the canonical upstream URI in both the
 *   authorization and the token request (RFC 8707), a loopback redirect
 *   (RFC 8252), a single-use `state`, and an exact-match check of `iss`
 *   (RFC 9207): a missing `iss` is rejected when the metadata advertises it;
 * - tokens are stored keyed by (issuer, resource) and sent only to the origin
 *   of that resource (the never-transit rule lives in http.ts).
 *
 * Network calls go through an injectable fetch (tests use servers on
 * 127.0.0.1); nothing here runs during a decision.
 */

import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { join } from "node:path";
import { atomicWrite, ensureDir, readText, withLock } from "../runtime/fsutil.js";
import type { Layout } from "../runtime/layout.js";
import { appendBounded as appendLog } from "../runtime/logbound.js";
import { gatewayDir, readGatewayInstall } from "./install.js";
import type { BackendFactory } from "../runtime/vault/backends.js";
import type { BackendId } from "../runtime/vault/index.js";

type Json = Record<string, unknown>;
export type Fetch = typeof fetch;

export const RULE_AUTH = "FW-MCP-AUTH";

/** The canonical form of a resource URI: lower-case scheme and host, no fragment, no trailing slash on the path. */
export function canonicalResource(u: string): string {
  const url = new URL(u);
  url.hash = "";
  let s = `${url.protocol}//${url.host.toLowerCase()}${url.pathname}${url.search}`;
  if (s.endsWith("/") && url.pathname !== "/") s = s.slice(0, -1);
  if (url.pathname === "/" && url.search === "") s = s.slice(0, -1);
  return s;
}

export function originOf(u: string): string {
  return new URL(u).origin;
}

/** The resource_metadata URL from a WWW-Authenticate header, if any. */
export function resourceMetadataUrl(header: string | null): string | null {
  if (header === null) return null;
  const m = /resource_metadata="([^"]+)"/i.exec(header);
  return m?.[1] ?? null;
}

export interface Discovery {
  resource: string;
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  registrationEndpoint?: string;
  issParameterSupported: boolean;
}

async function getJson(f: Fetch, url: string): Promise<Json | null> {
  const r = await f(url, { headers: { accept: "application/json" }, redirect: "error" });
  if (!r.ok) return null;
  const v = (await r.json()) as unknown;
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : null;
}

/** RFC 9728 then RFC 8414 discovery for an upstream MCP URL. Throws with a plain reason. */
export async function discover(f: Fetch, upstream: string): Promise<Discovery> {
  // GW11: the access token goes to the MCP server itself on every request, so it needs https as much as the
  // authorization server does (plain http only on loopback).
  secureEndpoint("MCP server", upstream);
  const resource = canonicalResource(upstream);
  const probe = await f(upstream, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: "{}", redirect: "manual" });
  let metaUrl = probe.status === 401 ? resourceMetadataUrl(probe.headers.get("www-authenticate")) : null;
  if (metaUrl === null) {
    const u = new URL(upstream);
    metaUrl = `${u.origin}/.well-known/oauth-protected-resource${u.pathname === "/" ? "" : u.pathname}`;
  }
  if (originOf(metaUrl) !== originOf(upstream)) throw new Error(`the protected resource metadata is on another origin (${originOf(metaUrl)})`);
  const prm = await getJson(f, metaUrl);
  if (prm === null) throw new Error("the server publishes no protected resource metadata (RFC 9728)");
  if (typeof prm.resource !== "string" || canonicalResource(prm.resource) !== resource) throw new Error(`the metadata names resource ${String(prm.resource)}, not ${resource}`);
  const servers = Array.isArray(prm.authorization_servers) ? prm.authorization_servers.filter((x): x is string => typeof x === "string") : [];
  const issuer = servers[0];
  if (issuer === undefined) throw new Error("the metadata names no authorization server");
  secureEndpoint("authorization server", issuer);
  const iu = new URL(issuer);
  const suffix = iu.pathname === "/" ? "" : iu.pathname;
  const as = (await getJson(f, `${iu.origin}/.well-known/oauth-authorization-server${suffix}`)) ?? (await getJson(f, `${iu.origin}/.well-known/openid-configuration${suffix}`));
  if (as === null) throw new Error(`no authorization server metadata at ${issuer}`);
  if (as.issuer !== issuer) throw new Error(`the authorization server's metadata names issuer ${String(as.issuer)}, not ${issuer}`);
  if (typeof as.authorization_endpoint !== "string" || typeof as.token_endpoint !== "string") throw new Error("the authorization server metadata lacks its endpoints");
  secureEndpoint("authorization endpoint", as.authorization_endpoint);
  secureEndpoint("token endpoint", as.token_endpoint);
  if (typeof as.registration_endpoint === "string") secureEndpoint("registration endpoint", as.registration_endpoint);
  const methods = Array.isArray(as.code_challenge_methods_supported) ? as.code_challenge_methods_supported : [];
  if (!methods.includes("S256")) throw new Error("the authorization server does not advertise PKCE S256");
  return {
    resource,
    issuer,
    authorizationEndpoint: as.authorization_endpoint,
    tokenEndpoint: as.token_endpoint,
    ...(typeof as.registration_endpoint === "string" ? { registrationEndpoint: as.registration_endpoint } : {}),
    issParameterSupported: as.authorization_response_iss_parameter_supported === true,
  };
}

/**
 * V15: the MCP authorization rules require HTTPS for every authorization server endpoint, and the gateway
 * requires it of the MCP server a token is for (GW11): codes, PKCE verifiers and tokens never travel in
 * clear text. Plain http is accepted only on this machine's loopback
 * addresses (a local test or development server).
 */
export function secureEndpoint(what: string, url: string): void {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new Error(`the ${what} ${url.slice(0, 200)} is not a URL`);
  }
  if (u.protocol === "https:") return;
  const loopback = u.hostname === "127.0.0.1" || u.hostname === "localhost" || u.hostname === "[::1]";
  if (u.protocol === "http:" && loopback) return;
  throw new Error(`the ${what} ${url.slice(0, 200)} does not use https; the gateway sends codes and tokens only over https`);
}

export function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

export function authorizationUrl(d: Discovery, clientId: string, redirectUri: string, state: string, challenge: string): string {
  const u = new URL(d.authorizationEndpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", redirectUri);
  u.searchParams.set("state", state);
  u.searchParams.set("code_challenge", challenge);
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("resource", d.resource);
  return u.toString();
}

/**
 * The authorization response's checks: the single-use state, and RFC 9207's issuer: compared by exact
 * string when present, and required when the metadata advertises it. Returns the code, or throws.
 */
export function checkAuthorizationResponse(d: Discovery, params: URLSearchParams, expectedState: string, used: Set<string>): string {
  const state = params.get("state");
  if (state === null || state !== expectedState || used.has(state)) throw new Error("the authorization response's state does not match (or was used already)");
  used.add(state);
  const iss = params.get("iss");
  if (iss === null && d.issParameterSupported) throw new Error("the authorization response has no iss although the authorization server advertises it (RFC 9207)");
  if (iss !== null && iss !== d.issuer) throw new Error(`the authorization response comes from issuer ${iss}, not ${d.issuer} (RFC 9207)`);
  const err = params.get("error");
  if (err !== null) throw new Error(`the authorization server refused: ${err}`);
  const code = params.get("code");
  if (code === null || code === "") throw new Error("the authorization response has no code");
  return code;
}

export interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
}

function tokenSetOf(v: Json): TokenSet {
  if (typeof v.access_token !== "string") throw new Error("the token response has no access_token");
  return { accessToken: v.access_token, ...(typeof v.refresh_token === "string" ? { refreshToken: v.refresh_token } : {}), ...(typeof v.expires_in === "number" ? { expiresAt: Date.now() + v.expires_in * 1000 } : {}) };
}

/** The token request: code, PKCE verifier and `resource` (RFC 8707). */
export async function exchangeCode(f: Fetch, d: Discovery, clientId: string, code: string, redirectUri: string, verifier: string): Promise<TokenSet> {
  secureEndpoint("token endpoint", d.tokenEndpoint);
  const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier, resource: d.resource });
  const r = await f(d.tokenEndpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body: body.toString(), redirect: "error" });
  if (!r.ok) throw new Error(`the token request failed (HTTP ${r.status})`);
  return tokenSetOf((await r.json()) as Json);
}

export async function refreshTokens(f: Fetch, d: Pick<Discovery, "tokenEndpoint" | "resource">, clientId: string, refreshToken: string): Promise<TokenSet> {
  secureEndpoint("token endpoint", d.tokenEndpoint);
  const body = new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId, resource: d.resource });
  const r = await f(d.tokenEndpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body: body.toString(), redirect: "error" });
  if (!r.ok) throw new Error(`the refresh failed (HTTP ${r.status})`);
  const t = tokenSetOf((await r.json()) as Json);
  return t.refreshToken !== undefined ? t : { ...t, refreshToken };
}

/** Dynamic client registration (RFC 7591) with application_type "native" (SEP-837). */
export async function registerClient(f: Fetch, d: Discovery, redirectUri: string): Promise<string> {
  if (d.registrationEndpoint === undefined) throw new Error("the authorization server offers no dynamic registration");
  secureEndpoint("registration endpoint", d.registrationEndpoint);
  const r = await f(d.registrationEndpoint, { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify({ client_name: "LaunchSafe Firewall MCP gateway", redirect_uris: [redirectUri], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none", application_type: "native" }), redirect: "error" });
  if (!r.ok) throw new Error(`registration failed (HTTP ${r.status})`);
  const v = (await r.json()) as Json;
  if (typeof v.client_id !== "string") throw new Error("registration returned no client_id");
  return v.client_id;
}

// --- token storage: keyed by (issuer, resource) -----------------------------------------------------

/**
 * Where upstream tokens live: in the vault (kind oauth, `vault://mcp/<server>`, oauth-vault.ts) when
 * `mcp login` could sign the entry (an approval key, a keychain or Secret Service); otherwise, as before,
 * in `gateway/tokens/` inside the protected data directory (mode 600; FW-TAMPER for an agent). Either way
 * never in a client's configuration and never where the agent can read them. The login file keeps what
 * is not secret, and with the vault the entry's name instead of the tokens.
 */
export interface StoredLogin {
  server: string;
  issuer: string;
  resource: string;
  clientId: string;
  tokenEndpoint: string;
  tokens: TokenSet;
}

export type LoginMeta = Omit<StoredLogin, "tokens"> & { tokens?: TokenSet; vault?: string };

function tokenFile(l: Layout, server: string): string {
  return join(gatewayDir(l), "tokens", `${createHash("sha256").update(server).digest("hex").slice(0, 32)}.json`);
}

export function saveLogin(l: Layout, s: StoredLogin): void {
  const p = tokenFile(l, s.server);
  ensureDir(join(gatewayDir(l), "tokens"));
  withLock(`${p}.lock`, () => atomicWrite(p, `${JSON.stringify(s)}\n`, 0o600));
}

/** The login's file without tokens: they are in the vault entry it names. */
export function saveLoginMeta(l: Layout, s: Omit<StoredLogin, "tokens"> & { vault: string }): void {
  const p = tokenFile(l, s.server);
  ensureDir(join(gatewayDir(l), "tokens"));
  const { server, issuer, resource, clientId, tokenEndpoint, vault } = s;
  withLock(`${p}.lock`, () => atomicWrite(p, `${JSON.stringify({ server, issuer, resource, clientId, tokenEndpoint, vault })}\n`, 0o600));
}

/** The login for a server and resource, with its tokens (file store) or the vault entry that holds them. */
export function loadLoginMeta(l: Layout, server: string, resource: string): LoginMeta | null {
  const t = readText(tokenFile(l, server));
  if (t === null) return null;
  try {
    const v = JSON.parse(t) as LoginMeta;
    if (v.server !== server || v.resource !== resource) return null;
    if (typeof v.vault === "string") return v;
    return typeof v.tokens?.accessToken === "string" ? v : null;
  } catch {
    return null;
  }
}

/** The stored login for a server and resource; never one issued for another resource. */
export function loadLogin(l: Layout, server: string, resource: string): StoredLogin | null {
  const t = readText(tokenFile(l, server));
  if (t === null) return null;
  try {
    const v = JSON.parse(t) as StoredLogin;
    return v.server === server && v.resource === resource && typeof v.tokens?.accessToken === "string" ? v : null;
  } catch {
    return null;
  }
}

// --- the person's command ---------------------------------------------------------------------------

export interface LoginIO {
  out: (s: string) => void;
  err: (s: string) => void;
  readSecret: (p: string) => Promise<string>;
  ask: (p: string) => Promise<string>;
  env: NodeJS.ProcessEnv;
  fetch?: Fetch;
  /** Tests: the browser step (receives the authorization URL, must hit the redirect). */
  openUrl?: (url: string) => Promise<void> | void;
  /** Where the tokens go (tests pass an in-memory store and a platform; null keeps them in the file store). */
  vault?: { openBackend?: BackendFactory; available?: (id: BackendId) => { ok: boolean; reason?: string }; platform?: NodeJS.Platform } | null;
  timeoutMs?: number;
}

/** `mcp login <server>`: discovery, registration, PKCE with a loopback redirect, token exchange, storage. */
export async function loginInteractive(l: Layout, server: string, io: LoginIO): Promise<number> {
  const f = io.fetch ?? fetch;
  let entry;
  try {
    entry = readGatewayInstall(l).entries.find((e) => e.server === server && e.upstream.kind === "http");
  } catch (e) {
    io.err(`gateway/install.json is unreadable: ${(e as Error).message}`);
    return 1;
  }
  if (entry === undefined || entry.upstream.kind !== "http") {
    io.err(`launchsafe-firewall mcp login: no wrapped HTTP server called ${server}. Wrap it first with mcp wrap-config.`);
    return 64;
  }
  const upstream = entry.upstream.url;
  try {
    const d = await discover(f, upstream);
    io.out(`${server}: resource ${d.resource}, authorization server ${d.issuer}.`);
    const used = new Set<string>();
    const state = randomBytes(16).toString("base64url");
    const { verifier, challenge } = pkce();
    const srv = createServer();
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as { port: number }).port;
    const redirectUri = `http://127.0.0.1:${port}/callback`;
    try {
      let clientId: string;
      if (d.registrationEndpoint !== undefined) clientId = await registerClient(f, d, redirectUri);
      else {
        clientId = (await io.ask("This authorization server offers no automatic registration. Paste the client id registered for the gateway: ")).trim();
        if (clientId === "") throw new Error("no client id");
      }
      const code = await new Promise<string>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("timed out waiting for the browser")), io.timeoutMs ?? 300_000);
        srv.on("request", (req, res) => {
          const u = new URL(req.url ?? "/", redirectUri);
          if (u.pathname !== "/callback") {
            res.writeHead(404).end();
            return;
          }
          // A request without this login's state is not the authorization server's answer to it (another local
          // process, a stale browser tab): refused, and the login goes on waiting for the real one.
          if (u.searchParams.get("state") !== state) {
            res.writeHead(400, { "content-type": "text/plain" }).end("LaunchSafe Firewall: this is not the answer to the sign-in in progress; it was ignored.");
            return;
          }
          try {
            const c = checkAuthorizationResponse(d, u.searchParams, state, used);
            res.writeHead(200, { "content-type": "text/plain" }).end("LaunchSafe Firewall: signed in. You can close this window.");
            clearTimeout(timer);
            resolve(c);
          } catch (e) {
            res.writeHead(400, { "content-type": "text/plain" }).end(`LaunchSafe Firewall refused this sign-in: ${(e as Error).message}`);
            clearTimeout(timer);
            reject(e as Error);
          }
        });
        const url = authorizationUrl(d, clientId, redirectUri, state, challenge);
        io.out(`Open this address in your browser to sign in:\n\n  ${url}\n`);
        void io.openUrl?.(url);
      });
      const tokens = await exchangeCode(f, d, clientId, code, redirectUri, verifier);
      const login: StoredLogin = { server, issuer: d.issuer, resource: d.resource, clientId, tokenEndpoint: d.tokenEndpoint, tokens };
      const inVault = await saveInVault(l, login, io);
      if (inVault === null) saveLogin(l, login);
      appendLog(l, { type: "gateway_auth", event: "login", server, issuer: d.issuer, resource: d.resource, store: inVault === null ? "file" : "vault" });
      io.out(`Signed in. The gateway sends this token only to ${originOf(d.resource)}${inVault !== null ? `; it is kept in the vault as vault://${inVault}` : ""}.`);
      return 0;
    } finally {
      srv.close();
    }
  } catch (e) {
    appendLog(l, { type: "gateway_auth", event: "login_failed", server, reason: (e as Error).message.slice(0, 300), rule: RULE_AUTH });
    io.err(`launchsafe-firewall mcp login ${server}: ${(e as Error).message}`);
    return 1;
  }
}

/**
 * Stores the login's tokens in the vault when it can (an approval key, a store the gateway can read
 * unattended, the passphrase); returns the entry's name, or null to keep them in the file store, saying why.
 */
async function saveInVault(l: Layout, login: StoredLogin, io: LoginIO): Promise<string | null> {
  if (io.vault === null) return null;
  const { approverPublicKey, unlockApprover } = await import("../runtime/approver.js");
  const { chooseBackend } = await import("../runtime/vault/store.js");
  const { openBackend, backendAvailable } = await import("../runtime/vault/backends.js");
  const { vaultPolicy } = await import("../policy-vault.js");
  const { loadPolicy } = await import("../runtime/config.js");
  const { storeLoginInVault, oauthVaultName } = await import("./oauth-vault.js");
  const pol = vaultPolicy(loadPolicy(l, []).config);
  const keep = (why: string): null => {
    io.out(`The token is kept in the gateway's own token file (${why}).`);
    return null;
  };
  if (!pol.enabled) return keep("the vault is switched off");
  if (oauthVaultName(login.server) === null) return keep(`the server name ${login.server} cannot be a vault name`);
  let pub: string | null = null;
  try {
    pub = approverPublicKey(l);
  } catch {
    pub = null;
  }
  if (pub === null) return keep('no approval passphrase is set; "launchsafe-firewall approver init" lets the vault hold it');
  const platform = io.vault?.platform ?? process.platform;
  const chosen = chooseBackend(platform, pol, io.vault?.available ?? ((id) => backendAvailable(id, { platform, env: io.env })));
  if (chosen.id === null) return keep(chosen.reason);
  if (chosen.id === "file") return keep("the encrypted file store needs your passphrase on every read, which the gateway does not have");
  const passphrase = await io.readSecret("Approval passphrase (signs the token's vault entry): ");
  try {
    const priv = unlockApprover(l, passphrase);
    const backend = (io.vault?.openBackend ?? openBackend)(chosen.id, l, { passphrase, platform, env: io.env });
    const name = storeLoginInVault(l, priv, login.server, login.tokens, backend, pol.confirmDefault.oauth);
    saveLoginMeta(l, { server: login.server, issuer: login.issuer, resource: login.resource, clientId: login.clientId, tokenEndpoint: login.tokenEndpoint, vault: name });
    return name;
  } catch (e) {
    io.err(`Could not store the token in the vault: ${(e as Error).message}`);
    return keep("the vault could not take it");
  }
}
