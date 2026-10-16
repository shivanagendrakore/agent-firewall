/**
 * Credentials: recognize them by shape, remember the ones a session has seen
 * (as hashes, never the values), and find them again in outgoing data, also
 * when they are base64, hex or URL encoded.
 *
 * Token shapes, credential names and the placeholder test are adapted from
 * LaunchSafe's agent-safety signals (Apache-2.0, same owner).
 */

import { base64Decode, hexToLatin1, sha256Hex, utf8Decode } from "./bytes.js";
import { hostMatches } from "./network.js";

export interface SecretShape {
  re: RegExp;
  name: string;
  /** Hosts this credential is meant to be sent to. Sending it there is normal; anywhere else is a leak. */
  issuers: readonly string[];
  /**
   * For a shape whose `re` scans forward to a closing line (a private key's END line): a lookahead capturing
   * that closing text. The shape is searched only up to the end of the last one, since no match of `re` can end
   * after it. Without this a text of many opening lines and no closing one is scanned to its end once per
   * opening line (quadratic), and a bound on the scan would stop a long real block from matching.
   */
  closer?: RegExp;
  /**
   * A match of `re` counts only when this says so (the capture group of `re` read as text, instead of a nested pattern
   * that backtracks). A match it rejects is not consumed: the scan goes on one character after where it started, as it
   * does where `re` fails, so text written in front of a credential cannot take it into a rejected match and hide it.
   */
  check?: (m: RegExpMatchArray) => boolean;
  /**
   * With `check`, for a `re` that takes only the shortest form of its last, unbounded part (a JWT's signature: 8
   * characters): a sticky pattern for the rest of the value, read once from the end of a match the check accepts. Read
   * in `re`, a long last part would be read again for every start the check rejects. It is a plain `*`, which keeps no
   * backtracking entry per character: `{8,}` over a run of a few million characters overflows the regular-expression
   * stack (a RangeError).
   */
  rest?: RegExp;
  /** The hosts this one value is meant for, when its text says (a Supabase key names its project): used in place of `issuers`. */
  issuersFor?: (value: string) => readonly string[];
  /** The part of a match the placeholder test reads, where the rest is not the secret (a database URL's password, not its host). */
  secretPart?: (value: string) => string;
}

/** The project reference a Supabase JWT names in its payload (`ref`), or null. */
function supabaseProjectRef(jwt: string): string | null {
  const payload = jwt.split(".")[1];
  if (payload === undefined) return null;
  try {
    const claims: unknown = JSON.parse(utf8Decode(base64Decode(payload.replace(/-/g, "+").replace(/_/g, "/"))));
    const ref = typeof claims === "object" && claims !== null ? (claims as { ref?: unknown }).ref : undefined;
    return typeof ref === "string" && /^[a-z0-9]{8,40}$/.test(ref) ? ref : null;
  } catch {
    return null;
  }
}

/** The password of a database URL (`scheme://user:password@host`), the text a placeholder test should read. */
function urlPassword(url: string): string {
  const afterScheme = url.slice(url.indexOf("//") + 2);
  const colon = afterScheme.indexOf(":");
  const at = afterScheme.lastIndexOf("@");
  return colon === -1 || at < colon ? url : afterScheme.slice(colon + 1, at);
}

/**
 * Issuer markers for hosts that are not one domain's subtree. amazonaws.com and googleapis.com also serve what a
 * customer owns (a bucket, an API Gateway or Lambda URL, an EC2 name), so a suffix match would count an attacker's
 * `x.execute-api.us-east-1.amazonaws.com` as the issuer; these name only the providers' own API hosts (see issuerMatches).
 */
const AWS_API = "aws-api:";
const GOOGLE_API = "google-api:";

export const SECRET_SHAPES: readonly SecretShape[] = [
  { re: /\bsk-ant-(?:api|admin|oat)\d{2}-[A-Za-z0-9_-]{20,}/g, name: "Anthropic API key", issuers: ["api.anthropic.com"] },
  { re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/g, name: "OpenAI API key", issuers: ["api.openai.com"] },
  { re: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}/g, name: "Stripe live secret key", issuers: ["api.stripe.com"] },
  { re: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g, name: "AWS access key id", issuers: [AWS_API, "aws.amazon.com"] },
  { re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, name: "GitHub token", issuers: ["github.com", "api.github.com", "githubusercontent.com"] },
  { re: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g, name: "GitHub token", issuers: ["github.com", "api.github.com", "githubusercontent.com"] },
  { re: /\bglpat-[A-Za-z0-9_-]{20,}/g, name: "GitLab token", issuers: ["gitlab.com"] },
  { re: /\bxox[abposr]-[A-Za-z0-9-]{20,}/g, name: "Slack token", issuers: ["slack.com"] },
  { re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/g, name: "Slack webhook URL", issuers: ["hooks.slack.com"] },
  { re: /\bAIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_])/g, name: "Google API key", issuers: [GOOGLE_API] },
  { re: /\bya29\.[0-9A-Za-z_-]{20,}/g, name: "Google OAuth token", issuers: [GOOGLE_API] },
  { re: /\bnpm_[A-Za-z0-9]{36}\b/g, name: "npm token", issuers: ["registry.npmjs.org", "npmjs.com"] },
  { re: /\bpypi-AgE[A-Za-z0-9_-]{50,}/g, name: "PyPI token", issuers: ["upload.pypi.org", "pypi.org"] },
  { re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_])/g, name: "SendGrid key", issuers: ["api.sendgrid.com"] },
  { re: /\bhf_[A-Za-z0-9]{34,}\b/g, name: "Hugging Face token", issuers: ["huggingface.co"] },
  { re: /\bdp\.(?:st|ct|sa|scim)\.[A-Za-z0-9_-]{40,}/g, name: "Doppler token", issuers: ["api.doppler.com"] },
  { re: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g, name: "Shopify token", issuers: ["myshopify.com"] },
  { re: /\b(?:r8_[A-Za-z0-9]{37})\b/g, name: "Replicate token", issuers: ["api.replicate.com"] },
  { re: /\bAccountKey=[A-Za-z0-9+/=]{40,}/g, name: "Azure storage key", issuers: ["core.windows.net"] },
  {
    // A JWT whose payload says service_role (at any base64 alignment): Supabase's key that bypasses row-level security.
    // The header and the payload are bounded, and the payload is searched for the marker as text, because "eyJ" can
    // start inside any run of base64url characters (a "-" is a word boundary) and each start would otherwise scan
    // the rest of the run: quadratic. A JOSE header is a few dozen characters (Supabase's is 36; 2,048 holds one
    // that carries a key set); a JWT travels in an HTTP header, which servers cap at 8 KB, so 8,192 holds the
    // largest payload one can carry. The same bounds as the agent-safety analyzer's shape (src/vendor). The signature
    // has no bound (RS256 is 342 characters, RSA-8192 1,366): `re` takes its first 8 characters and `rest` the others,
    // once, for a key that counts. A JWT whose payload has no marker is not consumed (SecretShape.check), so one
    // written just in front of a key, which reads the key's header as its payload, does not hide the key; each start
    // tried and rejected reads only a bounded header and payload, as a start that fails does.
    re: /\beyJ[A-Za-z0-9_-]{8,2048}\.([A-Za-z0-9_-]{1,8192})\.[A-Za-z0-9_-]{8}/g,
    rest: /[A-Za-z0-9_-]*/y,
    check: (m) => /c2VydmljZV9yb2xl|NlcnZpY2Vfcm9sZ|zZXJ2aWNlX3JvbGU/.test(m[1] ?? ""),
    name: "Supabase service-role key",
    // The key's own project when its payload names one; any project host otherwise (a project host is a tenant's).
    issuers: ["supabase.co", "supabase.com"],
    issuersFor: (v) => {
      const ref = supabaseProjectRef(v);
      return ref === null ? ["supabase.co", "supabase.com"] : [`=${ref}.supabase.co`, "=api.supabase.com"];
    },
  },
  {
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]{20,}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g,
    closer: /(?=(-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----))/g,
    name: "private key",
    issuers: [],
  },
  { re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g, name: "private key header", issuers: [] },
  { re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/[^:@/\s'"]*:[^@/\s'"]{6,}@[^/\s'"]+/g, name: "database URL with password", issuers: [], secretPart: urlPassword },
  { re: /\bgsk_[A-Za-z0-9]{40,}/g, name: "Groq API key", issuers: ["api.groq.com"] },
  { re: /\bxai-[A-Za-z0-9]{60,}/g, name: "xAI API key", issuers: ["api.x.ai"] },
  { re: /\bpplx-[A-Za-z0-9]{40,}/g, name: "Perplexity API key", issuers: ["api.perplexity.ai"] },
  { re: /\bxapp-\d-[A-Z0-9]{8,}-\d{8,}-[a-f0-9]{32,}/g, name: "Slack app-level token", issuers: ["slack.com"] },
  { re: /\bdo[opr]_v1_[a-f0-9]{64}\b/g, name: "DigitalOcean token", issuers: ["api.digitalocean.com"] },
  // A workspace host is a customer's own, so it cannot be narrowed to one (as for Shopify and Azure above).
  { re: /\bdapi[a-f0-9]{32}(?:-\d)?\b/g, name: "Databricks token", issuers: ["databricks.com", "azuredatabricks.net"] },
  { re: /\bwhsec_[A-Za-z0-9]{32,}/g, name: "Stripe webhook signing secret", issuers: [] },
];

/** Environment-variable names that hold credentials. */
export const CREDENTIAL_NAME = /(?:^|_|-)(?:API_?KEY|ACCESS_?KEY|SECRET(?:_?KEY)?|TOKEN|PASSWORD|PASSWD|PASS|PAT|PRIVATE_?KEY|SERVICE_?ROLE(?:_?KEY)?|CLIENT_?SECRET|AUTH|CREDENTIALS?|SESSION|COOKIE|DSN|CONNECTION_?STRING)(?:$|_|-)/i;
/** The names that say "secret" on their own. */
const STRONG_NAME = /(?:^|_|-)(?:API_?KEY|ACCESS_?KEY|SECRET(?:_?KEY)?|TOKEN|PASSWORD|PASSWD|PRIVATE_?KEY|SERVICE_?ROLE(?:_?KEY)?|CLIENT_?SECRET|CREDENTIALS?|DSN|CONNECTION_?STRING)(?:$|_|-)/i;
/** Words that are also ordinary settings (Django's AUTH_USER_MODEL, a SESSION_ENGINE): a secret only when the value looks like one. */
const WEAK_NAME = /(?:^|_|-)(?:PASS|PAT|AUTH|SESSION|COOKIE)(?:$|_|-)/i;

/** A value that reads as a secret and not as a setting: 16 or more characters, no dots, at least two kinds of character. */
function looksSecret(value: string): boolean {
  if (value.length < 16 || value.includes(".")) return false;
  const kinds = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(value)).length;
  return kinds >= 2;
}

/** Credential names that are always secrets, whatever the value looks like. */
export const PRODUCTION_NAME = /^(?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|DATABASE_URL|POSTGRES_URL|SUPABASE_DB_URL|MONGODB_URI|REDIS_URL|GOOGLE_APPLICATION_CREDENTIALS_JSON|AZURE_CLIENT_SECRET|STRIPE_SECRET_KEY|SUPABASE_SERVICE_ROLE_KEY)$/i;

/** Issuer hosts for well-known credential variables, so `curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com` is normal. */
const VARIABLE_ISSUERS: readonly { re: RegExp; hosts: readonly string[] }[] = [
  { re: /^(?:GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|GH_ENTERPRISE_TOKEN)$/, hosts: ["github.com", "api.github.com"] },
  { re: /^GITLAB_/, hosts: ["gitlab.com"] },
  { re: /^OPENAI_/, hosts: ["api.openai.com"] },
  { re: /^ANTHROPIC_/, hosts: ["api.anthropic.com"] },
  { re: /^STRIPE_/, hosts: ["api.stripe.com"] },
  { re: /^AWS_/, hosts: [AWS_API] },
  { re: /^NPM_/, hosts: ["registry.npmjs.org"] },
  { re: /^SLACK_/, hosts: ["slack.com"] },
  { re: /^SUPABASE_/, hosts: ["supabase.co", "supabase.com"] },
  { re: /^VERCEL_/, hosts: ["vercel.com", "api.vercel.com"] },
  { re: /^CLOUDFLARE_/, hosts: ["api.cloudflare.com"] },
  { re: /^SENTRY_/, hosts: ["sentry.io"] },
  { re: /^LINEAR_/, hosts: ["api.linear.app"] },
  { re: /^HF_|^HUGGING_?FACE_/, hosts: ["huggingface.co"] },
];

export function variableIssuers(name: string): readonly string[] {
  for (const v of VARIABLE_ISSUERS) if (v.re.test(name)) return v.hosts;
  return [];
}

/**
 * Whether a variable or key name holds a credential. camelCase names count (accessToken, openaiApiKey). With a
 * `value` (an assignment read from text), a bare AUTH, SESSION, COOKIE, PASS or PAT counts only when the value
 * looks like a secret; without one (a variable named in a command) it counts, as it always did.
 */
export function isCredentialVariable(name: string, value?: string): boolean {
  if (PRODUCTION_NAME.test(name)) return true;
  const spelled = name.replace(/([a-z0-9])([A-Z])/g, "$1_$2");
  if (STRONG_NAME.test(spelled)) return true;
  return WEAK_NAME.test(spelled) && (value === undefined || looksSecret(value));
}

/** Credentials that say they are test or mock values (Stripe test keys, sk-test-... fixtures). */
export function isTestSecret(value: string): boolean {
  return /^(?:sk-(?:test|fake|dummy|mock|example)[-_]|(?:sk|rk|pk)_test_)/i.test(value);
}

/** A value that is obviously not a real credential: a reference, a placeholder or an example. */
export function isPlaceholder(value: string): boolean {
  const v = value.trim();
  if (v.length < 8) return true;
  // A reference is short (the agent-safety analyzer's placeholder test bounds it at 200 too): the bound keeps a value
  // full of "${" and no "}" linear, where each "${" would scan to the end.
  if (/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(v) || /\$\{[^}]{1,200}\}/.test(v) || /^\$\(/.test(v)) return true;
  if (/^\{\{.*\}\}$/.test(v) || /^<.*>$/.test(v)) return true;
  if (/^(?:op|vault|secret|keychain|env|ssm|arn):/i.test(v)) return true;
  if (/your[-_]?|example|placeholder|changeme|change[-_]me|replace[-_]?me|redacted|dummy|sample|fake|insert[-_]|xxxx|\*\*\*\*/i.test(v)) return true;
  if (/^(.)\1+$/.test(v)) return true;
  return false;
}

export interface SecretHit {
  name: string;
  value: string;
  issuers: readonly string[];
}

/** `text` up to the end of the last place `closer` (a lookahead capturing the closing text) matches, or "" when it never does. */
function upToLastCloser(text: string, closer: RegExp): string {
  let end = 0;
  closer.lastIndex = 0;
  for (const m of text.matchAll(closer)) end = Math.max(end, (m.index as number) + (m[1] ?? "").length);
  return text.slice(0, end);
}

/**
 * The placeholder test for a match. For a URL shape it reads only the secret part, so a host with "sample" or
 * "fake" in it does not drop a real URL; a password shorter than isPlaceholder's minimum is padded, since that
 * minimum is for whole values (the shape itself takes passwords of 6 and more).
 */
function isPlaceholderPart(shape: SecretShape, v: string): boolean {
  if (shape.secretPart === undefined) return isPlaceholder(v);
  const part = shape.secretPart(v);
  return isPlaceholder(part.length < 8 ? part + "#".repeat(8 - part.length) : part);
}

/** Every credential-shaped string in a text. */
export function findSecrets(text: string): SecretHit[] {
  const out: SecretHit[] = [];
  const seen = new Set<string>();
  for (const shape of SECRET_SHAPES) {
    const scope = shape.closer === undefined ? text : upToLastCloser(text, shape.closer);
    const re = shape.re;
    re.lastIndex = 0;
    for (let m = re.exec(scope); m !== null; m = re.exec(scope)) {
      if (shape.check !== undefined && !shape.check(m)) {
        re.lastIndex = m.index + 1;
        continue;
      }
      let v = m[0];
      if (shape.rest !== undefined) {
        shape.rest.lastIndex = re.lastIndex;
        v += shape.rest.exec(scope)?.[0] ?? "";
        re.lastIndex = m.index + v.length;
      }
      if (seen.has(v) || isPlaceholderPart(shape, v)) continue;
      seen.add(v);
      out.push({ name: shape.name, value: v, issuers: shape.issuersFor?.(v) ?? shape.issuers });
    }
  }
  return out;
}

/**
 * Values assigned to credential-named keys in a text: `KEY=value`, `KEY: value`,
 * `"key": "value"`. This is how a .env file or a config dump looks.
 */
export function credentialAssignments(text: string): string[] {
  const out: string[] = [];
  const re = /(?:^|[\s,{;])["']?([A-Za-z_][A-Za-z0-9_.-]{1,80})["']?\s*[:=]\s*["']?([^\s"',;}]{8,512})/gm;
  for (const m of text.matchAll(re)) {
    const name = m[1] ?? "";
    const value = (m[2] ?? "").replace(/["']$/, "");
    if (!isCredentialVariable(name.replace(/[.-]/g, "_"), value)) continue;
    if (isPlaceholder(value) || /^(?:true|false|null|undefined|none)$/i.test(value)) continue;
    if (/^(?:https?:)?\/\//i.test(value) && !/:\/\/[^/@\s]+:[^/@\s]+@/.test(value)) continue;
    out.push(value);
  }
  return out;
}

// --- fingerprints ------------------------------------------------------------------------------------
// A fingerprint is "length:rollingHashA:rollingHashB:sha256-prefix". The rolling hashes let us scan any
// text for the secret at every offset in linear time; the SHA-256 prefix confirms a match. The secret
// itself is never stored.

const P = 2147483647; // 2^31 - 1
const BASE_A = 257;
const BASE_B = 131;

function mulmod(a: number, b: number): number {
  // a < 2^31, b < 2^31: split b to stay inside 2^53.
  const hi = Math.floor(b / 65536);
  const lo = b % 65536;
  return (((a * hi) % P) * 65536 + a * lo) % P;
}

function rolling(s: string, base: number): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (mulmod(h, base) + s.charCodeAt(i)) % P;
  return h;
}

function sha(s: string): string {
  return sha256Hex(s).slice(0, 24);
}

export const MIN_FINGERPRINT_LENGTH = 12;

export function fingerprint(secret: string): string | null {
  if (secret.length < MIN_FINGERPRINT_LENGTH || secret.length > 4096) return null;
  return `${secret.length}:${rolling(secret, BASE_A)}:${rolling(secret, BASE_B)}:${sha(secret)}`;
}

interface ParsedPrint {
  len: number;
  a: number;
  b: number;
  sha: string;
}

function parsePrint(fp: string): ParsedPrint | null {
  const m = /^(\d+):(\d+):(\d+):([0-9a-f]{24})$/.exec(fp);
  if (m === null) return null;
  return { len: Number(m[1]), a: Number(m[2]), b: Number(m[3]), sha: m[4] as string };
}

function powmod(base: number, exp: number): number {
  let r = 1;
  for (let i = 0; i < exp; i++) r = mulmod(r, base);
  return r;
}

/** Whether any fingerprinted secret occurs anywhere in the text. Linear in the text per distinct secret length. */
function scanRolling(text: string, byLen: Map<number, ParsedPrint[]>): boolean {
  for (const [len, prints] of byLen) {
    if (text.length < len) continue;
    const powA = powmod(BASE_A, len - 1);
    const powB = powmod(BASE_B, len - 1);
    let ha = rolling(text.slice(0, len), BASE_A);
    let hb = rolling(text.slice(0, len), BASE_B);
    for (let i = 0; ; i++) {
      for (const p of prints) {
        if (p.a === ha && p.b === hb && sha(text.slice(i, i + len)) === p.sha) return true;
      }
      if (i + len >= text.length) break;
      const out = text.charCodeAt(i);
      const inc = text.charCodeAt(i + len);
      ha = (mulmod((ha - mulmod(out, powA) + P) % P, BASE_A) + inc) % P;
      hb = (mulmod((hb - mulmod(out, powB) + P) % P, BASE_B) + inc) % P;
    }
  }
  return false;
}

/**
 * Where fingerprinted secrets occur in the clear in a text: [start, end) spans with the fingerprint that
 * matched, left to right, without overlaps. The vault's output scrub replaces them with the reference.
 */
export function fingerprintSpans(text: string, fingerprints: Iterable<string>): { start: number; end: number; fp: string }[] {
  const byLen = new Map<number, (ParsedPrint & { fp: string })[]>();
  for (const fp of fingerprints) {
    const p = parsePrint(fp);
    if (p === null) continue;
    const list = byLen.get(p.len) ?? [];
    list.push({ ...p, fp });
    byLen.set(p.len, list);
  }
  const spans: { start: number; end: number; fp: string }[] = [];
  for (const [len, prints] of byLen) {
    if (text.length < len) continue;
    const powA = powmod(BASE_A, len - 1);
    const powB = powmod(BASE_B, len - 1);
    let ha = rolling(text.slice(0, len), BASE_A);
    let hb = rolling(text.slice(0, len), BASE_B);
    for (let i = 0; ; i++) {
      for (const p of prints) {
        if (p.a === ha && p.b === hb && sha(text.slice(i, i + len)) === p.sha) spans.push({ start: i, end: i + len, fp: p.fp });
      }
      if (i + len >= text.length) break;
      const out = text.charCodeAt(i);
      const inc = text.charCodeAt(i + len);
      ha = (mulmod((ha - mulmod(out, powA) + P) % P, BASE_A) + inc) % P;
      hb = (mulmod((hb - mulmod(out, powB) + P) % P, BASE_B) + inc) % P;
    }
  }
  spans.sort((a, b) => a.start - b.start || b.end - a.end);
  const kept: typeof spans = [];
  for (const sp of spans) if (kept.length === 0 || sp.start >= (kept[kept.length - 1] as { end: number }).end) kept.push(sp);
  return kept;
}

/** The text, plus the decodings an exfiltrating agent would use. */
export function decodedVariants(text: string): string[] {
  const out = new Set<string>([text]);
  const add = (s: string | null): void => {
    if (s !== null && s.length >= MIN_FINGERPRINT_LENGTH) out.add(s);
  };
  // URL encoding (twice, for double-encoding). Each run of %XX escapes is decoded on its own: one malformed escape
  // elsewhere in the text must not keep the rest from being decoded.
  if (text.includes("%") || text.includes("+")) {
    const decodeRuns = (t: string): string =>
      t.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
        try {
          return decodeURIComponent(run);
        } catch {
          return run;
        }
      });
    const once = decodeRuns(text.replace(/\+/g, " "));
    add(once);
    add(decodeRuns(once));
  }
  const sample = text.length > 1_000_000 ? text.slice(0, 1_000_000) : text;
  // A run that starts mid-token is decoded from other starts too: the encoded value may begin at any alignment
  // (offsets 0-3 of a base64 run) or after a separator (a prefix, a path segment). The extra reads share one bound.
  let extra = 8_000_000;
  const tries = (run: string, pieces: boolean): void => {
    const starts = [0, 1, 2, 3];
    if (pieces) {
      let seps = 0;
      for (let i = 4; i < run.length && seps < 16; i++) {
        const c = run.charCodeAt(i - 1);
        if (c === 47 || c === 45 || c === 95) {
          starts.push(i);
          seps++;
        }
      }
    }
    for (const at of starts) {
      const piece = run.slice(at);
      if (piece.length < 16) break;
      if (at > 0 && (extra -= piece.length) < 0) return;
      add(tryBase64(piece));
    }
  };
  // Base64 / base64url runs.
  for (const m of sample.matchAll(/[A-Za-z0-9+/_-]{16,}={0,2}/g)) tries(m[0], true);
  // Base32 runs (RFC 4648), in either case.
  for (const m of sample.matchAll(/[A-Za-z2-7]{16,}={0,6}/g)) add(tryBase32(m[0]));
  // Hex runs.
  for (const m of sample.matchAll(/[0-9a-fA-F]{16,}/g)) {
    add(hexToLatin1(m[0]));
    // An odd character in front (a prefix that happens to be a hex digit) shifts every pair.
    if ((extra -= m[0].length) >= 0) add(hexToLatin1(m[0].slice(1)));
  }
  // Every DNS label joined: secrets split across labels (abc.def.attacker.com). FZ16: a match starts only where a
  // run of label characters starts; tried from inside a long run without dots, the pattern backtracked over the
  // rest of the run at every position (quadratic: seconds for 100 KB, minutes for the sidecar's 1 MiB). A match
  // that starts inside a run also starts at the run's start, so the matches are the same.
  const dotted = sample.match(/(?<![A-Za-z0-9_-])(?:[A-Za-z0-9_-]+\.){2,}[A-Za-z0-9_-]+/g);
  if (dotted !== null) for (const d of dotted) add(d.replace(/\./g, ""));
  return [...out];
}

function tryBase32(s: string): string | null {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const t = s.toUpperCase().replace(/=+$/, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of t) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (out.length < 8) return null;
  const txt = utf8Decode(Uint8Array.from(out));
  const printable = txt.replace(/[^\x20-\x7e]/g, "").length;
  return printable / txt.length > 0.9 ? txt : null;
}

function tryBase64(s: string): string | null {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  try {
    const buf = base64Decode(norm);
    if (buf.length < 8) return null;
    const txt = utf8Decode(buf);
    // Mostly printable: a decoded secret, not random bytes.
    const printable = txt.replace(/[^\x20-\x7e]/g, "").length;
    return printable / txt.length > 0.9 ? txt : null;
  } catch {
    return null;
  }
}

/** Whether the text contains a secret this session has seen, in the clear or encoded. */
export function containsFingerprint(text: string, fingerprints: Iterable<string>): boolean {
  const byLen = new Map<number, ParsedPrint[]>();
  for (const fp of fingerprints) {
    const p = parsePrint(fp);
    if (p === null) continue;
    const list = byLen.get(p.len) ?? [];
    list.push(p);
    byLen.set(p.len, list);
  }
  if (byLen.size === 0) return false;
  return decodedVariants(text).some((v) => scanRolling(v, byLen));
}

/** Masks every credential in a text, keeping four characters so a person can tell which one it was. */
export function redactSecrets(text: string, extraValues: readonly string[] = []): { text: string; count: number } {
  let count = 0;
  let out = text;
  const values = [...findSecrets(text).map((h) => h.value), ...extraValues].sort((a, b) => b.length - a.length);
  for (const v of values) {
    if (v.length < 8 || !out.includes(v)) continue;
    count++;
    out = out.split(v).join(`${v.slice(0, 4)}…[redacted by LaunchSafe Firewall]`);
  }
  return { text: out, count };
}

/** Whether every credential in the payload is going to the host that issued it. */
export function allGoingToIssuer(hits: readonly SecretHit[], host: string | undefined): boolean {
  if (host === undefined || hits.length === 0) return false;
  return hits.every((h) => h.issuers.some((i) => issuerMatches(host, i)));
}

const REGION = /^[a-z]{2}(?:-[a-z]+)+-\d$/;

/**
 * Whether a host is the issuer a pattern names: `hostMatches`, except for the two provider-wide markers. An AWS API
 * host is `service.amazonaws.com` or `service.region.amazonaws.com` (no customer-chosen label: not a bucket, API
 * Gateway, load balancer or EC2 name). A Google API host is a single label under googleapis.com.
 */
export function issuerMatches(host: string, issuer: string): boolean {
  if (issuer === AWS_API) {
    const labels = host.toLowerCase().replace(/\.$/, "").split(".");
    const n = labels.length;
    if (labels[n - 1] !== "com" || labels[n - 2] !== "amazonaws") return false;
    return n === 3 || (n === 4 && REGION.test(labels[1] as string));
  }
  if (issuer === GOOGLE_API) {
    const labels = host.toLowerCase().replace(/\.$/, "").split(".");
    return labels.length === 3 && labels[1] === "googleapis" && labels[2] === "com";
  }
  return hostMatches(host, issuer);
}
