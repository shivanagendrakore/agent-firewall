/**
 * Action classes (design 5.2): which normalized actions are sensitive.
 *
 * Site adapters (precise, for the top sites) are consulted first; generic
 * heuristics cover everything else. Unknown is not risky by default here (the
 * web has too many buttons); the leak guard covers data leaving through
 * unclassified forms. Inputs are what the content script measured; nothing
 * here touches the DOM.
 */
import { hostMatches } from "../vendor/firewall/engine/network.js";
import { hostOf } from "./domain.js";
import type { ActionClass, Classification, ControlContext, FieldInfo, NormalizedAction } from "./types.js";

/**
 * A site adapter: precise classification for one site. The gate lane
 * registers adapters (Gmail, Outlook web, Google Account, GitHub, Microsoft
 * consent, Stripe Checkout, Shopify checkout, Amazon checkout). An adapter
 * returns null when the action is not one it knows, and the heuristics run.
 */
export interface SiteAdapter {
  id: string;
  /** Host patterns (network.hostMatches syntax) of the top-level page or frame the adapter covers. */
  hosts: readonly string[];
  classify(action: NormalizedAction): { actionClass: ActionClass; signal: string } | null;
}

/**
 * Executable and installer downloads (design 5.2, download_exec). Office macro formats included. Archives (.zip,
 * .7z, .rar, .tar.gz and the like) are not on the list: they are everyday files, and what is inside is only
 * written when the person (or an OS-level agent) extracts it, which the extension cannot see. An executable
 * inside an archive is a residual (threat model 4, row 14).
 */
export const EXECUTABLE_EXTENSIONS: readonly string[] = [
  // Windows programs, installers, scripts and shortcuts.
  "exe", "msi", "msix", "msixbundle", "appx", "appxbundle", "msp", "mst", "com", "scr", "pif", "cpl", "dll", "sys", "ocx", "bat", "cmd", "ps1", "psm1", "psd1", "ps1xml", "psc1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ws", "hta", "msc", "reg", "inf", "lnk", "url", "scf", "chm", "hlp", "gadget", "application", "appref-ms", "xbap", "vsix", "library-ms", "settingcontent-ms", "diagcab", "msh", "mshxml",
  // macOS and Linux programs, installers and scripts.
  "dmg", "pkg", "mpkg", "app", "command", "tool", "terminal", "scpt", "applescript", "workflow", "sh", "bash", "zsh", "csh", "run", "bin", "deb", "rpm", "snap", "flatpakref", "appimage",
  // Cross-platform and mobile.
  "jar", "jnlp", "apk", "aab", "xapk", "ipa",
  // Disk images that mount as a drive with programs on it.
  "iso", "img", "vhd", "vhdx",
  // Office documents that carry macros or add-ins.
  "docm", "dotm", "xlsm", "xltm", "xlsb", "xlam", "xll", "pptm", "potm", "ppsm", "ppam", "sldm",
];

const EXECUTABLE_MIME = /^(?:application\/(?:x-msdownload|x-msdos-program|x-ms-installer|x-msi|vnd\.microsoft\.portable-executable|x-apple-diskimage|x-newton-compatible-pkg|vnd\.android\.package-archive|java-archive|x-java-archive|x-sh|x-shellscript|x-executable|x-mach-binary|vnd\.debian\.binary-package|x-rpm|x-redhat-package-manager|vnd\.ms-(?:word|excel|powerpoint)\.[a-z]*macroenabled[.\w]*)|text\/x-shellscript)$/i;

/** Payment provider frame hosts (design 5.2, payment): a submit or activation inside one is a payment. */
export const PAYMENT_FRAME_HOSTS: readonly string[] = [
  "js.stripe.com",
  "checkout.stripe.com",
  "m.stripe.network",
  "adyen.com",
  "adyenpayments.com",
  "braintreegateway.com",
  "braintree-api.com",
  "paypal.com",
  "paypalobjects.com",
  "pay.google.com",
  "squareup.com",
  "squarecdn.com",
  "checkout.com",
  "klarna.com",
  "afterpay.com",
];

/** OAuth consent endpoints of the adapter providers (design 5.2, oauth_consent): host pattern and path. */
const OAUTH_ENDPOINTS: readonly { host: string; path: RegExp }[] = [
  { host: "accounts.google.com", path: /^\/(?:o\/oauth2\/|signin\/oauth\/)/ },
  { host: "login.microsoftonline.com", path: /\/oauth2\/(?:v2\.0\/)?authorize|\/Consent\//i },
  { host: "login.live.com", path: /^\/oauth20_authorize/i },
  { host: "=github.com", path: /^\/login\/oauth\/authorize/ },
  { host: "slack.com", path: /^\/oauth\// },
  { host: "auth.atlassian.com", path: /^\/authorize/ },
  { host: "api.notion.com", path: /^\/v1\/oauth\/authorize/ },
  { host: "notion.so", path: /^\/install-integration/ },
];

const CONSENT_LABEL = /^\s*(?:allow|authori[sz]e|accept|grant|approve|continue|install|zulassen|autoriser|permitir|autorizar)\b/i;
const GENERIC_CONSENT_PATH = /\/oauth2?\/(?:v[\d.]+\/)?(?:authori[sz]e|consent|auth)\b|\/(?:authori[sz]e|consent)(?:\/|$)/i;

const PAYMENT_LABEL = /^\s*(?:place (?:your )?order|pay(?:\s+now)?\b|pay\s+[$€£¥]|buy now|buy\b|complete (?:purchase|order|payment|checkout)|confirm (?:and pay|purchase|order|payment)|submit (?:order|payment)|start (?:subscription|trial)|subscribe|book now|jetzt kaufen|kaufen|zahlungspflichtig bestellen|payer|commander|valider (?:et payer|la commande)|pagar|comprar|finalizar compra)/i;

const SEND_LABEL = /^\s*(?:send|send now|post|reply|reply all|forward|publish|tweet|share|comment|submit post|senden|envoyer|enviar|publicar)\s*$/i;

const ACCOUNT_SECURITY_LABEL =
  /\b(?:change (?:your )?password|update password|reset password|set (?:a )?new password|two[- ]?(?:factor|step)|2fa|2-step|multi[- ]factor|mfa|authenticator app|security key|passkey|recovery (?:email|phone|code|address)|backup codes|forwarding|forward (?:a copy|incoming|mail|to)|create (?:a )?filter|inbox rule|new rule|(?:create|generate|new|add) (?:(?:personal )?(?:access )?(?:api )?(?:key|token|secret)|ssh key|deploy key|app password)|personal access token|sign out (?:of )?all|revoke (?:all )?sessions?|remove device|trusted devices?)\b/i;

const ACCOUNT_SECURITY_PATH = /\/(?:settings\/(?:security|tokens|keys|personal-access-tokens|apps|developers|auth)|security(?:\/|$)|account\/(?:password|security)|signinoptions|two-step-verification|myaccount\/security|ManageMFA|iam\/)|#settings\/(?:fwdandpop|filters)/i;

const DELETE_LABEL =
  /\b(?:delete (?:my |your |this |the )?(?:account|repository|repo|organi[sz]ation|project|workspace|team|bucket|database|site|domain|all)|empty (?:the )?(?:trash|bin)|permanently delete|delete (?:forever|permanently)|close (?:my )?account|deactivate (?:my )?account|destroy|wipe)\b/i;

function fieldsOf(action: NormalizedAction): readonly FieldInfo[] {
  if (action.kind === "submit") return action.form.fields;
  if (action.kind === "activate" || action.kind === "upload" || action.kind === "paste" || action.kind === "type") return action.context.formFields ?? [];
  return [];
}

function hasCardFields(fields: readonly FieldInfo[]): boolean {
  return fields.some((f) => /\bcc-(?:number|csc|exp|exp-month|exp-year|name|type)\b/i.test(f.autocomplete ?? ""));
}

function hasPasswordChange(fields: readonly FieldInfo[]): boolean {
  return fields.some((f) => f.type === "password" && /\bnew-password\b/i.test(f.autocomplete ?? ""));
}

function frameHostOf(action: NormalizedAction): string | null {
  if (action.kind === "navigate" || action.kind === "download") return null;
  return hostOf(action.frame.origin);
}

/**
 * A label as a person reads it: compatibility forms folded (fullwidth letters,
 * no-break and other spaces), format characters dropped (zero-width, bidi
 * marks, soft hyphens), whitespace collapsed. innerText of "Place&nbsp;order"
 * carries U+00A0, and a page can split a word with U+200B; neither may hide a
 * control from the patterns below (BR11).
 */
export function normalizeLabel(raw: string): string {
  return raw
    .normalize("NFKC")
    .replace(/[\p{Cf}\u034f\u115f\u1160\u3164\uffa0]/gu, "")
    .replace(/[\s\p{Z}]+/gu, " ")
    .trim();
}

function labelOf(action: NormalizedAction): string {
  if (action.kind === "activate") return normalizeLabel(action.label);
  if (action.kind === "submit") return normalizeLabel(action.label ?? "");
  return "";
}

function contextOf(action: NormalizedAction): ControlContext | null {
  return action.kind === "navigate" || action.kind === "download" ? null : action.context;
}

function isOauthEndpoint(url: string): boolean {
  try {
    const u = new URL(url);
    return OAUTH_ENDPOINTS.some((e) => hostMatches(u.hostname, e.host) && e.path.test(u.pathname));
  } catch {
    return false;
  }
}

function isGenericConsentUrl(url: string): boolean {
  try {
    return GENERIC_CONSENT_PATH.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

function pathAndHash(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname + u.hash;
  } catch {
    return "";
  }
}

function lastSegment(url: string): string {
  try {
    const raw = new URL(url).pathname.split("/").pop() ?? "";
    try {
      return decodeURIComponent(raw);
    } catch {
      return raw;
    }
  } catch {
    return "";
  }
}

export function isExecutableDownload(filename: string, mime: string): boolean {
  // Windows drops trailing dots and spaces from a file name, so "setup.exe." and "setup.exe " save as setup.exe (BR12).
  const base = (filename.split(/[\\/]/).pop() ?? "").replace(/[\s.\p{Cf}]+$/u, "");
  const ext = /\.([A-Za-z0-9-]+)$/.exec(base)?.[1]?.toLowerCase();
  // A MIME type may carry parameters ("application/x-msdownload; charset=binary").
  const essence = (mime.split(";")[0] ?? "").trim();
  return (ext !== undefined && EXECUTABLE_EXTENSIONS.includes(ext)) || EXECUTABLE_MIME.test(essence);
}

/** A link href that does not leave the page: javascript:, a bare fragment, or this page's URL with a fragment. */
function staysOnPage(href: string, pageUrl: string): boolean {
  const h = href.trim();
  if (h === "" || h.startsWith("#") || /^javascript:/i.test(h)) return true;
  try {
    const u = new URL(h);
    if (u.protocol === "javascript:") return true;
    if (!h.includes("#")) return false;
    const p = new URL(pageUrl);
    u.hash = "";
    p.hash = "";
    return u.href === p.href;
  } catch {
    return false;
  }
}

export function isPaymentFrameHost(host: string, extra: readonly string[] = []): boolean {
  return PAYMENT_FRAME_HOSTS.some((p) => hostMatches(host, p)) || extra.some((p) => hostMatches(host, p));
}

const NONE: Classification = { actionClass: null, source: null, signals: [] };

function heuristic(actionClass: ActionClass, signal: string): Classification {
  return { actionClass, source: "heuristic", signals: [signal] };
}

/** Classifies one action: adapters first (precise), then generic heuristics. */
export function classify(action: NormalizedAction, adapters: readonly SiteAdapter[] = []): Classification {
  const ctx = contextOf(action);
  const pageHost = ctx === null ? null : hostOf(ctx.pageUrl);
  const frameHost = frameHostOf(action);
  for (const a of adapters) {
    const covers = a.hosts.some((p) => (pageHost !== null && hostMatches(pageHost, p)) || (frameHost !== null && hostMatches(frameHost, p)));
    if (!covers) continue;
    const hit = a.classify(action);
    if (hit !== null) return { actionClass: hit.actionClass, source: "adapter", signals: [`adapter:${a.id}:${hit.signal}`] };
  }

  switch (action.kind) {
    case "download":
      return isExecutableDownload(action.filename, action.mime) || isExecutableDownload(lastSegment(action.url), "")
        ? heuristic("download_exec", "executable_download")
        : NONE;
    case "upload":
      return heuristic("upload", "file_input");
    case "navigate":
    case "paste":
    case "type":
      // Data movement, not a sensitive control: the leak guard and the navigation policy judge these.
      return NONE;
    case "submit":
    case "activate":
      break;
  }

  const fields = fieldsOf(action);

  // `activate` on a plain link is a navigation, not a control; only buttons, submits and button-like roles are judged.
  // A link that stays on the page (href="#", "javascript:", a fragment of this page) is a button in disguise, and a link
  // inside a card form or a payment frame is a payment control whatever its href says (BR10).
  if (action.kind === "activate" && action.tag === "a" && action.role !== "button" && action.href !== undefined && !staysOnPage(action.href, ctx?.pageUrl ?? "")) {
    if (hasCardFields(fields)) return heuristic("payment", "card_fields");
    if (frameHost !== null && isPaymentFrameHost(frameHost)) return heuristic("payment", "payment_frame");
    return NONE;
  }

  const label = labelOf(action);
  const page = ctx?.pageUrl ?? "";

  if (isOauthEndpoint(page) && (action.kind === "submit" || CONSENT_LABEL.test(label))) return { actionClass: "oauth_consent", source: "adapter", signals: ["oauth_endpoint"] };
  if (isGenericConsentUrl(page) && CONSENT_LABEL.test(label)) return heuristic("oauth_consent", "consent_path_and_label");

  if (hasPasswordChange(fields)) return heuristic("account_security", "new_password_field");
  if (ACCOUNT_SECURITY_LABEL.test(label)) return heuristic("account_security", "security_label");
  if (ACCOUNT_SECURITY_PATH.test(pathAndHash(page)) && action.kind === "submit") return heuristic("account_security", "security_settings_path");

  if (hasCardFields(fields)) return heuristic("payment", "card_fields");
  if (frameHost !== null && isPaymentFrameHost(frameHost)) return heuristic("payment", "payment_frame");
  if (PAYMENT_LABEL.test(label)) return heuristic("payment", "payment_label");

  if (DELETE_LABEL.test(label)) return heuristic("delete", "destructive_label");

  const compose = ctx?.compose;
  if (SEND_LABEL.test(label) && compose !== undefined && compose.hasBody) return heuristic("send", compose.hasRecipient ? "compose_with_recipient" : "compose_body");

  return NONE;
}
