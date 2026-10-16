/**
 * Site adapters (design 5.2): precise classification for the top sites where
 * the generic heuristics in classify.ts are too loose or miss the real
 * control. Each adapter is consulted only on its own hosts (classify() checks
 * the page and frame host) and returns null for anything it does not know, so
 * the heuristics still run.
 *
 * v0.1 set: Gmail, Outlook web, Google Account, GitHub settings and OAuth,
 * Microsoft consent, Stripe Checkout, Shopify checkout, Amazon checkout.
 * Further adapters cover Slack, LinkedIn, X, Reddit (adapters-apps.ts), Google Drive
 * and Microsoft 365 sharing (adapters-sharing.ts), Apple ID and the AWS
 * console (adapters-cloud.ts), and GitHub's repository settings (adapters-github.ts).
 *
 * Adapters read only what the content script measured (labels, roles, the
 * page URL's path and hash, form fields, the compose context); no DOM here.
 * Labels on real sites carry shortcut hints and bidi marks ("Send \u202a(Ctrl-Enter)\u202c"),
 * so labels are normalised before matching.
 */
import type { SiteAdapter } from "./classify.js";
import { type Hit, inPage, isCommit, normalLabel, pageParts, SEND_NOW } from "./adapter-kit.js";
import { appsAdapters } from "./adapters-apps.js";
import { cloudAdapters } from "./adapters-cloud.js";
import { githubSettingsHit } from "./adapters-github.js";
import { sharingAdapters } from "./adapters-sharing.js";

export { normalLabel };

// ---- mail -------------------------------------------------------------------

/** Gmail: the send button (div role=button, label "Send \u202a(⌘Enter)\u202c"), Ctrl/⌘+Enter, forwarding and filters, delete forever. */
export const gmailAdapter: SiteAdapter = {
  id: "gmail",
  hosts: ["=mail.google.com"],
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    const { hash } = pageParts(a);
    if (/^#settings\/(?:fwdandpop|filters)\b/i.test(hash) && (isCommit(a, label) || /forwarding address|forward a copy|create filter/i.test(label))) return { actionClass: "account_security", signal: "forwarding_or_filters" };
    if (/^(?:create filter|add a forwarding address)$/i.test(label)) return { actionClass: "account_security", signal: "forwarding_or_filters" };
    if (/^(?:delete forever|empty trash now|empty spam now|delete all spam messages now)$/i.test(label)) return { actionClass: "delete", signal: "delete_forever" };
    if (a.kind === "activate" && SEND_NOW.test(label) && (a.context.compose?.hasBody === true || /enter/i.test(label) || a.role === "shortcut")) return { actionClass: "send", signal: "send" };
    return null;
  },
};

/** Outlook on the web: Send (title "Send (Ctrl+Enter)"), forwarding and inbox rules, empty folder. */
export const outlookAdapter: SiteAdapter = {
  id: "outlook",
  hosts: ["=outlook.live.com", "=outlook.office.com", "=outlook.office365.com", "=outlook.cloud.microsoft"],
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    const { path } = pageParts(a);
    if (/\/options\/mail\/(?:forwarding|rules|inboxrules)\b/i.test(path) && (isCommit(a, label) || /forwarding|rule/i.test(label))) return { actionClass: "account_security", signal: "forwarding_or_rules" };
    if (/^(?:enable forwarding|add new rule|keep a copy of forwarded messages)$/i.test(label)) return { actionClass: "account_security", signal: "forwarding_or_rules" };
    if (/^(?:empty folder|delete all|permanently delete|empty deleted items)$/i.test(label)) return { actionClass: "delete", signal: "empty_or_purge" };
    if (a.kind === "activate" && SEND_NOW.test(label) && (a.context.compose?.hasBody === true || /enter/i.test(label) || a.role === "shortcut")) return { actionClass: "send", signal: "send" };
    return null;
  },
};

// ---- account security and consent -------------------------------------------

/** Google Account: password, 2-Step Verification, recovery, app passwords, passkeys, third-party access, account deletion. */
export const googleAccountAdapter: SiteAdapter = {
  id: "google_account",
  hosts: ["=myaccount.google.com"],
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    const { path } = pageParts(a);
    if (/^\/(?:u\/\d+\/)?(?:delete-services-or-account|deleteaccount)\b/i.test(path) && (a.kind === "submit" || /delete/i.test(label))) return { actionClass: "delete", signal: "delete_account" };
    if (/^\/(?:u\/\d+\/)?(?:signinoptions|two-step-verification|security|recovery|apppasswords|connections|permissions|device-activity|security-checkup|account-recovery|passkeys)\b/i.test(path) && isCommit(a, label)) return { actionClass: "account_security", signal: "security_settings" };
    return null;
  },
};

/** GitHub: OAuth authorize and app installs, account and repository security settings, destructive settings. */
export const githubAdapter: SiteAdapter = {
  id: "github",
  hosts: ["=github.com"],
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    const { path } = pageParts(a);
    if (/^\/login\/oauth\/authorize\b|^\/login\/device\b/.test(path) && (a.kind === "submit" || /^authori[sz]e\b|^continue\b/i.test(label))) return { actionClass: "oauth_consent", signal: "oauth_authorize" };
    if (/^\/apps\/[^/]+\/installations\/(?:new|select_target)|^\/(?:organizations\/[^/]+\/)?settings\/installations\//.test(path) && (a.kind === "submit" || /^(?:install|install & authori[sz]e|authori[sz]e|save)\b/i.test(label))) return { actionClass: "oauth_consent", signal: "app_install" };
    const repoHit = githubSettingsHit(a);
    if (repoHit !== null) return repoHit;
    if (/^\/settings\//.test(path) || /^\/[^/]+\/[^/]+\/settings(?:\/|$)/.test(path) || /^\/organizations\/[^/]+\/settings\//.test(path)) {
      if (/delete (?:this )?(?:repository|organization|account|your account)|i want to delete this repository|i understand the consequences, delete|transfer (?:this )?repository|change (?:repository )?visibility|make (?:this repository )?public/i.test(label)) return { actionClass: "delete", signal: "destructive_setting" };
      if (/^\/settings\/(?:tokens|personal-access-tokens|keys|ssh|gpg|security|two_factor_authentication|auth|emails|admin|password|applications|apps|connections|developers|sessions|installations)\b/.test(path) && isCommit(a, label)) return { actionClass: "account_security", signal: "account_security_settings" };
      if (/^\/[^/]+\/[^/]+\/settings\/(?:keys|hooks|secrets|variables|access|collaboration|actions|environments|branches|rules|installations)\b/.test(path) && isCommit(a, label)) return { actionClass: "account_security", signal: "repo_security_settings" };
      if (/^\/organizations\/[^/]+\/settings\/(?:security|member_privileges|oauth_application_policy|personal-access-tokens|secrets|hooks|installations)\b/.test(path) && isCommit(a, label)) return { actionClass: "account_security", signal: "org_security_settings" };
    }
    return null;
  },
};

/** Microsoft identity: the consent prompt ("Accept"), and account security proofs. */
export const microsoftConsentAdapter: SiteAdapter = {
  id: "microsoft_consent",
  hosts: ["=login.microsoftonline.com", "=login.live.com", "=account.live.com", "=account.microsoft.com", "=mysignins.microsoft.com"],
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    const { path, host } = pageParts(a);
    if ((host === "login.microsoftonline.com" || host === "login.live.com") && /oauth2|consent|authorize|appconsent|oauth20_authorize/i.test(path) && (a.kind === "submit" || /^(?:accept|yes|allow|continue|consent)\b/i.test(label))) return { actionClass: "oauth_consent", signal: "consent_prompt" };
    if (/\/(?:proofs|password\/change|security|recovery|security-info|apppassword)/i.test(path) && isCommit(a, label)) return { actionClass: "account_security", signal: "security_settings" };
    return null;
  },
};

// ---- checkout -----------------------------------------------------------------

const PAY_LABEL = /^(?:pay|pay now|subscribe|start trial|start free trial|donate|book|reserve|confirm|complete order|complete purchase|place order|buy)\b/i;

/** Stripe Checkout (hosted page and payment links): the submit button ("Pay", "Subscribe", "Start trial", "Donate"). */
export const stripeCheckoutAdapter: SiteAdapter = {
  id: "stripe_checkout",
  hosts: ["=checkout.stripe.com", "=buy.stripe.com"],
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    if (a.kind === "submit" || (a.kind === "activate" && PAY_LABEL.test(label))) return { actionClass: "payment", signal: "checkout_submit" };
    return null;
  },
};

/**
 * Shopify checkout on Shopify's hosts. Checkouts on a store's own domain
 * (`/checkouts/...`) have no host to key on; there the generic payment labels
 * ("Pay now", "Complete order") and card fields carry it.
 */
export const shopifyCheckoutAdapter: SiteAdapter = {
  id: "shopify_checkout",
  hosts: ["checkout.shopify.com", "shop.app", "myshopify.com", "=pay.shopify.com"],
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    const { path, host } = pageParts(a);
    const inCheckout = /\/checkouts?\b|\/pay\b/.test(path) || host === "checkout.shopify.com" || host === "pay.shopify.com" || host.endsWith(".shop.app") || host === "shop.app";
    if (!inCheckout) return null;
    if ((a.kind === "activate" || a.kind === "submit") && /^(?:pay now|complete order|place order|pay|buy now|subscribe|confirm and pay|continue to payment)\b/i.test(label)) return { actionClass: "payment", signal: "checkout_pay" };
    return null;
  },
};

const AMAZON_HOSTS = ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.ca", "amazon.com.au", "amazon.co.jp", "amazon.in", "amazon.com.mx", "amazon.com.br", "amazon.nl", "amazon.se", "amazon.pl", "amazon.sg", "amazon.ae", "amazon.sa", "amazon.com.tr", "amazon.com.be", "amazon.eg"];

/** Amazon: "Place your order", "Buy Now", 1-Click, and account closure. */
export const amazonCheckoutAdapter: SiteAdapter = {
  id: "amazon_checkout",
  hosts: AMAZON_HOSTS,
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    const { path } = pageParts(a);
    if (/^(?:place your order|place order|buy now|buy with 1-click|1-click|confirm and pay|start your free trial|subscribe now|join prime)\b/i.test(label)) return { actionClass: "payment", signal: "buy" };
    if (a.kind === "submit" && /\/(?:gp\/buy|checkout|cpe\/executions|gp\/product\/handle-buy-box)\b/.test(path) && /order|buy|pay/i.test(label)) return { actionClass: "payment", signal: "checkout_submit" };
    if (/close (?:your )?(?:amazon )?account/i.test(label)) return { actionClass: "delete", signal: "close_account" };
    return null;
  },
};

/**
 * Hosts whose own checkout may receive a card typed into its card fields: the
 * checkout adapters' sites. A page cannot add itself (BR9); the person can add
 * hosts through policy.paymentHosts.
 */
/**
 * Shopify's own checkout hosts, exactly (m6). The adapter matches "shop.app" and "myshopify.com" with their
 * subdomains to gate more; as a card exemption that would let any store's *.myshopify.com page, or any name
 * under shop.app, receive a card as if it were Shopify's checkout.
 */
export const SHOPIFY_CHECKOUT_HOSTS: readonly string[] = ["=checkout.shopify.com", "=pay.shopify.com", "=shop.app"];

export const CHECKOUT_MERCHANT_HOSTS: readonly string[] = [...stripeCheckoutAdapter.hosts, ...SHOPIFY_CHECKOUT_HOSTS, ...amazonCheckoutAdapter.hosts];

/** The v0.1 adapters, in the order classify() consults them. */
export const ADAPTERS: readonly SiteAdapter[] = [gmailAdapter, outlookAdapter, googleAccountAdapter, githubAdapter, microsoftConsentAdapter, stripeCheckoutAdapter, shopifyCheckoutAdapter, amazonCheckoutAdapter, ...appsAdapters, ...sharingAdapters, ...cloudAdapters];
