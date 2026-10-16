/**
 * Adapters for account and cloud consoles (design 5.2):
 * Apple ID and the AWS console.
 *
 * Apple ID: sign-in and security settings (password, trusted phones, two-factor,
 * recovery key, app-specific passwords, devices) are `account_security`;
 * changing a payment method is `account_security` too (it redirects future
 * charges); paying a balance is `payment`.
 *
 * AWS console: IAM (users, access keys, roles, policies, groups, MFA) is
 * `account_security`; deleting or terminating resources is `delete`;
 * billing changes are `account_security` (payment method, account closure is
 * `delete`) and paying an invoice is `payment`.
 *
 * AWS pages are a single-page app: the service is in the path
 * (`/iam/home`, `/billing/home`) and the view in the hash (`#/users`).
 */
import type { SiteAdapter } from "./classify.js";
import { type Hit, inPage, isCommit, normalLabel, pageParts } from "./adapter-kit.js";

// ---- Apple ID -----------------------------------------------------------------

const APPLE_SECURITY = /^(?:change password|update password|reset password|add (?:a )?trusted phone number|(?:add|remove|edit) (?:a )?trusted (?:phone|device)s?|remove (?:this )?(?:phone number|device|from account)|turn (?:on|off) two[- ]factor authentication|turn off (?:two[- ]factor|2fa)|generate (?:an )?(?:app[- ]specific )?password|create (?:an )?(?:app[- ]specific )?password|revoke(?: all)?|(?:add|replace|turn on|turn off|create|generate) (?:a )?recovery key|(?:add|remove|change) (?:a )?(?:legacy|recovery) contact|(?:change|add|edit|update) (?:your )?(?:apple (?:id|account)|email(?: address)?|phone(?: number)?|reachable at|primary email)|sign out of all devices|set up (?:account recovery|security keys)|add (?:a )?security key|remove security key|add (?:a )?passkey|manage security keys)\b/i;
const APPLE_PAYMENT_CHANGE = /^(?:add|edit|update|change|remove|replace)\s+(?:a\s+|your\s+)?payment\b|^(?:update|change|edit|add|remove) (?:billing|payment) (?:information|method|details)|^remove payment method/i;
const APPLE_PAY = /^(?:pay|pay now|pay balance|pay outstanding balance|pay (?:the )?(?:amount|balance) due)$/i;
const APPLE_DELETE = /^(?:delete (?:your |my )?(?:apple )?account|request to delete your account|deactivate (?:your |my )?account|continue to delete)\b/i;

/** Apple ID / Apple Account: security settings and payment. */
export const appleIdAdapter: SiteAdapter = {
  id: "apple_id",
  hosts: ["=appleid.apple.com", "=account.apple.com", "=idmsa.apple.com", "=privacy.apple.com", "=iforgot.apple.com", "=secure.store.apple.com", "=secure2.store.apple.com"],
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    const { host, path } = pageParts(a);
    if (APPLE_DELETE.test(label) || (host === "privacy.apple.com" && /^(?:request to delete|delete) /i.test(label))) return { actionClass: "delete", signal: "delete_account" };
    if (a.kind === "activate" && APPLE_PAYMENT_CHANGE.test(label)) return { actionClass: "account_security", signal: "payment_method" };
    if (a.kind === "activate" && APPLE_PAY.test(label)) return { actionClass: "payment", signal: "pay_balance" };
    if (host === "iforgot.apple.com" && (a.kind === "submit" || /^(?:continue|reset password|next|done)$/i.test(label))) return { actionClass: "account_security", signal: "password_reset" };
    if (a.kind === "activate" && APPLE_SECURITY.test(label)) return { actionClass: "account_security", signal: "security_settings" };
    // Inside the security and payment panes, the dialogs' own Save / Done / Continue commit the change.
    if (/\/(?:account\/manage\/section\/(?:security|payment)|account\/manage\/(?:security|payment)|password|security|payment|account\/manage\/section\/devices)/i.test(path) && isCommit(a, label) && /^(?:save|update|confirm|done|remove|turn off|turn on|continue)\b/i.test(label)) return { actionClass: "account_security", signal: /payment/i.test(path) ? "payment_method" : "security_settings" };
    return null;
  },
};

// ---- AWS console -------------------------------------------------------------

const AWS_HOSTS = ["console.aws.amazon.com", "console.amazonaws-us-gov.com", "console.amazonaws.cn", "signin.aws.amazon.com", "us-east-1.signin.aws.amazon.com"];

const IAM_PLACE = /^\/(?:iam|iamv2)(?:\/|$)|#\/?(?:users|roles|policies|groups|security_credentials|home\?|account_settings|identity_providers|access_keys|mfa)|^\/(?:identity|singlesignon|sso)\b|\/securitycredentials\b|#\/security_credentials|\/iam\/home/i;
const IAM_COMMIT = /^(?:create (?:user|access key|new access key|role|policy|group|login profile|service[- ]specific credential|instance profile|identity provider|saml provider|oidc provider)|add (?:permissions|inline policy|users to group|mfa)|attach(?: policies| policy| existing policies directly)?|assign mfa(?: device)?|(?:make|set) (?:access key )?inactive|deactivate|activate|detach(?: policy)?|put policy|update(?: policy| trust policy| password policy| access key| login profile)?|save changes|edit policy|set password|reset password|enable console access|manage console access)\b/i;

const AWS_DELETE = /^(?:delete|terminate|empty|permanently delete|delete permanently|release|deregister|decommission|schedule key deletion|delete (?:bucket|instance|stack|cluster|database|db instance|function|table|volume|snapshot|vpc|subnet|security group|load balancer|key pair|key|role|user|policy|group|queue|topic|distribution|hosted zone|repository|image|secret|log group|file system|rule|bucket policy|object|objects|cache cluster|replication group|kms key|access key|resources?)|terminate(?: \(delete\))? instances?|terminate instance|empty bucket|delete stack|delete rds instance)\b/i;

const BILLING_PLACE = /^\/(?:billing|costmanagement|cost-management|account|bcm|invoices|payments)(?:\/|$)|#\/?(?:paymentpreferences|paymentmethods|payments|account|preferences)/i;
const BILLING_PAY = /^(?:pay now|make a payment|pay (?:balance|invoice|outstanding)|pay (?:selected|all)|complete payment|verify and add|verify and pay)\b/i;
const BILLING_METHOD = /^(?:add|edit|update|change|remove|delete|replace) (?:a )?(?:payment|credit card|card|debit card|bank account|billing|tax|payment method|default)\b|^(?:make default|set as default|set default)\b|^(?:verify and add|save payment|update payment)/i;

/** AWS console: IAM users, keys, roles and policies; deleting and terminating resources; billing. */
export const awsConsoleAdapter: SiteAdapter = {
  id: "aws_console",
  hosts: AWS_HOSTS,
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    const { path, hash } = pageParts(a);
    const place = path + hash;
    if (/^(?:close account|close your aws account|close aws account)\b/i.test(label)) return { actionClass: "delete", signal: "close_account" };
    if (BILLING_PLACE.test(place)) {
      if (BILLING_PAY.test(label)) return { actionClass: "payment", signal: "billing_pay" };
      if (BILLING_METHOD.test(label)) return { actionClass: "account_security", signal: "billing_settings" };
      if (/^\/(?:billing|account)\b/i.test(path) && /^(?:save(?: preferences| changes)?|update|apply)$/i.test(label)) return { actionClass: "account_security", signal: "billing_settings" };
    }
    if (IAM_PLACE.test(place) && /^delete\b/i.test(label)) return { actionClass: "delete", signal: "iam_delete" };
    if (IAM_PLACE.test(place) && (IAM_COMMIT.test(label) || /^remove\b/i.test(label))) return { actionClass: "account_security", signal: "iam_change" };
    if (AWS_DELETE.test(label)) return { actionClass: "delete", signal: "delete_resource" };
    // The access key lines in the account menu and the security credentials page.
    if (/\/securitycredentials\b|#\/security_credentials/i.test(place) && isCommit(a, label)) return { actionClass: "account_security", signal: "iam_change" };
    return null;
  },
};

export const cloudAdapters: readonly SiteAdapter[] = [appleIdAdapter, awsConsoleAdapter];
