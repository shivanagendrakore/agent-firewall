/**
 * Adapters for chat and social sites (design 5.2): Slack,
 * LinkedIn, X (Twitter) and Reddit. Each classifies by the real host and by
 * the control (its label, the page path, the fields around it); anything it
 * does not know returns null and the generic heuristics run.
 *
 * Posting, messaging, inviting and connecting are `send` (a person can allow
 * them for one site for one agent session); settings, app installs and
 * account changes are `account_security` or `oauth_consent` (never
 * session-grantable); deleting a workspace or account is `delete`.
 */
import type { SiteAdapter } from "./classify.js";
import { type Hit, hasField, inComposer, inPage, isCommit, isShortcut, normalLabel, pageParts, targetPath } from "./adapter-kit.js";

// ---- Slack ------------------------------------------------------------------

const SLACK_SEND = /^send(?: now| message)?\b(?!\s+(?:feedback|later|a (?:huddle|reminder)))/i;
const SLACK_INVITE_FIELD = /invit|add people|names or emails|email addresses|add by email/i;
const SLACK_SHARE_FIELD = /share (?:with|to|in)|channel|conversation|people|message/i;
const SLACK_ADMIN_PATH = /^\/(?:admin(?:\/|$)|apps\/manage|account\/(?:settings|security|billing)|customize|services\/(?:new|\w+\/edit)|marketplace\/[^/]+\/(?:install|add)|apps\/[^/]+\/(?:settings|permissions|install|remove)|workspace\/(?:settings|preferences))/i;
const SLACK_SETTINGS_LABEL = /^(?:save(?: changes| settings)?|update|apply|turn on|turn off|enable|disable|require|change|remove(?: app| from workspace)?|uninstall|approve|restrict|add(?: to slack| app)?|install(?: to workspace)?|allow|reinstall|rotate|regenerate|deactivate|confirm|yes)\b/i;

/** Slack: sending a message, inviting people, sharing a file, workspace and app settings. */
export const slackAdapter: SiteAdapter = {
  id: "slack",
  hosts: ["slack.com"],
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    const { path } = pageParts(a);
    if (/^(?:delete (?:this )?workspace|delete workspace|deactivate (?:my )?account|deactivate (?:this )?(?:member|account)|remove (?:this )?workspace)\b/i.test(label)) return { actionClass: "delete", signal: "delete_workspace_or_account" };
    if (a.kind === "activate" && /^(?:send invitations?|send invites?|invite to (?:the )?workspace)$/i.test(label)) return { actionClass: "send", signal: "invite" };
    if (a.kind === "activate" && SLACK_SEND.test(label) && hasField(a, SLACK_INVITE_FIELD)) return { actionClass: "send", signal: "invite" };
    if (/^\/admin\/invites?\b/i.test(path) && isCommit(a, label) && /invit|send|add/i.test(label)) return { actionClass: "send", signal: "invite" };
    if (a.kind === "activate" && /^(?:share|share file|share to channel|share in channel|send file)$/i.test(label) && hasField(a, SLACK_SHARE_FIELD)) return { actionClass: "send", signal: "share_file" };
    if (/^\/oauth\b/.test(path) && (a.kind === "submit" || /^(?:allow|authori[sz]e|accept|approve|add to slack|install)\b/i.test(label))) return { actionClass: "oauth_consent", signal: "app_authorize" };
    if (SLACK_ADMIN_PATH.test(path) && (a.kind === "submit" || SLACK_SETTINGS_LABEL.test(label))) {
      if (/^\/marketplace\/|^\/apps\/(?:manage|[^/]+\/(?:install|permissions))|^\/services\//i.test(path)) return { actionClass: "oauth_consent", signal: "app_install" };
      return { actionClass: "account_security", signal: "workspace_settings" };
    }
    if (a.kind === "activate" && /^send(?: now)?$/i.test(label) && inComposer(a)) return { actionClass: "send", signal: "message" };
    if (isShortcut(a) && inComposer(a)) return { actionClass: "send", signal: "message" };
    return null;
  },
};

// ---- LinkedIn ---------------------------------------------------------------

const LINKEDIN_POST = /^(?:post|post now|post all|repost|repost with your thoughts|share post|publish|comment|reply)$/i;
const LINKEDIN_CONNECT = /^(?:connect|send without a note|send invitation|send invite|send now|accept|invite .{1,80} to connect)$/i;

/** LinkedIn: posting, messaging, connection requests. */
export const linkedinAdapter: SiteAdapter = {
  id: "linkedin",
  hosts: ["linkedin.com"],
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    const { path } = pageParts(a);
    if (/^\/mynetwork\//i.test(path) || /^\/in\/|^\/search\/results\/people/i.test(path) || /^\/(?:company|school)\//i.test(path)) {
      if (a.kind === "activate" && LINKEDIN_CONNECT.test(label) && !/^accept$/i.test(label)) return { actionClass: "send", signal: "connection_request" };
      if (/^\/mynetwork\/invitation-manager/i.test(path) && /^accept$/i.test(label)) return { actionClass: "send", signal: "connection_accept" };
    }
    if (a.kind === "activate" && /^(?:send without a note|send invitation|send invite)$/i.test(label)) return { actionClass: "send", signal: "connection_request" };
    if (/^\/messaging\b/i.test(path) || /^\/(?:in\/[^/]+\/)?overlay\/(?:compose|messaging)/i.test(path)) {
      if (a.kind === "activate" && /^send(?: message)?$/i.test(label)) return { actionClass: "send", signal: "message" };
      if (isShortcut(a) && inComposer(a)) return { actionClass: "send", signal: "message" };
    }
    if (a.kind === "activate" && LINKEDIN_POST.test(label) && (inComposer(a) || /^\/(?:feed|posts|in\/|company\/|pulse|post\/new|article\/)/i.test(path) || path === "/")) return { actionClass: "send", signal: "post" };
    if (isShortcut(a) && inComposer(a)) return { actionClass: "send", signal: "post" };
    if (/^\/mypreferences\/|^\/psettings\//i.test(path) && isCommit(a, label)) return { actionClass: "account_security", signal: "account_settings" };
    if (/^\/psettings\/(?:close-account|account-management)|close (?:your )?account/i.test(path + " " + label) && /close|delete|continue|next/i.test(label)) return { actionClass: "delete", signal: "close_account" };
    return null;
  },
};

// ---- X (Twitter) ------------------------------------------------------------

const X_POST = /^(?:post|post all|reply|tweet|repost|quote|quote post|post your reply)$/i;
const X_SETTINGS_PATH = /^\/(?:settings\/(?:password|your_twitter_data|account|security|sessions|apps|connected_accounts|email|phone|deactivate|delete_your_account|two_factor_authentication|login_verification|add_phone|add_email|password_reset|remove_phone|security_and_account_access)|i\/flow\/(?:password_reset|login_verification|add_email|change_password|deactivate))/i;

/** X (Twitter): posting, direct messages, account settings. */
export const xAdapter: SiteAdapter = {
  id: "x",
  hosts: ["x.com", "twitter.com"],
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    const { path } = pageParts(a);
    if (/^\/settings\/(?:deactivate|delete_your_account)\b|^\/i\/flow\/deactivate/i.test(path) && (a.kind === "submit" || /^(?:deactivate|delete|confirm)/i.test(label))) return { actionClass: "delete", signal: "deactivate_account" };
    if (X_SETTINGS_PATH.test(path) && isCommit(a, label)) return { actionClass: "account_security", signal: "account_settings" };
    if (/^\/(?:messages|i\/chat|i\/messages)\b/i.test(path)) {
      if (a.kind === "activate" && /^send(?: message)?$/i.test(label)) return { actionClass: "send", signal: "direct_message" };
      if (isShortcut(a) && inComposer(a)) return { actionClass: "send", signal: "direct_message" };
    }
    if (a.kind === "activate" && X_POST.test(label) && (inComposer(a) || /^\/(?:compose\/|home\b|[^/]+\/status\/)/i.test(path))) return { actionClass: "send", signal: "post" };
    if (isShortcut(a) && inComposer(a)) return { actionClass: "send", signal: "post" };
    return null;
  },
};

// ---- Reddit -----------------------------------------------------------------

const REDDIT_SETTINGS_PATH = /^\/(?:settings(?:\/|$)|prefs\/(?:update|deactivate|delete|apps|password|security)?)/i;

/** Reddit (new and old): posts, comments, private messages and chats, account settings. */
export const redditAdapter: SiteAdapter = {
  id: "reddit",
  hosts: ["reddit.com"],
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    const { path } = pageParts(a);
    if (/delete (?:my |your )?account|deactivate (?:my |your )?account/i.test(label) && REDDIT_SETTINGS_PATH.test(path)) return { actionClass: "delete", signal: "delete_account" };
    if (REDDIT_SETTINGS_PATH.test(path) && isCommit(a, label) && !/^(?:continue|next|done)$/i.test(label)) return { actionClass: "account_security", signal: "account_settings" };
    if (REDDIT_SETTINGS_PATH.test(path) && /^(?:continue|next|done)$/i.test(label) && /password|email|connected|two-factor|2fa|authenticator/i.test(path)) return { actionClass: "account_security", signal: "account_settings" };
    // Old Reddit: forms with plain "save" and "submit" buttons.
    if (a.kind === "submit") {
      const target = targetPath(a);
      if (/^\/api\/(?:comment|submit)\b/i.test(target) || /^\/r\/[^/]+\/submit\b|^\/submit\b/i.test(path)) return { actionClass: "send", signal: /submit/i.test(target + path) ? "post" : "comment" };
      if (/^\/api\/compose\b|^\/message\/compose\b/i.test(target + path)) return { actionClass: "send", signal: "direct_message" };
      if (/^\/api\/(?:del_account|delete_user)\b/i.test(target)) return { actionClass: "delete", signal: "delete_account" };
    }
    if (a.kind === "activate") {
      if (/^send(?: message)?$/i.test(label) && (/^\/(?:message|chat|room)\b/i.test(path) || inComposer(a) || /^chat\./i.test(pageParts(a).host))) return { actionClass: "send", signal: "direct_message" };
      if (/^(?:post|comment|reply)$/i.test(label) && (inComposer(a) || /^\/r\/[^/]+\/(?:submit|comments)\b|^\/submit\b|^\/user\/[^/]+\/submit/i.test(path))) return { actionClass: "send", signal: /post/i.test(label) ? "post" : "comment" };
    }
    if (isShortcut(a) && inComposer(a)) return { actionClass: "send", signal: "message" };
    return null;
  },
};

export const appsAdapters: readonly SiteAdapter[] = [slackAdapter, linkedinAdapter, xAdapter, redditAdapter];
