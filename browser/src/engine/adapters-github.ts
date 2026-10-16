/**
 * GitHub repository settings (design 5.2): the controls
 * that delete, expose or re-key a repository. The v0.1 GitHub adapter covers
 * OAuth, app installs and the account settings pages; this adds, for a
 * repository (`/{owner}/{repo}/settings/...`) and an organisation
 * (`/organizations/{org}/settings/...`):
 *
 *   - delete, archive, transfer and visibility changes: `delete` (the
 *     destructive class; a public repository cannot be made private again
 *     from its readers' copies, and a deleted one is gone);
 *   - deploy keys and secrets and variables (Actions, Dependabot,
 *     Codespaces, environments): `account_security`.
 *
 * Forms are recognised by their target path as well as by their label, so a
 * relabelled button does not hide them.
 */
import { type Hit, type InPage, inPage, isCommit, normalLabel, pageParts, targetPath } from "./adapter-kit.js";

const REPO_SETTINGS = /^\/[^/]+\/[^/]+\/settings(?:\/|$)|^\/organizations\/[^/]+\/settings(?:\/|$)/;
const DESTRUCTIVE_LABEL = /^(?:i want to delete this repository|i have read and understand these effects|i understand, delete this repository|delete this repository|delete (?:this )?organi[sz]ation|i understand the consequences, delete|archive this repository|i understand, archive this repository|unarchive this repository|transfer(?: ownership| this repository)?|i understand, transfer this repository|i understand, change repository visibility|change (?:repository )?visibility|change to (?:public|private|internal)|make (?:this repository )?(?:public|private|internal)|i want to make this repository (?:public|private|internal))\b/i;
const DESTRUCTIVE_TARGET = /\/settings\/(?:delete|archive|unarchive|visibility|change_visibility|transfer|make_public|make_private)\b/;

/** What the repository settings page's destructive and key-handling controls are, or null (the caller's other rules then run). */
export function githubSettingsHit(a: InPage): Hit {
  if (!inPage(a)) return null;
  const { path } = pageParts(a);
  if (!REPO_SETTINGS.test(path)) return null;
  const label = normalLabel(a);
  if (a.kind === "submit" && DESTRUCTIVE_TARGET.test(targetPath(a))) return { actionClass: "delete", signal: "destructive_setting" };
  if (a.kind === "activate" && DESTRUCTIVE_LABEL.test(label)) return { actionClass: "delete", signal: "destructive_setting" };
  if (/\/settings\/keys(?:\/|$)/.test(path) && (isCommit(a, label) || /^add (?:deploy )?key$/i.test(label))) return { actionClass: "account_security", signal: "deploy_key" };
  if (/\/settings\/(?:secrets|variables|environments|actions\/(?:secrets|variables))\b/.test(path) && (isCommit(a, label) || /^(?:add|update|remove) (?:repository |environment |organi[sz]ation )?(?:secret|variable)$/i.test(label))) return { actionClass: "account_security", signal: "secrets" };
  if (/\/settings\/(?:keys|secrets|variables)\b/.test(path) && a.kind === "submit") return { actionClass: "account_security", signal: /keys/.test(path) ? "deploy_key" : "secrets" };
  return null;
}
