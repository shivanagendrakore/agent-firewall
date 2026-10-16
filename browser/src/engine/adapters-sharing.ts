/**
 * Adapters for document sharing dialogs (design 5.2):
 * Google Drive (and Docs, Sheets, Slides, which share the same dialog) and
 * Microsoft 365 (OneDrive, SharePoint, Office on the web).
 *
 * Two things matter in a sharing dialog:
 *   - sending access to people ("Send", "Share", "Share anyway", "Grant
 *     access"): `send`, because a person can reasonably allow it for one
 *     site for one session;
 *   - widening link access to anyone ("Anyone with the link", "Anyone on the
 *     internet"): `account_security`, never session-grantable, because it
 *     exposes the document to everyone who has the link.
 * Choosing a narrower audience ("Restricted", "Specific people", "People in
 * <org>") and "Copy link" are allowed.
 *
 * The dialog's own "Share" button and a toolbar "Share" button have the same
 * label; only the one in the dialog (a recipient field around it) is a
 * commit, so opening the dialog is never gated.
 */
import type { SiteAdapter } from "./classify.js";
import { type Hit, hasField, inPage, normalLabel, pageParts } from "./adapter-kit.js";

const PEOPLE_FIELD = /add people|people,? groups|people or groups|enter (?:a )?name|names? or e-?mail|e-?mail addresses?|add a name|invite people|grant access|share with/i;

/** An option or button that makes the link usable by anyone (not "Anyone in your organization"). */
const PUBLIC_LINK = /^(?:change to )?anyone(?: on the internet| with the link| with (?:this )?link| who has the link)?\b(?!\s+in\b)|^anyone$|^public(?: on the web)?$|^get link to anyone|^allow anyone/i;

function sharingHit(a: Parameters<NonNullable<SiteAdapter["classify"]>>[0], signalPrefix: string): Hit {
  if (!inPage(a)) return null;
  const label = normalLabel(a);
  if (a.kind === "activate" && PUBLIC_LINK.test(label)) return { actionClass: "account_security", signal: `${signalPrefix}_public_link` };
  if (a.kind === "activate" && /^(?:share|send) anyway$/i.test(label)) return { actionClass: "send", signal: `${signalPrefix}_share_external` };
  if (a.kind === "activate" && /^(?:send|share|grant access|invite|done|save)$/i.test(label) && hasField(a, PEOPLE_FIELD)) return { actionClass: "send", signal: `${signalPrefix}_share_people` };
  if (a.kind === "submit" && hasField(a, PEOPLE_FIELD)) return { actionClass: "send", signal: `${signalPrefix}_share_people` };
  return null;
}

/** Google Drive, Docs, Sheets, Slides: the sharing dialog (people and general access). */
export const googleDriveAdapter: SiteAdapter = {
  id: "google_drive",
  hosts: ["=drive.google.com", "=docs.google.com", "=sheets.google.com", "=slides.google.com", "=drive.usercontent.google.com", "=script.google.com"],
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    const hit = sharingHit(a, "drive");
    if (hit !== null) return hit;
    // The dialog's primary button is "Send" when people are notified; it sits in a frame with no field the content script can see.
    if (a.kind === "activate" && /^send$/i.test(label) && /\/(?:drive|document|spreadsheets|presentation|file|forms|folders)\b/i.test(pageParts(a).path)) return { actionClass: "send", signal: "drive_share_people" };
    if (a.kind === "activate" && /^(?:empty trash|delete forever|delete all forever)$/i.test(label)) return { actionClass: "delete", signal: "delete_forever" };
    return null;
  },
};

/** Microsoft 365 on the web: OneDrive, SharePoint, Office. Link settings ("Anyone with the link") and the Send / Grant access buttons. */
export const microsoft365SharingAdapter: SiteAdapter = {
  id: "microsoft365_sharing",
  hosts: ["=onedrive.live.com", "sharepoint.com", "=www.office.com", "=office.com", "=m365.cloud.microsoft", "=www.onedrive.com", "=1drv.ms", "=onedrive.com"],
  classify(a): Hit {
    if (!inPage(a)) return null;
    const label = normalLabel(a);
    const hit = sharingHit(a, "m365");
    if (hit !== null) return hit;
    // The Send dialog ("Send link"): button "Send" beside a "Add a name, group, or email" field; "Send link" is also its label in some builds.
    if (a.kind === "activate" && /^(?:send link|send invitation|send a link)$/i.test(label)) return { actionClass: "send", signal: "m365_share_people" };
    if (a.kind === "activate" && /^(?:stop sharing|remove link)$/i.test(label)) return null;
    if (a.kind === "activate" && /^(?:delete forever|empty recycle bin|permanently delete|delete all)$/i.test(label)) return { actionClass: "delete", signal: "delete_forever" };
    return null;
  },
};

export const sharingAdapters: readonly SiteAdapter[] = [googleDriveAdapter, microsoft365SharingAdapter];
