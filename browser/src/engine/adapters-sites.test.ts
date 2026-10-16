/**
 * The later adapters against real host names and realistic control shapes: an
 * allow case (a harmless control on the site is not classified) and a refusal
 * case (the sensitive control is) for each. Local look-alikes on .test hosts
 * are in test/e2e (they run the generic fallback, since an adapter is keyed on
 * the real host and a page cannot claim one).
 */
import { describe, expect, it } from "vitest";
import { ADAPTERS } from "./adapters.js";
import { classify } from "./classify.js";
import { activate, ctx, frame, submit } from "./test-helpers.js";
import type { ControlContext, FieldInfo, NormalizedAction } from "./types.js";

const cls = (a: NormalizedAction) => classify(a, ADAPTERS);
const klass = (a: NormalizedAction) => cls(a).actionClass;
const signal = (a: NormalizedAction) => cls(a).signals[0];

type Over = Partial<ControlContext> & { role?: string; tag?: string; href?: string };
/** A control on a page: the page URL, the label and what the content script measured around it. */
function btn(url: string, label: string, over: Over = {}): NormalizedAction {
  const { role, tag, href, ...c } = over;
  return activate(label, { frame: frame(new URL(url).origin), context: ctx(url, c), ...(role !== undefined ? { role } : {}), ...(tag !== undefined ? { tag } : {}), ...(href !== undefined ? { href } : {}) });
}
const composer: Over = { compose: { hasRecipient: false, hasBody: true } };
const field = (label: string, name = "f", type = "text"): FieldInfo => ({ name, type, label });
/** A form submit on a page, posting to targetUrl. */
function formOf(url: string, fields: FieldInfo[], label: string, targetUrl = url): NormalizedAction {
  const base = submit(fields, { frame: frame(new URL(url).origin), context: ctx(url), label });
  return { ...base, form: { fields, targetUrl, method: "post" } };
}

describe("Slack", () => {
  const app = "https://app.slack.com/client/T0123ABC/C0456DEF";
  it("sends a message (Send now button and Enter), and invitations", () => {
    expect(klass(btn(app, "Send now", composer))).toBe("send");
    expect(signal(btn(app, "Send now", composer))).toBe("adapter:slack:message");
    expect(klass(btn(app, "Send", { ...composer, role: "shortcut" }))).toBe("send");
    expect(klass(btn("https://acme.slack.com/admin/invites", "Send invitations"))).toBe("send");
    expect(klass(btn(app, "Send", { formFields: [field("Add people by email or name")] }))).toBe("send");
  });
  it("shares a file only from the share dialog", () => {
    expect(signal(btn(app, "Share", { formFields: [field("Share with a channel or person")] }))).toBe("adapter:slack:share_file");
    expect(klass(btn(app, "Share"))).toBeNull();
  });
  it("workspace and app settings: save on admin pages, installs and consent", () => {
    expect(signal(btn("https://acme.slack.com/admin/settings", "Save Changes"))).toBe("adapter:slack:workspace_settings");
    expect(klass(btn("https://acme.slack.com/admin/auth", "Require two-factor"))).toBe("account_security");
    expect(klass(btn("https://acme.slack.com/apps/manage/permissions", "Approve"))).toBe("oauth_consent");
    expect(klass(btn("https://slack.com/oauth/v2/authorize?client_id=1", "Allow"))).toBe("oauth_consent");
    expect(klass(btn("https://acme.slack.com/admin", "Delete workspace"))).toBe("delete");
  });
  it("refuses: Send feedback, Send later, navigation on admin pages, a Send with no composer, another host", () => {
    expect(klass(btn(app, "Send feedback", composer))).toBeNull();
    expect(klass(btn(app, "Send later", composer))).toBeNull();
    expect(klass(btn("https://acme.slack.com/admin/settings", "Learn more"))).toBeNull();
    expect(klass(btn(app, "Send now"))).toBeNull();
    expect(klass(btn("https://slack.example.test/admin/settings", "Save Changes"))).toBeNull();
    expect(klass(btn("https://notslack.com/admin/settings", "Save Changes"))).toBeNull();
  });
});

describe("LinkedIn", () => {
  it("posts, comments and messages", () => {
    expect(signal(btn("https://www.linkedin.com/feed/", "Post", composer))).toBe("adapter:linkedin:post");
    expect(klass(btn("https://www.linkedin.com/feed/", "Post"))).toBe("send");
    expect(klass(btn("https://www.linkedin.com/feed/update/urn:li:activity:1/", "Comment", composer))).toBe("send");
    expect(klass(btn("https://www.linkedin.com/messaging/thread/2-abc/", "Send"))).toBe("send");
    expect(klass(btn("https://www.linkedin.com/messaging/thread/2-abc/", "Send", { ...composer, role: "shortcut" }))).toBe("send");
  });
  it("connection requests, and accepting one", () => {
    expect(signal(btn("https://www.linkedin.com/in/jane-doe/", "Connect"))).toBe("adapter:linkedin:connection_request");
    expect(klass(btn("https://www.linkedin.com/in/jane-doe/", "Send without a note"))).toBe("send");
    expect(klass(btn("https://www.linkedin.com/search/results/people/?keywords=a", "Invite Jane Doe to connect"))).toBe("send");
    expect(klass(btn("https://www.linkedin.com/mynetwork/invitation-manager/", "Accept"))).toBe("send");
  });
  it("refuses: Post a job, Send feedback, a profile's Message, Accept elsewhere, other hosts", () => {
    expect(klass(btn("https://www.linkedin.com/jobs/", "Post a job"))).toBeNull();
    expect(klass(btn("https://www.linkedin.com/help/linkedin", "Send feedback"))).toBeNull();
    expect(klass(btn("https://www.linkedin.com/in/jane-doe/", "Follow"))).toBeNull();
    expect(klass(btn("https://www.linkedin.com/jobs/", "Accept"))).toBeNull();
    expect(klass(btn("https://linkedin.evil.test/feed/", "Post", composer))).toBe("send"); // generic composer fallback, source heuristic
    expect(cls(btn("https://linkedin.evil.test/feed/", "Post", composer)).source).toBe("heuristic");
    expect(klass(btn("https://linkedin.evil.test/in/x/", "Connect"))).toBeNull();
  });
  it("account preferences", () => {
    expect(klass(btn("https://www.linkedin.com/mypreferences/d/sign-in-and-security", "Save"))).toBe("account_security");
    expect(klass(btn("https://www.linkedin.com/mypreferences/d/sign-in-and-security", "Learn more"))).toBeNull();
  });
});

describe("X / Twitter", () => {
  it("posts and replies on x.com and twitter.com", () => {
    expect(signal(btn("https://x.com/compose/post", "Post", composer))).toBe("adapter:x:post");
    expect(klass(btn("https://twitter.com/home", "Tweet", composer))).toBe("send");
    expect(klass(btn("https://x.com/someone/status/1800000000000000000", "Reply"))).toBe("send");
    expect(klass(btn("https://x.com/home", "Repost", { role: "menuitem" }))).toBe("send");
  });
  it("direct messages, button and Enter", () => {
    expect(signal(btn("https://x.com/messages/123-456", "Send"))).toBe("adapter:x:direct_message");
    expect(klass(btn("https://x.com/messages/123-456", "Send", { ...composer, role: "shortcut" }))).toBe("send");
  });
  it("account settings and deactivation", () => {
    expect(klass(btn("https://x.com/settings/password", "Save"))).toBe("account_security");
    expect(klass(btn("https://x.com/settings/security", "Turn on"))).toBe("account_security");
    expect(klass(btn("https://x.com/settings/deactivate", "Deactivate"))).toBe("delete");
  });
  it("refuses: Like, Follow, a Send outside messages, settings navigation, look-alike host", () => {
    expect(klass(btn("https://x.com/home", "Like"))).toBeNull();
    expect(klass(btn("https://x.com/someone", "Follow"))).toBeNull();
    expect(klass(btn("https://x.com/explore", "Send"))).toBeNull();
    expect(klass(btn("https://x.com/settings/password", "Forgot password?"))).toBeNull();
    expect(klass(btn("https://x.com.evil.test/settings/password", "Save"))).toBeNull();
    expect(klass(btn("https://max.com/home", "Post", composer))).toBe("send"); // generic fallback
    expect(cls(btn("https://max.com/home", "Post", composer)).source).toBe("heuristic");
  });
});

describe("Reddit", () => {
  it("new Reddit: post, comment and chat", () => {
    expect(signal(btn("https://www.reddit.com/r/test/submit", "Post"))).toBe("adapter:reddit:post");
    expect(signal(btn("https://www.reddit.com/r/test/comments/abc/title/", "Comment", composer))).toBe("adapter:reddit:comment");
    expect(klass(btn("https://chat.reddit.com/room/!abc:reddit.com", "Send"))).toBe("send");
    expect(klass(btn("https://www.reddit.com/message/compose/", "Send"))).toBe("send");
  });
  it("old Reddit forms: comment, submit, private message", () => {
    const old = (path: string, target: string) => formOf(`https://old.reddit.com${path}`, [field("text", "text", "textarea")], "save", `https://old.reddit.com${target}`);
    expect(signal(old("/r/test/comments/abc/title/", "/api/comment"))).toBe("adapter:reddit:comment");
    expect(signal(old("/r/test/submit", "/api/submit"))).toBe("adapter:reddit:post");
    expect(klass(old("/message/compose", "/api/compose"))).toBe("send");
  });
  it("settings and account deletion", () => {
    expect(klass(btn("https://www.reddit.com/settings/account", "Save"))).toBe("account_security");
    expect(klass(btn("https://www.reddit.com/settings/account", "Delete account"))).toBe("delete");
    expect(klass(btn("https://old.reddit.com/prefs/update", "Save changes"))).toBe("account_security");
  });
  it("refuses: Upvote, Join, Reply that opens, other hosts, settings navigation", () => {
    expect(klass(btn("https://www.reddit.com/r/test/comments/abc/t/", "Join"))).toBeNull();
    expect(klass(btn("https://www.reddit.com/r/test/comments/abc/t/", "Share"))).toBeNull();
    expect(klass(btn("https://www.reddit.com/settings/account", "Learn more"))).toBeNull();
    expect(klass(btn("https://redditmirror.test/settings/account", "Save"))).toBeNull();
    expect(klass(btn("https://www.reddit.com/r/test/", "Post"))).toBeNull();
  });
});

describe("Apple ID", () => {
  const acct = "https://account.apple.com/account/manage/section/security";
  it("security settings", () => {
    expect(signal(btn(acct, "Change Password"))).toBe("adapter:apple_id:security_settings");
    expect(klass(btn(acct, "Add a Trusted Phone Number"))).toBe("account_security");
    expect(klass(btn("https://appleid.apple.com/account/manage", "Turn Off Two-Factor Authentication"))).toBe("account_security");
    expect(klass(btn("https://appleid.apple.com/account/manage", "Generate an app-specific password"))).toBe("account_security");
    expect(klass(btn(acct, "Save"))).toBe("account_security");
    expect(klass(btn("https://iforgot.apple.com/password/verify/appleid", "Continue"))).toBe("account_security");
  });
  it("payment: a method change is account security, paying a balance is a payment", () => {
    expect(signal(btn("https://account.apple.com/account/manage/section/payment", "Add Payment Method"))).toBe("adapter:apple_id:payment_method");
    expect(klass(btn("https://account.apple.com/account/manage/section/payment", "Remove Payment Method"))).toBe("account_security");
    expect(klass(btn("https://account.apple.com/account/manage/section/payment", "Pay Balance"))).toBe("payment");
    expect(klass(btn("https://privacy.apple.com/account", "Request to delete your account"))).toBe("delete");
  });
  it("refuses: Edit and Sign Out, Done on the personal information pane, other hosts", () => {
    expect(klass(btn("https://account.apple.com/account/manage", "Sign Out"))).toBeNull();
    expect(klass(btn("https://account.apple.com/account/manage/section/name", "Done"))).toBeNull();
    expect(klass(btn("https://support.apple.com/en-us/HT204915", "Change Password"))).toBe("account_security"); // generic label, not the adapter
    expect(cls(btn("https://support.apple.com/en-us/HT204915", "Change Password")).source).toBe("heuristic");
    expect(klass(btn("https://appleid.apple.com.evil.test/account/manage", "Add Payment Method"))).toBeNull();
  });
});

describe("AWS console", () => {
  const iam = "https://us-east-1.console.aws.amazon.com/iam/home?region=us-east-1#/users";
  it("IAM: users, access keys, policies, roles", () => {
    expect(signal(btn(iam, "Create user"))).toBe("adapter:aws_console:iam_change");
    expect(klass(btn("https://us-east-1.console.aws.amazon.com/iam/home#/users/details/ci?section=security_credentials", "Create access key"))).toBe("account_security");
    expect(klass(btn("https://console.aws.amazon.com/iamv2/home#/policies", "Create policy"))).toBe("account_security");
    expect(klass(btn("https://console.aws.amazon.com/iam/home#/roles", "Attach policies"))).toBe("account_security");
    expect(klass(btn("https://console.aws.amazon.com/iam/home#/users/details/ci", "Add permissions"))).toBe("account_security");
    expect(klass(btn(iam, "Delete"))).toBe("delete");
    expect(klass(btn("https://console.aws.amazon.com/iam/home#/security_credentials", "Make inactive"))).toBe("account_security");
  });
  it("deleting and terminating resources", () => {
    expect(signal(btn("https://us-west-2.console.aws.amazon.com/s3/buckets?region=us-west-2", "Delete bucket"))).toBe("adapter:aws_console:delete_resource");
    expect(klass(btn("https://eu-west-1.console.aws.amazon.com/ec2/home?region=eu-west-1#Instances:", "Terminate (delete) instance"))).toBe("delete");
    expect(klass(btn("https://console.aws.amazon.com/s3/buckets", "Empty"))).toBe("delete");
    expect(klass(btn("https://console.aws.amazon.com/cloudformation/home", "Delete stack"))).toBe("delete");
    expect(klass(btn("https://console.aws.amazon.com/rds/home", "Delete"))).toBe("delete");
  });
  it("billing: payment methods, paying, closing the account", () => {
    expect(klass(btn("https://us-east-1.console.aws.amazon.com/billing/home#/paymentpreferences", "Add payment method"))).toBe("account_security");
    expect(klass(btn("https://us-east-1.console.aws.amazon.com/billing/home#/paymentpreferences", "Make default"))).toBe("account_security");
    expect(klass(btn("https://console.aws.amazon.com/billing/home#/bills", "Pay now"))).toBe("payment");
    expect(klass(btn("https://console.aws.amazon.com/billing/home#/account", "Close account"))).toBe("delete");
  });
  it("refuses: View, Cancel, Next, Create bucket, IAM list navigation, other hosts", () => {
    expect(klass(btn(iam, "Cancel"))).toBeNull();
    expect(klass(btn(iam, "Next"))).toBeNull();
    expect(klass(btn("https://console.aws.amazon.com/iam/home#/users", "View user"))).toBeNull();
    expect(klass(btn("https://console.aws.amazon.com/s3/buckets", "Create bucket"))).toBeNull();
    expect(klass(btn("https://console.aws.amazon.com/billing/home#/bills", "Download invoice"))).toBeNull();
    expect(klass(btn("https://aws.amazon.com/iam/", "Create user"))).toBeNull();
    expect(klass(btn("https://console.aws.amazon.com.evil.test/iam/home#/users", "Create access key"))).toBe("account_security"); // generic label
    expect(cls(btn("https://console.aws.amazon.com.evil.test/iam/home#/users", "Create user")).source).toBeNull();
  });
});

describe("Google Drive", () => {
  const doc = "https://docs.google.com/document/d/1AbC/edit";
  const shareField = field("Add people, groups, spaces and calendar events", "peoplepicker", "text");
  it("the sharing dialog: Send, Share, Share anyway, Done", () => {
    expect(signal(btn("https://drive.google.com/drive/my-drive", "Send", { formFields: [shareField] }))).toBe("adapter:google_drive:drive_share_people");
    expect(klass(btn(doc, "Share", { formFields: [shareField] }))).toBe("send");
    expect(klass(btn(doc, "Share anyway"))).toBe("send");
    expect(klass(btn(doc, "Send"))).toBe("send");
  });
  it("general access: anyone with the link is account security", () => {
    expect(signal(btn(doc, "Anyone with the link", { role: "option" }))).toBe("adapter:google_drive:drive_public_link");
    expect(klass(btn("https://drive.google.com/drive/folders/1", "Change to anyone with the link"))).toBe("account_security");
    expect(klass(btn("https://docs.google.com/spreadsheets/d/1/edit", "Anyone on the internet"))).toBe("account_security");
  });
  it("refuses: the toolbar Share (opens the dialog), Restricted, org-only access, Copy link, Cancel", () => {
    expect(klass(btn(doc, "Share"))).toBeNull();
    expect(klass(btn(doc, "Restricted", { role: "option" }))).toBeNull();
    expect(klass(btn(doc, "Anyone in Acme Inc with the link", { role: "option" }))).toBeNull();
    expect(klass(btn(doc, "Copy link"))).toBeNull();
    expect(klass(btn(doc, "Cancel"))).toBeNull();
    expect(klass(btn("https://drive.google.com.evil.test/drive", "Anyone with the link"))).toBeNull();
  });
  it("a form submit with a people field is a share; delete forever is a delete", () => {
    expect(klass(formOf("https://drive.google.com/drive/my-drive", [shareField], "Send"))).toBe("send");
    expect(klass(btn("https://drive.google.com/drive/trash", "Delete forever"))).toBe("delete");
  });
});

describe("Microsoft 365 sharing", () => {
  const share = "https://contoso-my.sharepoint.com/personal/jo_contoso_com/_layouts/15/onedrive.aspx";
  const people = field("Add a name, group, or email", "people");
  it("Send in the share dialog, Grant access, Send link", () => {
    expect(signal(btn(share, "Send", { formFields: [people] }))).toBe("adapter:microsoft365_sharing:m365_share_people");
    expect(klass(btn("https://onedrive.live.com/?id=root", "Grant access", { formFields: [field("Enter a name or email address")] }))).toBe("send");
    expect(klass(btn("https://contoso.sharepoint.com/sites/team/Shared%20Documents/Forms/AllItems.aspx", "Send link"))).toBe("send");
  });
  it("link settings: anyone with the link is account security", () => {
    expect(klass(btn(share, "Anyone with the link can edit", { role: "radio" }))).toBe("account_security");
    expect(klass(btn("https://onedrive.live.com/?id=root", "Anyone"))).toBe("account_security");
    expect(klass(btn(share, "Anyone with the link", { role: "menuitemradio" }))).toBe("account_security");
  });
  it("refuses: People in Contoso, Specific people, Copy link, Stop sharing, Cancel, other hosts", () => {
    expect(klass(btn(share, "People in Contoso with the link"))).toBeNull();
    expect(klass(btn(share, "Specific people"))).toBeNull();
    expect(klass(btn(share, "Copy link"))).toBeNull();
    expect(klass(btn(share, "Stop sharing"))).toBeNull();
    expect(klass(btn(share, "Cancel"))).toBeNull();
    expect(klass(btn("https://sharepoint.com.evil.test/x", "Anyone with the link"))).toBeNull();
    expect(klass(btn("https://notsharepoint.com/x", "Send link"))).toBeNull();
  });
  it("Recycle bin purge is a delete", () => {
    expect(klass(btn("https://onedrive.live.com/?id=recycle", "Empty recycle bin"))).toBe("delete");
  });
});

describe("GitHub repository settings", () => {
  const repo = "https://github.com/acme/api/settings";
  it("delete, archive, transfer and visibility", () => {
    expect(klass(btn(repo, "Change visibility"))).toBe("delete");
    expect(klass(btn(repo, "Make private"))).toBe("delete");
    expect(klass(btn(repo, "I want to make this repository public"))).toBe("delete");
    expect(klass(btn(repo, "I understand, change repository visibility."))).toBe("delete");
    expect(klass(btn(repo, "Archive this repository"))).toBe("delete");
    expect(klass(btn(repo, "Transfer ownership"))).toBe("delete");
    expect(signal(btn(repo, "Delete this repository"))).toBe("adapter:github:destructive_setting");
  });
  it("forms are recognised by their target, whatever the button says", () => {
    expect(klass(formOf(repo, [], "Proceed", "https://github.com/acme/api/settings/delete"))).toBe("delete");
    expect(klass(formOf(repo, [], "OK", "https://github.com/acme/api/settings/change_visibility"))).toBe("delete");
    expect(klass(formOf(repo, [], "OK", "https://github.com/acme/api/settings/transfer"))).toBe("delete");
  });
  it("deploy keys and secrets", () => {
    expect(signal(btn("https://github.com/acme/api/settings/keys/new", "Add key"))).toBe("adapter:github:deploy_key");
    expect(klass(btn("https://github.com/acme/api/settings/keys", "Delete"))).toBe("account_security");
    expect(signal(btn("https://github.com/acme/api/settings/secrets/actions/new", "Add secret"))).toBe("adapter:github:secrets");
    expect(klass(btn("https://github.com/acme/api/settings/secrets/dependabot", "Remove secret"))).toBe("account_security");
    expect(klass(btn("https://github.com/acme/api/settings/variables/actions/new", "Add variable"))).toBe("account_security");
    expect(klass(btn("https://github.com/acme/api/settings/environments/123/edit", "Add secret"))).toBe("account_security");
    expect(klass(btn("https://github.com/organizations/acme/settings/secrets/actions/new", "Add secret"))).toBe("account_security");
    expect(klass(formOf("https://github.com/acme/api/settings/keys/new", [field("Key")], "x", "https://github.com/acme/api/settings/keys"))).toBe("account_security");
  });
  it("refuses: Star, Fork, Edit description in settings, Cancel, navigation, other hosts and paths", () => {
    expect(klass(btn("https://github.com/acme/api", "Fork"))).toBeNull();
    expect(klass(btn(repo, "Cancel"))).toBeNull();
    expect(klass(btn("https://github.com/acme/api/settings/keys", "Learn more"))).toBeNull();
    expect(klass(btn("https://github.com/acme/api/settings/secrets/actions", "New repository secret"))).toBeNull();
    expect(klass(btn("https://github.com/acme/api/issues/new", "Make private"))).toBeNull();
    expect(klass(btn("https://github.example.test/acme/api/settings", "Change visibility"))).toBeNull();
    expect(klass(btn("https://gist.github.com/acme/abc", "Delete"))).toBeNull();
  });
});

describe("adapter coverage", () => {
  it("every new adapter has hosts and an id once, and none covers a test host", () => {
    const ids = ADAPTERS.map((a) => a.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ["slack", "linkedin", "x", "reddit", "google_drive", "microsoft365_sharing", "apple_id", "aws_console"]) expect(ids).toContain(id);
    for (const a of ADAPTERS) for (const h of a.hosts) expect(h.endsWith(".test")).toBe(false);
  });
  it("ignores navigations and downloads", () => {
    for (const a of ADAPTERS) {
      expect(a.classify({ kind: "download", url: "https://slack.com/x.exe", filename: "x.exe", mime: "" })).toBeNull();
      expect(a.classify({ kind: "navigate", tabId: 1, frameId: 0, url: "https://console.aws.amazon.com/iam/home", resourceType: "main_frame" })).toBeNull();
    }
  });
});
