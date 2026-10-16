# Data usage disclosures (Web Store Privacy practices form)

The dashboard asks which user data types the extension collects, then three
certifications. The Chrome Web Store says disclosure is required "even when data
is processed or stored locally on a user's device"
(<https://developer.chrome.com/docs/webstore/program-policies/user-data-faq>).

Handled means the extension reads it on the device; nothing is transmitted.

## Data types

| Category | Check it? | Why / what exactly |
|---|---|---|
| Personally identifiable information | **Yes** | The leak guard reads form values, pasted text and displayed strings (names, email addresses, national IDs) in memory to detect them moving to another site. Fingerprints (one-way hashes) are kept for the agent session. A held action also keeps a masked preview for up to 5 minutes in memory-only session storage: an ordinary value's first three characters and its length, a card or ID number's last four digits. Not sent. |
| Health information | **Yes (conservative)** | A health-record site (for example mychart.org) is on the bundled sensitive-sites list, and the extension scans pages and form values there in memory like any other page. It does not look for health data as such. Not sent. |
| Financial and payment information | **Yes** | Detects card numbers (Luhn) and IBANs typed or pasted, and holds purchases. The form digest kept for a pending approval is a one-way hash; its field previews show a card number or IBAN as its last four digits and a card security code fully masked. A held leak keeps the finding's first four and last two characters for the approval card (session storage, up to 5 minutes). |
| Authentication information | **Yes** | Scans for secrets (keys, tokens, private keys, passwords in form fields and one-time codes) to stop them going to a new site. Fingerprints are kept for the session. A held secret keeps its first four and last two characters, in memory-only session storage, for up to 5 minutes. Not sent. |
| Personal communications | **Yes (conservative)** | Reads text of pages and compose fields (mail, chat) in memory to scan for hidden instructions and gate sends. Not stored. |
| Location | No | No geolocation or IP location is read. |
| Web history | **Yes** | Navigation events and URLs are scanned; the local log keeps the registrable domain of a held action for 30 days. A pending approval keeps the full address of the page the action came from, and a held download's full address, in memory-only session storage for up to 5 minutes. A blocked navigation's approval keeps the host, the amount of data and a salted hash of the address; the address itself is held in memory-only session storage until the tab moves on (at most 5 minutes) so an approved navigation can be reopened. Not sent anywhere. |
| User activity | **Yes** | Clicks, keystrokes in fields, pastes, uploads and downloads are observed to apply the gate. Only the verdict and action class are logged. A pending approval keeps masked previews of field values: an ordinary value's first three characters and its length; passwords, one-time codes and card security codes fully masked; card and ID numbers as their last four digits; secret-looking values hidden. |
| Website content | **Yes** | The core function: page text, attributes and DOM are scanned in memory. Not stored (except the opt-in 200-character evidence snippet of hidden text that got a page quarantined, kept in the local log only with "keep evidence" on). |

## Certifications (all three should be checked, and are true only if they stay true)

1. I do not sell or transfer user data to third parties, outside of the approved
   use cases. **True**: no data leaves the device.
2. I do not use or transfer user data for purposes that are unrelated to my
   item's single purpose. **True**.
3. I do not use or transfer user data to determine creditworthiness or for
   lending purposes. **True**.

## Other fields

- **Remote code:** No remote code. See `permissions-justification.md`.
- **Privacy policy URL:** the hosted `privacy-policy.md`.
- **Contact email (dashboard account):** set in the developer
  account; the policy contact is security@launchsafe.com.
- **Transmission:** none off the device. The extension's own requests are only
  the ones the person approves (re-downloading a held file from its site,
  reopening a held address). The optional native link (off until the person
  turns it on) passes log entries (domain, action class, verdict, rule ids, event codes, a
  salted hash; up to 500 earlier entries on connect), a taint flag and approval
  requests (each with the site's domain and a label of at most 200 characters
  that can come from the page; for an upload, the label includes the chosen file
  names) to the LaunchSafe firewall on the same computer over native messaging,
  never over the network. The firewall can send back an approve or deny for a
  pending approval. If a future feature transmits anything off the device
  (phone approval relay), these answers, the policy and the listing change
  first.

## Settings the person controls (for reviewers)

Retention (1 to 365 days), keep evidence (off by default), webdriver
detection, the always-on classes, and the trusted and sensitive site lists, all
in the side panel and stored in `chrome.storage.local` on the device (not
synced). While agent mode is on, changes that loosen protection are refused.
