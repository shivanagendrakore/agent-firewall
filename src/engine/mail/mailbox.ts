/**
 * Mailbox-side quarantine, decided (email guard): what the
 * local mailbox guard does with one scanned message. The guard itself (IMAP
 * IDLE/MOVE, Microsoft Graph delegated polling) is not in this build; this is
 * the pure decision it will run, so the rule is fixed and tested before any
 * code can move a person's mail.
 *
 * On by default in log mode: the mailbox guard starts in `log` mode. It records what
 * it would move and moves nothing until the person sets `enforce`. Moving
 * mail changes what the person sees, so false positives cost more than on the
 * agent's read path; and a message the parser could not read is logged, never
 * moved (moving on a parser bug would hide real mail).
 *
 * Pure: no I/O.
 */
import type { MailScan } from "./detect.js";

export type MailboxMode = "off" | "log" | "enforce";

export type MailboxAction =
  /** Leave the message where it is (and say why). */
  | { action: "none"; why: string }
  /** Log mode: record that enforce would move it; move nothing. */
  | { action: "would_move"; folder: string; why: string }
  /** Enforce mode: move it to the quarantine folder. */
  | { action: "move"; folder: string; why: string };

export const QUARANTINE_FOLDER = "LaunchSafe Quarantine";

/** The mailbox guard's decision for one scanned message. */
export function mailboxAction(scan: Pick<MailScan, "verdict" | "reasons" | "released">, mode: MailboxMode, folder = QUARANTINE_FOLDER): MailboxAction {
  if (mode === "off") return { action: "none", why: "the mailbox guard is off" };
  if (scan.released) return { action: "none", why: "the person released this message" };
  if (scan.verdict !== "quarantine") return { action: "none", why: `verdict ${scan.verdict}` };
  // Only the content rules move mail; a message that could not be read stays (logged).
  const content = scan.reasons.filter((r) => r !== "scan_incomplete" && r !== "scan_failed");
  if (content.length === 0) return { action: "none", why: `not fully read (${scan.reasons.join(", ")}); logged, never moved` };
  const why = `withheld by ${content.join(", ")}`;
  return mode === "enforce" ? { action: "move", folder, why } : { action: "would_move", folder, why };
}
