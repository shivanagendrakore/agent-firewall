/**
 * The email guard's interfaces for the parts that are not in this build
 * (connected mailboxes and the review flow). They are fixed here so the
 * detector, the filter, the review store and the CLI already speak to them:
 *
 * - `MailAccount`: a mailbox the person connects (`mail/accounts.json` in the
 *   protected data directory). Credentials are vault references, never values.
 * - `MailBackend`: the read-only client `mail serve` and `mail audit
 *   --account` use (IMAP on `node:tls` with `BODY.PEEK[]`, so nothing is
 *   marked read; Microsoft Graph delegated with `Mail.Read`). No send.
 * - `MailboxMover`: the one write E2 needs (move to and from the quarantine
 *   folder; IMAP `UID MOVE`, or `COPY` plus `\Deleted` with no `EXPUNGE`;
 *   Graph `move` with `Prefer: IdType="ImmutableId"`).
 * - `MailReadPath`: how the MCP gateway's mail filter calls the same code the
 *   hooks call today (`filterMailResult`), with the same records.
 *
 * Nothing here opens a connection. This build never sends or fetches mail.
 */
import type { MailFilterOptions, MailFilterResult } from "../../engine/mail/filter.js";
import type { MailboxMode } from "../../engine/mail/mailbox.js";

export interface MailAccount {
  name: string;
  provider: "imap" | "graph" | "gmail-imap";
  host?: string;
  port?: number;
  user: string;
  /** A vault reference (vault://mail/<account>), never a value. */
  credential: string;
  /** Authentication-Results authserv-ids learned from the first 50 messages or configured. */
  authservIds: string[];
  guard: { mode: MailboxMode; folder: string };
}

/** One message as a backend returns it: the raw source (preferred) or the provider's structured JSON. */
export interface FetchedMessage {
  /** The provider's id (IMAP UID with UIDVALIDITY, or a Graph immutable id). */
  id: string;
  raw?: Uint8Array;
  structured?: Record<string, unknown>;
}

/** Read-only mailbox access (E1 mode 2: `mail serve`, `mail audit --account`). */
export interface MailBackend {
  readonly account: MailAccount;
  list(o: { folder?: string; since?: Date; limit: number }): Promise<FetchedMessage[]>;
  get(id: string): Promise<FetchedMessage | null>;
  /** Provider-side search; its query is egress to the provider (FW-SEND-ARGS applies when untrusted and sensitive). */
  search(query: string, limit: number): Promise<FetchedMessage[]>;
  close(): Promise<void>;
}

/** The mailbox guard's one write (E2). Implementations never delete or expunge. */
export interface MailboxMover {
  ensureFolder(name: string): Promise<void>;
  move(id: string, folder: string): Promise<{ newId: string }>;
  /** Release: back to the inbox. */
  restore(id: string): Promise<{ newId: string }>;
}

/** The read path as the gateway will call it: the hooks' filter, with the gateway's records. */
export type MailReadPath = (result: unknown, opts: MailFilterOptions) => MailFilterResult;
