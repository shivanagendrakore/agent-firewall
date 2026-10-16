/**
 * Types of the remote guard (docs/library.md, "Remote guard"): the client of the local API sidecar
 * (`launchsafe-firewall serve --api`, docs/api-v0.md). Types only.
 */

import type { DecisionCore } from "./port.js";
import type { Authorization, ResultNote, ToolSpec } from "./types.js";

/** How a call is sent (docs/api-v0.md, "Decide request"). */
export type RemoteFormat = "native" | "engine" | "mcp";

export interface RemoteGuardOptions {
  /** The sidecar's unix socket. Default: `<firewall home>/api.sock` (LAUNCHSAFE_FIREWALL_HOME or ~/.launchsafe-firewall). */
  socketPath?: string;
  /**
   * Instead of the socket: `http://127.0.0.1:<port>` or `http://localhost:<port>` (never another host). Needs
   * `allowTcp: true`: any local process can listen on a port first and answer "allow", and it would receive the
   * token too; the socket is checked (owned by this user, mode 0600) before anything is sent.
   */
  baseUrl?: string;
  /** I7: accept the loopback TCP transport (`baseUrl`) and its risk. Default false: baseUrl is refused. */
  allowTcp?: boolean;
  /** This agent's token (`launchsafe-firewall api token add <agentId>`). */
  token?: string;
  /**
   * A token with the "prompt" role (`api token add <agentId> --role prompt`), sent with recordPrompt() only.
   * Without it, prompts go with `token` and the sidecar only logs them: the destinations and task scope a
   * prompt names apply only from a token made for what the person typed (docs/api.md, "Token roles").
   */
  promptToken?: string;
  /** The session id (namespaced by agent in the sidecar). Default: a random id. */
  session?: string;
  /** How long one request may take before it counts as unreachable (ms). Default 250. A timeout is never an allow. */
  timeoutMs?: number;
  /**
   * When the sidecar cannot be reached, times out, answers 503 (overloaded) or 429: let a read-only tool (in
   * `tools`: kind "read", results "trusted", privateData false) go ahead. Default true. Everything else is
   * denied, and so is every call, reads included, after a 500 or any other 5xx (the sidecar failed on the request).
   */
  failOpenReads?: boolean;
  /** Whether a person can answer an ask now. False: asks become holds. Default true. */
  attended?: boolean;
  /**
   * Permission modes that mean no one can answer (a call's `permissionMode`): the call is sent with
   * `attended: false`. Default ["dontAsk", "bypassPermissions", "auto"], the policy's default `unattendedPermissionModes`.
   */
  unattendedPermissionModes?: string[];
  /** Project roots, sent as `context.workspace`. */
  workspace?: string | string[];
  /** Sent as `context.cwd`. */
  cwd?: string;
  /**
   * The agent's tool specs, as the library takes them. Client-side knowledge only: they decide which
   * tools are read-only when the sidecar cannot answer, and that a declared tool is sent as "native".
   * The sidecar judges by the registry a person set (`launchsafe-firewall api tools set`), never by these.
   */
  tools?: Record<string, ToolSpec>;
  /** The format for a tool that is not in `tools` and not an `mcp__` tool. Default "native" (the registry). */
  format?: "native" | "engine";
  /** How long authorize() / requestApproval() wait for a person's approval in the firewall's queue (ms). Default 300000. */
  approvalTimeoutMs?: number;
  /** How often an approval is polled (ms). Default 1000. */
  approvalPollMs?: number;
  /** The largest response accepted (bytes). Default 2 MiB. */
  maxResponseBytes?: number;
  /** Told about each ask and hold (show the person where to approve: the approval id). Informs only. */
  onPending?: (decision: RemoteDecision) => void;
  /** Told about each failure talking to the sidecar. Default: console.warn. */
  onError?: (message: string) => void;
}

/** One rule of a sidecar decision. */
export interface RemoteRule {
  id: string;
  outcome: string;
  reason: string;
}

/** The session as the sidecar reports it. */
export interface RemoteSessionState {
  untrusted: boolean;
  untrustedBecause: string[];
  holdsPrivateData: boolean;
  privateBecause: string[];
  /** Not in the v0 contract; kept when the sidecar sends it. */
  namedDestinations?: string[];
}

export interface RemoteSessionSnapshot extends RemoteSessionState {
  session: string;
}

export type RemoteApprovalStatus = "pending" | "approved" | "denied" | "expired";

/** Why the guard decided on its own, without the sidecar's decision (the fail-closed table). */
export interface RemoteFailure {
  kind: "unavailable" | "timeout" | "server" | "rate-limited" | "api-error" | "protocol";
  /** The HTTP status, when there was one. */
  status?: number;
  detail: string;
}

/** A decision: the sidecar's, or the guard's own when the sidecar could not give one (`failure`). */
export interface RemoteDecision extends DecisionCore {
  /** The sidecar's id (recordResult sends it); null for a decision the guard made itself. */
  decisionId: string | null;
  /** How the call was sent. */
  format: RemoteFormat;
  /** The sidecar's rules with their outcome and reason. */
  ruleDetails: RemoteRule[];
  /** The session after this decision (absent for the guard's own decisions). */
  session?: RemoteSessionState;
  /** For a hold: the item in the firewall's queue. A recorded ask has none (the contract's rule); authorize() and a yes to approveAsked() queue it then. */
  approval?: { id: string; status: RemoteApprovalStatus };
  engine?: { version: string };
  log?: { seq: number; hash: string };
  /** Set when the sidecar could not be used: the verdict is the fail-closed table's. */
  failure?: RemoteFailure;
  /** What went wrong besides (a report that could not be sent, an onPending that threw). */
  problems?: string[];
}

export interface RemoteAuthorization extends Authorization<RemoteDecision> {
  /** For an approved ask: the retry's decision (allow), whose id recordResult uses. */
  retry?: RemoteDecision;
}

export interface ApprovalWait {
  id: string;
  /** "pending": not decided before the wait ended (or the wait failed: `error`). */
  status: RemoteApprovalStatus;
  error?: string;
}

export interface RemoteResultNote extends ResultNote {
  /** Whether the sidecar recorded it (else it is kept and sent before the next decision). */
  recorded: boolean;
  problems?: string[];
}

export interface RemoteRecorded {
  recorded: boolean;
  problems?: string[];
}

export interface RemoteHealth {
  ok: boolean;
  engine: { version: string };
}
