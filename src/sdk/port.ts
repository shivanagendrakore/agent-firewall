/**
 * The surface the framework integrations need from a guard (docs/library.md, "Remote guard"). Both the
 * in-process guard (createGuard, synchronous) and the remote guard (createRemoteGuard, which asks the
 * local API sidecar and so answers with promises) fit it, so one integration serves either. Integrations
 * await every call; awaiting a plain value is a no-op. Browser-safe: types only.
 */

import type { ApprovalAnswer, Authorization, GuardVerdict, ResultNote, ResultOptions, ToolCall } from "./types.js";

/** What every guard's decision carries, and all an integration reads from one. */
export interface DecisionCore {
  /** Correlates the decision with its log entry and an approval. */
  id: string;
  verdict: GuardVerdict;
  /** The call as the host gave it. */
  call: ToolCall;
  /** Stable rule ids, most severe first. */
  rules: string[];
  reasons: string[];
  /** One text for the person and the model ("" when allowed). */
  message: string;
  /** What an approval binds to. */
  actionHash: string;
  /** Set when the verdict is "hold". */
  held?: { id: string };
}

export type MaybePromise<T> = T | Promise<T>;

/** An answer to an ask, normalized. */
export interface ApprovalOutcome {
  approved: boolean;
  by?: string;
  note?: string;
}

/** A guard as the integrations use it. `Guard` and `RemoteGuard` both are one. */
export interface GuardPort<D extends DecisionCore = DecisionCore> {
  readonly session: string;
  /** A preview: records nothing. */
  check(call: ToolCall): MaybePromise<D>;
  /** Decides a call and records it. */
  decide(call: ToolCall): MaybePromise<D>;
  /** decide(), then a person's answer for an ask. Only an explicit yes allows. */
  authorize(call: ToolCall): Promise<Authorization<D>>;
  /** Puts one of this guard's asks to its person and records the answer. */
  requestApproval(decision: D): Promise<ApprovalOutcome>;
  /** Records a person's answer to an ask a framework put to them. */
  approveAsked(decision: D, answer: ApprovalAnswer): MaybePromise<ApprovalOutcome>;
  /** Records what a tool that ran returned. */
  recordResult(call: ToolCall, output: unknown, options?: ResultOptions): MaybePromise<ResultNote>;
  /** What the person typed. */
  recordPrompt(text: string): MaybePromise<void>;
}
