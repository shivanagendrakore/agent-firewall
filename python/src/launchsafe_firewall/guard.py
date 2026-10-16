"""`Guard` and `AsyncGuard`: the integrator-facing API.

    guard = Guard(tools=registry["tools"])
    auth = guard.authorize("send_email", {"to": "x@y.com"})
    if auth.allowed:
        output = send_email(...)
        guard.record_result(auth, output)
    else:
        give_the_model(auth.message)

`authorize()` never raises: an unreachable or failing sidecar is turned into a decision by the
contract's fail-closed table. Read-only tools (registry kind `read`, results trusted, no private
data, declared to the guard through `tools`) follow `fail_open_reads`; everything else is denied.

Reports (results and untrusted inputs) keep the session's state true. One that cannot be delivered
because the sidecar is away is kept and sent before the next decision; one the sidecar refuses
(a 4xx; a 413 after one resend cut smaller) cannot be resent, so from then on every non-read call
of this guard is denied.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Mapping
from dataclasses import replace
from types import TracebackType
from typing import Any

from ._core import (
    APPROVAL_POLL_MAX,
    APPROVAL_POLL_START,
    DEFAULT_APPROVAL_WAIT,
    MAX_PENDING_REPORTS,
    Authorization,
    PendingReport,
    ReportOutcome,
    ToolSpecs,
    after_queue,
    after_retry,
    bound,
    dry_run_result,
    fail_closed,
    from_decision,
    hold_without_approval,
    is_read_only,
    is_report_retryable,
    is_retryable,
    is_too_large,
    lost_state,
    queue_hold,
    random_session,
    rate_limit_pause,
    refused,
    safe_text,
    unserialisable,
    with_approval_status,
)
from .client import AsyncClient, Client, new_key
from .errors import FirewallAPIError, FirewallProtocolError, FirewallRateLimited, Problem
from .formats import native
from .types import Action, ApprovalRef, ApprovalState, DecideContext, ModelUsage, SessionInfo, Traffic


def _action(tool: str | Action, tool_input: Mapping[str, Any] | None, call_id: str | None) -> Action:
    if isinstance(tool, Action):
        if tool_input is not None:
            raise ValueError("pass the input inside the Action, not beside it")
        return tool
    return native(tool, tool_input, call_id=call_id)


class _GuardBase:
    def __init__(
        self,
        *,
        session: str | None,
        tools: ToolSpecs | None,
        fail_open_reads: bool,
        attended: bool | None,
        workspace: str | list[str] | tuple[str, ...] | None,
        cwd: str | None,
        approval_timeout: float,
        wait_for_approval: bool,
        traffic: Traffic | None = None,
    ) -> None:
        self.session = session or random_session()
        self.tools: ToolSpecs = dict(tools or {})
        self.fail_open_reads = fail_open_reads
        ws = (workspace,) if isinstance(workspace, str) else (tuple(workspace) if workspace is not None else None)
        self.context = DecideContext(attended=attended, workspace=ws, cwd=cwd, traffic=traffic)
        self.approval_timeout = approval_timeout
        self.wait_for_approval = wait_for_approval
        self._pending: list[PendingReport] = []
        self._lost: str | None = None
        self._paused_until = 0.0

    @property
    def state_lost(self) -> str | None:
        """Why this guard denies every non-read call (a report was refused or dropped), or None."""
        return self._lost

    def _read_only(self, action: Action) -> bool:
        return is_read_only(action, self.tools)

    def _precheck(self, action: Action) -> Authorization | None:
        """A decision made without calling the sidecar: lost state, or a rate-limit pause."""
        read_only = self._read_only(action)
        if self._lost is not None and not read_only:
            return lost_state(action, self._lost)
        if time.monotonic() < self._paused_until:
            err = FirewallRateLimited(429, _paused_problem(), None)
            return fail_closed(err, action, read_only, self.fail_open_reads)
        return None

    def _ask_wait(self, per_call: float | None) -> float:
        """Seconds an ask waits in the firewall's queue (0: not at all). A hold uses `approval_timeout` only."""
        if per_call is not None:
            return per_call
        if self.approval_timeout > 0:
            return self.approval_timeout
        return DEFAULT_APPROVAL_WAIT if self.wait_for_approval else 0.0

    def _waits(self, per_call: float | None, max_wait: float | None) -> tuple[float, float]:
        """(seconds an ask waits in the queue, seconds a hold waits), each at most `max_wait`."""
        ask = self._ask_wait(per_call)
        hold = self.approval_timeout if per_call is None else per_call
        if max_wait is not None:
            ask, hold = min(ask, max_wait), min(hold, max_wait)
        return ask, hold

    def longest_wait(self) -> float:
        """The longest an `authorize()` without per-call options may wait for a person, in seconds."""
        ask, hold = self._waits(None, None)
        return max(ask if self.wait_for_approval else 0.0, hold)

    def _unattended(self) -> DecideContext:
        return replace(self.context, attended=False)

    def _poll_failed(self, err: Exception) -> tuple[bool, float]:
        """(stop waiting, extra pause) for a failed poll: a refusal will not change by waiting; an outage might."""
        if isinstance(err, FirewallAPIError | FirewallProtocolError):
            return True, 0.0
        if isinstance(err, FirewallRateLimited):
            return False, rate_limit_pause(err)
        return not is_retryable(err), 0.0

    def _failed(self, err: BaseException, action: Action) -> Authorization:
        if isinstance(err, FirewallRateLimited):
            self._paused_until = time.monotonic() + rate_limit_pause(err)
        return fail_closed(err, action, self._read_only(action), self.fail_open_reads)

    def _flush_failed(self, err: BaseException, action: Action) -> Authorization | None:
        """The decision after the kept reports could not be sent first; None: ask the sidecar as usual.

        An outage fails closed by the table. A refused report has made the state lost by now: that
        denies a non-read call, while a read-only one still goes to the sidecar (the README's table).
        """
        if is_report_retryable(err):
            return self._failed(err, action)
        if self._read_only(action):
            return None
        return lost_state(action, self._lost or str(err))

    def _result_check(self, auth: Authorization) -> None:
        if auth.dry_run:
            raise dry_run_result()

    def _queue(self, report: PendingReport) -> None:
        self._pending.append(report)
        if len(self._pending) > MAX_PENDING_REPORTS:
            self._pending.pop(0)
            self._lost = "too many reports could not be delivered"

    def _report_failed(self, report: PendingReport, err: BaseException, queued_already: bool) -> ReportOutcome:
        if isinstance(err, FirewallRateLimited):
            self._paused_until = time.monotonic() + rate_limit_pause(err)
        if is_report_retryable(err):
            if not queued_already:
                self._queue(report)
            return ReportOutcome(recorded=False, queued=True, error=str(err))
        self._lost = f"a {report.kind} report was refused: {err}"
        return ReportOutcome(recorded=False, error=str(err))

    def _result_report(
        self, auth: Authorization, output: Any, failed: bool | None = None
    ) -> PendingReport | ReportOutcome:
        d = auth.decision
        if d is None or not auth.allowed:
            # Nothing ran under a firewall decision: a fail-open read (trusted results, no private
            # data, so nothing to taint) or a call that was not allowed.
            return ReportOutcome(recorded=False, error="no firewall decision to record this result against")
        args = {"decision_id": d.decision_id, "output": bound(output), "failed": failed}
        return PendingReport("result", args, new_key())

    @staticmethod
    def _input_report(source: str, content: Any, private: bool | None) -> PendingReport:
        return PendingReport("input", {"source": source, "content": bound(content), "private": private}, new_key())


def _paused_problem() -> Problem:
    return Problem(status=429, title="paused after a rate limit")


class Guard(_GuardBase):
    """Blocking guard over a `Client`. Thread-safe for parallel tool calls."""

    def __init__(
        self,
        client: Client | None = None,
        *,
        session: str | None = None,
        tools: ToolSpecs | None = None,
        fail_open_reads: bool = True,
        attended: bool | None = True,
        workspace: str | list[str] | tuple[str, ...] | None = None,
        cwd: str | None = None,
        approval_timeout: float = 0.0,
        wait_for_approval: bool = False,
        traffic: Traffic | None = None,
    ) -> None:
        """
        Args:
            client: the sidecar client (default: `Client()` on the default socket and token).
            session: this agent run's session id (default: a random one).
            tools: the agent's tool specs, as in the registry file the person set with
                `launchsafe-firewall api tools set` (its `"tools"` object). Used only to know which tools are
                read-only when the sidecar cannot answer; the sidecar's own registry decides.
            fail_open_reads: read-only tools run when the sidecar is unreachable, times out, answers 503
                or 429 (the contract's default; any other 5xx denies them). False: they are denied too.
            attended: whether a person can answer now (False: ask becomes hold). None: not sent.
            approval_timeout: seconds `authorize()` waits for a person to answer a hold (an ask only
                with `wait_for_approval=True`) in the firewall's queue (terminal, phone). 0: do not
                wait; the call is not allowed.
            wait_for_approval: also get an `ask` into that queue. The sidecar queues only holds, so the
                guard sends the identical call again with `attended: false` (the sidecar answers hold,
                with an approval id), waits for the approval (`approval_timeout` seconds, default 300 when
                this is on), and when it is approved decides the call once more: allowed once. Off (the
                default): an ask is not allowed and there is nothing to wait for.
            traffic: `context.traffic` of every decide: "network" for a network middleware (its token must
                be a `--traffic network` one); None (the default) leaves it out, which means "tool".
        """
        super().__init__(
            session=session,
            tools=tools,
            fail_open_reads=fail_open_reads,
            attended=attended,
            workspace=workspace,
            cwd=cwd,
            approval_timeout=approval_timeout,
            wait_for_approval=wait_for_approval,
            traffic=traffic,
        )
        self._owns_client = client is None
        self.client = client if client is not None else Client()
        # Reentrant: a failed flush holds it while it marks the report lost, and queueing takes it too.
        self._lock = threading.RLock()

    def __enter__(self) -> Guard:
        return self

    def __exit__(self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def _send(self, r: PendingReport, timeout: float | None = None) -> ReportOutcome:
        if r.kind == "result":
            res = self.client.record_result(
                self.session,
                r.args["decision_id"],
                r.args["output"],
                idempotency_key=r.key,
                timeout=timeout,
                failed=r.args.get("failed"),
            )
            return ReportOutcome(recorded=res.recorded, output=res.output)
        rec = self.client.report_input(
            self.session,
            r.args["source"],
            r.args["content"],
            private=r.args["private"],
            idempotency_key=r.key,
            timeout=timeout,
        )
        return ReportOutcome(recorded=rec.recorded)

    def _deliver(self, r: PendingReport, timeout: float | None = None) -> ReportOutcome:
        """`_send`, and after a 413 once more with the content cut smaller (not a lost state)."""
        try:
            return self._send(r, timeout)
        except Exception as e:
            if is_too_large(e) and r.shrink():
                return self._send(r, timeout)
            raise

    def _queue(self, report: PendingReport) -> None:
        with self._lock:  # never beside a flush that is taking reports off the queue
            super()._queue(report)

    def _flush(self, timeout: float | None = None) -> None:
        """Sends the reports kept from earlier, oldest first. Raises the first failure.

        `timeout`: seconds for each send (default: the client's). Before a decision it is the decide
        timeout, so parallel decisions queued behind one flush are not each kept waiting for a slow sidecar."""
        if not self._pending:
            return
        with self._lock:
            while self._pending:
                r = self._pending[0]
                try:
                    self._deliver(r, timeout)
                except Exception as e:
                    if not is_report_retryable(e):
                        self._pending.pop(0)
                        self._report_failed(r, e, queued_already=True)
                    raise
                self._pending.pop(0)

    def _report(self, r: PendingReport) -> ReportOutcome:
        try:
            self._flush()
        except BaseException as e:  # the earlier reports go first; this one waits behind them
            outcome = self._report_failed(r, e, queued_already=False)
            if not isinstance(e, Exception):
                raise  # an interruption: kept for sending again (above), but not swallowed
            return outcome
        try:
            return self._deliver(r)
        except BaseException as e:
            outcome = self._report_failed(r, e, queued_already=False)
            if not isinstance(e, Exception):
                raise
            return outcome

    def authorize(
        self,
        tool: str | Action,
        input: Mapping[str, Any] | None = None,
        *,
        call_id: str | None = None,
        approval_timeout: float | None = None,
        dry_run: bool = False,
        usage: ModelUsage | None = None,
        max_wait: float | None = None,
    ) -> Authorization:
        """Decides one call. Never raises; `allowed` is True only when the call may run now.

        `max_wait`: a cap, in seconds, on any wait for a person in this call (for a host that gives up
        on a callback after a set time); an approval still pending then is not allowed."""
        try:
            action = _action(tool, input, call_id)
        except Exception as e:
            return fail_closed(e, native(str(tool)), False, False)
        early = self._precheck(action)
        if early is not None:
            return early
        try:
            self._flush(self.client.decide_timeout)
        except Exception as e:
            stop = self._flush_failed(e, action)
            if stop is not None:
                return stop
        try:
            d = self.client.decide(self.session, action, context=self.context, dry_run=dry_run, usage=usage)
            auth = from_decision(d, action, dry_run)
        except (TypeError, ValueError) as e:  # building the request failed: the arguments are not JSON
            return unserialisable(e, action)
        except Exception as e:
            return self._failed(e, action)
        wait_ask, wait = self._waits(approval_timeout, max_wait)
        if self.wait_for_approval and not dry_run and auth.approval is None:
            if auth.verdict == "hold":
                return hold_without_approval(action)
            if auth.verdict == "ask" and wait_ask > 0:
                return self._queued_ask(auth, wait_ask)
        if dry_run or auth.verdict not in ("ask", "hold") or auth.approval is None or wait <= 0:
            return auth
        # The same tolerant polling as a queued ask: an outage or a 429 is waited out, a refusal is not.
        status, err = self._poll(auth.approval.id, wait)
        if err is not None and status != "approved":
            # Could not learn the answer: not a yes.
            return replace(auth, error=f"waiting for the approval failed: {safe_text(err)}")
        if status != "approved":
            return with_approval_status(auth, status)
        # Approved: the identical call again (same session, same action) gets allow once.
        try:
            return from_decision(self.client.decide(self.session, action, context=self.context), action)
        except Exception as e:
            return self._failed(e, action)

    def _poll(self, approval_id: str, timeout: float) -> tuple[ApprovalState, str | None]:
        """Polls the queue item with backoff until decided or `timeout`; an outage is retried, a refusal is not."""
        deadline = time.monotonic() + timeout
        interval, last = APPROVAL_POLL_START, None
        while True:
            pause = interval
            try:
                st = self.client.get_approval(approval_id)
                if st.status != "pending":
                    return st.status, None
            except Exception as e:
                stop, extra = self._poll_failed(e)
                if stop:
                    return "pending", str(e)
                last, pause = str(e), max(pause, extra)
            left = deadline - time.monotonic()
            if left <= 0:
                return "pending", last
            time.sleep(min(pause, left))
            interval = min(interval * 1.5, APPROVAL_POLL_MAX)

    def _queued_ask(self, ask: Authorization, wait: float) -> Authorization:
        """The ask has no queue item: decide the identical call as unattended (a hold), wait, decide again."""
        try:
            hold = self.client.decide(self.session, ask.action, context=self._unattended())
        except Exception as e:
            self._failed(e, ask.action)  # keeps the rate-limit pause; the result is never an allow
            return refused(ask, f"LaunchSafe Agent Firewall: the ask could not be put in the approval queue ({e})")
        bad = queue_hold(ask, hold)
        if bad is not None or hold.approval is None:
            return bad if bad is not None else hold_without_approval(ask.action)
        ref: ApprovalRef = hold.approval
        status, err = self._poll(ref.id, wait)
        denied = after_queue(ask, ref, status, err)
        if denied is not None:
            return denied
        try:
            retry = self.client.decide(self.session, ask.action, context=self.context)
        except Exception as e:
            self._failed(e, ask.action)
            return refused(
                ask, f"LaunchSafe Agent Firewall: approval {ref.id} was given, but deciding again failed ({e})", ref
            )
        return after_retry(ask, ref, retry)

    def check(self, tool: str | Action, input: Mapping[str, Any] | None = None) -> Authorization:
        """What authorize() would say now; records nothing (dryRun)."""
        return self.authorize(tool, input, dry_run=True)

    def record_result(self, auth: Authorization, output: Any, *, failed: bool | None = None) -> ReportOutcome:
        """Reports what an allowed tool returned. Give the model `outcome.output` when it is set (redacted).
        `failed=True`: the tool failed (counted toward the identical-failures spending limit).

        Raises ValueError (and sends nothing) for the Authorization of `check()`, a dry run: a programming
        error, not a failure of the firewall, so it does not touch the guard's state."""
        self._result_check(auth)
        r = self._result_report(auth, output, failed)
        return r if isinstance(r, ReportOutcome) else self._report(r)

    def report_input(self, source: str, content: Any, *, private: bool | None = None) -> ReportOutcome:
        """Untrusted content that reached the agent outside a tool call (a retrieved document, an email)."""
        return self._report(self._input_report(source, content, private))

    def record_prompt(self, text: str) -> ReportOutcome:
        """What the person typed (never model or tool text). A lost prompt only makes decisions stricter."""
        try:
            r = self.client.record_prompt(self.session, text)
            return ReportOutcome(recorded=r.recorded, applied=r.applied, detail=r.detail)
        except Exception as e:
            return ReportOutcome(recorded=False, applied=False, error=str(e))

    def state(self) -> SessionInfo:
        """The session snapshot. Raises FirewallError (it is not a decision)."""
        return self.client.get_session(self.session)


class AsyncGuard(_GuardBase):
    """asyncio guard over an `AsyncClient`; the same behaviour as `Guard`."""

    def __init__(
        self,
        client: AsyncClient | None = None,
        *,
        session: str | None = None,
        tools: ToolSpecs | None = None,
        fail_open_reads: bool = True,
        attended: bool | None = True,
        workspace: str | list[str] | tuple[str, ...] | None = None,
        cwd: str | None = None,
        approval_timeout: float = 0.0,
        wait_for_approval: bool = False,
        traffic: Traffic | None = None,
    ) -> None:
        super().__init__(
            session=session,
            tools=tools,
            fail_open_reads=fail_open_reads,
            attended=attended,
            workspace=workspace,
            cwd=cwd,
            approval_timeout=approval_timeout,
            wait_for_approval=wait_for_approval,
            traffic=traffic,
        )
        self._owns_client = client is None
        self.client = client if client is not None else AsyncClient()
        self._lock: asyncio.Lock | None = None

    async def __aenter__(self) -> AsyncGuard:
        return self

    async def __aexit__(self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def _send(self, r: PendingReport, timeout: float | None = None) -> ReportOutcome:
        if r.kind == "result":
            res = await self.client.record_result(
                self.session,
                r.args["decision_id"],
                r.args["output"],
                idempotency_key=r.key,
                timeout=timeout,
                failed=r.args.get("failed"),
            )
            return ReportOutcome(recorded=res.recorded, output=res.output)
        rec = await self.client.report_input(
            self.session,
            r.args["source"],
            r.args["content"],
            private=r.args["private"],
            idempotency_key=r.key,
            timeout=timeout,
        )
        return ReportOutcome(recorded=rec.recorded)

    async def _deliver(self, r: PendingReport, timeout: float | None = None) -> ReportOutcome:
        try:
            return await self._send(r, timeout)
        except Exception as e:
            if is_too_large(e) and r.shrink():
                return await self._send(r, timeout)
            raise

    # `_queue` needs no lock here: it does not await, so on the event loop it never runs beside a flush step.

    def _drop(self, r: PendingReport) -> None:
        """Takes `r` off the queue once handled, unless an overflow while it was awaited already evicted it
        (then the head is another, unsent report that must stay)."""
        if self._pending and self._pending[0] is r:
            self._pending.pop(0)

    async def _flush(self, timeout: float | None = None) -> None:
        if not self._pending:
            return
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            while self._pending:
                r = self._pending[0]
                try:
                    await self._deliver(r, timeout)
                except Exception as e:
                    if not is_report_retryable(e):
                        self._drop(r)
                        self._report_failed(r, e, queued_already=True)
                    raise
                self._drop(r)

    async def _report(self, r: PendingReport) -> ReportOutcome:
        try:
            await self._flush()
        except BaseException as e:  # a cancelled task too: the report is kept for sending again
            outcome = self._report_failed(r, e, queued_already=False)
            if not isinstance(e, Exception):
                raise
            return outcome
        try:
            return await self._deliver(r)
        except BaseException as e:
            outcome = self._report_failed(r, e, queued_already=False)
            if not isinstance(e, Exception):
                raise
            return outcome

    async def authorize(
        self,
        tool: str | Action,
        input: Mapping[str, Any] | None = None,
        *,
        call_id: str | None = None,
        approval_timeout: float | None = None,
        dry_run: bool = False,
        usage: ModelUsage | None = None,
        max_wait: float | None = None,
    ) -> Authorization:
        try:
            action = _action(tool, input, call_id)
        except Exception as e:
            return fail_closed(e, native(str(tool)), False, False)
        early = self._precheck(action)
        if early is not None:
            return early
        try:
            await self._flush(self.client.decide_timeout)
        except Exception as e:
            stop = self._flush_failed(e, action)
            if stop is not None:
                return stop
        try:
            d = await self.client.decide(self.session, action, context=self.context, dry_run=dry_run, usage=usage)
            auth = from_decision(d, action, dry_run)
        except (TypeError, ValueError) as e:
            return unserialisable(e, action)
        except Exception as e:
            return self._failed(e, action)
        wait_ask, wait = self._waits(approval_timeout, max_wait)
        if self.wait_for_approval and not dry_run and auth.approval is None:
            if auth.verdict == "hold":
                return hold_without_approval(action)
            if auth.verdict == "ask" and wait_ask > 0:
                return await self._queued_ask(auth, wait_ask)
        if dry_run or auth.verdict not in ("ask", "hold") or auth.approval is None or wait <= 0:
            return auth
        status, err = await self._poll(auth.approval.id, wait)
        if err is not None and status != "approved":
            return replace(auth, error=f"waiting for the approval failed: {safe_text(err)}")
        if status != "approved":
            return with_approval_status(auth, status)
        try:
            return from_decision(await self.client.decide(self.session, action, context=self.context), action)
        except Exception as e:
            return self._failed(e, action)

    async def _poll(self, approval_id: str, timeout: float) -> tuple[ApprovalState, str | None]:
        deadline = time.monotonic() + timeout
        interval, last = APPROVAL_POLL_START, None
        while True:
            pause = interval
            try:
                st = await self.client.get_approval(approval_id)
                if st.status != "pending":
                    return st.status, None
            except Exception as e:
                stop, extra = self._poll_failed(e)
                if stop:
                    return "pending", str(e)
                last, pause = str(e), max(pause, extra)
            left = deadline - time.monotonic()
            if left <= 0:
                return "pending", last
            await asyncio.sleep(min(pause, left))
            interval = min(interval * 1.5, APPROVAL_POLL_MAX)

    async def _queued_ask(self, ask: Authorization, wait: float) -> Authorization:
        try:
            hold = await self.client.decide(self.session, ask.action, context=self._unattended())
        except Exception as e:
            self._failed(e, ask.action)
            return refused(ask, f"LaunchSafe Agent Firewall: the ask could not be put in the approval queue ({e})")
        bad = queue_hold(ask, hold)
        if bad is not None or hold.approval is None:
            return bad if bad is not None else hold_without_approval(ask.action)
        ref: ApprovalRef = hold.approval
        status, err = await self._poll(ref.id, wait)
        denied = after_queue(ask, ref, status, err)
        if denied is not None:
            return denied
        try:
            retry = await self.client.decide(self.session, ask.action, context=self.context)
        except Exception as e:
            self._failed(e, ask.action)
            return refused(
                ask, f"LaunchSafe Agent Firewall: approval {ref.id} was given, but deciding again failed ({e})", ref
            )
        return after_retry(ask, ref, retry)

    async def check(self, tool: str | Action, input: Mapping[str, Any] | None = None) -> Authorization:
        return await self.authorize(tool, input, dry_run=True)

    async def record_result(self, auth: Authorization, output: Any, *, failed: bool | None = None) -> ReportOutcome:
        self._result_check(auth)
        r = self._result_report(auth, output, failed)
        return r if isinstance(r, ReportOutcome) else await self._report(r)

    async def report_input(self, source: str, content: Any, *, private: bool | None = None) -> ReportOutcome:
        return await self._report(self._input_report(source, content, private))

    async def record_prompt(self, text: str) -> ReportOutcome:
        try:
            r = await self.client.record_prompt(self.session, text)
            return ReportOutcome(recorded=r.recorded, applied=r.applied, detail=r.detail)
        except Exception as e:
            return ReportOutcome(recorded=False, applied=False, error=str(e))

    async def state(self) -> SessionInfo:
        return await self.client.get_session(self.session)
