"""What Guard and AsyncGuard share: the contract's fail-closed table as code, and small pure helpers."""

from __future__ import annotations

import json
import secrets
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any, Literal

from .errors import (
    FirewallHTTPError,
    FirewallProtocolError,
    FirewallRateLimited,
    FirewallServerError,
    FirewallUnavailable,
    FirewallUntrustedSocket,
)
from .types import Action, ApprovalRef, ApprovalState, Decision, RuleHit, Verdict

FW_UNAVAILABLE = "FW-UNAVAILABLE"
FW_RATE_LIMITED = "FW-RATE-LIMITED"
FW_API_ERROR = "FW-API-ERROR"

ToolSpecs = Mapping[str, Any]
"""The registry file's "tools" object: tool name to spec ({"kind", "results", "privateData"} or {"as", "map"})."""

# Reports whose content is bigger than this, as UTF-8 JSON bytes, are cut before sending: the sidecar
# refuses bodies over 1 MiB (413), and a refused report would leave the session's state incomplete. The
# source still taints the session.
MAX_REPORT_BYTES = 512 * 1024
# A report the sidecar still refuses as too large (413) is sent once more, cut to this.
SHRUNK_REPORT_BYTES = 64 * 1024
# Reports kept for retry while the sidecar is away; past this the session's state is marked lost.
MAX_PENDING_REPORTS = 1000
# A 429 without Retry-After: no call to the sidecar for this long (no tight retry loop).
DEFAULT_RATE_LIMIT_PAUSE = 1.0
MAX_RATE_LIMIT_PAUSE = 60.0

# `wait_for_approval=True` without an `approval_timeout`: how long an ask waits for a person (the TS guard's 5 minutes).
DEFAULT_APPROVAL_WAIT = 300.0
APPROVAL_POLL_START = 0.25
APPROVAL_POLL_MAX = 2.0

_BIDI = {0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}


def safe_text(s: str) -> str:
    """Control and bidi characters escaped (newlines kept), as the firewall's own messages are."""
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\n" or (o >= 0x20 and o != 0x7F and not (0x80 <= o < 0xA0) and o not in _BIDI):
            out.append(ch)
        else:
            out.append(f"\\u{o:04x}")
    return "".join(out)


def random_session() -> str:
    return f"sdk-{secrets.token_hex(12)}"


@dataclass(frozen=True)
class Authorization:
    """Whether a tool call may run now. Never raised: every failure is in here as a decision."""

    allowed: bool
    verdict: Verdict
    message: str
    """One text for the model and the person ("" when allowed by the firewall)."""
    action: Action
    rules: tuple[RuleHit, ...] = ()
    decision: Decision | None = None
    """The sidecar's decision; None when the SDK decided on its own because of a failure."""
    approval: ApprovalRef | None = None
    """For ask and hold: the approval in the firewall's queue (its last known status)."""
    error: str | None = None
    """What failed, when the SDK decided on its own (fail-open reads carry it too)."""
    dry_run: bool = False
    """From `check()`: a preview the sidecar did not record, so nothing may be recorded against it."""

    @property
    def decision_id(self) -> str | None:
        return self.decision.decision_id if self.decision is not None else None

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(r.id for r in self.rules)


@dataclass(frozen=True)
class ReportOutcome:
    """What a report (a result, an input, a prompt) came to. Reports never raise either."""

    recorded: bool
    output: str | None = None
    """For a result: the redacted copy the sidecar returned (give it to the model instead), if any."""
    queued: bool = False
    """Not delivered now; it is sent again before the next decision."""
    error: str | None = None
    applied: bool = True
    """For a prompt: False when the sidecar logged it but did not act on it (the token has no prompt role)."""
    detail: str | None = None
    """The sidecar's note on a report it did not apply."""


def is_read_only(action: Action, tools: ToolSpecs) -> bool:
    """The contract's read-only tool: registry kind `read`, results trusted, no private data.

    Only the host's own tools (native, openai.chat, anthropic) can be; engine and MCP calls never are
    here, because the SDK cannot see how the sidecar classifies them.
    """
    if action.format not in ("native", "openai.chat", "anthropic"):
        return False
    spec = tools.get(action.tool_name)
    if not isinstance(spec, Mapping):
        return False
    # privateData defaults to true in the registry, so only an explicit false counts.
    return spec.get("kind") == "read" and spec.get("results") == "trusted" and spec.get("privateData") is False


def from_decision(d: Decision, action: Action, dry_run: bool = False) -> Authorization:
    return Authorization(
        allowed=d.verdict == "allow",
        verdict=d.verdict,
        message=d.message,
        action=action,
        rules=d.rules,
        decision=d,
        approval=d.approval,
        dry_run=dry_run,
    )


def _describe(err: BaseException) -> str:
    if isinstance(err, FirewallHTTPError):
        p = err.problem
        text = p.title or p.detail
        return f"{err.status}{' ' + text[:120] if text else ''}"
    return str(err)[:200] or type(err).__name__


def fail_closed(err: BaseException, action: Action, read_only: bool, fail_open_reads: bool) -> Authorization:
    """The contract's fail-closed table (docs/api-v0.md, "Fail-closed (SDK side)")."""
    what = safe_text(_describe(err))
    rule: str
    if isinstance(err, FirewallRateLimited):
        rule = FW_RATE_LIMITED
        why = "the firewall is rate limiting this agent"
        retry = "try again later"
    elif isinstance(err, FirewallUnavailable | FirewallServerError):
        rule = FW_UNAVAILABLE
        why = f"the firewall could not be reached ({what})"
        retry = "try again when the firewall is running"
    else:
        rule = FW_API_ERROR
        why = f"the firewall refused the request ({what})"
        retry = "this needs a person to fix the agent's firewall setup"
    # Reads fail open only when the sidecar was not reached or said it was busy (429, 503). Any other 5xx
    # means it took the request and failed on it, so reads are denied too (as the TypeScript guard does).
    opens_for_reads = isinstance(err, FirewallUnavailable | FirewallRateLimited) or (
        isinstance(err, FirewallServerError) and err.status == 503
    )
    if opens_for_reads and read_only and fail_open_reads:
        hit = RuleHit(id=rule, outcome="allow", reason=f"read-only tool allowed while {why}")
        return Authorization(allowed=True, verdict="allow", message="", action=action, rules=(hit,), error=why)
    tool = safe_text(action.tool_name or action.format)[:200]
    message = f"LaunchSafe Agent Firewall blocked this: {tool}.\n- {why}\nIt was not done; {retry}. (rule {rule})"
    hit = RuleHit(id=rule, outcome="deny", reason=why)
    return Authorization(allowed=False, verdict="deny", message=message, action=action, rules=(hit,), error=why)


def unserialisable(err: BaseException, action: Action) -> Authorization:
    """A call whose arguments cannot be sent as JSON (a datetime, bytes, NaN): a fault of the call, not the setup."""
    what = safe_text(str(err))[:200] or type(err).__name__
    why = f"the call's arguments are not JSON-serialisable ({what})"
    tool = safe_text(action.tool_name or action.format)[:200]
    message = (
        f"LaunchSafe Agent Firewall blocked this: {tool}.\n- {why}\n"
        f"It was not done; call the tool again with JSON-serialisable arguments. (rule {FW_API_ERROR})"
    )
    hit = RuleHit(id=FW_API_ERROR, outcome="deny", reason=why)
    return Authorization(allowed=False, verdict="deny", message=message, action=action, rules=(hit,), error=why)


def lost_state(action: Action, why: str) -> Authorization:
    """A non-read call after a report was lost: the session's state may be incomplete, so deny."""
    reason = f"the session's state could not be kept true ({safe_text(why)[:200]})"
    tool = safe_text(action.tool_name or action.format)[:200]
    message = (
        f"LaunchSafe Agent Firewall blocked this: {tool}.\n- {reason}\n"
        f"It was not done; start a new session. (rule {FW_API_ERROR})"
    )
    hit = RuleHit(id=FW_API_ERROR, outcome="deny", reason=reason)
    return Authorization(allowed=False, verdict="deny", message=message, action=action, rules=(hit,), error=reason)


def with_approval_status(a: Authorization, status: ApprovalState) -> Authorization:
    if a.approval is None or status == a.approval.status:
        return a
    return replace(a, approval=replace(a.approval, status=status))


def hold_without_approval(action: Action) -> Authorization:
    """A recorded hold is a queue item; without an id it could never be approved: the sidecar is broken."""
    return fail_closed(FirewallProtocolError("a hold without an approval id"), action, False, False)


def refused(ask: Authorization, note: str, approval: ApprovalRef | None = None) -> Authorization:
    """An ask that did not become an allow: still the ask, with why, and the queue item if there was one."""
    note = safe_text(note)
    message = f"{ask.message}\n{note}" if ask.message else note
    return replace(ask, allowed=False, message=message, error=note, approval=approval or ask.approval)


def queue_hold(ask: Authorization, hold: Decision) -> Authorization | None:
    """None when `hold` is the queue item for `ask`'s action; else the refusal (or the API error) to return."""
    if ask.decision is None:
        return refused(
            ask, "LaunchSafe Agent Firewall: the ask has no firewall decision; the action was not let through"
        )
    if hold.verdict == "hold" and hold.approval is None:
        return hold_without_approval(ask.action)
    if hold.verdict != "hold" or hold.action_hash != ask.decision.action_hash:
        return refused(
            ask,
            "LaunchSafe Agent Firewall: the ask could not be put in the firewall's approval queue "
            f"(deciding it again gave {hold.verdict}); the action was not let through",
        )
    return None


def after_queue(ask: Authorization, ref: ApprovalRef, status: ApprovalState, error: str | None) -> Authorization | None:
    """None when the queue approved; else the refusal for a deny, expiry, timeout or a failed wait."""
    if status == "approved":
        return None
    why = f" ({safe_text(error)[:200]})" if error else ""
    note = f"LaunchSafe Agent Firewall: approval {ref.id} is {status}{why}; the action was not let through"
    return refused(ask, note, replace(ref, status=status))


def after_retry(ask: Authorization, ref: ApprovalRef, retry: Decision) -> Authorization:
    """The approval binds to the exact action: the retry must be allowed for the same action hash."""
    approved = replace(ref, status="approved")
    if ask.decision is None or retry.verdict != "allow" or retry.action_hash != ask.decision.action_hash:
        note = (
            f"LaunchSafe Agent Firewall: approval {ref.id} was given, but deciding the call again gave "
            f"{retry.verdict}; the action was not let through"
        )
        return refused(ask, note, approved)
    return replace(from_decision(retry, ask.action), approval=approved)


def json_bytes(value: Any) -> bytes:
    """`value` as the client sends it: compact JSON, UTF-8. A lone surrogate (which UTF-8 cannot carry) is
    sent as its JSON escape instead, so the body is always valid UTF-8 and the same JSON value."""
    text = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")


def _cut(text: str, total: int, limit: int) -> str:
    """The longest prefix of `text`, with a marker, whose JSON encoding is at most `limit` bytes.

    Measured on the encoded bytes, not on characters: a character is up to 4 bytes in UTF-8, and a
    quote, backslash or control character is 2 to 6 bytes once escaped in JSON.
    """
    marker = f"\n[cut by the launchsafe-firewall SDK: the content was {total} bytes as JSON]"

    def size(n: int) -> int:
        return len(json_bytes(text[:n] + marker))

    lo, hi = 0, min(len(text), limit)  # every character is at least one byte
    if size(0) > limit:
        return ""  # a limit too small for the marker itself (never the SDK's own limits)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if size(mid) <= limit:
            lo = mid
        else:
            hi = mid - 1
    return text[:lo] + marker


def bound(content: Any, limit: int = MAX_REPORT_BYTES) -> Any:
    """Content cut to fit in a request body (at most `limit` bytes of JSON); small content is sent as it is."""
    if isinstance(content, str):
        text = content
    else:
        try:
            encoded = json_bytes(content)
        except (TypeError, ValueError):
            text = repr(content)  # not JSON: sent as its text, so it still reaches the scanner
        else:
            if len(encoded) <= limit:
                return content
            text = encoded.decode("utf-8")
    total = len(json_bytes(text))
    if total <= limit:
        return text
    return _cut(text, total, limit)


def rate_limit_pause(err: FirewallRateLimited) -> float:
    ra = err.retry_after if err.retry_after is not None else DEFAULT_RATE_LIMIT_PAUSE
    return min(max(ra, 0.0), MAX_RATE_LIMIT_PAUSE)


def is_retryable(err: BaseException) -> bool:
    """A report that failed this way is kept and sent again; any other failure loses it."""
    return isinstance(err, FirewallUnavailable | FirewallServerError | FirewallRateLimited)


def is_report_retryable(err: BaseException) -> bool:
    """`is_retryable`, for a report: also a socket that is not trusted right now (the sidecar restarting makes
    it briefly the wrong mode or owner) and an interruption (a cancelled task, Ctrl-C), where the report may
    or may not have arrived; the Idempotency-Key makes sending it again safe. The token is still never sent
    to such a socket: every send checks the socket first. A decision still denies on `FirewallUntrustedSocket`."""
    return is_retryable(err) or isinstance(err, FirewallUntrustedSocket) or not isinstance(err, Exception)


ReportKind = Literal["result", "input"]


@dataclass
class PendingReport:
    kind: ReportKind
    args: dict[str, Any]
    key: str
    attempts: int = 0
    shrunk: bool = False

    def shrink(self) -> bool:
        """After a 413: cut the content to `SHRUNK_REPORT_BYTES` for one more try. False when already done."""
        if self.shrunk:
            return False
        self.shrunk = True
        # Another body: another Idempotency-Key, so the sidecar never sees one key with two bodies.
        self.key = uuid.uuid4().hex
        field_name = "output" if self.kind == "result" else "content"
        self.args[field_name] = bound(self.args[field_name], SHRUNK_REPORT_BYTES)
        return True


def is_too_large(err: BaseException) -> bool:
    return isinstance(err, FirewallHTTPError) and err.status == 413


def dry_run_result() -> ValueError:
    return ValueError(
        "record_result() was given the Authorization from check(), a dry run the firewall did not record; "
        "record the result of the authorize() that let the call run"
    )


__all__ = [
    "FW_API_ERROR",
    "FW_RATE_LIMITED",
    "FW_UNAVAILABLE",
    "Authorization",
    "ReportOutcome",
    "fail_closed",
    "is_read_only",
]
