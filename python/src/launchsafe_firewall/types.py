"""The v0 contract's request and response shapes (docs/api-v0.md), and their strict parsers.

Requests serialise to exactly the contract's field names; unset optional fields are left out, because
the sidecar answers 400 to an unknown field. Responses are parsed strictly for the fields the SDK
relies on (a missing or mistyped one is a FirewallProtocolError, which the Guard turns into a deny)
and leniently for the rest: an extra field is kept in `raw` and ignored, so a newer sidecar still works.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, cast

from .errors import FirewallProtocolError

Verdict = Literal["allow", "ask", "hold", "deny"]
ApprovalState = Literal["pending", "approved", "denied", "expired"]
ActionFormat = Literal["native", "engine", "openai.chat", "anthropic", "mcp"]

VERDICTS: frozenset[str] = frozenset({"allow", "ask", "hold", "deny"})
APPROVAL_STATES: frozenset[str] = frozenset({"pending", "approved", "denied", "expired"})
FORMATS: frozenset[str] = frozenset({"native", "engine", "openai.chat", "anthropic", "mcp"})

JSONObject = dict[str, Any]


# --- requests -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class McpInfo:
    """For format `mcp`: the server the tool belongs to, and where it was configured (unstated: untrusted)."""

    server: str
    source: str | None = None

    def to_json(self) -> JSONObject:
        out: JSONObject = {"server": self.server}
        if self.source is not None:
            out["source"] = self.source
        return out


@dataclass(frozen=True)
class Action:
    """One tool call, in one of the contract's formats. Build it with the helpers in `formats`."""

    format: ActionFormat
    tool: str | None = None
    input: Mapping[str, Any] | None = None
    call_id: str | None = None
    mcp: McpInfo | None = None
    raw: Mapping[str, Any] | None = None

    def to_json(self) -> JSONObject:
        out: JSONObject = {"format": self.format}
        if self.tool is not None:
            out["tool"] = self.tool
        if self.input is not None:
            out["input"] = dict(self.input)
        if self.call_id is not None:
            out["callId"] = self.call_id
        if self.mcp is not None:
            out["mcp"] = self.mcp.to_json()
        if self.raw is not None:
            out["raw"] = dict(self.raw)
        return out

    @property
    def tool_name(self) -> str:
        """The host's tool name, whatever the format (used for the local read-only lookup)."""
        if self.tool is not None:
            return self.tool
        raw = self.raw or {}
        if self.format == "openai.chat":
            fn = raw.get("function")
            if isinstance(fn, Mapping) and isinstance(fn.get("name"), str):
                return cast(str, fn["name"])
        if self.format == "anthropic" and isinstance(raw.get("name"), str):
            return cast(str, raw["name"])
        return ""


Traffic = Literal["tool", "network"]


@dataclass(frozen=True)
class DecideContext:
    """`context` of a decide request. `attended=False` turns an ask into a hold.

    `traffic`: `"network"` for a network middleware's request (its token must have been made with
    `api token add <agent> --traffic network`); left out, or `"tool"`, for the agent's own tool calls.
    """

    attended: bool | None = None
    workspace: tuple[str, ...] | None = None
    cwd: str | None = None
    traffic: Traffic | None = None

    def to_json(self) -> JSONObject:
        out: JSONObject = {}
        if self.attended is not None:
            out["attended"] = self.attended
        if self.workspace is not None:
            out["workspace"] = list(self.workspace)
        if self.cwd is not None:
            out["cwd"] = self.cwd
        if self.traffic is not None:
            out["traffic"] = self.traffic
        return out


@dataclass(frozen=True)
class ModelUsage:
    """The model usage behind one tool call (`usage` of a decide request), for the token and cost
    spending limits. `cost_usd` is your own estimate; the firewall keeps no prices."""

    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None

    def to_json(self) -> JSONObject:
        out: JSONObject = {}
        if self.input_tokens is not None:
            out["inputTokens"] = self.input_tokens
        if self.output_tokens is not None:
            out["outputTokens"] = self.output_tokens
        if self.cost_usd is not None:
            out["costUsd"] = self.cost_usd
        return out


@dataclass(frozen=True)
class DecideRequest:
    session: str
    action: Action
    context: DecideContext | None = None
    dry_run: bool = False
    usage: ModelUsage | None = None

    def to_json(self) -> JSONObject:
        out: JSONObject = {"session": self.session, "action": self.action.to_json()}
        if self.context is not None:
            ctx = self.context.to_json()
            if ctx:
                out["context"] = ctx
        if self.dry_run:
            out["dryRun"] = True
        if self.usage is not None:
            out["usage"] = self.usage.to_json()
        return out


# --- responses ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleHit:
    id: str
    outcome: str
    reason: str


@dataclass(frozen=True)
class SessionInfo:
    untrusted: bool
    untrusted_because: tuple[str, ...]
    holds_private_data: bool
    private_because: tuple[str, ...]
    raw: JSONObject = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class ApprovalRef:
    id: str
    status: ApprovalState
    raw: JSONObject = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class EngineInfo:
    version: str


@dataclass(frozen=True)
class LogRef:
    seq: int
    hash: str


@dataclass(frozen=True)
class Decision:
    decision_id: str
    verdict: Verdict
    rules: tuple[RuleHit, ...]
    message: str
    action_hash: str
    session: SessionInfo
    approval: ApprovalRef | None = None
    engine: EngineInfo | None = None
    log: LogRef | None = None
    raw: JSONObject = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class Health:
    ok: bool
    engine: EngineInfo | None


@dataclass(frozen=True)
class ResultRecorded:
    recorded: bool
    output: str | None = None


@dataclass(frozen=True)
class Recorded:
    recorded: bool
    applied: bool = True
    """False: the sidecar logged the report but did not act on it (a prompt from a token without the prompt role)."""
    detail: str | None = None


@dataclass(frozen=True)
class ApprovalStatus:
    id: str
    status: ApprovalState


# --- parsers --------------------------------------------------------------------------------------


def _bad(what: str) -> FirewallProtocolError:
    return FirewallProtocolError(f"malformed firewall response: {what}")


def _obj(v: Any, what: str) -> JSONObject:
    if not isinstance(v, dict):
        raise _bad(f"{what} is not an object")
    return cast(JSONObject, v)


def _str(o: JSONObject, key: str, what: str) -> str:
    v = o.get(key)
    if not isinstance(v, str):
        raise _bad(f"{what}.{key} is not a string")
    return v


def _bool(o: JSONObject, key: str, what: str) -> bool:
    v = o.get(key)
    if not isinstance(v, bool):
        raise _bad(f"{what}.{key} is not a boolean")
    return v


def _strs(o: JSONObject, key: str, what: str) -> tuple[str, ...]:
    v = o.get(key, [])
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise _bad(f"{what}.{key} is not a list of strings")
    return tuple(cast(list[str], v))


def parse_session(v: Any, what: str = "session") -> SessionInfo:
    o = _obj(v, what)
    return SessionInfo(
        untrusted=_bool(o, "untrusted", what),
        untrusted_because=_strs(o, "untrustedBecause", what),
        holds_private_data=_bool(o, "holdsPrivateData", what),
        private_because=_strs(o, "privateBecause", what),
        raw=o,
    )


def parse_engine(v: Any, what: str = "engine") -> EngineInfo | None:
    if v is None:
        return None
    o = _obj(v, what)
    return EngineInfo(version=_str(o, "version", what))


def _approval_state(o: JSONObject, what: str) -> ApprovalState:
    s = _str(o, "status", what)
    if s not in APPROVAL_STATES:
        raise _bad(f"{what}.status {s!r} is not a known approval status")
    return cast(ApprovalState, s)


def parse_approval_ref(v: Any, what: str = "approval") -> ApprovalRef | None:
    if v is None:
        return None
    o = _obj(v, what)
    return ApprovalRef(id=_str(o, "id", what), status=_approval_state(o, what), raw=o)


def parse_decision(v: Any) -> Decision:
    o = _obj(v, "decision")
    verdict = _str(o, "verdict", "decision")
    if verdict not in VERDICTS:
        raise _bad(f"decision.verdict {verdict!r} is not a known verdict")
    rules_v = o.get("rules")
    if not isinstance(rules_v, list):
        raise _bad("decision.rules is not a list")
    rules: list[RuleHit] = []
    for i, r in enumerate(rules_v):
        ro = _obj(r, f"decision.rules[{i}]")
        rules.append(
            RuleHit(
                id=_str(ro, "id", f"decision.rules[{i}]"),
                outcome=str(ro.get("outcome", "")),
                reason=str(ro.get("reason", "")),
            )
        )
    log_v = o.get("log")
    log: LogRef | None = None
    if log_v is not None:
        lo = _obj(log_v, "decision.log")
        seq = lo.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise _bad("decision.log.seq is not an integer")
        log = LogRef(seq=seq, hash=_str(lo, "hash", "decision.log"))
    return Decision(
        decision_id=_str(o, "decisionId", "decision"),
        verdict=cast(Verdict, verdict),
        rules=tuple(rules),
        message=_str(o, "message", "decision"),
        action_hash=_str(o, "actionHash", "decision"),
        session=parse_session(o.get("session"), "decision.session"),
        approval=parse_approval_ref(o.get("approval"), "decision.approval"),
        engine=parse_engine(o.get("engine"), "decision.engine"),
        log=log,
        raw=o,
    )


def parse_health(v: Any) -> Health:
    o = _obj(v, "health")
    return Health(ok=_bool(o, "ok", "health"), engine=parse_engine(o.get("engine"), "health.engine"))


def parse_result_recorded(v: Any) -> ResultRecorded:
    o = _obj(v, "result")
    out = o.get("output")
    if out is not None and not isinstance(out, str):
        raise _bad("result.output is not a string")
    return ResultRecorded(recorded=_bool(o, "recorded", "result"), output=out)


def parse_recorded(v: Any) -> Recorded:
    o = _obj(v, "response")
    applied = o.get("applied", True)
    detail = o.get("detail")
    if not isinstance(applied, bool):
        raise _bad("response.applied is not a boolean")
    if detail is not None and not isinstance(detail, str):
        raise _bad("response.detail is not a string")
    return Recorded(recorded=_bool(o, "recorded", "response"), applied=applied, detail=detail)


def parse_approval_status(v: Any) -> ApprovalStatus:
    o = _obj(v, "approval")
    return ApprovalStatus(id=_str(o, "id", "approval"), status=_approval_state(o, "approval"))
