"""Errors the client raises. The Guard turns every one of them into a decision (fail closed)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Problem:
    """An RFC 9457 problem document (`application/problem+json`), as far as the sidecar sent one."""

    type: str = "about:blank"
    title: str = ""
    status: int = 0
    detail: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


class FirewallError(Exception):
    """Base class for everything the client raises."""


class FirewallUnavailable(FirewallError):
    """The sidecar could not be reached (no socket, connection refused, reset)."""


class FirewallTimeout(FirewallUnavailable):
    """The sidecar did not answer in time. A timeout is never an allow."""


class FirewallUntrustedSocket(FirewallError):
    """The socket is not one the sidecar made (another owner, or open to other users): nothing was sent.

    Not an outage, so read-only tools do not fail open: a person has to fix the setup."""


class FirewallProtocolError(FirewallError):
    """The sidecar answered with something that is not the contract's shape (bad JSON, missing fields)."""


class FirewallHTTPError(FirewallError):
    """The sidecar answered with an error status."""

    def __init__(self, status: int, problem: Problem) -> None:
        self.status = status
        self.problem = problem
        text = problem.detail or problem.title or "error"
        super().__init__(f"firewall API returned {status}: {text}")


class FirewallServerError(FirewallHTTPError):
    """A 5xx answer. Denied like an unreachable sidecar, except that a 503 lets read-only tools through."""


class FirewallRateLimited(FirewallHTTPError):
    """A 429 answer. `retry_after` is in seconds, when the sidecar said."""

    def __init__(self, status: int, problem: Problem, retry_after: float | None) -> None:
        super().__init__(status, problem)
        self.retry_after = retry_after


class FirewallAPIError(FirewallHTTPError):
    """A 4xx answer other than 429 (bad request, bad token, refused origin, not found, too large)."""
