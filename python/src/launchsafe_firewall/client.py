"""Clients for the sidecar's /v1 API (docs/api-v0.md): `Client` (blocking) and `AsyncClient`.

The clients are thin and honest: they raise a `FirewallError` for every failure. `Guard` is the layer
that turns failures into decisions; call the client directly only when you handle errors yourself.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, TypeVar
from urllib.parse import quote, urlsplit

import httpx

from ._core import json_bytes
from .errors import (
    FirewallAPIError,
    FirewallError,
    FirewallHTTPError,
    FirewallProtocolError,
    FirewallRateLimited,
    FirewallServerError,
    FirewallTimeout,
    FirewallUnavailable,
    FirewallUntrustedSocket,
    Problem,
)
from .types import (
    Action,
    ApprovalStatus,
    DecideContext,
    DecideRequest,
    Decision,
    Health,
    ModelUsage,
    Recorded,
    ResultRecorded,
    SessionInfo,
    parse_approval_status,
    parse_decision,
    parse_health,
    parse_recorded,
    parse_result_recorded,
    parse_session,
)

T = TypeVar("T")

DEFAULT_DECIDE_TIMEOUT = 0.25
"""Seconds. The contract's default (docs/api-v0.md, "Fail-closed (SDK side)"). A timeout is not an allow."""
DEFAULT_TIMEOUT = 2.0
"""Seconds, for every call other than decide."""

TOKEN_ENV = "LAUNCHSAFE_FIREWALL_TOKEN"  # noqa: S105 - the variable's name, not a secret
HOME_ENV = "LAUNCHSAFE_FIREWALL_HOME"
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def firewall_home(env: Mapping[str, str] | None = None) -> Path:
    """The firewall's home: `$LAUNCHSAFE_FIREWALL_HOME` (made absolute), else `~/.launchsafe-firewall`.

    Matches `firewallHome()` in the firewall's `src/runtime/layout.ts`.
    """
    e = os.environ if env is None else env
    override = e.get(HOME_ENV, "")
    if override != "":
        return Path(os.path.abspath(override))
    return Path.home() / ".launchsafe-firewall"


def default_socket_path(env: Mapping[str, str] | None = None) -> Path:
    """`<firewall home>/api.sock`, where `serve --api` listens by default."""
    return firewall_home(env) / "api.sock"


def _check_token(token: str | None) -> str | None:
    # Surrounding whitespace is never part of a token (a token file or variable often ends in a newline).
    token = token.strip() if token is not None else None
    if token is None or token == "":
        return None
    if not all(0x21 <= ord(c) <= 0x7E for c in token):
        raise ValueError("the firewall token must be printable ASCII without spaces")
    return token


def _check_base_url(base_url: str) -> str:
    parts = urlsplit(base_url)
    if parts.scheme != "http" or parts.hostname is None or parts.hostname not in _LOOPBACK_HOSTS:
        raise ValueError("base_url must be http://127.0.0.1:<port> or http://localhost:<port>")
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username or parts.password:
        raise ValueError("base_url must be just the sidecar's origin, e.g. http://127.0.0.1:8787")
    return f"http://{parts.netloc}"


def _seg(value: str, what: str) -> str:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{what} must be a non-empty string")
    return quote(value, safe="")


def _retry_after(v: str | None) -> float | None:
    if v is None:
        return None
    try:
        s = float(v.strip())
    except ValueError:
        return None  # an HTTP date: not worth parsing for a local sidecar
    return s if s >= 0 else None


def _problem(code: int, content: bytes) -> Problem:
    try:
        body = json.loads(content)
    except ValueError:
        return Problem(status=code, detail=content.decode("utf-8", "replace")[:200])
    if not isinstance(body, dict):
        return Problem(status=code)

    def s(k: str) -> str:
        v = body.get(k)
        return v if isinstance(v, str) else ""

    status = body.get("status")
    return Problem(
        type=s("type") or "about:blank",
        title=s("title"),
        status=status if isinstance(status, int) else code,
        detail=s("detail"),
        raw=body,
    )


def _check(code: int, headers: httpx.Headers, content: bytes) -> Any:
    """The response body as JSON, or the right error for its status."""
    if code == 429:
        raise FirewallRateLimited(code, _problem(code, content), _retry_after(headers.get("retry-after")))
    if code >= 500:
        raise FirewallServerError(code, _problem(code, content))
    if code >= 400:
        raise FirewallAPIError(code, _problem(code, content))
    if code != 200:
        # Redirects are not followed and nothing in v0 answers with another 2xx.
        raise FirewallProtocolError(f"unexpected firewall response status {code}")
    try:
        return json.loads(content)
    except ValueError as e:
        raise FirewallProtocolError("malformed firewall response: body is not JSON") from e


def _translate(e: Exception) -> FirewallError:
    if isinstance(e, httpx.TimeoutException):
        return FirewallTimeout(f"no answer in time ({type(e).__name__})")
    return FirewallUnavailable(f"{type(e).__name__}: {e}" if str(e) else type(e).__name__)


def _late(timeout: float) -> FirewallTimeout:
    return FirewallTimeout(f"no complete answer within {timeout:g} s")


def _read_until(chunks: Iterator[bytes], deadline: float, timeout: float) -> bytes:
    """The body, read chunk by chunk; past the deadline the answer is not waited for (or trusted)."""
    body = bytearray()
    for chunk in chunks:
        body += chunk
        if time.monotonic() > deadline:
            raise _late(timeout)
    return bytes(body)


@dataclass(frozen=True)
class _Call:
    method: str
    path: str
    timeout: float
    body: dict[str, Any] | None = None
    auth: bool = True
    idempotency_key: str | None = None


def _encode(body: dict[str, Any]) -> bytes:
    return json_bytes(body)


class _Base:
    """What the blocking and async clients share: configuration and request building."""

    def __init__(
        self,
        *,
        socket_path: str | os.PathLike[str] | None,
        base_url: str | None,
        token: str | None,
        decide_timeout: float,
        timeout: float,
    ) -> None:
        if socket_path is not None and base_url is not None:
            raise ValueError("pass socket_path or base_url, not both")
        self.token = _check_token(token if token is not None else os.environ.get(TOKEN_ENV))
        self.base_url = _check_base_url(base_url) if base_url is not None else None
        self.socket_path = None if self.base_url is not None else Path(socket_path or default_socket_path())
        self.decide_timeout = decide_timeout
        self.timeout = timeout

    @property
    def _origin(self) -> str:
        return self.base_url if self.base_url is not None else "http://localhost"

    def _headers(self, c: _Call) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if c.body is not None:
            h["Content-Type"] = "application/json"
        if c.auth and self.token is not None:
            h["Authorization"] = f"Bearer {self.token}"
        if c.idempotency_key is not None:
            h["Idempotency-Key"] = c.idempotency_key
        return h

    def _check_socket(self) -> None:
        """No socket file: unavailable, without a connection attempt (httpcore leaks the socket of a failed one).

        A socket that another user owns, or that others may use, is refused before the token is sent: the
        sidecar makes its socket 0600 and owned by the person who runs it, so anything else may be an
        impostor answering `allow`. The messages never name the path: they reach the model.
        """
        if self.socket_path is None:
            return
        try:
            st = os.stat(self.socket_path)
        except OSError as e:
            raise FirewallUnavailable("no firewall socket at the configured path") from e
        if not stat.S_ISSOCK(st.st_mode):
            raise FirewallUnavailable("the configured firewall socket path is not a socket")
        getuid = getattr(os, "getuid", None)
        if getuid is not None and st.st_uid != getuid():
            raise FirewallUntrustedSocket("the firewall socket is owned by another user; the token was not sent")
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise FirewallUntrustedSocket(
                "the firewall socket is open to other users (it must be mode 0600); the token was not sent"
            )

    def _request(self, c: _Call) -> tuple[str, str, dict[str, str], bytes | None, httpx.Timeout]:
        self._check_socket()
        content = _encode(c.body) if c.body is not None else None
        return c.method, c.path, self._headers(c), content, httpx.Timeout(c.timeout)

    # The calls, as data. Each public method is one of these plus a parser.

    def _health(self, timeout: float | None) -> _Call:
        return _Call("GET", "/v1/health", timeout or self.timeout, auth=False)

    def _decide(
        self,
        session: str,
        action: Action,
        context: DecideContext | None,
        dry_run: bool,
        idempotency_key: str | None,
        timeout: float | None,
        usage: ModelUsage | None = None,
    ) -> _Call:
        _seg(session, "session")
        body = DecideRequest(session=session, action=action, context=context, dry_run=dry_run, usage=usage).to_json()
        return _Call("POST", "/v1/decide", timeout or self.decide_timeout, body, True, idempotency_key or new_key())

    def _results(
        self,
        session: str,
        decision_id: str,
        output: Any,
        key: str | None,
        timeout: float | None,
        failed: bool | None = None,
    ) -> _Call:
        _seg(decision_id, "decision_id")
        path = f"/v1/sessions/{_seg(session, 'session')}/results"
        body: dict[str, Any] = {"decisionId": decision_id, "output": output}
        if failed is not None:
            body["failed"] = failed
        return _Call("POST", path, timeout or self.timeout, body, True, key)

    def _inputs(
        self, session: str, source: str, content: Any, private: bool | None, key: str | None, timeout: float | None
    ) -> _Call:
        body: dict[str, Any] = {"source": source, "content": content}
        if private is not None:
            body["private"] = private
        path = f"/v1/sessions/{_seg(session, 'session')}/inputs"
        return _Call("POST", path, timeout or self.timeout, body, True, key)

    def _prompts(self, session: str, text: str, key: str | None, timeout: float | None) -> _Call:
        path = f"/v1/sessions/{_seg(session, 'session')}/prompts"
        return _Call("POST", path, timeout or self.timeout, {"text": text}, True, key)

    def _session(self, session: str, timeout: float | None) -> _Call:
        return _Call("GET", f"/v1/sessions/{_seg(session, 'session')}", timeout or self.timeout)

    def _approval(self, approval_id: str, timeout: float | None) -> _Call:
        return _Call("GET", f"/v1/approvals/{_seg(approval_id, 'approval_id')}", timeout or self.timeout)


def new_key() -> str:
    """A fresh Idempotency-Key."""
    return uuid.uuid4().hex


class Client(_Base):
    """Blocking client. Raises `FirewallError` subclasses; use `Guard` for fail-closed decisions."""

    def __init__(
        self,
        *,
        socket_path: str | os.PathLike[str] | None = None,
        base_url: str | None = None,
        token: str | None = None,
        decide_timeout: float = DEFAULT_DECIDE_TIMEOUT,
        timeout: float = DEFAULT_TIMEOUT,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        super().__init__(
            socket_path=socket_path, base_url=base_url, token=token, decide_timeout=decide_timeout, timeout=timeout
        )
        if transport is None:
            uds = str(self.socket_path) if self.socket_path is not None else None
            transport = httpx.HTTPTransport(uds=uds)
        # trust_env=False: no proxy from the environment ever sees the token or the calls.
        self._http = httpx.Client(base_url=self._origin, transport=transport, trust_env=False, follow_redirects=False)

    def __enter__(self) -> Client:
        return self

    def __exit__(self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    def _send(self, c: _Call, parse: Callable[[Any], T]) -> T:
        """One call. `c.timeout` is both httpx's per-phase timeout and a total deadline: a sidecar that
        trickles its answer is given up on, and an answer that completes past the deadline is not used."""
        method, path, headers, content, timeout = self._request(c)
        deadline = time.monotonic() + c.timeout
        try:
            with self._http.stream(method, path, headers=headers, content=content, timeout=timeout) as response:
                body = _read_until(response.iter_bytes(), deadline, c.timeout)
                code, response_headers = response.status_code, response.headers
        except (httpx.HTTPError, OSError) as e:
            raise _translate(e) from e
        if time.monotonic() > deadline:
            raise _late(c.timeout)
        return parse(_check(code, response_headers, body))

    def health(self, *, timeout: float | None = None) -> Health:
        return self._send(self._health(timeout), parse_health)

    def decide(
        self,
        session: str,
        action: Action,
        *,
        context: DecideContext | None = None,
        dry_run: bool = False,
        idempotency_key: str | None = None,
        timeout: float | None = None,
        usage: ModelUsage | None = None,
    ) -> Decision:
        """`POST /v1/decide`. An Idempotency-Key is set for you when you give none. `usage`: the model
        usage behind this call, counted toward the token and cost spending limits."""
        call = self._decide(session, action, context, dry_run, idempotency_key, timeout, usage)
        return self._send(call, parse_decision)

    def record_result(
        self,
        session: str,
        decision_id: str,
        output: Any,
        *,
        idempotency_key: str | None = None,
        timeout: float | None = None,
        failed: bool | None = None,
    ) -> ResultRecorded:
        """`failed=True`: the tool failed; it counts toward the identical-failures spending limit."""
        return self._send(
            self._results(session, decision_id, output, idempotency_key or new_key(), timeout, failed),
            parse_result_recorded,
        )

    def report_input(
        self,
        session: str,
        source: str,
        content: Any,
        *,
        private: bool | None = None,
        idempotency_key: str | None = None,
        timeout: float | None = None,
    ) -> Recorded:
        return self._send(
            self._inputs(session, source, content, private, idempotency_key or new_key(), timeout), parse_recorded
        )

    def record_prompt(
        self, session: str, text: str, *, idempotency_key: str | None = None, timeout: float | None = None
    ) -> Recorded:
        return self._send(self._prompts(session, text, idempotency_key or new_key(), timeout), parse_recorded)

    def get_session(self, session: str, *, timeout: float | None = None) -> SessionInfo:
        return self._send(self._session(session, timeout), parse_session)

    def get_approval(self, approval_id: str, *, timeout: float | None = None) -> ApprovalStatus:
        return self._send(self._approval(approval_id, timeout), parse_approval_status)

    def wait_for_approval(
        self,
        approval_id: str,
        *,
        timeout: float = 60.0,
        interval: float = 0.25,
        max_interval: float = 2.0,
    ) -> ApprovalStatus:
        """Polls until the approval is no longer pending or `timeout` seconds pass (then: still pending)."""
        deadline = time.monotonic() + timeout
        while True:
            status = self.get_approval(approval_id)
            remaining = deadline - time.monotonic()
            if status.status != "pending" or remaining <= 0:
                return status
            time.sleep(min(interval, remaining))
            interval = min(interval * 1.5, max_interval)


class AsyncClient(_Base):
    """asyncio client, the same calls as `Client`."""

    def __init__(
        self,
        *,
        socket_path: str | os.PathLike[str] | None = None,
        base_url: str | None = None,
        token: str | None = None,
        decide_timeout: float = DEFAULT_DECIDE_TIMEOUT,
        timeout: float = DEFAULT_TIMEOUT,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(
            socket_path=socket_path, base_url=base_url, token=token, decide_timeout=decide_timeout, timeout=timeout
        )
        if transport is None:
            uds = str(self.socket_path) if self.socket_path is not None else None
            transport = httpx.AsyncHTTPTransport(uds=uds)
        self._http = httpx.AsyncClient(
            base_url=self._origin, transport=transport, trust_env=False, follow_redirects=False
        )

    async def __aenter__(self) -> AsyncClient:
        return self

    async def __aexit__(self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _send(self, c: _Call, parse: Callable[[Any], T]) -> T:
        """As `Client._send`: `c.timeout` is per phase and the whole call's deadline (enforced by the loop)."""
        method, path, headers, content, timeout = self._request(c)
        request = self._http.request(method, path, headers=headers, content=content, timeout=timeout)
        try:
            response = await asyncio.wait_for(request, c.timeout)
        except asyncio.TimeoutError as e:  # before OSError: from 3.11 it is the builtin TimeoutError
            raise _late(c.timeout) from e
        except (httpx.HTTPError, OSError) as e:
            raise _translate(e) from e
        return parse(_check(response.status_code, response.headers, response.content))

    async def health(self, *, timeout: float | None = None) -> Health:
        return await self._send(self._health(timeout), parse_health)

    async def decide(
        self,
        session: str,
        action: Action,
        *,
        context: DecideContext | None = None,
        dry_run: bool = False,
        idempotency_key: str | None = None,
        timeout: float | None = None,
        usage: ModelUsage | None = None,
    ) -> Decision:
        return await self._send(
            self._decide(session, action, context, dry_run, idempotency_key, timeout, usage), parse_decision
        )

    async def record_result(
        self,
        session: str,
        decision_id: str,
        output: Any,
        *,
        idempotency_key: str | None = None,
        timeout: float | None = None,
        failed: bool | None = None,
    ) -> ResultRecorded:
        return await self._send(
            self._results(session, decision_id, output, idempotency_key or new_key(), timeout, failed),
            parse_result_recorded,
        )

    async def report_input(
        self,
        session: str,
        source: str,
        content: Any,
        *,
        private: bool | None = None,
        idempotency_key: str | None = None,
        timeout: float | None = None,
    ) -> Recorded:
        return await self._send(
            self._inputs(session, source, content, private, idempotency_key or new_key(), timeout), parse_recorded
        )

    async def record_prompt(
        self, session: str, text: str, *, idempotency_key: str | None = None, timeout: float | None = None
    ) -> Recorded:
        return await self._send(self._prompts(session, text, idempotency_key or new_key(), timeout), parse_recorded)

    async def get_session(self, session: str, *, timeout: float | None = None) -> SessionInfo:
        return await self._send(self._session(session, timeout), parse_session)

    async def get_approval(self, approval_id: str, *, timeout: float | None = None) -> ApprovalStatus:
        return await self._send(self._approval(approval_id, timeout), parse_approval_status)

    async def wait_for_approval(
        self,
        approval_id: str,
        *,
        timeout: float = 60.0,
        interval: float = 0.25,
        max_interval: float = 2.0,
    ) -> ApprovalStatus:
        deadline = time.monotonic() + timeout
        while True:
            status = await self.get_approval(approval_id)
            remaining = deadline - time.monotonic()
            if status.status != "pending" or remaining <= 0:
                return status
            await asyncio.sleep(min(interval, remaining))
            interval = min(interval * 1.5, max_interval)


__all__ = [
    "DEFAULT_DECIDE_TIMEOUT",
    "DEFAULT_TIMEOUT",
    "AsyncClient",
    "Client",
    "FirewallHTTPError",
    "default_socket_path",
    "firewall_home",
    "new_key",
]
