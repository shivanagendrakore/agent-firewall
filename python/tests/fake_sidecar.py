"""An in-process stand-in for `launchsafe-firewall serve --api`, served on a real unix socket or 127.0.0.1.

It implements the v0 contract's shapes (docs/api-v0.md) strictly enough to catch an SDK that sends
the wrong thing: unknown fields are 400, every call but health needs the bearer token, and decide
honours Idempotency-Key. Failures are injected per path with `fail()`. It runs no commands.
"""

from __future__ import annotations

import contextlib
import json
import os
import socketserver
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote

TOKEN = "test-token"

DECIDE_KEYS = {"session", "action", "context", "dryRun", "usage"}
ACTION_KEYS = {"format", "tool", "input", "callId", "mcp", "raw"}
CONTEXT_KEYS = {"attended", "workspace", "cwd", "traffic"}
FORMATS = {"native", "engine", "openai.chat", "anthropic", "mcp"}


@dataclass
class Seen:
    method: str
    path: str
    headers: dict[str, str]
    body: Any


@dataclass
class Failure:
    """Instead of answering: a status (optional body), a delay, bad JSON, a wrong shape or a hang-up."""

    status: int = 0
    body: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)
    delay: float = 0.0
    malformed: bool = False
    bad_shape: bool = False
    hang_up: bool = False
    trickle: float = 0.0  # answer normally, but one body byte at a time with this pause between them
    times: int = -1  # -1: every time


class Problem(Exception):
    def __init__(self, status: int, title: str, detail: str = "") -> None:
        super().__init__(title)
        self.status, self.title, self.detail = status, title, detail


class FakeSidecar:
    def __init__(self) -> None:
        self.verdicts: dict[str, str] = {}
        self.holds_without_id: set[str] = set()  # tools whose recorded hold carries no approval (a broken sidecar)
        self.prompts_not_applied = False  # answer prompts as a token without the prompt role would
        self.approvals: dict[str, str] = {}
        self.approval_script: dict[str, list[str]] = {}
        self.requests: list[Seen] = []
        self.failures: dict[str, Failure] = {}
        self.idempotent: dict[str, dict[str, Any]] = {}
        self.consumed: set[str] = set()
        self.tainted: dict[str, list[str]] = {}
        self.max_body = 1024 * 1024  # as the sidecar: a bigger request body is a 413
        self._seq = 0
        self._lock = threading.Lock()

    # --- test controls -----------------------------------------------------------------------------

    def fail(self, path_prefix: str, failure: Failure) -> None:
        self.failures[path_prefix] = failure

    def calls(self, path_prefix: str = "") -> list[Seen]:
        return [r for r in self.requests if r.path.startswith(path_prefix)]

    # --- the contract ------------------------------------------------------------------------------

    def _tool(self, action: dict[str, Any]) -> str:
        fmt = action.get("format")
        raw = action.get("raw") or {}
        if fmt == "openai.chat":
            return str(raw["function"]["name"])
        if fmt == "anthropic":
            return str(raw["name"])
        if fmt == "mcp":
            return f"mcp__{action['mcp']['server']}__{action['tool']}"
        return str(action.get("tool"))

    def _session_obj(self, session: str) -> dict[str, Any]:
        because = self.tainted.get(session, [])
        return {
            "untrusted": bool(because),
            "untrustedBecause": because,
            "holdsPrivateData": False,
            "privateBecause": [],
        }

    def decide(self, body: dict[str, Any], key: str | None) -> dict[str, Any]:
        _only(body, DECIDE_KEYS, "decide")
        action = body.get("action")
        if not isinstance(action, dict) or not isinstance(body.get("session"), str):
            raise Problem(400, "bad request", "session and action are required")
        _only(action, ACTION_KEYS, "action")
        if action.get("format") not in FORMATS:
            raise Problem(400, "unknown format")
        if "context" in body:
            _only(body["context"], CONTEXT_KEYS, "context")
            if body["context"].get("traffic", "tool") not in ("tool", "network"):
                raise Problem(400, "bad request", "traffic must be tool or network")
        if action["format"] in ("native", "engine", "mcp") and not isinstance(action.get("tool"), str):
            raise Problem(400, "bad request", "tool is required")
        if action["format"] == "mcp" and not isinstance(action.get("mcp"), dict):
            raise Problem(400, "bad request", "mcp is required")
        if key is not None and key in self.idempotent:
            return self.idempotent[key]
        session = body["session"]
        tool = self._tool(action)
        verdict = self.verdicts.get(tool, "allow")
        # As the real sidecar: an unattended ask is a hold (api-v0.md); asks themselves are never queued.
        if verdict == "ask" and (body.get("context") or {}).get("attended") is False:
            verdict = "hold"
        self._seq += 1
        out: dict[str, Any] = {
            "decisionId": f"dec_{self._seq}",
            "verdict": verdict,
            "rules": [],
            "message": "",
            "actionHash": f"sha256:{session}:{tool}",
            "session": self._session_obj(session),
            "engine": {"version": "0.3.0"},
            "log": {"seq": self._seq, "hash": f"sha256:log{self._seq}"},
        }
        approved = [a for a, s in self.approvals.items() if s == "approved" and a.startswith(f"{session}|{tool}|")]
        unused = [a for a in approved if a not in self.consumed]
        if verdict in ("ask", "hold") and unused:
            self.consumed.add(unused[0])
            out["verdict"] = "allow"
        elif verdict in ("ask", "hold", "deny"):
            rule = {"ask": "FW-SEND", "hold": "FW-SEND", "deny": "FW-SECRET"}[verdict]
            out["rules"] = [{"id": rule, "outcome": "deny" if verdict == "deny" else "approve", "reason": "test"}]
            out["message"] = f"LaunchSafe Firewall: {verdict} {tool}"
            if verdict == "hold" and not body.get("dryRun") and tool not in self.holds_without_id:
                aid = f"{session}|{tool}|{self._seq}"
                self.approvals[aid] = "pending"
                out["approval"] = {"id": aid, "status": "pending"}
        if key is not None:
            self.idempotent[key] = out
        return out

    def results(self, session: str, body: dict[str, Any]) -> dict[str, Any]:
        _only(body, {"decisionId", "output", "failed"}, "results")
        if not isinstance(body.get("decisionId"), str) or "output" not in body:
            raise Problem(400, "bad request")
        out: dict[str, Any] = {"recorded": True}
        if isinstance(body["output"], str) and "SECRET" in body["output"]:
            out["output"] = body["output"].replace("SECRET", "[redacted]")
        elif not isinstance(body["output"], str) and "SECRET" in json.dumps(body["output"]):
            # Structured output: the redacted copy is a string, as the contract says (its JSON text).
            out["output"] = json.dumps(body["output"]).replace("SECRET", "[redacted]")
        return out

    def inputs(self, session: str, body: dict[str, Any]) -> dict[str, Any]:
        _only(body, {"source", "content", "private"}, "inputs")
        if not isinstance(body.get("source"), str) or "content" not in body:
            raise Problem(400, "bad request")
        if "private" in body and not isinstance(body["private"], bool):
            raise Problem(400, "bad request", "private must be a boolean")
        self.tainted.setdefault(session, []).append(body["source"])
        return {"recorded": True}

    def prompts(self, session: str, body: dict[str, Any]) -> dict[str, Any]:
        _only(body, {"text"}, "prompts")
        if not isinstance(body.get("text"), str):
            raise Problem(400, "bad request")
        if self.prompts_not_applied:
            return {"recorded": True, "applied": False, "detail": "the token has no prompt role"}
        return {"recorded": True}

    def approval(self, aid: str) -> dict[str, Any]:
        if aid not in self.approvals:
            raise Problem(404, "not found", "unknown approval")
        script = self.approval_script.get(aid) or self.approval_script.get("*")
        if script:
            self.approvals[aid] = script.pop(0)
        return {"id": aid, "status": self.approvals[aid]}

    def handle(
        self, method: str, path: str, headers: dict[str, str], raw: bytes
    ) -> tuple[int, dict[str, str], bytes, float]:
        status, out_headers, body = self._handle(method, path, headers, raw)
        with self._lock:
            failure = next((f for p, f in self.failures.items() if path.startswith(p) and f.trickle), None)
        return status, out_headers, body, failure.trickle if failure is not None else 0.0

    def _handle(self, method: str, path: str, headers: dict[str, str], raw: bytes) -> tuple[int, dict[str, str], bytes]:
        if len(raw) > self.max_body:
            with self._lock:
                self.requests.append(Seen(method, path, headers, None))
            return _problem(Problem(413, "payload too large"))
        body: Any = None
        if raw:
            try:
                body = json.loads(raw)
            except ValueError:
                return _problem(Problem(400, "bad JSON"))
        with self._lock:
            self.requests.append(Seen(method, path, headers, body))
            failure = next(
                (f for p, f in self.failures.items() if path.startswith(p) and f.times != 0 and not f.trickle), None
            )
            if failure is not None and failure.times > 0:
                failure.times -= 1
        if failure is not None:
            if failure.delay:
                time.sleep(failure.delay)
            if failure.hang_up:
                return -1, {}, b""
            if failure.malformed:
                return 200, {"Content-Type": "application/json"}, b'{"verdict": "allow", '
            if failure.bad_shape:
                return 200, {"Content-Type": "application/json"}, b'{"verdict": "maybe", "decisionId": 1}'
            if failure.status:
                body_bytes = (
                    failure.body
                    if failure.body is not None
                    else json.dumps(
                        {
                            "type": "about:blank",
                            "title": f"status {failure.status}",
                            "status": failure.status,
                            "detail": "x",
                        }
                    ).encode()
                )
                return failure.status, {"Content-Type": "application/problem+json", **failure.headers}, body_bytes
        try:
            with self._lock:
                result = self._route(method, path, headers, body)
        except Problem as p:
            return _problem(p)
        return 200, {"Content-Type": "application/json"}, json.dumps(result).encode()

    def _route(self, method: str, path: str, headers: dict[str, str], body: Any) -> dict[str, Any]:
        if method == "GET" and path == "/v1/health":
            return {"ok": True, "engine": {"version": "0.3.0"}}
        if headers.get("authorization") != f"Bearer {TOKEN}":
            raise Problem(401, "unauthorized", "no or bad token")
        parts = path.split("/")
        if method == "POST" and path == "/v1/decide":
            return self.decide(_body(body), headers.get("idempotency-key"))
        if len(parts) == 5 and parts[1:3] == ["v1", "sessions"] and method == "POST":
            session = unquote(parts[3])
            handler: dict[str, Callable[[str, dict[str, Any]], dict[str, Any]]] = {
                "results": self.results,
                "inputs": self.inputs,
                "prompts": self.prompts,
            }
            if parts[4] in handler:
                return handler[parts[4]](session, _body(body))
        if len(parts) == 4 and parts[1:3] == ["v1", "sessions"] and method == "GET":
            return self._session_obj(unquote(parts[3]))
        if len(parts) == 4 and parts[1:3] == ["v1", "approvals"] and method == "GET":
            return self.approval(unquote(parts[3]))
        raise Problem(404, "not found")


def _only(o: Any, keys: set[str], what: str) -> None:
    if not isinstance(o, dict):
        raise Problem(400, "bad request", f"{what} must be an object")
    extra = set(o) - keys
    if extra:
        raise Problem(400, "unknown field", f"{what}: {sorted(extra)}")


def _body(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise Problem(400, "bad request", "body must be a JSON object")
    return body


def _problem(p: Problem) -> tuple[int, dict[str, str], bytes]:
    doc = {"type": "about:blank", "title": p.title, "status": p.status, "detail": p.detail}
    return p.status, {"Content-Type": "application/problem+json"}, json.dumps(doc).encode()


def _handler(fake: FakeSidecar) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            pass

        def address_string(self) -> str:
            return "local"

        def _do(self) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            headers = {k.lower(): v for k, v in self.headers.items()}
            status, out_headers, body, trickle = fake.handle(self.command, self.path, headers, raw)
            if status < 0:
                self.close_connection = True
                return
            # The client may have given up already (a timeout test).
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.send_response(status)
                for k, v in out_headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if not trickle:
                    self.wfile.write(body)
                    return
                for i in range(len(body)):
                    self.wfile.write(body[i : i + 1])
                    self.wfile.flush()
                    time.sleep(trickle)

        do_GET = _do
        do_POST = _do

    return Handler


class _UnixHTTPServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


class _TCPServer(ThreadingHTTPServer):
    daemon_threads = True


class Served:
    """A FakeSidecar listening on a unix socket (`kind="uds"`) or 127.0.0.1 (`kind="tcp"`)."""

    def __init__(self, kind: str) -> None:
        self.fake = FakeSidecar()
        self.kind = kind
        self._dir: str | None = None
        server: socketserver.BaseServer
        if kind == "uds":
            # A short path under /tmp: macOS limits unix socket paths to 104 bytes.
            self._dir = tempfile.mkdtemp(prefix="lsfw-", dir="/tmp")
            self.socket_path = os.path.join(self._dir, "api.sock")
            server = _UnixHTTPServer(self.socket_path, _handler(self.fake))
            os.chmod(self.socket_path, 0o600)  # as the sidecar makes it; the client refuses a wider one
            self.base_url: str | None = None
        else:
            tcp = _TCPServer(("127.0.0.1", 0), _handler(self.fake))
            self.base_url = f"http://127.0.0.1:{tcp.server_address[1]}"
            self.socket_path = ""
            server = tcp
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()

    def client_kwargs(self, token: str | None = TOKEN) -> dict[str, Any]:
        kw: dict[str, Any] = {"token": token}
        if self.kind == "uds":
            kw["socket_path"] = self.socket_path
        else:
            kw["base_url"] = self.base_url
        return kw

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._dir is not None:
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
            os.rmdir(self._dir)
