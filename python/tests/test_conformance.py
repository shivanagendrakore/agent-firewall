"""Every conformance vector (conformance/README.md) through this SDK's `Client` against the REAL sidecar.

The sidecar is the firewall's own server (`startApiServer`, what `serve --api` runs), started per vector by
tests/conformance_sidecar.mjs over a unix socket, configured as test/api/conformance-sidecar.test.ts configures it:
the reference environment, or the vector's prepared tree (conformance/setup.ts) for a vector with a `setup`. An
`approve` step is a person's approval in the firewall's queue, done by the driver, never through the API.

Each step goes through the SDK's typed calls (`decide`, `record_result`, `report_input`, `record_prompt`,
`get_session`), `usage` and `failed` included. A request those calls cannot express (the `invalid-*` vectors:
unknown fields, missing ones, wrong types; and a network middleware's `context.traffic`, which an agent's SDK has
no field for) is sent as is through the same client's transport, so the sidecar still sees the vector's exact body.
A step with `"token": "network"` goes through a second client holding the agent's network-middleware token, and a
step's `expectApi`, where the vector has one, is what the sidecar must answer.

Needs Node 22+ and the compiled firewall: at the repository root, `npm ci` and `npx tsc -p
tsconfig.conformance.json` (it writes dist-conformance/). Without them the tests skip and say why; set
LAUNCHSAFE_FIREWALL_CONFORMANCE=require to fail instead.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import quote

import pytest

from launchsafe_firewall import Client
from launchsafe_firewall.client import _Call, new_key
from launchsafe_firewall.errors import FirewallAPIError
from launchsafe_firewall.types import (
    Action,
    DecideContext,
    DecideRequest,
    Decision,
    McpInfo,
    ModelUsage,
    parse_decision,
)

T = TypeVar("T")

REPO = Path(__file__).resolve().parents[2]
VECTORS_DIR = REPO / "conformance" / "vectors"
DIST = REPO / "dist-conformance"
DRIVER = Path(__file__).resolve().parent / "conformance_sidecar.mjs"
ENDPOINT = {"result": "results", "input": "inputs", "prompt": "prompts"}
# Generous: these tests check verdicts, not latency (the first decisions of a cold process take longer).
TIMEOUT = 30.0


def _load_vectors() -> list[dict[str, Any]]:
    if not VECTORS_DIR.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for f in sorted(VECTORS_DIR.glob("*.json")):
        out.extend(json.loads(f.read_text(encoding="utf-8")))
    return out


VECTORS = _load_vectors()


def _canonical(v: Any) -> str:
    """JSON with sorted keys: `True` and `1` differ here, as they do on the wire."""
    return json.dumps(v, sort_keys=True, ensure_ascii=False)


class Sidecar:
    """The driver process: starts a server per vector and approves holds as a person would."""

    def __init__(self, node: str, home: Path) -> None:
        path = os.environ.get("PATH", "/usr/bin:/bin")
        env = {"PATH": path, "HOME": str(home), "TMPDIR": str(home), "LANG": "C.UTF-8"}
        # Fixed arguments (node, this repository's driver and build), no shell.
        self.proc = subprocess.Popen(  # noqa: S603
            [node, str(DRIVER), str(DIST)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env=env,
            text=True,
            encoding="utf-8",
        )

    def ask(self, msg: dict[str, Any]) -> dict[str, Any]:
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            if line == "":
                raise RuntimeError(f"the sidecar driver exited (code {self.proc.poll()})")
            if line.startswith('{"ok":'):
                answer: dict[str, Any] = json.loads(line)
                if answer.get("ok") is not True:
                    raise RuntimeError(f"the sidecar driver failed: {answer.get('error')}")
                return answer

    def close(self) -> None:
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        if self.proc.stdout is not None:
            self.proc.stdout.close()


def _unavailable() -> str | None:
    if not VECTORS:
        return f"no conformance vectors at {VECTORS_DIR}"
    if shutil.which("node") is None:
        return "node is not on PATH"
    if not (DIST / "conformance" / "setup.js").is_file() or not (DIST / "src" / "api" / "server.js").is_file():
        build = "at the repository root: npm ci && npx tsc -p tsconfig.conformance.json"
        return f"the compiled firewall is not at {DIST} ({build})"
    return None


@pytest.fixture(scope="module")
def sidecar() -> Iterator[Sidecar]:
    why = _unavailable()
    if why is not None:
        if os.environ.get("LAUNCHSAFE_FIREWALL_CONFORMANCE") == "require":
            pytest.fail(why)
        pytest.skip(why)
    node = shutil.which("node")
    assert node is not None
    with tempfile.TemporaryDirectory(prefix="lsfwpy-node-") as home:
        s = Sidecar(node, Path(home))
        try:
            yield s
        finally:
            s.close()


# --- one step through the SDK ---------------------------------------------------------------------


def _raw(client: Client, path: str, body: Any, parse: Callable[[Any], T], timeout: float = TIMEOUT) -> T:
    """A body the typed calls cannot express, sent through the client's own transport, auth and error mapping."""
    return client._send(_Call("POST", path, timeout, body, True, new_key()), parse)


def _typed_usage(u: Any) -> ModelUsage | None:
    if u is None:
        return None
    return ModelUsage(input_tokens=u.get("inputTokens"), output_tokens=u.get("outputTokens"), cost_usd=u.get("costUsd"))


def _typed_decide(req: dict[str, Any]) -> tuple[str, Action, DecideContext | None, bool, ModelUsage | None] | None:
    """The request as the SDK's typed decide arguments, or None when they would send a different body."""
    try:
        a = req["action"]
        m = a.get("mcp")
        action = Action(
            format=a["format"],
            tool=a.get("tool"),
            input=a.get("input"),
            call_id=a.get("callId"),
            mcp=McpInfo(server=m["server"], source=m.get("source")) if m is not None else None,
            raw=a.get("raw"),
        )
        c = req.get("context")
        context = None
        if c is not None:
            ws = c.get("workspace")
            context = DecideContext(
                attended=c.get("attended"), workspace=tuple(ws) if isinstance(ws, list) else ws, cwd=c.get("cwd")
            )
        session, dry_run = req["session"], req.get("dryRun", False)
        if not isinstance(session, str) or session == "" or not isinstance(dry_run, bool):
            return None
        usage = _typed_usage(req.get("usage"))
        sent = DecideRequest(session=session, action=action, context=context, dry_run=dry_run, usage=usage).to_json()
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
    return (session, action, context, dry_run, usage) if _canonical(sent) == _canonical(req) else None


def _decide(client: Client, req: dict[str, Any], typed: list[bool]) -> Decision:
    args = _typed_decide(req)
    typed.append(args is not None)
    if args is None:
        return _raw(client, "/v1/decide", req, parse_decision)
    session, action, context, dry_run, usage = args
    return client.decide(session, action, context=context, dry_run=dry_run, usage=usage, timeout=TIMEOUT)


def _identity(v: Any) -> Any:
    return v


def _record(client: Client, kind: str, session: str, body: dict[str, Any], typed: list[bool]) -> str | None:
    """A result, input or prompt step; returns the redacted output a result step answers with, if any."""
    keys = set(body)
    if (
        kind == "result"
        and {"decisionId", "output"} <= keys <= {"decisionId", "output", "failed"}
        and isinstance(body["decisionId"], str)
        and isinstance(body.get("failed", False), bool)
    ):
        typed.append(True)
        failed = body.get("failed")
        return client.record_result(session, body["decisionId"], body["output"], failed=failed, timeout=TIMEOUT).output
    if (
        kind == "input"
        and {"source", "content"} <= keys <= {"source", "content", "private"}
        and isinstance(body["source"], str)
        and isinstance(body.get("private", False), bool)
    ):
        typed.append(True)
        client.report_input(session, body["source"], body["content"], private=body.get("private"), timeout=TIMEOUT)
        return None
    if kind == "prompt" and keys == {"text"} and isinstance(body["text"], str):
        typed.append(True)
        client.record_prompt(session, body["text"], timeout=TIMEOUT)
        return None
    typed.append(False)
    path = f"/v1/sessions/{quote(session, safe='')}/{ENDPOINT[kind]}"
    answer = _raw(client, path, body, _identity)
    out = answer.get("output") if isinstance(answer, dict) else None
    return out if isinstance(out, str) else None


def run_vector(sidecar: Sidecar, vector: dict[str, Any], typed: list[bool]) -> tuple[list[Any], list[Any]]:
    """The vector's steps through the SDK: (what the sidecar answered, what the vector expects), in `expect` shape."""
    started = sidecar.ask({"op": "start", "vector": vector})
    steps: list[dict[str, Any]] = started["steps"]
    decisions: dict[int, Decision] = {}

    def ref(v: Any) -> Any:
        if isinstance(v, str) and v.startswith("@step:") and v[6:].isdigit():
            d = decisions.get(int(v[6:]))
            return d.decision_id if d is not None else None
        return v

    out: list[Any] = []
    try:
        sock = started["socket"]
        agent = Client(socket_path=sock, token=started["token"], decide_timeout=TIMEOUT, timeout=TIMEOUT)
        # The agent's network middleware's token, for steps with "token": "network".
        network = Client(socket_path=sock, token=started["networkToken"], decide_timeout=TIMEOUT, timeout=TIMEOUT)
        with agent as a, network as n:
            for i, step in enumerate(steps):
                kind, req = step["kind"], step["request"]
                c = n if step.get("token") == "network" else a
                try:
                    if kind == "decide":
                        d = _decide(c, req, typed)
                        decisions[i] = d
                        got: dict[str, Any] = {"verdict": d.verdict, "ruleIds": sorted({r.id for r in d.rules})}
                        if req.get("dryRun") is not True:
                            got["sessionUntrusted"] = d.session.untrusted
                            got["holdsPrivateData"] = d.session.holds_private_data
                        out.append(got)
                    elif kind == "approve":
                        held = decisions.get(int(str(req["decisionId"]).removeprefix("@step:")))
                        assert held is not None and held.approval is not None, f"step {i}: nothing to approve"
                        sidecar.ask({"op": "approve", "id": held.approval.id})
                        out.append({})
                    else:
                        # The session is the URL path in the API; without a usable one, the body keeps it (refused).
                        session = req.get("session")
                        usable = isinstance(session, str) and session != ""
                        body = {k: v for k, v in req.items() if k != "session"} if usable else dict(req)
                        if "decisionId" in body:
                            body["decisionId"] = ref(body["decisionId"])
                            if body["decisionId"] is None:
                                del body["decisionId"]  # as JSON.stringify drops an undefined reference
                        redacted = _record(c, kind, session if usable else "_", body, typed)
                        info = c.get_session(session)
                        got = {"sessionUntrusted": info.untrusted, "holdsPrivateData": info.holds_private_data}
                        if redacted is not None:
                            got["redacted"] = redacted
                        out.append(got)
                except FirewallAPIError as e:
                    if e.status != 400:
                        raise
                    out.append({"error": 400})
    finally:
        sidecar.ask({"op": "stop"})
    # Where the API answers otherwise than the library by design, the vector records that answer (expectApi).
    return out, [s.get("expectApi", s["expect"]) for s in steps]


# --- the tests ------------------------------------------------------------------------------------


def test_there_are_vectors() -> None:
    assert len(VECTORS) >= 150
    assert len({v["id"] for v in VECTORS}) == len(VECTORS)


@pytest.mark.parametrize("vector", VECTORS, ids=[v["id"] for v in VECTORS])
def test_vector(sidecar: Sidecar, vector: dict[str, Any]) -> None:
    typed: list[bool] = []
    got, want = run_vector(sidecar, vector, typed)
    assert got == want
    # A body the typed calls cannot express is only ever one the contract refuses, or a network middleware's request
    # (context.traffic "network": the SDK is an agent's client and has no field for it).
    for step, was_typed in zip((s for s in vector["steps"] if s["kind"] != "approve"), typed, strict=True):
        network = step.get("token") == "network" or _traffic(step["request"]) == "network"
        refused = step.get("expectApi", step["expect"]) == {"error": 400}
        assert was_typed or network or refused, f"the SDK cannot send {step['request']}"


def _traffic(req: Any) -> Any:
    ctx = req.get("context") if isinstance(req, dict) else None
    return ctx.get("traffic") if isinstance(ctx, dict) else None
