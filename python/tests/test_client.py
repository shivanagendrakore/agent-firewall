from __future__ import annotations

import os
import socket
import time
from pathlib import Path

import pytest

from launchsafe_firewall import (
    AsyncClient,
    Client,
    DecideContext,
    FirewallAPIError,
    FirewallProtocolError,
    FirewallRateLimited,
    FirewallServerError,
    FirewallTimeout,
    FirewallUnavailable,
    FirewallUntrustedSocket,
    Guard,
    ModelUsage,
    default_socket_path,
    engine,
    firewall_home,
    from_anthropic_tool_use,
    from_mcp_call,
    from_openai_tool_call,
    native,
)

from .fake_sidecar import TOKEN, Failure, Served


def test_health_needs_no_token(served: Served) -> None:
    with Client(**served.client_kwargs(token=None)) as c:
        h = c.health()
    assert h.ok is True
    assert h.engine is not None and h.engine.version == "0.3.0"
    assert "authorization" not in served.fake.calls("/v1/health")[0].headers


def test_decide_sends_the_contract_body_token_and_idempotency_key(served: Served) -> None:
    with Client(**served.client_kwargs()) as c:
        d = c.decide(
            "run-42",
            native("send_email", {"to": "x@y.com"}, call_id="call_abc"),
            context=DecideContext(attended=False, workspace=("/srv/app",), cwd="/srv/app"),
        )
    assert d.verdict == "allow"
    assert d.decision_id == "dec_1"
    assert d.log is not None and d.log.seq == 1
    seen = served.fake.calls("/v1/decide")[0]
    assert seen.headers["authorization"] == f"Bearer {TOKEN}"
    assert len(seen.headers["idempotency-key"]) == 32
    assert seen.headers["content-type"] == "application/json"
    assert seen.body == {
        "session": "run-42",
        "action": {"format": "native", "tool": "send_email", "input": {"to": "x@y.com"}, "callId": "call_abc"},
        "context": {"attended": False, "workspace": ["/srv/app"], "cwd": "/srv/app"},
    }


def test_decide_keys_differ_per_call_and_a_given_key_is_used(served: Served) -> None:
    with Client(**served.client_kwargs()) as c:
        c.decide("s", native("a"))
        c.decide("s", native("a"))
        first = c.decide("s", native("a"), idempotency_key="k1")
        again = c.decide("s", native("a"), idempotency_key="k1")
    keys = [r.headers["idempotency-key"] for r in served.fake.calls("/v1/decide")]
    assert keys[0] != keys[1]
    assert keys[2:] == ["k1", "k1"]
    assert first == again


def test_dry_run_is_sent(served: Served) -> None:
    served.fake.verdicts["send_email"] = "ask"
    with Client(**served.client_kwargs()) as c:
        d = c.decide("s", native("send_email"), dry_run=True)
    assert served.fake.calls("/v1/decide")[0].body["dryRun"] is True
    assert d.verdict == "ask" and d.approval is None


def test_usage_and_failed_are_sent_only_when_given(served: Served) -> None:
    with Client(**served.client_kwargs()) as c:
        c.decide("s", native("a"), usage=ModelUsage(input_tokens=1200, output_tokens=300, cost_usd=0.0045))
        c.decide("s", native("a"))
        c.record_result("s", "dec_1", "boom", failed=True)
        c.record_result("s", "dec_2", "ok")
    decides = served.fake.calls("/v1/decide")
    assert decides[0].body["usage"] == {"inputTokens": 1200, "outputTokens": 300, "costUsd": 0.0045}
    assert "usage" not in decides[1].body
    results = served.fake.calls("/v1/sessions/s/results")
    assert results[0].body == {"decisionId": "dec_1", "output": "boom", "failed": True}
    assert results[1].body == {"decisionId": "dec_2", "output": "ok"}


def test_every_format_helper_is_accepted_by_the_contract(served: Served) -> None:
    actions = [
        engine("Bash", {"command": "ls"}),
        from_openai_tool_call(
            {"id": "call_1", "type": "function", "function": {"name": "send_email", "arguments": '{"to":"a@b.c"}'}}
        ),
        from_anthropic_tool_use({"type": "tool_use", "id": "toolu_1", "name": "send_email", "input": {"to": "a"}}),
        from_mcp_call("gmail", {"name": "send", "arguments": {"to": "a"}}, source="user"),
    ]
    served.fake.verdicts["mcp__gmail__send"] = "deny"
    with Client(**served.client_kwargs()) as c:
        verdicts = [c.decide("s", a).verdict for a in actions]
    assert verdicts == ["allow", "allow", "allow", "deny"]
    bodies = [r.body["action"] for r in served.fake.calls("/v1/decide")]
    assert bodies[2]["raw"] == {"type": "tool_use", "id": "toolu_1", "name": "send_email", "input": {"to": "a"}}
    assert bodies[3] == {
        "format": "mcp",
        "tool": "send",
        "input": {"to": "a"},
        "mcp": {"server": "gmail", "source": "user"},
    }


def test_session_calls(served: Served) -> None:
    with Client(**served.client_kwargs()) as c:
        r = c.record_result("run/42", "dec_9", "token SECRET here")
        i = c.report_input("run/42", "web page https://example.com", "<p>hi</p>", private=True)
        p = c.record_prompt("run/42", "email the report to ana@example.com")
        s = c.get_session("run/42")
    assert r.recorded is True and r.output == "token [redacted] here"
    assert i.recorded is True and p.recorded is True
    assert s.untrusted is True and s.untrusted_because == ("web page https://example.com",)
    paths = [x.path for x in served.fake.requests]
    # The session id is one path segment, whatever it holds.
    assert paths == [
        "/v1/sessions/run%2F42/results",
        "/v1/sessions/run%2F42/inputs",
        "/v1/sessions/run%2F42/prompts",
        "/v1/sessions/run%2F42",
    ]
    assert served.fake.requests[0].body == {"decisionId": "dec_9", "output": "token SECRET here"}
    assert served.fake.requests[1].body["private"] is True


def test_report_input_leaves_private_out_when_unset(tcp: Served) -> None:
    with Client(**tcp.client_kwargs()) as c:
        c.report_input("s", "doc", {"any": "json"})
    assert tcp.fake.requests[0].body == {"source": "doc", "content": {"any": "json"}}


def test_get_and_wait_for_approval(served: Served) -> None:
    served.fake.verdicts["send_email"] = "hold"
    with Client(**served.client_kwargs()) as c:
        d = c.decide("s", native("send_email"))
        assert d.approval is not None and d.approval.status == "pending"
        assert c.get_approval(d.approval.id).status == "pending"
        served.fake.approval_script[d.approval.id] = ["pending", "pending", "approved"]
        st = c.wait_for_approval(d.approval.id, timeout=5, interval=0.01)
    assert st.status == "approved"
    assert len(served.fake.calls("/v1/approvals/")) == 4


def test_wait_for_approval_returns_pending_at_the_deadline(tcp: Served) -> None:
    tcp.fake.verdicts["x"] = "hold"
    with Client(**tcp.client_kwargs()) as c:
        d = c.decide("s", native("x"))
        assert d.approval is not None
        st = c.wait_for_approval(d.approval.id, timeout=0.1, interval=0.02)
    assert st.status == "pending"


def test_unknown_approval_is_404(tcp: Served) -> None:
    with Client(**tcp.client_kwargs()) as c, pytest.raises(FirewallAPIError) as e:
        c.get_approval("nope")
    assert e.value.status == 404 and e.value.problem.title == "not found"


@pytest.mark.parametrize("status", [400, 401, 403, 404, 413])
def test_4xx_is_an_api_error_with_the_problem(tcp: Served, status: int) -> None:
    tcp.fake.fail("/v1/decide", Failure(status=status))
    with Client(**tcp.client_kwargs()) as c, pytest.raises(FirewallAPIError) as e:
        c.decide("s", native("x"))
    assert e.value.status == status
    assert e.value.problem.status == status and e.value.problem.detail == "x"


def test_429_carries_retry_after(tcp: Served) -> None:
    tcp.fake.fail("/v1/decide", Failure(status=429, headers={"Retry-After": "3"}))
    with Client(**tcp.client_kwargs()) as c, pytest.raises(FirewallRateLimited) as e:
        c.decide("s", native("x"))
    assert e.value.retry_after == 3.0


@pytest.mark.parametrize("status", [500, 502, 503])
def test_5xx_is_a_server_error(tcp: Served, status: int) -> None:
    tcp.fake.fail("/v1/decide", Failure(status=status, body=b"not json"))
    with Client(**tcp.client_kwargs()) as c, pytest.raises(FirewallServerError) as e:
        c.decide("s", native("x"))
    assert e.value.problem.detail == "not json"


@pytest.mark.parametrize("failure", [Failure(malformed=True), Failure(bad_shape=True)])
def test_a_malformed_answer_is_a_protocol_error(served: Served, failure: Failure) -> None:
    served.fake.fail("/v1/decide", failure)
    with Client(**served.client_kwargs()) as c, pytest.raises(FirewallProtocolError):
        c.decide("s", native("x"))


def test_a_slow_decide_times_out_at_250ms(served: Served) -> None:
    served.fake.fail("/v1/decide", Failure(delay=0.6))
    with Client(**served.client_kwargs()) as c, pytest.raises(FirewallTimeout):
        c.decide("s", native("x"))


def test_a_trickled_answer_meets_a_total_deadline(served: Served) -> None:
    # Each byte comes well inside httpx's per-phase timeout; the whole answer would take seconds.
    served.fake.fail("/v1/decide", Failure(trickle=0.05))
    with Client(**served.client_kwargs()) as c:
        start = time.monotonic()
        with pytest.raises(FirewallTimeout):
            c.decide("s", native("x"))
        assert time.monotonic() - start < 1.0


async def test_async_a_trickled_answer_meets_a_total_deadline(tcp: Served) -> None:
    tcp.fake.fail("/v1/decide", Failure(trickle=0.05))
    async with AsyncClient(**tcp.client_kwargs()) as c:
        start = time.monotonic()
        with pytest.raises(FirewallTimeout):
            await c.decide("s", native("x"))
        assert time.monotonic() - start < 1.0


def test_a_socket_open_to_others_gets_no_token(served: Served) -> None:
    if served.kind != "uds":
        pytest.skip("a unix socket check")
    os.chmod(served.socket_path, 0o666)  # noqa: S103 - the permissive socket under test
    with Client(**served.client_kwargs()) as c, pytest.raises(FirewallUntrustedSocket, match="0600"):
        c.decide("s", native("x"))
    assert served.fake.requests == []
    os.chmod(served.socket_path, 0o600)
    read_only = {"r": {"kind": "read", "results": "trusted", "privateData": False}}
    g = Guard(Client(**served.client_kwargs()), tools=read_only)
    os.chmod(served.socket_path, 0o660)
    auth = g.authorize("r", {})
    g.client.close()
    assert not auth.allowed and auth.rule_ids == ("FW-API-ERROR",)  # not an outage: reads do not fail open
    assert served.fake.requests == []


def test_a_socket_another_user_owns_gets_no_token(served: Served, monkeypatch: pytest.MonkeyPatch) -> None:
    if served.kind != "uds":
        pytest.skip("a unix socket check")
    monkeypatch.setattr(os, "getuid", lambda: os.stat(served.socket_path).st_uid + 1)
    with Client(**served.client_kwargs()) as c, pytest.raises(FirewallUntrustedSocket, match="another user"):
        c.decide("s", native("x"))
    assert served.fake.requests == []


def test_token_whitespace_is_stripped(served: Served, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LAUNCHSAFE_FIREWALL_TOKEN", f"  {TOKEN}\n")
    with Client(**served.client_kwargs(token=None)) as c:
        assert c.decide("s", native("x")).verdict == "allow"
    with Client(**served.client_kwargs(token=f"{TOKEN}\r\n")) as c:
        assert c.decide("s", native("x")).verdict == "allow"


def test_a_hang_up_is_unavailable(served: Served) -> None:
    served.fake.fail("/v1/decide", Failure(hang_up=True))
    with Client(**served.client_kwargs()) as c, pytest.raises(FirewallUnavailable):
        c.decide("s", native("x"))


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_refused_connection_and_missing_socket_are_unavailable(tmp_path: Path) -> None:
    with Client(base_url=f"http://127.0.0.1:{_free_port()}", token=TOKEN) as c, pytest.raises(FirewallUnavailable):
        c.decide("s", native("x"))
    with Client(socket_path=tmp_path / "none.sock", token=TOKEN) as c, pytest.raises(FirewallUnavailable):
        c.health()
    (tmp_path / "file.sock").write_text("not a socket")
    with Client(socket_path=tmp_path / "file.sock", token=TOKEN) as c, pytest.raises(FirewallUnavailable):
        c.decide("s", native("x"))


def test_no_token_is_refused_by_the_sidecar(served: Served) -> None:
    with Client(**served.client_kwargs(token=None)) as c, pytest.raises(FirewallAPIError) as e:
        c.decide("s", native("x"))
    assert e.value.status == 401


def test_token_from_the_environment(served: Served, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LAUNCHSAFE_FIREWALL_TOKEN", TOKEN)
    with Client(**served.client_kwargs(token=None)) as c:
        assert c.decide("s", native("x")).verdict == "allow"


def test_an_explicit_token_wins_over_the_environment(tcp: Served, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LAUNCHSAFE_FIREWALL_TOKEN", "wrong")
    with Client(**tcp.client_kwargs()) as c:
        assert c.decide("s", native("x")).verdict == "allow"


@pytest.mark.parametrize("token", ["has space", "line\nbreak", "café"])
def test_a_token_that_could_break_the_header_is_refused(token: str) -> None:
    with pytest.raises(ValueError, match="printable ASCII"):
        Client(base_url="http://127.0.0.1:1", token=token)


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.0.5:8787",
        "https://127.0.0.1:8787",
        "http://example.com",
        "http://127.0.0.1:8787/v1",
        "http://user:pw@127.0.0.1:8787",
    ],
)
def test_base_url_must_be_a_loopback_origin(url: str) -> None:
    with pytest.raises(ValueError, match="base_url"):
        Client(base_url=url)


def test_loopback_origins_are_accepted() -> None:
    for url in ("http://127.0.0.1:8787", "http://localhost:8787/", "http://[::1]:8787"):
        Client(base_url=url).close()


def test_socket_path_and_base_url_are_exclusive() -> None:
    with pytest.raises(ValueError, match="not both"):
        Client(socket_path="/tmp/x.sock", base_url="http://127.0.0.1:1")  # noqa: S108


def test_default_socket_is_in_the_firewall_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LAUNCHSAFE_FIREWALL_HOME", str(tmp_path / "h"))
    assert default_socket_path() == tmp_path / "h" / "api.sock"
    assert Client().socket_path == tmp_path / "h" / "api.sock"
    # Relative is made absolute, as the firewall's resolve() does; empty means unset.
    assert firewall_home({"LAUNCHSAFE_FIREWALL_HOME": "rel"}) == Path.cwd() / "rel"
    assert firewall_home({"LAUNCHSAFE_FIREWALL_HOME": ""}) == Path.home() / ".launchsafe-firewall"
    assert firewall_home({}) == Path.home() / ".launchsafe-firewall"


def test_empty_session_is_refused_before_sending(tcp: Served) -> None:
    with Client(**tcp.client_kwargs()) as c, pytest.raises(ValueError, match="session"):
        c.decide("", native("x"))
    assert tcp.fake.requests == []


# --- async ----------------------------------------------------------------------------------------


async def test_async_client_covers_every_call(served: Served) -> None:
    served.fake.verdicts["send_email"] = "hold"
    async with AsyncClient(**served.client_kwargs()) as c:
        assert (await c.health()).ok
        d = await c.decide("s", native("send_email"))
        assert d.verdict == "hold" and d.approval is not None
        served.fake.approval_script[d.approval.id] = ["denied"]
        assert (await c.wait_for_approval(d.approval.id, timeout=2, interval=0.01)).status == "denied"
        assert (await c.get_approval(d.approval.id)).status == "denied"
        assert (await c.record_result("s", d.decision_id, "SECRET")).output == "[redacted]"
        assert (await c.report_input("s", "doc", "text")).recorded
        assert (await c.record_prompt("s", "hello")).recorded
        assert (await c.get_session("s")).untrusted
    assert "idempotency-key" in served.fake.calls("/v1/decide")[0].headers


async def test_async_errors_match_the_blocking_client(tcp: Served) -> None:
    async with AsyncClient(**tcp.client_kwargs()) as c:
        tcp.fake.fail("/v1/decide", Failure(delay=0.6, times=1))
        with pytest.raises(FirewallTimeout):
            await c.decide("s", native("x"))
        tcp.fake.fail("/v1/decide", Failure(status=429, times=1))
        with pytest.raises(FirewallRateLimited):
            await c.decide("s", native("x"))
        tcp.fake.fail("/v1/decide", Failure(malformed=True, times=1))
        with pytest.raises(FirewallProtocolError):
            await c.decide("s", native("x"))
    async with AsyncClient(base_url=f"http://127.0.0.1:{_free_port()}") as c:
        with pytest.raises(FirewallUnavailable):
            await c.health()
