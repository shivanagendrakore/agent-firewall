from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

# The Agents SDK exports traces to OpenAI unless told not to: tests make no network calls.
os.environ["OPENAI_AGENTS_DISABLE_TRACING"] = "1"
# Nor does CrewAI (older releases send telemetry by default and ask about tracing).
os.environ["CREWAI_DISABLE_TELEMETRY"] = "true"
os.environ["CREWAI_TRACING_ENABLED"] = "false"
os.environ["OTEL_SDK_DISABLED"] = "true"

from .fake_sidecar import Served


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """No test reads the real token or firewall home."""
    monkeypatch.delenv("LAUNCHSAFE_FIREWALL_TOKEN", raising=False)
    monkeypatch.setenv("LAUNCHSAFE_FIREWALL_HOME", str(tmp_path / "fw-home"))


@pytest.fixture(params=["uds", "tcp"])
def served(request: pytest.FixtureRequest) -> Iterator[Served]:
    s = Served(request.param)
    try:
        yield s
    finally:
        s.close()


@pytest.fixture
def tcp() -> Iterator[Served]:
    s = Served("tcp")
    try:
        yield s
    finally:
        s.close()
