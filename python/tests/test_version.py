from __future__ import annotations

import re
from pathlib import Path

import launchsafe_firewall


def test_version_matches_pyproject() -> None:
    # A regex, not tomllib: tomllib needs Python 3.11 and the SDK supports 3.10.
    text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    project = text.split("[project]", 1)[1].split("\n[", 1)[0]
    found = re.search(r'^version\s*=\s*"([^"]+)"', project, re.MULTILINE)
    assert found is not None
    assert launchsafe_firewall.__version__ == found.group(1)
