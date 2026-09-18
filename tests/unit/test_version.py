"""AUD-037/AUD-010/AUD-067: version drift guard.

Three surfaces hardcoded three different stale versions (API FastAPI
metadata, MCP serverInfo, dashboard footer). APP_VERSION is the single
code-level source; pyproject.toml must match — enforced here, where both
files exist (the repo; the runtime image never sees pyproject.toml).
"""

import tomllib
from pathlib import Path

from src.config.version import APP_VERSION

_PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


def test_app_version_matches_pyproject():
    data = tomllib.loads(_PYPROJECT.read_text())
    pyproject_version = data["project"]["version"]
    assert pyproject_version == APP_VERSION, (
        f"pyproject.toml version {pyproject_version!r} != APP_VERSION {APP_VERSION!r} — "
        "keep src/config/version.py and pyproject.toml in sync"
    )


def test_app_version_is_a_nonempty_semverish_string():
    assert isinstance(APP_VERSION, str)
    assert APP_VERSION.strip()
    parts = APP_VERSION.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)
