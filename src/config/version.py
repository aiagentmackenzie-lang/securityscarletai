"""Single source for the application version.

pyproject.toml declares package-mode = false, so the project is never
installed as a package and importlib.metadata cannot resolve it; the file
itself is not copied into the runtime Docker image (builder stage only).
The version therefore lives here, and pyproject.toml must be kept in sync —
enforced by tests/unit/test_version.py (which reads pyproject.toml in the
repo, where both files exist).

Every user-facing version surface must import APP_VERSION instead of
hardcoding a literal: the API's FastAPI metadata (AUD-010, Wave 10), the
MCP server's FastAPI metadata + initialize serverInfo (AUD-037), and the
dashboard footer (AUD-067, Wave 6).
"""

APP_VERSION = "0.8.0"
