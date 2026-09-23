"""Deliberately EMPTY package init for src.config (dashboard-boot fix, 2026-09-23).

dashboard/main.py imports `from src.config.version import APP_VERSION` --
and importing ANY src.config submodule executes THIS package __init__. The
old eager `from src.config.settings import settings` instantiated the FULL
API Settings here, requiring DB_PASSWORD / API_SECRET_KEY / API_BEARER_TOKEN
-- env the Streamlit dashboard (an API CLIENT with no DB access, no .env in
its image) never receives. First boot on the AUD-014 packaging-split image
surfaced it: the Streamlit server returns 200 /_stcore 200 even with a
crashed script, so the container reported "healthy" while the app rendered
a pydantic ValidationError page.

Contract, deliberately boring:
- Import config pieces from their SUBMODULES (`from src.config.settings
  import settings`, `from src.config.http_client import ...`) -- never via
  the package. The import system's submodule fallback keeps legacy
  `from src.config import http_client` working.
- NO re-exports here: a package-attr `from src.config import settings`
  binds the settings MODULE (Python's own submodule-binding), not the
  Settings instance -- that asymmetry is exactly what an eager or lazy
  re-export would make ambiguous. Direct submodule imports are unambiguous.
"""
