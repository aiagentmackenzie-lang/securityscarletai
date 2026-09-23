"""The empty src.config package init (dashboard-boot fix, 2026-09-23).

dashboard/main.py imports `from src.config.version import APP_VERSION` --
which executes src/config/__init__.py. The old eager
`from src.config.settings import settings` instantiated the FULL API
Settings there, requiring DB_PASSWORD/API_SECRET_KEY/API_BEARER_TOKEN --
env the Streamlit dashboard (an API CLIENT, no .env in its image) never
receives. First boot on the AUD-014 packaging-split image surfaced it: the
Streamlit server returns 200 / _stcore 200 even with a crashed script, so
the container reported "healthy" while the app rendered a pydantic
ValidationError page.

The subprocess pins run the REAL interpreter in a directory WITHOUT an
.env (tests/unit cwd) so pydantic-settings cannot fall back to a dotenv
source -- exactly the dashboard container's condition.
"""

import sys
from pathlib import Path
from subprocess import run

REPO = Path(__file__).resolve().parents[2]


class TestEmptyConfigPackageInit:
    def test_version_import_survives_empty_env(self):
        """THE pin: importing src.config.version (the dashboard's only need)
        must NOT require the API's full env. Subprocess = real interpreter +
        import machinery, cwd = a directory with NO .env, empty environment.
        Old code: pydantic ValidationError (non-zero exit)."""
        # argv is a fixed literal + sys.executable -- nothing user-supplied.
        proc = run(  # noqa: S603
            [sys.executable, "-c", "import src.config.version; print('ok')"],
            cwd=str(REPO / "tests" / "unit"),
            env={
                "PATH": "/usr/bin:/bin",
                "PYTHONPATH": str(REPO),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0, f"import failed: {proc.stderr[-500:]}"
        assert proc.stdout.strip() == "ok"

    def test_settings_submodule_import_still_binds_singleton(self):
        """The API path is unchanged: `from src.config.settings import
        settings` executes the module and binds the Settings instance
        (this test env has the repo .env present, so instantiation succeeds)."""
        from src.config.settings import settings

        assert settings.db_password  # required field -- present here
        assert settings.api_bearer_token.get_secret_value()  # noqa: S105

    def test_package_attr_fallback_binds_the_submodule(self):
        """Documented semantics: after any submodule import, the package attr
        is the settings MODULE (Python's own submodule binding) -- which is
        exactly why the package carries no re-exports."""
        import src.config as config_pkg
        import src.config.settings as settings_module  # binds package attr

        assert config_pkg.settings is settings_module
        assert settings_module.settings.db_password  # the instance lives here

    def test_settings_module_is_the_singleton(self):
        """Repeat imports yield ONE Settings instance (module-level
        singleton) -- the API's boot-time contract."""
        import importlib

        from src.config.settings import settings as s1

        s2 = importlib.import_module("src.config.settings").settings
        assert s1 is s2
