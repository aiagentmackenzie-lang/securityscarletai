"""AUD-014/AUD-015/AUD-034/AUD-083: packaging contract pins.

The multi-target Docker build splits the runtime into two images:
api/mcp carry ONLY the main dependency group (no Streamlit stack); the
dashboard target adds the dashboard group. These pins exist because the
packaging contract is easy to drift silently:

- a dependency re-added to [project.dependencies] instead of the dashboard
  group silently re-inflates the api/mcp image (the finding's exact cost);
- numpy/scikit-learn/joblib REMOVED from main breaks the API entrypoint's
  boot-time model training (entrypoint steps 4-5 train AlertTriageModel and
  UEBABaseline — sklearn/numpy/joblib are API runtime deps, NOT
  dashboard-only; the original audit's claim said otherwise and was wrong);
- jinja2/markupsafe undeclared = undeclared transitive deps (AUD-034/083):
  they arrive via streamlit→jinja2→markupsafe in dev, but the api/mcp image
  no longer carries streamlit, so both are direct imports there;
- the Makefile format target must match the lint/CI scope (dashboard/
  included) or dashboard code drifts unformatted.

Pins read the FILES (pyproject, Dockerfile, compose, Makefile, entrypoint) —
structural markers only, never prose.
"""

import tomllib
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_PYPROJECT = _REPO / "pyproject.toml"
_DOCKERFILE = _REPO / "Dockerfile"
_COMPOSE = _REPO / "docker-compose.yml"
_MAKEFILE = _REPO / "Makefile"
_ENTRYPOINT = _REPO / "scripts" / "entrypoint.sh"

DASHBOARD_ONLY_DEPS = {"pandas", "streamlit", "altair", "streamlit-autorefresh"}
MAIN_REQUIRED_DEPS = {"numpy", "scikit-learn", "joblib"}
DECLARED_DIRECT_DEPS = {"jinja2", "markupsafe"}


def _pyproject() -> dict:
    return tomllib.loads(_PYPROJECT.read_text())


def test_dashboard_group_exists_and_carries_exactly_the_viz_stack():
    groups = _pyproject()["dependency-groups"]
    assert "dashboard" in groups, (
        "the dashboard group must exist (AUD-014 split) — api/mcp images ship "
        "without the Streamlit stack only while these deps stay grouped"
    )
    names = {d.split(" ")[0].split(">")[0].split("=")[0] for d in groups["dashboard"]}
    assert names == DASHBOARD_ONLY_DEPS, (
        f"dashboard group drifted: {sorted(names)} != {sorted(DASHBOARD_ONLY_DEPS)}"
    )


def test_dashboard_group_is_not_optional():
    """Optional group → host `poetry install` skips it → unit tests (which
    import dashboard.*, which imports streamlit at module level) fail."""
    data = _pyproject()
    tool_groups = data.get("tool", {}).get("poetry", {}).get("group", {})
    dash = tool_groups.get("dashboard", {})
    optional = dash.get("optional", False) if isinstance(dash, dict) else False
    assert not optional, "dashboard group must stay non-optional (dev/CI installs it)"


def test_dashboard_viz_deps_are_not_main_dependencies():
    main = _pyproject()["project"]["dependencies"]
    main_names = {d.split(" ")[0].split(">")[0].split("=")[0] for d in main}
    leaked = main_names & DASHBOARD_ONLY_DEPS
    assert not leaked, (
        f"dashboard-only deps reappeared in [project.dependencies]: {sorted(leaked)} — "
        "they would ship in the api/mcp image again (the AUD-014 cost)"
    )


def test_ml_training_deps_stay_in_main_dependencies():
    # The entrypoint trains AlertTriageModel + UEBABaseline at boot; these are
    # api RUNTIME deps. Moving them to the dashboard group crash-loops the API
    # container on first boot (ImportError in src/ai/alert_triage.py / ueba.py).
    main = _pyproject()["project"]["dependencies"]
    main_names = {d.split(" ")[0].split(">")[0].split("=")[0] for d in main}
    missing = MAIN_REQUIRED_DEPS - main_names
    assert not missing, (
        f"ML deps left [project.dependencies]: {sorted(missing)} — the API "
        "entrypoint trains both models at boot and imports them directly"
    )
    # The entrypoint actually trains them — the contract above is not theoretical.
    entry = _ENTRYPOINT.read_text()
    assert "from src.ai.alert_triage import AlertTriageModel" in entry
    assert "from src.ai.ueba import UEBABaseline" in entry


def test_jinja2_and_markupsafe_are_declared_direct_dependencies():
    # AUD-034 (markupsafe — src/ai/untrusted.py) + AUD-083 (jinja2 —
    # src/ai/prompts.py). Both are direct imports in api-core code and the
    # api/mcp image no longer carries streamlit (their old transitive source).
    main = _pyproject()["project"]["dependencies"]
    main_names = {d.split(" ")[0].split(">")[0].split("=")[0] for d in main}
    missing = DECLARED_DIRECT_DEPS - main_names
    assert not missing, (
        f"undeclared direct deps: {sorted(missing)} — declared because the "
        "api/mcp image no longer carries the streamlit chain that supplied them"
    )


def test_pysigma_is_not_a_dependency():
    # W5-G: the pySigma PostgreSQLBackend was deleted (off-path dead code
    # with a lying docstring); the production path is the legacy parser in
    # src/detection/sigma.py. The dependency must not silently return.
    main = _pyproject()["project"]["dependencies"]
    main_names = {d.split(" ")[0].split(">")[0].split("=")[0] for d in main}
    assert "pysigma" not in main_names, "pysigma must stay removed (supply-chain reduction)"


def test_dockerfile_builds_split_targets_without_the_dashboard_group_for_api():
    dockerfile = _DOCKERFILE.read_text()
    # The api builder must exclude the dashboard group...
    assert "poetry install --without dev,dashboard" in dockerfile
    # ...and the dashboard builder must exclude DEV (poetry's default install
    # adds the dev group — measured: it re-evicts pytest/mypy/ruff into the
    # dashboard runtime image) while adding the dashboard group.
    assert "poetry install --without dev --with dashboard" in dockerfile
    # The runtime targets are declared as children of a shared base.
    assert "FROM runtime-base AS dashboard" in dockerfile
    assert "FROM runtime-base AS api" in dockerfile
    # api stays the DEFAULT (last stage): bare `docker build .` must produce
    # the api image (ci/release build steps pin it explicitly too, but the
    # default is the bare-`docker build` contract).
    last_from = [line for line in dockerfile.splitlines() if line.startswith("FROM")][-1]
    assert last_from.strip() == "FROM runtime-base AS api", (
        f"last Dockerfile stage is {last_from!r} — api must remain the default target"
    )


def test_compose_services_pin_their_dockerfile_targets():
    compose = _COMPOSE.read_text()
    assert "target: api" in compose, "api + mcp services must build the api target"
    assert "target: dashboard" in compose, "dashboard service must build the dashboard target"


def test_makefile_format_target_covers_the_lint_scope():
    # AUD-015: format must include every path lint checks (lint = src + dashboard;
    # CI format --check = src + dashboard + scripts + tests).
    makefile = _MAKEFILE.read_text()
    format_lines = [
        ln for ln in makefile.splitlines() if ln.lstrip().startswith("poetry run ruff format")
    ]
    assert format_lines, "Makefile format recipe missing"
    recipe = format_lines[0]
    # Must be a REAL recipe line (tab-prefixed), not prose or a comment.
    assert recipe.startswith("\t"), "format recipe must be a tab-prefixed Makefile recipe"
    for scope in ("src/", "tests/", "scripts/", "dashboard/"):
        assert scope in recipe, (
            f"make format is missing {scope} (lints and CI check it) — formatting drift"
        )
