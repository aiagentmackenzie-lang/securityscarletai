"""Integration test configuration.

Integration tests require a live PostgreSQL database.
They are automatically skipped when the DB is unavailable.
"""

import os

import pytest

# Skip all integration tests if no DATABASE_URL is configured
# or if the DB is not reachable.
_SKIP_INTEGRATION = not os.environ.get("DATABASE_URL") and not os.environ.get(
    "RUN_INTEGRATION_TESTS"
)


def pytest_configure(config):
    """Register the 'integration' marker."""
    config.addinivalue_line("markers", "integration: mark test as requiring a live database")


def pytest_collection_modifyitems(items):
    """Skip integration tests when DB is unavailable."""
    if _SKIP_INTEGRATION:
        skip_integration = pytest.mark.skip(
            reason="Integration tests require DATABASE_URL or RUN_INTEGRATION_TESTS=1"
        )
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)
