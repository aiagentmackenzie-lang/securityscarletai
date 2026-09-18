"""Cases-view unit pins (audit Fix Wave 6).

AUD-058: the case list built params["status_filter"] and passed it to
ApiClient.get_cases(status=...) — get_cases' Python parameter is `status`
(it maps to the wire param `status_filter` itself), so every non-"All"
status selection raised TypeError, masked by the view's broad except as a
generic "Unexpected error" banner. The param building is now a pure helper,
pinned here against the real client contract.
"""

from dashboard.api_client import ApiClient
from dashboard.cases_view import _case_query_params


class TestCaseQueryParams:
    def test_status_uses_client_param_name(self):
        """The kwarg must be `status` — passing `status_filter` was the
        TypeError (AUD-058)."""
        params = _case_query_params("In Progress", "All")
        assert params == {"status": "in_progress"}

    def test_all_yields_empty_params(self):
        assert _case_query_params("All", "All") == {}

    def test_severity_forwarded(self):
        assert _case_query_params("All", "High") == {"severity": "high"}

    def test_both_forwarded(self):
        params = _case_query_params("Open", "Critical")
        assert params == {"status": "open", "severity": "critical"}

    def test_params_are_accepted_by_get_cases_signature(self):
        """Contract pin: every key _case_query_params emits must be a real
        get_cases parameter — this is the seam the old code violated."""
        import inspect

        sig = inspect.signature(ApiClient.get_cases)
        for key in _case_query_params("Open", "Critical"):
            assert key in sig.parameters, f"get_cases has no parameter '{key}'"
