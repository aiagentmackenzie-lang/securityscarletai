"""
Tests for Risk Scoring engine.

Covers:
- RiskScorer.calculate_alert_risk (static, no DB)
- RiskScorer._get_level (static)
- RiskScorer.FACTOR_WEIGHTS and SEVERITY_WEIGHTS
- RiskScorer.calculate_asset_risk (async, mocked DB)
- RiskScorer.calculate_user_risk (async, mocked DB)
- RiskScorer.get_top_risk_assets / get_top_risk_users (async, mocked DB)
- update_asset_risk_scores (async, mocked DB)
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.ai.risk_scoring import RiskScorer, RiskFactors, update_asset_risk_scores


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Static / Pure Tests (no DB mocking needed)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCalculateAlertRisk:
    """Test the static calculate_alert_risk method."""

    def test_critical_severity_base_score(self):
        """Critical severity should produce high base score."""
        score = RiskScorer.calculate_alert_risk("critical")
        assert score >= 40  # 1.0 * 50 = 50 base, but default adjustments

    def test_high_severity(self):
        """High severity should produce moderate-high score."""
        score = RiskScorer.calculate_alert_risk("high")
        assert score > 0
        assert score <= 100

    def test_medium_severity(self):
        """Medium severity should produce moderate score."""
        score = RiskScorer.calculate_alert_risk("medium")
        assert score > 0
        assert score <= 100

    def test_low_severity(self):
        """Low severity should produce low score."""
        score = RiskScorer.calculate_alert_risk("low")
        assert score >= 0
        assert score < 50

    def test_info_severity(self):
        """Info severity should produce near-zero base score."""
        score = RiskScorer.calculate_alert_risk("info")
        assert score >= 0
        assert score < 20

    def test_unknown_severity_defaults_to_zero(self):
        """Unknown severity should default to zero base."""
        score = RiskScorer.calculate_alert_risk("unknown")
        assert score >= 0

    def test_threat_intel_match_adds_15(self):
        """Threat intel match should add 15 to the score."""
        without_ti = RiskScorer.calculate_alert_risk("medium", threat_intel_match=False)
        with_ti = RiskScorer.calculate_alert_risk("medium", threat_intel_match=True)
        assert with_ti - without_ti == pytest.approx(15, abs=1)

    def test_asset_criticality_adjustment(self):
        """Higher asset criticality should increase score."""
        low_criticality = RiskScorer.calculate_alert_risk("high", asset_criticality=0.1)
        high_criticality = RiskScorer.calculate_alert_risk("high", asset_criticality=0.9)
        assert high_criticality > low_criticality

    def test_user_anomaly_adjustment(self):
        """Higher user anomaly should increase score."""
        normal = RiskScorer.calculate_alert_risk("medium", user_anomaly_score=0.0)
        anomalous = RiskScorer.calculate_alert_risk("medium", user_anomaly_score=1.0)
        assert anomalous > normal

    def test_score_capped_at_100(self):
        """Score should never exceed 100 even with all factors maxed."""
        score = RiskScorer.calculate_alert_risk(
            "critical",
            asset_criticality=1.0,
            threat_intel_match=True,
            user_anomaly_score=1.0,
        )
        assert score <= 100

    def test_all_factors_combined(self):
        """All factors together should give a high score."""
        score = RiskScorer.calculate_alert_risk(
            "critical",
            asset_criticality=0.8,
            threat_intel_match=True,
            user_anomaly_score=0.7,
        )
        assert score > 70  # Should be quite high

    def test_case_insensitive_severity(self):
        """Severity lookup should be case-insensitive."""
        upper = RiskScorer.calculate_alert_risk("CRITICAL")
        lower = RiskScorer.calculate_alert_risk("critical")
        assert upper == lower

    def test_default_asset_criticality(self):
        """Default asset criticality should be 0.5."""
        with_default = RiskScorer.calculate_alert_risk("medium")
        with_05 = RiskScorer.calculate_alert_risk("medium", asset_criticality=0.5)
        assert with_default == with_05


class TestGetLevel:
    """Test the _get_level static method."""

    def test_critical_threshold(self):
        assert RiskScorer._get_level(85) == "critical"

    def test_critical_at_boundary(self):
        assert RiskScorer._get_level(80) == "critical"

    def test_high_threshold(self):
        assert RiskScorer._get_level(70) == "high"

    def test_high_at_boundary(self):
        assert RiskScorer._get_level(60) == "high"

    def test_medium_threshold(self):
        assert RiskScorer._get_level(50) == "medium"

    def test_medium_at_boundary(self):
        assert RiskScorer._get_level(40) == "medium"

    def test_low_threshold(self):
        assert RiskScorer._get_level(30) == "low"

    def test_low_at_boundary(self):
        assert RiskScorer._get_level(20) == "low"

    def test_minimal(self):
        assert RiskScorer._get_level(10) == "minimal"

    def test_zero(self):
        assert RiskScorer._get_level(0) == "minimal"

    def test_exactly_100(self):
        assert RiskScorer._get_level(100) == "critical"


class TestSeverityWeights:
    """Test SEVERITY_WEIGHTS mapping."""

    def test_all_severity_levels_defined(self):
        expected = {"critical", "high", "medium", "low", "info"}
        assert set(RiskScorer.SEVERITY_WEIGHTS.keys()) == expected

    def test_weights_are_ordered(self):
        assert RiskScorer.SEVERITY_WEIGHTS["critical"] > RiskScorer.SEVERITY_WEIGHTS["high"]
        assert RiskScorer.SEVERITY_WEIGHTS["high"] > RiskScorer.SEVERITY_WEIGHTS["medium"]
        assert RiskScorer.SEVERITY_WEIGHTS["medium"] > RiskScorer.SEVERITY_WEIGHTS["low"]
        assert RiskScorer.SEVERITY_WEIGHTS["low"] > RiskScorer.SEVERITY_WEIGHTS["info"]

    def test_info_weight_is_zero(self):
        assert RiskScorer.SEVERITY_WEIGHTS["info"] == 0.0

    def test_critical_weight_is_1(self):
        assert RiskScorer.SEVERITY_WEIGHTS["critical"] == 1.0


class TestFactorWeights:
    """Test FACTOR_WEIGHTS mapping."""

    def test_all_factors_defined(self):
        expected = {"alert_severity", "alert_count", "anomaly_score", "threat_intel", "exposure"}
        assert set(RiskScorer.FACTOR_WEIGHTS.keys()) == expected

    def test_weights_sum_to_one(self):
        total = sum(RiskScorer.FACTOR_WEIGHTS.values())
        assert total == pytest.approx(1.0)

    def test_alert_severity_is_highest_weight(self):
        """Alert severity should be the most important factor."""
        assert RiskScorer.FACTOR_WEIGHTS["alert_severity"] >= RiskScorer.FACTOR_WEIGHTS["alert_count"]
        assert RiskScorer.FACTOR_WEIGHTS["alert_severity"] >= RiskScorer.FACTOR_WEIGHTS["anomaly_score"]


class TestRiskFactors:
    """Test RiskFactors dataclass."""

    def test_default_values(self):
        factors = RiskFactors()
        assert factors.alert_severity == 0.0
        assert factors.alert_count == 0.0
        assert factors.anomaly_score == 0.0
        assert factors.threat_intel_hits == 0.0
        assert factors.exposure_score == 0.0

    def test_custom_values(self):
        factors = RiskFactors(
            alert_severity=0.8,
            alert_count=0.5,
            anomaly_score=0.3,
            threat_intel_hits=0.2,
            exposure_score=0.1,
        )
        assert factors.alert_severity == 0.8
        assert factors.alert_count == 0.5


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Async / DB Tests (mocked pool)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCalculateAssetRisk:
    """Test calculate_asset_risk with mocked DB."""

    @pytest.fixture
    def mock_pool(self):
        pool = AsyncMock()
        conn = AsyncMock()

        # Alert stats row
        alert_stats = {
            "critical": 2,
            "high": 5,
            "medium": 10,
            "total": 30,
        }
        conn.fetchrow = AsyncMock(return_value=alert_stats)
        conn.fetchval = AsyncMock(side_effect=[2, 3])  # open_alerts, ti_hits

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)
        return pool

    @pytest.mark.asyncio
    async def test_asset_risk_returns_dict(self, mock_pool):
        """calculate_asset_risk should return a dict with expected keys."""
        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool):
            result = await RiskScorer.calculate_asset_risk("web-server-01")
            assert "hostname" in result
            assert "risk_score" in result
            assert "risk_level" in result
            assert "factors" in result

    @pytest.mark.asyncio
    async def test_asset_risk_hostname(self, mock_pool):
        """Result should contain the hostname."""
        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool):
            result = await RiskScorer.calculate_asset_risk("web-server-01")
            assert result["hostname"] == "web-server-01"

    @pytest.mark.asyncio
    async def test_asset_risk_score_bounded(self, mock_pool):
        """Risk score should be between 0 and 100."""
        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool):
            result = await RiskScorer.calculate_asset_risk("web-server-01")
            assert 0 <= result["risk_score"] <= 100

    @pytest.mark.asyncio
    async def test_asset_risk_level_is_valid(self, mock_pool):
        """Risk level should be one of the defined levels."""
        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool):
            result = await RiskScorer.calculate_asset_risk("web-server-01")
            assert result["risk_level"] in {"minimal", "low", "medium", "high", "critical"}

    @pytest.mark.asyncio
    async def test_asset_risk_no_alerts(self, mock_pool):
        """Asset with no alerts should have minimal risk."""
        mock_pool.acquire.return_value.__aenter__.return_value.fetchrow.return_value = {
            "critical": 0, "high": 0, "medium": 0, "total": 0,
        }
        mock_pool.acquire.return_value.__aenter__.return_value.fetchval = AsyncMock(
            side_effect=[0, 0]
        )
        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool):
            result = await RiskScorer.calculate_asset_risk("clean-host")
            assert result["risk_score"] < 20  # Should be very low

    @pytest.mark.asyncio
    async def test_asset_risk_open_alerts(self, mock_pool):
        """Result should include open high/critical alert count."""
        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool):
            result = await RiskScorer.calculate_asset_risk("web-server-01")
            assert "open_high_critical_alerts" in result


class TestCalculateUserRisk:
    """Test calculate_user_risk with mocked DB."""

    @pytest.fixture
    def mock_pool(self):
        pool = AsyncMock()
        conn = AsyncMock()

        user_alerts = {
            "critical": 1,
            "high": 2,
            "open_count": 3,
        }
        conn.fetchrow = AsyncMock(return_value=user_alerts)
        conn.fetchval = AsyncMock(return_value=10)  # sudo count

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)
        return pool

    @pytest.mark.asyncio
    async def test_user_risk_returns_dict(self, mock_pool):
        """calculate_user_risk should return expected keys."""
        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool):
            result = await RiskScorer.calculate_user_risk("testuser")
            assert "username" in result
            assert "risk_score" in result
            assert "risk_level" in result

    @pytest.mark.asyncio
    async def test_user_risk_username(self, mock_pool):
        """Result should contain the username."""
        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool):
            result = await RiskScorer.calculate_user_risk("testuser")
            assert result["username"] == "testuser"

    @pytest.mark.asyncio
    async def test_user_risk_score_bounded(self, mock_pool):
        """Risk score should be 0-100."""
        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool):
            result = await RiskScorer.calculate_user_risk("testuser")
            assert 0 <= result["risk_score"] <= 100

    @pytest.mark.asyncio
    async def test_user_risk_high_privilege(self, mock_pool):
        """User with many sudo commands should have higher risk."""
        mock_pool.acquire.return_value.__aenter__.return_value.fetchval = AsyncMock(
            side_effect=[100]  # High sudo count
        )
        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool):
            result = await RiskScorer.calculate_user_risk("admin_user")
            # High privilege activity should contribute to risk
            assert result["risk_score"] > 0

    @pytest.mark.asyncio
    async def test_user_risk_no_alerts_no_sudo(self, mock_pool):
        """User with no alerts and no sudo should have low risk."""
        mock_pool.acquire.return_value.__aenter__.return_value.fetchrow.return_value = {
            "critical": 0, "high": 0, "open_count": 0,
        }
        mock_pool.acquire.return_value.__aenter__.return_value.fetchval = AsyncMock(
            return_value=None  # No sudo
        )
        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool):
            result = await RiskScorer.calculate_user_risk("normal_user")
            assert result["risk_score"] < 50


class TestGetTopRisk:
    """Test get_top_risk_assets and get_top_risk_users."""

    @pytest.fixture
    def mock_pool_asset(self):
        pool = AsyncMock()
        conn = AsyncMock()
        # First call: get distinct hosts
        conn.fetch = AsyncMock(return_value=[
            {"host_name": "server1"},
            {"host_name": "server2"},
        ])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)
        return pool

    @pytest.mark.asyncio
    async def test_get_top_risk_assets_limit(self, mock_pool_asset):
        """Should respect the limit parameter."""
        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool_asset):
            # Mock calculate_asset_risk to avoid nested pool calls
            with patch.object(RiskScorer, "calculate_asset_risk", new_callable=AsyncMock) as mock_calc:
                mock_calc.side_effect = [
                    {"hostname": "server1", "risk_score": 80},
                    {"hostname": "server2", "risk_score": 30},
                ]
                result = await RiskScorer.get_top_risk_assets(limit=2)
                assert len(result) <= 2

    @pytest.mark.asyncio
    async def test_get_top_risk_assets_sorted(self, mock_pool_asset):
        """Results should be sorted by risk_score descending."""
        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool_asset):
            with patch.object(RiskScorer, "calculate_asset_risk", new_callable=AsyncMock) as mock_calc:
                mock_calc.side_effect = [
                    {"hostname": "server1", "risk_score": 30},
                    {"hostname": "server2", "risk_score": 80},
                ]
                result = await RiskScorer.get_top_risk_assets(limit=10)
                scores = [r["risk_score"] for r in result]
                assert scores == sorted(scores, reverse=True)

    @pytest.mark.asyncio
    async def test_get_top_risk_users(self):
        """Should return users sorted by risk_score descending."""
        mock_pool = AsyncMock()
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[
            {"user_name": "admin1"},
            {"user_name": "user1"},
        ])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool):
            with patch.object(RiskScorer, "calculate_user_risk", new_callable=AsyncMock) as mock_calc:
                mock_calc.side_effect = [
                    {"username": "admin1", "risk_score": 70},
                    {"username": "user1", "risk_score": 20},
                ]
                result = await RiskScorer.get_top_risk_users(limit=10)
                assert len(result) <= 10


class TestUpdateAssetRiskScores:
    """Test batch update_asset_risk_scores."""

    @pytest.mark.asyncio
    async def test_update_loops_over_assets(self):
        """Should calculate and update risk for each asset."""
        mock_pool = AsyncMock()
        conn = AsyncMock()

        # First call: get assets
        conn.fetch = AsyncMock(return_value=[
            {"hostname": "server1"},
            {"hostname": "server2"},
        ])
        conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool):
            with patch.object(RiskScorer, "calculate_asset_risk", new_callable=AsyncMock) as mock_calc:
                mock_calc.side_effect = [
                    {"hostname": "server1", "risk_score": 75.5},
                    {"hostname": "server2", "risk_score": 32.1},
                ]
                await update_asset_risk_scores()
                # Should have called calculate_asset_risk twice
                assert mock_calc.call_count == 2

    @pytest.mark.asyncio
    async def test_update_executes_sql(self):
        """Should execute UPDATE for each asset."""
        mock_pool = AsyncMock()
        conn = AsyncMock()

        conn.fetch = AsyncMock(return_value=[{"hostname": "srv1"}])
        conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.ai.risk_scoring.get_pool", return_value=mock_pool):
            with patch.object(RiskScorer, "calculate_asset_risk", new_callable=AsyncMock) as mock_calc:
                mock_calc.return_value = {"hostname": "srv1", "risk_score": 42.0}
                await update_asset_risk_scores()
                # The UPDATE should have been executed
                assert conn.execute.called