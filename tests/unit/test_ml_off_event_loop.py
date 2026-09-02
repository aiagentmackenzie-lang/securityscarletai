"""P2.7 — ML training off the event loop.

sklearn's fit/cross_val_score are blocking CPU work. The trainers used to
call them synchronously inside async methods — /ai/train (and the hourly
auto-train) froze the WHOLE API for the fit duration.

Deterministic proof: each fit records the thread it ran on, and the test
asserts it is NOT the event-loop thread (asyncio.to_thread always executes
in a worker thread; a sync call would run on the loop thread).
"""
from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from sklearn.ensemble import IsolationForest, RandomForestClassifier


def _mock_pool(rows):
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=rows)

    class AsyncCtx:
        async def __aenter__(self):
            return mock_conn

        async def __aexit__(self, *args):
            return False

    mock_pool = AsyncMock()
    mock_pool.acquire = MagicMock(return_value=AsyncCtx())
    return mock_pool


def _label_rows(n: int) -> list:
    return [
        {"id": i, "status": "resolved" if i % 2 == 0 else "false_positive"}
        for i in range(n)
    ]


def _csv_fixture(tmp_path: Path) -> Path:
    """Well-separated 100-row CSV (50 TP / 50 FP) — same generator the v2
    suite uses."""
    from scripts.generate_training_data import _generate_rows, write_csv

    out = tmp_path / "good.csv"
    write_csv(_generate_rows(n=100, seed=42), out)
    return out


async def test_v1_train_fit_runs_off_event_loop_thread():
    from src.ai.alert_triage import AlertTriageModel

    loop_thread = threading.get_ident()
    fit_threads: list[int] = []
    real_fit = RandomForestClassifier.fit

    def recording_fit(self, X, y):
        fit_threads.append(threading.get_ident())
        return real_fit(self, X, y)

    model = AlertTriageModel(load=False)
    with (
        patch(
            "src.ai.alert_triage.get_pool",
            AsyncMock(return_value=_mock_pool(_label_rows(60))),
        ),
        patch.object(model, "extract_features", AsyncMock(return_value=[0.5] * 11)),
        patch.object(model, "_save_model"),
        patch.object(RandomForestClassifier, "fit", recording_fit),
    ):
        result = await model.train(min_samples=50)

    assert result is True
    assert fit_threads, "fit never ran"
    assert fit_threads[0] != loop_thread, (
        "sklearn fit ran on the event-loop thread — P2.7 regression: "
        "the API freezes during /ai/train again"
    )


async def test_v2_cv_loop_runs_off_event_loop_thread(tmp_path: Path):
    from src.ai.alert_triage import AlertTriageModel

    loop_thread = threading.get_ident()
    fit_threads: list[int] = []
    real_fit = RandomForestClassifier.fit

    def recording_fit(self, X, y):
        fit_threads.append(threading.get_ident())
        return real_fit(self, X, y)

    m = AlertTriageModel(load=False)
    with (
        patch("src.ai.alert_triage.MODEL_DIR", tmp_path / "models"),
        patch.object(RandomForestClassifier, "fit", recording_fit),
    ):
        result = await m.train_v2(csv_path=_csv_fixture(tmp_path))

    assert result["ok"] is True
    assert result["accepted"] is True
    assert fit_threads, "CV folds never ran"
    # EVERY fold fit ran off the loop
    assert all(t != loop_thread for t in fit_threads)


async def test_ueba_train_fit_runs_off_event_loop_thread():
    from src.ai.ueba import UEBABaseline

    loop_thread = threading.get_ident()
    fit_threads: list[int] = []
    real_fit = IsolationForest.fit

    def recording_fit(self, X):
        fit_threads.append(threading.get_ident())
        return real_fit(self, X)

    engine = UEBABaseline()
    features = {
        "login_hour_of_day": 9.0,
        "unique_processes_count": 5.0,
        "command_diversity": 0.5,
        "network_connections_count": 10.0,
        "unique_destination_ips": 4.0,
        "file_access_count": 3.0,
        "sudo_usage_count": 0.0,
        "session_duration_minutes": 30.0,
    }

    async def fake_features(user_name, days=7):
        return dict(features)

    with (
        patch(
            "src.ai.ueba.get_pool",
            AsyncMock(
                return_value=_mock_pool(
                    [{"user_name": f"user{i}"} for i in range(5)]
                )
            ),
        ),
        patch.object(engine, "extract_user_features", fake_features),
        patch.object(engine, "_save_model"),
        patch.object(IsolationForest, "fit", recording_fit),
    ):
        result = await engine.train(min_days=7)

    assert result is True
    assert fit_threads, "fit never ran"
    assert fit_threads[0] != loop_thread
