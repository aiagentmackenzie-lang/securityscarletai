"""FT-007 (fleet Wave F): benchmark LLM calls land in ai_usage like any other.

The harness was the one call family that logged tokens but persisted
nothing — the ai_usage doctrine says EVERY LLM call is audited. These
pins capture the record_usage contract at both case runners.
"""

from __future__ import annotations

from typing import Any

import pytest

import scripts.model_benchmark as bench
from src.ai.ollama_client import LLMResult


def _result(**overrides: Any) -> LLMResult:
    defaults: dict[str, Any] = dict(
        ok=True,
        text='{"verdict": "true_positive", "confidence": 0.9}',
        source="ollama",
        model_used="mistral:7b",
        tokens_in=568,
        tokens_out=279,
        latency_ms=3082,
        fallback_used=False,
    )
    defaults.update(overrides)
    return LLMResult(**defaults)


@pytest.mark.asyncio
async def test_verdict_case_records_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    async def fake_record_usage(**kwargs: Any) -> bool:
        captured.update(kwargs)
        return True

    async def fake_query_llm(**kwargs: Any) -> LLMResult:
        return _result()

    monkeypatch.setattr("src.ai.cost_tracker.record_usage", fake_record_usage)
    monkeypatch.setattr(bench, "query_llm", fake_query_llm)

    case = {
        "name": "test_malicious",
        "objective": "Decide the verdict",
        "evidence": [{"message": "reverse shell"}],
    }
    out = await bench.run_verdict_case(case)

    assert out["ok"] is True
    assert captured["endpoint"] == "ai.benchmark_verdict"
    assert captured["user"] is None  # system actor — no per-user quota
    assert captured["model"] == "mistral:7b"
    assert captured["tokens_in"] == 568
    assert captured["tokens_out"] == 279
    assert captured["latency_ms"] == 3082
    assert captured["prompt_version"] == "model_benchmark_verdict_v1"
    assert captured["source"] == "ollama"
    assert captured["fallback_used"] is False


@pytest.mark.asyncio
async def test_explanation_case_records_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    async def fake_record_usage(**kwargs: Any) -> bool:
        captured.update(kwargs)
        return True

    async def fake_query_llm(**kwargs: Any) -> LLMResult:
        return _result(model_used="phi4-mini", tokens_in=400, tokens_out=100)

    monkeypatch.setattr("src.ai.cost_tracker.record_usage", fake_record_usage)
    monkeypatch.setattr(bench, "query_llm", fake_query_llm)

    case = {
        "rule_name": "Reverse Shell Pattern Detected",
        "rule_description": "bash -i observed",
        "severity": "critical",
        "host_name": "demo-host",
        "mitre_techniques": ["T1059"],
        "evidence": {"message": "bash -i"},
        "related_logs_count": 3,
    }
    out = await bench.run_explanation_case(case)

    assert out["source"] == "ollama"
    assert captured["endpoint"] == "ai.benchmark_explanation"
    assert captured["user"] is None
    assert captured["model"] == "phi4-mini"
    assert captured["tokens_in"] == 400
    assert captured["tokens_out"] == 100
    assert captured["prompt_version"] == "model_benchmark_explanation_v1"


@pytest.mark.asyncio
async def test_usage_recording_is_fail_soft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A DB-less benchmark run must still complete (record_usage returns False)."""

    async def failing_record_usage(**kwargs: Any) -> bool:
        # The real record_usage returns False on any DB error (never raises).
        return False

    async def fake_query_llm(**kwargs: Any) -> LLMResult:
        return _result()

    monkeypatch.setattr("src.ai.cost_tracker.record_usage", failing_record_usage)
    monkeypatch.setattr(bench, "query_llm", fake_query_llm)

    case = {
        "name": "test_benign",
        "objective": "Decide",
        "evidence": [{"message": "normal ops"}],
    }
    out = await bench.run_verdict_case(case)
    assert out["ok"] is True  # the benchmark result is unaffected
