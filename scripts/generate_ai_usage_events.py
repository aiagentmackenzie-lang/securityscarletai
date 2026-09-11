"""AI-usage detection-matrix generator (V0.4/5 item 3).

Emits SYNTHETIC AI-usage events in the EXACT producer format
(src/ingestion/ai_usage.py) through the REAL ingest pipe (POST /ingest) --
the same convention as the V0.3 correlation matrix: one host per scenario,
true/false event pairs, no rule can pass on a fake vocabulary.

Scenarios (host ai-matrix-<scenario>, actor ai-matrix-<scenario>):
  TRUE (should fire):
    mcp_tool_denied_burst   15 denied calls  / 15m window  (threshold > 10)
    ai_prompt_injection     1 injection event               (any)
    mcp_tool_call_volume    60 allowed calls / 15m window  (threshold > 50)
    agent_run_burst         25 agent runs   / 15m window   (threshold > 20)
  FALSE (must stay silent):
    mcp_tool_denied_quiet    2 denied calls (below burst threshold)
    mcp_tool_call_quiet      3 allowed calls (below volume threshold)

Usage:
    AI-usage pipeline needs the standing stack:
      python -m scripts.generate_ai_usage_events \\
          --api http://127.0.0.1:8000 --token "$API_BEARER_TOKEN"

Cleanup (HITL): the synthetic rows carry host_name LIKE 'ai-matrix-%' on
logs; delete them the same way the V0.4 matrix rows are purged.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import datetime, timezone

import httpx

from src.config.logging import get_logger
from src.ingestion.ai_usage import build_ai_usage_event
from src.ingestion.schemas import NormalizedEvent

log = get_logger("scripts.generate_ai_usage_events")

MATRIX_HOST = "ai-matrix-{scenario}"
MATRIX_ACTOR = "ai-matrix-{scenario}"
INGEST_TIMEOUT = 10.0


def _events() -> list[tuple[str, list[NormalizedEvent]]]:
    """(scenario_name, events) pairs in the exact producer format."""
    host = lambda s: MATRIX_HOST.format(scenario=s)  # noqa: E731 -- local, documented
    actor = lambda s: MATRIX_ACTOR.format(scenario=s)  # noqa: E731

    scenarios: list[tuple[str, list[NormalizedEvent]]] = []

    # TRUE pairs (rule SHOULD fire) ------------------------------------------------
    denials = [
        build_ai_usage_event(
            "mcp_tool_denied",
            host_name=host("mcp_tool_denied_burst"),
            actor=actor("mcp_tool_denied_burst"),
            tool="investigate",
            session="probing-session",
            detail={"reason": "matrix"},
        )
        for _ in range(15)
    ]
    scenarios.append(("mcp_tool_denied_burst", denials))

    scenarios.append(
        (
            "ai_prompt_injection",
            [
                build_ai_usage_event(
                    "prompt_injection_detected",
                    host_name=host("prompt_injection"),
                    actor=actor("prompt_injection"),
                    detail={"surface": "agent_objective", "matrix": True},
                    severity="high",
                )
            ],
        )
    )

    scenarios.append(
        (
            "mcp_tool_call_volume",
            [
                build_ai_usage_event(
                    "mcp_tool_call",
                    host_name=host("mcp_tool_call_volume"),
                    actor=actor("mcp_tool_call_volume"),
                    tool="hunt",
                    session="scraping-session",
                    detail={"matrix": True},
                )
                for _ in range(60)
            ],
        )
    )

    scenarios.append(
        (
            "agent_run_burst",
            [
                build_ai_usage_event(
                    "agent_run_start",
                    host_name=host("agent_run_burst"),
                    actor=actor("agent_run_burst"),
                    detail={"matrix": True},
                )
                for _ in range(25)
            ],
        )
    )

    # FALSE pairs (must stay silent) -----------------------------------------------
    scenarios.append(
        (
            "mcp_tool_denied_quiet",
            [
                build_ai_usage_event(
                    "mcp_tool_denied",
                    host_name=host("mcp_tool_denied_quiet"),
                    actor=actor("mcp_tool_denied_quiet"),
                    tool="hunt",
                    detail={"reason": "below-threshold"},
                )
                for _ in range(2)
            ],
        )
    )
    scenarios.append(
        (
            "mcp_tool_call_quiet",
            [
                build_ai_usage_event(
                    "mcp_tool_call",
                    host_name=host("mcp_tool_call_quiet"),
                    actor=actor("mcp_tool_call_quiet"),
                    tool="hunt",
                    detail={"matrix": True},
                )
                for _ in range(3)
            ],
        )
    )
    return scenarios


async def _run(api: str, token: str, scenarios: list[tuple[str, list[NormalizedEvent]]]) -> int:
    total = 0
    async with httpx.AsyncClient(timeout=INGEST_TIMEOUT) as client:
        for name, events in scenarios:
            for chunk_start in range(0, len(events), 100):
                chunk = events[chunk_start : chunk_start + 100]
                response = await client.post(
                    f"{api.rstrip('/')}/api/v1/ingest",
                    json=[e.model_dump(by_alias=True, mode="json") for e in chunk],
                    headers={"Authorization": f"Bearer {token}"},
                )
                response.raise_for_status()
                total += len(chunk)
            print(f"  {name}: {len(events)} events")
    return total


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate AI-usage true/false event pairs through the real ingest pipe."
    )
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument(
        "--token",
        default="",
        help="API bearer token (reads API_BEARER_TOKEN from the environment when empty).",
    )
    args = parser.parse_args()

    token = args.token or os.environ.get("API_BEARER_TOKEN", "")
    if not token:
        print("FAIL: no token (--token or API_BEARER_TOKEN env)")
        return 1

    scenarios = _events()
    log.info(
        "ai_usage_matrix_ready",
        scenarios=[name for name, _ in scenarios],
        events=sum(len(e) for _, e in scenarios),
    )
    total = sum(len(e) for _, e in scenarios)
    print(f"Generating {total} events across {len(scenarios)} scenarios...")

    try:
        emitted = asyncio.run(_run(args.api, token, scenarios))
    except Exception as e:
        print(f"FAIL: {e}")
        return 1
    print(f"Emitted {emitted} events (source=ai_usage, category=ai).")
    stamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"Hosts: ai-matrix-* ; generated at {stamp}")
    print(
        "Expect (after a scheduler tick): alerts for mcp_tool_denial_burst, "
        "prompt_injection_attempt, mcp_tool_call_volume, agent_run_burst; "
        "NO alerts for the quiet scenarios."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
