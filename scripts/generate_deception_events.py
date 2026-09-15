"""Deception detection-matrix generator (Wave 1 W1.5).

Emits SYNTHETIC deception events in the EXACT producer format
(src/ingestion/deception.py) through the REAL ingest pipe (POST /ingest) --
the same convention as the AI-usage matrix (V0.4/5): one host per
scenario, true/false event pairs, no rule can pass on a fake vocabulary.

Scenarios (host deception-matrix-<scenario>):
  TRUE (should fire):
    canary_file_access   1 canary-file access event  (any; critical)
    canary_token_use     1 token-use event           (any; critical)
    service_probe        8 service probes (any touch fires; dedup gives
                         ONE alert for the host's burst)
  FALSE (must stay silent -- the closed-vocabulary gate):
    unknown_action       2 deception-category events whose event_action is
                         OUTSIDE the closed kind vocabulary
                         (src/ingestion/deception.py). A rogue producer that
                         emits an unmapped deception action must never fire
                         a deception rule -- fail-closed end to end.

Doctrine (W1.5): deception signals are high-fidelity by construction --
canary/token (critical) alerts auto-create a case in create_alert;
probes (high) alert + notify without an auto-case.

Usage:
    Deception pipeline needs the standing stack:
      python -m scripts.generate_deception_events \\
          --api http://127.0.0.1:8000 --token "$API_BEARER_TOKEN"

Cleanup (HITL): the synthetic rows carry host_name LIKE 'deception-matrix-%'
on logs; delete them the same way the V0.4 matrix rows are purged.
"""

from __future__ import annotations

import argparse
import asyncio
import os

import httpx

from src.config.logging import get_logger
from src.ingestion.deception import build_deception_event
from src.ingestion.schemas import NormalizedEvent

log = get_logger("scripts.generate_deception_events")

MATRIX_HOST = "deception-matrix-{scenario}"
INGEST_TIMEOUT = 10.0


def _scenarios() -> list[tuple[str, list[NormalizedEvent]]]:
    """(scenario_name, events) pairs in the exact producer format."""

    def host(scenario: str) -> str:
        return MATRIX_HOST.format(scenario=scenario)

    # TRUE pairs (rule SHOULD fire) ------------------------------------------------
    true_events: list[NormalizedEvent] = [
        build_deception_event(
            "canary_file_access",
            host_name=host("canary_file_access"),
            user_name=host("canary_file_access"),
            component="canary",
            detail={"path": "/var/opt/canary-secrets.txt", "action": "read"},
        ),
        build_deception_event(
            "canary_token_use",
            host_name=host("canary_token_use"),
            user_name=host("canary_token_use"),
            component="canary-token",
            detail={"token_id": "deception-matrix-token"},
        ),
    ]
    probes = [
        build_deception_event(
            "service_probe",
            host_name=host("service_probe"),
            user_name=host("service_probe"),
            component="honeytrap-smb",
            detail={"share": "IPC$", "attempt": i},
        )
        for i in range(8)
    ]
    true_events.extend(probes)

    # FALSE shapes (must stay silent -- the closed-vocabulary gate) ---------------
    # Valid-looking deception traffic whose event_action is outside the closed
    # kind vocabulary: the ingest accepts the row, but NO deception rule selects
    # an unmapped action -- fail-closed, end to end.
    false_events = []
    for _ in range(2):
        unmapped = build_deception_event("service_probe", host_name=host("unknown_action"))
        unmapped = unmapped.model_copy(update={"event_action": "deception_unmapped_kind"})
        false_events.append(unmapped)

    return [
        ("deception_true_pairs", true_events),
        ("deception_false_shapes", false_events),
    ]


async def _ingest(api: str, token: str) -> int:
    """Push every synthetic event through the REAL ingest pipe."""
    headers = {"Authorization": f"Bearer {token}"}
    accepted = 0
    async with httpx.AsyncClient() as client:
        for scenario, events in _scenarios():
            for event in events:
                resp = await client.post(
                    f"{api}/api/v1/ingest",
                    json=[event.model_dump(by_alias=True, mode="json")],
                    headers=headers,
                    timeout=INGEST_TIMEOUT,
                )
                if resp.status_code == 202:
                    accepted += 1
                else:
                    log.error(
                        "deception_matrix_ingest_failed",
                        scenario=scenario,
                        status=resp.status_code,
                        body=resp.text[:200],
                    )
    log.info("deception_matrix_done", accepted=accepted)
    return accepted


def main() -> None:
    parser = argparse.ArgumentParser(description="Deception detection-matrix generator")
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument(
        "--token",
        default=os.environ.get("API_BEARER_TOKEN", ""),
        help="Ingest bearer token (defaults to $API_BEARER_TOKEN)",
    )
    args = parser.parse_args()
    if not args.token:
        raise SystemExit("an ingest token is required (--token or $API_BEARER_TOKEN)")
    asyncio.run(_ingest(args.api, args.token))


if __name__ == "__main__":
    main()
