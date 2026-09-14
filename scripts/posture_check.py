#!/usr/bin/env python3
"""Posture / mode-isolation check for SecurityScarletAI (V0.3 build hygiene).

Fail-closed by design. Answers the one question that has bitten this
project twice: WHICH MODE is this boot, and is the environment honest
about it?

Modes (one mode per volume — never mix):
  prod  — local-production SIEM: PASSWORD_PEPPER or DATABASE_SUPERUSER_URL
          set (the local-prod overlay markers). Real telemetry, real data.
  demo  — DEMO_SEED_ENABLED=true: synthetic seed data for client demos.
  dev   — neither: plain compose, no seed, no pepper.

Checks (each returns a Problem or None):
  1. Prod posture must NOT carry the demo seed flag — a fresh prod volume
     booted with DEMO_SEED_ENABLED=true is born demo-seeded (demo data +
     demo_analyst user), silently. That is "the demo ruined the build".
  2. A PROD boot on a volume already seeded by the demo (demo_analyst
     user present) is a mode violation — refuse; the volume needs a
     documented down -v + re-bootstrap (HITL).
  3. (V0.7, found live 2026-09-12) A DEMO boot must NOT carry
     ENABLE_INGESTION_SHIPPER=true — the standing prod .env value rides
     along and the demo volume ingests REAL host telemetry (4,239 real
     rows leaked into a demo volume before this check existed).

Exit codes: 0 = pass, 1 = violation (caller must STOP).
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Optional

from src.config.logging import get_logger

log = get_logger("build.posture_check")

PROD_MARKERS = ("PASSWORD_PEPPER", "DATABASE_SUPERUSER_URL")


@dataclass
class Problem:
    check: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.check}] {self.detail}"


def _truthy(value: Optional[str]) -> bool:
    return (value or "").strip().lower() == "true"


def detect_posture(env: dict) -> str:
    """Classify the boot posture from environment markers."""
    if _truthy(env.get("DEMO_SEED_ENABLED")):
        return "demo"
    if any(env.get(marker) for marker in PROD_MARKERS):
        return "prod"
    return "dev"


def check_demo_flag_in_prod(env: dict) -> Optional[Problem]:
    """Prod posture with DEMO_SEED_ENABLED=true must refuse to boot.

    The demo seed rewrites the volume it runs on; letting it ride along
    on a prod boot is exactly the demo-ruins-build failure this check
    exists to prevent.
    """
    if _truthy(env.get("DEMO_SEED_ENABLED")) and any(env.get(marker) for marker in PROD_MARKERS):
        return Problem(
            check="demo-flag-in-prod",
            detail=(
                "DEMO_SEED_ENABLED=true is set alongside local-prod markers "
                "(PASSWORD_PEPPER/DATABASE_SUPERUSER_URL). One mode per "
                "volume: unset DEMO_SEED_ENABLED in .env, or use the demo "
                "posture (docs/DEMO.md) — refusing to seed a prod volume."
            ),
        )
    return None


async def check_demo_seeded_volume(conn) -> Optional[Problem]:
    """Refuse a PROD boot on a volume the demo seed has left live.

    The demo seed's signature is an ACTIVE demo_analyst with the
    documented demo credential (siem_users). The Sep 4 prod cutover
    DEACTIVATED the legacy demo user on the standing prod volume, so a
    deactivated row is not a live demo volume -- it is a consciously
    retired account. Checking is_active avoids a permanent false
    positive on the canonical prod deployment.
    """
    present = await conn.fetchval(
        "SELECT 1 FROM siem_users WHERE username = 'demo_analyst' AND is_active LIMIT 1"
    )
    if present:
        return Problem(
            check="demo-seeded-volume-in-prod",
            detail=(
                "Volume has a LIVE demo_analyst account but the boot is "
                "PROD posture. Mode violation: deactivate the demo user "
                "(or down -v + re-bootstrap for full removal; destroys "
                "data, explicit approval per docs/PRODUCTION.md). "
                "Refusing to start."
            ),
        )
    return None


def check_shipper_in_demo(env: dict) -> Optional[Problem]:
    """DEMO posture with ENABLE_INGESTION_SHIPPER=true must refuse to boot.

    Found live 2026-09-12: the standing prod .env value rode along on a
    demo boot and the demo's FileShipper ingested 4,239 REAL host rows
    into a synthetic-data volume (purged, but the gap was real). Demo
    provenance = synthetic-only telemetry; the real-telemetry shipper
    must never run in the demo posture.
    """
    if _truthy(env.get("DEMO_SEED_ENABLED")) and _truthy(env.get("ENABLE_INGESTION_SHIPPER")):
        return Problem(
            check="shipper-in-demo",
            detail=(
                "ENABLE_INGESTION_SHIPPER=true is set alongside "
                "DEMO_SEED_ENABLED=true. The demo volume must be synthetic-"
                "only (the Sep 12 demo boot ingested 4,239 real host rows "
                "this way). Unset ENABLE_INGESTION_SHIPPER for the demo "
                "posture — refusing to start a demo that ingests real "
                "telemetry."
            ),
        )
    return None


async def run_checks(env: dict, conn=None) -> list[Problem]:
    """Run the environment-level checks; volume check only when a conn is given."""
    problems: list[Problem] = []
    posture = detect_posture(env)
    log.info("posture_detected", posture=posture)
    # The conflict checks run REGARDLESS of the classified posture: an
    # ambiguous environment (demo flag + prod markers, or demo flag +
    # real-telemetry shipper) must fail loudly rather than pick a mode.
    demo_flag = check_demo_flag_in_prod(env)
    if demo_flag:
        problems.append(demo_flag)
    shipper = check_shipper_in_demo(env)
    if shipper:
        problems.append(shipper)
    if posture == "prod" and conn is not None:
        seeded = await check_demo_seeded_volume(conn)
        if seeded:
            problems.append(seeded)
    return problems


def main() -> int:  # pragma: no cover — thin CLI wrapper over run_checks

    from src.db.connection import get_pool

    async def _run() -> list[Problem]:
        if detect_posture(os.environ) != "prod":
            return await run_checks(os.environ)
        pool = await get_pool()
        async with pool.acquire() as conn:
            return await run_checks(os.environ, conn)

    problems = asyncio.run(_run())
    if problems:
        for problem in problems:
            print(f"POSTURE VIOLATION: {problem}", flush=True)
        return 1
    print("posture check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
