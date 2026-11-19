"""Replay the dead-letter queue (P1-E).

Failed write batches are persisted to `data/dead_letter/*.jsonl` by
`src/db/writer.py`. Nothing previously read them back — so on a DB outage,
events were stranded in a file that (a) lived on an ephemeral path in some
deployments and (b) was never replayed even when it survived. This script
reads each JSONL, reconstructs the NormalizedEvent, and re-ingests it. After a
file is fully replayed it moves to `data/dead_letter/processed/` so a re-run
doesn't double-ingest.

SS-040 — a poison row used to come back forever. The replay handed the whole
batch to `writer.flush()`; that call dead-letters a failing batch instead of
raising, so the replay could not tell success from failure, retired the
original file, and the poison row reappeared as a NEW dead-letter file on every
boot — re-attempting the whole batch each time.

Replay is now PER ROW and writes through the same SQL as the writer
(`build_rows`/`insert_rows`), so it can tell which row the database rejected:

  * row rejected as bad data (asyncpg DataError/IntegrityError, ValueError) ->
    quarantined to `data/dead_letter/quarantine/<date>.jsonl` with an
    `attempts` counter; the rest of the file still lands; the file is retired;
  * a row that already carries MAX_REPLAY_ATTEMPTS attempts is dropped
    (logged) instead of being replayed again;
  * anything else (connection lost, DB down) propagates: the file stays in
    place and is retried on the next boot — a transient outage must never
    quarantine good telemetry.

Run standalone:
    python -m scripts.replay_dead_letter

Called by scripts/entrypoint.sh on boot (best-effort, before uvicorn starts)
so stranded events get replayed after a restart.

Best-effort: a malformed line is logged and skipped (the rest of the file
still replays).
"""

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import asyncpg

from src.config.logging import get_logger
from src.db.connection import close_pool, get_pool
from src.db.writer import build_rows, insert_rows
from src.ingestion.schemas import NormalizedEvent

log = get_logger("scripts.replay_dead_letter")

DEAD_LETTER_DIR = Path("data/dead_letter")
PROCESSED_DIR = DEAD_LETTER_DIR / "processed"
# SS-040: rejected rows live here, OUTSIDE the *.jsonl glob the replay reads,
# so a quarantined row cannot re-enter the queue by being replayed again.
QUARANTINE_DIR = DEAD_LETTER_DIR / "quarantine"
# A row that fails this many replay attempts is poison; drop it loudly.
MAX_REPLAY_ATTEMPTS = 3

# Exceptions that mean "this ROW is unpalatable" (quarantine it) as opposed to
# "the database is unavailable right now" (leave the file for the next run).
POISON_ERRORS = (
    asyncpg.DataError,
    asyncpg.IntegrityConstraintViolationError,
    ValueError,
)


async def _persist_event(event: NormalizedEvent) -> None:
    """Persist exactly one event through the writer's own INSERT.

    Deliberately NOT `writer.write()+flush()`: flush swallows (and
    re-dead-letters) a failing batch, which is what made a poison row
    unkillable.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        await insert_rows(conn, build_rows([event]))


def _quarantine(path: Path, record: dict, event: NormalizedEvent, error: str) -> None:
    """Write a rejected row to the quarantine file with an attempt counter."""
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    day = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    target = QUARANTINE_DIR / f"{day}.jsonl"
    attempts = int(record.get("attempts", 0) or 0) + 1
    entry = {
        "quarantined": True,
        "quarantined_at": datetime.now(tz=timezone.utc).isoformat(),
        "source_file": path.name,
        "attempts": attempts,
        "quarantine_reason": error,
        "event": event.model_dump(mode="json"),
    }
    with open(target, "a") as fh:
        fh.write(json.dumps(entry, default=str) + "\n")
    log.error(
        "replay_row_quarantined",
        file=path.name,
        host=event.host_name,
        attempts=attempts,
        error=error[:300],
    )


async def replay_file(path: Path) -> tuple[int, int, int]:
    """Replay one JSONL dead-letter file. Returns (replayed, skipped, quarantined)."""
    replayed = 0
    skipped = 0
    quarantined = 0
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            event_payload = record.get("event") if isinstance(record, dict) else None
            if not isinstance(event_payload, dict):
                log.warning("replay_malformed_line", file=str(path), line=lineno)
                skipped += 1
                continue
            event = NormalizedEvent(**event_payload)
        except Exception as e:  # malformed line or reconstruction failure
            log.warning("replay_line_failed", file=str(path), line=lineno, error=str(e))
            skipped += 1
            continue

        attempts = int(record.get("attempts", 0) or 0)
        if attempts >= MAX_REPLAY_ATTEMPTS:
            log.error(
                "replay_row_dropped_max_attempts",
                file=str(path),
                line=lineno,
                host=event.host_name,
                attempts=attempts,
            )
            skipped += 1
            continue

        try:
            await _persist_event(event)
        except POISON_ERRORS as e:
            _quarantine(path, record, event, str(e))
            quarantined += 1
            continue
        replayed += 1
    return replayed, skipped, quarantined


async def replay_all(dead_letter_dir: Path = DEAD_LETTER_DIR) -> dict[str, int]:
    """Replay every *.jsonl in the dead-letter dir (not processed/ or quarantine/).

    Returns a summary dict. On a per-file DB error the file is left in place
    for the next run; a file whose rows were all replayed-or-quarantined moves
    to processed/.
    """
    if not dead_letter_dir.exists():
        log.info("replay_no_dir", dir=str(dead_letter_dir))
        return {"found": 0, "files": 0, "replayed": 0, "skipped": 0, "quarantined": 0}

    # Initialise the pool so re-ingestion can write.
    await get_pool()

    files = sorted(p for p in dead_letter_dir.glob("*.jsonl") if p.is_file())
    found = len(files)  # W5-I: the operator-visible "files existed" count
    total_replayed = 0
    total_skipped = 0
    total_quarantined = 0
    files_ok = 0

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    for f in files:
        try:
            replayed, skipped, quarantined = await replay_file(f)
            total_replayed += replayed
            total_skipped += skipped
            total_quarantined += quarantined
            # Retire the file: every row either landed, was quarantined, was
            # skipped as malformed, or exhausted its attempts. Nothing here may
            # be re-attempted as a batch (the SS-040 poison loop).
            dest = PROCESSED_DIR / f.name
            if dest.exists():
                # A previous run processed a same-named file; archive with a suffix.
                dest = PROCESSED_DIR / f"{f.name}.{int(__import__('time').time())}"
            f.rename(dest)
            files_ok += 1
            log.info(
                "replay_file_done",
                file=f.name,
                replayed=replayed,
                skipped=skipped,
                quarantined=quarantined,
            )
        except Exception as e:
            # DB error mid-file: leave the file in place for the next run.
            log.warning("replay_file_failed", file=f.name, error=str(e))

    await close_pool()

    log.info(
        "replay_complete",
        files=files_ok,
        replayed=total_replayed,
        skipped=total_skipped,
        quarantined=total_quarantined,
    )
    return {
        "found": found,
        "files": files_ok,
        "replayed": total_replayed,
        "skipped": total_skipped,
        "quarantined": total_quarantined,
    }


def main() -> None:
    summary = asyncio.run(replay_all())
    print(
        f"Replay complete: {summary['files']} file(s), "
        f"{summary['replayed']} event(s) re-ingested, "
        f"{summary['skipped']} skipped, "
        f"{summary['quarantined']} quarantined."
    )
    # W5-I: dead-letter files present but nothing re-ingested (all
    # malformed, or a DB error left them stranded) is a WARNING the
    # operator must see -- the entrypoint treats non-zero exit as a
    # non-fatal warning. Nothing stranded -> healthy no-op, exit 0.
    if summary["found"] > 0 and summary["replayed"] == 0 and summary["quarantined"] == 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
