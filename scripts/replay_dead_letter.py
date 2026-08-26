"""Replay the dead-letter queue (P1-E).

Failed write batches are persisted to `data/dead_letter/*.jsonl` by
`src/db/writer.py`. Nothing previously read them back — so on a DB outage,
events were stranded in a file that (a) lived on an ephemeral path in some
deployments and (b) was never replayed even when it survived. This script
reads each JSONL, reconstructs the NormalizedEvent, and re-ingests it via
the writer. After a file is fully and successfully replayed, it is moved to
`data/dead_letter/processed/` so a re-run doesn't double-ingest.

Run standalone:
    python -m scripts.replay_dead_letter

Called by scripts/entrypoint.sh on boot (best-effort, before uvicorn starts)
so stranded events get replayed after a restart.

Best-effort: a malformed line is logged and skipped (the rest of the file
still replays). A DB error mid-file stops that file and leaves it in place
for the next run; already-replayed files are moved to processed/.
"""
import asyncio
import json
import sys
from pathlib import Path

from src.config.logging import get_logger
from src.db.connection import close_pool, get_pool
from src.ingestion.schemas import NormalizedEvent
from src.services.writer import writer

log = get_logger("scripts.replay_dead_letter")

DEAD_LETTER_DIR = Path("data/dead_letter")
PROCESSED_DIR = DEAD_LETTER_DIR / "processed"


async def replay_file(path: Path) -> tuple[int, int]:
    """Replay one JSONL dead-letter file. Returns (replayed, skipped)."""
    replayed = 0
    skipped = 0
    lines = path.read_text().splitlines()
    for lineno, line in enumerate(lines, 1):
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
            await writer.write(event)
        except Exception as e:  # malformed line or reconstruction failure
            log.warning("replay_line_failed", file=str(path), line=lineno, error=str(e))
            skipped += 1
            continue
        replayed += 1
    # Flush whatever we buffered so it actually hits the DB.
    await writer.flush()
    return replayed, skipped


async def replay_all(dead_letter_dir: Path = DEAD_LETTER_DIR) -> dict[str, int]:
    """Replay every *.jsonl in the dead-letter dir (not the processed/ subdir).

    Returns a summary dict. On a per-file DB error the file is left in place
    for the next run; fully-replayed files move to processed/.
    """
    if not dead_letter_dir.exists():
        log.info("replay_no_dir", dir=str(dead_letter_dir))
        return {"files": 0, "replayed": 0, "skipped": 0}

    # Initialise the pool so re-ingestion can write.
    await get_pool()
    await writer.start()

    files = sorted(p for p in dead_letter_dir.glob("*.jsonl") if p.is_file())
    total_replayed = 0
    total_skipped = 0
    files_ok = 0

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    for f in files:
        try:
            replayed, skipped = await replay_file(f)
            total_replayed += replayed
            total_skipped += skipped
            # Only move the file if at least its parseable lines were flushed.
            # If replayed==0 and skipped>0 (all malformed), still move it so we
            # don't loop forever on a corrupt file.
            dest = PROCESSED_DIR / f.name
            if dest.exists():
                # A previous run processed a same-named file; archive with a suffix.
                dest = PROCESSED_DIR / f"{f.name}.{int(__import__('time').time())}"
            f.rename(dest)
            files_ok += 1
            log.info("replay_file_done", file=f.name, replayed=replayed, skipped=skipped)
        except Exception as e:
            # DB error mid-file: leave the file in place for the next run.
            log.warning("replay_file_failed", file=f.name, error=str(e))

    await writer.stop()
    await close_pool()

    log.info(
        "replay_complete",
        files=files_ok,
        replayed=total_replayed,
        skipped=total_skipped,
    )
    return {"files": files_ok, "replayed": total_replayed, "skipped": total_skipped}


def main() -> None:
    summary = asyncio.run(replay_all())
    print(f"Replay complete: {summary['files']} file(s), "
          f"{summary['replayed']} event(s) re-ingested, "
          f"{summary['skipped']} skipped.")
    if summary["replayed"] == 0 and summary["files"] == 0:
        sys.exit(0)


if __name__ == "__main__":
    main()
