"""
Log shipper -- tails osquery result logs and feeds them to the ingestion pipeline.

Polls the result log every ~1s (seek/tell based, not a file-watcher) and stores a
checkpoint (byte offset) so restarts don't re-ingest old data. (P2-07: the
earlier docstring claimed watchfiles, but the implementation is polling.)

W1-B crash semantics: the checkpoint persists a CONFIRMED offset — the parse
cursor only advances past bytes the writer has actually flushed. A hard crash
therefore re-reads at most one flush window: already-flushed events re-ingest
as DUPLICATES (bounded, at-least-once) instead of the old at-most-once LOSS,
where the checkpoint advanced past events still sitting in the writer buffer.
This matches the durable Redis path's documented at-least-once semantics.
"""

import asyncio
import os
from pathlib import Path

from src.config.logging import get_logger
from src.db.writer import LogWriter
from src.ingestion.parser import parse_osquery_line
from src.ingestion.schemas import parse_normalized_line

log = get_logger("ingestion.shipper")

CHECKPOINT_FILE = Path.home() / ".scarletai_shipper_checkpoint"


class FileShipper:
    """Tail a log file and ship events to the database.

    P2-22: the checkpoint file is per-instance (``checkpoint_path``) so multiple
    shippers watching different logs don't clobber each other's offset. Defaults
    to the legacy single global path for backward compatibility -- the
    single-shipper deployment (``maybe_create_shipper``) is unaffected.

    ``format`` selects the line parser:
      - "osquery"    -- osquery result-log lines (default; the telemetry pipe)
      - "normalized" -- one NDJSON NormalizedEvent per line (the auth
        shipper's output format, V0.3 identity telemetry; the same shape the
        API /ingest contract accepts)
    """

    def __init__(
        self,
        log_path: str,
        writer: LogWriter,
        checkpoint_path: Path | None = None,
        format: str = "osquery",  # noqa: A002 -- public keyword, mirrors parse format
    ):
        self.log_path = Path(log_path)
        self.writer = writer
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else CHECKPOINT_FILE
        if format not in ("osquery", "normalized"):
            raise ValueError(f"unsupported shipper format: {format!r}")
        self.format = format
        self._offset = self._load_checkpoint()
        # W1-B: the offset PERSISTED to the checkpoint file. Lags _offset by at
        # most one writer flush — _offset is the parse cursor, _confirmed_offset
        # is what a restart trusts. Only equal after writer.flush() succeeds.
        self._confirmed_offset = self._offset
        self._inode = self._get_inode()  # H-15: track inode for rotation detection
        self._running = False
        self._events_shipped = 0

    def _get_inode(self) -> int | None:
        """Get file inode number (0 on systems that don't support it)."""
        try:
            return os.stat(self.log_path).st_ino if self.log_path.exists() else None
        except OSError:
            return None

    async def run(self) -> None:
        """Main loop -- tail the file forever."""
        self._running = True
        log.info("shipper_started", path=str(self.log_path), offset=self._offset)

        while self._running:
            try:
                if not self.log_path.exists():
                    log.warning("log_file_missing", path=str(self.log_path))
                    await asyncio.sleep(5)
                    continue

                current_size = self.log_path.stat().st_size

                # H-15 fix: Detect log rotation via inode change OR file shrink
                current_inode = self._get_inode()
                if current_inode != self._inode:
                    log.info(
                        "log_rotation_detected",
                        old_inode=self._inode,
                        new_inode=current_inode,
                    )
                    self._offset = 0
                    # W1-B: both cursors move together on rotation — the new
                    # file's bytes are unconsumed by definition.
                    self._confirmed_offset = 0
                    self._inode = current_inode
                elif current_size < self._offset:
                    log.info(
                        "log_rotation_detected",
                        old_offset=self._offset,
                        new_size=current_size,
                        reason="file_shrank",
                    )
                    self._offset = 0
                    self._confirmed_offset = 0

                if current_size > self._offset:
                    await self._read_new_lines()

                await asyncio.sleep(1)  # Poll interval

            except Exception as e:
                log.error("shipper_error", error=str(e))
                await asyncio.sleep(5)

    async def _read_new_lines(self) -> None:
        """Read new lines from the current offset.

        AUD-006: this used to open the log in locale-encoding TEXT mode with
        no errors handler — one undecodable byte in an osquery line (cmdlines
        can carry arbitrary bytes) raised UnicodeDecodeError inside the
        iteration, the outer run() handler slept 5s and retried from the SAME
        offset: an infinite retry loop that stalled the pipe until manual
        intervention. Text-mode f.tell() also stored an opaque cookie as the
        byte checkpoint (fragile).

        The read is now BINARY with an ``errors="replace"`` decode (the
        fleet_shipper pattern): a corrupt byte can never wedge the loop. The
        offset advances over COMPLETE lines only, counted in RAW bytes — a
        trailing partial line waits for its newline (never ship half a JSON
        object), and byte counts come from the raw chunk, NOT the re-encoded
        text: one bad byte decodes to a 3-byte U+FFFD, so re-encoding would
        drift the checkpoint past unconsumed bytes (the trap the fleet
        shipper's len(text.encode()) shape carries).
        """
        parser = parse_osquery_line if self.format == "osquery" else parse_normalized_line
        with open(self.log_path, "rb") as f:
            f.seek(self._offset)
            chunk = f.read()
        if not chunk:
            return
        cut = chunk.rfind(b"\n")  # consume COMPLETE lines only
        if cut == -1:
            return
        consumed = chunk[: cut + 1]
        text = consumed.decode("utf-8", errors="replace")
        for line in text.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                event = parser(line)
            except Exception as e:
                # W1-C belt-and-braces: the parser promises never-raise, but
                # an exception escaping it used to stall this loop at the
                # same offset forever (run() retries from the unchanged
                # checkpoint — the exact AUD-006 wedge). Skip the poison
                # line; the checkpoint still advances over its bytes.
                log.warning(
                    "shipper_parse_line_skipped",
                    error=str(e),
                    line_preview=line[:200],
                )
                continue
            if event:
                await self.writer.write(event)
                self._events_shipped += 1
        self._offset += len(consumed)
        # W1-B: the checkpoint persists only what the writer CONFIRMED flushed.
        # Old code persisted the parse cursor immediately after buffering — a
        # hard crash in the writer's batch/2s-flush window lost those events
        # with the checkpoint already past them (at-most-once). Now: flush
        # first, then persist. A crash before confirmation re-reads at most
        # one flush window (bounded duplicates — at-least-once).
        try:
            await self.writer.flush()
        except Exception as e:
            # Unexpected flush failure (PostgresError/OSError are already
            # dead-lettered inside LogWriter). Don't persist — the confirmed
            # checkpoint lags, so a restart re-reads this window instead of
            # trusting bytes the writer never landed.
            log.error("shipper_flush_confirm_failed", error=str(e))
            return
        self._confirmed_offset = self._offset
        self._save_checkpoint()

    def _load_checkpoint(self) -> int:
        """Load the byte offset from the checkpoint file."""
        try:
            return int(self.checkpoint_path.read_text().strip())
        except (FileNotFoundError, ValueError):
            return 0

    def _save_checkpoint(self) -> None:
        """Persist the CONFIRMED byte offset (W1-B).

        Only called after writer.flush() confirmed the batch landed, so the
        file never contains an offset the writer hasn't flushed. Callers set
        ``_confirmed_offset = _offset`` first — the parse cursor may already
        be further ahead (that gap is the bounded re-read window).

        M-20 fix: Use atomic write via temp file + os.replace()
        to prevent corruption from crash mid-write.
        """
        temp_file = self.checkpoint_path.with_suffix(".tmp")
        try:
            temp_file.write_text(str(self._confirmed_offset))
            os.replace(temp_file, self.checkpoint_path)
        except OSError as e:
            log.error("checkpoint_save_failed", error=str(e))

    def stop(self) -> None:
        self._running = False
        log.info("shipper_stopped", events_shipped=self._events_shipped)
