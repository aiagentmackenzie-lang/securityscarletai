"""
Log shipper — tails osquery result logs and feeds them to the ingestion pipeline.

Uses watchfiles (Rust-based) for efficient file watching on macOS.
Stores a checkpoint (byte offset) so restarts don't re-ingest old data.
"""
import asyncio
from pathlib import Path

from src.config.logging import get_logger
from src.db.writer import LogWriter
from src.ingestion.parser import parse_osquery_line

log = get_logger("ingestion.shipper")

CHECKPOINT_FILE = Path.home() / ".scarletai_shipper_checkpoint"


class FileShipper:
    """Tail a log file and ship events to the database."""

    def __init__(self, log_path: str, writer: LogWriter):
        self.log_path = Path(log_path)
        self.writer = writer
        self._offset = self._load_checkpoint()
        self._running = False
        self._events_shipped = 0

    async def run(self) -> None:
        """Main loop — tail the file forever."""
        self._running = True
        log.info("shipper_started", path=str(self.log_path), offset=self._offset)

        while self._running:
            try:
                if not self.log_path.exists():
                    log.warning("log_file_missing", path=str(self.log_path))
                    await asyncio.sleep(5)
                    continue

                current_size = self.log_path.stat().st_size

                # Detect log rotation (file got smaller)
                if current_size < self._offset:
                    log.info("log_rotation_detected", old_offset=self._offset, new_size=current_size)
                    self._offset = 0

                if current_size > self._offset:
                    await self._read_new_lines()

                await asyncio.sleep(1)  # Poll interval

            except Exception as e:
                log.error("shipper_error", error=str(e))
                await asyncio.sleep(5)

    async def _read_new_lines(self) -> None:
        """Read new lines from the current offset."""
        with open(self.log_path, "r") as f:
            f.seek(self._offset)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = parse_osquery_line(line)
                if event:
                    await self.writer.write(event)
                    self._events_shipped += 1
            self._offset = f.tell()
            self._save_checkpoint()

    def _load_checkpoint(self) -> int:
        """Load the byte offset from the checkpoint file."""
        try:
            return int(CHECKPOINT_FILE.read_text().strip())
        except (FileNotFoundError, ValueError):
            return 0

    def _save_checkpoint(self) -> None:
        """Persist the current byte offset."""
        CHECKPOINT_FILE.write_text(str(self._offset))

    def stop(self) -> None:
        self._running = False
        log.info("shipper_stopped", events_shipped=self._events_shipped)
