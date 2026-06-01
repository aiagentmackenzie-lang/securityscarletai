"""Shared LogWriter instance — decouples ingestion from api.main lifecycle."""
from src.db.writer import LogWriter

writer = LogWriter()
