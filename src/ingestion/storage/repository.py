"""Repository for normalized telemetry.

Typical use::

    con = connect()                     # data/local/events.db
    repo = EventRepository(con)
    summary = repo.ingest_all()         # raw flow_events/trail_events -> events
    events = repo.get_events(source=EventSource.CLOUDTRAIL)

Semantics
---------
* Idempotent: ``event_id`` is the primary key and the FIRST write wins; re-ingesting
  the same raw rows adds nothing.
* Time filters are ``start <= timestamp < end`` in UTC (naive datetimes are treated as UTC).
* Results are ordered by ``(timestamp, event_id)`` so output is deterministic.
* Malformed raw records are recorded in ``ingest_errors`` and never abort ingestion.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from src.ingestion.normalization.mapper import normalize_batch
from src.ingestion.storage.models import event_to_row, format_ts, row_to_event
from src.shared.enums import EventSource
from src.shared.models import BaseTelemetryEvent

_INSERT = (
    "INSERT OR IGNORE INTO events (event_id, timestamp, source, action, actor, resource_id, "
    "source_ip, destination_ip, destination_port, raw_record_id, details_json, extra_json, "
    "ingested_at) VALUES (:event_id, :timestamp, :source, :action, :actor, :resource_id, "
    ":source_ip, :destination_ip, :destination_port, :raw_record_id, :details_json, "
    ":extra_json, :ingested_at)"
)


@dataclass
class IngestSummary:
    """Counts for one ingest run. ``read == stored + duplicates + skipped + malformed``."""
    read: int = 0
    stored: int = 0
    duplicates: int = 0
    skipped: int = 0     # valid but no traffic (NODATA/SKIPDATA)
    malformed: int = 0

    def __add__(self, other: "IngestSummary") -> "IngestSummary":
        return IngestSummary(*(a + b for a, b in zip(
            (self.read, self.stored, self.duplicates, self.skipped, self.malformed),
            (other.read, other.stored, other.duplicates, other.skipped, other.malformed))))


class EventRepository:
    def __init__(self, con: sqlite3.Connection):
        self.con = con
        self.con.row_factory = sqlite3.Row

    # ------------------------------------------------------------------ writes
    def save_events(self, events: Iterable[BaseTelemetryEvent]) -> int:
        """Insert events in one transaction. Returns how many were NEW (dupes ignored)."""
        now = datetime.now(timezone.utc)
        before = self.con.total_changes
        with self.con:
            self.con.executemany(_INSERT, [event_to_row(e, now) for e in events])
        return self.con.total_changes - before

    def save_event(self, event: BaseTelemetryEvent) -> bool:
        return self.save_events([event]) == 1

    def record_error(self, kind: str, record_id: Optional[str], message: str,
                     raw: Optional[Any] = None) -> None:
        """Store a normalization failure once per (kind, record, message)."""
        if record_id is None:
            record_id = "anon-" + hashlib.sha1(
                json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest()[:16]
        with self.con:
            self.con.execute(
                "INSERT OR IGNORE INTO ingest_errors (kind, record_id, error, created_at) "
                "VALUES (?,?,?,?)",
                (kind, record_id, message, format_ts(datetime.now(timezone.utc))))

    # ------------------------------------------------------------------- reads
    def get_event(self, event_id: str) -> Optional[BaseTelemetryEvent]:
        row = self.con.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        return row_to_event(row) if row else None

    def get_events(
        self,
        source: Optional[Union[EventSource, str]] = None,
        action: Optional[str] = None,
        resource_id: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[BaseTelemetryEvent]:
        clauses, params = [], []  # type: List[str], List[Any]
        if source is not None:
            clauses.append("source = ?")
            params.append(EventSource(source).value)
        if action is not None:
            clauses.append("action = ?")
            params.append(action)
        if resource_id is not None:
            clauses.append("resource_id = ?")
            params.append(resource_id)
        if start is not None:
            clauses.append("timestamp >= ?")
            params.append(format_ts(start))
        if end is not None:
            clauses.append("timestamp < ?")
            params.append(format_ts(end))
        sql = "SELECT * FROM events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY timestamp, event_id"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
        return [row_to_event(r) for r in self.con.execute(sql, params)]

    def count_events(self, source: Optional[Union[EventSource, str]] = None) -> int:
        if source is None:
            return self.con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        return self.con.execute("SELECT COUNT(*) FROM events WHERE source = ?",
                                (EventSource(source).value,)).fetchone()[0]

    def get_errors(self, kind: Optional[str] = None) -> List[Dict[str, str]]:
        sql, params = "SELECT kind, record_id, error FROM ingest_errors", []  # type: str, list
        if kind:
            sql, params = sql + " WHERE kind = ?", [kind]
        return [dict(r) for r in self.con.execute(sql + " ORDER BY id", params)]

    # ------------------------------------------------- raw tables -> events
    def _ingest_raw(self, table: str, kind: str) -> IngestSummary:
        exists = self.con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        if not exists:
            return IngestSummary()
        rows = [dict(r) for r in self.con.execute(f"SELECT * FROM {table}")]
        events, skipped, errors = normalize_batch(rows, kind)
        for record_id, message in errors:
            self.record_error(kind, record_id, message, raw=record_id)
        new = self.save_events(events)
        return IngestSummary(read=len(rows), stored=new, duplicates=len(events) - new,
                             skipped=skipped, malformed=len(errors))

    def ingest_raw_flow_events(self) -> IngestSummary:
        return self._ingest_raw("flow_events", "flow")

    def ingest_raw_trail_events(self) -> IngestSummary:
        return self._ingest_raw("trail_events", "cloudtrail")

    def ingest_all(self) -> IngestSummary:
        return self.ingest_raw_flow_events() + self.ingest_raw_trail_events()
