"""Storage models: table definitions and row <-> ``BaseTelemetryEvent`` conversion.

Tables
------
flow_events / trail_events   RAW tables written by ``run_collect.py`` (system of record).
events                       NORMALIZED ``BaseTelemetryEvent`` rows (what detection reads).
ingest_errors                records that failed normalization, kept for audit.

See docs/database-schema.md for column-level documentation.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Mapping

from src.shared.models import BaseTelemetryEvent

# Same 21-field order as the VPC flow log custom format (kept in sync with run_collect.py).
FLOW_FIELDS = [
    "version", "account_id", "interface_id", "srcaddr", "dstaddr", "srcport",
    "dstport", "protocol", "packets", "bytes", "start", "end", "action",
    "log_status", "vpc_id", "subnet_id", "instance_id", "tcp_flags",
    "flow_direction", "pkt_srcaddr", "pkt_dstaddr",
]

RAW_FLOW_DDL = (
    "CREATE TABLE IF NOT EXISTS flow_events (event_id TEXT PRIMARY KEY, "
    + ", ".join(f"{f} TEXT" for f in FLOW_FIELDS) + ")"
)
RAW_TRAIL_DDL = (
    "CREATE TABLE IF NOT EXISTS trail_events ("
    "event_id TEXT PRIMARY KEY, event_time TEXT, event_name TEXT, "
    "event_source TEXT, user_arn TEXT, source_ip TEXT, raw TEXT)"
)

EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS events (
    event_id         TEXT PRIMARY KEY,
    timestamp        TEXT NOT NULL,
    source           TEXT NOT NULL,
    action           TEXT NOT NULL,
    actor            TEXT,
    resource_id      TEXT,
    source_ip        TEXT,
    destination_ip   TEXT,
    destination_port INTEGER,
    raw_record_id    TEXT,
    details_json     TEXT NOT NULL DEFAULT '{}',
    extra_json       TEXT NOT NULL DEFAULT '{}',
    ingested_at      TEXT NOT NULL
)"""

ERRORS_DDL = """
CREATE TABLE IF NOT EXISTS ingest_errors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    record_id   TEXT NOT NULL,
    error       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (kind, record_id, error)
)"""

INDEX_DDL = [
    "CREATE INDEX IF NOT EXISTS idx_events_ts ON events (timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_source_ts ON events (source, timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_resource ON events (resource_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_action ON events (action)",
]

_CORE_FIELDS = set(BaseTelemetryEvent.model_fields)

TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # fixed width, UTC => string order == time order


def format_ts(dt: datetime) -> str:
    """UTC, fixed-width timestamp string. Naive datetimes are assumed to be UTC."""
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    return dt.strftime(TS_FORMAT)


def parse_ts(text: str) -> datetime:
    return datetime.strptime(text, TS_FORMAT).replace(tzinfo=timezone.utc)


def event_to_row(event: BaseTelemetryEvent, ingested_at: datetime) -> Dict[str, Any]:
    """Flatten an event into the ``events`` table row. Extra (non-contract) fields go to extra_json."""
    dumped = event.model_dump(mode="json")
    extras = {k: v for k, v in dumped.items() if k not in _CORE_FIELDS}
    return {
        "event_id": event.event_id,
        "timestamp": format_ts(event.timestamp),
        "source": event.source.value,
        "action": event.action,
        "actor": event.actor,
        "resource_id": event.resource_id,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "destination_port": event.destination_port,
        "raw_record_id": event.raw_record_id,
        "details_json": json.dumps(event.details, sort_keys=True),
        "extra_json": json.dumps(extras, sort_keys=True),
        "ingested_at": format_ts(ingested_at),
    }


def row_to_event(row: Mapping[str, Any]) -> BaseTelemetryEvent:
    """Rebuild the event from an ``events`` row (inverse of ``event_to_row``)."""
    data: Dict[str, Any] = json.loads(row["extra_json"] or "{}")
    data.update(
        event_id=row["event_id"],
        timestamp=parse_ts(row["timestamp"]),
        source=row["source"],
        action=row["action"],
        actor=row["actor"],
        resource_id=row["resource_id"],
        source_ip=row["source_ip"],
        destination_ip=row["destination_ip"],
        destination_port=row["destination_port"],
        raw_record_id=row["raw_record_id"],
        details=json.loads(row["details_json"] or "{}"),
    )
    return BaseTelemetryEvent(**data)
