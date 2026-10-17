"""SQLite connection and schema management.

The default path matches ``run_collect.py`` so the repository reads the same file the
collector writes. All DDL is ``IF NOT EXISTS``, so ``init_schema`` is safe to call on an
existing collector database (it only adds the normalized tables and indexes).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Union

from src.ingestion.storage.models import (
    ERRORS_DDL, EVENTS_DDL, INDEX_DDL, RAW_FLOW_DDL, RAW_TRAIL_DDL,
)

DEFAULT_DB_PATH = Path("data/local/events.db")
SCHEMA_VERSION = 1


def connect(path: Union[str, Path] = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open a connection (``":memory:"`` allowed), create parent dirs, ensure the schema."""
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.row_factory = sqlite3.Row
    init_schema(con)
    return con


def init_schema(con: sqlite3.Connection) -> None:
    """Create all tables/indexes if missing and stamp ``PRAGMA user_version``."""
    for ddl in (RAW_FLOW_DDL, RAW_TRAIL_DDL, EVENTS_DDL, ERRORS_DDL, *INDEX_DDL):
        con.execute(ddl)
    con.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    con.commit()
