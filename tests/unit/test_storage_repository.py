"""SQLite schema + EventRepository behaviour (in-memory databases)."""
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from src.ingestion.storage.database import SCHEMA_VERSION, connect, init_schema
from src.ingestion.storage.models import FLOW_FIELDS, event_to_row, format_ts, row_to_event
from src.ingestion.storage.repository import EventRepository, IngestSummary
from src.shared.enums import EventSource
from src.shared.models import BaseTelemetryEvent

T0 = datetime(2026, 10, 15, 10, 0, tzinfo=timezone.utc)


def ev(event_id="e1", offset=0, source=EventSource.VPC_FLOW, **kw):
    base = dict(event_id=event_id, timestamp=T0 + timedelta(seconds=offset), source=source,
                action="ACCEPT", resource_id="eni-1", source_ip="1.2.3.4",
                destination_ip="10.0.0.1", destination_port=22, details={"protocol": "tcp"})
    base.update(kw)
    return BaseTelemetryEvent(**base)


@pytest.fixture
def repo():
    con = connect(":memory:")
    yield EventRepository(con)
    con.close()


def add_raw_flow(con, **kw):
    rec = {f: "-" for f in FLOW_FIELDS}
    rec.update(event_id="rf-1", interface_id="eni-1", srcaddr="203.0.113.5", dstaddr="10.0.0.1",
               dstport="22", protocol="6", start="1792060206", action="ACCEPT", log_status="OK")
    rec.update(kw)
    con.execute(f"INSERT INTO flow_events (event_id,{','.join(FLOW_FIELDS)}) "
                f"VALUES (?{',?' * len(FLOW_FIELDS)})", [rec["event_id"], *(rec[f] for f in FLOW_FIELDS)])
    con.commit()


def add_raw_trail(con, event_id="rt-1", raw=None):
    raw = raw if raw is not None else json.dumps({
        "eventID": event_id, "eventTime": "2026-10-15T10:00:00Z", "eventName": "AuthorizeSecurityGroupIngress",
        "userIdentity": {"arn": "arn:aws:iam::1:user/u"}, "requestParameters": {"groupId": "sg-1"}})
    con.execute("INSERT INTO trail_events VALUES (?,?,?,?,?,?,?)",
                (event_id, "2026-10-15T10:00:00Z", "AuthorizeSecurityGroupIngress",
                 "ec2.amazonaws.com", "arn:aws:iam::1:user/u", "1.2.3.4", raw))
    con.commit()


# ------------------------------------------------------------------------- schema
def test_schema_creates_all_tables_and_version():
    con = connect(":memory:")
    names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"flow_events", "trail_events", "events", "ingest_errors"} <= names
    assert con.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_init_schema_is_idempotent_and_keeps_data():
    con = connect(":memory:")
    add_raw_flow(con)
    init_schema(con)
    init_schema(con)
    assert con.execute("SELECT COUNT(*) FROM flow_events").fetchone()[0] == 1


def test_init_schema_works_on_existing_collector_database(tmp_path):
    path = tmp_path / "events.db"
    old = sqlite3.connect(path)  # what run_collect.py leaves behind
    old.execute("CREATE TABLE trail_events (event_id TEXT PRIMARY KEY, event_time TEXT, event_name TEXT, "
                "event_source TEXT, user_arn TEXT, source_ip TEXT, raw TEXT)")
    old.execute("INSERT INTO trail_events VALUES ('a','t','n','s','u','i','{}')")
    old.commit(); old.close()
    con = connect(path)
    assert con.execute("SELECT COUNT(*) FROM trail_events").fetchone()[0] == 1
    assert con.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_connect_creates_parent_directory(tmp_path):
    con = connect(tmp_path / "nested" / "dir" / "x.db")
    assert (tmp_path / "nested" / "dir" / "x.db").exists()
    con.close()


# ---------------------------------------------------------------- row conversion
def test_round_trip_preserves_every_field():
    e = ev(actor="arn:x", details={"protocol": "tcp", "nested": {"a": [1, 2]}}, custom_field="kept")
    back = row_to_event(event_to_row(e, T0))
    assert back == e and back.custom_field == "kept"


def test_naive_timestamp_is_treated_as_utc():
    assert format_ts(datetime(2026, 1, 1, 0, 0)) == format_ts(datetime(2026, 1, 1, tzinfo=timezone.utc))


def test_non_utc_timestamp_is_converted():
    ist = timezone(timedelta(hours=5, minutes=30))
    assert format_ts(datetime(2026, 1, 1, 5, 30, tzinfo=ist)) == format_ts(datetime(2026, 1, 1, tzinfo=timezone.utc))


# -------------------------------------------------------------------- save / get
def test_save_and_get_event(repo):
    assert repo.save_event(ev()) is True
    assert repo.get_event("e1") == ev()


def test_get_missing_event_returns_none(repo):
    assert repo.get_event("nope") is None


def test_duplicate_event_id_is_ignored_first_write_wins(repo):
    repo.save_event(ev(action="ACCEPT"))
    assert repo.save_event(ev(action="REJECT")) is False
    assert repo.count_events() == 1 and repo.get_event("e1").action == "ACCEPT"


def test_save_events_returns_only_new_count(repo):
    repo.save_event(ev("a"))
    assert repo.save_events([ev("a"), ev("b"), ev("c")]) == 2


def test_save_empty_batch(repo):
    assert repo.save_events([]) == 0


def test_optional_fields_none_round_trip(repo):
    bare = BaseTelemetryEvent(event_id="bare", timestamp=T0, source=EventSource.CLOUDTRAIL, action="X")
    repo.save_event(bare)
    assert repo.get_event("bare") == bare


# --------------------------------------------------------------------- queries
@pytest.fixture
def populated(repo):
    repo.save_events([
        ev("f1", 0), ev("f2", 10, action="REJECT"), ev("f3", 20, resource_id="eni-2"),
        ev("c1", 5, source=EventSource.CLOUDTRAIL, action="AuthorizeSecurityGroupIngress",
           resource_id="sg-1"),
    ])
    return repo


def test_results_are_ordered_by_time(populated):
    assert [e.event_id for e in populated.get_events()] == ["f1", "c1", "f2", "f3"]


def test_equal_timestamps_ordered_by_event_id(repo):
    repo.save_events([ev("b", 0), ev("a", 0)])
    assert [e.event_id for e in repo.get_events()] == ["a", "b"]


def test_filter_by_source_enum_or_string(populated):
    assert [e.event_id for e in populated.get_events(source=EventSource.CLOUDTRAIL)] == ["c1"]
    assert len(populated.get_events(source="vpc_flow")) == 3


def test_filter_by_action_and_resource(populated):
    assert [e.event_id for e in populated.get_events(action="REJECT")] == ["f2"]
    assert [e.event_id for e in populated.get_events(resource_id="eni-2")] == ["f3"]


def test_time_window_is_start_inclusive_end_exclusive(populated):
    got = populated.get_events(start=T0 + timedelta(seconds=5), end=T0 + timedelta(seconds=20))
    assert [e.event_id for e in got] == ["c1", "f2"]


def test_limit_and_empty_result(populated):
    assert len(populated.get_events(limit=2)) == 2
    assert populated.get_events(resource_id="eni-none") == []


def test_unknown_source_filter_raises(populated):
    with pytest.raises(ValueError):
        populated.get_events(source="netflow")


def test_count_events(populated):
    assert populated.count_events() == 4 and populated.count_events(EventSource.VPC_FLOW) == 3


def test_filter_values_are_parameterized_not_interpolated(populated):
    assert populated.get_events(resource_id="x' OR '1'='1") == []


# ------------------------------------------------------------ raw -> normalized
def test_ingest_all_normalizes_both_raw_tables(repo):
    add_raw_flow(repo.con); add_raw_trail(repo.con)
    s = repo.ingest_all()
    assert s == IngestSummary(read=2, stored=2, duplicates=0, skipped=0, malformed=0)
    assert repo.count_events(EventSource.VPC_FLOW) == 1 and repo.count_events(EventSource.CLOUDTRAIL) == 1


def test_reingest_is_idempotent(repo):
    add_raw_flow(repo.con)
    repo.ingest_all()
    s = repo.ingest_all()
    assert s.stored == 0 and s.duplicates == 1 and repo.count_events() == 1


def test_incremental_ingest_adds_only_new_rows(repo):
    add_raw_flow(repo.con)
    repo.ingest_all()
    add_raw_flow(repo.con, event_id="rf-2")
    assert repo.ingest_all().stored == 1


def test_nodata_rows_are_skipped_not_errors(repo):
    add_raw_flow(repo.con, event_id="nd", log_status="NODATA", srcaddr="-", dstaddr="-", action="-")
    s = repo.ingest_raw_flow_events()
    assert s.skipped == 1 and s.malformed == 0 and repo.count_events() == 0 and repo.get_errors() == []


def test_malformed_rows_are_recorded_and_do_not_block_good_rows(repo):
    add_raw_flow(repo.con, event_id="good")
    add_raw_flow(repo.con, event_id="bad-ip", srcaddr="999.9.9.9")
    add_raw_trail(repo.con, event_id="bad-json", raw="{broken")
    s = repo.ingest_all()
    assert (s.read, s.stored, s.malformed) == (3, 1, 2)
    errs = repo.get_errors()
    assert {e["record_id"] for e in errs} == {"bad-ip", "bad-json"}
    assert [e["kind"] for e in repo.get_errors("flow")] == ["flow"]


def test_repeated_ingest_does_not_duplicate_error_rows(repo):
    add_raw_flow(repo.con, event_id="bad", srcaddr="nope")
    repo.ingest_all(); repo.ingest_all()
    assert len(repo.get_errors()) == 1


def test_summary_counts_add_up(repo):
    add_raw_flow(repo.con, event_id="ok")
    add_raw_flow(repo.con, event_id="nd", log_status="NODATA", srcaddr="-", dstaddr="-", action="-")
    add_raw_flow(repo.con, event_id="bad", srcaddr="x")
    repo.ingest_all()
    s = repo.ingest_all()
    assert s.read == s.stored + s.duplicates + s.skipped + s.malformed == 3


def test_ingest_without_raw_tables_returns_zero_summary():
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE events (event_id TEXT PRIMARY KEY, timestamp TEXT, source TEXT, action TEXT,"
                " actor TEXT, resource_id TEXT, source_ip TEXT, destination_ip TEXT, destination_port INTEGER,"
                " raw_record_id TEXT, details_json TEXT, extra_json TEXT, ingested_at TEXT)")
    assert EventRepository(con).ingest_raw_flow_events() == IngestSummary()


def test_record_error_with_no_id_is_still_stored(repo):
    repo.record_error("flow", None, "boom", raw={"a": 1})
    repo.record_error("flow", None, "boom", raw={"a": 1})
    assert len(repo.get_errors()) == 1 and repo.get_errors()[0]["record_id"].startswith("anon-")
