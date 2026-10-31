"""Tests for Task 5:
1. AttachTime parsing (including missing and invalid values).
2. Configurable event limit (MAX_ANALYSIS_EVENTS).
3. AlertService auto-refresh logic & thread safety.
4. SQS delete-only-on-success behavior (unittest.mock, no real AWS calls).
5. VPC Flow logs pagination and overlap window.
"""
import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.api.services.alert_service import AlertService, DEFAULT_MAX_ANALYSIS_EVENTS
from src.ingestion.collectors.stream_worker import TelemetryStreamWorker
from src.ingestion.storage.telemetry_repository import TelemetryRepository
from src.shared.models import AnalysisResult, DetectionAlert, PriorityLevel


# ---------------------------------------------------------------------------
# 1. AttachTime parsing tests
# ---------------------------------------------------------------------------

def test_attachtime_parsing_valid_iso(tmp_path):
    snap_file = tmp_path / "snapshot.json"
    content = {
        "taken_at": "2026-10-17T16:53:43.034696+00:00",
        "instances": [
            {
                "NetworkInterfaces": [
                    {
                        "NetworkInterfaceId": "eni-valid",
                        "Attachment": {
                            "AttachTime": "2026-10-15 09:59:57+00:00",
                        },
                        "Groups": [{"GroupId": "sg-1"}],
                    }
                ]
            }
        ],
    }
    snap_file.write_text(json.dumps(content))
    repo = TelemetryRepository(snapshot_path=snap_file)
    history = repo.load_configuration_history()
    assert len(history.attachments) == 1
    att = history.attachments[0]
    assert att.attached_at == datetime(2026, 10, 15, 9, 59, 57, tzinfo=timezone.utc)


def test_attachtime_parsing_naive_treated_as_utc(tmp_path):
    snap_file = tmp_path / "snapshot.json"
    content = {
        "taken_at": "2026-10-17T16:53:43Z",
        "instances": [
            {
                "NetworkInterfaces": [
                    {
                        "NetworkInterfaceId": "eni-naive",
                        "Attachment": {
                            "AttachTime": "2026-10-15T09:59:57",
                        },
                        "Groups": [{"GroupId": "sg-1"}],
                    }
                ]
            }
        ],
    }
    snap_file.write_text(json.dumps(content))
    repo = TelemetryRepository(snapshot_path=snap_file)
    history = repo.load_configuration_history()
    assert len(history.attachments) == 1
    att = history.attachments[0]
    assert att.attached_at.tzinfo == timezone.utc
    assert att.attached_at == datetime(2026, 10, 15, 9, 59, 57, tzinfo=timezone.utc)


def test_attachtime_missing_falls_back_to_taken_at(tmp_path):
    snap_file = tmp_path / "snapshot.json"
    content = {
        "taken_at": "2026-10-17T16:53:43+00:00",
        "instances": [
            {
                "NetworkInterfaces": [
                    {
                        "NetworkInterfaceId": "eni-no-attach",
                        "Attachment": {},
                        "Groups": [{"GroupId": "sg-1"}],
                    }
                ]
            }
        ],
    }
    snap_file.write_text(json.dumps(content))
    repo = TelemetryRepository(snapshot_path=snap_file)
    history = repo.load_configuration_history()
    assert len(history.attachments) == 1
    assert history.attachments[0].attached_at == datetime(2026, 10, 17, 16, 53, 43, tzinfo=timezone.utc)


def test_attachtime_invalid_falls_back_to_taken_at(tmp_path):
    snap_file = tmp_path / "snapshot.json"
    content = {
        "taken_at": "2026-10-17T16:53:43+00:00",
        "instances": [
            {
                "NetworkInterfaces": [
                    {
                        "NetworkInterfaceId": "eni-bad-attach",
                        "Attachment": {
                            "AttachTime": "not-a-date-string"
                        },
                        "Groups": [{"GroupId": "sg-1"}],
                    }
                ]
            }
        ],
    }
    snap_file.write_text(json.dumps(content))
    repo = TelemetryRepository(snapshot_path=snap_file)
    history = repo.load_configuration_history()
    assert len(history.attachments) == 1
    assert history.attachments[0].attached_at == datetime(2026, 10, 17, 16, 53, 43, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# 2. Configurable event limit (MAX_ANALYSIS_EVENTS)
# ---------------------------------------------------------------------------

def test_configurable_event_limit_default(monkeypatch):
    monkeypatch.delenv("MAX_ANALYSIS_EVENTS", raising=False)
    service = AlertService()
    assert service._get_max_analysis_events() == DEFAULT_MAX_ANALYSIS_EVENTS


def test_configurable_event_limit_env_override(monkeypatch):
    monkeypatch.setenv("MAX_ANALYSIS_EVENTS", "50000")
    service = AlertService()
    assert service._get_max_analysis_events() == 50000


def test_configurable_event_limit_invalid_env_falls_back(monkeypatch):
    monkeypatch.setenv("MAX_ANALYSIS_EVENTS", "invalid_number")
    service = AlertService()
    assert service._get_max_analysis_events() == DEFAULT_MAX_ANALYSIS_EVENTS


# ---------------------------------------------------------------------------
# 3. AlertService refresh logic & thread safety
# ---------------------------------------------------------------------------

def test_alert_service_refresh_logic():
    mock_repo = MagicMock()
    mock_repo.count_events.return_value = 10
    mock_repo.load_configuration_history.return_value = MagicMock()
    mock_repo.get_events.return_value = []

    service = AlertService(repository=mock_repo, refresh_interval_seconds=0.1)

    # Initial compute
    with patch("src.api.services.alert_service.analyze") as mock_analyze:
        res1 = AnalysisResult(alerts=[], nodes=[], edges=[], candidate_paths=[], scored_alerts=[])
        mock_analyze.return_value = res1

        res = service.get_analysis_result()
        assert res == res1
        assert mock_analyze.call_count == 1

        # Second call immediately: count unchanged, cache returned without re-analysis
        res_cached = service.get_analysis_result()
        assert res_cached == res1
        assert mock_analyze.call_count == 1

        # Event count changes and interval elapses -> triggers background refresh
        mock_repo.count_events.return_value = 20
        time.sleep(0.15)
        res_during = service.get_analysis_result()
        # Returns cached result immediately while background thread updates
        assert res_during == res1

        # Wait a short moment for background thread to finish
        time.sleep(0.1)
        assert mock_analyze.call_count >= 2


def test_alert_service_force_refresh():
    mock_repo = MagicMock()
    mock_repo.count_events.return_value = 10
    mock_repo.load_configuration_history.return_value = MagicMock()
    mock_repo.get_events.return_value = []

    res1 = AnalysisResult(alerts=[], nodes=[], edges=[], candidate_paths=[], scored_alerts=[])
    service = AlertService(repository=mock_repo, cached_result=res1)

    with patch("src.api.services.alert_service.analyze") as mock_analyze:
        res2 = AnalysisResult(alerts=[], nodes=[], edges=[], candidate_paths=[], scored_alerts=[])
        mock_analyze.return_value = res2

        # force_refresh=True forces synchronous recalculation
        res = service.get_analysis_result(force_refresh=True)
        assert res == res2
        assert mock_analyze.call_count == 1


# ---------------------------------------------------------------------------
# 4. SQS delete-only-on-success behavior
# ---------------------------------------------------------------------------

def test_sqs_delete_only_on_success(tmp_path):
    db_file = tmp_path / "test.db"
    con = sqlite3.connect(db_file)
    con.execute(
        "CREATE TABLE trail_events ("
        "event_id TEXT PRIMARY KEY, event_time TEXT, event_name TEXT, "
        "event_source TEXT, user_arn TEXT, source_ip TEXT, raw TEXT)"
    )

    mock_sqs = MagicMock()
    mock_s3 = MagicMock()
    mock_logs = MagicMock()

    cfg = {"profile": "test", "sqs_queue_url": "https://sqs.mock/queue"}
    worker = TelemetryStreamWorker(cfg)
    worker.sqs = mock_sqs
    worker.s3 = mock_s3
    worker.logs = mock_logs

    # Case A: Message fails during S3 processing -> NOT deleted from SQS
    mock_sqs.receive_message.return_value = {
        "Messages": [
            {
                "ReceiptHandle": "receipt-fail-1",
                "MessageId": "msg-fail",
                "Body": json.dumps({
                    "Records": [{"s3": {"bucket": {"name": "b"}, "object": {"key": "fail.json.gz"}}}]
                }),
            }
        ]
    }
    with patch.object(worker, "process_s3_event_record", side_effect=RuntimeError("S3 read error")):
        worker.poll_sqs_notifications(con)
        mock_sqs.delete_message.assert_not_called()

    # Case B: Message succeeds -> deleted from SQS
    mock_sqs.receive_message.return_value = {
        "Messages": [
            {
                "ReceiptHandle": "receipt-success-1",
                "MessageId": "msg-ok",
                "Body": json.dumps({
                    "Records": [{"s3": {"bucket": {"name": "b"}, "object": {"key": "ok.json.gz"}}}]
                }),
            }
        ]
    }
    with patch.object(worker, "process_s3_event_record", return_value=5):
        worker.poll_sqs_notifications(con)
        mock_sqs.delete_message.assert_called_once_with(
            QueueUrl="https://sqs.mock/queue",
            ReceiptHandle="receipt-success-1",
        )

    # Case C: Message with no Records (e.g. s3:TestEvent) -> acknowledged and deleted
    mock_sqs.delete_message.reset_mock()
    mock_sqs.receive_message.return_value = {
        "Messages": [
            {
                "ReceiptHandle": "receipt-test-event",
                "MessageId": "msg-test",
                "Body": json.dumps({"Event": "s3:TestEvent"}),
            }
        ]
    }
    worker.poll_sqs_notifications(con)
    mock_sqs.delete_message.assert_called_once_with(
        QueueUrl="https://sqs.mock/queue",
        ReceiptHandle="receipt-test-event",
    )
    con.close()


# ---------------------------------------------------------------------------
# 5. VPC Flow logs pagination and overlap window
# ---------------------------------------------------------------------------

def test_vpc_flow_pagination_and_overlap(tmp_path):
    db_file = tmp_path / "test_flow.db"
    con = sqlite3.connect(db_file)
    from src.ingestion.collectors.stream_worker import FLOW_FIELDS
    cols = ", ".join(f"{f} TEXT" for f in FLOW_FIELDS)
    con.execute(f"CREATE TABLE flow_events (event_id TEXT PRIMARY KEY, {cols})")

    mock_logs = MagicMock()
    # 2-page response
    line1 = " ".join(["val"] * len(FLOW_FIELDS))
    mock_logs.filter_log_events.side_effect = [
        {"events": [{"eventId": "ev-1", "message": line1}], "nextToken": "tok-1"},
        {"events": [{"eventId": "ev-2", "message": line1}], "nextToken": None},
    ]

    cursor_file = tmp_path / "cursor.json"
    cfg = {"profile": "test", "log_group": "/test/flow"}
    worker = TelemetryStreamWorker(cfg)
    worker.logs = mock_logs
    worker.cursor_path = cursor_file
    worker.last_flow_time = 1_000_000_000

    new_count = worker.poll_vpc_flow_logs(con)
    assert new_count == 2
    assert mock_logs.filter_log_events.call_count == 2

    # Check that overlap was subtracted in query
    first_call_kwargs = mock_logs.filter_log_events.call_args_list[0][1]
    # start_time = 1_000_000_000 - 300_000 = 999_700_000
    assert first_call_kwargs["startTime"] == 1_000_000_000 - (300 * 1000)

    # Check cursor file was written
    assert cursor_file.exists()
    cursor_data = json.loads(cursor_file.read_text())
    assert "last_flow_time" in cursor_data
    con.close()
