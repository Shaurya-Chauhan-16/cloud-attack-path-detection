"""Run the real sanitized lab fixtures through the full ingestion pipeline."""
import json
from pathlib import Path

import pytest

from src.ingestion.snapshots.aws_config import load_configuration_history
from src.ingestion.storage.database import connect
from src.ingestion.storage.repository import EventRepository
from src.shared.enums import EventSource

FIX = Path("fixtures/sanitized")


@pytest.fixture(scope="module")
def repo():
    con = connect(":memory:")
    for line in (FIX / "flow_events.jsonl").read_text().splitlines():
        r = json.loads(line)
        con.execute(f"INSERT INTO flow_events ({','.join(r)}) VALUES ({','.join('?' * len(r))})", list(r.values()))
    for line in (FIX / "trail_events.jsonl").read_text().splitlines():
        r = json.loads(line)
        con.execute(f"INSERT INTO trail_events ({','.join(r)}) VALUES ({','.join('?' * len(r))})", list(r.values()))
    con.commit()
    r = EventRepository(con)
    r.summary = r.ingest_all()
    return r


def test_every_real_record_is_accounted_for_with_no_errors(repo):
    s = repo.summary
    assert s.read == 4946 + 566
    assert s.malformed == 0 and repo.get_errors() == []
    assert s.skipped == 313                      # NODATA rows
    assert s.stored == 4633 + 566


def test_flow_events_have_usable_network_fields(repo):
    flows = repo.get_events(source=EventSource.VPC_FLOW)
    assert all(e.source_ip and e.destination_ip and e.resource_id for e in flows)
    assert {e.action for e in flows} == {"ACCEPT", "REJECT"}


def test_real_sg_changes_map_with_group_references(repo):
    changes = repo.get_events(action="AuthorizeSecurityGroupIngress")
    assert changes, "fixtures should contain SG authorize events"
    assert all(e.resource_id and e.resource_id.startswith("sg-") for e in changes)
    refs = [g for e in changes for p in e.details["ipPermissions"] for g in p["groups"]]
    assert refs, "lab scenario authorizes SG-to-SG access"


def test_real_snapshot_builds_configuration_history():
    h = load_configuration_history(next((FIX / "config_snapshots").glob("*.json")))
    assert h.attachments and h.eni_to_ip_map
