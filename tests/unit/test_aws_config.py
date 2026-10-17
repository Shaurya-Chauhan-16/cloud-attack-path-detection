"""Configuration snapshot -> ConfigurationHistory."""
from datetime import datetime, timezone

from src.ingestion.snapshots.aws_config import build_configuration_history

SNAP = {
    "taken_at": "2026-10-15T15:32:11+00:00",
    "instances": [{
        "InstanceId": "i-1",
        "NetworkInterfaces": [{
            "NetworkInterfaceId": "eni-1", "PrivateIpAddress": "10.20.1.10",
            "Association": {"PublicIp": "13.0.0.1"},
            "Groups": [{"GroupId": "sg-a"}, {"GroupId": "sg-b"}],
            "Attachment": {"AttachTime": "2026-10-15T09:00:00+00:00"},
        }],
    }],
}


def test_attachments_and_ip_map_built():
    h = build_configuration_history(SNAP)
    assert {(a.resource_id, a.security_group_id) for a in h.attachments} == {("eni-1", "sg-a"), ("eni-1", "sg-b")}
    assert h.eni_to_ip_map == {"eni-1": ["10.20.1.10", "13.0.0.1"]}
    assert h.get_resource_ids_for_ip("13.0.0.1") == ["eni-1"]


def test_attach_time_is_used_when_available():
    h = build_configuration_history(SNAP)
    assert h.attachments[0].attached_at == datetime(2026, 10, 15, 9, 0, tzinfo=timezone.utc)
    assert h.get_security_groups_for_resource("eni-1", datetime(2026, 10, 15, 10, tzinfo=timezone.utc)) == ["sg-a", "sg-b"]


def test_falls_back_to_snapshot_time_without_attach_time():
    snap = {"taken_at": SNAP["taken_at"], "instances": [{"NetworkInterfaces": [
        {"NetworkInterfaceId": "eni-9", "Groups": [{"GroupId": "sg-z"}]}]}]}
    assert build_configuration_history(snap).attachments[0].attached_at == datetime(2026, 10, 15, 15, 32, 11, tzinfo=timezone.utc)


def test_missing_and_malformed_sections_yield_empty_history():
    for snap in ({}, {"instances": None}, {"instances": [None, {}]},
                 {"instances": [{"NetworkInterfaces": [{"Groups": [{"GroupId": "sg-1"}]}]}]}):
        h = build_configuration_history(snap)
        assert h.attachments == [] and h.eni_to_ip_map == {}


def test_duplicate_groups_are_deduplicated():
    snap = {"taken_at": SNAP["taken_at"], "instances": [{"NetworkInterfaces": [
        {"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-a"}, {"GroupId": "sg-a"}]}]}]}
    assert len(build_configuration_history(snap).attachments) == 1


def test_bad_timestamps_do_not_crash():
    snap = {"taken_at": "garbage", "instances": [{"NetworkInterfaces": [
        {"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-a"}]}]}]}
    assert len(build_configuration_history(snap).attachments) == 1
