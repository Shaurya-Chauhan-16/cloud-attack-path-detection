"""CloudTrail -> BaseTelemetryEvent: normal, malformed and missing-field records."""
import json
from datetime import datetime, timezone

import pytest

from src.detection.correlation.cross_layer import CrossLayerCorrelator
from src.ingestion.normalization.mapper import (
    flatten_ip_permissions, normalize_batch, normalize_flow_record, normalize_trail_record,
)
from src.shared.enums import EventSource
from src.shared.exceptions import EventValidationError
from src.shared.models import ConfigurationHistory, SecurityGroupAttachment
from tests.unit.test_flow_normalization import flow as flow_rec

ARN = "arn:aws:iam::111122223333:user/lab-user-1"


def sg_record(name="AuthorizeSecurityGroupIngress", perms=None, **overrides):
    rec = {
        "eventID": "ct-1", "eventTime": "2026-10-15T10:00:00Z", "eventName": name,
        "eventSource": "ec2.amazonaws.com", "awsRegion": "ap-south-1",
        "sourceIPAddress": "198.18.3.73", "readOnly": False, "eventType": "AwsApiCall",
        "userIdentity": {"type": "IAMUser", "arn": ARN},
        "requestParameters": {"groupId": "sg-1", "ipPermissions": {"items": perms if perms is not None else [
            {"ipProtocol": "tcp", "fromPort": 8080, "toPort": 8080,
             "ipRanges": {"items": [{"cidrIp": "10.20.1.0/24"}]}, "groups": {}}]}},
        "responseElements": {"_return": True},
        "errorCode": None,
    }
    rec.update(overrides)
    return rec


def row_of(raw, **extra):
    """Shape the collector stores in the trail_events table."""
    return {"event_id": raw.get("eventID"), "event_time": raw.get("eventTime"),
            "event_name": raw.get("eventName"), "event_source": raw.get("eventSource"),
            "user_arn": (raw.get("userIdentity") or {}).get("arn"),
            "source_ip": raw.get("sourceIPAddress"), "raw": json.dumps(raw), **extra}


# ------------------------------------------------------------------ normal records
def test_authorize_sg_maps_contract_fields():
    ev = normalize_trail_record(sg_record())
    assert ev.source == EventSource.CLOUDTRAIL
    assert ev.event_id == ev.raw_record_id == "ct-1"
    assert ev.action == "AuthorizeSecurityGroupIngress"
    assert ev.actor == ARN and ev.resource_id == "sg-1"
    assert ev.source_ip == "198.18.3.73"
    assert ev.destination_ip is None and ev.destination_port is None
    assert ev.timestamp == datetime(2026, 10, 15, 10, 0, tzinfo=timezone.utc)
    assert ev.details["success"] is True and ev.details["direction"] == "ingress"
    assert ev.details["event_source"] == "ec2.amazonaws.com"


def test_collector_row_and_bare_record_map_identically():
    raw = sg_record()
    assert normalize_trail_record(row_of(raw)) == normalize_trail_record(raw)


def test_ip_permissions_are_unwrapped_to_plain_lists():
    perms = normalize_trail_record(sg_record()).details["ipPermissions"]
    assert perms == [{"ipProtocol": "tcp", "fromPort": 8080, "toPort": 8080,
                      "ipRanges": [{"cidrIp": "10.20.1.0/24"}], "ipv6Ranges": [], "groups": []}]


def test_sg_to_sg_reference_is_preserved_not_turned_into_a_cidr():
    perms = [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
              "groups": {"items": [{"groupId": "sg-source", "userId": "111122223333"}]}}]
    p = normalize_trail_record(sg_record(perms=perms)).details["ipPermissions"][0]
    assert p["groups"] == [{"groupId": "sg-source", "userId": "111122223333"}]
    assert p["ipRanges"] == []


def test_revoke_and_egress_variants():
    assert normalize_trail_record(sg_record("RevokeSecurityGroupIngress")).details["direction"] == "ingress"
    ev = normalize_trail_record(sg_record("AuthorizeSecurityGroupEgress"))
    assert ev.details["direction"] == "egress" and ev.resource_id == "sg-1"


def test_non_sg_event_has_no_sg_details_and_uses_resource_arn():
    raw = {"eventID": "ct-2", "eventTime": "2026-10-15T10:35:39Z", "eventName": "GetBucketVersioning",
           "userIdentity": {"arn": ARN}, "sourceIPAddress": "198.18.3.73",
           "resources": [{"ARN": "arn:aws:s3:::bucket"}]}
    ev = normalize_trail_record(raw)
    assert ev.resource_id == "arn:aws:s3:::bucket" and "ipPermissions" not in ev.details


# ---------------------------------------------------------------- failed API calls
def test_error_code_marks_event_failed_in_cross_layer_keys():
    ev = normalize_trail_record(sg_record(errorCode="UnauthorizedOperation", errorMessage="denied"))
    assert ev.details["success"] is False
    assert ev.details["errorCode"] == "UnauthorizedOperation"
    assert ev.details["errorMessage"] == "denied"


def test_failed_sg_change_produces_no_alert_in_correlator():
    """Contract test: mapper output keys must be the ones CrossLayerCorrelator reads."""
    ct = normalize_trail_record(sg_record(perms=[{"ipProtocol": "tcp", "fromPort": 3389, "toPort": 3389,
                                                  "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}],
                                          errorCode="UnauthorizedOperation"))
    fl = normalize_flow_record(flow_rec(dstport="3389", start="1792060210"))
    cfg = ConfigurationHistory(
        attachments=[SecurityGroupAttachment(resource_id="eni-1", security_group_id="sg-1",
                                             attached_at=datetime(2020, 1, 1, tzinfo=timezone.utc))],
        eni_to_ip_map={"eni-1": ["10.20.1.10"]})
    assert CrossLayerCorrelator().correlate([ct, fl], cfg) == []


def test_successful_open_sg_change_correlates_with_flow():
    ct = normalize_trail_record(sg_record(
        eventTime="2026-10-15T10:00:00Z",
        perms=[{"ipProtocol": "tcp", "fromPort": 3389, "toPort": 3389,
                "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]))
    start = int(datetime(2026, 10, 15, 10, 0, 30, tzinfo=timezone.utc).timestamp())
    fl = normalize_flow_record(flow_rec(dstport="3389", start=str(start)))
    cfg = ConfigurationHistory(
        attachments=[SecurityGroupAttachment(resource_id="eni-1", security_group_id="sg-1",
                                             attached_at=datetime(2020, 1, 1, tzinfo=timezone.utc))],
        eni_to_ip_map={"eni-1": ["10.20.1.10"]})
    alerts = CrossLayerCorrelator().correlate([ct, fl], cfg)
    assert len(alerts) == 1 and set(alerts[0].evidence_event_ids) == {"ct-1", "f-1"}


# ------------------------------------------------------------- missing-field records
def test_missing_user_identity_gives_none_actor():
    raw = sg_record(); del raw["userIdentity"]
    assert normalize_trail_record(raw).actor is None


def test_service_principal_uses_invoked_by():
    raw = sg_record(userIdentity={"type": "AWSService", "invokedBy": "config.amazonaws.com"})
    assert normalize_trail_record(raw).actor == "config.amazonaws.com"


def test_row_with_null_user_arn_still_maps():
    raw = sg_record(userIdentity={"type": "AWSService"})
    assert normalize_trail_record(row_of(raw)).actor is None


def test_service_name_as_source_ip_is_not_stored_as_ip():
    ev = normalize_trail_record(sg_record(sourceIPAddress="ec2.amazonaws.com"))
    assert ev.source_ip is None and ev.details["source_ip_raw"] == "ec2.amazonaws.com"


def test_sg_event_without_group_id_has_no_resource():
    raw = sg_record(); raw["requestParameters"] = {}
    ev = normalize_trail_record(raw)
    assert ev.resource_id is None and ev.details["ipPermissions"] == []


@pytest.mark.parametrize("params", [None, "oops", []])
def test_odd_request_parameters_do_not_crash(params):
    assert normalize_trail_record(sg_record(requestParameters=params)).resource_id is None


@pytest.mark.parametrize("field", ["eventID", "eventTime", "eventName"])
def test_missing_required_field_raises(field):
    raw = sg_record(); del raw[field]
    with pytest.raises(EventValidationError, match=field):
        normalize_trail_record(raw)


def test_row_falls_back_to_row_columns_when_raw_lacks_fields():
    raw = sg_record(); del raw["eventID"]
    row = row_of(sg_record())  # columns intact
    row["raw"] = json.dumps(raw)
    assert normalize_trail_record(row).event_id == "ct-1"


# --------------------------------------------------------------- malformed records
def test_unparseable_raw_json_raises():
    with pytest.raises(EventValidationError, match="raw"):
        normalize_trail_record({"event_id": "x", "raw": "{not json"})


def test_raw_json_not_an_object_raises():
    with pytest.raises(EventValidationError):
        normalize_trail_record({"event_id": "x", "raw": "[1,2]"})


def test_bad_timestamp_raises():
    with pytest.raises(EventValidationError, match="timestamp"):
        normalize_trail_record(sg_record(eventTime="last tuesday"))


def test_timestamp_with_offset_is_converted_to_utc():
    ev = normalize_trail_record(sg_record(eventTime="2026-10-15T15:30:00+05:30"))
    assert ev.timestamp == datetime(2026, 10, 15, 10, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("bad", [None, "str", 3, []])
def test_non_mapping_input_raises(bad):
    with pytest.raises(EventValidationError):
        normalize_trail_record(bad)


# ------------------------------------------------------------------------ helpers
def test_flatten_ip_permissions_tolerates_garbage():
    assert flatten_ip_permissions(None) == []
    assert flatten_ip_permissions({}) == []
    assert flatten_ip_permissions({"items": ["junk", 5, None]}) == []


def test_batch_isolates_bad_records_and_counts_everything():
    good = sg_record()
    bad = {"eventID": "bad-1", "eventTime": "nope", "eventName": "X"}
    events, skipped, errors = normalize_batch([good, bad, "junk"], "cloudtrail")
    assert [e.event_id for e in events] == ["ct-1"] and skipped == 0
    assert len(errors) == 2 and errors[1][0] is None


def test_batch_rejects_unknown_kind():
    with pytest.raises(ValueError):
        normalize_batch([], "netflow")
