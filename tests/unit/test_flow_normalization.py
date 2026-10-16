"""VPC Flow Log -> BaseTelemetryEvent: normal, malformed and missing-field records."""
from datetime import datetime, timezone

import pytest

from src.ingestion.normalization.mapper import normalize_flow_record
from src.shared.enums import EventSource
from src.shared.exceptions import EventValidationError


def flow(**overrides):
    rec = {
        "event_id": "f-1", "version": "5", "account_id": "111122223333",
        "interface_id": "eni-1", "srcaddr": "203.0.113.5", "dstaddr": "10.20.1.10",
        "srcport": "54000", "dstport": "8080", "protocol": "6", "packets": "4",
        "bytes": "240", "start": "1792060206", "end": "1792060225", "action": "ACCEPT",
        "log_status": "OK", "vpc_id": "vpc-1", "subnet_id": "subnet-1",
        "instance_id": "i-1", "tcp_flags": "2", "flow_direction": "ingress",
        "pkt_srcaddr": "203.0.113.5", "pkt_dstaddr": "10.20.1.10",
    }
    rec.update(overrides)
    return rec


# ------------------------------------------------------------------ normal records
def test_accepted_flow_maps_all_contract_fields():
    ev = normalize_flow_record(flow())
    assert ev.event_id == "f-1" and ev.raw_record_id == "f-1"
    assert ev.source == EventSource.VPC_FLOW
    assert ev.action == "ACCEPT" and ev.is_accepted_flow
    assert ev.resource_id == "eni-1"
    assert (ev.source_ip, ev.destination_ip, ev.destination_port) == ("203.0.113.5", "10.20.1.10", 8080)
    assert ev.actor is None
    assert ev.timestamp == datetime.fromtimestamp(1792060206, tz=timezone.utc)
    assert ev.protocol == "tcp"


def test_details_are_typed_and_complete():
    d = normalize_flow_record(flow()).details
    assert d["source_port"] == 54000 and d["packets"] == 4 and d["bytes"] == 240
    assert d["end"] == 1792060225 and d["tcp_flags"] == 2
    assert d["flow_direction"] == "ingress" and d["instance_id"] == "i-1"


def test_rejected_flow_and_lowercase_action():
    ev = normalize_flow_record(flow(action="reject"))
    assert ev.action == "REJECT" and ev.is_rejected_flow


@pytest.mark.parametrize("num,name", [("6", "tcp"), ("17", "udp"), ("1", "icmp")])
def test_protocol_numbers_map_to_names(num, name):
    assert normalize_flow_record(flow(protocol=num)).protocol == name


def test_unknown_protocol_number_is_kept_not_dropped():
    assert normalize_flow_record(flow(protocol="47")).protocol == "47"  # GRE


def test_ipv6_addresses_are_accepted():
    ev = normalize_flow_record(flow(srcaddr="2001:db8::1", dstaddr="2001:db8::2"))
    assert ev.source_ip == "2001:db8::1"


def test_icmp_with_port_zero_keeps_zero():
    assert normalize_flow_record(flow(protocol="1", dstport="0")).destination_port == 0


# ------------------------------------------------------- valid but non-traffic rows
@pytest.mark.parametrize("status", ["NODATA", "SKIPDATA", "nodata"])
def test_nodata_and_skipdata_return_none_not_error(status):
    rec = flow(log_status=status, srcaddr="-", dstaddr="-", dstport="-", action="-", protocol="-")
    assert normalize_flow_record(rec) is None


# ------------------------------------------------------------- missing-field records
def test_dash_dstport_becomes_none():
    assert normalize_flow_record(flow(dstport="-")).destination_port is None


def test_missing_interface_id_gives_none_resource():
    rec = flow(); del rec["interface_id"]
    assert normalize_flow_record(rec).resource_id is None


def test_optional_fields_absent_do_not_break_mapping():
    rec = {k: flow()[k] for k in ("event_id", "srcaddr", "dstaddr", "start", "action")}
    ev = normalize_flow_record(rec)
    assert ev.destination_port is None and "protocol" not in ev.details


@pytest.mark.parametrize("field", ["event_id", "srcaddr", "dstaddr", "start", "action"])
def test_missing_required_field_raises(field):
    rec = flow(); del rec[field]
    with pytest.raises(EventValidationError, match=field):
        normalize_flow_record(rec)


@pytest.mark.parametrize("field", ["event_id", "srcaddr", "dstaddr", "start", "action"])
def test_dash_or_empty_required_field_raises(field):
    for blank in ("-", "", "   ", None):
        with pytest.raises(EventValidationError):
            normalize_flow_record(flow(**{field: blank}))


# --------------------------------------------------------------- malformed records
@pytest.mark.parametrize("overrides", [
    {"srcaddr": "999.1.1.1"}, {"dstaddr": "not-an-ip"}, {"dstport": "http"},
    {"dstport": "70000"}, {"dstport": "-5"}, {"start": "yesterday"},
    {"action": "MAYBE"}, {"packets": "many"},
])
def test_malformed_values_raise(overrides):
    with pytest.raises(EventValidationError):
        normalize_flow_record(flow(**overrides))


@pytest.mark.parametrize("bad", [None, "a string", 42, ["list"]])
def test_non_mapping_input_raises(bad):
    with pytest.raises(EventValidationError):
        normalize_flow_record(bad)
