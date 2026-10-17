"""Normalize raw AWS telemetry into the shared ``BaseTelemetryEvent`` contract.

Two entry points:

* ``normalize_flow_record``  - one VPC Flow Log record (v5 custom format, as stored by
  ``run_collect.py`` in the ``flow_events`` table).
* ``normalize_trail_record`` - one CloudTrail record, either a collector row
  (``trail_events`` table, raw JSON in the ``raw`` column) or a bare CloudTrail record.

Contract for callers:

* A usable record  -> returns a ``BaseTelemetryEvent``.
* A record that is valid but carries no traffic (flow ``NODATA`` / ``SKIPDATA``)
  -> returns ``None``. This is not an error.
* A malformed record (not a mapping, missing a required field, bad IP/port/time)
  -> raises ``EventValidationError``. Nothing is guessed or silently defaulted.

``normalize_batch`` wraps both and returns ``(events, skipped_count, errors)`` so one bad
record never aborts a batch.
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from src.shared.constants import IP_PROTOCOL_MAP
from src.shared.enums import EventSource, FlowAction
from src.shared.exceptions import EventValidationError
from src.shared.models import BaseTelemetryEvent

NO_VALUE = "-"  # VPC Flow Logs use "-" for "not applicable"
NON_TRAFFIC_STATUSES = {"NODATA", "SKIPDATA"}

SG_ACTIONS = {
    "AuthorizeSecurityGroupIngress": "ingress",
    "AuthorizeSecurityGroupEgress": "egress",
    "RevokeSecurityGroupIngress": "ingress",
    "RevokeSecurityGroupEgress": "egress",
}


# --------------------------------------------------------------------------- helpers
def _present(value: Any) -> bool:
    return value is not None and str(value).strip() not in ("", NO_VALUE)


def _clean(rec: Mapping[str, Any], key: str) -> Optional[str]:
    value = rec.get(key)
    return str(value).strip() if _present(value) else None


def _require(rec: Mapping[str, Any], key: str, kind: str) -> str:
    value = _clean(rec, key)
    if value is None:
        raise EventValidationError(f"{kind} record missing required field '{key}'")
    return value


def _to_int(value: Optional[str], field: str, kind: str) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise EventValidationError(f"{kind} record has non-integer '{field}': {value!r}")


def _valid_ip(value: Optional[str], field: str, kind: str) -> Optional[str]:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise EventValidationError(f"{kind} record has invalid IP in '{field}': {value!r}")


def _epoch_to_dt(value: str, kind: str) -> datetime:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        raise EventValidationError(f"{kind} record has invalid epoch time: {value!r}")


def _iso_to_dt(value: str, kind: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EventValidationError(f"{kind} record has invalid timestamp: {value!r}")
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _protocol_name(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return IP_PROTOCOL_MAP.get(value.lower(), value.lower())


# ------------------------------------------------------------------------ VPC flow
def normalize_flow_record(rec: Mapping[str, Any]) -> Optional[BaseTelemetryEvent]:
    """Map one VPC Flow Log record to a ``BaseTelemetryEvent`` (source=vpc_flow)."""
    kind = "flow"
    if not isinstance(rec, Mapping):
        raise EventValidationError("flow record must be a mapping")

    event_id = _require(rec, "event_id", kind)

    status = (_clean(rec, "log_status") or "OK").upper()
    if status in NON_TRAFFIC_STATUSES:
        return None  # no packets observed in the window; nothing to model

    action = _require(rec, "action", kind).upper()
    if action not in {a.value for a in FlowAction}:
        raise EventValidationError(f"flow record has unknown action: {action!r}")

    src = _valid_ip(_require(rec, "srcaddr", kind), "srcaddr", kind)
    dst = _valid_ip(_require(rec, "dstaddr", kind), "dstaddr", kind)
    timestamp = _epoch_to_dt(_require(rec, "start", kind), kind)

    dport = _to_int(_clean(rec, "dstport"), "dstport", kind)
    if dport is not None and not 0 <= dport <= 65535:
        raise EventValidationError(f"flow record has out-of-range dstport: {dport}")

    details: Dict[str, Any] = {}
    proto = _protocol_name(_clean(rec, "protocol"))
    if proto is not None:
        details["protocol"] = proto
    for key in ("srcport", "packets", "bytes", "end", "tcp_flags"):
        val = _to_int(_clean(rec, key), key, kind)
        if val is not None:
            details["source_port" if key == "srcport" else key] = val
    for key in ("flow_direction", "vpc_id", "subnet_id", "instance_id",
                "account_id", "pkt_srcaddr", "pkt_dstaddr", "version"):
        val = _clean(rec, key)
        if val is not None:
            details[key] = val
    details["log_status"] = status

    return BaseTelemetryEvent(
        event_id=event_id,
        timestamp=timestamp,
        source=EventSource.VPC_FLOW,
        action=action,
        actor=None,  # flows have no principal; kept distinct from IAM actors
        resource_id=_clean(rec, "interface_id"),
        source_ip=src,
        destination_ip=dst,
        destination_port=dport,
        raw_record_id=event_id,
        details=details,
    )


# --------------------------------------------------------------------- CloudTrail
def _items(node: Any) -> List[Any]:
    """CloudTrail wraps EC2 lists as ``{"items": [...]}``; unwrap, tolerate ``{}``/None/list."""
    if isinstance(node, Mapping):
        inner = node.get("items")
        return list(inner) if isinstance(inner, list) else []
    return list(node) if isinstance(node, list) else []


def flatten_ip_permissions(ip_permissions: Any) -> List[Dict[str, Any]]:
    """Convert CloudTrail ``ipPermissions`` into a plain list of permission dicts.

    SG-to-SG references (``groups``) are preserved as ``groups`` so downstream
    correlation can see them; they are never coerced into a CIDR.
    """
    out: List[Dict[str, Any]] = []
    for perm in _items(ip_permissions):
        if not isinstance(perm, Mapping):
            continue
        flat: Dict[str, Any] = {"ipProtocol": perm.get("ipProtocol")}
        if perm.get("fromPort") is not None:
            flat["fromPort"] = perm["fromPort"]
        if perm.get("toPort") is not None:
            flat["toPort"] = perm["toPort"]
        flat["ipRanges"] = [r for r in _items(perm.get("ipRanges")) if isinstance(r, Mapping)]
        flat["ipv6Ranges"] = [r for r in _items(perm.get("ipv6Ranges")) if isinstance(r, Mapping)]
        flat["groups"] = [g for g in _items(perm.get("groups")) if isinstance(g, Mapping)]
        out.append(flat)
    return out


def _actor(raw: Mapping[str, Any]) -> Optional[str]:
    ident = raw.get("userIdentity")
    if not isinstance(ident, Mapping):
        return None
    for key in ("arn", "invokedBy"):
        if _present(ident.get(key)):
            return str(ident[key])
    return None


def _trail_raw(rec: Mapping[str, Any]) -> Mapping[str, Any]:
    """Collector rows keep the original record as JSON text in ``raw``; bare records pass through."""
    raw = rec.get("raw")
    if raw is None:
        return rec
    if isinstance(raw, Mapping):
        return raw
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        raise EventValidationError("cloudtrail row has unparseable 'raw' JSON")
    if not isinstance(parsed, Mapping):
        raise EventValidationError("cloudtrail 'raw' JSON is not an object")
    return parsed


def normalize_trail_record(rec: Mapping[str, Any]) -> BaseTelemetryEvent:
    """Map one CloudTrail record to a ``BaseTelemetryEvent`` (source=cloudtrail)."""
    kind = "cloudtrail"
    if not isinstance(rec, Mapping):
        raise EventValidationError("cloudtrail record must be a mapping")

    raw = _trail_raw(rec)
    event_id = _clean(raw, "eventID") or _clean(rec, "event_id")
    if event_id is None:
        raise EventValidationError("cloudtrail record missing required field 'eventID'")
    time_str = _clean(raw, "eventTime") or _clean(rec, "event_time")
    if time_str is None:
        raise EventValidationError("cloudtrail record missing required field 'eventTime'")
    action = _clean(raw, "eventName") or _clean(rec, "event_name")
    if action is None:
        raise EventValidationError("cloudtrail record missing required field 'eventName'")
    timestamp = _iso_to_dt(time_str, kind)

    params = raw.get("requestParameters")
    params = params if isinstance(params, Mapping) else {}

    resource_id = _clean(params, "groupId") if action in SG_ACTIONS else None
    if resource_id is None:
        resources = raw.get("resources")
        if isinstance(resources, list) and resources and isinstance(resources[0], Mapping):
            resource_id = _clean(resources[0], "ARN")

    # sourceIPAddress is sometimes a service name (e.g. "ec2.amazonaws.com"), not an IP.
    source_ip: Optional[str] = None
    details: Dict[str, Any] = {}
    raw_ip = _clean(raw, "sourceIPAddress") or _clean(rec, "source_ip")
    if raw_ip is not None:
        try:
            source_ip = str(ipaddress.ip_address(raw_ip))
        except ValueError:
            details["source_ip_raw"] = raw_ip

    for src_key, dst_key in (("eventSource", "event_source"), ("awsRegion", "aws_region"),
                             ("eventType", "event_type"), ("requestID", "request_id")):
        val = _clean(raw, src_key) or (_clean(rec, dst_key) if dst_key == "event_source" else None)
        if val is not None:
            details[dst_key] = val
    if isinstance(raw.get("readOnly"), bool):
        details["read_only"] = raw["readOnly"]

    # camelCase keys are what cross_layer.py reads
    if _present(raw.get("errorCode")):
        details["errorCode"] = str(raw["errorCode"])
    if _present(raw.get("errorMessage")):
        details["errorMessage"] = str(raw["errorMessage"])
    details["success"] = "errorCode" not in details and "errorMessage" not in details

    if action in SG_ACTIONS:
        details["direction"] = SG_ACTIONS[action]
        details["security_group_id"] = resource_id
        details["ipPermissions"] = flatten_ip_permissions(params.get("ipPermissions"))

    return BaseTelemetryEvent(
        event_id=event_id,
        timestamp=timestamp,
        source=EventSource.CLOUDTRAIL,
        action=action,
        actor=_actor(raw),
        resource_id=resource_id,
        source_ip=source_ip,
        destination_ip=None,
        destination_port=None,
        raw_record_id=event_id,
        details=details,
    )


# ------------------------------------------------------------------------- batches
def normalize_batch(
    records: Iterable[Mapping[str, Any]], kind: str
) -> Tuple[List[BaseTelemetryEvent], int, List[Tuple[Optional[str], str]]]:
    """Normalize many records. Returns ``(events, skipped_non_traffic, errors)``.

    ``kind`` is ``"flow"`` or ``"cloudtrail"``. ``errors`` is a list of
    ``(record_id_or_None, message)``; a bad record never aborts the batch.
    """
    fn = {"flow": normalize_flow_record, "cloudtrail": normalize_trail_record}.get(kind)
    if fn is None:
        raise ValueError(f"unknown record kind: {kind!r}")
    events: List[BaseTelemetryEvent] = []
    skipped = 0
    errors: List[Tuple[Optional[str], str]] = []
    for rec in records:
        try:
            ev = fn(rec)
        except EventValidationError as exc:
            rid = rec.get("event_id") if isinstance(rec, Mapping) else None
            errors.append((str(rid) if rid is not None else None, str(exc)))
            continue
        if ev is None:
            skipped += 1
        else:
            events.append(ev)
    return events, skipped, errors
