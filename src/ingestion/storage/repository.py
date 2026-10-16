"""Data access layer for Member 1's SQLite database and snapshot files.

Provides clean, read-only extraction of BaseTelemetryEvent and ConfigurationHistory
from data/local/events.db (or fixtures/sanitized) and snapshot JSONs.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Dict, List, Optional, Tuple

from src.shared.enums import EventSource
from src.shared.models import (
    BaseTelemetryEvent,
    ConfigurationHistory,
    SecurityGroupAttachment,
)


class TelemetryRepository:
    """Repository accessing Member 1's SQLite database and configuration snapshots."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        snapshot_path: Optional[str] = None,
    ):
        # Default paths to project standard locations
        self.db_path = Path(db_path) if db_path else Path("data/local/events.db")
        self.snapshot_path = Path(snapshot_path) if snapshot_path else Path("data/local/snapshots")

    def _get_connection(self) -> Optional[sqlite3.Connection]:
        if not self.db_path.exists():
            return None
        return sqlite3.connect(str(self.db_path))

    def load_configuration_history(self) -> ConfigurationHistory:
        """Parse configuration snapshot(s) into ConfigurationHistory.
        
        Reads snapshot JSON files from snapshot_path.
        """
        attachments: List[SecurityGroupAttachment] = []
        eni_to_ip_map: Dict[str, List[str]] = {}

        snap_files = []
        if self.snapshot_path.is_file():
            snap_files = [self.snapshot_path]
        elif self.snapshot_path.is_dir():
            snap_files = sorted(list(self.snapshot_path.glob("*.json")))

        if not snap_files:
            # Fall back to fixtures/sanitized/config_snapshots if available
            fixture_snaps = Path("fixtures/sanitized/config_snapshots")
            if fixture_snaps.is_dir():
                snap_files = sorted(list(fixture_snaps.glob("*.json")))

        for sf in snap_files:
            try:
                data = json.loads(sf.read_text())
                raw_time = data.get("taken_at")
                if raw_time:
                    snap_time = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
                else:
                    snap_time = datetime.now(timezone.utc)

                for inst in data.get("instances", []):
                    for ni in inst.get("NetworkInterfaces", []):
                        eni_id = ni.get("NetworkInterfaceId")
                        if not eni_id:
                            continue
                        ips = [
                            ip["PrivateIpAddress"]
                            for ip in ni.get("PrivateIpAddresses", [])
                            if "PrivateIpAddress" in ip
                        ]
                        if ips:
                            eni_to_ip_map[eni_id] = ips

                        for g in ni.get("Groups", []):
                            sg_id = g.get("GroupId")
                            if sg_id:
                                attachments.append(
                                    SecurityGroupAttachment(
                                        resource_id=eni_id,
                                        security_group_id=sg_id,
                                        attached_at=snap_time,
                                    )
                                )
            except Exception:
                continue

        return ConfigurationHistory(
            attachments=attachments,
            eni_to_ip_map=eni_to_ip_map,
        )

    def get_events(
        self,
        source: Optional[EventSource] = None,
        limit: int = 100,
        offset: int = 0,
        event_id: Optional[str] = None,
    ) -> List[BaseTelemetryEvent]:
        """Query normalized BaseTelemetryEvents from Member 1's SQLite database."""
        conn = self._get_connection()
        if not conn:
            return []

        events: List[BaseTelemetryEvent] = []
        try:
            cursor = conn.cursor()

            # 1. Query CloudTrail events
            if source is None or source == EventSource.CLOUDTRAIL:
                if event_id:
                    cursor.execute(
                        "SELECT event_id, event_time, event_name, event_source, user_arn, source_ip, raw "
                        "FROM trail_events WHERE event_id = ?",
                        (event_id,),
                    )
                else:
                    cursor.execute(
                        "SELECT event_id, event_time, event_name, event_source, user_arn, source_ip, raw "
                        "FROM trail_events ORDER BY event_time DESC LIMIT ? OFFSET ?",
                        (limit, offset),
                    )
                for row in cursor.fetchall():
                    eid, etime, ename, esrc, uarn, sip, raw_str = row
                    raw = json.loads(raw_str) if raw_str else {}
                    req = raw.get("requestParameters") or {}
                    group_id = req.get("groupId")
                    perms = req.get("ipPermissions", {})
                    items = perms.get("items", []) if isinstance(perms, dict) else perms

                    details: Dict[str, Any] = {"raw": raw, "requestParameters": req}
                    if items and isinstance(items, list):
                        first_item = items[0]
                        details["protocol"] = first_item.get("ipProtocol")
                        details["from_port"] = first_item.get("fromPort")
                        details["to_port"] = first_item.get("toPort")
                        ip_ranges = first_item.get("ipRanges", {})
                        if isinstance(ip_ranges, dict) and "items" in ip_ranges:
                            cidr_items = ip_ranges["items"]
                            if cidr_items and "cidrIp" in cidr_items[0]:
                                details["cidr_ipv4"] = cidr_items[0]["cidrIp"]
                        groups = first_item.get("groups", {})
                        if isinstance(groups, dict) and "items" in groups:
                            g_items = groups["items"]
                            if g_items and "groupId" in g_items[0]:
                                details["referenced_group_id"] = g_items[0]["groupId"]

                    try:
                        ts = datetime.fromisoformat(etime.replace("Z", "+00:00")) if etime else datetime.now(timezone.utc)
                    except Exception:
                        ts = datetime.now(timezone.utc)

                    events.append(
                        BaseTelemetryEvent(
                            event_id=eid,
                            timestamp=ts,
                            source=EventSource.CLOUDTRAIL,
                            action=ename,
                            actor=uarn,
                            resource_id=group_id,
                            source_ip=sip,
                            raw_record_id=raw.get("requestID"),
                            details=details,
                        )
                    )

            # 2. Query VPC Flow events
            if (source is None or source == EventSource.VPC_FLOW) and (not event_id or not events):
                if event_id:
                    cursor.execute(
                        "SELECT event_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, action, start, end "
                        "FROM flow_events WHERE event_id = ?",
                        (event_id,),
                    )
                else:
                    cursor.execute(
                        "SELECT event_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, action, start, end "
                        "FROM flow_events ORDER BY start DESC LIMIT ? OFFSET ?",
                        (limit, offset),
                    )
                for row in cursor.fetchall():
                    eid, eni, srcaddr, dstaddr, srcport, dstport, proto, act, start_ts, end_ts = row
                    try:
                        ts = datetime.fromtimestamp(int(start_ts), tz=timezone.utc)
                    except Exception:
                        ts = datetime.now(timezone.utc)

                    dest_port = int(dstport) if dstport and dstport.isdigit() else None

                    events.append(
                        BaseTelemetryEvent(
                            event_id=eid,
                            timestamp=ts,
                            source=EventSource.VPC_FLOW,
                            action=act,
                            resource_id=eni,
                            source_ip=srcaddr,
                            destination_ip=dstaddr,
                            destination_port=dest_port,
                            details={
                                "protocol": proto,
                                "srcport": srcport,
                                "start": start_ts,
                                "end": end_ts,
                            },
                        )
                    )
        finally:
            conn.close()

        return events

    def get_event_by_id(self, event_id: str) -> Optional[BaseTelemetryEvent]:
        """Fetch a single telemetry event by ID."""
        events = self.get_events(event_id=event_id, limit=1)
        return events[0] if events else None

    def get_events_by_ids(self, event_ids: List[str]) -> List[BaseTelemetryEvent]:
        """Fetch multiple telemetry events by their IDs."""
        found = []
        for eid in event_ids:
            evt = self.get_event_by_id(eid)
            if evt:
                found.append(evt)
        return found
