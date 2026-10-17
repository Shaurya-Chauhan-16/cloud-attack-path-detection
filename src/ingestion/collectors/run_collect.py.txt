"""Collector: python -m src.ingestion.collectors.run_collect [snapshot|flow|trail|all]

Reads settings from data/local/lab_config.json (gitignored):
{
  "profile": "attackpath-collector",
  "region": "ap-south-1",
  "log_group": "/attackpath/vpc-flow",
  "trail_bucket": "aws-cloudtrail-logs-XXXX",
  "vpc_id": "vpc-01016869033a18a15"
}
Writes to data/local/events.db (SQLite). Re-running adds only new records.
"""
import gzip
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3

CONFIG = Path("data/local/lab_config.json")
DB = Path("data/local/events.db")
SNAP_DIR = Path("data/local/snapshots")

FLOW_FIELDS = [
    "version", "account_id", "interface_id", "srcaddr", "dstaddr", "srcport",
    "dstport", "protocol", "packets", "bytes", "start", "end", "action",
    "log_status", "vpc_id", "subnet_id", "instance_id", "tcp_flags",
    "flow_direction", "pkt_srcaddr", "pkt_dstaddr",
]  # 21 fields, same order as the flow log custom format


def load_config():
    if not CONFIG.exists():
        sys.exit(f"Missing {CONFIG}. Create it first (see top of this file).")
    return json.loads(CONFIG.read_text())


def open_db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB)
    cols = ", ".join(f"{f} TEXT" for f in FLOW_FIELDS)
    con.execute(f"CREATE TABLE IF NOT EXISTS flow_events (event_id TEXT PRIMARY KEY, {cols})")
    con.execute(
        "CREATE TABLE IF NOT EXISTS trail_events ("
        "event_id TEXT PRIMARY KEY, event_time TEXT, event_name TEXT, "
        "event_source TEXT, user_arn TEXT, source_ip TEXT, raw TEXT)"
    )
    return con


def snapshot(cfg, session):
    ec2 = session.client("ec2")
    flt = [{"Name": "vpc-id", "Values": [cfg["vpc_id"]]}] if cfg.get("vpc_id") else []
    snap = {
        "taken_at": datetime.now(timezone.utc).isoformat(),
        "security_groups": ec2.describe_security_groups(Filters=flt)["SecurityGroups"],
        "instances": [
            i for r in ec2.describe_instances(Filters=flt)["Reservations"] for i in r["Instances"]
        ],
        "subnets": ec2.describe_subnets(Filters=flt)["Subnets"],
        "route_tables": ec2.describe_route_tables(Filters=flt)["RouteTables"],
    }
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    out = SNAP_DIR / f"snapshot_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
    out.write_text(json.dumps(snap, indent=2, default=str))
    print(f"snapshot: saved {out} "
          f"({len(snap['security_groups'])} security groups, {len(snap['instances'])} instances)")


def collect_flow(cfg, session, con):
    logs = session.client("logs")
    new = unparsed = 0
    kwargs = {"logGroupName": cfg["log_group"]}
    while True:
        resp = logs.filter_log_events(**kwargs)
        for ev in resp["events"]:
            parts = ev["message"].split()
            if len(parts) != len(FLOW_FIELDS):
                unparsed += 1
                continue
            cur = con.execute(
                f"INSERT OR IGNORE INTO flow_events VALUES (?{',?' * len(FLOW_FIELDS)})",
                [ev["eventId"], *parts],
            )
            new += cur.rowcount
        token = resp.get("nextToken")
        if not token:
            break
        kwargs["nextToken"] = token
    con.commit()
    print(f"flow logs: new={new} unparsed={unparsed}")


def collect_trail(cfg, session, con):
    s3 = session.client("s3")
    bucket = cfg["trail_bucket"]
    new = unparsed = files = 0
    pager = s3.get_paginator("list_objects_v2")
    for page in pager.paginate(Bucket=bucket, Prefix="AWSLogs/"):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if "/CloudTrail/" not in key or not key.endswith(".json.gz"):
                continue
            files += 1
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            try:
                records = json.loads(gzip.decompress(body))["Records"]
            except Exception:
                unparsed += 1
                continue
            for r in records:
                cur = con.execute(
                    "INSERT OR IGNORE INTO trail_events VALUES (?,?,?,?,?,?,?)",
                    (
                        r.get("eventID"), r.get("eventTime"), r.get("eventName"),
                        r.get("eventSource"),
                        (r.get("userIdentity") or {}).get("arn"),
                        r.get("sourceIPAddress"), json.dumps(r),
                    ),
                )
                new += cur.rowcount
    con.commit()
    print(f"cloudtrail: files={files} new={new} unparsed_files={unparsed}")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode not in {"snapshot", "flow", "trail", "all"}:
        sys.exit("Usage: run_collect [snapshot|flow|trail|all]")
    cfg = load_config()
    session = boto3.Session(profile_name=cfg["profile"], region_name=cfg["region"])
    if mode == "snapshot":
        snapshot(cfg, session)
        return
    con = open_db()
    if mode in {"flow", "all"}:
        collect_flow(cfg, session, con)
    if mode in {"trail", "all"}:
        collect_trail(cfg, session, con)


if __name__ == "__main__":
    main()
