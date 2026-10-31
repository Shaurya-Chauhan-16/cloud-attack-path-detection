"""Event-Driven Real-Time Telemetry Stream Consumer.

This worker implements an event-driven, decoupled streaming pipeline suitable
for research evaluation and production SOC environments:
1. Long-polls Amazon SQS for S3 ObjectCreated events (CloudTrail log flushes).
2. Streaming tail on CloudWatch VPC Flow Logs (filtering new events with token cursor).
3. Automatically writes new events into SQLite (data/local/events.db) with first-write-wins semantics.
4. Seamlessly feeds the real-time detection graph and frontend SOC dashboard.
"""
import gzip
import json
import logging
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [StreamWorker] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("stream_worker")

CONFIG_PATH = Path("data/local/lab_config.json")
DB_PATH = Path("data/local/events.db")
CURSOR_PATH = Path("data/local/flow_cursor.json")

FLOW_FIELDS = [
    "version", "account_id", "interface_id", "srcaddr", "dstaddr", "srcport",
    "dstport", "protocol", "packets", "bytes", "start", "end", "action",
    "log_status", "vpc_id", "subnet_id", "instance_id", "tcp_flags",
    "flow_direction", "pkt_srcaddr", "pkt_dstaddr",
]


def load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        sys.exit(f"Configuration file not found: {CONFIG_PATH}")
    return json.loads(CONFIG_PATH.read_text())


def get_db_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    cols = ", ".join(f"{f} TEXT" for f in FLOW_FIELDS)
    con.execute(f"CREATE TABLE IF NOT EXISTS flow_events (event_id TEXT PRIMARY KEY, {cols})")
    con.execute(
        "CREATE TABLE IF NOT EXISTS trail_events ("
        "event_id TEXT PRIMARY KEY, event_time TEXT, event_name TEXT, "
        "event_source TEXT, user_arn TEXT, source_ip TEXT, raw TEXT)"
    )
    return con


class TelemetryStreamWorker:
    def __init__(self, cfg: Dict[str, Any], session: Optional[boto3.Session] = None):
        self.cfg = cfg
        self.session = session
        self._init_aws_clients()
        self.queue_url = cfg.get("sqs_queue_url")
        self.log_group = cfg.get("log_group")
        self.cursor_path = CURSOR_PATH
        self.last_flow_time = self._load_flow_cursor()
        self.running = True

    def _init_aws_clients(self) -> None:
        """Initialize or re-initialize boto3 clients safely."""
        try:
            if not self.session:
                profile = self.cfg.get("profile")
                region = self.cfg.get("region", "ap-south-1")
                self.session = boto3.Session(
                    profile_name=profile if profile else None,
                    region_name=region,
                )
            self.sqs = self.session.client("sqs")
            self.s3 = self.session.client("s3")
            self.logs = self.session.client("logs")
        except Exception as e:
            logger.warning(f"Initial AWS client creation notice: {e}")

    def _load_flow_cursor(self) -> int:
        """Load persistent cursor timestamp in milliseconds, defaulting to 5 minutes ago."""
        if self.cursor_path.exists():
            try:
                data = json.loads(self.cursor_path.read_text())
                saved_time = data.get("last_flow_time")
                if saved_time and isinstance(saved_time, (int, float)):
                    return int(saved_time)
            except Exception as e:
                logger.warning(f"Could not read flow cursor from {self.cursor_path}: {e}")
        # Default: 5 minutes ago in ms
        return int(time.time() - 300) * 1000

    def _save_flow_cursor(self, cursor_time_ms: int) -> None:
        """Persist flow cursor timestamp to data/local."""
        try:
            self.cursor_path.parent.mkdir(parents=True, exist_ok=True)
            self.cursor_path.write_text(json.dumps({"last_flow_time": cursor_time_ms}))
        except Exception as e:
            logger.warning(f"Failed to save flow cursor to {self.cursor_path}: {e}")

    def process_s3_event_record(self, s3_info: Dict[str, Any], con: sqlite3.Connection) -> int:
        bucket = s3_info.get("bucket", {}).get("name")
        key = s3_info.get("object", {}).get("key")
        if not bucket or not key or not key.endswith(".json.gz"):
            return 0

        logger.info(f"Received CloudTrail notification for object: s3://{bucket}/{key}")
        try:
            resp = self.s3.get_object(Bucket=bucket, Key=key)
            decompressed = gzip.decompress(resp["Body"].read())
            records = json.loads(decompressed).get("Records", [])
            new_events = 0
            for r in records:
                cur = con.execute(
                    "INSERT OR IGNORE INTO trail_events VALUES (?,?,?,?,?,?,?)",
                    (
                        r.get("eventID"),
                        r.get("eventTime"),
                        r.get("eventName"),
                        r.get("eventSource"),
                        (r.get("userIdentity") or {}).get("arn"),
                        r.get("sourceIPAddress"),
                        json.dumps(r),
                    ),
                )
                new_events += cur.rowcount
            con.commit()
            logger.info(f"Successfully processed s3://{bucket}/{key}: {new_events} new CloudTrail events stored")
            return new_events
        except Exception as e:
            logger.error(f"Error processing s3://{bucket}/{key}: {e}")
            raise  # Do not swallow exception so caller knows processing failed

    def poll_sqs_notifications(self, con: sqlite3.Connection) -> int:
        if not self.queue_url:
            return 0

        resp = self.sqs.receive_message(
            QueueUrl=self.queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,  # Long-polling
            AttributeNames=["All"],
        )
        messages = resp.get("Messages", [])
        if not messages:
            return 0

        total_new = 0
        for msg in messages:
            receipt = msg["ReceiptHandle"]
            try:
                body = json.loads(msg["Body"])
            except Exception as ex:
                logger.warning(f"Error parsing SQS body as JSON (poison pill discarded): {ex}")
                # Delete malformed non-JSON message to avoid infinite poison loops
                self.sqs.delete_message(QueueUrl=self.queue_url, ReceiptHandle=receipt)
                continue

            records = body.get("Records")
            # If message has no Records (e.g. s3:TestEvent or non-record notification), acknowledge/delete it
            if not records:
                logger.info(f"Received non-record SQS notification (e.g. TestEvent), acknowledging.")
                self.sqs.delete_message(QueueUrl=self.queue_url, ReceiptHandle=receipt)
                continue

            # Process all s3 records in message
            success = True
            msg_new_events = 0
            for rec in records:
                if "s3" in rec:
                    try:
                        msg_new_events += self.process_s3_event_record(rec["s3"], con)
                    except Exception:
                        success = False
                        break

            # ONLY delete message if all records were processed successfully
            if success:
                total_new += msg_new_events
                self.sqs.delete_message(QueueUrl=self.queue_url, ReceiptHandle=receipt)
            else:
                logger.warning(f"Failed to process records for SQS message {msg.get('MessageId')}. Leaving in queue for retry.")

        return total_new

    def poll_vpc_flow_logs(self, con: sqlite3.Connection) -> int:
        if not self.log_group:
            return 0

        now_ms = int(time.time() * 1000)
        # Apply 5-minute overlap window (300,000 ms)
        overlap_ms = 300 * 1000
        start_query_ms = max(0, self.last_flow_time - overlap_ms)

        next_token: Optional[str] = None
        total_new_events = 0

        while True:
            kwargs: Dict[str, Any] = {
                "logGroupName": self.log_group,
                "startTime": start_query_ms,
                "endTime": now_ms,
                "limit": 1000,
            }
            if next_token:
                kwargs["nextToken"] = next_token

            resp = self.logs.filter_log_events(**kwargs)
            events = resp.get("events", [])
            for ev in events:
                parts = ev.get("message", "").split()
                if len(parts) == len(FLOW_FIELDS):
                    cur = con.execute(
                        f"INSERT OR IGNORE INTO flow_events VALUES (?{',?' * len(FLOW_FIELDS)})",
                        [ev["eventId"], *parts],
                    )
                    total_new_events += cur.rowcount
            con.commit()

            next_token = resp.get("nextToken")
            if not next_token:
                break

        # Move cursor forward to now_ms and persist it
        self.last_flow_time = now_ms
        self._save_flow_cursor(now_ms)

        if total_new_events > 0:
            logger.info(f"Streamed {total_new_events} new VPC Flow log events into database")
        return total_new_events

    def _is_credential_error(self, err: Exception) -> bool:
        """Check if exception represents an expired or missing AWS credential."""
        if isinstance(err, (NoCredentialsError, ProfileNotFound)):
            return True
        if isinstance(err, ClientError):
            code = err.response.get("Error", {}).get("Code", "")
            if code in ("ExpiredToken", "ExpiredTokenException", "RequestExpired", "AccessDenied"):
                return True
        err_msg = str(err).lower()
        if "security token included in the request is expired" in err_msg or "the security token included in the request is invalid" in err_msg:
            return True
        return False

    def run(self):
        logger.info("Starting Real-Time AWS Telemetry Streaming Worker...")
        logger.info(f"Target Database: {DB_PATH.resolve()}")
        logger.info(f"SQS Queue: {self.queue_url}")
        logger.info(f"CloudWatch Log Group: {self.log_group}")
        logger.info(f"Flow Cursor File: {self.cursor_path.resolve()}")

        con = get_db_connection()
        try:
            while self.running:
                try:
                    # 1. Check for real-time SQS CloudTrail push notifications
                    self.poll_sqs_notifications(con)

                    # 2. Check for VPC flow log delta stream
                    self.poll_vpc_flow_logs(con)

                    # Short pause before next cycle
                    time.sleep(2)
                except Exception as err:
                    if self._is_credential_error(err):
                        logger.error(f"AWS Credential error encountered ({err}). Profile or token may need refresh. Backing off for 30s...")
                        time.sleep(30)
                    else:
                        logger.error(f"Unexpected streaming worker error: {err}")
                        time.sleep(5)
        except KeyboardInterrupt:
            logger.info("Streaming worker stopped by user.")
        finally:
            con.close()


def main():
    cfg = load_config()
    worker = TelemetryStreamWorker(cfg)
    worker.run()


if __name__ == "__main__":
    main()
