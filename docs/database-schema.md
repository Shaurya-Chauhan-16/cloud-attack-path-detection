# Telemetry Storage Schema

Owner: Member 1 (ingestion). Database: SQLite, default `data/local/events.db`
(same file `run_collect.py` writes). Schema version: `PRAGMA user_version = 1`.

Code: `src/ingestion/storage/{models,database,repository}.py`,
mapping: `src/ingestion/normalization/mapper.py`.

## Data flow

```
AWS  --run_collect.py-->  flow_events / trail_events   (RAW, system of record)
                                   |  EventRepository.ingest_all()
                                   v  mapper.normalize_*  (validate + map)
                              events                    (NORMALIZED = BaseTelemetryEvent)
                              ingest_errors             (records that failed validation)
```

Raw tables are never modified by ingestion. `events` can always be rebuilt from them.

## Table `flow_events` (raw, written by the collector)
`event_id TEXT PRIMARY KEY` (CloudWatch eventId) plus 21 TEXT columns in VPC flow-log v5
custom-format order: `version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport,
protocol, packets, bytes, start, end, action, log_status, vpc_id, subnet_id, instance_id,
tcp_flags, flow_direction, pkt_srcaddr, pkt_dstaddr`. Values are strings; `-` means "n/a".

## Table `trail_events` (raw, written by the collector)
| column | meaning |
|---|---|
| `event_id` PK | CloudTrail `eventID` |
| `event_time` | ISO-8601 UTC |
| `event_name`, `event_source` | API name / service |
| `user_arn` | `userIdentity.arn` (NULL for some service-initiated calls) |
| `source_ip` | `sourceIPAddress` (may be a service name, not an IP) |
| `raw` | full original record as JSON text |

## Table `events` (normalized)
One row per `BaseTelemetryEvent` (`src/shared/models.py`).

| column | type | notes |
|---|---|---|
| `event_id` | TEXT PK | stable id; first write wins on duplicates |
| `timestamp` | TEXT NOT NULL | UTC, fixed width `YYYY-MM-DDTHH:MM:SS.ffffffZ` (string order = time order) |
| `source` | TEXT NOT NULL | `cloudtrail` \| `vpc_flow` \| `config` \| `system` |
| `action` | TEXT NOT NULL | `ACCEPT`/`REJECT` or CloudTrail `eventName` |
| `actor` | TEXT | IAM ARN (`invokedBy` for service callers); always NULL for flows |
| `resource_id` | TEXT | flow: ENI id. CloudTrail SG events: `sg-…`; others: first resource ARN |
| `source_ip`, `destination_ip` | TEXT | validated IPv4/IPv6; NULL if absent/not an IP |
| `destination_port` | INTEGER | 0-65535 or NULL |
| `raw_record_id` | TEXT | upstream id (same as `event_id` today) |
| `details_json` | TEXT | JSON object, see below |
| `extra_json` | TEXT | any non-contract fields (the model allows extras) |
| `ingested_at` | TEXT | when the row was stored |

Indexes: `timestamp`; `(source, timestamp)`; `resource_id`; `action`.

### `details` for `vpc_flow`
`protocol` (`tcp`/`udp`/`icmp`, unknown numbers kept as the number string), `source_port`,
`packets`, `bytes`, `end`, `tcp_flags` (ints); `flow_direction`, `vpc_id`, `subnet_id`,
`instance_id`, `account_id`, `pkt_srcaddr`, `pkt_dstaddr`, `version`; `log_status`.
Fields that are `-` are omitted.

### `details` for `cloudtrail`
`event_source`, `aws_region`, `event_type`, `request_id`, `read_only`,
`success` (bool), `errorCode` / `errorMessage` (only when present, camelCase because
`cross_layer.py` reads those keys), `source_ip_raw` (only when `sourceIPAddress` was not an IP).
For `Authorize/Revoke SecurityGroup{Ingress,Egress}` additionally:
`direction`, `security_group_id`, and `ipPermissions`, a **plain list** (CloudTrail's
`{"items": [...]}` wrappers removed):
```json
{"ipProtocol": "tcp", "fromPort": 8080, "toPort": 8080,
 "ipRanges":   [{"cidrIp": "10.20.1.0/24"}],
 "ipv6Ranges": [],
 "groups":     [{"groupId": "sg-source", "userId": "111122223333"}]}
```
`groups` carries security-group-to-security-group references unchanged.

## Table `ingest_errors`
`id` PK AUTOINCREMENT, `kind` (`flow`/`cloudtrail`), `record_id`, `error`, `created_at`;
`UNIQUE(kind, record_id, error)` so re-ingesting does not duplicate rows. Records without an
id get `anon-<hash>`.

## Normalization rules (what is stored, skipped, rejected)
| input | result |
|---|---|
| valid flow / trail record | stored |
| flow with `log_status` `NODATA`/`SKIPDATA` | **skipped** (counted, not an error, not stored) |
| flow `dstport` = `-` | stored with `destination_port = NULL` |
| flow missing/`-` `event_id`, `srcaddr`, `dstaddr`, `start`, `action` | **malformed** |
| bad IP, non-integer or out-of-range port, bad epoch, action not ACCEPT/REJECT | **malformed** |
| trail missing `eventID`/`eventTime`/`eventName` (checked in `raw`, then row columns) | **malformed** |
| trail `raw` not valid JSON / not an object, unparseable `eventTime` | **malformed** |
| trail no `userIdentity` / service-name `sourceIPAddress` | stored (`actor`/`source_ip` NULL) |
| anything that is not a mapping | **malformed** |

Flow timestamp = flow `start` (epoch seconds, UTC). Trail timestamps with offsets are converted to UTC.

## Repository API (`EventRepository`)
`save_event(s)`, `get_event`, `get_events(source, action, resource_id, start, end, limit)`,
`count_events`, `ingest_raw_flow_events`, `ingest_raw_trail_events`, `ingest_all`,
`get_errors`, `record_error`. Time filters are `start <= t < end`. Results are ordered by
`(timestamp, event_id)`. `ingest_all()` returns `IngestSummary(read, stored, duplicates, skipped, malformed)`
where `read = stored + duplicates + skipped + malformed`.

```python
from src.ingestion.storage.database import connect
from src.ingestion.storage.repository import EventRepository
repo = EventRepository(connect())          # data/local/events.db
print(repo.ingest_all())
events = repo.get_events(source="cloudtrail", action="AuthorizeSecurityGroupIngress")
```

## Configuration snapshots
`src/ingestion/snapshots/aws_config.py::load_configuration_history(path)` builds the shared
`ConfigurationHistory` (`attachments`, `eni_to_ip_map`) from a collector snapshot. A snapshot is
point-in-time: attachment start = ENI `Attachment.AttachTime` if present, else snapshot time.

## Running the tests
```bash
pip install -e ".[dev]"          # or: pip install pydantic networkx pytest
python -m pytest                              # everything
python -m pytest tests/unit/test_flow_normalization.py tests/unit/test_trail_normalization.py \
                 tests/unit/test_storage_repository.py tests/unit/test_aws_config.py -v
python -m pytest tests/integration/test_ingestion_fixtures.py   # real sanitized lab data
```
Tests use in-memory SQLite and `fixtures/sanitized/`; no AWS access needed.

## Known limitations
* Flow records are not deduplicated across ENIs (one packet crossing two ENIs = two events, as AWS logs it).
* Snapshots give state-at-a-time, not full attachment history; flows before the first snapshot cannot be attributed.
* `event_id` conflicts keep the first stored row; no update path.
* Only flow log v5 / 21-field format is supported by the raw table.
