"""Diagnose why the dashboard shows no alerts. Run: python debug_alerts.py"""
import inspect, time
from collections import Counter
from src.ingestion.storage.telemetry_repository import TelemetryRepository
from src.api.services import alert_service
from src.detection import analyze
from src.shared.enums import EventSource

print("1) Fixed files in place?")
print("   telemetry_repository uses AttachTime:", "AttachTime" in inspect.getsource(TelemetryRepository))
print("   alert_service limit 100000:", "limit=100000" in inspect.getsource(alert_service))

r = TelemetryRepository()
print("\n2) Paths:", r.db_path.resolve(), "| exists:", r.db_path.exists())
print("   snapshots:", r.snapshot_path.resolve(), "| files:", len(list(r.snapshot_path.glob('*.json'))) if r.snapshot_path.exists() else "FOLDER MISSING (run snapshot)")

cfg = r.load_configuration_history()
print("\n3) Config attachments:", len(cfg.attachments))
for a in cfg.attachments:
    print("  ", a.resource_id, "->", a.security_group_id, "from", a.attached_at)

ev = r.get_events(limit=100000)
print("\n4) Events loaded:", Counter(e.source.value for e in ev))
sg = [e for e in ev if e.action in ("AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress")]
print("   Security-group change events:", len(sg))
for e in sorted(sg, key=lambda x: x.timestamp):
    print("  ", e.timestamp, e.action, "sg:", e.resource_id, "port:", e.details.get("from_port"),
          "cidr:", e.details.get("cidr_ipv4"), "ref-sg:", e.details.get("referenced_group_id"))
flows = [e for e in ev if e.source == EventSource.VPC_FLOW and e.destination_port == 8080]
print("   Flows to port 8080:", len(flows), Counter(e.action for e in flows))
if flows:
    print("   8080 flows between", min(e.timestamp for e in flows), "and", max(e.timestamp for e in flows))
    print("   ENIs seen:", Counter(e.resource_id for e in flows))

t = time.time()
res = analyze(events=ev, configuration_history=cfg)
print("\n5) Alerts found:", len(res.alerts), "(%.1fs)" % (time.time() - t))
for a in res.alerts:
    print("  ", a.rule_id, a.priority.value, "-", a.explanation[:130])
