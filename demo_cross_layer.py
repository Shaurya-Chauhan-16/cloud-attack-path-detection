"""Demo script exercising CrossLayerCorrelator with synthetic events."""
import json
from datetime import datetime, timezone, timedelta
from src.shared.enums import EventSource
from src.shared.models import (
    BaseTelemetryEvent,
    ConfigurationHistory,
    SecurityGroupAttachment,
)
from src.detection.correlation.cross_layer import CrossLayerCorrelator

def run_demo():
    t0 = datetime.now(timezone.utc)
    config_history = ConfigurationHistory(
        attachments=[
            SecurityGroupAttachment(
                resource_id="eni-09a8b7c6d5e4",
                security_group_id="sg-bastion-ssh",
                attached_at=t0 - timedelta(hours=2),
                detached_at=None,
            )
        ],
        eni_to_ip_map={"eni-09a8b7c6d5e4": ["10.0.0.15"]},
    )

    ct_event = BaseTelemetryEvent(
        event_id="ct-evt-9912",
        timestamp=t0,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        actor="arn:aws:iam::123456789012:user/admin-jdoe",
        resource_id="sg-bastion-ssh",
        details={
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr_ipv4": "203.0.113.50/32",
        },
    )

    flow_event = BaseTelemetryEvent(
        event_id="flow-evt-4410",
        timestamp=t0 + timedelta(seconds=72),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-09a8b7c6d5e4",
        source_ip="203.0.113.50",
        destination_ip="10.0.0.15",
        destination_port=22,
        details={"protocol": "tcp"},
    )

    correlator = CrossLayerCorrelator(correlation_window_seconds=300)
    alerts = correlator.correlate([ct_event, flow_event], config_history)

    print(json.dumps([a.model_dump(mode="json") for a in alerts], indent=2))

if __name__ == "__main__":
    run_demo()
