"""Integration test for unified analyze() main interface."""
from datetime import datetime, timezone, timedelta
import pytest

from src.shared.enums import EventSource, PolicyDecision
from src.shared.models import (
    ApprovedCommunicationPolicy,
    BaseTelemetryEvent,
    ConfigurationHistory,
    PolicyRule,
    SecurityGroupAttachment,
)
from src.detection import analyze


def test_main_analyze_interface():
    t0 = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)

    policy = ApprovedCommunicationPolicy(
        policy_id="prod-pol",
        rules=[
            PolicyRule(
                rule_id="RULE-ALLOW-INTERNAL",
                source="10.0.0.0/8",
                destination="10.0.1.10",
                protocol="tcp",
                destination_port=443,
            )
        ],
    )

    config = ConfigurationHistory(
        attachments=[
            SecurityGroupAttachment(
                resource_id="eni-web",
                security_group_id="sg-web",
                attached_at=t0 - timedelta(days=1),
            )
        ],
        eni_to_ip_map={"eni-web": ["10.0.1.10"]},
    )

    events = [
        BaseTelemetryEvent(
            event_id="ct-1",
            timestamp=t0,
            source=EventSource.CLOUDTRAIL,
            action="AuthorizeSecurityGroupIngress",
            resource_id="sg-web",
            details={"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ipv4": "0.0.0.0/0"},
        ),
        BaseTelemetryEvent(
            event_id="fl-1",
            timestamp=t0 + timedelta(seconds=30),
            source=EventSource.VPC_FLOW,
            action="ACCEPT",
            resource_id="eni-web",
            source_ip="203.0.113.5",
            destination_ip="10.0.1.10",
            destination_port=22,
            details={"protocol": "tcp"},
        ),
    ]

    result = analyze(events=events, configuration_history=config, policy=policy)

    # Validate output contract
    assert len(result.alerts) > 0
    assert len(result.nodes) > 0
    assert len(result.edges) > 0
    assert len(result.scored_alerts) == len(result.alerts)

    # Ensure JSON-serializable
    dumped = result.model_dump(mode="json")
    assert "alerts" in dumped
    assert "nodes" in dumped
    assert "edges" in dumped
    assert "candidate_paths" in dumped
    assert "scored_alerts" in dumped
