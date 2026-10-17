"""Integration tests comparing Baseline Detector and Cross-Layer Correlator."""
from datetime import datetime, timezone, timedelta
import pytest

from src.shared.enums import EventSource, PolicyDecision, PriorityLevel
from src.shared.models import (
    ApprovedCommunicationPolicy,
    BaseTelemetryEvent,
    ConfigurationHistory,
    PolicyRule,
    SecurityGroupAttachment,
)
from src.detection.policy.engine import NetworkBaselineDetector
from src.detection.correlation.cross_layer import CrossLayerCorrelator


@pytest.fixture
def enterprise_environment():
    """Setup simulated corporate AWS cloud infrastructure telemetry and policy."""
    t0 = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)

    policy = ApprovedCommunicationPolicy(
        policy_id="corp-zero-trust-v1",
        rules=[
            # Only HTTPS from corporate subnet to web cluster is approved
            PolicyRule(
                rule_id="RULE-CORP-HTTPS",
                description="Approved HTTPS traffic to Web cluster",
                source="192.168.0.0/16",
                destination="10.0.1.0/24",
                protocol="tcp",
                destination_port=443,
                action=PolicyDecision.APPROVED,
            ),
        ],
    )

    config_history = ConfigurationHistory(
        attachments=[
            SecurityGroupAttachment(
                resource_id="eni-web-frontend",
                security_group_id="sg-web-prod",
                attached_at=t0 - timedelta(days=30),
                detached_at=None,
            ),
            SecurityGroupAttachment(
                resource_id="eni-db-backend",
                security_group_id="sg-db-prod",
                attached_at=t0 - timedelta(days=30),
                detached_at=None,
            ),
        ],
        eni_to_ip_map={
            "eni-web-frontend": ["10.0.1.10"],
            "eni-db-backend": ["10.0.2.50"],
        },
    )

    return {"t0": t0, "policy": policy, "config_history": config_history}


def test_cross_layer_vs_baseline_comparison(enterprise_environment):
    """Scenario:
    1. Legitimate approved traffic occurs (HTTPS to Web).
    2. An administrative change opens port 3389 (RDP) on sg-web-prod from an external IP.
    3. An accepted RDP flow occurs 45 seconds later.
    4. Unrelated blocked scan attempt occurs.

    Expectation:
    - NetworkBaselineDetector flags the unapproved RDP accepted flow (NET-BL-001).
    - CrossLayerCorrelator specifically correlates the CloudTrail event to the RDP flow (CORR-CROSS-001).
    - Neither flags the approved HTTPS flow or rejected scan.
    """
    env = enterprise_environment
    t0 = env["t0"]
    policy = env["policy"]
    config_history = env["config_history"]

    # 1. Approved legitimate HTTPS traffic
    legit_flow = BaseTelemetryEvent(
        event_id="flow-https-legit",
        timestamp=t0 + timedelta(minutes=1),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-web-frontend",
        source_ip="192.168.1.50",
        destination_ip="10.0.1.10",
        destination_port=443,
        details={"protocol": "tcp"},
    )

    # 2. Administrative change: AuthorizeSecurityGroupIngress on sg-web-prod opening port 3389
    ct_ingress = BaseTelemetryEvent(
        event_id="ct-auth-rdp",
        timestamp=t0 + timedelta(minutes=5),
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        actor="arn:aws:iam::123456789012:user/devops-engineer",
        resource_id="sg-web-prod",
        details={
            "protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_ipv4": "203.0.113.0/24",
        },
    )

    # 3. Accepted RDP flow matching the authorized rule 45s later
    rdp_flow = BaseTelemetryEvent(
        event_id="flow-rdp-accepted",
        timestamp=t0 + timedelta(minutes=5, seconds=45),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-web-frontend",
        source_ip="203.0.113.88",
        destination_ip="10.0.1.10",
        destination_port=3389,
        details={"protocol": "tcp"},
    )

    # 4. Rejected scan attempt
    scan_flow = BaseTelemetryEvent(
        event_id="flow-scan-rejected",
        timestamp=t0 + timedelta(minutes=6),
        source=EventSource.VPC_FLOW,
        action="REJECT",
        resource_id="eni-db-backend",
        source_ip="198.51.100.99",
        destination_ip="10.0.2.50",
        destination_port=22,
        details={"protocol": "tcp"},
    )

    all_telemetry = [legit_flow, ct_ingress, rdp_flow, scan_flow]

    # Run Baseline Detector
    baseline_detector = NetworkBaselineDetector(policy)
    baseline_alerts = baseline_detector.detect(all_telemetry)

    # Verify Baseline behavior
    assert len(baseline_alerts) == 1
    assert baseline_alerts[0].rule_id == "NET-BL-001"
    assert "flow-rdp-accepted" in baseline_alerts[0].evidence_event_ids

    # Run Cross-Layer Correlator
    correlator = CrossLayerCorrelator(correlation_window_seconds=300)
    cross_layer_alerts = correlator.correlate(all_telemetry, config_history)

    # Verify Cross-Layer behavior
    assert len(cross_layer_alerts) == 1
    cl_alert = cross_layer_alerts[0]
    assert cl_alert.rule_id == "CORR-CROSS-001"
    assert cl_alert.priority == PriorityLevel.HIGH
    assert "ct-auth-rdp" in cl_alert.evidence_event_ids
    assert "flow-rdp-accepted" in cl_alert.evidence_event_ids
    assert "eni-web-frontend" in cl_alert.related_resource_ids
    assert cl_alert.details["admin_actor"] == "arn:aws:iam::123456789012:user/devops-engineer"
    assert "NOT confirm application compromise" in cl_alert.explanation
