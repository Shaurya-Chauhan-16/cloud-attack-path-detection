"""Integration tests for PriorityScorer with Baseline Detector and CrossLayerCorrelator."""
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
from src.detection.scoring.priority import PriorityScorer


@pytest.fixture
def multi_tier_environment():
    t0 = datetime(2026, 10, 15, 16, 0, 0, tzinfo=timezone.utc)

    policy = ApprovedCommunicationPolicy(
        policy_id="zero-trust-prod",
        rules=[
            PolicyRule(
                rule_id="RULE-ALLOW-INTERNAL-WEB",
                source="10.0.1.0/24",
                destination="10.0.2.0/24",
                protocol="tcp",
                destination_port=443,
                action=PolicyDecision.APPROVED,
            ),
            PolicyRule(
                rule_id="RULE-DENY-SSH-DIRECT",
                source="*",
                destination="10.0.3.50",
                protocol="tcp",
                destination_port=22,
                action=PolicyDecision.UNAPPROVED,
            ),
        ],
    )

    config = ConfigurationHistory(
        attachments=[
            SecurityGroupAttachment(
                resource_id="eni-prod-db",
                security_group_id="sg-database",
                attached_at=t0 - timedelta(days=5),
            )
        ],
        eni_to_ip_map={"eni-prod-db": ["10.0.3.50"]},
    )

    return {"t0": t0, "policy": policy, "config": config}


def test_end_to_end_detection_and_scoring(multi_tier_environment):
    """Verifies that:
    1. Baseline detector produces a baseline alert.
    2. Cross-layer correlator produces a cross-layer alert.
    3. Scorer scores both alerts deterministically with proper comparative prioritization.
    """
    env = multi_tier_environment
    t0 = env["t0"]
    policy = env["policy"]
    config = env["config"]

    # 1. CT Event: Ingress authorized on sg-database
    ct_event = BaseTelemetryEvent(
        event_id="ct-db-open",
        timestamp=t0,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        actor="arn:aws:iam::123456789012:user/admin-alice",
        resource_id="sg-database",
        details={"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ipv4": "0.0.0.0/0"},
    )

    # 2. VPC Flow: Accepted flow matching the newly authorized rule
    flow_event = BaseTelemetryEvent(
        event_id="flow-db-ssh",
        timestamp=t0 + timedelta(seconds=40),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-prod-db",
        source_ip="198.51.100.99",
        destination_ip="10.0.3.50",
        destination_port=22,
        details={"protocol": "tcp"},
    )

    events = [ct_event, flow_event]

    # Run detectors
    baseline_detector = NetworkBaselineDetector(policy)
    baseline_alerts = baseline_detector.detect(events)
    assert len(baseline_alerts) == 1

    correlator = CrossLayerCorrelator()
    cross_layer_alerts = correlator.correlate(events, config)
    assert len(cross_layer_alerts) == 1

    # Score alerts
    scorer = PriorityScorer()
    scored_baseline = scorer.score(
        baseline_alerts[0], context={"resource_criticality": "high"}
    )
    scored_cross_layer = scorer.score(
        cross_layer_alerts[0], context={"resource_criticality": "critical"}
    )

    # Verify prioritization and factors
    assert scored_cross_layer.score_result.final_score > scored_baseline.score_result.final_score
    assert scored_cross_layer.score_result.priority_level in (PriorityLevel.HIGH, PriorityLevel.CRITICAL)
    assert "config_correlation" in scored_cross_layer.score_result.factor_contributions
    assert scored_cross_layer.score_result.factor_contributions["config_correlation"] == 20.0
