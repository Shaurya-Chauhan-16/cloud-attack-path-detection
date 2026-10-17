"""Unit tests for PolicyEngine and NetworkBaselineDetector (Phase 1)."""
from datetime import datetime, timezone, timedelta
import pytest

from src.shared.enums import EventSource, FlowAction, PolicyDecision, PriorityLevel
from src.shared.models import (
    ApprovedCommunicationPolicy,
    BaseTelemetryEvent,
    MaintenanceException,
    PolicyRule,
)
from src.detection.policy.engine import NetworkBaselineDetector, PolicyEngine


@pytest.fixture
def sample_policy():
    """Standard approved communication policy fixture."""
    now = datetime.now(timezone.utc)
    return ApprovedCommunicationPolicy(
        policy_id="test-policy-prod",
        rules=[
            PolicyRule(
                rule_id="RULE-WEB-HTTPS",
                description="Allow HTTPS to web servers",
                source="*",
                destination="10.0.1.0/24",
                protocol="tcp",
                destination_port=443,
                action=PolicyDecision.APPROVED,
            ),
            PolicyRule(
                rule_id="RULE-DB-ACCESS",
                description="Allow App tier to PostgreSQL database",
                source="10.0.1.0/24",
                destination="10.0.2.100",
                protocol="tcp",
                destination_port=5432,
                action=PolicyDecision.APPROVED,
            ),
            PolicyRule(
                rule_id="RULE-DENY-SSH-INTERNET",
                description="Explicitly block SSH from anywhere to all internal hosts",
                source="*",
                destination="10.0.0.0/16",
                protocol="tcp",
                destination_port=22,
                action=PolicyDecision.UNAPPROVED,
            ),
        ],
        maintenance_exceptions=[
            MaintenanceException(
                exception_id="MAINT-2026-PATCH",
                description="Bastion SSH access during maintenance window",
                start_time=now - timedelta(hours=1),
                end_time=now + timedelta(hours=1),
                source="198.51.100.5",
                destination="10.0.0.5",
                protocol="tcp",
                destination_port=22,
            )
        ],
    )


def test_approved_flow_allowed(sample_policy):
    """Test that accepted traffic conforming to policy is marked APPROVED and produces no alert."""
    detector = NetworkBaselineDetector(sample_policy)
    event = BaseTelemetryEvent(
        event_id="evt-001",
        timestamp=datetime.now(timezone.utc),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-001",
        source_ip="192.168.1.50",
        destination_ip="10.0.1.10",
        destination_port=443,
        details={"protocol": "tcp"},
    )

    alerts = detector.detect([event])
    assert len(alerts) == 0

    engine = PolicyEngine(sample_policy)
    decision, rule_id, _ = engine.evaluate_flow(event)
    assert decision == PolicyDecision.APPROVED
    assert rule_id == "RULE-WEB-HTTPS"


def test_unapproved_accepted_flow_generates_alert(sample_policy):
    """Test that accepted traffic violating policy triggers an alert with evidence preserved."""
    detector = NetworkBaselineDetector(sample_policy)
    # Direct database access from untrusted external IP
    event = BaseTelemetryEvent(
        event_id="evt-002",
        timestamp=datetime.now(timezone.utc),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-db-001",
        source_ip="203.0.113.15",
        destination_ip="10.0.2.100",
        destination_port=5432,
        details={"protocol": "tcp"},
    )

    alerts = detector.detect([event])
    assert len(alerts) == 1
    alert = alerts[0]

    assert alert.rule_id == "NET-BL-001"
    assert alert.priority == PriorityLevel.MEDIUM
    assert "evt-002" in alert.evidence_event_ids
    assert "eni-db-001" in alert.related_resource_ids
    assert alert.details["source_ip"] == "203.0.113.15"
    assert alert.details["destination_ip"] == "10.0.2.100"
    assert alert.details["destination_port"] == 5432


def test_rejected_flow_does_not_generate_alert(sample_policy):
    """Requirement: Rejected flows must not be classified as successful communication and shouldn't alert."""
    detector = NetworkBaselineDetector(sample_policy)
    event = BaseTelemetryEvent(
        event_id="evt-003",
        timestamp=datetime.now(timezone.utc),
        source=EventSource.VPC_FLOW,
        action="REJECT",
        resource_id="eni-db-001",
        source_ip="203.0.113.15",
        destination_ip="10.0.2.100",
        destination_port=5432,
        details={"protocol": "tcp"},
    )

    alerts = detector.detect([event])
    assert len(alerts) == 0


def test_explicit_maintenance_exception(sample_policy):
    """Test that traffic matching an active maintenance window is exempted."""
    detector = NetworkBaselineDetector(sample_policy)
    now = datetime.now(timezone.utc)
    event = BaseTelemetryEvent(
        event_id="evt-004",
        timestamp=now,
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-bastion-001",
        source_ip="198.51.100.5",
        destination_ip="10.0.0.5",
        destination_port=22,
        details={"protocol": "tcp"},
    )

    engine = PolicyEngine(sample_policy)
    decision, exc_id, reason = engine.evaluate_flow(event)
    assert decision == PolicyDecision.EXCEPTION
    assert exc_id == "MAINT-2026-PATCH"

    alerts = detector.detect([event])
    assert len(alerts) == 0


def test_maintenance_exception_expired(sample_policy):
    """Test that an event outside the maintenance window is not exempted and triggers alert."""
    detector = NetworkBaselineDetector(sample_policy)
    expired_time = datetime.now(timezone.utc) - timedelta(days=2)
    event = BaseTelemetryEvent(
        event_id="evt-005",
        timestamp=expired_time,
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-bastion-001",
        source_ip="198.51.100.5",
        destination_ip="10.0.0.5",
        destination_port=22,
        details={"protocol": "tcp"},
    )

    engine = PolicyEngine(sample_policy)
    decision, _, _ = engine.evaluate_flow(event)
    assert decision == PolicyDecision.UNAPPROVED

    alerts = detector.detect([event])
    assert len(alerts) == 1


def test_conflicting_rules_explicit_deny_precedence(sample_policy):
    """Deterministic behavior: Explicit UNAPPROVED rule takes precedence over broader wildcard permits."""
    detector = NetworkBaselineDetector(sample_policy)
    # SSH attempt to 10.0.1.5 (falls into 10.0.0.0/16 explicitly denied rule)
    event = BaseTelemetryEvent(
        event_id="evt-006",
        timestamp=datetime.now(timezone.utc),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-web-001",
        source_ip="10.0.1.20",
        destination_ip="10.0.1.5",
        destination_port=22,
        details={"protocol": "tcp"},
    )

    alerts = detector.detect([event])
    assert len(alerts) == 1
    assert alerts[0].details["violating_rule_id"] == "RULE-DENY-SSH-INTERNET"


def test_missing_or_ambiguous_telemetry_handled_conservatively(sample_policy):
    """Requirement: Conservative evaluation of missing/malformed IP or port fields."""
    detector = NetworkBaselineDetector(sample_policy)
    # Event missing source IP
    event_no_src = BaseTelemetryEvent(
        event_id="evt-007",
        timestamp=datetime.now(timezone.utc),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-001",
        source_ip=None,
        destination_ip="10.0.1.10",
        destination_port=443,
        details={"protocol": "tcp"},
    )

    alerts = detector.detect([event_no_src])
    assert len(alerts) == 1
    assert "Incomplete telemetry" in alerts[0].explanation


def test_numeric_protocol_mapping(sample_policy):
    """Ensure protocol '6' (IANA TCP number) is properly mapped and handled."""
    detector = NetworkBaselineDetector(sample_policy)
    event = BaseTelemetryEvent(
        event_id="evt-008",
        timestamp=datetime.now(timezone.utc),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-001",
        source_ip="10.0.1.50",
        destination_ip="10.0.2.100",
        destination_port=5432,
        details={"protocol": 6},  # Protocol 6 is TCP
    )

    alerts = detector.detect([event])
    assert len(alerts) == 0  # Approved rule matches
