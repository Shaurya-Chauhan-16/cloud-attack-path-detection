"""Unit tests for CrossLayerCorrelator (Phase 2)."""
from datetime import datetime, timezone, timedelta
import pytest

from src.shared.enums import EventSource, PriorityLevel
from src.shared.models import (
    BaseTelemetryEvent,
    ConfigurationHistory,
    SecurityGroupAttachment,
)
from src.detection.correlation.cross_layer import CrossLayerCorrelator


@pytest.fixture
def base_time():
    return datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def sample_config_history(base_time):
    return ConfigurationHistory(
        attachments=[
            SecurityGroupAttachment(
                resource_id="eni-target-001",
                security_group_id="sg-web-001",
                attached_at=base_time - timedelta(days=1),
                detached_at=None,
            )
        ],
        eni_to_ip_map={
            "eni-target-001": ["10.0.1.50"],
        },
    )


def test_successful_change_followed_by_matching_flow(base_time, sample_config_history):
    """1. Successful access-enabling configuration change followed by matching accepted flow produces a finding."""
    correlator = CrossLayerCorrelator(correlation_window_seconds=300)

    ct_event = BaseTelemetryEvent(
        event_id="ct-001",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        actor="arn:aws:iam::123456789012:user/admin-alice",
        resource_id="sg-web-001",
        details={
            "protocol": "tcp",
            "from_port": 8080,
            "to_port": 8080,
            "cidr_ipv4": "198.51.100.0/24",
        },
    )

    flow_event = BaseTelemetryEvent(
        event_id="flow-001",
        timestamp=base_time + timedelta(seconds=45),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-target-001",
        source_ip="198.51.100.22",
        destination_ip="10.0.1.50",
        destination_port=8080,
        details={"protocol": "tcp"},
    )

    alerts = correlator.correlate([ct_event, flow_event], sample_config_history)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "CORR-CROSS-001"
    assert alert.priority == PriorityLevel.HIGH
    assert "ct-001" in alert.evidence_event_ids
    assert "flow-001" in alert.evidence_event_ids
    assert "eni-target-001" in alert.related_resource_ids
    assert "NOT confirm application compromise" in alert.explanation


def test_failed_api_request_produces_no_finding(base_time, sample_config_history):
    """2. Failed CloudTrail API request produces no successful-change finding."""
    correlator = CrossLayerCorrelator()

    ct_event = BaseTelemetryEvent(
        event_id="ct-failed-001",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        actor="arn:aws:iam::123456789012:user/malicious-actor",
        resource_id="sg-web-001",
        details={
            "protocol": "tcp",
            "from_port": 8080,
            "to_port": 8080,
            "cidr_ipv4": "198.51.100.0/24",
            "errorCode": "Client.UnauthorizedOperation",
            "errorMessage": "You are not authorized to perform this operation.",
        },
    )

    flow_event = BaseTelemetryEvent(
        event_id="flow-001",
        timestamp=base_time + timedelta(seconds=45),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-target-001",
        source_ip="198.51.100.22",
        destination_ip="10.0.1.50",
        destination_port=8080,
        details={"protocol": "tcp"},
    )

    alerts = correlator.correlate([ct_event, flow_event], sample_config_history)
    assert len(alerts) == 0


def test_successful_change_with_no_traffic(base_time, sample_config_history):
    """3. Successful configuration change with no subsequent traffic produces no flow-correlation finding."""
    correlator = CrossLayerCorrelator()

    ct_event = BaseTelemetryEvent(
        event_id="ct-002",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        resource_id="sg-web-001",
        details={
            "protocol": "tcp",
            "from_port": 8080,
            "to_port": 8080,
            "cidr_ipv4": "198.51.100.0/24",
        },
    )

    alerts = correlator.correlate([ct_event], sample_config_history)
    assert len(alerts) == 0


def test_unrelated_configuration_and_traffic(base_time, sample_config_history):
    """4. Unrelated configuration change and accepted traffic remain unlinked."""
    correlator = CrossLayerCorrelator()

    ct_event = BaseTelemetryEvent(
        event_id="ct-003",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        resource_id="sg-unrelated-999",  # Different SG
        details={
            "protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_ipv4": "203.0.113.0/24",
        },
    )

    flow_event = BaseTelemetryEvent(
        event_id="flow-003",
        timestamp=base_time + timedelta(seconds=30),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-target-001",
        source_ip="198.51.100.22",
        destination_ip="10.0.1.50",
        destination_port=8080,
        details={"protocol": "tcp"},
    )

    alerts = correlator.correlate([ct_event, flow_event], sample_config_history)
    assert len(alerts) == 0


def test_flow_before_configuration_change(base_time, sample_config_history):
    """5. Flow occurring before the configuration change remains unlinked."""
    correlator = CrossLayerCorrelator()

    ct_event = BaseTelemetryEvent(
        event_id="ct-004",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        resource_id="sg-web-001",
        details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "0.0.0.0/0"},
    )

    flow_event = BaseTelemetryEvent(
        event_id="flow-prior",
        timestamp=base_time - timedelta(seconds=10),  # Prior flow!
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-target-001",
        source_ip="198.51.100.22",
        destination_ip="10.0.1.50",
        destination_port=8080,
        details={"protocol": "tcp"},
    )

    alerts = correlator.correlate([ct_event, flow_event], sample_config_history)
    assert len(alerts) == 0


def test_flow_outside_window(base_time, sample_config_history):
    """6. Flow outside the configured correlation window (e.g. >300s) remains unlinked."""
    correlator = CrossLayerCorrelator(correlation_window_seconds=300)

    ct_event = BaseTelemetryEvent(
        event_id="ct-005",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        resource_id="sg-web-001",
        details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "0.0.0.0/0"},
    )

    flow_event = BaseTelemetryEvent(
        event_id="flow-late",
        timestamp=base_time + timedelta(seconds=301),  # Exceeds 300s window
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-target-001",
        source_ip="198.51.100.22",
        destination_ip="10.0.1.50",
        destination_port=8080,
        details={"protocol": "tcp"},
    )

    alerts = correlator.correlate([ct_event, flow_event], sample_config_history)
    assert len(alerts) == 0


def test_incorrect_destination_does_not_correlate(base_time, sample_config_history):
    """7. Matching source but incorrect destination does not correlate."""
    correlator = CrossLayerCorrelator()

    ct_event = BaseTelemetryEvent(
        event_id="ct-006",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        resource_id="sg-web-001",
        details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "0.0.0.0/0"},
    )

    flow_event = BaseTelemetryEvent(
        event_id="flow-wrong-dest",
        timestamp=base_time + timedelta(seconds=20),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-other-999",  # Not attached to sg-web-001
        source_ip="198.51.100.22",
        destination_ip="10.0.9.99",
        destination_port=8080,
        details={"protocol": "tcp"},
    )

    alerts = correlator.correlate([ct_event, flow_event], sample_config_history)
    assert len(alerts) == 0


def test_incorrect_protocol_does_not_correlate(base_time, sample_config_history):
    """8. Matching destination but incorrect protocol does not correlate."""
    correlator = CrossLayerCorrelator()

    ct_event = BaseTelemetryEvent(
        event_id="ct-007",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        resource_id="sg-web-001",
        details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "0.0.0.0/0"},
    )

    flow_event = BaseTelemetryEvent(
        event_id="flow-udp",
        timestamp=base_time + timedelta(seconds=20),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-target-001",
        source_ip="198.51.100.22",
        destination_ip="10.0.1.50",
        destination_port=8080,
        details={"protocol": "udp"},  # UDP instead of TCP
    )

    alerts = correlator.correlate([ct_event, flow_event], sample_config_history)
    assert len(alerts) == 0


def test_incorrect_port_does_not_correlate(base_time, sample_config_history):
    """9. Matching protocol but incorrect port does not correlate."""
    correlator = CrossLayerCorrelator()

    ct_event = BaseTelemetryEvent(
        event_id="ct-008",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        resource_id="sg-web-001",
        details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "0.0.0.0/0"},
    )

    flow_event = BaseTelemetryEvent(
        event_id="flow-wrong-port",
        timestamp=base_time + timedelta(seconds=20),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-target-001",
        source_ip="198.51.100.22",
        destination_ip="10.0.1.50",
        destination_port=22,  # Port 22 instead of 8080
        details={"protocol": "tcp"},
    )

    alerts = correlator.correlate([ct_event, flow_event], sample_config_history)
    assert len(alerts) == 0


def test_source_cidr_mismatch_does_not_correlate(base_time, sample_config_history):
    """10. Source CIDR does not match the flow source."""
    correlator = CrossLayerCorrelator()

    ct_event = BaseTelemetryEvent(
        event_id="ct-009",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        resource_id="sg-web-001",
        details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "198.51.100.0/24"},
    )

    flow_event = BaseTelemetryEvent(
        event_id="flow-cidr-mismatch",
        timestamp=base_time + timedelta(seconds=20),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-target-001",
        source_ip="203.0.113.5",  # Outside 198.51.100.0/24
        destination_ip="10.0.1.50",
        destination_port=8080,
        details={"protocol": "tcp"},
    )

    alerts = correlator.correlate([ct_event, flow_event], sample_config_history)
    assert len(alerts) == 0


def test_revoked_rule_handled(base_time, sample_config_history):
    """11. A revoked rule before flow arrival invalidates the relationship."""
    correlator = CrossLayerCorrelator()

    ct_auth = BaseTelemetryEvent(
        event_id="ct-auth-010",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        resource_id="sg-web-001",
        details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "0.0.0.0/0"},
    )

    ct_revoke = BaseTelemetryEvent(
        event_id="ct-revoke-010",
        timestamp=base_time + timedelta(seconds=30),  # Revoked at +30s
        source=EventSource.CLOUDTRAIL,
        action="RevokeSecurityGroupIngress",
        resource_id="sg-web-001",
        details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "0.0.0.0/0"},
    )

    flow_event = BaseTelemetryEvent(
        event_id="flow-after-revoke",
        timestamp=base_time + timedelta(seconds=60),  # Flow arrives at +60s
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-target-001",
        source_ip="198.51.100.22",
        destination_ip="10.0.1.50",
        destination_port=8080,
        details={"protocol": "tcp"},
    )

    alerts = correlator.correlate([ct_auth, ct_revoke, flow_event], sample_config_history)
    assert len(alerts) == 0


def test_ambiguous_resource_mapping_not_silently_resolved(base_time):
    """12. Ambiguous IP-to-resource mapping is not silently guessed."""
    correlator = CrossLayerCorrelator()

    # Ambiguous config history: two different ENIs map to the same IP
    ambiguous_history = ConfigurationHistory(
        attachments=[
            SecurityGroupAttachment(
                resource_id="eni-A",
                security_group_id="sg-web-001",
                attached_at=base_time - timedelta(days=1),
            ),
            SecurityGroupAttachment(
                resource_id="eni-B",
                security_group_id="sg-other",
                attached_at=base_time - timedelta(days=1),
            ),
        ],
        eni_to_ip_map={
            "eni-A": ["10.0.1.50"],
            "eni-B": ["10.0.1.50"],  # Collision / ambiguous mapping
        },
    )

    ct_event = BaseTelemetryEvent(
        event_id="ct-012",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        resource_id="sg-web-001",
        details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "0.0.0.0/0"},
    )

    # Flow doesn't have resource_id populated, only destination_ip
    flow_event = BaseTelemetryEvent(
        event_id="flow-ambiguous",
        timestamp=base_time + timedelta(seconds=20),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id=None,
        source_ip="198.51.100.22",
        destination_ip="10.0.1.50",
        destination_port=8080,
        details={"protocol": "tcp"},
    )

    alerts = correlator.correlate([ct_event, flow_event], ambiguous_history)
    assert len(alerts) == 0


def test_missing_evidence_does_not_produce_unsupported_finding(base_time, sample_config_history):
    """13. Missing required fields in CT event skips correlation safely."""
    correlator = CrossLayerCorrelator()

    ct_event = BaseTelemetryEvent(
        event_id="ct-missing-details",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        resource_id=None,  # Missing SG resource_id and details
        details={},
    )

    flow_event = BaseTelemetryEvent(
        event_id="flow-013",
        timestamp=base_time + timedelta(seconds=20),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-target-001",
        source_ip="198.51.100.22",
        destination_ip="10.0.1.50",
        destination_port=8080,
        details={"protocol": "tcp"},
    )

    alerts = correlator.correlate([ct_event, flow_event], sample_config_history)
    assert len(alerts) == 0


def test_duplicate_events_do_not_produce_duplicate_findings(base_time, sample_config_history):
    """14. Duplicate events in batch do not duplicate alerts."""
    correlator = CrossLayerCorrelator()

    ct_event = BaseTelemetryEvent(
        event_id="ct-dup-014",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        resource_id="sg-web-001",
        details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "0.0.0.0/0"},
    )

    flow_event = BaseTelemetryEvent(
        event_id="flow-dup-014",
        timestamp=base_time + timedelta(seconds=20),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-target-001",
        source_ip="198.51.100.22",
        destination_ip="10.0.1.50",
        destination_port=8080,
        details={"protocol": "tcp"},
    )

    # Supply duplicates in list
    batch = [ct_event, ct_event, flow_event, flow_event]
    alerts = correlator.correlate(batch, sample_config_history)
    assert len(alerts) == 1


def test_multiple_matching_flows_handled_deterministically(base_time, sample_config_history):
    """15. Multiple matching flows aggregated into single finding with all evidence IDs preserved."""
    correlator = CrossLayerCorrelator()

    ct_event = BaseTelemetryEvent(
        event_id="ct-015",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        resource_id="sg-web-001",
        details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "0.0.0.0/0"},
    )

    flow_1 = BaseTelemetryEvent(
        event_id="flow-015-a",
        timestamp=base_time + timedelta(seconds=10),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-target-001",
        source_ip="198.51.100.22",
        destination_ip="10.0.1.50",
        destination_port=8080,
        details={"protocol": "tcp"},
    )

    flow_2 = BaseTelemetryEvent(
        event_id="flow-015-b",
        timestamp=base_time + timedelta(seconds=50),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-target-001",
        source_ip="198.51.100.23",
        destination_ip="10.0.1.50",
        destination_port=8080,
        details={"protocol": "tcp"},
    )

    alerts = correlator.correlate([ct_event, flow_1, flow_2], sample_config_history)
    assert len(alerts) == 1
    assert "ct-015" in alerts[0].evidence_event_ids
    assert "flow-015-a" in alerts[0].evidence_event_ids
    assert "flow-015-b" in alerts[0].evidence_event_ids
    assert alerts[0].details["matched_flows_count"] == 2


def test_out_of_order_input_produces_identical_result(base_time, sample_config_history):
    """16. Out-of-order input produces the same deterministic result as in-order input."""
    correlator = CrossLayerCorrelator()

    ct_event = BaseTelemetryEvent(
        event_id="ct-016",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        resource_id="sg-web-001",
        details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "0.0.0.0/0"},
    )

    flow_event = BaseTelemetryEvent(
        event_id="flow-016",
        timestamp=base_time + timedelta(seconds=20),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-target-001",
        source_ip="198.51.100.22",
        destination_ip="10.0.1.50",
        destination_port=8080,
        details={"protocol": "tcp"},
    )

    in_order_alerts = correlator.correlate([ct_event, flow_event], sample_config_history)
    out_of_order_alerts = correlator.correlate([flow_event, ct_event], sample_config_history)

    assert len(in_order_alerts) == 1
    assert len(out_of_order_alerts) == 1
    assert in_order_alerts[0].evidence_event_ids == out_of_order_alerts[0].evidence_event_ids
    assert in_order_alerts[0].related_resource_ids == out_of_order_alerts[0].related_resource_ids


def test_aws_ip_permissions_structure(base_time, sample_config_history):
    """17. Test standard nested AWS ipPermissions format."""
    correlator = CrossLayerCorrelator()

    ct_event = BaseTelemetryEvent(
        event_id="ct-017",
        timestamp=base_time,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        actor="arn:aws:iam::123456789012:user/admin-bob",
        resource_id="sg-web-001",
        details={
            "ipPermissions": [
                {
                    "ipProtocol": "tcp",
                    "fromPort": 443,
                    "toPort": 443,
                    "ipRanges": [{"cidrIp": "198.51.100.0/24"}],
                }
            ]
        },
    )

    flow_event = BaseTelemetryEvent(
        event_id="flow-017",
        timestamp=base_time + timedelta(seconds=15),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-target-001",
        source_ip="198.51.100.5",
        destination_ip="10.0.1.50",
        destination_port=443,
        details={"protocol": "tcp"},
    )

    alerts = correlator.correlate([ct_event, flow_event], sample_config_history)
    assert len(alerts) == 1
    assert "443" in alerts[0].explanation


def test_empty_input_produces_empty_result():
    """18. Empty input produces a valid empty result."""
    correlator = CrossLayerCorrelator()
    alerts = correlator.correlate([])
    assert alerts == []
