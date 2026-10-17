"""Unit tests for GraphBuilder (Phase 3)."""
from datetime import datetime, timezone, timedelta
import pytest

from src.shared.enums import EdgeNature, EventSource, RelationshipType
from src.shared.models import (
    ApprovedCommunicationPolicy,
    BaseTelemetryEvent,
    ConfigurationHistory,
    DetectionAlert,
    PolicyRule,
    SecurityGroupAttachment,
)
from src.detection.graph.builder import GraphBuilder


@pytest.fixture
def t0():
    return datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)


def test_empty_input_creates_valid_empty_graph():
    """1. Empty input creates a valid empty graph."""
    builder = GraphBuilder()
    g = builder.build_from_telemetry([])
    assert g.number_of_nodes() == 0
    assert g.number_of_edges() == 0

    data = builder.to_graph_data()
    assert len(data.nodes) == 0
    assert len(data.edges) == 0


def test_valid_accepted_flow_creates_observed_communication_edge(t0):
    """2. Valid accepted flow creates appropriate observed communication edge."""
    builder = GraphBuilder()
    flow = BaseTelemetryEvent(
        event_id="flow-001",
        timestamp=t0,
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-web-1",
        source_ip="198.51.100.10",
        destination_ip="10.0.1.5",
        destination_port=443,
        details={"protocol": "tcp"},
    )

    g = builder.build_from_telemetry([flow])
    assert g.number_of_nodes() == 2
    assert g.has_node("endpoint:198.51.100.10")
    assert g.has_node("eni-web-1")
    assert g.has_edge("endpoint:198.51.100.10", "eni-web-1")

    edge_data = list(g["endpoint:198.51.100.10"]["eni-web-1"].values())[0]
    assert edge_data["relation"] == RelationshipType.OBSERVED_COMMUNICATION.value
    assert edge_data["observed_or_inferred"] == EdgeNature.OBSERVED.value
    assert edge_data["port"] == 443
    assert edge_data["protocol"] == "tcp"


def test_edge_preserves_supporting_event_id(t0):
    """3. The edge preserves the supporting event ID."""
    builder = GraphBuilder()
    flow = BaseTelemetryEvent(
        event_id="ev-flow-1234",
        timestamp=t0,
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-01",
        source_ip="10.0.0.5",
        destination_ip="10.0.0.10",
        destination_port=80,
    )

    builder.build_from_telemetry([flow])
    data = builder.to_graph_data()
    assert len(data.edges) == 1
    assert "ev-flow-1234" in data.edges[0].evidence_event_ids


def test_duplicate_events_do_not_create_duplicate_evidence(t0):
    """4. Duplicate events in input do not create duplicate evidence IDs."""
    builder = GraphBuilder()
    flow = BaseTelemetryEvent(
        event_id="ev-dup-1",
        timestamp=t0,
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-01",
        source_ip="10.0.0.5",
        destination_ip="10.0.0.10",
        destination_port=80,
    )

    builder.build_from_telemetry([flow, flow])
    data = builder.to_graph_data()
    assert len(data.edges) == 1
    assert data.edges[0].evidence_event_ids == ["ev-dup-1"]


def test_repeated_flows_preserve_distinct_evidence_ids(t0):
    """5. Repeated flows at same timestamp merge into single edge with distinct evidence IDs."""
    builder = GraphBuilder()
    flow1 = BaseTelemetryEvent(
        event_id="ev-packet-1",
        timestamp=t0,
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-01",
        source_ip="10.0.0.5",
        destination_ip="10.0.0.10",
        destination_port=80,
    )
    flow2 = BaseTelemetryEvent(
        event_id="ev-packet-2",
        timestamp=t0,
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-01",
        source_ip="10.0.0.5",
        destination_ip="10.0.0.10",
        destination_port=80,
    )

    builder.build_from_telemetry([flow1, flow2])
    data = builder.to_graph_data()
    assert len(data.edges) == 1
    assert sorted(data.edges[0].evidence_event_ids) == ["ev-packet-1", "ev-packet-2"]


def test_missing_endpoint_identity_handled_conservatively(t0):
    """6. Incomplete telemetry (missing IPs) is handled conservatively without inventing nodes."""
    builder = GraphBuilder()
    flow_bad = BaseTelemetryEvent(
        event_id="ev-bad",
        timestamp=t0,
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id=None,
        source_ip=None,
        destination_ip="10.0.0.10",
    )

    g = builder.build_from_telemetry([flow_bad])
    assert g.number_of_nodes() == 0
    assert g.number_of_edges() == 0


def test_policy_permission_alone_does_not_create_observed_edge():
    """7. Policy permission alone creates permitted reachability, not observed communication."""
    builder = GraphBuilder()
    policy = ApprovedCommunicationPolicy(
        policy_id="test-pol",
        rules=[
            PolicyRule(
                rule_id="RULE-ALLOW-DB",
                source="10.0.1.10",
                destination="10.0.2.20",
                protocol="tcp",
                destination_port=5432,
            )
        ],
    )

    g = builder.build_from_telemetry([], policy=policy)
    assert g.number_of_nodes() == 2
    edge_data = list(g["endpoint:10.0.1.10"]["endpoint:10.0.2.20"].values())[0]
    assert edge_data["relation"] == RelationshipType.PERMITTED_REACHABILITY.value
    assert edge_data["observed_or_inferred"] == EdgeNature.PERMITTED.value
    assert edge_data["relation"] != RelationshipType.OBSERVED_COMMUNICATION.value


def test_inferred_relationships_distinguishable(t0):
    """8. Inferred relationships from cross-layer alerts remain clearly distinguishable from observed edges."""
    builder = GraphBuilder()
    alert = DetectionAlert(
        alert_id="alert-cross-1",
        rule_id="CORR-CROSS-001",
        rule_version="1.0.0",
        priority="high",
        explanation="Inferred enablement",
        evidence_event_ids=["ct-100", "flow-200"],
        related_resource_ids=["eni-app-server"],
        created_at=t0,
        details={
            "cloudtrail_event_id": "ct-100",
            "security_group_id": "sg-insecure",
            "uncertainty_note": "Uncertainty test",
        },
    )

    g = builder.build_from_telemetry([], alerts=[alert])
    assert g.has_edge("sg-insecure", "eni-app-server")
    edge_data = list(g["sg-insecure"]["eni-app-server"].values())[0]
    assert edge_data["relation"] == RelationshipType.INFERRED_SEQUENCE.value
    assert edge_data["observed_or_inferred"] == EdgeNature.INFERRED.value


def test_deterministic_identifiers(t0):
    """9. Node and edge IDs are deterministic across multiple runs."""
    builder1 = GraphBuilder()
    builder2 = GraphBuilder()

    flow = BaseTelemetryEvent(
        event_id="flow-det-1",
        timestamp=t0,
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-test",
        source_ip="1.2.3.4",
        destination_ip="5.6.7.8",
        destination_port=80,
    )

    g1 = builder1.build_from_telemetry([flow])
    g2 = builder2.build_from_telemetry([flow])

    data1 = builder1.to_graph_data()
    data2 = builder2.to_graph_data()

    assert data1.nodes[0].node_id == data2.nodes[0].node_id
    assert data1.edges[0].edge_id == data2.edges[0].edge_id


def test_graph_serialization_preserves_attributes(t0):
    """10. GraphData model dumps to valid JSON with required Member 3 API fields."""
    builder = GraphBuilder()
    flow = BaseTelemetryEvent(
        event_id="flow-json",
        timestamp=t0,
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-json",
        source_ip="192.168.1.1",
        destination_ip="10.0.0.1",
        destination_port=22,
        details={"protocol": "tcp"},
    )

    builder.build_from_telemetry([flow])
    data = builder.to_graph_data()
    serialized = data.model_dump(mode="json")

    assert "nodes" in serialized
    assert "edges" in serialized
    edge = serialized["edges"][0]
    assert edge["source_node"] == "endpoint:192.168.1.1"
    assert edge["target_node"] == "eni-json"
    assert edge["port"] == 22


def test_direction_preserved_correctly(t0):
    """11. Edge direction strictly follows source -> destination traffic flow."""
    builder = GraphBuilder()
    flow = BaseTelemetryEvent(
        event_id="flow-dir",
        timestamp=t0,
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-dst",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
    )

    g = builder.build_from_telemetry([flow])
    assert g.has_edge("endpoint:10.0.0.1", "eni-dst")
    assert not g.has_edge("eni-dst", "endpoint:10.0.0.1")


def test_unknown_resources_not_assigned_fabricated_identities(t0):
    """12. Unmapped external IPs receive endpoint: prefix instead of fabricated EC2 IDs."""
    builder = GraphBuilder()
    flow = BaseTelemetryEvent(
        event_id="flow-unknown",
        timestamp=t0,
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id=None,
        source_ip="203.0.113.5",
        destination_ip="198.51.100.7",
    )

    g = builder.build_from_telemetry([flow])
    assert "endpoint:203.0.113.5" in g.nodes()
    assert "endpoint:198.51.100.7" in g.nodes()
    # No fake "i-xxxx" or "eni-xxxx" generated
    assert not any(n.startswith("i-") or n.startswith("eni-") for n in g.nodes())
