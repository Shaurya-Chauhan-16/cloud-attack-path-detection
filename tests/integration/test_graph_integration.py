"""Integration tests for GraphBuilder and CandidatePathFinder with Phase 1 and 2 pipelines."""
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
from src.detection.correlation.cross_layer import CrossLayerCorrelator
from src.detection.graph.builder import GraphBuilder
from src.detection.graph.path_finder import CandidatePathFinder


@pytest.fixture
def enterprise_telemetry():
    t0 = datetime(2026, 10, 15, 15, 0, 0, tzinfo=timezone.utc)

    # 1. Configuration history
    config = ConfigurationHistory(
        attachments=[
            SecurityGroupAttachment(
                resource_id="eni-web",
                security_group_id="sg-web",
                attached_at=t0 - timedelta(days=1),
            ),
            SecurityGroupAttachment(
                resource_id="eni-app",
                security_group_id="sg-app",
                attached_at=t0 - timedelta(days=1),
            ),
            SecurityGroupAttachment(
                resource_id="eni-db",
                security_group_id="sg-db",
                attached_at=t0 - timedelta(days=1),
            ),
        ],
        eni_to_ip_map={
            "eni-web": ["10.0.1.10"],
            "eni-app": ["10.0.2.20"],
            "eni-db": ["10.0.3.30"],
        },
    )

    # 2. Administrative unauthorized SG modification (Cross-layer trigger)
    ct_event = BaseTelemetryEvent(
        event_id="ct-open-ingress",
        timestamp=t0,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        actor="arn:aws:iam::123456789012:user/compromised-dev",
        resource_id="sg-web",
        details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "0.0.0.0/0"},
    )

    # 3. Hop 1: External attacker connects to Web on 8080
    flow1 = BaseTelemetryEvent(
        event_id="flow-hop-1",
        timestamp=t0 + timedelta(seconds=60),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-web",
        source_ip="203.0.113.19",
        destination_ip="10.0.1.10",
        destination_port=8080,
        details={"protocol": "tcp"},
    )

    # 4. Hop 2: Web communicates to App
    flow2 = BaseTelemetryEvent(
        event_id="flow-hop-2",
        timestamp=t0 + timedelta(seconds=120),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-app",
        source_ip="10.0.1.10",
        destination_ip="10.0.2.20",
        destination_port=9000,
        details={"protocol": "tcp"},
    )

    # 5. Hop 3: App connects to DB
    flow3 = BaseTelemetryEvent(
        event_id="flow-hop-3",
        timestamp=t0 + timedelta(seconds=180),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-db",
        source_ip="10.0.2.20",
        destination_ip="10.0.3.30",
        destination_port=5432,
        details={"protocol": "tcp"},
    )

    return {
        "t0": t0,
        "config": config,
        "ct_event": ct_event,
        "flows": [flow1, flow2, flow3],
    }


def test_end_to_end_cross_layer_graph_and_path_finding(enterprise_telemetry):
    """Full pipeline test:
    1. Run CrossLayerCorrelator on CloudTrail + Flows to generate cross-layer alerts.
    2. Build MultiDiGraph including observed flows, attachments, and inferred alert relationships.
    3. Run CandidatePathFinder to discover multi-hop candidate lateral movement path.
    """
    data = enterprise_telemetry
    config = data["config"]
    all_events = [data["ct_event"]] + data["flows"]

    # Step 1: Run Cross-Layer Correlator
    correlator = CrossLayerCorrelator()
    alerts = correlator.correlate(all_events, config)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "CORR-CROSS-001"

    # Step 2: Build Graph
    builder = GraphBuilder()
    g = builder.build_from_telemetry(
        events=all_events,
        configuration_history=config,
        alerts=alerts,
    )

    # Verify nodes and edges
    graph_data = builder.to_graph_data()
    node_ids = [n.node_id for n in graph_data.nodes]
    assert "endpoint:203.0.113.19" in node_ids
    assert "eni-web" in node_ids
    assert "eni-app" in node_ids
    assert "eni-db" in node_ids
    assert "sg-web" in node_ids

    # Step 3: Find Candidate Attack Path from external IP to Database
    finder = CandidatePathFinder(max_depth=4)
    paths = finder.find_paths(
        g,
        source_nodes=["endpoint:203.0.113.19"],
        target_nodes=["eni-db"],
        allowed_relations=["observed_communication"],
    )

    assert len(paths) == 1
    path = paths[0]
    assert path.node_ids == ["endpoint:203.0.113.19", "eni-web", "eni-app", "eni-db"]
    assert path.evidence_event_ids == ["flow-hop-1", "flow-hop-2", "flow-hop-3"]
    assert path.start_time < path.end_time
    assert not path.contains_inferred_relationships
