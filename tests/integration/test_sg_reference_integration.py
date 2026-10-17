"""Integration test: SG-to-SG reference -> correlation -> graph -> candidate path."""
from datetime import datetime, timezone, timedelta

from src.shared.enums import EventSource
from src.shared.models import (
    BaseTelemetryEvent,
    ConfigurationHistory,
    SecurityGroupAttachment,
)
from src.detection.correlation.cross_layer import CrossLayerCorrelator
from src.detection.graph.builder import GraphBuilder
from src.detection.graph.path_finder import CandidatePathFinder


def _telemetry(group_id):
    t0 = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
    day_ago = t0 - timedelta(days=1)
    config = ConfigurationHistory(
        attachments=[
            SecurityGroupAttachment(resource_id="eni-app", security_group_id="sg-app", attached_at=day_ago),
            SecurityGroupAttachment(resource_id="eni-db", security_group_id="sg-db", attached_at=day_ago),
        ],
        eni_to_ip_map={"eni-app": ["10.0.2.10"], "eni-db": ["10.0.3.20"]},
    )
    ct = BaseTelemetryEvent(
        event_id="ct-1",
        timestamp=t0,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        actor="arn:aws:iam::123456789012:user/admin-alice",
        resource_id="sg-db",
        details={"ip_permissions": [{"ipProtocol": "tcp", "fromPort": 5432, "toPort": 5432,
                                     "userIdGroupPairs": [{"groupId": group_id}]}]},
    )
    flow = BaseTelemetryEvent(
        event_id="flow-1",
        timestamp=t0 + timedelta(seconds=30),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-db",
        source_ip="10.0.2.10",
        destination_ip="10.0.3.20",
        destination_port=5432,
        details={"protocol": "tcp"},
    )
    return [ct, flow], config


def test_end_to_end_path_traverses_sg_reference():
    events, config = _telemetry("sg-app")
    alerts = CrossLayerCorrelator().correlate(events, config)
    assert len(alerts) == 1

    builder = GraphBuilder()
    graph = builder.build_from_telemetry(events, config, alerts)

    paths = CandidatePathFinder().find_paths(
        graph,
        source_nodes=["eni-app"],
        target_nodes=["eni-db"],
        allowed_relations=["permitted_reachability", "inferred_sequence"],
        require_temporal_order=False,
    )
    sg_paths = [p for p in paths if p.node_ids == ["eni-app", "sg-app", "sg-db", "eni-db"]]
    assert len(sg_paths) == 1
    path = sg_paths[0]
    # Path crosses an inferred edge and must say so (candidate reachability, not confirmed attack)
    assert path.contains_inferred_relationships
    assert "ct-1" in path.evidence_event_ids


def test_end_to_end_missing_reference_has_no_sg_path():
    events, config = _telemetry("sg-ghost")
    alerts = CrossLayerCorrelator().correlate(events, config)
    assert alerts == []

    graph = GraphBuilder().build_from_telemetry(events, config, alerts)
    paths = CandidatePathFinder().find_paths(
        graph,
        source_nodes=["eni-app"],
        target_nodes=["eni-db"],
        allowed_relations=["permitted_reachability", "inferred_sequence"],
        require_temporal_order=False,
    )
    assert not any("sg-db" in p.node_ids for p in paths)
