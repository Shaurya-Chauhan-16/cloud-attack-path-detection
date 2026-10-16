"""Synthetic demonstration of GraphBuilder and CandidatePathFinder."""
import json
from datetime import datetime, timezone, timedelta
from src.shared.enums import EventSource
from src.shared.models import BaseTelemetryEvent, ConfigurationHistory, SecurityGroupAttachment
from src.detection.graph.builder import GraphBuilder
from src.detection.graph.path_finder import CandidatePathFinder

def run_demo():
    t0 = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Flow telemetry: Attacker -> Bastion -> Internal Database
    events = [
        BaseTelemetryEvent(
            event_id="flow-step-1",
            timestamp=t0,
            source=EventSource.VPC_FLOW,
            action="ACCEPT",
            resource_id="eni-bastion-host",
            source_ip="198.51.100.42",
            destination_ip="10.0.0.10",
            destination_port=22,
            details={"protocol": "tcp"},
        ),
        BaseTelemetryEvent(
            event_id="flow-step-2",
            timestamp=t0 + timedelta(seconds=90),
            source=EventSource.VPC_FLOW,
            action="ACCEPT",
            resource_id="eni-db-primary",
            source_ip="10.0.0.10",
            destination_ip="10.0.2.100",
            destination_port=5432,
            details={"protocol": "tcp"},
        ),
    ]

    config = ConfigurationHistory(
        attachments=[
            SecurityGroupAttachment(
                resource_id="eni-bastion-host",
                security_group_id="sg-bastion",
                attached_at=t0 - timedelta(days=1),
            ),
            SecurityGroupAttachment(
                resource_id="eni-db-primary",
                security_group_id="sg-db",
                attached_at=t0 - timedelta(days=1),
            ),
        ],
        eni_to_ip_map={
            "eni-bastion-host": ["10.0.0.10"],
            "eni-db-primary": ["10.0.2.100"],
        },
    )

    # Build Graph
    builder = GraphBuilder()
    graph = builder.build_from_telemetry(events, configuration_history=config)
    graph_data = builder.to_graph_data()


    # Find Candidate Paths from external endpoint to Database
    finder = CandidatePathFinder(max_depth=3)
    paths = finder.find_paths(
        graph,
        source_nodes=["endpoint:198.51.100.42"],
        target_nodes=["eni-db-primary"],
    )

    demo_output = {
        "graph_summary": {
            "node_count": len(graph_data.nodes),
            "edge_count": len(graph_data.edges),
        },
        "discovered_paths": [p.model_dump(mode="json") for p in paths],
    }

    print(json.dumps(demo_output, indent=2))

if __name__ == "__main__":
    run_demo()
