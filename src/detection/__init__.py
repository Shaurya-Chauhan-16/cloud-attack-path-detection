"""Main unified analysis interface for Member 2 engine.

Provides:
analyze(events, configuration_history, policy) -> AnalysisResult
"""
from typing import List, Optional

from src.shared.models import (
    AnalysisResult,
    ApprovedCommunicationPolicy,
    BaseTelemetryEvent,
    ConfigurationHistory,
)
from src.detection.policy.engine import NetworkBaselineDetector
from src.detection.correlation.cross_layer import CrossLayerCorrelator
from src.detection.graph.builder import GraphBuilder
from src.detection.graph.path_finder import CandidatePathFinder
from src.detection.scoring.priority import PriorityScorer


def analyze(
    events: List[BaseTelemetryEvent],
    configuration_history: Optional[ConfigurationHistory] = None,
    policy: Optional[ApprovedCommunicationPolicy] = None,
    max_path_depth: int = 4,
) -> AnalysisResult:
    """Stable, unified entry point for Member 2's detection and graph engine.

    Args:
        events: Raw or normalized telemetry events (CloudTrail & VPC Flow Logs).
        configuration_history: Historical snapshot of resource attachments.
        policy: Configured approved communication policy and maintenance windows.
        max_path_depth: Maximum candidate lateral movement path traversal depth.

    Returns:
        AnalysisResult containing alerts, graph nodes, graph edges, candidate paths, and scored alerts.
        Guaranteed to be JSON-serializable via .model_dump(mode="json") for Member 3's API.
    """
    all_alerts = []

    # 1. Run Network Baseline Detector (if policy provided)
    if policy:
        baseline_detector = NetworkBaselineDetector(policy)
        baseline_alerts = baseline_detector.detect(events)
        all_alerts.extend(baseline_alerts)

    # 2. Run Cross-Layer Correlator
    correlator = CrossLayerCorrelator()
    cross_layer_alerts = correlator.correlate(events, configuration_history)
    all_alerts.extend(cross_layer_alerts)

    # 3. Build Multi-relational Graph
    builder = GraphBuilder()
    graph = builder.build_from_telemetry(
        events=events,
        configuration_history=configuration_history,
        alerts=cross_layer_alerts,
        policy=policy,
    )
    graph_data = builder.to_graph_data()

    # 4. Find Candidate Attack Sequences
    path_finder = CandidatePathFinder(max_depth=max_path_depth)
    candidate_paths = path_finder.find_paths(graph)

    # 5. Score Alerts
    scorer = PriorityScorer()
    scored_alerts = [scorer.score(alert) for alert in all_alerts]

    return AnalysisResult(
        alerts=all_alerts,
        nodes=graph_data.nodes,
        edges=graph_data.edges,
        candidate_paths=candidate_paths,
        scored_alerts=scored_alerts,
    )
