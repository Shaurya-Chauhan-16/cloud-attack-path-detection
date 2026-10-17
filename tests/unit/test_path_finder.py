"""Unit tests for CandidatePathFinder (Phase 3)."""
from datetime import datetime, timezone, timedelta
import pytest
import networkx as nx

from src.shared.enums import EdgeNature, RelationshipType
from src.shared.models import CandidatePath
from src.detection.graph.builder import GraphBuilder
from src.detection.graph.path_finder import CandidatePathFinder


@pytest.fixture
def t0():
    return datetime(2026, 10, 15, 14, 0, 0, tzinfo=timezone.utc)


def test_valid_directed_path_discovered(t0):
    """1. A valid directed multi-hop path is discovered."""
    builder = GraphBuilder()
    builder.add_node("endpoint:attacker", "ip_endpoint")
    builder.add_node("eni-bastion", "eni")
    builder.add_node("eni-database", "eni")

    builder.add_edge(
        "endpoint:attacker",
        "eni-bastion",
        relation=RelationshipType.OBSERVED_COMMUNICATION.value,
        observed_or_inferred=EdgeNature.OBSERVED.value,
        evidence_event_ids=["flow-1"],
        valid_time=t0,
    )
    builder.add_edge(
        "eni-bastion",
        "eni-database",
        relation=RelationshipType.OBSERVED_COMMUNICATION.value,
        observed_or_inferred=EdgeNature.OBSERVED.value,
        evidence_event_ids=["flow-2"],
        valid_time=t0 + timedelta(minutes=1),
    )

    finder = CandidatePathFinder(max_depth=3)
    paths = finder.find_paths(
        builder.graph,
        source_nodes=["endpoint:attacker"],
        target_nodes=["eni-database"],
    )

    assert len(paths) == 1
    p = paths[0]
    assert p.node_ids == ["endpoint:attacker", "eni-bastion", "eni-database"]
    assert p.evidence_event_ids == ["flow-1", "flow-2"]
    assert not p.contains_inferred_relationships


def test_path_cannot_traverse_in_reverse(t0):
    """2. Path traversal strictly adheres to edge direction and cannot run in reverse."""
    builder = GraphBuilder()
    builder.add_edge(
        "nodeA",
        "nodeB",
        relation=RelationshipType.OBSERVED_COMMUNICATION.value,
        observed_or_inferred=EdgeNature.OBSERVED.value,
        evidence_event_ids=["ev-1"],
        valid_time=t0,
    )

    finder = CandidatePathFinder()
    reverse_paths = finder.find_paths(
        builder.graph, source_nodes=["nodeB"], target_nodes=["nodeA"]
    )
    assert len(reverse_paths) == 0


def test_cycles_do_not_cause_infinite_traversal(t0):
    """3. Cycles (loops) do not cause infinite recursion and produce simple paths only."""
    builder = GraphBuilder()
    # Cycle: A -> B -> C -> A
    builder.add_edge("A", "B", relation="test", observed_or_inferred="observed", evidence_event_ids=["1"], valid_time=t0)
    builder.add_edge("B", "C", relation="test", observed_or_inferred="observed", evidence_event_ids=["2"], valid_time=t0)
    builder.add_edge("C", "A", relation="test", observed_or_inferred="observed", evidence_event_ids=["3"], valid_time=t0)

    finder = CandidatePathFinder(max_depth=5)
    paths = finder.find_paths(builder.graph, source_nodes=["A"])
    # All paths must be simple (no node visited twice)
    for p in paths:
        assert len(p.node_ids) == len(set(p.node_ids))


def test_maximum_path_length_respected(t0):
    """4. Maximum path depth is strictly enforced."""
    builder = GraphBuilder()
    # A -> B -> C -> D -> E
    builder.add_edge("A", "B", relation="test", observed_or_inferred="observed", evidence_event_ids=["1"], valid_time=t0)
    builder.add_edge("B", "C", relation="test", observed_or_inferred="observed", evidence_event_ids=["2"], valid_time=t0)
    builder.add_edge("C", "D", relation="test", observed_or_inferred="observed", evidence_event_ids=["3"], valid_time=t0)
    builder.add_edge("D", "E", relation="test", observed_or_inferred="observed", evidence_event_ids=["4"], valid_time=t0)

    finder = CandidatePathFinder(max_depth=2)
    paths = finder.find_paths(builder.graph, source_nodes=["A"], target_nodes=["E"])
    assert len(paths) == 0  # Reaching E requires depth 4, exceeds max_depth 2


def test_disconnected_nodes_produce_no_false_path(t0):
    """5. Disconnected nodes yield 0 paths."""
    builder = GraphBuilder()
    builder.add_node("isolated-A", "eni")
    builder.add_node("isolated-B", "eni")

    finder = CandidatePathFinder()
    paths = finder.find_paths(builder.graph, source_nodes=["isolated-A"], target_nodes=["isolated-B"])
    assert len(paths) == 0


def test_temporal_inconsistencies_prevent_invalid_sequence(t0):
    """6. Chronologically backwards flows (later flow -> earlier flow) cannot form a valid causal sequence."""
    builder = GraphBuilder()
    # Step 1 happens at t0 + 10m
    builder.add_edge(
        "A", "B",
        relation="flow",
        observed_or_inferred="observed",
        evidence_event_ids=["f-late"],
        valid_time=t0 + timedelta(minutes=10),
    )
    # Step 2 happens EARLIER at t0 (impossible causal order)
    builder.add_edge(
        "B", "C",
        relation="flow",
        observed_or_inferred="observed",
        evidence_event_ids=["f-early"],
        valid_time=t0,
    )

    finder = CandidatePathFinder()
    paths = finder.find_paths(builder.graph, source_nodes=["A"], target_nodes=["C"], require_temporal_order=True)
    assert len(paths) == 0


def test_missing_timestamps_preserve_uncertainty(t0):
    """7. Missing timestamps in edges are flagged in uncertainty_reasons."""
    builder = GraphBuilder()
    builder.add_edge(
        "A", "B",
        relation="reachability",
        observed_or_inferred="permitted",
        evidence_event_ids=[],
        valid_time=None,  # No timestamp
    )

    finder = CandidatePathFinder()
    paths = finder.find_paths(builder.graph, source_nodes=["A"], target_nodes=["B"])
    assert len(paths) == 1
    assert any("lacks exact valid_time" in r for r in paths[0].uncertainty_reasons)


def test_evidence_ids_from_complete_path_retained(t0):
    """8. All supporting event IDs across every hop in the path are aggregated."""
    builder = GraphBuilder()
    builder.add_edge("X", "Y", relation="r1", observed_or_inferred="o", evidence_event_ids=["ev-x"], valid_time=t0)
    builder.add_edge("Y", "Z", relation="r2", observed_or_inferred="o", evidence_event_ids=["ev-y1", "ev-y2"], valid_time=t0)

    finder = CandidatePathFinder()
    paths = finder.find_paths(builder.graph, source_nodes=["X"], target_nodes=["Z"])
    assert len(paths) == 1
    assert paths[0].evidence_event_ids == ["ev-x", "ev-y1", "ev-y2"]


def test_inferred_relationships_explicitly_marked(t0):
    """9. Inferred steps mark contains_inferred_relationships=True and state uncertainty."""
    builder = GraphBuilder()
    builder.add_edge(
        "sg-insecure", "eni-web",
        relation=RelationshipType.INFERRED_SEQUENCE.value,
        observed_or_inferred=EdgeNature.INFERRED.value,
        evidence_event_ids=["alert-1"],
        valid_time=t0,
    )

    finder = CandidatePathFinder()
    paths = finder.find_paths(builder.graph, source_nodes=["sg-insecure"])
    assert len(paths) == 1
    assert paths[0].contains_inferred_relationships is True
    assert any("candidate reachability, not confirmed attack" in r for r in paths[0].uncertainty_reasons)


def test_empty_graph_returns_empty_result():
    """10. Empty graph returns empty list."""
    finder = CandidatePathFinder()
    assert finder.find_paths(nx.MultiDiGraph()) == []


def test_repeated_calls_deterministic(t0):
    """11. Successive calls produce identical ordering and path IDs."""
    builder = GraphBuilder()
    builder.add_edge("M", "N", relation="r", observed_or_inferred="o", evidence_event_ids=["1"], valid_time=t0)
    builder.add_edge("N", "O", relation="r", observed_or_inferred="o", evidence_event_ids=["2"], valid_time=t0)

    finder = CandidatePathFinder()
    res1 = finder.find_paths(builder.graph)
    res2 = finder.find_paths(builder.graph)

    assert [p.path_id for p in res1] == [p.path_id for p in res2]


def test_permitted_path_not_reported_as_observed(t0):
    """12. Paths traversing permitted edges do not confuse permitted reachability with observed flow."""
    builder = GraphBuilder()
    builder.add_edge(
        "A", "B",
        relation=RelationshipType.PERMITTED_REACHABILITY.value,
        observed_or_inferred=EdgeNature.PERMITTED.value,
        evidence_event_ids=[],
        valid_time=t0,
    )

    finder = CandidatePathFinder()
    paths = finder.find_paths(builder.graph, source_nodes=["A"], target_nodes=["B"])
    assert len(paths) == 1
    assert RelationshipType.PERMITTED_REACHABILITY.value in paths[0].relationship_types
    assert RelationshipType.OBSERVED_COMMUNICATION.value not in paths[0].relationship_types
