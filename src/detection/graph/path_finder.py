"""Candidate Path Finder using directed temporal traversal.

Finds candidate sequences through the directed multi-relational graph.

Constraints & Semantics:
1. Respects edge direction.
2. Cycle-safe: prevents infinite loops using node visitation sets.
3. Configurable max_depth (maximum path length).
4. Temporal consistency: along a path, each step's valid_time must not contradict prior steps.
5. Preserves all supporting evidence_event_ids and relationship types.
6. Clearly flags whether a path contains inferred relationships.
7. Explains uncertainty and avoids claiming confirmed lateral movement.
"""
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Set
import networkx as nx

from src.shared.enums import EdgeNature, RelationshipType
from src.shared.models import CandidatePath


class CandidatePathFinder:
    """Finds directed temporal candidate attack and lateral movement paths."""

    def __init__(self, max_depth: int = 5):
        self.max_depth = max_depth

    def _ensure_utc(self, dt: Optional[datetime]) -> Optional[datetime]:
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def _generate_path_id(self, node_ids: List[str], edge_ids: List[str]) -> str:
        """Create deterministic path identifier."""
        raw = f"{'-'.join(node_ids)}::{'-'.join(edge_ids)}"
        return f"path-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12]}"

    def find_paths(
        self,
        graph: nx.MultiDiGraph,
        source_nodes: Optional[List[str]] = None,
        target_nodes: Optional[List[str]] = None,
        allowed_relations: Optional[List[str]] = None,
        require_temporal_order: bool = True,
    ) -> List[CandidatePath]:
        """Discover candidate paths in the directed graph.

        Args:
            graph: MultiDiGraph built by GraphBuilder.
            source_nodes: Starting node IDs (if None, all nodes with in-degree == 0 or external endpoints).
            target_nodes: Goal node IDs (if None, all reachable nodes at path length >= 1).
            allowed_relations: Filter on edge relations to traverse.
            require_temporal_order: Whether edge timestamps must be non-decreasing.

        Returns:
            List of CandidatePath objects.
        """
        if not graph or graph.number_of_nodes() == 0:
            return []

        # Determine start nodes
        if source_nodes is not None:
            starts = [s for s in source_nodes if graph.has_node(s)]
        else:
            # Default starts: external endpoints or nodes with in_degree == 0
            starts = [
                n for n in graph.nodes()
                if n.startswith("endpoint:") or graph.in_degree(n) == 0
            ]
            if not starts:
                starts = list(graph.nodes())

        target_set = set(target_nodes) if target_nodes is not None else None
        results: List[CandidatePath] = []

        # Depth-first search for simple directed paths
        for start in sorted(starts):
            # Queue stores: (current_node, [node_path], [edge_data_list], visited_nodes_set)
            queue = [(start, [start], [], {start})]

            while queue:
                curr_node, path_nodes, path_edges, visited = queue.pop()

                # If current node is a target (and path has at least one edge), record path
                if len(path_edges) >= 1:
                    if target_set is None or curr_node in target_set:
                        candidate = self._construct_candidate_path(
                            path_nodes, path_edges
                        )
                        results.append(candidate)

                # Stop extending if reached max_depth
                if len(path_edges) >= self.max_depth:
                    continue

                # Explore outgoing directed edges
                for neighbor in sorted(graph.successors(curr_node)):
                    if neighbor in visited:
                        # Cycle prevention: simple paths only
                        continue

                    # Multi-edges between curr_node and neighbor
                    edge_dict = graph[curr_node][neighbor]
                    for key, edge_data in sorted(edge_dict.items(), key=lambda x: x[0]):
                        rel = edge_data.get("relation")
                        if allowed_relations and rel not in allowed_relations:
                            continue

                        # Check temporal consistency if required
                        if require_temporal_order and path_edges:
                            prev_time = self._ensure_utc(path_edges[-1].get("valid_time"))
                            curr_time = self._ensure_utc(edge_data.get("valid_time"))

                            if prev_time and curr_time and curr_time < prev_time:
                                # Temporal violation: causality cannot go backwards in time
                                continue

                        new_visited = set(visited)
                        new_visited.add(neighbor)
                        queue.append(
                            (
                                neighbor,
                                path_nodes + [neighbor],
                                path_edges + [edge_data],
                                new_visited,
                            )
                        )

        # Deduplicate and sort deterministically
        dedup_results: Dict[str, CandidatePath] = {}
        for r in results:
            if r.path_id not in dedup_results:
                dedup_results[r.path_id] = r

        sorted_results = sorted(
            list(dedup_results.values()),
            key=lambda p: (len(p.node_ids), p.node_ids[0], p.node_ids[-1], p.path_id),
        )
        return sorted_results

    def _construct_candidate_path(
        self, node_ids: List[str], edges: List[Dict[str, Any]]
    ) -> CandidatePath:
        """Helper to build CandidatePath model from traversed nodes and edge data."""
        edge_ids = [e["edge_id"] for e in edges]
        path_id = self._generate_path_id(node_ids, edge_ids)

        all_evidence: Set[str] = set()
        relations: List[str] = []
        timestamps: List[datetime] = []
        has_inferred = False
        uncertainties: List[str] = []

        for e in edges:
            all_evidence.update(e.get("evidence_event_ids", []))
            rel = e.get("relation", "unknown")
            relations.append(rel)
            nature = e.get("observed_or_inferred")

            if nature == EdgeNature.INFERRED.value or rel == RelationshipType.INFERRED_SEQUENCE.value:
                has_inferred = True

            v_time = self._ensure_utc(e.get("valid_time"))
            if v_time:
                timestamps.append(v_time)
            else:
                uncertainties.append(f"Edge {e['edge_id']} lacks exact valid_time.")

        if has_inferred:
            uncertainties.append(
                "Path contains inferred relationship(s); sequence indicates candidate reachability, not confirmed attack."
            )

        start_time = min(timestamps) if timestamps else None
        end_time = max(timestamps) if timestamps else None

        return CandidatePath(
            path_id=path_id,
            node_ids=node_ids,
            edge_ids=edge_ids,
            evidence_event_ids=sorted(list(all_evidence)),
            relationship_types=relations,
            start_time=start_time,
            end_time=end_time,
            contains_inferred_relationships=has_inferred,
            uncertainty_reasons=uncertainties,
        )
