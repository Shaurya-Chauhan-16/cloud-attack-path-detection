"""Graph Service for Phase 2 Member 3 API.

Coordinates graph retrieval from Member 2's analysis results.
Preserves observed-versus-inferred graph information and lateral candidate paths.
"""
from typing import Optional

from src.api.schemas.graph import GraphResponse
from src.api.services.alert_service import AlertService
from src.shared.enums import EdgeNature, RelationshipType
from src.shared.models import AnalysisResult, GraphData


class GraphService:
    """Service providing attack path graph data."""

    def __init__(self, alert_service: Optional[AlertService] = None):
        self.alert_service = alert_service or AlertService()

    def get_attack_graph(self) -> GraphResponse:
        """Retrieve the multi-relational attack graph from Member 2's analysis.
        
        Preserves observed, permitted, and inferred edge categories.
        """
        analysis = self.alert_service.get_analysis_result()

        inferred_count = sum(
            1 for e in analysis.edges
            if e.observed_or_inferred == EdgeNature.INFERRED.value or e.relation == RelationshipType.INFERRED_SEQUENCE.value
        )
        observed_count = sum(
            1 for e in analysis.edges
            if e.observed_or_inferred == EdgeNature.OBSERVED.value or e.relation == RelationshipType.OBSERVED_COMMUNICATION.value
        )
        permitted_count = sum(
            1 for e in analysis.edges
            if e.observed_or_inferred == EdgeNature.PERMITTED.value or e.relation == RelationshipType.PERMITTED_REACHABILITY.value
        )

        return GraphResponse(
            nodes=analysis.nodes,
            edges=analysis.edges,
            candidate_paths=analysis.candidate_paths,
            total_nodes=len(analysis.nodes),
            total_edges=len(analysis.edges),
            inferred_edge_count=inferred_count,
            observed_edge_count=observed_count,
            permitted_edge_count=permitted_count,
        )
