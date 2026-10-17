"""API Schemas for attack path graphs and analysis, adapted from src.shared.models.

Strictly reuses existing contracts without creating competing detection models.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from src.shared.models import (
    AnalysisResult,
    CandidatePath,
    GraphData,
    GraphEdge,
    GraphNode,
    ScoredAlert,
)


class GraphResponse(BaseModel):
    """API response schema for attack path graphs.

    Preserves observed-versus-inferred graph information and edge confidence.
    """
    model_config = ConfigDict(extra="allow")

    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    candidate_paths: List[CandidatePath] = Field(default_factory=list)
    total_nodes: int = 0
    total_edges: int = 0
    inferred_edge_count: int = 0
    observed_edge_count: int = 0
    permitted_edge_count: int = 0


class AnalysisResponse(AnalysisResult):
    """Full analysis result API response.

    Inherits directly from src.shared.models.AnalysisResult.
    """
    summary: Dict[str, Any] = Field(default_factory=dict)
