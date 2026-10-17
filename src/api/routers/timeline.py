"""Graph and Timeline API router for Member 3."""
from fastapi import APIRouter, Depends

from src.api.dependencies import get_graph_service
from src.api.schemas.graph import GraphResponse
from src.api.services.timeline_service import GraphService

router = APIRouter(prefix="/graph", tags=["Attack Path Graph"])


@router.get("", response_model=GraphResponse)
async def get_attack_graph(
    service: GraphService = Depends(get_graph_service),
) -> GraphResponse:
    """Retrieve the attack path graph generated from cross-layer telemetry analysis.

    Includes observed communication, permitted reachability, and inferred sequence edges.
    """
    return service.get_attack_graph()
