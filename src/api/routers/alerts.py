"""Alerts API router for Member 3."""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.dependencies import get_alert_service
from src.api.schemas.alerts import AlertFilterParams, AlertListResponse, AlertResponse
from src.api.services.alert_service import AlertService
from src.shared.enums import PriorityLevel

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    priority: Optional[PriorityLevel] = Query(None, description="Filter by alert priority"),
    rule_id: Optional[str] = Query(None, description="Filter by detection rule ID"),
    resource_id: Optional[str] = Query(None, description="Filter by affected resource ID"),
    case_id: Optional[str] = Query(None, description="Filter by case ID"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    service: AlertService = Depends(get_alert_service),
) -> AlertListResponse:
    """Retrieve all detection alerts matching optional filters."""
    filters = AlertFilterParams(
        priority=priority,
        rule_id=rule_id,
        resource_id=resource_id,
        case_id=case_id,
        limit=limit,
        offset=offset,
    )
    items = service.list_alerts(filters=filters)
    return AlertListResponse(total=len(items), items=items)


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    service: AlertService = Depends(get_alert_service),
) -> AlertResponse:
    """Retrieve details and explainable score breakdown for a specific alert."""
    alert = service.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return alert
