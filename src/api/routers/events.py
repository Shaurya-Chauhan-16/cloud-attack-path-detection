"""Events and Evidence API router for Member 3."""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.dependencies import get_alert_service, get_evidence_service
from src.api.schemas.events import EventEvidenceResponse, EventListResponse, TelemetryEventResponse
from src.api.services.alert_service import AlertService
from src.api.services.evidence_service import EvidenceService
from src.shared.enums import EventSource

router = APIRouter(prefix="/events", tags=["Events & Evidence"])


@router.get("", response_model=EventListResponse)
async def list_events(
    source: Optional[EventSource] = Query(None, description="Filter by event source"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    service: EvidenceService = Depends(get_evidence_service),
) -> EventListResponse:
    """List telemetry events (CloudTrail and VPC Flow Logs)."""
    items = service.list_events(source=source, limit=limit, offset=offset)
    return EventListResponse(total=len(items), items=items)


@router.get("/{event_id}", response_model=TelemetryEventResponse)
async def get_event(
    event_id: str,
    service: EvidenceService = Depends(get_evidence_service),
) -> TelemetryEventResponse:
    """Retrieve details for a single telemetry event."""
    evt = service.get_event_by_id(event_id)
    if not evt:
        raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found")
    return evt


@router.get("/evidence/alert/{alert_id}", response_model=EventEvidenceResponse)
async def get_alert_evidence(
    alert_id: str,
    alert_service: AlertService = Depends(get_alert_service),
    evidence_service: EvidenceService = Depends(get_evidence_service),
) -> EventEvidenceResponse:
    """Retrieve forensic evidence events associated with a detection alert.
    
    Includes explicit uncertainty notes and causation boundaries.
    """
    alert = alert_service.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    return evidence_service.get_evidence_for_alert(
        alert_id=alert_id,
        evidence_event_ids=alert.evidence_event_ids,
        uncertainty_disclaimer=alert.details.get("uncertainty_notes"),
    )
