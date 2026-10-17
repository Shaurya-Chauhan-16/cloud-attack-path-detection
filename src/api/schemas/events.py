"""API Schemas for telemetry events and evidence views, adapted from src.shared.models.

Strictly reuses existing contracts without creating competing detection models.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from src.shared.enums import EventSource
from src.shared.models import BaseTelemetryEvent


class TelemetryEventResponse(BaseTelemetryEvent):
    """API response schema for a telemetry event.
    
    Inherits directly from src.shared.models.BaseTelemetryEvent:
    - event_id: str
    - timestamp: datetime
    - source: EventSource
    - action: str
    - actor: Optional[str]
    - resource_id: Optional[str]
    - source_ip: Optional[str]
    - destination_ip: Optional[str]
    - destination_port: Optional[int]
    - raw_record_id: Optional[str]
    - details: Dict[str, Any]
    """
    raw_payload: Optional[Dict[str, Any]] = None


class EventListResponse(BaseModel):
    """Response containing a list of telemetry events."""
    model_config = ConfigDict(extra="allow")

    total: int
    items: List[TelemetryEventResponse]


class EventEvidenceResponse(BaseModel):
    """Evidence view grouping events referenced by an alert or investigation."""
    model_config = ConfigDict(extra="allow")

    alert_id: Optional[str] = None
    evidence_events: List[TelemetryEventResponse]
    uncertainty_notes: List[str] = Field(default_factory=list)
    total_events: int
