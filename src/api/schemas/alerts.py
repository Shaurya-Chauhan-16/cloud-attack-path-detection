"""API Schemas for detection alerts, adapted from src.shared.models.

Strictly reuses existing contracts without creating competing detection models.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from src.shared.enums import PriorityLevel
from src.shared.models import DetectionAlert, PriorityScoreResult, ScoredAlert


class AlertResponse(DetectionAlert):
    """API response schema for a single detection alert.
    
    Inherits all fields directly from src.shared.models.DetectionAlert:
    - alert_id: str
    - rule_id: str
    - rule_version: str
    - priority: PriorityLevel
    - explanation: str
    - evidence_event_ids: List[str]
    - related_resource_ids: List[str]
    - created_at: datetime
    - case_id: Optional[str]
    - details: Dict[str, Any]
    """
    score_result: Optional[PriorityScoreResult] = None


class AlertListResponse(BaseModel):
    """Paginated or listed response for detection alerts."""
    model_config = ConfigDict(extra="allow")

    total: int
    items: List[AlertResponse]


class AlertFilterParams(BaseModel):
    """Query filter parameters for listing alerts."""
    model_config = ConfigDict(extra="allow")

    priority: Optional[PriorityLevel] = None
    rule_id: Optional[str] = None
    resource_id: Optional[str] = None
    case_id: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)
