"""API Schemas for investigation cases.

Clarifies in-memory/temporary vs persistent state.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from src.shared.enums import PriorityLevel


class CaseCreateRequest(BaseModel):
    """Request payload to create a new investigation case."""
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    alert_ids: List[str] = Field(default_factory=list)
    priority: PriorityLevel = PriorityLevel.MEDIUM
    tags: List[str] = Field(default_factory=list)


class CaseResponse(BaseModel):
    """Investigation case response model.
    
    Note: Stored in-memory in Phase 2 unless database persistence is configured.
    """
    model_config = ConfigDict(extra="allow")

    case_id: str
    title: str
    description: Optional[str] = None
    priority: PriorityLevel = PriorityLevel.MEDIUM
    status: str = "open"  # 'open', 'investigating', 'resolved', 'closed'
    alert_ids: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    persistence_mode: str = "in-memory (Phase 2 foundation)"
