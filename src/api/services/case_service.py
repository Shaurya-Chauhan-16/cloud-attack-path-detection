"""Investigation Case Service for Phase 2 Member 3 API.

Provides clear in-memory case management for Phase 2.
Documents in-memory temporary behavior explicitly as required by Phase 2 rules.
"""
from datetime import datetime, timezone
from typing import Dict, List, Optional
import uuid

from src.api.schemas.cases import CaseCreateRequest, CaseResponse


class CaseService:
    """In-memory investigation case management service.

    IMPORTANT ARCHITECTURE NOTE:
    Phase 2 case persistence is in-memory only (cases reset upon process restart).
    Persistent SQLite/PostgreSQL storage for cases will be wired in future phases.
    """

    def __init__(self):
        self._cases: Dict[str, CaseResponse] = {}

    def create_case(self, req: CaseCreateRequest) -> CaseResponse:
        """Create a new investigation case in memory."""
        now = datetime.now(timezone.utc)
        case_id = f"case-{uuid.uuid4().hex[:8]}"
        case = CaseResponse(
            case_id=case_id,
            title=req.title,
            description=req.description,
            priority=req.priority,
            status="open",
            alert_ids=req.alert_ids,
            tags=req.tags,
            created_at=now,
            updated_at=now,
            persistence_mode="in-memory (Phase 2 temporary store)",
        )
        self._cases[case_id] = case
        return case

    def list_cases(self) -> List[CaseResponse]:
        """List all current cases from in-memory store."""
        return list(self._cases.values())

    def get_case(self, case_id: str) -> Optional[CaseResponse]:
        """Get an investigation case by its case_id."""
        return self._cases.get(case_id)

    def add_alert_to_case(self, case_id: str, alert_id: str) -> Optional[CaseResponse]:
        """Associate an alert with a case."""
        case = self._cases.get(case_id)
        if not case:
            return None
        if alert_id not in case.alert_ids:
            case.alert_ids.append(alert_id)
            case.updated_at = datetime.now(timezone.utc)
        return case

    def clear(self) -> None:
        """Clear all cases (useful for testing)."""
        self._cases.clear()
