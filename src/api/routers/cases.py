"""Case management API router for Member 3."""
from typing import List
from fastapi import APIRouter, Depends, HTTPException

from src.api.dependencies import get_case_service
from src.api.schemas.cases import CaseCreateRequest, CaseResponse
from src.api.services.case_service import CaseService

router = APIRouter(prefix="/cases", tags=["Cases"])


@router.get("", response_model=List[CaseResponse])
async def list_cases(
    service: CaseService = Depends(get_case_service),
) -> List[CaseResponse]:
    """List investigation cases."""
    return service.list_cases()


@router.post("", response_model=CaseResponse, status_code=201)
async def create_case(
    req: CaseCreateRequest,
    service: CaseService = Depends(get_case_service),
) -> CaseResponse:
    """Create a new investigation case."""
    return service.create_case(req)


@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(
    case_id: str,
    service: CaseService = Depends(get_case_service),
) -> CaseResponse:
    """Retrieve details for a specific investigation case."""
    case = service.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return case


@router.post("/{case_id}/alerts/{alert_id}", response_model=CaseResponse)
async def add_alert_to_case(
    case_id: str,
    alert_id: str,
    service: CaseService = Depends(get_case_service),
) -> CaseResponse:
    """Add a detection alert to an existing investigation case."""
    case = service.add_alert_to_case(case_id=case_id, alert_id=alert_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return case
