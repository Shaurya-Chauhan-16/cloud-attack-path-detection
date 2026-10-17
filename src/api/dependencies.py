"""FastAPI dependency injection providers for Member 3 API."""
from typing import Generator
from functools import lru_cache

from src.api.services.alert_service import AlertService
from src.api.services.case_service import CaseService
from src.api.services.evidence_service import EvidenceService
from src.api.services.timeline_service import GraphService
from src.ingestion.storage.repository import TelemetryRepository

# Shared singleton instances for in-memory / service wiring
_repo = TelemetryRepository()
_alert_service = AlertService(repository=_repo)
_evidence_service = EvidenceService(repository=_repo)
_graph_service = GraphService(alert_service=_alert_service)
_case_service = CaseService()


def get_telemetry_repository() -> TelemetryRepository:
    """Dependency provider for TelemetryRepository."""
    return _repo


def get_alert_service() -> AlertService:
    """Dependency provider for AlertService."""
    return _alert_service


def get_evidence_service() -> EvidenceService:
    """Dependency provider for EvidenceService."""
    return _evidence_service


def get_graph_service() -> GraphService:
    """Dependency provider for GraphService."""
    return _graph_service


def get_case_service() -> CaseService:
    """Dependency provider for CaseService."""
    return _case_service
