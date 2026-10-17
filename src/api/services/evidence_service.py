"""Evidence and Telemetry Service for Phase 2 Member 3 API.

Coordinates listing telemetry events and assembling forensic evidence views.
Preserves uncertainty notes and causal attribution disclaimers.
"""
from typing import List, Optional

from src.api.schemas.events import EventEvidenceResponse, TelemetryEventResponse
from src.ingestion.storage.repository import TelemetryRepository
from src.shared.enums import EventSource
from src.shared.models import BaseTelemetryEvent


class EvidenceService:
    """Service handling telemetry events and alert evidence extraction."""

    def __init__(self, repository: Optional[TelemetryRepository] = None):
        self.repository = repository or TelemetryRepository()

    def list_events(
        self,
        source: Optional[EventSource] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[TelemetryEventResponse]:
        """List telemetry events with optional filtering and pagination."""
        events = self.repository.get_events(source=source, limit=limit, offset=offset)
        return [
            TelemetryEventResponse(
                **evt.model_dump(),
                raw_payload=evt.details.get("raw") if evt.details else None,
            )
            for evt in events
        ]

    def get_event_by_id(self, event_id: str) -> Optional[TelemetryEventResponse]:
        """Fetch a single telemetry event by ID."""
        evt = self.repository.get_event_by_id(event_id)
        if not evt:
            return None
        return TelemetryEventResponse(
            **evt.model_dump(),
            raw_payload=evt.details.get("raw") if evt.details else None,
        )

    def get_evidence_for_alert(
        self,
        alert_id: str,
        evidence_event_ids: List[str],
        uncertainty_disclaimer: Optional[str] = None,
    ) -> EventEvidenceResponse:
        """Assemble an evidence bundle for an alert from its referenced event IDs.

        Preserves uncertainty notes and causation limits.
        """
        events = self.repository.get_events_by_ids(evidence_event_ids)
        items = [
            TelemetryEventResponse(
                **e.model_dump(),
                raw_payload=e.details.get("raw") if e.details else None,
            )
            for e in events
        ]

        uncertainty_notes = [
            "Correlated accepted network traffic establishes reachability enabled by configuration changes.",
            "Attribution disclaimer: Observed flow does not confirm application-layer compromise or malicious intent.",
            "IAM identity responsible for rule authorization is decoupled from the network endpoint initiating traffic.",
        ]
        if uncertainty_disclaimer:
            uncertainty_notes.append(uncertainty_disclaimer)

        return EventEvidenceResponse(
            alert_id=alert_id,
            evidence_events=items,
            uncertainty_notes=uncertainty_notes,
            total_events=len(items),
        )
