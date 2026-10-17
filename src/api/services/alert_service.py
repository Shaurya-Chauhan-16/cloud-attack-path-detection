"""Alert Service for Phase 2 Member 3 API.

Coordinates retrieval, filtering, and scoring of detection alerts.
Reuses Member 2's analyze() interface or pre-computed results.
"""
from typing import Dict, List, Optional

from src.api.schemas.alerts import AlertFilterParams, AlertResponse
from src.detection import analyze
from src.detection.scoring.priority import PriorityScorer
from src.ingestion.storage.repository import TelemetryRepository
from src.shared.enums import PriorityLevel
from src.shared.models import (
    AnalysisResult,
    ApprovedCommunicationPolicy,
    BaseTelemetryEvent,
    ConfigurationHistory,
    DetectionAlert,
    ScoredAlert,
)


class AlertService:
    """Service handling detection alerts operations."""

    def __init__(
        self,
        repository: Optional[TelemetryRepository] = None,
        cached_result: Optional[AnalysisResult] = None,
    ):
        self.repository = repository or TelemetryRepository()
        self._cached_result: Optional[AnalysisResult] = cached_result
        self._scorer = PriorityScorer()

    def set_analysis_result(self, result: AnalysisResult) -> None:
        """Cache an analysis result to avoid redundant re-analysis."""
        self._cached_result = result

    def get_analysis_result(
        self,
        policy: Optional[ApprovedCommunicationPolicy] = None,
        force_refresh: bool = False,
    ) -> AnalysisResult:
        """Get or compute analysis result using Member 2's analyze() interface.

        Strictly integrates with Member 2's analyze(), never inventing fake alerts.
        """
        if self._cached_result and not force_refresh:
            return self._cached_result

        config_history = self.repository.load_configuration_history()
        events = self.repository.get_events(limit=500)

        # Run Member 2 detection engine
        result = analyze(
            events=events,
            configuration_history=config_history,
            policy=policy,
        )
        self._cached_result = result
        return result

    def list_alerts(
        self,
        filters: Optional[AlertFilterParams] = None,
    ) -> List[AlertResponse]:
        """List alerts, optionally filtered by priority, rule_id, or resource_id."""
        analysis = self.get_analysis_result()
        scored_map = {
            sa.alert.alert_id: sa.score_result for sa in analysis.scored_alerts
        }

        alerts_out: List[AlertResponse] = []
        for alert in analysis.alerts:
            # Apply filters
            if filters:
                if filters.priority and alert.priority != filters.priority:
                    continue
                if filters.rule_id and alert.rule_id != filters.rule_id:
                    continue
                if filters.case_id and alert.case_id != filters.case_id:
                    continue
                if filters.resource_id and filters.resource_id not in alert.related_resource_ids:
                    continue

            score_res = scored_map.get(alert.alert_id)
            alert_resp = AlertResponse(
                **alert.model_dump(),
                score_result=score_res,
            )
            alerts_out.append(alert_resp)

        # Pagination
        if filters:
            return alerts_out[filters.offset : filters.offset + filters.limit]
        return alerts_out

    def get_alert_by_id(self, alert_id: str) -> Optional[AlertResponse]:
        """Retrieve a single alert by its unique alert_id."""
        analysis = self.get_analysis_result()
        scored_map = {
            sa.alert.alert_id: sa.score_result for sa in analysis.scored_alerts
        }
        for alert in analysis.alerts:
            if alert.alert_id == alert_id:
                return AlertResponse(
                    **alert.model_dump(),
                    score_result=scored_map.get(alert.alert_id),
                )
        return None
