"""Alert Service for Phase 2 Member 3 API.

Coordinates retrieval, filtering, and scoring of detection alerts.
Reuses Member 2's analyze() interface or pre-computed results.
"""
import os
import threading
import time
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

DEFAULT_MAX_ANALYSIS_EVENTS = 100000
DEFAULT_REFRESH_INTERVAL_SECONDS = 60.0


class AlertService:
    """Service handling detection alerts operations with thread-safe auto-refresh."""

    def __init__(
        self,
        repository: Optional[TelemetryRepository] = None,
        cached_result: Optional[AnalysisResult] = None,
        refresh_interval_seconds: Optional[float] = None,
    ):
        self.repository = repository or TelemetryRepository()
        self._cached_result: Optional[AnalysisResult] = cached_result
        self._scorer = PriorityScorer()
        self._lock = threading.Lock()
        self._is_refreshing: bool = False
        self._last_analysis_time: float = 0.0
        self._last_event_count: int = -1
        if refresh_interval_seconds is not None:
            self._refresh_interval = refresh_interval_seconds
        else:
            try:
                self._refresh_interval = float(
                    os.getenv("ALERT_REFRESH_INTERVAL_SECONDS", str(DEFAULT_REFRESH_INTERVAL_SECONDS))
                )
            except ValueError:
                self._refresh_interval = DEFAULT_REFRESH_INTERVAL_SECONDS

    def set_analysis_result(self, result: AnalysisResult) -> None:
        """Cache an analysis result to avoid redundant re-analysis."""
        with self._lock:
            self._cached_result = result
            self._last_analysis_time = time.time()
            try:
                self._last_event_count = self.repository.count_events()
            except Exception:
                pass

    def _get_max_analysis_events(self) -> int:
        """Get max analysis events from MAX_ANALYSIS_EVENTS env var or default 100,000."""
        env_val = os.getenv("MAX_ANALYSIS_EVENTS")
        if env_val:
            try:
                return int(env_val)
            except ValueError:
                pass
        return DEFAULT_MAX_ANALYSIS_EVENTS

    def _compute_analysis(
        self,
        policy: Optional[ApprovedCommunicationPolicy] = None,
    ) -> AnalysisResult:
        """Run Member 2 analyze() synchronously."""
        config_history = self.repository.load_configuration_history()
        limit = self._get_max_analysis_events()  # default limit=100000
        events = self.repository.get_events(limit=limit)

        result = analyze(
            events=events,
            configuration_history=config_history,
            policy=policy,
        )
        return result

    def _background_refresh(
        self,
        policy: Optional[ApprovedCommunicationPolicy] = None,
        current_count: int = 0,
    ) -> None:
        """Background thread worker to recompute analysis without blocking requests."""
        try:
            new_result = self._compute_analysis(policy=policy)
            with self._lock:
                self._cached_result = new_result
                self._last_analysis_time = time.time()
                self._last_event_count = current_count
        except Exception:
            pass
        finally:
            with self._lock:
                self._is_refreshing = False

    def get_analysis_result(
        self,
        policy: Optional[ApprovedCommunicationPolicy] = None,
        force_refresh: bool = False,
    ) -> AnalysisResult:
        """Get or compute analysis result using Member 2's analyze() interface.

        Strictly integrates with Member 2's analyze(), never inventing fake alerts.
        Supports thread-safe cached serving, background auto-refresh on count change,
        and explicit force_refresh.
        """
        now = time.time()
        current_count = self.repository.count_events()

        with self._lock:
            # Case 1: Explicit force refresh or no cached result yet -> compute synchronously
            if force_refresh or self._cached_result is None:
                new_result = self._compute_analysis(policy=policy)
                self._cached_result = new_result
                self._last_analysis_time = now
                self._last_event_count = current_count
                return self._cached_result

            # Case 2: Check if event count changed and refresh interval elapsed
            count_changed = (self._last_event_count != current_count)
            interval_elapsed = (now - self._last_analysis_time >= self._refresh_interval)

            if count_changed and interval_elapsed and not self._is_refreshing:
                self._is_refreshing = True
                thread = threading.Thread(
                    target=self._background_refresh,
                    kwargs={"policy": policy, "current_count": current_count},
                    daemon=True,
                )
                thread.start()

            # Always return atomic snapshot of cached result
            return self._cached_result

    def list_alerts(
        self,
        filters: Optional[AlertFilterParams] = None,
        force_refresh: bool = False,
    ) -> List[AlertResponse]:
        """List alerts, optionally filtered by priority, rule_id, or resource_id."""
        analysis = self.get_analysis_result(force_refresh=force_refresh)
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
