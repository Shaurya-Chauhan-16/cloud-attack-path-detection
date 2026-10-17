"""Explainable Priority Scoring Engine.

Computes transparent, deterministic priority scores [0.0 - 100.0] for security findings.

Principles & Rules:
1. Priority scores reflect investigation urgency, NOT calibrated probabilities of compromise.
2. Distinct factors with documented weights:
   - Detection Evidence Strength (max 35)
   - Policy Deviation (max 25)
   - Configuration Correlation & Enablement (max 20)
   - Resource Criticality Impact (max 20, only when reliably provided)
   - Uncertainty & Ambiguity Penalties (deductions)
3. Missing metadata is tracked explicitly and does NOT automatically increase risk.
4. An authorized maintenance context or exception reduces priority appropriately.
5. Scores are bounded deterministically between [0.0, 100.0] and map to PriorityLevel:
   - 0.0 - 29.9: LOW
   - 30.0 - 59.9: MEDIUM
   - 60.0 - 84.9: HIGH
   - 85.0 - 100.0: CRITICAL
"""
from typing import Any, Dict, List, Optional
from src.shared.constants import (
    CROSS_LAYER_RULE_ID,
    NETWORK_BASELINE_RULE_ID,
    PRIORITY_SCORER_VERSION,
)
from src.shared.enums import PriorityLevel
from src.shared.models import DetectionAlert, PriorityScoreResult, ScoredAlert


class PriorityScorer:
    """Calculates explainable, deterministic priority scores for alerts and candidate sequences."""

    # Default factor weights
    BASE_EVIDENCE_WEIGHT = 35.0
    POLICY_DEVIATION_WEIGHT = 25.0
    CONFIG_CORRELATION_WEIGHT = 20.0
    RESOURCE_IMPACT_WEIGHT = 20.0

    # Severity level thresholds
    THRESHOLD_CRITICAL = 85.0
    THRESHOLD_HIGH = 60.0
    THRESHOLD_MEDIUM = 30.0

    def __init__(
        self,
        scorer_version: str = PRIORITY_SCORER_VERSION,
        criticality_weights: Optional[Dict[str, float]] = None,
    ):
        self.scorer_version = scorer_version
        # Allowed explicit criticality metadata mappings
        self.criticality_weights = criticality_weights or {
            "critical": 20.0,
            "high": 15.0,
            "medium": 10.0,
            "low": 5.0,
        }

    def _determine_priority_level(self, score: float) -> PriorityLevel:
        """Map bounded numerical score to PriorityLevel enum."""
        if score >= self.THRESHOLD_CRITICAL:
            return PriorityLevel.CRITICAL
        elif score >= self.THRESHOLD_HIGH:
            return PriorityLevel.HIGH
        elif score >= self.THRESHOLD_MEDIUM:
            return PriorityLevel.MEDIUM
        return PriorityLevel.LOW

    def score(
        self,
        alert: DetectionAlert,
        context: Optional[Dict[str, Any]] = None,
    ) -> ScoredAlert:
        """Calculate explainable score for a DetectionAlert.

        Args:
            alert: The input DetectionAlert from baseline detector or cross-layer correlator.
            context: Optional contextual metadata (e.g. resource_criticality, maintenance_window).

        Returns:
            ScoredAlert envelope containing original alert and PriorityScoreResult.
        """
        ctx = context or {}
        contributions: Dict[str, float] = {}
        uncertainties: List[str] = []
        missing_fields: List[str] = []
        explanations: List[str] = []

        total_score = 0.0

        # Factor 1: Detection Evidence Strength (max 35.0)
        # Deduplicate evidence IDs so duplicate inputs do not inflate the score
        evidence_ids = sorted(list(set(alert.evidence_event_ids or [])))
        ev_count = len(evidence_ids)

        if alert.rule_id == CROSS_LAYER_RULE_ID:
            # Cross-layer telemetry: both CloudTrail and VPC Flow records are confirmed
            ev_score = 30.0
            if ev_count > 2:
                # Additional matching flow records provide extra corroborating evidence (capped at +5.0)
                ev_score = min(35.0, ev_score + (ev_count - 2) * 2.5)
            contributions["evidence_strength"] = ev_score
            explanations.append(
                f"Multi-source cross-layer evidence confirmed ({ev_count} distinct event records, +{ev_score:.1f})"
            )
        elif alert.rule_id == NETWORK_BASELINE_RULE_ID:
            ev_score = 20.0
            if ev_count > 1:
                ev_score = min(25.0, ev_score + (ev_count - 1) * 2.5)
            contributions["evidence_strength"] = ev_score
            explanations.append(
                f"Single-layer network telemetry evidence ({ev_count} distinct event records, +{ev_score:.1f})"
            )
        else:
            ev_score = 15.0
            contributions["evidence_strength"] = ev_score
            explanations.append(f"Standard finding evidence (+{ev_score:.1f})")

        total_score += ev_score

        # Factor 2: Policy Deviation (max 25.0)
        # Check if alert details indicate unapproved or explicitly forbidden traffic
        eval_reason = alert.details.get("evaluation_reason", "")
        is_maintenance = ctx.get("is_authorized_maintenance", False) or "maintenance" in eval_reason.lower()

        if is_maintenance:
            # Authorized maintenance window reduces priority
            policy_score = 5.0
            contributions["policy_deviation"] = policy_score
            explanations.append(
                f"Activity falls within an authorized maintenance context or exception (+{policy_score:.1f})"
            )
        elif "explicitly forbidden" in eval_reason.lower():
            policy_score = 25.0
            contributions["policy_deviation"] = policy_score
            explanations.append(
                f"Traffic violates explicit high-priority policy denial rule (+{policy_score:.1f})"
            )
        elif alert.rule_id == CROSS_LAYER_RULE_ID:
            # By default cross-layer ingress modifications create new reachability
            policy_score = 20.0
            contributions["policy_deviation"] = policy_score
            explanations.append(
                f"Configuration change altered network perimeter reachability (+{policy_score:.1f})"
            )
        else:
            policy_score = 15.0
            contributions["policy_deviation"] = policy_score
            explanations.append(
                f"Unapproved flow observed outside approved communication baseline (+{policy_score:.1f})"
            )

        total_score += policy_score

        # Factor 3: Configuration Correlation & Enablement (max 20.0)
        if alert.rule_id == CROSS_LAYER_RULE_ID:
            # Confirmed temporal and rule enablement
            config_score = 20.0
            contributions["config_correlation"] = config_score
            explanations.append(
                f"Administrative rule change demonstrably enabled the observed flow parameters (+{config_score:.1f})"
            )
        else:
            config_score = 0.0
            contributions["config_correlation"] = 0.0
            explanations.append("No correlating administrative configuration event identified (+0.0)")

        total_score += config_score

        # Factor 4: Resource Criticality Impact (max 20.0)
        # ONLY apply if explicitly provided in context; never fabricate
        resource_criticality = ctx.get("resource_criticality")
        if resource_criticality:
            crit_key = str(resource_criticality).lower()
            impact_score = self.criticality_weights.get(crit_key, 0.0)
            contributions["resource_impact"] = impact_score
            explanations.append(
                f"Target resource criticality verified as '{resource_criticality}' (+{impact_score:.1f})"
            )
        else:
            contributions["resource_impact"] = 0.0
            missing_fields.append("resource_criticality")
            uncertainties.append(
                "Resource criticality metadata is absent; score assumes baseline impact without speculation."
            )
            explanations.append("Resource criticality unassigned in telemetry (+0.0)")

        total_score += contributions["resource_impact"]

        # Factor 5: Uncertainty & Ambiguity Adjustments (Penalties / Deductions)
        uncertainty_penalty = 0.0

        # Check for ambiguous resource mapping
        if ctx.get("is_ambiguous_resource_mapping", False) or alert.details.get("is_ambiguous_mapping"):
            uncertainty_penalty += 15.0
            uncertainties.append(
                "Ambiguous resource/IP mapping: IP maps to multiple potential target resources."
            )

        # Check for missing timestamps in evidence
        if ctx.get("missing_timestamp", False) or alert.created_at is None:
            uncertainty_penalty += 10.0
            missing_fields.append("timestamp")
            uncertainties.append(
                "Evidence lacks exact temporal precision; sequence causality cannot be fully verified."
            )

        if "uncertainty_note" in alert.details:
            uncertainties.append(alert.details["uncertainty_note"])

        if uncertainty_penalty > 0.0:
            contributions["uncertainty_penalty"] = -uncertainty_penalty
            total_score = max(0.0, total_score - uncertainty_penalty)
            explanations.append(f"Uncertainty deduction applied (-{uncertainty_penalty:.1f})")

        # Bounding to [0.0, 100.0]
        final_score = round(max(0.0, min(100.0, total_score)), 1)
        priority_level = self._determine_priority_level(final_score)

        # Overall summary narrative
        explanations.append(
            f"Final score {final_score}/100 maps to {priority_level.value.upper()} priority. "
            "NOTE: This score reflects triage priority and evidence completeness; "
            "it is not a calibrated probability of compromise."
        )

        full_explanation = " | ".join(explanations)

        score_res = PriorityScoreResult(
            final_score=final_score,
            priority_level=priority_level,
            factor_contributions=contributions,
            explanation=full_explanation,
            uncertainty_reasons=uncertainties,
            scoring_version=self.scorer_version,
            missing_fields=missing_fields,
        )

        return ScoredAlert(alert=alert, score_result=score_res)
