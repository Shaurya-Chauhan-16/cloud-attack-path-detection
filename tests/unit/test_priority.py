"""Unit tests for Explainable PriorityScorer (Phase 4)."""
from datetime import datetime, timezone
import pytest

from src.shared.constants import CROSS_LAYER_RULE_ID, NETWORK_BASELINE_RULE_ID
from src.shared.enums import PriorityLevel
from src.shared.models import DetectionAlert
from src.detection.scoring.priority import PriorityScorer


@pytest.fixture
def t0():
    return datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def baseline_alert(t0):
    return DetectionAlert(
        alert_id="alert-bl-001",
        rule_id=NETWORK_BASELINE_RULE_ID,
        rule_version="1.0.0",
        priority=PriorityLevel.MEDIUM,
        explanation="Baseline violation",
        evidence_event_ids=["flow-1"],
        related_resource_ids=["eni-01"],
        created_at=t0,
        details={"evaluation_reason": "No matching approved rule"},
    )


@pytest.fixture
def cross_layer_alert(t0):
    return DetectionAlert(
        alert_id="alert-cl-001",
        rule_id=CROSS_LAYER_RULE_ID,
        rule_version="1.0.0",
        priority=PriorityLevel.HIGH,
        explanation="Cross layer correlation",
        evidence_event_ids=["ct-1", "flow-1"],
        related_resource_ids=["eni-01"],
        created_at=t0,
        details={
            "cloudtrail_event_id": "ct-1",
            "security_group_id": "sg-1",
            "uncertainty_note": "Reachability without confirmed compromise",
        },
    )


def test_identical_input_produces_identical_score(baseline_alert):
    """1. Determinism: Identical inputs produce identical scores."""
    scorer = PriorityScorer()
    res1 = scorer.score(baseline_alert)
    res2 = scorer.score(baseline_alert)

    assert res1.score_result.final_score == res2.score_result.final_score
    assert res1.score_result.priority_level == res2.score_result.priority_level
    assert res1.score_result.factor_contributions == res2.score_result.factor_contributions


def test_scores_remain_within_documented_range(baseline_alert, cross_layer_alert):
    """2. Bounds check: Scores strictly remain in [0.0, 100.0]."""
    scorer = PriorityScorer()
    s1 = scorer.score(baseline_alert).score_result.final_score
    s2 = scorer.score(cross_layer_alert).score_result.final_score

    assert 0.0 <= s1 <= 100.0
    assert 0.0 <= s2 <= 100.0


def test_stronger_evidence_increases_priority(baseline_alert, cross_layer_alert):
    """3. Cross-layer correlated alert receives higher score than network-only baseline."""
    scorer = PriorityScorer()
    bl_score = scorer.score(baseline_alert).score_result.final_score
    cl_score = scorer.score(cross_layer_alert).score_result.final_score

    assert cl_score > bl_score


def test_policy_violation_distinguished_from_explicit_deny(baseline_alert):
    """4. An explicit forbidden rule denial scores higher than generic baseline deviation."""
    scorer = PriorityScorer()
    standard_res = scorer.score(baseline_alert)

    explicit_deny_alert = baseline_alert.model_copy(deep=True)
    explicit_deny_alert.details["evaluation_reason"] = "Explicitly forbidden by policy rule RULE-DENY-SSH"

    deny_res = scorer.score(explicit_deny_alert)
    assert deny_res.score_result.factor_contributions["policy_deviation"] > standard_res.score_result.factor_contributions["policy_deviation"]
    assert deny_res.score_result.final_score > standard_res.score_result.final_score


def test_configuration_correlation_credit_only_for_cross_layer(baseline_alert, cross_layer_alert):
    """5. Network-only baseline receives 0 config_correlation credit."""
    scorer = PriorityScorer()
    bl_res = scorer.score(baseline_alert)
    cl_res = scorer.score(cross_layer_alert)

    assert bl_res.score_result.factor_contributions["config_correlation"] == 0.0
    assert cl_res.score_result.factor_contributions["config_correlation"] == 20.0


def test_authorized_maintenance_context_reduces_priority(cross_layer_alert):
    """6. Explicit authorized maintenance context lowers priority score."""
    scorer = PriorityScorer()
    standard_res = scorer.score(cross_layer_alert)

    maint_context = {"is_authorized_maintenance": True}
    maint_res = scorer.score(cross_layer_alert, context=maint_context)

    assert maint_res.score_result.final_score < standard_res.score_result.final_score
    assert maint_res.score_result.factor_contributions["policy_deviation"] == 5.0


def test_missing_resource_criticality_does_not_invent_impact(cross_layer_alert):
    """7. Missing resource criticality does not fabricate an impact value."""
    scorer = PriorityScorer()
    res = scorer.score(cross_layer_alert, context={})

    assert res.score_result.factor_contributions["resource_impact"] == 0.0
    assert "resource_criticality" in res.score_result.missing_fields


def test_explicit_criticality_properly_applied(cross_layer_alert):
    """7b. When reliable criticality metadata is present, it appropriately contributes to the score."""
    scorer = PriorityScorer()
    res = scorer.score(cross_layer_alert, context={"resource_criticality": "critical"})

    assert res.score_result.factor_contributions["resource_impact"] == 20.0
    assert res.score_result.final_score >= 85.0
    assert res.score_result.priority_level == PriorityLevel.CRITICAL


def test_ambiguous_resource_mapping_in_uncertainty_output(cross_layer_alert):
    """8. Ambiguous resource mapping incurs a penalty and is noted in uncertainty reasons."""
    scorer = PriorityScorer()
    res = scorer.score(cross_layer_alert, context={"is_ambiguous_resource_mapping": True})

    assert res.score_result.factor_contributions.get("uncertainty_penalty") == -15.0
    assert any("Ambiguous resource" in r for r in res.score_result.uncertainty_reasons)


def test_missing_timestamp_penalty(cross_layer_alert):
    """9. Missing timestamps are flagged and deducted."""
    scorer = PriorityScorer()
    res = scorer.score(cross_layer_alert, context={"missing_timestamp": True})

    assert any("temporal precision" in r for r in res.score_result.uncertainty_reasons)
    assert "timestamp" in res.score_result.missing_fields


def test_duplicate_evidence_does_not_inflate_score(t0):
    """10. Duplicate evidence event IDs are deduplicated and do not inflate evidence score."""
    scorer = PriorityScorer()
    alert_unique = DetectionAlert(
        alert_id="a1",
        rule_id=NETWORK_BASELINE_RULE_ID,
        rule_version="1.0.0",
        priority=PriorityLevel.MEDIUM,
        explanation="Unique",
        evidence_event_ids=["flow-1"],
        related_resource_ids=["eni-1"],
        created_at=t0,
    )
    alert_dups = DetectionAlert(
        alert_id="a2",
        rule_id=NETWORK_BASELINE_RULE_ID,
        rule_version="1.0.0",
        priority=PriorityLevel.MEDIUM,
        explanation="Dups",
        evidence_event_ids=["flow-1", "flow-1", "flow-1"],  # Repeated duplicate IDs
        related_resource_ids=["eni-1"],
        created_at=t0,
    )

    r1 = scorer.score(alert_unique)
    r2 = scorer.score(alert_dups)
    assert r1.score_result.factor_contributions["evidence_strength"] == r2.score_result.factor_contributions["evidence_strength"]


def test_changing_one_factor_has_explainable_effect(baseline_alert):
    """12. Modifying a single factor (e.g. adding resource criticality) has a testable delta."""
    scorer = PriorityScorer()
    s_base = scorer.score(baseline_alert, context={}).score_result.final_score
    s_high = scorer.score(baseline_alert, context={"resource_criticality": "high"}).score_result.final_score

    assert s_high - s_base == 15.0


def test_boundary_values_and_severity_thresholds(baseline_alert):
    """13. Threshold mapping works properly across boundary intervals."""
    scorer = PriorityScorer()
    assert scorer._determine_priority_level(85.0) == PriorityLevel.CRITICAL
    assert scorer._determine_priority_level(84.9) == PriorityLevel.HIGH
    assert scorer._determine_priority_level(60.0) == PriorityLevel.HIGH
    assert scorer._determine_priority_level(59.9) == PriorityLevel.MEDIUM
    assert scorer._determine_priority_level(30.0) == PriorityLevel.MEDIUM
    assert scorer._determine_priority_level(29.9) == PriorityLevel.LOW


def test_scoring_preserves_original_alert_evidence(cross_layer_alert):
    """15. Scored envelope preserves the original alert unmodified."""
    scorer = PriorityScorer()
    scored = scorer.score(cross_layer_alert)

    assert scored.alert.alert_id == cross_layer_alert.alert_id
    assert scored.alert.evidence_event_ids == cross_layer_alert.evidence_event_ids


def test_score_not_exposed_as_probability(cross_layer_alert):
    """16. Explanations clearly state the score is not a probability of compromise."""
    scorer = PriorityScorer()
    scored = scorer.score(cross_layer_alert)

    assert "not a calibrated probability of compromise" in scored.score_result.explanation
