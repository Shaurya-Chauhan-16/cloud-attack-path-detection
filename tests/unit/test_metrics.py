"""Unit tests for Evaluation Metrics (Phase 5)."""
from datetime import datetime, timezone
import pytest

from src.shared.enums import PriorityLevel
from src.shared.models import DetectionAlert
from src.detection.evaluation.metrics import (
    ClassificationMetrics,
    ExpectedRelationship,
    RelationshipMetrics,
    calculate_classification_metrics,
    calculate_relationship_metrics,
)


def test_perfect_predictions_produce_expected_metrics():
    """1. Perfect predictions: TP=10, FP=0, TN=10, FN=0 -> Precision=1.0, Recall=1.0, F1=1.0, FPR=0.0."""
    m = calculate_classification_metrics(tp=10, fp=0, tn=10, fn=0)
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1_score == 1.0
    assert m.false_positive_rate == 0.0
    assert m.false_discovery_rate == 0.0


def test_all_negative_predictions():
    """2. All-negative predictions: TP=0, FP=0, TN=10, FN=5 -> Recall=0.0, FPR=0.0."""
    m = calculate_classification_metrics(tp=0, fp=0, tn=10, fn=5)
    assert m.recall == 0.0
    assert m.precision == 0.0
    assert m.f1_score == 0.0
    assert m.false_positive_rate == 0.0


def test_all_positive_predictions():
    """3. All-positive predictions: TP=10, FP=10, TN=0, FN=0 -> Recall=1.0, Precision=0.5, FPR=1.0."""
    m = calculate_classification_metrics(tp=10, fp=10, tn=0, fn=0)
    assert m.recall == 1.0
    assert m.precision == 0.5
    assert m.false_positive_rate == 1.0
    assert m.false_discovery_rate == 0.5


def test_no_predicted_positives():
    """4. No predicted positives handled safely with zero division prevention."""
    m = calculate_classification_metrics(tp=0, fp=0, tn=5, fn=0)
    assert m.precision == 0.0
    assert m.recall == 0.0
    assert m.f1_score == 0.0


def test_no_ground_truth_positives():
    """5. No ground truth positives: TP=0, FP=2, TN=8, FN=0 -> FPR = 2/10 = 0.2."""
    m = calculate_classification_metrics(tp=0, fp=2, tn=8, fn=0)
    assert m.recall == 0.0
    assert m.precision == 0.0
    assert m.false_positive_rate == 0.2
    assert m.false_discovery_rate == 1.0


def test_confusion_matrix_counts():
    """6. Confusion matrix counts sum up correctly."""
    m = calculate_classification_metrics(tp=3, fp=2, tn=4, fn=1)
    assert m.total_cases == 10
    assert m.positive_ground_truth == 4
    assert m.negative_ground_truth == 6


def test_fpr_vs_fdr_distinction():
    """8. False Positive Rate (FP / (FP + TN)) is clearly distinct from False Discovery Rate (FP / (TP + FP))."""
    # TP=8, FP=2, TN=8, FN=2
    # FPR = 2 / (2 + 8) = 0.20
    # FDR = 2 / (8 + 2) = 0.20
    m1 = calculate_classification_metrics(tp=8, fp=2, tn=8, fn=2)
    assert m1.false_positive_rate == 0.2
    assert m1.false_discovery_rate == 0.2

    # TP=18, FP=2, TN=8, FN=2
    # FPR = 2 / (2 + 8) = 0.20
    # FDR = 2 / (18 + 2) = 0.10
    m2 = calculate_classification_metrics(tp=18, fp=2, tn=8, fn=2)
    assert m2.false_positive_rate == 0.20
    assert m2.false_discovery_rate == 0.10


def test_correct_relationship_matching():
    """9. Correct relationship matching between expected and predicted links."""
    expected = [
        ExpectedRelationship(config_event_id="ct-1", flow_event_id="fl-1", resource_id="eni-1"),
        ExpectedRelationship(config_event_id="ct-2", flow_event_id="fl-2", resource_id="eni-2"),
    ]

    predicted_alerts = [
        DetectionAlert(
            alert_id="a1",
            rule_id="CORR-CROSS-001",
            rule_version="1.0.0",
            priority=PriorityLevel.HIGH,
            explanation="Test",
            evidence_event_ids=["ct-1", "fl-1"],
            related_resource_ids=["eni-1"],
            created_at=datetime.now(timezone.utc),
            details={"cloudtrail_event_id": "ct-1", "flow_event_ids": ["fl-1"]},
        ),
        DetectionAlert(
            alert_id="a2",
            rule_id="CORR-CROSS-001",
            rule_version="1.0.0",
            priority=PriorityLevel.HIGH,
            explanation="Test",
            evidence_event_ids=["ct-2", "fl-2"],
            related_resource_ids=["eni-2"],
            created_at=datetime.now(timezone.utc),
            details={"cloudtrail_event_id": "ct-2", "flow_event_ids": ["fl-2"]},
        ),
    ]

    rel_metrics = calculate_relationship_metrics(expected, predicted_alerts)
    assert rel_metrics.true_positive_relationships == 2
    assert rel_metrics.false_positive_relationships == 0
    assert rel_metrics.false_negative_relationships == 0
    assert rel_metrics.precision == 1.0
    assert rel_metrics.recall == 1.0


def test_missing_and_extra_relationships():
    """10 & 11. Missing and extra relationships counted accurately."""
    expected = [
        ExpectedRelationship(config_event_id="ct-1", flow_event_id="fl-1", resource_id="eni-1"),
        ExpectedRelationship(config_event_id="ct-missing", flow_event_id="fl-m", resource_id="eni-m"),
    ]

    predicted_alerts = [
        DetectionAlert(
            alert_id="a1",
            rule_id="CORR-CROSS-001",
            rule_version="1.0.0",
            priority=PriorityLevel.HIGH,
            explanation="Test",
            evidence_event_ids=["ct-1", "fl-1"],
            related_resource_ids=["eni-1"],
            created_at=datetime.now(timezone.utc),
            details={"cloudtrail_event_id": "ct-1", "flow_event_ids": ["fl-1"]},
        ),
        DetectionAlert(
            alert_id="a-extra",
            rule_id="CORR-CROSS-001",
            rule_version="1.0.0",
            priority=PriorityLevel.HIGH,
            explanation="Extra",
            evidence_event_ids=["ct-extra", "fl-extra"],
            related_resource_ids=["eni-x"],
            created_at=datetime.now(timezone.utc),
            details={"cloudtrail_event_id": "ct-extra", "flow_event_ids": ["fl-extra"]},
        ),
    ]

    rel_metrics = calculate_relationship_metrics(expected, predicted_alerts)
    assert rel_metrics.true_positive_relationships == 1
    assert rel_metrics.false_positive_relationships == 1
    assert rel_metrics.false_negative_relationships == 1
    assert rel_metrics.precision == 0.5
    assert rel_metrics.recall == 0.5


def test_duplicate_findings_do_not_inflate_relationships():
    """12. Duplicate findings for the same relationship do not double-count."""
    expected = [
        ExpectedRelationship(config_event_id="ct-1", flow_event_id="fl-1", resource_id="eni-1")
    ]
    alert = DetectionAlert(
        alert_id="a1",
        rule_id="CORR-CROSS-001",
        rule_version="1.0.0",
        priority=PriorityLevel.HIGH,
        explanation="Test",
        evidence_event_ids=["ct-1", "fl-1"],
        related_resource_ids=["eni-1"],
        created_at=datetime.now(timezone.utc),
        details={"cloudtrail_event_id": "ct-1", "flow_event_ids": ["fl-1"]},
    )

    rel_metrics = calculate_relationship_metrics(expected, [alert, alert])
    assert rel_metrics.predicted_relationships == 1
    assert rel_metrics.true_positive_relationships == 1
    assert rel_metrics.false_positive_relationships == 0


def test_empty_datasets_return_zero_denominator_convention():
    """14. Empty dataset follows documented zero-denominator convention (returns 0.0)."""
    m = calculate_classification_metrics(tp=0, fp=0, tn=0, fn=0)
    assert m.precision == 0.0
    assert m.recall == 0.0
    assert m.f1_score == 0.0
    assert m.total_cases == 0


def test_zero_predicted_relationships_yields_none_precision_and_f1():
    """AUD-01: Zero predicted relationships must yield precision=None and F1=None, preserving recall=0.0."""
    expected = [
        ExpectedRelationship(config_event_id="ct-1", flow_event_id="fl-1", resource_id="eni-1")
    ]
    # No alerts predicted
    rel_m = calculate_relationship_metrics(expected, [])
    assert rel_m.predicted_relationships == 0
    assert rel_m.precision is None
    assert rel_m.f1_score is None
    assert rel_m.recall == 0.0
    assert "undefined (zero predicted relationships)" in rel_m.precision_status
    assert rel_m.recall_status == "evaluated"


def test_zero_ground_truth_relationships_yields_none_recall():
    """AUD-01: Zero ground truth relationships must yield recall=None, not silently assume 1.0."""
    predicted_alert = DetectionAlert(
        alert_id="a1",
        rule_id="CORR-CROSS-001",
        rule_version="1.0.0",
        priority=PriorityLevel.HIGH,
        explanation="Test",
        evidence_event_ids=["ct-1", "fl-1"],
        related_resource_ids=["eni-1"],
        created_at=datetime.now(timezone.utc),
        details={"cloudtrail_event_id": "ct-1", "flow_event_ids": ["fl-1"]},
    )
    rel_m = calculate_relationship_metrics([], [predicted_alert])
    assert rel_m.expected_relationships == 0
    assert rel_m.predicted_relationships == 1
    assert rel_m.precision == 0.0  # FP = 1, TP = 0
    assert rel_m.recall is None
    assert rel_m.f1_score is None
    assert "undefined (zero ground-truth relationships)" in rel_m.recall_status


def test_unsupported_detector_relationships_yields_not_supported_status():
    """AUD-01 & AUD-02: Baseline detector does not predict relationships; precision/F1 must be None."""
    expected = [
        ExpectedRelationship(config_event_id="ct-1", flow_event_id="fl-1", resource_id="eni-1")
    ]
    rel_m = calculate_relationship_metrics(
        expected, [], detector_supports_relationships=False
    )
    assert rel_m.precision is None
    assert rel_m.f1_score is None
    assert rel_m.recall == 0.0
    assert "not_supported" in rel_m.precision_status
