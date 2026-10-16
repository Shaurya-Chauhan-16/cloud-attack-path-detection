"""Integration tests for comparative evaluation engine."""
from datetime import datetime, timezone
import pytest

from src.shared.models import BaseTelemetryEvent, ConfigurationHistory, ApprovedCommunicationPolicy
from src.detection.policy.engine import NetworkBaselineDetector
from src.detection.correlation.cross_layer import CrossLayerCorrelator
from src.detection.evaluation.metrics import (
    ClassificationMetrics,
    RelationshipMetrics,
    run_detector_evaluation,
)
from src.detection.evaluation.scenarios import create_standard_evaluation_scenarios


@pytest.fixture
def eval_scenarios():
    return create_standard_evaluation_scenarios()


def test_baseline_detector_evaluation(eval_scenarios):
    """Run baseline detector across standardized scenarios."""
    def baseline_adapter(events, config, policy):
        detector = NetworkBaselineDetector(policy)
        return detector.detect(events)

    cls_m, rel_m, results, total_time = run_detector_evaluation(
        "Network-Baseline",
        baseline_adapter,
        eval_scenarios,
        detector_supports_relationships=False,
    )

    assert cls_m.total_cases == 12
    # Baseline flags unapproved accepted traffic regardless of configuration changes
    assert cls_m.true_positives > 0
    assert total_time > 0.0
    # Baseline does NOT reconstruct cross-layer relationships
    assert rel_m.predicted_relationships == 0
    assert rel_m.true_positive_relationships == 0
    assert rel_m.precision is None
    assert rel_m.f1_score is None
    assert "not_supported" in rel_m.precision_status



def test_cross_layer_detector_evaluation(eval_scenarios):
    """Run cross-layer correlator across standardized scenarios."""
    def cross_layer_adapter(events, config, policy):
        correlator = CrossLayerCorrelator()
        return correlator.correlate(events, config)

    cls_m, rel_m, results, total_time = run_detector_evaluation(
        "Cross-Layer", cross_layer_adapter, eval_scenarios
    )

    assert cls_m.total_cases == 12
    # Cross-layer correlator specifically identifies scenarios with verified SG change + matching flow
    assert rel_m.expected_relationships == 2
    assert rel_m.true_positive_relationships == 2
    assert rel_m.false_positive_relationships == 0
    assert rel_m.precision == 1.0
    assert rel_m.recall == 1.0
    assert rel_m.f1_score == 1.0


def test_leakage_safeguard_detector_inputs_contain_no_ground_truth(eval_scenarios):
    """Verify that detect function receives ONLY telemetry events, config history, and policy.
    Ground-truth labels, expected findings, and expected relationships are never passed.
    """
    for sc in eval_scenarios:
        # Assert events do not contain ground-truth metadata
        for ev in sc.events:
            assert "ground_truth" not in ev.details
            assert "is_positive" not in ev.details
            assert "expected_rule" not in ev.details
            assert "is_attack" not in ev.details
