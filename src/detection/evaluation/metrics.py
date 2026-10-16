"""Evaluation metrics and comparative analysis framework.

Implements rigorous, leak-free comparative evaluation for:
- Approach A: Network-only baseline detector.
- Approach B: Cross-layer correlation detector.

Metrics:
- Case-level Precision, Recall, F1, False Positive Rate (FPR), False Discovery Rate (FDR).
- Relationship Reconstruction Precision, Recall, F1.
- Monotonic processing latency (per-scenario and total).
- Confusion matrix counts (TP, FP, TN, FN).
"""
from dataclasses import dataclass, field
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from src.shared.models import (
    ApprovedCommunicationPolicy,
    BaseTelemetryEvent,
    ConfigurationHistory,
    DetectionAlert,
)


class ExpectedRelationship(BaseModel):
    """Ground-truth expected relationship linking administrative and network events."""
    config_event_id: str
    flow_event_id: str
    resource_id: str
    relation_type: str = "inferred_sequence"


class GroundTruthCase(BaseModel):
    """Isolated ground-truth specification for an evaluation scenario."""
    scenario_id: str
    category: str
    description: str
    is_positive_finding: bool  # True if expected to be flagged as unauthorized/anomalous
    expected_rule_id: Optional[str] = None
    expected_relationships: List[ExpectedRelationship] = Field(default_factory=list)


class EvaluationScenario(BaseModel):
    """Evaluation bundle containing input telemetry and decoupled ground truth."""
    scenario_id: str
    events: List[BaseTelemetryEvent] = Field(default_factory=list)
    configuration_history: Optional[ConfigurationHistory] = None
    policy: Optional[ApprovedCommunicationPolicy] = None
    ground_truth: GroundTruthCase


class ClassificationMetrics(BaseModel):
    """Case-level classification performance metrics with explicit zero-denominator handling."""
    total_cases: int = 0
    positive_ground_truth: int = 0
    negative_ground_truth: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    false_positive_rate: float = 0.0
    false_discovery_rate: float = 0.0


class RelationshipMetrics(BaseModel):
    """Linkage/Relationship reconstruction accuracy metrics."""
    expected_relationships: int = 0
    predicted_relationships: int = 0
    true_positive_relationships: int = 0
    false_positive_relationships: int = 0
    false_negative_relationships: int = 0
    precision: Optional[float] = None  # None if predicted_relationships == 0 (undefined)
    recall: Optional[float] = None     # None if expected_relationships == 0 (undefined)
    f1_score: Optional[float] = None   # None if precision or recall is None or sum is 0
    precision_status: str = "evaluated"
    recall_status: str = "evaluated"


class ScenarioEvaluationResult(BaseModel):
    """Per-scenario detector evaluation results."""
    scenario_id: str
    category: str
    ground_truth_positive: bool
    predicted_positive: bool
    is_true_positive: bool
    is_false_positive: bool
    is_true_negative: bool
    is_false_negative: bool
    alert_count: int
    alert_ids: List[str] = Field(default_factory=list)
    processing_latency_ms: float = 0.0


class ComparativeEvaluationReport(BaseModel):
    """Complete machine-readable comparative evaluation output."""
    dataset_name: str
    dataset_version: str
    scenario_count: int
    total_events_processed: int
    detector_a_baseline: Dict[str, Any]
    detector_b_cross_layer: Dict[str, Any]
    absolute_differences: Dict[str, Any]
    limitations_and_assumptions: List[str]


def calculate_classification_metrics(
    tp: int, fp: int, tn: int, fn: int
) -> ClassificationMetrics:
    """Calculate precision, recall, F1, FPR, and FDR deterministically."""
    total = tp + fp + tn + fn
    pos_gt = tp + fn
    neg_gt = fp + tn

    # Precision = TP / (TP + FP)
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0

    # Recall = TP / (TP + FN)
    recall = (tp / pos_gt) if pos_gt > 0 else 0.0

    # F1 Score
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    # False Positive Rate = FP / (FP + TN)
    fpr = (fp / neg_gt) if neg_gt > 0 else 0.0

    # False Discovery Rate = FP / (TP + FP)
    fdr = (fp / (tp + fp)) if (tp + fp) > 0 else 0.0

    return ClassificationMetrics(
        total_cases=total,
        positive_ground_truth=pos_gt,
        negative_ground_truth=neg_gt,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        false_positive_rate=round(fpr, 4),
        false_discovery_rate=round(fdr, 4),
    )


def calculate_relationship_metrics(
    expected: List[ExpectedRelationship],
    predicted_alerts: List[DetectionAlert],
    detector_supports_relationships: bool = True,
) -> RelationshipMetrics:
    """Evaluate accuracy of reconstructed relationships between configuration and flows.
    
    Convention for undefined metrics:
    - If detector does not support relationship reconstruction, precision and recall are None (status="not_supported").
    - If 0 relationships predicted: precision is None (status="undefined (zero predictions)"), F1 is None.
    - If 0 ground-truth relationships exist: recall is None (status="undefined (zero ground truth)"), F1 is None.
    - If both exist: precision = TP / Pred, recall = TP / Exp, F1 = 2*P*R / (P+R).
    """
    if not detector_supports_relationships:
        return RelationshipMetrics(
            expected_relationships=len(expected),
            predicted_relationships=0,
            true_positive_relationships=0,
            false_positive_relationships=0,
            false_negative_relationships=len(expected),
            precision=None,
            recall=0.0 if expected else None,
            f1_score=None,
            precision_status="not_supported (detector does not predict relationships)",
            recall_status="evaluated" if expected else "undefined (zero ground truth)",
        )

    expected_tuples: Set[Tuple[str, str, str]] = {
        (e.config_event_id, e.flow_event_id, e.resource_id) for e in expected
    }

    predicted_tuples: Set[Tuple[str, str, str]] = set()
    for alert in predicted_alerts:
        ct_id = alert.details.get("cloudtrail_event_id")
        flow_ids = alert.details.get("flow_event_ids") or [
            eid for eid in alert.evidence_event_ids if eid != ct_id
        ]
        res_ids = alert.related_resource_ids or [""]

        if ct_id and flow_ids:
            for fid in flow_ids:
                for rid in res_ids:
                    predicted_tuples.add((ct_id, fid, rid))

    tp_rel = len(expected_tuples.intersection(predicted_tuples))
    fp_rel = len(predicted_tuples - expected_tuples)
    fn_rel = len(expected_tuples - predicted_tuples)

    # Precision
    if predicted_tuples:
        prec = round(tp_rel / len(predicted_tuples), 4)
        prec_status = "evaluated"
    else:
        prec = None
        prec_status = "undefined (zero predicted relationships)"

    # Recall
    if expected_tuples:
        rec = round(tp_rel / len(expected_tuples), 4)
        rec_status = "evaluated"
    else:
        rec = None
        rec_status = "undefined (zero ground-truth relationships)"

    # F1
    if prec is not None and rec is not None and (prec + rec) > 0:
        f1 = round((2 * prec * rec) / (prec + rec), 4)
    else:
        f1 = None

    return RelationshipMetrics(
        expected_relationships=len(expected_tuples),
        predicted_relationships=len(predicted_tuples),
        true_positive_relationships=tp_rel,
        false_positive_relationships=fp_rel,
        false_negative_relationships=fn_rel,
        precision=prec,
        recall=rec,
        f1_score=f1,
        precision_status=prec_status,
        recall_status=rec_status,
    )


def run_detector_evaluation(
    detector_name: str,
    detect_fn: Callable[[List[BaseTelemetryEvent], Optional[ConfigurationHistory], Optional[ApprovedCommunicationPolicy]], List[DetectionAlert]],
    scenarios: List[EvaluationScenario],
    detector_supports_relationships: bool = True,
) -> Tuple[ClassificationMetrics, RelationshipMetrics, List[ScenarioEvaluationResult], float]:

    """Execute evaluation harness on a collection of scenarios using monotonic clock timing."""
    scenario_results: List[ScenarioEvaluationResult] = []
    all_expected_rels: List[ExpectedRelationship] = []
    all_predicted_alerts: List[DetectionAlert] = []

    tp = fp = tn = fn = 0
    t_start = time.perf_counter()

    for sc in scenarios:
        gt = sc.ground_truth
        all_expected_rels.extend(gt.expected_relationships)

        # STRICT ISOLATION SAFEGUARD: Pass only telemetry, configuration_history, and policy
        t_sc_start = time.perf_counter()
        alerts = detect_fn(sc.events, sc.configuration_history, sc.policy)
        t_sc_end = time.perf_counter()

        latency_ms = (t_sc_end - t_sc_start) * 1000.0
        all_predicted_alerts.extend(alerts)

        predicted_pos = len(alerts) > 0
        actual_pos = gt.is_positive_finding

        is_tp = actual_pos and predicted_pos
        is_fp = (not actual_pos) and predicted_pos
        is_tn = (not actual_pos) and (not predicted_pos)
        is_fn = actual_pos and (not predicted_pos)

        if is_tp:
            tp += 1
        elif is_fp:
            fp += 1
        elif is_tn:
            tn += 1
        elif is_fn:
            fn += 1

        scenario_results.append(
            ScenarioEvaluationResult(
                scenario_id=sc.scenario_id,
                category=gt.category,
                ground_truth_positive=actual_pos,
                predicted_positive=predicted_pos,
                is_true_positive=is_tp,
                is_false_positive=is_fp,
                is_true_negative=is_tn,
                is_false_negative=is_fn,
                alert_count=len(alerts),
                alert_ids=[a.alert_id for a in alerts],
                processing_latency_ms=round(latency_ms, 3),
            )
        )

    t_end = time.perf_counter()
    total_time_ms = (t_end - t_start) * 1000.0

    cls_metrics = calculate_classification_metrics(tp, fp, tn, fn)
    rel_metrics = calculate_relationship_metrics(
        all_expected_rels, all_predicted_alerts, detector_supports_relationships
    )

    return cls_metrics, rel_metrics, scenario_results, total_time_ms

