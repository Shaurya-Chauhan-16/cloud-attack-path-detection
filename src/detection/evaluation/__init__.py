"""Evaluation package initialisation."""
from src.detection.evaluation.metrics import (
    ClassificationMetrics,
    EvaluationScenario,
    GroundTruthCase,
    RelationshipMetrics,
    ScenarioEvaluationResult,
    calculate_classification_metrics,
    calculate_relationship_metrics,
    run_detector_evaluation,
)

__all__ = [
    "ClassificationMetrics",
    "EvaluationScenario",
    "GroundTruthCase",
    "RelationshipMetrics",
    "ScenarioEvaluationResult",
    "calculate_classification_metrics",
    "calculate_relationship_metrics",
    "run_detector_evaluation",
]
