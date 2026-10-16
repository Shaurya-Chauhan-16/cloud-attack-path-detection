"""Unit and round-trip tests for exported evaluation fixtures."""
import json
import os
import pytest

from src.shared.models import BaseTelemetryEvent, ConfigurationHistory, ApprovedCommunicationPolicy
from src.detection.evaluation.metrics import EvaluationScenario, GroundTruthCase
from src.detection.evaluation.scenarios import create_standard_evaluation_scenarios


def test_round_trip_fixture_serialization_and_deserialization():
    """Verify that exported fixtures deserialize identically to the original scenarios."""
    dev_inputs_path = os.path.join("fixtures", "evaluation", "development", "telemetry_and_config.json")
    dev_gt_path = os.path.join("fixtures", "evaluation", "development", "ground_truth.json")

    assert os.path.exists(dev_inputs_path)
    assert os.path.exists(dev_gt_path)

    with open(dev_inputs_path, "r", encoding="utf-8") as f:
        inputs_data = json.load(f)

    with open(dev_gt_path, "r", encoding="utf-8") as f:
        gt_data = json.load(f)

    assert len(inputs_data) == 8
    assert len(gt_data) == 8

    # Reconstruct first scenario and verify
    first_input = inputs_data[0]
    first_gt = gt_data[0]

    reconstructed_events = [BaseTelemetryEvent.model_validate(e) for e in first_input["events"]]
    reconstructed_config = (
        ConfigurationHistory.model_validate(first_input["configuration_history"])
        if first_input["configuration_history"]
        else None
    )
    reconstructed_policy = (
        ApprovedCommunicationPolicy.model_validate(first_input["policy"])
        if first_input["policy"]
        else None
    )
    reconstructed_gt = GroundTruthCase.model_validate(first_gt)

    reconstructed_scenario = EvaluationScenario(
        scenario_id=first_input["scenario_id"],
        events=reconstructed_events,
        configuration_history=reconstructed_config,
        policy=reconstructed_policy,
        ground_truth=reconstructed_gt,
    )

    original_scenarios = create_standard_evaluation_scenarios()
    original_first = original_scenarios[0]

    assert reconstructed_scenario.scenario_id == original_first.scenario_id
    assert len(reconstructed_scenario.events) == len(original_first.events)
    assert reconstructed_scenario.events[0].event_id == original_first.events[0].event_id
    assert reconstructed_scenario.ground_truth.is_positive_finding == original_first.ground_truth.is_positive_finding


def test_leak_free_payload_isolation():
    """Verify that telemetry_and_config.json contains NO ground-truth labels."""
    for split in ["development", "held_out"]:
        input_path = os.path.join("fixtures", "evaluation", split, "telemetry_and_config.json")
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for item in data:
            assert "ground_truth" not in item
            assert "is_positive_finding" not in item
            assert "expected_relationships" not in item
            assert "expected_rule_id" not in item
