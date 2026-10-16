"""Script to serialize reproducible evaluation fixtures into development and held-out subsets.

Generates:
- fixtures/evaluation/development/
    - telemetry_and_config.json  (detector inputs: events, config_history, policy)
    - ground_truth.json          (evaluation only: labels, expected findings/relationships)
- fixtures/evaluation/held_out/
    - telemetry_and_config.json
    - ground_truth.json
"""
import json
import os
import sys

sys.path.insert(0, os.path.abspath("."))

from src.detection.evaluation.scenarios import create_standard_evaluation_scenarios


def export_fixtures():
    scenarios = create_standard_evaluation_scenarios()

    # Defensible split:
    # Development set (8 scenarios): Core positive and negative functional test scenarios (sc-01 to sc-08)
    # Held-out set (4 scenarios): Edge cases not touched during initial development (sc-09 to sc-12: ambiguous mapping, out-of-order, missing data, revoked rules)
    dev_scenarios = scenarios[:8]
    held_out_scenarios = scenarios[8:]

    splits = [
        ("fixtures/evaluation/development", dev_scenarios),
        ("fixtures/evaluation/held_out", held_out_scenarios),
    ]

    for dir_path, split_data in splits:
        os.makedirs(dir_path, exist_ok=True)

        # 1. Export Detector Inputs (telemetry_and_config.json) - STRICTLY LEAK-FREE
        inputs_payload = []
        gt_payload = []

        for sc in split_data:
            # Inputs only
            sc_input = {
                "scenario_id": sc.scenario_id,
                "events": [e.model_dump(mode="json") for e in sc.events],
                "configuration_history": sc.configuration_history.model_dump(mode="json") if sc.configuration_history else None,
                "policy": sc.policy.model_dump(mode="json") if sc.policy else None,
            }
            inputs_payload.append(sc_input)

            # Ground truth only
            gt_payload.append(sc.ground_truth.model_dump(mode="json"))

        inputs_file = os.path.join(dir_path, "telemetry_and_config.json")
        with open(inputs_file, "w", encoding="utf-8") as f:
            json.dump(inputs_payload, f, indent=2)

        gt_file = os.path.join(dir_path, "ground_truth.json")
        with open(gt_file, "w", encoding="utf-8") as f:
            json.dump(gt_payload, f, indent=2)

        print(f"Exported {len(split_data)} scenarios to {dir_path}/")


if __name__ == "__main__":
    export_fixtures()
