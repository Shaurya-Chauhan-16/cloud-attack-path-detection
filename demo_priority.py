"""Synthetic demonstration of Explainable PriorityScorer."""
import json
from datetime import datetime, timezone
from src.shared.constants import CROSS_LAYER_RULE_ID
from src.shared.enums import PriorityLevel
from src.shared.models import DetectionAlert
from src.detection.scoring.priority import PriorityScorer

def run_demo():
    t0 = datetime.now(timezone.utc)

    # Cross-layer alert
    alert = DetectionAlert(
        alert_id="alert-demo-99",
        rule_id=CROSS_LAYER_RULE_ID,
        rule_version="1.0.0",
        priority=PriorityLevel.HIGH,
        explanation="Security group rule change enabled accepted ingress flow",
        evidence_event_ids=["ct-evt-101", "flow-evt-202"],
        related_resource_ids=["eni-core-prod-db"],
        created_at=t0,
        details={
            "cloudtrail_event_id": "ct-evt-101",
            "security_group_id": "sg-database",
            "uncertainty_note": "Reachability verified; application compromise unproven.",
        },
    )

    scorer = PriorityScorer()

    # Score with explicit target asset criticality context
    scored = scorer.score(alert, context={"resource_criticality": "high"})

    print(json.dumps(scored.model_dump(mode="json"), indent=2))

if __name__ == "__main__":
    run_demo()
