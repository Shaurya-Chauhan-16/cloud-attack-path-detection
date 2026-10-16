"""Generator for standardized, leak-free evaluation scenarios."""
from datetime import datetime, timezone, timedelta
from typing import List

from src.shared.enums import EventSource, PolicyDecision
from src.shared.models import (
    ApprovedCommunicationPolicy,
    BaseTelemetryEvent,
    ConfigurationHistory,
    PolicyRule,
    SecurityGroupAttachment,
)
from src.detection.evaluation.metrics import (
    EvaluationScenario,
    ExpectedRelationship,
    GroundTruthCase,
)


def create_standard_evaluation_scenarios() -> List[EvaluationScenario]:
    """Generates 12 standardized evaluation scenarios covering all required evaluation categories."""
    t0 = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)

    # Standard policy: Only HTTPS to 10.0.1.10 is approved
    standard_policy = ApprovedCommunicationPolicy(
        policy_id="eval-policy",
        rules=[
            PolicyRule(
                rule_id="RULE-HTTPS-APPROVED",
                source="*",
                destination="10.0.1.10",
                protocol="tcp",
                destination_port=443,
                action=PolicyDecision.APPROVED,
            )
        ],
    )

    # Standard configuration: eni-target is attached to sg-target
    standard_config = ConfigurationHistory(
        attachments=[
            SecurityGroupAttachment(
                resource_id="eni-target",
                security_group_id="sg-target",
                attached_at=t0 - timedelta(days=1),
            )
        ],
        eni_to_ip_map={"eni-target": ["10.0.1.10"]},
    )

    scenarios: List[EvaluationScenario] = []

    # 1. Normal approved traffic (Negative case)
    scenarios.append(
        EvaluationScenario(
            scenario_id="sc-01-normal-approved",
            events=[
                BaseTelemetryEvent(
                    event_id="fl-01",
                    timestamp=t0,
                    source=EventSource.VPC_FLOW,
                    action="ACCEPT",
                    resource_id="eni-target",
                    source_ip="192.168.1.100",
                    destination_ip="10.0.1.10",
                    destination_port=443,
                    details={"protocol": "tcp"},
                )
            ],
            configuration_history=standard_config,
            policy=standard_policy,
            ground_truth=GroundTruthCase(
                scenario_id="sc-01-normal-approved",
                category="normal_approved",
                description="Legitimate HTTPS traffic conforming to approved policy.",
                is_positive_finding=False,
            ),
        )
    )

    # 2. Authorized maintenance exception (Negative case)
    maint_policy = ApprovedCommunicationPolicy(
        policy_id="eval-maint-pol",
        rules=standard_policy.rules,
        maintenance_exceptions=[
            from_models := __import__("src.shared.models", fromlist=["MaintenanceException"]).MaintenanceException(
                exception_id="MAINT-EV-01",
                description="Scheduled database patch",
                start_time=t0 - timedelta(hours=1),
                end_time=t0 + timedelta(hours=1),
                source="198.51.100.5",
                destination="10.0.1.10",
                protocol="tcp",
                destination_port=22,
            )
        ],
    )
    scenarios.append(
        EvaluationScenario(
            scenario_id="sc-02-authorized-maintenance",
            events=[
                BaseTelemetryEvent(
                    event_id="fl-02",
                    timestamp=t0,
                    source=EventSource.VPC_FLOW,
                    action="ACCEPT",
                    resource_id="eni-target",
                    source_ip="198.51.100.5",
                    destination_ip="10.0.1.10",
                    destination_port=22,
                    details={"protocol": "tcp"},
                )
            ],
            configuration_history=standard_config,
            policy=maint_policy,
            ground_truth=GroundTruthCase(
                scenario_id="sc-02-authorized-maintenance",
                category="authorized_maintenance",
                description="SSH during approved maintenance window.",
                is_positive_finding=False,
            ),
        )
    )

    # 3. Unexpected SG change followed by matching accepted traffic (Positive case)
    scenarios.append(
        EvaluationScenario(
            scenario_id="sc-03-sg-change-matching-flow",
            events=[
                BaseTelemetryEvent(
                    event_id="ct-03",
                    timestamp=t0,
                    source=EventSource.CLOUDTRAIL,
                    action="AuthorizeSecurityGroupIngress",
                    actor="arn:aws:iam::123456789012:user/bad-actor",
                    resource_id="sg-target",
                    details={"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr_ipv4": "0.0.0.0/0"},
                ),
                BaseTelemetryEvent(
                    event_id="fl-03",
                    timestamp=t0 + timedelta(seconds=45),
                    source=EventSource.VPC_FLOW,
                    action="ACCEPT",
                    resource_id="eni-target",
                    source_ip="203.0.113.88",
                    destination_ip="10.0.1.10",
                    destination_port=3389,
                    details={"protocol": "tcp"},
                ),
            ],
            configuration_history=standard_config,
            policy=standard_policy,
            ground_truth=GroundTruthCase(
                scenario_id="sc-03-sg-change-matching-flow",
                category="cross_layer_enablement",
                description="Unauthorized SG change opening port 3389 followed by matching accepted RDP flow.",
                is_positive_finding=True,
                expected_rule_id="CORR-CROSS-001",
                expected_relationships=[
                    ExpectedRelationship(config_event_id="ct-03", flow_event_id="fl-03", resource_id="eni-target")
                ],
            ),
        )
    )

    # 4. Successful SG change without subsequent traffic (Negative flow case)
    scenarios.append(
        EvaluationScenario(
            scenario_id="sc-04-sg-change-no-traffic",
            events=[
                BaseTelemetryEvent(
                    event_id="ct-04",
                    timestamp=t0,
                    source=EventSource.CLOUDTRAIL,
                    action="AuthorizeSecurityGroupIngress",
                    actor="arn:aws:iam::123456789012:user/admin",
                    resource_id="sg-target",
                    details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "0.0.0.0/0"},
                )
            ],
            configuration_history=standard_config,
            policy=standard_policy,
            ground_truth=GroundTruthCase(
                scenario_id="sc-04-sg-change-no-traffic",
                category="config_no_traffic",
                description="Security group opened but no network communication attempted.",
                is_positive_finding=False,
            ),
        )
    )

    # 5. Unrelated SG change and accepted traffic (Negative correlation)
    scenarios.append(
        EvaluationScenario(
            scenario_id="sc-05-unrelated-change-traffic",
            events=[
                BaseTelemetryEvent(
                    event_id="ct-05",
                    timestamp=t0,
                    source=EventSource.CLOUDTRAIL,
                    action="AuthorizeSecurityGroupIngress",
                    resource_id="sg-different",
                    details={"protocol": "tcp", "from_port": 9000, "to_port": 9000, "cidr_ipv4": "10.0.0.0/8"},
                ),
                BaseTelemetryEvent(
                    event_id="fl-05",
                    timestamp=t0 + timedelta(seconds=20),
                    source=EventSource.VPC_FLOW,
                    action="ACCEPT",
                    resource_id="eni-target",
                    source_ip="192.168.1.5",
                    destination_ip="10.0.1.10",
                    destination_port=443,  # Conforms to approved policy!
                    details={"protocol": "tcp"},
                ),
            ],
            configuration_history=standard_config,
            policy=standard_policy,
            ground_truth=GroundTruthCase(
                scenario_id="sc-05-unrelated-change-traffic",
                category="unrelated_telemetry",
                description="Unrelated configuration change on different SG and normal approved HTTPS flow.",
                is_positive_finding=False,
            ),
        )
    )

    # 6. Failed CloudTrail API request (Negative case)
    scenarios.append(
        EvaluationScenario(
            scenario_id="sc-06-failed-api-request",
            events=[
                BaseTelemetryEvent(
                    event_id="ct-06",
                    timestamp=t0,
                    source=EventSource.CLOUDTRAIL,
                    action="AuthorizeSecurityGroupIngress",
                    actor="arn:aws:iam::123456789012:user/intruder",
                    resource_id="sg-target",
                    details={
                        "protocol": "tcp",
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_ipv4": "0.0.0.0/0",
                        "errorCode": "Client.UnauthorizedOperation",
                    },
                )
            ],
            configuration_history=standard_config,
            policy=standard_policy,
            ground_truth=GroundTruthCase(
                scenario_id="sc-06-failed-api-request",
                category="failed_api_call",
                description="Blocked administrative call should not indicate perimeter change.",
                is_positive_finding=False,
            ),
        )
    )

    # 7. Unapproved flow without preceding configuration change (Positive baseline, negative cross-layer)
    scenarios.append(
        EvaluationScenario(
            scenario_id="sc-07-unapproved-flow-no-config-change",
            events=[
                BaseTelemetryEvent(
                    event_id="fl-07",
                    timestamp=t0,
                    source=EventSource.VPC_FLOW,
                    action="ACCEPT",
                    resource_id="eni-target",
                    source_ip="198.51.100.99",
                    destination_ip="10.0.1.10",
                    destination_port=21,  # Unapproved FTP
                    details={"protocol": "tcp"},
                )
            ],
            configuration_history=standard_config,
            policy=standard_policy,
            ground_truth=GroundTruthCase(
                scenario_id="sc-07-unapproved-flow-no-config-change",
                category="unapproved_network_only",
                description="Unapproved flow violating policy without any CloudTrail event.",
                is_positive_finding=True,
                expected_rule_id="NET-BL-001",
            ),
        )
    )

    # 8. Flow outside correlation window (Negative correlation)
    scenarios.append(
        EvaluationScenario(
            scenario_id="sc-08-flow-outside-window",
            events=[
                BaseTelemetryEvent(
                    event_id="ct-08",
                    timestamp=t0,
                    source=EventSource.CLOUDTRAIL,
                    action="AuthorizeSecurityGroupIngress",
                    resource_id="sg-target",
                    details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "0.0.0.0/0"},
                ),
                BaseTelemetryEvent(
                    event_id="fl-08",
                    timestamp=t0 + timedelta(seconds=600),  # 10 minutes later (window is 300s)
                    source=EventSource.VPC_FLOW,
                    action="ACCEPT",
                    resource_id="eni-target",
                    source_ip="198.51.100.10",
                    destination_ip="10.0.1.10",
                    destination_port=8080,
                    details={"protocol": "tcp"},
                ),
            ],
            configuration_history=standard_config,
            policy=standard_policy,
            ground_truth=GroundTruthCase(
                scenario_id="sc-08-flow-outside-window",
                category="outside_window",
                description="Flow exceeds 300s correlation window from config change.",
                is_positive_finding=True,  # Baseline detects unapproved flow, but cross-layer must reject link
                expected_rule_id="NET-BL-001",
            ),
        )
    )

    # 9. Ambiguous resource mapping (Negative correlation)
    ambiguous_config = ConfigurationHistory(
        attachments=standard_config.attachments,
        eni_to_ip_map={"eni-A": ["10.0.1.10"], "eni-B": ["10.0.1.10"]},
    )
    scenarios.append(
        EvaluationScenario(
            scenario_id="sc-09-ambiguous-resource-mapping",
            events=[
                BaseTelemetryEvent(
                    event_id="ct-09",
                    timestamp=t0,
                    source=EventSource.CLOUDTRAIL,
                    action="AuthorizeSecurityGroupIngress",
                    resource_id="sg-target",
                    details={"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ipv4": "0.0.0.0/0"},
                ),
                BaseTelemetryEvent(
                    event_id="fl-09",
                    timestamp=t0 + timedelta(seconds=20),
                    source=EventSource.VPC_FLOW,
                    action="ACCEPT",
                    resource_id=None,  # Ambiguous!
                    source_ip="198.51.100.10",
                    destination_ip="10.0.1.10",
                    destination_port=8080,
                    details={"protocol": "tcp"},
                ),
            ],
            configuration_history=ambiguous_config,
            policy=standard_policy,
            ground_truth=GroundTruthCase(
                scenario_id="sc-09-ambiguous-resource-mapping",
                category="ambiguous_mapping",
                description="Ambiguous IP-to-ENI mapping prevents safe correlation.",
                is_positive_finding=True,  # Baseline detects unapproved flow
                expected_rule_id="NET-BL-001",
            ),
        )
    )

    # 10. Out-of-order telemetry with matching events (Positive case)
    scenarios.append(
        EvaluationScenario(
            scenario_id="sc-10-out-of-order-telemetry",
            events=[
                BaseTelemetryEvent(
                    event_id="fl-10",
                    timestamp=t0 + timedelta(seconds=30),  # Delivered first in array
                    source=EventSource.VPC_FLOW,
                    action="ACCEPT",
                    resource_id="eni-target",
                    source_ip="203.0.113.1",
                    destination_ip="10.0.1.10",
                    destination_port=8443,
                    details={"protocol": "tcp"},
                ),
                BaseTelemetryEvent(
                    event_id="ct-10",
                    timestamp=t0,  # Delivered second in array
                    source=EventSource.CLOUDTRAIL,
                    action="AuthorizeSecurityGroupIngress",
                    resource_id="sg-target",
                    details={"protocol": "tcp", "from_port": 8443, "to_port": 8443, "cidr_ipv4": "0.0.0.0/0"},
                ),
            ],
            configuration_history=standard_config,
            policy=standard_policy,
            ground_truth=GroundTruthCase(
                scenario_id="sc-10-out-of-order-telemetry",
                category="out_of_order",
                description="Out of order batch arrival resolved deterministically.",
                is_positive_finding=True,
                expected_rule_id="CORR-CROSS-001",
                expected_relationships=[
                    ExpectedRelationship(config_event_id="ct-10", flow_event_id="fl-10", resource_id="eni-target")
                ],
            ),
        )
    )

    # 11. Missing required evidence (Negative correlation)
    scenarios.append(
        EvaluationScenario(
            scenario_id="sc-11-missing-evidence",
            events=[
                BaseTelemetryEvent(
                    event_id="ct-11",
                    timestamp=t0,
                    source=EventSource.CLOUDTRAIL,
                    action="AuthorizeSecurityGroupIngress",
                    resource_id=None,  # Missing SG resource_id!
                    details={},
                )
            ],
            configuration_history=standard_config,
            policy=standard_policy,
            ground_truth=GroundTruthCase(
                scenario_id="sc-11-missing-evidence",
                category="missing_data",
                description="Event missing required attributes cannot correlate.",
                is_positive_finding=False,
            ),
        )
    )

    # 12. Rule revoked before flow occurs (Negative correlation)
    scenarios.append(
        EvaluationScenario(
            scenario_id="sc-12-rule-revoked-before-flow",
            events=[
                BaseTelemetryEvent(
                    event_id="ct-12-auth",
                    timestamp=t0,
                    source=EventSource.CLOUDTRAIL,
                    action="AuthorizeSecurityGroupIngress",
                    resource_id="sg-target",
                    details={"protocol": "tcp", "from_port": 2222, "to_port": 2222, "cidr_ipv4": "0.0.0.0/0"},
                ),
                BaseTelemetryEvent(
                    event_id="ct-12-revoke",
                    timestamp=t0 + timedelta(seconds=15),
                    source=EventSource.CLOUDTRAIL,
                    action="RevokeSecurityGroupIngress",
                    resource_id="sg-target",
                    details={"protocol": "tcp", "from_port": 2222, "to_port": 2222, "cidr_ipv4": "0.0.0.0/0"},
                ),
                BaseTelemetryEvent(
                    event_id="fl-12",
                    timestamp=t0 + timedelta(seconds=40),
                    source=EventSource.VPC_FLOW,
                    action="ACCEPT",
                    resource_id="eni-target",
                    source_ip="198.51.100.7",
                    destination_ip="10.0.1.10",
                    destination_port=2222,
                    details={"protocol": "tcp"},
                ),
            ],
            configuration_history=standard_config,
            policy=standard_policy,
            ground_truth=GroundTruthCase(
                scenario_id="sc-12-rule-revoked-before-flow",
                category="revoked_rule",
                description="Revocation prior to flow arrival invalidates causal enablement relationship.",
                is_positive_finding=True,  # Baseline detects unapproved flow
                expected_rule_id="NET-BL-001",
            ),
        )
    )

    return scenarios
