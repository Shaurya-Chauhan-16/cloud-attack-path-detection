"""Approved Communication Policy Engine and Network-Only Baseline Detector.

Responsible for:
1. Evaluating flows against an explicitly defined approved policy.
2. Handling CIDR matches, protocol aliases, and port ranges.
3. Checking temporal maintenance exceptions.
4. Deterministic resolution of conflicting rules (explicit deny / unapproved precedence).
5. Network-only baseline detection flagging accepted flows that violate policy.
"""
from datetime import datetime, timezone
import ipaddress
import uuid
from typing import List, Optional, Tuple

from src.shared.constants import (
    IP_PROTOCOL_MAP,
    NETWORK_BASELINE_RULE_ID,
    NETWORK_BASELINE_RULE_VERSION,
)
from src.shared.enums import PolicyDecision, PriorityLevel
from src.shared.models import (
    ApprovedCommunicationPolicy,
    BaseTelemetryEvent,
    DetectionAlert,
    MaintenanceException,
    PolicyRule,
)


class PolicyEngine:
    """Evaluates network telemetry against approved communication policies and exceptions."""

    def __init__(self, policy: ApprovedCommunicationPolicy):
        self.policy = policy

    def _match_ip_or_cidr(self, candidate_ip_str: Optional[str], pattern: str) -> bool:
        """Check if an IP string satisfies an exact IP or CIDR pattern."""
        if pattern == "*" or pattern.lower() == "any":
            return True
        if not candidate_ip_str:
            # Missing IP cannot be safely assumed to match a specific CIDR or address
            return False

        try:
            candidate_ip = ipaddress.ip_address(candidate_ip_str)
        except ValueError:
            return False

        try:
            # Pattern could be CIDR (e.g., 10.0.0.0/16) or single IP (10.0.1.5)
            net = ipaddress.ip_network(pattern, strict=False)
            return candidate_ip in net
        except ValueError:
            return False

    def _normalize_protocol(self, protocol_str: Optional[str]) -> str:
        """Normalize numeric and string protocol representations."""
        if not protocol_str:
            return "*"
        norm = str(protocol_str).strip().lower()
        return IP_PROTOCOL_MAP.get(norm, norm)

    def _match_protocol(self, event_proto: Optional[str], rule_proto: str) -> bool:
        """Check protocol compatibility."""
        rule_norm = self._normalize_protocol(rule_proto)
        if rule_norm in ("*", "all"):
            return True
        if not event_proto:
            # Missing protocol cannot be assumed to match a specific rule protocol
            return False
        ev_norm = self._normalize_protocol(event_proto)
        return ev_norm == rule_norm

    def _match_port(
        self,
        event_port: Optional[int],
        rule_port: Optional[int],
        rule_range: Optional[List[int]],
    ) -> bool:
        """Check if destination port matches a single port or range."""
        # If rule specifies neither, all ports are permitted
        if rule_port is None and rule_range is None:
            return True
        if event_port is None:
            # Missing port cannot be assumed to match specific port rule
            return False

        if rule_port is not None and event_port == rule_port:
            return True

        if rule_range and len(rule_range) == 2:
            start_port, end_port = rule_range
            if start_port <= event_port <= end_port:
                return True

        return False

    def check_maintenance_exception(
        self, event: BaseTelemetryEvent
    ) -> Optional[MaintenanceException]:
        """Check if the event falls within an approved maintenance window."""
        event_time = event.timestamp
        if event_time.tzinfo is None:
            # Assume UTC if naive
            event_time = event_time.replace(tzinfo=timezone.utc)

        for exc in self.policy.maintenance_exceptions:
            start = exc.start_time
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
            end = exc.end_time
            if end.tzinfo is None:
                end = end.replace(tzinfo=timezone.utc)

            if start <= event_time <= end:
                # Validate network parameters
                if (
                    self._match_ip_or_cidr(event.source_ip, exc.source)
                    and self._match_ip_or_cidr(event.destination_ip, exc.destination)
                    and self._match_protocol(event.protocol, exc.protocol)
                    and self._match_port(event.destination_port, exc.destination_port, None)
                ):
                    return exc
        return None

    def evaluate_flow(
        self, event: BaseTelemetryEvent
    ) -> Tuple[PolicyDecision, Optional[str], Optional[str]]:
        """Evaluate flow against the policy.

        Returns:
            Tuple of (PolicyDecision, rule_or_exception_id, reason)
        """
        # 1. First check if flow falls into an active approved maintenance exception
        maintenance_match = self.check_maintenance_exception(event)
        if maintenance_match:
            return (
                PolicyDecision.EXCEPTION,
                maintenance_match.exception_id,
                f"Approved maintenance exception: {maintenance_match.description}",
            )

        # Conservative validation: missing source_ip, destination_ip, or destination_port
        # when evaluating network flows cannot be treated as approved
        if not event.source_ip or not event.destination_ip:
            return (
                PolicyDecision.UNAPPROVED,
                None,
                "Incomplete telemetry: missing source_ip or destination_ip",
            )

        # 2. Evaluate against configured rules.
        # Deterministic conflict resolution: If any matching rule explicitly marks UNAPPROVED,
        # it overrides APPROVED rules (Conservative security posture).
        matching_rules = []
        for rule in self.policy.rules:
            src_match = self._match_ip_or_cidr(event.source_ip, rule.source)
            dst_match = self._match_ip_or_cidr(event.destination_ip, rule.destination)
            proto_match = self._match_protocol(event.protocol, rule.protocol)
            port_match = self._match_port(
                event.destination_port, rule.destination_port, rule.destination_port_range
            )

            if src_match and dst_match and proto_match and port_match:
                matching_rules.append(rule)

        if not matching_rules:
            return (
                PolicyDecision.UNAPPROVED,
                None,
                f"No matching approved rule for flow from {event.source_ip} to {event.destination_ip}:{event.destination_port}",
            )

        # Check for explicit unapproved/denial rule match
        for r in matching_rules:
            if r.action == PolicyDecision.UNAPPROVED:
                return (
                    PolicyDecision.UNAPPROVED,
                    r.rule_id,
                    f"Explicitly forbidden by policy rule {r.rule_id}: {r.description or ''}",
                )

        # All matching rules approve the traffic
        primary_match = matching_rules[0]
        return (
            PolicyDecision.APPROVED,
            primary_match.rule_id,
            f"Approved by policy rule {primary_match.rule_id}: {primary_match.description or ''}",
        )


class NetworkBaselineDetector:
    """Network-only baseline detector.

    Identifies accepted network flows that violate approved communication policy.
    Rejects flows that are marked REJECT from generating false positive baseline alerts.
    """

    def __init__(self, policy: ApprovedCommunicationPolicy):
        self.policy_engine = PolicyEngine(policy)

    def detect(self, events: List[BaseTelemetryEvent]) -> List[DetectionAlert]:
        """Process telemetry events and generate detection alerts for unapproved accepted flows."""
        alerts: List[DetectionAlert] = []

        for event in events:
            # Rule: Only accepted VPC flows are evaluated for unauthorized successful communication
            if not event.is_accepted_flow:
                continue

            decision, rule_id, reason = self.policy_engine.evaluate_flow(event)

            if decision == PolicyDecision.UNAPPROVED:
                # Create an alert adhering strictly to the shared alert contract
                alert = DetectionAlert(
                    alert_id=f"alert-{uuid.uuid4().hex[:12]}",
                    rule_id=NETWORK_BASELINE_RULE_ID,
                    rule_version=NETWORK_BASELINE_RULE_VERSION,
                    priority=PriorityLevel.MEDIUM,
                    explanation=(
                        f"Unapproved network communication detected: accepted flow from "
                        f"{event.source_ip} to {event.destination_ip}:{event.destination_port} "
                        f"(proto: {event.protocol or 'unknown'}). Reason: {reason}"
                    ),
                    evidence_event_ids=[event.event_id],
                    related_resource_ids=[event.resource_id] if event.resource_id else [],
                    created_at=datetime.now(timezone.utc),
                    case_id=None,
                    details={
                        "source_ip": event.source_ip,
                        "destination_ip": event.destination_ip,
                        "destination_port": event.destination_port,
                        "protocol": event.protocol,
                        "violating_rule_id": rule_id,
                        "evaluation_reason": reason,
                    },
                )
                alerts.append(alert)

        return alerts
