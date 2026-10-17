"""Cross-Layer Correlation Engine.

Correlates successful administrative security group modifications (AWS CloudTrail)
with subsequent accepted network communication (VPC Flow Logs).

Key Principles:
1. Verifies the administrative operation actually succeeded (no API errors).
2. Verifies the rule modification enables the observed flow parameters (source, dest, proto, port).
3. Verifies that the security group was attached to the target resource/ENI at the flow timestamp
   using timestamped configuration history.
4. Enforces a strict temporal correlation window (default 300s) after rule authorization.
5. Verifies the rule was not revoked prior to the flow.
5b. For SG-to-SG rules (UserIdGroupPairs / source_security_group_id), verifies the flow's source
   ENI carried the referenced security group at flow time; never treats a reference as a wildcard.
6. Does NOT equate configuration identity with flow traffic identity.
7. Preserves uncertainty and explicitly documents candidate relationship rather than confirmed compromise.
"""
from datetime import datetime, timezone
import ipaddress
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from src.shared.constants import (
    CROSS_LAYER_RULE_ID,
    CROSS_LAYER_RULE_VERSION,
    DEFAULT_CORRELATION_WINDOW_SECONDS,
    IP_PROTOCOL_MAP,
)
from src.shared.enums import EventSource, PriorityLevel
from src.shared.models import (
    ApprovedCommunicationPolicy,
    BaseTelemetryEvent,
    ConfigurationHistory,
    DetectionAlert,
    SecurityGroupRule,
)


class CrossLayerCorrelator:
    """Correlator linking administrative configuration changes to matching accepted network flows."""

    def __init__(
        self,
        correlation_window_seconds: int = DEFAULT_CORRELATION_WINDOW_SECONDS,
        policy: Optional[ApprovedCommunicationPolicy] = None,
    ):
        self.correlation_window_seconds = correlation_window_seconds
        self.policy = policy

    def _ensure_utc(self, dt: datetime) -> datetime:
        """Ensure datetime has UTC timezone."""
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def _normalize_protocol(self, proto: Optional[Any]) -> str:
        """Normalize protocol representation."""
        if proto is None:
            return "*"
        norm = str(proto).strip().lower()
        return IP_PROTOCOL_MAP.get(norm, norm)

    def _is_ip_in_cidr(self, ip_str: Optional[str], cidr_str: Optional[str]) -> bool:
        """Conservative matching of IP against CIDR or wildcard."""
        if not cidr_str or cidr_str == "*" or cidr_str.lower() == "any" or cidr_str == "0.0.0.0/0":
            return True
        if not ip_str:
            return False

        try:
            cand_ip = ipaddress.ip_address(ip_str)
            net = ipaddress.ip_network(cidr_str, strict=False)
            return cand_ip in net
        except ValueError:
            return False

    def _is_port_in_range(
        self, port: Optional[int], from_port: Optional[int], to_port: Optional[int]
    ) -> bool:
        """Verify whether an observed port falls within a rule's port interval."""
        if from_port is None and to_port is None:
            return True
        if port is None:
            return False

        low = from_port if from_port is not None else 0
        high = to_port if to_port is not None else 65535
        return low <= port <= high

    def _is_cloudtrail_api_success(self, event: BaseTelemetryEvent) -> bool:
        """Conservatively check if a CloudTrail event represents a successful API operation.

        Requires:
        - No error code or error message present in details or event fields.
        - If 'success' or 'response_elements' is explicitly provided, it must not indicate failure.
        """
        details = event.details or {}

        # Look for AWS CloudTrail standard error fields
        error_code = details.get("errorCode") or details.get("error_code")
        error_msg = details.get("errorMessage") or details.get("error_message")
        if error_code is not None or error_msg is not None:
            return False

        if "success" in details and details["success"] is False:
            return False

        # Some normalizers include a top-level responseElements boolean/dict
        response_elements = details.get("responseElements")
        if response_elements is False or response_elements == "false":
            return False

        return True

    @staticmethod
    def _extract_referenced_sg_ids(group_pairs: Any) -> List[str]:
        """Extract referenced security group IDs from AWS UserIdGroupPairs.

        Accepts the AWS shapes (``groupId`` / ``GroupId`` / ``group_id``) and bare ID strings.
        Entries without a usable, non-empty string ID are dropped rather than guessed.
        """
        if isinstance(group_pairs, (dict, str)):
            group_pairs = [group_pairs]
        if not isinstance(group_pairs, list):
            return []

        ref_ids: List[str] = []
        for pair in group_pairs:
            if isinstance(pair, dict):
                raw = pair.get("groupId") or pair.get("GroupId") or pair.get("group_id")
            else:
                raw = pair
            if isinstance(raw, str) and raw.strip():
                ref_id = raw.strip()
                if ref_id not in ref_ids:
                    ref_ids.append(ref_id)
        return ref_ids

    def _resolve_source_resource(
        self,
        flow: BaseTelemetryEvent,
        configuration_history: Optional[ConfigurationHistory],
    ) -> Optional[str]:
        """Map a flow's source IP to exactly one ENI/resource, or None if unknown/ambiguous."""
        if not configuration_history or not flow.source_ip:
            return None
        candidates = configuration_history.get_resource_ids_for_ip(flow.source_ip)
        if len(candidates) == 1:
            return candidates[0]
        return None

    def _extract_sg_rules_from_event(
        self, event: BaseTelemetryEvent
    ) -> List[SecurityGroupRule]:
        """Extract added or modified security group rules from an administrative event."""
        rules: List[SecurityGroupRule] = []
        details = event.details or {}
        sg_id = event.resource_id or details.get("security_group_id") or details.get("groupId")
        if not sg_id:
            return []

        # Case 1: Structured 'ip_permissions' or 'ipPermissions' (AWS standard)
        ip_perms = details.get("ip_permissions") or details.get("ipPermissions")
        if isinstance(ip_perms, list):
            for perm in ip_perms:
                proto = self._normalize_protocol(perm.get("ipProtocol") or perm.get("protocol"))
                from_p = perm.get("fromPort") or perm.get("from_port")
                to_p = perm.get("toPort") or perm.get("to_port")
                ip_ranges = perm.get("ipRanges") or perm.get("ip_ranges") or []

                # SG-to-SG references (AWS UserIdGroupPairs): source is a security group, not a CIDR.
                raw_pairs = (
                    perm.get("userIdGroupPairs")
                    or perm.get("UserIdGroupPairs")
                    or perm.get("user_id_group_pairs")
                )
                ref_sg_ids = self._extract_referenced_sg_ids(raw_pairs)
                for ref_sg_id in ref_sg_ids:
                    rules.append(
                        SecurityGroupRule(
                            security_group_id=sg_id,
                            protocol=proto,
                            from_port=from_p,
                            to_port=to_p,
                            referenced_security_group_id=ref_sg_id,
                        )
                    )
                if raw_pairs and not ref_sg_ids and not ip_ranges:
                    # Group pairs were present but unusable: never fall back to a 0.0.0.0/0 wildcard.
                    continue
                if ref_sg_ids and not ip_ranges:
                    continue

                if isinstance(ip_ranges, list) and ip_ranges:
                    for ip_range in ip_ranges:
                        cidr = (
                            ip_range.get("cidrIp")
                            or ip_range.get("cidr_ipv4")
                            or ip_range.get("cidr_ip")
                            if isinstance(ip_range, dict)
                            else str(ip_range)
                        )
                        rules.append(
                            SecurityGroupRule(
                                security_group_id=sg_id,
                                protocol=proto,
                                from_port=from_p,
                                to_port=to_p,
                                cidr_ipv4=cidr,
                            )
                        )
                else:
                    # Single permission without explicit ipRanges list (e.g., wildcard)
                    cidr = perm.get("cidr_ipv4") or perm.get("cidrIp") or "0.0.0.0/0"
                    rules.append(
                        SecurityGroupRule(
                            security_group_id=sg_id,
                            protocol=proto,
                            from_port=from_p,
                            to_port=to_p,
                            cidr_ipv4=cidr,
                        )
                    )
            return rules

        # Case 2: Flat normalized attributes in details
        sg_ref_keys = ("source_security_group_id", "sourceSecurityGroupId")
        flat_ref_present = any(k in details for k in sg_ref_keys)
        if (
            "protocol" in details
            or "from_port" in details
            or "cidr_ipv4" in details
            or flat_ref_present
        ):
            proto = self._normalize_protocol(details.get("protocol"))
            cidr = details.get("cidr_ipv4") or details.get("cidr_ip")
            ref_sg_ids = self._extract_referenced_sg_ids(
                [details.get(k) for k in sg_ref_keys if details.get(k)]
            )

            # CIDR rule: kept exactly as before unless the event is purely an SG reference.
            if cidr or not flat_ref_present:
                rules.append(
                    SecurityGroupRule(
                        security_group_id=sg_id,
                        protocol=proto,
                        from_port=details.get("from_port"),
                        to_port=details.get("to_port"),
                        cidr_ipv4=cidr,
                    )
                )
            # SG-reference rule(s). An unusable reference yields no rule (no wildcard fallback).
            for ref_sg_id in ref_sg_ids:
                rules.append(
                    SecurityGroupRule(
                        security_group_id=sg_id,
                        protocol=proto,
                        from_port=details.get("from_port"),
                        to_port=details.get("to_port"),
                        referenced_security_group_id=ref_sg_id,
                    )
                )

        return rules

    def _is_revoked(
        self,
        rule: SecurityGroupRule,
        auth_time: datetime,
        flow_time: datetime,
        revocation_events: List[BaseTelemetryEvent],
    ) -> bool:
        """Check if an administrative revocation occurred between rule authorization and flow time."""
        for rev in revocation_events:
            rev_time = self._ensure_utc(rev.timestamp)
            if auth_time < rev_time <= flow_time:
                rev_rules = self._extract_sg_rules_from_event(rev)
                for r in rev_rules:
                    if r.security_group_id == rule.security_group_id:
                        # A revoke of a CIDR rule does not revoke an SG-reference rule (and vice versa)
                        if r.referenced_security_group_id != rule.referenced_security_group_id:
                            continue
                        # Check protocol and port match
                        if (
                            (r.protocol in ("*", "all") or r.protocol == rule.protocol)
                            and (r.from_port is None or r.from_port == rule.from_port)
                            and (r.to_port is None or r.to_port == rule.to_port)
                        ):
                            return True
        return False

    def correlate(
        self,
        events: List[BaseTelemetryEvent],
        configuration_history: Optional[ConfigurationHistory] = None,
    ) -> List[DetectionAlert]:
        """Correlate administrative events with subsequent matching accepted VPC flows.

        Args:
            events: Telemetry batch (CloudTrail and VPC Flow Logs).
            configuration_history: Historical snapshot of resource attachments.

        Returns:
            List of structured DetectionAlert objects representing correlated cross-layer findings.
        """
        if not events:
            return []

        # 1. Deduplicate by event_id deterministically
        deduped_events_map: Dict[str, BaseTelemetryEvent] = {}
        for ev in events:
            if ev.event_id not in deduped_events_map:
                deduped_events_map[ev.event_id] = ev

        all_events = list(deduped_events_map.values())

        # 2. Partition events into categories
        ct_auth_events: List[BaseTelemetryEvent] = []
        ct_revoke_events: List[BaseTelemetryEvent] = []
        vpc_accepted_flows: List[BaseTelemetryEvent] = []

        for ev in all_events:
            if ev.source == EventSource.CLOUDTRAIL:
                act = ev.action.lower()
                if "authorizesecuritygroupingress" in act or "authorize_security_group_ingress" in act:
                    ct_auth_events.append(ev)
                elif "revokesecuritygroupingress" in act or "revoke_security_group_ingress" in act:
                    if self._is_cloudtrail_api_success(ev):
                        ct_revoke_events.append(ev)
            elif ev.is_accepted_flow:
                vpc_accepted_flows.append(ev)

        # Sort deterministically by UTC timestamp and event_id
        ct_auth_events.sort(key=lambda x: (self._ensure_utc(x.timestamp), x.event_id))
        vpc_accepted_flows.sort(key=lambda x: (self._ensure_utc(x.timestamp), x.event_id))

        findings: List[DetectionAlert] = []

        # 3. For each successful ingress authorization, search for matching accepted flows
        for ct_ev in ct_auth_events:
            # Validate API success
            if not self._is_cloudtrail_api_success(ct_ev):
                continue

            sg_rules = self._extract_sg_rules_from_event(ct_ev)
            if not sg_rules:
                continue

            ct_time = self._ensure_utc(ct_ev.timestamp)
            matching_flows: List[BaseTelemetryEvent] = []
            matched_resource_ids: Set[str] = set()
            reasons: List[str] = []
            sg_ref_sources: Dict[Tuple[str, str, str, Optional[int], Optional[int]], Set[str]] = {}

            for rule in sg_rules:
                for flow in vpc_accepted_flows:
                    flow_time = self._ensure_utc(flow.timestamp)

                    # Temporal constraint: flow must occur AFTER change, within correlation window
                    delta_seconds = (flow_time - ct_time).total_seconds()
                    if delta_seconds < 0 or delta_seconds > self.correlation_window_seconds:
                        continue

                    # Validate protocol match
                    flow_proto = self._normalize_protocol(flow.protocol)
                    if rule.protocol not in ("*", "all") and rule.protocol != flow_proto:
                        continue

                    # Validate destination port match
                    if not self._is_port_in_range(flow.destination_port, rule.from_port, rule.to_port):
                        continue

                    # Validate source: SG-reference rule vs CIDR rule
                    src_res_id: Optional[str] = None
                    if rule.referenced_security_group_id:
                        # Source must resolve to exactly one ENI that carried the referenced SG at flow time.
                        # Without configuration history, or on unknown/ambiguous mapping, do not assume.
                        src_res_id = self._resolve_source_resource(flow, configuration_history)
                        if not src_res_id:
                            continue
                        src_sgs = configuration_history.get_security_groups_for_resource(
                            src_res_id, flow_time
                        )
                        if rule.referenced_security_group_id not in src_sgs:
                            continue
                    elif not self._is_ip_in_cidr(flow.source_ip, rule.cidr_ipv4):
                        continue

                    # Validate destination resource and Security Group association
                    target_res_id = flow.resource_id
                    if not target_res_id and configuration_history and flow.destination_ip:
                        candidate_res = configuration_history.get_resource_ids_for_ip(flow.destination_ip)
                        if len(candidate_res) == 1:
                            target_res_id = candidate_res[0]
                        elif len(candidate_res) > 1:
                            # Ambiguous mapping: cannot safely assume association
                            continue

                    if not target_res_id:
                        # Missing resource mapping: cannot verify SG attachment to flow interface
                        continue

                    # If configuration history is provided, verify SG attachment at flow time
                    if configuration_history:
                        attached_sgs = configuration_history.get_security_groups_for_resource(
                            target_res_id, flow_time
                        )
                        if rule.security_group_id not in attached_sgs:
                            continue

                    # Check for rule revocation between authorization and flow
                    if self._is_revoked(rule, ct_time, flow_time, ct_revoke_events):
                        continue

                    # Record verified SG-to-SG reference (source ENI -> referenced SG -> protected SG)
                    if rule.referenced_security_group_id:
                        ref_key = (
                            rule.referenced_security_group_id,
                            rule.security_group_id,
                            rule.protocol,
                            rule.from_port,
                            rule.to_port,
                        )
                        sg_ref_sources.setdefault(ref_key, set()).add(src_res_id)

                    # Flow verified as matching and enabled by rule
                    if flow not in matching_flows:
                        matching_flows.append(flow)
                        matched_resource_ids.add(target_res_id)
                        if rule.referenced_security_group_id:
                            rule_desc = (
                                f"referenced_sg={rule.referenced_security_group_id} "
                                f"(source ENI {src_res_id} attached to it at flow time)"
                            )
                        else:
                            rule_desc = f"cidr={rule.cidr_ipv4}"
                        reasons.append(
                            f"Flow {flow.event_id} ({flow.source_ip} -> {flow.destination_ip}:{flow.destination_port} "
                            f"{flow_proto}) matched SG {rule.security_group_id} rule "
                            f"(proto={rule.protocol}, port={rule.from_port}-{rule.to_port}, {rule_desc}) "
                            f"{int(delta_seconds)}s after configuration change."
                        )

            if matching_flows:
                # Construct finding preserving uncertainty
                flow_ids = [f.event_id for f in matching_flows]
                actor_str = ct_ev.actor or "Unknown IAM Principal"
                explanation = (
                    f"Cross-layer correlation detected: Administrative event {ct_ev.event_id} "
                    f"by actor '{actor_str}' authorized security group ingress rule(s) enabling traffic. "
                    f"Subsequently, {len(matching_flows)} matching accepted flow(s) were observed within the "
                    f"{self.correlation_window_seconds}s window. "
                    f"Evidence: {'; '.join(reasons)}. "
                    f"NOTE: Correlated accepted traffic establishes reachability and rule enablement; "
                    f"it does NOT confirm application compromise, malicious intent, or that the IAM actor "
                    f"was responsible for generating the network traffic."
                )

                sg_references = [
                    {
                        "referenced_security_group_id": ref_sg,
                        "security_group_id": prot_sg,
                        "protocol": proto,
                        "from_port": from_p,
                        "to_port": to_p,
                        "source_resource_ids": sorted(srcs),
                    }
                    for (ref_sg, prot_sg, proto, from_p, to_p), srcs in sorted(
                        sg_ref_sources.items(), key=lambda kv: tuple(str(x) for x in kv[0])
                    )
                ]

                alert = DetectionAlert(
                    alert_id=f"alert-cross-{uuid.uuid4().hex[:12]}",
                    rule_id=CROSS_LAYER_RULE_ID,
                    rule_version=CROSS_LAYER_RULE_VERSION,
                    priority=PriorityLevel.HIGH,
                    explanation=explanation,
                    evidence_event_ids=[ct_ev.event_id] + flow_ids,
                    related_resource_ids=sorted(list(matched_resource_ids)),
                    created_at=datetime.now(timezone.utc),
                    case_id=None,
                    details={
                        "cloudtrail_event_id": ct_ev.event_id,
                        "flow_event_ids": flow_ids,
                        "admin_actor": ct_ev.actor,
                        "security_group_id": sg_rules[0].security_group_id if sg_rules else None,
                        "correlation_window_seconds": self.correlation_window_seconds,
                        "matched_flows_count": len(matching_flows),
                        "sg_references": sg_references,
                        "referenced_security_group_ids": sorted(
                            {r["referenced_security_group_id"] for r in sg_references}
                        ),
                        "uncertainty_note": "Network flow actor and IAM actor remain distinct; reachability established without confirmed exploitation.",
                    },
                )
                findings.append(alert)

        return findings
