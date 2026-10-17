"""Directed Temporal Graph Builder using NetworkX.

Constructs multi-relational graphs distinguishing:
1. Observed network communication (VPC Flow Logs ACCEPT).
2. Permitted network reachability (Security Group ingress rules / policies).
3. Inferred relationships (Cross-layer correlation findings / candidate attack steps).

Preserves:
- edge_id, source_node, target_node, relation, observed_or_inferred,
  evidence_event_ids, valid_time, confidence_reason, protocol, port.
"""
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Tuple
import networkx as nx

from src.shared.enums import EdgeNature, EventSource, RelationshipType
from src.shared.models import (
    ApprovedCommunicationPolicy,
    BaseTelemetryEvent,
    ConfigurationHistory,
    DetectionAlert,
    GraphData,
    GraphEdge,
    GraphNode,
)


class GraphBuilder:
    """Constructs and manages directed temporal property graphs from multi-layer security telemetry."""

    def __init__(self):
        self.graph = nx.MultiDiGraph()

    def _ensure_utc(self, dt: Optional[datetime]) -> Optional[datetime]:
        """Ensure UTC timezone on datetime."""
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def _generate_node_id(self, identifier: str, node_type: str) -> str:
        """Create deterministic node identifier."""
        clean_id = identifier.strip()
        return clean_id

    def _generate_edge_id(
        self,
        src: str,
        dst: str,
        relation: str,
        proto: Optional[str],
        port: Optional[int],
        valid_time: Optional[datetime],
    ) -> str:
        """Deterministic hash-based edge ID."""
        t_str = valid_time.isoformat() if valid_time else "none"
        raw = f"{src}->{dst}:{relation}:{proto or '*'}:{port or '*'}:{t_str}"
        return f"edge-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12]}"

    def add_node(
        self,
        node_id: str,
        node_type: str,
        ip_addresses: Optional[List[str]] = None,
        label: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Add or update a node with deterministic attributes."""
        norm_id = self._generate_node_id(node_id, node_type)
        ips = ip_addresses or []
        props = properties or {}

        if self.graph.has_node(norm_id):
            # Merge IP addresses and properties deterministically
            existing = self.graph.nodes[norm_id]
            merged_ips = sorted(list(set(existing.get("ip_addresses", []) + ips)))
            existing["ip_addresses"] = merged_ips
            existing["properties"].update(props)
        else:
            self.graph.add_node(
                norm_id,
                node_id=norm_id,
                node_type=node_type,
                ip_addresses=sorted(list(set(ips))),
                label=label or norm_id,
                properties=props,
            )
        return norm_id

    def add_edge(
        self,
        source_node: str,
        target_node: str,
        relation: str,
        observed_or_inferred: str,
        evidence_event_ids: List[str],
        valid_time: Optional[datetime] = None,
        confidence_reason: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Add a directed edge or deduplicate into an existing edge while preserving distinct evidence IDs."""
        v_time = self._ensure_utc(valid_time)
        norm_proto = str(protocol).lower() if protocol else None
        edge_id = self._generate_edge_id(
            source_node, target_node, relation, norm_proto, port, v_time
        )

        # Check if identical edge already exists between source and target
        if self.graph.has_edge(source_node, target_node):
            for key, data in self.graph[source_node][target_node].items():
                if (
                    data.get("relation") == relation
                    and data.get("protocol") == norm_proto
                    and data.get("port") == port
                    and data.get("valid_time") == v_time
                ):
                    # Edge exists: deduplicate evidence deterministically
                    merged_ev = sorted(list(set(data["evidence_event_ids"] + evidence_event_ids)))
                    data["evidence_event_ids"] = merged_ev
                    if details:
                        data["details"].update(details)
                    return data["edge_id"]

        edge_attrs = {
            "edge_id": edge_id,
            "source_node": source_node,
            "target_node": target_node,
            "relation": relation,
            "observed_or_inferred": observed_or_inferred,
            "evidence_event_ids": sorted(list(set(evidence_event_ids))),
            "valid_time": v_time,
            "confidence_reason": confidence_reason or "Empirical telemetry observation",
            "protocol": norm_proto,
            "port": port,
            "details": details or {},
        }

        self.graph.add_edge(source_node, target_node, key=edge_id, **edge_attrs)
        return edge_id

    def build_from_telemetry(
        self,
        events: List[BaseTelemetryEvent],
        configuration_history: Optional[ConfigurationHistory] = None,
        alerts: Optional[List[DetectionAlert]] = None,
        policy: Optional[ApprovedCommunicationPolicy] = None,
    ) -> nx.MultiDiGraph:
        """Build a unified directed graph from flows, configuration history, and cross-layer alerts."""
        # 1. Process VPC Flow Logs -> Observed Communication
        for ev in events:
            if ev.is_accepted_flow:
                # Resolve source node (use known ENI mapping or IP endpoint)
                src_node = None
                if configuration_history and ev.source_ip:
                    enis = configuration_history.get_resource_ids_for_ip(ev.source_ip)
                    if len(enis) == 1:
                        src_node = self.add_node(enis[0], "eni", ip_addresses=[ev.source_ip])
                if not src_node:
                    if ev.source_ip:
                        src_node = self.add_node(f"endpoint:{ev.source_ip}", "ip_endpoint", ip_addresses=[ev.source_ip])
                    else:
                        continue  # Incomplete telemetry cannot form a safe endpoint

                # Resolve destination node
                dst_node = None
                if ev.resource_id:
                    dst_node = self.add_node(ev.resource_id, "eni", ip_addresses=[ev.destination_ip] if ev.destination_ip else [])
                elif configuration_history and ev.destination_ip:
                    enis = configuration_history.get_resource_ids_for_ip(ev.destination_ip)
                    if len(enis) == 1:
                        dst_node = self.add_node(enis[0], "eni", ip_addresses=[ev.destination_ip])

                if not dst_node:
                    if ev.destination_ip:
                        dst_node = self.add_node(f"endpoint:{ev.destination_ip}", "ip_endpoint", ip_addresses=[ev.destination_ip])
                    else:
                        continue

                # Add observed communication edge
                self.add_edge(
                    source_node=src_node,
                    target_node=dst_node,
                    relation=RelationshipType.OBSERVED_COMMUNICATION.value,
                    observed_or_inferred=EdgeNature.OBSERVED.value,
                    evidence_event_ids=[ev.event_id],
                    valid_time=ev.timestamp,
                    confidence_reason="Observed accepted VPC flow record",
                    protocol=ev.protocol,
                    port=ev.destination_port,
                    details={
                        "source_ip": ev.source_ip,
                        "destination_ip": ev.destination_ip,
                        "action": ev.action,
                    },
                )

        # 2. Process Configuration History -> Permitted Reachability (SG associations)
        if configuration_history:
            for att in configuration_history.attachments:
                res_node = self.add_node(att.resource_id, "eni")
                sg_node = self.add_node(att.security_group_id, "security_group")
                # Directed edge: Resource has SecurityGroup association
                self.add_edge(
                    source_node=res_node,
                    target_node=sg_node,
                    relation=RelationshipType.PERMITTED_REACHABILITY.value,
                    observed_or_inferred=EdgeNature.PERMITTED.value,
                    evidence_event_ids=[],
                    valid_time=att.attached_at,
                    confidence_reason="Historical configuration snapshot attachment",
                    details={"attached_at": att.attached_at.isoformat()},
                )

        # 3. Process Policy Rules -> Permitted Reachability
        if policy:
            for rule in policy.rules:
                # If rule specifies concrete endpoints (not wildcards), map permitted reachability
                if rule.source != "*" and rule.destination != "*":
                    src_id = f"endpoint:{rule.source}"
                    dst_id = f"endpoint:{rule.destination}"
                    self.add_node(src_id, "ip_endpoint")
                    self.add_node(dst_id, "ip_endpoint")
                    self.add_edge(
                        source_node=src_id,
                        target_node=dst_id,
                        relation=RelationshipType.PERMITTED_REACHABILITY.value,
                        observed_or_inferred=EdgeNature.PERMITTED.value,
                        evidence_event_ids=[],
                        valid_time=None,
                        confidence_reason=f"Approved policy rule {rule.rule_id}",
                        protocol=rule.protocol,
                        port=rule.destination_port,
                        details={"rule_id": rule.rule_id},
                    )

        # 4. Process Cross-Layer Correlation Alerts -> Inferred Sequence
        if alerts:
            ct_times = {ev.event_id: ev.timestamp for ev in events}
            for alert in alerts:
                # Extract evidence and related resources
                ct_id = alert.details.get("cloudtrail_event_id")
                sg_id = alert.details.get("security_group_id")
                related_res = alert.related_resource_ids or []

                if sg_id and related_res:
                    sg_node = self.add_node(sg_id, "security_group")
                    for res_id in related_res:
                        res_node = self.add_node(res_id, "eni")
                        # Inferred sequence edge: SG change enabled access to resource
                        self.add_edge(
                            source_node=sg_node,
                            target_node=res_node,
                            relation=RelationshipType.INFERRED_SEQUENCE.value,
                            observed_or_inferred=EdgeNature.INFERRED.value,
                            evidence_event_ids=alert.evidence_event_ids,
                            valid_time=alert.created_at,
                            confidence_reason="Inferred enablement from cross-layer correlation",
                            details={
                                "alert_id": alert.alert_id,
                                "admin_actor": alert.details.get("admin_actor"),
                                "uncertainty": alert.details.get("uncertainty_note"),
                            },
                        )

                # 5. SG-to-SG references verified by correlation:
                #    referenced SG --(permitted_reachability)--> protected SG.
                #    Combined with ENI -> SG attachment edges this yields
                #    source ENI -> referenced SG -> protected SG -> target ENI.
                self._add_sg_reference_edges(alert, ct_id, ct_times)

        return self.graph

    @staticmethod
    def _clean_id(value: Any) -> Optional[str]:
        """Return a stripped non-empty string ID, else None (never fabricate identities)."""
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    def _add_sg_reference_edges(
        self,
        alert: DetectionAlert,
        ct_id: Optional[str],
        ct_times: Dict[str, datetime],
    ) -> None:
        """Add permitted-reachability edges for SG-to-SG references recorded on an alert."""
        refs = alert.details.get("sg_references") or []
        if not isinstance(refs, list):
            return
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            ref_sg = self._clean_id(ref.get("referenced_security_group_id"))
            prot_sg = self._clean_id(ref.get("security_group_id")) or self._clean_id(
                alert.details.get("security_group_id")
            )
            if not ref_sg or not prot_sg:
                continue  # Missing/unusable reference: no edge rather than a guessed one

            ref_node = self.add_node(ref_sg, "security_group")
            prot_node = self.add_node(prot_sg, "security_group")
            from_p, to_p = ref.get("from_port"), ref.get("to_port")
            port = from_p if from_p is not None and from_p == to_p else None
            self.add_edge(
                source_node=ref_node,
                target_node=prot_node,
                relation=RelationshipType.PERMITTED_REACHABILITY.value,
                observed_or_inferred=EdgeNature.PERMITTED.value,
                evidence_event_ids=[ct_id] if ct_id else [],
                valid_time=ct_times.get(ct_id) if ct_id else None,
                confidence_reason=(
                    "Ingress rule referencing source security group "
                    "(authorization validated by cross-layer correlation)"
                ),
                protocol=ref.get("protocol"),
                port=port,
                details={
                    "alert_id": alert.alert_id,
                    "from_port": from_p,
                    "to_port": to_p,
                    "source_resource_ids": sorted(ref.get("source_resource_ids") or []),
                },
            )

    def to_graph_data(self) -> GraphData:
        """Export graph to JSON-serializable GraphData model for Member 3 API/UI."""
        nodes: List[GraphNode] = []
        for n_id, data in self.graph.nodes(data=True):
            nodes.append(
                GraphNode(
                    node_id=n_id,
                    node_type=data.get("node_type", "unknown"),
                    ip_addresses=data.get("ip_addresses", []),
                    label=data.get("label", n_id),
                    properties=data.get("properties", {}),
                )
            )

        edges: List[GraphEdge] = []
        for u, v, key, data in self.graph.edges(keys=True, data=True):
            edges.append(
                GraphEdge(
                    edge_id=data["edge_id"],
                    source_node=data["source_node"],
                    target_node=data["target_node"],
                    relation=data["relation"],
                    observed_or_inferred=data["observed_or_inferred"],
                    evidence_event_ids=data.get("evidence_event_ids", []),
                    valid_time=data.get("valid_time"),
                    confidence_reason=data.get("confidence_reason"),
                    protocol=data.get("protocol"),
                    port=data.get("port"),
                    details=data.get("details", {}),
                )
            )

        # Sort deterministically
        nodes.sort(key=lambda x: x.node_id)
        edges.sort(key=lambda x: (x.source_node, x.target_node, x.edge_id))
        return GraphData(nodes=nodes, edges=edges)
