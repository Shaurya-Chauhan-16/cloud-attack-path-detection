"""Shared data models using Pydantic v2.

Adheres strictly to the Member 1 / Member 2 / Member 3 shared contract.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict

from src.shared.enums import EventSource, FlowAction, PriorityLevel, PolicyDecision


class BaseTelemetryEvent(BaseModel):
    """Agreed shared event contract across team members.
    
    Attributes:
        event_id: Stable identifier for the event.
        timestamp: UTC timestamp of the event.
        source: Origin of telemetry (e.g. cloudtrail, vpc_flow, config).
        action: Event action (e.g. ACCEPT, REJECT, AuthorizeSecurityGroupIngress).
        actor: Principal or entity responsible (e.g. IAM ARN, or None for flows).
        resource_id: Identifier of the primary resource (e.g. eni-xxx, sg-xxx, i-xxx).
        source_ip: IPv4/IPv6 source address.
        destination_ip: IPv4/IPv6 destination address.
        destination_port: Integer destination port (or None if not applicable).
        raw_record_id: Upstream log identifier.
        details: Additional context, protocol info, packet counts, etc.
    """
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    event_id: str
    timestamp: datetime
    source: EventSource
    action: str
    actor: Optional[str] = None
    resource_id: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    raw_record_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

    @property
    def protocol(self) -> Optional[str]:
        """Extract protocol from details or top-level details if present."""
        proto = self.details.get("protocol")
        if proto is not None:
            return str(proto).lower()
        return None

    @property
    def is_accepted_flow(self) -> bool:
        """Helper to determine if the event represents an accepted VPC flow."""
        return (
            self.source == EventSource.VPC_FLOW
            and self.action.upper() == FlowAction.ACCEPT.value
        )

    @property
    def is_rejected_flow(self) -> bool:
        """Helper to determine if the event represents a rejected VPC flow."""
        return (
            self.source == EventSource.VPC_FLOW
            and self.action.upper() == FlowAction.REJECT.value
        )


class PolicyRule(BaseModel):
    """Specification of an approved network communication rule."""
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    description: Optional[str] = None
    source: str = "*"  # IP or CIDR or '*'
    destination: str = "*"  # IP or CIDR or '*'
    protocol: str = "*"  # 'tcp', 'udp', 'icmp', or '*' / 'all'
    destination_port: Optional[int] = None  # Specific port or None for any
    destination_port_range: Optional[List[int]] = None  # [start_port, end_port]
    action: PolicyDecision = PolicyDecision.APPROVED


class MaintenanceException(BaseModel):
    """Explicit approved temporary maintenance window exception."""
    model_config = ConfigDict(extra="forbid")

    exception_id: str
    description: str
    start_time: datetime
    end_time: datetime
    source: str = "*"
    destination: str = "*"
    protocol: str = "*"
    destination_port: Optional[int] = None


class ApprovedCommunicationPolicy(BaseModel):
    """Collection of approved rules and maintenance windows."""
    model_config = ConfigDict(extra="allow")

    policy_id: str = "default_policy"
    rules: List[PolicyRule] = Field(default_factory=list)
    maintenance_exceptions: List[MaintenanceException] = Field(default_factory=list)


class DetectionAlert(BaseModel):
    """Agreed shared alert contract consumed by Member 3 (API & UI)."""
    model_config = ConfigDict(extra="allow")

    alert_id: str
    rule_id: str
    rule_version: str
    priority: PriorityLevel
    explanation: str
    evidence_event_ids: List[str]
    related_resource_ids: List[str]
    created_at: datetime
    case_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class SecurityGroupRule(BaseModel):
    """Normalized security group rule description."""
    model_config = ConfigDict(extra="allow")

    rule_id: Optional[str] = None
    security_group_id: str
    protocol: str = "*"
    from_port: Optional[int] = None
    to_port: Optional[int] = None
    cidr_ipv4: Optional[str] = None
    cidr_ipv6: Optional[str] = None
    description: Optional[str] = None


class SecurityGroupAttachment(BaseModel):
    """Timestamped historical mapping between an ENI / resource and security groups."""
    model_config = ConfigDict(extra="allow")

    resource_id: str  # e.g., eni-xxxx or i-xxxx
    security_group_id: str  # e.g., sg-xxxx
    attached_at: datetime
    detached_at: Optional[datetime] = None


class ConfigurationHistory(BaseModel):
    """Container for historical configuration snapshots provided by Member 1."""
    model_config = ConfigDict(extra="allow")

    attachments: List[SecurityGroupAttachment] = Field(default_factory=list)
    eni_to_ip_map: Dict[str, List[str]] = Field(default_factory=dict)  # eni_id -> list of IPs

    def get_security_groups_for_resource(
        self, resource_id: str, timestamp: datetime
    ) -> List[str]:
        """Find security group IDs attached to resource at a specific timestamp."""
        active_sgs = []
        for att in self.attachments:
            if att.resource_id == resource_id:
                # Compare timestamps ensuring timezone awareness
                att_time = att.attached_at
                det_time = att.detached_at
                if att_time.tzinfo is None and timestamp.tzinfo is not None:
                    att_time = att_time.replace(tzinfo=timestamp.tzinfo)
                elif att_time.tzinfo is not None and timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=att_time.tzinfo)

                if det_time is not None:
                    if det_time.tzinfo is None and timestamp.tzinfo is not None:
                        det_time = det_time.replace(tzinfo=timestamp.tzinfo)
                    elif det_time.tzinfo is not None and timestamp.tzinfo is None:
                        timestamp = timestamp.replace(tzinfo=det_time.tzinfo)

                if att_time <= timestamp and (det_time is None or timestamp < det_time):
                    active_sgs.append(att.security_group_id)
        return active_sgs

    def get_resource_ids_for_ip(self, ip_address: str) -> List[str]:
        """Map IP address to associated ENI resource IDs based on snapshot."""
        matched = []
        for eni_id, ips in self.eni_to_ip_map.items():
            if ip_address in ips:
                matched.append(eni_id)
        return matched


class GraphNode(BaseModel):
    """Represents an entity or endpoint in the directed attack path graph."""
    model_config = ConfigDict(extra="allow")

    node_id: str
    node_type: str  # e.g., 'eni', 'instance', 'security_group', 'ip_endpoint'
    ip_addresses: List[str] = Field(default_factory=list)
    label: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """Represents a directed relationship between two entities."""
    model_config = ConfigDict(extra="allow")

    edge_id: str
    source_node: str
    target_node: str
    relation: str
    observed_or_inferred: str  # 'observed', 'permitted', or 'inferred'
    evidence_event_ids: List[str] = Field(default_factory=list)
    valid_time: Optional[datetime] = None
    confidence_reason: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class GraphData(BaseModel):
    """JSON-serializable container of graph nodes and edges for Member 3 API."""
    model_config = ConfigDict(extra="allow")

    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)


class CandidatePath(BaseModel):
    """Structured result representing a candidate traversal sequence."""
    model_config = ConfigDict(extra="allow")

    path_id: str
    node_ids: List[str]
    edge_ids: List[str]
    evidence_event_ids: List[str]
    relationship_types: List[str]
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    contains_inferred_relationships: bool = False
    uncertainty_reasons: List[str] = Field(default_factory=list)


class PriorityScoreResult(BaseModel):
    """Structured, explainable priority score breakdown."""
    model_config = ConfigDict(extra="allow")

    final_score: float  # Bounded [0.0, 100.0]
    priority_level: PriorityLevel  # LOW, MEDIUM, HIGH, CRITICAL
    factor_contributions: Dict[str, float] = Field(default_factory=dict)
    explanation: str
    uncertainty_reasons: List[str] = Field(default_factory=list)
    scoring_version: str = "1.0.0"
    missing_fields: List[str] = Field(default_factory=list)


class ScoredAlert(BaseModel):
    """Envelope linking original DetectionAlert with its explainable priority score."""
    model_config = ConfigDict(extra="allow")

    alert: DetectionAlert
    score_result: PriorityScoreResult


class AnalysisResult(BaseModel):
    """Main interface output contract: JSON-serializable alerts, graph nodes, and edges."""
    model_config = ConfigDict(extra="allow")

    alerts: List[DetectionAlert] = Field(default_factory=list)
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    candidate_paths: List[CandidatePath] = Field(default_factory=list)
    scored_alerts: List[ScoredAlert] = Field(default_factory=list)




