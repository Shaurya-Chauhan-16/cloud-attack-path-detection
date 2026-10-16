"""Shared enumerations for cloud attack path detection."""
from enum import Enum


class EventSource(str, Enum):
    CLOUDTRAIL = "cloudtrail"
    VPC_FLOW = "vpc_flow"
    CONFIG = "config"
    SYSTEM = "system"


class FlowAction(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"
    ANY = "*"


class PriorityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyDecision(str, Enum):
    APPROVED = "APPROVED"
    UNAPPROVED = "UNAPPROVED"
    EXCEPTION = "EXCEPTION"


class RelationshipType(str, Enum):
    """Categorization of graph edge semantics."""
    OBSERVED_COMMUNICATION = "observed_communication"
    PERMITTED_REACHABILITY = "permitted_reachability"
    INFERRED_SEQUENCE = "inferred_sequence"


class EdgeNature(str, Enum):
    OBSERVED = "observed"
    PERMITTED = "permitted"
    INFERRED = "inferred"

