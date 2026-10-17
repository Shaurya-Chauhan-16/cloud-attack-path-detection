"""Shared constants across detection and telemetry pipelines."""

# Protocol number to standard name mapping
IP_PROTOCOL_MAP = {
    "6": "tcp",
    "17": "udp",
    "1": "icmp",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "-1": "all",
    "all": "all",
}

# Standard rule versions
NETWORK_BASELINE_RULE_ID = "NET-BL-001"
NETWORK_BASELINE_RULE_VERSION = "1.0.0"

CROSS_LAYER_RULE_ID = "CORR-CROSS-001"
CROSS_LAYER_RULE_VERSION = "1.0.0"
DEFAULT_CORRELATION_WINDOW_SECONDS = 300

PRIORITY_SCORER_VERSION = "1.0.0"
