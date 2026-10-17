"""Unit tests for security-group-to-security-group (SG-to-SG) reference handling.

Covers CrossLayerCorrelator (AWS UserIdGroupPairs / source_security_group_id) and
GraphBuilder representation of the verified references.
"""
from datetime import datetime, timezone, timedelta
import pytest

from src.shared.enums import EdgeNature, EventSource, RelationshipType
from src.shared.models import (
    BaseTelemetryEvent,
    ConfigurationHistory,
    SecurityGroupAttachment,
)
from src.detection.correlation.cross_layer import CrossLayerCorrelator
from src.detection.graph.builder import GraphBuilder


@pytest.fixture
def t0():
    return datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def config(t0):
    """eni-app carries sg-app (the referenced SG); eni-db carries sg-db (the protected SG)."""
    day_ago = t0 - timedelta(days=1)
    return ConfigurationHistory(
        attachments=[
            SecurityGroupAttachment(resource_id="eni-app", security_group_id="sg-app", attached_at=day_ago),
            SecurityGroupAttachment(resource_id="eni-db", security_group_id="sg-db", attached_at=day_ago),
        ],
        eni_to_ip_map={"eni-app": ["10.0.2.10"], "eni-db": ["10.0.3.20"]},
    )


def _authorize(t0, details, event_id="ct-ref-001", resource_id="sg-db"):
    return BaseTelemetryEvent(
        event_id=event_id,
        timestamp=t0,
        source=EventSource.CLOUDTRAIL,
        action="AuthorizeSecurityGroupIngress",
        actor="arn:aws:iam::123456789012:user/admin-alice",
        resource_id=resource_id,
        details=details,
    )


def _revoke(t0, details, event_id="ct-rev-001", resource_id="sg-db"):
    return BaseTelemetryEvent(
        event_id=event_id,
        timestamp=t0,
        source=EventSource.CLOUDTRAIL,
        action="RevokeSecurityGroupIngress",
        resource_id=resource_id,
        details=details,
    )


def _flow(t0, source_ip="10.0.2.10", dest_ip="10.0.3.20", port=5432, offset=30, event_id="flow-ref-001"):
    return BaseTelemetryEvent(
        event_id=event_id,
        timestamp=t0 + timedelta(seconds=offset),
        source=EventSource.VPC_FLOW,
        action="ACCEPT",
        resource_id="eni-db",
        source_ip=source_ip,
        destination_ip=dest_ip,
        destination_port=port,
        details={"protocol": "tcp"},
    )


def _aws_perm(pairs, port=5432):
    return {
        "ip_permissions": [
            {"ipProtocol": "tcp", "fromPort": port, "toPort": port, "userIdGroupPairs": pairs}
        ]
    }


# --------------------------------------------------------------------------- #
# Valid references
# --------------------------------------------------------------------------- #

def test_user_id_group_pairs_reference_correlates(t0, config):
    """Valid UserIdGroupPairs reference + flow from an ENI attached to the referenced SG -> alert."""
    ct = _authorize(t0, _aws_perm([{"groupId": "sg-app", "userId": "123456789012"}]))
    alerts = CrossLayerCorrelator().correlate([ct, _flow(t0)], config)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.related_resource_ids == ["eni-db"]
    assert alert.details["referenced_security_group_ids"] == ["sg-app"]
    assert alert.details["sg_references"] == [
        {
            "referenced_security_group_id": "sg-app",
            "security_group_id": "sg-db",
            "protocol": "tcp",
            "from_port": 5432,
            "to_port": 5432,
            "source_resource_ids": ["eni-app"],
        }
    ]
    assert "referenced_sg=sg-app" in alert.explanation


@pytest.mark.parametrize("key", ["GroupId", "group_id"])
def test_alternate_group_id_key_spellings(t0, config, key):
    ct = _authorize(t0, _aws_perm([{key: "sg-app"}]))
    assert len(CrossLayerCorrelator().correlate([ct, _flow(t0)], config)) == 1


@pytest.mark.parametrize("perm_key", ["UserIdGroupPairs", "user_id_group_pairs"])
def test_alternate_pairs_key_spellings(t0, config, perm_key):
    details = {"ip_permissions": [{"ipProtocol": "tcp", "fromPort": 5432, "toPort": 5432,
                                   perm_key: [{"groupId": "sg-app"}]}]}
    assert len(CrossLayerCorrelator().correlate([_authorize(t0, details), _flow(t0)], config)) == 1


@pytest.mark.parametrize("key", ["source_security_group_id", "sourceSecurityGroupId"])
def test_flat_source_security_group_id_correlates(t0, config, key):
    """Flat normalized event with source_security_group_id is handled."""
    ct = _authorize(t0, {"protocol": "tcp", "from_port": 5432, "to_port": 5432, key: "sg-app"})
    alerts = CrossLayerCorrelator().correlate([ct, _flow(t0)], config)
    assert len(alerts) == 1
    assert alerts[0].details["referenced_security_group_ids"] == ["sg-app"]


def test_multiple_group_pairs_each_become_a_rule(t0, config):
    """Only the pair whose SG the source actually carries enables the flow."""
    ct = _authorize(t0, _aws_perm([{"groupId": "sg-other"}, {"groupId": "sg-app"}]))
    alerts = CrossLayerCorrelator().correlate([ct, _flow(t0)], config)
    assert len(alerts) == 1
    assert alerts[0].details["referenced_security_group_ids"] == ["sg-app"]


def test_cidr_and_group_pair_in_same_permission(t0, config):
    """A permission with both ipRanges and group pairs yields both kinds of rule."""
    details = {"ip_permissions": [{
        "ipProtocol": "tcp", "fromPort": 5432, "toPort": 5432,
        "ipRanges": [{"cidrIp": "198.51.100.0/24"}],
        "userIdGroupPairs": [{"groupId": "sg-app"}],
    }]}
    ct = _authorize(t0, details)
    cidr_flow = _flow(t0, source_ip="198.51.100.9", event_id="flow-cidr")
    alerts = CrossLayerCorrelator().correlate([ct, _flow(t0), cidr_flow], config)
    assert len(alerts) == 1
    assert sorted(alerts[0].evidence_event_ids[1:]) == ["flow-cidr", "flow-ref-001"]
    assert alerts[0].details["referenced_security_group_ids"] == ["sg-app"]


def test_existing_cidr_rules_unchanged_by_sg_support(t0, config):
    """Regression: CIDR-only rules still work and record no SG references."""
    ct = _authorize(t0, {"protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidr_ipv4": "10.0.2.0/24"})
    alerts = CrossLayerCorrelator().correlate([ct, _flow(t0)], config)
    assert len(alerts) == 1
    assert alerts[0].details["sg_references"] == []
    assert alerts[0].details["referenced_security_group_ids"] == []


# --------------------------------------------------------------------------- #
# Missing / unusable references
# --------------------------------------------------------------------------- #

def test_reference_does_not_act_as_wildcard(t0, config):
    """An SG reference must never be widened to 0.0.0.0/0: a flow from an unrelated IP gets no alert."""
    ct = _authorize(t0, _aws_perm([{"groupId": "sg-app"}]))
    outsider = _flow(t0, source_ip="203.0.113.77")
    assert CrossLayerCorrelator().correlate([ct, outsider], config) == []


def test_source_not_in_referenced_sg_no_alert(t0, config):
    """Referenced SG exists in config but the flow source ENI is not attached to it."""
    ct = _authorize(t0, _aws_perm([{"groupId": "sg-app"}]))
    flow = _flow(t0, source_ip="10.0.3.20")  # eni-db, carries sg-db only
    assert CrossLayerCorrelator().correlate([ct, flow], config) == []


def test_referenced_sg_unknown_to_configuration_no_alert(t0, config):
    """Reference to an SG that no known ENI carries cannot be verified -> no alert."""
    ct = _authorize(t0, _aws_perm([{"groupId": "sg-ghost"}]))
    assert CrossLayerCorrelator().correlate([ct, _flow(t0)], config) == []


def test_no_configuration_history_no_alert(t0):
    """SG membership cannot be verified without configuration history -> conservative no alert."""
    ct = _authorize(t0, _aws_perm([{"groupId": "sg-app"}]))
    assert CrossLayerCorrelator().correlate([ct, _flow(t0)], None) == []


def test_unknown_source_ip_no_alert(t0, config):
    ct = _authorize(t0, _aws_perm([{"groupId": "sg-app"}]))
    assert CrossLayerCorrelator().correlate([ct, _flow(t0, source_ip="10.9.9.9")], config) == []


def test_ambiguous_source_mapping_no_alert(t0):
    """Source IP shared by two ENIs is not silently resolved."""
    day_ago = t0 - timedelta(days=1)
    cfg = ConfigurationHistory(
        attachments=[
            SecurityGroupAttachment(resource_id="eni-app", security_group_id="sg-app", attached_at=day_ago),
            SecurityGroupAttachment(resource_id="eni-app2", security_group_id="sg-app", attached_at=day_ago),
            SecurityGroupAttachment(resource_id="eni-db", security_group_id="sg-db", attached_at=day_ago),
        ],
        eni_to_ip_map={"eni-app": ["10.0.2.10"], "eni-app2": ["10.0.2.10"], "eni-db": ["10.0.3.20"]},
    )
    ct = _authorize(t0, _aws_perm([{"groupId": "sg-app"}]))
    assert CrossLayerCorrelator().correlate([ct, _flow(t0)], cfg) == []


def test_source_sg_attached_after_flow_no_alert(t0):
    """Membership is evaluated at flow time: attaching sg-app after the flow does not count."""
    cfg = ConfigurationHistory(
        attachments=[
            SecurityGroupAttachment(resource_id="eni-app", security_group_id="sg-app",
                                    attached_at=t0 + timedelta(minutes=10)),
            SecurityGroupAttachment(resource_id="eni-db", security_group_id="sg-db",
                                    attached_at=t0 - timedelta(days=1)),
        ],
        eni_to_ip_map={"eni-app": ["10.0.2.10"], "eni-db": ["10.0.3.20"]},
    )
    ct = _authorize(t0, _aws_perm([{"groupId": "sg-app"}]))
    assert CrossLayerCorrelator().correlate([ct, _flow(t0)], cfg) == []


def test_source_sg_detached_before_flow_no_alert(t0):
    cfg = ConfigurationHistory(
        attachments=[
            SecurityGroupAttachment(resource_id="eni-app", security_group_id="sg-app",
                                    attached_at=t0 - timedelta(days=1), detached_at=t0 + timedelta(seconds=10)),
            SecurityGroupAttachment(resource_id="eni-db", security_group_id="sg-db",
                                    attached_at=t0 - timedelta(days=1)),
        ],
        eni_to_ip_map={"eni-app": ["10.0.2.10"], "eni-db": ["10.0.3.20"]},
    )
    ct = _authorize(t0, _aws_perm([{"groupId": "sg-app"}]))
    assert CrossLayerCorrelator().correlate([ct, _flow(t0, offset=30)], cfg) == []


@pytest.mark.parametrize("pairs", [[{}], [{"groupId": ""}], [{"groupId": None}], [{"groupId": 123}], [None]])
def test_malformed_group_pairs_produce_no_rule_and_no_wildcard(t0, config, pairs):
    """Unusable group pair must not fall back to a 0.0.0.0/0 wildcard."""
    ct = _authorize(t0, _aws_perm(pairs))
    correlator = CrossLayerCorrelator()
    assert correlator._extract_sg_rules_from_event(ct) == []
    outsider = _flow(t0, source_ip="203.0.113.77")
    assert correlator.correlate([ct, _flow(t0), outsider], config) == []


def test_empty_flat_source_security_group_id_produces_no_rule(t0):
    ct = _authorize(t0, {"protocol": "tcp", "from_port": 5432, "to_port": 5432, "source_security_group_id": ""})
    assert CrossLayerCorrelator()._extract_sg_rules_from_event(ct) == []


def test_failed_authorization_with_reference_no_alert(t0, config):
    details = _aws_perm([{"groupId": "sg-app"}])
    details["errorCode"] = "UnauthorizedOperation"
    assert CrossLayerCorrelator().correlate([_authorize(t0, details), _flow(t0)], config) == []


# --------------------------------------------------------------------------- #
# Revocation
# --------------------------------------------------------------------------- #

def test_revoking_the_sg_reference_invalidates_flow(t0, config):
    ct = _authorize(t0, _aws_perm([{"groupId": "sg-app"}]))
    rev = _revoke(t0 + timedelta(seconds=10), _aws_perm([{"groupId": "sg-app"}]))
    assert CrossLayerCorrelator().correlate([ct, rev, _flow(t0, offset=30)], config) == []


def test_revoking_a_different_reference_does_not_invalidate(t0, config):
    ct = _authorize(t0, _aws_perm([{"groupId": "sg-app"}]))
    rev = _revoke(t0 + timedelta(seconds=10), _aws_perm([{"groupId": "sg-other"}]))
    assert len(CrossLayerCorrelator().correlate([ct, rev, _flow(t0, offset=30)], config)) == 1


def test_revoking_a_cidr_rule_does_not_revoke_sg_reference(t0, config):
    ct = _authorize(t0, _aws_perm([{"groupId": "sg-app"}]))
    rev = _revoke(t0 + timedelta(seconds=10),
                  {"protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidr_ipv4": "0.0.0.0/0"})
    assert len(CrossLayerCorrelator().correlate([ct, rev, _flow(t0, offset=30)], config)) == 1


def test_revoking_an_sg_reference_does_not_revoke_cidr_rule(t0, config):
    ct = _authorize(t0, {"protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidr_ipv4": "10.0.2.0/24"})
    rev = _revoke(t0 + timedelta(seconds=10), _aws_perm([{"groupId": "sg-app"}]))
    assert len(CrossLayerCorrelator().correlate([ct, rev, _flow(t0, offset=30)], config)) == 1


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #

def test_sg_reference_alert_is_deterministic_across_input_order(t0, config):
    ct = _authorize(t0, _aws_perm([{"groupId": "sg-app"}]))
    f1, f2 = _flow(t0, offset=20, event_id="flow-a"), _flow(t0, offset=40, event_id="flow-b")
    a1 = CrossLayerCorrelator().correlate([ct, f1, f2], config)[0]
    a2 = CrossLayerCorrelator().correlate([f2, f1, ct], config)[0]
    assert a1.evidence_event_ids == a2.evidence_event_ids
    assert a1.details["sg_references"] == a2.details["sg_references"]


# --------------------------------------------------------------------------- #
# Graph relationships
# --------------------------------------------------------------------------- #

def _build(t0, config, details):
    events = [_authorize(t0, details), _flow(t0)]
    alerts = CrossLayerCorrelator().correlate(events, config)
    builder = GraphBuilder()
    graph = builder.build_from_telemetry(events, config, alerts)
    return builder, graph, alerts


def _edges(graph, src, dst, relation):
    return [d for _, _, d in graph.out_edges(src, data=True)
            if d["target_node"] == dst and d["relation"] == relation]


def test_graph_has_sg_to_sg_permitted_edge(t0, config):
    _, graph, alerts = _build(t0, config, _aws_perm([{"groupId": "sg-app"}]))
    edges = _edges(graph, "sg-app", "sg-db", RelationshipType.PERMITTED_REACHABILITY.value)
    assert len(edges) == 1
    edge = edges[0]
    assert edge["observed_or_inferred"] == EdgeNature.PERMITTED.value
    assert edge["evidence_event_ids"] == ["ct-ref-001"]
    assert edge["protocol"] == "tcp"
    assert edge["port"] == 5432
    assert edge["valid_time"] == t0
    assert edge["details"]["source_resource_ids"] == ["eni-app"]
    assert edge["details"]["alert_id"] == alerts[0].alert_id
    assert graph.nodes["sg-app"]["node_type"] == "security_group"
    assert graph.nodes["sg-db"]["node_type"] == "security_group"


def test_graph_sg_reference_direction_is_referenced_to_protected(t0, config):
    """Direction: referenced (source) SG -> protected SG, never the reverse."""
    _, graph, _ = _build(t0, config, _aws_perm([{"groupId": "sg-app"}]))
    assert graph.has_edge("sg-app", "sg-db")
    assert not _edges(graph, "sg-db", "sg-app", RelationshipType.PERMITTED_REACHABILITY.value)


def test_graph_connects_source_eni_through_sgs_to_target_eni(t0, config):
    """eni-app -> sg-app -> sg-db -> eni-db is traversable via attachment, reference and inferred edges."""
    _, graph, _ = _build(t0, config, _aws_perm([{"groupId": "sg-app"}]))
    assert graph.has_edge("eni-app", "sg-app")
    assert graph.has_edge("sg-app", "sg-db")
    assert _edges(graph, "sg-db", "eni-db", RelationshipType.INFERRED_SEQUENCE.value)


def test_graph_sg_edge_serializes_through_graph_data(t0, config):
    builder, _, _ = _build(t0, config, _aws_perm([{"groupId": "sg-app"}]))
    data = builder.to_graph_data()
    matches = [e for e in data.edges if e.source_node == "sg-app" and e.target_node == "sg-db"]
    assert len(matches) == 1
    assert matches[0].relation == "permitted_reachability"
    assert matches[0].details["from_port"] == 5432


def test_graph_port_range_not_collapsed_to_single_port(t0, config):
    details = {"ip_permissions": [{"ipProtocol": "tcp", "fromPort": 5432, "toPort": 5440,
                                   "userIdGroupPairs": [{"groupId": "sg-app"}]}]}
    ct = _authorize(t0, details)
    flow = _flow(t0, port=5435)
    alerts = CrossLayerCorrelator().correlate([ct, flow], config)
    builder = GraphBuilder()
    graph = builder.build_from_telemetry([ct, flow], config, alerts)
    edge = _edges(graph, "sg-app", "sg-db", RelationshipType.PERMITTED_REACHABILITY.value)[0]
    assert edge["port"] is None
    assert (edge["details"]["from_port"], edge["details"]["to_port"]) == (5432, 5440)


def test_graph_missing_reference_creates_no_sg_edge(t0, config):
    """Unverifiable reference -> no alert -> no SG-to-SG edge and no fabricated sg node."""
    events = [_authorize(t0, _aws_perm([{"groupId": "sg-ghost"}])), _flow(t0)]
    alerts = CrossLayerCorrelator().correlate(events, config)
    assert alerts == []
    graph = GraphBuilder().build_from_telemetry(events, config, alerts)
    assert "sg-ghost" not in graph.nodes
    assert not graph.has_edge("sg-app", "sg-db")


def test_graph_cidr_alert_has_no_sg_reference_edge(t0, config):
    """CIDR-based alert keeps previous graph shape: no SG-to-SG edge."""
    details = {"protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidr_ipv4": "10.0.2.0/24"}
    _, graph, alerts = _build(t0, config, details)
    assert len(alerts) == 1
    assert not graph.has_edge("sg-app", "sg-db")


def test_graph_ignores_malformed_sg_references_on_alert(t0):
    """Hand-built/legacy alerts with malformed sg_references add no edges and don't crash."""
    from src.shared.models import DetectionAlert
    from src.shared.enums import PriorityLevel
    alert = DetectionAlert(
        alert_id="a1", rule_id="R", rule_version="1", priority=PriorityLevel.HIGH,
        explanation="x", evidence_event_ids=["ct-1"], related_resource_ids=[],
        created_at=t0,
        details={"cloudtrail_event_id": "ct-1", "security_group_id": "sg-db",
                 "sg_references": [{"referenced_security_group_id": ""}, {"security_group_id": "sg-db"},
                                   "junk", None, {"referenced_security_group_id": 5}]},
    )
    graph = GraphBuilder().build_from_telemetry([], None, [alert])
    assert graph.number_of_edges() == 0


def test_graph_repeated_alert_deduplicates_sg_edge_evidence(t0, config):
    events = [_authorize(t0, _aws_perm([{"groupId": "sg-app"}])), _flow(t0)]
    alerts = CrossLayerCorrelator().correlate(events, config)
    builder = GraphBuilder()
    graph = builder.build_from_telemetry(events, config, alerts + alerts)
    assert len(_edges(graph, "sg-app", "sg-db", RelationshipType.PERMITTED_REACHABILITY.value)) == 1
