"""Unit tests for Phase 2 API schemas, services, and endpoints."""
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.schemas.alerts import AlertFilterParams, AlertResponse
from src.api.schemas.cases import CaseCreateRequest
from src.api.schemas.events import EventEvidenceResponse, TelemetryEventResponse
from src.api.schemas.graph import GraphResponse
from src.api.services.alert_service import AlertService
from src.api.services.case_service import CaseService
from src.api.services.evidence_service import EvidenceService
from src.api.services.timeline_service import GraphService
from src.shared.enums import EventSource, PriorityLevel
from src.shared.models import (
    AnalysisResult,
    BaseTelemetryEvent,
    CandidatePath,
    DetectionAlert,
    GraphEdge,
    GraphNode,
    PriorityScoreResult,
    ScoredAlert,
)


@pytest.fixture
def empty_alert_service():
    """Service backed by an empty analysis result."""
    empty_result = AnalysisResult(
        alerts=[],
        nodes=[],
        edges=[],
        candidate_paths=[],
        scored_alerts=[],
    )
    return AlertService(cached_result=empty_result)


@pytest.fixture
def populated_alert_service():
    """Service populated with sample alerts and graph."""
    now = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
    alert = DetectionAlert(
        alert_id="alert-test-001",
        rule_id="CORR-CROSS-001",
        rule_version="1.0.0",
        priority=PriorityLevel.HIGH,
        explanation="Test cross-layer correlation explanation.",
        evidence_event_ids=["ct-01", "fl-01"],
        related_resource_ids=["eni-target", "sg-target"],
        created_at=now,
    )
    score_result = PriorityScoreResult(
        final_score=85.0,
        priority_level=PriorityLevel.HIGH,
        explanation="High severity due to administrative cross-layer enablement.",
    )
    node1 = GraphNode(node_id="node-1", node_type="eni", ip_addresses=["10.0.1.10"])
    node2 = GraphNode(node_id="node-2", node_type="sg", ip_addresses=[])
    edge = GraphEdge(
        edge_id="edge-1",
        source_node="node-1",
        target_node="node-2",
        relation="inferred_sequence",
        observed_or_inferred="inferred",
        evidence_event_ids=["ct-01", "fl-01"],
    )
    result = AnalysisResult(
        alerts=[alert],
        nodes=[node1, node2],
        edges=[edge],
        candidate_paths=[
            CandidatePath(
                path_id="path-1",
                node_ids=["node-1", "node-2"],
                edge_ids=["edge-1"],
                evidence_event_ids=["ct-01", "fl-01"],
                relationship_types=["inferred_sequence"],
                contains_inferred_relationships=True,
                uncertainty_reasons=["Heuristic timing correlation"],
            )
        ],
        scored_alerts=[ScoredAlert(alert=alert, score_result=score_result)],
    )
    return AlertService(cached_result=result)


# --- 1. Schema Validation Tests ---

def test_alert_schema_validation():
    """Test AlertResponse schema validation with and without score_result."""
    now = datetime.now(timezone.utc)
    alert_data = {
        "alert_id": "alt-101",
        "rule_id": "CORR-CROSS-001",
        "rule_version": "1.0.0",
        "priority": "high",
        "explanation": "Valid test explanation",
        "evidence_event_ids": ["e1", "e2"],
        "related_resource_ids": ["res-1"],
        "created_at": now.isoformat(),
        "details": {"test": "data"},
    }
    resp = AlertResponse.model_validate(alert_data)
    assert resp.alert_id == "alt-101"
    assert resp.priority == PriorityLevel.HIGH
    assert resp.score_result is None


def test_telemetry_schema_validation():
    """Test TelemetryEventResponse validation adhering to BaseTelemetryEvent."""
    now = datetime.now(timezone.utc)
    event_data = {
        "event_id": "evt-01",
        "timestamp": now.isoformat(),
        "source": "vpc_flow",
        "action": "ACCEPT",
        "resource_id": "eni-12345",
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "destination_port": 8080,
        "details": {"protocol": "tcp"},
    }
    resp = TelemetryEventResponse.model_validate(event_data)
    assert resp.event_id == "evt-01"
    assert resp.source == EventSource.VPC_FLOW
    assert resp.protocol == "tcp"


def test_graph_schema_observed_vs_inferred():
    """Test GraphResponse preserves observed and inferred counts and edges."""
    node = GraphNode(node_id="n1", node_type="eni")
    e_obs = GraphEdge(
        edge_id="e1",
        source_node="n1",
        target_node="n2",
        relation="observed_communication",
        observed_or_inferred="observed",
    )
    e_inf = GraphEdge(
        edge_id="e2",
        source_node="n2",
        target_node="n3",
        relation="inferred_sequence",
        observed_or_inferred="inferred",
    )
    graph = GraphResponse(
        nodes=[node],
        edges=[e_obs, e_inf],
        total_nodes=1,
        total_edges=2,
        observed_edge_count=1,
        inferred_edge_count=1,
    )
    assert graph.observed_edge_count == 1
    assert graph.inferred_edge_count == 1
    assert graph.edges[1].observed_or_inferred == "inferred"


# --- 2. Service Layer Tests ---

def test_alert_service_empty_dataset(empty_alert_service):
    """Test AlertService with empty analysis returns empty list and handles missing ID."""
    alerts = empty_alert_service.list_alerts()
    assert alerts == []

    missing = empty_alert_service.get_alert_by_id("non-existent-alert")
    assert missing is None


def test_alert_service_filtering(populated_alert_service):
    """Test AlertService listing and filtering."""
    # List all
    alerts = populated_alert_service.list_alerts()
    assert len(alerts) == 1
    assert alerts[0].alert_id == "alert-test-001"
    assert alerts[0].score_result is not None
    assert alerts[0].score_result.final_score == 85.0

    # Filter matching
    matching = populated_alert_service.list_alerts(
        AlertFilterParams(priority=PriorityLevel.HIGH)
    )
    assert len(matching) == 1

    # Filter non-matching
    non_matching = populated_alert_service.list_alerts(
        AlertFilterParams(priority=PriorityLevel.LOW)
    )
    assert len(non_matching) == 0

    # Retrieve by ID
    found = populated_alert_service.get_alert_by_id("alert-test-001")
    assert found is not None
    assert found.alert_id == "alert-test-001"


def test_graph_service(populated_alert_service):
    """Test GraphService generates proper counts and preserves edge classification."""
    graph_service = GraphService(alert_service=populated_alert_service)
    graph_resp = graph_service.get_attack_graph()
    assert graph_resp.total_nodes == 2
    assert graph_resp.total_edges == 1
    assert graph_resp.inferred_edge_count == 1
    assert graph_resp.observed_edge_count == 0
    assert len(graph_resp.candidate_paths) == 1
    assert graph_resp.candidate_paths[0].contains_inferred_relationships is True


def test_case_service_in_memory_behavior():
    """Test CaseService in-memory creation, listing, retrieval, and missing ID."""
    svc = CaseService()
    svc.clear()

    # Create case
    case = svc.create_case(
        CaseCreateRequest(
            title="Unauthorized Bastion SSH Investigation",
            description="Investigating port 22 opening followed by external login.",
            alert_ids=["alt-1"],
            priority=PriorityLevel.HIGH,
            tags=["investigation", "ssh"],
        )
    )
    assert case.case_id.startswith("case-")
    assert case.status == "open"
    assert "in-memory" in case.persistence_mode

    # Retrieve case
    fetched = svc.get_case(case.case_id)
    assert fetched is not None
    assert fetched.title == case.title

    # Add alert
    updated = svc.add_alert_to_case(case.case_id, "alt-2")
    assert "alt-2" in updated.alert_ids

    # Missing case
    missing = svc.get_case("case-nonexistent")
    assert missing is None


def test_evidence_service_uncertainty_notes():
    """Test EvidenceService uncertainty preservation and evidence assembly."""
    evidence_svc = EvidenceService()
    # Mocking repository lookup via dummy list
    res = evidence_svc.get_evidence_for_alert(
        alert_id="alt-demo",
        evidence_event_ids=[],
        uncertainty_disclaimer="Custom temporal gap notice.",
    )
    assert res.alert_id == "alt-demo"
    assert len(res.uncertainty_notes) >= 3
    assert any("Custom temporal gap notice." in n for n in res.uncertainty_notes)
    assert any("Attribution disclaimer" in n for n in res.uncertainty_notes)


# --- 3. Endpoints Integration Tests ---

def test_api_alerts_endpoints():
    """Test /alerts API routes with TestClient."""
    client = TestClient(app)
    response = client.get("/alerts")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data

    # 404 on missing alert
    missing_resp = client.get("/alerts/missing-id-404")
    assert missing_resp.status_code == 404


def test_api_events_endpoints():
    """Test /events and /events/{event_id} routes with TestClient."""
    client = TestClient(app)
    response = client.get("/events?limit=5")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data

    # 404 on missing event
    missing_resp = client.get("/events/non-existent-event-999")
    assert missing_resp.status_code == 404


def test_api_graph_endpoint():
    """Test /graph endpoint returning GraphResponse."""
    client = TestClient(app)
    response = client.get("/graph")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert "candidate_paths" in data
    assert "inferred_edge_count" in data


def test_api_cases_endpoints():
    """Test /cases POST and GET endpoints."""
    client = TestClient(app)
    create_payload = {
        "title": "API Test Case",
        "description": "Integration test created case",
        "priority": "critical",
        "alert_ids": ["alt-test"],
        "tags": ["api-test"],
    }
    create_resp = client.post("/cases", json=create_payload)
    assert create_resp.status_code == 201
    created_case = create_resp.json()
    case_id = created_case["case_id"]

    # Get case
    get_resp = client.get(f"/cases/{case_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["title"] == "API Test Case"

    # Missing case 404
    missing_resp = client.get("/cases/case-missing-999")
    assert missing_resp.status_code == 404
