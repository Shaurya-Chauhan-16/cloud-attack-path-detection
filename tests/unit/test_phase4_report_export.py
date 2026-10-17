"""Unit tests for Phase 4 Report Exporter and HTML Report Endpoint."""
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.schemas.alerts import AlertResponse
from src.api.schemas.cases import CaseResponse
from src.api.schemas.events import EventEvidenceResponse, TelemetryEventResponse
from src.api.schemas.graph import GraphResponse
from src.reports.exporter import ReportExporter, escape
from src.shared.enums import EventSource, PriorityLevel
from src.shared.models import GraphEdge, GraphNode, PriorityScoreResult


def test_html_escaping_utility():
    """Verify that script tags, angle brackets, and quotes are properly escaped."""
    malicious = "<script>alert('XSS')</script> & \"quote\""
    sanitized = escape(malicious)
    assert "<script>" not in sanitized
    assert "&lt;script&gt;" in sanitized
    assert "&amp;" in sanitized
    assert "&quot;quote&quot;" in sanitized
    assert escape(None) == ""


def test_report_exporter_with_malicious_untrusted_input():
    """Verify that malicious event payloads and case titles cannot inject HTML into the report."""
    now = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
    case = CaseResponse(
        case_id="case-sec-001",
        title="<script>document.cookie</script> Ingress Attack",
        description="<img src=x onerror=alert(1)>",
        priority=PriorityLevel.CRITICAL,
        status="open",
        alert_ids=["alt-xss"],
        tags=["<b onmouseover=evil()>tag</b>"],
        created_at=now,
        updated_at=now,
        persistence_mode="in-memory",
    )

    alert = AlertResponse(
        alert_id="<script>alert(2)</script>",
        rule_id="RULE-<XSS>",
        rule_version="1.0.0",
        priority=PriorityLevel.HIGH,
        explanation="<iframe src='malicious.com'></iframe>",
        evidence_event_ids=["evt-1"],
        related_resource_ids=["<svg onload=alert(3)>"],
        created_at=now,
        score_result=PriorityScoreResult(
            final_score=95.0,
            priority_level=PriorityLevel.CRITICAL,
            explanation="<script>score_expl</script>",
        ),
    )

    event = TelemetryEventResponse(
        event_id="evt-1",
        timestamp=now,
        source=EventSource.CLOUDTRAIL,
        action="<script>evil_action()</script>",
        actor="<script>evil_actor()</script>",
        resource_id="sg-<xss>",
        source_ip="1.2.3.4",
        details={},
    )

    evidence_bundle = EventEvidenceResponse(
        alert_id=alert.alert_id,
        evidence_events=[event],
        uncertainty_notes=["<script>fake_note()</script>"],
        total_events=1,
    )

    report_html = ReportExporter.generate_case_html_report(
        case=case,
        alerts=[alert],
        evidence_bundle=evidence_bundle,
        graph_data=None,
        is_synthetic=True,
    )

    # Assert dangerous unescaped tags are absent
    assert "<script>" not in report_html
    assert "</script>" not in report_html
    assert "<img src=x onerror=" not in report_html
    assert "<iframe" not in report_html
    assert "<svg onload=" not in report_html

    # Assert escaped versions are present
    assert "&lt;script&gt;document.cookie&lt;/script&gt;" in report_html
    assert "&lt;img src=x onerror=alert(1)&gt;" in report_html
    assert "TELEMETRY FIDELITY NOTICE" in report_html
    assert "in-memory" in report_html


def test_report_exporter_empty_datasets():
    """Verify that empty alerts, empty evidence, and empty graph are safely handled."""
    now = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
    case = CaseResponse(
        case_id="case-empty-001",
        title="Empty Test Case",
        description=None,
        priority=PriorityLevel.LOW,
        status="open",
        alert_ids=[],
        tags=[],
        created_at=now,
        updated_at=now,
        persistence_mode="in-memory",
    )

    report_html = ReportExporter.generate_case_html_report(
        case=case,
        alerts=[],
        evidence_bundle=None,
        graph_data=None,
        is_synthetic=True,
    )

    assert "No alerts currently linked" in report_html
    assert "No direct telemetry evidence events" in report_html
    assert "No attack graph topology entities" in report_html
    assert "Empty Test Case" in report_html


def test_report_exporter_with_graph_and_paths():
    """Verify graph nodes, edges, observed vs inferred classifications, and candidate paths."""
    now = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
    case = CaseResponse(
        case_id="case-graph-001",
        title="Graph Test Case",
        priority=PriorityLevel.HIGH,
        status="open",
        alert_ids=[],
        tags=["graph-test"],
        created_at=now,
        updated_at=now,
        persistence_mode="in-memory",
    )

    graph_data = GraphResponse(
        nodes=[
            GraphNode(node_id="eni-web", node_type="eni"),
            GraphNode(node_id="sg-web", node_type="security_group"),
        ],
        edges=[
            GraphEdge(
                edge_id="edge-1",
                source_node="eni-web",
                target_node="sg-web",
                relation="inferred_sequence",
                observed_or_inferred="inferred",
            ),
            GraphEdge(
                edge_id="edge-2",
                source_node="eni-web",
                target_node="eni-db",
                relation="observed_communication",
                observed_or_inferred="observed",
                port=5432,
            ),
        ],
        candidate_paths=[],
        total_nodes=2,
        total_edges=2,
        observed_edge_count=1,
        inferred_edge_count=1,
        permitted_edge_count=0,
    )

    report_html = ReportExporter.generate_case_html_report(
        case=case,
        alerts=[],
        graph_data=graph_data,
        is_synthetic=True,
    )

    assert "INFERRED" in report_html
    assert "OBSERVED" in report_html
    assert "Observed Communication" in report_html
    assert "Inferred Sequences" in report_html
    assert "eni-web &rarr; sg-web" in report_html


def test_api_report_endpoint_success_and_404():
    """Verify /reports/cases/{case_id}/html endpoint returns valid HTML file attachment."""
    client = TestClient(app)

    # 1. Create a case
    create_payload = {
        "title": "Incident Report API Test Case",
        "description": "Verifying HTML report download route",
        "priority": "high",
        "alert_ids": [],
        "tags": ["report-test"],
    }
    create_resp = client.post("/cases", json=create_payload)
    assert create_resp.status_code == 201
    case_id = create_resp.json()["case_id"]

    # 2. Export HTML report
    report_resp = client.get(f"/reports/cases/{case_id}/html")
    assert report_resp.status_code == 200
    assert report_resp.headers["content-type"].startswith("text/html")
    assert "attachment" in report_resp.headers["content-disposition"]
    assert f"incident-report-{case_id}.html" in report_resp.headers["content-disposition"]
    assert "X-Report-Format" in report_resp.headers
    assert report_resp.headers["X-Report-Format"] == "HTML"
    assert "<!DOCTYPE html>" in report_resp.text
    assert "Incident Report API Test Case" in report_resp.text

    # 3. Test unknown case ID returns 404
    missing_resp = client.get("/reports/cases/non-existent-case-id-404/html")
    assert missing_resp.status_code == 404
    assert "not found" in missing_resp.json()["detail"].lower()
