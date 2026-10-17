"""Reports API router for incident report export."""
from fastapi import APIRouter, Depends, HTTPException, Query, Response

from src.api.dependencies import get_alert_service, get_case_service, get_evidence_service, get_graph_service
from src.api.services.alert_service import AlertService
from src.api.services.case_service import CaseService
from src.api.services.evidence_service import EvidenceService
from src.api.services.timeline_service import GraphService
from src.reports.exporter import ReportExporter

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/cases/{case_id}/html", response_class=Response)
async def export_case_report_html(
    case_id: str,
    case_service: CaseService = Depends(get_case_service),
    alert_service: AlertService = Depends(get_alert_service),
    evidence_service: EvidenceService = Depends(get_evidence_service),
    graph_service: GraphService = Depends(get_graph_service),
) -> Response:
    """Generate and return a standalone HTML incident report for an investigation case.

    Safely handles unknown case IDs with 404, escapes untrusted telemetry strings,
    and documents synthetic evaluation data and in-memory persistence status.
    """
    case = case_service.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    # Fetch alerts linked to this case
    all_alerts = alert_service.list_alerts()
    case_alerts = [a for a in all_alerts if a.alert_id in case.alert_ids or a.case_id == case_id]

    # Assemble linked evidence events across the case alerts
    evidence_event_ids = []
    uncertainty_notes = []
    for a in case_alerts:
        evidence_event_ids.extend(a.evidence_event_ids)
        if a.details and "uncertainty_notes" in a.details:
            uncertainty_notes.append(a.details["uncertainty_notes"])

    evidence_bundle = None
    if evidence_event_ids:
        evidence_bundle = evidence_service.get_evidence_for_alert(
            alert_id=case_id,
            evidence_event_ids=list(set(evidence_event_ids)),
            uncertainty_disclaimer="; ".join(uncertainty_notes) if uncertainty_notes else None,
        )

    # Fetch topology
    graph_data = graph_service.get_attack_graph()

    html_content = ReportExporter.generate_case_html_report(
        case=case,
        alerts=case_alerts,
        evidence_bundle=evidence_bundle,
        graph_data=graph_data,
        is_synthetic=True,
    )

    filename = f"incident-report-{case_id}.html"
    return Response(
        content=html_content,
        media_type="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Report-Format": "HTML",
            "X-Persistence-Mode": case.persistence_mode,
        },
    )
