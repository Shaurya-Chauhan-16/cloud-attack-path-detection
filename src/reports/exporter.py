"""HTML Incident Report Generator and Exporter.

Renders secure, escaped HTML incident reports combining case, alert,
evidence, graph, and uncertainty disclaimer data.
"""
from datetime import datetime, timezone
import html
from typing import Any, Dict, List, Optional

from src.api.schemas.alerts import AlertResponse
from src.api.schemas.cases import CaseResponse
from src.api.schemas.events import EventEvidenceResponse, TelemetryEventResponse
from src.api.schemas.graph import GraphResponse


def escape(val: Any) -> str:
    """Safely escape text for HTML output to prevent XSS / executable script injection."""
    if val is None:
        return ""
    return html.escape(str(val))


class ReportExporter:
    """Generates structured HTML forensic incident reports."""

    @staticmethod
    def generate_case_html_report(
        case: CaseResponse,
        alerts: List[AlertResponse],
        evidence_bundle: Optional[EventEvidenceResponse] = None,
        graph_data: Optional[GraphResponse] = None,
        is_synthetic: bool = True,
    ) -> str:
        """Render self-contained HTML incident report with escaped variables."""
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Case details
        case_id = escape(case.case_id)
        title = escape(case.title)
        desc = escape(case.description or "No description provided.")
        priority = escape(case.priority.upper())
        status = escape(case.status.upper())
        tags = [escape(t) for t in case.tags]
        tags_html = "".join(f'<span class="badge tag">{t}</span>' for t in tags) if tags else "<em>None</em>"
        persistence_mode = escape(case.persistence_mode)

        # Synthetic telemetry disclaimer
        synthetic_notice = ""
        if is_synthetic:
            synthetic_notice = """
            <div class="banner warning-banner">
                <strong>⚠️ TELEMETRY FIDELITY NOTICE:</strong>
                This report was generated using synthetic AWS CloudTrail and VPC Flow Log benchmark telemetry. 
                Data demonstrates cross-layer detection, topological graph reconstruction, and lateral movement analysis in a controlled evaluation environment.
            </div>
            """

        # Persistence disclaimer
        persistence_notice = f"""
        <div class="banner info-banner">
            <strong>ℹ️ CASE PERSISTENCE NOTICE:</strong>
            Case storage mode: <code>{persistence_mode}</code>. 
            Case records are managed in-memory in Phase 2/4 and will reset upon application service restart.
        </div>
        """

        # Alerts section
        alerts_html = ""
        if not alerts:
            alerts_html = "<p class='empty-text'>No alerts currently linked to this investigation case.</p>"
        else:
            alerts_rows = []
            for a in alerts:
                aid = escape(a.alert_id)
                rule = escape(f"{a.rule_id} v{a.rule_version}")
                prio = escape(a.priority.upper())
                prio_class = f"badge badge-{escape(a.priority.lower())}"
                expl = escape(a.explanation)
                score_html = "N/A"
                if a.score_result:
                    score_val = f"{a.score_result.final_score:.1f}/100"
                    score_prio = escape(a.score_result.priority_level.upper())
                    score_html = f"<strong>{escape(score_val)}</strong> ({score_prio})"
                resources = escape(", ".join(a.related_resource_ids) if a.related_resource_ids else "None")
                created = escape(a.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if hasattr(a.created_at, "strftime") else str(a.created_at))

                alerts_rows.append(f"""
                <tr>
                    <td><span class="{prio_class}">{prio}</span></td>
                    <td><code>{aid}</code></td>
                    <td><code>{rule}</code></td>
                    <td>{score_html}</td>
                    <td>{resources}</td>
                    <td>{created}</td>
                    <td>{expl}</td>
                </tr>
                """)
            alerts_html = f"""
            <table class="report-table">
                <thead>
                    <tr>
                        <th>Priority</th>
                        <th>Alert ID</th>
                        <th>Rule ID</th>
                        <th>Priority Score</th>
                        <th>Target Resources</th>
                        <th>Detected At</th>
                        <th>Explanation</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(alerts_rows)}
                </tbody>
            </table>
            """

        # Evidence events timeline
        evidence_events: List[TelemetryEventResponse] = []
        uncertainty_notes: List[str] = [
            "Correlated accepted network traffic establishes reachability enabled by configuration changes.",
            "Attribution disclaimer: Observed flow does not confirm application-layer compromise or malicious intent.",
            "IAM identity responsible for rule authorization is decoupled from the network endpoint initiating traffic.",
        ]
        if evidence_bundle:
            evidence_events = evidence_bundle.evidence_events
            if evidence_bundle.uncertainty_notes:
                uncertainty_notes = evidence_bundle.uncertainty_notes

        timeline_html = ""
        if not evidence_events:
            timeline_html = "<p class='empty-text'>No direct telemetry evidence events associated with this report.</p>"
        else:
            events_rows = []
            for e in evidence_events:
                eid = escape(e.event_id)
                src = escape(e.source.upper())
                src_class = "badge-cloudtrail" if "cloudtrail" in e.source.lower() else "badge-vpcflow"
                action = escape(e.action)
                actor_ip = escape(e.actor or f"{e.source_ip} -> {e.destination_ip}:{e.destination_port}" if e.source_ip else "—")
                target = escape(e.resource_id or "—")
                ts = escape(e.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if hasattr(e.timestamp, "strftime") else str(e.timestamp))

                events_rows.append(f"""
                <tr>
                    <td style="white-space: nowrap;"><code>{ts}</code></td>
                    <td><span class="badge {src_class}">{src}</span></td>
                    <td><strong>{action}</strong></td>
                    <td>{actor_ip}</td>
                    <td><code>{target}</code></td>
                    <td><small><code>{eid}</code></small></td>
                </tr>
                """)

            timeline_html = f"""
            <table class="report-table">
                <thead>
                    <tr>
                        <th>Timestamp (UTC)</th>
                        <th>Telemetry Source</th>
                        <th>Action</th>
                        <th>Actor / Flow Endpoint</th>
                        <th>Target Resource</th>
                        <th>Event ID</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(events_rows)}
                </tbody>
            </table>
            """

        # Graph summary
        graph_html = ""
        if not graph_data or (graph_data.total_nodes == 0 and graph_data.total_edges == 0):
            graph_html = "<p class='empty-text'>No attack graph topology entities associated with this report.</p>"
        else:
            edges_rows = []
            for edge in graph_data.edges:
                eid = escape(edge.edge_id)
                src = escape(edge.source_node)
                tgt = escape(edge.target_node)
                rel = escape(edge.relation)
                nature = escape(edge.observed_or_inferred.lower())
                nature_badge = f"badge badge-{nature}"
                port_proto = escape(f"{edge.protocol or 'tcp'}:{edge.port}" if edge.port else edge.protocol or "—")

                edges_rows.append(f"""
                <tr>
                    <td><code>{src} &rarr; {tgt}</code></td>
                    <td><span class="{nature_badge}">{nature.upper()}</span></td>
                    <td>{rel}</td>
                    <td>{port_proto}</td>
                    <td><small><code>{eid}</code></small></td>
                </tr>
                """)

            paths_html = ""
            if graph_data.candidate_paths:
                p_items = []
                for p in graph_data.candidate_paths:
                    pid = escape(p.path_id)
                    hops = escape("  →  ".join(p.node_ids))
                    has_inferred = '<span class="badge badge-inferred">Inferred Hops</span>' if p.contains_inferred_relationships else ""
                    unc = escape("; ".join(p.uncertainty_reasons)) if p.uncertainty_reasons else "None"
                    p_items.append(f"""
                    <div class="path-card">
                        <div class="path-header">
                            <strong><code>{pid}</code></strong> {has_inferred}
                        </div>
                        <div class="path-hops">{hops}</div>
                        <div class="path-uncertainty"><small>Uncertainty reasons: {unc}</small></div>
                    </div>
                    """)
                paths_html = f"""
                <h4 style="margin-top: 18px; margin-bottom: 8px;">Candidate Lateral Traversal Paths ({len(graph_data.candidate_paths)})</h4>
                {''.join(p_items)}
                """

            graph_html = f"""
            <div class="graph-stats-grid">
                <div class="stat-box">
                    <span class="stat-label">Total Nodes</span>
                    <span class="stat-value">{graph_data.total_nodes}</span>
                </div>
                <div class="stat-box">
                    <span class="stat-label">Observed Communication</span>
                    <span class="stat-value text-blue">{graph_data.observed_edge_count}</span>
                </div>
                <div class="stat-box">
                    <span class="stat-label">Permitted Reachability</span>
                    <span class="stat-value text-green">{graph_data.permitted_edge_count}</span>
                </div>
                <div class="stat-box">
                    <span class="stat-label">Inferred Sequences</span>
                    <span class="stat-value text-amber">{graph_data.inferred_edge_count}</span>
                </div>
            </div>

            <h4 style="margin-top: 18px; margin-bottom: 8px;">Multi-Relational Topology Edges ({len(graph_data.edges)})</h4>
            <table class="report-table">
                <thead>
                    <tr>
                        <th>Relationship Traversal</th>
                        <th>Nature Classification</th>
                        <th>Semantic Type</th>
                        <th>Protocol / Port</th>
                        <th>Edge ID</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(edges_rows)}
                </tbody>
            </table>
            {paths_html}
            """

        # Uncertainty notes HTML
        unc_items = "".join(f"<li>{escape(n)}</li>" for n in uncertainty_notes)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Incident Report: {title} ({case_id})</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #0b0f19;
            color: #f1f5f9;
            line-height: 1.5;
            margin: 0;
            padding: 32px;
        }}
        .report-container {{
            max-width: 1100px;
            margin: 0 auto;
            background-color: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 36px;
        }}
        h1, h2, h3, h4 {{
            color: #f8fafc;
            margin-top: 0;
        }}
        h1 {{
            font-size: 24px;
            border-bottom: 2px solid #334155;
            padding-bottom: 12px;
            margin-bottom: 16px;
        }}
        h2 {{
            font-size: 18px;
            margin-top: 32px;
            margin-bottom: 12px;
            border-bottom: 1px solid #334155;
            padding-bottom: 6px;
            color: #818cf8;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
            background-color: #0f172a;
            padding: 16px;
            border-radius: 6px;
            border: 1px solid #334155;
        }}
        .meta-item span {{
            display: block;
            font-size: 11px;
            text-transform: uppercase;
            color: #94a3b8;
            margin-bottom: 2px;
        }}
        .meta-item strong {{
            font-size: 14px;
            color: #f8fafc;
        }}
        .banner {{
            padding: 14px 18px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 13px;
        }}
        .warning-banner {{
            background-color: rgba(245, 158, 11, 0.15);
            border: 1px solid #f59e0b;
            color: #fde68a;
        }}
        .info-banner {{
            background-color: rgba(99, 102, 241, 0.15);
            border: 1px solid #6366f1;
            color: #c7d2fe;
        }}
        .report-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 12px;
            background-color: #0f172a;
            border-radius: 6px;
            overflow: hidden;
            border: 1px solid #334155;
        }}
        .report-table th, .report-table td {{
            padding: 10px 14px;
            border-bottom: 1px solid #334155;
            text-align: left;
        }}
        .report-table th {{
            background-color: #090d16;
            color: #94a3b8;
            font-weight: 600;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-critical {{ background-color: rgba(244, 63, 94, 0.2); color: #fda4af; border: 1px solid #f43f5e; }}
        .badge-high {{ background-color: rgba(245, 158, 11, 0.2); color: #fde68a; border: 1px solid #f59e0b; }}
        .badge-medium {{ background-color: rgba(234, 179, 8, 0.2); color: #fef08a; border: 1px solid #eab308; }}
        .badge-low {{ background-color: rgba(16, 185, 129, 0.2); color: #a7f3d0; border: 1px solid #10b981; }}
        .badge-cloudtrail {{ background-color: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }}
        .badge-vpcflow {{ background-color: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid #3b82f6; }}
        .badge-observed {{ background-color: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid #3b82f6; }}
        .badge-permitted {{ background-color: rgba(16, 185, 129, 0.2); color: #a7f3d0; border: 1px solid #10b981; }}
        .badge-inferred {{ background-color: rgba(245, 158, 11, 0.2); color: #fde68a; border: 1px solid #f59e0b; }}
        .tag {{ background-color: #334155; color: #cbd5e1; margin-right: 4px; }}
        .graph-stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-top: 12px;
        }}
        .stat-box {{
            background-color: #0f172a;
            border: 1px solid #334155;
            padding: 12px;
            border-radius: 6px;
        }}
        .stat-label {{ display: block; font-size: 11px; text-transform: uppercase; color: #94a3b8; }}
        .stat-value {{ font-size: 20px; font-weight: 700; color: #f8fafc; }}
        .text-blue {{ color: #93c5fd; }}
        .text-green {{ color: #a7f3d0; }}
        .text-amber {{ color: #fde68a; }}
        .path-card {{
            background-color: #0f172a;
            border: 1px solid #334155;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 8px;
        }}
        .path-hops {{
            font-family: monospace;
            font-size: 13px;
            margin: 6px 0;
            color: #cbd5e1;
        }}
        .path-uncertainty {{ color: #94a3b8; font-size: 12px; }}
        .uncertainty-box {{
            background-color: rgba(15, 23, 42, 0.8);
            border-left: 4px solid #f59e0b;
            padding: 16px;
            border-radius: 4px;
            margin-top: 12px;
        }}
        .uncertainty-box ul {{
            margin: 6px 0 0 0;
            padding-left: 20px;
            color: #cbd5e1;
            font-size: 13px;
        }}
        .empty-text {{
            color: #94a3b8;
            font-style: italic;
            padding: 12px 0;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 16px;
            border-top: 1px solid #334155;
            font-size: 12px;
            color: #64748b;
            display: flex;
            justifyContent: space-between;
        }}
        code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background-color: rgba(0,0,0,0.3);
            padding: 1px 4px;
            border-radius: 3px;
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <h1>Cloud Attack Path Detection &bull; Incident Report</h1>

        {synthetic_notice}
        {persistence_notice}

        <div class="meta-grid">
            <div class="meta-item">
                <span>Case Identifier</span>
                <strong>{case_id}</strong>
            </div>
            <div class="meta-item">
                <span>Case Title</span>
                <strong>{title}</strong>
            </div>
            <div class="meta-item">
                <span>Priority</span>
                <span class="badge badge-{case.priority.lower()}">{priority}</span>
            </div>
            <div class="meta-item">
                <span>Investigation Status</span>
                <strong>{status}</strong>
            </div>
            <div class="meta-item">
                <span>Tags</span>
                <div>{tags_html}</div>
            </div>
            <div class="meta-item">
                <span>Generated At</span>
                <strong>{now_str}</strong>
            </div>
        </div>

        <div style="margin-bottom: 24px;">
            <span style="font-size: 12px; text-transform: uppercase; color: #94a3b8; font-weight: 600;">Executive Summary & Notes</span>
            <p style="margin-top: 4px; color: #cbd5e1; font-size: 14px;">{desc}</p>
        </div>

        <h2>Linked Detection Alerts ({len(alerts)})</h2>
        {alerts_html}

        <h2>Forensic Evidence Timeline ({len(evidence_events)})</h2>
        {timeline_html}

        <h2>Attack Graph & Lateral Movement Topology</h2>
        {graph_html}

        <h2>Forensic Uncertainty & Operational Limitations</h2>
        <div class="uncertainty-box">
            <strong>Key Attribution & Uncertainty Considerations:</strong>
            <ul>
                {unc_items}
            </ul>
        </div>

        <div class="footer">
            <span>Cloud-Network Attack Path and Lateral Movement Detection</span>
            <span>Document format: HTML incident export &bull; Verification timestamp: {now_str}</span>
        </div>
    </div>
</body>
</html>
"""
