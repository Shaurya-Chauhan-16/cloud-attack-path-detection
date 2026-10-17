import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getAlertById } from "../api/alerts";
import { getAlertEvidence } from "../api/events";
import { AlertResponse } from "../types/alert";
import { EventEvidenceResponse, TelemetryEventResponse } from "../types/event";
import { EmptyState, ErrorBanner, LoadingSpinner, PriorityBadge, UncertaintyDisclaimer } from "../components/common";

export function AlertDetails() {
  const { alertId } = useParams<{ alertId: string }>();
  const [alert, setAlert] = useState<AlertResponse | null>(null);
  const [evidence, setEvidence] = useState<EventEvidenceResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    if (!alertId) return;
    setLoading(true);
    setError(null);
    try {
      const [alertData, evidenceData] = await Promise.all([
        getAlertById(alertId),
        getAlertEvidence(alertId).catch(() => null),
      ]);
      setAlert(alertData);
      setEvidence(evidenceData);
    } catch (err: any) {
      setError(err?.message || "Failed to retrieve alert details or evidence");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [alertId]);

  if (loading) {
    return <LoadingSpinner message="Loading alert forensic evidence and score breakdown..." />;
  }

  if (error || !alert) {
    return (
      <div style={{ maxWidth: "1280px", margin: "0 auto", padding: "24px 16px" }}>
        <ErrorBanner message={error || "Alert not found."} onRetry={loadData} />
        <Link to="/alerts" style={{ color: "#818cf8", textDecoration: "none" }}>&larr; Back to alerts</Link>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: "1280px", margin: "0 auto", padding: "24px 16px" }}>
      {/* Back button */}
      <div style={{ marginBottom: "16px" }}>
        <Link to="/alerts" style={{ color: "#818cf8", textDecoration: "none", fontSize: "14px", fontWeight: 500 }}>
          &larr; Back to Alerts
        </Link>
      </div>

      {/* Header card */}
      <div style={{ backgroundColor: "#1e293b", padding: "24px", borderRadius: "8px", border: "1px solid #334155", marginBottom: "24px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "16px" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "8px" }}>
              <PriorityBadge priority={alert.priority} />
              <span style={{ fontFamily: "monospace", fontSize: "14px", color: "#94a3b8" }}>{alert.alert_id}</span>
              <span style={{ backgroundColor: "#0f172a", color: "#818cf8", padding: "2px 8px", borderRadius: "4px", fontSize: "12px", border: "1px solid #334155" }}>
                {alert.rule_id} v{alert.rule_version}
              </span>
            </div>
            <h1 style={{ fontSize: "20px", fontWeight: 600, color: "#f8fafc", margin: "0 0 12px 0" }}>
              {alert.explanation}
            </h1>
            <div style={{ fontSize: "13px", color: "#94a3b8" }}>
              Detected at: {new Date(alert.created_at).toUTCString()}
            </div>
          </div>

          {alert.score_result && (
            <div style={{ backgroundColor: "#0f172a", padding: "16px 20px", borderRadius: "6px", border: "1px solid #334155", textAlign: "right" }}>
              <div style={{ color: "#94a3b8", fontSize: "12px", textTransform: "uppercase" }}>Priority Score</div>
              <div style={{ fontSize: "32px", fontWeight: 700, color: "#f8fafc", marginTop: "2px" }}>
                {alert.score_result.final_score.toFixed(1)}
                <span style={{ fontSize: "14px", color: "#64748b" }}> / 100</span>
              </div>
              <div style={{ fontSize: "12px", color: "#818cf8", marginTop: "2px" }}>
                {alert.score_result.priority_level.toUpperCase()}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Uncertainty & Boundaries */}
      <UncertaintyDisclaimer notes={evidence?.uncertainty_notes} />

      {/* Score Explanation / Breakdown */}
      {alert.score_result && (
        <div style={{ backgroundColor: "#1e293b", padding: "20px", borderRadius: "8px", border: "1px solid #334155", marginBottom: "24px" }}>
          <h2 style={{ fontSize: "15px", fontWeight: 600, color: "#f8fafc", margin: "0 0 8px 0" }}>
            Scoring Rationale & Factor Contributions
          </h2>
          <p style={{ color: "#cbd5e1", fontSize: "13px", margin: "0 0 16px 0" }}>
            {alert.score_result.explanation}
          </p>
          {alert.score_result.factor_contributions && Object.keys(alert.score_result.factor_contributions).length > 0 && (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "12px" }}>
              {Object.entries(alert.score_result.factor_contributions).map(([factor, val]) => (
                <div key={factor} style={{ backgroundColor: "#0f172a", padding: "10px 14px", borderRadius: "4px", border: "1px solid #334155" }}>
                  <div style={{ color: "#94a3b8", fontSize: "11px", textTransform: "uppercase" }}>{factor.replace(/_/g, " ")}</div>
                  <div style={{ color: "#f8fafc", fontSize: "16px", fontWeight: 600, marginTop: "2px" }}>{val}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Forensic Evidence Timeline */}
      <div style={{ backgroundColor: "#1e293b", borderRadius: "8px", border: "1px solid #334155", overflow: "hidden" }}>
        <div style={{ padding: "16px 20px", borderBottom: "1px solid #334155" }}>
          <h2 style={{ fontSize: "15px", fontWeight: 600, color: "#f8fafc", margin: 0 }}>
            Forensic Evidence Events ({evidence?.evidence_events.length || alert.evidence_event_ids.length})
          </h2>
          <p style={{ margin: "4px 0 0 0", color: "#94a3b8", fontSize: "13px" }}>
            Telemetry records directly linked to this cross-layer detection finding
          </p>
        </div>

        {evidence && evidence.evidence_events.length > 0 ? (
          <div style={{ padding: "20px" }}>
            <div style={{ borderLeft: "2px solid #475569", marginLeft: "12px", paddingLeft: "24px", display: "flex", flexDirection: "column", gap: "24px" }}>
              {evidence.evidence_events.map((evt) => (
                <div key={evt.event_id} style={{ position: "relative" }}>
                  {/* Timeline circle */}
                  <div
                    style={{
                      position: "absolute",
                      left: "-31px",
                      top: "2px",
                      width: "12px",
                      height: "12px",
                      borderRadius: "50%",
                      backgroundColor: evt.source === "cloudtrail" ? "#f59e0b" : "#3b82f6",
                      border: "2px solid #0f172a",
                    }}
                  />
                  <div style={{ backgroundColor: "#0f172a", padding: "16px", borderRadius: "6px", border: "1px solid #334155" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px", flexWrap: "wrap", gap: "8px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <span
                          style={{
                            padding: "2px 8px",
                            borderRadius: "4px",
                            fontSize: "11px",
                            fontWeight: 600,
                            textTransform: "uppercase",
                            backgroundColor: evt.source === "cloudtrail" ? "rgba(245, 158, 11, 0.2)" : "rgba(59, 130, 246, 0.2)",
                            color: evt.source === "cloudtrail" ? "#fbbf24" : "#60a5fa",
                            border: `1px solid ${evt.source === "cloudtrail" ? "rgba(245, 158, 11, 0.4)" : "rgba(59, 130, 246, 0.4)"}`,
                          }}
                        >
                          {evt.source}
                        </span>
                        <strong style={{ color: "#f8fafc", fontSize: "14px" }}>{evt.action}</strong>
                      </div>
                      <span style={{ color: "#94a3b8", fontSize: "12px", fontFamily: "monospace" }}>
                        {new Date(evt.timestamp).toUTCString()}
                      </span>
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "10px", fontSize: "12px", marginTop: "12px" }}>
                      <div>
                        <span style={{ color: "#64748b" }}>Event ID: </span>
                        <span style={{ color: "#cbd5e1", fontFamily: "monospace" }}>{evt.event_id}</span>
                      </div>
                      {evt.actor && (
                        <div>
                          <span style={{ color: "#64748b" }}>Actor: </span>
                          <span style={{ color: "#cbd5e1" }}>{evt.actor}</span>
                        </div>
                      )}
                      {evt.resource_id && (
                        <div>
                          <span style={{ color: "#64748b" }}>Target Resource: </span>
                          <span style={{ color: "#cbd5e1", fontFamily: "monospace" }}>{evt.resource_id}</span>
                        </div>
                      )}
                      {evt.source_ip && (
                        <div>
                          <span style={{ color: "#64748b" }}>Flow: </span>
                          <span style={{ color: "#cbd5e1", fontFamily: "monospace" }}>
                            {evt.source_ip} &rarr; {evt.destination_ip}:{evt.destination_port} ({evt.details?.protocol || "tcp"})
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div style={{ padding: "20px" }}>
            <p style={{ color: "#94a3b8", fontSize: "13px" }}>
              Event ID references: {alert.evidence_event_ids.join(", ")}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
