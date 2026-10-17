import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getAlerts } from "../api/alerts";
import { getGraph } from "../api/graph";
import { AlertResponse } from "../types/alert";
import { GraphResponse } from "../types/graph";
import { EmptyState, ErrorBanner, LoadingSpinner, PriorityBadge, UncertaintyDisclaimer } from "../components/common";

export function Dashboard() {
  const [alerts, setAlerts] = useState<AlertResponse[]>([]);
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadDashboardData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [alertsRes, graphRes] = await Promise.all([
        getAlerts({ limit: 10 }),
        getGraph(),
      ]);
      setAlerts(alertsRes.items || []);
      setGraph(graphRes);
    } catch (err: any) {
      setError(err?.message || "Failed to load SOC dashboard metrics");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  const counts = {
    critical: alerts.filter((a) => a.priority === "critical").length,
    high: alerts.filter((a) => a.priority === "high").length,
    medium: alerts.filter((a) => a.priority === "medium").length,
    low: alerts.filter((a) => a.priority === "low").length,
    total: alerts.length,
  };

  return (
    <div style={{ maxWidth: "1280px", margin: "0 auto", padding: "24px 16px" }}>
      {/* Header */}
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 700, color: "#f8fafc", margin: "0 0 6px 0" }}>
          Security Operations Dashboard
        </h1>
        <p style={{ margin: 0, color: "#94a3b8", fontSize: "14px" }}>
          Continuous cross-layer telemetry correlation & lateral movement detection
        </p>
      </div>

      {error && <ErrorBanner message={error} onRetry={loadDashboardData} />}

      {loading ? (
        <LoadingSpinner message="Aggregating security telemetry and analyzing attack paths..." />
      ) : (
        <>
          {/* Summary Cards */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
              gap: "16px",
              marginBottom: "28px",
            }}
          >
            <div style={{ backgroundColor: "#1e293b", padding: "20px", borderRadius: "8px", border: "1px solid #334155" }}>
              <div style={{ color: "#94a3b8", fontSize: "13px", fontWeight: 500, textTransform: "uppercase" }}>Total Alerts</div>
              <div style={{ fontSize: "28px", fontWeight: 700, color: "#f8fafc", marginTop: "8px" }}>{counts.total}</div>
              <div style={{ fontSize: "12px", color: "#64748b", marginTop: "4px" }}>Active correlation findings</div>
            </div>

            <div style={{ backgroundColor: "#1e293b", padding: "20px", borderRadius: "8px", border: "1px solid #334155", borderLeft: "4px solid #f43f5e" }}>
              <div style={{ color: "#f43f5e", fontSize: "13px", fontWeight: 500, textTransform: "uppercase" }}>Critical Priority</div>
              <div style={{ fontSize: "28px", fontWeight: 700, color: "#fda4af", marginTop: "8px" }}>{counts.critical}</div>
              <div style={{ fontSize: "12px", color: "#94a3b8", marginTop: "4px" }}>Immediate triage required</div>
            </div>

            <div style={{ backgroundColor: "#1e293b", padding: "20px", borderRadius: "8px", border: "1px solid #334155", borderLeft: "4px solid #f59e0b" }}>
              <div style={{ color: "#f59e0b", fontSize: "13px", fontWeight: 500, textTransform: "uppercase" }}>High Priority</div>
              <div style={{ fontSize: "28px", fontWeight: 700, color: "#fde68a", marginTop: "8px" }}>{counts.high}</div>
              <div style={{ fontSize: "12px", color: "#94a3b8", marginTop: "4px" }}>Cross-layer enabled flows</div>
            </div>

            <div style={{ backgroundColor: "#1e293b", padding: "20px", borderRadius: "8px", border: "1px solid #334155", borderLeft: "4px solid #6366f1" }}>
              <div style={{ color: "#818cf8", fontSize: "13px", fontWeight: 500, textTransform: "uppercase" }}>Attack Graph Entities</div>
              <div style={{ fontSize: "28px", fontWeight: 700, color: "#c7d2fe", marginTop: "8px" }}>
                {graph ? `${graph.total_nodes} nodes / ${graph.total_edges} edges` : "0"}
              </div>
              <div style={{ fontSize: "12px", color: "#94a3b8", marginTop: "4px" }}>
                {graph ? `${graph.inferred_edge_count} inferred relations` : "Empty topology"}
              </div>
            </div>
          </div>

          <UncertaintyDisclaimer />

          {/* Recent Alerts List */}
          <div style={{ backgroundColor: "#1e293b", borderRadius: "8px", border: "1px solid #334155", overflow: "hidden", marginBottom: "32px" }}>
            <div style={{ padding: "16px 20px", borderBottom: "1px solid #334155", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h2 style={{ fontSize: "16px", fontWeight: 600, color: "#f8fafc", margin: 0 }}>Recent Detection Alerts</h2>
              <Link to="/alerts" style={{ color: "#818cf8", fontSize: "13px", textDecoration: "none", fontWeight: 500 }}>
                View all alerts &rarr;
              </Link>
            </div>

            {alerts.length === 0 ? (
              <EmptyState
                title="No Active Detection Alerts"
                description="Zero anomalies or cross-layer policy violations detected in the ingested telemetry."
              />
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "13px" }}>
                <thead>
                  <tr style={{ backgroundColor: "#0f172a", color: "#94a3b8", borderBottom: "1px solid #334155" }}>
                    <th style={{ padding: "12px 20px" }}>Priority</th>
                    <th style={{ padding: "12px 20px" }}>Alert ID</th>
                    <th style={{ padding: "12px 20px" }}>Rule</th>
                    <th style={{ padding: "12px 20px" }}>Explanation</th>
                    <th style={{ padding: "12px 20px" }}>Evidence</th>
                    <th style={{ padding: "12px 20px", textAlign: "right" }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.slice(0, 5).map((a) => (
                    <tr key={a.alert_id} style={{ borderBottom: "1px solid #334155" }}>
                      <td style={{ padding: "14px 20px" }}>
                        <PriorityBadge priority={a.priority} />
                      </td>
                      <td style={{ padding: "14px 20px", fontFamily: "monospace", color: "#cbd5e1" }}>
                        {a.alert_id}
                      </td>
                      <td style={{ padding: "14px 20px", color: "#94a3b8" }}>
                        <span style={{ backgroundColor: "#0f172a", padding: "2px 6px", borderRadius: "4px", border: "1px solid #334155" }}>
                          {a.rule_id}
                        </span>
                      </td>
                      <td style={{ padding: "14px 20px", color: "#cbd5e1", maxWidth: "420px" }}>
                        <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {a.explanation}
                        </div>
                      </td>
                      <td style={{ padding: "14px 20px", color: "#94a3b8" }}>
                        {a.evidence_event_ids.length} event(s)
                      </td>
                      <td style={{ padding: "14px 20px", textAlign: "right" }}>
                        <Link
                          to={`/alerts/${encodeURIComponent(a.alert_id)}`}
                          style={{
                            color: "#818cf8",
                            textDecoration: "none",
                            fontWeight: 500,
                            padding: "4px 10px",
                            backgroundColor: "rgba(99, 102, 241, 0.1)",
                            borderRadius: "4px",
                            border: "1px solid rgba(99, 102, 241, 0.3)",
                          }}
                        >
                          Investigate
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </div>
  );
}
