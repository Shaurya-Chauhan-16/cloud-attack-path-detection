import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getAlerts } from "../api/alerts";
import { getGraph } from "../api/graph";
import { getEvents } from "../api/events";
import { AlertResponse } from "../types/alert";
import { GraphResponse } from "../types/graph";
import { TelemetryEventResponse } from "../types/event";
import { EmptyState, ErrorBanner, LoadingSpinner, PriorityBadge, UncertaintyDisclaimer } from "../components/common";

export function Dashboard() {
  const [alerts, setAlerts] = useState<AlertResponse[]>([]);
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [events, setEvents] = useState<TelemetryEventResponse[]>([]);
  const [totalEvents, setTotalEvents] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());

  const loadDashboardData = async (isBackground = false) => {
    if (!isBackground) setLoading(true);
    setError(null);
    try {
      const [alertsRes, graphRes, eventsRes] = await Promise.all([
        getAlerts({ limit: 10 }),
        getGraph(),
        getEvents(undefined, 10),
      ]);
      setAlerts(alertsRes.items || []);
      setGraph(graphRes);
      setEvents(eventsRes.items || []);
      setTotalEvents(eventsRes.total || 0);
      setLastRefreshed(new Date());
    } catch (err: any) {
      if (!isBackground) {
        setError(err?.message || "Failed to load SOC dashboard metrics");
      }
    } finally {
      if (!isBackground) setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      loadDashboardData(true);
    }, 4000); // Poll every 4 seconds for new streamed events
    return () => clearInterval(interval);
  }, [autoRefresh]);

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
      <div style={{ marginBottom: "28px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 700, color: "#f8fafc", margin: "0 0 6px 0" }}>
            Security Operations Dashboard
          </h1>
          <p style={{ margin: 0, color: "#94a3b8", fontSize: "14px" }}>
            Continuous cross-layer telemetry correlation & lateral movement detection
          </p>
        </div>

        {/* Real-time Streaming Indicator & Controls */}
        <div style={{ display: "flex", alignItems: "center", gap: "12px", backgroundColor: "#1e293b", padding: "8px 14px", borderRadius: "8px", border: "1px solid #334155" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span
              style={{
                width: "9px",
                height: "9px",
                borderRadius: "50%",
                backgroundColor: autoRefresh ? "#10b981" : "#64748b",
                boxShadow: autoRefresh ? "0 0 8px #10b981" : "none",
                display: "inline-block",
                transition: "all 0.3s ease",
              }}
            />
            <span style={{ fontSize: "12px", fontWeight: 600, color: autoRefresh ? "#34d399" : "#94a3b8" }}>
              {autoRefresh ? "LIVE STREAM ACTIVE" : "STREAM PAUSED"}
            </span>
          </div>

          <span style={{ fontSize: "11px", color: "#64748b" }}>
            {lastRefreshed.toLocaleTimeString()}
          </span>

          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            style={{
              padding: "4px 10px",
              fontSize: "12px",
              fontWeight: 500,
              backgroundColor: autoRefresh ? "#334155" : "#4f46e5",
              color: "#f8fafc",
              border: "none",
              borderRadius: "4px",
              cursor: "pointer",
            }}
          >
            {autoRefresh ? "Pause" : "Resume"}
          </button>
        </div>
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

            <div style={{ backgroundColor: "#1e293b", padding: "20px", borderRadius: "8px", border: "1px solid #334155", borderLeft: "4px solid #10b981" }}>
              <div style={{ color: "#34d399", fontSize: "13px", fontWeight: 500, textTransform: "uppercase" }}>AWS Ingested Logs</div>
              <div style={{ fontSize: "28px", fontWeight: 700, color: "#a7f3d0", marginTop: "8px" }}>
                {totalEvents > 0 ? totalEvents.toLocaleString() : "0"}
              </div>
              <div style={{ fontSize: "12px", color: "#94a3b8", marginTop: "4px" }}>
                CloudTrail & VPC Flow Logs
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

          {/* Ingested AWS Telemetry Log Feed */}
          <div style={{ backgroundColor: "#1e293b", borderRadius: "8px", border: "1px solid #334155", overflow: "hidden", marginBottom: "32px" }}>
            <div style={{ padding: "16px 20px", borderBottom: "1px solid #334155", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <h2 style={{ fontSize: "16px", fontWeight: 600, color: "#f8fafc", margin: "0 0 4px 0" }}>
                  Live AWS Telemetry Logs
                </h2>
                <span style={{ fontSize: "12px", color: "#94a3b8" }}>
                  Latest ingested CloudTrail API calls & VPC Flow network events ({totalEvents.toLocaleString()} total)
                </span>
              </div>
              <Link to="/timeline" style={{ color: "#818cf8", fontSize: "13px", textDecoration: "none", fontWeight: 500 }}>
                Full timeline feed &rarr;
              </Link>
            </div>

            {events.length === 0 ? (
              <EmptyState
                title="No Ingested Logs"
                description="Zero AWS telemetry events found in the database. Run collector to ingest AWS events."
              />
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "13px" }}>
                <thead>
                  <tr style={{ backgroundColor: "#0f172a", color: "#94a3b8", borderBottom: "1px solid #334155" }}>
                    <th style={{ padding: "12px 20px" }}>Timestamp (UTC)</th>
                    <th style={{ padding: "12px 20px" }}>Source</th>
                    <th style={{ padding: "12px 20px" }}>Action</th>
                    <th style={{ padding: "12px 20px" }}>Actor / Connection</th>
                    <th style={{ padding: "12px 20px" }}>Resource</th>
                    <th style={{ padding: "12px 20px" }}>Event ID</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.event_id} style={{ borderBottom: "1px solid #334155" }}>
                      <td style={{ padding: "12px 20px", color: "#cbd5e1", whiteSpace: "nowrap", fontFamily: "monospace", fontSize: "12px" }}>
                        {new Date(e.timestamp).toISOString()}
                      </td>
                      <td style={{ padding: "12px 20px" }}>
                        <span
                          style={{
                            padding: "2px 8px",
                            borderRadius: "4px",
                            fontSize: "11px",
                            fontWeight: 600,
                            textTransform: "uppercase",
                            backgroundColor: e.source === "cloudtrail" ? "rgba(245, 158, 11, 0.2)" : "rgba(59, 130, 246, 0.2)",
                            color: e.source === "cloudtrail" ? "#fbbf24" : "#60a5fa",
                            border: `1px solid ${e.source === "cloudtrail" ? "rgba(245, 158, 11, 0.4)" : "rgba(59, 130, 246, 0.4)"}`,
                          }}
                        >
                          {e.source === "cloudtrail" ? "CloudTrail" : "VPC Flow"}
                        </span>
                      </td>
                      <td style={{ padding: "12px 20px", fontWeight: 600, color: "#f8fafc" }}>
                        {e.action}
                      </td>
                      <td style={{ padding: "12px 20px", color: "#94a3b8", maxWidth: "260px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {e.source === "vpc_flow" ? (
                          <span style={{ fontFamily: "monospace", fontSize: "12px" }}>
                            {e.source_ip} &rarr; {e.destination_ip}:{e.destination_port}
                          </span>
                        ) : (
                          <span title={e.actor || e.source_ip || "—"}>
                            {e.actor ? e.actor.split("/").pop() || e.actor : e.source_ip || "—"}
                          </span>
                        )}
                      </td>
                      <td style={{ padding: "12px 20px", fontFamily: "monospace", color: "#cbd5e1", fontSize: "12px" }}>
                        {e.resource_id || "—"}
                      </td>
                      <td style={{ padding: "12px 20px", fontFamily: "monospace", color: "#64748b", fontSize: "11px" }}>
                        {e.event_id.slice(0, 16)}...
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
