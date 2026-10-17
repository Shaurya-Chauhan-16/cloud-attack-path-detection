import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getAlerts } from "../api/alerts";
import { AlertFilterParams, AlertResponse, PriorityLevel } from "../types/alert";
import { EmptyState, ErrorBanner, LoadingSpinner, PriorityBadge } from "../components/common";

export function Alerts() {
  const [alerts, setAlerts] = useState<AlertResponse[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [priorityFilter, setPriorityFilter] = useState<PriorityLevel | "">("");
  const [searchTerm, setSearchTerm] = useState<string>("");

  const loadAlerts = async () => {
    setLoading(true);
    setError(null);
    try {
      const params: AlertFilterParams = { limit: 100 };
      if (priorityFilter) {
        params.priority = priorityFilter;
      }
      const res = await getAlerts(params);
      setAlerts(res.items || []);
    } catch (err: any) {
      setError(err?.message || "Failed to query alerts from backend API");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [priorityFilter]);

  const filteredAlerts = alerts.filter((a) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      a.alert_id.toLowerCase().includes(term) ||
      a.rule_id.toLowerCase().includes(term) ||
      a.explanation.toLowerCase().includes(term) ||
      a.related_resource_ids.some((r) => r.toLowerCase().includes(term))
    );
  });

  return (
    <div style={{ maxWidth: "1280px", margin: "0 auto", padding: "24px 16px" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 700, color: "#f8fafc", margin: "0 0 6px 0" }}>
            Detection Alerts
          </h1>
          <p style={{ margin: 0, color: "#94a3b8", fontSize: "14px" }}>
            Cross-layer and network baseline alerts generated from ingested telemetry
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <div
        style={{
          backgroundColor: "#1e293b",
          padding: "16px",
          borderRadius: "8px",
          border: "1px solid #334155",
          display: "flex",
          gap: "16px",
          alignItems: "center",
          flexWrap: "wrap",
          marginBottom: "24px",
        }}
      >
        <div style={{ flex: 1, minWidth: "240px" }}>
          <input
            type="text"
            placeholder="Search alerts by ID, rule, resource, or keyword..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: "100%",
              padding: "8px 12px",
              backgroundColor: "#0f172a",
              border: "1px solid #334155",
              borderRadius: "6px",
              color: "#f8fafc",
              fontSize: "14px",
              outline: "none",
            }}
          />
        </div>

        <div>
          <select
            value={priorityFilter}
            onChange={(e) => setPriorityFilter(e.target.value as PriorityLevel | "")}
            style={{
              padding: "8px 12px",
              backgroundColor: "#0f172a",
              border: "1px solid #334155",
              borderRadius: "6px",
              color: "#f8fafc",
              fontSize: "14px",
              outline: "none",
            }}
          >
            <option value="">All Priorities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <button
          onClick={loadAlerts}
          style={{
            padding: "8px 16px",
            backgroundColor: "#334155",
            color: "#f8fafc",
            border: "none",
            borderRadius: "6px",
            fontSize: "14px",
            fontWeight: 500,
            cursor: "pointer",
          }}
        >
          Refresh
        </button>
      </div>

      {error && <ErrorBanner message={error} onRetry={loadAlerts} />}

      {loading ? (
        <LoadingSpinner message="Querying detection alerts..." />
      ) : filteredAlerts.length === 0 ? (
        <EmptyState
          title="No Alerts Found"
          description={searchTerm || priorityFilter ? "No alerts match the applied filters." : "No detection alerts found in the database."}
        />
      ) : (
        <div style={{ backgroundColor: "#1e293b", borderRadius: "8px", border: "1px solid #334155", overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "13px" }}>
            <thead>
              <tr style={{ backgroundColor: "#0f172a", color: "#94a3b8", borderBottom: "1px solid #334155" }}>
                <th style={{ padding: "12px 16px" }}>Priority</th>
                <th style={{ padding: "12px 16px" }}>Alert ID</th>
                <th style={{ padding: "12px 16px" }}>Rule ID</th>
                <th style={{ padding: "12px 16px" }}>Explanation</th>
                <th style={{ padding: "12px 16px" }}>Related Resources</th>
                <th style={{ padding: "12px 16px" }}>Timestamp</th>
                <th style={{ padding: "12px 16px", textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((a) => (
                <tr key={a.alert_id} style={{ borderBottom: "1px solid #334155" }}>
                  <td style={{ padding: "14px 16px" }}>
                    <PriorityBadge priority={a.priority} />
                  </td>
                  <td style={{ padding: "14px 16px", fontFamily: "monospace", color: "#cbd5e1" }}>
                    {a.alert_id}
                  </td>
                  <td style={{ padding: "14px 16px", color: "#94a3b8" }}>
                    <span style={{ backgroundColor: "#0f172a", padding: "2px 6px", borderRadius: "4px", border: "1px solid #334155" }}>
                      {a.rule_id}
                    </span>
                  </td>
                  <td style={{ padding: "14px 16px", color: "#cbd5e1", maxWidth: "360px" }}>
                    <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {a.explanation}
                    </div>
                  </td>
                  <td style={{ padding: "14px 16px", color: "#94a3b8" }}>
                    {a.related_resource_ids.join(", ") || "—"}
                  </td>
                  <td style={{ padding: "14px 16px", color: "#94a3b8", whiteSpace: "nowrap" }}>
                    {new Date(a.created_at).toLocaleString()}
                  </td>
                  <td style={{ padding: "14px 16px", textAlign: "right" }}>
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
                      Details & Evidence
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
