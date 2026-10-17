import React, { useEffect, useState } from "react";
import { getEvents } from "../api/events";
import { EventListResponse, EventSource, TelemetryEventResponse } from "../types/event";
import { EmptyState, ErrorBanner, LoadingSpinner, UncertaintyDisclaimer } from "../components/common";

export function TelemetryTimelinePage() {
  const [events, setEvents] = useState<TelemetryEventResponse[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [sourceFilter, setSourceFilter] = useState<EventSource | "">("");

  const loadEvents = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getEvents(sourceFilter || undefined, 100);
      setEvents(res.items || []);
    } catch (err: any) {
      setError(err?.message || "Failed to load telemetry events");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, [sourceFilter]);

  return (
    <div style={{ maxWidth: "1280px", margin: "0 auto", padding: "24px 16px" }}>
      {/* Header */}
      <div style={{ marginBottom: "24px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 700, color: "#f8fafc", margin: "0 0 6px 0" }}>
          Telemetry Timeline & Ingested Events
        </h1>
        <p style={{ margin: 0, color: "#94a3b8", fontSize: "14px" }}>
          Chronological event feed from AWS CloudTrail administrative calls and VPC Flow Logs
        </p>
      </div>

      {/* Filter */}
      <div style={{ backgroundColor: "#1e293b", padding: "16px", borderRadius: "8px", border: "1px solid #334155", display: "flex", gap: "16px", alignItems: "center", marginBottom: "24px" }}>
        <div>
          <label style={{ fontSize: "13px", color: "#94a3b8", marginRight: "8px" }}>Source Filter:</label>
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value as EventSource | "")}
            style={{ padding: "8px 12px", backgroundColor: "#0f172a", border: "1px solid #334155", borderRadius: "6px", color: "#f8fafc", fontSize: "14px" }}
          >
            <option value="">All Telemetry Sources</option>
            <option value="cloudtrail">AWS CloudTrail</option>
            <option value="vpc_flow">VPC Flow Logs</option>
          </select>
        </div>

        <button
          onClick={loadEvents}
          style={{ padding: "8px 16px", backgroundColor: "#334155", color: "#f8fafc", border: "none", borderRadius: "6px", fontSize: "14px", fontWeight: 500, cursor: "pointer" }}
        >
          Refresh Feed
        </button>
      </div>

      <UncertaintyDisclaimer />

      {error && <ErrorBanner message={error} onRetry={loadEvents} />}

      {loading ? (
        <LoadingSpinner message="Querying chronological telemetry events..." />
      ) : events.length === 0 ? (
        <EmptyState
          title="No Telemetry Events"
          description="Zero records returned for the selected filter."
        />
      ) : (
        <div style={{ backgroundColor: "#1e293b", borderRadius: "8px", border: "1px solid #334155", overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "13px" }}>
            <thead>
              <tr style={{ backgroundColor: "#0f172a", color: "#94a3b8", borderBottom: "1px solid #334155" }}>
                <th style={{ padding: "12px 16px" }}>Timestamp (UTC)</th>
                <th style={{ padding: "12px 16px" }}>Source</th>
                <th style={{ padding: "12px 16px" }}>Action</th>
                <th style={{ padding: "12px 16px" }}>Actor / IP Details</th>
                <th style={{ padding: "12px 16px" }}>Target Resource</th>
                <th style={{ padding: "12px 16px" }}>Event ID</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.event_id} style={{ borderBottom: "1px solid #334155" }}>
                  <td style={{ padding: "12px 16px", color: "#cbd5e1", whiteSpace: "nowrap", fontFamily: "monospace" }}>
                    {new Date(e.timestamp).toISOString()}
                  </td>
                  <td style={{ padding: "12px 16px" }}>
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
                      {e.source}
                    </span>
                  </td>
                  <td style={{ padding: "12px 16px", fontWeight: 600, color: "#f8fafc" }}>
                    {e.action}
                  </td>
                  <td style={{ padding: "12px 16px", color: "#94a3b8", maxWidth: "300px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {e.source === "vpc_flow" ? (
                      <span style={{ fontFamily: "monospace" }}>
                        {e.source_ip} &rarr; {e.destination_ip}:{e.destination_port}
                      </span>
                    ) : (
                      <span>{e.actor || e.source_ip || "—"}</span>
                    )}
                  </td>
                  <td style={{ padding: "12px 16px", fontFamily: "monospace", color: "#cbd5e1" }}>
                    {e.resource_id || "—"}
                  </td>
                  <td style={{ padding: "12px 16px", fontFamily: "monospace", color: "#64748b", fontSize: "11px" }}>
                    {e.event_id}
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
