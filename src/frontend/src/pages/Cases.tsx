import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getCases, createCase } from "../api/cases";
import { CaseCreateRequest, CaseResponse } from "../types/case";
import { EmptyState, ErrorBanner, LoadingSpinner, PriorityBadge } from "../components/common";

export function CaseInvestigationPage() {
  const [cases, setCases] = useState<CaseResponse[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // New Case Modal / Form
  const [showCreate, setShowCreate] = useState<boolean>(false);
  const [title, setTitle] = useState<string>("");
  const [description, setDescription] = useState<string>("");
  const [priority, setPriority] = useState<"low" | "medium" | "high" | "critical">("medium");

  const loadCases = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getCases();
      setCases(data);
    } catch (err: any) {
      setError(err?.message || "Failed to load investigation cases");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, []);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title) return;
    try {
      await createCase({
        title,
        description,
        priority,
        alert_ids: [],
        tags: ["investigation"],
      });
      setTitle("");
      setDescription("");
      setShowCreate(false);
      loadCases();
    } catch (err: any) {
      alert("Failed to create case: " + err?.message);
    }
  };

  const downloadReport = (caseId: string) => {
    // Direct link to the actual backend HTML report export endpoint
    window.open(`/api/reports/cases/${encodeURIComponent(caseId)}/html`, "_blank");
  };

  return (
    <div style={{ maxWidth: "1280px", margin: "0 auto", padding: "24px 16px" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 700, color: "#f8fafc", margin: "0 0 6px 0" }}>
            Case Investigations & Incident Reports
          </h1>
          <p style={{ margin: 0, color: "#94a3b8", fontSize: "14px" }}>
            Triage lateral movement cases, review forensic evidence, and export incident reports
          </p>
        </div>
        <button
          onClick={() => setShowCreate(!showCreate)}
          style={{
            padding: "8px 16px",
            backgroundColor: "#4f46e5",
            color: "#ffffff",
            border: "none",
            borderRadius: "6px",
            fontSize: "14px",
            fontWeight: 600,
            cursor: "pointer",
          }}
        >
          {showCreate ? "Cancel" : "+ New Investigation Case"}
        </button>
      </div>

      {/* In-Memory Persistence Warning Notice */}
      <div
        style={{
          padding: "12px 16px",
          backgroundColor: "rgba(99, 102, 241, 0.15)",
          border: "1px solid #6366f1",
          borderRadius: "6px",
          color: "#c7d2fe",
          fontSize: "13px",
          marginBottom: "20px",
        }}
      >
        <strong>ℹ️ Storage Notice:</strong> Case records are stored in-memory in Phase 2/4 and will reset upon application service restart.
      </div>

      {/* Create Case Form Modal */}
      {showCreate && (
        <form
          onSubmit={handleCreateCase}
          style={{
            backgroundColor: "#1e293b",
            padding: "20px",
            borderRadius: "8px",
            border: "1px solid #334155",
            marginBottom: "24px",
            display: "flex",
            flexDirection: "column",
            gap: "14px",
          }}
        >
          <h3 style={{ margin: 0, color: "#f8fafc", fontSize: "16px" }}>Create Investigation Case</h3>
          <div>
            <label style={{ display: "block", color: "#94a3b8", fontSize: "12px", marginBottom: "4px" }}>Case Title</label>
            <input
              type="text"
              required
              placeholder="e.g. Cross-layer SG modification enabling external SSH"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              style={{ width: "100%", padding: "8px 12px", backgroundColor: "#0f172a", border: "1px solid #334155", borderRadius: "6px", color: "#f8fafc", fontSize: "14px" }}
            />
          </div>
          <div>
            <label style={{ display: "block", color: "#94a3b8", fontSize: "12px", marginBottom: "4px" }}>Description</label>
            <textarea
              rows={2}
              placeholder="Detailed hypothesis, affected principals, or investigation scope"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              style={{ width: "100%", padding: "8px 12px", backgroundColor: "#0f172a", border: "1px solid #334155", borderRadius: "6px", color: "#f8fafc", fontSize: "14px" }}
            />
          </div>
          <div style={{ display: "flex", gap: "16px" }}>
            <div>
              <label style={{ display: "block", color: "#94a3b8", fontSize: "12px", marginBottom: "4px" }}>Priority</label>
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value as any)}
                style={{ padding: "8px 12px", backgroundColor: "#0f172a", border: "1px solid #334155", borderRadius: "6px", color: "#f8fafc", fontSize: "14px" }}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
            <div style={{ alignSelf: "flex-end" }}>
              <button
                type="submit"
                style={{ padding: "9px 20px", backgroundColor: "#10b981", color: "#ffffff", border: "none", borderRadius: "6px", fontSize: "14px", fontWeight: 600, cursor: "pointer" }}
              >
                Save Case
              </button>
            </div>
          </div>
        </form>
      )}

      {error && <ErrorBanner message={error} onRetry={loadCases} />}

      {loading ? (
        <LoadingSpinner message="Loading investigation cases..." />
      ) : cases.length === 0 ? (
        <EmptyState
          title="No Investigation Cases Yet"
          description="Create your first investigation case to group correlated detection alerts and generate comprehensive incident reports."
          actionText="+ Create Initial Case"
          actionLink="#"
        />
      ) : (
        <div style={{ backgroundColor: "#1e293b", borderRadius: "8px", border: "1px solid #334155", overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "13px" }}>
            <thead>
              <tr style={{ backgroundColor: "#0f172a", color: "#94a3b8", borderBottom: "1px solid #334155" }}>
                <th style={{ padding: "12px 16px" }}>Priority</th>
                <th style={{ padding: "12px 16px" }}>Case ID</th>
                <th style={{ padding: "12px 16px" }}>Title</th>
                <th style={{ padding: "12px 16px" }}>Status</th>
                <th style={{ padding: "12px 16px" }}>Linked Alerts</th>
                <th style={{ padding: "12px 16px" }}>Created</th>
                <th style={{ padding: "12px 16px", textAlign: "right" }}>Export Incident Report</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((c) => (
                <tr key={c.case_id} style={{ borderBottom: "1px solid #334155" }}>
                  <td style={{ padding: "14px 16px" }}>
                    <PriorityBadge priority={c.priority} />
                  </td>
                  <td style={{ padding: "14px 16px", fontFamily: "monospace", color: "#cbd5e1" }}>
                    {c.case_id}
                  </td>
                  <td style={{ padding: "14px 16px", color: "#f8fafc", fontWeight: 500 }}>
                    <div>{c.title}</div>
                    {c.description && <div style={{ fontSize: "12px", color: "#94a3b8", marginTop: "2px" }}>{c.description}</div>}
                  </td>
                  <td style={{ padding: "14px 16px" }}>
                    <span style={{ textTransform: "uppercase", fontSize: "11px", fontWeight: 600, color: "#a5b4fc" }}>
                      {c.status}
                    </span>
                  </td>
                  <td style={{ padding: "14px 16px", color: "#94a3b8" }}>
                    {c.alert_ids.length} alert(s)
                  </td>
                  <td style={{ padding: "14px 16px", color: "#94a3b8", whiteSpace: "nowrap" }}>
                    {new Date(c.created_at).toLocaleDateString()}
                  </td>
                  <td style={{ padding: "14px 16px", textAlign: "right" }}>
                    <button
                      onClick={() => downloadReport(c.case_id)}
                      style={{
                        padding: "6px 12px",
                        backgroundColor: "#1e1b4b",
                        border: "1px solid #6366f1",
                        borderRadius: "6px",
                        color: "#a5b4fc",
                        fontSize: "12px",
                        fontWeight: 600,
                        cursor: "pointer",
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "6px",
                      }}
                    >
                      <span>📥</span>
                      <span>Export HTML Report</span>
                    </button>
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
