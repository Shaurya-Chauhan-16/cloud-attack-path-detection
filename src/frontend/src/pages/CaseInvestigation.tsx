import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getGraph } from "../api/graph";
import { CandidatePath, GraphEdge, GraphNode, GraphResponse } from "../types/graph";
import { EmptyState, ErrorBanner, LoadingSpinner, UncertaintyDisclaimer } from "../components/common";

export function AttackGraphPage() {
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);

  const loadGraph = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getGraph();
      setGraph(data);
    } catch (err: any) {
      setError(err?.message || "Failed to load attack graph topology");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadGraph();
  }, []);

  const getEdgeNatureStyle = (nature: string) => {
    const n = nature.toLowerCase();
    if (n === "observed") {
      return {
        bg: "rgba(59, 130, 246, 0.15)",
        border: "#3b82f6",
        text: "#93c5fd",
        badge: "Observed Traffic",
      };
    }
    if (n === "permitted") {
      return {
        bg: "rgba(16, 185, 129, 0.15)",
        border: "#10b981",
        text: "#6ee7b7",
        badge: "Permitted Reachability",
      };
    }
    // inferred
    return {
      bg: "rgba(245, 158, 11, 0.15)",
      border: "#f59e0b",
      text: "#fde68a",
      badge: "Inferred Sequence",
    };
  };

  return (
    <div style={{ maxWidth: "1280px", margin: "0 auto", padding: "24px 16px" }}>
      {/* Header */}
      <div style={{ marginBottom: "24px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 700, color: "#f8fafc", margin: "0 0 6px 0" }}>
          Attack Path & Lateral Movement Graph
        </h1>
        <p style={{ margin: 0, color: "#94a3b8", fontSize: "14px" }}>
          Directed temporal graph topology distinguishing observed communication, permitted reachability, and inferred sequences
        </p>
      </div>

      {error && <ErrorBanner message={error} onRetry={loadGraph} />}

      {loading ? (
        <LoadingSpinner message="Reconstructing multi-relational graph from cross-layer telemetry..." />
      ) : !graph || (graph.nodes.length === 0 && graph.edges.length === 0) ? (
        <EmptyState
          title="No Attack Graph Available"
          description="There are currently no nodes or edges in the detection graph. Ingest telemetry or run analysis to generate topology."
        />
      ) : (
        <>
          {/* Classification Stats Bar */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
              gap: "16px",
              marginBottom: "20px",
            }}
          >
            <div style={{ backgroundColor: "#1e293b", padding: "16px", borderRadius: "8px", border: "1px solid #334155" }}>
              <div style={{ color: "#94a3b8", fontSize: "12px", textTransform: "uppercase" }}>Total Entities (Nodes)</div>
              <div style={{ fontSize: "24px", fontWeight: 700, color: "#f8fafc", marginTop: "4px" }}>{graph.total_nodes}</div>
            </div>

            <div style={{ backgroundColor: "#1e293b", padding: "16px", borderRadius: "8px", border: "1px solid #334155", borderLeft: "4px solid #3b82f6" }}>
              <div style={{ color: "#60a5fa", fontSize: "12px", textTransform: "uppercase" }}>Observed Communication</div>
              <div style={{ fontSize: "24px", fontWeight: 700, color: "#93c5fd", marginTop: "4px" }}>{graph.observed_edge_count}</div>
              <div style={{ fontSize: "11px", color: "#64748b" }}>Confirmed packet flow logs</div>
            </div>

            <div style={{ backgroundColor: "#1e293b", padding: "16px", borderRadius: "8px", border: "1px solid #334155", borderLeft: "4px solid #10b981" }}>
              <div style={{ color: "#34d399", fontSize: "12px", textTransform: "uppercase" }}>Permitted Reachability</div>
              <div style={{ fontSize: "24px", fontWeight: 700, color: "#a7f3d0", marginTop: "4px" }}>{graph.permitted_edge_count}</div>
              <div style={{ fontSize: "11px", color: "#64748b" }}>Security group authorization</div>
            </div>

            <div style={{ backgroundColor: "#1e293b", padding: "16px", borderRadius: "8px", border: "1px solid #334155", borderLeft: "4px solid #f59e0b" }}>
              <div style={{ color: "#fbbf24", fontSize: "12px", textTransform: "uppercase" }}>Inferred Sequences</div>
              <div style={{ fontSize: "24px", fontWeight: 700, color: "#fde68a", marginTop: "4px" }}>{graph.inferred_edge_count}</div>
              <div style={{ fontSize: "11px", color: "#64748b" }}>Cross-layer correlated paths</div>
            </div>
          </div>

          <UncertaintyDisclaimer />

          {/* Graph Visualization & Entity Browser */}
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "20px", marginBottom: "28px" }}>
            {/* Visual Topology Panel */}
            <div style={{ backgroundColor: "#1e293b", borderRadius: "8px", border: "1px solid #334155", padding: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                <h2 style={{ fontSize: "16px", fontWeight: 600, color: "#f8fafc", margin: 0 }}>
                  Topology Visualization
                </h2>
                <span style={{ fontSize: "12px", color: "#94a3b8" }}>
                  Interactive relationship map
                </span>
              </div>

              {/* Graphical Node & Edge Canvas Representation */}
              <div
                style={{
                  backgroundColor: "#0f172a",
                  borderRadius: "6px",
                  border: "1px solid #334155",
                  padding: "24px",
                  minHeight: "360px",
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "space-around",
                  gap: "24px",
                }}
              >
                {/* Node Grid */}
                <div>
                  <div style={{ fontSize: "12px", color: "#64748b", textTransform: "uppercase", marginBottom: "12px", letterSpacing: "0.05em" }}>
                    Network & Cloud Entities ({graph.nodes.length})
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "12px" }}>
                    {graph.nodes.map((node) => {
                      const isSelected = selectedNode?.node_id === node.node_id;
                      return (
                        <div
                          key={node.node_id}
                          onClick={() => {
                            setSelectedNode(node);
                            setSelectedEdge(null);
                          }}
                          style={{
                            padding: "10px 16px",
                            backgroundColor: isSelected ? "#3730a3" : "#1e293b",
                            border: `2px solid ${isSelected ? "#818cf8" : "#475569"}`,
                            borderRadius: "8px",
                            cursor: "pointer",
                            transition: "all 0.15s ease-in-out",
                          }}
                        >
                          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                            <span style={{ fontSize: "14px" }}>
                              {node.node_type === "eni" ? "🔌" : node.node_type === "instance" ? "💻" : node.node_type === "security_group" ? "🛡️" : "🌐"}
                            </span>
                            <span style={{ fontWeight: 600, fontSize: "13px", color: "#f8fafc", fontFamily: "monospace" }}>
                              {node.node_id}
                            </span>
                          </div>
                          <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>
                            {node.node_type.toUpperCase()} {node.ip_addresses.length > 0 && `(${node.ip_addresses.join(", ")})`}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Edge Sequence Representation */}
                <div>
                  <div style={{ fontSize: "12px", color: "#64748b", textTransform: "uppercase", marginBottom: "12px", letterSpacing: "0.05em" }}>
                    Directed Relationships & Attack Sequences ({graph.edges.length})
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                    {graph.edges.map((edge) => {
                      const isSelected = selectedEdge?.edge_id === edge.edge_id;
                      const style = getEdgeNatureStyle(edge.observed_or_inferred);
                      return (
                        <div
                          key={edge.edge_id}
                          onClick={() => {
                            setSelectedEdge(edge);
                            setSelectedNode(null);
                          }}
                          style={{
                            padding: "12px 16px",
                            backgroundColor: isSelected ? "#3730a3" : style.bg,
                            border: `1px solid ${isSelected ? "#818cf8" : style.border}`,
                            borderRadius: "6px",
                            cursor: "pointer",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            flexWrap: "wrap",
                            gap: "8px",
                          }}
                        >
                          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                            <span style={{ fontFamily: "monospace", fontSize: "12px", color: "#f8fafc" }}>
                              {edge.source_node}
                            </span>
                            <span style={{ color: style.text, fontWeight: 700, fontSize: "14px" }}>&rarr;</span>
                            <span style={{ fontFamily: "monospace", fontSize: "12px", color: "#f8fafc" }}>
                              {edge.target_node}
                            </span>
                          </div>

                          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            <span
                              style={{
                                padding: "2px 8px",
                                borderRadius: "4px",
                                fontSize: "11px",
                                fontWeight: 600,
                                textTransform: "uppercase",
                                backgroundColor: "rgba(15, 23, 42, 0.6)",
                                color: style.text,
                                border: `1px solid ${style.border}`,
                              }}
                            >
                              {style.badge}
                            </span>
                            <span style={{ fontSize: "11px", color: "#cbd5e1" }}>
                              {edge.relation} {edge.port && `(:${edge.port})`}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>

            {/* Inspector Panel */}
            <div style={{ backgroundColor: "#1e293b", borderRadius: "8px", border: "1px solid #334155", padding: "20px" }}>
              <h2 style={{ fontSize: "16px", fontWeight: 600, color: "#f8fafc", margin: "0 0 16px 0" }}>
                Inspector Details
              </h2>

              {selectedNode ? (
                <div>
                  <div style={{ color: "#818cf8", fontSize: "12px", textTransform: "uppercase", fontWeight: 600, marginBottom: "4px" }}>
                    Node Attributes
                  </div>
                  <h3 style={{ fontSize: "16px", fontWeight: 600, color: "#f8fafc", margin: "0 0 12px 0", fontFamily: "monospace" }}>
                    {selectedNode.node_id}
                  </h3>
                  <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "13px" }}>
                    <div>
                      <span style={{ color: "#64748b" }}>Type: </span>
                      <span style={{ color: "#cbd5e1", fontWeight: 500 }}>{selectedNode.node_type}</span>
                    </div>
                    <div>
                      <span style={{ color: "#64748b" }}>IP Addresses: </span>
                      <span style={{ color: "#cbd5e1", fontFamily: "monospace" }}>
                        {selectedNode.ip_addresses.join(", ") || "None"}
                      </span>
                    </div>
                    {Object.keys(selectedNode.properties || {}).length > 0 && (
                      <div style={{ marginTop: "12px" }}>
                        <span style={{ color: "#64748b", display: "block", marginBottom: "4px" }}>Properties:</span>
                        <pre style={{ backgroundColor: "#0f172a", padding: "8px", borderRadius: "4px", fontSize: "11px", overflow: "auto" }}>
                          {JSON.stringify(selectedNode.properties, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              ) : selectedEdge ? (
                <div>
                  <div style={{ color: "#818cf8", fontSize: "12px", textTransform: "uppercase", fontWeight: 600, marginBottom: "4px" }}>
                    Relationship Attributes
                  </div>
                  <h3 style={{ fontSize: "14px", fontWeight: 600, color: "#f8fafc", margin: "0 0 12px 0", fontFamily: "monospace" }}>
                    {selectedEdge.edge_id}
                  </h3>
                  <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "13px" }}>
                    <div>
                      <span style={{ color: "#64748b" }}>Nature: </span>
                      <span style={{ color: "#cbd5e1", fontWeight: 600, textTransform: "uppercase" }}>
                        {selectedEdge.observed_or_inferred}
                      </span>
                    </div>
                    <div>
                      <span style={{ color: "#64748b" }}>Traversal: </span>
                      <span style={{ color: "#cbd5e1", fontFamily: "monospace" }}>
                        {selectedEdge.source_node} &rarr; {selectedEdge.target_node}
                      </span>
                    </div>
                    <div>
                      <span style={{ color: "#64748b" }}>Semantic Relation: </span>
                      <span style={{ color: "#cbd5e1" }}>{selectedEdge.relation}</span>
                    </div>
                    {selectedEdge.protocol && (
                      <div>
                        <span style={{ color: "#64748b" }}>Protocol / Port: </span>
                        <span style={{ color: "#cbd5e1" }}>
                          {selectedEdge.protocol.toUpperCase()} {selectedEdge.port && `:${selectedEdge.port}`}
                        </span>
                      </div>
                    )}
                    <div>
                      <span style={{ color: "#64748b" }}>Linked Evidence Events: </span>
                      <span style={{ color: "#cbd5e1", fontFamily: "monospace" }}>
                        {selectedEdge.evidence_event_ids.join(", ") || "None"}
                      </span>
                    </div>
                  </div>
                </div>
              ) : (
                <p style={{ color: "#94a3b8", fontSize: "13px" }}>
                  Select any node or edge in the graph canvas to inspect topological attributes and evidence references.
                </p>
              )}
            </div>
          </div>

          {/* Candidate Attack Paths */}
          {graph.candidate_paths && graph.candidate_paths.length > 0 && (
            <div style={{ backgroundColor: "#1e293b", borderRadius: "8px", border: "1px solid #334155", padding: "20px" }}>
              <h2 style={{ fontSize: "16px", fontWeight: 600, color: "#f8fafc", margin: "0 0 12px 0" }}>
                Candidate Traversal Paths ({graph.candidate_paths.length})
              </h2>
              <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                {graph.candidate_paths.map((p) => (
                  <div key={p.path_id} style={{ backgroundColor: "#0f172a", padding: "14px 18px", borderRadius: "6px", border: "1px solid #334155" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <span style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: 600, color: "#818cf8" }}>
                        {p.path_id}
                      </span>
                      {p.contains_inferred_relationships && (
                        <span style={{ padding: "2px 8px", borderRadius: "4px", fontSize: "11px", backgroundColor: "rgba(245, 158, 11, 0.2)", color: "#fbbf24", border: "1px solid rgba(245, 158, 11, 0.4)" }}>
                          Contains Inferred Hops
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: "13px", color: "#f1f5f9", fontFamily: "monospace" }}>
                      {p.node_ids.join("  →  ")}
                    </div>
                    {p.uncertainty_reasons.length > 0 && (
                      <div style={{ marginTop: "8px", fontSize: "12px", color: "#94a3b8" }}>
                        <em>Uncertainty: {p.uncertainty_reasons.join("; ")}</em>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
