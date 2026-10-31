import React, { useEffect, useState, useMemo, useCallback } from "react";
import { Link } from "react-router-dom";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  Node,
  Edge,
  useReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "dagre";

import { getGraph } from "../api/graph";
import { CandidatePath, GraphEdge, GraphNode, GraphResponse } from "../types/graph";
import { EmptyState, ErrorBanner, LoadingSpinner, UncertaintyDisclaimer } from "../components/common";
import { SecurityNodeComponent } from "../components/SecurityNodeComponent";

const NODE_WIDTH = 230;
const NODE_HEIGHT = 75;

// Define custom node types outside component to prevent re-creation
const nodeTypes = {
  securityNode: SecurityNodeComponent,
};

// Automatic Dagre hierarchical layout generator
function getLayoutedElements(
  nodes: Node[],
  edges: Edge[],
  direction: "TB" | "LR" = "LR"
) {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  dagreGraph.setGraph({
    rankdir: direction,
    nodesep: 50,
    ranksep: 80,
    marginx: 30,
    marginy: 30,
  });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    return {
      ...node,
      position: {
        x: nodeWithPosition ? nodeWithPosition.x - NODE_WIDTH / 2 : 0,
        y: nodeWithPosition ? nodeWithPosition.y - NODE_HEIGHT / 2 : 0,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}

// Sub-component inside ReactFlowProvider to have access to useReactFlow controls
function FlowCanvas({
  rawNodes,
  rawEdges,
  filterNature,
  onSelectNode,
  onSelectEdge,
  selectedNodeId,
  selectedEdgeId,
}: {
  rawNodes: GraphNode[];
  rawEdges: GraphEdge[];
  filterNature: string;
  onSelectNode: (node: GraphNode | null) => void;
  onSelectEdge: (edge: GraphEdge | null) => void;
  selectedNodeId?: string;
  selectedEdgeId?: string;
}) {
  const { fitView } = useReactFlow();

  // Filter raw edges based on user's active filter
  const filteredRawEdges = useMemo(() => {
    if (filterNature === "all") return rawEdges;
    return rawEdges.filter(
      (e) => (e.observed_or_inferred || "").toLowerCase() === filterNature.toLowerCase()
    );
  }, [rawEdges, filterNature]);

  // Set of valid node IDs
  const validNodeIds = useMemo(() => {
    return new Set(rawNodes.map((n) => n.node_id));
  }, [rawNodes]);

  // Transform GraphNodes -> ReactFlow Nodes
  const initialRfNodes: Node[] = useMemo(() => {
    return rawNodes.map((n) => ({
      id: n.node_id,
      type: "securityNode",
      data: {
        graphNode: n,
        isSelected: n.node_id === selectedNodeId,
      },
      position: { x: 0, y: 0 },
    }));
  }, [rawNodes, selectedNodeId]);

  // Transform GraphEdges -> ReactFlow Edges with correct colors & arrowheads
  const initialRfEdges: Edge[] = useMemo(() => {
    return filteredRawEdges
      .filter((e) => validNodeIds.has(e.source_node) && validNodeIds.has(e.target_node))
      .map((e) => {
        const nature = (e.observed_or_inferred || "").toLowerCase();
        const isSelected = e.edge_id === selectedEdgeId;

        let strokeColor = "#3b82f6"; // default blue (observed)
        let strokeDasharray: string | undefined = undefined;

        if (nature === "permitted") {
          strokeColor = "#10b981"; // green
        } else if (nature === "inferred") {
          strokeColor = "#f59e0b"; // amber / orange
          strokeDasharray = "5 5";
        }

        const label = e.port
          ? `${e.protocol ? e.protocol.toUpperCase() + " " : ""}:${e.port}`
          : e.relation === "permitted_reachability"
          ? "Permitted"
          : undefined;

        return {
          id: e.edge_id,
          source: e.source_node,
          target: e.target_node,
          type: "smoothstep",
          animated: nature === "inferred" || nature === "observed",
          label: label,
          labelStyle: {
            fill: strokeColor,
            fontWeight: 600,
            fontSize: 10,
            fontFamily: "monospace",
          },
          labelBgStyle: {
            fill: "#0f172a",
            fillOpacity: 0.85,
            stroke: strokeColor,
            strokeWidth: 1,
            rx: 3,
            ry: 3,
          },
          labelBgPadding: [4, 2] as [number, number],
          style: {
            stroke: isSelected ? "#f8fafc" : strokeColor,
            strokeWidth: isSelected ? 3 : 2,
            strokeDasharray: strokeDasharray,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: isSelected ? "#f8fafc" : strokeColor,
            width: 16,
            height: 16,
          },
          data: { graphEdge: e },
        };
      });
  }, [filteredRawEdges, validNodeIds, selectedEdgeId]);

  // Compute Dagre layout
  const { nodes: layoutedNodes, edges: layoutedEdges } = useMemo(() => {
    return getLayoutedElements(initialRfNodes, initialRfEdges, "LR");
  }, [initialRfNodes, initialRfEdges]);

  const [nodes, setNodes, onNodesChange] = useNodesState(layoutedNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(layoutedEdges);

  // Sync when layouted elements change
  useEffect(() => {
    setNodes(layoutedNodes);
    setEdges(layoutedEdges);
    setTimeout(() => {
      fitView({ padding: 0.2 });
    }, 50);
  }, [layoutedNodes, layoutedEdges, fitView]);

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      const gNode = rawNodes.find((n) => n.node_id === node.id) || null;
      onSelectNode(gNode);
      onSelectEdge(null);
    },
    [rawNodes, onSelectNode, onSelectEdge]
  );

  const handleEdgeClick = useCallback(
    (_: React.MouseEvent, edge: Edge) => {
      const gEdge = rawEdges.find((e) => e.edge_id === edge.id) || null;
      onSelectEdge(gEdge);
      onSelectNode(null);
    },
    [rawEdges, onSelectEdge, onSelectNode]
  );

  const handlePaneClick = useCallback(() => {
    onSelectNode(null);
    onSelectEdge(null);
  }, [onSelectNode, onSelectEdge]);

  return (
    <div style={{ width: "100%", height: "550px", position: "relative" }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        onEdgeClick={handleEdgeClick}
        onPaneClick={handlePaneClick}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.2}
        maxZoom={2.0}
        proOptions={{ hideAttribution: true }}
        style={{ backgroundColor: "#090d16", borderRadius: "8px" }}
      >
        <Background color="#334155" gap={20} size={1} />
        <Controls
          showInteractive={false}
          style={{
            backgroundColor: "#1e293b",
            borderColor: "#334155",
            fill: "#f8fafc",
            borderRadius: "6px",
            overflow: "hidden",
          }}
        />
        <MiniMap
          nodeColor={(n) => {
            const type = (n.data as any)?.graphNode?.node_type;
            if (type === "instance") return "#6366f1";
            if (type === "eni") return "#0284c7";
            if (type === "security_group") return "#10b981";
            return "#f59e0b";
          }}
          maskColor="rgba(15, 23, 42, 0.7)"
          style={{
            backgroundColor: "#0f172a",
            border: "1px solid #334155",
            borderRadius: "6px",
          }}
        />
      </ReactFlow>
    </div>
  );
}

export function AttackGraphPage() {
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [filterNature, setFilterNature] = useState<string>("all");

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

  return (
    <div style={{ maxWidth: "1400px", margin: "0 auto", padding: "24px 16px" }}>
      {/* Header */}
      <div style={{ marginBottom: "24px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 700, color: "#f8fafc", margin: "0 0 6px 0" }}>
          Attack Path & Lateral Movement Graph
        </h1>
        <p style={{ margin: 0, color: "#94a3b8", fontSize: "14px" }}>
          Interactive directed temporal graph topology distinguishing observed communication, permitted reachability, and inferred sequences
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
              <div style={{ fontSize: "11px", color: "#64748b" }}>Instances, ENIs & Endpoints</div>
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

          {/* Graph Controls & Legend Bar */}
          <div
            style={{
              backgroundColor: "#1e293b",
              borderRadius: "8px",
              border: "1px solid #334155",
              padding: "12px 18px",
              marginBottom: "16px",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "12px",
            }}
          >
            {/* Filter Buttons */}
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ fontSize: "12px", color: "#94a3b8", fontWeight: 600 }}>Filter Edges:</span>
              {[
                { id: "all", label: "All Relationships" },
                { id: "observed", label: "Observed Flows", color: "#3b82f6" },
                { id: "permitted", label: "Permitted Rules", color: "#10b981" },
                { id: "inferred", label: "Inferred Sequences", color: "#f59e0b" },
              ].map((btn) => (
                <button
                  key={btn.id}
                  onClick={() => setFilterNature(btn.id)}
                  style={{
                    padding: "4px 10px",
                    fontSize: "12px",
                    fontWeight: 500,
                    borderRadius: "4px",
                    cursor: "pointer",
                    backgroundColor: filterNature === btn.id ? "#334155" : "transparent",
                    color: filterNature === btn.id ? "#f8fafc" : "#94a3b8",
                    border: `1px solid ${filterNature === btn.id ? btn.color || "#818cf8" : "#334155"}`,
                  }}
                >
                  {btn.label}
                </button>
              ))}
            </div>

            {/* Visual Legend */}
            <div style={{ display: "flex", alignItems: "center", gap: "16px", fontSize: "12px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <span style={{ width: 14, height: 3, backgroundColor: "#3b82f6", display: "inline-block" }} />
                <span style={{ color: "#93c5fd" }}>Observed</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <span style={{ width: 14, height: 3, backgroundColor: "#10b981", display: "inline-block" }} />
                <span style={{ color: "#6ee7b7" }}>Permitted</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <span style={{ width: 14, height: 3, borderTop: "2px dashed #f59e0b", display: "inline-block" }} />
                <span style={{ color: "#fde68a" }}>Inferred</span>
              </div>
            </div>
          </div>

          {/* Main Visual Topology Viewport + Inspector Layout */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: "20px", marginBottom: "28px" }}>
            {/* Visual Canvas Container */}
            <div
              style={{
                backgroundColor: "#1e293b",
                borderRadius: "8px",
                border: "1px solid #334155",
                padding: "16px",
                display: "flex",
                flexDirection: "column",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <h2 style={{ fontSize: "15px", fontWeight: 600, color: "#f8fafc", margin: 0 }}>
                    Connected Network Topology
                  </h2>
                  <span style={{ fontSize: "11px", color: "#64748b" }}>
                    (Scroll to zoom, drag to pan, click nodes/edges to inspect)
                  </span>
                </div>
                <button
                  onClick={loadGraph}
                  style={{
                    padding: "4px 10px",
                    fontSize: "12px",
                    backgroundColor: "#334155",
                    color: "#f8fafc",
                    border: "none",
                    borderRadius: "4px",
                    cursor: "pointer",
                  }}
                >
                  Reload Topology
                </button>
              </div>

              {/* Connected React Flow Graph Canvas */}
              <ReactFlowProvider>
                <FlowCanvas
                  rawNodes={graph.nodes}
                  rawEdges={graph.edges}
                  filterNature={filterNature}
                  onSelectNode={setSelectedNode}
                  onSelectEdge={setSelectedEdge}
                  selectedNodeId={selectedNode?.node_id}
                  selectedEdgeId={selectedEdge?.edge_id}
                />
              </ReactFlowProvider>
            </div>

            {/* Interactive Inspector Panel */}
            <div
              style={{
                backgroundColor: "#1e293b",
                borderRadius: "8px",
                border: "1px solid #334155",
                padding: "20px",
                maxHeight: "620px",
                overflowY: "auto",
              }}
            >
              <h2 style={{ fontSize: "16px", fontWeight: 600, color: "#f8fafc", margin: "0 0 16px 0" }}>
                Inspector Details
              </h2>

              {selectedNode ? (
                <div>
                  <div style={{ color: "#818cf8", fontSize: "11px", textTransform: "uppercase", fontWeight: 700, marginBottom: "4px" }}>
                    Selected Entity
                  </div>
                  <h3 style={{ fontSize: "15px", fontWeight: 600, color: "#f8fafc", margin: "0 0 12px 0", fontFamily: "monospace", wordBreak: "break-all" }}>
                    {selectedNode.node_id}
                  </h3>
                  <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "13px" }}>
                    <div>
                      <span style={{ color: "#64748b" }}>Type: </span>
                      <span style={{ color: "#cbd5e1", fontWeight: 600, textTransform: "uppercase" }}>
                        {selectedNode.node_type}
                      </span>
                    </div>
                    <div>
                      <span style={{ color: "#64748b" }}>IP Addresses: </span>
                      <span style={{ color: "#cbd5e1", fontFamily: "monospace" }}>
                        {selectedNode.ip_addresses && selectedNode.ip_addresses.length > 0
                          ? selectedNode.ip_addresses.join(", ")
                          : "None"}
                      </span>
                    </div>
                    {selectedNode.label && (
                      <div>
                        <span style={{ color: "#64748b" }}>Label: </span>
                        <span style={{ color: "#cbd5e1" }}>{selectedNode.label}</span>
                      </div>
                    )}
                    {selectedNode.properties && Object.keys(selectedNode.properties).length > 0 && (
                      <div style={{ marginTop: "8px" }}>
                        <span style={{ color: "#64748b", display: "block", marginBottom: "4px" }}>Properties:</span>
                        <pre style={{ backgroundColor: "#0f172a", padding: "8px", borderRadius: "4px", fontSize: "11px", overflow: "auto", color: "#94a3b8" }}>
                          {JSON.stringify(selectedNode.properties, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              ) : selectedEdge ? (
                <div>
                  <div style={{ color: "#818cf8", fontSize: "11px", textTransform: "uppercase", fontWeight: 700, marginBottom: "4px" }}>
                    Selected Relationship
                  </div>
                  <h3 style={{ fontSize: "13px", fontWeight: 600, color: "#f8fafc", margin: "0 0 12px 0", fontFamily: "monospace" }}>
                    {selectedEdge.edge_id}
                  </h3>
                  <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "13px" }}>
                    <div>
                      <span style={{ color: "#64748b" }}>Verification Nature: </span>
                      <span
                        style={{
                          fontWeight: 700,
                          textTransform: "uppercase",
                          color:
                            selectedEdge.observed_or_inferred === "permitted"
                              ? "#34d399"
                              : selectedEdge.observed_or_inferred === "inferred"
                              ? "#fbbf24"
                              : "#60a5fa",
                        }}
                      >
                        {selectedEdge.observed_or_inferred}
                      </span>
                    </div>
                    <div>
                      <span style={{ color: "#64748b" }}>Source Entity: </span>
                      <div style={{ color: "#cbd5e1", fontFamily: "monospace", fontSize: "12px", wordBreak: "break-all" }}>
                        {selectedEdge.source_node}
                      </div>
                    </div>
                    <div>
                      <span style={{ color: "#64748b" }}>Target Entity: </span>
                      <div style={{ color: "#cbd5e1", fontFamily: "monospace", fontSize: "12px", wordBreak: "break-all" }}>
                        {selectedEdge.target_node}
                      </div>
                    </div>
                    <div>
                      <span style={{ color: "#64748b" }}>Relation: </span>
                      <span style={{ color: "#cbd5e1" }}>{selectedEdge.relation}</span>
                    </div>
                    {selectedEdge.port && (
                      <div>
                        <span style={{ color: "#64748b" }}>Protocol / Port: </span>
                        <span style={{ color: "#cbd5e1", fontFamily: "monospace" }}>
                          {selectedEdge.protocol ? selectedEdge.protocol.toUpperCase() + " " : ""}
                          Port {selectedEdge.port}
                        </span>
                      </div>
                    )}
                    {selectedEdge.valid_time && (
                      <div>
                        <span style={{ color: "#64748b" }}>Timestamp: </span>
                        <span style={{ color: "#cbd5e1", fontFamily: "monospace", fontSize: "11px" }}>
                          {new Date(selectedEdge.valid_time).toISOString()}
                        </span>
                      </div>
                    )}
                    {selectedEdge.confidence_reason && (
                      <div>
                        <span style={{ color: "#64748b" }}>Confidence Reason: </span>
                        <span style={{ color: "#94a3b8", fontSize: "12px" }}>{selectedEdge.confidence_reason}</span>
                      </div>
                    )}
                    {selectedEdge.evidence_event_ids && selectedEdge.evidence_event_ids.length > 0 && (
                      <div>
                        <span style={{ color: "#64748b" }}>Evidence IDs ({selectedEdge.evidence_event_ids.length}):</span>
                        <div style={{ maxHeight: "80px", overflowY: "auto", marginTop: "4px" }}>
                          {selectedEdge.evidence_event_ids.map((id) => (
                            <div key={id} style={{ fontFamily: "monospace", fontSize: "10px", color: "#64748b" }}>
                              {id}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div style={{ color: "#94a3b8", fontSize: "13px" }}>
                  <p>Click on any node card or edge arrow on the canvas to inspect its full properties, protocols, ports, and forensic evidence.</p>
                </div>
              )}
            </div>
          </div>

          {/* Candidate Attack Paths Traversal */}
          {graph.candidate_paths && graph.candidate_paths.length > 0 && (
            <div style={{ backgroundColor: "#1e293b", borderRadius: "8px", border: "1px solid #334155", padding: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                <h2 style={{ fontSize: "16px", fontWeight: 600, color: "#f8fafc", margin: 0 }}>
                  Candidate Traversal Paths ({graph.candidate_paths.length})
                </h2>
                <span style={{ fontSize: "12px", color: "#94a3b8" }}>
                  Multi-hop lateral movement chains
                </span>
              </div>
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
