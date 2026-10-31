import React, { memo } from "react";
import { Handle, Position, NodeProps } from "@xyflow/react";
import { GraphNode } from "../types/graph";

export interface CustomNodeData {
  graphNode: GraphNode;
  isSelected?: boolean;
}

const getNodeTheme = (nodeType: string) => {
  const type = (nodeType || "").toLowerCase();
  if (type === "instance" || type === "ec2") {
    return {
      icon: "💻",
      border: "#6366f1",
      borderSelected: "#a5b4fc",
      bg: "#1e1b4b",
      badgeBg: "rgba(99, 102, 241, 0.2)",
      badgeColor: "#a5b4fc",
      badgeText: "EC2 Instance",
    };
  }
  if (type === "eni" || type === "network_interface") {
    return {
      icon: "🔌",
      border: "#0284c7",
      borderSelected: "#38bdf8",
      bg: "#0c4a6e",
      badgeBg: "rgba(2, 132, 199, 0.2)",
      badgeColor: "#38bdf8",
      badgeText: "ENI Interface",
    };
  }
  if (type === "security_group" || type === "sg") {
    return {
      icon: "🛡️",
      border: "#10b981",
      borderSelected: "#34d399",
      bg: "#064e3b",
      badgeBg: "rgba(16, 185, 129, 0.2)",
      badgeColor: "#6ee7b7",
      badgeText: "Security Group",
    };
  }
  // Default to ip_endpoint / external / internet
  return {
    icon: "🌐",
    border: "#f59e0b",
    borderSelected: "#fbbf24",
    bg: "#451a03",
    badgeBg: "rgba(245, 158, 11, 0.2)",
    badgeColor: "#fde68a",
    badgeText: "IP Endpoint",
  };
};

export const SecurityNodeComponent = memo(({ data, selected }: NodeProps) => {
  const nodeData = data as unknown as CustomNodeData;
  const graphNode = nodeData?.graphNode;
  if (!graphNode) return null;

  const theme = getNodeTheme(graphNode.node_type);
  const isHighlighted = selected || nodeData.isSelected;

  // Truncate long display names if needed
  const displayName = graphNode.label || graphNode.node_id;

  return (
    <div
      style={{
        width: 230,
        backgroundColor: "#0f172a",
        border: `2px solid ${isHighlighted ? theme.borderSelected : theme.border}`,
        borderRadius: "8px",
        boxShadow: isHighlighted
          ? `0 0 16px ${theme.borderSelected}, 0 4px 6px -1px rgba(0, 0, 0, 0.5)`
          : "0 4px 10px rgba(0, 0, 0, 0.4)",
        color: "#f8fafc",
        fontFamily: "system-ui, -apple-system, sans-serif",
        overflow: "hidden",
        transition: "all 0.15s ease",
        cursor: "pointer",
      }}
    >
      {/* Target handle on top and left */}
      <Handle
        type="target"
        position={Position.Top}
        style={{ background: theme.border, width: 8, height: 8 }}
      />
      <Handle
        type="target"
        position={Position.Left}
        id="left"
        style={{ background: theme.border, width: 8, height: 8 }}
      />

      {/* Header Bar */}
      <div
        style={{
          backgroundColor: theme.bg,
          padding: "6px 10px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          borderBottom: `1px solid ${theme.border}44`,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <span style={{ fontSize: "14px" }}>{theme.icon}</span>
          <span
            style={{
              fontSize: "10px",
              fontWeight: 700,
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              color: theme.badgeColor,
            }}
          >
            {theme.badgeText}
          </span>
        </div>
        {graphNode.ip_addresses && graphNode.ip_addresses.length > 0 && (
          <span
            style={{
              fontSize: "10px",
              color: "#94a3b8",
              backgroundColor: "rgba(15, 23, 42, 0.6)",
              padding: "1px 4px",
              borderRadius: "3px",
              fontFamily: "monospace",
            }}
          >
            {graphNode.ip_addresses[0]}
          </span>
        )}
      </div>

      {/* Body */}
      <div style={{ padding: "8px 10px" }}>
        <div
          title={displayName}
          style={{
            fontFamily: "monospace",
            fontSize: "12px",
            fontWeight: 600,
            color: "#f8fafc",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {displayName}
        </div>

        {graphNode.properties?.vpc_id && (
          <div style={{ fontSize: "10px", color: "#64748b", marginTop: "3px", fontFamily: "monospace" }}>
            VPC: {graphNode.properties.vpc_id}
          </div>
        )}
      </div>

      {/* Source handle on bottom and right */}
      <Handle
        type="source"
        position={Position.Bottom}
        style={{ background: theme.border, width: 8, height: 8 }}
      />
      <Handle
        type="source"
        position={Position.Right}
        id="right"
        style={{ background: theme.border, width: 8, height: 8 }}
      />
    </div>
  );
});

SecurityNodeComponent.displayName = "SecurityNodeComponent";
