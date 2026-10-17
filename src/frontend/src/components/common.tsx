import React from "react";
import { Link } from "react-router-dom";
import { PriorityLevel } from "../types/alert";

export function PriorityBadge({ priority }: { priority: PriorityLevel | string }) {
  const norm = priority.toLowerCase();
  let bg = "bg-slate-800 text-slate-300 border-slate-700";

  if (norm === "critical") {
    bg = "bg-rose-950/80 text-rose-400 border-rose-800/60";
  } else if (norm === "high") {
    bg = "bg-amber-950/80 text-amber-400 border-amber-800/60";
  } else if (norm === "medium") {
    bg = "bg-yellow-950/80 text-yellow-400 border-yellow-800/60";
  } else if (norm === "low") {
    bg = "bg-emerald-950/80 text-emerald-400 border-emerald-800/60";
  }

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "2px 8px",
        borderRadius: "4px",
        fontSize: "12px",
        fontWeight: 600,
        textTransform: "uppercase",
        letterSpacing: "0.05em",
        border: "1px solid",
      }}
      className={bg}
    >
      {priority}
    </span>
  );
}

export function LoadingSpinner({ message = "Loading security telemetry..." }: { message?: string }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "48px 16px" }}>
      <div
        style={{
          width: "36px",
          height: "36px",
          border: "3px solid #334155",
          borderTopColor: "#6366f1",
          borderRadius: "50%",
          animation: "spin 1s linear infinite",
        }}
      />
      <p style={{ marginTop: "16px", color: "#94a3b8", fontSize: "14px" }}>{message}</p>
      <style>{`@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }`}</style>
    </div>
  );
}

export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div
      style={{
        padding: "16px",
        backgroundColor: "rgba(153, 27, 27, 0.2)",
        border: "1px solid rgba(239, 68, 68, 0.4)",
        borderRadius: "8px",
        color: "#fca5a5",
        marginBottom: "24px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
      }}
    >
      <div>
        <strong style={{ display: "block", color: "#f87171", marginBottom: "4px" }}>Security Telemetry Query Error</strong>
        <span style={{ fontSize: "14px" }}>{message}</span>
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          style={{
            backgroundColor: "#ef4444",
            color: "#ffffff",
            border: "none",
            borderRadius: "4px",
            padding: "6px 14px",
            fontSize: "13px",
            fontWeight: 500,
            cursor: "pointer",
          }}
        >
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  actionLink,
  actionText,
}: {
  title: string;
  description: string;
  actionLink?: string;
  actionText?: string;
}) {
  return (
    <div
      style={{
        padding: "48px 24px",
        textAlign: "center",
        backgroundColor: "#0f172a",
        borderRadius: "8px",
        border: "1px dashed #334155",
        margin: "16px 0",
      }}
    >
      <div style={{ fontSize: "32px", marginBottom: "12px", opacity: 0.8 }}>🛡️</div>
      <h3 style={{ margin: "0 0 8px 0", color: "#f1f5f9", fontSize: "16px", fontWeight: 600 }}>{title}</h3>
      <p style={{ margin: "0 0 16px 0", color: "#94a3b8", fontSize: "14px", maxWidth: "480px", marginLeft: "auto", marginRight: "auto" }}>
        {description}
      </p>
      {actionLink && actionText && (
        <Link
          to={actionLink}
          style={{
            display: "inline-block",
            backgroundColor: "#4f46e5",
            color: "#ffffff",
            textDecoration: "none",
            padding: "8px 16px",
            borderRadius: "6px",
            fontSize: "13px",
            fontWeight: 500,
          }}
        >
          {actionText}
        </Link>
      )}
    </div>
  );
}

export function UncertaintyDisclaimer({ notes }: { notes?: string[] }) {
  const defaultNotes = [
    "Correlated accepted network traffic establishes reachability enabled by configuration changes.",
    "Attribution disclaimer: Observed flow does not confirm application-layer compromise or malicious intent.",
    "IAM identity responsible for rule authorization is decoupled from the network endpoint initiating traffic.",
  ];
  const displayNotes = notes && notes.length > 0 ? notes : defaultNotes;

  return (
    <div
      style={{
        backgroundColor: "rgba(30, 41, 59, 0.7)",
        border: "1px solid #334155",
        borderLeft: "4px solid #f59e0b",
        padding: "16px",
        borderRadius: "4px",
        margin: "16px 0",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#fbbf24", fontWeight: 600, fontSize: "13px", marginBottom: "8px" }}>
        <span>⚠️</span> Forensic Uncertainty & Attribution Boundaries
      </div>
      <ul style={{ margin: 0, paddingLeft: "20px", color: "#cbd5e1", fontSize: "13px", lineHeight: "1.6" }}>
        {displayNotes.map((note, idx) => (
          <li key={idx}>{note}</li>
        ))}
      </ul>
    </div>
  );
}
