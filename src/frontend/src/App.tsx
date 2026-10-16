import React from "react";
import { BrowserRouter, Link, Route, Routes, useLocation } from "react-router-dom";
import { Dashboard } from "./pages/Dashboard";
import { Alerts } from "./pages/Alerts";
import { AlertDetails } from "./pages/AlertDetails";
import { AttackGraphPage } from "./pages/CaseInvestigation";
import { TelemetryTimelinePage } from "./pages/Timeline";
import { CaseInvestigationPage } from "./pages/Cases";

function NavigationBar() {
  const location = useLocation();

  const links = [
    { to: "/", label: "Dashboard", icon: "📊" },
    { to: "/alerts", label: "Alerts", icon: "🚨" },
    { to: "/cases", label: "Cases & Reports", icon: "📁" },
    { to: "/graph", label: "Attack Graph", icon: "🕸️" },
    { to: "/timeline", label: "Telemetry Timeline", icon: "⏱️" },
  ];

  return (
    <header style={{ backgroundColor: "#0f172a", borderBottom: "1px solid #1e293b", position: "sticky", top: 0, zIndex: 50 }}>
      <div style={{ maxWidth: "1280px", margin: "0 auto", padding: "0 16px", height: "64px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        {/* Brand */}
        <Link to="/" style={{ display: "flex", alignItems: "center", gap: "10px", textDecoration: "none" }}>
          <span style={{ fontSize: "20px" }}>🛡️</span>
          <div>
            <span style={{ fontWeight: 700, fontSize: "16px", color: "#f8fafc", letterSpacing: "-0.02em" }}>
              Cloud Attack Path Detection
            </span>
            <span style={{ display: "block", fontSize: "11px", color: "#64748b", fontWeight: 500 }}>
              Member 3 SOC Investigation Console
            </span>
          </div>
        </Link>

        {/* Links */}
        <nav style={{ display: "flex", gap: "8px" }}>
          {links.map((link) => {
            const isActive = location.pathname === link.to || (link.to !== "/" && location.pathname.startsWith(link.to));
            return (
              <Link
                key={link.to}
                to={link.to}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  padding: "6px 14px",
                  borderRadius: "6px",
                  textDecoration: "none",
                  fontSize: "13px",
                  fontWeight: 500,
                  backgroundColor: isActive ? "#1e293b" : "transparent",
                  color: isActive ? "#818cf8" : "#94a3b8",
                  border: `1px solid ${isActive ? "#334155" : "transparent"}`,
                  transition: "all 0.15s ease",
                }}
              >
                <span>{link.icon}</span>
                <span>{link.label}</span>
              </Link>
            );
          })}
        </nav>

        {/* Environment status indicator */}
        <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "12px", color: "#94a3b8" }}>
          <span style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: "#10b981", display: "inline-block" }} />
          <span>API Connected</span>
        </div>
      </div>
    </header>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <div style={{ minHeight: "100vh", backgroundColor: "#0b0f19", color: "#f1f5f9", display: "flex", flexDirection: "column" }}>
        <NavigationBar />
        <main style={{ flex: 1 }}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/alerts/:alertId" element={<AlertDetails />} />
            <Route path="/cases" element={<CaseInvestigationPage />} />
            <Route path="/graph" element={<AttackGraphPage />} />
            <Route path="/timeline" element={<TelemetryTimelinePage />} />
          </Routes>
        </main>
        <footer style={{ backgroundColor: "#0f172a", borderTop: "1px solid #1e293b", padding: "16px", textAlign: "center", fontSize: "12px", color: "#64748b" }}>
          Cloud-Network Attack Path & Lateral Movement Detection &bull; Cross-Layer Security Telemetry Research Platform
        </footer>
      </div>
    </BrowserRouter>
  );
}

export default App;
