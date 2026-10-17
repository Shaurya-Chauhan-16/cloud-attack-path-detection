"""FastAPI backend service for Cloud-Network Attack Path Detection.

Phase 1 & Phase 2 foundation providing API schemas, services, and endpoints.
"""
from typing import Dict
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routers import alerts, cases, events, reports, timeline

app = FastAPI(
    title="Cloud-Network Attack Path Detection API",
    description="Backend API service for cross-layer telemetry analysis, attack path graphs, and alert management.",
    version="0.1.0",
)

# CORS middleware for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(alerts.router)
app.include_router(events.router)
app.include_router(timeline.router)
app.include_router(cases.router)
app.include_router(reports.router)


@app.get("/health", tags=["Health"])
async def health_check() -> Dict[str, str]:
    """Health check endpoint to verify backend service readiness."""
    return {
        "status": "healthy",
        "service": "cloud-attack-path-detection-api",
        "version": "0.1.0",
    }
