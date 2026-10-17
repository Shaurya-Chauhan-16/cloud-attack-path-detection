"""Unit tests for FastAPI app initialization and health endpoint."""
from fastapi.testclient import TestClient

from src.api.main import app


def test_app_initialization():
    """Test that the FastAPI application initializes properly with expected metadata."""
    assert app is not None
    assert app.title == "Cloud-Network Attack Path Detection API"
    assert app.version == "0.1.0"


def test_health_endpoint():
    """Test the /health endpoint returns HTTP 200 and valid status payload."""
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "cloud-attack-path-detection-api"
    assert data["version"] == "0.1.0"


def test_cors_headers():
    """Test that CORS middleware allows requests from frontend origins."""
    client = TestClient(app)
    response = client.get(
        "/health",
        headers={"Origin": "http://localhost:3000"}
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") in ["*", "http://localhost:3000"]
