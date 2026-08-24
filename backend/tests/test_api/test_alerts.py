"""
Tests for alert API endpoints
"""
import pytest
from fastapi.testclient import TestClient
from datetime import datetime

from app.main import app
from app.db.session import SessionLocal
from app.models.alert import Alert


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def auth_headers(client):
    """Get authentication headers"""
    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "admin",
            "password": "ChangeThisPassword123!"
        }
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_list_alerts(client, auth_headers):
    """Test listing alerts"""
    response = client.get(
        "/api/v1/alerts/",
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_get_alert_stats(client, auth_headers):
    """Test alert statistics"""
    response = client.get(
        "/api/v1/alerts/stats",
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "by_severity" in data
    assert "by_category" in data


def test_filter_alerts_by_severity(client, auth_headers):
    """Test filtering alerts by severity"""
    response = client.get(
        "/api/v1/alerts/?severity=HIGH",
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # All returned alerts should be HIGH severity
    for alert in data:
        assert alert["severity"] == "HIGH"


def test_update_alert_unauthorized(client):
    """Test that updating alert requires authentication"""
    response = client.patch(
        "/api/v1/alerts/1",
        json={"status": "acknowledged"}
    )
    
    assert response.status_code == 401
