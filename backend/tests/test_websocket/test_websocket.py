"""
Tests for WebSocket functionality
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_websocket_connection(client):
    """Test WebSocket connection without auth"""
    with client.websocket_connect("/api/v1/ws/events") as websocket:
        # Should receive welcome message
        data = websocket.receive_json()
        assert data["type"] == "connection_established"
        assert "timestamp" in data


def test_websocket_ping_pong(client):
    """Test WebSocket ping/pong"""
    with client.websocket_connect("/api/v1/ws/events") as websocket:
        # Skip welcome message
        websocket.receive_json()
        
        # Send ping
        websocket.send_text("ping")
        
        # Should receive pong
        data = websocket.receive_json()
        assert data["type"] == "pong"


def test_websocket_dashboard_connection(client):
    """Test dashboard WebSocket endpoint"""
    with client.websocket_connect("/api/v1/ws/dashboard") as websocket:
        data = websocket.receive_json()
        assert data["type"] == "connection_established"
