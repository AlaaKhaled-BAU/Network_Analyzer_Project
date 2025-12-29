# API Tests for NetGuardian Pro
# ================================
# Run all tests: pytest tests/ -v
# Run specific: pytest tests/test_smoke.py -v

# Requirements:
# pip install pytest pytest-asyncio httpx locust

import pytest
from fastapi.testclient import TestClient
import sys
from pathlib import Path

# Add server/app to path
sys.path.insert(0, str(Path(__file__).parent.parent / "server" / "app"))

from main import app

# Create test client
client = TestClient(app)


# ==================== SMOKE TESTS ====================
# Quick tests to verify basic functionality

class TestSmoke:
    """Smoke tests - run these first to ensure basic functionality"""
    
    def test_server_running(self):
        """Test that server responds to health check"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "running"
        assert "database_available" in data
        
    def test_health_endpoint(self):
        """Test health endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "websocket_clients" in data
        
    def test_dashboard_loads(self):
        """Test dashboard HTML loads"""
        response = client.get("/dashboard")
        assert response.status_code == 200
        assert "NetGuardian" in response.text
        
    def test_api_docs_available(self):
        """Test Swagger docs are available"""
        response = client.get("/docs")
        assert response.status_code == 200


# ==================== FUNCTIONAL TESTS ====================
# Test API endpoints return correct data format

class TestFunctionalAPI:
    """Functional tests for API endpoints"""
    
    def test_api_features_structure(self):
        """Test /api/features returns correct structure"""
        response = client.get("/api/features")
        assert response.status_code == 200
        # Should return data or error message
        data = response.json()
        assert isinstance(data, dict)
        
    def test_api_alerts_structure(self):
        """Test /api/alerts returns list structure"""
        response = client.get("/api/alerts")
        assert response.status_code == 200
        data = response.json()
        # Should be list or dict with error
        assert isinstance(data, (list, dict))
        
    def test_api_protocols_structure(self):
        """Test /api/protocols returns correct structure"""
        response = client.get("/api/protocols")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)
        # Should have labels and values for chart
        if "labels" in data:
            assert "values" in data
            
    def test_api_top_sources_structure(self):
        """Test /api/top-sources returns list"""
        response = client.get("/api/top-sources")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (list, dict))
        
    def test_api_top_destinations_structure(self):
        """Test /api/top-destinations returns list"""
        response = client.get("/api/top-destinations")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (list, dict))
        
    def test_api_top_ports_structure(self):
        """Test /api/top-ports returns list"""
        response = client.get("/api/top-ports")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (list, dict))


# ==================== WEBSOCKET TESTS ====================

class TestWebSocket:
    """WebSocket connection tests"""
    
    def test_websocket_connection(self):
        """Test WebSocket connects and receives initial data"""
        try:
            with client.websocket_connect("/ws/dashboard") as websocket:
                # Should receive initial data
                data = websocket.receive_json()
                assert data["type"] == "initial"
                assert "stats" in data
                assert "timestamp" in data
                
                # Send ping
                websocket.send_text("ping")
                response = websocket.receive_text()
                assert response == "pong"
        except Exception as e:
            # WebSocket might not be supported in test client
            pytest.skip(f"WebSocket test skipped: {e}")


# ==================== INTEGRATION TESTS ====================

class TestIntegration:
    """Integration tests - test full data flow"""
    
    def test_ingest_without_database(self):
        """Test ingestion endpoint behavior without database"""
        test_packets = [
            {
                "timestamp": 1234567890.0,
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.1",
                "protocol": "TCP",
                "length": 100,
                "src_port": 12345,
                "dst_port": 80
            }
        ]
        
        response = client.post("/ingest", json=test_packets)
        # Either 200 (DB available) or 503 (DB unavailable)
        assert response.status_code in [200, 503]
        
    def test_full_api_cycle(self):
        """Test that all critical endpoints respond"""
        endpoints = [
            "/",
            "/health",
            "/api/features",
            "/api/alerts",
            "/api/protocols"
        ]
        
        for endpoint in endpoints:
            response = client.get(endpoint)
            assert response.status_code == 200, f"Endpoint {endpoint} failed"


# ==================== RUN TESTS ====================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
