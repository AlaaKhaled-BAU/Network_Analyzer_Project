"""
Load Testing for NetGuardian Pro API
=====================================

This file uses Locust to perform load testing on the API.

Run with:
    locust -f tests/locustfile.py --host=http://localhost:8000

Then open http://localhost:8089 to configure and start the test.
"""

from locust import HttpUser, task, between


class DashboardUser(HttpUser):
    """Simulates a user viewing the dashboard"""
    
    # Wait 1-3 seconds between tasks (simulates user behavior)
    wait_time = between(1, 3)
    
    @task(5)  # Weight 5 - most common
    def view_dashboard(self):
        """Load main dashboard"""
        self.client.get("/dashboard")
    
    @task(3)  # Weight 3
    def get_features(self):
        """Fetch traffic features"""
        self.client.get("/api/features")
    
    @task(2)  # Weight 2
    def get_alerts(self):
        """Fetch security alerts"""
        self.client.get("/api/alerts")
    
    @task(2)
    def get_protocols(self):
        """Fetch protocol distribution"""
        self.client.get("/api/protocols")
    
    @task(1)
    def get_top_sources(self):
        """Fetch top source IPs"""
        self.client.get("/api/top-sources")
    
    @task(1)
    def get_top_destinations(self):
        """Fetch top destination IPs"""
        self.client.get("/api/top-destinations")
    
    @task(1)
    def health_check(self):
        """Health check"""
        self.client.get("/health")


class PacketIngester(HttpUser):
    """Simulates sender.py sending packets"""
    
    # Send packets every 0.5-2 seconds
    wait_time = between(0.5, 2)
    
    @task
    def ingest_packets(self):
        """Send batch of packets"""
        test_packets = [
            {
                "timestamp": 1234567890.0 + i,
                "src_ip": f"192.168.1.{100 + (i % 50)}",
                "dst_ip": "10.0.0.1",
                "protocol": "TCP" if i % 2 == 0 else "UDP",
                "length": 100 + (i * 10),
                "src_port": 12345 + i,
                "dst_port": 80 if i % 3 == 0 else 443
            }
            for i in range(50)  # 50 packets per batch
        ]
        
        self.client.post("/ingest", json=test_packets)


# ==================== HOW TO USE ====================
"""
1. Install Locust:
   pip install locust

2. Start your server:
   cd server
   uvicorn app.main:app --host 0.0.0.0 --port 8000

3. Run Locust (in another terminal):
   locust -f tests/locustfile.py --host=http://localhost:8000

4. Open browser:
   http://localhost:8089

5. Configure test:
   - Number of users: Start with 10, increase to 100
   - Spawn rate: 5 users/second
   - Click "Start Swarming"

6. Monitor results:
   - Watch RPS (requests per second)
   - Watch response times
   - Watch failure rate

Target Metrics for Network Analyzer:
- Dashboard: < 200ms response time
- API endpoints: < 100ms response time
- Packet ingestion: > 1000 packets/second throughput
- No failures up to 50 concurrent users
"""
