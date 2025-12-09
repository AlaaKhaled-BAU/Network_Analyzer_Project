#!/usr/bin/env python3
"""
Seed script to populate the database with test data for dashboard visualization
"""

from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, Float, Boolean, DateTime, Text
from datetime import datetime
import random
import time

# Database setup
DATABASE_URL = "sqlite:///./traffic_analyzer.db"
engine = create_engine(DATABASE_URL)
metadata = MetaData()

# Define tables
raw_packets_table = Table(
    "raw_packets", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", Float),
    Column("interface", String),
    Column("src_ip", String),
    Column("dst_ip", String),
    Column("protocol", String),
    Column("length", Integer),
    Column("src_port", Integer, nullable=True),
    Column("dst_port", Integer, nullable=True),
    Column("tcp_flags", String, nullable=True),
    Column("tcp_syn", Boolean, nullable=True),
    Column("tcp_ack", Boolean, nullable=True),
    Column("tcp_fin", Boolean, nullable=True),
    Column("tcp_rst", Boolean, nullable=True),
    Column("tcp_psh", Boolean, nullable=True),
    Column("seq", Integer, nullable=True),
    Column("ack", Integer, nullable=True),
    Column("icmp_type", Integer, nullable=True),
    Column("icmp_code", Integer, nullable=True),
    Column("arp_op", Integer, nullable=True),
    Column("arp_psrc", String, nullable=True),
    Column("arp_pdst", String, nullable=True),
    Column("arp_hwsrc", String, nullable=True),
    Column("arp_hwdst", String, nullable=True),
    Column("dns_query", Boolean, nullable=True),
    Column("dns_qname", String, nullable=True),
    Column("dns_qtype", Integer, nullable=True),
    Column("dns_response", Boolean, nullable=True),
    Column("dns_answer_count", Integer, nullable=True),
    Column("dns_answer_size", Integer, nullable=True),
    Column("http_method", String, nullable=True),
    Column("http_path", String, nullable=True),
    Column("http_status_code", String, nullable=True),
    Column("http_host", String, nullable=True),
    Column("inserted_at", DateTime, default=datetime.utcnow)
)

traffic_table = Table(
    "traffic_data", metadata,
    Column("id_num", Integer, primary_key=True, autoincrement=True),
    Column("dest_ip", String),
    Column("source_mac", String),
    Column("dest_mac", String),
    Column("packet_count", Integer),
    Column("packet_per_sec", Float),
    Column("byte_count", Integer),
    Column("byte_per_sec", Float),
    Column("tcp_flags", String),
    Column("connection_attempts", Integer),
    Column("unique_ports", Integer),
    Column("protocol", String),
    Column("predicted_label", String),
    Column("created_at", DateTime, default=datetime.utcnow)
)

# Test data generators
protocols = ["TCP", "UDP", "ICMP", "DNS", "HTTP"]
tcp_flags = ["S", "SA", "A", "PA", "FA", "R", ""]
source_ips = ["192.168.1.100", "192.168.1.101", "192.168.1.102", "10.0.0.5", "10.0.0.10"]
dest_ips = ["8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1", "172.16.0.1", "93.184.216.34"]
source_macs = ["00:1A:2B:3C:4D:5E", "00:1A:2B:3C:4D:5F", "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", "FF:EE:DD:CC:BB:AA"]
dest_macs = ["00:50:56:C0:00:01", "00:50:56:C0:00:02", "00:0C:29:XX:YY:ZZ"]

# Attack labels for alerts view
attack_labels = ["DDoS Attack", "Port Scanning", "Brute Force", "Normal", "Normal", "Normal", "Normal", "Normal"]

def generate_raw_packets(count=100):
    """Generate raw packet test data"""
    packets = []
    base_time = time.time() - 3600  # Start 1 hour ago
    
    for i in range(count):
        protocol = random.choice(protocols)
        src_ip = random.choice(source_ips)
        dst_ip = random.choice(dest_ips)
        
        packet = {
            "timestamp": base_time + (i * 10),
            "interface": "eth0",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "length": random.randint(64, 1500),
            "src_port": random.randint(1024, 65535) if protocol in ["TCP", "UDP"] else None,
            "dst_port": random.choice([80, 443, 22, 53, 8080, 3389]) if protocol in ["TCP", "UDP"] else None,
            "tcp_flags": random.choice(tcp_flags) if protocol == "TCP" else None,
            "tcp_syn": random.choice([True, False]) if protocol == "TCP" else None,
            "tcp_ack": random.choice([True, False]) if protocol == "TCP" else None,
            "tcp_fin": False,
            "tcp_rst": False,
            "tcp_psh": random.choice([True, False]) if protocol == "TCP" else None,
            "seq": random.randint(1000, 999999) if protocol == "TCP" else None,
            "ack": random.randint(1000, 999999) if protocol == "TCP" else None,
            "dns_query": True if protocol == "DNS" else None,
            "dns_qname": random.choice(["google.com", "facebook.com", "github.com"]) if protocol == "DNS" else None,
            "http_method": random.choice(["GET", "POST"]) if protocol == "HTTP" else None,
            "http_path": random.choice(["/", "/api/data", "/index.html"]) if protocol == "HTTP" else None,
        }
        packets.append(packet)
    
    return packets

def generate_traffic_flows(count=50):
    """Generate aggregated traffic flow data"""
    flows = []
    
    for i in range(count):
        protocol = random.choice(protocols)
        label = random.choice(attack_labels)
        packet_count = random.randint(10, 500)
        byte_count = random.randint(1000, 500000)
        
        flow = {
            "dest_ip": random.choice(dest_ips),
            "source_mac": random.choice(source_macs),
            "dest_mac": random.choice(dest_macs),
            "packet_count": packet_count,
            "packet_per_sec": round(packet_count / 5.0, 2),
            "byte_count": byte_count,
            "byte_per_sec": round(byte_count / 5.0, 2),
            "tcp_flags": random.choice(tcp_flags),
            "connection_attempts": random.randint(1, 50),
            "unique_ports": random.randint(1, 20),
            "protocol": protocol,
            "predicted_label": label,
            "created_at": datetime.utcnow()
        }
        flows.append(flow)
    
    return flows

def seed_database():
    """Populate database with test data"""
    print("🌱 Seeding database with test data...")
    
    # Create tables if they don't exist
    metadata.create_all(engine)
    
    with engine.begin() as conn:
        # Clear existing data
        print("  Clearing existing data...")
        conn.execute(raw_packets_table.delete())
        conn.execute(traffic_table.delete())
        
        # Insert raw packets
        print("  Inserting 100 raw packets...")
        packets = generate_raw_packets(100)
        for packet in packets:
            conn.execute(raw_packets_table.insert().values(**packet))
        
        # Insert traffic flows
        print("  Inserting 50 traffic flows...")
        flows = generate_traffic_flows(50)
        for flow in flows:
            conn.execute(traffic_table.insert().values(**flow))
    
    print("✅ Database seeded successfully!")
    print(f"   - {len(packets)} raw packets")
    print(f"   - {len(flows)} traffic flows")
    print(f"   - {len([f for f in flows if f['predicted_label'] != 'Normal'])} security alerts")
    print("\n🚀 Start the server with: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload")
    print("📊 Then visit: http://localhost:8000/dashboard")

if __name__ == "__main__":
    seed_database()
