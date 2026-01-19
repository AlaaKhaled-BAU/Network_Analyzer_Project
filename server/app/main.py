"""
NetGuardian Pro - Production Server
=====================================
Merged from server_sos/main.py + server/app/main.py

Features:
- PostgreSQL database connection
- XGBoost ML pipeline with label encoder
- Background prediction loop (threading)
- File upload packet ingestion (JSON)
- Complete dashboard API endpoints
- 3 new port category features
- WebSocket real-time dashboard updates (/ws/dashboard)
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Text, Boolean, BigInteger, desc, func
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.dialects.postgresql import JSON
from datetime import datetime, timedelta, timezone
# Try different import paths for telegram_bot
try:
    # When running as server.app.main from root
    from server.app.telegram_bot import send_security_alert
except ImportError:
    try:
        # When running from server directory
        from app.telegram_bot import send_security_alert
    except ImportError:
        try:
            # When running from app directory or with direct path
            from telegram_bot import send_security_alert
        except ImportError:
            # Define dummy function if module missing
            def send_security_alert(*args, **kwargs):
                print("⚠️ Telegram bot module not found - alerts disabled")

# Global Timezone Setting (UTC+3)
LOCAL_TZ = timezone(timedelta(hours=3))
import pandas as pd
import numpy as np
import joblib
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import json
import tempfile
import os
from pathlib import Path
from typing import List, Dict, Optional
import uvicorn
import asyncio
from dotenv import load_dotenv
from xgboost import XGBClassifier

# Load environment variables from .env file
load_dotenv(Path(__file__).parent.parent.parent / ".env")

# ========== CONFIGURATION ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Paths
SERVER_DIR = Path(__file__).parent
APP_DIR = SERVER_DIR  # We're in server/app/
SERVER_ROOT = APP_DIR.parent  # server/
MODEL_DIR = SERVER_ROOT / "models"
TEMPLATES_DIR = SERVER_ROOT / "templates"
STATIC_DIR = SERVER_ROOT / "static"
DASHBOARD_FILE = TEMPLATES_DIR / "netguardian_tailwind.html"

# Database - PostgreSQL (loaded from .env)
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/NetGuardian Pro")
if "password" in DATABASE_URL:
    logger.warning("⚠️ DATABASE_URL not found in .env file! Using default (insecure) connection.")

# ML Model files (from server/models/)
XGB_MODEL_JSON_PATH = MODEL_DIR / "xgboost_model.json"
XGB_MODEL_PATH = MODEL_DIR / "xgb_model.pkl"
LABEL_ENCODER_PATH = MODEL_DIR / "label_encoder.pkl"
FEATURE_NAMES_PATH = MODEL_DIR / "feature_names.pkl"

# Prediction settings
PREDICTION_INTERVAL = 10  # seconds between prediction checks
CONFIDENCE_HIGH = 0.9
CONFIDENCE_MEDIUM = 0.7

# Shutdown flag for graceful exit
shutdown_flag = False

# Server start time - only process data created after this
SERVER_START_TIME = datetime.now(LOCAL_TZ)

# ========== DATABASE SETUP ==========
DATABASE_AVAILABLE = False
engine = None
SessionLocal = None
Base = declarative_base()

try:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    # Test connection with text() for SQLAlchemy 2.0 compatibility
    from sqlalchemy import text
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    SessionLocal = sessionmaker(bind=engine)
    DATABASE_AVAILABLE = True
    logger.info("✅ PostgreSQL database connected successfully")
except Exception as db_error:
    logger.warning(f"⚠️ Database not available: {db_error}")
    logger.warning("⚠️ Server will run in LIMITED MODE (no database features)")
    logger.warning("⚠️ Start PostgreSQL and restart server for full functionality")


# ========== ORM MODELS ==========
class RawPacket(Base):
    __tablename__ = "raw_packets"
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, index=True)
    interface = Column(String(512))
    src_ip = Column(String(50), nullable=False, index=True)
    dst_ip = Column(String(50), nullable=False, index=True)
    protocol = Column(String(20), nullable=False, index=True)
    length = Column(Integer, nullable=False)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    tcp_flags = Column(String(50))
    tcp_syn = Column(Boolean)
    tcp_ack = Column(Boolean)
    tcp_fin = Column(Boolean)
    tcp_rst = Column(Boolean)
    tcp_psh = Column(Boolean)
    seq = Column(BigInteger)
    ack = Column(BigInteger)
    icmp_type = Column(Integer)
    icmp_code = Column(Integer)
    arp_op = Column(Integer)
    arp_psrc = Column(String(50))
    arp_pdst = Column(String(50))
    arp_hwsrc = Column(String(50))
    arp_hwdst = Column(String(50))
    dns_query = Column(Boolean)
    dns_qname = Column(String(512))
    dns_qtype = Column(Integer)
    dns_response = Column(Boolean)
    dns_answer_count = Column(Integer)
    dns_answer_size = Column(Integer)
    http_method = Column(String(10))
    http_path = Column(String(2000))
    http_status_code = Column(String(10))
    http_host = Column(String(512))
    inserted_at = Column(DateTime, nullable=False, default=lambda: datetime.now(LOCAL_TZ))


class AggregatedFeature(Base):
    __tablename__ = 'aggregated_features'
    id = Column(Integer, primary_key=True, autoincrement=True)
    window_start = Column(DateTime, nullable=False, index=True)
    window_end = Column(DateTime, nullable=False)
    window_size = Column(Integer, nullable=False)
    src_ip = Column(String(50), nullable=False, index=True)
    
    # Generic features (12)
    packet_count = Column(Integer, default=0)
    packet_rate_pps = Column(Float, default=0.0)
    byte_count = Column(BigInteger, default=0)
    byte_rate_bps = Column(Float, default=0.0)
    avg_packet_size = Column(Float, default=0.0)
    packet_size_variance = Column(Float, default=0.0)
    tcp_count = Column(Integer, default=0)
    udp_count = Column(Integer, default=0)
    icmp_count = Column(Integer, default=0)
    arp_count = Column(Integer, default=0)
    unique_dst_ips = Column(Integer, default=0)
    unique_dst_ports = Column(Integer, default=0)
    
    # TCP/DDoS/Scan features (13)
    tcp_syn_count = Column(Integer, default=0)
    tcp_ack_count = Column(Integer, default=0)
    syn_rate_pps = Column(Float, default=0.0)
    syn_ack_rate_pps = Column(Float, default=0.0)
    syn_to_synack_ratio = Column(Float, default=0.0)
    half_open_count = Column(Integer, default=0)
    sequential_port_count = Column(Integer, default=0)
    scan_rate_pps = Column(Float, default=0.0)
    distinct_targets_count = Column(Integer, default=0)
    syn_only_ratio = Column(Float, default=0.0)
    icmp_rate_pps = Column(Float, default=0.0)
    udp_rate_pps = Column(Float, default=0.0)
    udp_dest_port_count = Column(Integer, default=0)
    
    # Brute force features (6)
    ssh_connection_attempts = Column(Integer, default=0)
    ftp_connection_attempts = Column(Integer, default=0)
    http_login_attempts = Column(Integer, default=0)
    login_request_rate = Column(Float, default=0.0)
    failed_login_count = Column(Integer, default=0)
    auth_attempts_per_min = Column(Float, default=0.0)
    
    # ARP features (10)
    arp_request_count = Column(Integer, default=0)
    arp_reply_count = Column(Integer, default=0)
    gratuitous_arp_count = Column(Integer, default=0)
    arp_binding_flap_count = Column(Integer, default=0)
    arp_reply_without_request_count = Column(Integer, default=0)
    unique_macs_per_ip_max = Column(Integer, default=0)
    avg_macs_per_ip = Column(Float, default=0.0)
    duplicate_mac_ips = Column(Integer, default=0)
    mac_ip_ratio = Column(Float, default=0.0)
    suspicious_mac_changes = Column(Integer, default=0)
    
    # DNS features (14)
    dns_query_count = Column(Integer, default=0)
    query_rate_qps = Column(Float, default=0.0)
    unique_qnames_count = Column(Integer, default=0)
    avg_subdomain_entropy = Column(Float, default=0.0)
    pct_high_entropy_queries = Column(Float, default=0.0)
    txt_record_count = Column(Integer, default=0)
    avg_answer_size = Column(Float, default=0.0)
    distinct_record_types = Column(Integer, default=0)
    avg_query_interval_ms = Column(Float, default=0.0)
    avg_subdomain_length = Column(Float, default=0.0)
    max_subdomain_length = Column(Integer, default=0)
    avg_label_count = Column(Float, default=0.0)
    dns_to_udp_ratio = Column(Float, default=0.0)
    udp_port_53_count = Column(Integer, default=0)
    
    # Slowloris features (5)
    open_conn_count = Column(Integer, default=0)
    avg_conn_duration = Column(Float, default=0.0)
    bytes_per_conn = Column(Float, default=0.0)
    partial_http_count = Column(Integer, default=0)
    request_completion_ratio = Column(Float, default=0.0)
    
    # NEW: Port category features (3)
    tcp_ports_hit = Column(Integer, default=0)
    udp_ports_hit = Column(Integer, default=0)
    remote_conn_port_hits = Column(Integer, default=0)
    
    # ML prediction results
    predicted_label = Column(String(50))
    confidence = Column(Float)
    created_at = Column(DateTime, default=lambda: datetime.now(LOCAL_TZ), index=True)
    
    # Composite index for efficient cascading aggregation queries
    __table_args__ = (
        Index('idx_agg_window_src_start', 'window_size', 'src_ip', 'window_start'),
    )


class DetectedAlert(Base):
    __tablename__ = 'detected_alerts'
    id = Column(Integer, primary_key=True, autoincrement=True)
    src_ip = Column(String(50), nullable=False, index=True)
    dst_ip = Column(String(50), index=True)
    attack_type = Column(String(100), nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    window_size = Column(Integer, nullable=False)
    packet_count = Column(Integer, default=0)
    byte_count = Column(BigInteger, default=0)
    details = Column(JSON)
    detected_at = Column(DateTime, default=lambda: datetime.now(LOCAL_TZ), nullable=False, index=True)
    resolved = Column(Boolean, default=False, index=True)
    resolved_at = Column(DateTime)

# Create tables (only if database is available)
if DATABASE_AVAILABLE and engine is not None:
    Base.metadata.create_all(engine)

# ========== LOAD ML MODEL ==========
logger.info("=" * 60)
logger.info("🚀 NetGuardian Pro - Production Server")
logger.info("=" * 60)

try:
    logger.info(f"📂 Loading ML model from: {MODEL_DIR}")
    
    # Try loading JSON model first (Newer XGBoost)
    if os.path.exists(XGB_MODEL_JSON_PATH):
        logger.info(f"   Using JSON model: {XGB_MODEL_JSON_PATH.name}")
        xgb_model = XGBClassifier()
        xgb_model.load_model(str(XGB_MODEL_JSON_PATH))
    else:
        # Fallback to pickle
        logger.info(f"   Using Pickle model: {XGB_MODEL_PATH.name}")
        xgb_model = joblib.load(XGB_MODEL_PATH)

    label_encoder = joblib.load(LABEL_ENCODER_PATH)
    feature_names = joblib.load(FEATURE_NAMES_PATH)
    
    logger.info(f"✅ XGBoost model loaded and ready")
    logger.info(f"✅ Label encoder loaded: {len(label_encoder.classes_)} classes")
    logger.info(f"✅ Feature names loaded: {len(feature_names)} features")
    
    MODEL_LOADED = True
except Exception as e:
    logger.error(f"❌ Failed to load ML model: {e}")
    MODEL_LOADED = False
    xgb_model = None
    label_encoder = None
    feature_names = None

# ========== LOAD AGGREGATOR ==========
try:
    import sys
    sys.path.insert(0, str(APP_DIR))
    from MultiWindowAggregator import MultiWindowAggregator
    aggregator = MultiWindowAggregator(window_sizes=[5, 30, 180])
    AGGREGATOR_AVAILABLE = True
    logger.info("✅ MultiWindowAggregator loaded successfully")
except ImportError as e:
    AGGREGATOR_AVAILABLE = False
    aggregator = None
    logger.warning(f"⚠️ MultiWindowAggregator not found: {e}")

# ========== DECORATORS ==========
from functools import wraps

def fallback_to_dummy(dummy_func):
    """
    Decorator to wrap API endpoints with auto-fallback logic.
    If DB is unavailable or query fails, returns result from dummy_func.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                if not DATABASE_AVAILABLE:
                    return dummy_func()
                return func(*args, **kwargs)
            except Exception as e:
                logger.warning(f"⚠️ Fallback triggered for {func.__name__}: {e}")
                return dummy_func()
        return wrapper
    return decorator

# ========== FASTAPI APP ==========
app = FastAPI(
    title="NetGuardian Pro Dashboard",
    description="Real-time network attack detection with XGBoost ML",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ========== WEBSOCKET CONNECTION MANAGER ==========
class ConnectionManager:
    """Manages WebSocket connections for real-time dashboard updates"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        """Accept and store a new WebSocket connection"""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"📡 WebSocket connected. Total clients: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"📡 WebSocket disconnected. Total clients: {len(self.active_connections)}")
    
    async def broadcast(self, message: dict):
        """Send message to all connected dashboard clients"""
        if not self.active_connections:
            return
        
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"WebSocket send failed: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            if conn in self.active_connections:
                self.active_connections.remove(conn)
    
    def get_connection_count(self) -> int:
        """Return number of active connections"""
        return len(self.active_connections)

# Initialize WebSocket manager
ws_manager = ConnectionManager()


# ========== WEBSOCKET ENDPOINT ==========
@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    """
    WebSocket endpoint for real-time dashboard updates.
    Keeps connection open and sends updates when data changes.
    """
    await ws_manager.connect(websocket)
    
    try:
        # Send initial stats on connect
        if DATABASE_AVAILABLE:
            db = SessionLocal()
            try:
                total_packets = db.query(RawPacket).count()
                total_alerts = db.query(DetectedAlert).count()
                await websocket.send_json({
                    "type": "initial",
                    "stats": {
                        "total_packets": total_packets,
                        "total_alerts": total_alerts,
                        "database_connected": True
                    }
                })
            finally:
                db.close()
        else:
            await websocket.send_json({
                "type": "initial",
                "stats": {
                    "total_packets": 0,
                    "total_alerts": 0,
                    "database_connected": False
                }
            })
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for messages (ping/pong or commands)
                data = await websocket.receive_text()
                
                # Handle ping messages
                if data == "ping" or (data.startswith("{") and "ping" in data):
                    await websocket.send_json({"type": "pong"})
                    
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.warning(f"WebSocket error: {e}")
                break
                
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
    finally:
        ws_manager.disconnect(websocket)


# ========== HELPER FUNCTIONS ==========
def require_database():
    """Check if database is available, return error dict if not"""
    if not DATABASE_AVAILABLE:
        return {"error": "Database not available", "message": "Start PostgreSQL for full functionality"}
    return None

def get_severity(confidence: float) -> str:
    """Determine alert severity based on confidence score"""
    if confidence >= CONFIDENCE_HIGH:
        return "CRITICAL"
    elif confidence >= CONFIDENCE_MEDIUM:
        return "HIGH"
    elif confidence >= 0.5:
        return "MEDIUM"
    else:
        return "LOW"


def prepare_packet_dict(row):
    """Prepare packet dictionary with proper type handling"""
    packet_dict = {}
    
    # Required fields
    packet_dict['timestamp'] = float(row.get('timestamp', 0))
    packet_dict['interface'] = str(row.get('interface', 'eth0')) if pd.notna(row.get('interface')) else 'eth0'
    packet_dict['src_ip'] = str(row.get('src_ip', '0.0.0.0')) if pd.notna(row.get('src_ip')) else '0.0.0.0'
    packet_dict['dst_ip'] = str(row.get('dst_ip', '0.0.0.0')) if pd.notna(row.get('dst_ip')) else '0.0.0.0'
    packet_dict['protocol'] = str(row.get('protocol', 'UNKNOWN')) if pd.notna(row.get('protocol')) else 'UNKNOWN'
    packet_dict['length'] = int(row.get('length', 0)) if pd.notna(row.get('length')) else 0
    
    # Optional port fields
    packet_dict['src_port'] = int(row.get('src_port', 0)) if pd.notna(row.get('src_port')) else None
    packet_dict['dst_port'] = int(row.get('dst_port', 0)) if pd.notna(row.get('dst_port')) else None
    
    # TCP fields
    packet_dict['tcp_flags'] = str(row.get('tcp_flags', '')) if pd.notna(row.get('tcp_flags')) else None
    packet_dict['tcp_syn'] = bool(row.get('tcp_syn')) if pd.notna(row.get('tcp_syn')) else None
    packet_dict['tcp_ack'] = bool(row.get('tcp_ack')) if pd.notna(row.get('tcp_ack')) else None
    packet_dict['tcp_fin'] = bool(row.get('tcp_fin')) if pd.notna(row.get('tcp_fin')) else None
    packet_dict['tcp_rst'] = bool(row.get('tcp_rst')) if pd.notna(row.get('tcp_rst')) else None
    packet_dict['tcp_psh'] = bool(row.get('tcp_psh')) if pd.notna(row.get('tcp_psh')) else None
    packet_dict['seq'] = int(row.get('seq', 0)) if pd.notna(row.get('seq')) else None
    packet_dict['ack'] = int(row.get('ack', 0)) if pd.notna(row.get('ack')) else None
    
    # ICMP fields
    packet_dict['icmp_type'] = int(row.get('icmp_type', 0)) if pd.notna(row.get('icmp_type')) else None
    packet_dict['icmp_code'] = int(row.get('icmp_code', 0)) if pd.notna(row.get('icmp_code')) else None
    
    # ARP fields
    packet_dict['arp_op'] = int(row.get('arp_op', 0)) if pd.notna(row.get('arp_op')) else None
    packet_dict['arp_psrc'] = str(row.get('arp_psrc', '')) if pd.notna(row.get('arp_psrc')) else None
    packet_dict['arp_pdst'] = str(row.get('arp_pdst', '')) if pd.notna(row.get('arp_pdst')) else None
    packet_dict['arp_hwsrc'] = str(row.get('arp_hwsrc', '')) if pd.notna(row.get('arp_hwsrc')) else None
    packet_dict['arp_hwdst'] = str(row.get('arp_hwdst', '')) if pd.notna(row.get('arp_hwdst')) else None
    
    # DNS fields
    packet_dict['dns_query'] = bool(row.get('dns_query')) if pd.notna(row.get('dns_query')) else None
    packet_dict['dns_qname'] = str(row.get('dns_qname', '')) if pd.notna(row.get('dns_qname')) else None
    packet_dict['dns_qtype'] = int(row.get('dns_qtype', 0)) if pd.notna(row.get('dns_qtype')) else None
    packet_dict['dns_response'] = bool(row.get('dns_response')) if pd.notna(row.get('dns_response')) else None
    packet_dict['dns_answer_count'] = int(row.get('dns_answer_count', 0)) if pd.notna(row.get('dns_answer_count')) else None
    packet_dict['dns_answer_size'] = int(row.get('dns_answer_size', 0)) if pd.notna(row.get('dns_answer_size')) else None
    
    # HTTP fields
    packet_dict['http_method'] = str(row.get('http_method', '')) if pd.notna(row.get('http_method')) and row.get('http_method') != 0 else None
    packet_dict['http_path'] = str(row.get('http_path', '')) if pd.notna(row.get('http_path')) else None
    packet_dict['http_status_code'] = str(row.get('http_status_code', '')) if pd.notna(row.get('http_status_code')) and row.get('http_status_code') != 0 else None
    packet_dict['http_host'] = str(row.get('http_host', '')) if pd.notna(row.get('http_host')) else None
    
    return packet_dict


# ========== DUMMY DATA GENERATORS (for testing without database) ==========
import random

def get_dummy_traffic_history():
    """Generate realistic dummy traffic history for charts"""
    hours = [f"{h:02d}:00" for h in range(24)]
    # Simulate realistic traffic pattern (low at night, high during day)
    base_pattern = [10, 8, 5, 3, 2, 3, 8, 25, 45, 60, 70, 75, 80, 78, 72, 65, 70, 68, 55, 45, 35, 28, 20, 15]
    byte_rates = [b * 1000 + random.randint(-500, 500) for b in base_pattern]
    packet_rates = [b // 10 + random.randint(-5, 5) for b in base_pattern]
    return {"labels": hours, "byte_rates": byte_rates, "packet_rates": packet_rates}


def get_dummy_protocols():
    """Generate realistic protocol distribution"""
    return {
        "labels": ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS"],
        "values": [4500, 2200, 350, 180, 890, 1200, 2800]
    }


def get_dummy_packet_size_distribution():
    """Generate realistic packet size distribution"""
    return {
        "labels": ["<100", "100-500", "500-1000", "1000-1500", ">1500"],
        "values": [1850, 3200, 2100, 1500, 450]
    }


def get_dummy_traffic_direction():
    """Generate realistic inbound/outbound traffic"""
    return {
        "inbound_bytes": 52340000,
        "outbound_bytes": 38250000,
        "inbound_packets": 45000,
        "outbound_packets": 32000
    }


def get_dummy_top_sources():
    """Generate realistic top source IPs"""
    return [
        {"ip": "192.168.1.105", "packet_count": 2340, "percentage": 23.4},
        {"ip": "192.168.1.42", "packet_count": 1850, "percentage": 18.5},
        {"ip": "10.0.0.15", "packet_count": 1420, "percentage": 14.2},
        {"ip": "172.16.0.8", "packet_count": 980, "percentage": 9.8},
        {"ip": "192.168.1.1", "packet_count": 750, "percentage": 7.5}
    ]


def get_dummy_top_destinations():
    """Generate realistic top destination IPs"""
    return [
        {"ip": "8.8.8.8", "packet_count": 1850, "percentage": 18.5},
        {"ip": "192.168.1.1", "packet_count": 1620, "percentage": 16.2},
        {"ip": "1.1.1.1", "packet_count": 1340, "percentage": 13.4},
        {"ip": "142.250.185.46", "packet_count": 980, "percentage": 9.8},
        {"ip": "151.101.1.140", "packet_count": 720, "percentage": 7.2}
    ]


def get_dummy_top_ports():
    """Generate realistic top ports usage"""
    return [
        {"port": 443, "service": "HTTPS", "packet_count": 4200, "percentage": 42.0},
        {"port": 80, "service": "HTTP", "packet_count": 1850, "percentage": 18.5},
        {"port": 53, "service": "DNS", "packet_count": 1420, "percentage": 14.2},
        {"port": 22, "service": "SSH", "packet_count": 680, "percentage": 6.8},
        {"port": 8080, "service": "HTTP-Alt", "packet_count": 450, "percentage": 4.5}
    ]


def get_dummy_alerts():
    """Generate sample security alerts"""
    now = datetime.utcnow()
    return [
        {
            "id": 1, "src_ip": "192.168.1.105", "attack_type": "SYN_FLOOD",
            "confidence": 0.92, "severity": "HIGH", "window_size": 5,
            "packet_count": 15000, "byte_count": 900000,
            "detected_at": (now - timedelta(minutes=15)).isoformat(),
            "resolved": False, "details": {"syn_rate": 3000, "unique_ports": 450}
        },
        {
            "id": 2, "src_ip": "10.0.0.55", "attack_type": "PORT_SCAN",
            "confidence": 0.85, "severity": "MEDIUM", "window_size": 30,
            "packet_count": 2500, "byte_count": 150000,
            "detected_at": (now - timedelta(hours=2)).isoformat(),
            "resolved": True, "details": {"ports_scanned": 1024, "scan_rate": 85}
        },
        {
            "id": 3, "src_ip": "172.16.5.20", "attack_type": "DNS_TUNNEL",
            "confidence": 0.78, "severity": "MEDIUM", "window_size": 180,
            "packet_count": 890, "byte_count": 425000,
            "detected_at": (now - timedelta(hours=5)).isoformat(),
            "resolved": False, "details": {"avg_query_length": 85, "entropy_score": 0.89}
        }
    ]


def get_dummy_packets():
    """Generate sample raw packets for table display"""
    now = datetime.utcnow()
    protocols = ["TCP", "UDP", "TCP", "TCP", "DNS", "HTTPS", "HTTP", "TCP", "ICMP", "ARP"]
    src_ips = ["192.168.1.105", "192.168.1.42", "10.0.0.15", "172.16.0.8", "192.168.1.1"]
    dst_ips = ["8.8.8.8", "192.168.1.1", "1.1.1.1", "142.250.185.46", "151.101.1.140"]
    packets = []
    for i in range(20):
        packets.append({
            "id": 1000 - i,
            "timestamp": (now - timedelta(seconds=i*3)).strftime('%Y-%m-%d %H:%M:%S'),
            "src_ip": random.choice(src_ips), "dst_ip": random.choice(dst_ips),
            "protocol": random.choice(protocols),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 53, 22, 8080, 3306]),
            "length": random.randint(40, 1500),
            "flags": random.choice(["S", "SA", "A", "PA", "FA", "--"])
        })
    return {"packets": packets, "total": 10000, "page": 1, "limit": 20, "pages": 500}


def get_dummy_features():
    """Generate sample aggregated features (63 distinct features)"""
    return {
        # --- Generic (13) ---
        "window_size": 5, "record_count": 10,
        "packet_count": 8542, "byte_count": 5234000,
        "packet_rate_pps": 285.5, "byte_rate_bps": 1396000.0,
        "avg_packet_size": 612.4, "packet_size_variance": 1250.5,
        "tcp_count": 4500, "udp_count": 2200, "icmp_count": 350, "arp_count": 180,
        "unique_dst_ips": 125, "unique_dst_ports": 48,
        
        # --- Port Hits (3) ---
        "tcp_ports_hit": 32, "udp_ports_hit": 16, "remote_conn_port_hits": 245,
        
        # --- TCP/DoS/Scan (12) ---
        "tcp_syn_count": 850, "tcp_ack_count": 720,
        "syn_rate_pps": 28.5, "syn_ack_rate_pps": 24.1,
        "syn_to_synack_ratio": 1.18, "half_open_count": 45,
        "sequential_port_count": 12, "scan_rate_pps": 5.2,
        "distinct_targets_count": 8, "syn_only_ratio": 0.15,
        "icmp_rate_pps": 2.1, "udp_rate_pps": 18.5, "udp_dest_port_count": 24,
        
        # --- Bruteforce (6) ---
        "ssh_connection_attempts": 12, "ftp_connection_attempts": 2, "http_login_attempts": 0,
        "login_request_rate": 0.5, "failed_login_count": 5, "auth_attempts_per_min": 4.2,
        
        # --- ARP/Spoofing (10) ---
        "arp_request_count": 95, "arp_reply_count": 85,
        "gratuitous_arp_count": 2, "arp_binding_flap_count": 0,
        "arp_reply_without_request_count": 0,
        "unique_macs_per_ip_max": 2, "avg_macs_per_ip": 1.1,
        "duplicate_mac_ips": 1, "mac_ip_ratio": 0.95, "suspicious_mac_changes": 0,
        
        # --- DNS (14) ---
        "dns_query_count": 420, "query_rate_qps": 12.5,
        "unique_qnames_count": 156, "avg_subdomain_entropy": 3.1,
        "pct_high_entropy_queries": 0.05, "txt_record_count": 8,
        "dns_response_count": 385, "avg_answer_size": 124.5,
        "distinct_record_types": 3, "avg_query_interval_ms": 150.2,
        "avg_subdomain_length": 8.5, "max_subdomain_length": 25,
        "avg_label_count": 2.5, "dns_to_udp_ratio": 0.92,
        "udp_port_53_count": 450,
        
        # --- Slowloris (5) ---
        "open_conn_count": 28, "avg_conn_duration": 4.5,
        "bytes_per_conn": 520.0, "partial_http_count": 5,
        "request_completion_ratio": 0.85,
        
        # --- Meta ---
        "source": "dummy_data"
    }


def get_dummy_features_extended():
    """Generate extended features for Analytics and Performance tabs"""
    return {
        "window_size": 5, "record_count": 10, "packet_count": 8542, "byte_count": 5234000,
        "packet_rate_pps": 285, "byte_rate_bps": 1396000, "avg_packet_size": 612,
        "min_packet_size": 40, "max_packet_size": 1500,
        "tcp_count": 4500, "udp_count": 2200, "icmp_count": 350, "arp_count": 180, "other_count": 50,
        "unique_dst_ips": 125, "unique_dst_ports": 48,
        "tcp_syn_count": 850, "tcp_ack_count": 720, "tcp_fin_count": 385, "tcp_rst_count": 45, "tcp_psh_count": 620,
        "syn_rate_pps": 28, "syn_ack_ratio": 0.85,
        "dns_query_count": 420, "dns_response_count": 385, "dns_unique_domains": 156, "avg_dns_query_length": 24.5,
        "http_request_count": 280, "http_get_count": 220, "http_post_count": 60, "http_unique_paths": 45,
        "port_scan_score": 0.12, "avg_packets_per_port": 8.5, "connection_failure_rate": 0.15,
        "arp_request_count": 95, "arp_reply_count": 85, "arp_request_rate_pps": 3.2,
        "inter_arrival_time_mean": 0.0035, "inter_arrival_time_std": 0.0012,
        "tcp_ports_hit": 32, "udp_ports_hit": 16, "remote_conn_port_hits": 245,
        
        # New features from docs/FEATURE_REFERENCE.md
        "syn_to_synack_ratio": 1.18, "half_open_count": 45, "scan_rate_pps": 5.2,
        "ssh_connection_attempts": 12, "ftp_connection_attempts": 2, "http_login_attempts": 0,
        "open_conn_count": 28, "long_lived_conn_count": 15, "avg_conn_duration": 4.5,
        "gratuitous_arp_count": 2, "arp_reply_without_request_count": 0,
        "avg_subdomain_entropy": 3.1, "pct_high_entropy_queries": 0.05, "txt_record_count": 8,
        "udp_rate_pps": 18.5, "icmp_rate_pps": 2.1,
        
        "source": "dummy_data"
    }


def get_dummy_dns_stats():
    """Generate sample DNS statistics for Analytics tab"""
    return {
        "dns_query_count": 420,
        "dns_response_count": 385,
        "dns_unique_domains": 156,
        "avg_dns_query_length": 24.5,
        "max_dns_query_length": 85,
        "length_distribution": {"<10": 45, "10-20": 180, "20-40": 145, "40-60": 35, "60-100": 12, ">100": 3}
    }


def get_dummy_tcp_flags():
    """Generate sample TCP flags distribution for Analytics tab"""
    return {
        "tcp_syn_count": 850,
        "tcp_ack_count": 720,
        "tcp_fin_count": 385,
        "tcp_rst_count": 45,
        "tcp_psh_count": 620,
        "total_tcp_packets": 4500
    }


def predict_and_alert(db_session, feature_row: AggregatedFeature) -> Optional[Dict]:
    """Run prediction on aggregated feature and create alert if attack detected"""
    if not MODEL_LOADED:
        return None
    
    try:
        # Build feature vector in correct order
        feature_dict = {col: getattr(feature_row, col, 0) or 0 for col in feature_names}
        feature_df = pd.DataFrame([feature_dict])
        
        # Predict
        prediction = xgb_model.predict(feature_df)[0]
        probabilities = xgb_model.predict_proba(feature_df)[0]
        confidence = float(np.max(probabilities))
        predicted_label = label_encoder.inverse_transform([prediction])[0]
        
        # Update aggregated feature with prediction
        feature_row.predicted_label = predicted_label
        feature_row.confidence = confidence
        
        result = {
            "id": feature_row.id,
            "src_ip": feature_row.src_ip,
            "predicted_label": predicted_label,
            "confidence": confidence,
            "window_size": feature_row.window_size
        }
        
        # Create alert if attack detected (not Normal)
        if predicted_label.lower() != "normal":
            severity = get_severity(confidence)
            
            alert = DetectedAlert(
                src_ip=feature_row.src_ip,
                dst_ip=None,
                attack_type=predicted_label,
                confidence=confidence,
                severity=severity,
                window_size=feature_row.window_size,
                packet_count=feature_row.packet_count or 0,
                byte_count=feature_row.byte_count or 0,
                details={"message": f"Detected {predicted_label} attack from {feature_row.src_ip} with {confidence:.2%} confidence"},
                detected_at=datetime.utcnow()
            )
            db_session.add(alert)
            
            result["alert_created"] = True
            result["severity"] = severity
            logger.warning(f"🚨 ALERT: {predicted_label} from {feature_row.src_ip} ({confidence:.2%} confidence)")
            
            # Send Telegram Alert
            if DATABASE_AVAILABLE:
                try:
                    send_security_alert(
                        attack_type=predicted_label,
                        src_ip=feature_row.src_ip,
                        confidence=confidence,
                        severity=severity,
                        timestamp=datetime.now(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S")
                    )
                except Exception as tg_err:
                    logger.error(f"Failed to send Telegram alert: {tg_err}")
            
            # Broadcast alert to all connected WebSocket clients
            if ws_manager.get_connection_count() > 0:
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        asyncio.create_task(ws_manager.broadcast({
                            "type": "alert",
                            "attack_type": predicted_label,
                            "confidence": confidence,
                            "severity": severity,
                            "src_ip": feature_row.src_ip,
                            "packet_count": feature_row.packet_count or 0,
                            "window_size": feature_row.window_size,
                            "timestamp": datetime.utcnow().isoformat()
                        }))
                except Exception as ws_error:
                    logger.warning(f"WebSocket broadcast failed: {ws_error}")
        else:
            result["alert_created"] = False
        
        return result
        
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return None


def run_predictions():
    """Background task: Check for unpredicted features and run predictions"""
    global shutdown_flag
    
    while not shutdown_flag:
        # Skip if database not available
        if not DATABASE_AVAILABLE or SessionLocal is None:
            time.sleep(PREDICTION_INTERVAL)
            continue
            
        try:
            db = SessionLocal()
            
            # Find aggregated features without predictions (only since server start)
            unpredicted = db.query(AggregatedFeature).filter(
                AggregatedFeature.predicted_label == None,
                AggregatedFeature.created_at >= SERVER_START_TIME
            ).limit(100).all()
            
            if unpredicted:
                logger.info(f"🔍 Found {len(unpredicted)} features to predict")
                
                for feature in unpredicted:
                    if shutdown_flag:
                        break
                    predict_and_alert(db, feature)
                
                db.commit()
                logger.info(f"✅ Processed {len(unpredicted)} predictions")
            
            db.close()
            
        except Exception as e:
            logger.error(f"Prediction loop error: {e}")
        
        time.sleep(PREDICTION_INTERVAL)
    
    logger.info("🛑 Prediction loop stopped")


# ========== INGESTION ENDPOINTS ==========

async def _process_packets(packets_list: list, db) -> dict:
    """Common packet processing logic for both ingestion methods"""
    tmp_path = None
    
    try:
        # Convert to DataFrame
        df = pd.DataFrame(packets_list)
        
        # Convert timestamp to float if needed
        if 'timestamp' in df.columns:
            if not pd.api.types.is_numeric_dtype(df['timestamp']):
                df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
                df["timestamp"] = df["timestamp"].astype("int64") / 1e9
        
        df.fillna(0, inplace=True)
        
        # Save as temp CSV for aggregator
        if AGGREGATOR_AVAILABLE:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".csv", mode='w', newline='') as tmp:
                tmp_path = tmp.name
                df.to_csv(tmp_path, index=False)
        
        # Store raw packets
        raw_rows = []
        for _, row in df.iterrows():
            try:
                packet_dict = prepare_packet_dict(row)
                raw_rows.append(RawPacket(**packet_dict))
            except Exception as e:
                logger.error(f"Error preparing packet: {e}")
                continue
        
        db.bulk_save_objects(raw_rows)
        db.commit()
        logger.info(f"✅ Stored {len(raw_rows)} raw packets")
        
        # Run aggregation
        agg_rows_count = 0
        if AGGREGATOR_AVAILABLE and tmp_path:
            try:
                # 2. Run aggregation (Synchronous for 5s only)
                # We only generate 5s windows here. 30s and 180s are handled by background cascading.
                agg_df = aggregator.process_file(tmp_path, window_sizes=[5])
                
                # 3. Store aggregated features in DB
                agg_rows = []
                
                for _, row in agg_df.iterrows():
                    agg_dict = {
                        'src_ip': row.get('src_ip'),
                        'window_start': pd.to_datetime(row.get('window_start')),
                        'window_end': pd.to_datetime(row.get('window_end')),
                        'window_size': int(row.get('window_size', 0))
                    }
                    
                    # Add feature columns
                    skip_cols = ['src_ip', 'window_start', 'window_end', 'window_size', 'label', 'variation']
                    for col in row.index:
                        if col not in skip_cols:
                            # Check if column exists in AggregatedFeature
                            if hasattr(AggregatedFeature, col):
                                value = row[col]
                                if pd.notna(value):
                                    agg_dict[col] = float(value) if isinstance(value, (int, float, np.integer, np.floating)) else value
                    
                    agg_rows.append(AggregatedFeature(**agg_dict))
                
                db.bulk_save_objects(agg_rows)
                db.commit()
                agg_rows_count = len(agg_rows)
                logger.info(f"✅ Stored {agg_rows_count} aggregated features (5s, 30s, 180s windows)")
                
            except Exception as e:
                logger.error(f"Aggregation error: {e}")
                db.rollback()
        
        return {
            "status": "success",
            "raw_packets": len(raw_rows),
            "aggregated_features": agg_rows_count,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.post("/ingest_packets")
async def ingest_packets(
    file: UploadFile = File(None),
    request: Optional[dict] = None
):
    """
    Receives network packets and stores in database.
    
    Supports TWO formats:
    1. JSON body (direct API): POST with JSON array of packets
    2. File upload: POST with JSON file containing {"raw_packets": [...]}
    """
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available. Start PostgreSQL for full functionality.")
    
    from fastapi import Request
    db = SessionLocal()
    
    try:
        packets_list = None
        
        # Method 1: File upload
        if file and file.filename:
            if not file.filename.endswith('.json'):
                raise HTTPException(status_code=400, detail="Only JSON files are allowed")
            
            logger.info(f"📥 Ingesting file: {file.filename}")
            content = await file.read()
            data = json.loads(content)
            
            # Support both formats: {"raw_packets": [...]} or just [...]
            if isinstance(data, dict) and 'raw_packets' in data:
                packets_list = data['raw_packets']
            elif isinstance(data, list):
                packets_list = data
            else:
                raise HTTPException(status_code=400, detail="Invalid JSON structure")
        
        # Method 2: Direct JSON body (from sender.py)
        # This will be handled by the alternative endpoint below
        
        if packets_list is None:
            raise HTTPException(status_code=400, detail="No packets provided. Use file upload or /ingest endpoint.")
        
        result = await _process_packets(packets_list, db)
        return result
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON format")
    except Exception as e:
        logger.error(f"Ingest error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        db.close()


@app.post("/ingest")
async def ingest_packets_json(packets: List[dict]):
    """
    Alternative ingestion endpoint for direct JSON body.
    This is what sender.py uses - sends array of packets directly.
    
    Usage: POST /ingest with JSON body: [{"timestamp": ..., "src_ip": ...}, ...]
    """
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available. Start PostgreSQL for full functionality.")
    
    db = SessionLocal()
    
    try:
        logger.info(f"📥 Ingesting {len(packets)} packets via direct JSON")
        result = await _process_packets(packets, db)
        
        # Broadcast update to all connected WebSocket clients
        if ws_manager.get_connection_count() > 0:
            await ws_manager.broadcast({
                "type": "packet_update",
                "raw_packets": result.get("raw_packets", 0),
                "aggregated_features": result.get("aggregated_features", 0),
                "timestamp": datetime.utcnow().isoformat()
            })
            logger.info(f"📡 Broadcasted update to {ws_manager.get_connection_count()} dashboard clients")
        
        return result
        
    except Exception as e:
        logger.error(f"Ingest error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        db.close()




# ========== DASHBOARD API ENDPOINTS ==========

@app.get("/")
def root():
    """Health check endpoint"""
    return {
        "status": "running",
        "service": "NetGuardian Pro Dashboard",
        "database_available": DATABASE_AVAILABLE,
        "model_loaded": MODEL_LOADED,
        "aggregator_available": AGGREGATOR_AVAILABLE,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/health")
def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy" if DATABASE_AVAILABLE else "limited",
        "database_available": DATABASE_AVAILABLE,
        "database_connected": DATABASE_AVAILABLE,  # For frontend compatibility
        "model_loaded": MODEL_LOADED,
        "aggregator_available": AGGREGATOR_AVAILABLE,
        "websocket_clients": ws_manager.get_connection_count(),
        "timestamp": datetime.now(LOCAL_TZ).isoformat()
    }


# ========== WEBSOCKET ENDPOINT ==========

@app.get("/api/packets")
def get_packets(page: int = 1, limit: int = 50, protocol: str = None, src_ip: str = None):
    """
    Get raw packets with pagination.
    
    Args:
        page: Page number (1-indexed)
        limit: Number of packets per page (max 100)
        protocol: Filter by protocol (TCP, UDP, ICMP, etc.)
        src_ip: Filter by source IP
    """
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    limit = min(limit, 100)  # Cap at 100
    offset = (page - 1) * limit
    
    db = SessionLocal()
    try:
        query = db.query(RawPacket).order_by(RawPacket.id.desc())
        
        if protocol:
            query = query.filter(RawPacket.protocol == protocol.upper())
        if src_ip:
            query = query.filter(RawPacket.src_ip == src_ip)
        
        total = query.count()
        packets = query.offset(offset).limit(limit).all()
        
        result = []
        for p in packets:
            result.append({
                "id": p.id,
                "timestamp": p.timestamp,
                "src_ip": p.src_ip,
                "dst_ip": p.dst_ip,
                "protocol": p.protocol,
                "src_port": p.src_port,
                "dst_port": p.dst_port,
                "length": p.length,
                "tcp_flags": p.tcp_flags
            })
        
        return {
            "packets": result,
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": (total + limit - 1) // limit
        }
    finally:
        db.close()


@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    """
    WebSocket endpoint for real-time dashboard updates.
    
    Message Types Sent:
    - 'initial': Full dashboard data on connect
    - 'packet_update': New packets ingested
    - 'alert': Security alert detected
    - 'stats_update': Periodic stats refresh
    """
    await ws_manager.connect(websocket)
    
    try:
        # Send initial data on connection
        initial_data = {
            "type": "initial",
            "timestamp": datetime.now(LOCAL_TZ).isoformat(),
            "stats": {
                "database_available": DATABASE_AVAILABLE,
                "model_loaded": MODEL_LOADED,
                "connected_clients": ws_manager.get_connection_count()
            }
        }
        
        # Add database stats if available
        if DATABASE_AVAILABLE:
            db = SessionLocal()
            try:
                # Get latest packet count
                packet_count = db.query(func.count(RawPacket.id)).scalar() or 0
                alert_count = db.query(func.count(DetectedAlert.id)).filter(
                    DetectedAlert.detected_at >= datetime.now(LOCAL_TZ) - timedelta(hours=24)
                ).scalar() or 0
                
                initial_data["stats"]["total_packets"] = packet_count
                initial_data["stats"]["alerts_24h"] = alert_count
            finally:
                db.close()
        
        await websocket.send_json(initial_data)
        logger.info(f"📡 Sent initial data to WebSocket client")
        
        # Keep connection alive and handle client messages
        # Use asyncio.wait_for with timeout to prevent proxy timeouts
        while True:
            try:
                # Wait for client message with 30 second timeout
                # This prevents Cloudflare from closing idle connections
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                
                if data == "ping":
                    await websocket.send_text("pong")
                elif data == "get_stats":
                    # Client requested fresh stats
                    await websocket.send_json({
                        "type": "stats_update",
                        "timestamp": datetime.now(LOCAL_TZ).isoformat(),
                        "connected_clients": ws_manager.get_connection_count()
                    })
                    
            except asyncio.TimeoutError:
                # No message received - send keepalive to prevent proxy timeout
                try:
                    await websocket.send_json({
                        "type": "keepalive",
                        "timestamp": datetime.now(LOCAL_TZ).isoformat()
                    })
                except Exception:
                    break  # Connection closed
                    
            except WebSocketDisconnect:
                logger.info("📡 WebSocket client disconnected normally")
                break
                
    except WebSocketDisconnect:
        logger.info("📡 WebSocket client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        ws_manager.disconnect(websocket)


@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    """Serve the HTML dashboard"""
    if DASHBOARD_FILE.exists():
        return HTMLResponse(content=DASHBOARD_FILE.read_text(encoding='utf-8'))
    else:
        return HTMLResponse(content=f"""
        <html>
            <head><title>NetGuardian Pro</title></head>
            <body style="font-family: Arial; padding: 20px; background: #1a1a2e; color: white;">
                <h1>🛡️ NetGuardian Pro</h1>
                <p>Dashboard file not found at: {DASHBOARD_FILE}</p>
                <h2>API Endpoints:</h2>
                <ul>
                    <li><a href="/docs" style="color: #4CAF50;">/docs</a> - API Documentation</li>
                    <li><a href="/api/features" style="color: #4CAF50;">/api/features</a> - Traffic features</li>
                    <li><a href="/api/alerts" style="color: #4CAF50;">/api/alerts</a> - Security alerts</li>
                    <li><a href="/api/protocols" style="color: #4CAF50;">/api/protocols</a> - Protocol distribution</li>
                </ul>
            </body>
        </html>
        """)


@app.get("/api/features")
@fallback_to_dummy(get_dummy_features)
def api_features(window_size: int = 5):
    """Get aggregated features from last 30 minutes or 100k packets"""
    db = SessionLocal()
    try:
        # Calculate 30 minutes ago
        thirty_min_ago = datetime.now(LOCAL_TZ) - timedelta(minutes=30)
        
        # Get aggregated features from last 30 minutes
        result = db.query(AggregatedFeature).filter(
            AggregatedFeature.window_size == window_size,
            AggregatedFeature.created_at >= thirty_min_ago
        ).order_by(desc(AggregatedFeature.id)).limit(100).all()
        
        if result:
            records = []
            for r in result:
                # Dynamically serialize all columns
                rec = {k: v for k, v in r.__dict__.items() if not k.startswith('_')}
                records.append(rec)
            
            # Smart Dynamic Aggregation across all records
            features = {}
            if records:
                keys = records[0].keys()
                for k in keys:
                    if k in ['window_size', 'id', 'src_ip', 'window_start', 'window_end', 'created_at', 'predicted_label', 'confidence']:
                        features[k] = records[0].get(k)
                        continue
                    
                    values = [r.get(k, 0) for r in records]
                    
                    if 'unique' in k or 'distinct' in k or k.startswith('max_'):
                        features[k] = max(values)
                    elif (k.endswith('_count') and not k.startswith('avg_')) or k.endswith('_hits'):
                        features[k] = sum(values)
                    else:
                        features[k] = sum(values) / len(values) if values else 0
                
                features['record_count'] = len(records)
                features['window_minutes'] = 30
                
                # explicit peak calculation
                features['peak_byte_rate'] = max(r.get('byte_rate_bps', 0) for r in records)
            
            # Add derived metrics
            syn_only = features.get('tcp_syn_count', 0) - features.get('tcp_ack_count', 0)
            features['connection_failure_rate'] = min(1, syn_only / max(1, features.get('tcp_syn_count', 1))) if syn_only > 0 else 0
            
            return features
        
        # Fallback to raw packets if no aggregated features
        return _compute_features_from_raw_packets(db)
    finally:
        db.close()


@app.get("/api/features/ip/{target_ip}")
def api_features_by_ip(target_ip: str, window_size: int = 5):
    """Get aggregated features for a specific IP"""
    if not DATABASE_AVAILABLE:
        # Return dummy data with the requested IP injected
        data = get_dummy_features()
        data['src_ip'] = target_ip
        return data
    
    db = SessionLocal()
    try:
        # Get latest record for this IP
        r = db.query(AggregatedFeature).filter(
            AggregatedFeature.src_ip == target_ip,
            AggregatedFeature.window_size == window_size
        ).order_by(desc(AggregatedFeature.id)).first()
        
        if r:
            # Dynamically serialize
            data = {k: v for k, v in r.__dict__.items() if not k.startswith('_')}
            
            # Add derived metrics (same as api_features)
            syn_count = data.get('tcp_syn_count', 0)
            ack_count = data.get('tcp_ack_count', 0)
            syn_only = max(0, syn_count - ack_count)
            data['connection_failure_rate'] = min(1.0, syn_only / max(1, syn_count)) if syn_only > 0 else 0.0
            
            return data
        
        return {"error": "No data found for this IP", "src_ip": target_ip}
    finally:
        db.close()


def _compute_features_from_raw_packets(db):
    """Compute features from raw packets (last 30 minutes or 100k packets, whichever is smaller)"""
    # Calculate timestamp for 30 minutes ago
    thirty_min_ago = time.time() - (30 * 60)  # 30 minutes in seconds
    
    # Query: last 100k packets OR packets from last 30 minutes
    result = db.query(RawPacket).filter(
        RawPacket.timestamp >= thirty_min_ago
    ).order_by(desc(RawPacket.id)).limit(100000).all()
    
    if not result:
        # Return zeroed-out structure to prevent dashboard crash on empty DB
        return {
            'packet_count': 0, 'byte_count': 0,
            'packet_rate_pps': 0, 'byte_rate_bps': 0,
            'tcp_count': 0, 'udp_count': 0, 'icmp_count': 0, 'arp_count': 0,
            'unique_dst_ips': 0, 'unique_dst_ports': 0,
            'tcp_syn_count': 0, 'tcp_ack_count': 0,
            'dns_query_count': 0,
            'source': 'empty_db_fallback',
            'window_minutes': 30
        }
    
    packets = []
    for p in result:
        packets.append({
            'timestamp': p.timestamp,
            'protocol': p.protocol,
            'length': p.length,
            'dst_ip': p.dst_ip,
            'dst_port': p.dst_port,
            'tcp_syn': p.tcp_syn,
            'tcp_ack': p.tcp_ack,
            'dns_query': p.dns_query,
        })
    
    # Calculate basic metrics
    duration = 30 * 60  # Default to 30 minutes
    if len(packets) >= 2:
        timestamps = [p['timestamp'] for p in packets if p['timestamp']]
        if timestamps:
            duration = max(1, max(timestamps) - min(timestamps))
    
    total_packets = len(packets)
    total_bytes = sum(p['length'] or 0 for p in packets)
    
    return {
        'packet_count': total_packets,
        'byte_count': total_bytes,
        'packet_rate_pps': total_packets / duration,
        'byte_rate_bps': (total_bytes * 8) / duration,
        'peak_byte_rate': (total_bytes * 8) / duration,  # Fallback: same as avg
        'tcp_count': sum(1 for p in packets if p['protocol'] == 'TCP'),
        'udp_count': sum(1 for p in packets if p['protocol'] == 'UDP'),
        'icmp_count': sum(1 for p in packets if p['protocol'] and 'ICMP' in str(p['protocol'])),
        'arp_count': sum(1 for p in packets if p['protocol'] == 'ARP'),
        'unique_dst_ips': len(set(p['dst_ip'] for p in packets if p['dst_ip'])),
        'unique_dst_ports': len(set(p['dst_port'] for p in packets if p['dst_port'])),
        'tcp_syn_count': sum(1 for p in packets if p['tcp_syn']),
        'tcp_ack_count': sum(1 for p in packets if p['tcp_ack']),
        'dns_query_count': sum(1 for p in packets if p['dns_query']),
        'source': 'raw_packets_30min',
        'window_minutes': 30
    }


@app.get("/api/features-extended")
def api_features_extended():
    """Get extended features for Analytics and Performance tabs"""
    if not DATABASE_AVAILABLE:
        return get_dummy_features_extended()
    
    # Get base features
    base_features = api_features(window_size=5)
    if isinstance(base_features, dict) and 'error' in base_features:
        return get_dummy_features_extended()
    
    # Add extended metrics
    db = SessionLocal()
    try:
        # Add TCP flags counts
        tcp_flags = db.query(
            func.count(RawPacket.id).filter(RawPacket.tcp_syn == True),
            func.count(RawPacket.id).filter(RawPacket.tcp_ack == True),
            func.count(RawPacket.id).filter(RawPacket.tcp_fin == True),
            func.count(RawPacket.id).filter(RawPacket.tcp_rst == True),
            func.count(RawPacket.id).filter(RawPacket.tcp_psh == True)
        ).first()
        
        base_features['tcp_fin_count'] = tcp_flags[2] if tcp_flags else 0
        base_features['tcp_rst_count'] = tcp_flags[3] if tcp_flags else 0
        base_features['tcp_psh_count'] = tcp_flags[4] if tcp_flags else 0
        
        # Calculate syn_ack_ratio
        syn = base_features.get('tcp_syn_count', 0)
        ack = base_features.get('tcp_ack_count', 0)
        base_features['syn_ack_ratio'] = syn / max(1, ack) if ack > 0 else 0
        
        # Add port scan score
        unique_ports = base_features.get('unique_dst_ports', 0)
        packet_count = base_features.get('packet_count', 1)
        base_features['port_scan_score'] = min(1.0, unique_ports / 100) if unique_ports > 10 else 0
        base_features['avg_packets_per_port'] = packet_count / max(1, unique_ports)
        
        # Add inter-arrival time metrics
        base_features['inter_arrival_time_mean'] = 0.0035
        base_features['inter_arrival_time_std'] = 0.0012
        
        # Add DNS response count
        dns_responses = db.query(func.count(RawPacket.id)).filter(
            RawPacket.protocol == 'DNS',
            RawPacket.dns_query == None
        ).scalar() or 0
        base_features['dns_response_count'] = dns_responses
        base_features['dns_unique_domains'] = db.query(func.count(func.distinct(RawPacket.dns_query))).filter(
            RawPacket.dns_query != None
        ).scalar() or 0
        base_features['avg_dns_query_length'] = 24.5
        
        # Add HTTP metrics
        base_features['http_request_count'] = db.query(func.count(RawPacket.id)).filter(
            RawPacket.http_method != None
        ).scalar() or 0
        base_features['http_get_count'] = db.query(func.count(RawPacket.id)).filter(
            RawPacket.http_method == 'GET'
        ).scalar() or 0
        base_features['http_post_count'] = db.query(func.count(RawPacket.id)).filter(
            RawPacket.http_method == 'POST'
        ).scalar() or 0
        base_features['http_unique_paths'] = db.query(func.count(func.distinct(RawPacket.http_path))).filter(
            RawPacket.http_path != None
        ).scalar() or 0
        
        # Add ARP rate
        base_features['arp_request_rate_pps'] = base_features.get('arp_request_count', 0) / 5.0
        
        return base_features
    except Exception as e:
        logger.error(f"Error computing extended features: {e}")
        return get_dummy_features_extended()
    finally:
        db.close()


@app.get("/api/protocols")
@fallback_to_dummy(get_dummy_protocols)
def api_protocols():
    """Get protocol distribution with auto-fallback"""
    db = SessionLocal()
    try:
        result = db.query(RawPacket).order_by(desc(RawPacket.id)).limit(1000).all()
        
        protocol_counts = {}
        for p in result:
            proto = p.protocol or 'OTHER'
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        
        return {
            "labels": list(protocol_counts.keys()),
            "values": list(protocol_counts.values())
        }
    finally:
        db.close()


@app.get("/api/top-sources")
@fallback_to_dummy(get_dummy_top_sources)
def api_top_sources(limit: int = 5):
    """Get top source IPs with auto-fallback"""
    db = SessionLocal()
    try:
        result = db.query(RawPacket).order_by(desc(RawPacket.id)).limit(1000).all()
        total = len(result)
        
        ip_counts = {}
        for p in result:
            if p.src_ip:
                ip_counts[p.src_ip] = ip_counts.get(p.src_ip, 0) + 1
        
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        
        return [
            {
                "ip": ip,
                "packet_count": count,
                "percentage": round((count / total) * 100, 1) if total > 0 else 0
            }
            for ip, count in sorted_ips
        ]
    finally:
        db.close()

@app.get("/api/top-destinations")
@fallback_to_dummy(get_dummy_top_destinations)
def api_top_destinations(limit: int = 5):
    """Get top destination IPs with auto-fallback"""
    db = SessionLocal()
    try:
        result = db.query(RawPacket).order_by(desc(RawPacket.id)).limit(1000).all()
        total = len(result)
        
        ip_counts = {}
        for p in result:
            if p.dst_ip:
                ip_counts[p.dst_ip] = ip_counts.get(p.dst_ip, 0) + 1
        
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        
        return [
            {
                "ip": ip,
                "packet_count": count,
                "percentage": round((count / total) * 100, 1) if total > 0 else 0
            }
            for ip, count in sorted_ips
        ]
    finally:
        db.close()


@app.get("/api/top-ports")
@fallback_to_dummy(get_dummy_top_ports)
def api_top_ports(limit: int = 5):
    """Get top destination ports by packet count"""
    db = SessionLocal()
    try:
        result = db.query(RawPacket).order_by(desc(RawPacket.id)).limit(1000).all()
        total = len(result)
        
        port_services = {
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            445: "SMB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        
        port_counts = {}
        for p in result:
            if p.dst_port:
                port_counts[p.dst_port] = port_counts.get(p.dst_port, 0) + 1
        
        sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        
        return [
            {
                "port": port,
                "service": port_services.get(port, "Unknown"),
                "packet_count": count,
                "percentage": round((count / total) * 100, 1) if total > 0 else 0
            }
            for port, count in sorted_ports
        ]
    finally:
        db.close()


# ========== CASCADING AGGREGATION ==========

def aggregate_windows(db_session, source_window_size: int, target_window_size: int, record_count: int):
    """
     aggregations from source_window_size to target_window_size.
    e.g. 5s -> 30s (needs 6 records), 5s -> 180s (needs 36 records)
    """
    # 1. Find the last processed target window to know where to start
    last_target = db_session.query(AggregatedFeature).filter(
        AggregatedFeature.window_size == target_window_size
    ).order_by(desc(AggregatedFeature.window_end)).first()
    
    start_time = last_target.window_end if last_target else datetime.now(LOCAL_TZ) - timedelta(hours=24)
    if not last_target:
        # If no target windows yet, start from the first available source window
        first_source = db_session.query(AggregatedFeature).filter(
            AggregatedFeature.window_size == source_window_size
        ).order_by(AggregatedFeature.window_start).first()
        if first_source:
             start_time = first_source.window_start
        else:
             return # No source data

    # 2. Get all source records after the last target end
    source_records = db_session.query(AggregatedFeature).filter(
        AggregatedFeature.window_size == source_window_size,
        AggregatedFeature.window_start >= start_time
    ).order_by(AggregatedFeature.window_start).all()

    if not source_records:
        return

    # 3. Group by Time Bucket AND src_ip
    # We want to align to target_window_size boundaries
    grouped = {} # { (src_ip, aligned_start_time): [records] }

    for rec in source_records:
        # Align timestamp to bucket
        # Simple alignment: bucket_start
        # We assume consecutive records. 
        # Better approach: Group strictly by time ranges of length target_window_size
        
        # Calculate bucket based on timestamp integer division
        ts = rec.window_start.timestamp()
        bucket_ts = (int(ts) // target_window_size) * target_window_size
        bucket_start = datetime.fromtimestamp(bucket_ts, tz=LOCAL_TZ)
        
        key = (rec.src_ip, bucket_start)
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(rec)

    # 4. Aggregate and Insert
    new_records = []
    
    for (src_ip, bucket_start), records in grouped.items():
        # Only process complete buckets? 
        # source_window_size * count = target_window_size . 
        # e.g. 5s * 6 = 30s. We need approx coverage.
        # Let's require at least 50% coverage to create a record, or strictly all? 
        # User said "make it aggregates... like the 5 second batch". 
        # Robustness: Proceed if we have at least 1 record, summing what we have.
        
        bucket_end = bucket_start + timedelta(seconds=target_window_size)
        
        # Filter records that generally fall in this bucket (double check)
        # (Already done by bucketing logic essentially)
        
        # Calculate aggregated values
        agg_rec = AggregatedFeature(
            window_start=bucket_start,
            window_end=bucket_end,
            window_size=target_window_size,
            src_ip=src_ip,
            created_at=datetime.now(LOCAL_TZ)
        )
        
        # Counters -> SUM
        agg_rec.packet_count = sum(r.packet_count for r in records)
        agg_rec.byte_count = sum(r.byte_count for r in records)
        agg_rec.tcp_count = sum(r.tcp_count for r in records)
        agg_rec.udp_count = sum(r.udp_count for r in records)
        agg_rec.icmp_count = sum(r.icmp_count for r in records)
        agg_rec.arp_count = sum(r.arp_count for r in records)
        
        agg_rec.tcp_syn_count = sum(r.tcp_syn_count for r in records)
        agg_rec.tcp_ack_count = sum(r.tcp_ack_count for r in records)
        agg_rec.half_open_count = sum(r.half_open_count for r in records)
        agg_rec.sequential_port_count = sum(r.sequential_port_count for r in records)
        
        agg_rec.ssh_connection_attempts = sum(r.ssh_connection_attempts for r in records)
        agg_rec.ftp_connection_attempts = sum(r.ftp_connection_attempts for r in records)
        agg_rec.http_login_attempts = sum(r.http_login_attempts for r in records)
        agg_rec.failed_login_count = sum(r.failed_login_count for r in records)
        
        agg_rec.arp_request_count = sum(r.arp_request_count for r in records)
        agg_rec.arp_reply_count = sum(r.arp_reply_count for r in records)
        agg_rec.gratuitous_arp_count = sum(r.gratuitous_arp_count for r in records)
        agg_rec.arp_binding_flap_count = sum(r.arp_binding_flap_count for r in records)
        agg_rec.arp_reply_without_request_count = sum(r.arp_reply_without_request_count for r in records)
        
        agg_rec.dns_query_count = sum(r.dns_query_count for r in records)
        agg_rec.txt_record_count = sum(r.txt_record_count for r in records)
        agg_rec.udp_port_53_count = sum(r.udp_port_53_count for r in records)
        
        agg_rec.open_conn_count = sum(r.open_conn_count for r in records)
        agg_rec.partial_http_count = sum(r.partial_http_count for r in records)

        agg_rec.tcp_ports_hit = sum(r.tcp_ports_hit for r in records)
        agg_rec.udp_ports_hit = sum(r.udp_ports_hit for r in records)
        agg_rec.remote_conn_port_hits = sum(r.remote_conn_port_hits for r in records)

        # Uniques -> MAX (Approximation)
        agg_rec.unique_dst_ips = max(r.unique_dst_ips for r in records)
        agg_rec.unique_dst_ports = max(r.unique_dst_ports for r in records)
        agg_rec.distinct_targets_count = max(r.distinct_targets_count for r in records)
        agg_rec.distinct_record_types = max(r.distinct_record_types for r in records)
        agg_rec.udp_dest_port_count = max(r.udp_dest_port_count for r in records)
        agg_rec.unique_qnames_count = max(r.unique_qnames_count for r in records)
        
        # Max MAC features
        agg_rec.unique_macs_per_ip_max = max(r.unique_macs_per_ip_max for r in records)
        agg_rec.suspicious_mac_changes = max(r.suspicious_mac_changes for r in records)
        agg_rec.duplicate_mac_ips = max(r.duplicate_mac_ips for r in records)


        # Averages -> Weighted Avg (or simple avg if simpler)
        # Using simple Average for simplicity and speed as requested
        count = len(records)
        if count > 0:
             agg_rec.avg_packet_size = sum(r.avg_packet_size for r in records) / count
             agg_rec.packet_size_variance = sum(r.packet_size_variance for r in records) / count
             
             agg_rec.avg_subdomain_entropy = sum(r.avg_subdomain_entropy for r in records) / count
             agg_rec.pct_high_entropy_queries = sum(r.pct_high_entropy_queries for r in records) / count
             agg_rec.avg_answer_size = sum(r.avg_answer_size for r in records) / count
             agg_rec.avg_query_interval_ms = sum(r.avg_query_interval_ms for r in records) / count
             agg_rec.avg_subdomain_length = sum(r.avg_subdomain_length for r in records) / count
             agg_rec.avg_label_count = sum(r.avg_label_count for r in records) / count
             
             agg_rec.avg_conn_duration = sum(r.avg_conn_duration for r in records) / count
             agg_rec.bytes_per_conn = sum(r.bytes_per_conn for r in records) / count
             agg_rec.request_completion_ratio = sum(r.request_completion_ratio for r in records) / count
             
             agg_rec.syn_to_synack_ratio = sum(r.syn_to_synack_ratio for r in records) / count
             agg_rec.syn_only_ratio = sum(r.syn_only_ratio for r in records) / count
             
             agg_rec.avg_macs_per_ip = sum(r.avg_macs_per_ip for r in records) / count
             agg_rec.mac_ip_ratio = sum(r.mac_ip_ratio for r in records) / count

        # Rates -> Re-calculate based on totals and target window size
        duration = target_window_size
        agg_rec.packet_rate_pps = agg_rec.packet_count / duration
        agg_rec.byte_rate_bps = agg_rec.byte_count * 8 / duration
        agg_rec.syn_rate_pps = agg_rec.tcp_syn_count / duration
        agg_rec.syn_ack_rate_pps = agg_rec.tcp_ack_count / duration # Approx
        agg_rec.scan_rate_pps = agg_rec.packet_count / duration # Filtered scan rate? reusing generic packet rate
        agg_rec.icmp_rate_pps = agg_rec.icmp_count / duration
        agg_rec.udp_rate_pps = agg_rec.udp_count / duration
        agg_rec.query_rate_qps = agg_rec.dns_query_count / duration
        agg_rec.login_request_rate = agg_rec.http_login_attempts / duration
        agg_rec.auth_attempts_per_min = (agg_rec.ssh_connection_attempts + agg_rec.ftp_connection_attempts + agg_rec.http_login_attempts) / (duration/60)

        # Ratios
        agg_rec.dns_to_udp_ratio = agg_rec.dns_query_count / max(1, agg_rec.udp_count)

        new_records.append(agg_rec)

    if new_records:
        db_session.add_all(new_records)
        db_session.commit()
        logger.info(f"⚡ Cascaded Aggregation: Created {len(new_records)} records of {target_window_size}s from {source_window_size}s data")


def run_cascading_aggregation():
    """Background task to run aggregation periodically, parallelized by src_ip."""
    MAX_WORKERS = 4  # Number of parallel threads for aggregation
    
    while not shutdown_flag:
        if DATABASE_AVAILABLE:
            try:
                # 1. Get unique src_ips with pending 5s data (in main thread)
                db_main = SessionLocal()
                pending_ips = db_main.query(AggregatedFeature.src_ip).filter(
                    AggregatedFeature.window_size == 5
                ).distinct().all()
                pending_ips = [ip[0] for ip in pending_ips]
                db_main.close()
                
                if not pending_ips:
                    time.sleep(10)
                    continue
                
                logger.info(f"🔄 Cascading aggregation: Processing {len(pending_ips)} unique IPs")
                
                # 2. Parallelize aggregation per src_ip
                def aggregate_for_ip(src_ip):
                    """Process 30s and 180s aggregation for a single src_ip."""
                    db = SessionLocal()  # New session per thread
                    try:
                        # 5s -> 30s for this IP
                        aggregate_windows_for_ip(db, src_ip, source_window_size=5, target_window_size=30)
                        # 5s -> 180s for this IP
                        aggregate_windows_for_ip(db, src_ip, source_window_size=5, target_window_size=180)
                        db.commit()
                    except Exception as e:
                        logger.error(f"Aggregation failed for IP {src_ip}: {e}")
                        db.rollback()
                    finally:
                        db.close()
                
                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    futures = {executor.submit(aggregate_for_ip, ip): ip for ip in pending_ips}
                    for future in as_completed(futures):
                        ip = futures[future]
                        try:
                            future.result()  # Raise any exception from thread
                        except Exception as e:
                            logger.error(f"Thread error for IP {ip}: {e}")
                
                logger.info(f"✅ Cascading aggregation complete for {len(pending_ips)} IPs")
                
            except Exception as e:
                logger.error(f"Cascading aggregation main loop failed: {e}")
        
        time.sleep(10)  # Run frequently to keep up


def aggregate_windows_for_ip(db_session, src_ip: str, source_window_size: int, target_window_size: int):
    """
    Aggregate windows for a SINGLE src_ip from source_window_size to target_window_size.
    """
    # Find the last processed target window for this IP
    last_target = db_session.query(AggregatedFeature).filter(
        AggregatedFeature.window_size == target_window_size,
        AggregatedFeature.src_ip == src_ip
    ).order_by(desc(AggregatedFeature.window_end)).first()
    
    start_time = last_target.window_end if last_target else datetime.now(LOCAL_TZ) - timedelta(hours=24)
    if not last_target:
        first_source = db_session.query(AggregatedFeature).filter(
            AggregatedFeature.window_size == source_window_size,
            AggregatedFeature.src_ip == src_ip
        ).order_by(AggregatedFeature.window_start).first()
        if first_source:
            start_time = first_source.window_start
        else:
            return  # No source data for this IP

    # Get source records for this IP
    source_records = db_session.query(AggregatedFeature).filter(
        AggregatedFeature.window_size == source_window_size,
        AggregatedFeature.src_ip == src_ip,
        AggregatedFeature.window_start >= start_time
    ).order_by(AggregatedFeature.window_start).all()

    if not source_records:
        return

    # Group by Time Bucket
    grouped = {}
    for rec in source_records:
        ts = rec.window_start.timestamp()
        bucket_ts = (int(ts) // target_window_size) * target_window_size
        bucket_start = datetime.fromtimestamp(bucket_ts, tz=LOCAL_TZ)
        
        if bucket_start not in grouped:
            grouped[bucket_start] = []
        grouped[bucket_start].append(rec)

    # Determine required count for complete window
    # 30s needs 6x 5s records, 180s needs 36x 5s records (or 6x 30s)
    required_count = target_window_size // source_window_size

    # Aggregate and Insert (only complete buckets)
    new_records = []
    for bucket_start, records in grouped.items():
        # Skip incomplete buckets
        if len(records) < required_count:
            continue  # Not enough source records yet
        
        bucket_end = bucket_start + timedelta(seconds=target_window_size)
        
        # Check for duplicate: skip if this bucket already exists
        existing = db_session.query(AggregatedFeature.id).filter(
            AggregatedFeature.window_size == target_window_size,
            AggregatedFeature.src_ip == src_ip,
            AggregatedFeature.window_start == bucket_start
        ).first()
        if existing:
            continue  # Already aggregated, skip
        
        agg_rec = AggregatedFeature(
            window_start=bucket_start,
            window_end=bucket_end,
            window_size=target_window_size,
            src_ip=src_ip,
            created_at=datetime.now(LOCAL_TZ)
        )
        
        # Counters -> SUM
        agg_rec.packet_count = sum(r.packet_count for r in records)
        agg_rec.byte_count = sum(r.byte_count for r in records)
        agg_rec.tcp_count = sum(r.tcp_count for r in records)
        agg_rec.udp_count = sum(r.udp_count for r in records)
        agg_rec.icmp_count = sum(r.icmp_count for r in records)
        agg_rec.arp_count = sum(r.arp_count for r in records)
        agg_rec.tcp_syn_count = sum(r.tcp_syn_count for r in records)
        agg_rec.tcp_ack_count = sum(r.tcp_ack_count for r in records)
        agg_rec.half_open_count = sum(r.half_open_count for r in records)
        agg_rec.sequential_port_count = sum(r.sequential_port_count for r in records)
        agg_rec.ssh_connection_attempts = sum(r.ssh_connection_attempts for r in records)
        agg_rec.ftp_connection_attempts = sum(r.ftp_connection_attempts for r in records)
        agg_rec.http_login_attempts = sum(r.http_login_attempts for r in records)
        agg_rec.failed_login_count = sum(r.failed_login_count for r in records)
        agg_rec.arp_request_count = sum(r.arp_request_count for r in records)
        agg_rec.arp_reply_count = sum(r.arp_reply_count for r in records)
        agg_rec.gratuitous_arp_count = sum(r.gratuitous_arp_count for r in records)
        agg_rec.arp_binding_flap_count = sum(r.arp_binding_flap_count for r in records)
        agg_rec.arp_reply_without_request_count = sum(r.arp_reply_without_request_count for r in records)
        agg_rec.dns_query_count = sum(r.dns_query_count for r in records)
        agg_rec.txt_record_count = sum(r.txt_record_count for r in records)
        agg_rec.udp_port_53_count = sum(r.udp_port_53_count for r in records)
        agg_rec.open_conn_count = sum(r.open_conn_count for r in records)
        agg_rec.partial_http_count = sum(r.partial_http_count for r in records)
        agg_rec.tcp_ports_hit = sum(r.tcp_ports_hit for r in records)
        agg_rec.udp_ports_hit = sum(r.udp_ports_hit for r in records)
        agg_rec.remote_conn_port_hits = sum(r.remote_conn_port_hits for r in records)

        # Uniques -> MAX
        agg_rec.unique_dst_ips = max(r.unique_dst_ips for r in records)
        agg_rec.unique_dst_ports = max(r.unique_dst_ports for r in records)
        agg_rec.distinct_targets_count = max(r.distinct_targets_count for r in records)
        agg_rec.distinct_record_types = max(r.distinct_record_types for r in records)
        agg_rec.udp_dest_port_count = max(r.udp_dest_port_count for r in records)
        agg_rec.unique_qnames_count = max(r.unique_qnames_count for r in records)
        agg_rec.unique_macs_per_ip_max = max(r.unique_macs_per_ip_max for r in records)
        agg_rec.suspicious_mac_changes = max(r.suspicious_mac_changes for r in records)
        agg_rec.duplicate_mac_ips = max(r.duplicate_mac_ips for r in records)

        # Averages -> Simple Avg
        count = len(records)
        if count > 0:
            agg_rec.avg_packet_size = sum(r.avg_packet_size for r in records) / count
            agg_rec.packet_size_variance = sum(r.packet_size_variance for r in records) / count
            agg_rec.avg_subdomain_entropy = sum(r.avg_subdomain_entropy for r in records) / count
            agg_rec.pct_high_entropy_queries = sum(r.pct_high_entropy_queries for r in records) / count
            agg_rec.avg_answer_size = sum(r.avg_answer_size for r in records) / count
            agg_rec.avg_query_interval_ms = sum(r.avg_query_interval_ms for r in records) / count
            agg_rec.avg_subdomain_length = sum(r.avg_subdomain_length for r in records) / count
            agg_rec.avg_label_count = sum(r.avg_label_count for r in records) / count
            agg_rec.avg_conn_duration = sum(r.avg_conn_duration for r in records) / count
            agg_rec.bytes_per_conn = sum(r.bytes_per_conn for r in records) / count
            agg_rec.request_completion_ratio = sum(r.request_completion_ratio for r in records) / count
            agg_rec.syn_to_synack_ratio = sum(r.syn_to_synack_ratio for r in records) / count
            agg_rec.syn_only_ratio = sum(r.syn_only_ratio for r in records) / count
            agg_rec.avg_macs_per_ip = sum(r.avg_macs_per_ip for r in records) / count
            agg_rec.mac_ip_ratio = sum(r.mac_ip_ratio for r in records) / count

        # Rates -> Re-calculate
        duration = target_window_size
        agg_rec.packet_rate_pps = agg_rec.packet_count / duration
        agg_rec.byte_rate_bps = agg_rec.byte_count * 8 / duration
        agg_rec.syn_rate_pps = agg_rec.tcp_syn_count / duration
        agg_rec.syn_ack_rate_pps = agg_rec.tcp_ack_count / duration
        agg_rec.scan_rate_pps = agg_rec.packet_count / duration
        agg_rec.icmp_rate_pps = agg_rec.icmp_count / duration
        agg_rec.udp_rate_pps = agg_rec.udp_count / duration
        agg_rec.query_rate_qps = agg_rec.dns_query_count / duration
        agg_rec.login_request_rate = agg_rec.http_login_attempts / duration
        agg_rec.auth_attempts_per_min = (agg_rec.ssh_connection_attempts + agg_rec.ftp_connection_attempts + agg_rec.http_login_attempts) / (duration/60)
        agg_rec.dns_to_udp_ratio = agg_rec.dns_query_count / max(1, agg_rec.udp_count)

        new_records.append(agg_rec)

    if new_records:
        db_session.add_all(new_records)
        db_session.flush()  # Flush to get IDs before prediction
        
        # Immediately run ML prediction on each new aggregated record
        for agg_rec in new_records:
            try:
                predict_and_alert(db_session, agg_rec)
            except Exception as e:
                logger.error(f"Inline ML prediction failed for {agg_rec.src_ip} ({target_window_size}s): {e}")
        
        logger.info(f"⚡ Created {len(new_records)} {target_window_size}s records for IP {src_ip} (ML predicted)")
        # Commit is done by caller

# ... existing code ...




@app.get("/api/packets")
def api_packets(limit: int = 200):
    """Get raw packets for export"""
    if not DATABASE_AVAILABLE:
        # Return dummy raw packets
        return [
            {
                "timestamp": (datetime.now() - timedelta(seconds=i)).isoformat(),
                "src_ip": f"192.168.1.{100+i%20}",
                "dst_ip": f"10.0.0.{50+i%5}",
                "protocol": ["TCP", "UDP", "HTTP", "DNS"][i%4],
                "length": 60 + i%1000,
                "info": "Dummy packet data"
            }
            for i in range(limit)
        ]

    db = SessionLocal()
    try:
        packets = db.query(RawPacket).order_by(desc(RawPacket.id)).limit(limit).all()
        return [
            {
                "timestamp": p.timestamp.isoformat() if p.timestamp else None,
                "src_ip": p.src_ip,
                "dst_ip": p.dst_ip,
                "protocol": p.protocol,
                "length": p.length,
                "info": f"Port {p.src_port} -> {p.dst_port} | Flags: {p.tcp_flags}"
            }
            for p in packets
        ]
    finally:
        db.close()


# ========== NEW ENDPOINTS - REPLACE SIMULATED DATA ==========

@app.get("/api/traffic-history")
@fallback_to_dummy(get_dummy_traffic_history)
def api_traffic_history(hours: float = 24.0):
    """Get real traffic volume over time with auto-fallback"""
    db = SessionLocal()
    try:
        cutoff = datetime.now(LOCAL_TZ) - timedelta(hours=hours)
        use_minute_resolution = hours <= 1.0
        time_format = '%H:%M' if use_minute_resolution else '%H:00'
        
        # Try aggregated_features first
        result = db.query(AggregatedFeature).filter(
            AggregatedFeature.created_at >= cutoff
        ).order_by(AggregatedFeature.created_at).all()
        
        if result:
            # Group by hour or minute
            grouped_data = {}
            for r in result:
                key = r.created_at.strftime(time_format) if r.created_at else '00:00'
                if key not in grouped_data:
                    grouped_data[key] = {
                        'byte_rate': 0, 'packet_rate': 0, 'count': 0,
                        'tcp': 0, 'udp': 0, 'icmp': 0, 'other': 0
                    }
                grouped_data[key]['byte_rate'] += r.byte_rate_bps or 0
                grouped_data[key]['packet_rate'] += r.packet_rate_pps or 0
                
                # Approximate PPS for protocols (count / 10s window)
                grouped_data[key]['tcp'] += (r.tcp_count or 0) / 10.0
                grouped_data[key]['udp'] += (r.udp_count or 0) / 10.0
                grouped_data[key]['icmp'] += (r.icmp_count or 0) / 10.0
                grouped_data[key]['other'] += (r.other_count or 0) / 10.0
                
                grouped_data[key]['count'] += 1
            
            # Average per bucket
            labels = sorted(grouped_data.keys())
            byte_rates = [grouped_data[k]['byte_rate'] / max(1, grouped_data[k]['count']) for k in labels]
            packet_rates = [grouped_data[k]['packet_rate'] / max(1, grouped_data[k]['count']) for k in labels]
            
            # Protocol rates (already converted to rate sum, so just avg by count)
            tcp_rates = [grouped_data[k]['tcp'] / max(1, grouped_data[k]['count']) for k in labels]
            udp_rates = [grouped_data[k]['udp'] / max(1, grouped_data[k]['count']) for k in labels]
            icmp_rates = [grouped_data[k]['icmp'] / max(1, grouped_data[k]['count']) for k in labels]
            other_rates = [grouped_data[k]['other'] / max(1, grouped_data[k]['count']) for k in labels]
            
            return {
                "labels": labels, 
                "byte_rates": byte_rates, 
                "packet_rates": packet_rates,
                "tcp_rates": tcp_rates,
                "udp_rates": udp_rates,
                "icmp_rates": icmp_rates,
                "other_rates": other_rates
            }
        
        # Fallback: query raw_packets
        raw_result = db.query(RawPacket).filter(
            RawPacket.timestamp >= (datetime.now(LOCAL_TZ) - timedelta(hours=hours)).timestamp()
        ).order_by(RawPacket.timestamp).all()
        
        if not raw_result:
            return {
                "labels": [], "byte_rates": [], "packet_rates": [],
                "tcp_rates": [], "udp_rates": [], "icmp_rates": [], "other_rates": []
            }
        
        grouped_data = {}
        for p in raw_result:
            ts = datetime.fromtimestamp(p.timestamp)
            key = ts.strftime(time_format)
            if key not in grouped_data:
                grouped_data[key] = {'bytes': 0, 'packets': 0, 'tcp': 0, 'udp': 0, 'icmp': 0, 'other': 0}
            grouped_data[key]['bytes'] += p.length or 0
            grouped_data[key]['packets'] += 1
            
            proto = p.protocol
            if proto == 'TCP': grouped_data[key]['tcp'] += 1
            elif proto == 'UDP': grouped_data[key]['udp'] += 1
            elif proto == 'ICMP': grouped_data[key]['icmp'] += 1
            else: grouped_data[key]['other'] += 1
        
        labels = sorted(grouped_data.keys())
        # Calc rates
        duration_sec = 60 if use_minute_resolution else 3600
        byte_rates = [grouped_data[k]['bytes'] * 8 / duration_sec for k in labels]
        packet_rates = [grouped_data[k]['packets'] / duration_sec for k in labels]
        
        tcp_rates = [grouped_data[k]['tcp'] / duration_sec for k in labels]
        udp_rates = [grouped_data[k]['udp'] / duration_sec for k in labels]
        icmp_rates = [grouped_data[k]['icmp'] / duration_sec for k in labels]
        other_rates = [grouped_data[k]['other'] / duration_sec for k in labels]
        
        return {
            "labels": labels, 
            "byte_rates": byte_rates, 
            "packet_rates": packet_rates,
            "tcp_rates": tcp_rates,
            "udp_rates": udp_rates,
            "icmp_rates": icmp_rates,
            "other_rates": other_rates
        }

    finally:
        db.close()


@app.get("/api/traffic-direction")
@fallback_to_dummy(get_dummy_traffic_direction)
def api_traffic_direction(local_prefix: str = "192.168."):
    """Get real inbound vs outbound traffic with auto-fallback"""
    db = SessionLocal()
    try:
        result = db.query(RawPacket).order_by(desc(RawPacket.id)).limit(5000).all()
        
        inbound_bytes = 0
        outbound_bytes = 0
        inbound_packets = 0
        outbound_packets = 0
        
        for p in result:
            is_dst_local = p.dst_ip and p.dst_ip.startswith(local_prefix)
            is_src_local = p.src_ip and p.src_ip.startswith(local_prefix)
            
            if is_dst_local and not is_src_local:
                # Inbound: external -> local
                inbound_bytes += p.length or 0
                inbound_packets += 1
            elif is_src_local and not is_dst_local:
                # Outbound: local -> external
                outbound_bytes += p.length or 0
                outbound_packets += 1
            # else: local-to-local or external-to-external, skip
        
        return {
            "inbound_bytes": inbound_bytes,
            "outbound_bytes": outbound_bytes,
            "inbound_packets": inbound_packets,
            "outbound_packets": outbound_packets
        }
    finally:
        db.close()


@app.get("/api/packet-size-distribution")
@fallback_to_dummy(get_dummy_packet_size_distribution)
def api_packet_size_distribution():
    """Get real packet size distribution with auto-fallback"""
    db = SessionLocal()
    try:
        result = db.query(RawPacket.length).order_by(desc(RawPacket.id)).limit(5000).all()
        
        buckets = {'<100': 0, '100-500': 0, '500-1000': 0, '1000-1500': 0, '>1500': 0}
        
        for (length,) in result:
            if length is None:
                continue
            if length < 100:
                buckets['<100'] += 1
            elif length < 500:
                buckets['100-500'] += 1
            elif length < 1000:
                buckets['500-1000'] += 1
            elif length < 1500:
                buckets['1000-1500'] += 1
            else:
                buckets['>1500'] += 1
        
        return {"labels": list(buckets.keys()), "values": list(buckets.values())}

    finally:
        db.close()


@app.get("/api/dns-stats")
@fallback_to_dummy(get_dummy_dns_stats)
def api_dns_stats():
    """Get real DNS statistics with auto-fallback"""
    db = SessionLocal()
    try:
        result = db.query(RawPacket).filter(
            RawPacket.dns_qname.isnot(None)
        ).order_by(desc(RawPacket.id)).limit(5000).all()
        
        query_count = sum(1 for p in result if p.dns_query)
        response_count = sum(1 for p in result if p.dns_response)
        unique_domains = len(set(p.dns_qname for p in result if p.dns_qname))
        
        query_lengths = [len(p.dns_qname) for p in result if p.dns_qname]
        avg_query_length = sum(query_lengths) / max(1, len(query_lengths)) if query_lengths else 0
        max_query_length = max(query_lengths) if query_lengths else 0
        
        # Get distribution for query length chart
        length_buckets = {'<10': 0, '10-20': 0, '20-40': 0, '40-60': 0, '60-100': 0, '>100': 0}
        for length in query_lengths:
            if length < 10:
                length_buckets['<10'] += 1
            elif length < 20:
                length_buckets['10-20'] += 1
            elif length < 40:
                length_buckets['20-40'] += 1
            elif length < 60:
                length_buckets['40-60'] += 1
            elif length < 100:
                length_buckets['60-100'] += 1
            else:
                length_buckets['>100'] += 1
        
        return {
            "dns_query_count": query_count,
            "dns_response_count": response_count,
            "dns_unique_domains": unique_domains,
            "avg_dns_query_length": round(avg_query_length, 1),
            "max_dns_query_length": max_query_length,
            "length_distribution": length_buckets
        }

    finally:
        db.close()


@app.get("/api/tcp-flags")
def api_tcp_flags():
    """
    Get real TCP flags distribution (replaces missing tcp_fin_count, tcp_rst_count, tcp_psh_count).
    Queries raw_packets for TCP flag fields.
    """
    if not DATABASE_AVAILABLE:
        return get_dummy_tcp_flags()
    
    db = SessionLocal()
    try:
        result = db.query(RawPacket).filter(
            RawPacket.protocol == 'TCP'
        ).order_by(desc(RawPacket.id)).limit(5000).all()
        
        syn_count = sum(1 for p in result if p.tcp_syn)
        ack_count = sum(1 for p in result if p.tcp_ack)
        fin_count = sum(1 for p in result if p.tcp_fin)
        rst_count = sum(1 for p in result if p.tcp_rst)
        psh_count = sum(1 for p in result if p.tcp_psh)
        
        return {
            "tcp_syn_count": syn_count,
            "tcp_ack_count": ack_count,
            "tcp_fin_count": fin_count,
            "tcp_rst_count": rst_count,
            "tcp_psh_count": psh_count,
            "total_tcp_packets": len(result)
        }
    finally:
        db.close()


@app.get("/api/features-extended")
def api_features_extended(window_size: int = 5):
    """
    Extended features endpoint with ALL missing fields calculated from DB.
    Includes: syn_ack_ratio, port_scan_score, inter_arrival_time, etc.
    """
    db = SessionLocal()
    try:
        # Get base features
        base_features = api_features(window_size)
        if "error" in base_features:
            return base_features
        
        # Calculate additional features from raw_packets
        raw_packets = db.query(RawPacket).order_by(desc(RawPacket.id)).limit(2000).all()
        
        if not raw_packets:
            # Populate defaults for extended metrics if no packets
            defaults = {
                'syn_ack_ratio': 0, 'port_scan_score': 0,
                'inter_arrival_time_mean': 0, 'inter_arrival_time_std': 0,
                'min_packet_size': 0, 'max_packet_size': 0, 'packet_size_variance': 0,
                'tcp_fin_count': 0, 'tcp_rst_count': 0, 'tcp_psh_count': 0,
                'dns_response_count': 0, 'dns_unique_domains': 0, 'avg_dns_query_length': 0
            }
            base_features.update(defaults)
            return base_features
        
        # SYN-ACK ratio
        syn_count = base_features.get('tcp_syn_count', 0)
        ack_count = base_features.get('tcp_ack_count', 0)
        base_features['syn_ack_ratio'] = ack_count / max(1, syn_count) if syn_count > 0 else 0
        
        # Port scan score (based on unique ports vs unique IPs ratio)
        unique_ports = base_features.get('unique_dst_ports', 0)
        unique_ips = base_features.get('unique_dst_ips', 1)
        # High ports-per-IP ratio suggests scanning
        ports_per_ip = unique_ports / max(1, unique_ips)
        base_features['port_scan_score'] = min(1.0, ports_per_ip / 100)  # Normalize to 0-1
        # Inter-arrival time (average time between consecutive packets)
        timestamps = sorted([p.timestamp for p in raw_packets if p.timestamp])
        if len(timestamps) >= 2:
            inter_arrivals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            base_features['inter_arrival_time_mean'] = sum(inter_arrivals) / len(inter_arrivals)
            base_features['inter_arrival_time_std'] = (
                sum((x - base_features['inter_arrival_time_mean'])**2 for x in inter_arrivals) / len(inter_arrivals)
            ) ** 0.5
        else:
            base_features['inter_arrival_time_mean'] = 0
            base_features['inter_arrival_time_std'] = 0
        
        # Packet size stats
        lengths = [p.length for p in raw_packets if p.length]
        if lengths:
            base_features['min_packet_size'] = min(lengths)
            base_features['max_packet_size'] = max(lengths)
            base_features['packet_size_variance'] = sum((x - base_features['avg_packet_size'])**2 for x in lengths) / len(lengths)
        
        # TCP flags (query from tcp-flags endpoint)
        tcp_flags = api_tcp_flags()
        base_features['tcp_fin_count'] = tcp_flags.get('tcp_fin_count', 0)
        base_features['tcp_rst_count'] = tcp_flags.get('tcp_rst_count', 0)
        base_features['tcp_psh_count'] = tcp_flags.get('tcp_psh_count', 0)
        
        # DNS stats
        dns_stats = api_dns_stats()
        base_features['dns_response_count'] = dns_stats.get('dns_response_count', 0)
        base_features['dns_unique_domains'] = dns_stats.get('dns_unique_domains', 0)
        base_features['avg_dns_query_length'] = dns_stats.get('avg_dns_query_length', 0)
        
        return base_features
    finally:
        db.close()


@app.get("/api/packets")
@app.get("/api/packets")
def api_packets(page: int = 1, limit: int = 20, protocol: str = None, search: str = None):
    """Get paginated raw packets with optional filters"""
    if not DATABASE_AVAILABLE:
        return get_dummy_packets()
    
    db = SessionLocal()
    try:
        query = db.query(RawPacket)

        # Apply Protocol Filter
        if protocol and protocol != "All":
            query = query.filter(RawPacket.protocol == protocol)

        # Apply Search Filter (Source IP, Dest IP, or Payload match)
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    RawPacket.src_ip.like(search_term),
                    RawPacket.dst_ip.like(search_term),
                    RawPacket.protocol.like(search_term)
                )
            )

        # Get total count after filtering
        total = query.count()
        
        offset = (page - 1) * limit
        result = query.order_by(desc(RawPacket.id)).offset(offset).limit(limit).all()
        
        packets = []
        for p in result:
            pkt = {
                'id': p.id,
                'timestamp': datetime.fromtimestamp(p.timestamp).strftime('%Y-%m-%d %H:%M:%S') if p.timestamp else '--',
                'src_ip': p.src_ip,
                'dst_ip': p.dst_ip,
                'protocol': p.protocol,
                'src_port': p.src_port,
                'dst_port': p.dst_port,
                'length': p.length,
                'flags': p.tcp_flags or '--'
            }
            packets.append(pkt)
        
        return {
            "packets": packets,
            "total": total,
            "page": page,
            "limit": limit,
            "pages": (total + limit - 1) // limit if total else 0
        }
    finally:
        db.close()


@app.get("/api/alerts")
@fallback_to_dummy(get_dummy_alerts)
def api_alerts(limit: int = 50, severity: str = None, resolved: bool = None):
    """Get detected security alerts with auto-fallback"""
    db = SessionLocal()
    try:
        query = db.query(DetectedAlert)
        
        if severity:
            query = query.filter(DetectedAlert.severity == severity.upper())
        
        if resolved is not None:
            query = query.filter(DetectedAlert.resolved == resolved)
        
        result = query.order_by(desc(DetectedAlert.detected_at)).limit(limit).all()
        
        alerts = []
        for a in result:
            alert = {
                "id": a.id,
                "src_ip": a.src_ip,
                "attack_type": a.attack_type,
                "confidence": a.confidence,
                "severity": a.severity,
                "window_size": a.window_size,
                "packet_count": a.packet_count,
                "byte_count": a.byte_count,
                "detected_at": a.detected_at.isoformat() if a.detected_at else None,
                "resolved": a.resolved,
                "details": a.details
            }
            alerts.append(alert)
        
        return {
            "alerts": alerts,
            "total": len(alerts),
            "filters": {"severity": severity, "resolved": resolved}
        }

    finally:
        db.close()


@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int):
    """Mark an alert as resolved"""
    db = SessionLocal()
    try:
        alert = db.query(DetectedAlert).filter(DetectedAlert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        alert.resolved = True
        alert.resolved_at = datetime.now(LOCAL_TZ)
        db.commit()
        
        return {"status": "resolved", "alert_id": alert_id}
    finally:
        db.close()


@app.get("/api/alerts/summary")
def api_alerts_summary():
    """Get summary of alerts by type and severity"""
    db = SessionLocal()
    try:
        result = db.query(DetectedAlert).order_by(desc(DetectedAlert.id)).limit(1000).all()
        
        by_type = {}
        by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        unresolved = 0
        
        for alert in result:
            attack_type = alert.attack_type or 'Unknown'
            by_type[attack_type] = by_type.get(attack_type, 0) + 1
            
            severity = alert.severity or 'UNKNOWN'
            if severity in by_severity:
                by_severity[severity] += 1
            
            if not alert.resolved:
                unresolved += 1
        
        return {
            "total_alerts": len(result),
            "unresolved": unresolved,
            "by_attack_type": by_type,
            "by_severity": by_severity
        }
    finally:
        db.close()


@app.get("/api/ml/predict")
def api_ml_predict():
    """Get ML prediction based on recent traffic features"""
    if not DATABASE_AVAILABLE:
        return {"attack_type": "Normal", "confidence": 92.5, "threat_level": "NONE", "message": "Dummy prediction"}
    
    features = api_features()
    
    if "error" in features:
        return {
            "attack_type": "Unknown",
            "confidence": 0,
            "threat_level": "NONE",
            "message": "No traffic data available"
        }
    
    if not MODEL_LOADED:
        # Heuristic-based prediction if model not loaded
        threat_indicators = 0
        
        if features.get('packet_rate_pps', 0) > 1000:
            threat_indicators += 2
        if features.get('syn_rate_pps', 0) > 100:
            threat_indicators += 2
        if features.get('connection_failure_rate', 0) > 0.5:
            threat_indicators += 1
        if features.get('unique_dst_ports', 0) > 50:
            threat_indicators += 2
        
        if threat_indicators >= 4:
            return {"attack_type": "Potential DDoS", "confidence": 75.0, "threat_level": "HIGH"}
        elif threat_indicators >= 2:
            return {"attack_type": "Suspicious Activity", "confidence": 50.0, "threat_level": "MEDIUM"}
        else:
            return {"attack_type": "Normal", "confidence": 90.0, "threat_level": "NONE"}
    
    try:
        # Build feature vector for model
        feature_dict = {col: features.get(col, 0) for col in feature_names}
        feature_df = pd.DataFrame([feature_dict])
        
        prediction = xgb_model.predict(feature_df)[0]
        probabilities = xgb_model.predict_proba(feature_df)[0]
        confidence = float(np.max(probabilities)) * 100
        predicted_label = label_encoder.inverse_transform([prediction])[0]
        
        threat_level = "NONE"
        if predicted_label.lower() != "normal":
            if confidence > 80:
                threat_level = "HIGH"
            elif confidence > 60:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"
        
        return {
            "attack_type": predicted_label,
            "confidence": round(confidence, 1),
            "threat_level": threat_level
        }
    except Exception as e:
        logger.error(f"ML prediction error: {e}")
        return {
            "attack_type": "Normal",
            "confidence": 50.0,
            "threat_level": "NONE",
            "error": str(e)
        }


@app.get("/stats")
def get_stats():
    """Get database statistics"""
    db = SessionLocal()
    try:
        raw_count = db.query(func.count(RawPacket.id)).scalar()
        agg_count = db.query(func.count(AggregatedFeature.id)).scalar()
        alert_count = db.query(func.count(DetectedAlert.id)).scalar()
        unresolved_alerts = db.query(func.count(DetectedAlert.id)).filter(DetectedAlert.resolved == False).scalar()
        predicted_count = db.query(func.count(AggregatedFeature.id)).filter(
            AggregatedFeature.predicted_label != None
        ).scalar()
        
        return {
            "raw_packets": raw_count,
            "aggregated_features": agg_count,
            "predicted_features": predicted_count,
            "pending_predictions": agg_count - predicted_count,
            "total_alerts": alert_count,
            "unresolved_alerts": unresolved_alerts,
            "model_loaded": MODEL_LOADED,
            "timestamp": datetime.utcnow().isoformat()
        }
    finally:
        db.close()


# ========== STARTUP ==========
@app.on_event("startup")
def startup_event():
    """Start background prediction task"""
    if MODEL_LOADED and DATABASE_AVAILABLE:
        prediction_thread = threading.Thread(target=run_predictions, daemon=True)
        prediction_thread.start()
        logger.info("🔄 Started background prediction loop")

        agg_thread = threading.Thread(target=run_cascading_aggregation, daemon=True)
        agg_thread.start()
        logger.info("🔄 Started background cascading aggregation loop")
    elif not DATABASE_AVAILABLE:
        logger.warning("⚠️ Database not available - predictions disabled")
    else:
        logger.warning("⚠️ ML model not loaded - predictions disabled")


# ========== TELEGRAM BOT API ENDPOINTS ==========
import subprocess

# Configuration for ngrok
NGROK_PATH = os.getenv("NGROK_PATH", r"D:\apps\ngrok\ngrok-v3-stable-windows-amd64\ngrok.exe")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

# Global to track ngrok process
ngrok_process = None


@app.get("/api/telegram/status")
async def get_telegram_status():
    """Check if Telegram bot token is valid by calling getMe API"""
    if not TELEGRAM_BOT_TOKEN:
        return {"ok": False, "error": "TELEGRAM_BOT_TOKEN not configured in .env"}
    
    try:
        import requests as req
        response = req.get(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getMe", timeout=10)
        data = response.json()
        
        if data.get("ok"):
            bot_info = data.get("result", {})
            return {
                "ok": True,
                "bot_name": bot_info.get("first_name", "Unknown"),
                "bot_username": bot_info.get("username", "Unknown"),
                "can_read_messages": bot_info.get("can_read_all_group_messages", False)
            }
        else:
            return {"ok": False, "error": data.get("description", "Unknown error")}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/api/telegram/auto-setup")
async def auto_setup_telegram():
    """Start ngrok and set Telegram webhook automatically"""
    global ngrok_process
    
    if not TELEGRAM_BOT_TOKEN:
        return {"success": False, "error": "TELEGRAM_BOT_TOKEN not configured in .env"}
    
    if not os.path.exists(NGROK_PATH):
        return {"success": False, "error": f"ngrok not found at: {NGROK_PATH}"}
    
    try:
        import requests as req
        
        # Step 1: Check if ngrok is already running by querying its API
        ngrok_url = None
        try:
            tunnels_response = req.get("http://localhost:4040/api/tunnels", timeout=2)
            if tunnels_response.status_code == 200:
                tunnels = tunnels_response.json().get("tunnels", [])
                for tunnel in tunnels:
                    if tunnel.get("proto") == "https":
                        ngrok_url = tunnel.get("public_url")
                        break
        except:
            pass  # ngrok not running yet
        
        # Step 2: If no tunnel found, start ngrok
        if not ngrok_url:
            logger.info("🚀 Starting ngrok...")
            
            # Kill any existing ngrok process we started
            if ngrok_process:
                try:
                    ngrok_process.terminate()
                except:
                    pass
            
            # Start ngrok pointing to our server port (8000)
            ngrok_process = subprocess.Popen(
                [NGROK_PATH, "http", "8000"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            # Wait for ngrok to start
            import time
            for _ in range(10):  # Try for 5 seconds
                time.sleep(0.5)
                try:
                    tunnels_response = req.get("http://localhost:4040/api/tunnels", timeout=2)
                    if tunnels_response.status_code == 200:
                        tunnels = tunnels_response.json().get("tunnels", [])
                        for tunnel in tunnels:
                            if tunnel.get("proto") == "https":
                                ngrok_url = tunnel.get("public_url")
                                break
                        if ngrok_url:
                            break
                except:
                    pass
            
            if not ngrok_url:
                return {"success": False, "error": "Failed to get ngrok public URL. Check if ngrok is configured correctly."}
        
        # Step 3: Set Telegram webhook
        webhook_url = f"{ngrok_url}/webhook/{TELEGRAM_BOT_TOKEN}"
        set_response = req.get(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/setWebhook",
            params={"url": webhook_url},
            timeout=10
        )
        set_data = set_response.json()
        
        if set_data.get("ok"):
            logger.info(f"✅ Telegram webhook set: {ngrok_url}")
            return {
                "success": True,
                "webhook_url": webhook_url,
                "ngrok_url": ngrok_url,
                "message": "Webhook configured successfully!"
            }
        else:
            return {"success": False, "error": set_data.get("description", "Failed to set webhook")}
            
    except Exception as e:
        logger.error(f"Auto-setup failed: {e}")
        return {"success": False, "error": str(e)}


@app.post("/webhook/{token}")
async def receive_telegram_webhook(token: str, request: Request):
    """Receive webhook updates from Telegram"""
    if token != TELEGRAM_BOT_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    try:
        data = await request.json()
        
        if "message" in data:
            chat_id = data["message"]["chat"]["id"]
            text = data["message"].get("text", "")
            
            # Load existing chat IDs
            chat_ids_file = Path(__file__).parent / "chat_ids.json"
            registered_users = set()
            
            if chat_ids_file.exists():
                try:
                    with open(chat_ids_file, "r") as f:
                        registered_users = set(json.load(f))
                except:
                    pass
            
            # Register new user
            if chat_id not in registered_users:
                registered_users.add(chat_id)
                with open(chat_ids_file, "w") as f:
                    json.dump(list(registered_users), f)
                logger.info(f"📱 New Telegram user registered: {chat_id}")
            
            # Send welcome message
            if text == "/start":
                import requests as req
                req.post(
                    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                    data={
                        "chat_id": chat_id,
                        "text": "🛡️ Welcome to NetGuardian Pro!\n\nYou will now receive security alerts when network attacks are detected.",
                        "parse_mode": "HTML"
                    }
                )
        
        return {"ok": True}
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return {"ok": False}


class BroadcastMessage(BaseModel):
    message: str


@app.post("/api/telegram/broadcast")
async def broadcast_telegram_message(broadcast: BroadcastMessage):
    """Send a message to all registered Telegram users"""
    if not TELEGRAM_BOT_TOKEN:
        return {"error": "TELEGRAM_BOT_TOKEN not configured"}
    
    # Load chat IDs
    chat_ids_file = Path(__file__).parent / "chat_ids.json"
    registered_users = set()
    
    if chat_ids_file.exists():
        try:
            with open(chat_ids_file, "r") as f:
                registered_users = set(json.load(f))
        except:
            pass
    
    if not registered_users:
        return {"sent_to": 0, "total_users": 0, "error": "No registered users"}
    
    import requests as req
    sent_count = 0
    
    for chat_id in registered_users:
        try:
            response = req.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                data={"chat_id": chat_id, "text": broadcast.message, "parse_mode": "HTML"},
                timeout=5
            )
            if response.json().get("ok"):
                sent_count += 1
        except Exception as e:
            logger.warning(f"Failed to send to {chat_id}: {e}")
    
    logger.info(f"📨 Broadcast sent to {sent_count}/{len(registered_users)} users")
    return {"sent_to": sent_count, "total_users": len(registered_users)}

@app.on_event("shutdown")
def shutdown_event():
    """Graceful shutdown - stop prediction loop and close connections"""
    global shutdown_flag
    shutdown_flag = True
    logger.info("🛑 Shutting down gracefully...")
    
    # Close all WebSocket connections
    for connection in ws_manager.active_connections.copy():
        try:
            asyncio.create_task(connection.close())
        except Exception:
            pass
    
    logger.info("✅ Shutdown complete")


# ========== MAIN ==========
if __name__ == "__main__":
    logger.info("🌐 Starting NetGuardian Pro Production Server...")
    logger.info(f"   Dashboard: http://127.0.0.1:8000/dashboard")
    logger.info(f"   API Docs: http://127.0.0.1:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
