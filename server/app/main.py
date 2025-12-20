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
"""

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Text, Boolean, BigInteger, desc, func
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.dialects.postgresql import JSON
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
import joblib
import logging
import threading
import time
import json
import tempfile
import os
from pathlib import Path
from typing import List, Dict, Optional
import uvicorn

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

# Database - PostgreSQL
DATABASE_URL = "postgresql://postgres:987456@localhost:5432/NetGuardian Pro"

# ML Model files (from server/models/)
XGB_MODEL_PATH = MODEL_DIR / "xgb_model.pkl"
LABEL_ENCODER_PATH = MODEL_DIR / "label_encoder.pkl"
FEATURE_NAMES_PATH = MODEL_DIR / "feature_names.pkl"

# Prediction settings
PREDICTION_INTERVAL = 10  # seconds between prediction checks
CONFIDENCE_HIGH = 0.9
CONFIDENCE_MEDIUM = 0.7

# ========== DATABASE SETUP ==========
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


# ========== ORM MODELS ==========
class RawPacket(Base):
    __tablename__ = "raw_packets"
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, index=True)
    interface = Column(String(50))
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
    dns_qname = Column(String(255))
    dns_qtype = Column(Integer)
    dns_response = Column(Boolean)
    dns_answer_count = Column(Integer)
    dns_answer_size = Column(Integer)
    http_method = Column(String(10))
    http_path = Column(String(500))
    http_status_code = Column(String(10))
    http_host = Column(String(255))
    inserted_at = Column(DateTime, nullable=False, default=datetime.utcnow)


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
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


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
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    resolved = Column(Boolean, default=False, index=True)
    resolved_at = Column(DateTime)


# Create tables
Base.metadata.create_all(engine)

# ========== LOAD ML MODEL ==========
logger.info("=" * 60)
logger.info("🚀 NetGuardian Pro - Production Server")
logger.info("=" * 60)

try:
    logger.info(f"📂 Loading ML model from: {MODEL_DIR}")
    xgb_model = joblib.load(XGB_MODEL_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)
    feature_names = joblib.load(FEATURE_NAMES_PATH)
    
    logger.info(f"✅ XGBoost model loaded successfully")
    logger.info(f"✅ Label encoder loaded: {len(label_encoder.classes_)} classes")
    logger.info(f"✅ Feature names loaded: {len(feature_names)} features")
    logger.info(f"   Classes: {list(label_encoder.classes_)}")
    
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


# ========== HELPER FUNCTIONS ==========
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
        else:
            result["alert_created"] = False
        
        return result
        
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return None


def run_predictions():
    """Background task: Check for unpredicted features and run predictions"""
    while True:
        try:
            db = SessionLocal()
            
            # Find aggregated features without predictions
            unpredicted = db.query(AggregatedFeature).filter(
                AggregatedFeature.predicted_label == None
            ).limit(100).all()
            
            if unpredicted:
                logger.info(f"🔍 Found {len(unpredicted)} features to predict")
                
                for feature in unpredicted:
                    predict_and_alert(db, feature)
                
                db.commit()
                logger.info(f"✅ Processed {len(unpredicted)} predictions")
            
            db.close()
            
        except Exception as e:
            logger.error(f"Prediction loop error: {e}")
        
        time.sleep(PREDICTION_INTERVAL)


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
                agg_df = aggregator.process_file(tmp_path)
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
    db = SessionLocal()
    
    try:
        logger.info(f"📥 Ingesting {len(packets)} packets via direct JSON")
        result = await _process_packets(packets, db)
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
        "model_loaded": MODEL_LOADED,
        "aggregator_available": AGGREGATOR_AVAILABLE,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/health")
def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "model_loaded": MODEL_LOADED,
        "aggregator_available": AGGREGATOR_AVAILABLE,
        "timestamp": datetime.utcnow().isoformat()
    }


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
def api_features(window_size: int = 5):
    """Get aggregated features from aggregated_features table"""
    db = SessionLocal()
    try:
        # Get from aggregated_features
        result = db.query(AggregatedFeature).filter(
            AggregatedFeature.window_size == window_size
        ).order_by(desc(AggregatedFeature.id)).limit(10).all()
        
        if result:
            records = []
            for r in result:
                rec = {
                    'packet_count': r.packet_count or 0,
                    'byte_count': r.byte_count or 0,
                    'packet_rate_pps': r.packet_rate_pps or 0,
                    'byte_rate_bps': r.byte_rate_bps or 0,
                    'avg_packet_size': r.avg_packet_size or 0,
                    'tcp_count': r.tcp_count or 0,
                    'udp_count': r.udp_count or 0,
                    'icmp_count': r.icmp_count or 0,
                    'arp_count': r.arp_count or 0,
                    'unique_dst_ips': r.unique_dst_ips or 0,
                    'unique_dst_ports': r.unique_dst_ports or 0,
                    'tcp_syn_count': r.tcp_syn_count or 0,
                    'tcp_ack_count': r.tcp_ack_count or 0,
                    'syn_rate_pps': r.syn_rate_pps or 0,
                    'syn_to_synack_ratio': r.syn_to_synack_ratio or 0,
                    'dns_query_count': r.dns_query_count or 0,
                    'arp_request_count': r.arp_request_count or 0,
                    'arp_reply_count': r.arp_reply_count or 0,
                    'tcp_ports_hit': r.tcp_ports_hit or 0,
                    'udp_ports_hit': r.udp_ports_hit or 0,
                    'remote_conn_port_hits': r.remote_conn_port_hits or 0,
                }
                records.append(rec)
            
            # Aggregate across all records
            features = {
                'window_size': window_size,
                'record_count': len(records),
                'packet_count': sum(r['packet_count'] for r in records),
                'byte_count': sum(r['byte_count'] for r in records),
                'packet_rate_pps': sum(r['packet_rate_pps'] for r in records),
                'byte_rate_bps': sum(r['byte_rate_bps'] for r in records),
                'avg_packet_size': sum(r['avg_packet_size'] for r in records) / max(1, len(records)),
                'tcp_count': sum(r['tcp_count'] for r in records),
                'udp_count': sum(r['udp_count'] for r in records),
                'icmp_count': sum(r['icmp_count'] for r in records),
                'arp_count': sum(r['arp_count'] for r in records),
                'unique_dst_ips': max(r['unique_dst_ips'] for r in records),
                'unique_dst_ports': max(r['unique_dst_ports'] for r in records),
                'tcp_syn_count': sum(r['tcp_syn_count'] for r in records),
                'tcp_ack_count': sum(r['tcp_ack_count'] for r in records),
                'syn_rate_pps': sum(r['syn_rate_pps'] for r in records),
                'syn_to_synack_ratio': sum(r['syn_to_synack_ratio'] for r in records) / max(1, len(records)),
                'dns_query_count': sum(r['dns_query_count'] for r in records),
                'arp_request_count': sum(r['arp_request_count'] for r in records),
                'arp_reply_count': sum(r['arp_reply_count'] for r in records),
                'tcp_ports_hit': max(r['tcp_ports_hit'] for r in records),
                'udp_ports_hit': max(r['udp_ports_hit'] for r in records),
                'remote_conn_port_hits': sum(r['remote_conn_port_hits'] for r in records),
            }
            
            # Add derived metrics
            syn_only = features['tcp_syn_count'] - features['tcp_ack_count']
            features['connection_failure_rate'] = min(1, syn_only / max(1, features['tcp_syn_count'])) if syn_only > 0 else 0
            
            return features
        
        # Fallback: compute from raw packets
        return _compute_features_from_raw_packets(db)
    finally:
        db.close()


def _compute_features_from_raw_packets(db):
    """Fallback: compute features from raw packets"""
    result = db.query(RawPacket).order_by(desc(RawPacket.id)).limit(1000).all()
    
    if not result:
        return {"error": "No data available"}
    
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
    duration = 5
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
        'tcp_count': sum(1 for p in packets if p['protocol'] == 'TCP'),
        'udp_count': sum(1 for p in packets if p['protocol'] == 'UDP'),
        'icmp_count': sum(1 for p in packets if p['protocol'] and 'ICMP' in str(p['protocol'])),
        'arp_count': sum(1 for p in packets if p['protocol'] == 'ARP'),
        'unique_dst_ips': len(set(p['dst_ip'] for p in packets if p['dst_ip'])),
        'unique_dst_ports': len(set(p['dst_port'] for p in packets if p['dst_port'])),
        'tcp_syn_count': sum(1 for p in packets if p['tcp_syn']),
        'tcp_ack_count': sum(1 for p in packets if p['tcp_ack']),
        'dns_query_count': sum(1 for p in packets if p['dns_query']),
        'source': 'raw_packets_fallback'
    }


@app.get("/api/protocols")
def api_protocols():
    """Get protocol distribution for charts"""
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
def api_top_sources(limit: int = 5):
    """Get top source IPs by packet count"""
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
def api_top_destinations(limit: int = 5):
    """Get top destination IPs by packet count"""
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


@app.get("/api/packets")
def api_packets(page: int = 1, limit: int = 20):
    """Get paginated raw packets"""
    db = SessionLocal()
    try:
        total = db.query(func.count(RawPacket.id)).scalar()
        
        offset = (page - 1) * limit
        result = db.query(RawPacket).order_by(desc(RawPacket.id)).offset(offset).limit(limit).all()
        
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
def api_alerts(limit: int = 50, severity: str = None, resolved: bool = None):
    """Get detected security alerts"""
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
        alert.resolved_at = datetime.utcnow()
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
    if MODEL_LOADED:
        prediction_thread = threading.Thread(target=run_predictions, daemon=True)
        prediction_thread.start()
        logger.info("🔄 Started background prediction loop")
    else:
        logger.warning("⚠️ ML model not loaded - predictions disabled")


# ========== MAIN ==========
if __name__ == "__main__":
    logger.info("🌐 Starting NetGuardian Pro Production Server...")
    logger.info(f"   Dashboard: http://127.0.0.1:8000/dashboard")
    logger.info(f"   API Docs: http://127.0.0.1:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
