from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, Float, Boolean, DateTime, Text, select
from sqlalchemy.orm import sessionmaker
from typing import List, Optional
from datetime import datetime
import pandas as pd
import joblib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ------------------- Database Setup -------------------
# Using SQLite for testing (comment this and uncomment PostgreSQL for production)
DATABASE_URL = "sqlite:///./traffic_analyzer.db"
# DATABASE_URL = "postgresql://postgres:987456@localhost:5432/Traffic_Analyzer"

engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
metadata = MetaData()

# Table 1: Raw Packets (for logging and audit trail)
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

# Table 2: Aggregated Features (from multi_window_aggregator)
aggregated_features_table = Table(
    "aggregated_features", metadata,
    # Identity
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("src_ip", String),
    Column("window_start", DateTime),
    Column("window_end", DateTime),
    Column("window_size", Integer),  # 5, 30, or 180 seconds
    
    # Generic features
    Column("packet_count", Integer),
    Column("packet_rate_pps", Float),
    Column("byte_count", Integer),
    Column("byte_rate_bps", Float),
    Column("avg_packet_size", Float),
    Column("packet_size_variance", Float),
    Column("tcp_count", Integer),
    Column("udp_count", Integer),
    Column("icmp_count", Integer),
    Column("arp_count", Integer),
    Column("unique_dst_ips", Integer),
    Column("unique_dst_ports", Integer),
    
    # TCP/DDoS/Scan features
    Column("tcp_syn_count", Integer),
    Column("tcp_ack_count", Integer),
    Column("syn_rate_pps", Float),
    Column("syn_ack_rate_pps", Float),
    Column("syn_to_synack_ratio", Float),
    Column("half_open_count", Integer),
    Column("sequential_port_count", Integer),
    Column("scan_rate_pps", Float),
    Column("distinct_targets_count", Integer),
    Column("syn_only_ratio", Float),
    Column("icmp_rate_pps", Float),
    Column("udp_rate_pps", Float),
    Column("udp_dest_port_count", Integer),
    
    # Bruteforce features
    Column("ssh_connection_attempts", Integer, nullable=True),
    Column("ftp_connection_attempts", Integer, nullable=True),
    Column("http_login_attempts", Integer, nullable=True),
    Column("login_request_rate", Float, nullable=True),
    Column("failed_login_count", Integer, nullable=True),
    Column("auth_attempts_per_min", Float, nullable=True),
    
    # ARP features
    Column("arp_request_count", Integer, nullable=True),
    Column("arp_reply_count", Integer, nullable=True),
    Column("gratuitous_arp_count", Integer, nullable=True),
    Column("arp_binding_flap_count", Integer, nullable=True),
    Column("arp_reply_without_request_count", Integer, nullable=True),
    
    # DNS features
    Column("dns_query_count", Integer, nullable=True),
    Column("query_rate_qps", Float, nullable=True),
    Column("unique_qnames_count", Integer, nullable=True),
    Column("avg_subdomain_entropy", Float, nullable=True),
    Column("pct_high_entropy_queries", Float, nullable=True),
    Column("txt_record_count", Integer, nullable=True),
    Column("avg_answer_size", Float, nullable=True),
    Column("distinct_record_types", Integer, nullable=True),
    Column("avg_query_interval_ms", Float, nullable=True),
    
    # Slowloris features
    Column("open_conn_count", Integer, nullable=True),
    Column("avg_conn_duration", Float, nullable=True),
    Column("bytes_per_conn", Float, nullable=True),
    Column("partial_http_count", Integer, nullable=True),
    Column("request_completion_ratio", Float, nullable=True),
    
    # ML prediction (added later by ML service)
    Column("predicted_label", String, nullable=True),
    Column("confidence", Float, nullable=True),
    
    Column("created_at", DateTime, default=datetime.utcnow)
)

# Table 3: Detected Alerts (security events from ML)
detected_alerts_table = Table(
    "detected_alerts", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("src_ip", String),
    Column("dst_ip", String, nullable=True),
    Column("attack_type", String),
    Column("confidence", Float),
    Column("severity", String),  # LOW, MEDIUM, HIGH, CRITICAL
    Column("window_size", Integer),
    Column("packet_count", Integer),
    Column("byte_count", Integer),
    Column("details", Text, nullable=True),  # JSON with additional info
    Column("detected_at", DateTime),
    Column("resolved", Boolean, default=False),
    Column("resolved_at", DateTime, nullable=True),
    Column("created_at", DateTime, default=datetime.utcnow)
)

metadata.create_all(engine)
Session = sessionmaker(bind=engine)

# ------------------- Load ML Model -------------------
try:
    model = joblib.load("AI_model.pkl")
    logger.info("ML model loaded successfully")
except Exception as e:
    logger.error(f"Failed to load ML model: {e}")
    model = None

# ------------------- FastAPI App -------------------
app = FastAPI(title="Network Traffic Analyzer API")

# Add CORS middleware for dashboard
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------- Pydantic Models -------------------
class RawPacket(BaseModel):
    timestamp: float
    interface: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    length: int
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    tcp_syn: Optional[bool] = None
    tcp_ack: Optional[bool] = None
    tcp_fin: Optional[bool] = None
    tcp_rst: Optional[bool] = None
    tcp_psh: Optional[bool] = None
    seq: Optional[int] = None
    ack: Optional[int] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    arp_op: Optional[int] = None
    arp_psrc: Optional[str] = None
    arp_pdst: Optional[str] = None
    arp_hwsrc: Optional[str] = None
    arp_hwdst: Optional[str] = None
    dns_query: Optional[bool] = None
    dns_qname: Optional[str] = None
    dns_qtype: Optional[int] = None
    dns_response: Optional[bool] = None
    dns_answer_count: Optional[int] = None
    dns_answer_size: Optional[int] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_status_code: Optional[str] = None
    http_host: Optional[str] = None

class Traffic(BaseModel):
    dest_ip: str
    source_mac: str
    dest_mac: str
    packet_count: int
    packet_per_sec: float
    byte_count: int
    byte_per_sec: float
    tcp_flags: str
    connection_attempts: int
    unique_ports: int
    protocol: str

# ------------------- Helper Functions -------------------
def prepare_features(data):
    """Prepare features for ML model prediction"""
    df = pd.DataFrame([data])
    
    # Ensure text values are strings
    df['protocol'] = df['protocol'].astype(str)
    df['tcp_flags'] = df['tcp_flags'].astype(str)
    
    # One-hot encoding
    df = pd.get_dummies(df, columns=['protocol', 'tcp_flags'])
    
    # Add missing columns according to model
    for col in model.feature_names_in_:
        if col not in df.columns:
            df[col] = 0

    df = df[model.feature_names_in_]
    
    # Convert to float to avoid dtype issues
    df = df.astype(float)
    return df

# ------------------- API Endpoints -------------------

@app.post("/ingest_packets")
async def ingest_packets(packets: List[RawPacket]):
    """
    Ingest batch of raw packets from sniffer.
    1. Store raw packets in raw_packets table
    2. Run aggregation via multi_window_aggregator
    3. Store aggregated features in aggregated_features table
    4. Generate alerts if attacks detected
    """
    import sys
    import os
    
    try:
        # 1. Store raw packets
        with engine.begin() as conn:
            for packet in packets:
                ins = raw_packets_table.insert().values(**packet.dict())
                conn.execute(ins)
        
        logger.info(f"Inserted {len(packets)} raw packets into database")
        
        # 2. Run aggregation
        try:
            # Import aggregator
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from multi_window_aggregator import MultiWindowAggregator
            
            # Convert packets to DataFrame
            packet_dicts = [p.dict() for p in packets]
            df = pd.DataFrame(packet_dicts)
            
            if not df.empty and 'timestamp' in df.columns and 'src_ip' in df.columns:
                # Process with aggregator
                aggregator = MultiWindowAggregator(window_sizes=[5, 30, 180])
                features_df = aggregator.process_dataframe(df)
                
                # 3. Store aggregated features
                if not features_df.empty:
                    with engine.begin() as conn:
                        for _, row in features_df.iterrows():
                            # Convert row to dict, handling NaN values
                            record = {}
                            for col in row.index:
                                val = row[col]
                                if pd.isna(val):
                                    record[col] = None
                                elif hasattr(val, 'isoformat'):  # datetime
                                    record[col] = val
                                else:
                                    record[col] = val
                            
                            ins = aggregated_features_table.insert().values(**record)
                            conn.execute(ins)
                    
                    logger.info(f"Stored {len(features_df)} aggregated feature records")
                    
                    # 4. Generate alerts using XGBoost ML model prediction
                    alerts_generated = 0
                    
                    if model is not None:
                        for _, row in features_df.iterrows():
                            try:
                                # Prepare features for ML prediction
                                feature_cols = [
                                    'packet_count', 'packet_rate_pps', 'byte_count', 'byte_rate_bps',
                                    'avg_packet_size', 'packet_size_variance',
                                    'tcp_count', 'udp_count', 'icmp_count', 'arp_count',
                                    'unique_dst_ips', 'unique_dst_ports',
                                    'tcp_syn_count', 'tcp_ack_count', 'syn_rate_pps', 'syn_ack_rate_pps',
                                    'syn_to_synack_ratio', 'half_open_count', 'sequential_port_count',
                                    'scan_rate_pps', 'distinct_targets_count', 'syn_only_ratio',
                                    'icmp_rate_pps', 'udp_rate_pps', 'udp_dest_port_count',
                                    'dns_query_count', 'query_rate_qps', 'unique_qnames_count',
                                    'avg_subdomain_entropy'
                                ]
                                
                                # Build feature vector
                                feature_values = []
                                for col in feature_cols:
                                    val = row.get(col, 0)
                                    feature_values.append(float(val) if val is not None and not pd.isna(val) else 0.0)
                                
                                # Create DataFrame for prediction
                                X = pd.DataFrame([feature_values], columns=feature_cols)
                                
                                # Add missing columns if model expects them
                                if hasattr(model, 'feature_names_in_'):
                                    for col in model.feature_names_in_:
                                        if col not in X.columns:
                                            X[col] = 0
                                    X = X[model.feature_names_in_]
                                
                                # Get prediction
                                prediction = model.predict(X)[0]
                                
                                # Get confidence (probability) if available
                                confidence = 85.0  # Default
                                if hasattr(model, 'predict_proba'):
                                    proba = model.predict_proba(X)[0]
                                    confidence = float(max(proba) * 100)
                                
                                # Map prediction to attack type
                                attack_type = str(prediction)
                                
                                # Only generate alert if NOT normal traffic
                                if attack_type.lower() not in ['normal', 'benign', '0', 'none']:
                                    # Determine severity based on attack type and confidence
                                    if confidence >= 90:
                                        severity = "CRITICAL"
                                    elif confidence >= 75:
                                        severity = "HIGH"
                                    elif confidence >= 60:
                                        severity = "MEDIUM"
                                    else:
                                        severity = "LOW"
                                    
                                    # Store alert
                                    with engine.begin() as conn:
                                        alert = {
                                            'src_ip': row.get('src_ip'),
                                            'dst_ip': None,
                                            'attack_type': attack_type,
                                            'confidence': confidence,
                                            'severity': severity,
                                            'window_size': row.get('window_size'),
                                            'packet_count': int(row.get('packet_count', 0) or 0),
                                            'byte_count': int(row.get('byte_count', 0) or 0),
                                            'details': None,
                                            'detected_at': datetime.utcnow(),
                                            'resolved': False,
                                            'resolved_at': None
                                        }
                                        ins = detected_alerts_table.insert().values(**alert)
                                        conn.execute(ins)
                                        alerts_generated += 1
                                        
                            except Exception as pred_error:
                                logger.error(f"Prediction error for row: {pred_error}")
                                continue
                    else:
                        logger.warning("ML model not loaded - skipping attack detection")
                    
                    if alerts_generated > 0:
                        logger.warning(f"Generated {alerts_generated} security alerts!")
        
        except Exception as agg_error:
            logger.error(f"Aggregation error (non-fatal): {agg_error}")
            # Continue - aggregation failure shouldn't block packet ingestion
        
        return {
            "status": "success",
            "packets_received": len(packets),
            "message": "Packets stored and processed"
        }
    except Exception as e:
        logger.error(f"Error inserting packets: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict")
def predict_traffic(traffic: Traffic):
    """
    Predict traffic label for aggregated flow.
    This is the original endpoint for pre-aggregated data.
    """
    if model is None:
        raise HTTPException(status_code=503, detail="ML model not loaded")
    
    try:
        data = traffic.dict()
        features = prepare_features(data)
        pred_label = model.predict(features)[0]
        data["predicted_label"] = pred_label

        # Store in traffic_data table
        ins = traffic_table.insert().values(**data)
        with engine.begin() as conn:
            conn.execute(ins)

        return {"predicted_label": pred_label, "data": data}
    except Exception as e:
        logger.error(f"Error in prediction: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ------------------- Web UI Endpoints -------------------

@app.get("/", response_class=HTMLResponse)
def last_10_traffic_page():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <title>Last 10 Traffic Records</title>
    <style>
      table { border-collapse: collapse; width: 100%; }
      th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
      th { background-color: #f2f2f2; }
    </style>
    </head>
    <body>
    <h2>Last 10 Traffic Records</h2>
    <table id="trafficTable">
      <thead>
        <tr>
          <th>ID</th>
          <th>Dest IP</th>
          <th>Source MAC</th>
          <th>Dest MAC</th>
          <th>Packet Count</th>
          <th>Packet/sec</th>
          <th>Byte Count</th>
          <th>Byte/sec</th>
          <th>TCP Flags</th>
          <th>Connection Attempts</th>
          <th>Unique Ports</th>
          <th>Protocol</th>
          <th>Predicted Label</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>

    <script>
    async function fetchTraffic() {
        const response = await fetch('/api/last10');
        const data = await response.json();
        console.log(data);
        const tbody = document.querySelector('#trafficTable tbody');
        tbody.innerHTML = '';
        data.forEach(row => {
            const tr = document.createElement('tr');
            Object.values(row).forEach(val => {
                const td = document.createElement('td');
                td.textContent = val;
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        });
    }
    fetchTraffic();
    setInterval(fetchTraffic, 5000);
    </script>
    </body>
    </html>
    """
    return html_content

@app.get("/alltraffic_page", response_class=HTMLResponse)
def all_traffic_page():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <title>All Traffic Records</title>
    <style>
      table { border-collapse: collapse; width: 100%; }
      th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
      th { background-color: #f2f2f2; }
    </style>
    </head>
    <body>
    <h2>All Traffic Records</h2>
    <table id="trafficTable">
      <thead>
        <tr>
          <th>ID</th>
          <th>Dest IP</th>
          <th>Source MAC</th>
          <th>Dest MAC</th>
          <th>Packet Count</th>
          <th>Packet/sec</th>
          <th>Byte Count</th>
          <th>Byte/sec</th>
          <th>TCP Flags</th>
          <th>Connection Attempts</th>
          <th>Unique Ports</th>
          <th>Protocol</th>
          <th>Predicted Label</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>

    <script>
    async function fetchTraffic() {
        const response = await fetch('/api/alltraffic');
        const data = await response.json();
        console.log(data);
        const tbody = document.querySelector('#trafficTable tbody');
        tbody.innerHTML = '';
        data.forEach(row => {
            const tr = document.createElement('tr');
            Object.values(row).forEach(val => {
                const td = document.createElement('td');
                td.textContent = val;
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        });
    }
    fetchTraffic();
    setInterval(fetchTraffic, 5000);
    </script>
    </body>
    </html>
    """
    return html_content

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    """Serve the NetGuardian Pro analytics dashboard"""
    import os
    
    # Get the directory containing main.py
    base_dir = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(base_dir, "..", "templates")
    
    # Try to serve netguardian_tailwind.html first, fall back to dashboard.html
    template_files = [
        "netguardian_tailwind.html",
        "dashboard.html"
    ]
    
    for template_file in template_files:
        template_path = os.path.join(templates_dir, template_file)
        if os.path.exists(template_path):
            with open(template_path, 'r', encoding='utf-8') as f:
                return HTMLResponse(content=f.read())
    
    return HTMLResponse(content="<h1>Dashboard not found</h1>", status_code=404)

# ------------------- JSON API Endpoints -------------------
@app.get("/api/last10")
def api_last_10_features():
    """Get last 10 aggregated feature records"""
    conn = engine.connect()
    sel = select(aggregated_features_table).order_by(aggregated_features_table.c.id.desc()).limit(10)
    result = conn.execute(sel).mappings().all()
    conn.close()
    return [dict(row) for row in result]

@app.get("/api/alltraffic")
def api_all_features():
    """Get all aggregated feature records"""
    conn = engine.connect()
    sel = select(aggregated_features_table).order_by(aggregated_features_table.c.id.desc()).limit(100)
    result = conn.execute(sel).mappings().all()
    conn.close()
    return [dict(row) for row in result]

@app.get("/api/raw_packets/last/{count}")
def api_last_raw_packets(count: int = 100):
    """Get last N raw packets"""
    conn = engine.connect()
    sel = select(raw_packets_table).order_by(raw_packets_table.c.id.desc()).limit(count)
    result = conn.execute(sel).mappings().all()
    conn.close()
    return [dict(row) for row in result]

@app.get("/health")
def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "timestamp": datetime.utcnow().isoformat()
    }

# ------------------- NetGuardian Dashboard API Endpoints -------------------

@app.get("/api/features")
def api_features(window_size: int = 5):
    """
    Get aggregated features from aggregated_features table.
    Falls back to raw packet calculation if no aggregated data.
    """
    conn = engine.connect()
    
    # Try to get from aggregated_features first
    sel = select(aggregated_features_table).where(
        aggregated_features_table.c.window_size == window_size
    ).order_by(aggregated_features_table.c.id.desc()).limit(10)
    result = conn.execute(sel).mappings().all()
    
    if result:
        # Aggregate the most recent records
        records = [dict(row) for row in result]
        conn.close()
        
        # Sum/average the features across all source IPs
        features = {
            'window_size': window_size,
            'record_count': len(records),
            'packet_count': sum(r.get('packet_count', 0) or 0 for r in records),
            'byte_count': sum(r.get('byte_count', 0) or 0 for r in records),
            'packet_rate_pps': sum(r.get('packet_rate_pps', 0) or 0 for r in records),
            'byte_rate_bps': sum(r.get('byte_rate_bps', 0) or 0 for r in records),
            'avg_packet_size': sum(r.get('avg_packet_size', 0) or 0 for r in records) / max(1, len(records)),
            'tcp_count': sum(r.get('tcp_count', 0) or 0 for r in records),
            'udp_count': sum(r.get('udp_count', 0) or 0 for r in records),
            'icmp_count': sum(r.get('icmp_count', 0) or 0 for r in records),
            'arp_count': sum(r.get('arp_count', 0) or 0 for r in records),
            'unique_dst_ips': max(r.get('unique_dst_ips', 0) or 0 for r in records),
            'unique_dst_ports': max(r.get('unique_dst_ports', 0) or 0 for r in records),
            'tcp_syn_count': sum(r.get('tcp_syn_count', 0) or 0 for r in records),
            'tcp_ack_count': sum(r.get('tcp_ack_count', 0) or 0 for r in records),
            'syn_rate_pps': sum(r.get('syn_rate_pps', 0) or 0 for r in records),
            'syn_to_synack_ratio': sum(r.get('syn_to_synack_ratio', 0) or 0 for r in records) / max(1, len(records)),
            'dns_query_count': sum(r.get('dns_query_count', 0) or 0 for r in records),
            'arp_request_count': sum(r.get('arp_request_count', 0) or 0 for r in records),
            'arp_reply_count': sum(r.get('arp_reply_count', 0) or 0 for r in records),
        }
        
        # Add derived metrics
        features['connection_failure_rate'] = 0
        syn_only = features['tcp_syn_count'] - (features.get('tcp_ack_count', 0) or 0)
        if syn_only > 0:
            features['connection_failure_rate'] = min(1, syn_only / features['tcp_syn_count'])
        
        return features
    
    conn.close()
    
    # Fallback: compute from raw packets (for backward compatibility)
    return _compute_features_from_raw_packets()


def _compute_features_from_raw_packets():
    """Fallback: compute features from raw packets"""
    conn = engine.connect()
    sel = select(raw_packets_table).order_by(raw_packets_table.c.id.desc()).limit(1000)
    result = conn.execute(sel).mappings().all()
    conn.close()
    
    packets = [dict(row) for row in result]
    
    if not packets:
        return {"error": "No data available"}
    
    # Calculate basic metrics
    duration = 5  # default
    if len(packets) >= 2:
        timestamps = [p.get('timestamp', 0) for p in packets if p.get('timestamp')]
        if timestamps:
            duration = max(1, max(timestamps) - min(timestamps))
    
    total_packets = len(packets)
    total_bytes = sum(p.get('length', 0) or 0 for p in packets)
    
    return {
        'packet_count': total_packets,
        'byte_count': total_bytes,
        'packet_rate_pps': total_packets / duration,
        'byte_rate_bps': (total_bytes * 8) / duration,
        'tcp_count': sum(1 for p in packets if p.get('protocol') == 'TCP'),
        'udp_count': sum(1 for p in packets if p.get('protocol') == 'UDP'),
        'icmp_count': sum(1 for p in packets if p.get('protocol') and 'ICMP' in str(p.get('protocol'))),
        'arp_count': sum(1 for p in packets if p.get('protocol') == 'ARP'),
        'unique_dst_ips': len(set(p.get('dst_ip') for p in packets if p.get('dst_ip'))),
        'unique_dst_ports': len(set(p.get('dst_port') for p in packets if p.get('dst_port'))),
        'tcp_syn_count': sum(1 for p in packets if p.get('tcp_syn')),
        'tcp_ack_count': sum(1 for p in packets if p.get('tcp_ack')),
        'dns_query_count': sum(1 for p in packets if p.get('dns_query')),
        'source': 'raw_packets_fallback'
    }


@app.get("/api/alerts")
def api_alerts(limit: int = 50, severity: str = None, resolved: bool = None):
    """
    Get detected security alerts.
    
    Args:
        limit: Maximum number of alerts to return
        severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
        resolved: Filter by resolution status
    """
    conn = engine.connect()
    
    # Build query with optional filters
    query = select(detected_alerts_table)
    
    if severity:
        query = query.where(detected_alerts_table.c.severity == severity.upper())
    
    if resolved is not None:
        query = query.where(detected_alerts_table.c.resolved == resolved)
    
    query = query.order_by(detected_alerts_table.c.id.desc()).limit(limit)
    result = conn.execute(query).mappings().all()
    conn.close()
    
    alerts = []
    for row in result:
        alert = dict(row)
        # Format datetime fields
        if alert.get('detected_at'):
            try:
                alert['detected_at'] = alert['detected_at'].isoformat()
            except:
                pass
        if alert.get('created_at'):
            try:
                alert['created_at'] = alert['created_at'].isoformat()
            except:
                pass
        alerts.append(alert)
    
    return {
        "alerts": alerts,
        "total": len(alerts),
        "filters": {
            "severity": severity,
            "resolved": resolved
        }
    }


@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int):
    """Mark an alert as resolved"""
    from sqlalchemy import update
    
    with engine.begin() as conn:
        stmt = update(detected_alerts_table).where(
            detected_alerts_table.c.id == alert_id
        ).values(resolved=True, resolved_at=datetime.utcnow())
        result = conn.execute(stmt)
    
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return {"status": "resolved", "alert_id": alert_id}


@app.get("/api/alerts/summary")
def api_alerts_summary():
    """Get summary of alerts by type and severity"""
    conn = engine.connect()
    
    # Get all recent alerts
    sel = select(detected_alerts_table).order_by(detected_alerts_table.c.id.desc()).limit(1000)
    result = conn.execute(sel).mappings().all()
    conn.close()
    
    alerts = [dict(row) for row in result]
    
    # Summarize
    by_type = {}
    by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    unresolved = 0
    
    for alert in alerts:
        attack_type = alert.get('attack_type', 'Unknown')
        by_type[attack_type] = by_type.get(attack_type, 0) + 1
        
        severity = alert.get('severity', 'UNKNOWN')
        if severity in by_severity:
            by_severity[severity] += 1
        
        if not alert.get('resolved'):
            unresolved += 1
    
    return {
        "total_alerts": len(alerts),
        "unresolved": unresolved,
        "by_attack_type": by_type,
        "by_severity": by_severity
    }


@app.get("/api/protocols")
def api_protocols():
    """Get protocol distribution for charts"""
    conn = engine.connect()
    sel = select(raw_packets_table).order_by(raw_packets_table.c.id.desc()).limit(1000)
    result = conn.execute(sel).mappings().all()
    conn.close()
    
    packets = [dict(row) for row in result]
    
    # Count protocols
    protocol_counts = {}
    for p in packets:
        proto = p.get('protocol', 'OTHER') or 'OTHER'
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
    
    return {
        "labels": list(protocol_counts.keys()),
        "values": list(protocol_counts.values())
    }


@app.get("/api/top-sources")
def api_top_sources(limit: int = 5):
    """Get top source IPs by packet count"""
    conn = engine.connect()
    sel = select(raw_packets_table).order_by(raw_packets_table.c.id.desc()).limit(1000)
    result = conn.execute(sel).mappings().all()
    conn.close()
    
    packets = [dict(row) for row in result]
    total = len(packets)
    
    # Count by source IP
    ip_counts = {}
    for p in packets:
        ip = p.get('src_ip')
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    # Sort and get top N
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    return [
        {
            "ip": ip,
            "packet_count": count,
            "percentage": round((count / total) * 100, 1) if total > 0 else 0
        }
        for ip, count in sorted_ips
    ]


@app.get("/api/top-destinations")
def api_top_destinations(limit: int = 5):
    """Get top destination IPs by packet count"""
    conn = engine.connect()
    sel = select(raw_packets_table).order_by(raw_packets_table.c.id.desc()).limit(1000)
    result = conn.execute(sel).mappings().all()
    conn.close()
    
    packets = [dict(row) for row in result]
    total = len(packets)
    
    # Count by destination IP
    ip_counts = {}
    for p in packets:
        ip = p.get('dst_ip')
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    # Sort and get top N
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    return [
        {
            "ip": ip,
            "packet_count": count,
            "percentage": round((count / total) * 100, 1) if total > 0 else 0
        }
        for ip, count in sorted_ips
    ]


@app.get("/api/top-ports")
def api_top_ports(limit: int = 5):
    """Get top destination ports by packet count"""
    conn = engine.connect()
    sel = select(raw_packets_table).order_by(raw_packets_table.c.id.desc()).limit(1000)
    result = conn.execute(sel).mappings().all()
    conn.close()
    
    packets = [dict(row) for row in result]
    total = len(packets)
    
    # Common port to service mapping
    port_services = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    
    # Count by destination port
    port_counts = {}
    for p in packets:
        port = p.get('dst_port')
        if port:
            port_counts[port] = port_counts.get(port, 0) + 1
    
    # Sort and get top N
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


@app.get("/api/packets")
def api_packets(page: int = 1, limit: int = 20):
    """Get paginated raw packets"""
    conn = engine.connect()
    
    # Get total count
    from sqlalchemy import func
    count_sel = select(func.count()).select_from(raw_packets_table)
    total = conn.execute(count_sel).scalar()
    
    # Get paginated results
    offset = (page - 1) * limit
    sel = select(raw_packets_table).order_by(raw_packets_table.c.id.desc()).offset(offset).limit(limit)
    result = conn.execute(sel).mappings().all()
    conn.close()
    
    packets = []
    for row in result:
        p = dict(row)
        # Format timestamp
        if p.get('timestamp'):
            try:
                ts = datetime.fromtimestamp(p['timestamp'])
                p['timestamp'] = ts.strftime('%Y-%m-%d %H:%M:%S')
            except:
                pass
        # Add flags field for display
        p['flags'] = p.get('tcp_flags', '--')
        packets.append(p)
    
    return {
        "packets": packets,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit if total else 0
    }


@app.get("/api/ml/predict")
def api_ml_predict():
    """
    Get ML prediction based on recent traffic features.
    Returns attack type, confidence, and threat level.
    """
    # Get features first
    features = api_features()
    
    if "error" in features:
        return {
            "attack_type": "Unknown",
            "confidence": 0,
            "threat_level": "NONE",
            "message": "No traffic data available"
        }
    
    if model is None:
        # Return a heuristic-based prediction if model not loaded
        threat_indicators = 0
        
        # Check for DDoS indicators
        if features.get('packet_rate_pps', 0) > 1000:
            threat_indicators += 2
        if features.get('syn_rate_pps', 0) > 100:
            threat_indicators += 2
        if features.get('connection_failure_rate', 0) > 0.5:
            threat_indicators += 1
        
        # Check for port scan indicators
        if features.get('unique_dst_ports', 0) > 50:
            threat_indicators += 2
        
        # Determine threat level
        if threat_indicators >= 4:
            return {
                "attack_type": "Potential DDoS",
                "confidence": 75.0,
                "threat_level": "HIGH"
            }
        elif threat_indicators >= 2:
            return {
                "attack_type": "Suspicious Activity",
                "confidence": 50.0,
                "threat_level": "MEDIUM"
            }
        else:
            return {
                "attack_type": "Normal",
                "confidence": 90.0,
                "threat_level": "NONE"
            }
    
    # If model is loaded, use it for prediction
    try:
        # Prepare features for model
        data = {
            'packet_count': features.get('packet_count', 0),
            'packet_per_sec': features.get('packet_rate_pps', 0),
            'byte_count': features.get('byte_count', 0),
            'byte_per_sec': features.get('byte_rate_bps', 0),
            'tcp_flags': 'SYN' if features.get('tcp_syn_count', 0) > 0 else 'NONE',
            'connection_attempts': features.get('tcp_syn_count', 0),
            'unique_ports': features.get('unique_dst_ports', 0),
            'protocol': 'TCP'
        }
        
        model_features = prepare_features(data)
        prediction = model.predict(model_features)[0]
        
        # Get probability if available
        confidence = 85.0
        if hasattr(model, 'predict_proba'):
            proba = model.predict_proba(model_features)[0]
            confidence = max(proba) * 100
        
        # Determine threat level
        threat_level = "NONE"
        if prediction.lower() != "normal":
            if confidence > 80:
                threat_level = "HIGH"
            elif confidence > 60:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"
        
        return {
            "attack_type": prediction,
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


# ------------------- Serve Static Files -------------------
from fastapi.staticfiles import StaticFiles
import os

# Mount static files directory
static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

