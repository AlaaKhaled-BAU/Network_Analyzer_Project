import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ------------------- Database Setup -------------------
DATABASE_URL = "postgresql://postgres:987456@localhost:5432/Traffic_Analyzer"
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
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

# Table 2: Aggregated Traffic Flows (for ML predictions)
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

# Table 3: 5-Second Window Predictions
predictions_5s_table = Table(
    "predictions_5s", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("window_start", DateTime),
    Column("window_end", DateTime),
    Column("total_packets", Integer),
    Column("unique_src_ips", Integer),
    Column("unique_dst_ips", Integer),
    Column("flow_count", Integer),
    Column("avg_packet_rate", Float),
    Column("avg_byte_rate", Float),
    Column("predicted_label", String),
    Column("confidence", Float, nullable=True),
    Column("features_json", Text, nullable=True),
    Column("created_at", DateTime, default=datetime.utcnow)
)

# Table 4: 30-Second Window Predictions  
predictions_30s_table = Table(
    "predictions_30s", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("window_start", DateTime),
    Column("window_end", DateTime),
    Column("total_packets", Integer),
    Column("unique_src_ips", Integer),
    Column("unique_dst_ips", Integer),
    Column("flow_count", Integer),
    Column("avg_packet_rate", Float),
    Column("avg_byte_rate", Float),
    Column("predicted_label", String),
    Column("confidence", Float, nullable=True),
    Column("features_json", Text, nullable=True),
    Column("created_at", DateTime, default=datetime.utcnow)
)

# Table 5: 3-Minute Window Predictions
predictions_3min_table = Table(
    "predictions_3min", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("window_start", DateTime),
    Column("window_end", DateTime),
    Column("total_packets", Integer),
    Column("unique_src_ips", Integer),
    Column("unique_dst_ips", Integer),
    Column("flow_count", Integer),
    Column("avg_packet_rate", Float),
    Column("avg_byte_rate", Float),
    Column("predicted_label", String),
    Column("confidence", Float, nullable=True),
    Column("features_json", Text, nullable=True),
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
    Stores them in raw_packets table for logging.
    """
    try:
        with engine.begin() as conn:
            for packet in packets:
                ins = raw_packets_table.insert().values(**packet.dict())
                conn.execute(ins)
        
        logger.info(f"Inserted {len(packets)} raw packets into database")
        return {
            "status": "success",
            "packets_received": len(packets),
            "message": "Packets stored in raw_packets table"
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

# ------------------- JSON API Endpoints -------------------
@app.get("/api/last10")
def api_last_10_traffic():
    conn = engine.connect()
    sel = select(traffic_table).order_by(traffic_table.c.id_num.desc()).limit(10)
    result = conn.execute(sel).mappings().all()
    conn.close()
    return [dict(row) for row in result]

@app.get("/api/alltraffic")
def api_all_traffic():
    conn = engine.connect()
    sel = select(traffic_table).order_by(traffic_table.c.id_num.desc())
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
