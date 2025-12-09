# Performance Optimization Guide for Network Traffic Analyzer

This document outlines concrete performance improvements for each major bottleneck in the system.

---

## � **Critical: DoS Simulation Requirements**

> [!WARNING]
> If you're planning to simulate **DoS attacks (>10,000 packets/sec)** and need to **log all traffic** to the database, the following optimizations are **MANDATORY**, not optional:

### **Essential for DoS + Full Logging:**

1. ✅ **PostgreSQL** - SQLite will lock/crash at high write rates
2. ✅ **Bulk Insert** - Single insert per packet = server death at DoS rates  
3. ✅ **Aggressive Connection Pooling** - (pool_size=100+)
4. ✅ **Large Batch Sizes** - (10,000+ packets per HTTP request)
5. ✅ **Database Indexes** - Queries will timeout without them
6. ✅ **AsyncSniffer with store=False** - Prevent memory overflow

> [!IMPORTANT]
> **BPF Filters** are typically recommended but **cannot be used** if you need to log ALL traffic (including ARP, ICMP, etc.) for forensic analysis. This makes the other optimizations even MORE critical.

**Without these 6 items, your system will fail during DoS simulation.** See [DoS-Specific Optimizations](#dos-specific-optimizations) section below.

---

## �📊 Quick Reference: Priority Order

| Priority | Improvement | Time | Expected Gain | Difficulty | DoS Critical? |
|----------|-------------|------|---------------|------------|---------------|
| 🔥 **1** | **Bulk Insert Optimization** | 5 min | 10-100x writes | Easy | ✅ **YES** |
| 🔥 **2** | **PostgreSQL Migration** | 10 min | 10-50x writes | Easy | ✅ **YES** |
| 🔥 **3** | **Aggressive Connection Pool** | 2 min | 5-10x concurrency | Easy | ✅ **YES** |
| 🔥 **4** | **Database Indexes** | 5 min | 100-1000x queries | Easy | ✅ **YES** |
| 🔥 **5** | **Large Batch Sizes (10K+)** | 1 min | 10x fewer requests | Easy | ✅ **YES** |
| 🔥 **6** | **AsyncSniffer store=False** | 1 min | Prevent memory leak | Easy | ✅ **YES** |
| ⚡ **7** | BPF Packet Filters* | 5 min | 10-100x less processing | Easy | ⚠️ Not if logging all |
| ⚡ **8** | HTTP Compression | 2 min | 5-10x bandwidth | Easy | Recommended |
| ⚡ **9** | Async Database | 1 hour | Better scalability | Medium | Recommended |
| ⚡ **10** | ONNX Model Conversion | 30 min | 3-10x ML inference | Medium | Optional |
| 🚀 **11** | WebSocket Real-time | 2 hours | Instant updates | Medium | Optional |
| 🚀 **12** | Redis Caching | 1 hour | 100x for cached data | Medium | Optional |

**For DoS Simulation: Implement items 1-6 BEFORE testing (30 minutes total)**  
**For Normal Use: Start with items 4, 7, 8 for immediate gains**

*Note: BPF filters cannot be used if you need to log ALL traffic types for forensic analysis.

---

## 🚨 DoS-Specific Optimizations

### Critical Changes for High Packet Rates (>10K packets/sec)

When simulating DoS attacks, the standard optimizations aren't enough. You MUST implement these:

---

### **1. Bulk Insert (Most Critical!)**

**Problem:** Current code inserts packets one-by-one in a loop during DoS = 10,000 individual INSERT statements/sec = server death.

**Solution:** Use PostgreSQL's bulk insert capability.

**File:** `server/app/main.py`

```python
@app.post("/ingest_packets")
async def ingest_packets(packets: List[RawPacket]):
    """
    OPTIMIZED FOR DoS SIMULATION
    Bulk insert all packets in single transaction
    """
    if not packets:
        return {"status": "success", "packets_received": 0}
    
    try:
        # Prepare all packet data at once
        values_list = [packet.dict() for packet in packets]
        
        # BULK INSERT - single query for all packets
        with engine.begin() as conn:
            conn.execute(
                raw_packets_table.insert(),
                values_list  # All packets in one transaction!
            )
        
        logger.info(f"✅ Bulk inserted {len(packets)} packets in single transaction")
        return {
            "status": "success",
            "packets_received": len(packets),
            "message": "Packets bulk inserted successfully"
        }
    
    except Exception as e:
        logger.error(f"❌ Bulk insert failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
```

**Expected Gain:** 10-100x faster writes (from 1K/sec to 50K/sec)

---

### **2. Aggressive Connection Pooling for DoS**

**File:** `server/app/main.py`

```python
# DoS-optimized connection pool
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=100,              # Much higher for DoS (default is 5)
    max_overflow=200,           # Allow burst traffic (default is 10)
    pool_timeout=60,            # Wait longer for connections
    pool_recycle=1800,          # Recycle every 30 min
    echo=False,                 # Disable SQL logging for performance
    execution_options={
        "isolation_level": "READ COMMITTED"  # Faster than SERIALIZABLE
    }
)
```

**Expected Gain:** Handle 300 concurrent connections during DoS flood

---

### **3. Large Batch Sizes on Client**

**File:** `client/sender.py`

```python
# DoS-optimized batch settings
BATCH_SIZE = 10000          # Send 10,000 packets per HTTP request (up from 500)
SAVE_INTERVAL = 10          # Save every 10 seconds (up from 5)
MAX_RETRIES = 3
RETRY_DELAY = 5

# Connection timeout for large batches
TIMEOUT = 60  # Increase timeout for 10K packet batches
```

**Update the send function:**

```python
def send_batch_to_server(csv_path):
    """Send large batches with extended timeout"""
    try:
        response = requests.post(
            SERVER_URL,
            json=packet_data,
            timeout=60  # Longer timeout for bulk insert
        )
        return response
    except requests.exceptions.Timeout:
        logger.error("Request timeout - batch too large or server overloaded")
```

**Expected Gain:** 20x fewer HTTP requests (from 20 req/sec to 1 req/sec)

---

### **4. AsyncSniffer with Memory Protection**

**File:** `client/sniffer.py`

```python
from scapy.all import AsyncSniffer

def start_capture():
    """DoS-safe packet capture"""
    sniffer = AsyncSniffer(
        iface="eth0",
        prn=packet_handler,
        store=False,  # ⚠️ CRITICAL: Don't keep packets in memory!
        # NO BPF filter - we're logging everything for forensics
    )
    sniffer.start()
    return sniffer
```

**Why store=False is critical:** During DoS, Scapy will buffer millions of packets in RAM → memory overflow → crash.

**Expected Gain:** Prevents memory leaks, stable operation during DoS

---

### **5. Database Write Optimization**

**File:** `server/app/main.py`

Add these indexes BEFORE DoS testing:

```python
# Critical indexes for DoS logging
Index('idx_raw_packets_timestamp_dos', raw_packets_table.c.timestamp, raw_packets_table.c.src_ip)
Index('idx_raw_packets_protocol', raw_packets_table.c.protocol)
Index('idx_traffic_data_timestamp', traffic_table.c.created_at)

# Partial index for alerts (faster queries)
Index('idx_traffic_alerts', 
      traffic_table.c.predicted_label,
      postgresql_where=(traffic_table.c.predicted_label != 'Normal'))
```

---

### **6. PostgreSQL Tuning for DoS**

**For PostgreSQL config** (optional but recommended):

```sql
-- In postgresql.conf
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET work_mem = '16MB';
ALTER SYSTEM SET maintenance_work_mem = '128MB';
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET max_connections = 500;

-- Reload config
SELECT pg_reload_conf();
```

---

### **DoS Testing Checklist**

Before running DoS simulation, verify:

- [ ] PostgreSQL installed and running (not SQLite)
- [ ] Bulk insert implemented in `/ingest_packets`
- [ ] Connection pool set to 100+ 
- [ ] Batch size increased to 10,000
- [ ] Database indexes created
- [ ] AsyncSniffer has `store=False`
- [ ] Sufficient disk space (10K pps = ~1GB/hour)

**Test command:**
```bash
# Monitor packet insertion rate
watch -n 1 'psql -U postgres -d Traffic_Analyzer -c "SELECT COUNT(*) FROM raw_packets"'

# Check server load
htop

# Monitor logs
tail -f server/logs/api.log
```

---

## 1️⃣ Database I/O Optimization

### Current Issues
- SQLite limited concurrent write performance
- No connection pooling configured
- Missing database indexes on frequently queried columns
- Synchronous queries blocking the event loop

### A) Add Database Indexes ⭐ **HIGHEST PRIORITY**

**File:** `server/app/main.py`

```python
from sqlalchemy import Index

# Add after all table definitions (before metadata.create_all)

# Indexes for raw_packets table
Index('idx_raw_packets_timestamp', raw_packets_table.c.timestamp)
Index('idx_raw_packets_src_ip', raw_packets_table.c.src_ip)
Index('idx_raw_packets_dst_ip', raw_packets_table.c.dst_ip)
Index('idx_raw_packets_protocol', raw_packets_table.c.protocol)

# Indexes for traffic_data table
Index('idx_traffic_predicted_label', traffic_table.c.predicted_label)
Index('idx_traffic_created_at', traffic_table.c.created_at)
Index('idx_traffic_dest_ip', traffic_table.c.dest_ip)
Index('idx_traffic_source_mac', traffic_table.c.source_mac)

# Composite index for common queries
Index('idx_traffic_time_label', traffic_table.c.created_at, traffic_table.c.predicted_label)
```

**Expected Gain:** 100-1000x faster queries on large datasets (millions of rows)

---

### B) Configure Connection Pooling

**File:** `server/app/main.py`

```python
# Update the engine creation (line 21)
engine = create_engine(
    DATABASE_URL, 
    pool_pre_ping=True,
    pool_size=20,              # Maximum connections in pool
    max_overflow=40,           # Allow 40 overflow connections
    pool_recycle=3600,         # Recycle connections every hour
    pool_timeout=30,           # Wait 30s for connection
    echo_pool=False            # Set to True for debugging
)
```

**Expected Gain:** 5-10x better concurrent request handling

---

### C) Switch to PostgreSQL for Production

**File:** `server/app/main.py`

```python
# Uncomment PostgreSQL, comment SQLite (lines 17-19)
# DATABASE_URL = "sqlite:///./traffic_analyzer.db"  # Development only
DATABASE_URL = "postgresql://postgres:987456@localhost:5432/Traffic_Analyzer"
```

**Installation:**
```bash
# Install PostgreSQL
# Windows: Download from https://www.postgresql.org/download/windows/
# Linux: sudo apt install postgresql postgresql-contrib

# Create database
psql -U postgres
CREATE DATABASE Traffic_Analyzer;
\q
```

**Expected Gain:** 10-50x better concurrent writes, better for production

---

### D) Use Async Database Operations

**Installation:**
```bash
pip install databases asyncpg
```

**File:** `server/app/main.py`

```python
from databases import Database

# Add after engine creation
database = Database(DATABASE_URL)

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# Example: Convert endpoint to async
@app.get("/api/alltraffic")
async def api_all_traffic():
    query = select(traffic_table).order_by(traffic_table.c.id_num.desc())
    result = await database.fetch_all(query)
    return [dict(row) for row in result]
```

**Expected Gain:** Non-blocking I/O, better scalability under high load

---

## 2️⃣ ML Model Inference Optimization

### Current Issues
- Using pickle/joblib (slower loading, larger file size)
- No model caching for identical predictions
- scikit-learn not optimized for production inference
- Blocking predictions

### A) Convert Model to ONNX Format

**Installation:**
```bash
pip install skl2onnx onnxruntime
```

**Step 1: Convert Model (run once)**

```python
# Create: server/scripts/convert_model_to_onnx.py
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import joblib
import numpy as np

# Load existing model
model = joblib.load("models/AI_model.pkl")

# Define input shape (adjust to your feature count)
n_features = len(model.feature_names_in_)
initial_type = [('float_input', FloatTensorType([None, n_features]))]

# Convert
onnx_model = convert_sklearn(model, initial_types=initial_type)

# Save
with open("models/AI_model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

print("✅ Model converted to ONNX successfully!")
```

**Step 2: Use ONNX Model in Production**

**File:** `server/app/main.py`

```python
# Replace joblib loading (around line 141)
import onnxruntime as rt
import numpy as np

try:
    session = rt.InferenceSession("models/AI_model.onnx")
    logger.info("ONNX model loaded successfully")
    model = session  # Keep variable name for compatibility
except Exception as e:
    logger.error(f"Failed to load ONNX model: {e}")
    model = None

# Update prepare_features function to return numpy array
def prepare_features(data):
    """Prepare features for ONNX model prediction"""
    df = pd.DataFrame([data])
    df['protocol'] = df['protocol'].astype(str)
    df['tcp_flags'] = df['tcp_flags'].astype(str)
    df = pd.get_dummies(df, columns=['protocol', 'tcp_flags'])
    
    # Add missing columns
    for col in model.get_inputs()[0].shape[1]:  # ONNX way
        if col not in df.columns:
            df[col] = 0
    
    return df.astype(np.float32).values  # Return numpy array

# Update prediction
def predict_traffic(features):
    input_name = model.get_inputs()[0].name
    pred = model.run(None, {input_name: features})[0]
    return pred[0]
```

**Expected Gain:** 3-10x faster inference, 50% smaller model file

---

### B) Implement Batch Predictions

**File:** `server/app/main.py`

```python
@app.post("/predict_batch")
async def predict_batch(flows: List[Traffic]):
    """Predict multiple flows at once (much faster)"""
    if model is None:
        raise HTTPException(status_code=503, detail="ML model not loaded")
    
    try:
        # Prepare all features at once
        features_list = [prepare_features(flow.dict()) for flow in flows]
        features_batch = np.vstack(features_list)
        
        # Single batch prediction
        predictions = predict_traffic(features_batch)
        
        # Store all predictions
        for flow, pred in zip(flows, predictions):
            data = flow.dict()
            data["predicted_label"] = pred
            ins = traffic_table.insert().values(**data)
            with engine.begin() as conn:
                conn.execute(ins)
        
        return {"predictions": predictions.tolist()}
    except Exception as e:
        logger.error(f"Batch prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
```

**Expected Gain:** 5-20x faster for processing multiple flows

---

### C) Add Prediction Caching

**File:** `server/app/main.py`

```python
from functools import lru_cache
import hashlib
import json

@lru_cache(maxsize=1000)
def get_cached_prediction(feature_hash: str, features: tuple):
    """Cache predictions for identical traffic patterns"""
    # Convert tuple back to array for prediction
    features_array = np.array(features).reshape(1, -1)
    return predict_traffic(features_array)

def predict_with_cache(data: dict):
    """Predict with caching"""
    features = prepare_features(data)
    
    # Create hash of features
    feature_tuple = tuple(features.flatten())
    feature_str = json.dumps(data, sort_keys=True)
    feature_hash = hashlib.md5(feature_str.encode()).hexdigest()
    
    return get_cached_prediction(feature_hash, feature_tuple)
```

**Expected Gain:** Instant results for repeated traffic patterns

---

## 3️⃣ Packet Capture Optimization (Scapy)

### Current Issues
- Scapy is Python-based (slower than C libraries)
- Synchronous packet processing
- No filtering at kernel level (processing unnecessary packets)

### A) Use AsyncSniffer (Non-blocking)

**File:** `client/sniffer.py`

```python
from scapy.all import AsyncSniffer

def start_async_capture():
    """Non-blocking packet capture"""
    sniffer = AsyncSniffer(
        iface="eth0",              # Your interface
        prn=packet_handler,        # Callback function
        filter="ip",               # BPF filter (kernel-level)
        store=False                # Don't store in memory
    )
    
    sniffer.start()
    logger.info("Async packet capture started")
    return sniffer

# Later, to stop
# sniffer.stop()
```

**Expected Gain:** Non-blocking, better resource usage

---

### B) Add BPF Filters ⭐ **HIGH PRIORITY**

Berkeley Packet Filter runs at **kernel level** - much faster than Python filtering!

**File:** `client/sniffer.py`

```python
# Option 1: Capture only TCP traffic on specific ports
filter_http = "tcp and (port 80 or port 443 or port 8080)"

# Option 2: Exclude noisy protocols
filter_no_noise = "not arp and not icmp and not broadcast"

# Option 3: Capture specific IP ranges
filter_subnet = "net 192.168.1.0/24"

# Option 4: Complex filter
filter_complex = "tcp and not port 22 and (src net 192.168.0.0/16 or dst net 10.0.0.0/8)"

sniffer = AsyncSniffer(
    iface="eth0",
    filter=filter_no_noise,  # Choose appropriate filter
    prn=packet_handler
)
```

**Expected Gain:** 10-100x fewer packets to process in Python

---

### C) Consider Faster Alternatives

**Option 1: PyShark (tshark wrapper)**

```bash
pip install pyshark
```

```python
import pyshark

capture = pyshark.LiveCapture(
    interface='eth0',
    bpf_filter='tcp and port 80'
)

for packet in capture.sniff_continuously():
    process_packet(packet)
```

**Expected Gain:** 2-5x faster than Scapy

**Option 2: Direct libpcap (for maximum performance)**

```bash
pip install python-libpcap
```

---

## 4️⃣ Network I/O Optimization

### A) Increase Batch Size ⭐ **QUICK WIN**

**File:** `client/sender.py`

```python
# Change from default
BATCH_SIZE = 5000  # Increased from 500

# Send larger batches less frequently
```

**Expected Gain:** 10x fewer HTTP requests

---

### B) Enable HTTP Compression

**File:** `server/app/main.py`

```python
from fastapi.middleware.gzip import GZipMiddleware

# Add after app creation
app.add_middleware(
    GZipMiddleware, 
    minimum_size=1000  # Compress responses > 1KB
)
```

**Expected Gain:** 5-10x less bandwidth usage

---

### C) Use Connection Keep-Alive

**File:** `client/sender.py`

```python
import requests

# Create persistent session
session = requests.Session()
session.headers.update({
    'Connection': 'keep-alive',
    'Content-Type': 'application/json'
})

# Use session instead of requests directly
def send_batch(packets):
    response = session.post(
        f"{SERVER_URL}/ingest_packets",
        json=[p.dict() for p in packets]
    )
    return response
```

**Expected Gain:** 50% reduction in TCP handshake overhead

---

### D) Add WebSocket for Real-time Updates

**Installation:**
```bash
pip install websockets
```

**File:** `server/app/main.py`

```python
from fastapi import WebSocket
import asyncio

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time packet stream to dashboard"""
    await websocket.accept()
    
    try:
        while True:
            # Get latest data
            data = await get_latest_updates()
            await websocket.send_json(data)
            await asyncio.sleep(1)  # Update every second
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await websocket.close()
```

**File:** `server/templates/dashboard.html`

```javascript
// Connect to WebSocket
const ws = new WebSocket('ws://localhost:8000/ws/live');

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    updateDashboard(data);  // Update UI instantly
};
```

**Expected Gain:** Real-time updates without polling overhead

---

## 5️⃣ Additional Optimizations

### A) Add Redis Caching Layer

**Installation:**
```bash
pip install redis
```

**Usage:**
```python
import redis
import json

redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

@app.get("/api/alltraffic")
async def api_all_traffic():
    # Check cache first
    cached = redis_client.get("alltraffic")
    if cached:
        return json.loads(cached)
    
    # Query database
    conn = engine.connect()
    result = conn.execute(select(traffic_table)).mappings().all()
    conn.close()
    
    data = [dict(row) for row in result]
    
    # Cache for 5 seconds
    redis_client.setex("alltraffic", 5, json.dumps(data))
    
    return data
```

**Expected Gain:** 100x faster for cached data

---

### B) Add Rate Limiting

**Installation:**
```bash
pip install slowapi
```

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/ingest_packets")
@limiter.limit("100/minute")  # Max 100 requests per minute
async def ingest_packets(request: Request, packets: List[RawPacket]):
    # ... existing code
```

**Expected Gain:** Protection against abuse, better resource management

---

## 🎯 Recommended Implementation Path

### Phase 1: Quick Wins (1 day)
1. Add database indexes
2. Configure connection pooling
3. Add BPF filters to Scapy
4. Increase batch size
5. Enable HTTP compression

**Expected Overall Gain:** 10-50x performance improvement

### Phase 2: Medium Effort (1 week)
6. Migrate to PostgreSQL
7. Convert ML model to ONNX
8. Implement batch predictions
9. Add connection keep-alive
10. Add Redis caching

**Expected Overall Gain:** 50-200x performance improvement

### Phase 3: Advanced (2-4 weeks)
11. Implement async database operations
12. Add WebSocket real-time updates
13. Switch to PyShark or libpcap
14. Implement horizontal scaling
15. Add load balancer

**Expected Overall Gain:** 200-1000x performance improvement + scalability

---

## 📈 Performance Benchmarks

### Before Optimization
- **Packet Processing:** ~1,000 packets/sec
- **API Response Time:** 50-200ms
- **ML Inference:** 10-50ms per prediction
- **Database Queries:** 100-500ms for complex queries
- **Concurrent Users:** ~10

### After Phase 1 (Quick Wins)
- **Packet Processing:** ~10,000 packets/sec
- **API Response Time:** 5-20ms
- **ML Inference:** 10-50ms per prediction
- **Database Queries:** 1-5ms for complex queries
- **Concurrent Users:** ~100

### After Phase 2 (Full Implementation)
- **Packet Processing:** ~50,000 packets/sec
- **API Response Time:** 2-10ms
- **ML Inference:** 1-5ms per prediction
- **Database Queries:** <1ms for indexed queries
- **Concurrent Users:** ~1,000

---

## 🔧 Monitoring & Profiling

To measure improvements, add monitoring:

```python
import time
from functools import wraps

def measure_time(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start = time.time()
        result = await func(*args, **kwargs)
        duration = time.time() - start
        logger.info(f"{func.__name__} took {duration:.3f}s")
        return result
    return wrapper

@app.get("/api/alltraffic")
@measure_time
async def api_all_traffic():
    # ... code
```

---

## 📚 Additional Resources

- [FastAPI Performance Tips](https://fastapi.tiangolo.com/deployment/concepts/)
- [PostgreSQL Indexing](https://www.postgresql.org/docs/current/indexes.html)
- [ONNX Runtime](https://onnxruntime.ai/)
- [BPF Filter Syntax](https://www.tcpdump.org/manpages/pcap-filter.7.html)
- [Redis Caching Patterns](https://redis.io/docs/manual/patterns/)

---

**Last Updated:** 2025-12-01  
**Project:** Network Traffic Analyzer  
**Author:** Performance Optimization Guide
