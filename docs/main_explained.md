# main.py - FastAPI Server & System Core

## 📋 Overview

**File:** `server/app/main.py`  
**Purpose:** The central nervous system of NetGuardian Pro.  
**Role:**  
1.  **API Server:** Serves REST endpoints for historical data.
2.  **WebSocket Server:** Pushes real-time metrics to the dashboard.
3.  **ML Engine:** Runs background threads for threat detection.
4.  **Database Manager:** Handles PostgreSQL connections and ORM models.

---

## 🏗️ Architecture: Hybrid Real-Time System

The server uses a **Hybrid Architecture** to balance load and responsiveness:

```mermaid
graph TD
    Client[Browser Dashboard]
    
    subgraph "FastAPI Server (main.py)"
        WS[WebSocket Endpoint /ws/dashboard]
        REST[REST APIs /api/*]
        ML[ML Prediction Thread]
        Agg[MultiWindow Aggregator]
    end
    
    DB[(PostgreSQL)]
    
    Client -->|1. Initial Load (Historical)| REST
    Client <-->|2. Real-Time Updates (Push)| WS
    
    REST --> DB
    WS --> DB
    
    ML -->|Read Features| DB
    ML -->|Write Alerts| DB
```

---

## 🔧 Key Components

### **1. Real-Time WebSockets (Limitless Updates)**
*   **Endpoint**: `/ws/dashboard`
*   **Manager**: `ConnectionManager` (Handles multiple client connections)
*   **Function**: Pushes a JSON payload every 2 seconds containing:
    *   Total Packets Processed
    *   Active Alerts
    *   System Health Status

### **2. REST API Endpoints (Historical Data)**
Used for populating charts and tables on page load:
*   `GET /api/features`: Aggregated traffic stats (Latency, Bandwidth, Jitter).
*   `GET /api/protocols`: Protocol distribution (TCP/UDP/ICMP).
*   `GET /api/top-sources`: Top talker IPs.
*   `GET /api/alerts`: History of detected threats.

### **3. ML Threat Detection & Cascading Aggregation**
*   **Model**: XGBoost (`xgboost_model.json`)
*   **Prediction Trigger**: Called **inline** immediately after each 30s/180s aggregation completes.
*   **Background Threads**:
    1.  `run_predictions`: Fallback thread that processes any unpredicted 5s features (polls every 10s).
    2.  `run_cascading_aggregation`: Builds 30s/180s windows from 6/36 complete 5s records, then calls ML inline.
*   **Files**:
    *   `models/xgboost_model.json` (The Brain)
    *   `models/label_encoder.pkl` (The Translator)

### **4. Database Models (SQLAlchemy)**
*   **RawPacket**: Full fidelity storage of every frame.
*   **AggregatedFeature**: Compressed statistical summaries (5s/30s/180s windows).
*   **DetectedAlert**: Security incidents found by ML.
*   **Index**: `idx_agg_window_src_start` on `(window_size, src_ip, window_start)` for fast aggregation queries.

---

## ⚙️ Configuration & Environment

The server creates its configuration dynamically from `.env`:

```env
DATABASE_URL=postgresql://postgres:password@localhost:5432/NetGuardian Pro
ML_MODEL_PATH=server/models/xgboost_model.json
```

---

## 🚀 Running the Server

### Development Mode
```bash
# Auto-reloads on code changes
uvicorn server.app.main:app --reload --host 0.0.0.0 --port 5000
```

### Production Mode
```bash
# Optimized for performance
uvicorn server.app.main:app --host 0.0.0.0 --port 5000 --workers 4
```

---


