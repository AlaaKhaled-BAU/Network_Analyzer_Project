# Network Traffic Analyzer

Client-Server architecture for real-time network traffic analysis with ML-based intrusion detection.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- PostgreSQL database
- Administrator/root privileges (for packet capture)

### Installation

**Server**:
```bash
cd server
pip install -r requirements.txt
# Update DATABASE_URL in app/main.py and aggregator.py
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Aggregator** (separate terminal):
```bash
cd server
python aggregator.py
```

**Client**:
```bash
cd client
pip install -r requirements.txt
# Update SERVER_URL in sniffer.py
python sniffer.py  # Requires admin/root
```

## 📋 Architecture

```
Sniffer (Scapy) → CSV every 5s → Sender → HTTP POST → Server (FastAPI) → PostgreSQL
                                                              ↓
                                                         raw_packets
                                                              ↓
                                                    Aggregator (multi-window)
                                                    /         |         \
                                              5s window   30s window   3min window
                                                  ↓           ↓            ↓
                                            predictions_5s  predictions_30s  predictions_3min
                                                              ↓
                                                      ML Predictor (Random Forest)
                                                              ↓
                                                      traffic_data (predictions)
```

## ✨ Features

- **Real-Time Detection**: 5-second upload intervals for fast attack detection
- **Multi-Window Analysis**: Three time windows (5s, 30s, 3min) for comprehensive threat detection
- **Optimized Aggregation**: Cascading windows (30s and 3min built from 5s data)
- **Dual Storage**: Raw packets for forensics + aggregated flows for ML
- **Retry & Resilience**: Automatic retries with disk fallback during outages
- **Separate ML Service**: Dedicated Random Forest prediction service
- **Zero Race Conditions**: Atomic file writes with ready markers

## 📚 Documentation

- **[DEPLOYMENT.md](DEPLOYMENT.md)**: Complete deployment guide
- **[walkthrough.md](.gemini/antigravity/brain/*/walkthrough.md)**: Detailed refactoring walkthrough
- **[implementation_plan.md](.gemini/antigravity/brain/*/implementation_plan.md)**: Technical design decisions

## 🔧 Configuration

### Sniffer (client/sniffer.py)
```python
SAVE_INTERVAL = 5  # Save CSV every 5 seconds (real-time detection)
```

### Sender (client/sender.py)
```python
SERVER_URL = "http://YOUR_SERVER:8000/ingest_packets"
POLL_INTERVAL = 1  # Check for files every 1 second
BATCH_SIZE = 500   # Packets per HTTP request
```

### Aggregator (server/aggregator.py)
```python
# Multi-window processing:
# - 5s:   Every 5 seconds (from raw_packets)
# - 30s:  Every 30 seconds (aggregates 6 × 5s predictions)
# - 3min: Every 3 minutes (aggregates 36 × 5s predictions)
DATABASE_URL = "postgresql://USER:PASSWORD@HOST:PORT/DATABASE"
```

## 📊 API Endpoints

- `POST /ingest_packets` - Receive packet batches (every ~5 seconds)
- `GET /api/last10` - Last 10 flows (JSON)
- `GET /api/alltraffic` - All flows (JSON)
- `GET /api/raw_packets/last/{count}` - Raw packets (JSON)
- `GET /health` - Health check
- `GET /` - Web dashboard

**Database Tables:**
- `raw_packets` - Complete packet logs (all 33 features)
- `traffic_data` - Aggregated flows with ML predictions
- `predictions_5s` - 5-second window analysis
- `predictions_30s` - 30-second window analysis
- `predictions_3min` - 3-minute window analysis

## 🛠️ Troubleshooting

**Connection errors**: Check server is running with `curl http://SERVER:8000/health`

**Failed uploads**: Check `client/logs/failed_uploads/` and run `python sender.py`

**Missing packets**: Increase `BATCH_SIZE` or use `AsyncSniffer` for high traffic

See [DEPLOYMENT.md](DEPLOYMENT.md) for more details.

## 📝 License

MIT
