# Network Traffic Analyzer

Client-Server architecture for real-time network traffic analysis with ML-based intrusion detection.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- PostgreSQL database (or SQLite for development)
- Administrator/root privileges (for packet capture)

### Installation

**Server**:
```bash
cd server
pip install -r requirements.txt
# Update DATABASE_URL in app/main.py
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Client**:
```bash
cd client
pip install -r requirements.txt
# Update SERVER_URL in sender.py
python sniffer.py -i 1 --send   # Sniff interface #1 and upload (requires admin)
# OR run separately:
python sniffer.py -i 1           # Sniff only
python sender.py                 # Upload only (separate terminal)
```

---

## 📋 Architecture

```
┌─────────────┐                ┌─────────────┐                ┌─────────────┐
│ sniffer.py  │ → JSON (5s) → │ sender.py   │ → HTTP POST → │ Server API  │
│ (Process 1) │   + .ready    │ (Process 2) │   (JSON)      │  (FastAPI)  │
└─────────────┘  OR --send    └─────────────┘                └──────┬──────┘
                                                                    │
                                                           ┌────────┴────────┐
                                                           │ Ingestion Logic │
                                                           │ → 5s Aggregation│
                                                           └────────┬────────┘
                                                                    │
                                                          ┌─────────┴─────────┐
                                                          │ PostgreSQL        │
                                                          │ raw + 5s features │
                                                          └─────────┬─────────┘
                                                                    │
                                             ┌──────────────────────┴──────────────────────┐
                                             │ Background Threads                          │
                                             │                                             │
                                             │ 1. 5s Prediction (Polling)                  │
                                             │    [Query Unlabeled] → [ML Predict] → Alert │
                                             │                                             │
                                             │ 2. Cascading & Prediction (Inline)          │
                                             │    [6× 5s → 30s ] → [ML Predict] → Alert    │
                                             │    [36× 5s → 180s] → [ML Predict] → Alert   │
                                             └─────────────────────────────────────────────┘
```

### File Flow

```
client/logs/
├── pending_upload/          # Sniffer writes here
│   ├── packets_YYYYMMDD_HHMMSS.json
│   └── packets_YYYYMMDD_HHMMSS.json.ready  ← Signals file is complete
├── processed/               # Successfully uploaded files
└── failed_uploads/          # Files that couldn't be uploaded
```

---

## ✨ Features

- **Real-Time Detection**: 5-second upload intervals for fast attack detection
- **Multi-Window Analysis**: Three time windows (5s, 30s, 3min) for comprehensive threat detection
- **Cascading Aggregation**: 5s windows on ingest; 30s/180s built from DB (requires 6/36 records)
- **Inline ML Prediction**: `predict_and_alert()` runs immediately after each 30s/180s aggregation
- **Parallelized Processing**: ThreadPoolExecutor processes multiple IPs concurrently
- **Dual Storage**: Raw packets for forensics + aggregated flows for ML
- **Retry & Resilience**: Automatic retries with disk fallback during outages
- **Zero Race Conditions**: Atomic file writes with `.ready` markers
- **8 Attack Types**: Port Scan, SSH Brute Force, Slowloris, ARP Spoof, DNS Tunnel, SYN/UDP/ICMP Floods

---

## 📦 Dependencies

### Server
| Package | Purpose |
|---------|---------|
| `fastapi` | REST API framework |
| `uvicorn` | ASGI server |
| `sqlalchemy` | Database ORM |
| `pandas` | Data processing |
| `xgboost` | ML predictions |
| `scikit-learn` | ML utilities |
| `psycopg2-binary` | PostgreSQL driver |

### Client
| Package | Purpose |
|---------|---------|
| `scapy` | Packet capture |
| `requests` | HTTP uploads |

### Database Options
```python
# SQLite (development)
DATABASE_URL = "sqlite:///traffic_analyzer.db"

# PostgreSQL (production)
DATABASE_URL = "postgresql://user:password@localhost:5432/network_analyzer"
```

---

## 📚 Documentation

- **[DEPLOYMENT.md](DEPLOYMENT.md)**: Complete deployment guide
- **[PERFORMANCE_OPTIMIZATION.md](PERFORMANCE_OPTIMIZATION.md)**: DoS simulation & optimization
- **[CHANGELOG.md](CHANGELOG.md)**: Recent changes and improvements
- **[docs/](docs/)**: Component documentation (sniffer, sender, main, aggregator)

---

## 🔧 Configuration

### Sniffer (client/sniffer.py)
```bash
python sniffer.py --help              # Show all options
python sniffer.py -i 1 --send         # Sniff + upload in one command
python sniffer.py -i 1,2 -s 5 -b 50000  # Custom settings
```

| Argument | Default | Description |
|----------|---------|-------------|
| `-i` | Interactive | Interface selection |
| `-s` | 5 seconds | Save interval |
| `-b` | 50000 | Buffer size limit |
| `--send` | Off | Also start sender |

### Sender (client/sender.py)
```python
SERVER_URL = "http://YOUR_SERVER:8000/ingest"
POLL_INTERVAL = 1    # Check for files every 1 second
BATCH_SIZE = 1000    # Packets per HTTP request
```

### Server (server/app/main.py)
```python
DATABASE_URL = "postgresql://USER:PASSWORD@HOST:PORT/DATABASE"
```

---

## 📊 API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/ingest` | POST | Receive packet batches |
| `/api/features?window_size=N` | GET | Aggregated features by window |
| `/api/alerts` | GET | Security alerts with filters |
| `/api/last10` | GET | Last 10 flows (JSON) |
| `/api/alltraffic` | GET | All flows (JSON) |

| `/dashboard` | GET | Web dashboard |

**Database Tables:**
- `raw_packets` - Complete packet logs (all 33 features)
- `aggregated_features` - All window sizes (5s/30s/180s) with ML features
- `detected_alerts` - Security alerts with severity & resolution tracking

---

## 🔒 Race Condition Prevention

1. **Sniffer writes to temp file** → `packets_TIMESTAMP.json.tmp`
2. **Atomic rename when complete** → `packets_TIMESTAMP.json`
3. **Create ready marker** → `packets_TIMESTAMP.json.ready`
4. **Sender only processes files with `.ready` marker**

This ensures sender **never** sees incomplete files.

---

## 🛠️ Troubleshooting

**Connection errors**: Check server is running and access `http://SERVER:8000/docs`

**Failed uploads**: Check `client/logs/failed_uploads/` and run `python sender.py`

**Missing packets**: Increase `BATCH_SIZE` or use `AsyncSniffer` for high traffic

**Files stuck in pending_upload**: Check sender is running and server is accessible

See [DEPLOYMENT.md](DEPLOYMENT.md) for more details.

---

## 📝 License

This project is licensed under the [MIT License](LICENSE).

