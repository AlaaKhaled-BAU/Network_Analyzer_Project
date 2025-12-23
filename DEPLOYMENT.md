# Network Traffic Analyzer - Deployment Guide

## Overview

The refactored architecture uses **direct HTTP streaming** from client to server with **server-side aggregation** and **dual storage** (raw packets + ML flows).

## Architecture Components

```
┌─────────────────┐
│  sniffer.py     │  Captures packets, saves to JSON every 5s
│  (Client)       │
└────────┬────────┘
         │ JSON files + .ready markers
         ▼
┌─────────────────┐
│  sender.py      │  Monitors files, uploads via HTTP POST
│  (Client)       │
└────────┬────────┘
         │ HTTP POST /ingest
         ▼
┌───────────────────────────────────────────────┐
│  main.py (FastAPI Server)                     │
│  ├── Stores packets in raw_packets           │
│  ├── Runs MultiWindowAggregator (5s/30s/3min) │
│  ├── Stores features in aggregated_features  │
│  └── XGBoost ML predictions → detected_alerts │
└───────────────────────────────────────────────┘
                         │
                         ▼
                   PostgreSQL
              (3 tables: raw_packets,
               aggregated_features,
               detected_alerts)
```

## Installation

### Server Setup

1. **Install Dependencies**:
```bash
cd server
pip install -r requirements.txt
```

2. **Setup PostgreSQL Database**:
```sql
CREATE DATABASE Traffic_Analyzer;
```

3. **Update Database Credentials**:
Edit `server/app/main.py`:
```python
DATABASE_URL = "postgresql://YOUR_USER:YOUR_PASSWORD@localhost:5432/Traffic_Analyzer"
```

4. **ML Model Files**:
Ensure these files exist in `server/models/`:
- `xgb_model.pkl` - XGBoost model
- `label_encoder.pkl` - Label encoder
- `feature_names.pkl` - Feature names

### Client Setup

1. **Install Dependencies**:
```bash
cd client
pip install scapy requests
```

2. **Update Server URL**:
Edit `client/sender.py`:
```python
SERVER_URL = "http://YOUR_SERVER_IP:8000/ingest"
```

## Running the System

### Start Server (Terminal 1)

```bash
cd server
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Start Client (Terminal 2)

**Windows (Administrator required)**:
```bash
cd client
python sniffer.py -i 1 --send    # Sniff interface #1 and upload
```

**Linux**:
```bash
cd client
sudo python sniffer.py -i 1 --send
```

> **Note:** The `--send` flag starts the sender in the background. You can also run `sniffer.py` and `sender.py` separately in two terminals.

## Configuration

### Sniffer Settings

```bash
# Command-line options
python sniffer.py --help
python sniffer.py -i 1 -s 5 -b 50000 --send
```

| Option | Default | Description |
|--------|---------|-------------|
| `-i` / `--interfaces` | Interactive | Interface selection (1, 1,2,3, or all) |
| `-s` / `--save-interval` | 5 seconds | JSON save frequency |
| `-b` / `--buffer-size` | 50000 | Max packets before forced save |
| `--send` | Off | Also run sender in background |

### Server Settings

Aggregation is handled automatically by `main.py` on packet ingestion.

## Features

### 1. Direct HTTP Streaming
- No file I/O overhead
- Real-time packet delivery
- Automatic batching for efficiency

### 2. Retry & Resilience
- 3 automatic retries with exponential backoff
- Failed batches saved to `client/logs/failed_uploads/`
- Manual retry with `python sender.py`

### 3. Dual Storage
- **raw_packets**: Complete packet logs for audit/forensics
- **aggregated_features**: Multi-window ML features (5s/30s/180s)
- **detected_alerts**: Security alerts with severity tracking

### 4. Integrated Aggregation
- Automatic multi-window aggregation (5s, 30s, 3min) on ingestion
- XGBoost ML predictions in background thread
- Severity-based alert generation

## API Endpoints

### Client → Server

- `POST /ingest`: Receive batch of raw packets
  ```json
  [
    {
      "timestamp": 1234567890.123,
      "interface": "eth0",
      "src_ip": "192.168.1.1",
      "dst_ip": "8.8.8.8",
      "protocol": "TCP",
      ...
    }
  ]
  ```

### Web UI

- `GET /`: Last 10 aggregated flows (HTML)
- `GET /alltraffic_page`: All aggregated flows (HTML)

### JSON API

- `GET /api/features?window_size=N`: Aggregated features (5/30/180)
- `GET /api/alerts`: Security alerts
- `GET /api/protocols`: Protocol distribution
- `GET /api/top-sources`: Top source IPs
- `GET /api/top-destinations`: Top destination IPs
- `GET /api/top-ports`: Top destination ports
- `GET /health`: Health check

## Troubleshooting

### Server Connection Errors

If sniffer shows "Connection error: Server may be down":
1. Check server is running: `curl http://SERVER_IP:8000/health`
2. Check firewall allows port 8000
3. Verify SERVER_URL in sniffer.py

### Packet Dropping

If you see packet drops:
1. Increase `BATCH_SIZE` to reduce HTTP overhead
2. Use fewer network interfaces
3. Consider running on dedicated hardware

### Database Connection Issues

```bash
# Test PostgreSQL connection
psql -U postgres -d Traffic_Analyzer

# Check if tables exist
\dt
```

### Failed Uploads

Check `client/logs/failed_uploads/` for batches that couldn't be sent:
```bash
# Manually retry failed uploads
python sender.py
```

## Monitoring

### Check Sniffer Status
```bash
# View sniffer logs
tail -f client/logs/sniffer.log
```

### Check Server Status
```bash
# View server logs
tail -f server/logs/server.log

# Check raw packet count
psql -U postgres -d Traffic_Analyzer -c "SELECT COUNT(*) FROM raw_packets;"

# Check aggregated features (by window size)
psql -U postgres -d Traffic_Analyzer -c "SELECT window_size, COUNT(*) FROM aggregated_features GROUP BY window_size;"

# Check detected alerts
psql -U postgres -d Traffic_Analyzer -c "SELECT COUNT(*) FROM detected_alerts;"
```

## Performance Tuning

### High Traffic Networks

For networks with >10,000 packets/sec:

1. **Increase Batch Size**:
```python
BATCH_SIZE = 500
BATCH_TIMEOUT = 10
```

2. **Use Dedicated Database**:
- Move PostgreSQL to separate server
- Use connection pooling
- Enable PostgreSQL performance tuning

3. **Scale Horizontally**:
- Run multiple sniffer instances on different interfaces
- Use load balancer for FastAPI server
- Run multiple aggregator instances

## Security Considerations

1. **Use HTTPS**: Update SERVER_URL to `https://...`
2. **Add Authentication**: Implement API keys or OAuth
3. **Network Isolation**: Run sniffer on isolated monitoring network
4. **Database Encryption**: Enable PostgreSQL SSL/TLS
5. **Sanitize Logs**: Raw packets may contain sensitive data

## Comparison: Old vs New Architecture

| Feature | Old (File-Based) | New (HTTP Streaming) |
|---------|------------------|----------------------|
| Latency | 1-60 minutes | 30 seconds |
| Race Conditions | YES (critical) | NO |
| Server Outage Handling | Data loss | Retry + fallback |
| Disk I/O | Heavy | Minimal |
| Complexity | sniffer + sender | sniffer only |
| Scalability | Limited | High |
| Data Integrity | Risk of corruption | Guaranteed |
