# Network Traffic Analyzer - Deployment Guide

## Overview

The refactored architecture uses **direct HTTP streaming** from client to server with **server-side aggregation** and **dual storage** (raw packets + ML flows).

## Architecture Components

```
┌─────────────────┐
│  sniffer.py     │  Captures packets, batches them, sends via HTTP POST
│  (Client)       │
└────────┬────────┘
         │ HTTP POST /ingest_packets
         ▼
┌─────────────────┐
│  main.py        │  FastAPI server, receives raw packets
│  (Server)       │
└────────┬────────┘
         │
         ├──► PostgreSQL (raw_packets table) ──┐
         │                                      │
         │                                      ▼
         │                              ┌──────────────┐
         │                              │ aggregator.py│ Async aggregation
         │                              └──────┬───────┘
         │                                     │
         └──────► PostgreSQL (traffic_data) ◄──┘
                  (with ML predictions)
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
Edit `server/app/main.py` and `server/aggregator.py`:
```python
DATABASE_URL = "postgresql://YOUR_USER:YOUR_PASSWORD@localhost:5432/Traffic_Analyzer"
```

4. **Place ML Model**:
Ensure `AI_model.pkl` is in `server/models/` directory.

### Client Setup

1. **Install Dependencies**:
```bash
cd client
pip install scapy requests
```

2. **Update Server URL**:
Edit `client/sniffer.py`:
```python
SERVER_URL = "http://YOUR_SERVER_IP:8000/ingest_packets"
```

## Running the System

### Start Server (Terminal 1)

```bash
cd server
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Start Aggregator (Terminal 2)

```bash
cd server
python aggregator.py
```

### Start Sniffer (Terminal 3)

**Windows (Administrator required)**:
```bash
cd client
python sniffer.py
```

**Linux**:
```bash
cd client
sudo python sniffer.py
```

## Configuration

### Sniffer Batch Settings

Edit `client/sniffer.py`:

```python
BATCH_SIZE = 100        # Send after 100 packets
BATCH_TIMEOUT = 30      # Or send after 30 seconds
MAX_RETRIES = 3         # Retry failed uploads 3 times
RETRY_DELAY = 5         # Wait 5 seconds between retries
```

### Aggregator Settings

Edit `server/aggregator.py`:

```python
await asyncio.sleep(30)  # Aggregate every 30 seconds (line 138)
timedelta(days=7)        # Keep raw packets for 7 days (line 150)
```

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
- **traffic_data**: Aggregated flows with ML predictions

### 4. Server-Side Aggregation
- Automatic flow aggregation every 30 seconds
- ML predictions on aggregated data
- Automatic cleanup of old raw packets

## API Endpoints

### Client → Server

- `POST /ingest_packets`: Receive batch of raw packets
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

- `GET /api/last10`: Last 10 flows (JSON)
- `GET /api/alltraffic`: All flows (JSON)
- `GET /api/raw_packets/last/{count}`: Last N raw packets (JSON)
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

# Check aggregated flow count
psql -U postgres -d Traffic_Analyzer -c "SELECT COUNT(*) FROM traffic_data;"
```

### Check Aggregator Status
```bash
# View aggregator logs
tail -f server/logs/aggregator.log
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
