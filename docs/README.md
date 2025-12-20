# Documentation Index

Welcome to the Network Traffic Analyzer documentation! This index will guide you to the right documentation for each component.

---

## 📚 Documentation Files

### **Client-Side Components**

1. **[sniffer_explained.md](sniffer_explained.md)** - Packet Capture Module
   - **What it does:** Captures network packets and saves to JSON files
   - **Read this if you want to:**
     - Understand how packet capture works
     - Change capture intervals or filters
     - Troubleshoot packet capture issues
     - Optimize memory usage

2. **[sender_explained.md](sender_explained.md)** - File Upload Manager
   - **What it does:** Monitors JSON files and uploads to server
   - **Read this if you want to:**
     - Understand the file monitoring system
     - Configure upload retry logic
     - Troubleshoot upload failures
     - Manage processed/failed files

---

### **Server-Side Components**

3. **[main_explained.md](main_explained.md)** - FastAPI Server
   - **What it does:** Receives data and provides web dashboards
   - **Read this if you want to:**
     - Understand the API endpoints
     - Configure database connections
     - Set up web dashboards
     - Add new API endpoints

4. **[aggregator_explained.md](aggregator_explained.md)** - Flow Aggregation Service
   - **What it does:** Converts raw packets → flows → ML predictions
   - **Read this if you want to:**
     - Understand flow aggregation logic
     - Configure aggregation intervals
     - Optimize ML predictions
     - Manage database cleanup

---

## 🗺️ Quick Navigation

### By Task

| I want to... | Read this file |
|--------------|----------------|
| Set up packet capture | [sniffer_explained.md](sniffer_explained.md) |
| Configure file uploads | [sender_explained.md](sender_explained.md) |
| Set up the server | [main_explained.md](main_explained.md) |
| Understand flow aggregation | [aggregator_explained.md](aggregator_explained.md) |
| Deploy the entire system | [../DEPLOYMENT.md](../DEPLOYMENT.md) |
| Understand the architecture | [../SEPARATED_ARCHITECTURE.md](../SEPARATED_ARCHITECTURE.md) |

---

### By Component

```
┌─────────────────────────────────────────────────────┐
│                 CLIENT SIDE                         │
│─────────────────────────────────────────────────────│
│                                                     │
│  sniffer.py          →    sender.py                │
│  [sniffer_explained]      [sender_explained]       │
│                                                     │
│  Captures packets         Uploads to server        │
│                                                     │
└─────────────────────────────────────────────────────┘
                         ↓
                    (HTTP POST)
                         ↓
┌─────────────────────────────────────────────────────┐
│                 SERVER SIDE                         │
│─────────────────────────────────────────────────────│
│                                                     │
│  main.py             →    aggregator.py            │
│  [main_explained]         [aggregator_explained]   │
│                                                     │
│  Receives data            Aggregates & predicts    │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## 📖 Reading Order

### For New Users
1. Start with [../README.md](../README.md) - Project overview
2. Read [../SEPARATED_ARCHITECTURE.md](../SEPARATED_ARCHITECTURE.md) - Architecture
3. Read [sniffer_explained.md](sniffer_explained.md) - Understand capture
4. Read [sender_explained.md](sender_explained.md) - Understand uploads
5. Read [main_explained.md](main_explained.md) - Understand server
6. Read [aggregator_explained.md](aggregator_explained.md) - Understand ML
7. Follow [../DEPLOYMENT.md](../DEPLOYMENT.md) - Deploy system

### For Developers
1. [sniffer_explained.md](sniffer_explained.md) - Client capture logic
2. [sender_explained.md](sender_explained.md) - Client upload logic
3. [main_explained.md](main_explained.md) - Server API
4. [aggregator_explained.md](aggregator_explained.md) - ML pipeline

### For System Administrators
1. [../DEPLOYMENT.md](../DEPLOYMENT.md) - Deployment guide
2. [main_explained.md](main_explained.md) - Server configuration
3. [aggregator_explained.md](aggregator_explained.md) - Background services

---

## 🔧 Component Details

### **sniffer.py** (Lines: 415)
- **Language:** Python
- **Dependencies:** Scapy, threading
- **Requires:** Admin/root privileges
- **Output:** JSON files in `logs/pending_upload/`
- **Key Features:**
  - Multi-interface capture
  - 30+ packet features
  - Atomic file writes
  - Periodic saves (5s)

### **sender.py** (Lines: 260)
- **Language:** Python
- **Dependencies:** requests
- **Requires:** Network access to server
- **Input:** JSON files from `logs/pending_upload/`
- **Key Features:**
  - Continuous file monitoring
  - HTTP uploads with retry
  - Exponential backoff
  - Failed upload queue

### **main.py** (Lines: 351)
- **Language:** Python (FastAPI)
- **Dependencies:** FastAPI, SQLAlchemy, PostgreSQL
- **Port:** 8000 (default)
- **Key Features:**
  - `/ingest_packets` endpoint
  - Web dashboards
  - JSON APIs
  - Health checks

### **aggregator.py** (Lines: 260)
- **Language:** Python
- **Dependencies:** SQLAlchemy, pandas, joblib
- **Runs:** Background async service
- **Key Features:**
  - Flow aggregation (30s cycles)
  - ML predictions
  - Database cleanup (hourly)

---

## 🐛 Troubleshooting Guide

### Issue: Packets not being captured
→ Read: [sniffer_explained.md - Troubleshooting section](sniffer_explained.md#-troubleshooting)

### Issue: Files not being uploaded
→ Read: [sender_explained.md - Troubleshooting section](sender_explained.md#-troubleshooting)

### Issue: Server errors or slow responses
→ Read: [main_explained.md - Troubleshooting section](main_explained.md#-troubleshooting)

### Issue: Flows not being created
→ Read: [aggregator_explained.md - Troubleshooting section](aggregator_explained.md#-troubleshooting)

---

## 🎯 Quick Reference

### Configuration Files

| Setting | File | Line | Default | Purpose |
|---------|------|------|---------|---------|
| Save interval | sniffer.py | 28 | 5s | How often to save JSON |
| Server URL | sender.py | 36 | `http://...` | Upload destination |
| Poll interval | sender.py | 37 | 1s | File check frequency |
| Database URL | main.py | 21 | `postgresql://...` | Database connection |
| Aggregation interval | aggregator.py | 138 | 30s | Flow processing frequency |

### Important Directories

| Directory | Purpose | Created by | Used by |
|-----------|---------|------------|---------|
| `logs/pending_upload/` | JSON files waiting upload | sniffer.py | sender.py |
| `logs/processed/` | Successfully uploaded | sender.py | - |
| `logs/failed_uploads/` | Failed uploads | sender.py | sender.py (retry) |

### Database Tables

| Table | Purpose | Written by | Read by |
|-------|---------|------------|---------|
| `raw_packets` | Complete packet logs | main.py | aggregator.py |
| `traffic_data` | Aggregated flows | aggregator.py | main.py (dashboards) |

---

## 📞 Getting Help

1. **Check the relevant component documentation** (see navigation above)
2. **Review troubleshooting sections** in each file
3. **Check logs** for error messages
4. **Review [DEPLOYMENT.md](../DEPLOYMENT.md)** for setup issues

---

## 🔄 Data Flow Summary

```
Network Traffic
    ↓
[sniffer.py] → Capture & extract features
    ↓
JSON files (logs/pending_upload/)
    ↓
[sender.py] → Monitor & upload to /ingest
    ↓
HTTP POST
    ↓
[main.py] → Receive & store
    ↓
PostgreSQL (raw_packets table)
    ↓
[aggregator.py] → Aggregate & predict
    ↓
PostgreSQL (traffic_data table)
    ↓
Web Dashboard (main.py)
```

---

## 📝 Document Metadata

- **Created:** 2025-11-29
- **Total Documentation Files:** 4
- **Total Lines Documented:** ~1500 lines
- **Last Updated:** 2025-11-29

---

For the complete project overview, see [README.md](../README.md)  
For deployment instructions, see [DEPLOYMENT.md](../DEPLOYMENT.md)  
For architecture details, see [SEPARATED_ARCHITECTURE.md](../SEPARATED_ARCHITECTURE.md)
