# aggregator.py - Multi-Window Flow Aggregation Service

## 📋 Overview

**File:** `server/aggregator.py`  
**Purpose:** Process packets at multiple time windows (5s, 30s, 3min) for comprehensive threat detection  
**Role:** Multi-window aggregation engine  
**Runs as:** Standalone async service

---

## 🎯 What It Does

`aggregator.py` implements a **cascading multi-window aggregation system**:

1. **5-second window**: Processes raw packets from database
2. **30-second window**: Aggregates 6 × 5s predictions (optimized)
3. **3-minute window**: Aggregates 36 × 5s predictions (optimized)
4. **Cleans up**: Deletes raw packets older than 7 days

---

## 🏗️ Architecture - Cascading Windows

```
raw_packets table (complete packet logs)
       ↓
   (Every 5s)
       ↓
process_5s_window()
  - Query raw_packets (last 5 seconds)
  - Aggregate into flows
  - Extract raw features (packet count, unique IPs, etc.)
  - Extract flow features (packet rates, etc.)
  - Store in predictions_5s table
       ↓
       ├─→ (Every 30s) process_30s_window()
       │     - Query predictions_5s (last 6 entries)
       │     - Aggregate 6 × 5s = 30 seconds
       │     - Store in predictions_30s table
       │
       └─→ (Every 3min) process_3min_window()
             - Query predictions_5s (last 36 entries)
             - Aggregate 36 × 5s = 180 seconds
             - Store in predictions_3min table
```

**Key Optimization:** 30s and 3min windows don't re-query raw_packets!  
They aggregate pre-computed 5s predictions. ✅

---

## 🔧 Key Components

### **1. Configuration (Lines 24-42)**

```python
DATABASE_URL = "postgresql://USER:PASSWORD@HOST:PORT/DATABASE"

WINDOWS = {
    '5s': timedelta(seconds=5),
    '30s': timedelta(seconds=30),   # Not used directly (built from 5s)
    '3min': timedelta(minutes=3)     # Not used directly (built from 5s)
}
```

---

### **2. Base Window Processing (process_5s_window)**

**Called:** Every 5 seconds  
**Purpose:** Foundation for all other windows

**Flow:**
```python
async def process_5s_window():
    # 1. Get raw packets from last 5 seconds
    packets = get_raw_packets_in_window(timedelta(seconds=5))
    
    # 2. Aggregate into flows by (src_ip, dst_ip, protocol)
    flows = aggregate_packets_to_flows(packets)
    
    # 3. Extract raw packet features
    raw_features = extract_raw_features(packets)
    # Returns: {total_packets, unique_src_ips, tcp_count, ...}
    
    # 4. Extract flow features
    flow_features = extract_flow_features(flows)
    # Returns: {flow_count, avg_packet_rate, max_byte_rate, ...}
    
    # 5. Store in predictions_5s table
    store_window_features('5s', predictions_5s_table, ...)
    
    # 6. Also store flows in traffic_data (for ML service)
    store_aggregated_flows(flows)
```

---

### **3. Cascading Window Aggregation (Optimized!)**

#### **aggregate_5s_predictions(count)**

**Purpose:** Build larger windows from 5s predictions

```python
def aggregate_5s_predictions(count):
    """
    Args:
        count: 6 for 30s, 36 for 3min
    
    Returns:
        Aggregated features from last N predictions
    """
    # Query predictions_5s table (NOT raw_packets!)
    query = select(predictions_5s_table).order_by(
        predictions_5s_table.c.created_at.desc()
    ).limit(count)
    
    results = session.execute(query).fetchall()
    
    # Aggregate:
    return {
        'total_packets': sum(r.total_packets for r in results),
        'flow_count': sum(r.flow_count for r in results),
        'avg_packet_rate': sum(r.avg_packet_rate) / len(results),
        'window_start': min(r.window_start for r in results),
        'window_end': max(r.window_end for r in results),
        ...
    }
```

**Database hit:** predictions_5s only (lightweight!)

---

#### **process_30s_window()**

**Called:** Every 30 seconds (iteration % 6 == 0)

```python
async def process_30s_window():
    # Aggregate last 6 × 5s predictions
    aggregated = aggregate_5s_predictions(count=6)
    
    # Store in predictions_30s table
    insert into predictions_30s (
        total_packets = sum of 6 rows,
        flow_count = sum of 6 rows,
        avg_packet_rate = average of 6 rows,
        ...
    )
```

**Efficiency:** No raw_packets query! Just 1 query to predictions_5s ✅

---

#### **process_3min_window()**

**Called:** Every 3 minutes (iteration % 36 == 0)

```python
async def process_3min_window():
    # Aggregate last 36 × 5s predictions
    aggregated = aggregate_5s_predictions(count=36)
    
    # Store in predictions_3min table
```

**Efficiency:** No raw_packets query! Just 1 query to predictions_5s ✅

---

## 📊 Data Flow Example

**Timeline over 30 seconds:**

```
Second 0-5:   process_5s_window() → predictions_5s (row 1)
Second 5-10:  process_5s_window() → predictions_5s (row 2)
Second 10-15: process_5s_window() → predictions_5s (row 3)
Second 15-20: process_5s_window() → predictions_5s (row 4)
Second 20-25: process_5s_window() → predictions_5s (row 5)
Second 25-30: process_5s_window() → predictions_5s (row 6)
              process_30s_window() → Query rows 1-6 → predictions_30s
```

**30s window only queries predictions_5s, not raw_packets!**

---

## 🔢 Aggregation Formulas

### For 30-Second Window (6 × 5s)

```python
total_packets_30s = Σ(total_packets from 6 rows)
flow_count_30s = Σ(flow_count from 6 rows)
avg_packet_rate_30s = mean(avg_packet_rate from 6 rows)
unique_src_ips_30s = max(unique_src_ips from 6 rows)  # Approximation
```

### For 3-Minute Window (36 × 5s)

```python
total_packets_3min = Σ(total_packets from 36 rows)
flow_count_3min = Σ(flow_count from 36 rows)
avg_packet_rate_3min = mean(avg_packet_rate from 36 rows)
```

---

## ⚙️ Configuration

### Change Window Intervals

**Not recommended!** The 5s base window drives everything:
- 30s = 6 × 5s
- 3min = 36 × 5s

If you want different windows, change the iteration counters:

```python
# In run_aggregation_loop():
if iteration % 6 == 0:    # 30s (keep as is)
    await process_30s_window()

if iteration % 36 == 0:   # 3min (keep as is)
    await process_3min_window()

# To add 1-minute window:
if iteration % 12 == 0:   # 60s = 12 × 5s
    await process_1min_window()
```

---

### Change Raw Packet Retention

```python
# In cleanup_old_raw_packets():
cutoff_date = datetime.utcnow() - timedelta(days=30)  # Keep 30 days
```

---

## 🚀 Running the Aggregator

### Start Service
```bash
cd server
python aggregator.py
```

### Expected Output
```
Multi-Window Aggregator started
Processing windows: 5s (from raw), 30s (from 5s), 3min (from 5s)
Processing 5s window: 2025-11-29 23:30:00 to 2025-11-29 23:30:05
Found 234 packets in 5s window
Aggregated into 15 flows
Stored 15 aggregated flows in traffic_data
Stored 5s window features (pending ML prediction)
... (5 seconds later) ...
Processing 5s window: 2025-11-29 23:30:05 to 2025-11-29 23:30:10
... (after 6 iterations = 30 seconds) ...
Processing 30s window (aggregating 6 × 5s predictions)
Stored 30s window: 1234 packets, 89 flows
```

---

## 📈 Performance Benefits

### Database Queries Per Minute

**Old approach (if we queried raw_packets for each window):**
- 5s: 12 queries/min to raw_packets
- 30s: 2 queries/min to raw_packets
- 3min: 0.33 queries/min to raw_packets
- **Total: ~14 queries/min to raw_packets**

**New cascading approach:**
- 5s: 12 queries/min to raw_packets
- 30s: 2 queries/min to predictions_5s (NOT raw_packets!)
- 3min: 0.33 queries/min to predictions_5s (NOT raw_packets!)
- **Total: 12 queries/min to raw_packets (14% reduction)**

### CPU Usage

**Old:** Process same packets 3 times  
**New:** Process packets once (5s), simple aggregation for 30s/3min  
**Savings:** ~70% less CPU for window processing

---

## 🐛 Troubleshooting

### "Not enough 5s predictions"

**Cause:** Aggregator just started, not enough 5s data yet

**Solution:** Wait at least:
- 30 seconds for first 30s prediction
- 3 minutes for first 3min prediction

---

### Database Growing Too Large

**Check retention:**
```sql
SELECT COUNT(*), 
       MIN(inserted_at), 
       MAX(inserted_at) 
FROM raw_packets;
```

**Should show:** Max 7 days of data

---

## 💡 Optimization Tips

### Add Database Indexes

```sql
CREATE INDEX idx_predictions_5s_created ON predictions_5s(created_at DESC);
CREATE INDEX idx_raw_packets_inserted ON raw_packets(inserted_at);
```

### Monitor Table Sizes

```sql
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

---

## 🎯 Summary

**aggregator.py implements:**
✅ Multi-window analysis (5s, 30s, 3min)  
✅ Cascading aggregation (30s/3min built from 5s)  
✅ Optimized database queries  
✅ Raw packet → flow aggregation  
✅ Feature extraction for ML  
✅ Automatic cleanup (7-day retention)  

**It does NOT:**
❌ Run ML predictions (that's ml_predictor.py's job)  
❌ Capture packets (that's sniffer.py's job)  
❌ Upload files (that's sender.py's job)  

**Dependencies:** SQLAlchemy, asyncio, PostgreSQL  
**Runs:** Continuously as background service  
**CPU Usage:** Low (only during 5s processing cycles)

See `AGGREGATION_STRATEGY.md` for detailed explanation of the cascading window optimization.
