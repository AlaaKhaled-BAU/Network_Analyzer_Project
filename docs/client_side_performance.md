# Client-Side Performance Optimizations

This document describes the performance improvements made to the **sniffer** and **sender** components of the Network Analyzer client.

---

## Overview

The client consists of two main components:
- **`sniffer.py`** - Captures network packets and saves to JSON files
- **`sender.py`** - Monitors for new files and uploads to server

Both were optimized for better CPU utilization, memory management, and network efficiency.

---

## Sniffer Improvements

### 1. Network Interface Selection (CLI)

**Problem:** The sniffer spawned a thread for every network interface, even when only monitoring one was needed.

**Solution:** Added command-line interface for selecting specific interfaces.

**Usage:**
```bash
python sniffer.py --list              # List all interfaces with numbers
python sniffer.py                     # Interactive mode (prompts you)
python sniffer.py -i 1                # Sniff only interface #1
python sniffer.py -i 1,3,5            # Sniff interfaces #1, #3, and #5
python sniffer.py -i all              # Sniff all interfaces
```

**Effect:**
- Fewer threads = less CPU overhead
- Reduces unnecessary packet processing
- User controls exactly which interfaces to monitor

---

### 2. Buffer Size Limit

**Problem:** The packet buffer could grow indefinitely, potentially causing out-of-memory (OOM) crashes during high traffic (e.g., DDoS attacks).

**Solution:** Added `MAX_BUFFER_SIZE` (default: 50,000 packets). When the buffer reaches this limit, it forces an immediate save.

**Usage:**
```bash
python sniffer.py -b 100000    # Custom buffer limit of 100k packets
python sniffer.py -s 10        # Custom save interval of 10 seconds
```

**Effect:**
- Prevents memory exhaustion during traffic spikes
- No packet loss (force-save, not drop)
- Configurable via CLI (`--buffer-size`)

**Default Values:**
| Parameter | Default | Description |
|-----------|---------|-------------|
| `SAVE_INTERVAL` | 5 seconds | Time-based save trigger |
| `MAX_BUFFER_SIZE` | 50,000 packets | Size-based save trigger |

---

### 3. Queue-Based Buffer (Lock Contention Fix)

**Problem:** Multiple NIC threads competed for a single lock when adding packets, causing bottlenecks under high load.

**Before:**
```python
self.buffer = []
self.lock = threading.Lock()

def add_packet(self, packet):
    with self.lock:  # All threads wait here
        self.buffer.append(packet)
```

**Solution:** Replaced list + lock with Python's `queue.Queue`, which is optimized for multi-producer scenarios.

**After:**
```python
import queue
self.packet_queue = queue.Queue()

def add_packet(self, packet):
    self.packet_queue.put(packet)  # Thread-safe, no explicit lock
```

**Effect:**
- Multiple NIC threads can add packets simultaneously
- No lock contention bottleneck
- Better throughput under high traffic

---

## Sender Improvements

### 1. HTTP Connection Pooling

**Problem:** Each HTTP POST created a new TCP connection, adding ~30-50ms overhead per request (TCP handshake).

**Before:**
```python
response = requests.post(SERVER_URL, json=packets)  # New connection each time
```

**Solution:** Use `requests.Session()` to reuse TCP connections (HTTP Keep-Alive).

**After:**
```python
http_session = requests.Session()
http_session.headers.update({'Content-Type': 'application/json'})

response = http_session.post(SERVER_URL, json=packets)  # Reuses connection
```

**Effect:**
- ~30-50ms saved per request
- Connection stays alive between requests
- Automatic reconnection if connection drops

**Example Impact:**
| Scenario | Without Pooling | With Pooling | Savings |
|----------|-----------------|--------------|---------|
| 50 batch file | ~5.25 seconds | ~3.05 seconds | ~2.2 seconds |

---

### 2. Sequential File Processing (Kept As-Is)

**Decision:** Keep sequential file processing instead of parallel.

**Why We Evaluated Parallel:**
- Could process multiple files simultaneously with `ThreadPoolExecutor`
- Would be ~2-4x faster when files are backlogged

**Why We Kept Sequential:**
- **Simplicity** - easier to debug and maintain
- **Server load** - parallel uploads could overwhelm the server
- **Usually not needed** - sender polls every 1 second, files rarely pile up
- **No risk** - no race conditions or interleaved logs

**Current Flow:**
```
File 1 → Upload → Done
File 2 → Upload → Done
File 3 → Upload → Done
```

If backlogs become an issue in the future, parallel processing can be added.

---

## Sniffer CLI Usage Guide

The sniffer supports several command-line arguments for customization. Here's a detailed guide:

### Running the Sniffer

```bash
cd client
python sniffer.py [options]
```

> **Note:** Requires administrator/root privileges for packet capture.

---

### Available Arguments

#### `-l` / `--list` — List Interfaces

**Purpose:** Display all available network interfaces with numbers, then exit.

**Example:**
```bash
python sniffer.py --list
```

**Output:**
```
======================================================================
AVAILABLE NETWORK INTERFACES
======================================================================
   1. Realtek Gaming GbE Family Controller (192.168.1.5)
   2. Radmin VPN (26.178.118.134)
   3. Intel(R) Wi-Fi 6 AX201 (192.168.1.10)
   4. Npcap Loopback Adapter
----------------------------------------------------------------------
   0. ALL interfaces (4 total)
======================================================================
```

**Default:** Not set (sniffer doesn't just list and exit)

---

#### `-i` / `--interfaces` — Select Interfaces

**Purpose:** Choose which network interfaces to sniff.

**Options:**
| Value | Meaning |
|-------|---------|
| `all` or `0` | Sniff on ALL interfaces |
| `1` | Sniff only interface #1 |
| `1,3` | Sniff interfaces #1 and #3 |
| `2,4,5` | Sniff interfaces #2, #4, and #5 |

**Examples:**
```bash
# Sniff only on Wi-Fi (interface #3)
python sniffer.py -i 3

# Sniff on Ethernet and VPN (interfaces #1 and #2)
python sniffer.py -i 1,2

# Sniff on all interfaces
python sniffer.py -i all
python sniffer.py -i 0
```

**Default:** If not specified, enters **interactive mode** — displays interfaces and prompts you to choose.

---

#### `-s` / `--save-interval` — Save Interval

**Purpose:** How often (in seconds) to save buffered packets to a JSON file.

**Examples:**
```bash
# Save every 10 seconds instead of default 5
python sniffer.py -s 10

# Save every 2 seconds for more real-time monitoring
python sniffer.py -s 2
```

**Default:** `5` seconds

**When to change:**
- **Increase** (e.g., 30) → Fewer, larger files, less disk I/O
- **Decrease** (e.g., 2) → More real-time, but more files

---

#### `-b` / `--buffer-size` — Buffer Size Limit

**Purpose:** Maximum number of packets to hold in memory before forcing a save.

**Examples:**
```bash
# Allow up to 100,000 packets in buffer
python sniffer.py -b 100000

# Smaller buffer for low-memory systems
python sniffer.py -b 10000
```

**Default:** `50000` packets (~15-25 MB of JSON)

**When to change:**
- **Increase** → More memory usage, fewer forced saves
- **Decrease** → Less memory usage, more frequent saves

---

#### `--send` — Combined Sniff and Send Mode

**Purpose:** Start the sender in a background thread alongside sniffing. This allows you to run a single command instead of two separate terminals.

**Examples:**
```bash
# Sniff on interface #1 and upload to server automatically
python sniffer.py -i 1 --send

# Full setup: specific interface, custom settings, with automatic upload
python sniffer.py -i 2 -s 5 -b 50000 --send
```

**Default:** Disabled (sniffer only saves files locally)

**How it works:**
1. Sniffer captures packets → saves JSON files to `pending_upload/`
2. Sender (in background thread) watches folder → uploads to server
3. Both run in the same process, stop together with Ctrl+C

**When to use:**
- **With `--send`:** Single command for production monitoring
- **Without `--send`:** Testing, or when running sender separately

> **Note:** You can still run `sender.py` separately if preferred. The `--send` flag is optional convenience.

---

### Combined Examples

```bash
# Monitor only Wi-Fi (#3), save every 10 seconds, buffer up to 100k packets
python sniffer.py -i 3 -s 10 -b 100000

# Monitor Ethernet and Loopback, quick saves for real-time analysis
python sniffer.py -i 1,4 -s 2

# Interactive mode with custom buffer size
python sniffer.py -b 25000

# Just list interfaces and exit
python sniffer.py -l

# Sniff AND send to server in one command
python sniffer.py -i 1 --send

# Full example: specific interface, custom settings, with sending
python sniffer.py -i 2 -s 5 -b 50000 --send
```

---

### Quick Reference Table

| Argument | Short | Default | Description | Example |
|----------|-------|---------|-------------|---------|
| `--list` | `-l` | False | List interfaces and exit | `-l` |
| `--interfaces` | `-i` | Interactive | Which interfaces to sniff | `-i 1,2` or `-i all` |
| `--save-interval` | `-s` | 5 seconds | Time between saves | `-s 10` |
| `--buffer-size` | `-b` | 50000 | Max packets before forced save | `-b 100000` |
| `--send` | — | False | Also start sender to upload files | `--send` |

---

## Sender Configuration

The sender uses constants defined at the top of `sender.py`:

| Constant | Default | Description |
|----------|---------|-------------|
| `SERVER_URL` | `http://26.178.118.134:8000/ingest` | Server endpoint |
| `POLL_INTERVAL` | 1 second | How often to check for new files |
| `MAX_RETRIES` | 3 | Upload retry attempts before marking as failed |
| `RETRY_DELAY` | 5 seconds | Base delay between retries (uses exponential backoff: 5s, 10s, 20s) |
| `BATCH_SIZE` | 1000 | Packets per upload request |

To change sender settings, edit the constants in `client/sender.py`.

---

## Performance Summary

| Component | Improvement | Impact |
|-----------|-------------|--------|
| Sniffer | Interface selection | Fewer threads, less CPU |
| Sniffer | Buffer limit | Prevents OOM, no data loss |
| Sniffer | Queue-based buffer | No lock contention |
| Sender | Connection pooling | ~2 seconds faster per large file |
| Sender | Sequential processing | Simplicity, reliability |

---

## Future Considerations

If performance issues arise, these could be explored:
1. **Parallel file uploads** - for handling file backlogs
2. **Compression** - gzip JSON before upload
3. **Binary format** - MessagePack instead of JSON
4. **Async sender** - Full asyncio rewrite with aiohttp

For now, the current optimizations provide a good balance of performance and simplicity.
