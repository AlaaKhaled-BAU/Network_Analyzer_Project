# NetGuardian Pro: Network Traffic Analysis & Threat Detection
**Presentation Structure (40 Minutes)**
**Presenters:** 3 (Presenter A, Presenter B, Presenter C)

---

## 🕒 Time Distribution (Approximate)
- **Part 1: Architecture & Client-Side Networking** (12 mins) - Presenter A
- **Part 2: Server-Side Processing & Aggregation** (14 mins) - Presenter B
- **Part 3: Real-Time Communication & Threat Detection** (14 mins) - Presenter C

---

## 🎤 Part 1: Architecture & Client-Side Networking (Presenter A)

### Slide 1: Title & Introduction
- **Visual:** Project Logo/Title.
- **Talking Points:** Brief intro of team. Goal: Building a scalable, real-time network traffic analyzer.

### Slide 2: High-Level Architecture
- **Visual:** Architecture diagram from `README.md` (Sniffer -> Sender -> API -> DB -> ML).
- **Talking Points:** The journey of a packet. Separation of concerns (Client vs Server).

### Slide 3: The Sniffer (Packet Capture)
- **Visual:** Code snippet of `scapy` capture or CLI interface screenshot.
- **Talking Points:**
  - Using `scapy` for capture.
  - Raw packet parsing (IP, TCP, UDP headers).
  - Challenge: Handling high throughput without dropping packets.

### Slide 4: ⚖️ Design Choice: Handling High Throughput
- **Option 1 (Rejected): Simple List + Locks**
  - *Why not?* Thread contention. When NIC threads write and sender reads, everything freezes.
- **Option 2 (Selected): Queue-Based Buffer**
  - *Why?* `queue.Queue` handles concurrency natively. No manual locking needed.
  - *Optimization:* `MAX_BUFFER_SIZE` (50k packets) to prevent OOM crashes during DDoS.

### Slide 5: The Sender (Data Transmission)
- **Visual:** JSON payload structure (screenshot of a generated JSON file).
- **Talking Points:**
  - Batching packets (5s intervals).
  - Why file-based buffering? Resilience. If server dies, files queue up on disk (`pending_upload`).

### Slide 6: ⚖️ Design Choice: Transport Protocol
- **Option 1 (Basic):** New HTTP connection per file.
  - *Drawback:* TCP 3-way handshake overhead (30-50ms) for every request.
- **Option 2 (Selected):** HTTP Connection Pooling (`requests.Session`).
  - *Benefit:* Reuses existing TCP connection (Keep-Alive).
  - *Result:* 40% faster uploads for small batches.

---

## 🎤 Part 2: Server-Side Processing & Aggregation (Presenter B)

### Slide 7: Ingestion & The "Window" Concept
- **Visual:** Timeline showing continuous traffic vs. discrete windows.
- **Talking Points:**
  - Raw packets are too noisy for analysis.
  - We need statistical "windows" to see trends (rates, averages).
  - Windows: **5s** (Real-time), **30s** (Trends), **180s** (Baselines).

### Slide 8: ⚖️ Design Choice: Aggregation Strategy (The Big Pivot)
- **Approach 1 (Previous): Synchronous Aggregation**
  - *How:* Ingest raw packets -> Calculate 5s, 30s, 180s immediately in memory.
  - *Problem:* Inconsistent 30s/180s windows. A 5s batch doesn't contain enough history for a true 30s average.
- **Approach 2 (Current): Cascading Aggregation**
  - *How:* Ingest -> 5s Window -> DB -> Background Thread -> 30s/180s.
  - *Benefit:* Accuracy. We wait for exactly **6** x 5s records to build a perfect 30s window.

### Slide 9: Implementing Cascading Aggregation
- **Visual:** Flowchart from `aggregation_strategy.md` (Background Thread Logic).
- **Talking Points:**
  - "The Water Bucket Analogy": Wait for the small buckets (5s) to fill the medium bucket (30s).
  - **Count-Based Triggers:** We trigger 30s aggregation only when we have 6 records (not just based on time).
  - **Granularity:** Aggregation happens **per Source IP**.

### Slide 10: ⚖️ Design Choice: Optimization & Parallelism
- **Challenge:** Aggregating thousands of IPs sequentially is too slow.
- **Solution:** `ThreadPoolExecutor` (Parallel processing).
- **Database Optimization:** Composite Index `(window_size, src_ip, window_start)`.
  - *Why?* Changed lookup from O(N) to O(log N). Critical for checking "Do we have 6 records yet?".

---

## 🎤 Part 3: Real-Time Communication & Threat Detection (Presenter C)

### Slide 11: Machine Learning Integration
- **Visual:** Flowchart showing Aggregation -> Inline ML Prediction.
- **Talking Points:**
  - We don't just store data; we judge it.
  - **Inline Prediction:** As soon as a 30s window is created, XGBoost analyzes it immediately.
  - **Why XGBoost?** High performance on structured tabular data (traffic features).

### Slide 12: Network Attacks We Detect
- **Visual:** Screenshot of the "Security" page with an alert table.
- **Talking Points:**
  - **Volume Attacks:** UDP Flood, ICMP Flood, SYN Flood (detected via high packet rates in 5s windows).
  - **Behavioral Attacks:** Port Scanning (high unique dst_ports), Slowloris (partial HTTP headers).
  - *Demo/Screenshot:* Show an active alert for a Port Scan.

### Slide 13: ⚖️ Design Choice: Dashboard Updates
- **Option 1 (Old): HTTP Polling**
  - *How:* Browser asks "Any new data?" every 5 seconds.
  - *Drawback:* 5700+ requests/hour per client. 2.5s average delay.
- **Option 2 (New): WebSockets**
  - *How:* Persistent full-duplex connection. Server **pushes** data.
  - *Result:* 0 unnecessary requests. <100ms delay.
  - *Impact:* "It feels alive."

### Slide 14: Demonstration / Screenshots
- **Visuals Needed:**
  1. **Dashboard Overview:** Show traffic charts updating.
  2. **Attack Simulation:** `dataset_capture_gui.py` or console output showing an attack starting.
  3. **Alert Trigger:** The exact moment the dashboard turns red/shows a toast notification.

### Slide 15: Performance & Future Work
- **Visual:** Summary Table from `server_side_optimization.md`.
- **Key Metrics:**
  - 99% reduction in HTTP overhead (WebSockets).
  - Zero duplicate records (Database logic).
- **Future:**
  - Support for distributed sensors (multiple Sniffers).
  - Moving to `asyncpg` for even higher DB throughput.

### Slide 16: Q&A
