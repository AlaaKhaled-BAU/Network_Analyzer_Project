# NetGuardian Pro Component Reference Guide

This document provides a detailed explanation of every page, component, and metric within the NetGuardian Pro interface. It is designed to help network engineers understand the goals, importance, and underlying calculations of the data presented.

---

## 1. Dashboard Page
**Goal**: Provide a high-level, real-time overview of network health and critical metrics.
**Importance**: Allows immediate identification of network outages, congestion, or security threats.

### A. Global Controls
*   **Time Range Selector**: Allows filtering historical data. Options:
    *   *Last 30 Minutes* (Real-time troubleshooting)
    *   *Last 24 Hours* (Default view)
    *   *Last 7 Days* (Weekly trend)
    *   *Last 30 Days* (Monthly capacity planning)
*   **Export Report**: Generates a CSV Executive Summary containing all KPIs and Top-N lists (Sources, Destinations, Ports).
*   **Last Updated**: Timestamp showing when the data snapshot was taken (auto-refreshes).
*   **Database Status**: Indicator showing connection health to PostgreSQL (Green = Connected, Red = Disconnected).

### B. Network Health Score (Gauge)
*   **Representation**: A 0-100 score indicating overall system stability.
*   **Formula**:
    ```javascript
    Score = 100 - (LossPenalty + RetransPenalty + PortScanPenalty + ArpPenalty)
    
    // Detailed Penalty Calculations:
    // 1. LossPenalty = (connection_failure_rate * 50)      -> High impact (Max 50 pts)
    // 2. RetransPenalty = (tcp_rst_ratio * 20)             -> Medium impact (Max 20 pts)
    // 3. PortScanPenalty = (port_scan_score * 15)          -> Security impact (Max 15 pts)
    // 4. ArpPenalty = 10 (if ARP Rate > 10 pps)            -> Storm detection (Flat 10 pts)
    ```
*   **Interpretation**: >90 is Excellent, <70 indicates issues.

### C. Main KPI Cards
1.  **Peak Traffic**: Highest recorded bandwidth rate.
    *   *Calculation*: `max(byte_rate_bps) * 8` (converted to Mbps/Gbps).
2.  **Avg Traffic**: Current bandwidth usage.
    *   *Calculation*: `current_byte_rate_bps * 8` (converted to Mbps/Gbps).
3.  **Total Packets**: Cumulative count of processed packets since server start.
4.  **Active Connections**: Number of active TCP sessions.
    *   *Calculation*: Count of unique TCP flows or tracked connections in state table.

### D. Secondary Metrics
1.  **Packet Loss**: Percentage of failed connection attempts.
    *   *Formula*: `(connection_failure_rate * 100)`%
    *   *Visual Alert*: Turns **RED** if Loss > 1.0%.
2.  **Avg Latency**: Mean inter-arrival time between packets.
    *   *Formula*: `inter_arrival_time_mean * 1000` (ms)
    *   *Visual Alert*: Turns **RED** if Latency > 100ms.
3.  **Bandwidth Usage**: % Utilization of interface capacity.
    *   *Formula*: `(Current_Bps / Interface_Speed) * 100` (Default 1Gbps).
4.  **TCP Traffic**: Percentage of traffic that is TCP.
    *   *Formula*: `(tcp_count / total_packets) * 100`
5.  **Packets/sec**: Current throughput in PPS.
    *   *Source*: Backend aggregated `packet_rate_pps`.

### E. Charts
1.  **Traffic Volume (24h)**: Line chart of bandwidth trend.
2.  **Protocol Distribution**: Doughnut chart (TCP/UDP/ICMP/Other).
3.  **Protocol Traffic Trends**: Stacked area chart showing how protocols evolve over time.
4.  **Packet Size Distribution**: Bar chart of packet sizes (<100B, >1500B, etc.).

### F. Top Talker Tables
1.  **Top Source IPs**: List of IPs sending the most traffic.
2.  **Top Destination IPs**: List of IP targets receiving the most traffic.
3.  **Top Ports Usage**: Most active ports (e.g., 80, 443, 22) and their mapped services.
    *   *Columns*: Address/Port, Packet Count, Percentage of Total.

---

## 2. Analytics Page
**Goal**: Detailed inspection of network behavior and specific feature analysis.
**Importance**: Used for deep-dive troubleshooting and individual IP forensic analysis.

### A. Controls
*   **Generate Report**: Detailed PDF/CSV report of current analytics view.
*   **Feature Inspector**:
    *   **Search**: Filter all 63 features by specific IP address.
    *   **Inspect/Reset**: Load specific IP data or reset to global view.

### B. KPI Cards
1.  **Network Health**: Same metric as Dashboard, but focused view.
2.  **Connection Quality**: Composite score (0-100) based on stability.
    *   *Formula*: `(SuccessRate * 0.4 + SynAckHealth * 0.4 + RstHealth * 0.2) * 100`
3.  **Protocol Diversity**: Shannon Entropy score (0-1.0).
    *   *Formula*: `(-sum(p * log2(p))) / 2`
    *   *Meaning*: Higher score = more diverse traffic mix; Lower = monotonous (potential attack).
4.  **Traffic Efficiency**: Ratio of useful payload to headers/retransmissions.
    *   *Formula*: `(PayloadRatio * 0.4 + ProtoEfficiency * 0.3 + RetransEfficiency * 0.3) * 100`

### C. Charts (Grid View)
1.  **Network Health Gauge**: Visual representation of the overall stability score.
2.  **Connection Success Rate**: Line chart tracking successful vs failed handshakes over time.
3.  **TCP Flags Analysis**: Bar chart comparing TCP Control Flags (SYN, ACK, FIN, RST).
    *   *Use Case*: High SYN with low ACK indicates SYN Flood. High RST indicates connection rejection.
4.  **DNS Activity Analysis**: Histogram of DNS query/response volumes.

### D. Deep Packet Inspection (Feature Grid)
*   **Representation**: A complete readout of all 63 raw features extracted by the engine.
*   **Key Categories**:
    *   **Traffic Counters**: Packet counts, Byte rates.
    *   **TCP Analysis**: Flag counts, Window sizes, Urgency pointers.
    *   **Time Analysis**: Inter-arrival times, Jitter stats.
    *   **DNS Stats**: Query/Response counts, Length stats.

---

## 3. Performance Page
**Goal**: Analyze efficiency and quality of service (QoS).
**Importance**: Optimizing network throughput and reducing waste.

### A. Efficiency KPI Cards
1.  **Bandwidth Utilization**: Percent of interface capacity used.
    *   *Formula*: `(Current_Bps * 8 / Interface_Speed) * 100` (Assumes 1Gbps link).
    *   *Interpretation*: >80% indicates congestion.
2.  **Avg Packet Size**: Mean size of captured frames.
    *   *Significance*: Very small (<64B) suggests control traffic/attacks; Very large (>1300B) suggests file transfers.
3.  **SYN-ACK Ratio**: Success rate of TCP handshakes.
    *   *Formula*: `tcp_ack_count / tcp_syn_count`
    *   *Interpretation*: Should be ~1.0. Low ratio (<0.5) implies connection failures or SYN flooding.
4.  **Inter-Arrival Time**: Average time gap between packets.
    *   *Significance*: Low variance = smooth flow (VoIP); High variance = Jitter.

### B. Performance Charts
1.  **Byte Rate Over Time**: Line chart of bandwidth (MB/s).
2.  **Packet Rate Over Time**: Line chart of throughput (PPS).
    *   *Analysis*: Comparing these two reveals efficiency. High PPS + Low Byte Rate = Inefficient (Small packets).
3.  **Unique Destinations**: Bar chart comparing Unique Target IPs vs Unique Target Ports.
    *   *Use Case*: If Ports >> IPs, it indicates Port Scanning.
4.  **Port Scan Score (Gauge)**: Calculated risk score (0-100).
    *   *Formula*: `min(1.0, (unique_dst_ports / unique_dst_ips) / 100)`
    *   *Visual Alert*: Gauge turns Orange > 40, Red > 70.

---

## 4. Security Page
**Goal**: Detect and visualize cyber threats using AI and heuristics.
**Importance**: Proactive defense against DDoS, Scanning, and Tunneling.

### A. Global Status Indicator
*   **Alert Banner**: Top-level visual indicator.
    *   **Green**: "All Clear" - No active threats.
    *   **Red**: "Threat Detected" - Displays specific attack type (e.g., "DDoS Attack Detected").

### B. Security KPI Cards
1.  **ML Detection Status**: Application of XGBoost AI model.
    *   *States*: Normal, DDoS, Port Scan, DNS Tunnel, Brute Force.
2.  **ML Confidence**: Probability score of the current prediction (0-100%).
3.  **Threat Level**: Risk assessment (NONE, LOW, HIGH, CRITICAL).
4.  **DNS Health**: Composite security score for DNS traffic.
    *   *Formula*: `100 - (TunnelingRisk * 100)`
    *   *Risk Factors*: Query Length (>60 chars), Burst Ratio (>10% total traffic), Unanswered Queries.

### C. Telegram Threat Alerts
*   **Configuration**: Integration with Telegram via Webhook (ngrok).
*   **Broadcast**: Manual capability to send security alerts to all subscribers.
*   **Statistics**: Tracking of total subscribers and alerts delivered today.

### D. Security Charts
1.  **Attack Type Probabilities**: Bar chart showing the AI model's confidence distribution across all attack classes.
2.  **Port Activity Heatmap**: Visual grid/bubble chart identifying which ports are being targeted most aggressively.
3.  **Connection Failure Analysis**: Trend line of failed connections. High failure rates often indicate Brute Force or DDoS.
4.  **DNS Query Length**: Histogram of query sizes.
    *   *Significance*: Right-skewed distribution (many large queries) indicates **DNS Tunneling**.

### E. Threat Incident Log
*   **Representation**: Scrollable history of all detected security events.
*   **Columns**: Timestamp, Threat Type, Source IP, Confidence, Status (Active/Resolved).

---

## 5. Packets Page
**Goal**: Raw data inspection and forensic analysis of individual frames.
**Importance**: Validating specific events or debugging network connectivity issues logic.

### A. Controls
*   **Protocol Filter**: Dropdown to isolate specific traffic types (TCP, UDP, ICMP, ARP).
*   **Search Bar**: Server-side filter searching for Source or Destination IP addresses.
*   **Export CSV**: Downloads the currently filtered dataset for external analysis (Wireshark/Excel).

### B. Packet Table
*   **Pagination**: Server-side paging (20 packets per page) for performance.
*   **Columns**:
    1.  **Timestamp**: Exact arrival time.
    2.  **Src IP**: Originating address.
    3.  **Dst IP**: Target address.
    4.  **Protocol**: Layer 4 protocol (color-coded badge).
    5.  **Src Port**: Originating port.
    6.  **Dst Port**: Target/Service port.
    7.  **Length**: Frame size in bytes.
    8.  **Flags**: TCP Control flags (e.g., [S], [A], [F], [R]).
