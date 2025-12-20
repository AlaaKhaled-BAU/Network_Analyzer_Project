# Dashboard KPI Feasibility Analysis

Analysis of all dashboard KPIs - whether each can be extracted from `raw_packets`, `aggregated_features`, or derived via formulas.

---

## 📊 DASHBOARD PAGE

| KPI | Source | Feasible? | How |
|-----|--------|-----------|-----|
| **Peak Traffic** | `aggregated_features` | ✅ YES | `MAX(byte_rate_bps)` over time window |
| **Avg Traffic** | `aggregated_features` | ✅ YES | `AVG(byte_rate_bps)` or direct field |
| **Total Packets** | `aggregated_features` | ✅ YES | `SUM(packet_count)` |
| **Active Connections** | `aggregated_features` | ✅ YES | Use `open_conn_count` OR derive: `tcp_syn_count - half_open_count` |
| **Packet Loss** | Derived | ✅ YES | Derive: `(tcp_syn_count - tcp_ack_count) / tcp_syn_count` |
| **Avg Latency** | `raw_packets` | ✅ YES | Calculate inter-arrival: `AVG(timestamp[i+1] - timestamp[i])` per flow |
| **Bandwidth Usage** | `aggregated_features` | ✅ YES | `byte_rate_bps * 8` (needs configurable max) |
| **TCP Traffic %** | `aggregated_features` | ✅ YES | `tcp_count / packet_count * 100` |
| **Packets/sec** | `aggregated_features` | ✅ YES | Direct: `packet_rate_pps` |
| **Top Source IPs** | `raw_packets` | ✅ YES | `GROUP BY src_ip ORDER BY COUNT(*)` |
| **Top Dest IPs** | `raw_packets` | ✅ YES | `GROUP BY dst_ip ORDER BY COUNT(*)` |
| **Top Ports** | `raw_packets` | ✅ YES | `GROUP BY dst_port ORDER BY COUNT(*)` |
| **Traffic Volume Chart** | `aggregated_features` | ✅ YES | Query by `window_start` timestamp, aggregate `byte_count` |
| **Protocol Distribution** | `aggregated_features` | ✅ YES | `tcp_count`, `udp_count`, `icmp_count`, `arp_count` |
| **Inbound vs Outbound** | `raw_packets` | ⚠️ PARTIAL | Need to define "local" IPs, then filter by `src_ip`/`dst_ip` matching local subnet |
| **Packet Size Distribution** | `raw_packets` | ✅ YES | `GROUP BY CASE WHEN length < 100 THEN '<100' ... END` histogram |

---

## 📈 ANALYTICS PAGE

| KPI | Source | Feasible? | How |
|-----|--------|-----------|-----|
| **Network Health** | Derived | ✅ YES | Formula using `syn_to_synack_ratio`, `tcp_count`, `arp_count` |
| **Connection Quality** | Derived | ✅ YES | Use `syn_to_synack_ratio`, `half_open_count` |
| **Protocol Diversity** | `aggregated_features` | ✅ YES | Entropy: `-Σ(p * log2(p))` where p = protocol_count/total |
| **Traffic Efficiency** | Derived | ✅ YES | Formula using `avg_packet_size`, `tcp_ack_count`, `packet_count` |
| **Health Gauge** | Derived | ✅ YES | Same as Network Health |
| **Connection Success** | `aggregated_features` | ✅ YES | `1 - syn_only_ratio` or `syn_to_synack_ratio` |
| **TCP Flags Chart** | `raw_packets` | ✅ YES | Count: `SUM(tcp_syn)`, `SUM(tcp_ack)`, `SUM(tcp_fin)`, `SUM(tcp_rst)`, `SUM(tcp_psh)` |
| **DNS Analysis** | `aggregated_features` | ✅ YES | `dns_query_count`, `query_rate_qps`, `unique_qnames_count`, `avg_subdomain_entropy` |

---

## 🔒 SECURITY PAGE

| KPI | Source | Feasible? | How |
|-----|--------|-----------|-----|
| **ML Detection Status** | `aggregated_features` | ✅ YES | `predicted_label` field |
| **ML Confidence** | `aggregated_features` | ✅ YES | `confidence` field |
| **Threat Level** | Derived | ✅ YES | Derive from `predicted_label` + `confidence` thresholds |
| **DNS Health** | `aggregated_features` | ✅ YES | Use `avg_subdomain_entropy`, `pct_high_entropy_queries`, `txt_record_count` |
| **Attack Probabilities** | ML model | ✅ YES | Model's `predict_proba()` returns class probabilities |
| **Port Activity Heatmap** | `raw_packets` | ✅ YES | `GROUP BY dst_port, HOUR(timestamp) ORDER BY COUNT(*)` |
| **Connection Failure** | `aggregated_features` | ✅ YES | Time-series of `half_open_count` or `syn_only_ratio` by `window_start` |
| **DNS Query Length Dist** | `raw_packets` | ✅ YES | `GROUP BY LENGTH(dns_qname) RANGE` from `dns_qname` field |

---

## ⚡ PERFORMANCE PAGE

| KPI | Source | Feasible? | How |
|-----|--------|-----------|-----|
| **Bandwidth Utilization** | `aggregated_features` | ✅ YES | `byte_rate_bps` (needs configurable max) |
| **Avg Packet Size** | `aggregated_features` | ✅ YES | Direct: `avg_packet_size` |
| **SYN-ACK Ratio** | `aggregated_features` | ✅ YES | Direct: `syn_to_synack_ratio` |
| **Inter-Arrival Time** | `raw_packets` | ✅ YES | `AVG(t2-t1)` from consecutive packets per src_ip |
| **Byte Rate Chart** | `aggregated_features` | ✅ YES | Query `byte_rate_bps` by `window_start` over time |
| **Packet Rate Chart** | `aggregated_features` | ✅ YES | Query `packet_rate_pps` by `window_start` over time |
| **Unique Dest Trend** | `aggregated_features` | ✅ YES | Query `unique_dst_ips` by `window_start` over time |
| **Port Scan Score** | `aggregated_features` | ✅ YES | Use `scan_rate_pps`, `sequential_port_count`, `distinct_targets_count` |

---

## Summary

| Verdict | Count | Notes |
|---------|-------|-------|
| ✅ **Fully Extractable** | **31** | Direct fields or SQL/formulas |
| ⚠️ **Partial** | **1** | Inbound vs Outbound (needs local subnet config) |
| ❌ **Impossible** | **0** | None |

**All 32 KPIs are extractable** from the database schema.
