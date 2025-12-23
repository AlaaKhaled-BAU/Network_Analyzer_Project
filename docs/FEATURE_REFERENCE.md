# Aggregated Feature Reference

Complete list of all 71 aggregated features extracted by `MultiWindowAggregator.py`, their importance for ML detection, and associated attack types.

---

## 🌐 Generic Network Features (12 columns)

These are fundamental traffic metrics used as baseline for all attack detection.

| Feature | Description | Why Important | Associated Attacks |
|---------|-------------|---------------|-------------------|
| `packet_count` | Total packets in window | Baseline metric; sudden spikes indicate flooding attacks | **DDoS**, **SYN Flood**, **UDP Flood** |
| `packet_rate_pps` | Packets per second | Rate-based detection; high rates indicate flooding | **All DDoS variants** |
| `byte_count` | Total bytes transferred | Volume-based detection | **DDoS**, **Data Exfiltration** |
| `byte_rate_bps` | Bits per second | Bandwidth consumption monitoring | **Volumetric DDoS** |
| `avg_packet_size` | Average packet size | Small packets = SYN flood; Large = amplification | **SYN Flood**, **DNS Amplification** |
| `packet_size_variance` | Packet size variance | Low variance = automated attack; High = normal traffic | **Bot attacks**, **Scripted attacks** |
| `tcp_count` | TCP packet count | Protocol distribution baseline | **SYN Flood**, **Slowloris** |
| `udp_count` | UDP packet count | UDP-based attack detection | **UDP Flood**, **DNS Amplification** |
| `icmp_count` | ICMP packet count | ICMP-based attack detection | **Ping Flood**, **ICMP Tunneling** |
| `arp_count` | ARP packet count | LAN-level attack detection | **ARP Spoofing/Poisoning** |
| `unique_dst_ips` | Unique destination IPs | Fan-out pattern detection | **Port Scan**, **Worm propagation** |
| `unique_dst_ports` | Unique destination ports | Port scanning detection | **Port Scan**, **Service enumeration** |

---

## 🔥 TCP/DDoS/Scan Features (13 columns)

Critical features for detecting TCP-based attacks and reconnaissance.

| Feature | Description | Why Important | Associated Attacks |
|---------|-------------|---------------|-------------------|
| `tcp_syn_count` | SYN packets sent | High SYN without ACK = flood | **SYN Flood** |
| `tcp_ack_count` | ACK packets received | SYN/ACK ratio indicates attack | **SYN Flood** |
| `syn_rate_pps` | SYN packets per second | Rate-based SYN flood detection | **SYN Flood** |
| `syn_ack_rate_pps` | SYN-ACK packets/sec | Low SYN-ACK = server overwhelmed | **SYN Flood** |
| `syn_to_synack_ratio` | SYN to SYN-ACK ratio | **KEY INDICATOR**: Ratio > 3:1 = attack | **SYN Flood** |
| `half_open_count` | Half-open connections | Resources exhaustion indicator | **SYN Flood**, **Slowloris** |
| `sequential_port_count` | Sequential port access | Pattern indicates port scanning | **Port Scan** |
| `scan_rate_pps` | Scan rate per second | Fast scanning detection | **Port Scan**, **Service enumeration** |
| `distinct_targets_count` | Unique targets scanned | Wide scanning = reconnaissance | **Port Scan**, **Network mapping** |
| `syn_only_ratio` | % traffic that is SYN-only | High % = SYN flood | **SYN Flood** |
| `icmp_rate_pps` | ICMP packets per second | ICMP flood detection | **Ping Flood**, **Smurf Attack** |
| `udp_rate_pps` | UDP packets per second | UDP flood detection | **UDP Flood** |
| `udp_dest_port_count` | Unique UDP dest ports | Random ports = UDP flood | **UDP Flood**, **Amplification** |

---

## 🔐 Bruteforce Features (6 columns)

Features for detecting credential-guessing attacks.

| Feature | Description | Why Important | Associated Attacks |
|---------|-------------|---------------|-------------------|
| `ssh_connection_attempts` | SSH connections (port 22) | High count = SSH brute force | **SSH Brute Force** |
| `ftp_connection_attempts` | FTP connections (port 20/21) | High count = FTP brute force | **FTP Brute Force** |
| `http_login_attempts` | HTTP login POST requests | Repeated logins = web brute force | **Web Login Brute Force** |
| `login_request_rate` | Login requests per second | Fast attempts = automated attack | **Credential Stuffing** |
| `failed_login_count` | HTTP 401/403 responses | Many failures = guessing attack | **Brute Force**, **Credential Stuffing** |
| `auth_attempts_per_min` | Auth attempts per minute | Rate limiting threshold | **All Brute Force variants** |

---

## 📡 ARP Spoofing Features (10 columns)

Features for detecting LAN-level MITM attacks.

| Feature | Description | Why Important | Associated Attacks |
|---------|-------------|---------------|-------------------|
| `arp_request_count` | ARP requests sent | Baseline ARP activity | **ARP Spoofing** |
| `arp_reply_count` | ARP replies received | Many replies = potential spoofing | **ARP Spoofing** |
| `gratuitous_arp_count` | Unsolicited ARP announcements | **KEY INDICATOR**: High = spoofing | **ARP Spoofing/Poisoning** |
| `arp_binding_flap_count` | MAC-IP changes | Rapid changes = active spoofing | **ARP Spoofing** |
| `arp_reply_without_request_count` | Unrequested ARP replies | **KEY INDICATOR**: Spoofing sign | **ARP Spoofing** |
| `unique_macs_per_ip_max` | Max MACs seen per IP | Multiple MACs = MITM attempt | **ARP Spoofing**, **MITM** |
| `avg_macs_per_ip` | Average MACs per IP | Should be ~1; higher = anomaly | **ARP Spoofing** |
| `duplicate_mac_ips` | IPs sharing same MAC | Gateway impersonation | **ARP Spoofing**, **Gateway hijack** |
| `mac_ip_ratio` | MAC to IP ratio | Low ratio = many IPs per MAC | **ARP Spoofing** |
| `suspicious_mac_changes` | IPs with >1 MAC | Direct spoofing indicator | **ARP Spoofing** |

---

## 🌍 DNS Tunneling Features (14 columns)

Features for detecting data exfiltration via DNS.

| Feature | Description | Why Important | Associated Attacks |
|---------|-------------|---------------|-------------------|
| `dns_query_count` | Total DNS queries | High volume = potential tunneling | **DNS Tunneling** |
| `query_rate_qps` | Queries per second | Fast queries = automated exfil | **DNS Tunneling** |
| `unique_qnames_count` | Unique query names | Many unique = encoded data | **DNS Tunneling** |
| `avg_subdomain_entropy` | Subdomain randomness | **KEY INDICATOR**: High entropy = encoded data | **DNS Tunneling** |
| `pct_high_entropy_queries` | % high-entropy queries | High % = tunneling | **DNS Tunneling** |
| `txt_record_count` | TXT record requests | **KEY INDICATOR**: TXT used for tunneling | **DNS Tunneling** |
| `avg_answer_size` | Average DNS response size | Large responses = data transfer | **DNS Tunneling**, **DNS Amplification** |
| `distinct_record_types` | Unique DNS record types | Many types = reconnaissance | **DNS Enumeration** |
| `avg_query_interval_ms` | Query timing | Regular intervals = automated | **DNS Tunneling** |
| `avg_subdomain_length` | Subdomain length | Long subdomains = encoded payload | **DNS Tunneling** |
| `max_subdomain_length` | Maximum subdomain length | Very long = suspicious | **DNS Tunneling** |
| `avg_label_count` | DNS label count | Many labels = tunneling | **DNS Tunneling** |
| `dns_to_udp_ratio` | DNS to UDP traffic ratio | High ratio = DNS abuse | **DNS Tunneling**, **DNS Amplification** |
| `udp_port_53_count` | UDP port 53 packets | DNS traffic volume | **DNS-based attacks** |

---

## 🐢 Slowloris Features (5 columns)

Features for detecting HTTP slow attacks.

| Feature | Description | Why Important | Associated Attacks |
|---------|-------------|---------------|-------------------|
| `open_conn_count` | Open connections | **KEY INDICATOR**: Many open = Slowloris | **Slowloris** |
| `avg_conn_duration` | Connection duration | Long-lived connections = slow attack | **Slowloris**, **Slow Read** |
| `long_lived_conn_count` | Connections >30s | Abnormal connection retention | **Slowloris** |
| `incomplete_http_ratio` | % incomplete HTTP | High % = Slowloris | **Slowloris**, **Slow POST** |
| `connection_rate` | New connections/sec | Slow but steady = Slowloris pattern | **Slowloris** |

---

## 📊 Meta/ML Features (6 columns)

Window identification and ML output.

| Feature | Description | Why Important | Associated Attacks |
|---------|-------------|---------------|-------------------|
| `src_ip` | Source IP address | Identify attack source | All |
| `window_start` | Window start time | Time-series analysis | All |
| `window_end` | Window end time | Window bounds | All |
| `window_size` | Window duration (5/30/180s) | Multi-scale detection | All |
| `predicted_label` | ML classification result | Attack type prediction | All |
| `created_at` | Record creation time | Audit trail | All |

---

## 🎯 Attack Detection Summary

| Attack Type | Key Features to Monitor | Detection Threshold |
|-------------|------------------------|---------------------|
| **SYN Flood** | `syn_to_synack_ratio`, `half_open_count`, `syn_rate_pps` | Ratio > 3:1 |
| **UDP Flood** | `udp_rate_pps`, `udp_dest_port_count` | Rate > 10,000 pps |
| **Port Scan** | `sequential_port_count`, `unique_dst_ports`, `scan_rate_pps` | >50 ports/min |
| **SSH Brute Force** | `ssh_connection_attempts`, `auth_attempts_per_min` | >10 attempts/min |
| **ARP Spoofing** | `gratuitous_arp_count`, `arp_reply_without_request_count` | >5 unsolicited |
| **DNS Tunneling** | `avg_subdomain_entropy`, `txt_record_count`, `pct_high_entropy_queries` | Entropy > 3.5 |
| **Slowloris** | `open_conn_count`, `incomplete_http_ratio`, `avg_conn_duration` | >100 half-open |
| **ICMP Flood** | `icmp_rate_pps`, `icmp_count` | Rate > 1,000 pps |

---

## 📈 Feature Importance for ML

Features ranked by typical importance in XGBoost model:

1. 🥇 `syn_to_synack_ratio` - Best DDoS indicator
2. 🥈 `avg_subdomain_entropy` - Best DNS tunneling indicator  
3. 🥉 `half_open_count` - Resource exhaustion indicator
4. `packet_rate_pps` - Volume-based detection
5. `gratuitous_arp_count` - ARP spoofing indicator
6. `unique_dst_ports` - Port scan indicator
7. `ssh_connection_attempts` - Brute force indicator
---

## ⚠️ Duplicate & Low-Importance Features

Features that may be redundant, derived from others, or have low ML importance.

### Duplicate/Redundant Features

| Feature | Duplicates/Overlaps With | Recommendation |
|---------|--------------------------|----------------|
| `byte_count` | `byte_rate_bps * window_size` | Keep `byte_rate_bps` (normalized) |
| `packet_count` | `packet_rate_pps * window_size` | Keep `packet_rate_pps` (normalized) |
| `tcp_syn_count` | `syn_rate_pps * window_size` | Keep `syn_rate_pps` (rate-based) |
| `tcp_ack_count` | Used only to derive `syn_to_synack_ratio` | Keep only the ratio |
| `arp_request_count` | Low value; `gratuitous_arp_count` is key | Consider removing |
| `arp_reply_count` | `arp_reply_without_request_count` is more specific | Consider removing |
| `udp_port_53_count` | Overlaps with `dns_query_count` | Keep DNS-specific |
| `avg_macs_per_ip` | Similar to `unique_macs_per_ip_max` | Keep max only |

### Low-Importance Features (Often Near-Zero)

| Feature | Why Low Importance | Recommendation |
|---------|-------------------|----------------|
| `ftp_connection_attempts` | FTP rarely used in modern networks | Keep for legacy networks |
| `http_login_attempts` | Requires HTTP parsing; often 0 | Keep if monitoring web apps |
| `distinct_record_types` | Low variance in normal traffic | Keep for DNS enumeration only |
| `avg_query_interval_ms` | Noisy metric | Consider removing |
| `connection_rate` | Overlaps with `open_conn_count` | Keep `open_conn_count` |

### Meta Features (Not for ML Training)

These should be **excluded from ML feature vectors**:

| Feature | Reason to Exclude |
|---------|------------------|
| `id` | Auto-increment ID |
| `src_ip` | Identifier, not numeric feature |
| `window_start` | Timestamp (use for grouping only) |
| `window_end` | Timestamp |
| `window_size` | Categorical (5/30/180) |
| `predicted_label` | ML output, not input! |
| `created_at` | Record timestamp |

### Features Recommended for Removal

If optimizing for model size/speed, consider removing these:

| Feature | Impact if Removed |
|---------|------------------|
| `packet_count` | ❌ Low - derived from rate × time |
| `byte_count` | ❌ Low - derived from rate × time |
| `tcp_ack_count` | ❌ Low - only used in ratio |
| `arp_request_count` | ❌ Low - normal ARP behavior |
| `avg_query_interval_ms` | ❌ Low - noisy |
| `connection_rate` | ❌ Low - redundant |

**Total Removable:** 6 features → Reduces from 71 to 65 columns

---

*Last Updated: 2025-12-23*

