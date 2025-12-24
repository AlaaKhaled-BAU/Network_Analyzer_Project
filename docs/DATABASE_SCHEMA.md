# Database Schema Reference

Complete database schema for the Network Analyzer project.

---

## Table 1: `raw_packets` (34 columns)

Raw packet storage for audit trail and debugging.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| id | Integer | PK | Auto-increment ID |
| timestamp | Float | No | Unix timestamp |
| interface | String | No | Network interface |
| src_ip | String | No | Source IP |
| dst_ip | String | No | Destination IP |
| protocol | String | No | TCP/UDP/ICMP/ARP |
| length | Integer | No | Packet size (bytes) |
| src_port | Integer | Yes | Source port |
| dst_port | Integer | Yes | Destination port |
| tcp_flags | String | Yes | TCP flag string |
| tcp_syn | Boolean | Yes | SYN flag |
| tcp_ack | Boolean | Yes | ACK flag |
| tcp_fin | Boolean | Yes | FIN flag |
| tcp_rst | Boolean | Yes | RST flag |
| tcp_psh | Boolean | Yes | PSH flag |
| seq | Integer | Yes | TCP sequence number |
| ack | Integer | Yes | TCP acknowledgment number |
| icmp_type | Integer | Yes | ICMP type |
| icmp_code | Integer | Yes | ICMP code |
| arp_op | Integer | Yes | ARP operation (1=request, 2=reply) |
| arp_psrc | String | Yes | ARP source IP |
| arp_pdst | String | Yes | ARP destination IP |
| arp_hwsrc | String | Yes | ARP source MAC |
| arp_hwdst | String | Yes | ARP destination MAC |
| dns_query | Boolean | Yes | Is DNS query |
| dns_qname | String | Yes | DNS query name |
| dns_qtype | Integer | Yes | DNS query type |
| dns_response | Boolean | Yes | Is DNS response |
| dns_answer_count | Integer | Yes | DNS answer count |
| dns_answer_size | Integer | Yes | DNS answer size |
| http_method | String | Yes | HTTP method |
| http_path | String | Yes | HTTP path |
| http_status_code | String | Yes | HTTP status code |
| http_host | String | Yes | HTTP host header |
| inserted_at | DateTime | No | Record insertion time |

---

## Table 2: `aggregated_features` (71 columns)

Multi-window aggregated features for ML prediction.

### Identity (5 columns)

| Column | Type | Description |
|--------|------|-------------|
| id | Integer PK | Auto-increment ID |
| src_ip | String | Source IP address |
| window_start | DateTime | Window start time |
| window_end | DateTime | Window end time |
| window_size | Integer | Window size (5, 30, or 180 seconds) |

### Generic Features (12 columns)

| Column | Type | Description |
|--------|------|-------------|
| packet_count | Integer | Total packets in window |
| packet_rate_pps | Float | Packets per second |
| byte_count | Integer | Total bytes |
| byte_rate_bps | Float | Bits per second |
| avg_packet_size | Float | Average packet size |
| packet_size_variance | Float | Packet size variance |
| tcp_count | Integer | TCP packet count |
| udp_count | Integer | UDP packet count |
| icmp_count | Integer | ICMP packet count |
| arp_count | Integer | ARP packet count |
| unique_dst_ips | Integer | Unique destination IPs |
| unique_dst_ports | Integer | Unique destination ports |

### TCP/DDoS/Scan Features (13 columns)

| Column | Type | Description |
|--------|------|-------------|
| tcp_syn_count | Integer | SYN packets |
| tcp_ack_count | Integer | ACK packets |
| syn_rate_pps | Float | SYN packets per second |
| syn_ack_rate_pps | Float | SYN-ACK packets per second |
| syn_to_synack_ratio | Float | SYN to SYN-ACK ratio |
| half_open_count | Integer | Half-open connections |
| sequential_port_count | Integer | Sequential port accesses |
| scan_rate_pps | Float | Port scan rate |
| distinct_targets_count | Integer | Unique target IPs |
| syn_only_ratio | Float | SYN-only traffic ratio |
| icmp_rate_pps | Float | ICMP packets per second |
| udp_rate_pps | Float | UDP packets per second |
| udp_dest_port_count | Integer | Unique UDP destination ports |

### Bruteforce Features (6 columns)

| Column | Type | Description |
|--------|------|-------------|
| ssh_connection_attempts | Integer | SSH connection attempts (port 22) |
| ftp_connection_attempts | Integer | FTP connection attempts (port 20/21) |
| http_login_attempts | Integer | HTTP login attempts |
| login_request_rate | Float | Login requests per second |
| failed_login_count | Integer | Failed logins (401/403) |
| auth_attempts_per_min | Float | Authentication attempts per minute |

### ARP Features (10 columns)

| Column | Type | Description |
|--------|------|-------------|
| arp_request_count | Integer | ARP requests |
| arp_reply_count | Integer | ARP replies |
| gratuitous_arp_count | Integer | Gratuitous ARP packets |
| arp_binding_flap_count | Integer | MAC-IP binding changes |
| arp_reply_without_request_count | Integer | Unsolicited ARP replies |
| unique_macs_per_ip_max | Integer | Max MACs seen for any IP |
| avg_macs_per_ip | Float | Average MACs per IP |
| duplicate_mac_ips | Integer | IPs sharing same MAC |
| mac_ip_ratio | Float | MAC to IP ratio |
| suspicious_mac_changes | Integer | IPs with >1 MAC |

### DNS Features (14 columns)

| Column | Type | Description |
|--------|------|-------------|
| dns_query_count | Integer | DNS queries |
| query_rate_qps | Float | Queries per second |
| unique_qnames_count | Integer | Unique query names |
| avg_subdomain_entropy | Float | Average subdomain entropy |
| pct_high_entropy_queries | Float | % high entropy queries |
| txt_record_count | Integer | TXT record queries |
| avg_answer_size | Float | Average DNS answer size |
| distinct_record_types | Integer | Distinct DNS record types |
| avg_query_interval_ms | Float | Average query interval (ms) |
| avg_subdomain_length | Float | Average subdomain length |
| max_subdomain_length | Integer | Max subdomain length |
| avg_label_count | Float | Average DNS label count |
| dns_to_udp_ratio | Float | DNS to UDP traffic ratio |
| udp_port_53_count | Integer | UDP port 53 packets |

### Slowloris Features (5 columns)

| Column | Type | Description |
|--------|------|-------------|
| open_conn_count | Integer | Open connections |
| avg_conn_duration | Float | Average connection duration |
| bytes_per_conn | Float | Bytes per connection |
| partial_http_count | Integer | Partial HTTP requests |
| request_completion_ratio | Float | HTTP request completion ratio |

### Port Category Features (3 columns)

| Column | Type | Description |
|--------|------|-------------|
| tcp_ports_hit | Integer | Unique TCP ports hit (out of 26 monitored) |
| udp_ports_hit | Integer | Unique UDP ports hit (out of 6 monitored) |
| remote_conn_port_hits | Integer | Hits to remote access ports (22, 23, 2222, 3389, 5900, 5901) |

### ML Output (2 columns)

| Column | Type | Description |
|--------|------|-------------|
| predicted_label | String | ML prediction result |
| confidence | Float | Prediction confidence (0-1) |

### Metadata (1 column)

| Column | Type | Description |
|--------|------|-------------|
| created_at | DateTime | Record creation time |

---

## Table 3: `detected_alerts` (13 columns)

Security alerts generated by ML detection.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| id | Integer | PK | Auto-increment ID |
| src_ip | String | No | Attacker IP |
| dst_ip | String | Yes | Target IP |
| attack_type | String | No | Classification result |
| confidence | Float | No | ML confidence (0-100) |
| severity | String | No | LOW/MEDIUM/HIGH/CRITICAL |
| window_size | Integer | No | Detection window (5/30/180) |
| packet_count | Integer | No | Packets in window |
| byte_count | Integer | No | Bytes in window |
| details | Text | Yes | JSON with additional info |
| detected_at | DateTime | No | Alert timestamp |
| resolved | Boolean | No | Resolution status |
| resolved_at | DateTime | Yes | Resolution timestamp |
| created_at | DateTime | No | Record creation time |

---

## Attack Types (9 classes)

| Index | Label | Description |
|-------|-------|-------------|
| 0 | Normal | Legitimate traffic |
| 1 | arp_spoof | ARP spoofing attack |
| 2 | dns_tunnel | DNS tunneling |
| 3 | icmp_flood | ICMP flood DDoS |
| 4 | port_scan | Port scanning |
| 5 | slowloris | Slowloris HTTP attack |
| 6 | ssh_brute | SSH brute force |
| 7 | syn_flood | SYN flood DDoS |
| 8 | udp_flood | UDP flood DDoS |
