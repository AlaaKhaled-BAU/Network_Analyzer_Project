# Changelog

## [2026-02-19T04:34] Server & ML Sync

### [Change] main.py — RawPacket ORM
- Added `src_mac`, `dst_mac`, `dhcp_type` columns to match sniffer output

### [Change] main.py — AggregatedFeature ORM
- Added 9 new features: `tcp_rst_count`, `tcp_fin_count`, `rst_to_syn_ratio`, `icmp_redirect_count`, `icmp_broadcast_count`, `unique_src_mac_count`, `land_attack_count`, `dhcp_discover_count`, `dhcp_discover_rate`
- Removed 12 dead features no longer produced by aggregator: `syn_ack_rate_pps`, `syn_to_synack_ratio`, `scan_rate_pps`, `http_login_attempts`, `login_request_rate`, `failed_login_count`, `avg_macs_per_ip`, `mac_ip_ratio`, `avg_answer_size`, `udp_port_53_count`, `request_completion_ratio`, `tcp_ports_hit`, `udp_ports_hit`

### [Change] main.py — prepare_packet_dict()
- Added `src_mac`, `dst_mac`, `dhcp_type` field mappings

### [Change] main.py — Aggregator init
- Updated window sizes from `[5, 30, 180]` → `[2, 5, 30, 180]`
- Updated inline processing from `window_sizes=[5]` → `[2, 5]`

### [Change] sniffer.py — SAVE_INTERVAL
- Reduced from 5s to 2s to match 2s detection window

## [2026-02-18]
- [Change] Added `process_dataframe()` to `MultiWindowAggregator.py` to support direct DataFrame processing without file I/O.
- [Change] Modified `server/app/main.py`: `_process_packets()` now uses `process_dataframe()` and runs `predict_and_alert()` inline.
- [Change] Modified `server/app/main.py`: Increased `PREDICTION_INTERVAL` from 10s to 30s.
- [Change] Modified `client/sniffer.py`: Reduced `SAVE_INTERVAL` from 5s to 2s.
- [Change] Modified `client/sender.py`: Reduced `POLL_INTERVAL` from 1s to 0.5s.

## [2026-02-18T13:21] Phase C: Attack Expansion

### [Change] sniffer.py — Added L2/DHCP capture
- Added `src_mac`, `dst_mac` fields (Ether layer) for all packets
- Added `dhcp_type` parsing (BOOTP/DHCP message-type option)
- Added imports: `Ether`, `BOOTP`, `DHCP`

### [Change] MultiWindowAggregator.py — Feature overhaul
- Default windows: `[5,30,180]` → `[2,5,30,180]`
- Added `_dhcp_features()` extractor
- Added features: `tcp_rst_count`, `tcp_fin_count`, `rst_to_syn_ratio`, `icmp_redirect_count`, `icmp_broadcast_count`, `unique_src_mac_count`, `land_attack_count`, `dhcp_discover_count`, `dhcp_discover_rate`
- Removed 13 dead features (see walkthrough)
- Fixed Slowloris `open_conn_count` grouping (dst-only → 4-tuple)

### [Fix] attack_core.py — 3 bug fixes
- Port scan: removed ACK packet generation (polluted syn_only_ratio)
- ARP spoof: added `gateway_ip` param, uses it as `psrc` instead of `my_ip`
- brute_force_basic: removed SYN-ACK and RST/RA packets (unrealistic)

### [Change] attack_core.py — 6 new attack implementations
- `dhcp_starvation_impl`: DHCP Discover flood with random MACs (L2/L3)
- `tcp_rst_impl`: Forged RST packets to kill connections (L4)
- `icmp_redirect_impl`: ICMP Type 5 route hijacking (L3)
- `cam_overflow_impl`: Random Source MAC broadcast flood (L2)
- `smurf_impl`: ICMP Echo to broadcast with spoofed source (L3)
- `land_impl`: TCP SYN where src_ip == dst_ip (L3/L4)

### [Change] attack_config.json — 6 new attack sections
- Added: dhcp_starvation, tcp_rst_injection, icmp_redirect, cam_overflow, smurf, land_attack
- Each with 3-4 variations across intensities and durations
- Refined config: Added `2s` duration variations to ALL 14 attack types (cloned from 5s variations) to match the new 2s detection window.
- Config Strategy Update: Implemented a Matrix Strategy for variations, decoupling intensity and duration. Added specific "Flash Burst" (High/2s) and "Stealth" (Low/180s) variations for all attack types.
- DDoS Simulation: Updated `attack_core.py` to use randomized source IPs (`RandIP`) for SYN, UDP, and ICMP floods, enabling simulation of Distributed Denial of Service (DDoS) attacks instead of just single-source DoS.
- [Feature] Implemented Advanced DNS Mirroring to simulate '8.8.8.8' destination visibility for sniffers (Destination Spoofing).
- [Modify] Updated `attack_core.py` to support `mirror_mac` and `preserve_dst` in `dns_tunnel_impl`.
- [Modify] Updated `attacker_gui.py` to pass these new parameters.
- [Config] Added new 'Destination Spoofing' variation to `dns_tunnel` in `attack_config.json`.
