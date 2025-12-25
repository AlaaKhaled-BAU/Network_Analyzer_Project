"""
Multi-Window Compact Network Traffic Aggregator for ML Training

Processes raw packet captures with multiple time scales:
- 5-second windows (base, fast attacks)
- 30-second windows (medium-term patterns)
- 3-minute windows (slow attacks, trends)

One record per (src_ip, window, window_size) with ~40 compact features.
"""

import pandas as pd
import numpy as np
import math
from datetime import datetime, timedelta
from pathlib import Path
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def str_to_bool(val):
    """Convert string boolean to Python boolean."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() == 'true'
    return bool(val)


class MultiWindowAggregator:
    """
    Aggregates raw packets into multiple window sizes simultaneously.
    Outputs one dataset with all window sizes labeled.
    """

    def __init__(self, window_sizes=[5, 30, 180]):
        """
        Args:
            window_sizes: List of window sizes in seconds.
                         Default: [5, 30, 180] for 5s, 30s, 3min
        """
        self.window_sizes = sorted(window_sizes)  # Process in order
        self.arp_cache = {}

    # ========== IO ==========

    def load_raw_packets(self, filepath):
        """Load raw packets from CSV/JSON and normalize timestamp and boolean columns."""
        filepath = Path(filepath)
        if filepath.suffix == ".csv":
            df = pd.read_csv(filepath)
        elif filepath.suffix == ".json":
            df = pd.read_json(filepath)
        else:
            raise ValueError(f"Unsupported file format: {filepath.suffix}")

        if "timestamp" not in df.columns:
            raise ValueError("Input must contain 'timestamp' column")

        # Convert to datetime
        if np.issubdtype(df["timestamp"].dtype, np.number):
            df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s", errors="coerce")
        else:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        df = df.dropna(subset=["timestamp"])
        
        # Normalize boolean columns (sniffer stores as strings 'True'/'False')
        bool_columns = ["tcp_syn", "tcp_ack", "tcp_fin", "tcp_rst", "tcp_psh", "dns_query", "dns_response"]
        for col in bool_columns:
            if col in df.columns:
                df[col] = df[col].apply(str_to_bool)
        
        # Fallback DNS detection: if dns_query is still False but it's UDP port 53, mark as DNS
        if "dns_query" in df.columns and "protocol" in df.columns and "dst_port" in df.columns:
            udp_port_53 = (df["protocol"] == "UDP") & (df["dst_port"].astype(str).isin(["53", "53.0"]))
            df.loc[udp_port_53 & (df["dns_query"] == False), "dns_query"] = True
        
        logger.info(f"Loaded {len(df)} packets from {filepath}")
        return df

    def load_multiple_files(self, filepaths):
        """
        Load and merge multiple CSV/JSON files by timestamp.
        
        Args:
            filepaths: List of file paths to load
            
        Returns:
            Combined DataFrame sorted by timestamp
        """
        all_dfs = []
        for fp in filepaths:
            try:
                df = self.load_raw_packets(fp)
                all_dfs.append(df)
            except Exception as e:
                logger.warning(f"Failed to load {fp}: {e}")
                
        if not all_dfs:
            raise ValueError("No valid files could be loaded")
            
        combined = pd.concat(all_dfs, ignore_index=True)
        combined = combined.sort_values("timestamp").reset_index(drop=True)
        logger.info(f"Combined {len(filepaths)} files → {len(combined)} total packets")
        return combined

    def extract_label_from_folder(self, folder_name):
        """
        Extract attack type label from folder name.
        e.g., 'syn_flood_var1' → 'syn_flood'
        """
        import re
        # Remove _varN suffix to get attack type
        match = re.match(r"(.+?)_var\d+", folder_name)
        if match:
            return match.group(1)
        return folder_name  # Fallback to full name

    def process_variation_folder(self, folder_path, label=None):
        """
        Process a single variation folder containing multiple CSV files.
        
        Args:
            folder_path: Path to variation folder (e.g., attack_datasets/syn_flood_var1)
            label: Optional label override. If None, uses 'attack_label' column from CSV.
                   Falls back to folder name if column is missing.
            
        Returns:
            DataFrame with aggregated features for all window sizes
        """
        folder_path = Path(folder_path)
        
        # Get all CSV files in folder
        csv_files = sorted(folder_path.glob("*.csv"))
        if not csv_files:
            logger.warning(f"No CSV files found in {folder_path}")
            return pd.DataFrame()
            
        logger.info(f"Processing {folder_path.name}: {len(csv_files)} files")
        
        # Load and merge all files
        combined_df = self.load_multiple_files(csv_files)
        
        # Check if attack_label column exists
        has_attack_label = "attack_label" in combined_df.columns
        if has_attack_label:
            logger.info(f"  Using 'attack_label' column from CSV (found {combined_df['attack_label'].nunique()} unique labels)")
        else:
            # Fallback to folder name if no attack_label column
            fallback_label = label if label else self.extract_label_from_folder(folder_path.name)
            combined_df["attack_label"] = fallback_label
            logger.info(f"  No 'attack_label' column found, using folder name: '{fallback_label}'")
        
        # Process with windowing
        all_records = []
        for window_size in self.window_sizes:
            logger.info(f"  Processing {window_size}s windows...")
            self.arp_cache = {}
            
            windows = self.create_windows(combined_df, window_size)
            
            for win_start, win_end, win_df in windows:
                # Group by BOTH src_ip AND attack_label
                # This creates separate records for normal vs attack traffic from same IP
                for (src_ip, attack_label), group_df in win_df.groupby(["src_ip", "attack_label"]):
                    if pd.isna(src_ip):
                        continue
                    
                    # Handle NaN labels
                    if pd.isna(attack_label):
                        attack_label = "Unknown"
                        
                    rec = self._features_for_src_ip(
                        src_ip, group_df, win_start, win_end, window_size
                    )
                    rec["label"] = attack_label
                    rec["variation"] = folder_path.name
                    all_records.append(rec)
                    
        out_df = pd.DataFrame(all_records)
        if not out_df.empty:
            out_df = out_df.sort_values(["window_size", "window_start"]).reset_index(drop=True)
            
        logger.info(f"  Generated {len(out_df)} records from {folder_path.name}")
        return out_df

    def process_dataset_folder(self, root_folder, progress_callback=None):
        """
        Process entire attack_datasets folder, looping through all variations.
        
        Args:
            root_folder: Path to attack_datasets folder
            progress_callback: Optional function(current, total, folder_name) for progress updates
            
        Returns:
            Combined DataFrame with all variations aggregated
        """
        root_folder = Path(root_folder)
        
        # Get all variation subdirectories
        variation_folders = sorted([
            d for d in root_folder.iterdir() 
            if d.is_dir() and not d.name.startswith(".")
        ])
        
        if not variation_folders:
            raise ValueError(f"No variation folders found in {root_folder}")
            
        logger.info(f"Found {len(variation_folders)} variation folders in {root_folder}")
        
        all_results = []
        for i, folder in enumerate(variation_folders):
            if progress_callback:
                progress_callback(i + 1, len(variation_folders), folder.name)
                
            try:
                result = self.process_variation_folder(folder)
                if not result.empty:
                    all_results.append(result)
            except Exception as e:
                logger.error(f"Failed to process {folder.name}: {e}")
                
        if not all_results:
            raise ValueError("No data generated from any variation folder")
            
        combined = pd.concat(all_results, ignore_index=True)
        combined = combined.sort_values(["variation", "window_size", "window_start"]).reset_index(drop=True)
        
        logger.info(f"Total: {len(combined)} records from {len(all_results)} variations")
        return combined

    def create_windows(self, df, window_size):
        """
        Split packets into fixed windows of specified size.

        Args:
            df: DataFrame with packets
            window_size: Window size in seconds

        Returns:
            List of (start, end, window_df) tuples
        """
        if df.empty:
            return []

        min_ts = df["timestamp"].min()
        max_ts = df["timestamp"].max()

        windows = []
        start = min_ts
        delta = timedelta(seconds=window_size)

        while start < max_ts:
            end = start + delta
            win_df = df[(df["timestamp"] >= start) & (df["timestamp"] < end)]
            if not win_df.empty:
                windows.append((start, end, win_df))
            start = end

        return windows

    # ========== MAIN PIPELINE ==========

    def process_file(self, filepath, label=None):
        """
        Process file with all configured window sizes.
        
        Uses 'attack_label' column from CSV if present, otherwise uses
        the provided label parameter or leaves it blank.

        Returns:
            DataFrame with columns including 'window_size' to distinguish scales
        """
        df = self.load_raw_packets(filepath)
        
        # Check if attack_label column exists
        has_attack_label = "attack_label" in df.columns
        if has_attack_label:
            logger.info(f"Using 'attack_label' column from CSV (found {df['attack_label'].nunique()} unique labels)")
        elif label is not None:
            # Use provided label as fallback
            df["attack_label"] = label
            logger.info(f"No 'attack_label' column found, using provided label: '{label}'")
        else:
            # No label available
            df["attack_label"] = "Unknown"
            logger.warning("No 'attack_label' column and no label provided, using 'Unknown'")

        all_records = []

        # Process each window size
        for window_size in self.window_sizes:
            logger.info(f"Processing {window_size}s windows...")

            # Reset ARP cache for each window size
            self.arp_cache = {}

            windows = self.create_windows(df, window_size)
            logger.info(f"  Created {len(windows)} windows of {window_size}s")

            # Extract features for each source IP AND attack_label in each window
            for win_start, win_end, win_df in windows:
                for (src_ip, attack_label), group_df in win_df.groupby(["src_ip", "attack_label"]):
                    if pd.isna(src_ip):
                        continue
                    
                    # Handle NaN labels
                    if pd.isna(attack_label):
                        attack_label = "Unknown"

                    rec = self._features_for_src_ip(
                        src_ip, group_df, win_start, win_end, window_size
                    )
                    rec["label"] = attack_label
                    all_records.append(rec)

        out_df = pd.DataFrame(all_records)
        logger.info(f"Generated {len(out_df)} total records across all window sizes")

        # Sort by window_size, then timestamp for easier analysis
        if not out_df.empty:
            out_df = out_df.sort_values(["window_size", "window_start"]).reset_index(drop=True)

        return out_df

    def save_results(self, df, output_path, fmt="csv"):
        """Save aggregated features to CSV/JSON."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "csv":
            df.to_csv(output_path, index=False)
        elif fmt == "json":
            df.to_json(output_path, orient="records", indent=2)
        else:
            raise ValueError(f"Unsupported format: {fmt}")

        logger.info(f"Saved {len(df)} records to {output_path}")

    # ========== FEATURE EXTRACTION ==========

    def _features_for_src_ip(self, src_ip, df, win_start, win_end, window_size):
        """
        Extract compact feature set for one (src_ip, window, window_size).
        """
        duration = (win_end - win_start).total_seconds()
        if duration <= 0:
            duration = window_size

        out = {
            "src_ip": src_ip,
            "window_start": win_start,
            "window_end": win_end,
            "window_size": window_size,  # NEW: Track which window size this is
        }

        # Extract all feature groups
        out.update(self._generic_features(df, duration))
        out.update(self._tcp_ddos_scan_features(df, duration))
        out.update(self._bruteforce_features(df, duration))
        out.update(self._arp_features(df))
        out.update(self._dns_features(df, duration))
        out.update(self._slowloris_features(df, duration))

        return out

    # ---------- FEATURE GROUPS (same as compact version) ----------

    def _generic_features(self, df, duration):
        length = df["length"] if "length" in df.columns else None
        packet_count = len(df)
        packet_rate = packet_count / duration
        byte_count = int(length.sum()) if length is not None else 0
        byte_rate = byte_count * 8.0 / duration if duration > 0 else 0.0
        avg_size = float(length.mean()) if length is not None else 0.0
        size_var = float(length.var()) if length is not None else 0.0

        proto = df["protocol"] if "protocol" in df.columns else pd.Series([], dtype=str)
        tcp_count = int((proto == "TCP").sum())
        udp_count = int((proto == "UDP").sum())
        icmp_count = int(proto.str.contains("ICMP", na=False).sum())
        arp_count = int((proto == "ARP").sum())

        unique_dst_ips = int(df["dst_ip"].nunique()) if "dst_ip" in df.columns else 0
        unique_dst_ports = int(df["dst_port"].nunique()) if "dst_port" in df.columns else 0

        # Port hit features for remote connection detection
        tcp_ports_hit = 0  # All TCP except remote connection ports
        udp_ports_hit = 0  # All UDP except remote connection ports
        remote_conn_port_hits = 0  # Remote connection ports: SSH(22), Telnet(23), Rlogin(513), RDP(3389), VNC(5900), X11(6000-6063)
        
        if "dst_port" in df.columns and "protocol" in df.columns:
            tcp_mask = df["protocol"] == "TCP"
            udp_mask = df["protocol"] == "UDP"
            
            # All remote connection ports (to exclude from general tcp/udp counts)
            remote_conn_ports = [22, 23, 513, 3389, 5900] + list(range(6000, 6064))
            remote_conn_mask = df["dst_port"].isin(remote_conn_ports)
            
            # TCP ports hit: all TCP packets EXCEPT remote connection ports
            tcp_ports_hit = int((tcp_mask & ~remote_conn_mask).sum())
            
            # UDP ports hit: all UDP packets EXCEPT remote connection ports
            udp_ports_hit = int((udp_mask & ~remote_conn_mask).sum())
            
            # Remote connection port hits: any protocol targeting remote conn ports
            remote_conn_port_hits = int(remote_conn_mask.sum())

        return {
            "packet_count": packet_count,
            "packet_rate_pps": packet_rate,
            "byte_count": byte_count,
            "byte_rate_bps": byte_rate,
            "avg_packet_size": avg_size,
            "packet_size_variance": size_var,
            "tcp_count": tcp_count,
            "udp_count": udp_count,
            "icmp_count": icmp_count,
            "arp_count": arp_count,
            "unique_dst_ips": unique_dst_ips,
            "unique_dst_ports": unique_dst_ports,
            "tcp_ports_hit": tcp_ports_hit,
            "udp_ports_hit": udp_ports_hit,
            "remote_conn_port_hits": remote_conn_port_hits,
        }

    def _tcp_ddos_scan_features(self, df, duration):
        if "protocol" in df.columns:
            tcp_df = df[df["protocol"] == "TCP"]
            udp_df = df[df["protocol"] == "UDP"]
            icmp_df = df[df["protocol"].str.contains("ICMP", na=False)]
        else:
            tcp_df = pd.DataFrame()
            udp_df = pd.DataFrame()
            icmp_df = pd.DataFrame()

        tcp_syn = tcp_df["tcp_syn"] if "tcp_syn" in tcp_df.columns else pd.Series([], dtype=bool)
        tcp_ack = tcp_df["tcp_ack"] if "tcp_ack" in tcp_df.columns else pd.Series([], dtype=bool)

        tcp_syn_count = int(tcp_syn.sum())
        tcp_ack_count = int(tcp_ack.sum())
        syn_rate_pps = tcp_syn_count / duration if duration > 0 else 0.0

        if "tcp_syn" in tcp_df.columns and "tcp_ack" in tcp_df.columns:
            syn_ack_count = int(((tcp_df["tcp_syn"] == True) & (tcp_df["tcp_ack"] == True)).sum())
        else:
            syn_ack_count = 0

        syn_ack_rate_pps = syn_ack_count / duration if duration > 0 else 0.0
        syn_to_synack_ratio = float(tcp_syn_count / syn_ack_count) if syn_ack_count > 0 else float(tcp_syn_count)

        if {"dst_ip", "dst_port"}.issubset(tcp_df.columns):
            syn_flows = tcp_df[tcp_df["tcp_syn"] == True][["dst_ip", "dst_port"]].dropna()
            ack_flows = tcp_df[tcp_df["tcp_ack"] == True][["dst_ip", "dst_port"]].dropna()
            syn_set = set(map(tuple, syn_flows.values))
            ack_set = set(map(tuple, ack_flows.values))
            half_open_count = len(syn_set - ack_set)
        else:
            half_open_count = 0

        if "dst_port" in df.columns:
            dst_ports = df["dst_port"].dropna().astype(int)
            if len(dst_ports) > 1:
                sorted_ports = sorted(dst_ports.tolist())
                sequential_port_count = sum(
                    1 for i in range(len(sorted_ports) - 1)
                    if sorted_ports[i + 1] - sorted_ports[i] == 1
                )
            else:
                sequential_port_count = 0
        else:
            sequential_port_count = 0

        scan_rate_pps = len(tcp_df) / duration if duration > 0 else 0.0
        distinct_targets_count = int(df["dst_ip"].nunique()) if "dst_ip" in df.columns else 0

        total_syn = tcp_syn_count
        total_ack = tcp_ack_count
        syn_only_ratio = float(total_syn / (total_syn + total_ack)) if (total_syn + total_ack) > 0 else 0.0

        icmp_rate_pps = len(icmp_df) / duration if duration > 0 else 0.0
        udp_rate_pps = len(udp_df) / duration if duration > 0 else 0.0
        udp_dest_port_count = int(udp_df["dst_port"].nunique()) if "dst_port" in udp_df.columns else 0

        return {
            "tcp_syn_count": tcp_syn_count,
            "tcp_ack_count": tcp_ack_count,
            "syn_rate_pps": syn_rate_pps,
            "syn_ack_rate_pps": syn_ack_rate_pps,
            "syn_to_synack_ratio": syn_to_synack_ratio,
            "half_open_count": half_open_count,
            "sequential_port_count": sequential_port_count,
            "scan_rate_pps": scan_rate_pps,
            "distinct_targets_count": distinct_targets_count,
            "syn_only_ratio": syn_only_ratio,
            "icmp_rate_pps": icmp_rate_pps,
            "udp_rate_pps": udp_rate_pps,
            "udp_dest_port_count": udp_dest_port_count,
        }

    def _bruteforce_features(self, df, duration):
        if "http_method" in df.columns:
            http_df = df[df["http_method"].notna()]
        else:
            http_df = pd.DataFrame()

        login_attempts = 0
        if "http_path" in http_df.columns:
            login_patterns = ["login", "signin", "auth", "authenticate"]
            login_attempts = int(
                http_df["http_path"]
                .astype(str)
                .str.contains("|".join(login_patterns), case=False, na=False)
                .sum()
            )

        failed_login_count = 0
        if "http_status_code" in http_df.columns:
            failed_login_count = int(
                http_df["http_status_code"].astype(str).isin(["401", "403"]).sum()
            )

        if "protocol" in df.columns:
            tcp_df = df[df["protocol"] == "TCP"]
        else:
            tcp_df = pd.DataFrame()

        if "dst_port" in tcp_df.columns:
            ssh_attempts = int((tcp_df["dst_port"] == 22).sum())
            ftp_attempts = int(tcp_df["dst_port"].isin([20, 21]).sum())
        else:
            ssh_attempts = 0
            ftp_attempts = 0

        login_request_rate = (login_attempts / duration) if duration > 0 else 0.0
        total_auth_attempts = ssh_attempts + ftp_attempts + login_attempts
        auth_attempts_per_min = (total_auth_attempts / (duration / 60.0)) if duration > 0 else 0.0

        return {
            "ssh_connection_attempts": ssh_attempts,
            "ftp_connection_attempts": ftp_attempts,
            "http_login_attempts": login_attempts,
            "login_request_rate": login_request_rate,
            "failed_login_count": failed_login_count,
            "auth_attempts_per_min": auth_attempts_per_min,
        }

    def _arp_features(self, df):
        """Extract ARP features with MAC-per-IP analysis for spoof detection."""
        default_features = {
            "arp_request_count": 0,
            "arp_reply_count": 0,
            "gratuitous_arp_count": 0,
            "arp_binding_flap_count": 0,
            "arp_reply_without_request_count": 0,
            # NEW: MAC-per-IP detection features
            "unique_macs_per_ip_max": 0,       # Max MACs seen for any single IP
            "avg_macs_per_ip": 0.0,            # Average MACs per IP
            "duplicate_mac_ips": 0,            # Count of IPs sharing same MAC
            "mac_ip_ratio": 0.0,               # Ratio of unique MACs to unique IPs
            "suspicious_mac_changes": 0,       # IPs with more than 1 MAC (spoof indicator)
        }
        
        if "protocol" not in df.columns:
            return default_features

        arp_df = df[df["protocol"] == "ARP"]
        if arp_df.empty:
            return default_features

        # Basic ARP counts
        arp_op = arp_df["arp_op"] if "arp_op" in arp_df.columns else pd.Series([], dtype=float)
        arp_request_count = int((arp_op == 1).sum())
        arp_reply_count = int((arp_op == 2).sum())

        # Gratuitous ARP (src == dst)
        gratuitous_arp_count = 0
        if {"arp_psrc", "arp_pdst"}.issubset(arp_df.columns):
            gratuitous_arp_count = int((arp_df["arp_psrc"] == arp_df["arp_pdst"]).sum())

        # MAC-per-IP analysis
        binding_flap_count = 0
        ip_to_macs = {}  # Track all MACs seen per IP
        mac_to_ips = {}  # Track all IPs per MAC
        
        if {"arp_psrc", "arp_hwsrc"}.issubset(arp_df.columns):
            for _, row in arp_df.iterrows():
                ip = row["arp_psrc"]
                mac = row["arp_hwsrc"]
                
                if pd.isna(ip) or pd.isna(mac):
                    continue
                
                ip = str(ip)
                mac = str(mac)
                
                # Track binding flaps (MAC changes for same IP)
                if ip in self.arp_cache and self.arp_cache[ip] != mac:
                    binding_flap_count += 1
                self.arp_cache[ip] = mac
                
                # Track IP → MACs mapping
                if ip not in ip_to_macs:
                    ip_to_macs[ip] = set()
                ip_to_macs[ip].add(mac)
                
                # Track MAC → IPs mapping
                if mac not in mac_to_ips:
                    mac_to_ips[mac] = set()
                mac_to_ips[mac].add(ip)
        
        # ALSO analyze Ethernet MAC addresses for all packets (not just ARP)
        # This works on real network interfaces where src_mac/dst_mac are captured
        if {"src_mac", "src_ip"}.issubset(df.columns):
            eth_df = df[df["src_mac"].notna() & (df["src_mac"] != '')]
            for _, row in eth_df.iterrows():
                ip = row.get("src_ip")
                mac = row.get("src_mac")
                
                if pd.isna(ip) or pd.isna(mac) or ip == '' or mac == '':
                    continue
                
                ip = str(ip)
                mac = str(mac)
                
                # Track IP → MACs mapping from Ethernet layer
                if ip not in ip_to_macs:
                    ip_to_macs[ip] = set()
                ip_to_macs[ip].add(mac)
                
                if mac not in mac_to_ips:
                    mac_to_ips[mac] = set()
                mac_to_ips[mac].add(ip)

        # Calculate MAC-per-IP features
        unique_macs_per_ip_max = 0
        avg_macs_per_ip = 0.0
        suspicious_mac_changes = 0
        
        if ip_to_macs:
            mac_counts = [len(macs) for macs in ip_to_macs.values()]
            unique_macs_per_ip_max = max(mac_counts)
            avg_macs_per_ip = float(sum(mac_counts) / len(mac_counts))
            suspicious_mac_changes = sum(1 for count in mac_counts if count > 1)
        
        # Count IPs sharing same MAC (suspicious)
        duplicate_mac_ips = 0
        if mac_to_ips:
            duplicate_mac_ips = sum(len(ips) for ips in mac_to_ips.values() if len(ips) > 1)
        
        # MAC/IP ratio (should be ~1.0 normally, high = suspicious)
        unique_macs = len(set().union(*ip_to_macs.values())) if ip_to_macs else 0
        unique_ips = len(ip_to_macs)
        mac_ip_ratio = float(unique_macs / unique_ips) if unique_ips > 0 else 0.0

        reply_without_request_count = max(0, arp_reply_count - arp_request_count)

        return {
            "arp_request_count": arp_request_count,
            "arp_reply_count": arp_reply_count,
            "gratuitous_arp_count": gratuitous_arp_count,
            "arp_binding_flap_count": binding_flap_count,
            "arp_reply_without_request_count": reply_without_request_count,
            "unique_macs_per_ip_max": unique_macs_per_ip_max,
            "avg_macs_per_ip": avg_macs_per_ip,
            "duplicate_mac_ips": duplicate_mac_ips,
            "mac_ip_ratio": mac_ip_ratio,
            "suspicious_mac_changes": suspicious_mac_changes,
        }

    def _dns_features(self, df, duration):
        """Extract DNS features with enhanced tunneling detection."""
        default_features = {
            "dns_query_count": 0,
            "query_rate_qps": 0.0,
            "unique_qnames_count": 0,
            "avg_subdomain_entropy": 0.0,
            "pct_high_entropy_queries": 0.0,
            "txt_record_count": 0,
            "avg_answer_size": 0.0,
            "distinct_record_types": 0,
            "avg_query_interval_ms": 0.0,
            # NEW: Enhanced DNS tunnel detection features
            "avg_subdomain_length": 0.0,
            "max_subdomain_length": 0,
            "avg_label_count": 0.0,
            "dns_to_udp_ratio": 0.0,
            "udp_port_53_count": 0,
        }
        
        if "dns_query" not in df.columns:
            return default_features

        dns_df = df[df["dns_query"] == True]
        
        # Count UDP port 53 packets (even if not flagged as DNS)
        udp_port_53_count = 0
        if "protocol" in df.columns and "dst_port" in df.columns:
            udp_port_53_count = int(
                ((df["protocol"] == "UDP") & (df["dst_port"].astype(str).isin(["53", "53.0"]))).sum()
            )
        
        if dns_df.empty and udp_port_53_count == 0:
            return default_features

        qnames = dns_df["dns_qname"].dropna().astype(str) if "dns_qname" in dns_df.columns else pd.Series([], dtype=str)
        dns_query_count = max(len(dns_df), udp_port_53_count)  # Use higher count
        query_rate_qps = dns_query_count / duration if duration > 0 else 0.0
        unique_qnames_count = int(qnames.nunique()) if not qnames.empty else 0

        def entropy(s):
            if not s:
                return 0.0
            probs = [s.count(c) / len(s) for c in set(s)]
            return -sum(p * math.log2(p) for p in probs if p > 0)

        def subdomain_length(s):
            """Get length of the subdomain part (everything before the main domain)."""
            parts = s.split('.')
            if len(parts) > 2:
                return len('.'.join(parts[:-2]))
            return len(parts[0]) if parts else 0

        def label_count(s):
            """Count number of labels (dots + 1) in domain."""
            return s.count('.') + 1 if s else 0

        avg_entropy = 0.0
        pct_high_entropy = 0.0
        avg_subdomain_len = 0.0
        max_subdomain_len = 0
        avg_labels = 0.0

        if not qnames.empty:
            entropies = qnames.apply(entropy)
            avg_entropy = float(entropies.mean())
            high_entropy_threshold = 3.5
            pct_high_entropy = float((entropies > high_entropy_threshold).mean())
            
            # Subdomain analysis (key for DNS tunnel detection)
            subdomain_lengths = qnames.apply(subdomain_length)
            avg_subdomain_len = float(subdomain_lengths.mean())
            max_subdomain_len = int(subdomain_lengths.max())
            
            # Label count (DNS tunnels often have many subdomains)
            label_counts = qnames.apply(label_count)
            avg_labels = float(label_counts.mean())

        txt_record_count = 0
        distinct_record_types = 0
        if "dns_qtype" in dns_df.columns:
            txt_record_count = int((dns_df["dns_qtype"] == 16).sum())
            distinct_record_types = int(dns_df["dns_qtype"].nunique())

        avg_answer_size = 0.0
        if "dns_answer_size" in dns_df.columns:
            avg_answer_size = float(dns_df["dns_answer_size"].mean())

        avg_query_interval_ms = 0.0
        if len(dns_df) > 1:
            ts_sorted = dns_df["timestamp"].sort_values()
            intervals = ts_sorted.diff().dt.total_seconds() * 1000.0
            avg_query_interval_ms = float(intervals.mean())

        # DNS to UDP ratio (high ratio = more DNS tunneling suspected)
        udp_count = len(df[df["protocol"] == "UDP"]) if "protocol" in df.columns else 0
        dns_to_udp_ratio = float(dns_query_count / udp_count) if udp_count > 0 else 0.0

        return {
            "dns_query_count": dns_query_count,
            "query_rate_qps": query_rate_qps,
            "unique_qnames_count": unique_qnames_count,
            "avg_subdomain_entropy": avg_entropy,
            "pct_high_entropy_queries": pct_high_entropy,
            "txt_record_count": txt_record_count,
            "avg_answer_size": avg_answer_size,
            "distinct_record_types": distinct_record_types,
            "avg_query_interval_ms": avg_query_interval_ms,
            "avg_subdomain_length": avg_subdomain_len,
            "max_subdomain_length": max_subdomain_len,
            "avg_label_count": avg_labels,
            "dns_to_udp_ratio": dns_to_udp_ratio,
            "udp_port_53_count": udp_port_53_count,
        }

    def _slowloris_features(self, df, duration):
        if "protocol" in df.columns:
            tcp_df = df[df["protocol"] == "TCP"]
        else:
            tcp_df = pd.DataFrame()

        if "http_method" in df.columns:
            http_df = df[df["http_method"].notna()]
        else:
            http_df = pd.DataFrame()

        if {"dst_ip", "dst_port"}.issubset(tcp_df.columns) and not tcp_df.empty:
            groups = tcp_df.groupby(["dst_ip", "dst_port"])
            open_conn_count = len(groups)

            conn_durations = []
            for _, g in groups:
                d = (g["timestamp"].max() - g["timestamp"].min()).total_seconds()
                conn_durations.append(d)
            avg_conn_duration = float(np.mean(conn_durations)) if conn_durations else 0.0

            partial_http_count = 0
            if "tcp_syn" in tcp_df.columns:
                for (dst_ip, dst_port), g in groups:
                    has_syn = bool(g["tcp_syn"].any())
                    has_http = False
                    if "http_method" in g.columns:
                        has_http = bool(g["http_method"].notna().any())
                    if has_syn and not has_http and dst_port in [80, 8080, 8000, 3000, 443]:
                        partial_http_count += 1
        else:
            open_conn_count = 0
            avg_conn_duration = 0.0
            partial_http_count = 0

        if open_conn_count > 0 and "length" in df.columns:
            bytes_per_conn = float(df["length"].sum() / open_conn_count)
        else:
            bytes_per_conn = 0.0

        if not http_df.empty:
            if "http_status_code" in http_df.columns:
                completed = http_df["http_status_code"].notna().sum()
            else:
                completed = 0
            total_http = len(http_df)
            request_completion_ratio = float(completed / total_http) if total_http > 0 else 1.0
        else:
            request_completion_ratio = 1.0

        return {
            "open_conn_count": open_conn_count,
            "avg_conn_duration": avg_conn_duration,
            "bytes_per_conn": bytes_per_conn,
            "partial_http_count": partial_http_count,
            "request_completion_ratio": request_completion_ratio,
        }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Multi-Window Network Traffic Aggregator (5s, 30s, 3min)"
    )
    parser.add_argument("input_file", help="Input CSV/JSON with raw packets")
    parser.add_argument("output_file", help="Output CSV/JSON with multi-window features")
    parser.add_argument(
        "--label",
        help="Traffic label (Normal, DDoS, Port Scanning, etc.)",
        default=None,
    )
    parser.add_argument(
        "--windows",
        type=int,
        nargs="+",
        default=[5, 30, 180],
        help="Window sizes in seconds (default: 5 30 180)",
    )
    parser.add_argument(
        "--format",
        choices=["csv", "json"],
        default="csv",
        help="Output format (default: csv)",
    )

    args = parser.parse_args()

    agg = MultiWindowAggregator(window_sizes=args.windows)
    result = agg.process_file(args.input_file, label=args.label)
    agg.save_results(result, args.output_file, fmt=args.format)

    # Show summary
    logger.info("="*60)
    logger.info("SUMMARY")
    logger.info("="*60)
    logger.info(f"Total records: {len(result)}")
    if not result.empty:
        logger.info("\nRecords per window size:")
        print(result.groupby("window_size").size())
        logger.info(f"\nFeatures: {len(result.columns)} columns")
        logger.info(f"Columns: {list(result.columns[:10])}...")
