"""
Dataset Capture GUI - Easy interface for packet capture during attack simulations

Self-contained packet capture with CSV export for ML dataset generation.
Use this tool when simulating attacks to capture labeled traffic.

THEMED VERSION: Matches Network Attack Simulator styling
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import sys
import time
import csv
import signal
from datetime import datetime
from pathlib import Path

# Check for scapy
try:
    from scapy.all import sniff, get_if_list, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ARP, DNS, DNSQR, Raw, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# Configuration
LOOPBACK_IP = '127.0.0.1'
DNS_TUNNEL_SERVERS = {
    '8.8.8.8', '8.8.4.4',      # Google DNS
    '1.1.1.1', '1.0.0.1',      # Cloudflare DNS
    '9.9.9.9',                  # Quad9 DNS
    '208.67.222.222', '208.67.220.220',  # OpenDNS
}

# Theme Colors (matching Attack Simulator)
BG_COLOR = "#1e1e2e"
CARD_BG = "#2b2b3c"
ACCENT_COLOR = "#89b4fa"
SUCCESS_COLOR = "#a6e3a1"
ERROR_COLOR = "#f38ba8"
WARNING_COLOR = "#fab387"
TEXT_COLOR = "#cdd6f4"


class PacketSniffer:
    """Packet capture engine with CSV export"""
    
    def __init__(self, callback=None):
        self.running = False
        self.packet_buffer = []
        self.buffer_lock = threading.Lock()
        self.packet_count = 0
        self.capture_start = None
        self.callback = callback  # For GUI updates
        self.threads = []
        
        # Configuration (set before start)
        self.capture_dir = './captures'
        self.attack_label = 'unknown'
        self.capture_duration = 180
        self.attacker_ip = ''
        
        # Interface mapping
        self.interface_map = {}
        self._build_interface_map()
        
    def _build_interface_map(self):
        """Build map of raw GUIDs to friendly names"""
        try:
            from scapy.all import IFACES
            for raw_name, iface in IFACES.items():
                try:
                    friendly = getattr(iface, 'description', '') or getattr(iface, 'name', '') or raw_name
                    if friendly and friendly != raw_name:
                        self.interface_map[raw_name] = friendly
                except:
                    pass
        except:
            pass

    
    def decode_tcp_flags(self, flag_value):
        """Convert TCP flag integer to readable flags string"""
        flags = []
        if flag_value & 1: flags.append("FIN")
        if flag_value & 2: flags.append("SYN")
        if flag_value & 4: flags.append("RST")
        if flag_value & 8: flags.append("PSH")
        if flag_value & 16: flags.append("ACK")
        if flag_value & 32: flags.append("URG")
        if flag_value & 64: flags.append("ECE")
        if flag_value & 128: flags.append("CWR")
        return ",".join(flags)
    
    def to_csv_value(self, val):
        """Convert Python value to CSV format"""
        if val is None:
            return ''
        elif isinstance(val, bool):
            return str(val)
        else:
            return val
    
    def get_conditional_label(self, src_ip, dst_ip, dst_port=None, protocol=None):
        """Apply attack label based on traffic characteristics"""
        # Only label traffic if it matches the configured attacker IP
        # User must explicitly set attacker IP (e.g., 127.0.0.1 for loopback attacks)
        if self.attacker_ip:
            if src_ip == self.attacker_ip or dst_ip == self.attacker_ip:
                return self.attack_label
        
        # Check for DNS tunnel pattern
        if protocol == 'UDP' and dst_port in [53, '53', 53.0]:
            if dst_ip in DNS_TUNNEL_SERVERS:
                if 'dns_tunnel' in self.attack_label.lower():
                    return self.attack_label
                return 'dns_tunnel'
        
        # Also check src_ip for DNS responses coming back
        if protocol == 'UDP' and src_ip in DNS_TUNNEL_SERVERS:
            if 'dns_tunnel' in self.attack_label.lower():
                return self.attack_label
            return 'dns_tunnel'
        
        return 'Normal'
    
    def packet_summary(self, pkt, interface):
        """Extract packet features"""
        self.packet_count += 1
        
        # Resolve friendly name
        friendly_interface = self.interface_map.get(interface, interface)
        if friendly_interface == interface:
             # Fallback cleanup if not in map
             friendly_interface = interface.split('{')[0].strip('\\').replace('Device\\NPF_', '')
        
        summary = {
            'timestamp': pkt.time,
            'interface': friendly_interface,
            'src_mac': '',
            'dst_mac': '',
            'src_ip': '',
            'dst_ip': '',
            'protocol': '',
            'length': len(pkt),
            'src_port': '',
            'dst_port': '',
            'tcp_flags': '',
            'tcp_syn': '',
            'tcp_ack': '',
            'tcp_fin': '',
            'tcp_rst': '',
            'tcp_psh': '',
            'seq': '',
            'ack': '',
            'icmp_type': '',
            'icmp_code': '',
            'arp_op': '',
            'arp_psrc': '',
            'arp_pdst': '',
            'arp_hwsrc': '',
            'arp_hwdst': '',
            'dns_query': '',
            'dns_qname': '',
            'dns_qtype': '',
            'dns_response': '',
            'dns_answer_count': '',
            'dns_answer_size': '',
            'http_method': '',
            'http_path': '',
            'http_status_code': '',
            'http_host': '',
            'attack_label': ''
        }
        
        # Extract Ethernet MAC addresses
        try:
            if Ether in pkt:
                summary['src_mac'] = pkt[Ether].src
                summary['dst_mac'] = pkt[Ether].dst
        except:
            pass
        
        # IPv4
        if IP in pkt:
            summary['src_ip'] = pkt[IP].src
            summary['dst_ip'] = pkt[IP].dst
            
            if TCP in pkt:
                tcp = pkt[TCP]
                summary['protocol'] = 'TCP'
                summary['src_port'] = tcp.sport
                summary['dst_port'] = tcp.dport
                summary['tcp_flags'] = self.decode_tcp_flags(tcp.flags.value)
                summary['seq'] = tcp.seq
                summary['ack'] = tcp.ack
                
                summary['tcp_syn'] = str(bool(tcp.flags.value & 0x02))
                summary['tcp_ack'] = str(bool(tcp.flags.value & 0x10))
                summary['tcp_fin'] = str(bool(tcp.flags.value & 0x01))
                summary['tcp_rst'] = str(bool(tcp.flags.value & 0x04))
                summary['tcp_psh'] = str(bool(tcp.flags.value & 0x08))
                
                # HTTP detection
                if Raw in pkt and tcp.dport in [80, 8080, 8000, 3000]:
                    payload = bytes(pkt[Raw].load)
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        lines = payload_str.split('\r\n')
                        if lines:
                            first_line = lines[0].split()
                            if len(first_line) >= 2 and first_line[0] in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']:
                                summary['http_method'] = first_line[0]
                                summary['http_path'] = first_line[1] if len(first_line) > 1 else ''
                                for line in lines[1:]:
                                    if line.lower().startswith('host:'):
                                        summary['http_host'] = line.split(':', 1)[1].strip()
                                        break
                            elif first_line[0].startswith('HTTP/'):
                                if len(first_line) >= 2:
                                    summary['http_status_code'] = first_line[1]
                    except:
                        pass
            
            elif UDP in pkt:
                udp = pkt[UDP]
                summary['protocol'] = 'UDP'
                summary['src_port'] = udp.sport
                summary['dst_port'] = udp.dport
                
                if DNS in pkt:
                    dns = pkt[DNS]
                    summary['dns_query'] = str(dns.qr == 0)
                    summary['dns_response'] = str(dns.qr == 1)
                    
                    if DNSQR in pkt:
                        try:
                            summary['dns_qname'] = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                            summary['dns_qtype'] = pkt[DNSQR].qtype
                        except:
                            pass
                    
                    if dns.qr == 1 and dns.an:
                        summary['dns_answer_count'] = dns.ancount
                        answer_size = 0
                        try:
                            rr = dns.an
                            while rr:
                                if hasattr(rr, 'rdata'):
                                    answer_size += len(str(rr.rdata))
                                rr = rr.payload if hasattr(rr, 'payload') else None
                            summary['dns_answer_size'] = answer_size
                        except:
                            pass
            
            elif ICMP in pkt:
                icmp = pkt[ICMP]
                summary['protocol'] = 'ICMP'
                summary['icmp_type'] = icmp.type
                summary['icmp_code'] = icmp.code
            
            else:
                summary['protocol'] = 'OTHER'
        
        # IPv6
        elif IPv6 in pkt:
            summary['src_ip'] = pkt[IPv6].src
            summary['dst_ip'] = pkt[IPv6].dst
            
            if TCP in pkt:
                tcp = pkt[TCP]
                summary['protocol'] = 'TCP'
                summary['src_port'] = tcp.sport
                summary['dst_port'] = tcp.dport
                summary['tcp_flags'] = self.decode_tcp_flags(tcp.flags.value)
                summary['seq'] = tcp.seq
                summary['ack'] = tcp.ack
                
                summary['tcp_syn'] = str(bool(tcp.flags.value & 0x02))
                summary['tcp_ack'] = str(bool(tcp.flags.value & 0x10))
                summary['tcp_fin'] = str(bool(tcp.flags.value & 0x01))
                summary['tcp_rst'] = str(bool(tcp.flags.value & 0x04))
                summary['tcp_psh'] = str(bool(tcp.flags.value & 0x08))
            
            elif UDP in pkt:
                udp = pkt[UDP]
                summary['protocol'] = 'UDP'
                summary['src_port'] = udp.sport
                summary['dst_port'] = udp.dport
                
                if DNS in pkt:
                    dns = pkt[DNS]
                    summary['dns_query'] = str(dns.qr == 0)
                    summary['dns_response'] = str(dns.qr == 1)
                    
                    if DNSQR in pkt:
                        try:
                            summary['dns_qname'] = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                            summary['dns_qtype'] = pkt[DNSQR].qtype
                        except:
                            pass
                    
                    if dns.qr == 1 and dns.an:
                        summary['dns_answer_count'] = dns.ancount
            
            elif ICMPv6EchoRequest in pkt:
                icmpv6 = pkt[ICMPv6EchoRequest]
                summary['protocol'] = 'ICMPv6'
                summary['icmp_type'] = icmpv6.type
                summary['icmp_code'] = icmpv6.code
            
            else:
                summary['protocol'] = 'OTHER'
        
        # ARP
        elif ARP in pkt:
            arp = pkt[ARP]
            summary['protocol'] = 'ARP'
            summary['arp_op'] = arp.op
            summary['arp_psrc'] = arp.psrc
            summary['arp_pdst'] = arp.pdst
            summary['arp_hwsrc'] = arp.hwsrc
            summary['arp_hwdst'] = arp.hwdst
            # Also populate src_ip/dst_ip from ARP addresses for consistency
            summary['src_ip'] = arp.psrc
            summary['dst_ip'] = arp.pdst
        
        else:
            summary['protocol'] = 'OTHER'
        
        # Apply conditional labeling
        summary['attack_label'] = self.get_conditional_label(
            summary['src_ip'],
            summary['dst_ip'],
            dst_port=summary.get('dst_port'),
            protocol=summary.get('protocol')
        )
        
        return {k: self.to_csv_value(v) for k, v in summary.items()}
    
    def save_packets_to_csv(self, packets, filename):
        """Save packets to CSV file"""
        if not packets:
            return False
        
        try:
            file_exists = os.path.exists(filename)
            mode = 'a' if file_exists else 'w'
            
            with open(filename, mode, newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=packets[0].keys())
                if not file_exists:
                    writer.writeheader()
                writer.writerows(packets)
            
            return True
        except Exception as e:
            if self.callback:
                self.callback(f"ERROR saving CSV: {e}", "error")
            return False
    
    def should_stop_capture(self):
        """Check if capture duration has elapsed"""
        if not self.running:
            return True
        if self.capture_start is None:
            return False
        elapsed = (datetime.now() - self.capture_start).total_seconds()
        return elapsed >= self.capture_duration
    
    def sniff_interface(self, interface):
        """Sniff packets on a specific interface"""
        friendly = self.interface_map.get(interface, interface)
        # Fallback cleanup
        if friendly == interface:
             friendly = interface.split('{')[0].strip('\\').replace('Device\\NPF_', '')
             
        if self.callback:
            self.callback(f"Started sniffing on: {friendly}", "info")
        
        def handle_packet(pkt):
            if self.should_stop_capture():
                return True
            
            try:
                summary = self.packet_summary(pkt, interface)
                with self.buffer_lock:
                    self.packet_buffer.append(summary)
            except Exception as e:
                pass
        
        try:
            while self.running and not self.should_stop_capture():
                sniff(
                    prn=handle_packet,
                    store=False,
                    iface=interface,
                    timeout=5,
                    stop_filter=lambda x: self.should_stop_capture()
                )
        except Exception as e:
            if self.callback:
                self.callback(f"Sniffer error on {interface}: {e}", "error")
    
    def periodic_saver(self):
        """Periodically save buffer to CSV"""
        save_interval = 180
        
        while self.running and not self.should_stop_capture():
            time.sleep(save_interval)
            
            packets_to_save = []
            with self.buffer_lock:
                if self.packet_buffer:
                    packets_to_save = self.packet_buffer.copy()
                    self.packet_buffer = []
            
            if packets_to_save:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = os.path.join(self.capture_dir, f"{self.attack_label}_{timestamp}.csv")
                if self.save_packets_to_csv(packets_to_save, filename):
                    if self.callback:
                        self.callback(f"Saved {len(packets_to_save)} packets to {os.path.basename(filename)}", "success")
    
    def start(self, capture_dir, attack_label, duration, attacker_ip=''):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is not installed. Install with: pip install scapy")
        
        self.capture_dir = capture_dir
        self.attack_label = attack_label
        self.capture_duration = duration
        self.attacker_ip = attacker_ip
        self.running = True
        self.packet_count = 0
        self.packet_buffer = []
        self.threads = []
        
        os.makedirs(capture_dir, exist_ok=True)
        
        # Get all network interfaces
        interfaces = get_if_list()
        if self.callback:
            self.callback(f"Detected {len(interfaces)} interfaces", "info")
        
        self.capture_start = datetime.now()
        
        # Start periodic saver thread
        saver_thread = threading.Thread(target=self.periodic_saver, daemon=True)
        saver_thread.start()
        self.threads.append(saver_thread)
        
        # Start a sniffing thread for each interface
        for iface in interfaces:
            t = threading.Thread(target=self.sniff_interface, args=(iface,), daemon=True)
            t.start()
            self.threads.append(t)
    
    def stop(self):
        """Stop packet capture and save remaining packets"""
        self.running = False
        
        # Wait a bit for threads to finish
        time.sleep(2)
        
        # Save remaining packets
        if self.packet_buffer:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.join(self.capture_dir, f"{self.attack_label}_{timestamp}_FINAL.csv")
            if self.save_packets_to_csv(self.packet_buffer, filename):
                if self.callback:
                    self.callback(f"FINAL: Saved {len(self.packet_buffer)} packets to {os.path.basename(filename)}", "success")
            self.packet_buffer = []
        
        return self.packet_count


class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Dataset Capture")
        
        # Position window (right half by default, like attack simulator)
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        window_width = screen_width // 2
        window_height = screen_height - 80
        x_position = screen_width // 2
        y_position = 0
        self.root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
        self.root.minsize(900, 600)
        
        # Apply dark theme
        self.root.configure(bg=BG_COLOR)
        
        # State
        self.sniffer = None
        self.is_running = False
        self.start_time = None
        
        self.setup_styles()
        self.setup_ui()
        self.update_timer()
        self.update_packet_count()
    
    def setup_styles(self):
        """Configure ttk styles to match Attack Simulator theme"""
        style = ttk.Style(self.root)
        style.theme_use("clam")
        
        # Frame styles
        style.configure("TFrame", background=BG_COLOR)
        style.configure("Card.TFrame", background=CARD_BG)
        
        # Label styles
        style.configure("TLabel", background=BG_COLOR, foreground=TEXT_COLOR, font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground=ACCENT_COLOR, background=BG_COLOR)
        style.configure("Status.TLabel", font=("Segoe UI", 12, "bold"), background=BG_COLOR)
        style.configure("Timer.TLabel", font=("Consolas", 28, "bold"), foreground=TEXT_COLOR, background=CARD_BG)
        style.configure("Card.TLabel", background=CARD_BG, foreground=TEXT_COLOR, font=("Segoe UI", 10))
        
        # LabelFrame styles
        style.configure("Card.TLabelframe", background=CARD_BG, relief="flat", borderwidth=2)
        style.configure("Card.TLabelframe.Label", font=("Segoe UI", 11, "bold"), foreground=ACCENT_COLOR, background=CARD_BG)
        
        # Button styles
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), background=ACCENT_COLOR, foreground=BG_COLOR, borderwidth=0, padding=[12, 8])
        style.map("Accent.TButton", background=[("active", "#74a8e8")])
        
        style.configure("Stop.TButton", font=("Segoe UI", 11, "bold"), background=ERROR_COLOR, foreground="#ffffff", borderwidth=0, padding=[14, 8])
        style.map("Stop.TButton", background=[("active", "#d63031")])
        
        style.configure("Small.TButton", font=("Segoe UI", 9), background=ACCENT_COLOR, foreground=BG_COLOR, borderwidth=0, padding=[8, 4])
        style.map("Small.TButton", background=[("active", "#74a8e8")])
        
        # Entry and Combobox styles
        style.configure("TEntry", fieldbackground=CARD_BG, foreground=TEXT_COLOR, borderwidth=1)
        style.configure("TCombobox", fieldbackground=CARD_BG, foreground=TEXT_COLOR, borderwidth=1)
        style.configure("TSpinbox", fieldbackground=CARD_BG, foreground=TEXT_COLOR, borderwidth=1)
        
        # Checkbutton styles
        style.configure("TCheckbutton", background=CARD_BG, foreground=TEXT_COLOR, font=("Segoe UI", 10))
    
    def setup_ui(self):
        # ==========================================
        # HEADER
        # ==========================================
        header = ttk.Frame(self.root, padding=(16, 12))
        header.pack(fill="x")
        
        # Title
        ttk.Label(header, text="🎯 Dataset Capture", style="Header.TLabel").pack(side="left")
        
        # Status indicator
        self.status_label = ttk.Label(header, text="🟢 Ready", style="Status.TLabel", foreground=SUCCESS_COLOR)
        self.status_label.pack(side="left", padx=20)
        
        # Stop button (right side)
        self.stop_btn = ttk.Button(header, text="🛑 STOP", command=self.stop_capture, style="Stop.TButton", state=tk.DISABLED)
        self.stop_btn.pack(side="right", padx=8)
        
        # Open captures folder button
        ttk.Button(header, text="📁 Captures", command=self.open_captures_folder, style="Accent.TButton").pack(side="right")
        
        # ==========================================
        # MAIN CONTENT (Two-column layout)
        # ==========================================
        content = ttk.Frame(self.root, padding=16)
        content.pack(fill="both", expand=True)
        
        # LEFT COLUMN - Settings
        left = ttk.Frame(content)
        left.pack(side="left", fill="both", expand=True, padx=(0, 12))
        
        # Configuration Card
        config_card = ttk.LabelFrame(left, text="⚙ Capture Configuration", style="Card.TLabelframe", padding=12)
        config_card.pack(fill="x", pady=(0, 12))
        
        settings_grid = ttk.Frame(config_card, style="Card.TFrame")
        settings_grid.pack(fill="x")
        
        # Attacker IP
        ttk.Label(settings_grid, text="🎯 Attacker IP:", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 6), pady=6)
        self.attacker_ip = ttk.Entry(settings_grid, width=20, font=("Consolas", 10))
        self.attacker_ip.grid(row=0, column=1, sticky="w", padx=6, pady=6)
        self.attacker_ip.insert(0, "26.0.0.0")
        ttk.Label(settings_grid, text="(optional)", style="Card.TLabel", foreground="#888").grid(row=0, column=2, padx=5, sticky="w")
        
        # Attack Label
        ttk.Label(settings_grid, text="🏷 Attack Label:", style="Card.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 6), pady=6)
        self.attack_label = ttk.Combobox(settings_grid, width=18, font=("Segoe UI", 10),
            values=['syn_flood', 'udp_flood', 'icmp_flood', 'port_scan', 
                   'dns_tunnel', 'arp_spoof', 'ssh_brute', 'slowloris', 'Normal'])
        self.attack_label.grid(row=1, column=1, sticky="w", padx=6, pady=6)
        self.attack_label.set('syn_flood')
        
        # Duration
        ttk.Label(settings_grid, text="⏱ Duration (sec):", style="Card.TLabel").grid(row=2, column=0, sticky="w", padx=(0, 6), pady=6)
        self.duration = ttk.Entry(settings_grid, width=20, font=("Consolas", 10))
        self.duration.grid(row=2, column=1, sticky="w", padx=6, pady=6)
        self.duration.insert(0, "300")
        
        # Output Directory
        ttk.Label(settings_grid, text="📁 Output Folder:", style="Card.TLabel").grid(row=3, column=0, sticky="w", padx=(0, 6), pady=6)
        
        dir_frame = ttk.Frame(settings_grid, style="Card.TFrame")
        dir_frame.grid(row=3, column=1, columnspan=2, sticky="w", padx=6, pady=6)
        
        self.output_dir = ttk.Entry(dir_frame, width=18, font=("Consolas", 10))
        self.output_dir.pack(side="left")
        self.output_dir.insert(0, "./captures")
        
        ttk.Button(dir_frame, text="Browse", command=self.browse_folder, style="Small.TButton", width=8).pack(side="left", padx=(6, 0))
        
        # Status Card
        status_card = ttk.LabelFrame(left, text="📊 Capture Status", style="Card.TLabelframe", padding=16)
        status_card.pack(fill="x", pady=(0, 12))
        
        status_inner = ttk.Frame(status_card, style="Card.TFrame")
        status_inner.pack(fill="x")
        
        # Timer display (large)
        self.timer_label = ttk.Label(status_inner, text="00:00:00", style="Timer.TLabel")
        self.timer_label.pack(pady=10)
        
        # Packet counter
        self.packets_label = ttk.Label(status_inner, text="📦 Packets: 0", style="Card.TLabel", font=("Segoe UI", 12))
        self.packets_label.pack(pady=5)
        
        # Control Buttons Card
        btn_card = ttk.Frame(left, style="TFrame")
        btn_card.pack(fill="x", pady=12)
        
        self.start_btn = ttk.Button(btn_card, text="▶ START CAPTURE", command=self.start_capture, style="Accent.TButton")
        self.start_btn.pack(fill="x", pady=4)
        
        # RIGHT COLUMN - Activity Log
        right = ttk.Frame(content)
        right.pack(side="right", fill="both", expand=True)
        
        log_card = ttk.LabelFrame(right, text="📋 Activity Log", style="Card.TLabelframe", padding=12)
        log_card.pack(fill="both", expand=True)
        
        self.log_text = scrolledtext.ScrolledText(
            log_card, 
            width=50, 
            height=20, 
            state=tk.DISABLED, 
            wrap=tk.WORD,
            background=BG_COLOR, 
            foreground=TEXT_COLOR,
            font=("Consolas", 9),
            insertbackground=TEXT_COLOR
        )
        self.log_text.pack(fill="both", expand=True)
        
        # Configure log tags for colored messages
        self.log_text.tag_config("info", foreground=TEXT_COLOR)
        self.log_text.tag_config("success", foreground=SUCCESS_COLOR)
        self.log_text.tag_config("error", foreground=ERROR_COLOR)
        self.log_text.tag_config("warning", foreground=WARNING_COLOR)
        
        # ==========================================
        # FOOTER
        # ==========================================
        footer = ttk.Frame(self.root, padding=(16, 10))
        footer.pack(fill="x")
        
        ttk.Label(footer, text="💡 Run as Administrator for best results", foreground=ACCENT_COLOR).pack(side="left")
        
        # Clear log button
        ttk.Button(footer, text="🗑", command=self.clear_log, width=3).pack(side="right", padx=4)
        
        # Initial log messages
        self.log("🚀 Dataset Capture Tool loaded", "success")
        if SCAPY_AVAILABLE:
            self.log("✓ Scapy installed - packet capture available", "success")
        else:
            self.log("⚠ Scapy NOT installed - capture will not work", "warning")
            self.log("   Install with: pip install scapy", "info")
        self.log("💡 Run as Administrator for best results", "info")
    
    def browse_folder(self):
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            self.output_dir.delete(0, tk.END)
            self.output_dir.insert(0, folder)
    
    def open_captures_folder(self):
        """Open the captures folder in file explorer"""
        path = os.path.abspath(self.output_dir.get())
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
        try:
            if os.name == "nt":
                os.startfile(path)
            else:
                os.system(f"xdg-open {path} &")
        except Exception as e:
            self.log(f"Error opening folder: {e}", "error")
    
    def clear_log(self):
        """Clear the activity log"""
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)
    
    def log(self, message, level="info"):
        self.log_text.configure(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", level)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)
    
    def validate_inputs(self):
        # Validate IP (optional, can be empty)
        ip = self.attacker_ip.get().strip()
        if ip:
            parts = ip.split('.')
            if len(parts) != 4:
                messagebox.showerror("Error", "Invalid Attacker IP format")
                return False
            try:
                if not all(0 <= int(p) <= 255 for p in parts):
                    raise ValueError
            except:
                messagebox.showerror("Error", "Invalid Attacker IP")
                return False
        
        # Validate duration
        try:
            dur = int(self.duration.get())
            if dur <= 0:
                raise ValueError
        except:
            messagebox.showerror("Error", "Duration must be a positive number")
            return False
        
        # Check if scapy is available
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", 
                "Scapy is not installed!\n\nInstall with:\npip install scapy")
            return False
        
        return True
    
    def sniffer_callback(self, message, level="info"):
        """Callback for sniffer messages"""
        self.root.after(0, lambda: self.log(message, level))
    
    def start_capture(self):
        if not self.validate_inputs():
            return
        
        # Create output directory
        output_dir = self.output_dir.get()
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            # Create sniffer instance
            self.sniffer = PacketSniffer(callback=self.sniffer_callback)
            
            # Start capture in background thread
            duration = int(self.duration.get())
            attack_label = self.attack_label.get()
            attacker_ip = self.attacker_ip.get().strip()
            
            def start_sniff():
                self.sniffer.start(
                    capture_dir=output_dir,
                    attack_label=attack_label,
                    duration=duration,
                    attacker_ip=attacker_ip
                )
            
            threading.Thread(target=start_sniff, daemon=True).start()
            
            self.is_running = True
            self.start_time = time.time()
            
            # Update UI
            self.status_label.config(text="🔴 CAPTURING", foreground=ERROR_COLOR)
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            
            # Disable inputs
            self.attacker_ip.config(state=tk.DISABLED)
            self.attack_label.config(state=tk.DISABLED)
            self.duration.config(state=tk.DISABLED)
            self.output_dir.config(state=tk.DISABLED)
            
            self.log(f"⏺ Started capture", "success")
            self.log(f"   Label: {attack_label}", "info")
            self.log(f"   Duration: {duration}s", "info")
            self.log(f"   Output: {output_dir}", "info")
            if attacker_ip:
                self.log(f"   Attacker IP: {attacker_ip}", "info")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start sniffer:\n{e}")
            self.log(f"ERROR: {e}", "error")
    
    def stop_capture(self):
        self.log("⏹ Stopping capture...", "warning")
        
        def stop_sniff():
            if self.sniffer:
                total_packets = self.sniffer.stop()
                self.root.after(0, lambda: self.log(f"✅ Capture complete! Total packets: {total_packets}", "success"))
                self.sniffer = None
        
        threading.Thread(target=stop_sniff, daemon=True).start()
        
        self.is_running = False
        
        # Update UI
        self.status_label.config(text="🟢 Ready", foreground=SUCCESS_COLOR)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        # Re-enable inputs
        self.attacker_ip.config(state=tk.NORMAL)
        self.attack_label.config(state='readonly')
        self.duration.config(state=tk.NORMAL)
        self.output_dir.config(state=tk.NORMAL)
    
    def update_timer(self):
        """Update timer display"""
        if self.is_running and self.start_time:
            elapsed = int(time.time() - self.start_time)
            try:
                duration = int(self.duration.get())
            except:
                duration = 300
            remaining = max(0, duration - elapsed)
            
            hours = remaining // 3600
            minutes = (remaining % 3600) // 60
            seconds = remaining % 60
            
            self.timer_label.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
            
            # Auto-stop when duration reached
            if elapsed >= duration:
                self.stop_capture()
        
        # Schedule next update
        self.root.after(1000, self.update_timer)
    
    def update_packet_count(self):
        """Update packet count display"""
        if self.is_running and self.sniffer:
            count = self.sniffer.packet_count
            self.packets_label.config(text=f"📦 Packets: {count:,}")
        
        # Schedule next update
        self.root.after(500, self.update_packet_count)
    
    def on_closing(self):
        if self.is_running:
            if messagebox.askokcancel("Quit", "Capture is running. Stop and quit?"):
                self.stop_capture()
                time.sleep(1)  # Give time for cleanup
                self.root.destroy()
        else:
            self.root.destroy()


def main():
    # Check for admin
    if os.name == 'nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            messagebox.showerror("Error", 
                "Administrator privileges required!\n\nRight-click and 'Run as administrator'")
            sys.exit(1)
    
    # Check for scapy
    if not SCAPY_AVAILABLE:
        root = tk.Tk()
        root.withdraw()
        messagebox.showwarning("Warning", 
            "Scapy is not installed!\n\nInstall with:\npip install scapy\n\nThe GUI will still open but capture won't work.")
        root.destroy()
    
    root = tk.Tk()
    app = SnifferGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == '__main__':
    main()
