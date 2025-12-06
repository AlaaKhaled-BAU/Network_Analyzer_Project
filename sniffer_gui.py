"""
GUI for Network Packet Sniffer - COMPLETE VERSION

All features from original sniffer.py including:
- Full TCP/UDP/ICMP/ARP support
- HTTP request/response parsing
- DNS query/response with answer size
- IPv4 and IPv6
- All TCP flags (SYN, ACK, FIN, RST, PSH)
- Sequence/ACK numbers
- ARP hardware addresses
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import csv
import os
from datetime import datetime
from pathlib import Path
import queue

# Import sniffer functions
try:
    from scapy.all import (sniff, get_if_list, IP, IPv6, TCP, UDP, ICMP, 
                           ICMPv6EchoRequest, ARP, DNS, DNSQR, DNSRR, Raw)
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    messagebox.showerror(
        "Import Error",
        "Scapy is not installed!\n\nInstall it with:\npip install scapy"
    )


class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer - Complete")
        self.root.geometry("800x700")
        self.root.resizable(True, True)

        # Sniffer state
        self.is_running = False
        self.packet_buffer = []
        self.packet_count = 0
        self.start_time = None
        self.output_dir = None
        self.sniffer_threads = []
        self.log_queue = queue.Queue()

        self.setup_ui()
        self.update_log_from_queue()

    # ========== COMPLETE PACKET SUMMARY (from original sniffer.py) ==========

    def decode_tcp_flags(self, flag_value):
        """Convert TCP flag integer to readable flags list."""
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

    def packet_summary(self, pkt, interface):
        """Complete packet summary with ALL fields from original sniffer.py"""
        summary = {
            'timestamp': pkt.time,
            'interface': interface,
            'src_ip': None,
            'dst_ip': None,
            'protocol': None,
            'length': len(pkt),
            'src_port': None,
            'dst_port': None,
            'tcp_flags': None,
            'tcp_syn': None,
            'tcp_ack': None,
            'tcp_fin': None,
            'tcp_rst': None,
            'tcp_psh': None,
            'seq': None,
            'ack': None,
            'icmp_type': None,
            'icmp_code': None,
            'arp_op': None,
            'arp_psrc': None,
            'arp_pdst': None,
            'arp_hwsrc': None,
            'arp_hwdst': None,
            'dns_query': None,
            'dns_qname': None,
            'dns_qtype': None,
            'dns_response': None,
            'dns_answer_count': None,
            'dns_answer_size': None,
            'http_method': None,
            'http_path': None,
            'http_status_code': None,
            'http_host': None
        }

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

                # Individual TCP flag booleans for ML features
                summary['tcp_syn'] = bool(tcp.flags.value & 0x02)
                summary['tcp_ack'] = bool(tcp.flags.value & 0x10)
                summary['tcp_fin'] = bool(tcp.flags.value & 0x01)
                summary['tcp_rst'] = bool(tcp.flags.value & 0x04)
                summary['tcp_psh'] = bool(tcp.flags.value & 0x08)

                # HTTP detection (common ports: 80, 443, 8080, etc.)
                if Raw in pkt and tcp.dport in [80, 8080, 8000, 3000]:
                    payload = bytes(pkt[Raw].load)
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        lines = payload_str.split('\r\n')
                        if lines:
                            first_line = lines[0].split()

                            # HTTP Request
                            if len(first_line) >= 2 and first_line[0] in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']:
                                summary['http_method'] = first_line[0]
                                summary['http_path'] = first_line[1] if len(first_line) > 1 else None

                                # Extract Host header
                                for line in lines[1:]:
                                    if line.lower().startswith('host:'):
                                        summary['http_host'] = line.split(':', 1)[1].strip()
                                        break

                            # HTTP Response
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

                # DNS detection (port 53)
                if DNS in pkt:
                    dns = pkt[DNS]
                    summary['dns_query'] = dns.qr == 0  # 0 = query, 1 = response
                    summary['dns_response'] = dns.qr == 1

                    # DNS Query fields
                    if DNSQR in pkt:
                        try:
                            summary['dns_qname'] = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                            summary['dns_qtype'] = pkt[DNSQR].qtype
                        except:
                            pass

                    # DNS Response fields
                    if dns.qr == 1 and dns.an:
                        summary['dns_answer_count'] = dns.ancount

                        # Calculate total answer size
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

                # Individual TCP flag booleans
                summary['tcp_syn'] = bool(tcp.flags.value & 0x02)
                summary['tcp_ack'] = bool(tcp.flags.value & 0x10)
                summary['tcp_fin'] = bool(tcp.flags.value & 0x01)
                summary['tcp_rst'] = bool(tcp.flags.value & 0x04)
                summary['tcp_psh'] = bool(tcp.flags.value & 0x08)

            elif UDP in pkt:
                udp = pkt[UDP]
                summary['protocol'] = 'UDP'
                summary['src_port'] = udp.sport
                summary['dst_port'] = udp.dport

                # DNS detection
                if DNS in pkt:
                    dns = pkt[DNS]
                    summary['dns_query'] = dns.qr == 0
                    summary['dns_response'] = dns.qr == 1

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
            summary['arp_op'] = arp.op  # 1=request, 2=reply
            summary['arp_psrc'] = arp.psrc
            summary['arp_pdst'] = arp.pdst
            summary['arp_hwsrc'] = arp.hwsrc
            summary['arp_hwdst'] = arp.hwdst

        else:
            summary['protocol'] = 'OTHER'

        return summary

    # ========== GUI SETUP ==========

    def setup_ui(self):
        """Create the GUI layout"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

        row = 0

        # ========== TITLE ==========
        title_label = ttk.Label(
            main_frame, 
            text="🌐 Network Packet Sniffer (Complete)",
            font=("Arial", 14, "bold")
        )
        title_label.grid(row=row, column=0, columnspan=2, pady=(0, 10))

        # ========== OUTPUT DIRECTORY SECTION ==========
        row += 1
        ttk.Label(main_frame, text="Output Directory:", 
                  font=("Arial", 10, "bold")).grid(
            row=row, column=0, columnspan=2, sticky=tk.W, pady=(0, 5)
        )

        row += 1
        dir_frame = ttk.Frame(main_frame)
        dir_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        dir_frame.columnconfigure(0, weight=1)

        self.dir_label = ttk.Label(
            dir_frame, 
            text="No directory selected (will use ./logs/captured_packets)", 
            foreground="gray"
        )
        self.dir_label.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))

        self.dir_btn = ttk.Button(dir_frame, text="Browse...", 
                                   command=self.browse_directory)
        self.dir_btn.grid(row=0, column=1)

        # ========== SAVE MODE SECTION ==========
        row += 1
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).grid(
            row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10
        )

        row += 1
        ttk.Label(main_frame, text="Save Mode:", 
                  font=("Arial", 10, "bold")).grid(
            row=row, column=0, columnspan=2, sticky=tk.W, pady=(0, 5)
        )

        row += 1
        self.save_mode = tk.StringVar(value="auto")

        radio_frame = ttk.Frame(main_frame)
        radio_frame.grid(row=row, column=0, columnspan=2, sticky=tk.W, pady=(0, 5))

        ttk.Radiobutton(
            radio_frame,
            text="Auto-save (save every X seconds during capture)",
            variable=self.save_mode,
            value="auto",
            command=self.toggle_interval_entry
        ).pack(anchor=tk.W)

        ttk.Radiobutton(
            radio_frame,
            text="Manual save (save all packets only when Stop is pressed)",
            variable=self.save_mode,
            value="manual",
            command=self.toggle_interval_entry
        ).pack(anchor=tk.W, pady=(5, 0))

        # Auto-save interval
        row += 1
        interval_frame = ttk.Frame(main_frame)
        interval_frame.grid(row=row, column=0, columnspan=2, sticky=tk.W, pady=(5, 10))

        ttk.Label(interval_frame, text="  Auto-save interval (seconds):").pack(side=tk.LEFT)

        self.interval_var = tk.StringVar(value="5")
        self.interval_entry = ttk.Entry(interval_frame, textvariable=self.interval_var, width=10)
        self.interval_entry.pack(side=tk.LEFT, padx=5)

        # ========== INTERFACE SELECTION ==========
        row += 1
        ttk.Label(main_frame, text="Network Interface:", 
                  font=("Arial", 10, "bold")).grid(
            row=row, column=0, columnspan=2, sticky=tk.W, pady=(0, 5)
        )

        row += 1
        if SCAPY_AVAILABLE:
            interfaces = get_if_list()
            self.interface_var = tk.StringVar(value="all")
            interface_combo = ttk.Combobox(
                main_frame, 
                textvariable=self.interface_var,
                values=["all"] + interfaces,
                state="readonly",
                width=40
            )
            interface_combo.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        else:
            ttk.Label(main_frame, text="Scapy not available", foreground="red").grid(
                row=row, column=0, columnspan=2, sticky=tk.W
            )

        # ========== CONTROL BUTTONS ==========
        row += 1
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).grid(
            row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10
        )

        row += 1
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=row, column=0, columnspan=2, pady=10)

        self.start_btn = ttk.Button(
            button_frame, 
            text="▶ Start Capture",
            command=self.start_capture,
            width=20
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(
            button_frame,
            text="■ Stop Capture",
            command=self.stop_capture,
            state=tk.DISABLED,
            width=20
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # ========== STATISTICS ==========
        row += 1
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        stats_frame.columnconfigure(1, weight=1)

        ttk.Label(stats_frame, text="Packets Captured:").grid(row=0, column=0, sticky=tk.W)
        self.packet_count_label = ttk.Label(stats_frame, text="0", font=("Arial", 12, "bold"))
        self.packet_count_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))

        ttk.Label(stats_frame, text="Capture Time:").grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        self.time_label = ttk.Label(stats_frame, text="00:00:00", font=("Arial", 12, "bold"))
        self.time_label.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=(5, 0))

        ttk.Label(stats_frame, text="Status:").grid(row=2, column=0, sticky=tk.W, pady=(5, 0))
        self.status_label = ttk.Label(stats_frame, text="Idle", 
                                       font=("Arial", 12, "bold"), foreground="gray")
        self.status_label.grid(row=2, column=1, sticky=tk.W, padx=(10, 0), pady=(5, 0))

        # ========== LOG OUTPUT ==========
        row += 1
        ttk.Label(main_frame, text="Log Output:", 
                  font=("Arial", 10, "bold")).grid(
            row=row, column=0, columnspan=2, sticky=tk.W, pady=(0, 5)
        )

        row += 1
        self.log_text = scrolledtext.ScrolledText(
            main_frame, 
            height=15, 
            state=tk.DISABLED,
            wrap=tk.WORD, 
            font=("Courier", 9)
        )
        self.log_text.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))

        main_frame.rowconfigure(row, weight=1)

        # Configure log tags
        self.log_text.tag_config("INFO", foreground="blue")
        self.log_text.tag_config("ERROR", foreground="red")
        self.log_text.tag_config("SUCCESS", foreground="green")
        self.log_text.tag_config("WARNING", foreground="orange")

        # Welcome message
        self.log("✅ Complete Sniffer - All fields from original sniffer.py", "SUCCESS")
        self.log("Features: TCP/UDP/ICMP/ARP, HTTP, DNS, IPv4/IPv6", "INFO")
        self.log("1. Select output directory (optional)", "INFO")
        self.log("2. Choose save mode (auto or manual)", "INFO")
        self.log("3. Select network interface", "INFO")
        self.log("4. Click 'Start Capture'\n", "INFO")

    def toggle_interval_entry(self):
        """Enable/disable interval entry based on save mode"""
        if self.save_mode.get() == "auto":
            self.interval_entry.config(state=tk.NORMAL)
        else:
            self.interval_entry.config(state=tk.DISABLED)

    def browse_directory(self):
        """Browse for output directory"""
        directory = filedialog.askdirectory(
            title="Select Output Directory for Captured Packets"
        )

        if directory:
            self.output_dir = directory
            self.dir_label.config(text=directory, foreground="black")
            self.log(f"Output directory: {directory}", "INFO")

    def log(self, message, tag="INFO"):
        """Add message to log (thread-safe via queue)"""
        self.log_queue.put((message, tag))

    def update_log_from_queue(self):
        """Update log text from queue (runs in main thread)"""
        try:
            while True:
                message, tag = self.log_queue.get_nowait()
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, f"{message}\n", tag)
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
        except queue.Empty:
            pass

        # Schedule next update
        self.root.after(100, self.update_log_from_queue)

    def start_capture(self):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy is not installed!")
            return

        # Validate interval for auto-save
        if self.save_mode.get() == "auto":
            try:
                interval = int(self.interval_var.get())
                if interval < 1:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Error", "Invalid auto-save interval! Must be >= 1 second.")
                return

        # Set output directory
        if not self.output_dir:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            self.output_dir = os.path.join(script_dir, 'logs', 'captured_packets')
            os.makedirs(self.output_dir, exist_ok=True)
            self.dir_label.config(text=self.output_dir, foreground="black")

        # Reset state
        self.packet_buffer = []
        self.packet_count = 0
        self.start_time = datetime.now()
        self.is_running = True

        # Update UI
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.dir_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Capturing...", foreground="green")

        self.log("\n" + "="*60, "INFO")
        self.log("Starting packet capture...", "SUCCESS")
        self.log(f"Save mode: {self.save_mode.get()}", "INFO")
        if self.save_mode.get() == "auto":
            self.log(f"Auto-save interval: {self.interval_var.get()}s", "INFO")
        self.log(f"Output: {self.output_dir}", "INFO")
        self.log(f"Interface: {self.interface_var.get()}", "INFO")
        self.log("="*60 + "\n", "INFO")

        # Start sniffing threads
        interface = self.interface_var.get()
        if interface == "all":
            interfaces = get_if_list()
        else:
            interfaces = [interface]

        for iface in interfaces:
            t = threading.Thread(
                target=self.sniff_thread,
                args=(iface,),
                daemon=True
            )
            t.start()
            self.sniffer_threads.append(t)
            self.log(f"Started sniffing on {iface}", "INFO")

        # Start auto-save thread if needed
        if self.save_mode.get() == "auto":
            auto_save_thread = threading.Thread(
                target=self.auto_save_thread,
                daemon=True
            )
            auto_save_thread.start()

        # Start statistics update thread
        stats_thread = threading.Thread(target=self.update_stats, daemon=True)
        stats_thread.start()

    def sniff_thread(self, interface):
        """Thread for sniffing packets on an interface"""
        def handle_packet(pkt):
            if not self.is_running:
                return

            try:
                summary = self.packet_summary(pkt, interface)
                if summary:
                    self.packet_buffer.append(summary)
                    self.packet_count += 1
            except Exception as e:
                pass  # Ignore packet processing errors

        while self.is_running:
            try:
                sniff(prn=handle_packet, store=0, iface=interface, timeout=1, quiet=True)
            except Exception as e:
                self.log(f"Error on {interface}: {str(e)}", "ERROR")
                break

    def auto_save_thread(self):
        """Thread for auto-saving packets at intervals"""
        import time
        interval = int(self.interval_var.get())
        last_save = datetime.now()

        while self.is_running:
            time.sleep(1)
            elapsed = (datetime.now() - last_save).total_seconds()

            if elapsed >= interval and self.packet_buffer:
                self.save_packets_to_file(auto=True)
                last_save = datetime.now()

    def save_packets_to_file(self, auto=False):
        """Save packets to CSV file"""
        if not self.packet_buffer:
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"packets_{timestamp}.csv"
        filepath = os.path.join(self.output_dir, filename)

        try:
            # Copy buffer
            packets_to_save = self.packet_buffer.copy()

            # Clear buffer only if auto-save
            if auto:
                self.packet_buffer.clear()

            # Write to file
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                if packets_to_save:
                    writer = csv.DictWriter(f, fieldnames=packets_to_save[0].keys())
                    writer.writeheader()
                    writer.writerows(packets_to_save)

            save_type = "Auto-saved" if auto else "Saved"
            self.log(f"{save_type} {len(packets_to_save)} packets to {filename}", "SUCCESS")

        except Exception as e:
            self.log(f"Error saving file: {str(e)}", "ERROR")

    def update_stats(self):
        """Update statistics display"""
        import time

        while self.is_running:
            if self.start_time:
                elapsed = datetime.now() - self.start_time
                hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
                minutes, seconds = divmod(remainder, 60)
                time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

                self.root.after(0, lambda: self.packet_count_label.config(text=str(self.packet_count)))
                self.root.after(0, lambda: self.time_label.config(text=time_str))

            time.sleep(0.5)

    def stop_capture(self):
        """Stop packet capture"""
        self.is_running = False
        self.status_label.config(text="Stopping...", foreground="orange")

        # Wait for threads to finish
        for t in self.sniffer_threads:
            t.join(timeout=2)
        self.sniffer_threads.clear()

        self.log("\nStopped packet capture", "WARNING")

        # Save remaining packets if manual mode
        if self.save_mode.get() == "manual":
            self.log(f"Saving {len(self.packet_buffer)} captured packets...", "INFO")
            self.save_packets_to_file(auto=False)

        # Final save for any remaining packets in auto mode
        elif self.packet_buffer:
            self.log(f"Saving final {len(self.packet_buffer)} packets...", "INFO")
            self.save_packets_to_file(auto=False)

        # Update UI
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.dir_btn.config(state=tk.NORMAL)
        self.status_label.config(text="Idle", foreground="gray")

        self.log(f"\nTotal packets captured: {self.packet_count}", "SUCCESS")
        self.log(f"Files saved to: {self.output_dir}\n", "INFO")

        # Show completion dialog
        messagebox.showinfo(
            "Capture Complete",
            f"Captured {self.packet_count} packets\n"
            f"Saved to: {self.output_dir}"
        )


def main():
    """Launch the GUI"""
    root = tk.Tk()

    # Apply theme
    try:
        style = ttk.Style()
        available_themes = style.theme_names()
        if 'clam' in available_themes:
            style.theme_use('clam')
    except:
        pass

    app = SnifferGUI(root)

    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')

    root.mainloop()


if __name__ == "__main__":
    main()
