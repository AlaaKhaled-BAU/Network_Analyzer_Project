# JSON-only sniffer - no CSV
import json
import ipaddress
from scapy.all import sniff, get_if_list, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ARP, DNS, DNSQR, DNSRR, Raw
import os
from datetime import datetime, timedelta
from pathlib import Path
import signal
import threading
import logging
import time

# --- Configure Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- Create logs folder inside script's directory ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(SCRIPT_DIR, 'logs')
PENDING_DIR = os.path.join(LOGS_DIR, 'pending_upload')  # Files ready for upload
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(PENDING_DIR, exist_ok=True)
logger.info(f"Logs folder created at {LOGS_DIR}")

# --- Configuration ---
SAVE_INTERVAL = 5  # Save JSON every 5 seconds for real-time detection

# --- File Generation Functions ---
def generate_json_filename():
    """Generate timestamped JSON filename"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return os.path.join(PENDING_DIR, f'packets_{timestamp}.json')

def save_to_json_atomic(packets, base_filename):
    """
    Save packets to JSON file atomically with .ready marker
    Uses temp file + rename for atomic operation
    """
    if not packets:
        logger.warning("No packets to save")
        return
    
    # Write to temporary file first
    temp_file = base_filename + '.tmp'
    ready_marker = base_filename + '.ready'
    
    try:
        # Write to temp file as JSON array
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(packets, f, indent=None)  # Compact JSON
        
        # Atomic rename (this is instantaneous)
        os.replace(temp_file, base_filename)
        
        # Create ready marker to signal sender.py
        Path(ready_marker).touch()
        
        logger.info(f"✓ Saved {len(packets)} packets to {os.path.basename(base_filename)}")
        
    except Exception as e:
        logger.error(f"Failed to save JSON: {e}")
        # Clean up temp file if it exists
        if os.path.exists(temp_file):
            os.remove(temp_file)

# --- TCP Flags Decoder ---
def decode_tcp_flags(flag_value):
    """Convert TCP flag integer to readable flags list."""
    flags = []
    if flag_value & 1:
        flags.append("FIN")
    if flag_value & 2:
        flags.append("SYN")
    if flag_value & 4:
        flags.append("RST")
    if flag_value & 8:
        flags.append("PSH")
    if flag_value & 16:
        flags.append("ACK")
    if flag_value & 32:
        flags.append("URG")
    if flag_value & 64:
        flags.append("ECE")
    if flag_value & 128:
        flags.append("CWR")
    return ",".join(flags)

# --- Packet Summary Function ---
def packet_summary(pkt, interface):
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
            summary['tcp_flags'] = decode_tcp_flags(tcp.flags.value)
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
            summary['tcp_flags'] = decode_tcp_flags(tcp.flags.value)
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

# --- Graceful exit ---
running = True

def signal_handler(sig, frame):
    global running
    logger.info("Stopping capture...")
    running = False

signal.signal(signal.SIGINT, signal_handler)

# --- Packet Buffer Manager ---
class PacketBuffer:
    """Manages packet buffering and periodic saves"""
    def __init__(self, save_interval):
        self.save_interval = save_interval
        self.buffer = []
        self.last_save_time = datetime.now()
        self.lock = threading.Lock()
        self.start_save_timer()
    
    def add_packet(self, packet):
        """Add packet to buffer"""
        with self.lock:
            self.buffer.append(packet)
    
    def save_buffer(self):
        """Save current buffer to file"""
        with self.lock:
            if not self.buffer:
                return
            
            packets_to_save = self.buffer.copy()
            self.buffer.clear()
            self.last_save_time = datetime.now()
        
        # Save in background thread
        json_file = generate_json_filename()
        save_thread = threading.Thread(
            target=save_to_json_atomic,
            args=(packets_to_save, json_file),
            daemon=True
        )
        save_thread.start()
    
    def periodic_save(self):
        """Periodically save buffer to CSV"""
        while running:
            time.sleep(1)
            
            time_since_last_save = (datetime.now() - self.last_save_time).total_seconds()
            
            if self.buffer and time_since_last_save >= self.save_interval:
                logger.info(f"Auto-saving {len(self.buffer)} packets")
                self.save_buffer()
    
    def start_save_timer(self):
        """Start background thread for periodic saving"""
        save_thread = threading.Thread(target=self.periodic_save, daemon=True)
        save_thread.start()

def sniff_interface(interface, buffer):
    """Sniff packets on interface and add to buffer"""
    logger.info(f"Started sniffing on {interface}")
    
    def handle_packet(pkt):
        summary = packet_summary(pkt, interface)
        if summary:
            buffer.add_packet(summary)

    while running:
        sniff(prn=handle_packet, store=0, iface=interface, timeout=1)

def main():
    logger.info("Starting packet sniffer (storage-only mode)...")
    logger.info(f"Files will be saved to: {PENDING_DIR}")
    logger.info(f"Save interval: {SAVE_INTERVAL} seconds")
    
    # Create packet buffer
    packet_buffer = PacketBuffer(SAVE_INTERVAL)
    
    # Get network interfaces
    interfaces = get_if_list()
    logger.info(f"Interfaces detected: {interfaces}")

    # Start a thread for each interface
    threads = []
    for iface in interfaces:
        t = threading.Thread(target=sniff_interface, args=(iface, packet_buffer), daemon=True)
        t.start()
        threads.append(t)

    # Keep main thread alive
    logger.info("Sniffer running. Press Ctrl+C to stop.")
    while running:
        time.sleep(1)
    
    # Save final buffer before exit
    logger.info("Saving final buffer...")
    packet_buffer.save_buffer()
    
    # Wait briefly for save to complete
    time.sleep(1)
    
    logger.info("Sniffer stopped")

if __name__ == '__main__':
    main()
