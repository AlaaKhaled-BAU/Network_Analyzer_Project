# JSON-only sniffer - no CSV
import json
import argparse
from scapy.all import sniff, get_if_list, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ARP, DNS, DNSQR, DNSRR, Raw
import os
from datetime import datetime, timedelta
from pathlib import Path
import signal
import threading
import logging
import time
import sys
import importlib.util

# --- Interface Mapping Global ---
INTERFACE_MAP = {}


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
MAX_BUFFER_SIZE = 50000  # Max packets before forced save (prevents OOM)

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
    # Resolve friendly name if available
    friendly_interface = INTERFACE_MAP.get(interface, interface)
    
    summary = {
        'timestamp': pkt.time,
        'interface': friendly_interface,
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
    """
    Thread-safe packet buffer using queue.Queue for multi-producer efficiency.
    
    Uses Python's queue.Queue which is optimized for multi-threaded scenarios
    where multiple producers (NIC threads) add packets concurrently.
    """
    def __init__(self, save_interval, max_buffer_size=MAX_BUFFER_SIZE):
        import queue as queue_module
        self.queue_module = queue_module  # Store for later use
        
        self.save_interval = save_interval
        self.max_buffer_size = max_buffer_size
        
        # Use queue.Queue for thread-safe multi-producer operations
        self.packet_queue = queue_module.Queue()
        
        self.last_save_time = datetime.now()
        self.force_save_count = 0
        self._running = True
        
        # Lock for force-save check to prevent multiple threads triggering save simultaneously
        self._save_lock = threading.Lock()
        
        self.start_save_timer()
    
    def add_packet(self, packet):
        """Add packet to queue - thread-safe, no explicit locking needed"""
        self.packet_queue.put(packet)  # Thread-safe put
        
        # Check if queue is getting full - trigger early save (with lock to prevent race)
        current_size = self.packet_queue.qsize()
        if current_size >= self.max_buffer_size:
            # Use lock to ensure only one thread triggers the save
            with self._save_lock:
                # Double-check after acquiring lock (another thread may have already saved)
                if self.packet_queue.qsize() >= self.max_buffer_size:
                    self.force_save_count += 1
                    logger.warning(f"Buffer full (~{self.max_buffer_size} packets), forcing save #{self.force_save_count}")
                    self._save_buffer_internal()
    
    def _save_buffer_internal(self):
        """Internal save method - drains queue and saves to file"""
        # Quickly drain the queue
        packets_to_save = []
        try:
            while True:
                packet = self.packet_queue.get_nowait()
                packets_to_save.append(packet)
        except self.queue_module.Empty:
            pass  # Queue is empty - expected
        
        if not packets_to_save:
            return
        
        self.last_save_time = datetime.now()
        
        # Save in background thread to not block producers
        json_file = generate_json_filename()
        save_thread = threading.Thread(
            target=save_to_json_atomic,
            args=(packets_to_save, json_file),
            daemon=True
        )
        save_thread.start()
    
    def periodic_save(self):
        """Periodically save queue contents to file"""
        while self._running and running:
            time.sleep(1)
            
            time_since_last_save = (datetime.now() - self.last_save_time).total_seconds()
            
            # Save if interval passed and queue has packets
            if not self.packet_queue.empty() and time_since_last_save >= self.save_interval:
                queue_size = self.packet_queue.qsize()
                logger.info(f"Auto-saving ~{queue_size} packets")
                with self._save_lock:
                    self._save_buffer_internal()
    
    def save_buffer(self):
        """Public method to save buffer - thread-safe"""
        with self._save_lock:
            self._save_buffer_internal()
    
    def start_save_timer(self):
        """Start background thread for periodic saving"""
        save_thread = threading.Thread(target=self.periodic_save, daemon=True)
        save_thread.start()

def sniff_interface(interface, buffer):
    """Sniff packets on interface and add to buffer"""
    friendly = INTERFACE_MAP.get(interface, interface)
    logger.info(f"Started sniffing on {friendly} ({interface})")
    
    captured_any = False
    
    def handle_packet(pkt):
        nonlocal captured_any
        if not captured_any:
            logger.info(f"✓ Detected first packet on {friendly}! Sniffing active...")
            captured_any = True
            
        summary = packet_summary(pkt, interface)
        if summary:
            buffer.add_packet(summary)

    while running:
        sniff(prn=handle_packet, store=0, iface=interface, timeout=1)

def display_interfaces():
    """Display all available network interfaces with numbers and friendly names"""
    from scapy.all import IFACES
    
    interfaces = []
    interface_info = []
    
    # Build interface list with friendly names
    for raw_name, iface in IFACES.items():
        try:
            # Get IP address if available
            ip = getattr(iface, 'ip', None) or ''
            
            # Get friendly name (description)
            friendly = getattr(iface, 'description', '') or getattr(iface, 'name', '') or raw_name
            
            # Skip if no friendly name and no IP
            if not friendly and not ip:
                continue
                
            interfaces.append(raw_name)
            interface_info.append({
                'raw': raw_name,
                'friendly': friendly,
                'ip': ip
            })
        except:
            # Fallback: add raw name
            interfaces.append(raw_name)
            interface_info.append({
                'raw': raw_name,
                'friendly': raw_name,
                'ip': ''
            })
    
    # Also add any from get_if_list not in IFACES
    raw_list = get_if_list()
    for raw_name in raw_list:
        if raw_name not in interfaces:
            interfaces.append(raw_name)
            interface_info.append({
                'raw': raw_name,
                'friendly': raw_name.split('{')[0].strip('\\').replace('Device\\NPF_', ''),
                'ip': ''
            })
    
    print("\n" + "=" * 70)
    print("AVAILABLE NETWORK INTERFACES")
    print("=" * 70)
    for i, info in enumerate(interface_info, 1):
        ip_str = f" ({info['ip']})" if info['ip'] else ""
        print(f"  {i:2}. {info['friendly']}{ip_str}")
    print("-" * 70)
    print(f"   0. ALL interfaces ({len(interfaces)} total)")
    print("=" * 70 + "\n")
    
    return interfaces

def parse_interface_selection(selection: str, interfaces: list) -> list:
    """
    Parse interface selection string.
    
    Args:
        selection: Can be '0' or 'all' for all interfaces, 
                   or comma-separated numbers like '1,2,4'
        interfaces: List of available interface names
    
    Returns:
        List of selected interface names
    """
    selection = selection.strip().lower()
    
    # All interfaces
    if selection in ('0', 'all'):
        return interfaces
    
    # Parse comma-separated numbers
    try:
        indices = [int(x.strip()) for x in selection.split(',')]
        selected = []
        for idx in indices:
            if 1 <= idx <= len(interfaces):
                selected.append(interfaces[idx - 1])
            else:
                logger.warning(f"Invalid interface number: {idx} (valid: 1-{len(interfaces)})")
        return selected
    except ValueError:
        logger.error(f"Invalid selection format: {selection}")
        return []

def build_interface_map():
    """Populate the global INTERFACE_MAP with raw -> friendly name mappings"""
    from scapy.all import IFACES
    global INTERFACE_MAP
    
    # Clear existing map
    INTERFACE_MAP.clear()
    
    # 1. Add mappings from Scapy's IFACES (most reliable for friendly names)
    for raw_name, iface in IFACES.items():
        try:
            friendly = getattr(iface, 'description', '') or getattr(iface, 'name', '') or raw_name
            if friendly and friendly != raw_name:
                INTERFACE_MAP[raw_name] = friendly
        except:
            pass
            
    # 2. Add cleanups for any raw names from get_if_list() not yet mapped
    # e.g., remove \Device\NPF_ prefix if no better name found
    try:
        raw_list = get_if_list()
        for raw_name in raw_list:
            if raw_name not in INTERFACE_MAP:
                # Try simple string cleanup as fallback
                clean_name = raw_name.split('{')[0].strip('\\').replace('Device\\NPF_', '')
                if clean_name != raw_name:
                    INTERFACE_MAP[raw_name] = clean_name
    except:
        pass
        
    logger.info(f"Mapped {len(INTERFACE_MAP)} interfaces to friendly names")


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Network packet sniffer with interface selection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sniffer.py                    # Interactive mode
  python sniffer.py -i 1 --send        # Legacy HTTP mode
  python sniffer.py -i 1 --send        # Legacy HTTP mode
"""
    )

    parser.add_argument(
        '-i', '--interfaces',
        type=str,
        default=None,
        help="Interface selection: 'all'/0 for all, or comma-separated numbers (e.g., '1,2,4')"
    )
    parser.add_argument(
        '-l', '--list',
        action='store_true',
        help="List available interfaces and exit"
    )
    parser.add_argument(
        '-s', '--save-interval',
        type=int,
        default=SAVE_INTERVAL,
        help=f"Save interval in seconds (default: {SAVE_INTERVAL})"
    )
    parser.add_argument(
        '-b', '--buffer-size',
        type=int,
        default=MAX_BUFFER_SIZE,
        help=f"Max packets in buffer before forced save (default: {MAX_BUFFER_SIZE})"
    )
    parser.add_argument(
        '--send',
        action='store_true',
        help="Also start the sender to upload files to server (runs in background)"
    )
    
    args = parser.parse_args()
    
    # Get all interfaces
    all_interfaces = get_if_list()
    
    # Build the friendly name map
    build_interface_map()
    
    # Just list interfaces and exit
    if args.list:
        display_interfaces()
        sys.exit(0)
    
    # Determine which interfaces to use
    if args.interfaces is None:
        # Interactive mode - display and prompt
        display_interfaces()
        try:
            selection = input("Enter interface selection (0=all, or comma-separated numbers): ").strip()
            if not selection:
                selection = '0'  # Default to all
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            sys.exit(0)
        selected_interfaces = parse_interface_selection(selection, all_interfaces)
    else:
        # Use command line argument
        selected_interfaces = parse_interface_selection(args.interfaces, all_interfaces)
    
    if not selected_interfaces:
        logger.error("No valid interfaces selected. Use --list to see available interfaces.")
        sys.exit(1)
    
    logger.info("=" * 60)
    logger.info("Starting packet sniffer (storage-only mode)")
    logger.info("=" * 60)
    logger.info(f"Files will be saved to: {PENDING_DIR}")
    logger.info(f"Save interval: {args.save_interval} seconds")
    logger.info(f"Buffer limit: {args.buffer_size} packets")
    logger.info(f"Selected interfaces ({len(selected_interfaces)}):")
    for iface in selected_interfaces:
        friendly = INTERFACE_MAP.get(iface, iface)
        logger.info(f"  → {friendly}")
    logger.info("=" * 60)
    
    # Start sender in background if --send flag is used
    sender_thread = None
    sender_module = None  # Store reference for shutdown
    if args.send:
        try:
            # Import HTTP sender module from same directory
            sender_path = os.path.join(SCRIPT_DIR, 'sender.py')
            module_name = 'sender'
            logger.info("Using HTTP SENDER")

            spec = importlib.util.spec_from_file_location(module_name, sender_path)
            sender_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(sender_module)
            
            # Start sender in background thread
            logger.info("Starting sender in background...")
            
            sender_thread = threading.Thread(
                target=sender_module.monitor_and_upload,
                daemon=True
            )
            sender_thread.start()
            logger.info(f"Sender started - uploading to {sender_module.SERVER_URL}")
        except Exception as e:
            logger.error(f"Failed to start sender: {e}")
            logger.warning("Continuing with sniffing only...")
    
    # Start sniffer
    
    # Create packet buffer with configured limits
    packet_buffer = PacketBuffer(args.save_interval, args.buffer_size)
    
    # Start a thread for each selected interface
    threads = []
    for iface in selected_interfaces:
        t = threading.Thread(target=sniff_interface, args=(iface, packet_buffer), daemon=True)
        t.start()
        threads.append(t)

    # Keep main thread alive
    logger.info("Sniffer running. Press Ctrl+C to stop.")
    while running:
        time.sleep(1)
    
    # Stop sender gracefully if it was started
    if sender_module is not None:
        logger.info("Stopping sender...")
        if hasattr(sender_module, 'stop_sender'):
            sender_module.stop_sender()


    
    # Save final buffer before exit
    logger.info("Saving final buffer...")
    packet_buffer.save_buffer()
    
    # Wait briefly for save to complete
    time.sleep(1)
    
    logger.info("Sniffer stopped")

if __name__ == '__main__':
    main()

