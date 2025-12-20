"""
loopback_sniffer.py - Multi-NIC Attack Dataset Sniffer

Features:
- Captures from ALL network interfaces simultaneously
- Time-based capture (configurable via CAPTURE_DURATION env var, default 180s)
- Conditional labeling: only labels traffic involving 127.0.0.1
- CSV format compatible with ML pipeline
"""

import csv
import os
import time
import signal
import sys
import threading
from datetime import datetime
from pathlib import Path
from scapy.all import sniff, get_if_list, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ARP, DNS, DNSQR, Raw
import logging

# Fix Windows encoding issues
if sys.stdout:
    sys.stdout.reconfigure(encoding='utf-8')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('sniffer.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# Configuration from environment or defaults
CAPTURE_DIR = os.environ.get('CAPTURE_DIR', './captures')
ATTACK_LABEL = os.environ.get('ATTACK_LABEL', 'unknown')
CAPTURE_DURATION = int(os.environ.get('CAPTURE_DURATION', '180'))  # Default 3 minutes
LOOPBACK_IP = '127.0.0.1'

# For 2-machine setup: Set ATTACKER_IP to the attacker's IP address
# Traffic from this IP will be labeled as attack traffic
ATTACKER_IP = os.environ.get('ATTACKER_IP', '')  # e.g., '26.x.x.x' for Radmin VPN

# Known DNS servers used for DNS tunnel attacks
# Traffic to these IPs on port 53 will be labeled as dns_tunnel
DNS_TUNNEL_SERVERS = {
    '8.8.8.8',        # Google DNS
    '8.8.4.4',        # Google DNS
    '1.1.1.1',        # Cloudflare DNS
    '1.0.0.1',        # Cloudflare DNS
    '9.9.9.9',        # Quad9 DNS
    '208.67.222.222', # OpenDNS
    '208.67.220.220', # OpenDNS
}

os.makedirs(CAPTURE_DIR, exist_ok=True)
logger.info(f"Output directory: {CAPTURE_DIR}")
if ATTACKER_IP:
    logger.info(f"Attacker IP: {ATTACKER_IP} (traffic from this IP will be labeled as attack)")

# Global variables
packet_buffer = []
buffer_lock = threading.Lock()
running = True
start_time = datetime.now()
capture_start = None
packet_count = 0

def signal_handler(sig, frame):
    global running
    logger.info("\nStopping capture...")
    running = False

signal.signal(signal.SIGINT, signal_handler)
# Windows-compatible signal handling
if os.name == 'nt':
    signal.signal(signal.SIGBREAK, signal_handler)

def decode_tcp_flags(flag_value):
    """Convert TCP flag integer to readable flags string - NO SPACES"""
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
    return ",".join(flags)  # NO SPACES!

def to_csv_value(val):
    """Convert Python value to CSV format - empty string if None"""
    if val is None:
        return ''
    elif isinstance(val, bool):
        return str(val)  # "True" or "False" as strings
    else:
        return val

def get_conditional_label(src_ip, dst_ip, dst_port=None, protocol=None):
    """
    Apply attack label based on traffic characteristics:
    - 127.0.0.1 traffic → ATTACK_LABEL (from environment)
    - ATTACKER_IP traffic → ATTACK_LABEL (for 2-machine setup)
    - Traffic to known DNS servers on port 53 → ATTACK_LABEL (if label is dns_tunnel) or 'dns_tunnel'
    - All other traffic → 'Normal'
    """
    # Check for loopback traffic (standard attack pattern)
    if src_ip == LOOPBACK_IP or dst_ip == LOOPBACK_IP:
        return ATTACK_LABEL
    
    # Check for traffic from configured attacker IP (2-machine setup)
    if ATTACKER_IP and src_ip == ATTACKER_IP:
        return ATTACK_LABEL
    
    # Check for DNS tunnel pattern: UDP to known DNS servers on port 53
    # If ATTACK_LABEL is dns_tunnel (or contains it), use ATTACK_LABEL for consistency
    if protocol == 'UDP' and dst_port in [53, '53', 53.0]:
        if dst_ip in DNS_TUNNEL_SERVERS:
            if 'dns_tunnel' in ATTACK_LABEL.lower():
                return ATTACK_LABEL  # Use configured label (e.g., dns_tunnel_var1)
            return 'dns_tunnel'
    
    # Also check src_ip for DNS responses coming back
    if protocol == 'UDP' and src_ip in DNS_TUNNEL_SERVERS:
        if 'dns_tunnel' in ATTACK_LABEL.lower():
            return ATTACK_LABEL
        return 'dns_tunnel'
    
    # Everything else is Normal traffic
    return 'Normal'

def packet_summary(pkt, interface):
    """Extract packet features with conditional labeling"""
    global packet_count
    packet_count += 1

    # Initialize with empty strings (not None)
    summary = {
        'timestamp': pkt.time,
        'interface': interface,
        'src_mac': '',  # NEW: Ethernet source MAC
        'dst_mac': '',  # NEW: Ethernet dest MAC
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
        'attack_label': ''  # Will be set conditionally
    }

    # Extract Ethernet MAC addresses (works on real interfaces, not loopback)
    try:
        from scapy.all import Ether
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
            summary['tcp_flags'] = decode_tcp_flags(tcp.flags.value)
            summary['seq'] = tcp.seq
            summary['ack'] = tcp.ack

            # Boolean TCP flags as strings: "True" or "False"
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

                        # HTTP Request
                        if len(first_line) >= 2 and first_line[0] in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']:
                            summary['http_method'] = first_line[0]
                            summary['http_path'] = first_line[1] if len(first_line) > 1 else ''

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

            # DNS detection
            if DNS in pkt:
                dns = pkt[DNS]
                summary['dns_query'] = str(dns.qr == 0)  # "True" or "False"
                summary['dns_response'] = str(dns.qr == 1)

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

            # Boolean TCP flags as strings
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

            # DNS detection
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

    else:
        summary['protocol'] = 'OTHER'

    # Apply conditional labeling based on traffic type
    summary['attack_label'] = get_conditional_label(
        summary['src_ip'], 
        summary['dst_ip'],
        dst_port=summary.get('dst_port'),
        protocol=summary.get('protocol')
    )

    # Convert all values to CSV format (empty string if None)
    return {k: to_csv_value(v) for k, v in summary.items()}

def save_packets_to_csv(packets, filename):
    """Save packets to CSV file with exact format"""
    if not packets:
        logger.warning("No packets to save!")
        return False

    try:
        file_exists = os.path.exists(filename)
        mode = 'a' if file_exists else 'w'

        with open(filename, mode, newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=packets[0].keys())
            if not file_exists:
                writer.writeheader()
                logger.info(f"[+] Created CSV with header: {filename}")
            writer.writerows(packets)

        logger.info(f"[+] SAVED {len(packets)} packets to: {os.path.basename(filename)}")
        return True

    except Exception as e:
        logger.error(f"[-] FAILED to save CSV: {e}")
        return False

def should_stop_capture():
    """Check if capture duration has elapsed"""
    global capture_start, running
    if not running:
        return True
    if capture_start is None:
        return False
    elapsed = (datetime.now() - capture_start).total_seconds()
    return elapsed >= CAPTURE_DURATION

def sniff_interface(interface):
    """Sniff packets on a specific interface"""
    global packet_buffer, running
    
    logger.info(f"Started sniffing on: {interface}")
    
    def handle_packet(pkt):
        global packet_buffer
        if should_stop_capture():
            return True  # Stop sniffing
        
        try:
            summary = packet_summary(pkt, interface)
            with buffer_lock:
                packet_buffer.append(summary)
        except Exception as e:
            logger.error(f"Error processing packet on {interface}: {e}")
    
    try:
        while running and not should_stop_capture():
            sniff(
                prn=handle_packet,
                store=False,
                iface=interface,
                timeout=5,  # Check every 5 seconds
                stop_filter=lambda x: should_stop_capture()
            )
    except Exception as e:
        logger.error(f"Sniffer error on {interface}: {e}")

def periodic_saver():
    """Periodically save buffer to CSV"""
    global packet_buffer, running
    save_interval = 30  # Save every 30 seconds
    
    while running and not should_stop_capture():
        time.sleep(save_interval)
        
        with buffer_lock:
            if packet_buffer:
                packets_to_save = packet_buffer.copy()
                packet_buffer = []
        
        if packets_to_save:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.join(CAPTURE_DIR, f"{ATTACK_LABEL}_{timestamp}.csv")
            save_packets_to_csv(packets_to_save, filename)

def main():
    global packet_buffer, capture_start, running

    logger.info("=" * 80)
    logger.info("MULTI-NIC ATTACK DATASET SNIFFER")
    logger.info("=" * 80)
    logger.info(f"Attack label: {ATTACK_LABEL}")
    logger.info(f"Capture duration: {CAPTURE_DURATION} seconds")
    logger.info(f"Labeling: Only traffic involving {LOOPBACK_IP}")
    logger.info(f"Output directory: {os.path.abspath(CAPTURE_DIR)}")
    logger.info(f"Started at: {start_time}")
    logger.info("=" * 80)

    # Get all network interfaces
    interfaces = get_if_list()
    logger.info(f"\nDetected {len(interfaces)} interfaces: {interfaces}")

    # Start capture timer
    capture_start = datetime.now()
    logger.info(f"\nStarting {CAPTURE_DURATION}-second capture on ALL interfaces...")
    logger.info("Press Ctrl+C to stop early\n")
    logger.info("=" * 80)

    # Start periodic saver thread
    saver_thread = threading.Thread(target=periodic_saver, daemon=True)
    saver_thread.start()

    # Start a sniffing thread for each interface
    threads = []
    for iface in interfaces:
        t = threading.Thread(target=sniff_interface, args=(iface,), daemon=True)
        t.start()
        threads.append(t)

    try:
        # Main loop - wait for capture duration
        while running and not should_stop_capture():
            time.sleep(1)
            elapsed = (datetime.now() - capture_start).total_seconds()
            remaining = max(0, CAPTURE_DURATION - elapsed)
            
            if int(elapsed) % 30 == 0 and int(elapsed) > 0:  # Log every 30 seconds
                logger.info(f"Capture progress: {int(elapsed)}s / {CAPTURE_DURATION}s ({packet_count} packets)")

    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")

    finally:
        running = False
        
        # Give threads time to finish
        time.sleep(2)
        
        # Save remaining packets
        logger.info(f"\nSaving remaining {len(packet_buffer)} packets...")
        if packet_buffer:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.join(CAPTURE_DIR, f"{ATTACK_LABEL}_{timestamp}_FINAL.csv")
            save_packets_to_csv(packet_buffer, filename)

        elapsed = (datetime.now() - start_time).total_seconds()
        logger.info("\n" + "=" * 80)
        logger.info("CAPTURE COMPLETE")
        logger.info("=" * 80)
        logger.info(f"Duration: {elapsed:.1f} seconds")
        logger.info(f"Total packets captured: {packet_count}")
        logger.info(f"Interfaces monitored: {len(interfaces)}")
        logger.info(f"Output directory: {os.path.abspath(CAPTURE_DIR)}")

        # List all CSV files
        csv_files = sorted([f for f in os.listdir(CAPTURE_DIR) if f.endswith('.csv')])
        logger.info(f"\nCSV files created: {len(csv_files)}")
        for csv_file in csv_files:
            file_path = os.path.join(CAPTURE_DIR, csv_file)
            file_size = os.path.getsize(file_path)
            logger.info(f"  [+] {csv_file} ({file_size:,} bytes)")
        logger.info("=" * 80)

if __name__ == '__main__':
    main()
