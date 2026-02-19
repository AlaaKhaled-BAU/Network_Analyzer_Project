#!/bin/bash

# setup_env.sh
# Sets up the environment for NetGuardian Pro Attack Simulations
# Usage: ./setup_env.sh [attacker|victim]

if [ "$1" != "attacker" ] && [ "$1" != "victim" ]; then
    echo "Usage: ./setup_env.sh [attacker|victim]"
    echo "  attacker: Installs python libs (scapy, paramiko) and tools"
    echo "  victim:   Installs vulnerable services (ssh-server, nginx, tcpdump)"
    exit 1
fi

ROLE=$1

if [ "$ROLE" == "attacker" ]; then
    echo "=== SETTING UP ATTACKER MACHINE ==="
    
    # 1. Update & Install Core Tools
    sudo apt-get update
    sudo apt-get install -y python3-pip python3-venv libpcap-dev git tcpreplay iperf3

    # 2. Setup Virtual Environment (Recommended)
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        echo "Created venv. Activate with: source venv/bin/activate"
    fi
    
    # 3. Install Python Dependencies
    # (Assuming we are in the project root or running this standalone)
    source venv/bin/activate || true
    pip install scapy paramiko requests pandas numpy python-nmap
    
    echo "=== ATTACKER SETUP COMPLETE ==="
    echo "Run: source venv/bin/activate"
    echo "Run: sudo python3 attack_simulator.py (requires root for Scapy)"

elif [ "$ROLE" == "victim" ]; then
    echo "=== SETTING UP VICTIM MACHINE ==="
    
    # 1. Install SSH Server (Port 22 Target)
    sudo apt-get update
    sudo apt-get install -y openssh-server
    sudo systemctl enable ssh
    sudo systemctl start ssh
    echo "[+] SSH Server active on Port 22"

    # 2. Install Nginx Web Server (Port 80/443 Target)
    # Using Nginx as it handles Slowloris better than Apache default config (good for testing)
    sudo apt-get install -y nginx
    sudo systemctl enable nginx
    sudo systemctl start nginx
    echo "[+] Nginx Web Server active on Port 80"

    # 3. Install TCPDump (For Sniffing Validation)
    sudo apt-get install -y tcpdump
    
    # 4. Create a Dummy "Flag" File for Exfiltration testing
    echo "This is a secret file for testing purposes." > secret_data.txt

    # 5. Install DHCP Server (Target for Starvation)
    # WARNING: Do NOT run this on your main home network if you already have a router doing DHCP!
    # Ideally, run this in an isolated lab network.
    sudo apt-get install -y isc-dhcp-server
    # We stop it by default to prevent accidents
    sudo systemctl stop isc-dhcp-server
    sudo systemctl disable isc-dhcp-server
    echo "[+] ISC DHCP Server installed (Disabled by default for safety)"
    
    # 6. Install iperf3 (To simulate specific attack traffic for RST Injection to kill)
    sudo apt-get install -y iperf3
    
    # 7. Enable Broadcast Pings (For Smurf Attack to work efficiently)
    # By default, Linux ignores broadcast ICMP. We enable it to be a "willing victim".
    sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0
    echo "net.ipv4.icmp_echo_ignore_broadcasts=0" | sudo tee -a /etc/sysctl.conf
    
    echo "=== VICTIM SETUP COMPLETE ==="
    echo "IP Address: $(hostname -I)"
    echo "Ensure firewall allows ports 22, 80, 443"
fi
