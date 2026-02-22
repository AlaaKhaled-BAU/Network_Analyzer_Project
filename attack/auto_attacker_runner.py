import json
import logging
import time
import requests
import argparse
import sys
import random
from concurrent.futures import ThreadPoolExecutor
import urllib3

# Import dynamic attack generator
from attack_core import *

# Suppress annoying InsecureRequest warnings if running HTTPS (we use HTTP here mostly though)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('Auto_Attacker')

class AutoAttacker:
    def __init__(self, config_path="attack_config.json", target_api_url="http://127.0.0.1:9999"):
        self.config_path = config_path
        self.target_api_url = target_api_url.rstrip('/')
        self.config = self._load_config()
        self.active_threads = []
        
    def _load_config(self):
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config {self.config_path}: {e}")
            sys.exit(1)
            
    def _trigger_target_start(self, label, duration, attacker_ip):
        """Tell the VM to start sniffing and labeling"""
        payload = {
            "label": label,
            "duration": duration,
            "attacker_ip": attacker_ip
        }
        try:
            resp = requests.post(f"{self.target_api_url}/start", json=payload, timeout=5)
            if resp.status_code == 200:
                logger.info(f"[C2 -> VM] Requested capture start for '{label}'")
                return True
            else:
                logger.error(f"VM rejected start request: {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Could not reach VM API at {self.target_api_url}: {e}")
            return False

    def _trigger_target_stop(self):
        """Force the VM to stop capture and flush CSV"""
        try:
            resp = requests.post(f"{self.target_api_url}/stop", timeout=10)
            if resp.status_code == 200:
                logger.info("[C2 -> VM] Requested capture stop & flush.")
                return True
            else:
                logger.error(f"VM rejected stop request: {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Could not stop VM Capture: {e}")
            return False

    def get_my_ip(self):
        # Hacky way to get the local IP routing outward
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            s.connect(('10.254.254.254', 1))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'

    def execute_variation(self, attack_type, variation, global_target):
        """Runs a single attack variation"""
        intensity = variation.get("intensity", 100)
        delay = variation.get("delay", 0.0)
        duration = variation.get("duration", 60)
        
        # Determine port
        port = variation.get("port")
        if not port:
            port = random.choice(variation.get("ports", [80])) if "ports" in variation else 80
            
        variation_desc = variation.get("description", "Unknown Variation")
        logger.info(f"==== 🚀 STARTING: {attack_type} ({variation_desc}) ====")
        
        # 1. Inform VM to start capturing (with retry)
        attacker_ip = self.get_my_ip()
        sync_success = False
        for attempt in range(3):
            sync_success = self._trigger_target_start(attack_type, duration, attacker_ip)
            if sync_success:
                break
            logger.warning(f"VM sync attempt {attempt+1}/3 failed. Retrying in {2 ** attempt}s...")
            time.sleep(2 ** attempt)
        
        if not sync_success:
            logger.error("Skipping attack after 3 failed VM sync attempts.")
            return
            
        # Give sniffer exactly 2 seconds to initialize threads on VM
        time.sleep(2)
        
        # 2. Fire the attack logic
        logger.info(f"Firing attack against {global_target}:{port} for {duration} seconds...")
        
        # Reset the global stop event defined in attack_core
        stop_event.clear()
        
        # Extract specific parameters safely for specialized attacks
        users = variation.get("users", ["admin", "root"])
        passwords = variation.get("passwords", ["password", "123456"])
        connections = variation.get("connections", 150)
        qps = variation.get("qps", 10)
        dns_server = variation.get("dns_server", "8.8.8.8")
        
        # Dispatch to correct function in attack_core.py
        func_map = {
            "syn_flood": lambda: syn_flood_impl(global_target, port, intensity, delay, duration, attack_type),
            "udp_flood": lambda: udp_flood_impl(global_target, port, intensity, delay, duration, attack_type),
            "icmp_flood": lambda: icmp_flood_impl(global_target, intensity, delay, duration, attack_type),
            "port_scan": lambda: port_scan_impl(global_target, variation.get("ports", "1-1024"), delay, duration, attack_type),
            "dns_tunnel": lambda: dns_tunnel_impl(global_target, dns_server, qps, duration, attack_type, variation.get("mirror_to"), variation.get("mirror_mac"), variation.get("preserve_dst", False)),
            "slowloris": lambda: slowloris_impl(global_target, port, connections, duration, attack_type),
            "ssh_brute_force": lambda: ssh_brute_force_impl(global_target, port, users, passwords, delay, duration, attack_type),
            # L2 and Edge cases
            "dhcp_starvation": lambda: dhcp_starvation_impl(global_target, intensity, delay, duration, attack_type),
            "tcp_rst_injection": lambda: tcp_rst_impl(global_target, port, intensity, delay, duration, attack_type),
            "icmp_redirect": lambda: icmp_redirect_impl(global_target, variation.get("gateway_ip", "192.168.1.1"), intensity, delay, duration, attack_type),
            "cam_overflow": lambda: cam_overflow_impl(global_target, intensity, delay, duration, attack_type),
            "smurf": lambda: smurf_impl(global_target, variation.get("broadcast_ip", "255.255.255.255"), intensity, delay, duration, attack_type),
            "land_attack": lambda: land_impl(global_target, port, intensity, delay, duration, attack_type),
            "arp_spoof": lambda: arp_spoof_impl(global_target, variation.get("fake_mac", "00:11:22:33:44:55"), intensity, duration, attack_type, fake_mac2=variation.get("fake_mac2"), mac_switch_delay=variation.get("mac_switch_delay", 0))
        }
        
        attack_func = func_map.get(attack_type)
        if not attack_func:
            logger.error(f"Unknown attack type in config: {attack_type}")
            return
            
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(attack_func)
            
            # Wait for strict duration
            time.sleep(duration)
            
            # 3. Stop Attack
            logger.info("Stopping attack generator...")
            stop_event.set()
            # Ensure thread exits
            try:
                future.result(timeout=5)
            except Exception as e:
                logger.warning(f"Generator thread forceful termination: {e}")
                
        # 4. Stop VM Capture explicitly to force CSV flush
        self._trigger_target_stop()

        logger.info(f"==== 🏁 FINISHED: {attack_type} ====\n")

    def run_all(self):
        global_target = self.config.get("target", "127.0.0.1")
        cooldown = self.config.get("cooldown_period", 10)
        
        logger.info("=" * 60)
        logger.info("🤖 FULL AUTOMATION PROTOCOL INITIATED")
        logger.info(f"Targeting: {global_target}")
        logger.info(f"VM API: {self.target_api_url}")
        logger.info("=" * 60)
        
        # Find all active attacks in json
        for attack_type, attack_category in self.config.get("attacks", {}).items():
            if attack_category.get("enabled", True):
                
                for variation in attack_category.get("variations", []):
                    # Execute
                    self.execute_variation(attack_type, variation, global_target)
                    
                    # Inter-attack cooldown
                    logger.info(f"Cooling down for {cooldown} seconds...")
                    time.sleep(cooldown)
                    
        logger.info("✅ ALL CONFIGURED ATTACKS FULLY EXECUTED & DATASETS GENERATED!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Automated Host Attack Runner')
    parser.add_argument('-c', '--config', type=str, default='attack_config.json', help='Attack Config JSON')
    parser.add_argument('-t', '--target-api', type=str, required=True, help='URL of the VM API (e.g. http://192.168.1.100:9999)')
    args = parser.parse_args()
    
    runner = AutoAttacker(config_path=args.config, target_api_url=args.target_api)
    runner.run_all()
