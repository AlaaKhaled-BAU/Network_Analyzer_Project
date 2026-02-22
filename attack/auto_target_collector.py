import argparse
import json
import logging
import os
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Import the precise sniffing/labeling engine we just perfected
try:
    from dataset_capture_gui import PacketSniffer, SCAPY_AVAILABLE
except ImportError:
    print("ERROR: Must be run from the 'attack' directory alongside dataset_capture_gui.py")
    exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('API_Collector')

# Global Sniffer Instance
current_sniffer = None
sniffer_lock = threading.Lock()

class CollectorAPIHandler(BaseHTTPRequestHandler):
    
    def _send_response(self, code, data):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_POST(self):
        global current_sniffer
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/start':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                req = json.loads(post_data.decode('utf-8'))
                label = req.get('label')
                duration = req.get('duration', 60)
                attacker_ip = req.get('attacker_ip', '')
                
                if not label:
                    return self._send_response(400, {"status": "error", "message": "Missing 'label'"})
                
                with sniffer_lock:
                    if current_sniffer and current_sniffer.running:
                        # Stop existing before starting new
                        current_sniffer.stop()
                        time.sleep(1)
                    
                    logger.info(f"STARTING CAPTURE: Label={label} | Duration={duration}s | IP={attacker_ip}")
                    
                    # Create new instance (preserves accurate states/buffers)
                    current_sniffer = PacketSniffer(callback=lambda msg, lvl: logger.info(f"[Sniffer] {msg}"))
                    
                    # Ensure captures dir exists
                    capture_dir = os.path.join(os.getcwd(), 'captures')
                    os.makedirs(capture_dir, exist_ok=True)
                    
                    # Start capture asynchronously
                    def start_bg():
                        current_sniffer.start(
                            capture_dir=capture_dir,
                            attack_label=label,
                            duration=duration,
                            attacker_ip=attacker_ip
                        )
                    threading.Thread(target=start_bg, daemon=True).start()
                
                return self._send_response(200, {
                    "status": "success", 
                    "message": f"Started capturing {label}"
                })
                
            except Exception as e:
                logger.error(f"Failed to parse request: {e}")
                return self._send_response(400, {"status": "error", "message": str(e)})

        elif parsed_path.path == '/stop':
            with sniffer_lock:
                if current_sniffer and current_sniffer.running:
                    logger.info("STOP command received. Flushing packets to disk...")
                    count = current_sniffer.stop()
                    return self._send_response(200, {
                        "status": "success", 
                        "message": f"Stopped capture. Flushed {count} packets."
                    })
                else:
                    return self._send_response(400, {
                        "status": "error", 
                        "message": "No capture currently running."
                    })
            
        else:
            self._send_response(404, {"status": "error", "message": "Endpoint not found"})

    def log_message(self, format, *args):
        # Suppress noisy HTTP logs, we use standard logging
        pass

def run_server(port=9999):
    if not SCAPY_AVAILABLE:
        logger.error("Scapy is not installed! Cannot run collector.")
        exit(1)
        
    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, CollectorAPIHandler)
    logger.info("=" * 60)
    logger.info(f"🚀 HEADLESS TARGET COLLECTOR API RUNNING")
    logger.info(f"   Listening for C2 commands on port {port}")
    logger.info("   Run this strictly on the Victim VM!")
    logger.info("=" * 60)
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down API...")
        if current_sniffer and current_sniffer.running:
            current_sniffer.stop()
        httpd.server_close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Automated Target Collector API')
    parser.add_argument('-p', '--port', type=int, default=9999, help='API Port (default: 9999)')
    args = parser.parse_args()
    run_server(args.port)
