import grpc
import time
import json
import os
import glob
import logging
import sys

# Add parent dir to path to import proto modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import packet_pb2
import packet_pb2_grpc

# Configuration
SERVER_ADDRESS = 'localhost:50051'
LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
PENDING_DIR = os.path.join(LOGS_DIR, 'pending_upload')

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - Sender - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_packet_stream(files):
    """
    Generator function that yields Packet messages.
    Reads/processes files one by one.
    """
    for filepath in files:
        try:
            logger.info(f"Processing {os.path.basename(filepath)}...")
            with open(filepath, 'r') as f:
                data = json.load(f)
                
            # If plain list
            packets = data if isinstance(data, list) else []
            
            for p in packets:
                interface_val = str(p.get('interface', ''))
                
                yield packet_pb2.Packet(
                    timestamp=float(p.get('timestamp', 0)),
                    interface=interface_val,
                    src_ip=str(p.get('src_ip', '') or ''),
                    dst_ip=str(p.get('dst_ip', '') or ''),
                    protocol=str(p.get('protocol', '') or ''),
                    length=int(p.get('length', 0)),
                    src_port=int(p.get('src_port') or 0),
                    dst_port=int(p.get('dst_port') or 0),
                    tcp_flags=str(p.get('tcp_flags', '') or ''),
                    
                    # Optional bools
                    tcp_syn=bool(p.get('tcp_syn', False)),
                    tcp_ack=bool(p.get('tcp_ack', False)),
                    tcp_fin=bool(p.get('tcp_fin', False)),
                    tcp_rst=bool(p.get('tcp_rst', False)),
                    tcp_psh=bool(p.get('tcp_psh', False)),
                    
                    # Add others as needed
                )
            
            # Delete file after successful yield (processed by stream)
            # Note: In a real stream failure, we might want to keep the file.
            # But here we yield the object. The sending happens when 'yield' is consumed.
            # So actual deletion should strictly verify sending success.
            # For simplicity in this demo, we mark for deletion in the outer loop or here.
            
        except Exception as e:
            logger.error(f"Error reading file {filepath}: {e}")

def run():
    while True:
        try:
            # Find all .json.ready files
            ready_files = glob.glob(os.path.join(PENDING_DIR, '*.json.ready'))
            if not ready_files:
                time.sleep(1)
                continue
                
            # Get corresponding json files
            files_to_send = []
            for ready_marker in ready_files:
                json_file = ready_marker.replace('.ready', '')
                if os.path.exists(json_file):
                    files_to_send.append(json_file)
            
            if not files_to_send:
                continue

            # Establish connection
            with grpc.insecure_channel(SERVER_ADDRESS) as channel:
                stub = packet_pb2_grpc.IngestServiceStub(channel)
                
                # Create the stream generator
                packet_iterator = generate_packet_stream(files_to_send)
                
                # Call the streaming RPC
                response = stub.StreamPackets(packet_iterator)
                
                logger.info(f"Sent batch. Server received: {response.received_count} packets. Status: {response.status}")
                
                # Cleanup files upon success
                if response.status == "OK":
                    for f in files_to_send:
                        try:
                            if os.path.exists(f): os.remove(f)
                            marker = f + '.ready'
                            if os.path.exists(marker): os.remove(marker)
                        except Exception as e:
                            logger.error(f"Cleanup error: {e}")
                            
        except Exception as e:
            logger.error(f"Sender Loop Error: {e}")
            time.sleep(5)

if __name__ == '__main__':
    logger.info(f"gRPC Sender starting. Monitoring {PENDING_DIR}")
    run()
