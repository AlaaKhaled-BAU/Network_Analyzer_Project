"""
Sender - Continuously monitors for new CSV files and uploads to server
Runs as separate process from sniffer.py
"""

import os
import csv
import json
import requests
import logging
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict

# --- Configure Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- Configuration ---
SCRIPT_DIR = Path(__file__).parent
LOGS_DIR = SCRIPT_DIR / 'logs'
PENDING_DIR = LOGS_DIR / 'pending_upload'  # Watch this folder
FAILED_DIR = LOGS_DIR / 'failed_uploads'   # Move failed files here
PROCESSED_DIR = LOGS_DIR / 'processed'     # Move successful uploads here

# Create directories
PENDING_DIR.mkdir(parents=True, exist_ok=True)
FAILED_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# Server configuration
SERVER_URL = "http://26.178.118.134:8000/ingest_packets"
POLL_INTERVAL = 1  # Check for new files every 1 second
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds
BATCH_SIZE = 500  # Upload up to 500 packets per request

# --- Helper Functions ---
def read_csv_file(csv_path: Path) -> List[Dict]:
    """Read CSV file and return list of packet dictionaries"""
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            packets = list(reader)
        
        # Convert string booleans and numbers to proper types
        for packet in packets:
            for key, value in packet.items():
                if value == 'True':
                    packet[key] = True
                elif value == 'False':
                    packet[key] = False
                elif value == 'None' or value == '':
                    packet[key] = None
                elif key in ['length', 'src_port', 'dst_port', 'seq', 'ack', 
                            'icmp_type', 'icmp_code', 'arp_op', 'dns_qtype', 
                            'dns_answer_count', 'dns_answer_size']:
                    try:
                        packet[key] = int(value) if value else None
                    except:
                        pass
                elif key == 'timestamp':
                    try:
                        packet[key] = float(value)
                    except:
                        pass
        
        return packets
    
    except Exception as e:
        logger.error(f"Error reading CSV {csv_path}: {e}")
        return []

def upload_packets(packets: List[Dict], retry_count: int = 0) -> bool:
    """Upload packets to server via HTTP POST"""
    try:
        response = requests.post(
            SERVER_URL,
            json=packets,
            timeout=30,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            logger.info(f"✓ Successfully uploaded {len(packets)} packets")
            return True
        else:
            logger.error(f"Server returned {response.status_code}: {response.text}")
            return False
            
    except requests.exceptions.ConnectionError:
        logger.error(f"Connection error (attempt {retry_count + 1}/{MAX_RETRIES})")
        return False
    except requests.exceptions.Timeout:
        logger.error(f"Request timeout (attempt {retry_count + 1}/{MAX_RETRIES})")
        return False
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return False

def upload_with_retry(packets: List[Dict]) -> bool:
    """Try to upload with exponential backoff"""
    for attempt in range(MAX_RETRIES):
        if upload_packets(packets, retry_count=attempt):
            return True
        
        if attempt < MAX_RETRIES - 1:
            delay = RETRY_DELAY * (2 ** attempt)  # Exponential backoff
            logger.info(f"Retrying in {delay} seconds...")
            time.sleep(delay)
    
    return False

def process_csv_file(csv_path: Path) -> bool:
    """Process a single CSV file"""
    ready_marker = csv_path.with_suffix('.csv.ready')
    
    # Check if file has .ready marker
    if not ready_marker.exists():
        return False
    
    logger.info(f"Processing {csv_path.name}...")
    
    # Read packets from CSV
    packets = read_csv_file(csv_path)
    
    if not packets:
        logger.warning(f"No packets in {csv_path.name}, skipping")
        # Remove empty file
        csv_path.unlink()
        ready_marker.unlink()
        return True
    
    # Upload packets (in batches if large file)
    success = True
    total_packets = len(packets)
    
    for i in range(0, total_packets, BATCH_SIZE):
        batch = packets[i:i + BATCH_SIZE]
        logger.info(f"Uploading batch {i//BATCH_SIZE + 1} ({len(batch)} packets)...")
        
        if not upload_with_retry(batch):
            success = False
            break
    
    if success:
        # Move to processed directory
        processed_path = PROCESSED_DIR / csv_path.name
        csv_path.rename(processed_path)
        ready_marker.unlink()
        logger.info(f"✓ {csv_path.name} processed successfully ({total_packets} packets)")
    else:
        # Move to failed directory
        failed_path = FAILED_DIR / csv_path.name
        csv_path.rename(failed_path)
        ready_marker.unlink()
        logger.warning(f"✗ {csv_path.name} moved to failed_uploads/")
    
    return success

def retry_failed_uploads():
    """Retry previously failed uploads"""
    failed_files = list(FAILED_DIR.glob('packets_*.csv'))
    
    if not failed_files:
        return
    
    logger.info(f"Found {len(failed_files)} failed uploads, retrying...")
    
    for failed_file in failed_files:
        logger.info(f"Retrying {failed_file.name}...")
        
        # Read and upload
        packets = read_csv_file(failed_file)
        if packets and upload_with_retry(packets):
            # Move to processed
            processed_path = PROCESSED_DIR / failed_file.name
            failed_file.rename(processed_path)
            logger.info(f"✓ Retry successful for {failed_file.name}")
        else:
            logger.warning(f"✗ Retry failed for {failed_file.name}")
        
        time.sleep(1)  # Brief pause between retries

def monitor_and_upload():
    """Main loop - monitor for new files and upload"""
    logger.info("Sender started - monitoring for new files...")
    logger.info(f"Watching: {PENDING_DIR}")
    logger.info(f"Server: {SERVER_URL}")
    logger.info(f"Poll interval: {POLL_INTERVAL} seconds")
    
    # Initial retry of failed uploads
    retry_failed_uploads()
    
    last_retry_check = datetime.now()
    
    while True:
        try:
            # Find CSV files with .ready markers
            csv_files = []
            for ready_file in PENDING_DIR.glob('*.ready'):
                csv_file = ready_file.with_suffix('')  # Remove .ready extension
                if csv_file.exists() and csv_file.suffix == '.csv':
                    csv_files.append(csv_file)
            
            # Process files in chronological order
            csv_files.sort()
            
            for csv_file in csv_files:
                process_csv_file(csv_file)
            
            # Periodically retry failed uploads (every 5 minutes)
            if (datetime.now() - last_retry_check).total_seconds() > 300:
                retry_failed_uploads()
                last_retry_check = datetime.now()
            
            # Wait before next check
            time.sleep(POLL_INTERVAL)
            
        except KeyboardInterrupt:
            logger.info("Sender stopped by user")
            break
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            time.sleep(POLL_INTERVAL)

def main():
    """Entry point"""
    logger.info("=" * 60)
    logger.info("Network Traffic Analyzer - Sender")
    logger.info("=" * 60)
    
    # Check if sniffer is generating files
    if not PENDING_DIR.exists():
        logger.warning(f"Directory {PENDING_DIR} doesn't exist!")
        logger.warning("Make sure sniffer.py is running first.")
    
    # Start monitoring
    monitor_and_upload()

if __name__ == "__main__":
    main()
