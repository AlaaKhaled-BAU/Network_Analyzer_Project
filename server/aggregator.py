"""
Multi-Window Traffic Aggregator
Processes packets at 5-second, 30-second, and 3-minute intervals
Feeds aggregated features to ML prediction service
"""

import os
import sys
import asyncio
import logging
import json
from datetime import datetime, timedelta
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database connection (generic - update with your credentials)
DATABASE_URL = "postgresql://USER:PASSWORD@HOST:PORT/DATABASE"
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

# Import tables from main
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from app.main import (
    raw_packets_table,
    traffic_table,
    predictions_5s_table,
    predictions_30s_table,
    predictions_3min_table
)

session = Session(engine)

# Track processing state
last_processed_ids = {
    '5s': 0,
    '30s': 0,
    '3min': 0
}

# Time windows
WINDOWS = {
    '5s': timedelta(seconds=5),
    '30s': timedelta(seconds=30),
    '3min': timedelta(minutes=3)
}

def get_raw_packets_in_window(time_window):
    """
    Get raw packets from the database within the specified time window
    """
    cutoff_time = datetime.utcnow() - time_window
    
    query = select(raw_packets_table).where(
        raw_packets_table.c.inserted_at >= cutoff_time
    ).order_by(raw_packets_table.c.id)
    
    results = session.execute(query).fetchall()
    
    # Convert to list of dicts
    packets = []
    for row in results:
        packets.append(dict(row._mapping))
    
    return packets

def aggregate_packets_to_flows(packets):
    """
    Aggregate packets into flows based on (src_ip, dst_ip, protocol)
    Returns list of flow dictionaries
    """
    if not packets:
        return []
    
    flows = defaultdict(lambda: {
        'packet_count': 0,
        'byte_count': 0,
        'unique_ports': set(),
        'tcp_flags': set(),
        'connection_attempts': 0,
        'start_time': float('inf'),
        'end_time': 0,
        'src_ip': None,
        'dst_ip': None,
        'protocol': None
    })
    
    for pkt in packets:
        # Flow key
        flow_key = (pkt.get('src_ip'), pkt.get('dst_ip'), pkt.get('protocol'))
        flow = flows[flow_key]
        
        # Basic info
        if flow['src_ip'] is None:
            flow['src_ip'] = pkt.get('src_ip')
            flow['dst_ip'] = pkt.get('dst_ip')
            flow['protocol'] = pkt.get('protocol')
        
        # Packet stats
        flow['packet_count'] +=1
        flow['byte_count'] += pkt.get('length', 0)
        
        # Ports
        if pkt.get('src_port'):
            flow['unique_ports'].add(pkt.get('src_port'))
        if pkt.get('dst_port'):
            flow['unique_ports'].add(pkt.get('dst_port'))
        
        # TCP flags
        if pkt.get('tcp_flags'):
            for flag in str(pkt.get('tcp_flags')).split(','):
                flow['tcp_flags'].add(flag.strip())
        
        # Connection attempts (SYN packets)
        if pkt.get('tcp_syn'):
            flow['connection_attempts'] += 1
        
        # Time range
        if pkt.get('timestamp'):
            flow['start_time'] = min(flow['start_time'], pkt.get('timestamp'))
            flow['end_time'] = max(flow['end_time'], pkt.get('timestamp'))
    
    # Calculate rates and finalize flows
    result_flows = []
    for flow_key, flow in flows.items():
        # Time duration
        duration = flow['end_time'] - flow['start_time']
        if duration == 0:
            duration = 1  # Avoid division by zero
        
        # Rates
        packet_per_sec = flow['packet_count'] / duration
        byte_per_sec = flow['byte_count'] / duration
        
        result_flows.append({
            'dest_ip': flow['dst_ip'],
            'source_mac': 'unknown',  # Not captured in sniffer
            'dest_mac': 'unknown',
           ' packet_count': flow['packet_count'],
            'packet_per_sec': packet_per_sec,
            'byte_count': flow['byte_count'],
            'byte_per_sec': byte_per_sec,
            'tcp_flags': ','.join(flow['tcp_flags']) if flow['tcp_flags'] else '',
            'connection_attempts': flow['connection_attempts'],
            'unique_ports': len(flow['unique_ports']),
            'protocol': flow['protocol'] or 'unknown'
        })
    
    return result_flows

def extract_raw_features(packets):
    """
    Extract features directly from raw packet data
    Used for ML prediction along with aggregated features
    """
    if not packets:
        return {
            'total_packets': 0,
            'unique_src_ips': 0,
            'unique_dst_ips': 0,
            'tcp_count': 0,
            'udp_count': 0,
            'icmp_count': 0,
            'syn_count': 0,
            'avg_packet_size': 0
        }
    
    src_ips = set()
    dst_ips = set()
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    syn_count = 0
    total_bytes = 0
    
    for pkt in packets:
        if pkt.get('src_ip'):
            src_ips.add(pkt.get('src_ip'))
        if pkt.get('dst_ip'):
            dst_ips.add(pkt.get('dst_ip'))
        
        protocol = pkt.get('protocol', '').upper()
        if protocol == 'TCP':
            tcp_count += 1
        elif protocol == 'UDP':
            udp_count += 1
        elif 'ICMP' in protocol:
            icmp_count += 1
        
        if pkt.get('tcp_syn'):
            syn_count += 1
        
        total_bytes += pkt.get('length', 0)
    
    return {
        'total_packets': len(packets),
        'unique_src_ips': len(src_ips),
        'unique_dst_ips': len(dst_ips),
        'tcp_count': tcp_count,
        'udp_count': udp_count,
        'icmp_count': icmp_count,
        'syn_count': syn_count,
        'avg_packet_size': total_bytes / len(packets) if packets else 0
    }

def extract_flow_features(flows):
    """
    Extract features from aggregated flows
    """
    if not flows:
        return {
            'flow_count': 0,
            'avg_packet_rate': 0,
            'avg_byte_rate': 0,
            'max_packet_rate': 0,
            'max_byte_rate': 0,
            'total_unique_ports': 0
        }
    
    packet_rates = [f['packet_per_sec'] for f in flows]
    byte_rates = [f['byte_per_sec'] for f in flows]
    all_ports = sum([f['unique_ports'] for f in flows])
    
    return {
        'flow_count': len(flows),
        'avg_packet_rate': sum(packet_rates) / len(packet_rates),
        'avg_byte_rate': sum(byte_rates) / len(byte_rates),
        'max_packet_rate': max(packet_rates) if packet_rates else 0,
        'max_byte_rate': max(byte_rates) if byte_rates else 0,
        'total_unique_ports': all_ports
    }

def store_aggregated_flows(flows):
    """
    Store aggregated flows in traffic_data table
    ML prediction service will pick these up
    """
    for flow in flows:
        ins = traffic_table.insert().values(**flow)
        session.execute(ins)
    
    session.commit()
    logger.info(f"Stored {len(flows)} aggregated flows in traffic_data")

def store_window_features(window_name, table, window_start, window_end, raw_features, flow_features):
    """
    Store combined features for ML prediction
    ML service (ml_predictor.py) will read this and add predictions
    """
    combined_features = {**raw_features, **flow_features}
    
    ins = table.insert().values(
        window_start=window_start,
        window_end=window_end,
        total_packets=raw_features['total_packets'],
        unique_src_ips=raw_features['unique_src_ips'],
        unique_dst_ips=raw_features['unique_dst_ips'],
        flow_count=flow_features['flow_count'],
        avg_packet_rate=flow_features['avg_packet_rate'],
        avg_byte_rate=flow_features['avg_byte_rate'],
        predicted_label='pending',  # ML service will update this
        confidence=None,  # ML service will update this
        features_json=json.dumps(combined_features)
    )
    
    session.execute(ins)
    session.commit()
    logger.info(f"Stored {window_name} window features (pending ML prediction)")

async def process_5s_window():
    """
    Process 5-second window from raw packets
    This is the base window - all others build from this
    """
    window_end = datetime.utcnow()
    window_start = window_end - WINDOWS['5s']
    
    logger.info(f"Processing 5s window: {window_start} to {window_end}")
    
    # 1. Get raw packets
    packets = get_raw_packets_in_window(WINDOWS['5s'])
    
    if not packets:
        logger.info(f"No packets in 5s window")
        return
    
    logger.info(f"Found {len(packets)} packets in 5s window")
    
    # 2. Aggregate into flows
    flows = aggregate_packets_to_flows(packets)
    logger.info(f"Aggregated into {len(flows)} flows")
    
    # 3. Store flows in traffic_data (for ML service)
    store_aggregated_flows(flows)
    
    # 4. Extract raw features
    raw_features = extract_raw_features(packets)
    
    # 5. Extract flow features
    flow_features = extract_flow_features(flows)
    
    # 6. Store combined features (ML service will add predictions)
    store_window_features('5s', predictions_5s_table, window_start, window_end, raw_features, flow_features)

def aggregate_5s_predictions(count):
    """
    Aggregate multiple 5-second predictions into a larger window
    
    Args:
        count: Number of 5s windows to aggregate (6 for 30s, 36 for 3min)
    
    Returns:
        Aggregated features dictionary
    """
    # Query last N entries from predictions_5s
    query = select(predictions_5s_table).order_by(
        predictions_5s_table.c.created_at.desc()
    ).limit(count)
    
    results = session.execute(query).fetchall()
    
    if not results or len(results) < count:
        logger.warning(f"Not enough 5s predictions (found {len(results)}, need {count})")
        return None
    
    # Aggregate the features
    total_packets = sum(r.total_packets for r in results)
    unique_src_ips = len(set())  # Would need to parse features_json for exact count
    unique_dst_ips = len(set())  # Would need to parse features_json for exact count
    total_flows = sum(r.flow_count for r in results)
    avg_packet_rate = sum(r.avg_packet_rate for r in results) / len(results)
    avg_byte_rate = sum(r.avg_byte_rate for r in results) / len(results)
    
    # Parse features_json to get more accurate unique counts
    all_src_ips = set()
    all_dst_ips = set()
    
    for r in results:
        if r.features_json:
            try:
                features = json.loads(r.features_json)
                # We'd need to store IP lists in features_json for this
                # For now, use max as approximation
                if not all_src_ips:
                    all_src_ips.add(r.unique_src_ips)
                if not all_dst_ips:
                    all_dst_ips.add(r.unique_dst_ips)
            except:
                pass
    
    unique_src_ips = max((r.unique_src_ips for r in results), default=0)
    unique_dst_ips = max((r.unique_dst_ips for r in results), default=0)
    
    # Window time range
    window_start = min(r.window_start for r in results)
    window_end = max(r.window_end for r in results)
    
    return {
        'window_start': window_start,
        'window_end': window_end,
        'total_packets': total_packets,
        'unique_src_ips': unique_src_ips,
        'unique_dst_ips': unique_dst_ips,
        'flow_count': total_flows,
        'avg_packet_rate': avg_packet_rate,
        'avg_byte_rate': avg_byte_rate
    }

async def process_30s_window():
    """
    Process 30-second window by aggregating 6 × 5s predictions
    Much more efficient than re-querying raw_packets
    """
    logger.info("Processing 30s window (aggregating 6 × 5s predictions)")
    
    # Aggregate last 6 × 5s predictions (= 30 seconds)
    aggregated = aggregate_5s_predictions(count=6)
    
    if not aggregated:
        logger.warning("Cannot process 30s window - insufficient 5s data")
        return
    
    # Store in predictions_30s table
    ins = predictions_30s_table.insert().values(
        window_start=aggregated['window_start'],
        window_end=aggregated['window_end'],
        total_packets=aggregated['total_packets'],
        unique_src_ips=aggregated['unique_src_ips'],
        unique_dst_ips=aggregated['unique_dst_ips'],
        flow_count=aggregated['flow_count'],
        avg_packet_rate=aggregated['avg_packet_rate'],
        avg_byte_rate=aggregated['avg_byte_rate'],
        predicted_label='pending',
        confidence=None,
        features_json=json.dumps(aggregated)
    )
    
    session.execute(ins)
    session.commit()
    logger.info(f"Stored 30s window: {aggregated['total_packets']} packets, {aggregated['flow_count']} flows")

async def process_3min_window():
    """
    Process 3-minute window by aggregating 36 × 5s predictions
    Even more efficient - no raw packet queries at all
    """
    logger.info("Processing 3min window (aggregating 36 × 5s predictions)")
    
    # Aggregate last 36 × 5s predictions (= 180 seconds = 3 minutes)
    aggregated = aggregate_5s_predictions(count=36)
    
    if not aggregated:
        logger.warning("Cannot process 3min window - insufficient 5s data")
        return
    
    # Store in predictions_3min table
    ins = predictions_3min_table.insert().values(
        window_start=aggregated['window_start'],
        window_end=aggregated['window_end'],
        total_packets=aggregated['total_packets'],
        unique_src_ips=aggregated['unique_src_ips'],
        unique_dst_ips=aggregated['unique_dst_ips'],
        flow_count=aggregated['flow_count'],
        avg_packet_rate=aggregated['avg_packet_rate'],
        avg_byte_rate=aggregated['avg_byte_rate'],
        predicted_label='pending',
        confidence=None,
        features_json=json.dumps(aggregated)
    )
    
    session.execute(ins)
    session.commit()
    logger.info(f"Stored 3min window: {aggregated['total_packets']} packets, {aggregated['flow_count']} flows")

async def cleanup_old_raw_packets():
    """
    Clean up raw packets older than 7 days to prevent database bloat
    """
    while True:
        try:
            await asyncio.sleep(3600)  # Run every hour
            
            cutoff_date = datetime.utcnow() - timedelta(days=7)
            
            delete_query = raw_packets_table.delete().where(
                raw_packets_table.c.inserted_at < cutoff_date
            )
            
            result = session.execute(delete_query)
            session.commit()
            
            if result.rowcount > 0:
                logger.info(f"Cleaned up {result.rowcount} old raw packets (>7 days)")
        
        except Exception as e:
            logger.error(f"Error in cleanup: {e}")
            session.rollback()

async def run_aggregation_loop():
    """
    Main aggregation loop
    - Every 5 seconds: Process 5s window from raw_packets
    - Every 30 seconds: Aggregate 6 × 5s predictions
    - Every 3 minutes: Aggregate 36 × 5s predictions
    """
    logger.info("Multi-Window Aggregator started")
    logger.info("Processing windows: 5s (from raw), 30s (from 5s), 3min (from 5s)")
    
    iteration = 0
    
    while True:
        try:
            iteration += 1
            
            # Always process 5-second window from raw packets
            await process_5s_window()
            
            # Every 6th iteration (30 seconds), aggregate from 5s predictions
            if iteration % 6 == 0:
                await process_30s_window()
            
            # Every 36th iteration (3 minutes), aggregate from 5s predictions
            if iteration % 36 == 0:
                await process_3min_window()
            
            # Wait 5 seconds before next cycle
            await asyncio.sleep(5)
        
        except Exception as e:
            logger.error(f"Error in aggregation loop: {e}")
            session.rollback()
            await asyncio.sleep(5)

async def main():
    """Main entry point"""
    logger.info("=" * 60)
    logger.info("Multi-Window Traffic Aggregator")
    logger.info("=" * 60)
    logger.info(f"Database: {DATABASE_URL}")
    logger.info("=" * 60)
    
    # Run aggregation and cleanup concurrently
    await asyncio.gather(
        run_aggregation_loop(),
        cleanup_old_raw_packets()
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Aggregator stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
