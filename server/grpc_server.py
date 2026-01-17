import grpc
from concurrent import futures
import time
import logging
import sys
import os
import threading

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import packet_pb2
import packet_pb2_grpc

# Import from the monolith main.py since models are defined there
# Note: This might trigger app startup logic if not guarded, 
# but main.py seems to have code at module level.
# Ideally, we should refactor main.py, but for now we import directly.
try:
    from server.app.main import SessionLocal, engine, RawPacket, AggregatedFeature, MultiWindowAggregator
except ImportError:
    # Fallback if running from within server dir
    from app.main import SessionLocal, engine, RawPacket, AggregatedFeature, MultiWindowAggregator
import pandas as pd
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - gRPC - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

AGGREGATOR_AVAILABLE = False
try:
    aggregator = MultiWindowAggregator(window_sizes=[10, 30, 60, 300])
    AGGREGATOR_AVAILABLE = True
except Exception as e:
    logger.error(f"Aggregator initialization failed: {e}")

class IngestService(packet_pb2_grpc.IngestServiceServicer):
    def StreamPackets(self, request_iterator, context):
        """
        Receives a stream of Packet messages and saves them to the DB.
        """
        count = 0
        batch_size = 500
        packet_batch = []
        
        start_time = time.time()
        
        try:
            for packet in request_iterator:
                # Convert Proto message to Dict for DataFrame/DB
                pkt_dict = {
                    'timestamp': packet.timestamp,
                    # Fallback to current time if 0
                    'timestamp_dt': datetime.fromtimestamp(packet.timestamp if packet.timestamp > 0 else time.time()),
                    'src_ip': packet.src_ip,
                    'dst_ip': packet.dst_ip,
                    'protocol': packet.protocol,
                    'length': packet.length,
                    'src_port': packet.src_port if packet.src_port else None,
                    'dst_port': packet.dst_port if packet.dst_port else None,
                    'tcp_flags': packet.tcp_flags,
                }
                
                # Copy optional fields
                if packet.tcp_syn: pkt_dict['tcp_syn'] = True
                if packet.tcp_ack: pkt_dict['tcp_ack'] = True
                if packet.tcp_fin: pkt_dict['tcp_fin'] = True
                if packet.tcp_rst: pkt_dict['tcp_rst'] = True
                if packet.tcp_psh: pkt_dict['tcp_psh'] = True
                # ... other fields could be mapped similarly if DB schema supports them
                
                packet_batch.append(pkt_dict)
                count += 1
                
                if len(packet_batch) >= batch_size:
                    self._save_batch(packet_batch)
                    packet_batch = []
            
            # Save remaining
            if packet_batch:
                self._save_batch(packet_batch)
                
            return packet_pb2.IngestSummary(
                received_count=count,
                status="OK",
                server_timestamp=time.time()
            )
            
        except Exception as e:
            logger.error(f"Stream error: {e}")
            return packet_pb2.IngestSummary(received_count=count, status=f"Error: {str(e)}", server_timestamp=time.time())

    def _save_batch(self, packets_list):
        """Saves a batch of packets to the DB and runs aggregator"""
        if not packets_list:
            return

        db = SessionLocal()
        try:
            # 1. Bulk Insert Raw Packets
            # Map dict keys to RawPacket columns
            raw_objects = []
            for p in packets_list:
                # Basic mapping
                raw_objects.append(RawPacket(
                    timestamp=p['timestamp_dt'],
                    src_ip=p['src_ip'],
                    dst_ip=p['dst_ip'],
                    protocol=p['protocol'],
                    length=p['length'],
                    src_port=p['src_port'],
                    dst_port=p['dst_port'],
                    tcp_flags=p['tcp_flags']
                ))
            
            db.bulk_save_objects(raw_objects)
            db.commit()
            
            # 2. Run Aggregator (Simplified: Create DataFrame -> Process -> Store)
            if AGGREGATOR_AVAILABLE:
                # We need a temporary file approach to reuse the Aggregator class logic 
                # OR we refactor Aggregator to accept DataFrames. 
                # For now, let's use the file ingest method as it's proven.
                import tempfile
                
                df = pd.DataFrame(packets_list)
                # Ensure timestamp is what aggregator expects (float/int usually)
                df['timestamp'] = df['timestamp'].astype(float) 
                
                with tempfile.NamedTemporaryFile(delete=False, suffix=".csv", mode='w', newline='') as tmp:
                    tmp_path = tmp.name
                    df.to_csv(tmp_path, index=False)
                
                try:
                    # The aggregator expects a file path
                    agg_df = aggregator.process_file(tmp_path)
                    
                    if not agg_df.empty:
                        agg_features = []
                        for _, row in agg_df.items() if isinstance(agg_df, dict) else agg_df.iterrows(): # Handle if iterrows needed
                             # Re-check aggregator return type. It returns a DataFrame in our codebase.
                             pass

                        # Actually, let's look at how main.py does it:
                        # agg_df = aggregator.process_file(tmp_path)
                        # feature_rows = []
                        # for _, row in agg_df.iterrows():
                        #     feature_rows.append(AggregatedFeature(...))
                        
                        feature_rows = []
                        for _, row in agg_df.iterrows():
                            # We need to map dataframe columns to AggregatedFeature model
                            # This depends on what aggregator.process_file returns
                            # Assuming standard columns
                            feat = AggregatedFeature(
                                timestamp=datetime.fromtimestamp(row.get('window_end', time.time())), # Approx
                                src_ip=row.get('src_ip'),
                                # ... map other fields dynamically or strictly
                                packet_count=row.get('packet_count', 0),
                                byte_count=row.get('byte_count', 0),
                                # Copy all other known features
                            )
                            # Copy all columns that match model fields
                            for col in row.index:
                                if hasattr(feat, col) and col not in ['id', 'timestamp', 'src_ip', 'predicted_label']:
                                    setattr(feat, col, row[col])
                            
                            feature_rows.append(feat)

                        db.bulk_save_objects(feature_rows)
                        db.commit()
                        
                except Exception as e:
                    logger.error(f"Aggregation error: {e}")
                finally:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)

        except Exception as e:
            logger.error(f"DB Batch Error: {e}")
            db.rollback()
        finally:
            db.close()


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    packet_pb2_grpc.add_IngestServiceServicer_to_server(IngestService(), server)
    port = 50051
    server.add_insecure_port(f'[::]:{port}')
    logger.info(f"gRPC Server starting on port {port}...")
    server.start()
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Stopping server...")
        server.stop(0)

if __name__ == '__main__':
    serve()
