import pandas as pd
import numpy as np
import tempfile
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.getcwd())

from server.app.MultiWindowAggregator import MultiWindowAggregator

def test_process_dataframe_equivalence():
    agg = MultiWindowAggregator()
    
    # Create sample data
    data = []
    base_ts = 1700000000
    for i in range(20):
        data.append({
            "timestamp": base_ts + i * 0.5,
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "protocol": "TCP",
            "length": 64 + i,
            "src_port": 12345,
            "dst_port": 80,
            "tcp_syn": True if i % 2 == 0 else False,
            "tcp_ack": False,
            "dns_query": False,
            "attack_label": "Normal"
        })
    
    df = pd.DataFrame(data)
    
    # 1. Process via file (old way)
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode='w', newline='') as tmp:
        df.to_csv(tmp.name, index=False)
        tmp_path = tmp.name
        
    try:
        res_file = agg.process_file(tmp_path, window_sizes=[5])
    finally:
        os.remove(tmp_path)
        
    # 2. Process via DataFrame (new way)
    res_df = agg.process_dataframe(df.copy(), window_sizes=[5])
    
    # Compare
    print(f"File result shape: {res_file.shape}")
    print(f"DataFrame result shape: {res_df.shape}")
    
    assert len(res_file) == len(res_df), f"Row count mismatch: {len(res_file)} vs {len(res_df)}"
    
    # Sort just in case
    res_file = res_file.sort_values(["window_start", "window_size"]).reset_index(drop=True)
    res_df = res_df.sort_values(["window_start", "window_size"]).reset_index(drop=True)
    
    # Check numeric columns
    numeric_cols = res_file.select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        # Allow tiny float differences
        diff = (res_file[col] - res_df[col]).abs().max()
        if diff > 1e-9:
             print(f"❌ Column {col} mismatch! Max diff: {diff}")
             print(res_file[col].head())
             print(res_df[col].head())
             sys.exit(1)
             
    print("✅ process_dataframe() matches process_file() exactly!")

if __name__ == "__main__":
    test_process_dataframe_equivalence()
