#!/bin/bash

# Integration Test for Phase B: Latency Reduction
# 1. Start Server
# 2. Send Test Packet
# 3. Verify Inline Prediction Log

echo "🚀 Starting Integration Test..."

# Kill any existing server
pkill -f "uvicorn" || true
sleep 1

# Start Server in background
cd /media/alaa/data/UNI/Network_Analyzer_Project
source venv/bin/activate || true
export PYTHONPATH=$PYTHONPATH:$(pwd)
nohup python3 server/app/main.py > server.log 2>&1 &
SERVER_PID=$!
echo "📡 Server started with PID $SERVER_PID"

# Wait for server to be ready
echo "⏳ Waiting for server startup..."
for i in {1..30}; do
    if grep -q "Application startup complete" server.log; then
        echo "✅ Server is ready!"
        break
    fi
    sleep 1
done

# Send a simulated packet via curl to /ingest (fastest way to test ingestion pipeline)
# MUST include all boolean fields to avoid KeyError in aggregator
echo "📤 Sending test packet..."
curl -X POST "http://127.0.0.1:8000/ingest" \
     -H "Content-Type: application/json" \
     -d '[{
        "timestamp": '$(date +%s)',
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8",
        "protocol": "TCP",
        "length": 100,
        "src_port": 12345,
        "dst_port": 80,
        "tcp_flags": "S",
        "tcp_syn": true,
        "tcp_ack": false,
        "tcp_fin": false,
        "tcp_rst": false,
        "tcp_psh": false,
        "dns_query": false,
        "dns_response": false,
        "arp_op": 0
     }]'

# Check logs for "Inline predictions"
echo "🔍 Checking logs for inline prediction..."
sleep 5 # processing time should be <2s now, but give it 5s to be safe

if grep -q "🚀 Inline predictions" server.log; then
    echo "✅ SUCCESS: Inline prediction detected in logs!"
    grep "🚀 Inline predictions" server.log
else
    echo "❌ FAILURE: Inline prediction NOT found in logs."
    echo "Last 20 lines of server.log:"
    tail -n 20 server.log
fi

# Cleanup
kill $SERVER_PID
echo "🛑 Test finished."
