#!/bin/bash
# Start server in background
echo "Starting server..."
# Kill any existing server on 9999
fuser -k 9999/tcp 2>/dev/null

./venv/bin/python3 -m uvicorn server.app.main:app --host 127.0.0.1 --port 9999 > /tmp/server.log 2>&1 &
PID=$!
echo "Server PID: $PID"
sleep 5

# Check if running
if ! ps -p $PID > /dev/null; then
    echo "❌ Server failed to start"
    cat /tmp/server.log
    exit 1
fi

echo "Server running. Sending test packets to /ingest..."

# Send test packet to ingest
RESPONSE=$(curl -s -X POST http://127.0.0.1:9999/ingest \
  -H "Content-Type: application/json" \
  -d '[
    {"timestamp": '$(date +%s)', "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "protocol": "TCP", "length": 100, "src_port": 111, "dst_port": 80, "tcp_syn": true}
  ]')

echo "Response: $RESPONSE"

# Check for "inline_predictions" in response
if echo "$RESPONSE" | grep -q "inline_predictions"; then
    echo "✅ Inline predictions confirmed in response"
else
    echo "❌ Missing inline_predictions in response"
    cat /tmp/server.log
    kill $PID
    exit 1
fi

# Cleanup
echo "Stopping server..."
kill $PID
