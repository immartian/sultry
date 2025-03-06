#\!/bin/bash

# Clear any previous logs
rm -f test_server.log test_client.log curl_output.log

echo "=== Starting Sultry SNI Concealment Test ==="
echo "$(date)"

# Make sure go is in the PATH
export PATH=$PATH:/usr/local/go/bin

# Kill any existing processes
echo "Killing any existing Sultry processes..."
pkill -f "sultry.*--mode server" || true
pkill -f "sultry.*--mode client" || true
pkill -f "go run.*--mode server" || true
pkill -f "go run.*--mode client" || true
sleep 1

# Start server with explicit logging
echo "=== Starting server component ==="
cd "$(dirname "$0")"
go run . --mode server > test_server.log 2>&1 &
SERVER_PID=$\!
echo "Server started with PID: $SERVER_PID"

# Give the server time to start
sleep 3

# Check if server is running
if \! ps -p $SERVER_PID > /dev/null; then
    echo "ERROR: Server failed to start\!"
    echo "Server log:"
    cat test_server.log
    exit 1
fi

# Start client with explicit logging
echo "=== Starting client component ==="
go run . --mode client > test_client.log 2>&1 &
CLIENT_PID=$\!
echo "Client started with PID: $CLIENT_PID"

# Give the client time to start
sleep 3

# Check if client is running
if \! ps -p $CLIENT_PID > /dev/null; then
    echo "ERROR: Client failed to start\!"
    echo "Client log:"
    cat test_client.log
    exit 1
fi

# Test connection
echo "=== Making test request ==="
curl -v -x http://127.0.0.1:7008 https://example.com > curl_output.log 2>&1
CURL_EXIT=$?

echo "Curl exit code: $CURL_EXIT"
echo "Curl output (first 20 lines):"
head -n 20 curl_output.log

# Wait longer for logs to be written
sleep 4

# Check server logs for SNI resolution
echo "=== Checking server logs ==="
if grep -q "CREATING CONNECTION TO example.com" test_server.log; then
    echo "✅ SNI CONCEALMENT WORKING: Server received and resolved SNI"
    grep -A 5 "CREATING CONNECTION TO example.com" test_server.log
else
    echo "❌ SNI CONCEALMENT FAILED: Server did not log SNI resolution"
    echo "Last 20 lines of server log:"
    tail -n 20 test_server.log
fi

# Check client logs for OOB usage
echo "=== Checking client logs ==="
if grep -q "SNI concealment" test_client.log; then
    echo "✅ CLIENT USING OOB: Client initiated SNI concealment"
    grep -A 5 "SNI concealment" test_client.log
else
    echo "❌ CLIENT NOT USING OOB: Client did not attempt SNI concealment"
    echo "Last 20 lines of client log:"
    tail -n 20 test_client.log
fi

# Clean up
echo "=== Cleaning up ==="
kill $SERVER_PID $CLIENT_PID 2>/dev/null || true
wait

echo "=== Test complete ==="
echo "Server log: test_server.log"
echo "Client log: test_client.log"
echo "Curl output: curl_output.log"

echo "=== Running manual verification ==="
echo "1. Checking if config has SNI concealment enabled:"
grep -A1 "prioritize_sni_concealment" config.json

echo "2. Server log - looking for SNI resolution patterns:"
grep -i "SNI" test_server.log || echo "No SNI references found in server log"
grep -i "connection" test_server.log | grep -i "example.com" || echo "No matching connections found"

echo "3. Client log - looking for OOB usage:"
grep -i "OOB" test_client.log || echo "No OOB references found in client log"
grep -i "SNI" test_client.log || echo "No SNI references found in client log"

echo "=== Advanced debugging complete ==="
