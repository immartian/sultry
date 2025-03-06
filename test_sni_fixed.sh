#\!/bin/bash

# Clear any previous logs
rm -f test_server.log test_client.log curl_output.log

echo "=== Starting SNI Concealment Test with FIXED OOB Module ==="
echo "$(date)"

# Make sure go is in the PATH
export PATH=$PATH:/usr/local/go/bin

# Kill any existing processes
echo "Killing any existing Sultry processes..."
pkill -f "sultry" || true
pkill -f "go run.*--mode" || true
sleep 2

# Verify ports are free
echo "Checking if ports are free..."
if nc -z 127.0.0.1 7008 2>/dev/null; then
    echo "ERROR: Port 7008 is still in use. Exiting."
    exit 1
fi
if nc -z 127.0.0.1 9008 2>/dev/null; then
    echo "ERROR: Port 9008 is still in use. Exiting."
    exit 1
fi

# Start server with explicit logging
echo "=== Starting server component ==="
cd "$(dirname "$0")"
go run . --mode server > test_server.log 2>&1 &
SERVER_PID=$\!
echo "Server started with PID: $SERVER_PID"

# Give the server time to start
sleep 4

# Check if server is running
if \! ps -p $SERVER_PID > /dev/null; then
    echo "ERROR: Server failed to start\!"
    echo "Server log:"
    cat test_server.log
    exit 1
fi

# Verify server is listening on 9008
if \! nc -z 127.0.0.1 9008 2>/dev/null; then
    echo "ERROR: Server not listening on port 9008\!"
    exit 1
else
    echo "✅ Server confirmed listening on port 9008"
fi

# Start client with explicit logging
echo "=== Starting client component ==="
go run . --mode client > test_client.log 2>&1 &
CLIENT_PID=$\!
echo "Client started with PID: $CLIENT_PID"

# Give the client time to start
sleep 4

# Check if client is running
if \! ps -p $CLIENT_PID > /dev/null; then
    echo "ERROR: Client failed to start\!"
    echo "Client log:"
    cat test_client.log
    exit 1
fi

# Verify client is listening on 7008
if \! nc -z 127.0.0.1 7008 2>/dev/null; then
    echo "ERROR: Client not listening on port 7008\!"
    exit 1
else
    echo "✅ Client confirmed listening on port 7008"
fi

# Test connection
echo "=== Making test request ==="
curl -v -x http://127.0.0.1:7008 https://example.com > curl_output.log 2>&1
CURL_EXIT=$?

echo "Curl exit code: $CURL_EXIT"
echo "Curl output (first 20 lines):"
head -n 20 curl_output.log

# Wait longer for logs to be written
sleep 3

# Check if the request was successful
if grep -q "Example Domain" curl_output.log; then
    echo "✅ Request successful: Found 'Example Domain' in response"
else
    echo "❌ Request failed: 'Example Domain' not found in response"
fi

# Check OOB module initialization logs
echo "=== Checking OOB module initialization ==="
if grep -q "OOB Module initialized with active peer" test_client.log; then
    echo "✅ OOB MODULE INITIALIZED: Active peer set during initialization"
    grep -A 1 "OOB Module initialized with active peer" test_client.log
else
    echo "❌ OOB MODULE INITIALIZATION FAILED: No active peer set"
fi

# Check client logs for OOB usage
echo "=== Checking client logs for SNI concealment ==="
if grep -q "SNI CONCEALMENT: Initiating connection" test_client.log; then
    echo "✅ CLIENT ATTEMPTING SNI CONCEALMENT"
    grep -A 5 "SNI CONCEALMENT: Initiating connection" test_client.log
    
    # Check if server address is found
    if grep -q "Using OOB server at [^ ]" test_client.log; then
        echo "✅ OOB SERVER ADDRESS FOUND"
        grep "Using OOB server at" test_client.log
    else
        echo "❌ OOB SERVER ADDRESS EMPTY OR MISSING"
    fi
    
    # Check if SNI resolution request was sent
    if grep -q "Sending SNI resolution request to OOB server" test_client.log; then
        echo "✅ SNI RESOLUTION REQUEST SENT"
    else
        echo "❌ SNI RESOLUTION REQUEST NOT SENT"
    fi
    
    # Check if connection was successful
    if grep -q "SNI CONCEALMENT SUCCESSFUL" test_client.log; then
        echo "✅ SNI CONCEALMENT SUCCESSFUL"
        grep "SNI CONCEALMENT SUCCESSFUL" test_client.log
    else
        echo "❌ SNI CONCEALMENT FAILED OR FELL BACK TO DIRECT CONNECTION"
        grep -A 3 "Falling back to direct connection" test_client.log || echo "No fallback message found"
    fi
else
    echo "❌ CLIENT NOT USING SNI CONCEALMENT"
fi

# Check server logs for SNI resolution
echo "=== Checking server logs for SNI resolution ==="
if grep -q "RECEIVED SNI RESOLUTION REQUEST" test_server.log; then
    echo "✅ SERVER RECEIVED SNI RESOLUTION REQUEST"
    grep -A 10 "RECEIVED SNI RESOLUTION REQUEST" test_server.log
    
    # Check if DNS resolution was successful
    if grep -q "DNS resolution successful" test_server.log; then
        echo "✅ DNS RESOLUTION SUCCESSFUL"
        grep -A 2 "DNS resolution successful" test_server.log
    else
        echo "❌ DNS RESOLUTION FAILED OR NOT ATTEMPTED"
    fi
    
    # Check if connection to target was successful
    if grep -q "CONNECTED TO TARGET" test_server.log; then
        echo "✅ SERVER CONNECTED TO TARGET"
        grep "CONNECTED TO TARGET" test_server.log
    else
        echo "❌ SERVER FAILED TO CONNECT TO TARGET"
    fi
    
    # Check if SNI resolution was completed
    if grep -q "SNI RESOLUTION COMPLETE" test_server.log; then
        echo "✅ SNI RESOLUTION COMPLETE"
        grep "SNI RESOLUTION COMPLETE" test_server.log
    else
        echo "❌ SNI RESOLUTION INCOMPLETE"
    fi
else
    echo "❌ SERVER DID NOT RECEIVE SNI RESOLUTION REQUEST"
fi

# Clean up
echo "=== Cleaning up ==="
kill $SERVER_PID $CLIENT_PID 2>/dev/null || true
wait

echo "=== Test complete ==="
echo "Server log: test_server.log"
echo "Client log: test_client.log"
echo "Curl output: curl_output.log"
