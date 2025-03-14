#!/bin/bash

# Clear any previous logs
rm -f *.log

echo "=== Starting SNI Concealment Test with Direct Connection ==="
echo "$(date)"

# Make sure go is in the PATH
export PATH=$PATH:/usr/local/go/bin

# Build Sultry first
echo "=== Building Sultry ==="
cd "$(dirname "$0")"
make build
BUILD_STATUS=$?
if [ $BUILD_STATUS -ne 0 ]; then
    echo "❌ Build failed with exit code $BUILD_STATUS"
    exit 1
else
    echo "✅ Build successful"
fi

# Set the test domain - use google.com as it will definitely resolve
TEST_DOMAIN="google.com"
echo "Using test domain: $TEST_DOMAIN"

# Make sure go is in the PATH
export PATH=$PATH:/usr/local/go/bin

# Kill any existing processes
echo "Killing any existing Sultry processes..."
pkill -f "sultry" || true
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
./bin/sultry -mode=server -local 127.0.0.1:9008 > test_server.log 2>&1 &
SERVER_PID=$!
echo "Server started with PID: $SERVER_PID"

# Give the server time to start
sleep 4

# Check if server is running
if ! ps -p $SERVER_PID > /dev/null; then
    echo "ERROR: Server failed to start!"
    echo "Server log:"
    cat test_server.log
    exit 1
fi

# Verify server is listening on 9008 for TCP and 9009 for HTTP
if ! nc -z 127.0.0.1 9008 2>/dev/null; then
    echo "ERROR: Server not listening on port 9008 (TCP)!"
    exit 1
else
    echo "✅ Server confirmed listening on port 9008 (TCP)"
fi

# Try to connect to the HTTP API on 9009
if ! timeout 1 curl -s http://127.0.0.1:9009/ > /dev/null 2>&1; then
    echo "⚠️ HTTP API not detected on port 9009 - this may be expected with direct OOB"
else
    echo "✅ HTTP API confirmed on port 9009"
fi

# Start client with explicit logging
echo "=== Starting client component ==="
./bin/sultry -mode=client -direct-oob -local 127.0.0.1:7008 -remote 127.0.0.1:9009 > test_client.log 2>&1 &
CLIENT_PID=$!
echo "Client started with PID: $CLIENT_PID"

# Give the client time to start
sleep 4

# Check if client is running
if ! ps -p $CLIENT_PID > /dev/null; then
    echo "ERROR: Client failed to start!"
    echo "Client log:"
    cat test_client.log
    exit 1
fi

# Verify client is listening on 7008
if ! nc -z 127.0.0.1 7008 2>/dev/null; then
    echo "ERROR: Client not listening on port 7008!"
    exit 1
else
    echo "✅ Client confirmed listening on port 7008"
fi

# Check if the test domain resolves
echo "Verifying DNS resolution for $TEST_DOMAIN..."
if ! host $TEST_DOMAIN > /dev/null; then
    echo "WARNING: Test domain $TEST_DOMAIN does not resolve!"
    echo "Checking internet connectivity..."
    if ! ping -c 1 8.8.8.8 > /dev/null 2>&1; then
        echo "ERROR: No internet connectivity detected!"
    else
        echo "Internet connectivity confirmed. DNS may be misconfigured."
    fi
    # Try to use an IP address instead
    TEST_DOMAIN="142.250.72.46" # Google IP
    echo "Falling back to IP address: $TEST_DOMAIN"
fi

# Start tcpdump to monitor connections
echo "=== Starting network monitoring ==="
tcpdump -i any port 443 -n -t -s 0 -w test_network_traffic.pcap > /dev/null 2>&1 &
TCPDUMP_PID=$!
echo "Network monitor started with PID: $TCPDUMP_PID"

# Test connection
echo "=== Making test request (first connection) ==="
curl -v -x http://127.0.0.1:7008 https://$TEST_DOMAIN > curl_output.log 2>&1
CURL_EXIT=$?

# Wait a moment for session ticket processing
sleep 3

# Make a second connection to test session resumption
echo "=== Making test request (second connection for session resumption) ==="
curl -v -x http://127.0.0.1:7008 https://$TEST_DOMAIN >> curl_output.log 2>&1
CURL_EXIT2=$?
echo "Second curl exit code: $CURL_EXIT2"

# Wait a bit for monitoring
sleep 5

# Kill tcpdump
kill $TCPDUMP_PID 2>/dev/null || true

echo "Curl exit code: $CURL_EXIT"
echo "Curl output (first 20 lines):"
head -n 20 curl_output.log

# Wait longer for logs to be written
sleep 3

# Check if the request was successful
if grep -q "google" curl_output.log; then
    echo "✅ Request successful: Found 'google' in response"
else
    echo "❌ Request failed: 'google' not found in response"
fi

# ADDED TESTS FOR HANDSHAKE DETECTION AND DIRECT CONNECTION

# Check for handshake detection
echo "=== Checking handshake completion detection ==="
if grep -q "Handshake complete" test_client.log; then
    echo "✅ HANDSHAKE COMPLETION DETECTED"
    grep -A 2 "Handshake complete" test_client.log
else
    echo "❌ HANDSHAKE COMPLETION NOT DETECTED"
fi

# Check for direct connection establishment
echo "=== Checking direct connection establishment ==="
if grep -q "Established direct connection to" test_client.log; then
    echo "✅ DIRECT CONNECTION ESTABLISHED"
    grep -A 2 "Established direct connection to" test_client.log
    
    # Check for bidirectional relay
    if grep -q "Starting bidirectional relay" test_client.log; then
        echo "✅ BIDIRECTIONAL RELAY STARTED FOR DIRECT CONNECTION"
        grep -A 2 "Starting bidirectional relay" test_client.log
    else
        echo "❌ NO BIDIRECTIONAL RELAY FOR DIRECT CONNECTION"
    fi
else
    echo "❌ NO DIRECT CONNECTION ESTABLISHED"
fi

# Check for session ticket
echo "=== Checking session ticket handling ==="
if grep -q "Session Ticket received" test_client.log || grep -q "Session Ticket received" test_server.log || grep -q "Detected NewSessionTicket" test_client.log; then
    echo "✅ SESSION TICKET DETECTED"
    grep -e "Session Ticket" -e "NewSessionTicket" test_client.log test_server.log || true
else
    echo "❌ NO SESSION TICKET DETECTED"
fi

# Check for connection cleanup on server
echo "=== Checking server connection cleanup ==="
if grep -q "Proxy connection closed for session" test_server.log; then
    echo "✅ SERVER CLEANED UP CONNECTION AFTER HANDSHAKE"
    grep "Proxy connection closed for session" test_server.log
elif grep -q "Releasing connection" test_server.log; then
    echo "✅ SERVER RELEASING CONNECTION AFTER HANDSHAKE"
    grep "Releasing connection" test_server.log
else
    echo "❌ SERVER DID NOT CLEAN UP CONNECTION"
fi

# Analyze network traffic
echo "=== Analyzing network traffic ==="
# This requires tcpdump to have successfully captured traffic
if [ -f test_network_traffic.pcap ] && [ -s test_network_traffic.pcap ]; then
    # Get client IP and proxy port
    CLIENT_PORT=7008
    
    echo "Connection summary by IP and port:"
    tcpdump -n -r test_network_traffic.pcap | grep -E 'tcp|udp' | awk '{print $3 " <-> " $5}' | sort | uniq -c
    
    # Check for direct connection (traffic to 443 not going through proxy)
    DIRECT_CONNS=$(tcpdump -n -r test_network_traffic.pcap "port 443 and not port $CLIENT_PORT" | grep -c "")
    if [ $DIRECT_CONNS -gt 0 ]; then
        echo "✅ DIRECT CONNECTION TRAFFIC DETECTED: $DIRECT_CONNS packets"
        tcpdump -n -r test_network_traffic.pcap "port 443 and not port $CLIENT_PORT" | head -5
    else
        echo "❌ NO DIRECT CONNECTION TRAFFIC DETECTED"
    fi
else
    echo "⚠️ Could not analyze network traffic - missing or empty capture file"
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

# SUMMARY OF HANDSHAKE AND DIRECT CONNECTION
echo "=== SUMMARY ==="
echo "Direct Connection Flow:"

# Check handshake completion status
if grep -q "Handshake complete" test_client.log; then
    echo "1. ✅ Handshake completion detected"
else
    echo "1. ❌ Handshake completion NOT detected"
fi

# Check direct connection establishment  
if grep -q "Established direct connection to" test_client.log; then
    echo "2. ✅ Direct connection established"
else
    echo "2. ❌ Direct connection NOT established"
fi

# Check server cleanup
if grep -q "Proxy connection closed for session" test_server.log || grep -q "Releasing connection" test_server.log; then
    echo "3. ✅ Server cleaned up connection after handshake"
else
    echo "3. ❌ Server DID NOT clean up connection after handshake"
fi

# Clean up
echo "=== Cleaning up ==="
kill $SERVER_PID $CLIENT_PID 2>/dev/null || true
wait

echo "=== Test complete ==="
echo "Server log: test_server.log"
echo "Client log: test_client.log"
echo "Curl output: curl_output.log"
echo "Network capture: test_network_traffic.pcap"