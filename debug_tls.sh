#!/bin/bash

# This simplified script avoids using sudo and curl, which may be restricted

# Clear any previous logs
rm -f debug_server.log debug_client.log debug_openssl.log

# Test domain
TEST_DOMAIN="google.com"
PROXY_PORT=7088
SERVER_PORT=9088

# Kill any existing processes
echo "Killing any existing Sultry processes..."
pkill -f "sultry" || true
pkill -f "go run.*--mode" || true
sleep 2

# Start server with custom port
echo "=== Starting server component on port $SERVER_PORT ==="
cd "$(dirname "$0")"
go run . --mode server -local 127.0.0.1:$SERVER_PORT > debug_server.log 2>&1 &
SERVER_PID=$!
echo "Server started with PID: $SERVER_PID"

# Give the server time to start
sleep 3

# Verify server is running
if ! ps -p $SERVER_PID > /dev/null; then
    echo "ERROR: Server failed to start!"
    cat debug_server.log
    exit 1
fi

# Start client with custom port
echo "=== Starting client component on port $PROXY_PORT ==="
go run . --mode client -local 127.0.0.1:$PROXY_PORT -remote 127.0.0.1:$SERVER_PORT > debug_client.log 2>&1 &
CLIENT_PID=$!
echo "Client started with PID: $CLIENT_PID"

# Give the client time to start
sleep 3

# Check if client is running
if ! ps -p $CLIENT_PID > /dev/null; then
    echo "ERROR: Client failed to start!"
    cat debug_client.log
    exit 1
fi

# Test with openssl
echo "=== Testing with openssl ==="
echo "GET / HTTP/1.1
Host: $TEST_DOMAIN
Connection: close

" | openssl s_client -connect $TEST_DOMAIN:443 -proxy 127.0.0.1:$PROXY_PORT -brief > debug_openssl.log 2>&1
OPENSSL_EXIT=$?
echo "OpenSSL exit code: $OPENSSL_EXIT"

# Allow time for logs to be written
sleep 2

# Clean up
echo "=== Cleaning up ==="
kill $SERVER_PID $CLIENT_PID
wait

echo "=== Test complete ==="
echo "Server log: debug_server.log"
echo "Client log: debug_client.log"
echo "OpenSSL output: debug_openssl.log"

# Check for successful connection
if grep -q "Verification" debug_openssl.log; then
    echo "✅ OPENSSL TEST SUCCESSFUL"
    head -n 10 debug_openssl.log
else
    echo "❌ OPENSSL TEST FAILED"
    cat debug_openssl.log
fi

# Check if any SSL records were logged
echo "=== TLS Record Analysis ==="
grep -E "TLS Record|TLS Handshake|Forwarded ClientHello" debug_client.log

# Look for specific errors
echo "=== Error Analysis ==="
grep -E "Error|SSL_ERROR|failed|❌" debug_client.log debug_server.log || echo "No errors found"