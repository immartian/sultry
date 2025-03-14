#\!/bin/bash
# This script runs Sultry with proper network OOB communication

# Build the latest version
go build -o bin/sultry

# Use a different client port to avoid conflicts
CLIENT_PORT=7009
SERVER_PORT=9009

# First, start the server component in the background
echo "Starting Sultry OOB server on localhost:${SERVER_PORT}..."
./bin/sultry -mode server -local "localhost:${SERVER_PORT}" > server.log 2>&1 &
SERVER_PID=$\!

# Wait a bit for the server to start
sleep 1

# Now start the client component in the foreground
echo "Starting Sultry client on localhost:${CLIENT_PORT} (using OOB server at localhost:${SERVER_PORT})..."
./bin/sultry -mode client -local "localhost:${CLIENT_PORT}" -remote "localhost:${SERVER_PORT}"

# When the client exits, kill the server
kill $SERVER_PID
