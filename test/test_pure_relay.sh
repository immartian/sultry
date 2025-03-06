#!/bin/bash

# Test script for Sultry TLS proxy with curl
# Tests both TLS 1.2 and TLS 1.3 connections

echo "Testing TLS 1.3 connection (default in curl)"
curl -v --proxy http://127.0.0.1:7008 https://www.cnn.com -o /dev/null

echo -e "\n\nTesting TLS 1.2 connection (forced)"
curl -v --tlsv1.2 --proxy http://127.0.0.1:7008 https://www.cnn.com -o /dev/null

echo -e "\n\nTesting HTTP/1.1 connection (forced)"
curl -v --http1.1 --proxy http://127.0.0.1:7008 https://www.cnn.com -o /dev/null 

echo -e "\n\nAll tests completed."