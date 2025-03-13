# Sultry Development Guide

This document provides guidelines and examples for working with the Sultry codebase.

## Setup

Ensure you have Go installed (v1.16+) and have cloned the repository:

```bash
git clone https://github.com/yourusername/sultry.git
cd sultry
```

## Building

```bash
go build
```

This builds the `sultry` binary.

## Testing

Run the integrated test script:

```bash
./test.sh
```

This test script performs a full end-to-end test of the proxy functionality, including:
- SNI concealment
- Direct connection establishment
- Session ticket handling
- Connection cleanup

## Core Components Overview

### Client Component

Run the client component with:

```bash
./sultry --mode client
```

### Server Component

Run the server component with:

```bash
./sultry --mode server
```

## Extending the Codebase

### Adding a New OOB Channel Type

To implement a new OOB channel type:

1. Add the new channel type in `oob.go`
2. Implement the channel handler functions
3. Register the channel in the OOB module initialization

Example:

```go
// NewCustomChannel creates a custom OOB channel
func NewCustomChannel(config ChannelConfig) (*Channel, error) {
    channel := &Channel{
        Type:    "custom",
        Address: config.Address,
        Port:    config.Port,
        // Add custom channel properties
    }
    
    // Initialize the channel
    
    return channel, nil
}
```

### Adding TLS Protocol Support

To extend TLS protocol support:

1. Add the new TLS version constants in `utils.go`
2. Implement the required parsing functions
3. Update the handshake detection logic

Example:

```go
// Example of adding support for a new TLS version
const (
    // Existing constants
    ...
    
    // New TLS version
    TLSVersion14 = 0x0305
)

// Update detection function
func detectTLSVersion(data []byte) uint16 {
    if len(data) < 5 {
        return 0
    }
    
    version := binary.BigEndian.Uint16(data[1:3])
    return version
}
```

### Session Management

To implement custom session management:

1. Extend the `SessionState` struct in `server.go`
2. Implement cleanup and lifecycle functions
3. Add monitoring for session state

Example:

```go
// Add a new field to SessionState
type SessionState struct {
    // Existing fields
    ...
    
    // New field
    CustomData    map[string]interface{}
}

// Add a function to update custom data
func updateSessionCustomData(sessionID string, key string, value interface{}) {
    sessionsMu.Lock()
    defer sessionsMu.Unlock()
    
    if session, exists := sessions[sessionID]; exists {
        if session.CustomData == nil {
            session.CustomData = make(map[string]interface{})
        }
        session.CustomData[key] = value
    }
}
```

## Debugging

### Log File Analysis

The test script generates logs for both client and server:

- `test_client.log`: Client-side logs
- `test_server.log`: Server-side logs

Look for emojis in the logs to quickly identify message types:

- ✅ Success message
- ❌ Error message
- 🔹 Informational message
- 🔒 Security-related message
- ⚠️ Warning message

### Network Traffic Analysis

Capture network traffic for debugging:

```bash
tcpdump -i any 'port 7008 or port 9008 or port 443' -w capture.pcap
```

Analyze the capture with Wireshark focusing on:
- TLS traffic patterns
- Connection establishment
- Handshake messages

### Common Debugging Steps

1. Check proper detection of TLS handshake completion:
   - Search for "Handshake complete" in client logs

2. Verify direct connection establishment:
   - Look for "Direct connection established" messages
   - Check for "Starting bidirectional relay" following direct connection

3. Examine server connection cleanup:
   - Verify "Proxy connection closed for session" messages
   - Check timing between handshake completion and connection closure

## Performance Optimization

### Key Areas for Optimization

1. Session State Management:
   - The server maintains sessions in `server.go`
   - Consider optimizing cleanup intervals for high-traffic scenarios

2. Connection Handling:
   - The relay functions in `client.go` handle bidirectional data transfer
   - Large buffer sizes improve performance but increase memory usage

3. OOB Communication:
   - The HTTP endpoints in `server.go` handle OOB requests
   - Consider optimizing request/response formats for lower latency