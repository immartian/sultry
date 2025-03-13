# Sultry Codebase Overview

## Project Structure

Sultry is a specialized TLS proxy designed for SNI concealment and censorship circumvention. The codebase has the following structure:

```
sultry/
├── client.go       # Client-side proxy implementation
├── server.go       # Server-side proxy implementation
├── config.go       # Configuration handling
├── utils.go        # TLS utility functions
├── oob.go          # Out-of-Band (OOB) communication module
├── main.go         # Entry point
└── test.sh         # Integration test script
```

## Core Components

### 1. TLS Proxy (client.go)

The core proxy functionality is implemented in client.go and divided into several connection strategies:

1. **OOB Handshake Relay**
   - Full ClientHello Concealment - Entire ClientHello relayed via OOB
   - SNI-only Concealment - Only SNI info sent via OOB

2. **Pure Tunnel Mode**
   - Standard HTTP CONNECT proxy tunneling

3. **Direct HTTP Fetch**
   - For handling plain HTTP requests 

The TLS proxy adapts its strategy based on configuration and runtime conditions, attempting to provide the most secure connection possible.

### 2. Server Component (server.go)

The server.go file implements the server-side functions:

1. **HTTP API for OOB communication**
   - Various endpoints for handshake relay
   - Session management for connections 

2. **Target Connection Management**
   - Establishing connections to target servers
   - Relaying data between client and target

3. **Handshake Handling**
   - Detecting handshake completion
   - Session ticket management
   - SSL/TLS protocol parsing

### 3. OOB Module (oob.go)

The Out-of-Band module supports alternative channels for relaying handshake information:

1. **HTTP-based relay channel**
   - Primary channel for ClientHello and ServerHello messages

2. **Channel Management**
   - Peer discovery
   - Fallback mechanism

### 4. Utils (utils.go)

Utility functions focused on TLS protocol parsing:

1. **TLS Record Handling**
   - Record header parsing
   - Message type detection
   - Handshake completion detection

2. **SNI Extraction**
   - Reading SNI extension from ClientHello

## Key Functional Flows

### SNI Concealment Flow

1. Client initiates connection through proxy
2. ClientHello with SNI is intercepted
3. ClientHello is relayed to server via OOB channel 
4. Server establishes connection to target server
5. ServerHello response is relayed back via OOB
6. Handshake completion is detected
7. Direct connection is established for application data
8. Server connection is cleaned up

### Session Ticket Handling Flow

1. Server sends NewSessionTicket message to client
2. Client stores ticket for future connections
3. Future connections can use session resumption
4. Resumption allows skipping full handshake

## Optimization Opportunities

The codebase has potential for further optimization:

1. **Extract session management code** from server.go into a separate module
2. **Create a dedicated module for HTTP handlers** to slim down server.go
3. **Split large relay functions** from client.go into a separate file
4. **Modularize connection strategies** in client.go for better maintainability

## Implementation Practices

The codebase follows several key practices:

1. **Detailed logging** with different emoji indicators for types of messages
2. **Connection optimization** with TCP parameters like keepalive and nodelay
3. **Timeout handling** to prevent resource leakage
4. **Fallback mechanisms** when primary strategies fail
5. **Atomic writes** for TLS records to avoid partial record transmission