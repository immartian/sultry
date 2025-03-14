# Sultry Codebase Overview

## Project Structure

Sultry is a specialized TLS proxy designed for SNI concealment and censorship circumvention. The codebase is organized in a clean, modular structure:

```
sultry/
├── config.go       # Configuration handling
├── main.go         # Entry point
├── pkg/
│   ├── client/     # Client-side proxy functionality
│   ├── connection/ # Connection handling
│   ├── relay/      # Data relay functionality
│   ├── server/     # Server-side proxy functionality
│   ├── session/    # Session management
│   └── tls/        # TLS protocol utilities
└── test.sh         # Integration test script
```

## Core Components

### Modular Implementation

The modular implementation breaks down functionality into focused packages:

### 1. TLS Module (pkg/tls)

Handles TLS protocol operations:
- Record header parsing and validation
- Message type detection
- Handshake completion detection
- SNI extraction from ClientHello
- Session ticket message detection

### 2. Session Management (pkg/session)

Manages connection state:
- Client-side session operations (client_session.go)
- Server-side session state (manager.go) 
- Session ticket handling for TLS resumption (session.go)
- Target info tracking across OOB communications

### 3. Relay Functions (pkg/relay)

Handles data transfer between connections:
- Bidirectional data relay with TLS awareness (relay.go)
- Direct connection establishment (tunnel.go)
- Session ticket detection during relaying

### 4. Connection Handling (pkg/connection)

Manages different connection types:
- HTTP CONNECT tunnel handling
- Direct TLS connection handling
- OOB tunnel handling
- Full ClientHello concealment strategy
- SNI-only concealment strategy

### 5. Client Implementation (pkg/client)

Simplified client-side proxy:
- Connection acceptance and routing
- Functional options pattern for configuration
- Delegate to connection package for specific handling

### 6. Server Implementation (pkg/server)

Simplified server-side proxy:
- HTTP API endpoints for OOB communication
- Session management
- Target connection handling

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

## Completed Optimizations

The following optimizations have been implemented:

1. ✅ **Extract session management code** into pkg/session
2. ✅ **Create a dedicated module for relay functions** in pkg/relay
3. ✅ **Modularize connection strategies** in pkg/connection
4. ✅ **Implement proper TLS utilities module** in pkg/tls
5. ✅ **Create smaller, focused implementations** of client and server components
6. ✅ **Eliminate HTTP API overhead** with direct OOB communication option
7. ✅ **Automatic port management** to prevent conflicts between TCP and HTTP servers

## Implementation Practices

The codebase follows several key practices:

1. **Detailed logging** with different emoji indicators for types of messages
2. **Connection optimization** with TCP parameters like keepalive and nodelay
3. **Timeout handling** to prevent resource leakage
4. **Fallback mechanisms** when primary strategies fail
5. **Atomic writes** for TLS records to avoid partial record transmission
6. **Separation of concerns** with each package handling specific functionality
7. **Functional options pattern** for flexible configuration
8. **Interface-based design** for improved testability
9. **Both modular and original implementations** maintained for compatibility

## Building and Running

The project includes a Makefile with the following targets:

```
make build           # Build both original and modular versions
make build-original  # Build only the original version
make build-modular   # Build only the modular version
make clean           # Clean up binaries
make test            # Run tests
```

After building, you can run either version:

```
# Original version
./bin/sultry -mode client -local 127.0.0.1:8080

# Modular version
./bin/sultry-mod -mode client -local 127.0.0.1:8080
```