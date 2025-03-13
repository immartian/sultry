# Sultry Architecture

## Overview

Sultry is a specialized TLS proxy that implements several techniques for concealing Server Name Indication (SNI) and circumventing censorship. The architecture consists of client and server components that work together to establish secure, censorship-resistant connections.

## Core Components

```
┌─────────────┐           ┌─────────────┐           ┌─────────────┐
│             │           │             │           │             │
│   Client    │◄────►│    │    Proxy    │◄────►│    │    Target   │
│ Application │           │             │           │   Server    │
│             │           │             │           │             │
└─────────────┘           └─────────────┘           └─────────────┘
                              ▲     ▲
                              │     │
                              │     │
                              ▼     ▼
                         ┌─────────────┐
                         │             │
                         │  OOB Server │
                         │   Component │
                         │             │
                         └─────────────┘
```

### Client Component

The client-side proxy is responsible for:

1. Intercepting client TLS connections
2. Determining the optimal connection strategy
3. Concealing SNI information when needed
4. Managing OOB communication for handshake relay
5. Switching to direct connection after handshake completion

### Server Component 

The server-side proxy is responsible for:

1. Receiving OOB requests from clients
2. Establishing connections to target servers
3. Relaying handshake information
4. Managing sessions and tracking connection states
5. Providing target server information to clients for direct connections

### Out-of-Band (OOB) Module

The OOB module handles communication between client and server components through alternative channels:

1. HTTP-based protocols for relaying handshake information
2. Session management and synchronization
3. Target server discovery and resolution

## Connection Flows

### Full ClientHello Concealment (Primary Flow)

```
┌────────┐          ┌────────┐          ┌─────────┐          ┌────────┐
│        │          │        │          │         │          │        │
│ Client │───HTTPS──►  Proxy │          │OOB Proxy│          │ Target │
│        │          │        │          │         │          │        │
└────────┘          └────────┘          └─────────┘          └────────┘
    │                    │                   │                    │
    │ 1. ClientHello     │                   │                    │
    │───────────────────►│                   │                    │
    │                    │ 2. Relay via OOB  │                    │
    │                    │───────────────────►                    │
    │                    │                   │ 3. Connect & Send  │
    │                    │                   │ ClientHello        │
    │                    │                   │───────────────────►│
    │                    │                   │                    │
    │                    │                   │ 4. ServerHello     │
    │                    │                   │◄───────────────────│
    │                    │ 5. Relay via OOB  │                    │
    │                    │◄───────────────────                    │
    │ 6. ServerHello     │                   │                    │
    │◄───────────────────│                   │                    │
    │                    │                   │                    │
    │ 7. Handshake       │                   │                    │
    │   Completion       │                   │                    │
    │───────────────────►│                   │                    │
    │                    │ 8. Signal Handshake                    │
    │                    │   Completion      │                    │
    │                    │───────────────────►                    │
    │                    │                   │ 9. Release Proxy   │
    │                    │                   │   Connection       │
    │                    │                   │───────────────────►│
    │                    │                   │                    │
    │ 10. Direct Application Data            │                    │
    │────────────────────────────────────────────────────────────►│
    │                    │                   │                    │
    │◄───────────────────────────────────────────────────────────│
```

### Direct Connection Establishment

```
┌────────┐          ┌────────┐          ┌────────┐
│        │          │        │          │        │
│ Client │───TLS────►  Proxy │───TLS────► Target │
│        │          │        │          │        │
└────────┘          └────────┘          └────────┘
    │                    │                  │
    │                    │                  │
    │<──────────────────Handshake via Proxy─────────────────>│
    │                    │                  │
    │                    │                  │
    │      Direct connection established    │
    │<─────────────────────────────────────>│
    │                    │                  │
    │        Proxy connection released      │
    │                    └──────────────────┘
```

## Session States and Management

The server component maintains session states to track connection progress:

```
SessionState
┌─────────────────────────────┐
│                             │
│ TargetConn        net.Conn  │◄─────► Target Server
│ HandshakeComplete bool      │
│ LastActivity      time.Time │
│ ServerResponses   [][]byte  │
│ ClientMessages    [][]byte  │
│ ResponseQueue     chan      │
│ ...                         │
└─────────────────────────────┘
```

Sessions are stored in a global map indexed by a unique session ID:

```
sessions map[string]*SessionState
```

## TLS Protocol Handling

Sultry implements specialized TLS processing:

1. **Record Parsing**: Detects and parses TLS record headers to identify message types.
2. **Handshake Detection**: Identifies when a TLS handshake has completed.
3. **SNI Extraction**: Extracts Server Name Indication from ClientHello messages.
4. **Session Ticket Management**: Captures and stores TLS session tickets for resumption.

## Optimization Strategies

1. **Connection Pooling**: Reuses connections where possible to reduce overhead.
2. **TCP Optimization**: Sets TCP parameters for optimal performance.
3. **Bidirectional Relay**: Efficiently relays data in both directions.
4. **Session Cleanup**: Regularly cleans up inactive sessions to prevent resource leaks.