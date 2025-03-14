# Sultry Runtime Behavior

## Network-Based Out-of-Band (OOB) Communication

Sultry now supports full network-based OOB communication, allowing the client and server components to run on different machines. This is a significant enhancement over the previous implementation that used direct function calls within the same process.

### Network OOB Architecture

```
┌────────┐          ┌────────┐          ┌─────────┐          ┌────────┐
│        │          │        │          │         │          │        │
│ Client │───HTTPS──► Client │───HTTP───► Server  │───TLS────► Target │
│ App    │          │ Proxy  │          │ Proxy   │          │ Server │
│        │          │        │          │         │          │        │
└────────┘          └────────┘          └─────────┘          └────────┘
```

### Key Components

1. **HTTPOOBClient**: Implemented in `pkg/session/client_session.go`, this component handles the client-side of the network OOB communication. It makes HTTP requests to the server component for:
   - Getting target information based on the ClientHello
   - Signaling handshake completion
   - Checking server status

2. **HTTP API Endpoints**: Implemented in `server.go`, these endpoints handle the server-side of the network OOB communication:
   - `/api/getTargetInfo`: Processes the ClientHello and returns target information
   - `/api/signalHandshakeCompletion`: Handles handshake completion signals
   - `/api/status`: Provides server status information

### Configuration

Network OOB behavior is controlled through the following configuration options:

```json
{
  "RemoteProxyAddr": "192.168.2.24:9008",  // Address of the remote OOB server
  "ProxyMode": "client",                   // "client", "server", or "dual"
  "OOBServerPort": 9008,                   // Port for the OOB server to listen on
  "ListenPort": 8080                       // Port for the client proxy to listen on
}
```

### Deployment Sequence

1. Start the server component on the remote machine:
   ```
   ./sultry -mode server
   ```

2. Start the client component on the local machine:
   ```
   ./sultry -mode client -remote 192.168.2.24:9008
   ```

3. Configure the client application to use the client proxy:
   ```
   curl -x localhost:8080 https://example.com
   ```

### Network Requirements

- The client must be able to reach the server on port 9008 (or configured OOBServerPort)
- Server must have appropriate firewall rules to allow incoming connections on the OOB port
- Client must have internet access to reach target websites

### Error Handling

When the server is unavailable, the client will display warning messages and may retry the connection. Current limitations:
- No automatic retry mechanism
- No fallback to direct mode
- Limited error information for network failures

## Two-Phase Connection Model

The implementation uses a two-phase connection model to balance privacy and performance:

### Phase 1: TLS Handshake via OOB

- ClientHello and TLS handshake are relayed via the OOB server
- This conceals the TLS handshake information from network observers
- Protects against SNI filtering and TLS fingerprinting

### Phase 2: Direct Connection for Application Data

- After handshake completion, client establishes direct connection to target
- Application data flows directly between client and target server
- Provides optimal performance for data-intensive applications
- No additional network hops for application data

### Benefits

1. **Privacy for Handshake**: The sensitive parts of the connection (ClientHello, SNI) are protected
2. **Performance for Data Transfer**: Direct connection provides optimal performance
3. **Balanced Approach**: Combines the best aspects of privacy and performance

### Future Enhancements

Planned improvements to the network OOB implementation:
1. Connection retry mechanism with exponential backoff
2. Heartbeat functionality to monitor server health
3. Server discovery mechanism
4. Load balancing across multiple servers
5. Enhanced error reporting and diagnostics