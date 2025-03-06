# Sultry - TLS Proxy with SNI Concealment

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Sultry is an advanced TLS proxy designed to provide privacy through SNI concealment while maintaining compatibility with standard TLS applications.

## Architecture

Sultry employs a dual-component architecture:

1. **Client Component** (`client.go`): Manages incoming client connections, handles HTTP requests, HTTPS tunneling, and relays TLS data.
2. **Server Component** (`server.go`): Processes SNI information, establishes target connections, and coordinates with the client component.

### Architectural Diagram

```
                           ┌─────────────────────────────────────────────┐
                           │             Sultry Proxy                    │
                           └─────────────────────────────────────────────┘
                                               │
                                               ▼
┌──────────────┐          ┌───────────────────────────────────────┐          ┌────────────────┐
│              │          │                                       │          │                │
│              │  HTTP/   │ ┌─────────────────┐ ┌──────────────┐  │          │                │
│    Client    ◄─────────►│ │ Client Component│ │Server Component│  │◄────────►  Target Server │
│  (Browser/   │  HTTPS   │ │   (client.go)   │ │  (server.go)  │  │  TCP/TLS │   (Website)    │
│    curl)     │  Proxy   │ └─────────┬───────┘ └──────┬───────┘  │          │                │
│              │ Protocol │           │                │          │          │                │
└──────────────┘          └───────────┼────────────────┼──────────┘          └────────────────┘
                                      │                │
                                      │     OOB HTTP   │
                                      └───────────────►┘
                                      API Communication
```

### Connection Strategies Diagram

```
                        ┌───────────────────────────────────────────┐
                        │           Connection Strategies           │
                        └───────────────────────────────────────────┘
                                            │
                 ┌──────────────────────────┼──────────────────────────┐
                 │                          │                          │
    ┌────────────▼───────────┐  ┌───────────▼──────────────┐  ┌────────▼───────────┐
    │                        │  │                          │  │                     │
    │   Pure Tunnel Mode     │  │   OOB SNI Resolution     │  │  Direct HTTP Fetch  │
    │ (handleTunnelConnect)  │  │ (getTargetConnViaOOB)    │  │(handleDirectHttpReq)│
    │                        │  │                          │  │                     │
    └────────────┬───────────┘  └───────────┬──────────────┘  └─────────┬──────────┘
                 │                          │                           │
                 │                          │                           │
    ┌────────────▼───────────┐  ┌───────────▼──────────────┐  ┌─────────▼──────────┐
    │                        │  │                          │  │                     │
    │  Bidirectional Relay   │  │  Split Tunnel w/OOB SNI  │  │   Direct HTTP GET   │
    │      (relayData)       │  │      Resolution          │  │    via net/http     │
    │                        │  │                          │  │                     │
    └────────────────────────┘  └──────────────────────────┘  └─────────────────────┘
```

### Connection Handling Strategies

Sultry uses a split tunnel approach to provide SNI privacy with optimal performance:

1. **SNI Concealment via OOB Resolution**
   - **OOB SNI Resolution**: 
     - Extracts SNI metadata from ClientHello
     - Sends ONLY SNI information (not TLS records) via OOB channel
     - Server resolves hostname and returns IP information
     - Client creates direct TCP tunnel using resolved IP
     - Completely conceals SNI information from network monitors/firewalls
     - Prevents SNI-based censorship or tracking
     - Preserves TLS integrity by keeping all TLS records on one connection

2. **Full TLS Tunnel**
   - All TLS traffic (including handshake) flows through a single TCP connection
   - Dedicated TCP tunnel handles the complete TLS session
   - Full compatibility with TLS 1.2, 1.3 and HTTP/1.1, HTTP/2
   - No TLS state machine disruption
   - Maintains proper TLS record boundaries

3. **Alternative Modes**
   - **Pure Tunnel Mode**: For when SNI concealment is not required
   - **Direct HTTP Fetch**: For non-TLS HTTP requests

## Key Features

- **Split Tunnel SNI Privacy**: Conceals SNI while maintaining TLS integrity
- **Optimized Performance**: Dedicated TCP tunnel for TLS traffic
- **Censorship Resistance**: Prevents SNI-based filtering and tracking 
- **Protocol Flexibility**: Works with all TLS protocols (1.2, 1.3) and HTTP versions (1.1, 2)
- **Clean Architecture**: Separates SNI resolution from TLS record handling
- **Transparent Operation**: Applications connect normally without special configuration
- **Configurable Behavior**: Easy to adjust privacy vs. performance trade-offs
- **Simple Configuration**: Easy setup via config.json

## Usage

1. Configure in config.json
2. Run with `go run .` or `go build && ./sultry`
3. Configure your client to use the proxy

### For HTTP connections:
```bash
curl -x http://127.0.0.1:7008 http://example.com/
```

### For HTTPS connections (now works with standard curl):
```bash
curl -x http://127.0.0.1:7008 https://example.com/
```

### For maximum compatibility with older clients:
```bash
curl --tlsv1.2 --http1.1 -x http://127.0.0.1:7008 https://example.com/
```

## Technical Details

### HTTPS Handling Process

```
┌──────────┐                  ┌────────────┐                 ┌────────────┐
│          │                  │            │                 │            │
│  Client  │                  │   Proxy    │                 │  Target    │
│          │                  │            │                 │   Server   │
└────┬─────┘                  └─────┬──────┘                 └─────┬──────┘
     │                              │                              │
     │   1. HTTP CONNECT Request    │                              │
     │ ─────────────────────────────>                              │
     │                              │                              │
     │                              │    2. TCP Connection         │
     │                              │ ─────────────────────────────>
     │                              │                              │
     │  3. 200 Connection           │                              │
     │     Established              │                              │
     │ <─────────────────────────────                              │
     │                              │                              │
     │                              │                              │
     │   4. TLS ClientHello         │                              │
     │ ─────────────────────────────>                              │
     │                              │   4. TLS ClientHello         │
     │                              │ ─────────────────────────────>
     │                              │                              │
     │                              │   5. TLS ServerHello         │
     │                              │ <─────────────────────────────
     │   5. TLS ServerHello         │                              │
     │ <─────────────────────────────                              │
     │                              │                              │
     │          TLS Handshake continues...                         │
     │                              │                              │
     │   6. Application Data        │                              │
     │ ─────────────────────────────>                              │
     │                              │   6. Application Data        │
     │                              │ ─────────────────────────────>
     │                              │                              │
     │                              │   7. HTTP Response           │
     │                              │ <─────────────────────────────
     │   7. HTTP Response           │                              │
     │ <─────────────────────────────                              │
     │                              │                              │
```

1. Client sends an HTTP CONNECT request to the proxy
2. Proxy establishes a TCP connection to the target server
3. Proxy returns "200 Connection Established" to client
4. Client and target server perform TLS handshake through the proxy tunnel
5. Data is relayed bidirectionally with TLS record logging

### Data Relay Features

- TLS record inspection and logging for debugging
- Connection optimization with TCP_NODELAY, keep-alive settings
- Efficient buffer management to avoid fragmenting TLS records
- Connection timeouts to prevent hanging on network issues

### Configuration

```json
{
  "local_proxy_addr": "127.0.0.1:7008",
  "relay_port": 9008,
  "oob_channels": [
    {
      "type": "http",
      "address": "127.0.0.1", 
      "port": 9008
    }
  ],
  "cover_sni": "harvard.edu",
  "prioritize_sni_concealment": true,
  "handshake_timeout": 10000
}
```

#### Configuration Options

- **local_proxy_addr**: The address and port where the local proxy listens
- **relay_port**: The port where the OOB relay server listens
- **oob_channels**: List of out-of-band channel configurations
- **cover_sni**: A fake SNI value to use when real SNI needs to be concealed
- **prioritize_sni_concealment**: When true, always use OOB for SNI concealment (default: false)
- **handshake_timeout**: Timeout in milliseconds for TLS handshake operations (default: 5000)

## Implementation Details

### Original Design & Challenges

The original design attempted to relay TLS handshake messages via an out-of-band HTTP channel:

1. **Full TLS Handshake Relay**: 
   - Relayed complete TLS handshake messages via an out-of-band HTTP channel
   - Server component established connection to target
   - Attempted to relay all TLS records back and forth during handshake
   - Used dedicated HTTP endpoints for record transfer

2. **TLS State Machine Issues**:
   - TLS protocol requires strict state tracking across a single connection
   - Splitting handshake and application data across different channels broke TLS
   - Resulted in "wrong version number" and MAC validation errors
   - Connections would reset or fail after handshake completed

3. **Protocol Limitations**:
   - Required specific TLS version and HTTP protocol restrictions
   - Compatibility limited to certain clients and configurations
   - Caused fragility when mixing different protocol versions

### Current Implementation

Our implementation uses a split tunnel architecture that maintains TLS integrity:

1. **OOB SNI Resolution**:
   - **Client Side**:
     - Extracts ONLY SNI metadata from ClientHello (doesn't send full TLS record)
     - Gets target resolution via OOB channel
     - Creates direct TCP tunnel using resolved target
     - Implementation in `getTargetConnViaOOB` function
   
   - **Server Side**:
     - Resolves hostname from SNI information
     - Returns connection information to client
     - Implementation in `handleCreateConnection` function

2. **Full TCP Tunnel for TLS**:
   - All TLS traffic flows through a single, dedicated TCP connection
   - TLS record integrity preserved (no record splitting or reassembly)
   - Full compatibility with all TLS versions and HTTP protocol negotiation
   - Implementation in `handleTunnelConnect` function

3. **Strategy Selection & Configuration**:
   - Intelligent fallback to standard tunneling when needed
   - Smart connection handling based on request type
   - Implementation in `handleConnection` function

4. **Logging & Debugging**:
   - Improved TLS record parsing and logging
   - Diagnostics for connection issues
   - Implementation in `logTLSRecord` function

### Implementation Challenges Overcome

1. **TLS Record Integrity**:
   - **Challenge**: Maintaining TLS protocol integrity across the connection
   - **Solution**: Split tunnel design that keeps all TLS records on one TCP connection

2. **SNI Concealment**:
   - **Challenge**: Hiding SNI while maintaining normal TLS connection
   - **Solution**: Metadata-only OOB channel for SNI resolution with direct TCP tunneling

3. **Protocol Compatibility**:
   - **Challenge**: Supporting all TLS versions and HTTP protocols without restrictions
   - **Solution**: Clean architecture that doesn't interfere with TLS/HTTP protocol negotiation

4. **Connection Reliability**:
   - **Challenge**: Ensuring robust connections that work with any TLS-based website
   - **Solution**: Separate concerns between metadata exchange and TLS record handling

5. **Buffer Management**:
   - **Challenge**: Properly handling TLS records without fragmenting or corrupting
   - **Solution**: Optimized buffer sizes and improved TLS record parsing

## Future Directions

Several potential enhancement paths for Sultry:

1. **Enhanced SNI Concealment**:
   - Multiple cover SNI domains for rotation
   - Domain fronting techniques
   - Randomized SNI patterns
   - ECH (Encrypted Client Hello) implementation when standards mature

2. **Protocol Enhancement**:
   - Add HTTP/3 (QUIC) explicit support
   - Implement WebSocket secure tunneling
   - Support SOCKS5 protocol for broader application compatibility

3. **Performance Optimization**:
   - Connection pooling for faster response times
   - Intelligent buffer sizing based on content type
   - Multi-threaded relay for high-throughput scenarios

4. **Advanced Privacy Features**:
   - Traffic padding to resist timing attacks
   - TLS fingerprint randomization
   - Protocol obfuscation techniques
   - Integration with other privacy tools (Tor, etc.)

5. **Deployment Flexibility**:
   - Containerization for easy deployment
   - Distributed proxy architecture for load balancing
   - Cloud-native integration options

## Technical Challenges & Solutions

### TLS Protocol Challenges
- **Challenge**: The TLS protocol state machine requires consistent message sequencing
- **Solution**: Implemented split tunnel design that maintains TLS record ordering

### SNI Extraction & Concealment
- **Challenge**: Needed to extract SNI without breaking the TLS connection
- **Solution**: Improved parser that extracts just SNI metadata without affecting the TLS record flow

### Protocol Version Negotiation
- **Challenge**: HTTP/2 ALPN negotiation and TLS version compatibility  
- **Solution**: Clean TCP tunnel that doesn't interfere with protocol negotiation

### Buffer Management
- **Challenge**: TLS records must be handled as complete units without fragmentation
- **Solution**: Optimal buffer sizing and improved data relay mechanisms

### Connection Stability
- **Challenge**: Maintaining stable connections across varied network conditions
- **Solution**: Robust error handling and timeout management

## Troubleshooting

If you encounter issues:

### SNI Resolution Issues
1. Check if `prioritize_sni_concealment` is set to `true` in config.json
2. Verify the OOB channels are correctly configured and reachable
3. Make sure the `cover_sni` value is a legitimate domain
4. Check logs for successful SNI extraction and resolution

### Connection Issues
1. Verify that your client is correctly configured to use the proxy
2. Check logs for TLS record information and any errors
3. Ensure firewall rules allow connections to the target servers
4. For advanced debugging, enable verbose logging with higher log levels

### Protocol Compatibility Issues
1. Sultry should work with all TLS versions and HTTP protocols by default
2. No client flags are required - standard curl or browser configuration should work
3. If you experience issues with specific sites, check the logs for protocol details
4. Verify the SNI extraction is working correctly for that specific domain

Remember that Sultry maintains TLS integrity by keeping all TLS records on a single TCP connection while using an out-of-band channel only for SNI resolution.

## License

Sultry is released under the MIT License. See the [LICENSE](LICENSE) file for details.

## Firewall Considerations

### Post-Handshake Communication and Firewall Detection

After the SNI resolution phase, Sultry's communication with the target server is indistinguishable from regular TLS traffic:

1. **Initial SNI Resolution**:
   - Only metadata (SNI hostname) is sent via OOB channel
   - This prevents SNI-based filtering and censorship
   - Deep packet inspection cannot detect the actual target server from TLS ClientHello

2. **TLS Traffic Flow**:
   - All TLS traffic (including handshake) flows through a standard TCP tunnel
   - From a firewall's perspective, this appears as regular TLS traffic
   - The connection appears to be going to the IP address directly, not to a proxy
   - TLS encryption prevents inspection of the application data

3. **Firewall Detection Resistance**:
   - No special protocol signatures that would identify Sultry traffic
   - Standard TLS/HTTP protocols used throughout
   - No traffic pattern anomalies that would trigger heuristic detection
   - Firewall would need to block all TLS traffic to block Sultry

For maximum privacy in restrictive network environments, consider using Sultry in combination with other privacy tools that address different detection vectors.
