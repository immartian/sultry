# Sultry Runtime Guide

This guide provides instructions for running the Sultry proxy with full ClientHello concealment.

## Quick Start

1. **Server Mode (Outside censored network)**
   ```bash
   # Run server component on a machine with unrestricted internet access
   ./sultry --mode server
   ```

2. **Client Mode (Inside censored network)**
   ```bash
   # Run client component on the local machine
   ./sultry --mode client
   ```

3. **Dual Mode (Testing)**
   ```bash
   # Run both client and server on the same machine for testing
   ./sultry --mode dual
   ```

## Testing Your Connection

### Using curl

Test HTTP:
```bash
curl -x http://127.0.0.1:7008 http://example.com/
```

Test HTTPS (with ClientHello concealment):
```bash
curl -v -x http://127.0.0.1:7008 https://www.google.com/
```

### Using a browser

Configure your browser to use the proxy:
- Proxy address: `127.0.0.1`
- Port: `7008`
- Type: HTTP proxy

## Configuration

The default configuration is in `config.json`. Key options:

```json
{
  "local_proxy_addr": "127.0.0.1:7008",
  "relay_port": 9008,
  "oob_channels": [
    {
      "type": "http",
      "address": "your-server-ip", 
      "port": 9008
    }
  ],
  "cover_sni": "harvard.edu",
  "prioritize_sni_concealment": true,
  "full_clienthello_concealment": true,
  "handshake_timeout": 10000,
  "enforce_tls13": true
}
```

For remote deployment, update the `oob_channels` section with your server's actual IP address.

## Features

- **Full ClientHello Concealment**: Complete protection against TLS handshake analysis
- **TLS 1.3 Enforcement**: Option to enforce TLS 1.3 for maximum security
- **Direct Connections**: Efficient application data transfer after secure handshake
- **Fallback Mechanisms**: Graceful degradation to ensure service availability
- **Error Recovery**: Robust handling of network issues and connection resets

### TLS 1.3 Enforcement

When `enforce_tls13` is enabled, Sultry will:
1. Detect the TLS version negotiated during handshake
2. Use direct connections only for TLS 1.3 targets
3. Fall back to secure OOB relay for non-TLS 1.3 targets
4. Provide maximum protection against protocol downgrade attacks

## Troubleshooting

1. **Connection failures**: 
   - Check if the server component is running and accessible
   - Verify firewall rules allow access to ports 7008 and 9008

2. **Slow connections**:
   - Increase `handshake_timeout` in config.json
   - Try multiple OOB channels for redundancy

3. **Debug logging**:
   - Run with environment variable `DEBUG=1` for verbose logging
   ```bash
   DEBUG=1 ./sultry --mode client
   ```

## Security Considerations

- Always use the latest version for best security
- The server component should be hosted on a trusted network
- Full ClientHello concealment provides maximum privacy but may not work with all websites

For more detailed information, see the main [README.md](README.md) file.