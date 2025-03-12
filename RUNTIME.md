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
- **Full OOB Relay**: Application data goes through OOB channel for maximum compatibility
- **Complete Protection**: Application data fully protected from traffic analysis
- **Fallback Mechanisms**: Graceful degradation to ensure service availability
- **Error Recovery**: Robust handling of network issues and connection resets

### Full OOB Relay Mode

Sultry uses OOB relay for both handshake and application data, which:
1. Ensures maximum compatibility with all website protocols
2. Prevents TLS record MAC failures by maintaining connection state
3. Provides consistent behavior across different protocol versions
4. Offers complete protection against TLS fingerprinting throughout the session

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