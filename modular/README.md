# Sultry Modular Implementation

This directory contains the early development of the modular version of Sultry. Note that the development has now been moved to the main `pkg/` directory for better integration.

## Overview

The modular version separates the large monolithic files (client.go and server.go) into smaller, more maintainable packages:

- **tls.go**: TLS protocol utilities
- **relay.go**: Data relay functionality
- **handlers.go**: HTTP handlers for the server API
- **tunnel.go**: Direct connection establishment

## Features

- SNI concealment for improved privacy and censorship resistance
- TLS record parsing and analysis
- Session ticket management
- Out-of-band relay for handshake data

## Current Status

The modular implementation has been completed and moved to the main `pkg/` directory structure. This directory serves as historical reference for the initial modular design.

Please use the implementation in `pkg/` for the latest version.

## Usage

See the main README.md and CODEBASE.md for detailed usage instructions of the modular version.

```bash
# Build the modular version
make build-modular

# Run it
./bin/sultry-mod -mode client -local 127.0.0.1:8080
```
