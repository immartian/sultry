/*
Sultry - TLS Proxy with Multiple Connection Strategies

Architecture Overview:

1. Pure Tunnel Mode (Primary):
   Client → Client Proxy → [Direct TCP Connection] → Target Server

2. OOB Handshake Relay (For SNI Concealment):
   Client → Client Proxy → [Firewall] → Server Proxy → Target Server
                       ↑                    ↓
                       OOB Channel (SNI hidden)

3. Direct HTTP Fetch:
   Client → Client Proxy → [HTTP Request] → Target Server

The proxy system offers multiple strategies with automatic fallback:
- Pure Tunnel Mode provides the highest reliability and compatibility
- OOB Handshake Relay conceals SNI information from network monitors
- Direct HTTP Fetch efficiently handles plain HTTP requests

By implementing these strategies, Sultry balances security, privacy,
and reliability based on the specific requirements of each connection.
*/

package main

import (
	"flag"
	"log"
)

func main() {
	// three modes: client(default)/server/dual
	var mode = flag.String("mode", "client", "proxy mode: client/server/dual")
	flag.Parse()

	// Load configuration
	config, err := LoadConfig("config.json")
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}

	switch *mode {
	case "client":
		client(config)
	case "server":
		server(config)
	case "dual":
		go client(config)
		server(config)
	}

}
