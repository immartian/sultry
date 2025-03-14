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
	"fmt"
	"log"
	"os"
	"os/signal"
	"sultry/pkg/client"
	"sultry/pkg/relay"
	"sultry/pkg/server"
	"sultry/pkg/session"
	"syscall"
)

// OOBModule handles out-of-band communication
type OOBModule struct {
	ServerAddress string
}

// GetServerAddress returns the OOB server address
func (o *OOBModule) GetServerAddress() string {
	return o.ServerAddress
}

func main() {
	// Parse command line flags
	mode := flag.String("mode", "client", "Operation mode (client, server, dual)")
	localAddr := flag.String("local", "127.0.0.1:8080", "Local proxy address")
	remoteAddr := flag.String("remote", "localhost:9090", "Remote proxy address")
	coverSNI := flag.String("cover-sni", "", "Use an alternative SNI value")
	prioritizeSNI := flag.Bool("prioritize-sni", false, "Prioritize SNI concealment over direct tunneling")
	oobChannels := flag.Int("oob-channels", 2, "Number of OOB channels")
	fullClientHello := flag.Bool("full-clienthello", true, "Use full ClientHello concealment")
	handshakeTimeout := flag.Int("handshake-timeout", 10000, "Handshake timeout in milliseconds")
	connectionPoolSize := flag.Int("connection-pool", 100, "Connection pool size")
	configPath := flag.String("config", "config.json", "Path to configuration file")
	
	flag.Parse()

	// Load configuration
	config, err := LoadConfig(*configPath)
	if err != nil {
		log.Printf("⚠️ Failed to load config from %s: %v", *configPath, err)
		log.Println("ℹ️ Using command line parameters instead")
		
		// Use command line parameters
		config = &Config{
			Mode:                      *mode,
			LocalProxyAddr:            *localAddr,
			RemoteProxyAddr:           *remoteAddr,
			CoverSNI:                  *coverSNI, 
			PrioritizeSNI:             *prioritizeSNI,
			OOBChannels:               *oobChannels,
			FullClientHelloConcealment: *fullClientHello,
			HandshakeTimeout:          *handshakeTimeout,
			ConnectionPoolSize:        *connectionPoolSize,
		}
	} else {
		// Override with command line parameters if explicitly provided by the user
		// Check if flag was explicitly set by the user (not using default value)
		modeFlag := flag.Lookup("mode")
		if modeFlag != nil && len(flag.Args()) > 0 {
			config.Mode = *mode
		}
		
		localFlag := flag.Lookup("local")
		if localFlag != nil && *localAddr != "127.0.0.1:8080" {
			config.LocalProxyAddr = *localAddr
		}
		
		remoteFlag := flag.Lookup("remote")
		if remoteFlag != nil && *remoteAddr != "localhost:9090" {
			config.RemoteProxyAddr = *remoteAddr
		}
		
		coverSNIFlag := flag.Lookup("cover-sni")
		if coverSNIFlag != nil && *coverSNI != "" {
			config.CoverSNI = *coverSNI
		}
		
		// For boolean flags, we can check based on non-default values
		if *prioritizeSNI != false {
			config.PrioritizeSNI = *prioritizeSNI
		}
		
		if *oobChannels != 2 {
			config.OOBChannels = *oobChannels
		}
		
		if *fullClientHello != true {
			config.FullClientHelloConcealment = *fullClientHello
		}
		
		if *handshakeTimeout != 10000 {
			config.HandshakeTimeout = *handshakeTimeout
		}
		
		if *connectionPoolSize != 100 {
			config.ConnectionPoolSize = *connectionPoolSize
		}
	}

	// Set up signal handling for graceful shutdown
	setupSignalHandling()

	// Start in the appropriate mode
	switch config.Mode {
	case "client":
		startClient(config)
	case "server":
		startServer(config)
	case "dual":
		go startClient(config)
		startServer(config)
	default:
		fmt.Println("Invalid mode:", config.Mode)
		os.Exit(1)
	}
}

func startClient(config *Config) {
	// Initialize OOB module
	oobModule := &OOBModule{
		ServerAddress: config.RemoteProxyAddr,
	}
	
	// Initialize session manager
	sessionManager := session.NewSessionManager(oobModule)
	
	// Initialize tunnel manager
	tunnelManager := relay.NewTunnelManager(sessionManager)
	
	fmt.Println("Client mode started on", config.LocalProxyAddr)
	
	// Initialize client proxy with options
	clientProxy := client.NewClientProxy(
		sessionManager,
		tunnelManager,
		client.WithFakeSNI(config.CoverSNI),
		client.WithPrioritizeSNI(config.PrioritizeSNI),
		client.WithFullClientHelloConcealment(config.FullClientHelloConcealment),
		client.WithHandshakeTimeout(config.HandshakeTimeout),
	)
	
	// Start client proxy
	err := clientProxy.Start(config.LocalProxyAddr)
	if err != nil {
		log.Fatalf("❌ Failed to start client proxy: %v", err)
	}
}

func startServer(config *Config) {
	// Initialize session manager
	sessionManager := session.NewManager()
	
	// Start session cleanup
	go sessionManager.StartCleanup(60 * 1e9) // 60 seconds
	
	fmt.Println("Server mode started on", config.LocalProxyAddr)
	
	// Initialize server proxy
	serverProxy := server.NewServerProxy(sessionManager)
	
	// Start server proxy
	err := serverProxy.Start(config.LocalProxyAddr)
	if err != nil {
		log.Fatalf("❌ Failed to start server proxy: %v", err)
	}
}

func setupSignalHandling() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-c
		fmt.Println("\nShutting down gracefully...")
		os.Exit(0)
	}()
}
