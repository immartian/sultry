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
	"net"
	"os"
	"os/signal"
	"sultry/pkg/client"
	"sultry/pkg/relay"
	"sultry/pkg/server"
	"sultry/pkg/session"
	"syscall"
	"time"
)

func main() {
	// Parse command line flags
	mode := flag.String("mode", "client", "Operation mode (client, server, dual)")
	localAddr := flag.String("local", "127.0.0.1:8080", "Local proxy address")
	remoteAddr := flag.String("remote", "localhost:9090", "Remote proxy address (for client mode)")
	coverSNI := flag.String("cover-sni", "", "Use an alternative SNI value")
	prioritizeSNI := flag.Bool("prioritize-sni", false, "Prioritize SNI concealment over direct tunneling")
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
			Mode:                       *mode,
			LocalProxyAddr:             *localAddr,
			RemoteProxyAddr:            *remoteAddr,
			CoverSNI:                   *coverSNI,
			PrioritizeSNI:              *prioritizeSNI,
			FullClientHelloConcealment: *fullClientHello,
			HandshakeTimeout:           *handshakeTimeout,
			ConnectionPoolSize:         *connectionPoolSize,
		}
	} else {
		// Always override mode from command line flag
		config.Mode = *mode

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

	// Log the final config
	log.Printf("USING MODE: %s", config.Mode)

	// Manual override for test compatibility
	if flag.Lookup("mode").Value.String() == "server" {
		log.Println("FORCING SERVER MODE FROM FLAG")
		config.Mode = "server"
	}
	
	// Debug logging for mode
	log.Printf("Flag mode value: %s", flag.Lookup("mode").Value.String())
	log.Printf("Config mode value: %s", config.Mode)

	// Mode handling
	switch config.Mode {
	case "client":
		log.Println("STARTING IN CLIENT MODE")

		// Configure the HTTP OOB client to communicate with the OOB server
		oobServerAddr := config.RemoteProxyAddr
		// Only use localhost if RemoteProxyAddr is not set
		if oobServerAddr == "" && config.RelayPort > 0 {
			// Use relay port if specified and no remote address
			oobServerAddr = fmt.Sprintf("localhost:%d", config.RelayPort)
		}
		
		// Use first OOB channel if available and RemoteProxyAddr is not set
		if oobServerAddr == "" && config.OOBChannels != nil {
			// Try to extract the first OOB channel
			log.Printf("🔒 Looking for OOB channels in config...")
			if channels, ok := config.OOBChannels.([]interface{}); ok && len(channels) > 0 {
				if channel, ok := channels[0].(map[string]interface{}); ok {
					address := channel["address"].(string)
					port := int(channel["port"].(float64))
					oobServerAddr = fmt.Sprintf("%s:%d", address, port)
					log.Printf("🔒 Using first OOB channel from config: %s", oobServerAddr)
				}
			}
		}
		
		// Check if the server is available
		_, err = net.DialTimeout("tcp", oobServerAddr, 100*time.Millisecond)
		if err != nil {
			log.Printf("⚠️ WARNING: OOB server at %s is not available.", oobServerAddr)
			log.Printf("⚠️ You must start a server component separately with: ./bin/sultry -mode server")
			log.Printf("⚠️ Or use dual mode: ./bin/sultry -mode dual")
		}
		
		log.Printf("🔒 SNI CONCEALMENT: Using OOB server at %s", oobServerAddr)
		
		// Create HTTP OOB client
		oobClient := &session.HTTPOOBClient{
			ServerAddress: oobServerAddr,
		}
		
		// Initialize session manager with HTTP client
		sessionManager := session.NewSessionManager(oobClient)
		
		// Initialize tunnel manager
		tunnelManager := relay.NewTunnelManager(sessionManager)
		
		// Clear client logs
		log.Printf("🔒 NETWORK MODE: Using HTTP API for OOB communication")
		log.Printf("🔒 Using OOB server at %s", oobServerAddr)
		
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

	case "server":
		log.Println("STARTING IN SERVER MODE")
		startServer(config)

	case "dual":
		// First, clear the logs so we can see what we're doing
		log.Println("----------------------------------------")
		log.Println("STARTING IN DUAL MODE WITH NETWORK OOB")
		log.Println("----------------------------------------")
		
		// Create a session manager for the server
		serverSessionManager := session.NewManager()
		
		// Determine port for the OOB server
		oobPort := 9008
		if config.RelayPort > 0 {
			oobPort = config.RelayPort
		}
		
		// Configure the server address
		oobAddr := fmt.Sprintf("0.0.0.0:%d", oobPort)
		
		// Start the server on the OOB port
		log.Printf("Starting OOB server on %s", oobAddr)
		go func() {
			serverProxy := server.NewServerProxy(serverSessionManager)
			if err := serverProxy.Start(oobAddr); err != nil {
				log.Fatalf("❌ Failed to start OOB server: %v", err)
			}
		}()
		
		// Start session cleanup
		go serverSessionManager.StartCleanup(60 * time.Second)
		
		// Wait for the server to start up
		time.Sleep(1 * time.Second)
		
		// Configure the client to use network OOB
		log.Printf("Starting client using network OOB to %s", oobAddr)
		
		// Create HTTP OOB client
		oobClient := &session.HTTPOOBClient{
			ServerAddress: oobAddr,
		}
		
		// Initialize session manager with HTTP client
		sessionManager := session.NewSessionManager(oobClient)
		
		// Initialize tunnel manager
		tunnelManager := relay.NewTunnelManager(sessionManager)
		
		// Clear client logs
		log.Printf("🔒 NETWORK MODE: Using HTTP API for OOB communication")
		log.Printf("🔒 Using OOB server at %s", oobAddr)
		
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

	default:
		fmt.Println("Invalid mode:", config.Mode)
		os.Exit(1)
	}
}

func startClient(config *Config, serverManager *session.Manager) {
	// Create a direct OOB client that points to the server session manager
	oobClient := &session.DirectOOB{
		Manager: serverManager,
	}

	// Print clear log indicating we're using direct function calls, not HTTP API
	log.Printf("🔹 DIRECT MODE: Using local function calls for OOB communication (no HTTP API)")
	log.Printf("🔹 Using direct OOB communication")

	// Initialize session manager
	sessionManager := session.NewSessionManager(oobClient)

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

func startClientWithHTTP(config *Config) {
	// Configure server address to always use the relay port
	// This ensures we're using HTTP API even in dual mode
	serverAddr := fmt.Sprintf("localhost:%d", config.RelayPort)

	// Create an HTTP OOB client that connects to the server
	oobClient := &session.HTTPOOBClient{
		ServerAddress: serverAddr,
	}

	// Print clear log indicating we're using HTTP API
	log.Printf("🔒 NETWORK MODE: Using HTTP API for OOB communication")
	log.Printf("🔒 Using OOB server at %s", serverAddr)

	// Initialize session manager
	sessionManager := session.NewSessionManager(oobClient)

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
	log.Println("SERVER FUNCTION CALLED")

	// Initialize session manager
	sessionManager := session.NewManager()

	// Start session cleanup
	go sessionManager.StartCleanup(60 * time.Second)

	// Start server with the new manager
	startServerWithManager(config, sessionManager)
}

func startServerWithManager(config *Config, sessionManager *session.Manager) {
	// Calculate server address for the OOB server, using 0.0.0.0 to listen on all interfaces
	serverAddr := fmt.Sprintf("0.0.0.0:%d", config.RelayPort)
	
	fmt.Printf("Server mode started on %s\n", serverAddr)

	// Initialize server proxy
	serverProxy := server.NewServerProxy(sessionManager)

	// Start server proxy on the relay port
	err := serverProxy.Start(serverAddr)
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
