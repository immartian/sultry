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
	"strconv"
	"sultry/pkg/client"
	"sultry/pkg/relay"
	"sultry/pkg/server"
	"sultry/pkg/session"
	"syscall"
	"time"
)

// OOBModule handles out-of-band communication
type OOBModule struct {
	ServerAddress string
}

// GetServerAddress returns the OOB server address
func (o *OOBModule) GetServerAddress() string {
	return o.ServerAddress
}

// SignalHandshakeCompletionDirect implements OOBClient interface
func (o *OOBModule) SignalHandshakeCompletionDirect(sessionID string) error {
	// This is a remote module, so this method shouldn't be called directly
	log.Printf("⚠️ Warning: Called direct method on remote OOB module")
	return fmt.Errorf("direct methods not available on remote OOB modules")
}

// GetTargetInfoDirect implements OOBClient interface
func (o *OOBModule) GetTargetInfoDirect(sessionID string, clientHello []byte) (*session.TargetInfo, error) {
	// This is a remote module, so this method shouldn't be called directly
	log.Printf("⚠️ Warning: Called direct method on remote OOB module")
	return nil, fmt.Errorf("direct methods not available on remote OOB modules")
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
	directOOB := flag.Bool("direct-oob", false, "Use direct OOB communication (no HTTP API)")
	
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
			DirectOOB:                 *directOOB,
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

	// Special case for direct OOB in non-dual mode
	if config.DirectOOB && config.Mode != "dual" {
		if config.Mode == "client" {
			// Create a local server session manager
			serverSessionManager := session.NewManager()
			
			// Start session cleanup in the background
			go serverSessionManager.StartCleanup(60 * time.Second)
			
			// Start client with direct access
			startClient(config, serverSessionManager)
		} else {
			log.Println("⚠️ Warning: direct-oob flag has no effect in server-only mode")
			startServer(config)
		}
		return
	}
	
	// Log the final config
	log.Printf("USING MODE: %s", config.Mode)
	
	// Manual override for debug purposes
	if flag.Lookup("mode").Value.String() == "server" {
		log.Println("FORCING SERVER MODE FROM FLAG")
		config.Mode = "server"
	}
	
	// Regular mode handling
	switch config.Mode {
	case "client":
		log.Println("STARTING IN CLIENT MODE")
		startClient(config, nil)
	case "server":
		log.Println("STARTING IN SERVER MODE")
		startServer(config)
	case "dual":
		// Create a session manager first for direct use
		serverSessionManager := session.NewManager()
		
		// Start the client with direct access to the server session manager
		go startClient(config, serverSessionManager)
		
		// Start session cleanup in the background
		go serverSessionManager.StartCleanup(60 * time.Second)
		
		// Start the server with the same session manager
		startServerWithManager(config, serverSessionManager)
	default:
		fmt.Println("Invalid mode:", config.Mode)
		os.Exit(1)
	}
}

func startClient(config *Config, serverManager *session.Manager) {
	var oobClient session.OOBClient
	
	// If we have a server manager, use direct OOB
	if serverManager != nil {
		log.Println("🔹 Using direct OOB implementation for local communication")
		oobClient = &session.DirectOOB{
			Manager: serverManager,
		}
	} else {
		// Use HTTP OOB for remote communication
		log.Println("🔹 Using HTTP OOB implementation for remote communication")
		// Calculate API address based on the remote address
		host, port, err := net.SplitHostPort(config.RemoteProxyAddr)
		if err != nil {
			log.Printf("⚠️ Invalid remote address format %s, using as-is", config.RemoteProxyAddr)
			oobClient = &OOBModule{
				ServerAddress: config.RemoteProxyAddr,
			}
		} else {
			// Use port+1 for API as we did in the server
			apiPort, err := incrementPort(port)
			if err != nil {
				log.Printf("⚠️ Failed to calculate API port: %v, using original port", err)
				oobClient = &OOBModule{
					ServerAddress: config.RemoteProxyAddr,
				}
			} else {
				apiAddr := net.JoinHostPort(host, apiPort)
				log.Printf("🔹 Using API address %s", apiAddr)
				oobClient = &OOBModule{
					ServerAddress: apiAddr,
				}
			}
		}
	}
	
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
	fmt.Printf("Server mode started on %s (API on port+1)\n", config.LocalProxyAddr)
	
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

// incrementPort adds 1 to the port number
func incrementPort(portStr string) (string, error) {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", err
	}
	
	// Increment port by 1
	port++
	
	// Ensure we're in valid range
	if port > 65535 {
		return "", fmt.Errorf("port number exceeds maximum (65535)")
	}
	
	return strconv.Itoa(port), nil
}
