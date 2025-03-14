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

// Config represents configuration options for the proxy
type Config struct {
	Mode                      string
	LocalProxyAddr            string
	RemoteProxyAddr           string
	CoverSNI                  string
	PrioritizeSNI             bool
	OOBChannels               int
	FullClientHelloConcealment bool
	HandshakeTimeout          int
	ConnectionPoolSize        int
}

// OOBModule handles out-of-band communication
type OOBModule struct {
	ServerAddress string
}

// GetServerAddress returns the OOB server address
func (o *OOBModule) GetServerAddress() string {
	return o.ServerAddress
}

// NewOOBModule creates a new OOB module
func NewOOBModule(channels int) *OOBModule {
	return &OOBModule{
		ServerAddress: "localhost:9090",
	}
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
	
	flag.Parse()

	// Set up configuration
	config := &Config{
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
	oobModule := NewOOBModule(config.OOBChannels)
	
	// Initialize session manager
	sessionManager := session.NewSessionManager(oobModule)
	
	// Initialize tunnel manager
	tunnelManager := relay.NewTunnelManager(sessionManager)
	
	// Set up signal handling for graceful shutdown
	setupSignalHandling()
	
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
	
	// Set up signal handling for graceful shutdown
	setupSignalHandling()
	
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