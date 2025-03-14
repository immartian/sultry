package client

import (
	"fmt"
	"log"
	"net"
	"sultry/pkg/connection"
	"sultry/pkg/relay"
	"sultry/pkg/session"
)

// ClientProxy handles the client-side proxy functionality with multiple connection strategies
type ClientProxy struct {
	SessionManager             *session.SessionManager
	TunnelManager              *relay.TunnelManager
	FakeSNI                    string
	PrioritizeSNI              bool
	FullClientHelloConcealment bool
	HandshakeTimeout           int
}

// NewClientProxy creates a new client proxy
func NewClientProxy(sessionManager *session.SessionManager, tunnelManager *relay.TunnelManager, options ...Option) *ClientProxy {
	cp := &ClientProxy{
		SessionManager: sessionManager,
		TunnelManager:  tunnelManager,
		HandshakeTimeout: 10000, // Default timeout: 10 seconds
	}
	
	// Apply options
	for _, opt := range options {
		opt(cp)
	}
	
	return cp
}

// Option is a functional option for configuring ClientProxy
type Option func(*ClientProxy)

// WithFakeSNI sets the fake SNI value
func WithFakeSNI(sni string) Option {
	return func(cp *ClientProxy) {
		cp.FakeSNI = sni
	}
}

// WithPrioritizeSNI sets whether to prioritize SNI concealment
func WithPrioritizeSNI(prioritize bool) Option {
	return func(cp *ClientProxy) {
		cp.PrioritizeSNI = prioritize
	}
}

// WithFullClientHelloConcealment sets whether to use full ClientHello concealment
func WithFullClientHelloConcealment(full bool) Option {
	return func(cp *ClientProxy) {
		cp.FullClientHelloConcealment = full
	}
}

// WithHandshakeTimeout sets the handshake timeout
func WithHandshakeTimeout(timeout int) Option {
	return func(cp *ClientProxy) {
		cp.HandshakeTimeout = timeout
	}
}

// Start runs the client proxy
func (cp *ClientProxy) Start(localAddr string) error {
	// Log configuration
	cp.logConfig()
	
	// Create listener
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to start client proxy: %w", err)
	}
	defer listener.Close()
	
	log.Printf("🔒 Sultry client proxy listening on %s", localAddr)
	
	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("❌ Connection error: %v", err)
			continue
		}
		
		go cp.handleConnection(conn)
	}
}

// Log the current configuration
func (cp *ClientProxy) logConfig() {
	if cp.PrioritizeSNI {
		if cp.FullClientHelloConcealment {
			log.Println("🔒 ENHANCED PROTECTION: Full ClientHello concealment enabled")
			log.Println("🔒 Complete TLS handshake will be relayed via OOB for maximum protection")
		} else {
			log.Println("🔒 SNI concealment prioritized - OOB will be used to protect server name only")
		}
	} else {
		log.Println("🔹 Standard mode - direct tunnel will be used with OOB as fallback")
	}
}

// handleConnection processes incoming connections and routes them to appropriate handlers
func (cp *ClientProxy) handleConnection(conn net.Conn) {
	defer conn.Close()
	
	log.Printf("🔹 Received connection from %s", conn.RemoteAddr())
	
	// Create connection handler with our options
	connHandler := connection.NewConnectionHandler(
		cp.SessionManager,
		cp.TunnelManager,
		connection.ConnectionOptions{
			PrioritizeSNI:              cp.PrioritizeSNI,
			FullClientHelloConcealment: cp.FullClientHelloConcealment,
			FakeSNI:                    cp.FakeSNI,
			HandshakeTimeout:           cp.HandshakeTimeout,
		},
	)
	
	// Handle the connection using our modular connection handler
	connHandler.HandleConnection(conn)
}