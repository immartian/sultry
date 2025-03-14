package relay

import (
	"fmt"
	"log"
	"net"
	"time"

	"sultry/pkg/session"
)

// TunnelManager handles tunneling and direct connection establishment
type TunnelManager struct {
	SessionManager *session.SessionManager
}

// NewTunnelManager creates a new tunnel manager
func NewTunnelManager(sessionManager *session.SessionManager) *TunnelManager {
	return &TunnelManager{
		SessionManager: sessionManager,
	}
}

// EstablishDirectConnectionAfterHandshake creates a direct connection to the target server
// after the handshake is complete
func (tm *TunnelManager) EstablishDirectConnectionAfterHandshake(sessionID string) (net.Conn, error) {
	log.Printf("🔹 Establishing direct connection for session %s", sessionID)

	// First, get target information from the OOB server
	targetInfo, err := tm.SessionManager.GetTargetInfo(sessionID, nil)
	if err != nil {
		log.Printf("❌ Failed to get target information: %v", err)
		return nil, err
	}

	// Log what we're connecting to
	log.Printf("🔹 Target information: Host=%s, IP=%s, Port=%d",
		targetInfo.TargetHost, targetInfo.TargetIP, targetInfo.TargetPort)

	// Connect to the target IP directly
	targetAddr := fmt.Sprintf("%s:%d", targetInfo.TargetIP, targetInfo.TargetPort)
	log.Printf("🔹 Connecting directly to %s", targetAddr)

	conn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("❌ Failed to connect to target: %v", err)
		return nil, err
	}

	log.Printf("✅ Direct connection established to %s", targetAddr)

	// Optimize connection
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		log.Printf("🔹 TCP connection optimized")
	}

	// Important: This exact log message format is expected by the test script
	log.Printf("✅ Established direct connection to %s", targetAddr)

	return conn, nil
}

// SignalHandshakeCompletion signals to the server that the handshake is complete
func (tm *TunnelManager) SignalHandshakeCompletion(sessionID string) error {
	log.Printf("🔹 Signaling handshake completion for session %s", sessionID)
	return tm.SessionManager.SignalHandshakeCompletion(sessionID)
}

// ReleaseConnection releases the connection on the server
func (tm *TunnelManager) ReleaseConnection(sessionID string) error {
	log.Printf("🔹 Releasing connection for session %s", sessionID)
	return tm.SessionManager.ReleaseConnection(sessionID)
}

// FallbackToRelayMode handles fallback when direct connection fails
func (tm *TunnelManager) FallbackToRelayMode(clientConn net.Conn, sessionID string) {
	log.Printf("🔹 Falling back to relay mode for session %s", sessionID)
	log.Printf("ℹ️ Warning: Relay mode not implemented in direct OOB mode")
}
