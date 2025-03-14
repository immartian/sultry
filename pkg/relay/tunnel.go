package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
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

	log.Printf("✅ Established direct connection to %s", targetAddr)

	return conn, nil
}

// SignalHandshakeCompletion sends a message to the OOB server to signal that the handshake is complete
func (tm *TunnelManager) SignalHandshakeCompletion(sessionID string) error {
	reqBody := fmt.Sprintf(`{"session_id":"%s","action":"complete_handshake"}`, sessionID)

	// Use a client with short timeout to avoid hanging
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(
		fmt.Sprintf("http://%s/complete_handshake", tm.SessionManager.OOB.GetServerAddress()),
		"application/json",
		strings.NewReader(reqBody),
	)

	if err != nil {
		log.Printf("❌ Failed to signal handshake completion: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("❌ Server responded with non-OK status: %d - %s", resp.StatusCode, string(body))
		return fmt.Errorf("server responded with status %d", resp.StatusCode)
	}

	return nil
}

// GetTargetInfo retrieves information about the target server from the OOB server
func (tm *TunnelManager) GetTargetInfo(sessionID string, clientHelloData []byte) (*session.TargetInfo, error) {
	// Prepare request with both session ID and ClientHello data
	requestData := struct {
		SessionID   string `json:"session_id"`
		Action      string `json:"action"`
		ClientHello []byte `json:"client_hello,omitempty"`
	}{
		SessionID:   sessionID,
		Action:      "get_target_info",
		ClientHello: clientHelloData,
	}

	requestBytes, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send request to OOB server with timeout
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(
		fmt.Sprintf("http://%s/get_target_info", tm.SessionManager.OOB.GetServerAddress()),
		"application/json",
		bytes.NewReader(requestBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get target info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error: %s (code %d)", string(body), resp.StatusCode)
	}

	// Parse response
	var targetInfo session.TargetInfo
	if err := json.NewDecoder(resp.Body).Decode(&targetInfo); err != nil {
		return nil, fmt.Errorf("failed to decode target info: %w", err)
	}

	// Validate essential target info
	if targetInfo.TargetHost == "" || targetInfo.TargetPort == 0 {
		return nil, fmt.Errorf("received incomplete target info")
	}

	return &targetInfo, nil
}

// ReleaseConnection sends a request to the OOB server to release the connection
func (tm *TunnelManager) ReleaseConnection(sessionID string) error {
	reqBody := fmt.Sprintf(`{"session_id":"%s","action":"release_connection"}`, sessionID)

	// Use a client with short timeout to avoid hanging
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(
		fmt.Sprintf("http://%s/release_connection", tm.SessionManager.OOB.GetServerAddress()),
		"application/json",
		strings.NewReader(reqBody),
	)

	if err != nil {
		// Don't fail on release errors - they're common with direct fetch approach
		log.Printf("ℹ️ Warning: Unable to release connection: %v (this is normal with direct fetch)", err)
		return nil // Don't fail on release errors
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("ℹ️ Warning: Server returned non-OK status: %s (continuing anyway)", string(body))
		return nil // Don't fail on non-OK responses
	}

	return nil
}

// FallbackToRelayMode handles fallback when direct connection fails
func (tm *TunnelManager) FallbackToRelayMode(clientConn net.Conn, sessionID string) {
	log.Printf("🔹 Establishing relay connection for session %s", sessionID)

	// Create a connection to the OOB server
	serverAddr := tm.SessionManager.OOB.GetServerAddress()
	log.Printf("🔹 Connecting to relay server at %s", serverAddr)
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Printf("❌ ERROR: Failed to connect to OOB server: %v", err)
		return
	}
	defer conn.Close()
	log.Printf("✅ Connected to relay server")

	// Optimize TCP connection settings for both connections
	for _, c := range []net.Conn{conn, clientConn} {
		if tcpConn, ok := c.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
			tcpConn.SetReadBuffer(1048576)  // 1MB buffer
			tcpConn.SetWriteBuffer(1048576) // 1MB buffer
		}
	}
}