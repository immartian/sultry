package main

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
)

// establishDirectConnectionAfterHandshake creates a direct connection to the target server
// after the handshake is complete
func (p *TLSProxy) establishDirectConnectionAfterHandshake(sessionID string) (net.Conn, error) {
	log.Printf("🔹 Establishing direct connection for session %s", sessionID)

	// First, get target information from the OOB server
	targetInfo, err := p.getTargetInfo(sessionID, nil)
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

	log.Printf("✅ Established direct connection to %s for session %s", targetAddr, sessionID)

	// Note: In a future version, we could include session ticket and other TLS state
	// data to allow for even more seamless resumption of the TLS session without
	// requiring a full handshake again.

	return conn, nil
}

// signalHandshakeCompletion sends a message to the OOB server to signal that the handshake is complete
func (p *TLSProxy) signalHandshakeCompletion(sessionID string) error {
	reqBody := fmt.Sprintf(`{"session_id":"%s","action":"complete_handshake"}`, sessionID)

	// Use a client with short timeout to avoid hanging
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(
		fmt.Sprintf("http://%s/complete_handshake", p.OOB.GetServerAddress()),
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

// getTargetInfo retrieves information about the target server from the OOB server
func (p *TLSProxy) getTargetInfo(sessionID string, clientHelloData []byte) (*TargetInfo, error) {
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
		fmt.Sprintf("http://%s/get_target_info", p.OOB.GetServerAddress()),
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
	var targetInfo TargetInfo
	if err := json.NewDecoder(resp.Body).Decode(&targetInfo); err != nil {
		return nil, fmt.Errorf("failed to decode target info: %w", err)
	}

	// Validate essential target info
	if targetInfo.TargetHost == "" || targetInfo.TargetPort == 0 {
		return nil, fmt.Errorf("received incomplete target info")
	}

	return &targetInfo, nil
}

// releaseOOBConnection sends a request to the OOB server to release the connection
func (p *TLSProxy) releaseOOBConnection(sessionID string) error {
	reqBody := fmt.Sprintf(`{"session_id":"%s","action":"release_connection"}`, sessionID)

	// Use a client with short timeout to avoid hanging
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(
		fmt.Sprintf("http://%s/release_connection", p.OOB.GetServerAddress()),
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