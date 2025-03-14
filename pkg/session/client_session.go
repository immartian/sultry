package session

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// TargetInfo holds information about the target server
type TargetInfo struct {
	TargetHost    string   `json:"target_host"`
	TargetIP      string   `json:"target_ip"`
	TargetPort    int      `json:"target_port"`
	SNI           string   `json:"sni"`
	SessionTicket []byte   `json:"session_ticket"`
	MasterSecret  []byte   `json:"master_secret"`
	Version       int      `json:"tls_version"`
	ALPN          string   `json:"alpn_protocol"`  // The negotiated ALPN protocol (h2, http/1.1, etc.)
}

// OOBClient defines an interface for Out-of-Band communications
type OOBClient interface {
	GetServerAddress() string
}

// SessionManager manages client-side session operations
type SessionManager struct {
	OOB OOBClient
}

// NewSessionManager creates a new session manager
func NewSessionManager(oobClient OOBClient) *SessionManager {
	return &SessionManager{
		OOB: oobClient,
	}
}

// SignalHandshakeCompletion signals to the server that handshake is complete
func (sm *SessionManager) SignalHandshakeCompletion(sessionID string) error {
	// Signal to the server that handshake is complete
	reqBody := fmt.Sprintf(`{"session_id":"%s", "action":"complete_handshake"}`, sessionID)
	resp, err := http.Post(
		fmt.Sprintf("http://%s/complete_handshake", sm.OOB.GetServerAddress()),
		"application/json",
		strings.NewReader(reqBody),
	)

	if err != nil {
		return fmt.Errorf("failed to signal handshake completion: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server rejected handshake completion: %s", string(body))
	}

	return nil
}

// GetTargetInfo retrieves information about the target server for a session
func (sm *SessionManager) GetTargetInfo(sessionID string, clientHelloData []byte) (*TargetInfo, error) {
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
		fmt.Sprintf("http://%s/get_target_info", sm.OOB.GetServerAddress()),
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

// ReleaseConnection signals to the server to release an OOB connection
func (sm *SessionManager) ReleaseConnection(sessionID string) error {
	reqBody := fmt.Sprintf(`{"session_id":"%s","action":"release_connection"}`, sessionID)

	// Use a client with short timeout to avoid hanging
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(
		fmt.Sprintf("http://%s/release_connection", sm.OOB.GetServerAddress()),
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