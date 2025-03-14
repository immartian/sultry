package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sultry/pkg/session"
	"sultry/pkg/tls"
	"time"
)

// HandleCompleteHandshake handles the complete_handshake endpoint
// This endpoint is called when the handshake is complete and it's time to establish direct connection
func HandleCompleteHandshake(w http.ResponseWriter, r *http.Request, manager *session.Manager) {
	var req struct {
		SessionID string `json:"session_id"`
		Action    string `json:"action"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	sessionState := manager.GetSession(req.SessionID)
	if sessionState == nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Mark handshake as complete
	manager.MarkHandshakeComplete(req.SessionID)
	log.Printf("✅ Handshake marked complete for session %s. Releasing connection.", req.SessionID)

	// Close connection after a brief delay to ensure all buffered data is sent
	go func() {
		time.Sleep(500 * time.Millisecond) // Ensure state sync before dropping connection

		// Remove the session to free up resources
		manager.RemoveSession(req.SessionID)

		log.Printf("🔹 Proxy connection closed for session %s", req.SessionID)
	}()

	w.WriteHeader(http.StatusOK)
}

// HandleGetTargetInfo returns information about the target server for a session
// This is used by the client to establish a direct connection
func HandleGetTargetInfo(w http.ResponseWriter, r *http.Request, manager *session.Manager) {
	// Parse request
	var req struct {
		SessionID   string `json:"session_id"`
		Action      string `json:"action"`
		ClientHello []byte `json:"client_hello,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("❌ Invalid target info request: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	sessionID := req.SessionID
	if sessionID == "" {
		log.Printf("❌ Missing session ID in target info request")
		http.Error(w, "Session ID is required", http.StatusBadRequest)
		return
	}

	log.Printf("🔹 Received target info request for session %s", sessionID)

	// Get the session
	sessionState := manager.GetSession(sessionID)
	if sessionState == nil || sessionState.TargetConn == nil {
		log.Printf("❌ Session %s not found or invalid for target info", sessionID)
		http.Error(w, fmt.Sprintf("Session %s not found or invalid", sessionID), http.StatusNotFound)
		return
	}

	// Check if handshake is complete
	if !sessionState.HandshakeComplete {
		log.Printf("❌ Handshake not complete for session %s, can't provide target info", sessionID)
		http.Error(w, fmt.Sprintf("Handshake not complete for session %s", sessionID), http.StatusBadRequest)
		return
	}

	// Get target connection information
	targetAddr := sessionState.TargetConn.RemoteAddr().(*net.TCPAddr)
	targetHost := targetAddr.IP.String()
	targetPort := targetAddr.Port

	// Resolve IP to hostname if possible
	hostnames, err := net.LookupAddr(targetHost)
	if err == nil && len(hostnames) > 0 {
		// Use the first hostname and remove the trailing dot
		hostname := hostnames[0]
		if hostname[len(hostname)-1] == '.' {
			hostname = hostname[:len(hostname)-1]
		}
		log.Printf("🔹 Resolved %s to hostname %s", targetHost, hostname)
		targetHost = hostname
	}

	// Use the SNI as the hostname if available
	var sni string = targetHost // Default to IP/hostname
	if len(sessionState.ClientMessages) > 0 {
		extractedSNI, err := tls.ExtractSNIFromClientHello(sessionState.ClientMessages[0])
		if err == nil && extractedSNI != "" {
			sni = extractedSNI
			log.Printf("🔹 Using original SNI from ClientHello: %s", sni)
		}
	}

	// Detect TLS version from the handshake
	var tlsVersion int = 0x0301 // Default to TLS 1.0
	if len(sessionState.ServerResponses) > 0 && len(sessionState.ServerResponses[0]) >= 5 {
		serverHello := sessionState.ServerResponses[0]
		// Extract TLS version from ServerHello
		tlsVersion = int(uint16(serverHello[1])<<8 | uint16(serverHello[2]))
		log.Printf("🔹 Detected TLS version: 0x%04x", tlsVersion)
	}

	// Prepare response
	response := struct {
		TargetHost    string `json:"target_host"`
		TargetIP      string `json:"target_ip"`
		TargetPort    int    `json:"target_port"`
		SNI           string `json:"sni"`
		SessionTicket []byte `json:"session_ticket,omitempty"`
		Version       int    `json:"tls_version"`
	}{
		TargetHost: targetHost,
		TargetIP:   targetAddr.IP.String(),
		TargetPort: targetPort,
		SNI:        sni,
		Version:    tlsVersion,
	}

	// Set JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ Sent target info for session %s: %s:%d", sessionID, targetHost, targetPort)
}

// HandleReleaseConnection releases a connection when it's no longer needed
func HandleReleaseConnection(w http.ResponseWriter, r *http.Request, manager *session.Manager) {
	var req struct {
		SessionID string `json:"session_id"`
		Action    string `json:"action"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" {
		http.Error(w, "Session ID is required", http.StatusBadRequest)
		return
	}

	// Check if the session exists
	sessionState := manager.GetSession(req.SessionID)
	if sessionState != nil {
		// Remove the session
		manager.RemoveSession(req.SessionID)
		log.Printf("🔹 Released session %s", req.SessionID)
	}

	w.WriteHeader(http.StatusOK)
}

// HandleGetResponse returns the server response for a given session
func HandleGetResponse(w http.ResponseWriter, r *http.Request, manager *session.Manager) {
	var req struct {
		SessionID string `json:"session_id"`
		Index     int    `json:"index"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	sessionState := manager.GetSession(req.SessionID)
	if sessionState == nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Lock the session for reading responses
	sessionState.Mu.Lock()
	defer sessionState.Mu.Unlock()

	// Check if there are any responses to return
	var response []byte
	var handshakeComplete bool

	// If index is provided, use it, otherwise get the first response
	if req.Index >= 0 && req.Index < len(sessionState.ServerResponses) {
		response = sessionState.ServerResponses[req.Index]
		log.Printf("🔹 Returning server response at index %d (%d bytes)", req.Index, len(response))
	} else if len(sessionState.ServerResponses) > 0 {
		response = sessionState.ServerResponses[0]
		sessionState.ServerResponses = sessionState.ServerResponses[1:]
		log.Printf("🔹 Returning first server response (%d bytes)", len(response))
	}
	handshakeComplete = sessionState.HandshakeComplete

	// Construct response
	resp := struct {
		Data              []byte `json:"data"`
		HandshakeComplete bool   `json:"handshake_complete"`
	}{
		Data:              response,
		HandshakeComplete: handshakeComplete,
	}

	// Set JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
