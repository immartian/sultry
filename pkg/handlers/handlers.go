package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// handleCompleteHandshake handles the complete_handshake endpoint
// This endpoint is called when the handshake is complete and it's time to establish direct connection
func handleCompleteHandshake(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Action    string `json:"action"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	sessionsMu.Lock()
	session, exists := sessions[req.SessionID]
	sessionsMu.Unlock()

	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Mark handshake as complete
	session.HandshakeComplete = true
	log.Printf("✅ Handshake marked complete for session %s. Releasing connection.", req.SessionID)

	// Close connection after a brief delay to ensure all buffered data is sent
	go func() {
		time.Sleep(500 * time.Millisecond) // Ensure state sync before dropping connection
		
		if session.TargetConn != nil {
			session.TargetConn.Close()
		}
		
		// Remove the session to free up resources
		sessionsMu.Lock()
		delete(sessions, req.SessionID)
		sessionsMu.Unlock()
		
		log.Printf("🔹 Proxy connection closed for session %s", req.SessionID)
	}()

	w.WriteHeader(http.StatusOK)
}

// handleGetTargetInfo returns information about the target server for a session
// This is used by the client to establish a direct connection
func handleGetTargetInfo(w http.ResponseWriter, r *http.Request) {
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
	sessionsMu.Lock()
	session, exists := sessions[sessionID]
	sessionsMu.Unlock()

	if !exists || session.TargetConn == nil {
		log.Printf("❌ Session %s not found or invalid for target info", sessionID)
		http.Error(w, fmt.Sprintf("Session %s not found or invalid", sessionID), http.StatusNotFound)
		return
	}

	// Check if handshake is complete
	if !session.HandshakeComplete {
		log.Printf("❌ Handshake not complete for session %s, can't provide target info", sessionID)
		http.Error(w, fmt.Sprintf("Handshake not complete for session %s", sessionID), http.StatusBadRequest)
		return
	}

	// Get target connection information
	targetAddr := session.TargetConn.RemoteAddr().(*net.TCPAddr)
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
	if len(session.ClientMessages) > 0 {
		extractedSNI, err := extractSNIFromClientHello(session.ClientMessages[0])
		if err == nil && extractedSNI != "" {
			sni = extractedSNI
			log.Printf("🔹 Using original SNI from ClientHello: %s", sni)
		}
	}

	// Detect TLS version from the handshake
	var tlsVersion int = 0x0301 // Default to TLS 1.0
	if len(session.ServerResponses) > 0 && len(session.ServerResponses[0]) >= 5 {
		serverHello := session.ServerResponses[0]
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

// handleReleaseConnection releases a connection when it's no longer needed
func handleReleaseConnection(w http.ResponseWriter, r *http.Request) {
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

	sessionsMu.Lock()
	session, exists := sessions[req.SessionID]
	if exists {
		if session.TargetConn != nil {
			session.TargetConn.Close()
			log.Printf("🔹 Closed target connection for session %s", req.SessionID)
		}
		delete(sessions, req.SessionID)
		log.Printf("🔹 Released session %s", req.SessionID)
	}
	sessionsMu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// handleGetResponse returns the server response for a given session
func handleGetResponse(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	sessionsMu.Lock()
	session, exists := sessions[req.SessionID]
	sessionsMu.Unlock()

	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Update session activity time
	session.LastActivity = time.Now()

	// Check if there are any responses to return
	sessionsMu.Lock()
	var response []byte
	var handshakeComplete bool

	if len(session.ServerResponses) > 0 {
		response = session.ServerResponses[0]
		session.ServerResponses = session.ServerResponses[1:]
		log.Printf("🔹 Returning critical first server response (%d bytes)", len(response))
	}
	handshakeComplete = session.HandshakeComplete
	sessionsMu.Unlock()

	// Construct response
	resp := struct {
		Data             []byte `json:"data"`
		HandshakeComplete bool   `json:"handshake_complete"`
	}{
		Data:             response,
		HandshakeComplete: handshakeComplete,
	}

	// Set JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}