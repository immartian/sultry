package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sultry/pkg/session"
	"sultry/pkg/tls"
	"time"
)

// ServerProxy handles the server-side proxy functionality
type ServerProxy struct {
	SessionManager *session.Manager
	API            *http.ServeMux
}

// IsClient returns false because this is the server component
func (sp *ServerProxy) IsClient() bool {
	return false
}

// NewServerProxy creates a new server proxy
func NewServerProxy(sessionManager *session.Manager) *ServerProxy {
	sp := &ServerProxy{
		SessionManager: sessionManager,
		API:            http.NewServeMux(),
	}
	
	// Register API endpoints
	sp.registerEndpoints()
	
	return sp
}

// registerEndpoints registers the HTTP API endpoints
func (sp *ServerProxy) registerEndpoints() {
	// Register API endpoints
	sp.API.HandleFunc("/complete_handshake", sp.handleCompleteHandshake)
	sp.API.HandleFunc("/get_target_info", sp.handleGetTargetInfo)
	sp.API.HandleFunc("/release_connection", sp.handleReleaseConnection)
	sp.API.HandleFunc("/get_response", sp.handleGetResponse)
}

// Start runs the server proxy
func (sp *ServerProxy) Start(localAddr string) error {
	// Calculate API address based on the local address
	host, port, err := net.SplitHostPort(localAddr)
	if err != nil {
		return fmt.Errorf("invalid address format %s: %w", localAddr, err)
	}
	
	// Use the port + 1 for the API server
	apiPort, err := incrementPort(port)
	if err != nil {
		return fmt.Errorf("failed to calculate API port: %w", err)
	}
	
	apiAddr := net.JoinHostPort(host, apiPort)
	
	// Start the HTTP API server
	go func() {
		log.Printf("🔒 Sultry OOB API server listening on %s", apiAddr)
		if err := http.ListenAndServe(apiAddr, sp.API); err != nil {
			log.Printf("❌ Failed to start API server: %v", err)
			// Don't fatal here, as we might still be able to use direct OOB
		}
	}()
	
	// Start the TCP listener for OOB connections
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	
	log.Printf("🔒 Sultry OOB server listening on %s", localAddr)
	
	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("❌ Connection error: %v", err)
			continue
		}
		
		go sp.handleConnection(conn)
	}
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

// handleConnection processes incoming OOB connections
func (sp *ServerProxy) handleConnection(conn net.Conn) {
	defer conn.Close()
	
	log.Printf("🔹 Received OOB connection from %s", conn.RemoteAddr())
	
	// Generate a session ID for this connection
	sessionID := generateSessionID()
	
	// Create a new session for this connection
	sp.SessionManager.CreateSession(sessionID, "")
	
	// Set the target connection in the session
	// Note: In a real implementation, this would be connected to the actual target
	// For now, we're just storing the client connection
	sp.SessionManager.SetTargetConn(sessionID, conn)
	
	// Start bidirectional relay to the target
	// In a real implementation, this would handle the relaying to the target server
	go sp.handleTargetCommunication(sessionID, conn)
}

// HTTP API endpoint handlers
// These would be implemented to handle the various API endpoints
// For now, they're just placeholder stubs

func (sp *ServerProxy) handleCompleteHandshake(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Action    string `json:"action"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" {
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	// Get the session state
	session := sp.SessionManager.GetSession(req.SessionID)
	if session == nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Mark handshake as complete
	sp.SessionManager.MarkHandshakeComplete(req.SessionID)
	log.Printf("✅ Handshake completed for session %s", req.SessionID)

	w.WriteHeader(http.StatusOK)
}

func (sp *ServerProxy) handleGetTargetInfo(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID   string `json:"session_id"`
		Action      string `json:"action"`
		ClientHello []byte `json:"client_hello,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" {
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	// Get the session state
	session := sp.SessionManager.GetSession(req.SessionID)
	if session == nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Create target information from the session
	targetInfo := struct {
		TargetHost    string `json:"target_host"`
		TargetIP      string `json:"target_ip"`
		TargetPort    int    `json:"target_port"`
		SNI           string `json:"sni"`
		SessionTicket []byte `json:"session_ticket,omitempty"`
		Version       int    `json:"tls_version"`
	}{
		TargetHost: session.SNI,
		TargetPort: 443, // Default to HTTPS port
		SNI:        session.SNI,
		// Session ticket if available
		SessionTicket: session.SessionTicket,
	}

	// Add any resolved IP information if available
	// In a real implementation, this would be populated with actual target IP
	targetInfo.TargetIP = session.SNI // Placeholder, would normally resolve this

	// Return the target info as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(targetInfo); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (sp *ServerProxy) handleReleaseConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Action    string `json:"action"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" {
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	// Get the session state
	session := sp.SessionManager.GetSession(req.SessionID)
	if session == nil {
		// Session already released or not found - this is OK
		w.WriteHeader(http.StatusOK)
		return
	}

	// Remove the session
	sp.SessionManager.RemoveSession(req.SessionID)
	log.Printf("✅ Released connection for session %s", req.SessionID)

	w.WriteHeader(http.StatusOK)
}

// handleTargetCommunication handles communication with the target server
func (sp *ServerProxy) handleTargetCommunication(sessionID string, clientConn net.Conn) {
	log.Printf("🔹 Starting target communication for session %s", sessionID)
	
	// Get the session
	session := sp.SessionManager.GetSession(sessionID)
	if session == nil {
		log.Printf("❌ Session %s not found", sessionID)
		return
	}
	
	// In a real implementation, we would establish a connection to the target
	// and relay data between the client and target
	// For now, we'll just simulate some basic functionality
	
	// Buffer for reading from the client
	buffer := make([]byte, 16384)
	
	for {
		// Read from the client
		n, err := clientConn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("❌ Error reading from client: %v", err)
			}
			break
		}
		
		if n > 0 {
			// Process the client data
			data := buffer[:n]
			
			// Check if it's a TLS record
			if n >= 5 {
				recordType, version, _, err := tls.ParseTLSRecordHeader(data)
				if err == nil {
					log.Printf("🔹 Session %s: TLS Record Type=%d, Version=0x%04x", 
						sessionID, recordType, version)
					
					// Check for handshake completion
					if tls.IsHandshakeComplete(data) {
						log.Printf("✅ Session %s: Handshake complete", sessionID)
						sp.SessionManager.MarkHandshakeComplete(sessionID)
					}
					
					// Check for session ticket
					if tls.IsSessionTicketMessage(data) {
						log.Printf("🎫 Session %s: Session ticket received", sessionID)
						session.SessionTicket = make([]byte, n)
						copy(session.SessionTicket, data)
					}
				}
			}
			
			// Store the client message
			sp.SessionManager.StoreClientMessage(sessionID, data)
			
			// Create a mock response - in a real implementation, this would be
			// the response from the target server
			response := make([]byte, n)
			copy(response, data)
			
			// Store the response
			sp.SessionManager.StoreServerResponse(sessionID, response)
			
			// If this is the first message, try to extract SNI
			if len(session.ClientMessages) == 1 {
				sni, err := tls.ExtractSNIFromClientHello(data)
				if err == nil {
					session.SNI = sni
					log.Printf("✅ Session %s: Extracted SNI: %s", sessionID, sni)
				}
			}
		}
	}
	
	log.Printf("🔹 Target communication ended for session %s", sessionID)
}

// generateSessionID generates a unique session ID
func generateSessionID() string {
	return fmt.Sprintf("%d-%x", time.Now().UnixNano(), makeRandomBytesHex(8))
}

// makeRandomBytesHex generates random bytes as hex string
func makeRandomBytesHex(n int) string {
	bytes := make([]byte, n)
	for i := 0; i < n; i++ {
		bytes[i] = byte(time.Now().UnixNano() & 0xff)
		time.Sleep(1 * time.Nanosecond)
	}
	return fmt.Sprintf("%x", bytes)
}

func (sp *ServerProxy) handleGetResponse(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Action    string `json:"action"`
		Index     int    `json:"index"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" {
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	// Get the session state
	session := sp.SessionManager.GetSession(req.SessionID)
	if session == nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Use mutex to protect access to server responses
	session.Mu.Lock()
	defer session.Mu.Unlock()

	// Check if index is valid
	if req.Index < 0 || req.Index >= len(session.ServerResponses) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "no_data",
			"message": "No more responses",
		})
		return
	}

	// Get the response
	response := session.ServerResponses[req.Index]

	// Send the response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "success",
		"data":     response,
		"index":    req.Index,
		"has_more": req.Index+1 < len(session.ServerResponses),
	})
}