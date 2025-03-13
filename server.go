// Server component of the Sultry proxy system.
//
// This component is responsible for:
// 1. Establishing connections to target servers
// 2. Handling TLS handshakes with targets
// 3. Relaying data between client component and targets
// 4. Managing out-of-band (OOB) communication for SNI concealment
//
// The server component plays a crucial role in the SNI concealment strategy:
// - It receives ClientHello messages from the client component via HTTP
// - It connects to the real target server and forwards the ClientHello
// - It relays the ServerHello and subsequent handshake messages back to the client
// - After handshake completion, it helps establish a direct connection for data transfer
//
// By handling the TLS handshake through HTTP, this approach conceals the SNI
// information from network monitors/firewalls that might be inspecting the traffic
// between the client and the proxy server.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SessionState represents the state of a TLS session.
type SessionState struct {
	TargetConn        net.Conn
	HandshakeComplete bool
	LastActivity      time.Time
	ServerResponses   [][]byte
	ClientMessages    [][]byte
	ResponseQueue     chan []byte
	Adopted           bool
	ServerMsgIndex    int        // Index into ServerResponses for direct access
	mu                sync.Mutex // Protects all fields in this struct
}

// Global session store
var (
	sessions   = make(map[string]*SessionState)
	sessionsMu sync.Mutex
)

func server(config *Config) {
	// Configure more verbose logging
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	log.Println("🚀 Starting Sultry server component...")
	log.Println("📝 Configuration:", fmt.Sprintf("%+v", *config))

	// Set up HTTP handlers for different endpoints
	http.HandleFunc("/", legacyServe)              // Legacy endpoint for backward compatibility
	http.HandleFunc("/handshake", handleHandshake) // New endpoint for handshake messages
	http.HandleFunc("/appdata", handleAppData)     // New endpoint for application data
	http.HandleFunc("/complete_handshake", handleCompleteHandshake)
	http.HandleFunc("/adopt_connection", handleAdoptConnection)
	http.HandleFunc("/get_target_info", handleGetTargetInfo)        // New endpoint for getting target server information
	http.HandleFunc("/release_connection", handleReleaseConnection) // New endpoint for releasing connections
	http.HandleFunc("/get_response", handleGetResponse)             // New endpoint for getting server responses
	http.HandleFunc("/send_data", handleSendData)                   // New endpoint for sending client data
	http.HandleFunc("/create_connection", handleCreateConnection)   // New endpoint for simplified SNI concealment
	http.HandleFunc("/tunnel", handleTunnel)                        // New endpoint for direct TCP tunneling

	// Log all registered routes
	log.Println("📌 Registered HTTP handlers:")
	log.Println("   - /                   (Legacy endpoint)")
	log.Println("   - /handshake          (Handshake message handler)")
	log.Println("   - /appdata            (Application data handler)")
	log.Println("   - /complete_handshake (Handshake completion handler)")
	log.Println("   - /adopt_connection   (Connection adoption handler)")
	log.Println("   - /get_target_info    (Target info handler)")
	log.Println("   - /release_connection (Connection release handler)")
	log.Println("   - /get_response       (Response retrieval handler)")
	log.Println("   - /send_data          (Data sending handler)")
	log.Println("   - /create_connection  (SNI resolution handler)")

	// Start cleanup goroutine
	go cleanupInactiveSessions()

	log.Println("🔹 TLS Relay service listening on port", config.RelayPort)
	log.Println("✅ Server ready to accept connections")
	log.Fatal(http.ListenAndServe(":"+fmt.Sprint(config.RelayPort), nil))
}

// Legacy handler for backward compatibility
func legacyServe(w http.ResponseWriter, r *http.Request) {
	var req ClientHelloRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	clientHello := req.Data
	sni := req.SNI

	if len(clientHello) == 0 {
		http.Error(w, "ClientHello data is required", http.StatusBadRequest)
		return
	}

	log.Println("🔹 Performing TLS handshake with real server for:", sni)

	// Forward the ClientHello to the real target
	serverHello, err := forwardClientHello(clientHello, sni)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch ServerHello: %v", err), http.StatusInternalServerError)
		return
	}

	w.Write(serverHello)
}

// Handler for new handshake messages
func handleHandshake(w http.ResponseWriter, r *http.Request) {
	var req HandshakeMessageRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	sessionID := req.SessionID
	clientMsg := req.Data
	sni := req.SNI

	if len(clientMsg) == 0 {
		http.Error(w, "Client message data is required", http.StatusBadRequest)
		return
	}

	// Check if this is a new session
	sessionsMu.Lock()
	session, exists := sessions[sessionID]
	sessionsMu.Unlock()

	if !exists {
		// This is a new session, initialize it
		log.Printf("🔹 Initiating new TLS handshake session %s for SNI: %s", sessionID, sni)
		err = handleOOBRequest(sessionID, clientMsg, sni)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to initialize handshake: %v", err), http.StatusInternalServerError)
			return
		}

		// Get the first server response (ServerHello)
		sessionsMu.Lock()
		session = sessions[sessionID]
		sessionsMu.Unlock()

		if session == nil {
			http.Error(w, "Session initialization failed", http.StatusInternalServerError)
			return
		}

		// Wait for the first response from the server
		select {
		case serverResponse := <-session.ResponseQueue:
			w.Write(serverResponse)
		case <-time.After(30 * time.Second):
			http.Error(w, "Timeout waiting for server response", http.StatusGatewayTimeout)
		}
		return
	}

	// This is an existing session, forward the client message
	isComplete, err := handleClientMessage(sessionID, clientMsg)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to process client message: %v", err), http.StatusInternalServerError)
		return
	}

	// If the handshake is complete, return an empty response to signal completion
	if isComplete {
		w.Write([]byte{})
		return
	}

	// Wait for the server's response
	select {
	case serverResponse := <-session.ResponseQueue:
		w.Write(serverResponse)
	case <-time.After(30 * time.Second):
		http.Error(w, "Timeout waiting for server response", http.StatusGatewayTimeout)
	}
}

// Handler for application data
func handleAppData(w http.ResponseWriter, r *http.Request) {
	var req AppDataRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	sessionID := req.SessionID
	data := req.Data

	if len(data) == 0 {
		http.Error(w, "Application data is required", http.StatusBadRequest)
		return
	}

	// Check if the session exists
	sessionsMu.Lock()
	session, exists := sessions[sessionID]
	sessionsMu.Unlock()

	if !exists || !session.HandshakeComplete {
		http.Error(w, "Invalid session or handshake not complete", http.StatusBadRequest)
		return
	}

	// Forward the application data to the target with timeout
	session.TargetConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = session.TargetConn.Write(data)
	session.TargetConn.SetWriteDeadline(time.Time{})
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to write application data: %v", err), http.StatusInternalServerError)
		return
	}

	// Application data was sent successfully
	session.LastActivity = time.Now()
	w.WriteHeader(http.StatusOK)
}

// Initialize a new OOB handshake session
func handleOOBRequest(sessionID string, clientHello []byte, sni string) error {
	// Connect to the target server with optimized settings
	// Use a dialer with timeout for better connection performance
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	targetConn, err := dialer.Dial("tcp", sni+":443")
	if err != nil {
		log.Printf("❌ Failed to connect to %s: %v", sni, err)
		return fmt.Errorf("failed to connect to %s: %w", sni, err)
	}

	if tcpConn, ok := targetConn.(*net.TCPConn); ok {
		// Optimize TCP settings for TLS handshake performance
		tcpConn.SetNoDelay(true) // Disable Nagle's algorithm
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetReadBuffer(32768)  // 32KB read buffer
		tcpConn.SetWriteBuffer(32768) // 32KB write buffer
	}
	log.Printf("🔒 Connected to target server via SNI-concealed channel: %s", sni)

	// Create a new session
	session := &SessionState{
		TargetConn:        targetConn,
		HandshakeComplete: false,
		LastActivity:      time.Now(),
		ServerResponses:   make([][]byte, 0),
		ResponseQueue:     make(chan []byte, 100), // Much larger buffer
	}

	// Store the session
	sessionsMu.Lock()
	sessions[sessionID] = session
	sessionsMu.Unlock()

	// Send ClientHello to target
	_, err = targetConn.Write(clientHello)
	if err != nil {
		log.Printf("❌ Failed to send ClientHello to target: %v", err)
		return fmt.Errorf("failed to send ClientHello to target: %w", err)
	}

	log.Printf("🔹 Sent ClientHello to target server for session: %s", sessionID)

	// Start reading responses from target
	go handleTargetResponses(sessionID, targetConn)

	return nil
}

// In handleTargetResponses function in server.go:
func handleTargetResponses(sessionID string, targetConn net.Conn) {
	defer func() {
		log.Printf("🔹 Closing target connection for session %s", sessionID)
		targetConn.Close()
	}()

	// Use a larger buffer for more reliable handshake processing
	buffer := make([]byte, 1048576) // Increase buffer size to 1MB for large TLS records

	// When session is adopted, we should stop processing in this function
	var directConnStarted bool = false

	// We don't want to send ChangeCipherSpec during this phase anymore
	// It's better to let the normal TLS handshake complete naturally

	for {
		// Check if the session has been adopted and hijacked to a direct connection
		sessionsMu.Lock()
		session, exists := sessions[sessionID]
		sessionAdopted := exists && session.Adopted
		sessionsMu.Unlock()

		if sessionAdopted && !directConnStarted {
			// Session has been adopted, but direct connection hasn't been fully established yet
			log.Printf("🔹 Session %s is adopted, waiting for direct connection setup...", sessionID)
			directConnStarted = true

			// We'll continue reading data for a short time to make sure the transition is smooth
			// After this cycle, we'll keep checking if the session still exists
		} else if sessionAdopted && directConnStarted {
			// Check if the session still exists - if not, direct relay is fully taking over
			sessionsMu.Lock()
			_, stillExists := sessions[sessionID]
			sessionsMu.Unlock()

			if !stillExists {
				log.Printf("🔹 Session %s has been transferred to direct relay, stopping target reader", sessionID)
				return
			}
		}

		// Read response from target server with reasonable timeout
		targetConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := targetConn.Read(buffer)
		targetConn.SetReadDeadline(time.Time{}) // Reset the deadline after read

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("⚠️ Read timeout from target server for session %s, continuing", sessionID)
				continue
			} else if err != io.EOF {
				log.Printf("❌ ERROR reading from target: %v", err)
			} else {
				log.Printf("🔹 Target server closed connection for session %s", sessionID)
			}

			// IMPORTANT: Signal any waiting clients about connection close
			sessionsMu.Lock()
			session, exists := sessions[sessionID]
			if exists && !session.Adopted {
				// Send empty response to unblock any waiting clients
				select {
				case session.ResponseQueue <- []byte{}:
					// Signaled waiting client
				default:
					// No clients waiting, that's OK
				}
			}
			sessionsMu.Unlock()
			break
		}

		// Store and forward the response data
		responseData := buffer[:n]

		sessionsMu.Lock()
		session, exists = sessions[sessionID]
		if exists {
			// Always keep track of server responses
			session.ServerResponses = append(session.ServerResponses, responseData)

			// Always log what we received
			if !session.Adopted {
				session.ResponseQueue <- responseData
				log.Printf("🔹 Queued handshake response (%d bytes) for session %s", len(responseData), sessionID)
			} else {
				// When adopted, don't queue to ResponseQueue, but log what was received
				// This data will be handled by the direct connection
				log.Printf("🔹 Session %s is adopted, target sent %d bytes (handled by direct connection)",
					sessionID, len(responseData))

				// Check first few bytes of response data to help debug
				if len(responseData) > 0 {
					if len(responseData) >= 5 {
						recordType := responseData[0]
						// Only interpret as TLS record if it's a valid TLS record type (20-24)
						if recordType >= 20 && recordType <= 24 {
							version := (uint16(responseData[1]) << 8) | uint16(responseData[2])
							length := (uint16(responseData[3]) << 8) | uint16(responseData[4])
							log.Printf("🔹 Target TLS record: Type=%d, Version=0x%04x, Length=%d",
								recordType, version, length)
							log.Printf("🔹 First 16 bytes: %x", responseData[:min(16, len(responseData))])
						} else {
							// This is likely application data
							log.Printf("🔹 Target application data: %d bytes", len(responseData))
						}
					} else {
						log.Printf("🔹 Short data: %x", responseData)
					}
				}
			}
		}
		sessionsMu.Unlock()
	}
}

// Handle a message from the client
func handleClientMessage(sessionID string, message []byte) (bool, error) {
	sessionsMu.Lock()
	session, exists := sessions[sessionID]
	sessionsMu.Unlock()

	if !exists {
		return false, fmt.Errorf("session %s not found", sessionID)
	}

	// Update last activity
	session.LastActivity = time.Now()

	// Forward the message to the target with timeout
	session.TargetConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := session.TargetConn.Write(message)
	session.TargetConn.SetWriteDeadline(time.Time{})
	if err != nil {
		log.Printf("❌ Failed to write client message to target: %v", err)
		return false, fmt.Errorf("failed to write client message: %w", err)
	}

	// Analyze if this message completes the handshake
	_, isComplete := analyzeHandshakeStatus(message)

	// Mark the handshake as complete if determined
	if isComplete {
		session.HandshakeComplete = true
	}

	return isComplete, nil
}

// Analyze if a message is part of the handshake and if it completes the handshake
func analyzeHandshakeStatus(data []byte) (isHandshake bool, isComplete bool) {
	if len(data) < 5 {
		return false, false
	}

	recordType := data[0]

	// TLS handshake record type is 22
	isHandshake = (recordType == 22)

	// Don't try to detect handshake completion by record inspection
	// Instead, rely on receiving application data or the client's explicit signal

	return isHandshake, false // Never auto-complete based on record inspection
}

// Periodic cleanup of inactive sessions
func cleanupInactiveSessions() {
	for {
		time.Sleep(60 * time.Second)

		sessionsMu.Lock()
		now := time.Now()

		for sessionID, session := range sessions {
			// Clean up sessions inactive for more than 10 minutes
			if now.Sub(session.LastActivity) > 10*time.Minute {
				log.Printf("🧹 Cleaning up inactive session %s", sessionID)

				if session.TargetConn != nil {
					session.TargetConn.Close()
				}

				delete(sessions, sessionID)
			}
		}

		sessionsMu.Unlock()
	}
}

// Legacy function for backward compatibility
func forwardClientHello(clientHelloData []byte, sni string) ([]byte, error) {
	log.Println("🔹 Starting TLS handshake with:", sni)

	// Connect to the target server
	conn, err := net.Dial("tcp", sni+":443")
	if err != nil {
		log.Printf("❌ Failed to connect to %s: %v", sni, err)
		return nil, fmt.Errorf("failed to connect to %s: %w", sni, err)
	}
	defer conn.Close()

	log.Println("🔹 Connected to:", sni)

	// Analyze the ClientHello data
	recordType, version, msgLen, err := parseRecordHeader(clientHelloData)
	if err != nil {
		return nil, err
	}

	log.Printf("🔹 ClientHello details: RecordType=%d, Version=0x%x, Length=%d",
		recordType, version, msgLen)

	// Check if it's a valid TLS handshake message
	if recordType != 22 { // 22 is the value for Handshake
		return nil, fmt.Errorf("not a handshake message (type=%d)", recordType)
	}

	// Forward the ClientHello as-is
	_, err = conn.Write(clientHelloData)
	if err != nil {
		log.Printf("❌ Failed to write ClientHello: %v", err)
		return nil, fmt.Errorf("failed to write ClientHello: %w", err)
	}

	log.Println("🔹 Sent ClientHello to server, waiting for response")

	// Read the ServerHello response
	// First, read the TLS record header (5 bytes)
	recordHeader := make([]byte, 5)
	_, err = conn.Read(recordHeader)
	if err != nil {
		log.Printf("❌ Failed to read ServerHello header: %v", err)
		return nil, fmt.Errorf("failed to read ServerHello header: %w", err)
	}

	// Parse the record header to determine message length
	responseType := recordHeader[0]
	responseVer := binary.BigEndian.Uint16(recordHeader[1:3])
	responseLen := binary.BigEndian.Uint16(recordHeader[3:5])

	log.Printf("🔹 ServerHello response: Type=%d, Version=0x%x, Length=%d",
		responseType, responseVer, responseLen)

	// Read the actual handshake message
	serverHelloData := make([]byte, responseLen)
	_, err = conn.Read(serverHelloData)
	if err != nil {
		log.Printf("❌ Failed to read ServerHello data: %v", err)
		return nil, fmt.Errorf("failed to read ServerHello data: %w", err)
	}

	// Combine the record header and message data for a complete response
	completeResponse := append(recordHeader, serverHelloData...)

	log.Printf("🔹 Successfully received ServerHello (%d bytes)", len(completeResponse))

	// Format a human-readable response for debugging
	info := fmt.Sprintf(`{
		"tls_record_type": %d,
		"tls_version": "0x%x",
		"response_length": %d,
		"server_name": "%s",
		"raw_data_length": %d
	}`, responseType, responseVer, responseLen, sni, len(completeResponse))

	log.Printf("🔹 Server response info: %s", info)

	// Return the raw ServerHello data
	return completeResponse, nil
}

// Parse the TLS record header
func parseRecordHeader(data []byte) (byte, uint16, uint16, error) {
	if len(data) < 5 {
		return 0, 0, 0, fmt.Errorf("data too short for TLS record header")
	}

	recordType := data[0]
	version := binary.BigEndian.Uint16(data[1:3])
	length := binary.BigEndian.Uint16(data[3:5])

	return recordType, version, length, nil
}

// Add to server.go
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

// Handler for connection adoption requests - critical for TLS proxying
func handleAdoptConnection(w http.ResponseWriter, r *http.Request) {
	// Read the JSON request body
	var req struct {
		SessionID string `json:"session_id"`
		Protocol  string `json:"protocol,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	sessionID := req.SessionID
	if sessionID == "" {
		http.Error(w, "Session ID is required", http.StatusBadRequest)
		return
	}

	// Get the session
	sessionsMu.Lock()
	session, exists := sessions[sessionID]
	sessionsMu.Unlock()

	if !exists || session.TargetConn == nil {
		http.Error(w, fmt.Sprintf("Session %s not found or invalid", sessionID), http.StatusNotFound)
		return
	}

	log.Printf("🔹 Adoption request received for session %s", sessionID)

	// Check if handshake is complete
	if !session.HandshakeComplete {
		log.Printf("❌ Handshake not complete for session %s, rejecting adoption", sessionID)
		http.Error(w, fmt.Sprintf("Handshake not complete for session %s", sessionID), http.StatusBadRequest)
		return
	}

	log.Printf("✅ Handshake confirmed complete for session %s", sessionID)

	// Hijack the HTTP connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("❌ Server doesn't support hijacking for session %s", sessionID)
		http.Error(w, "Server doesn't support hijacking", http.StatusInternalServerError)
		return
	}
	log.Printf("🔹 Hijacking HTTP connection for session %s", sessionID)

	clientConn, bufrw, err := hj.Hijack()
	if err != nil {
		log.Printf("❌ Hijacking failed for session %s: %v", sessionID, err)
		http.Error(w, fmt.Sprintf("Hijacking failed: %v", err), http.StatusInternalServerError)
		return
	}
	log.Printf("✅ Successfully hijacked HTTP connection for session %s", sessionID)

	// Mark session as adopted - use mutex to prevent race conditions
	session.mu.Lock()
	session.Adopted = true
	session.mu.Unlock()
	log.Printf("✅ Session %s marked as adopted", sessionID)

	// Send HTTP 200 OK
	log.Printf("🔹 Sending 200 OK response for session %s", sessionID)

	// Detect TLS version from ServerHello - for logging only
	tlsVersion := "TLSv1.2" // Default
	session.mu.Lock()
	if len(session.ServerResponses) > 0 && len(session.ServerResponses[0]) >= 5 {
		ver := (uint16(session.ServerResponses[0][1]) << 8) | uint16(session.ServerResponses[0][2])
		switch ver {
		case 0x0303:
			tlsVersion = "TLSv1.2" // TLS 1.2 record version
		case 0x0304:
			tlsVersion = "TLSv1.3" // TLS 1.3 record version
		}
		log.Printf("🔹 Detected TLS version in use: %s (0x%04x)", tlsVersion, ver)
	}
	session.mu.Unlock()
	
	// This is the initial HTTP response to the CONNECT request, which happens BEFORE the TLS handshake
	// So it's safe to send HTTP here
	
	// Include TLS version information in headers for client to use
	responseStr := "HTTP/1.1 200 OK\r\n" +
		"Connection: keep-alive\r\n" +
		"X-Proxy-Status: Direct-Connection-Established\r\n" +
		"X-Protocol: " + tlsVersion + "\r\n" +
		"\r\n"

	if _, err := bufrw.WriteString(responseStr); err != nil {
		log.Printf("❌ ERROR writing response: %v", err)
		return
	}

	if err := bufrw.Flush(); err != nil {
		log.Printf("❌ ERROR flushing buffer: %v", err)
		return
	}

	// Ensure the response buffer is fully flushed
	if err := bufrw.Flush(); err != nil {
		log.Printf("❌ ERROR flushing buffer for session %s: %v", sessionID, err)
		return
	}
	log.Printf("✅ Sent 200 OK response for session %s", sessionID)

	// Set proper TCP options for improved performance
	if tcpConn, ok := session.TargetConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetReadBuffer(1048576)  // 1MB buffer
		tcpConn.SetWriteBuffer(1048576) // 1MB buffer
	}
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetReadBuffer(1048576)  // 1MB buffer
		tcpConn.SetWriteBuffer(1048576) // 1MB buffer
	}

	// For HTTP/2, we need a passthrough relay approach
	// Don't attempt to read ANY data here as it breaks the TLS protocol state
	log.Printf("🔹 Starting pure passthrough relay without HTTP/2 preface detection")

	// For HTTP/2 to work, we must not interfere with the TLS sequence at all
	// Any attempt to read data here breaks the cryptographic MAC sequence
	log.Printf("🔹 Using pure relay mode, letting the protocol flow naturally")

	// Extract the SNI for logging purposes
	session.mu.Lock()
	var sni string = "unknown"
	if len(session.ClientMessages) > 0 {
		// Extract SNI
		extractedSNI, err := extractSNIFromClientHello(session.ClientMessages[0])
		if err == nil && extractedSNI != "" {
			sni = extractedSNI
		}

		// Check for HTTP/2 support - just for logging
		if bytes.Contains(session.ClientMessages[0], []byte("h2")) {
			log.Printf("🔹 Detected HTTP/2 ALPN in ClientHello message")
		}
	}
	session.mu.Unlock()

	// Don't send an initial GET request - let the client send its own request
	log.Printf("🔹 Waiting for client to send HTTP request for: %s", sni)

	log.Printf("✅ Connection ready for bidirectional relay (session %s)", sessionID)

	// Start bidirectional relay in a separate goroutine
	go func() {
		log.Printf("✅ Starting bidirectional relay for session %s", sessionID)

		// CRITICAL FIX: DON'T forward pending TLS handshake responses after connection adoption
		// This would corrupt the TLS MAC sequence and cause "decryption failed or bad record mac" errors
		session.mu.Lock()
		if len(session.ServerResponses) > 0 && session.ServerMsgIndex < len(session.ServerResponses) {
			log.Printf("🔹 Found %d pending TLS handshake responses - NOT forwarding to avoid corruption",
				len(session.ServerResponses)-session.ServerMsgIndex)

			// Update the index to mark as consumed, but don't actually send them
			session.ServerMsgIndex = len(session.ServerResponses)
		}
		session.mu.Unlock()

		// Skip manually trying to complete the TLS handshake with signals
		// This was causing connection issues - we'll let the data relay handle it
		log.Printf("🔹 Proceeding directly to HTTP data relay")

		// Instead of artificial delay, let's ensure proper protocol state management
		// Flush any pending operations to ensure TLS state is properly synchronized
		// The key is not manipulating the TLS state once handshake is complete

		// Phase 2: Direct communication with maintained TLS state
		// Get the negotiated TLS version for logging
		tlsVersionStr := "TLS-Unknown"
		session.mu.Lock()
		if len(session.ServerResponses) > 0 && len(session.ServerResponses[0]) >= 5 {
			ver := (uint16(session.ServerResponses[0][1]) << 8) | uint16(session.ServerResponses[0][2])
			switch ver {
			case 0x0303:
				tlsVersionStr = "TLSv1.2"
			case 0x0304:
				tlsVersionStr = "TLSv1.3"
			default:
				tlsVersionStr = fmt.Sprintf("TLS-0x%04x", ver)
			}
		}
		session.mu.Unlock()
		
		// CRITICAL: Don't send any HTTP response at this point!
		// The TLS handshake is already complete and sending unencrypted HTTP over
		// an encrypted TLS connection will break the state machine
		log.Printf("🔹 Using TLS version: %s in pure relay mode", tlsVersionStr)
		log.Printf("🔹 Phase 1 complete: SNI concealment handshake successful")
		log.Printf("🔹 Phase 2 beginning: Direct client-server communication")

		// Instead of direct fetch, we'll use a pure bidirectional relay with the existing connection
		// This maintains TLS state and allows the client to communicate directly with the server

		// No need to start a new connection - we already have a valid, authenticated TLS connection
		// Just set up the relay between client and target server

		// Enable graceful shutdown behavior to handle connection resets
		log.Printf("🔹 Enabling graceful shutdown behavior to handle connection resets")

		defer func() {
			if r := recover(); r != nil {
				log.Printf("❌ PANIC in bidirectional relay: %v", r)
			}

			// Close connections
			if session.TargetConn != nil {
				session.TargetConn.Close()
			}
			if clientConn != nil {
				clientConn.Close()
			}
			log.Printf("✅ Connections closed for session %s", sessionID)

			// Clean up session
			sessionsMu.Lock()
			delete(sessions, sessionID)
			sessionsMu.Unlock()
		}()

		// Start bidirectional relay immediately without direct fetch
		log.Printf("🔹 Starting pure bidirectional relay for phase 2 communication")

		// Use wait group for the two copy operations
		var wg sync.WaitGroup
		wg.Add(2)

		// Client -> Target with enhanced progress logging
		go func() {
			defer wg.Done()
			// Use a much larger buffer to handle large TLS records and HTTP requests
			buffer := make([]byte, 1048576) // 1MB buffer
			var totalBytes int64

			for {
				// Read from client with longer timeout
				clientConn.SetReadDeadline(time.Now().Add(120 * time.Second))
				nr, err := clientConn.Read(buffer)
				clientConn.SetReadDeadline(time.Time{})

				if err != nil {
					if err == io.EOF || strings.Contains(err.Error(), "use of closed") {
						log.Printf("🔹 Client closed connection (normal)")
					} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						log.Printf("🔹 Client read timeout, continuing...")
						continue
					} else {
						log.Printf("❌ Server side: Client->Target relay error: %v", err)
					}
					break
				}

				if nr > 0 {
					// Log application data details
					log.Printf("🔹 SERVER DATA: Client->Target: Read %d bytes", nr)
					if nr >= 5 {
						recordType := buffer[0]
						// Only interpret as TLS record if it's a valid TLS record type (20-24)
						if recordType >= 20 && recordType <= 24 {
							version := (uint16(buffer[1]) << 8) | uint16(buffer[2])
							length := (uint16(buffer[3]) << 8) | uint16(buffer[4])
							log.Printf("🔹 SERVER DATA: Client->Target TLS record: Type=%d, Version=0x%04x, Length=%d",
								recordType, version, length)
							log.Printf("🔹 SERVER DATA: First 16 bytes: %x", buffer[:min(16, nr)])
						} else {
							// This is likely application data
							log.Printf("🔹 SERVER DATA: Client->Target application data: %d bytes", nr)
						}
					}

					// Write to target with timeout
					session.TargetConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
					nw, err := session.TargetConn.Write(buffer[:nr])
					session.TargetConn.SetWriteDeadline(time.Time{})
					if err != nil {
						log.Printf("❌ Server side: Client->Target relay error writing: %v", err)
						break
					}

					if nw != nr {
						log.Printf("⚠️ Server side: Short write to target %d/%d bytes", nw, nr)
					} else {
						log.Printf("✅ Server side: Client->Target: Successfully forwarded %d bytes", nw)
					}

					totalBytes += int64(nw)
				}
			}

			log.Printf("🔹 Server side: Client->Target relay finished: %d bytes total", totalBytes)
		}()

		// Target -> Client with enhanced progress logging
		go func() {
			defer wg.Done()
			// Use a much larger buffer to handle large TLS records and HTTP responses
			buffer := make([]byte, 1048576) // 1MB buffer
			var totalBytes int64

			for {
				// Read from target with longer timeout
				session.TargetConn.SetReadDeadline(time.Now().Add(120 * time.Second))
				nr, err := session.TargetConn.Read(buffer)
				session.TargetConn.SetReadDeadline(time.Time{})

				if err != nil {
					if err == io.EOF || strings.Contains(err.Error(), "use of closed") {
						log.Printf("🔹 Target closed connection (normal)")
					} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						log.Printf("🔹 Target read timeout, continuing...")
						continue
					} else {
						log.Printf("❌ Server side: Target->Client relay error: %v", err)
					}
					break
				}

				if nr > 0 {
					// Try to detect if this is HTTP response data
					if nr > 10 && bytes.HasPrefix(buffer[:nr], []byte("HTTP/1.")) {
						log.Printf("🔹 SERVER DATA: Received HTTP response from target: %d bytes", nr)

						// Get the status line
						statusLine := ""
						for i, b := range buffer[:min(100, nr)] {
							if b == '\n' {
								statusLine = string(buffer[:i])
								break
							}
						}
						log.Printf("🔹 HTTP RESPONSE: %s", statusLine)

						// Try to find response body
						bodyStart := bytes.Index(buffer[:nr], []byte("\r\n\r\n"))
						if bodyStart > 0 {
							bodyStart += 4 // Skip \r\n\r\n
							bodyLen := nr - bodyStart
							if bodyLen > 0 {
								log.Printf("🔹 HTTP BODY: %d bytes", bodyLen)
								previewLen := min(100, bodyLen)
								log.Printf("🔹 BODY PREVIEW: %s", string(buffer[bodyStart:bodyStart+previewLen]))
							}
						}
					} else {
						// Regular TLS data
						log.Printf("🔹 SERVER DATA: Target->Client: Read %d bytes", nr)
						if nr >= 5 {
							recordType := buffer[0]
							// Only interpret as TLS record if it's a valid TLS record type (20-24)
							if recordType >= 20 && recordType <= 24 {
								version := (uint16(buffer[1]) << 8) | uint16(buffer[2])
								length := (uint16(buffer[3]) << 8) | uint16(buffer[4])
								log.Printf("🔹 SERVER DATA: Target->Client TLS record: Type=%d, Version=0x%04x, Length=%d",
									recordType, version, length)
								log.Printf("🔹 SERVER DATA: First 16 bytes: %x", buffer[:min(16, nr)])
							} else {
								// This is likely application data
								log.Printf("🔹 SERVER DATA: Target->Client application data: %d bytes", nr)
							}
						}
					}

					// Write to client with better error handling
					clientConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
					nw, err := clientConn.Write(buffer[:nr])
					clientConn.SetWriteDeadline(time.Time{})
					if err != nil {
						if strings.Contains(err.Error(), "broken pipe") ||
							strings.Contains(err.Error(), "use of closed") {
							log.Printf("ℹ️ Client connection closed, stopping relay gracefully")
							return
						}
						log.Printf("❌ Server side: Target->Client relay error writing: %v", err)
						break
					}

					if nw != nr {
						log.Printf("⚠️ Server side: Short write to client %d/%d bytes", nw, nr)
					} else {
						log.Printf("✅ Server side: Target->Client: Successfully forwarded %d bytes", nw)
					}

					totalBytes += int64(nw)
				}
			}

			log.Printf("🔹 Server side: Target->Client relay finished: %d bytes total", totalBytes)
		}()

		// Wait for both directions to complete
		wg.Wait()
		log.Printf("✅ Bidirectional relay completed for session %s", sessionID)
	}()
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Extract SNI from ClientHello for target info
func extractSNIFromClientHello(clientHello []byte) (string, error) {
	if len(clientHello) < 43 { // Minimum length for a valid ClientHello
		return "", errors.New("ClientHello too short")
	}

	// Ensure this is a TLS ClientHello by checking the first few bytes
	if clientHello[0] != 0x16 { // TLS handshake type
		return "", errors.New("Not a TLS handshake")
	}
	if clientHello[5] != 0x01 { // ClientHello message type
		return "", errors.New("Not a ClientHello message")
	}

	// Find the TLS extensions section
	var pos = 43 // Start after fixed-length fields
	if pos+2 > len(clientHello) {
		return "", errors.New("Malformed ClientHello")
	}

	// Skip session ID
	sessionIDLen := int(clientHello[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(clientHello) {
		return "", errors.New("Malformed ClientHello (session ID too short)")
	}

	// Skip cipher suites
	cipherSuitesLen := int(clientHello[pos])<<8 | int(clientHello[pos+1])
	pos += 2 + cipherSuitesLen
	if pos+1 > len(clientHello) {
		return "", errors.New("Malformed ClientHello (cipher suites too short)")
	}

	// Skip compression methods
	compressionLen := int(clientHello[pos])
	pos += 1 + compressionLen
	if pos+2 > len(clientHello) {
		return "", errors.New("Malformed ClientHello (compression methods too short)")
	}

	// Read extensions length
	extensionsLen := int(clientHello[pos])<<8 | int(clientHello[pos+1])
	pos += 2
	if pos+extensionsLen > len(clientHello) {
		return "", errors.New("Malformed ClientHello (extensions too short)")
	}

	// Iterate through TLS extensions to find the SNI
	for pos+4 <= len(clientHello) {
		extType := int(clientHello[pos])<<8 | int(clientHello[pos+1])
		extLen := int(clientHello[pos+2])<<8 | int(clientHello[pos+3])
		pos += 4

		// Check if this is the SNI extension (type 0x0000)
		if extType == 0x0000 {
			if pos+2 > len(clientHello) {
				return "", errors.New("Malformed SNI extension")
			}
			sniListLen := int(clientHello[pos])<<8 | int(clientHello[pos+1])
			pos += 2

			if pos+sniListLen > len(clientHello) {
				return "", errors.New("SNI list length mismatch")
			}

			// Only one name is typically present
			if sniListLen < 3 || clientHello[pos] != 0x00 { // Ensure it's a valid host_name entry
				return "", errors.New("Invalid SNI entry")
			}

			// Read the hostname length
			hostnameLen := int(clientHello[pos+1])<<8 | int(clientHello[pos+2])
			pos += 3

			if pos+hostnameLen > len(clientHello) {
				return "", errors.New("Hostname length mismatch")
			}

			// Extract the hostname
			sni := string(clientHello[pos : pos+hostnameLen])
			return sni, nil
		}

		// Move to next extension
		pos += extLen
	}

	return "", errors.New("SNI not found in ClientHello")
}

// Enhanced handleGetTargetInfo provides target server connection details
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

	// Construct comprehensive response for direct connection
	response := struct {
		TargetHost    string `json:"target_host"`
		TargetIP      string `json:"target_ip"`
		TargetPort    int    `json:"target_port"`
		SessionTicket []byte `json:"session_ticket,omitempty"`
		MasterSecret  []byte `json:"master_secret,omitempty"`
		SNI           string `json:"sni"`
		Version       int    `json:"tls_version"`
	}{
		TargetHost: targetHost,
		TargetIP:   targetAddr.IP.String(),
		TargetPort: targetPort,
		// In a full implementation, we would extract these from the TLS session
		// SessionTicket: extractedTicket,
		// MasterSecret:  extractedSecret,
		SNI:     sni,
		Version: tlsVersion,
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	log.Printf("✅ Sent target info for session %s: %s:%d", sessionID, targetHost, targetPort)
}

// handleTunnel provides direct TCP tunneling between client and target
func handleTunnel(w http.ResponseWriter, r *http.Request) {
    // Extract session ID from header
    sessionID := r.Header.Get("X-Session-ID")
    if sessionID == "" {
        log.Printf("❌ Missing X-Session-ID header in tunnel request")
        http.Error(w, "X-Session-ID header is required", http.StatusBadRequest)
        return
    }

    log.Printf("🔹 Received tunnel request for session %s", sessionID)

    // Get the session
    sessionsMu.Lock()
    session, exists := sessions[sessionID]
    sessionsMu.Unlock()

    if !exists || session.TargetConn == nil {
        log.Printf("❌ Session %s not found or invalid for tunnel", sessionID)
        http.Error(w, fmt.Sprintf("Session %s not found or invalid", sessionID), http.StatusNotFound)
        return
    }

    // Check if handshake is complete
    if !session.HandshakeComplete {
        log.Printf("❌ Handshake not complete for session %s, rejecting tunnel", sessionID)
        http.Error(w, fmt.Sprintf("Handshake not complete for session %s", sessionID), http.StatusBadRequest)
        return
    }

    log.Printf("✅ Handshake confirmed complete for session %s, proceeding with tunnel", sessionID)

    // Hijack the HTTP connection
    hj, ok := w.(http.Hijacker)
    if !ok {
        log.Printf("❌ Server doesn't support hijacking for session %s", sessionID)
        http.Error(w, "Server doesn't support hijacking", http.StatusInternalServerError)
        return
    }
    log.Printf("🔹 Hijacking HTTP connection for tunnel session %s", sessionID)

    clientConn, bufrw, err := hj.Hijack()
    if err != nil {
        log.Printf("❌ Hijacking failed for tunnel session %s: %v", sessionID, err)
        http.Error(w, fmt.Sprintf("Hijacking failed: %v", err), http.StatusInternalServerError)
        return
    }
    log.Printf("✅ Successfully hijacked HTTP connection for tunnel session %s", sessionID)

    // Mark session as adopted
    session.mu.Lock()
    session.Adopted = true
    session.mu.Unlock()
    log.Printf("✅ Session %s marked as adopted for tunneling", sessionID)

    // Send HTTP 200 OK
    responseStr := "HTTP/1.1 200 OK\r\n" +
        "Connection: keep-alive\r\n" +
        "X-Proxy-Status: Tunnel-Established\r\n" +
        "\r\n"

    if _, err := bufrw.WriteString(responseStr); err != nil {
        log.Printf("❌ ERROR writing tunnel response: %v", err)
        clientConn.Close()
        return
    }

    if err := bufrw.Flush(); err != nil {
        log.Printf("❌ ERROR flushing buffer: %v", err)
        clientConn.Close()
        return
    }
    log.Printf("✅ Sent 200 OK response for tunnel session %s", sessionID)

    // Optimize TCP settings for the tunnel
    if tcpConn, ok := session.TargetConn.(*net.TCPConn); ok {
        tcpConn.SetNoDelay(true)
        tcpConn.SetKeepAlive(true)
        tcpConn.SetKeepAlivePeriod(30 * time.Second)
        tcpConn.SetReadBuffer(1048576)  // 1MB buffer
        tcpConn.SetWriteBuffer(1048576) // 1MB buffer
    }
    if tcpConn, ok := clientConn.(*net.TCPConn); ok {
        tcpConn.SetNoDelay(true)
        tcpConn.SetKeepAlive(true)
        tcpConn.SetKeepAlivePeriod(30 * time.Second)
        tcpConn.SetReadBuffer(1048576)  // 1MB buffer
        tcpConn.SetWriteBuffer(1048576) // 1MB buffer
    }

    log.Printf("✅ Connection ready for bidirectional tunnel (session %s)", sessionID)

    // Start bidirectional relay in a separate goroutine
    go func() {
        log.Printf("✅ Starting bidirectional tunnel relay for session %s", sessionID)

        // Enable graceful shutdown behavior to handle connection resets
        defer func() {
            if r := recover(); r != nil {
                log.Printf("❌ PANIC in tunnel relay: %v", r)
            }

            // Close connections
            if session.TargetConn != nil {
                session.TargetConn.Close()
            }
            if clientConn != nil {
                clientConn.Close()
            }
            log.Printf("✅ Tunnel connections closed for session %s", sessionID)

            // Clean up session
            sessionsMu.Lock()
            delete(sessions, sessionID)
            sessionsMu.Unlock()
            log.Printf("✅ Cleaned up session %s after tunnel completion", sessionID)
        }()

        // Use wait group for the two copy operations
        var wg sync.WaitGroup
        wg.Add(2)

        // Client -> Target relay
        go func() {
            defer wg.Done()
            buffer := make([]byte, 1048576) // 1MB buffer
            var totalBytes int64

            for {
                // Read from client with timeout
                clientConn.SetReadDeadline(time.Now().Add(120 * time.Second))
                nr, err := clientConn.Read(buffer)
                clientConn.SetReadDeadline(time.Time{})

                if err != nil {
                    if err == io.EOF || strings.Contains(err.Error(), "use of closed") {
                        log.Printf("🔹 Client closed tunnel connection (normal)")
                    } else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                        log.Printf("🔹 Client read timeout, continuing tunnel...")
                        continue
                    } else {
                        log.Printf("❌ Tunnel: Client->Target relay error: %v", err)
                    }
                    break
                }

                if nr > 0 {
                    log.Printf("🔹 TUNNEL: Client->Target: Read %d bytes", nr)

                    // Write to target with timeout
                    session.TargetConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
                    nw, err := session.TargetConn.Write(buffer[:nr])
                    session.TargetConn.SetWriteDeadline(time.Time{})
                    if err != nil {
                        log.Printf("❌ Tunnel: Client->Target relay error writing: %v", err)
                        break
                    }

                    if nw != nr {
                        log.Printf("⚠️ Tunnel: Short write to target %d/%d bytes", nw, nr)
                    } else {
                        log.Printf("✅ Tunnel: Client->Target: Successfully forwarded %d bytes", nw)
                    }

                    totalBytes += int64(nw)
                }
            }

            log.Printf("🔹 Tunnel: Client->Target relay finished: %d bytes total", totalBytes)
        }()

        // Target -> Client relay
        go func() {
            defer wg.Done()
            buffer := make([]byte, 1048576) // 1MB buffer
            var totalBytes int64

            for {
                // Read from target with timeout
                session.TargetConn.SetReadDeadline(time.Now().Add(120 * time.Second))
                nr, err := session.TargetConn.Read(buffer)
                session.TargetConn.SetReadDeadline(time.Time{})

                if err != nil {
                    if err == io.EOF || strings.Contains(err.Error(), "use of closed") {
                        log.Printf("🔹 Target closed tunnel connection (normal)")
                    } else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                        log.Printf("🔹 Target read timeout, continuing tunnel...")
                        continue
                    } else {
                        log.Printf("❌ Tunnel: Target->Client relay error: %v", err)
                    }
                    break
                }

                if nr > 0 {
                    log.Printf("🔹 TUNNEL: Target->Client: Read %d bytes", nr)

                    // Write to client with timeout
                    clientConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
                    nw, err := clientConn.Write(buffer[:nr])
                    clientConn.SetWriteDeadline(time.Time{})
                    if err != nil {
                        if strings.Contains(err.Error(), "broken pipe") ||
                            strings.Contains(err.Error(), "use of closed") {
                            log.Printf("ℹ️ Client tunnel connection closed, stopping relay gracefully")
                            return
                        }
                        log.Printf("❌ Tunnel: Target->Client relay error writing: %v", err)
                        break
                    }

                    if nw != nr {
                        log.Printf("⚠️ Tunnel: Short write to client %d/%d bytes", nw, nr)
                    } else {
                        log.Printf("✅ Tunnel: Target->Client: Successfully forwarded %d bytes", nw)
                    }

                    totalBytes += int64(nw)
                }
            }

            log.Printf("🔹 Tunnel: Target->Client relay finished: %d bytes total", totalBytes)
        }()

        // Wait for both directions to complete
        wg.Wait()
        log.Printf("✅ Bidirectional tunnel completed for session %s", sessionID)
    }()
}

// Handler for releasing OOB resources
func handleReleaseConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Action    string `json:"action"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("❌ Invalid release connection request: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	sessionID := req.SessionID
	if sessionID == "" {
		log.Printf("❌ Missing session ID in release connection request")
		http.Error(w, "Session ID is required", http.StatusBadRequest)
		return
	}

	log.Printf("🔹 Received release connection request for session %s", sessionID)

	// Get the session - don't delete, just mark
	sessionsMu.Lock()
	session, exists := sessions[sessionID]
	if exists {
		session.mu.Lock()
		session.Adopted = true
		session.mu.Unlock()
		log.Printf("✅ Session %s marked as adopted and released", sessionID)
	} else {
		// This is normal with direct fetch approach - not a problem
		log.Printf("ℹ️ Session %s not found for release connection (this is normal with direct fetch)", sessionID)
	}
	sessionsMu.Unlock()

	// Return success regardless - best effort
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// Handle client requests for server responses during handshake
func handleGetResponse(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Action    string `json:"action"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("❌ Invalid get_response request: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	sessionID := req.SessionID
	if sessionID == "" {
		log.Printf("❌ Missing session ID in get_response request")
		http.Error(w, "Session ID is required", http.StatusBadRequest)
		return
	}

	log.Printf("🔹 Received get_response request for session %s", sessionID)

	// Get the session
	sessionsMu.Lock()
	session, exists := sessions[sessionID]
	sessionsMu.Unlock()

	if !exists {
		log.Printf("❌ Session %s not found for get_response", sessionID)
		http.Error(w, fmt.Sprintf("Session %s not found", sessionID), http.StatusNotFound)
		return
	}

	// Try to read from ResponseQueue with a timeout to avoid blocking
	var responseData []byte

	// Get handshake status
	session.mu.Lock()
	handshakeComplete := session.HandshakeComplete
	responseQueueLen := len(session.ResponseQueue)
	lastActivityTime := session.LastActivity
	numServerResponses := len(session.ServerResponses)

	// CRITICAL FIX: Check if we have ServerResponses but empty ResponseQueue
	// This handles the case where the ServerResponses were stored but not properly queued
	if numServerResponses > 0 && responseQueueLen == 0 && !session.Adopted {
		// Get the server message index to determine which response to send
		serverMsgIndex := session.ServerMsgIndex
		if serverMsgIndex < numServerResponses {
			log.Printf("🔹 Found unqueued response #%d for session %s, adding to response queue",
				serverMsgIndex+1, sessionID)
			// Get the response directly from ServerResponses
			responseData = session.ServerResponses[serverMsgIndex]
			// Increment the server message index for next time
			session.ServerMsgIndex++
			log.Printf("✅ Retrieved %d bytes directly from ServerResponses for session %s",
				len(responseData), sessionID)
		}
	}
	session.mu.Unlock()

	log.Printf("🔹 Session %s status: handshakeComplete=%t, responseQueue=%d items, responses=%d, lastActivity=%v",
		sessionID, handshakeComplete, responseQueueLen, numServerResponses,
		time.Since(lastActivityTime).Truncate(time.Second))

	// Only if we didn't get a response directly from ServerResponses, try the queue
	if responseData == nil {
		// Try to read from channel with timeout
		select {
		case data := <-session.ResponseQueue:
			responseData = data
			log.Printf("✅ Retrieved %d bytes from response queue for session %s", len(data), sessionID)
		case <-time.After(100 * time.Millisecond):
			log.Printf("🔹 No data available in response queue for session %s (timeout)", sessionID)
			// No data available in the queue, return empty response
		}
	}

	// Send response
	response := struct {
		Data              []byte `json:"data"`
		HandshakeComplete bool   `json:"handshake_complete"`
	}{
		Data:              responseData,
		HandshakeComplete: handshakeComplete,
	}

	// Log what we're sending back
	if len(responseData) > 0 {
		log.Printf("✅ Sending %d bytes to client for session %s", len(responseData), sessionID)
		if len(responseData) >= 5 {
			recordType := responseData[0]
			version := (uint16(responseData[1]) << 8) | uint16(responseData[2])
			log.Printf("🔹 TLS Record in response: Type=%d, Version=0x%04x", recordType, version)
		}
	} else {
		log.Printf("🔹 Sending empty data response to client for session %s (handshakeComplete=%t)",
			sessionID, handshakeComplete)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Handle client data sent during handshake
func handleSendData(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Action    string `json:"action"`
		Data      []byte `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("❌ Invalid send_data request: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	sessionID := req.SessionID
	if sessionID == "" || len(req.Data) == 0 {
		log.Printf("❌ Missing session ID or data in send_data request")
		http.Error(w, "Session ID and data are required", http.StatusBadRequest)
		return
	}

	log.Printf("🔹 Received send_data request (%d bytes) for session %s", len(req.Data), sessionID)

	// Get the session
	sessionsMu.Lock()
	session, exists := sessions[sessionID]
	sessionsMu.Unlock()

	if !exists || session.TargetConn == nil {
		log.Printf("❌ Session %s not found or invalid for send_data", sessionID)
		http.Error(w, fmt.Sprintf("Session %s not found or invalid", sessionID), http.StatusNotFound)
		return
	}

	// Analyze handshake status if needed
	isHandshake, _ := analyzeHandshakeStatus(req.Data)

	// Store the client message if it's a handshake
	if isHandshake {
		session.mu.Lock()
		session.ClientMessages = append(session.ClientMessages, req.Data)
		session.mu.Unlock()
	}

	// Forward the data to the target with timeout
	session.TargetConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := session.TargetConn.Write(req.Data)
	session.TargetConn.SetWriteDeadline(time.Time{})
	if err != nil {
		log.Printf("❌ Failed to forward data to target: %v", err)
		http.Error(w, fmt.Sprintf("Failed to forward data: %v", err), http.StatusInternalServerError)
		return
	}

	// Update last activity
	session.mu.Lock()
	session.LastActivity = time.Now()
	session.mu.Unlock()

	log.Printf("✅ Forwarded %d bytes from client to target for session %s", len(req.Data), sessionID)

	// Send response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// handleCreateConnection is a simplified handler for SNI concealment
// without TLS record manipulation. It takes a host:port from the client,
// creates a connection to that target, and returns the real IP and port.
func handleCreateConnection(w http.ResponseWriter, r *http.Request) {
	log.Println("📣 RECEIVED SNI RESOLUTION REQUEST")
	
	var req struct {
		SessionID string `json:"session_id"`
		SNI       string `json:"sni"`
		Port      string `json:"port"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("❌ SNI RESOLUTION ERROR: Invalid request: %v", err)
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}
	
	log.Printf("📝 SNI RESOLUTION REQUEST DETAILS:")
	log.Printf("   Session ID: %s", req.SessionID)
	log.Printf("   SNI Value: %s", req.SNI)
	log.Printf("   Port: %s", req.Port)
	
	if req.SessionID == "" || req.SNI == "" {
		log.Printf("❌ SNI RESOLUTION ERROR: Missing SessionID or SNI")
		http.Error(w, "Session ID and SNI are required", http.StatusBadRequest)
		return
	}
	
	// Set port to 443 if not specified
	port := req.Port
	if port == "" {
		port = "443"
		log.Printf("ℹ️ Using default port 443")
	}
	
	log.Printf("🔹 CREATING CONNECTION TO %s:%s FOR SNI CONCEALMENT", req.SNI, port)
	
	// Establish connection to target
	target := fmt.Sprintf("%s:%s", req.SNI, port)
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	
	log.Printf("🔹 Attempting DNS resolution for %s", req.SNI)
	ips, err := net.LookupIP(req.SNI)
	if err != nil {
		log.Printf("⚠️ DNS resolution failed: %v", err)
	} else {
		log.Printf("✅ DNS resolution successful: %v", ips)
	}
	
	log.Printf("🔹 Dialing TCP connection to %s", target)
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		log.Printf("❌ SNI RESOLUTION FAILED: Could not connect to target: %v", err)
		http.Error(w, fmt.Sprintf("Failed to connect to target: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Get the actual target address
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	log.Printf("✅ CONNECTED TO TARGET: %s:%d", remoteAddr.IP.String(), remoteAddr.Port) 
	
	// Close connection - client will create a new one
	conn.Close()
	log.Printf("🔹 Connection closed - client will create new connection")
	
	// Return the address info to client
	response := struct {
		Status  string `json:"status"`
		Address string `json:"address"`
		Port    string `json:"port"`
	}{
		Status:  "ok",
		Address: remoteAddr.IP.String(),
		Port:    fmt.Sprintf("%d", remoteAddr.Port),
	}
	
	log.Printf("✅ SNI RESOLUTION COMPLETE: %s (%s:%d)",
		req.SNI, remoteAddr.IP.String(), remoteAddr.Port)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	
	log.Println("📣 SNI RESOLUTION RESPONSE SENT")
}
