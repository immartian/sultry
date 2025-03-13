package demo

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
	
	"github.com/yourusername/sultry/pkg/handlers"
	"github.com/yourusername/sultry/pkg/session"
	"github.com/yourusername/sultry/pkg/tls"
)

// This file demonstrates how server.go could be refactored to use the modular packages

// ServerProxy represents the server-side proxy functionality
type ServerProxy struct {
	SessionMgr *session.Manager
	Port       int
}

// NewServerProxy creates a new server proxy
func NewServerProxy(port int) *ServerProxy {
	return &ServerProxy{
		SessionMgr: session.NewManager(),
		Port:       port,
	}
}

// Start starts the server proxy
func (s *ServerProxy) Start() error {
	// Set up HTTP handlers
	http.HandleFunc("/handshake", s.handshakeHandler)
	http.HandleFunc("/complete_handshake", s.completeHandshakeHandler)
	http.HandleFunc("/get_target_info", s.getTargetInfoHandler)
	http.HandleFunc("/release_connection", s.releaseConnectionHandler)
	http.HandleFunc("/get_response", s.getResponseHandler)
	http.HandleFunc("/send_data", s.sendDataHandler)
	
	// Start session cleanup goroutine
	go s.SessionMgr.StartCleanup(5 * time.Minute)
	
	// Start HTTP server
	addr := fmt.Sprintf(":%d", s.Port)
	log.Printf("🔹 Server listening on %s", addr)
	return http.ListenAndServe(addr, nil)
}

// handshakeHandler handles handshake initialization
func (s *ServerProxy) handshakeHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID   string `json:"session_id"`
		ClientHello []byte `json:"client_hello"`
		SNI         string `json:"sni"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	// Create session
	sess := s.SessionMgr.CreateSession(req.SessionID, req.SNI)
	
	// Store ClientHello
	sess.StoreClientMessage(req.ClientHello)
	
	// Extract SNI if needed
	sni := req.SNI
	if sni == "" && len(req.ClientHello) > 0 {
		extractedSNI, err := tls.ExtractSNIFromClientHello(req.ClientHello)
		if err == nil {
			sni = extractedSNI
		}
	}
	
	// Connect to target
	targetAddr := fmt.Sprintf("%s:443", sni)
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to target: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Store target connection
	sess.SetTargetConn(targetConn)
	
	// Send ClientHello to target
	_, err = targetConn.Write(req.ClientHello)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to send ClientHello: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Start reading responses from target
	go s.handleTargetResponses(req.SessionID, targetConn)
	
	w.WriteHeader(http.StatusOK)
}

// handleTargetResponses reads responses from the target server
func (s *ServerProxy) handleTargetResponses(sessionID string, targetConn net.Conn) {
	buffer := make([]byte, 16384)
	
	for {
		// Read from target
		targetConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := targetConn.Read(buffer)
		targetConn.SetReadDeadline(time.Time{})
		
		if err != nil {
			log.Printf("❌ ERROR reading from target: %v", err)
			return
		}
		
		if n > 0 {
			// Store the response
			s.SessionMgr.StoreServerResponse(sessionID, buffer[:n])
			
			// Check if this is a session ticket
			if tls.IsSessionTicketMessage(buffer[:n]) {
				log.Printf("🎫 Session Ticket detected for session %s", sessionID)
			}
			
			// Check if handshake is complete
			if tls.IsHandshakeComplete(buffer[:n]) {
				log.Printf("✅ Handshake complete for session %s", sessionID)
				s.SessionMgr.MarkHandshakeComplete(sessionID)
			}
		}
	}
}

// completeHandshakeHandler handles handshake completion
func (s *ServerProxy) completeHandshakeHandler(w http.ResponseWriter, r *http.Request) {
	handlers.HandleCompleteHandshake(w, r, s.SessionMgr)
}

// getTargetInfoHandler returns information about the target server
func (s *ServerProxy) getTargetInfoHandler(w http.ResponseWriter, r *http.Request) {
	handlers.HandleGetTargetInfo(w, r, s.SessionMgr)
}

// releaseConnectionHandler releases a connection
func (s *ServerProxy) releaseConnectionHandler(w http.ResponseWriter, r *http.Request) {
	handlers.HandleReleaseConnection(w, r, s.SessionMgr)
}

// getResponseHandler returns a response for a given session
func (s *ServerProxy) getResponseHandler(w http.ResponseWriter, r *http.Request) {
	handlers.HandleGetResponse(w, r, s.SessionMgr)
}

// sendDataHandler handles data sent by the client
func (s *ServerProxy) sendDataHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Data      []byte `json:"data"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	// Get the session
	sess := s.SessionMgr.GetSession(req.SessionID)
	if sess == nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}
	
	// Get the target connection
	targetConn := sess.GetTargetConn()
	if targetConn == nil {
		http.Error(w, "Target connection not found", http.StatusNotFound)
		return
	}
	
	// Forward data to target
	_, err := targetConn.Write(req.Data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to send data: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Check if this completes the handshake
	if tls.IsHandshakeComplete(req.Data) {
		s.SessionMgr.MarkHandshakeComplete(req.SessionID)
	}
	
	w.WriteHeader(http.StatusOK)
}