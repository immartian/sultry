package session

import (
	"log"
	"net"
	"sync"
	"time"
)

// SessionState represents the state of a TLS session
type SessionState struct {
	TargetConn        net.Conn     // Connection to target server
	ClientMessages    [][]byte     // Client messages in sequence
	ServerResponses   [][]byte     // Server responses in sequence
	HandshakeComplete bool         // Whether handshake is complete
	LastActivity      time.Time    // Last activity time for timeout
	ConnectedAt       time.Time    // When the connection was established
	SNI               string       // Server Name Indication
	SessionTicket     []byte       // TLS session ticket for resumption
	ResponseQueue     chan []byte  // Channel for response queue
	Adopted           bool         // Whether the connection has been adopted
	ServerMsgIndex    int          // Index into ServerResponses for direct access
	mu                sync.Mutex   // Protects all fields in this struct
}

// createSessionState creates a new session state
func createSessionState(sni string) *SessionState {
	return &SessionState{
		ClientMessages:    make([][]byte, 0),
		ServerResponses:   make([][]byte, 0),
		HandshakeComplete: false,
		LastActivity:      time.Now(),
		ConnectedAt:       time.Now(),
		SNI:               sni,
		ResponseQueue:     make(chan []byte, 10),
	}
}

// cleanupInactiveSessions removes inactive sessions to prevent memory leaks
func cleanupInactiveSessions() {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	
	cutoffTime := time.Now().Add(-5 * time.Minute)
	var sessionsToRemove []string
	
	for id, session := range sessions {
		if session.LastActivity.Before(cutoffTime) {
			sessionsToRemove = append(sessionsToRemove, id)
		}
	}
	
	for _, id := range sessionsToRemove {
		session := sessions[id]
		if session.TargetConn != nil {
			session.TargetConn.Close()
		}
		delete(sessions, id)
	}
	
	if len(sessionsToRemove) > 0 {
		log.Printf("🧹 Cleaned up %d inactive sessions", len(sessionsToRemove))
	}
}

// scheduleSessionCleanup sets up periodic cleanup of inactive sessions
func scheduleSessionCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			cleanupInactiveSessions()
		}
	}()
}