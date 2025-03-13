package session

import (
	"log"
	"net"
	"sync"
	"time"
)

// Manager handles session management
type Manager struct {
	sessions   map[string]*SessionState
	sessionsMu sync.RWMutex
}

// NewManager creates a new session manager
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*SessionState),
	}
}

// CreateSession creates a new session
func (m *Manager) CreateSession(sessionID, sni string) *SessionState {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	
	session := &SessionState{
		ClientMessages:    make([][]byte, 0),
		ServerResponses:   make([][]byte, 0),
		HandshakeComplete: false,
		LastActivity:      time.Now(),
		ConnectedAt:       time.Now(),
		SNI:               sni,
		ResponseQueue:     make(chan []byte, 10),
	}
	
	m.sessions[sessionID] = session
	return session
}

// GetSession retrieves a session
func (m *Manager) GetSession(sessionID string) *SessionState {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()
	
	return m.sessions[sessionID]
}

// StoreClientMessage stores a client message
func (m *Manager) StoreClientMessage(sessionID string, message []byte) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	
	if session, exists := m.sessions[sessionID]; exists {
		// Make a copy of the message
		msgCopy := make([]byte, len(message))
		copy(msgCopy, message)
		
		session.ClientMessages = append(session.ClientMessages, msgCopy)
		session.LastActivity = time.Now()
	}
}

// StoreServerResponse stores a server response
func (m *Manager) StoreServerResponse(sessionID string, response []byte) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	
	if session, exists := m.sessions[sessionID]; exists {
		// Make a copy of the response
		respCopy := make([]byte, len(response))
		copy(respCopy, response)
		
		session.ServerResponses = append(session.ServerResponses, respCopy)
		session.LastActivity = time.Now()
	}
}

// SetTargetConn sets the target connection for a session
func (m *Manager) SetTargetConn(sessionID string, conn net.Conn) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	
	if session, exists := m.sessions[sessionID]; exists {
		session.TargetConn = conn
		session.LastActivity = time.Now()
	}
}

// MarkHandshakeComplete marks a handshake as complete
func (m *Manager) MarkHandshakeComplete(sessionID string) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	
	if session, exists := m.sessions[sessionID]; exists {
		session.HandshakeComplete = true
		session.LastActivity = time.Now()
	}
}

// RemoveSession removes a session
func (m *Manager) RemoveSession(sessionID string) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	
	if session, exists := m.sessions[sessionID]; exists {
		if session.TargetConn != nil {
			session.TargetConn.Close()
		}
		
		delete(m.sessions, sessionID)
	}
}

// StartCleanup starts periodic session cleanup
func (m *Manager) StartCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	
	for range ticker.C {
		m.Cleanup()
	}
}

// Cleanup removes inactive sessions
func (m *Manager) Cleanup() {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	
	cutoffTime := time.Now().Add(-5 * time.Minute)
	var sessionsToRemove []string
	
	for id, session := range m.sessions {
		if session.LastActivity.Before(cutoffTime) {
			sessionsToRemove = append(sessionsToRemove, id)
		}
	}
	
	for _, id := range sessionsToRemove {
		session := m.sessions[id]
		if session.TargetConn != nil {
			session.TargetConn.Close()
		}
		
		delete(m.sessions, id)
	}
	
	if len(sessionsToRemove) > 0 {
		log.Printf("🧹 Cleaned up %d inactive sessions", len(sessionsToRemove))
	}
}