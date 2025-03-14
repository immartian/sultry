package session

import (
	"log"
	"sync"
	"time"
)

// SessionTicket stores TLS session resumption information
type SessionTicket struct {
	Data      []byte    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
	SNI       string    `json:"sni"`
}

var (
	// Store session tickets by hostname
	sessionTickets     = make(map[string]*SessionTicket)
	sessionTicketsMu   sync.RWMutex
)

// StoreSessionTicket stores a session ticket for a given hostname
func StoreSessionTicket(hostname string, data []byte) {
	if hostname == "" || len(data) == 0 {
		log.Printf("⚠️ Cannot store session ticket: invalid hostname or data")
		return
	}

	sessionTicketsMu.Lock()
	defer sessionTicketsMu.Unlock()

	// Create a copy of the data to ensure it persists
	ticketData := make([]byte, len(data))
	copy(ticketData, data)

	sessionTickets[hostname] = &SessionTicket{
		Data:      ticketData,
		Timestamp: time.Now(),
		SNI:       hostname,
	}

	log.Printf("✅ Stored session ticket for %s (%d bytes)", hostname, len(data))
}

// HasValidSessionTicket checks if we have a valid session ticket for the given server
func HasValidSessionTicket(targetServer string) (bool, []byte) {
	sessionTicketsMu.RLock()
	defer sessionTicketsMu.RUnlock()
	
	ticket, exists := sessionTickets[targetServer]
	if !exists || ticket == nil || len(ticket.Data) == 0 {
		return false, nil
	}
	
	// Check if the ticket has expired (24 hours)
	if time.Since(ticket.Timestamp) > 24*time.Hour {
		log.Printf("⚠️ Session ticket for %s has expired", targetServer)
		return false, nil
	}
	
	log.Printf("✅ Found valid session ticket for %s (%d bytes, age: %s)",
		targetServer, len(ticket.Data), time.Since(ticket.Timestamp))
	return true, ticket.Data
}