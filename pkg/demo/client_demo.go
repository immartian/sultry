package demo

import (
	"fmt"
	"log"
	"net"
	"time"
	
	"github.com/yourusername/sultry/pkg/relay"
	"github.com/yourusername/sultry/pkg/session"
	"github.com/yourusername/sultry/pkg/tls"
)

// This file demonstrates how client.go could be refactored to use the modular packages

// ClientProxy represents the client-side proxy functionality
type ClientProxy struct {
	OOBServer  string
	SessionMgr *session.Manager
}

// NewClientProxy creates a new client proxy
func NewClientProxy(oobServer string) *ClientProxy {
	return &ClientProxy{
		OOBServer:  oobServer,
		SessionMgr: session.NewManager(),
	}
}

// HandleConnection processes an incoming client connection
func (c *ClientProxy) HandleConnection(clientConn net.Conn) {
	defer clientConn.Close()
	
	// Read initial data from client (e.g., ClientHello or HTTP CONNECT)
	buffer := make([]byte, 1024)
	n, err := clientConn.Read(buffer)
	if err != nil {
		log.Printf("❌ ERROR: Failed to read initial bytes: %v", err)
		return
	}
	
	// Example of using the tls package
	if n >= 5 && buffer[0] == tls.RecordTypeHandshake {
		// This is a TLS handshake
		recordType, version, length, _ := tls.ParseTLSRecordHeader(buffer[:n])
		log.Printf("🔹 Detected TLS handshake: RecordType=%d, Version=0x%04x, Length=%d",
			recordType, version, length)
			
		// Extract SNI if available
		if n >= 43 {  // Minimum length for ClientHello with SNI
			sni, err := tls.ExtractSNIFromClientHello(buffer[:n])
			if err == nil {
				log.Printf("🔹 Extracted SNI: %s", sni)
				
				// Create a session for this connection
				sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
				c.SessionMgr.CreateSession(sessionID, sni)
				
				// Handle TLS handshake
				c.handleTLSHandshake(clientConn, buffer[:n], sessionID, sni)
			}
		}
	} else {
		// Handle other protocols or HTTP CONNECT
		// ...
	}
}

// handleTLSHandshake handles TLS handshake using the relay package
func (c *ClientProxy) handleTLSHandshake(clientConn net.Conn, clientHello []byte, sessionID, sni string) {
	// Example of initiating handshake via OOB
	targetInfo, err := relay.InitiateHandshake(c.OOBServer, sessionID, clientHello, sni)
	if err != nil {
		log.Printf("❌ ERROR initiating handshake: %v", err)
		return
	}
	
	// Get ServerHello from OOB server
	serverHello, err := relay.GetHandshakeResponse(c.OOBServer, sessionID)
	if err != nil {
		log.Printf("❌ ERROR getting ServerHello: %v", err)
		return
	}
	
	// Forward ServerHello to client
	_, err = clientConn.Write(serverHello)
	if err != nil {
		log.Printf("❌ ERROR forwarding ServerHello: %v", err)
		return
	}
	
	// Complete handshake...
	
	// Detect handshake completion
	buffer := make([]byte, 16384)
	for {
		n, err := clientConn.Read(buffer)
		if err != nil {
			log.Printf("❌ ERROR reading from client: %v", err)
			return
		}
		
		// Send client data to server
		err = relay.SendHandshakeData(c.OOBServer, sessionID, buffer[:n])
		if err != nil {
			log.Printf("❌ ERROR sending data to server: %v", err)
			return
		}
		
		// Check if handshake is complete
		if tls.IsHandshakeComplete(buffer[:n]) {
			log.Printf("✅ Handshake complete for session %s", sessionID)
			
			// Signal handshake completion
			relay.SignalHandshakeCompletion(c.OOBServer, sessionID)
			
			// Establish direct connection
			targetConn, err := relay.EstablishDirectConnection(
				c.OOBServer, 
				sessionID,
				targetInfo.TargetIP,
				targetInfo.TargetPort,
			)
			if err != nil {
				log.Printf("❌ ERROR establishing direct connection: %v", err)
				return
			}
			
			// Start bidirectional relay with session ticket detection
			buffer1 := make([]byte, 32768)
			buffer2 := make([]byte, 32768)
			
			go relay.RelayDataWithSessionTicketDetection(
				clientConn, 
				targetConn, 
				buffer1, 
				"client → target", 
				nil,
			)
			
			go relay.RelayDataWithSessionTicketDetection(
				targetConn, 
				clientConn, 
				buffer2, 
				"target → client", 
				func(data []byte) {
					if tls.IsSessionTicketMessage(data) {
						log.Printf("🎫 Session Ticket received for %s", sni)
						session.StoreSessionTicket(sni, data)
					}
				},
			)
			
			break
		}
	}
}