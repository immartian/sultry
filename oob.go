// OOB (Out-of-Band) Module for the Sultry proxy system.
//
// This module is central to the SNI concealment strategy, providing:
// 1. Out-of-band communication channel between client and server components
// 2. Secure transmission of TLS handshake messages via HTTP
// 3. Session management for ongoing connections
// 4. Target server information exchange
//
// The OOB system allows TLS handshake messages to be exchanged through HTTP requests
// rather than direct TCP connections, which effectively conceals the SNI information
// from network monitoring systems or firewalls. Instead of sending the ClientHello
// with SNI directly to the target server, it's sent to our server component via HTTP,
// preventing SNI detection through traffic analysis.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// OOBChannel interface defines the methods for out-of-band communication.
type OOBChannel interface {
	// Initialize a new handshake session
	InitiateHandshake(sessionID string, clientHello []byte, sni string) error

	// Get the next message from the server during handshake
	GetNextServerMessage(sessionID string) (message []byte, isHandshakeComplete bool, err error)

	// Send a client message during handshake
	SendClientMessage(sessionID string, message []byte) (isHandshakeComplete bool, err error)

	// Application data functions
	SendApplicationData(sessionID string, data []byte) error
	ReceiveApplicationData(sessionID string) ([]byte, error)

	// Session management
	CleanupHandshake(sessionID string) error
	CloseSession(sessionID string) error
}

// OOBChannelConfig represents the configuration for an out-of-band communication channel.
type OOBChannelConfig struct {
	Type    string `json:"type"`
	Address string `json:"address,omitempty"`
	Port    int16  `json:"port,omitempty"`
}

// OOBModule implements the OOBChannel interface for HTTP-based out-of-band communication.
type OOBModule struct {
	Channels     []OOBChannelConfig
	activePeer   string
	sessionStore map[string]*SessionData
	mu           sync.Mutex
}

// HandshakeResponse represents a response from the server during handshake
type HandshakeResponse struct {
	Data              []byte `json:"data"`
	HandshakeComplete bool   `json:"handshake_complete"`
}

// SessionData stores session-related information.
type SessionData struct {
	SNI               string
	HandshakeComplete bool
	ServerMessages    [][]byte
	ClientMessages    [][]byte
	ServerMsgIndex    int
	ApplicationData   chan []byte
	ResponseQueue     chan struct{}
}

// ClientHelloRequest represents the payload for an SNI request.
type ClientHelloRequest struct {
	SNI  string `json:"sni"`
	Data []byte `json:"client_hello"`
}

// HandshakeMessageRequest represents the payload for a handshake message.
type HandshakeMessageRequest struct {
	SessionID string `json:"session_id"`
	SNI       string `json:"sni"`
	Data      []byte `json:"data"`
}

// AppDataRequest represents the payload for application data.
type AppDataRequest struct {
	SessionID string `json:"session_id"`
	Data      []byte `json:"data"`
}

// NewOOBModule initializes the OOB module.
func NewOOBModule(channels []OOBChannelConfig) *OOBModule {
	return &OOBModule{
		Channels:     channels,
		sessionStore: make(map[string]*SessionData),
	}
}

// InitiateHandshake initializes a new handshake session.
func (o *OOBModule) InitiateHandshake(sessionID string, clientHello []byte, sni string) error {
	log.Printf("🔹 Initiating handshake for session %s with SNI %s", sessionID, sni)

	o.mu.Lock()
	defer o.mu.Unlock()

	// Create a new session
	o.sessionStore[sessionID] = &SessionData{
		SNI:               sni,
		HandshakeComplete: false,
		ServerMessages:    make([][]byte, 0),
		ClientMessages:    [][]byte{clientHello}, // Store initial ClientHello
		ServerMsgIndex:    0,
		ApplicationData:   make(chan []byte, 100),
	}

	// Find an active peer for this session
	if o.activePeer == "" {
		// Try connecting to available OOB peers
		for _, channel := range o.Channels {
			if channel.Type == "http" && len(channel.Address) > 0 {
				peer := fmt.Sprintf("%s:%d", channel.Address, channel.Port)
				if o.CanConnect(peer) {
					o.activePeer = peer
					break
				}
			}
		}
	}

	if o.activePeer == "" {
		return fmt.Errorf("no available OOB peers")
	}

	// Send the initial ClientHello to the OOB peer
	serverHello, err := o.sendOOBHandshakeMessage(sessionID, clientHello, sni)
	if err != nil {
		return fmt.Errorf("failed to send initial ClientHello: %w", err)
	}

	// Store the ServerHello response
	o.sessionStore[sessionID].ServerMessages = append(o.sessionStore[sessionID].ServerMessages, serverHello)

	return nil
}

// GetNextServerMessage gets the next message from the server during handshake.
func (o *OOBModule) GetNextServerMessage(sessionID string) ([]byte, bool, error) {
	o.mu.Lock()
	session, exists := o.sessionStore[sessionID]
	o.mu.Unlock()

	if !exists {
		return nil, false, fmt.Errorf("session %s not found", sessionID)
	}

	// If we've already processed all messages, signal handshake completion
	if session.ServerMsgIndex >= len(session.ServerMessages) {
		// THIS IS THE KEY FIX - Return empty message with "true" to signal completion
		return []byte{}, true, nil // No error! This is normal handshake completion
	}

	// Return the next message
	msg := session.ServerMessages[session.ServerMsgIndex]
	session.ServerMsgIndex++

	// Check if this was the last message
	isComplete := session.ServerMsgIndex >= len(session.ServerMessages)

	return msg, isComplete, nil
}

// SendClientMessage sends a client message during handshake.
func (o *OOBModule) SendClientMessage(sessionID string, message []byte) (bool, error) {
	o.mu.Lock()
	session, exists := o.sessionStore[sessionID]
	if !exists {
		o.mu.Unlock()
		return false, fmt.Errorf("session %s not found", sessionID)
	}

	// Store the client message
	session.ClientMessages = append(session.ClientMessages, message)
	o.mu.Unlock()

	// Send the message to the OOB peer
	serverResponse, err := o.sendOOBHandshakeMessage(sessionID, message, session.SNI)
	if err != nil {
		return false, fmt.Errorf("failed to send client message: %w", err)
	}

	// Store the server response
	o.mu.Lock()
	defer o.mu.Unlock()

	session = o.sessionStore[sessionID] // Re-fetch in case it changed
	if session == nil {
		return false, fmt.Errorf("session %s was closed", sessionID)
	}

	// Check if this message completes the handshake
	if len(serverResponse) == 0 {
		session.HandshakeComplete = true
		return true, nil
	}

	session.ServerMessages = append(session.ServerMessages, serverResponse)

	// For simplicity, let's assume the handshake is not complete yet
	return false, nil
}

// SendApplicationData sends application data.
func (o *OOBModule) SendApplicationData(sessionID string, data []byte) error {
	o.mu.Lock()
	session, exists := o.sessionStore[sessionID]
	o.mu.Unlock()

	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	// Ensure handshake is complete
	if !session.HandshakeComplete {
		return fmt.Errorf("handshake not complete for session %s", sessionID)
	}

	// Create app data request
	reqPayload := AppDataRequest{
		SessionID: sessionID,
		Data:      data,
	}

	reqBody, err := json.Marshal(reqPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal app data request: %w", err)
	}

	// Send the app data to the OOB peer
	resp, err := http.Post(fmt.Sprintf("http://%s/appdata", o.activePeer), "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to send app data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("app data request failed with status %d", resp.StatusCode)
	}

	return nil
}

// ReceiveApplicationData receives application data.
func (o *OOBModule) ReceiveApplicationData(sessionID string) ([]byte, error) {
	o.mu.Lock()
	session, exists := o.sessionStore[sessionID]
	o.mu.Unlock()

	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	// Ensure handshake is complete
	if !session.HandshakeComplete {
		return nil, fmt.Errorf("handshake not complete for session %s", sessionID)
	}

	// Wait for data with timeout
	select {
	case data := <-session.ApplicationData:
		return data, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timeout waiting for application data")
	}
}

// CleanupHandshake cleans up the handshake session.
func (o *OOBModule) CleanupHandshake(sessionID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	session, exists := o.sessionStore[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	// Reset handshake state
	session.ServerMessages = nil
	session.ClientMessages = nil
	session.ServerMsgIndex = 0
	session.HandshakeComplete = false

	return nil
}

// CloseSession closes the session.
func (o *OOBModule) CloseSession(sessionID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	_, exists := o.sessionStore[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	// Delete the session
	delete(o.sessionStore, sessionID)

	return nil
}

// RelayTLSHandshake sends the ClientHello and returns the ServerHello.
// This method is kept for backward compatibility.
func (o *OOBModule) RelayTLSHandshake(reqID string, clientHelloData []byte, realSNI string) ([]byte, error) {
	// Initialize a session
	err := o.InitiateHandshake(reqID, clientHelloData, realSNI)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch ServerHello: %w", err)
	}

	// Get the server's response (ServerHello)
	serverHello, _, err := o.GetNextServerMessage(reqID)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch ServerHello: %w", err)
	}

	return serverHello, nil
}

// sendOOBHandshakeMessage sends a handshake message over the OOB channel.
// sendOOBHandshakeMessage uses shorter timeouts to avoid long hangs when using direct fetch
func (o *OOBModule) sendOOBHandshakeMessage(sessionID string, data []byte, sni string) ([]byte, error) {
	if o.activePeer == "" {
		return nil, fmt.Errorf("no active OOB peer")
	}

	// Create the request payload
	reqPayload := HandshakeMessageRequest{
		SessionID: sessionID,
		SNI:       sni,
		Data:      data,
	}

	reqBody, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal handshake message: %w", err)
	}

	// Send the request to the OOB peer with a shorter timeout
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(fmt.Sprintf("http://%s/handshake", o.activePeer), "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("OOB request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OOB request failed: %s", string(body))
	}

	// Read the response
	serverResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OOB response: %w", err)
	}

	// Check if the response is empty (indicates end of handshake)
	if len(serverResponse) == 0 {
		return nil, nil
	}

	return serverResponse, nil
}

// CanConnect checks if a connection to the peer can be established.
func (o *OOBModule) CanConnect(peer string) bool {
	conn, err := net.DialTimeout("tcp", peer, 2*time.Second)
	if err != nil {
		log.Printf("⚠️ Failed to connect to OOB peer %s: %v", peer, err)
		return false
	}
	conn.Close()
	log.Printf("🔹 Successfully connected to OOB peer %s", peer)
	return true
}

// AdoptConnection provides direct access to the connection with the target server after handshake
func (o *OOBModule) AdoptConnection(sessionID string) (net.Conn, error) {
	// First check if handshake is complete
	o.mu.Lock()
	session, exists := o.sessionStore[sessionID]
	handshakeComplete := exists && session.HandshakeComplete
	o.mu.Unlock()

	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	if !handshakeComplete {
		return nil, fmt.Errorf("handshake not complete for session %s", sessionID)
	}

	// Check if the server side connection is available
	// We need to ask the server to give us direct access to its target connection
	reqPayload := struct {
		SessionID string `json:"session_id"`
		Action    string `json:"action"`
	}{
		SessionID: sessionID,
		Action:    "adopt_connection",
	}

	reqBody, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(fmt.Sprintf("http://%s/adopt_connection", o.activePeer),
		"application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to contact OOB server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server refused adoption: %s", string(body))
	}

	// Server accepted the adoption request
	// Now create a connection wrapper that uses the OOB channel for data transfer
	conn := &oobConn{
		oob:       o,
		sessionID: sessionID,
		closed:    false,
	}

	log.Printf("✅ Connection adopted for session %s", sessionID)
	return conn, nil
}

// oobConn implements net.Conn interface for application data over OOB
type oobConn struct {
	oob       *OOBModule
	sessionID string
	closed    bool
	mu        sync.Mutex
}

func (c *oobConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.EOF
	}
	c.mu.Unlock()

	// Get data from OOB channel
	data, err := c.oob.ReceiveApplicationData(c.sessionID)
	if err != nil {
		return 0, err
	}

	// Copy data to caller's buffer
	n = copy(b, data)
	return n, nil
}

func (c *oobConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.EOF
	}
	c.mu.Unlock()

	// Send data over OOB channel
	err = c.oob.SendApplicationData(c.sessionID, b)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

func (c *oobConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	return c.oob.CloseSession(c.sessionID)
}

func (c *oobConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *oobConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// GetServerAddress returns the address of the active OOB server
func (o *OOBModule) GetServerAddress() string {
	o.mu.Lock()
	defer o.mu.Unlock()

	return o.activePeer
}

// GetHandshakeResponse gets the next handshake response from the server
func (o *OOBModule) GetHandshakeResponse(sessionID string) (*HandshakeResponse, error) {
	o.mu.Lock()
	session, exists := o.sessionStore[sessionID]
	o.mu.Unlock()
	
	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}
	
	// Critical bugfix: If this is our first response request and we have data, ALWAYS return it
	o.mu.Lock()
	isFirstResponse := session.ServerMsgIndex == 0 && len(session.ServerMessages) > 0
	if isFirstResponse {
		resp := session.ServerMessages[0]
		session.ServerMsgIndex = 1
		o.mu.Unlock()
		log.Printf("🔹 Returning critical first server response (%d bytes)", len(resp))
		return &HandshakeResponse{
			Data:              resp,
			HandshakeComplete: false,
		}, nil
	}
	o.mu.Unlock()
	
	// Normal case for subsequent messages
	data, isComplete, err := o.GetNextServerMessage(sessionID)
	if err != nil {
		return nil, err
	}
	
	return &HandshakeResponse{
		Data:              data,
		HandshakeComplete: isComplete,
	}, nil
}

// SendHandshakeData sends client handshake data to the server
func (o *OOBModule) SendHandshakeData(sessionID string, data []byte) error {
	_, err := o.SendClientMessage(sessionID, data)
	return err
}
func (c *oobConn) SetDeadline(t time.Time) error {
	// Not implemented
	return nil
}

func (c *oobConn) SetReadDeadline(t time.Time) error {
	// Not implemented
	return nil
}

func (c *oobConn) SetWriteDeadline(t time.Time) error {
	// Not implemented
	return nil
}
