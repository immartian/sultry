package pkg

import (
	"github.com/yourusername/sultry/pkg/handlers"
	"github.com/yourusername/sultry/pkg/relay"
	"github.com/yourusername/sultry/pkg/session"
	"github.com/yourusername/sultry/pkg/tls"
)

// This file serves as an interface to the different packages for ease of import.
// In the future, when client.go and server.go are refactored, they can import these packages.

// BuildInfo returns version information about the modular packages
func BuildInfo() string {
	return "Sultry Modular Packages v0.1.0"
}

// Here we can expose key functions from each package
var (
	// TLS Functions
	ParseTLSRecordHeader = tls.ParseTLSRecordHeader
	IsHandshakeComplete  = tls.IsHandshakeComplete 
	IsSessionTicketMessage = tls.IsSessionTicketMessage
	ExtractSNIFromClientHello = tls.ExtractSNIFromClientHello
	LogTLSRecord = tls.LogTLSRecord
	
	// Relay Functions
	RelayData = relay.RelayData
	RelayDataWithSessionTicketDetection = relay.RelayDataWithSessionTicketDetection
	BiRelayData = relay.BiRelayData
	
	// Session Functions 
	StoreSessionTicket = session.StoreSessionTicket
	HasValidSessionTicket = session.HasValidSessionTicket
	CreateSessionState = session.CreateSessionState
	CleanupInactiveSessions = session.CleanupInactiveSessions
	
	// Handler Functions
	HandleCompleteHandshake = handlers.HandleCompleteHandshake
	HandleGetTargetInfo = handlers.HandleGetTargetInfo
	HandleReleaseConnection = handlers.HandleReleaseConnection
	HandleGetResponse = handlers.HandleGetResponse
)

// Constants from TLS package
const (
	RecordTypeChangeCipherSpec = tls.RecordTypeChangeCipherSpec
	RecordTypeAlert           = tls.RecordTypeAlert
	RecordTypeHandshake       = tls.RecordTypeHandshake
	RecordTypeApplicationData = tls.RecordTypeApplicationData 
	RecordTypeHeartbeat       = tls.RecordTypeHeartbeat
	
	HandshakeTypeClientHello = tls.HandshakeTypeClientHello
	HandshakeTypeServerHello = tls.HandshakeTypeServerHello
	HandshakeTypeCertificate = tls.HandshakeTypeCertificate
	HandshakeTypeFinished    = tls.HandshakeTypeFinished
	HandshakeTypeNewSessionTicket = tls.HandshakeTypeNewSessionTicket
)