// Package pkg provides an interface to the different packages for ease of import
package pkg

import (
	"sultry/pkg/tls"
)

// BuildInfo returns version information about the modular packages
func BuildInfo() string {
	return "Sultry Modular Packages v0.1.0"
}

// Constants from TLS package
const (
	// TLS Record Types
	RecordTypeChangeCipherSpec = tls.RecordTypeChangeCipherSpec
	RecordTypeAlert            = tls.RecordTypeAlert
	RecordTypeHandshake        = tls.RecordTypeHandshake
	RecordTypeApplicationData  = tls.RecordTypeApplicationData
	RecordTypeHeartbeat        = tls.RecordTypeHeartbeat

	// TLS Handshake Types
	HandshakeTypeClientHello      = tls.HandshakeTypeClientHello
	HandshakeTypeServerHello      = tls.HandshakeTypeServerHello
	HandshakeTypeCertificate      = tls.HandshakeTypeCertificate
	HandshakeTypeFinished         = tls.HandshakeTypeFinished
	HandshakeTypeNewSessionTicket = tls.HandshakeTypeNewSessionTicket
)
