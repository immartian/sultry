package tls

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
)

// TLS Record Types constants
const (
	RecordTypeChangeCipherSpec = 20
	RecordTypeAlert            = 21
	RecordTypeHandshake        = 22
	RecordTypeApplicationData  = 23
	RecordTypeHeartbeat        = 24
)

// TLS Handshake Types constants
const (
	HandshakeTypeClientHello        = 1
	HandshakeTypeServerHello        = 2
	HandshakeTypeCertificate        = 11
	HandshakeTypeServerKeyExchange  = 12
	HandshakeTypeCertificateRequest = 13
	HandshakeTypeServerHelloDone    = 14
	HandshakeTypeClientKeyExchange  = 16
	HandshakeTypeFinished           = 20
	HandshakeTypeNewSessionTicket   = 4
)

// TLS Version constants
const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)

// ParseTLSRecordHeader parses a TLS record header
func ParseTLSRecordHeader(data []byte) (byte, uint16, uint16, error) {
	if len(data) < 5 {
		return 0, 0, 0, fmt.Errorf("data too short to be a TLS record: %d bytes", len(data))
	}

	recordType := data[0]
	version := binary.BigEndian.Uint16(data[1:3])
	length := binary.BigEndian.Uint16(data[3:5])

	return recordType, version, length, nil
}

// IsHandshakeComplete determines if a TLS handshake has been completed
func IsHandshakeComplete(data []byte) bool {
	// Check for basic TLS record type
	if len(data) < 5 {
		return false
	}

	recordType := data[0]
	if recordType == RecordTypeApplicationData {
		return true
	}

	// Check for Finished message in TLS
	if recordType == RecordTypeHandshake && len(data) > 6 && data[5] == HandshakeTypeFinished {
		return true
	}

	return false
}

// IsSessionTicketMessage determines if a TLS message is a NewSessionTicket
func IsSessionTicketMessage(data []byte) bool {
	if len(data) < 6 {
		return false
	}

	// Check if it's a handshake record
	if data[0] != RecordTypeHandshake {
		return false
	}

	// Check if it's a NewSessionTicket message (type 4)
	return data[5] == HandshakeTypeNewSessionTicket
}

// analyzeTLSHandshakeStatus analyzes TLS message for handshake progress
func analyzeTLSHandshakeStatus(message []byte) (isHandshake bool, isComplete bool) {
	if len(message) < 5 {
		return false, false
	}

	recordType, _, _, _ := ParseTLSRecordHeader(message)

	// Check if this is a handshake record
	isHandshake = (recordType == RecordTypeHandshake)

	// Application data means handshake is complete
	if recordType == RecordTypeApplicationData {
		return false, true
	}

	// Check for Finished message in handshake
	if isHandshake && len(message) > 5 {
		handshakeType := message[5]
		if handshakeType == HandshakeTypeFinished {
			return true, true
		}
	}

	return isHandshake, false
}

// logTLSRecord logs information about a TLS record for debugging
func logTLSRecord(data []byte, label string) {
	if len(data) < 5 {
		log.Printf("⚠️ %s: Data too short to be a TLS record (%d bytes)", label, len(data))
		return
	}

	recordType, version, msgLen, _ := ParseTLSRecordHeader(data)

	// Determine record type string
	typeStr := "Unknown"
	switch recordType {
	case RecordTypeChangeCipherSpec:
		typeStr = "ChangeCipherSpec"
	case RecordTypeAlert:
		typeStr = "Alert"
	case RecordTypeHandshake:
		typeStr = "Handshake"
	case RecordTypeApplicationData:
		typeStr = "ApplicationData"
	case RecordTypeHeartbeat:
		typeStr = "Heartbeat"
	}

	// Determine TLS version string
	versionStr := "Unknown"
	switch version {
	case VersionTLS10:
		versionStr = "TLS 1.0"
	case VersionTLS11:
		versionStr = "TLS 1.1"
	case VersionTLS12:
		versionStr = "TLS 1.2"
	case VersionTLS13:
		versionStr = "TLS 1.3"
	default:
		versionStr = "Unknown"
	}

	log.Printf("🔹 %s: TLS Record [Type=%s (%d), Version=%s (0x%04x), Length=%d]",
		label, typeStr, recordType, versionStr, version, msgLen)

	// For handshake messages, try to determine the handshake type
	if recordType == RecordTypeHandshake && len(data) >= 6 {
		handshakeType := data[5]
		typeStr := "Unknown"

		switch handshakeType {
		case HandshakeTypeClientHello:
			typeStr = "ClientHello"
		case HandshakeTypeServerHello:
			typeStr = "ServerHello"
		case HandshakeTypeCertificate:
			typeStr = "Certificate"
		case HandshakeTypeServerKeyExchange:
			typeStr = "ServerKeyExchange"
		case HandshakeTypeCertificateRequest:
			typeStr = "CertificateRequest"
		case HandshakeTypeServerHelloDone:
			typeStr = "ServerHelloDone"
		case HandshakeTypeClientKeyExchange:
			typeStr = "ClientKeyExchange"
		case HandshakeTypeFinished:
			typeStr = "Finished"
		case HandshakeTypeNewSessionTicket:
			typeStr = "NewSessionTicket"
		}

		log.Printf("🔹 %s: Handshake Message [Type=%s (%d)]", label, typeStr, handshakeType)
	}
}

// ExtractSNIFromClientHello extracts the Server Name Indication from a ClientHello message
func ExtractSNIFromClientHello(clientHello []byte) (string, error) {
	if len(clientHello) < 43 { // Minimum size for a ClientHello with extensions
		return "", errors.New("client hello too short")
	}

	// Check if it's a handshake record
	if clientHello[0] != RecordTypeHandshake {
		return "", errors.New("not a handshake record")
	}

	// Check if it's a ClientHello message
	if len(clientHello) > 6 && clientHello[5] != HandshakeTypeClientHello {
		return "", errors.New("not a client hello message")
	}

	// Skip record header (5 bytes) and handshake header (4 bytes)
	offset := 9

	// Skip client version (2 bytes)
	offset += 2

	// Skip client random (32 bytes)
	offset += 32

	// Skip session ID
	if offset+1 >= len(clientHello) {
		return "", errors.New("client hello too short - can't read session ID length")
	}
	sessionIDLen := int(clientHello[offset])
	offset += 1 + sessionIDLen

	// Skip cipher suites
	if offset+2 >= len(clientHello) {
		return "", errors.New("client hello too short - can't read cipher suites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(clientHello[offset : offset+2]))
	offset += 2 + cipherSuitesLen

	// Skip compression methods
	if offset+1 >= len(clientHello) {
		return "", errors.New("client hello too short - can't read compression methods length")
	}
	compressionMethodsLen := int(clientHello[offset])
	offset += 1 + compressionMethodsLen

	// Check if we have extensions
	if offset+2 > len(clientHello) {
		return "", errors.New("no extensions in client hello")
	}

	// Get extensions length
	extensionsLen := int(binary.BigEndian.Uint16(clientHello[offset : offset+2]))
	offset += 2

	if offset+extensionsLen > len(clientHello) {
		return "", errors.New("client hello too short - extensions exceed message length")
	}

	// Parse extensions
	endOfExtensions := offset + extensionsLen
	for offset < endOfExtensions {
		// Read extension type and length
		if offset+4 > len(clientHello) {
			return "", errors.New("extension header exceeds message length")
		}
		extensionType := binary.BigEndian.Uint16(clientHello[offset : offset+2])
		extensionLen := int(binary.BigEndian.Uint16(clientHello[offset+2 : offset+4]))
		offset += 4

		// Check if it's the server name extension (type 0)
		if extensionType == 0 {
			// Skip server name list length
			if offset+2 > len(clientHello) {
				return "", errors.New("server name extension too short")
			}
			serverNameListLen := int(binary.BigEndian.Uint16(clientHello[offset : offset+2]))
			offset += 2

			// Check if we have enough data for the server name list
			if offset+serverNameListLen > len(clientHello) {
				return "", errors.New("server name list exceeds message length")
			}

			// Read server name entries
			endOfList := offset + serverNameListLen
			for offset < endOfList {
				// Read name type and length
				if offset+3 > len(clientHello) {
					return "", errors.New("server name entry exceeds message length")
				}
				nameType := clientHello[offset]
				nameLen := int(binary.BigEndian.Uint16(clientHello[offset+1 : offset+3]))
				offset += 3

				// Check if it's a hostname (type 0)
				if nameType == 0 {
					if offset+nameLen > len(clientHello) {
						return "", errors.New("hostname exceeds message length")
					}
					hostname := string(clientHello[offset : offset+nameLen])
					return hostname, nil
				}

				// Skip to next entry
				offset += nameLen
			}

			return "", errors.New("no hostname found in server name extension")
		}

		// Skip to next extension
		offset += extensionLen
	}

	return "", errors.New("no server name extension found")
}
