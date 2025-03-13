package main

import (
	"encoding/binary"
	"log"
)

// TLS Record Types
const (
	RecordTypeChangeCipherSpec = 20
	RecordTypeAlert           = 21
	RecordTypeHandshake       = 22
	RecordTypeApplicationData = 23
	RecordTypeHeartbeat       = 24
)

// TLS Handshake Types
const (
	HandshakeTypeClientHello         = 1
	HandshakeTypeServerHello         = 2
	HandshakeTypeCertificate         = 11
	HandshakeTypeServerKeyExchange   = 12
	HandshakeTypeCertificateRequest  = 13
	HandshakeTypeServerHelloDone     = 14
	HandshakeTypeClientKeyExchange   = 16
	HandshakeTypeFinished            = 20
	HandshakeTypeNewSessionTicket    = 4
)

// parseTLSRecordHeader parses a TLS record header (renamed to avoid conflict)
func parseTLSRecordHeader(data []byte) (byte, uint16, uint16, error) {
	if len(data) < 5 {
		return 0, 0, 0, nil
	}

	recordType := data[0]
	version := binary.BigEndian.Uint16(data[1:3])
	length := binary.BigEndian.Uint16(data[3:5])

	return recordType, version, length, nil
}

// isHandshakeComplete determines if a TLS handshake has been completed
func isHandshakeComplete(data []byte) bool {
    // Check for TLS 1.3 handshake completion
    // (Look for Finished message or application data)
    
    // Check for basic TLS record type
    if len(data) < 5 {
        return false
    }
    
    recordType := data[0]
    if recordType == RecordTypeApplicationData {
        return true
    }
    
    // Check for Finished message in TLS 1.3
    if recordType == RecordTypeHandshake && len(data) > 6 && data[5] == HandshakeTypeFinished {
        return true // Handshake type 20 is Finished
    }
    
    return false
}

// isSessionTicketMessage determines if a TLS message is a NewSessionTicket
func isSessionTicketMessage(data []byte) bool {
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

// analyzeTLSHandshakeStatus analyzes TLS message for handshake progress (renamed to avoid conflict)
func analyzeTLSHandshakeStatus(message []byte) (isHandshake bool, isComplete bool) {
	if len(message) < 5 {
		return false, false
	}

	recordType, _, _, _ := parseTLSRecordHeader(message)
	
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
	
	recordType, version, msgLen, _ := parseTLSRecordHeader(data)
	
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
	case 0x0301:
		versionStr = "TLS 1.0"
	case 0x0302:
		versionStr = "TLS 1.1"
	case 0x0303:
		versionStr = "TLS 1.2"
	case 0x0304:
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