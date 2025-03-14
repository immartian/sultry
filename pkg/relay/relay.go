package relay

import (
	"io"
	"log"
	"net"
	"strings"
	"time"

	"sultry/pkg/tls"
)

// RelayData handles bidirectional data transfer between connections with enhanced TLS handling
func RelayData(source, destination net.Conn, buffer []byte, label string) {
	var totalBytes int64

	for {
		// Read from source with timeout
		source.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := source.Read(buffer)
		source.SetReadDeadline(time.Time{})

		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "use of closed") {
				log.Printf("🔹 %s: Connection closed normally", label)
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("🔹 %s: Read timeout, continuing...", label)
				continue
			} else {
				log.Printf("❌ %s: Error reading: %v", label, err)
			}
			break
		}

		if n > 0 {
			// Log what we're relaying (first few bytes only)
			if n >= 5 {
				recordType := buffer[0]
				// Only interpret as TLS record if it's a valid TLS record type
				if recordType >= tls.RecordTypeChangeCipherSpec && recordType <= tls.RecordTypeHeartbeat {
					version := (uint16(buffer[1]) << 8) | uint16(buffer[2])
					length := (uint16(buffer[3]) << 8) | uint16(buffer[4])
					expectedLen := int(length) + 5 // record header (5 bytes) + payload length

					// Enhanced version logging with human-readable format
					versionStr := "Unknown"
					if version == tls.VersionTLS12 {
						versionStr = "TLS1.2"
					} else if version == tls.VersionTLS13 {
						versionStr = "TLS1.3"
					} else if version == tls.VersionTLS10 {
						versionStr = "TLS1.0"
					} else if version == tls.VersionTLS11 {
						versionStr = "TLS1.1"
					}

					// CRITICAL: Verify we have a complete TLS record
					// TLS requires exact record boundaries for MAC verification
					if n < expectedLen {
						log.Printf("⚠️ %s: Incomplete TLS record: got %d bytes, expected %d",
							label, n, expectedLen)

						// For TLS, incomplete records will cause MAC failures
						// but they are commonly seen with large certificates
						if recordType == tls.RecordTypeHandshake {
							log.Printf("ℹ️ %s: Handshake record may be split across multiple TCP segments (normal)", label)
						}
					}

					log.Printf("🔹 %s: TLS Record: Type=%d (%s), Version=%s (0x%04x), Length=%d/%d",
						label, recordType, getTLSRecordTypeName(recordType), versionStr, version, length, n)

					// Special handling for TLS 1.3 records with 0x0303 version field
					// This is normal in TLS 1.3, which uses 0x0303 in the record layer for compatibility
					if version == tls.VersionTLS12 {
						log.Printf("ℹ️ %s: Note: TLS record with 0x0303 version field is normal in both TLS 1.2 and TLS 1.3", label)
					}
				} else {
					// This is likely application data
					log.Printf("🔹 %s: Application data: %d bytes", label, n)
				}
			}

			// Write to destination immediately to avoid buffering delays
			// For TLS records, we must ensure they're written completely and atomically
			written, err := destination.Write(buffer[:n])
			if err != nil {
				log.Printf("❌ %s: Error writing: %v", label, err)
				break
			}

			totalBytes += int64(written)

			if written < n {
				log.Printf("⚠️ %s: Short write: %d/%d bytes", label, written, n)
			}
		}
	}

	log.Printf("✅ %s: Relay complete, total bytes transferred: %d", label, totalBytes)
}

// Helper function to get readable TLS record type names
func getTLSRecordTypeName(recordType byte) string {
	switch recordType {
	case tls.RecordTypeChangeCipherSpec:
		return "ChangeCipherSpec"
	case tls.RecordTypeAlert:
		return "Alert"
	case tls.RecordTypeHandshake:
		return "Handshake"
	case tls.RecordTypeApplicationData:
		return "ApplicationData"
	case tls.RecordTypeHeartbeat:
		return "Heartbeat"
	default:
		return "Unknown"
	}
}

// RelayDataWithSessionTicketDetection relays data and checks for session tickets
func RelayDataWithSessionTicketDetection(src, dst net.Conn, buffer []byte, label string, processData func([]byte)) {
	var totalBytes int64

	for {
		// Read from source with timeout
		src.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := src.Read(buffer)
		src.SetReadDeadline(time.Time{})

		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "use of closed") {
				log.Printf("🔹 %s: Connection closed normally", label)
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("🔹 %s: Read timeout, continuing...", label)
				continue
			} else {
				log.Printf("❌ %s: Error reading: %v", label, err)
			}
			break
		}

		if n > 0 {
			// Check for session ticket in the TLS records
			if tls.IsSessionTicketMessage(buffer[:n]) {
				log.Printf("🎫 %s: Detected NewSessionTicket message (%d bytes)", label, n)

				// Check if we have a handler for this
				if processData != nil {
					processData(buffer[:n])
				}
			} else if n >= 5 {
				recordType, version, length, err := tls.ParseTLSRecordHeader(buffer[:n])
				if err == nil && recordType >= tls.RecordTypeChangeCipherSpec && recordType <= tls.RecordTypeHeartbeat {
					expectedLen := int(length) + 5 // record header (5 bytes) + payload length

					// Enhanced version logging with human-readable format
					versionStr := "Unknown"
					if version == tls.VersionTLS12 {
						versionStr = "TLS1.2"
					} else if version == tls.VersionTLS13 {
						versionStr = "TLS1.3"
					} else if version == tls.VersionTLS10 {
						versionStr = "TLS1.0"
					} else if version == tls.VersionTLS11 {
						versionStr = "TLS1.1"
					}

					log.Printf("🔹 %s: TLS Record: Type=%d (%s), Version=%s (0x%04x), Length=%d/%d",
						label, recordType, getTLSRecordTypeName(recordType), versionStr, version, length, n)

					// CRITICAL: Verify we have a complete TLS record
					if n < expectedLen {
						log.Printf("⚠️ %s: Incomplete TLS record: got %d bytes, expected %d",
							label, n, expectedLen)

						// Handshake records are often split
						if recordType == tls.RecordTypeHandshake {
							log.Printf("ℹ️ %s: Handshake record may be split across multiple TCP segments (normal)", label)
						}
					}
				}

				// Call the optional data processor if provided
				if processData != nil {
					processData(buffer[:n])
				}
			}

			// Write the data
			written, err := dst.Write(buffer[:n])
			if err != nil {
				log.Printf("❌ %s: Error writing: %v", label, err)
				break
			}

			totalBytes += int64(written)

			if written < n {
				log.Printf("⚠️ %s: Short write: %d/%d bytes", label, written, n)
			}
		}
	}

	log.Printf("✅ %s: Relay complete, total bytes transferred: %d", label, totalBytes)
}

// BiRelayData sets up bidirectional relaying between two connections
func BiRelayData(conn1, conn2 net.Conn, label1, label2 string) {
	buffer1 := make([]byte, 32768)
	buffer2 := make([]byte, 32768)

	go RelayData(conn1, conn2, buffer1, label1)
	go RelayData(conn2, conn1, buffer2, label2)
}

// BiRelayDataWithTicketDetection sets up bidirectional relaying with session ticket detection
func BiRelayDataWithTicketDetection(conn1, conn2 net.Conn, label1, label2 string, processor func([]byte)) {
	buffer1 := make([]byte, 32768)
	buffer2 := make([]byte, 32768)

	go RelayDataWithSessionTicketDetection(conn1, conn2, buffer1, label1, nil)
	go RelayDataWithSessionTicketDetection(conn2, conn1, buffer2, label2, processor)
}

// SimpleRelayConnections provides a direct bidirectional relay between two connections
// This uses io.Copy for maximum efficiency and correct handling of TLS record boundaries
func SimpleRelayConnections(clientConn, targetConn net.Conn) {
	// Use a channel to coordinate shutdown
	done := make(chan bool, 2)

	// Client to target
	go func() {
		// We need a large buffer for TLS handshakes with big certificates
		buf := make([]byte, 65536)

		// Create a buffered copy for better performance with TLS
		_, err := io.CopyBuffer(targetConn, clientConn, buf)
		if err != nil && err != io.EOF {
			log.Printf("❌ Error in client→target relay: %v", err)
		}

		// Signal completion and close connection
		done <- true
	}()

	// Target to client
	go func() {
		// We need a large buffer for TLS handshakes with big certificates
		buf := make([]byte, 65536)

		// Create a buffered copy for better performance with TLS
		_, err := io.CopyBuffer(clientConn, targetConn, buf)
		if err != nil && err != io.EOF {
			log.Printf("❌ Error in target→client relay: %v", err)
		}

		// Signal completion and close connection
		done <- true
	}()

	// Wait for both goroutines to finish
	<-done

	// Ensure both connections are closed
	clientConn.Close()
	targetConn.Close()

	// Drain the channel
	select {
	case <-done:
	default:
	}

	log.Printf("✅ Connection relay completed")
}
