package relay

import (
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// relayData handles bidirectional data transfer between connections
func relayData(src, dst net.Conn, buffer []byte, label string) {
	defer func() {
		log.Printf("🔹 %s: Connection closed normally", label)
	}()

	var bytesWritten int64

	for {
		// Set read deadline to prevent blocking forever
		src.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := src.Read(buffer)
		src.SetReadDeadline(time.Time{}) // Clear deadline

		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "reset") {
				log.Printf("❌ %s: Error reading: %v", label, err)
			}
			break
		}

		if n > 0 {
			// Log TLS record info if applicable
			if n >= 5 {
				recordType := buffer[0]
				if recordType >= 20 && recordType <= 24 {
					version := (uint16(buffer[1]) << 8) | uint16(buffer[2])
					length := (uint16(buffer[3]) << 8) | uint16(buffer[4])
					log.Printf("🔹 %s: TLS Record: Type=%d, Version=0x%04x, Length=%d/%d",
						label, recordType, version, n-5, n)
					if version == 0x0303 {
						log.Printf("ℹ️ %s: Note: TLS record with 0x0303 version field is normal in both TLS 1.2 and TLS 1.3", label)
					}
				}
			}

			log.Printf("🔒 %s: Ensuring atomic write for complete TLS record (%d bytes)", label, n)
			written, err := dst.Write(buffer[:n])
			if err != nil {
				log.Printf("❌ %s: Error writing: %v", label, err)
				break
			}

			bytesWritten += int64(written)
			log.Printf("✅ %s: TLS record completely written (%d bytes)", label, written)
		}
	}

	log.Printf("✅ %s: Relay complete, %d bytes transferred", label, bytesWritten)
}

// relayDataWithSessionTicketDetection relays data and checks for session tickets
func relayDataWithSessionTicketDetection(src, dst net.Conn, buffer []byte, label string, processData func([]byte)) {
	defer func() {
		log.Printf("🔹 %s: Connection closed normally", label)
	}()

	for {
		src.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := src.Read(buffer)
		src.SetReadDeadline(time.Time{}) // Clear deadline

		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "reset") {
				log.Printf("❌ %s: Error reading: %v", label, err)
			}
			return
		}

		if n > 0 {
			// Check for session ticket in the TLS records
			if n >= 6 && buffer[0] == RecordTypeHandshake && buffer[5] == HandshakeTypeNewSessionTicket {
				log.Printf("🎫 %s: Detected NewSessionTicket message (%d bytes)", label, n)
				
				// Check if we have a handler for this
				if processData != nil {
					processData(buffer[:n])
				}
			} else if n >= 5 {
				recordType, version, _, _ := parseTLSRecordHeader(buffer[:n])
				if recordType >= 20 && recordType <= 24 {
					log.Printf("🔹 %s: TLS Record: Type=%d, Version=0x%04x, Length=%d/%d",
						label, recordType, version, n-5, n)
				}
				
				// Call the optional data processor if provided
				if processData != nil {
					processData(buffer[:n])
				}
			}

			// Write the data
			_, err := dst.Write(buffer[:n])
			if err != nil {
				log.Printf("❌ %s: Error writing: %v", label, err)
				return
			}
		}
	}
}

// biRelayData sets up bidirectional relaying between two connections
func biRelayData(conn1, conn2 net.Conn, label1, label2 string) {
	buffer1 := make([]byte, 32768)
	buffer2 := make([]byte, 32768)
	
	go relayData(conn1, conn2, buffer1, label1)
	go relayData(conn2, conn1, buffer2, label2)
}

// biRelayDataWithTicketDetection sets up bidirectional relaying with session ticket detection
func biRelayDataWithTicketDetection(conn1, conn2 net.Conn, label1, label2 string, processor func([]byte)) {
	buffer1 := make([]byte, 32768)
	buffer2 := make([]byte, 32768)
	
	go relayDataWithSessionTicketDetection(conn1, conn2, buffer1, label1, nil)
	go relayDataWithSessionTicketDetection(conn2, conn1, buffer2, label2, processor)
}