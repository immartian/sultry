package main

import (
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// RelayStats tracks statistics about a relay
type RelayStats struct {
	BytesSent     int64
	BytesReceived int64
	StartTime     time.Time
	EndTime       time.Time
}

// relayData handles bidirectional data transfer between connections
// This function is used extensively throughout both client and server code
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