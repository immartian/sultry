package main

import (
	"encoding/hex"
	"sultry/pkg/tls"
	"testing"
)

func TestIsHandshakeComplete(t *testing.T) {
	tests := []struct {
		name     string
		hexData  string
		expected bool
	}{
		{
			name:     "Empty data",
			hexData:  "",
			expected: false,
		},
		{
			name:     "Too short for TLS record",
			hexData:  "1601",
			expected: false,
		},
		{
			name:     "Application data record",
			hexData:  "170303001a", // Record type 23 (application data), TLS 1.2, length 26
			expected: true,
		},
		{
			name:     "Handshake record but not Finished",
			hexData:  "160303003a0100", // Handshake record but type 1 (ClientHello)
			expected: false,
		},
		{
			name:     "Finished message",
			hexData:  "1603030005140000", // Handshake record with type 20 (Finished)
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := hex.DecodeString(tt.hexData)
			if err != nil {
				t.Fatalf("Failed to decode hex data: %v", err)
			}

			result := tls.IsHandshakeComplete(data)
			if result != tt.expected {
				t.Errorf("tls.IsHandshakeComplete() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsSessionTicketMessage(t *testing.T) {
	tests := []struct {
		name     string
		hexData  string
		expected bool
	}{
		{
			name:     "Empty data",
			hexData:  "",
			expected: false,
		},
		{
			name:     "Too short for TLS record",
			hexData:  "1603",
			expected: false,
		},
		{
			name:     "Not a handshake record",
			hexData:  "15030300", // Alert record
			expected: false,
		},
		{
			name:     "Handshake record but not NewSessionTicket",
			hexData:  "1603030001", // Handshake record but not the right type
			expected: false,
		},
		{
			name:     "NewSessionTicket message",
			hexData:  "160303000104", // Handshake record with type 4 (NewSessionTicket)
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := hex.DecodeString(tt.hexData)
			if err != nil {
				t.Fatalf("Failed to decode hex data: %v", err)
			}

			result := tls.IsSessionTicketMessage(data)
			if result != tt.expected {
				t.Errorf("tls.IsSessionTicketMessage() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseTLSRecordHeader(t *testing.T) {
	tests := []struct {
		name        string
		hexData     string
		wantType    byte
		wantVersion uint16
		wantLength  uint16
		wantError   bool
	}{
		{
			name:        "Empty data",
			hexData:     "",
			wantType:    0,
			wantVersion: 0,
			wantLength:  0,
			wantError:   true,
		},
		{
			name:        "Too short for TLS record",
			hexData:     "1603",
			wantType:    0,
			wantVersion: 0,
			wantLength:  0,
			wantError:   true,
		},
		{
			name:        "Valid TLS record",
			hexData:     "160303002a", // Handshake, TLS 1.2, length 42
			wantType:    22,
			wantVersion: 0x0303,
			wantLength:  42,
			wantError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := hex.DecodeString(tt.hexData)
			if err != nil {
				t.Fatalf("Failed to decode hex data: %v", err)
			}

			gotType, gotVersion, gotLength, err := tls.ParseTLSRecordHeader(data)

			if (err != nil) != tt.wantError {
				t.Errorf("tls.ParseTLSRecordHeader() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError {
				if gotType != tt.wantType {
					t.Errorf("tls.ParseTLSRecordHeader() type = %v, want %v", gotType, tt.wantType)
				}
				if gotVersion != tt.wantVersion {
					t.Errorf("tls.ParseTLSRecordHeader() version = %v, want %v", gotVersion, tt.wantVersion)
				}
				if gotLength != tt.wantLength {
					t.Errorf("tls.ParseTLSRecordHeader() length = %v, want %v", gotLength, tt.wantLength)
				}
			}
		})
	}
}
