package main

import (
	"encoding/json"
	"os"
)

// OOBChannelConfig is defined in oob.go

// Config represents the application configuration
type Config struct {
	LocalProxyAddr           string             `json:"local_proxy_addr"`
	RelayPort                int                `json:"relay_port"`
	CoverSNI                 string             `json:"cover_sni,omitempty"`
	OOBChannels              []OOBChannelConfig `json:"oob_channels"` // Changed from []OOBChannel
	PrioritizeSNI            bool               `json:"prioritize_sni_concealment"`
	FullClientHelloConcealment bool               `json:"full_clienthello_concealment"`
	HandshakeTimeout         int                `json:"handshake_timeout,omitempty"`
	EnforceTLS13             bool               `json:"enforce_tls13,omitempty"`
}

// LoadConfig reads the configuration from the specified file.
func LoadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
