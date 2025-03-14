package main

import (
	"encoding/json"
	"os"
)

// Config represents the application configuration
type Config struct {
	Mode                      string `json:"mode,omitempty"`
	LocalProxyAddr            string `json:"local_proxy_addr"`
	RemoteProxyAddr           string `json:"remote_proxy_addr,omitempty"`
	CoverSNI                  string `json:"cover_sni,omitempty"`
	PrioritizeSNI             bool   `json:"prioritize_sni_concealment"`
	OOBChannels               int    `json:"oob_channels,omitempty"`
	FullClientHelloConcealment bool   `json:"full_clienthello_concealment"`
	HandshakeTimeout          int    `json:"handshake_timeout,omitempty"`
	ConnectionPoolSize        int    `json:"connection_pool_size,omitempty"`
	EnforceTLS13              bool   `json:"enforce_tls13,omitempty"`
	UseOOBForApplicationData  bool   `json:"use_oob_for_application_data,omitempty"`
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
	
	// Set defaults for any missing values
	if config.Mode == "" {
		config.Mode = "client"
	}
	if config.LocalProxyAddr == "" {
		config.LocalProxyAddr = "127.0.0.1:8080"
	}
	if config.RemoteProxyAddr == "" {
		config.RemoteProxyAddr = "localhost:9090"
	}
	if config.OOBChannels == 0 {
		config.OOBChannels = 2
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = 10000
	}
	if config.ConnectionPoolSize == 0 {
		config.ConnectionPoolSize = 100
	}

	return &config, nil
}
