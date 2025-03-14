package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// min returns the smaller of x or y.
func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// expandPath expands ~ to the user's home directory
func expandPath(path string) string {
	if path == "" {
		return ""
	}

	if path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[1:])
	}

	return path
}

// parseEnvInt parses an environment variable as an integer with a default value
func parseEnvInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	intValue, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}

	return intValue
}

// parseEnvBool parses an environment variable as a boolean with a default value
func parseEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	lowerValue := strings.ToLower(value)
	if lowerValue == "true" || lowerValue == "yes" || lowerValue == "1" {
		return true
	}
	if lowerValue == "false" || lowerValue == "no" || lowerValue == "0" {
		return false
	}

	return defaultValue
}

// contains checks if a string is in a slice of strings
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}