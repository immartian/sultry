package test

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
)

func main() {
	// Set up a proxy URL
	proxyURL, err := url.Parse("http://127.0.0.1:7008")
	if err != nil {
		log.Fatalf("Failed to parse proxy URL: %v", err)
	}

	// Create a Transport that uses the proxy
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		// Disable HTTP/2 for maximum compatibility
		ForceAttemptHTTP2: false,
		// Set reasonable timeouts
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
	}

	// Create an HTTP client that uses the transport
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Minute,
	}

	// Test URLs to verify proxy functionality
	testURLs := []string{
		"https://www.google.com/",
		"https://www.example.com/",
		"https://www.cnn.com/",
	}

	// Test each URL
	for _, testURL := range testURLs {
		fmt.Printf("\n--- Testing URL: %s ---\n\n", testURL)

		// Create the request
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			fmt.Printf("Failed to create request for %s: %v\n", testURL, err)
			continue
		}

		// Add some basic headers
		req.Header.Set("User-Agent", "Sultry-Test-Client/1.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		// Execute the request
		startTime := time.Now()
		resp, err := client.Do(req)
		requestTime := time.Since(startTime)

		if err != nil {
			fmt.Printf("❌ Request failed for %s: %v\n", testURL, err)
			continue
		}

		// Always close response body
		defer resp.Body.Close()

		// Read the response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("❌ Failed to read response body: %v\n", err)
			continue
		}

		// Print information about the response
		fmt.Printf("✅ Successfully fetched %s\n", testURL)
		fmt.Printf("Status: %s\n", resp.Status)
		fmt.Printf("Request time: %v\n", requestTime)
		fmt.Printf("Response size: %d bytes\n", len(body))
		fmt.Printf("Content type: %s\n", resp.Header.Get("Content-Type"))

		// Print the first 200 characters of the response for verification
		preview := body
		if len(preview) > 200 {
			preview = preview[:200]
		}
		fmt.Printf("Response preview: %s\n", string(preview))
	}
}
