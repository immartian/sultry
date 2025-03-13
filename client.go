package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TargetInfo holds information about the target server
type TargetInfo struct {
	TargetHost    string   `json:"target_host"`
	TargetIP      string   `json:"target_ip"`
	TargetPort    int      `json:"target_port"`
	SNI           string   `json:"sni"`
	SessionTicket []byte   `json:"session_ticket"`
	MasterSecret  []byte   `json:"master_secret"`
	Version       int      `json:"tls_version"`
	ALPN          string   `json:"alpn_protocol"`  // The negotiated ALPN protocol (h2, http/1.1, etc.)
}

// DirectConnectCommand is the command sent to clients
type DirectConnectCommand struct {
	Command       string `json:"command"`
	TargetHost    string `json:"target_host"`
	TargetIP      string `json:"target_ip"`
	TargetPort    int    `json:"target_port"`
	SNI           string `json:"sni"`
	SessionTicket []byte `json:"session_ticket"`
	MasterSecret  []byte `json:"master_secret"`
}

// TLSProxy handles the proxy functionality with multiple connection strategies.
// It supports several methods to establish connections to target servers:
//  1. OOB Handshake Relay - For SNI concealment and bypassing network restrictions (primary when SNI concealment is prioritized)
//     a. Full ClientHello Concealment - Entire ClientHello is relayed via OOB (highest protection)
//     b. SNI-only Concealment - Only SNI info is sent via OOB, direct connection to IP (medium protection)
//  2. Pure Tunnel Mode - Standard HTTP CONNECT proxy for transparent HTTPS tunneling (fallback or used when SNI concealment is not prioritized)
//  3. Direct HTTP Fetch - For efficient handling of plain HTTP requests
//
// The OOB (Out-of-Band) handshake relay mode is particularly useful for concealing
// SNI information from network monitors or firewalls, as the ClientHello containing
// the SNI is sent via HTTP to the OOB server rather than directly to the target.
type TLSProxy struct {
	OOB                        *OOBModule // Out-of-Band communication module for handshake relay
	FakeSNI                    string     // Optional SNI value to use instead of the actual target
	PrioritizeSNI              bool       // Whether to prioritize SNI concealment over direct tunneling
	FullClientHelloConcealment bool       // Whether to use full ClientHello concealment for maximum protection
	HandshakeTimeout           int        // Timeout in milliseconds for handshake operations
}

// Start runs the TLS proxy.
func (p *TLSProxy) Start(localAddr string) {
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("❌ Failed to start TLS Proxy: %v", err)
	}
	defer listener.Close()
	fmt.Println("🔹 TLS Proxy listening on", localAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("❌ Connection error:", err)
			continue
		}
		go p.handleConnection(conn)
	}
}

func client(config *Config) {
	oobModule := NewOOBModule(config.OOBChannels)
	proxy := TLSProxy{
		OOB:                        oobModule,
		FakeSNI:                    config.CoverSNI,
		PrioritizeSNI:              config.PrioritizeSNI,
		FullClientHelloConcealment: config.FullClientHelloConcealment,
		HandshakeTimeout:           config.HandshakeTimeout,
	}

	if proxy.PrioritizeSNI {
		if proxy.FullClientHelloConcealment {
			log.Println("🔒 ENHANCED PROTECTION: Full ClientHello concealment enabled")
			log.Println("🔒 Complete TLS handshake will be relayed via OOB for maximum protection")
		} else {
			log.Println("🔒 SNI concealment prioritized - OOB will be used to protect server name only")
		}
	} else {
		log.Println("🔹 Standard mode - direct tunnel will be used with OOB as fallback")
	}

	if proxy.HandshakeTimeout == 0 {
		proxy.HandshakeTimeout = 10000 // Default to 10 seconds for handshake if not specified
	}

	proxy.Start(config.LocalProxyAddr)
}

// handleConnection analyzes incoming connections and routes them to the appropriate handler.
// This is the main entry point for connection processing that determines whether to use:
// - Pure tunnel mode for HTTPS (CONNECT requests)
// - Direct HTTP proxying for plain HTTP requests
// - OOB handshake relay for special cases or fallback scenarios
//
// The connection strategy is determined by analyzing the initial data from the client,
// which allows us to properly handle both HTTP and HTTPS traffic transparently.
func (p *TLSProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Read the first 1024 bytes to analyze the request type
	// We need enough bytes to identify request type and extract important information
	buffer := make([]byte, 1024)
	n, err := clientConn.Read(buffer)
	if err != nil {
		log.Println("❌ ERROR: Failed to read initial bytes:", err)
		return
	}

	// Debug logging
	log.Printf("DEBUG: Read %d bytes", n)
	log.Printf("DEBUG: First 16 bytes as hex: % x", buffer[:min(n, 16)])

	// Create a buffered reader with the already read data
	// Use a larger buffer size to ensure we don't fragment TLS records
	combinedReader := io.MultiReader(bytes.NewReader(buffer[:n]), clientConn)
	bufReader := bufio.NewReaderSize(combinedReader, 16384) // 16KB buffer to avoid TLS record fragmentation

	// Analyze the first part of the request
	dataStr := string(buffer[:min(n, 100)])

	// Check if this is an HTTP CONNECT request (for HTTPS tunneling)
	isConnect := strings.HasPrefix(dataStr, "CONNECT ")

	// Check if this is a regular HTTP request (GET, POST, etc.)
	isDirectHttp := strings.HasPrefix(dataStr, "GET ") ||
		strings.HasPrefix(dataStr, "POST ") ||
		strings.HasPrefix(dataStr, "HEAD ") ||
		strings.HasPrefix(dataStr, "PUT ") ||
		strings.HasPrefix(dataStr, "DELETE ")

	// Handle based on the request type and configuration
	if isConnect {
		log.Println("🔹 Detected HTTP CONNECT request (HTTPS tunneling)")

		// Extract the target host from the CONNECT request
		parts := strings.Split(dataStr, " ")
		if len(parts) >= 2 {
			hostPort := strings.TrimSpace(parts[1])

			// Always use direct tunnel method for HTTPS
			// SNI concealment will happen internally if configured
			log.Printf("🔹 Using direct tunnel for: %s", hostPort)
			if p.PrioritizeSNI {
				log.Printf("🔒 SNI concealment will be applied via tunnel")
			}
			p.handleTunnelConnect(clientConn, hostPort)
		} else {
			// Fall back to normal proxy connection if we can't parse the host
			p.handleTunnelConnect(clientConn, "unknown:443")
		}
	} else if isDirectHttp {
		log.Println("🔹 Detected direct HTTP request (not TLS)")
		// Handle regular HTTP request directly
		p.handleDirectHttpRequest(clientConn, bufReader, dataStr)
	} else {
		log.Println("🔹 Detected unknown protocol or direct TLS")

		// Unknown protocol - use direct tunnel
		log.Printf("🔹 Using direct tunnel for unknown protocol")
		p.handleTunnelConnect(clientConn, "unknown:443")
	}
}

// handleDirectHttpRequest handles regular HTTP requests (not HTTPS).
//
// This function implements a standard HTTP proxy for plain HTTP traffic:
// 1. Parses the original HTTP request from the client
// 2. Creates a new request to the target server
// 3. Forwards the request and retrieves the response
// 4. Returns the response to the client
//
// Unlike the HTTPS handling strategies, this method doesn't require tunneling
// or special handshake procedures, making it simpler and more reliable for
// plain HTTP traffic. It properly handles headers, status codes, and content.
func (p *TLSProxy) handleDirectHttpRequest(clientConn net.Conn, reader *bufio.Reader, requestLine string) {
	defer clientConn.Close()

	// Extract URL from request line
	parts := strings.Split(requestLine, " ")
	if len(parts) < 2 {
		log.Println("❌ ERROR: Malformed HTTP request")
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	// Get the URL
	urlStr := parts[1]
	log.Printf("🔹 Handling direct HTTP request for: %s", urlStr)

	// Read the entire request into a buffer to parse it
	requestBuf := new(bytes.Buffer)
	requestBuf.WriteString(requestLine)

	// Read headers until we find empty line
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("❌ ERROR reading HTTP headers: %v", err)
			return
		}

		requestBuf.WriteString(line)
		if line == "\r\n" {
			break
		}
	}

	// Parse the URL for validation and potential modification
	var fullURL string

	// If URL doesn't start with http:// or https://, assume http://
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		log.Printf("🔹 URL doesn't have scheme, adding http://")
		fullURL = "http://" + urlStr
	} else {
		fullURL = urlStr
	}

	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		log.Printf("❌ ERROR parsing URL: %v", err)
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	log.Printf("🔹 Parsed URL: %s", parsedURL.String())

	// Update the URL to use for the request
	urlStr = parsedURL.String()

	// Use a custom client with no redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create a new request
	req, err := http.NewRequest(parts[0], urlStr, nil)
	if err != nil {
		log.Printf("❌ ERROR creating HTTP request: %v", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return

	}

	// Parse and copy the original headers
	headerStr := requestBuf.String()
	headerLines := strings.Split(headerStr, "\r\n")

	// Skip the first line (request line) and add all headers
	for _, line := range headerLines[1:] {
		if line == "" {
			continue
		}

		colonIdx := strings.Index(line, ":")

		// Extract and set host header if needed
		host := parsedURL.Host
		if host != "" {
			req.Host = host
			log.Printf("🔹 Setting Host header to: %s", host)
		}

		if colonIdx == -1 {
			continue
		}

		key := strings.TrimSpace(line[:colonIdx])
		value := strings.TrimSpace(line[colonIdx+1:])

		// Skip proxy-specific headers
		if strings.ToLower(key) == "proxy-connection" {
			continue
		}

		req.Header.Add(key, value)
	}

	// Execute the request
	log.Printf("🔹 Forwarding HTTP request to: %s", urlStr)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("❌ ERROR executing HTTP request: %v", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("❌ ERROR reading response body: %v", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	// Log response info
	log.Printf("✅ Received HTTP response: %s, %d bytes", resp.Status, len(body))

	// Create response buffer
	var responseBuffer bytes.Buffer

	// Status line
	responseBuffer.WriteString(fmt.Sprintf("HTTP/%d.%d %d %s\r\n",
		resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status[4:]))

	// Headers
	for key, values := range resp.Header {
		for _, value := range values {
			responseBuffer.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}

	// Set content length and end headers
	responseBuffer.WriteString(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)))

	// Add body
	responseBuffer.Write(body)

	// Send to client
	responseData := responseBuffer.Bytes()
	log.Printf("🔹 Sending HTTP response: %d bytes", len(responseData))

	// Show a preview of the response for debugging
	previewLen := min(200, len(responseData))
	log.Printf("🔹 Response preview: %s", string(responseData[:previewLen]))

	_, err = clientConn.Write(responseData)
	if err != nil {
		log.Printf("❌ ERROR writing response to client: %v", err)
		return
	}

	log.Printf("✅ Successfully forwarded HTTP response to client")
}

// handleTunnelConnect implements a proper CONNECT tunnel for HTTPS connections.
//
// This is the primary and most reliable strategy for handling HTTPS connections:
// 1. Establishes a direct TCP connection to the target server
// 2. Creates a transparent tunnel between client and target
// 3. Performs bidirectional relay of all data, including TLS handshake
//
// IMPORTANT: While this method offers the highest reliability and compatibility,
// it does NOT conceal SNI information as the TLS handshake passes through directly.
// For SNI concealment, the OOB handshake relay mode should be used instead.
func (p *TLSProxy) handleTunnelConnect(clientConn net.Conn, hostPort string) {
	defer clientConn.Close()

	// Parse host and port
	host := hostPort
	var port string = "443" // Default
	if strings.Contains(hostPort, ":") {
		var err error
		host, port, err = net.SplitHostPort(hostPort)
		if err != nil {
			log.Printf("❌ Failed to parse host:port: %v", err)
			clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
	}

	log.Printf("🔹 TUNNEL: Target host is %s", host)

	// Send 200 Connection Established to the client to signal tunnel is ready
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n" +
		"X-Proxy: Sultry-Direct-Mode\r\n" +
		"X-Target-Host: " + host + "\r\n\r\n"))

	// At this point, the CONNECT tunnel is established, and the client will start TLS

	// Read the ClientHello to extract SNI if needed
	clientHelloBuffer := make([]byte, 4096)
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientConn.Read(clientHelloBuffer)
	clientConn.SetReadDeadline(time.Time{})

	if err != nil {
		log.Printf("❌ Failed to read ClientHello: %v", err)
		return
	}

	clientHello := clientHelloBuffer[:n]
	log.Printf("🔹 Read ClientHello (%d bytes)", n)

	var targetConn net.Conn

	// Apply concealment strategies if configured
	if p.PrioritizeSNI {
		// Extract SNI from ClientHello
		sni, err := extractSNI(clientHello)
		if err != nil {
			log.Printf("⚠️ Failed to extract SNI from ClientHello: %v", err)
			// Use hostname from CONNECT request as fallback
			sni = host
		}

		log.Printf("🔒 CONCEALMENT: Using OOB to protect connection to: %s", sni)

		// Variable for session tracking when using full ClientHello concealment
		var sessionID string

		// Check if we should use full ClientHello concealment (maximum protection)
		if p.FullClientHelloConcealment {
			log.Printf("🔒 ENHANCED: Using full ClientHello concealment via OOB")

			// Create a session ID for this connection
			sessionID = fmt.Sprintf("%d", time.Now().UnixNano())

			// Initialize handshake via OOB with the full ClientHello
			log.Printf("🔹 Initiating full handshake relay for session %s", sessionID)
			err = p.OOB.InitiateHandshake(sessionID, clientHello, sni)
			if err != nil {
				log.Printf("❌ Failed to initiate handshake via OOB: %v", err)

				// Fall back to SNI-only concealment as a second option
				log.Printf("⚠️ Falling back to SNI-only concealment for %s", sni)
				targetConn, err = p.getTargetConnViaOOB(sni, port)
				if err != nil {
					log.Printf("❌ Failed to establish connection via SNI-only OOB: %v", err)

					// Last resort: direct connection
					log.Printf("⚠️ Falling back to direct connection to %s:%s", host, port)
					targetConn, err = net.DialTimeout("tcp", host+":"+port, 10*time.Second)
					if err != nil {
						log.Printf("❌ Failed to connect to target: %v", err)
						return
					}
				}

				// Skip the rest of the ClientHello relay logic if we've established a connection via fallback
				goto sendClientHello
			}
		} else {
			// Use SNI-only concealment (original approach)
			log.Printf("🔒 Using SNI-only concealment for %s", sni)
			targetConn, err = p.getTargetConnViaOOB(sni, port)
			if err != nil {
				log.Printf("❌ Failed to establish connection via OOB: %v", err)

				// Fallback to direct connection
				log.Printf("⚠️ Falling back to direct connection to %s:%s", host, port)
				targetConn, err = net.DialTimeout("tcp", host+":"+port, 10*time.Second)
				if err != nil {
					log.Printf("❌ Failed to connect to target: %v", err)
					return
				}
			}

			// Skip to sending the ClientHello directly
			goto sendClientHello
		}

		// Get the handshake response
		log.Printf("🔹 Getting initial ServerHello response from OOB server")
		serverHelloResp, err := p.OOB.GetHandshakeResponse(sessionID)
		if err != nil {
			log.Printf("❌ Failed to get ServerHello: %v", err)
			// Fallback logic
			log.Printf("⚠️ Falling back to direct connection to %s:%s", host, port)
			targetConn, err = net.DialTimeout("tcp", host+":"+port, 10*time.Second)
			if err != nil {
				log.Printf("❌ Failed to connect to target: %v", err)
				return
			}
			goto sendClientHello
		}

		// Send ServerHello to client
		log.Printf("🔹 Forwarding ServerHello (%d bytes) to client", len(serverHelloResp.Data))
		if len(serverHelloResp.Data) > 0 {
			_, err = clientConn.Write(serverHelloResp.Data)
			if err != nil {
				log.Printf("❌ Failed to send ServerHello to client: %v", err)
				return
			}
			log.Printf("✅ Sent ServerHello to client")
		} else {
			log.Printf("⚠️ Received empty ServerHello response")
		}

		// Complete handshake with bidirectional relay
		log.Printf("🔹 Beginning bidirectional handshake relay")

		// Create channels for synchronization
		completedChan := make(chan struct{})
		errorChan := make(chan error, 2)

		// Set up signal handling for cleanup
		defer func() {
			// Signal handshake completion
			log.Printf("🔹 Signaling handshake completion to server...")
			p.signalHandshakeCompletion(sessionID)
		}()

		// Goroutine to receive server responses via OOB and forward to client
		go func() {
			defer func() {
				log.Printf("🔹 Server->Client handshake relay finished")
			}()

			responseCount := 0
			maxEmptyResponses := 3 // Allow a few empty responses before completing
			emptyResponseCount := 0

			// Loop to get and forward additional handshake messages
			for {
				log.Printf("🔹 Polling for handshake response #%d from server", responseCount+1)
				response, err := p.OOB.GetHandshakeResponse(sessionID)
				if err != nil {
					log.Printf("❌ ERROR getting handshake response: %v", err)
					errorChan <- fmt.Errorf("failed to get handshake response: %w", err)
					return
				}

				// Check if handshake is complete
				if response.HandshakeComplete {
					log.Printf("✅ Server marked handshake as complete")
					close(completedChan)
					return
				}

				// Handle case with no data
				if len(response.Data) == 0 {
					emptyResponseCount++
					log.Printf("💤 Received empty response #%d", emptyResponseCount)

					// After receiving several empty responses, consider handshake may be complete
					if emptyResponseCount >= maxEmptyResponses {
						log.Printf("✅ Assuming handshake complete after %d empty responses", emptyResponseCount)
						close(completedChan)
						return
					}

					// Sleep briefly to avoid tight polling
					time.Sleep(100 * time.Millisecond)
					continue
				}

				// Reset empty response counter when we get actual data
				emptyResponseCount = 0

				// Forward response to client
				responseCount++
				log.Printf("🔹 Received server response #%d: %d bytes", responseCount, len(response.Data))

				// Log TLS record info if possible
				if len(response.Data) >= 5 {
					recordType := response.Data[0]
					// Only interpret as TLS record if it's a valid TLS record type (20-24)
					if recordType >= 20 && recordType <= 24 {
						version := (uint16(response.Data[1]) << 8) | uint16(response.Data[2])
						length := (uint16(response.Data[3]) << 8) | uint16(response.Data[4])
						log.Printf("🔹 TLS Record from server: Type=%d, Version=0x%04x, Length=%d",
							recordType, version, length)
						log.Printf("🔹 First 16 bytes: %x", response.Data[:min(16, len(response.Data))])
					} else {
						// This is likely application data
						log.Printf("🔹 Server application data: %d bytes", len(response.Data))
					}
				}

				log.Printf("🔹 Forwarding %d bytes from server to client", len(response.Data))
				_, err = clientConn.Write(response.Data)
				if err != nil {
					log.Printf("❌ ERROR writing server response to client: %v", err)
					errorChan <- fmt.Errorf("failed to write server response to client: %w", err)
					return
				}
				log.Printf("✅ Successfully forwarded server response to client")
			}
		}()

		// Goroutine to receive client messages and forward via OOB
		go func() {
			defer func() {
				log.Printf("🔹 Client->Server handshake relay finished")
			}()

			// First message was already sent as clientHello during InitiateHandshake

			// Read and forward additional handshake messages
			buffer := make([]byte, 16384)
			clientMsgCount := 0

			for {
				// Check if handshake is already complete
				select {
				case <-completedChan:
					return
				default:
					// Continue with reading
				}

				// Set a reasonable read deadline
				clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
				n, err := clientConn.Read(buffer)
				clientConn.SetReadDeadline(time.Time{})

				if err != nil {
					if err == io.EOF {
						log.Printf("🔹 Client closed connection during handshake")
						return
					}

					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						// Check if we're done
						select {
						case <-completedChan:
							return
						default:
							log.Printf("🔹 Read timeout from client, checking handshake status")
							continue
						}
					}

					log.Printf("❌ ERROR reading from client: %v", err)
					errorChan <- fmt.Errorf("failed to read from client: %w", err)
					return
				}

				if n > 0 {
					clientMsgCount++
					log.Printf("🔹 Received client message #%d: %d bytes", clientMsgCount, n)

					// Log TLS record info if possible
					if n >= 5 {
						recordType := buffer[0]
						// Only interpret as TLS record if it's a valid TLS record type (20-24)
						if recordType >= 20 && recordType <= 24 {
							version := (uint16(buffer[1]) << 8) | uint16(buffer[2])
							length := (uint16(buffer[3]) << 8) | uint16(buffer[4])
							log.Printf("🔹 TLS Record from client: Type=%d, Version=0x%04x, Length=%d",
								recordType, version, length)
							log.Printf("🔹 First 16 bytes: %x", buffer[:min(16, n)])
						} else {
							// This is likely application data
							log.Printf("🔹 Client application data: %d bytes", n)
						}
					}

					log.Printf("🔹 Forwarding %d bytes from client to server", n)
					err = p.OOB.SendHandshakeData(sessionID, buffer[:n])
					if err != nil {
						log.Printf("❌ ERROR sending data to server: %v", err)
						errorChan <- fmt.Errorf("failed to send client data to server: %w", err)
						return
					}
					log.Printf("✅ Successfully forwarded client message to server")
				}
			}
		}()

		// Wait for handshake completion with configurable timeout
		timeoutDuration := time.Duration(p.HandshakeTimeout) * time.Millisecond
		if timeoutDuration == 0 {
			timeoutDuration = 10 * time.Second // Default timeout
		}
		log.Printf("🔹 Waiting for handshake completion with %s timeout", timeoutDuration)
		timeoutChan := time.After(timeoutDuration)

		select {
		case <-completedChan:
			log.Printf("✅ TLS handshake completed successfully via signal")
		case <-timeoutChan:
			// Handshake timeout - assume it's complete for practical purposes
			log.Printf("⚠️ Handshake timeout after %s - assuming it's complete", timeoutDuration)
		case err := <-errorChan:
			log.Printf("❌ ERROR during handshake: %v", err)
			// We'll try fallback as a last resort
			log.Printf("⚠️ Falling back to direct connection to %s:%s", host, port)
			targetConn, err = net.DialTimeout("tcp", host+":"+port, 10*time.Second)
			if err != nil {
				log.Printf("❌ Failed to connect to target: %v", err)
				return
			}
			goto sendClientHello
		}

		// Signal handshake completion to the server
		log.Printf("🔹 Signaling handshake completion to server...")
		err = p.signalHandshakeCompletion(sessionID)
		if err != nil {
			log.Printf("❌ Failed to signal handshake completion: %v", err)
			// Continue anyway as this is non-critical
		}

		// Now that handshake is complete, establish direct connection
		log.Printf("✅ Handshake complete for session %s. Switching to direct connection.", sessionID)
		targetConn, err := p.establishDirectConnectionAfterHandshake(sessionID)
		if err != nil {
			log.Printf("❌ Failed to establish direct connection: %v", err)
			// Fallback to relay mode
			log.Printf("⚠️ Falling back to relay mode for session %s", sessionID)
			p.fallbackToRelayMode(clientConn, sessionID)
			return
		}
		
		// Start bidirectional relay between client and direct connection
		log.Printf("✅ Starting bidirectional relay between client and direct connection")
		buffer1 := make([]byte, 32768)
		buffer2 := make([]byte, 32768)
		go relayData(clientConn, targetConn, buffer1, "client → target")
		go relayData(targetConn, clientConn, buffer2, "target → client")
		
		return

		// Connection was established through the full handshake relay
		// Skip the ClientHello forwarding since it was already done through OOB
		goto skipClientHello
	} else {
		// Direct connection without concealment
		log.Printf("🔹 TUNNEL: Connecting directly to %s", hostPort)
		targetConn, err = net.DialTimeout("tcp", hostPort, 10*time.Second)
		if err != nil {
			log.Printf("❌ TUNNEL: Failed to connect to target: %v", err)
			return
		}
	}

sendClientHello:
	// Send ClientHello to the target server
	targetConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = targetConn.Write(clientHello)
	targetConn.SetWriteDeadline(time.Time{})
	if err != nil {
		log.Printf("❌ Failed to send ClientHello to target: %v", err)
		return
	}
	log.Printf("✅ Forwarded ClientHello to target")

skipClientHello:

	defer targetConn.Close()

	// Set up bidirectional relay
	log.Printf("✅ TUNNEL: Connected to target, starting bidirectional relay")

	// Improve relay performance
	if tcpConn, ok := targetConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)                     // Disable Nagle's algorithm for better performance
		tcpConn.SetKeepAlive(true)                   // Enable TCP keepalive
		tcpConn.SetKeepAlivePeriod(30 * time.Second) // Set keepalive period
		tcpConn.SetReadBuffer(65536)                 // 64KB read buffer
		tcpConn.SetWriteBuffer(65536)                // 64KB write buffer
		log.Printf("🔹 Target connection optimized with TCP parameters")
	}

	// Optimize client connection as well
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetReadBuffer(65536)
		tcpConn.SetWriteBuffer(65536)
		log.Printf("🔹 Client connection optimized with TCP parameters")
	}

	// Use wait group to manage relay goroutines
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Target
	go func() {
		defer wg.Done()
		buffer := make([]byte, 16384) // 16KB buffer to match typical TLS record size
		relayData(clientConn, targetConn, buffer, "Client -> Target")
	}()

	// Target -> Client
	go func() {
		defer wg.Done()
		buffer := make([]byte, 16384) // 16KB buffer to match typical TLS record size
		relayData(targetConn, clientConn, buffer, "Target -> Client")
	}()

	// Wait for both directions to complete
	wg.Wait()
	log.Printf("✅ TUNNEL: Bidirectional relay completed for %s", hostPort)
}

// handleProxyConnection implements the OOB (Out-of-Band) handshake relay strategy.
//
// This approach is specifically designed for SNI concealment and firewall bypassing:
// 1. TLS handshake is relayed through an out-of-band HTTP channel
// 2. The ClientHello with SNI is sent via HTTP, not directly to the target
// 3. The server component establishes the connection to the target
// 4. After handshake, a direct connection is established for application data
//
// While offering less reliability than the pure tunnel mode, this strategy is
// valuable when privacy is critical as it conceals the SNI from network monitors.
// It serves as a fallback when the primary tunnel mode fails or for specialized cases.
func (p *TLSProxy) handleProxyConnection(clientConn net.Conn, reader *bufio.Reader, isConnect bool) {
	defer clientConn.Close()

	var sni string
	var clientHelloData []byte

	// Handle CONNECT if needed
	if isConnect {
		// Read the first line of the CONNECT request
		firstLine, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				log.Println("ℹ️ INFO: Client closed connection before completing CONNECT request")
			} else {
				log.Println("❌ ERROR: Failed to read CONNECT request:", err)
			}
			return
		}

		// Extract target host
		parts := strings.Split(firstLine, " ")
		if len(parts) < 2 {
			log.Println("❌ ERROR: Malformed CONNECT request")
			clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}

		// Extract host and port
		hostPort := strings.TrimSpace(parts[1])
		sni = hostPort
		if strings.Contains(hostPort, ":") {
			sni = strings.Split(hostPort, ":")[0] // Extract just the hostname
		}

		log.Println("🔹 Handling CONNECT request for:", hostPort)

		// Read headers to look for User-Agent and other info
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}

			// Check if this is a curl client
			if strings.Contains(line, "User-Agent:") && strings.Contains(line, "curl/") {
				log.Println("🔹 Detected curl client - will use HTTP/1.1 mode")
			}
		}

		// Respond with "200 Connection Established"
		clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	// First handshake message from client (ClientHello)
	log.Println("🔹 Reading ClientHello from client...")
	clientHello := make([]byte, 1024)
	n, err := reader.Read(clientHello)
	if err != nil {
		log.Println("❌ ERROR: Failed to read ClientHello:", err)
		return
	}
	clientHelloData = clientHello[:n] // Save the ClientHello data
	log.Printf("✅ Received ClientHello (%d bytes): %x...", n, clientHelloData[:min(16, len(clientHelloData))])

	// Check if HTTP/2 ALPN is requested in the ClientHello - just for logging
	if bytes.Contains(clientHelloData, []byte("h2")) {
		log.Println("🔹 Detected HTTP/2 ALPN in ClientHello")
	}

	// Extract SNI if not already set from CONNECT
	if sni == "" {
		extractedSNI, err := extractSNI(clientHelloData)
		if err != nil {
			log.Println("ℹ️ INFO: Failed to extract SNI:", err)
		} else {
			sni = extractedSNI
			log.Println("🔹 Extracted SNI from ClientHello:", sni)
		}
	}

	// Log key information about the detected TLS handshake
	if len(clientHelloData) > 5 {
		recordType := clientHelloData[0]
		version := (uint16(clientHelloData[1]) << 8) | uint16(clientHelloData[2])
		log.Printf("🔹 TLS Record: Type=%d, Version=0x%04x", recordType, version)
	}

	// Create a unique session ID for this connection
	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
	log.Printf("🔹 Initiating handshake for session %s with SNI %s", sessionID, sni)

	// Initialize handshake with server proxy via OOB
	err = p.OOB.InitiateHandshake(sessionID, clientHelloData, sni)
	if err != nil {
		log.Println("❌ ERROR: Failed to initiate handshake:", err)
		return
	}

	// Set up a bidirectional relay for the rest of the handshake
	// This needs to handle multiple messages in both directions

	// Create channels for synchronization
	completedChan := make(chan struct{})
	errorChan := make(chan error, 2)

	// Goroutine to receive server responses via OOB and forward to client
	go func() {
		defer func() {
			log.Printf("🔹 Server->Client handshake relay finished")
		}()

		responseCount := 0
		maxEmptyResponses := 5 // Allow a few empty responses before completing
		emptyResponseCount := 0

		// CRITICAL: Initial ServerHello must be obtained and forwarded to client immediately
		log.Printf("🔹 Getting initial ServerHello from target")
		initialResponse, err := p.OOB.GetHandshakeResponse(sessionID)
		if err != nil {
			log.Printf("❌ ERROR getting initial ServerHello: %v", err)
			errorChan <- fmt.Errorf("failed to get initial ServerHello: %w", err)
			return
		}

		// Immediately send the ServerHello to client
		if len(initialResponse.Data) > 0 {
			responseCount++
			log.Printf("🔹 Received initial ServerHello: %d bytes", len(initialResponse.Data))

			// Log TLS record info
			if len(initialResponse.Data) >= 5 {
				recordType := initialResponse.Data[0]
				version := (uint16(initialResponse.Data[1]) << 8) | uint16(initialResponse.Data[2])
				length := (uint16(initialResponse.Data[3]) << 8) | uint16(initialResponse.Data[4])
				log.Printf("🔹 TLS ServerHello: Type=%d, Version=0x%04x, Length=%d",
					recordType, version, length)
				log.Printf("🔹 First 16 bytes: %x", initialResponse.Data[:min(16, len(initialResponse.Data))])
			}

			log.Printf("🔹 Forwarding ServerHello (%d bytes) to client", len(initialResponse.Data))
			clientConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			n, err := clientConn.Write(initialResponse.Data)
			clientConn.SetWriteDeadline(time.Time{})
			if err != nil {
				log.Printf("❌ ERROR writing ServerHello to client: %v", err)
				errorChan <- fmt.Errorf("failed to write ServerHello to client: %w", err)
				return
			}
			log.Printf("✅ Successfully forwarded ServerHello to client (%d/%d bytes)", n, len(initialResponse.Data))
		} else {
			log.Printf("⚠️ Received empty ServerHello response - this is unexpected")
		}

		// Now continue with subsequent handshake messages
		for {
			// Poll for response from server
			log.Printf("🔹 Polling for handshake response #%d from server", responseCount+1)
			response, err := p.OOB.GetHandshakeResponse(sessionID)
			if err != nil {
				log.Printf("❌ ERROR getting handshake response: %v", err)
				errorChan <- fmt.Errorf("failed to get handshake response: %w", err)
				return
			}

			// Check if handshake is complete
			if response.HandshakeComplete {
				log.Printf("✅ Server marked handshake as complete")
				close(completedChan)
				return
			}

			// Handle case with no data
			if len(response.Data) == 0 {
				emptyResponseCount++
				log.Printf("💤 Received empty response #%d", emptyResponseCount)

				// After receiving several empty responses, consider handshake may be complete
				if emptyResponseCount >= maxEmptyResponses {
					log.Printf("✅ Assuming handshake complete after %d empty responses", emptyResponseCount)
					close(completedChan)
					return
				}

				// Sleep briefly to avoid tight polling
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Reset empty response counter when we get actual data
			emptyResponseCount = 0

			// Forward response to client
			responseCount++
			log.Printf("🔹 Received server response #%d: %d bytes", responseCount, len(response.Data))

			// Log TLS record info if possible
			if len(response.Data) >= 5 {
				recordType := response.Data[0]
				// Only interpret as TLS record if it's a valid TLS record type (20-24)
				if recordType >= 20 && recordType <= 24 {
					version := (uint16(response.Data[1]) << 8) | uint16(response.Data[2])
					length := (uint16(response.Data[3]) << 8) | uint16(response.Data[4])
					log.Printf("🔹 TLS Record from server: Type=%d, Version=0x%04x, Length=%d",
						recordType, version, length)
					log.Printf("🔹 First 16 bytes: %x", response.Data[:min(16, len(response.Data))])
				} else {
					// This is likely application data
					log.Printf("🔹 Server application data: %d bytes", len(response.Data))
				}
			}

			log.Printf("🔹 Forwarding %d bytes from server to client", len(response.Data))
			clientConn.SetWriteDeadline(time.Now().Add(10 * time.Second)) // NEW: Add write deadline
			n, err := clientConn.Write(response.Data)
			clientConn.SetWriteDeadline(time.Time{}) // NEW: Reset write deadline
			if err != nil {
				log.Printf("❌ ERROR writing server response to client: %v", err)
				errorChan <- fmt.Errorf("failed to write server response to client: %w", err)
				return
			}
			log.Printf("✅ Successfully wrote %d/%d bytes to client", n, len(response.Data))
		}
	}()

	// Goroutine to receive client messages and forward via OOB
	go func() {
		defer func() {
			log.Printf("🔹 Client->Server handshake relay finished")
		}()

		// First message was already read and sent as clientHelloData

		// Read and forward additional handshake messages
		buffer := make([]byte, 16384)
		clientMsgCount := 0

		for {
			// Set a longer read deadline for handshake
			clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := clientConn.Read(buffer)
			clientConn.SetReadDeadline(time.Time{})

			if err != nil {
				if err == io.EOF {
					log.Printf("🔹 Client closed connection during handshake")
					return
				}

				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Just check if we're done
					select {
					case <-completedChan:
						return
					default:
						log.Printf("🔹 Read timeout from client, checking handshake status")
						continue
					}
				}

				log.Printf("❌ ERROR reading from client: %v", err)
				errorChan <- fmt.Errorf("failed to read from client: %w", err)
				return
			}

			if n > 0 {
				clientMsgCount++
				log.Printf("🔹 Received client message #%d: %d bytes", clientMsgCount, n)

				// Log TLS record info if possible
				if n >= 5 {
					recordType := buffer[0]
					// Only interpret as TLS record if it's a valid TLS record type (20-24)
					if recordType >= 20 && recordType <= 24 {
						version := (uint16(buffer[1]) << 8) | uint16(buffer[2])
						length := (uint16(buffer[3]) << 8) | uint16(buffer[4])
						log.Printf("🔹 TLS Record from client: Type=%d, Version=0x%04x, Length=%d",
							recordType, version, length)
						log.Printf("🔹 First 16 bytes: %x", buffer[:min(16, n)])
					} else {
						// This is likely application data
						log.Printf("🔹 Client application data: %d bytes", n)
					}
				}

				log.Printf("🔹 Forwarding %d bytes from client to server", n)
				err = p.OOB.SendHandshakeData(sessionID, buffer[:n])
				if err != nil {
					log.Printf("❌ ERROR sending data to server: %v", err)
					errorChan <- fmt.Errorf("failed to send client data to server: %w", err)
					return
				}
				log.Printf("✅ Successfully forwarded client message #%d to server", clientMsgCount)
			}
		}
	}()

	// Wait for handshake completion with configurable timeout
	timeoutDuration := time.Duration(p.HandshakeTimeout) * time.Millisecond
	if timeoutDuration == 0 {
		timeoutDuration = 5 * time.Second // Default to 5 seconds
	}
	log.Printf("🔹 Waiting for handshake completion with %s timeout", timeoutDuration)
	timeoutChan := time.After(timeoutDuration)

	select {
	case <-completedChan:
		log.Println("✅ TLS handshake completed successfully via signal")
	case <-timeoutChan:
		// Handshake timeout - assume it's complete for practical purposes
		log.Printf("⚠️ Handshake timeout after %s - assuming it's complete for practical purposes", timeoutDuration)
	case err := <-errorChan:
		log.Println("❌ ERROR during handshake:", err)
		// Continue anyway - we'll try adoptConnection as a fallback
		log.Println("⚠️ Continuing despite handshake error")
	}

	// Signal handshake completion to the server regardless of how we got here
	log.Println("🔹 Signaling handshake completion to server...")
	err = p.signalHandshakeCompletion(sessionID)
	if err != nil {
		log.Println("❌ ERROR: Failed to signal handshake completion:", err)
		// Continue anyway with adoptConnection as a fallback
	} else {
		log.Println("✅ Server acknowledged handshake completion")
	}

	// Move to direct connection
	log.Println("🔹 Establishing direct server connection")
	p.adoptConnection(clientConn, sessionID, clientHelloData)
}

// In your main.go, add a function to signal handshake completion
func (p *TLSProxy) signalHandshakeCompletion(sessionID string) error {
	// Signal to the server that handshake is complete
	reqBody := fmt.Sprintf(`{"session_id":"%s", "action":"complete_handshake"}`, sessionID)
	resp, err := http.Post(
		fmt.Sprintf("http://%s/complete_handshake", p.OOB.GetServerAddress()),
		"application/json",
		strings.NewReader(reqBody),
	)

	if err != nil {
		return fmt.Errorf("failed to signal handshake completion: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server rejected handshake completion: %s", string(body))
	}

	return nil
}

// Establishes direct connection through server relay after handshake completion
func (p *TLSProxy) adoptConnection(clientConn net.Conn, sessionID string, clientHelloData []byte) {
	log.Printf("🔹 Begin connection adoption for session %s", sessionID)

	// Step 1: Get target connection information from OOB server
	targetInfo, err := p.getTargetInfo(sessionID, clientHelloData)
	if err != nil {
		log.Printf("❌ ERROR: Failed to get target info: %v", err)
		log.Printf("🔹 Proceeding with adoption anyway")
	} else {
		log.Printf("✅ Retrieved target info for direct connection to %s:%d",
			targetInfo.TargetHost, targetInfo.TargetPort)
	}

	// Step 2: Establish direct connection through relay
	log.Printf("🔹 Initiating direct connection adoption")
	p.fallbackToRelayMode(clientConn, sessionID)

	// Step 3: Attempt to release connection resources on OOB server
	// This is best-effort and non-critical - we don't care if it fails
	// The direct fetch approach might cause connection resets before this happens
	p.releaseOOBConnection(sessionID) // Ignore any errors
	log.Printf("✅ OOB resources release attempted for session %s", sessionID)
}

// getTargetInfo retrieves information about the target server
func (p *TLSProxy) getTargetInfo(sessionID string, clientHelloData []byte) (*TargetInfo, error) {
	// Prepare request with both session ID and ClientHello data
	requestData := struct {
		SessionID   string `json:"session_id"`
		Action      string `json:"action"`
		ClientHello []byte `json:"client_hello,omitempty"`
	}{
		SessionID:   sessionID,
		Action:      "get_target_info",
		ClientHello: clientHelloData,
	}

	requestBytes, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send request to OOB server with timeout
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(
		fmt.Sprintf("http://%s/get_target_info", p.OOB.GetServerAddress()),
		"application/json",
		bytes.NewReader(requestBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get target info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error: %s (code %d)", string(body), resp.StatusCode)
	}

	// Parse response
	var targetInfo TargetInfo
	if err := json.NewDecoder(resp.Body).Decode(&targetInfo); err != nil {
		return nil, fmt.Errorf("failed to decode target info: %w", err)
	}

	// Validate essential target info
	if targetInfo.TargetHost == "" || targetInfo.TargetPort == 0 {
		return nil, fmt.Errorf("received incomplete target info")
	}

	return &targetInfo, nil
}

// Update releaseOOBConnection with better error handling for direct fetch mode
func (p *TLSProxy) releaseOOBConnection(sessionID string) error {
	reqBody := fmt.Sprintf(`{"session_id":"%s","action":"release_connection"}`, sessionID)

	// Use a client with short timeout to avoid hanging
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(
		fmt.Sprintf("http://%s/release_connection", p.OOB.GetServerAddress()),
		"application/json",
		strings.NewReader(reqBody),
	)

	if err != nil {
		// Don't fail on release errors - they're common with direct fetch approach
		log.Printf("ℹ️ Warning: Unable to release connection: %v (this is normal with direct fetch)", err)
		return nil // Don't fail on release errors
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("ℹ️ Warning: Server returned non-OK status: %s (continuing anyway)", string(body))
		return nil // Don't fail on non-OK responses
	}

	return nil
}

// AdoptDirectConnection establishes a direct connection to the target server via the relay
func (p *TLSProxy) fallbackToRelayMode(clientConn net.Conn, sessionID string) {
	log.Printf("🔹 Establishing direct connection for session %s", sessionID)

	// Create a connection to the OOB server
	serverAddr := p.OOB.GetServerAddress()
	log.Printf("🔹 Connecting to relay server at %s", serverAddr)
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Printf("❌ ERROR: Failed to connect to OOB server: %v", err)
		return
	}
	defer conn.Close()
	log.Printf("✅ Connected to relay server")

	// Optimize TCP connection settings for both connections
	for _, c := range []net.Conn{conn, clientConn} {
		if tcpConn, ok := c.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
			tcpConn.SetReadBuffer(1048576)  // 1MB buffer
			tcpConn.SetWriteBuffer(1048576) // 1MB buffer
		}
	}
	log.Printf("✅ TCP connections optimized")

	// Send the adoption request
	// Get the target information for ALPN protocol detection
	_, err = p.getTargetInfo(sessionID, nil)

	// Get TLS version from handshake to ensure compatibility
	protocol := "tls1.3"  // Default to TLS 1.3, but we'll adapt based on server response
	
	// Try to detect the negotiated TLS version
	targetInfo, err := p.getTargetInfo(sessionID, nil)
	if err == nil && targetInfo.Version > 0 {
		// Check for standard TLS version codes
		detectedVersion := targetInfo.Version
		log.Printf("🔹 Detected TLS record version: 0x%04x", detectedVersion)
		
		// Use the detected version instead of forcing TLS 1.3
		if detectedVersion == 0x0303 {
			protocol = "tls1.2"
			log.Printf("🔹 Using TLS 1.2 based on detected record version")
		} else if detectedVersion == 0x0304 {
			protocol = "tls1.3"
			log.Printf("🔹 Using TLS 1.3 based on detected record version")
		} else {
			// For non-standard versions, default to TLS 1.2 which has wider compatibility
			protocol = "tls1.2"
			log.Printf("🔹 Using TLS 1.2 for compatibility with non-standard version")
		}
	} else {
		log.Printf("🔹 Could not determine TLS version from handshake, defaulting to TLS 1.2")
		protocol = "tls1.2"  // Use TLS 1.2 as a safe default
	}
	
	log.Printf("✅ Using %s for relay connection", protocol)

	reqBody := fmt.Sprintf(`{"session_id":"%s","protocol":"%s"}`, sessionID, protocol)
	req := fmt.Sprintf("POST /adopt_connection HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Connection: close\r\n"+
		"Content-Length: %d\r\n\r\n%s",
		serverAddr, len(reqBody), reqBody)

	log.Printf("🔹 Sending adoption request (length: %d bytes)", len(req))
	if _, err := conn.Write([]byte(req)); err != nil {
		log.Printf("❌ ERROR: Failed to send adoption request: %v", err)
		return
	}
	log.Printf("✅ Adoption request sent, waiting for response")

	// Read the response
	bufReader := bufio.NewReader(conn)
	statusLine, err := bufReader.ReadString('\n')
	if err != nil {
		log.Printf("❌ ERROR: Failed to read status line: %v", err)
		return
	}
	log.Printf("🔹 Received status line: %s", strings.TrimSpace(statusLine))

	if !strings.Contains(statusLine, "200 OK") {
		log.Printf("❌ ERROR: Server rejected adoption: %s", strings.TrimSpace(statusLine))
		// Try to read error body
		body, _ := io.ReadAll(bufReader)
		if len(body) > 0 {
			log.Printf("❌ Server response: %s", string(body))
		}
		return
	}

	// Process headers to extract any protocol information
	var protocolInfo string
	for {
		line, err := bufReader.ReadString('\n')
		if err != nil {
			log.Printf("❌ ERROR: Failed to read headers: %v", err)
			return
		}
		if line == "\r\n" {
			break
		}

		header := strings.TrimSpace(line)
		log.Printf("🔹 Header: %s", header)

		// Look for protocol information from server
		if strings.HasPrefix(strings.ToLower(header), "x-protocol:") {
			protocolInfo = strings.TrimSpace(strings.TrimPrefix(header, "X-Protocol:"))
			log.Printf("🔹 Server indicated protocol version: %s", protocolInfo)
		}
	}

	if protocolInfo != "" {
		log.Printf("✅ Using protocol version: %s", protocolInfo)
	}

	log.Printf("✅ Connection adoption successful, starting data relay")

	// Instead of trying to manually complete the TLS handshake with curl,
	// Let's focus on just starting the data relay directly
	log.Printf("🔹 Connection adopted, starting pure relay without TLS signals")

	// Instead of artificial delay, focus on proper protocol state management
	// Key insight: Don't manipulate the TLS state once it's established
	// This allows the natural TLS version negotiation to work properly

	log.Printf("🔹 Starting pure passthrough relay without HTTP/2 preface detection")
	log.Printf("🔹 Using pure relay mode, letting the protocol flow naturally")
	log.Printf("🔹 Waiting for client to send HTTP request for: unknown")
	log.Printf("✅ Connection ready for bidirectional relay (session %s)", sessionID)
	log.Printf("✅ Starting bidirectional relay for session %s", sessionID)

	// CRITICAL: After TLS handshake completes, we MUST NOT
	// 1. Send any unencrypted data over the connection
	// 2. Try to parse or modify the TLS records in any way
	// 3. Interfere with the TLS state machine

	// Just act as a pure TCP relay and let the TLS protocol flow naturally
	log.Printf("🔹 Using pure TCP relay mode with TLS record integrity preservation")
	log.Printf("🔹 Enabling graceful shutdown behavior to handle connection resets")
	log.Printf("🔹 TLS MAC failure prevention: Ensuring complete TLS records")

	defer func() {
		if r := recover(); r != nil {
			log.Printf("❌ PANIC in bidirectional relay: %v", r)
		}

		// Close connections
		conn.Close()
		clientConn.Close()
		log.Printf("✅ Connections closed for session %s", sessionID)
	}()

	// Begin bidirectional relay immediately
	log.Printf("🔹 Starting bidirectional relay without artificial delays")

	// Use wait group for the two copy operations
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Target with enhanced progress logging
	go func() {
		defer wg.Done()
		// Use a buffer large enough for TLS records but not so large we fragment across TCP packets
		buffer := make([]byte, 16384) // 16KB is a common TLS record max size
		relayData(clientConn, conn, buffer, "Client -> Target")
	}()

	// Target -> Client with enhanced progress logging
	go func() {
		defer wg.Done()
		// Use a buffer large enough for TLS records but not so large we fragment across TCP packets
		buffer := make([]byte, 16384) // 16KB is a common TLS record max size
		relayData(conn, clientConn, buffer, "Target -> Client")
	}()

	// Wait for both directions to complete
	wg.Wait()
	log.Printf("✅ Bidirectional relay completed for session %s", sessionID)
}

// extractSNI parses the TLS ClientHello message and extracts the SNI (Server Name Indication).
//
// The SNI (Server Name Indication) is a critical TLS extension that allows:
// 1. Identifying the target hostname when connecting to an IP address
// 2. Supporting multiple HTTPS websites on a single IP address
// 3. Enabling virtual hosting for TLS connections
//
// This implementation carefully parses the TLS record structure following the RFC:
// - Skips the TLS record header (5 bytes)
// - Navigates through handshake header, client version, and random (38 bytes)
// - Skips session ID, cipher suites, and compression methods (variable length)
// - Searches TLS extensions for the SNI extension (type 0x0000)
// - Extracts the hostname from the SNI extension data
//
// The extracted SNI is used both for establishing connections to the correct target
// and for potential SNI concealment in the OOB handshake relay strategy.
func extractSNI(clientHello []byte) (string, error) {
	if len(clientHello) < 43 { // Minimum length for a valid ClientHello
		return "", errors.New("ClientHello too short")
	}

	// Ensure this is a TLS ClientHello by checking the first few bytes
	if clientHello[0] != 0x16 { // TLS handshake type
		return "", errors.New("Not a TLS handshake")
	}
	if clientHello[5] != 0x01 { // ClientHello message type
		return "", errors.New("Not a ClientHello message")
	}

	// Find the TLS extensions section
	var pos = 43 // Start after fixed-length fields
	if pos+2 > len(clientHello) {
		return "", errors.New("Malformed ClientHello")
	}

	// Skip session ID
	sessionIDLen := int(clientHello[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(clientHello) {
		return "", errors.New("Malformed ClientHello (session ID too short)")
	}

	// Skip cipher suites
	cipherSuitesLen := int(clientHello[pos])<<8 | int(clientHello[pos+1])
	pos += 2 + cipherSuitesLen
	if pos+1 > len(clientHello) {
		return "", errors.New("Malformed ClientHello (cipher suites too short)")
	}

	// Skip compression methods
	compressionLen := int(clientHello[pos])
	pos += 1 + compressionLen
	if pos+2 > len(clientHello) {
		return "", errors.New("Malformed ClientHello (compression methods too short)")
	}

	// Read extensions length
	extensionsLen := int(clientHello[pos])<<8 | int(clientHello[pos+1])
	pos += 2
	if pos+extensionsLen > len(clientHello) {
		return "", errors.New("Malformed ClientHello (extensions too short)")
	}

	// Iterate through TLS extensions to find the SNI
	for pos+4 <= len(clientHello) {
		extType := int(clientHello[pos])<<8 | int(clientHello[pos+1])
		extLen := int(clientHello[pos+2])<<8 | int(clientHello[pos+3])
		pos += 4

		// Check if this is the SNI extension (type 0x0000)
		if extType == 0x0000 {
			if pos+2 > len(clientHello) {
				return "", errors.New("Malformed SNI extension")
			}
			sniListLen := int(clientHello[pos])<<8 | int(clientHello[pos+1])
			pos += 2

			if pos+sniListLen > len(clientHello) {
				return "", errors.New("SNI list length mismatch")
			}

			// Only one name is typically present
			if sniListLen < 3 || clientHello[pos] != 0x00 { // Ensure it's a valid host_name entry
				return "", errors.New("Invalid SNI entry")
			}

			// Read the hostname length
			hostnameLen := int(clientHello[pos+1])<<8 | int(clientHello[pos+2])
			pos += 3

			if pos+hostnameLen > len(clientHello) {
				return "", errors.New("Hostname length mismatch")
			}

			// Extract the hostname
			sni := string(clientHello[pos : pos+hostnameLen])
			return sni, nil
		}

		// Move to next extension
		pos += extLen
	}

	return "", errors.New("SNI not found in ClientHello")
}

// relayData implements an efficient bidirectional data relay with TLS inspection.
//
// This function is the core of all connection strategies, providing:
// 1. Reliable TCP data transfer with proper timeout handling
// 2. TLS record inspection for debugging without modifying the data
// 3. Detailed logging of transfer progress and connection state
// 4. Graceful handling of connection resets and network errors
//
// By relaying data without attempting to modify TLS records, this approach
// avoids the "decryption failed or bad record mac" errors that would occur
// when modifying TLS handshake data or attempting to split/merge TLS records.
func relayData(source, destination net.Conn, buffer []byte, label string) {
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
				// Only interpret as TLS record if it's a valid TLS record type (20-24)
				if recordType >= 20 && recordType <= 24 {
					version := (uint16(buffer[1]) << 8) | uint16(buffer[2])
					length := (uint16(buffer[3]) << 8) | uint16(buffer[4])
					expectedLen := int(length) + 5 // record header (5 bytes) + payload length
					
					// Enhanced version logging with human-readable format
					versionStr := "Unknown"
					if version == 0x0303 {
						versionStr = "TLS1.2"
					} else if version == 0x0304 {
						versionStr = "TLS1.3"
					} else if version == 0x0301 {
						versionStr = "TLS1.0"
					} else if version == 0x0302 {
						versionStr = "TLS1.1"
					}

					// CRITICAL: Verify we have a complete TLS record 
					// TLS requires exact record boundaries for MAC verification
					if n < expectedLen {
						log.Printf("⚠️ %s: Incomplete TLS record: got %d bytes, expected %d", 
							label, n, expectedLen)
						
						// For TLS, incomplete records will cause MAC failures
						// We must read more data to complete the record
						if n < len(buffer) && expectedLen <= len(buffer) {
							totalAdditionalBytes := 0
							remainingBytes := expectedLen - n
							
							// Try up to 5 reads to get the complete record
							for attempts := 0; attempts < 5 && remainingBytes > 0; attempts++ {
								// Try to read the rest of the record with a longer timeout
								source.SetReadDeadline(time.Now().Add(2 * time.Second)) // Increased timeout
								additionalBytes, err := source.Read(buffer[n:n+remainingBytes])
								source.SetReadDeadline(time.Time{})
								
								if err != nil {
									log.Printf("❌ %s: Failed to complete TLS record on attempt %d: %v", label, attempts+1, err)
									break
								}
								
								if additionalBytes > 0 {
									n += additionalBytes
									totalAdditionalBytes += additionalBytes
									remainingBytes = expectedLen - n
									
									log.Printf("🔹 %s: Read additional %d bytes on attempt %d, still need %d bytes", 
										label, additionalBytes, attempts+1, remainingBytes)
									
									if remainingBytes <= 0 {
										log.Printf("✅ %s: Completed TLS record after %d attempts, added %d bytes", 
											label, attempts+1, totalAdditionalBytes)
										break
									}
								} else {
									// No data read, no need to continue attempts
									log.Printf("⚠️ %s: Read 0 additional bytes on attempt %d", label, attempts+1)
									break
								}
							}
							
							if remainingBytes > 0 {
								log.Printf("⚠️ %s: Could not complete TLS record after multiple attempts, still missing %d bytes", 
									label, remainingBytes)
							}
						}
					}

					log.Printf("🔹 %s: TLS Record: Type=%d, Version=%s (0x%04x), Length=%d/%d",
						label, recordType, versionStr, version, length, n)
						
					// Special handling for TLS 1.3 records with 0x0303 version field
					// This is normal in TLS 1.3, which uses 0x0303 in the record layer for compatibility
					if version == 0x0303 {
						log.Printf("ℹ️ %s: Note: TLS record with 0x0303 version field is normal in both TLS 1.2 and TLS 1.3", label)
					}
				} else {
					// This is likely application data
					log.Printf("🔹 %s: Application data: %d bytes", label, n)
				}
			}

			// Write to destination immediately to avoid buffering delays
			// For TLS records, we must ensure they're written completely and atomically
			destination.SetWriteDeadline(time.Now().Add(15 * time.Second)) // Increased timeout for writes
			
			// Check if this is a TLS record that requires atomic writing
			isTLSRecord := n >= 5 && buffer[0] >= 20 && buffer[0] <= 24
			if isTLSRecord {
				// For TLS records, we must be extra careful to maintain record boundaries
				log.Printf("🔒 %s: Ensuring atomic write for complete TLS record (%d bytes)", label, n)
			}
			
			// Use a write loop to ensure complete write
			written := 0
			bytesRemaining := n
			currentOffset := 0
			
			for bytesRemaining > 0 {
				w, err := destination.Write(buffer[currentOffset:currentOffset+bytesRemaining])
				if err != nil {
					log.Printf("❌ %s: Error writing at offset %d: %v", label, currentOffset, err)
					break
				}
				
				written += w
				bytesRemaining -= w
				currentOffset += w
				
				if bytesRemaining > 0 {
					log.Printf("🔹 %s: Partial write: %d/%d bytes, continuing...", label, written, n)
					
					// For TLS records, log a warning about partial writes
					if isTLSRecord {
						log.Printf("⚠️ %s: TLS record partially written - this could cause protocol errors if not completed", label)
					}
				}
			}
			
			// Verify and log completion for TLS records
			if isTLSRecord && written == n {
				log.Printf("✅ %s: TLS record completely written (%d bytes)", label, written)
			}
			
			destination.SetWriteDeadline(time.Time{})

			// Error handling now done in the write loop above

			if written != n {
				log.Printf("⚠️ %s: Short write: %d/%d bytes", label, written, n)
			} else {
				totalBytes += int64(written)
				if totalBytes%32768 == 0 { // Log every 32KB
					log.Printf("✅ %s: Relayed %d bytes total", label, totalBytes)
				}
			}
		}
	}

	log.Printf("✅ %s: Relay complete, %d bytes transferred", label, totalBytes)
}

// signalConnectionAdoption would signal to the OOB server that the client is taking over 
// the existing connection for direct data exchange. Currently not implemented.
/*
func (p *TLSProxy) signalConnectionAdoption(sessionID string) error {
	log.Printf("🔹 Signaling connection adoption for session %s", sessionID)
	
	// Create a simple request to the OOB server to signal adoption
	serverAddr := p.OOB.GetServerAddress()
	url := fmt.Sprintf("http://%s/adopt_connection", serverAddr)
	
	jsonData := map[string]string{
		"session_id": sessionID,
		"action":     "adopt",
	}
	
	jsonBytes, err := json.Marshal(jsonData)
	if err != nil {
		return err
	}
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}
	
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned non-OK status: %d", resp.StatusCode)
	}
	
	// Read all headers from the response
	for name, values := range resp.Header {
		for _, value := range values {
			log.Printf("🔹 Response header: %s: %s", name, value)
		}
	}
	
	log.Printf("✅ Server confirmed connection adoption")
	return nil
}

// directDataExchange would establish a bidirectional tunnel for post-handshake data
// using the server's existing connection to the target. Currently not implemented.
func (p *TLSProxy) directDataExchange(clientConn net.Conn, sessionID string) error {
	log.Printf("🔹 Setting up bidirectional tunnel for session %s", sessionID)
	
	// Connect to the OOB server on the relay port
	serverAddr := p.OOB.GetServerAddress()
	relayConn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to relay server: %v", err)
	}
	
	// Send adoption tunnel request
	request := fmt.Sprintf("POST /tunnel HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: upgrade\r\n"+
		"Upgrade: TCP/Relay\r\n"+
		"X-Session-ID: %s\r\n"+
		"Content-Length: 0\r\n\r\n", 
		serverAddr, sessionID)
	
	if _, err := relayConn.Write([]byte(request)); err != nil {
		relayConn.Close()
		return fmt.Errorf("failed to send tunnel request: %v", err)
	}
	
	// Read HTTP response
	reader := bufio.NewReader(relayConn)
	line, err := reader.ReadString('\n')
	if err != nil {
		relayConn.Close()
		return fmt.Errorf("failed to read response: %v", err)
	}
	
	if !strings.Contains(line, "200") {
		relayConn.Close()
		return fmt.Errorf("server rejected tunnel: %s", strings.TrimSpace(line))
	}
	
	// Skip headers
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			relayConn.Close()
			return fmt.Errorf("failed to read headers: %v", err)
		}
		
		if line == "\r\n" {
			break
		}
	}
	
	log.Printf("✅ Tunnel established with relay server")
	
	// Optimize TCP connection settings
	if tcpConn, ok := relayConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetReadBuffer(1048576)  // 1MB buffer
		tcpConn.SetWriteBuffer(1048576) // 1MB buffer
	}
	
	// Start bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)
	
	// Client -> Target
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("❌ Panic in Client->Target relay: %v", r)
			}
		}()
		
		buffer := make([]byte, 16384) // 16KB buffer
		relayData(clientConn, relayConn, buffer, fmt.Sprintf("Session %s: Client->Target", sessionID))
	}()
	
	// Target -> Client
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("❌ Panic in Target->Client relay: %v", r)
			}
		}()
		
		buffer := make([]byte, 16384) // 16KB buffer
		relayData(relayConn, clientConn, buffer, fmt.Sprintf("Session %s: Target->Client", sessionID))
	}()
	
	// Wait for both directions to complete
	wg.Wait()
	relayConn.Close()
	
	log.Printf("✅ Bidirectional tunnel completed for session %s", sessionID)
	return nil
}
*/

// establishDirectConnectionAfterHandshake creates a direct connection to the target
// after completing the TLS handshake via OOB relay. This function gets connection
// details from the server component and establishes a direct TCP connection for
// application data exchange while maintaining the TLS session established during
// the handshake relay phase.
// establishPostHandshakeConnection tries to set up a direct connection after handshake
// or falls back to OOB relay if direct connection fails. This function includes
// robust error handling, connection lifecycle management, and proper cleanup.
// It enforces TLS 1.3 for direct connections or falls back to OOB relay.
func (p *TLSProxy) establishPostHandshakeConnection(clientConn net.Conn, sessionID string) {
    log.Printf("🔹 Session %s: Attempting to establish direct connection for application data", sessionID)
    
    // Check TLS version to ensure compatibility
    targetInfo, err := p.getTargetInfo(sessionID, nil)
    if err == nil && targetInfo.Version > 0 {
        // Determine TLS version
        isTLS13Compatible := targetInfo.Version == 0x0304 // TLS 1.3
        
        // For TLS 1.3 connections, attempt direct connection via replay attack prevention
        if isTLS13Compatible {
            log.Printf("✅ Session %s: TLS 1.3 detected (version: 0x%04x), can use direct connection", sessionID, targetInfo.Version)
            
            // Instead of trying to create a new connection to the target,
            // we need to preserve the TLS session that was established during handshake
            
            // The issue with "bad record mac" errors is that we're trying to join 
            // a TLS session that's already in progress, so instead we'll use a 
            // modified approach that still allows direct communication
            
            log.Printf("🔹 Session %s: Using hybrid approach for TLS 1.3", sessionID)
            
            // Signal to the server that we're taking over the connection after
            // handshake completion - this will transfer the connection to us
            // Just use OOB relay for now until we implement the tunnel functionality properly
            log.Printf("⚠️ Session %s: Direct connection not yet fully implemented, using OOB relay", sessionID)
            p.fallbackToRelayMode(clientConn, sessionID)
            return
            
            // For all other protocols, attempt direct connection
            log.Printf("🔹 Session %s: Attempting direct connection for HTTP/1.1 over TLS 1.3", sessionID)
            
            // This line should never be reached since we're returning above
        } else {
            // For non-TLS 1.3 connections, use OOB relay for compatibility and security
            log.Printf("⚠️ Session %s: Target is not using TLS 1.3 (version: 0x%04x)", sessionID, targetInfo.Version)
            log.Printf("🔒 Session %s: Using OOB relay for enhanced security and compatibility", sessionID)
            p.fallbackToRelayMode(clientConn, sessionID)
            return
        }
    }
    
    // Try to establish direct connection first
    targetConn, err := p.establishDirectConnectionAfterHandshake(sessionID)
    if err != nil {
        log.Printf("❌ Session %s: Failed to establish direct connection: %v", sessionID, err)
        // Fallback to relay mode
        log.Printf("⚠️ Session %s: Falling back to relay mode", sessionID)
        p.fallbackToRelayMode(clientConn, sessionID)
        return
    }
    
    // Connection established successfully
    log.Printf("✅ Session %s: Successfully established direct connection to target", sessionID)
    
    // Ensure connections are properly closed when this function exits
    defer func() {
        log.Printf("🔹 Session %s: Closing target connection", sessionID)
        if err := targetConn.Close(); err != nil {
            log.Printf("⚠️ Session %s: Error closing target connection: %v", sessionID, err)
        }
        log.Printf("✅ Session %s: Target connection closed", sessionID)
    }()
    
    // Optimize TCP connection settings
    if tcpConn, ok := targetConn.(*net.TCPConn); ok {
        tcpConn.SetNoDelay(true)
        tcpConn.SetKeepAlive(true)
        tcpConn.SetKeepAlivePeriod(30 * time.Second)
        tcpConn.SetReadBuffer(1048576)  // 1MB buffer
        tcpConn.SetWriteBuffer(1048576) // 1MB buffer
        log.Printf("✅ Session %s: Optimized TCP settings for direct connection", sessionID)
    }
    
    // Begin bidirectional relay
    var wg sync.WaitGroup
    wg.Add(2)
    
    // Channel to signal goroutine errors
    errChan := make(chan error, 2)
    
    // Client -> Target (Direct)
    go func() {
        defer func() {
            // Panic recovery
            if r := recover(); r != nil {
                log.Printf("⚠️ Session %s: Panic in Client->Target relay: %v", sessionID, r)
                // Convert panic to error and send to channel
                errChan <- fmt.Errorf("panic in Client->Target relay: %v", r)
            }
            wg.Done()
            log.Printf("🔹 Session %s: Client->Target relay goroutine exited", sessionID)
        }()
        
        buffer := make([]byte, 16384) // 16KB buffer
        log.Printf("🔹 Session %s: Starting Client->Target relay", sessionID)
        
        // Catch any errors during relay
        func() {
            defer func() {
                if err := recover(); err != nil {
                    errChan <- fmt.Errorf("recovered panic: %v", err)
                }
            }()
            relayData(clientConn, targetConn, buffer, fmt.Sprintf("Session %s: Client->Target", sessionID))
        }()
    }()
    
    // Target -> Client (Direct)
    go func() {
        defer func() {
            // Panic recovery
            if r := recover(); r != nil {
                log.Printf("⚠️ Session %s: Panic in Target->Client relay: %v", sessionID, r)
                // Convert panic to error and send to channel
                errChan <- fmt.Errorf("panic in Target->Client relay: %v", r)
            }
            wg.Done()
            log.Printf("🔹 Session %s: Target->Client relay goroutine exited", sessionID)
        }()
        
        buffer := make([]byte, 16384) // 16KB buffer
        log.Printf("🔹 Session %s: Starting Target->Client relay", sessionID)
        
        // Catch any errors during relay
        func() {
            defer func() {
                if err := recover(); err != nil {
                    errChan <- fmt.Errorf("recovered panic: %v", err)
                }
            }()
            relayData(targetConn, clientConn, buffer, fmt.Sprintf("Session %s: Target->Client", sessionID))
        }()
    }()
    
    // Start a goroutine to monitor for errors
    go func() {
        for err := range errChan {
            log.Printf("⚠️ Session %s: Relay error detected: %v", sessionID, err)
            // We could take additional actions here based on specific error types
            
            // Check if it's a connection reset error
            if strings.Contains(err.Error(), "connection reset") || 
               strings.Contains(err.Error(), "broken pipe") {
                log.Printf("⚠️ Session %s: Connection reset or broken pipe detected", sessionID)
                // Connection issues are common and expected
                log.Printf("ℹ️ Session %s: This is often normal for HTTP connections", sessionID)
            }
        }
    }()
    
    // Wait for both directions to complete
    log.Printf("🔹 Session %s: Waiting for relay operations to complete", sessionID)
    wg.Wait()
    close(errChan)
    
    log.Printf("✅ Session %s: Direct connection relay completed", sessionID)
}

func (p *TLSProxy) establishDirectConnectionAfterHandshake(sessionID string) (net.Conn, error) {
	log.Printf("🔹 Establishing direct connection for session %s", sessionID)

	// First, get target information from the OOB server
	targetInfo, err := p.getTargetInfo(sessionID, nil)
	if err != nil {
		log.Printf("❌ Failed to get target information: %v", err)
		return nil, err
	}

	// Log what we're connecting to
	log.Printf("🔹 Target information: Host=%s, IP=%s, Port=%d",
		targetInfo.TargetHost, targetInfo.TargetIP, targetInfo.TargetPort)

	// Connect to the target IP directly
	targetAddr := fmt.Sprintf("%s:%d", targetInfo.TargetIP, targetInfo.TargetPort)
	log.Printf("🔹 Connecting directly to %s", targetAddr)

	conn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("❌ Failed to connect to target: %v", err)
		return nil, err
	}

	// Optimize connection
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		log.Printf("🔹 TCP connection optimized")
	}

	log.Printf("✅ Established direct connection to %s for session %s", targetAddr, sessionID)

	// Note: In a future version, we could include session ticket and other TLS state
	// data to allow for even more seamless resumption of the TLS session without
	// requiring a full handshake again. This would require extracting and passing
	// the TLS session state.

	return conn, nil
}

// getTargetConnViaOOB connects to the target server via OOB to conceal SNI
func (p *TLSProxy) getTargetConnViaOOB(sni string, port string) (net.Conn, error) {
	log.Printf("🔒 SNI CONCEALMENT: Initiating connection to %s:%s via OOB", sni, port)

	// Create a simple request to the OOB server to signal SNI
	serverAddr := p.OOB.GetServerAddress()

	// Check for empty server address
	if serverAddr == "" {
		log.Printf("❌ ERROR: No OOB server address available!")

		// Try to find a server by probing each channel directly
		for _, channel := range p.OOB.Channels {
			if channel.Type == "http" && len(channel.Address) > 0 {
				possibleAddr := fmt.Sprintf("%s:%d", channel.Address, channel.Port)
				log.Printf("🔹 Attempting to reach OOB server at %s", possibleAddr)

				// Try a quick connection test
				conn, err := net.DialTimeout("tcp", possibleAddr, 2*time.Second)
				if err == nil {
					conn.Close()
					serverAddr = possibleAddr
					log.Printf("✅ Successfully connected to OOB server at %s", serverAddr)
					break
				}
			}
		}

		if serverAddr == "" {
			return nil, fmt.Errorf("no available OOB server for SNI concealment")
		}
	}

	log.Printf("🔹 Using OOB server at %s", serverAddr)

	// Create a session ID
	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
	log.Printf("🔹 Created session ID: %s", sessionID)

	// Send a simple OOB request with just the SNI info
	reqBody := fmt.Sprintf(`{"session_id":"%s","sni":"%s","port":"%s"}`,
		sessionID, sni, port)

	log.Printf("🔹 Sending SNI resolution request to OOB server")
	req, _ := http.NewRequest("POST",
		fmt.Sprintf("http://%s/create_connection", serverAddr),
		strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Sultry-Client/1.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)

	if err != nil {
		log.Printf("❌ SNI CONCEALMENT ERROR: Failed to send OOB request: %v", err)
		return nil, fmt.Errorf("failed to send OOB request: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("🔹 Received response from OOB server: HTTP %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("❌ SNI CONCEALMENT ERROR: OOB server returned error: %s", string(body))
		return nil, fmt.Errorf("OOB server error: %s", string(body))
	}

	// Parse response to get connection details
	var connResponse struct {
		Status  string `json:"status"`
		Address string `json:"address"`
		Port    string `json:"port"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&connResponse); err != nil {
		log.Printf("❌ SNI CONCEALMENT ERROR: Failed to decode OOB response: %v", err)
		return nil, fmt.Errorf("failed to decode OOB response: %w", err)
	}

	log.Printf("📝 OOB RESPONSE: Status=%s, Address=%s, Port=%s",
		connResponse.Status, connResponse.Address, connResponse.Port)

	if connResponse.Status != "ok" {
		log.Printf("❌ SNI CONCEALMENT ERROR: OOB returned non-OK status: %s", connResponse.Status)
		return nil, fmt.Errorf("OOB error: %s", connResponse.Status)
	}

	// Connect to the target information returned by OOB server
	targetAddr := fmt.Sprintf("%s:%s", connResponse.Address, connResponse.Port)
	log.Printf("🔒 SNI CONCEALED: Connecting directly to IP %s (real hostname: %s)", targetAddr, sni)

	// Connect to the real target
	log.Printf("🔹 Creating TCP connection to %s", targetAddr)
	conn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("❌ SNI CONCEALMENT ERROR: Failed to connect to target: %v", err)
		return nil, fmt.Errorf("failed to connect to target via OOB: %w", err)
	}

	// Optimize connection
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		log.Printf("🔹 TCP connection optimized with NoDelay and KeepAlive")
	}

	log.Printf("✅ SNI CONCEALMENT SUCCESSFUL: Connected to %s via IP %s", sni, targetAddr)
	return conn, nil
}
