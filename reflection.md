# **Protocol Handling and Implementation Plan for Out-of-Band (OOB) TLS Handshake with Direct Connection**

## **🎯 Goal**
Ensure that after the **TLS handshake is completed via the proxy (OOB mechanism)**, the **client and server can exchange application data directly** without the proxy's involvement—minimizing censorship risk and network detectability. The proxy should only be re-engaged for **future handshakes** or session resumption when necessary.

---

## **🔍 Core Design Rationale**
1. **Separation of Handshake and Application Data**
   - The **TLS handshake (ClientHello & ServerHello exchange)** is the only phase that requires proxy mediation.
   - Once the handshake is complete, the client **should communicate directly with the server**.

2. **Avoiding Persistent Proxy Use**
   - A persistent proxy connection **increases detectability** because it keeps a consistent channel open.
   - Dropping the proxy connection **immediately after handshake completion** ensures that the client behaves like a normal, non-proxied user.

3. **Preserving TLS Session Resumption for Future Handshakes**
   - TLS 1.3 supports **session resumption via session tickets** to avoid repeating full handshakes.
   - If session resumption is enabled, subsequent connections should **not** require proxy intervention.

---

## **📝 Incremental Implementation Plan**

We'll implement the required changes incrementally, focusing on one feature at a time with proper testing at each step.

### **Phase 1: Reliable Handshake Completion Detection**

**Goal**: Accurately detect when TLS handshake is complete to trigger direct connection establishment.

**Changes**:
1. Extract `isHandshakeComplete` function to utils.go for better organization:
   ```go
   // isHandshakeComplete determines if a TLS handshake has been completed
   func isHandshakeComplete(data []byte) bool {
       // Check for TLS 1.3 handshake completion
       // (Look for Finished message or application data)
       
       // Check for basic TLS record type
       if len(data) < 5 {
           return false
       }
       
       recordType := data[0]
       if recordType == 23 { // Application Data
           return true
       }
       
       // Check for Finished message in TLS 1.3
       if recordType == 22 && len(data) > 6 && data[5] == 20 {
           return true // Handshake type 20 is Finished
       }
       
       return false
   }
   ```

2. Enhance session state in server.go to track handshake completion:
   ```go
   type SessionState struct {
       // existing fields
       HandshakeComplete bool
       LastHandshakeMessage time.Time
       
       // For better handshake detection
       FinishedReceived bool
       ApplicationDataSeen bool
   }
   ```

**Testing Method**:
1. Create a unit test for handshake detection using known TLS packet captures
2. Implement logging to track handshake progress

### **Phase 2: Direct Connection Establishment**

**Goal**: Implement and verify working direct connection after handshake

**Changes**:
1. Enhance `establishDirectConnectionAfterHandshake` in client.go:
   ```go
   func establishDirectConnectionAfterHandshake(targetIP, targetPort string, session *SessionState) (net.Conn, error) {
       // Create direct connection to target
       conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", targetIP, targetPort))
       if err != nil {
           return nil, fmt.Errorf("failed to establish direct connection: %w", err)
       }
       
       // Set TCP optimizations
       if tcpConn, ok := conn.(*net.TCPConn); ok {
           tcpConn.SetKeepAlive(true)
           tcpConn.SetKeepAlivePeriod(30 * time.Second)
           tcpConn.SetNoDelay(true)
       }
       
       log.Printf("✅ Direct connection established to %s:%s", targetIP, targetPort)
       
       // If session ticket is available, could use it for resumption
       return conn, nil
   }
   ```

2. Modify `handleProxyConnection` to establish direct connection:
   ```go
   // In handleProxyConnection
   if isHandshakeComplete(sessionData) {
       log.Printf("✅ Handshake complete for session %s. Switching to direct connection.", sessionID)
       
       // Signal to server that handshake is complete
       signalHandshakeCompletion(sessionID)
       
       // Establish direct connection to target
       directConn, err := establishDirectConnectionAfterHandshake(targetIP, targetPort, sessionData)
       if err != nil {
           log.Printf("❌ Failed to establish direct connection: %v", err)
           // Fallback to relay mode if direct connection fails
           fallbackToRelayMode(clientConn, sessionID)
           return
       }
       
       // Start bidirectional relay between client and direct connection
       go relayData(clientConn, directConn, "client-target")
       go relayData(directConn, clientConn, "target-client")
       
       return
   }
   ```

**Testing Method**:
1. Create a test client that establishes connection via proxy
2. Verify direct connection is established after handshake
3. Use tcpdump to confirm traffic flows directly after handshake

### **Phase 3: Session Ticket Handling and Resumption**

**Goal**: Implement session ticket detection and TLS session resumption

**Changes**:
1. Implement session ticket detection:
   ```go
   // isSessionTicketMessage determines if a TLS message is a NewSessionTicket
   func isSessionTicketMessage(data []byte) bool {
       if len(data) < 6 {
           return false
       }
       
       // Check if it's a handshake record
       if data[0] != 22 { // TLS handshake record type
           return false
       }
       
       // Check if it's a NewSessionTicket message (type 4)
       return data[5] == 4
   }
   ```

2. Store session tickets in server.go:
   ```go
   // In handleTargetResponses
   if isSessionTicketMessage(responseData) {
       log.Printf("🔹 Session Ticket received for session %s.", sessionID)
       
       sessionsMu.Lock()
       session.SessionTicket = make([]byte, len(responseData))
       copy(session.SessionTicket, responseData)
       sessionsMu.Unlock()
   }
   ```

3. Implement session resumption check in client.go:
   ```go
   func hasValidSessionTicket(targetServer string) (bool, []byte) {
       // Check if we have a stored session ticket for this server
       sessionTicketsMu.Lock()
       ticket, exists := sessionTickets[targetServer]
       sessionTicketsMu.Unlock()
       
       if !exists || ticket == nil || len(ticket) == 0 {
           return false, nil
       }
       
       // Check if ticket has expired (simplified)
       if time.Since(ticket.Timestamp) > 24*time.Hour {
           return false, nil
       }
       
       return true, ticket.Data
   }
   ```

**Testing Method**:
1. Write a test that completes a handshake and verifies session ticket is captured
2. Implement a test client that reuses session for resumed connections
3. Check logs to confirm proxy is bypassed for resumed sessions

### **Phase 4: Connection Cleanup and Resource Management**

**Goal**: Ensure proxy connections are properly released after handshake

**Changes**:
1. Enhance `handleCompleteHandshake` in server.go:
   ```go
   func handleCompleteHandshake(w http.ResponseWriter, r *http.Request) {
       var req struct {
           SessionID string `json:"session_id"`
           Action    string `json:"action"`
       }

       if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
           http.Error(w, "Invalid request", http.StatusBadRequest)
           return
       }

       sessionsMu.Lock()
       session, exists := sessions[req.SessionID]
       sessionsMu.Unlock()

       if !exists {
           http.Error(w, "Session not found", http.StatusNotFound)
           return
       }

       // Mark handshake as complete
       sessionsMu.Lock()
       session.HandshakeComplete = true
       sessionsMu.Unlock()
       
       log.Printf("✅ Handshake marked complete for session %s. Releasing connection.", req.SessionID)

       // Close connection after a brief delay to ensure all buffered data is sent
       go func() {
           time.Sleep(500 * time.Millisecond)
           
           // Close the target connection
           if session.TargetConn != nil {
               session.TargetConn.Close()
           }
           
           // Remove the session from the sessions map
           sessionsMu.Lock()
           delete(sessions, req.SessionID)
           sessionsMu.Unlock()
           
           log.Printf("🔹 Proxy connection closed for session %s", req.SessionID)
       }()

       w.WriteHeader(http.StatusOK)
   }
   ```

2. Implement session tracking and cleanup:
   ```go
   // Add session cleanup function
   func cleanupInactiveSessions() {
       sessionsMu.Lock()
       defer sessionsMu.Unlock()
       
       cutoffTime := time.Now().Add(-5 * time.Minute)
       var sessionsToRemove []string
       
       for id, session := range sessions {
           if session.LastActivity.Before(cutoffTime) {
               sessionsToRemove = append(sessionsToRemove, id)
           }
       }
       
       for _, id := range sessionsToRemove {
           session := sessions[id]
           if session.TargetConn != nil {
               session.TargetConn.Close()
           }
           delete(sessions, id)
       }
       
       if len(sessionsToRemove) > 0 {
           log.Printf("🧹 Cleaned up %d inactive sessions", len(sessionsToRemove))
       }
   }
   ```

**Testing Method**:
1. Add instrumentation to count active sessions
2. Verify sessions are properly closed after handshake completion
3. Check for resource leaks after multiple connections

## **🔬 Comprehensive Testing Strategy**

### **Unit Testing**

Create unit tests for key functions:
- `isHandshakeComplete`
- `isSessionTicketMessage`
- `extractSNI`
- Session management functions

### **Integration Testing**

1. **Test Script: Full Flow Test**
   ```bash
   #!/bin/bash
   # Full connection flow test
   
   # Start proxy in dual mode
   ./sultry -mode dual &
   PROXY_PID=$!
   sleep 2
   
   # Make connection through proxy
   curl -x localhost:8080 https://example.com > /dev/null
   
   # Check if direct connection is established
   DIRECT_CONN=$(netstat -an | grep example.com | grep -v 8080 | wc -l)
   
   if [ "$DIRECT_CONN" -gt 0 ]; then
     echo "✅ Direct connection established"
   else
     echo "❌ No direct connection found"
   fi
   
   # Clean up
   kill $PROXY_PID
   ```

2. **Test Script: Session Resumption Test**
   ```bash
   #!/bin/bash
   # Session resumption test
   
   # Start proxy in dual mode
   ./sultry -mode dual &
   PROXY_PID=$!
   sleep 2
   
   # First connection (should use proxy for handshake)
   curl -x localhost:8080 https://example.com > /dev/null
   
   # Check logs for session ticket
   TICKET=$(grep "Session Ticket received" /var/log/sultry.log | wc -l)
   if [ "$TICKET" -gt 0 ]; then
     echo "✅ Session ticket received"
   else
     echo "❌ No session ticket found"
   fi
   
   # Second connection (should use session resumption)
   curl -x localhost:8080 https://example.com > /dev/null
   
   # Check logs for resumption
   RESUMPTION=$(grep "Resuming session" /var/log/sultry.log | wc -l)
   if [ "$RESUMPTION" -gt 0 ]; then
     echo "✅ Session resumption successful"
   else
     echo "❌ Session resumption failed"
   fi
   
   # Clean up
   kill $PROXY_PID
   ```

### **Performance and Reliability Testing**

1. **Connection Throughput Test**
   ```bash
   #!/bin/bash
   # Test connection throughput
   
   # Start proxy in dual mode
   ./sultry -mode dual &
   PROXY_PID=$!
   sleep 2
   
   # Make 100 sequential connections
   for i in {1..100}; do
     curl -s -o /dev/null -x localhost:8080 https://example.com
     echo -n "."
   done
   echo ""
   
   # Check active sessions (should be minimal)
   grep "active sessions" /var/log/sultry.log | tail -1
   
   # Clean up
   kill $PROXY_PID
   ```

2. **Long-running Stability Test**
   ```bash
   #!/bin/bash
   # Test long-running stability
   
   # Start proxy in dual mode
   ./sultry -mode dual &
   PROXY_PID=$!
   sleep 2
   
   # Run for 1 hour with periodic connections
   END_TIME=$((SECONDS + 3600))
   while [ $SECONDS -lt $END_TIME ]; do
     curl -s -o /dev/null -x localhost:8080 https://example.com
     echo "Connection at $(date)"
     sleep 60
   done
   
   # Check for memory leaks or resource issues
   ps -o pid,rss,vsz $PROXY_PID
   
   # Clean up
   kill $PROXY_PID
   ```

## **💻 Recommended Development Process**

1. **Start with Core Handshake Detection**
   - Implement and test accurate handshake completion detection
   - Add logging to trace handshake state transitions

2. **Then Implement Direct Connection**
   - Develop the direct connection establishment after handshake
   - Test both success and failure paths

3. **Add Session Resumption**
   - Implement session ticket capture and storage
   - Develop session resumption logic

4. **Finally Add Resource Management**
   - Implement proper connection cleanup
   - Add session tracking and inactive session removal

For each phase:
1. Create a feature branch
2. Write the implementation
3. Create tests to verify functionality
4. Run integration tests
5. Document behavior and edge cases

## **🚀 Summary of Expected Improvements**

| Issue | Fix | Result |
|--------|--------|--------|
| **Proxy keeps relaying encrypted data** | **Drop connection after handshake** | 🔥 Reduces detectability |
| **Proxy used for every connection** | **Enable TLS session resumption** | 🎯 Eliminates unnecessary OOB handshakes |
| **Direct connection not established** | **Ensure client switches to direct TCP** | ⚡ Improves performance, reduces load |
| **Proxy remains open for too long** | **Release session after handshake** | 🚀 Makes proxy usage intermittent |

## **📋 Implementation Checklist**

- [ ] Extract and improve handshake detection
- [ ] Implement direct connection establishment
- [ ] Add session ticket handling
- [ ] Implement session resumption
- [ ] Add connection cleanup and resource management
- [ ] Create unit tests for core functions
- [ ] Develop integration tests
- [ ] Create performance and reliability tests
- [ ] Document the implementation