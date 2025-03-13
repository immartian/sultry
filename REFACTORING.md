# Refactoring Roadmap for Sultry

This document outlines the plan for refactoring the Sultry codebase to improve maintainability, reduce file sizes, and enhance modularity.

## Current State

The codebase currently has two large files that handle most of the functionality:

- **client.go**: 2318 lines
- **server.go**: 1761 lines

These files contain mixed responsibilities including:
- TLS protocol handling
- Connection management
- HTTP handling
- Data relay
- Session management

## Refactoring Goals

1. Reduce file sizes to under 500 lines per file
2. Separate concerns into logical modules
3. Improve code reuse
4. Maintain full compatibility with existing behavior
5. Make testing easier

## Modular Structure

We've started the refactoring process by creating modular packages in the `pkg/` directory:

```
pkg/
├── tls/         # TLS protocol handling
├── relay/       # Connection relay functionality
├── session/     # Session management
└── handlers/    # HTTP handlers
```

## Step-by-Step Refactoring Plan

### Phase 1: Function Extraction

1. Identify functions with minimal dependencies
2. Move them to appropriate packages
3. Update function signatures to be exported
4. Fix any internal references
5. Test each change incrementally

### Phase 2: Interface Definition

1. Define clear interfaces between packages
2. Create facade pattern for backward compatibility
3. Update client.go and server.go to use the new interfaces

### Phase 3: State Management

1. Refactor global state (e.g., sessions)
2. Implement context-based state management
3. Reduce usage of global variables

### Phase 4: Dependency Injection

1. Refactor constructor functions
2. Implement dependency injection
3. Make testing easier with mock dependencies

## Detailed Function Mapping

### From client.go to pkg/tls/

| Original Function        | New Function             | Line Numbers |
|--------------------------|--------------------------|--------------|
| isHandshakeComplete      | tls.IsHandshakeComplete | 40-65        |
| isSessionTicketMessage   | tls.IsSessionTicketMessage | 66-79     |
| parseTLSRecordHeader     | tls.ParseTLSRecordHeader | 30-41      |
| logTLSRecord             | tls.LogTLSRecord        | 108-177      |
| extractSNI               | tls.ExtractSNIFromClientHello | 1038-1138 |

### From client.go to pkg/relay/

| Original Function        | New Function             | Line Numbers |
|--------------------------|--------------------------|--------------|
| relayData                | relay.RelayData         | 1686-1750    |
| establishDirectConnectionAfterHandshake | relay.EstablishDirectConnection | 2053-2095 |
| signalHandshakeCompletion | relay.SignalHandshakeCompletion | 1260-1301 |
| getTargetInfo            | relay.GetTargetInfo     | 1194-1240    |
| releaseOOBConnection     | relay.ReleaseConnection | 1243-1268    |

### From server.go to pkg/session/

| Original Function        | New Function             | Line Numbers |
|--------------------------|--------------------------|--------------|
| SessionState struct      | session.SessionState     | 35-45        |
| cleanupInactiveSessions  | session.CleanupInactiveSessions | 460-484 |

### From server.go to pkg/handlers/

| Original Function        | New Function             | Line Numbers |
|--------------------------|--------------------------|--------------|
| handleCompleteHandshake  | handlers.HandleCompleteHandshake | 580-621 |
| handleGetTargetInfo      | handlers.HandleGetTargetInfo | 1129-1203 |
| handleReleaseConnection  | handlers.HandleReleaseConnection | 1464-1488 |
| handleGetResponse        | handlers.HandleGetResponse | 1505-1554 |

## Refactoring Challenges

1. **Circular Dependencies**: Some functions have circular dependencies that need to be resolved.
2. **Global State**: The codebase relies heavily on global state.
3. **Error Handling**: Error handling needs to be consistent across packages.
4. **Interface Design**: Interfaces need to be designed carefully to maintain compatibility.

## Testing Strategy

1. Create a baseline test suite before refactoring
2. Test each refactored component independently
3. Integration test after each refactoring phase
4. Verify behavior matches original implementation

## Future Considerations

1. **API Stability**: Ensure the refactored code maintains a stable API
2. **Documentation**: Update documentation to reflect the new structure
3. **Performance**: Benchmark before and after to ensure performance is maintained
4. **Extensibility**: Design the new structure to be more extensible