# Refactoring Roadmap for Sultry

## Current State

The codebase still has two large files that handle most of the functionality:

- **client.go**: 2131 lines (reduced from 2318 lines)
- **server.go**: 1761 lines

## Refactoring Goals

1. Reduce file sizes to under 500 lines per file
2. Separate concerns into logical modules
3. Improve code reuse
4. Maintain full compatibility with existing behavior
5. Make testing easier

## Modular Structure Progress

We've made significant progress in implementing the modular structure in the `pkg/` directory:

```
pkg/
├── tls/         # TLS protocol handling - IMPLEMENTED
├── relay/       # Connection relay functionality - IMPLEMENTED
├── session/     # Session management - IMPLEMENTED
└── handlers/    # HTTP handlers - PARTIALLY IMPLEMENTED
```

### Phase 1 Progress: Function Extraction

✅ Completed:
- TLS utility functions have been moved to pkg/tls
- Session ticket management has been moved to pkg/session 
- Relay functionality has been moved to pkg/relay

🚧 In Progress:
- Many functions still remain in client.go and server.go

### Phase 2 TODO: Interface Definition

- Define clear interfaces between packages
- Create facade pattern for backward compatibility
- Update client.go and server.go to use the new interfaces

### Phase 3 TODO: State Management

- Refactor global state (e.g., sessions)
- Implement context-based state management
- Reduce usage of global variables

### Phase 4 TODO: Dependency Injection

- Refactor constructor functions
- Implement dependency injection
- Make testing easier with mock dependencies

## Next Steps

The next step is to focus on extracting the core connection handling logic from client.go and server.go. This includes:

1. Create a pkg/connection package for connection-related functionality
2. Move handleProxyConnection from client.go to pkg/connection
3. Move handleHTTPConnection from client.go to pkg/connection
4. Move handleTunnelRequest from client.go to pkg/connection

For server.go, we need to:

1. Extract the HTTP handlers to pkg/handlers
2. Move server connection functionality to pkg/connection

After this, we will focus on refactoring the main client and server structures to use the new modular packages.

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