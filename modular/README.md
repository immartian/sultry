# Modular Code Structure (Future Implementation)

This directory contains a proposed modular structure for the Sultry codebase. The goal is to break down the large client.go and server.go files into smaller, more focused modules.

## Current Files

- **relay.go**: Contains functions for relaying data between connections
- **handlers.go**: Contains HTTP handler functions for the server component
- **tunnel.go**: Contains functions for establishing direct connections after handshake
- **tls.go**: Contains TLS protocol utilities and constants

## Implementation Strategy

The files in this directory are not currently used in the build but serve as a blueprint for future refactoring. To implement this modular approach:

1. Carefully remove the corresponding functions from client.go and server.go
2. Move these files to the root directory
3. Update imports as necessary
4. Resolve any naming conflicts or duplicate functions

## Benefits of Modularization

- **Improved readability**: Smaller files with clear responsibilities
- **Better maintainability**: Changes to one module don't affect others
- **Easier testing**: Modules can be tested independently
- **Simpler collaboration**: Multiple developers can work on different modules
- **More flexibility**: Modules can be reused across different components

## Implementation Notes

The modular structure was designed to minimize changes to the existing code while improving maintainability. The functions in these files match the signatures of the original functions to make the transition smoother.

Each file contains clear comments explaining the purpose and usage of each function, making it easier for new developers to understand the codebase.