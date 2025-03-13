# Changelog

## [Unreleased]
### Added
- Direct connection establishment after handshake completion 
- Session ticket detection and management
- Enhanced TLS handshake detection in utils.go
- Comprehensive test script with diagnostics
- Detailed architecture documentation in ARCHITECTURE.md
- Developer guide with examples and best practices in DEVELOPMENT.md
- Codebase overview in CODEBASE.md

### Changed
- Updated test.sh script to build Sultry before each run
- Improved documentation for all major components
- Optimized relay functions for better performance
- Enhanced logging in client.go and server.go for better debugging

### Fixed
- Server connection cleanup after handshake completion
- Fixed handshake completion detection
- Fixed bidirectional relay implementation
- Fixed test script to properly detect direct connection establishment