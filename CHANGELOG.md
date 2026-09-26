# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-26

### Breaking
- **The v1 API is disabled by default** (`LEGACY_V1_ENABLED=false`) and will be removed after 2026-11-25. Set `LEGACY_V1_ENABLED=true` to re-enable it temporarily; v1 responses then carry `Deprecation` and `Sunset` headers and the server logs a warning.
- **The root `AUTH_TOKEN` no longer reads or writes secrets.** It creates tenants and issues tokens; all data access uses tenant tokens on `/v2`. Pre-tenant data is in the `legacy` tenant: `sealbox-cli --token $AUTH_TOKEN tenant token create legacy --token-file ...`
- **The CLI defaults to `api_version = "v2"`.** Configs saved with `v1` print a deprecation warning; run `sealbox-cli config set server.api_version v2`.
- **The web UI uses `/v2` and requires a tenant token** to log in.
- `secret export` refuses to overwrite an existing file without `--force`.

### Added
- `key export` / `key import`: back up and restore the local key pair in a passphrase-encrypted bundle (Argon2id + AES-256-GCM)
- `secret export --all-versions` exports every retained version, not just the latest
- `secret export --passphrase` / `--passphrase-file` creates archives that can be imported without any RSA key
- `secret import` checks the archive's key fingerprint and reports both fingerprints when `--private-key` points at the wrong key; it fails early if the target server has no active key
- `sealbox-server backup` / `restore` and `sealbox-cli admin backup` (`GET /v2/admin/backup`) for integrity-checked whole-database snapshots
- `DELETE /v2/cleanup-expired` (tenant) and `DELETE /v2/admin/cleanup-expired` (all tenants, root token)
- `key status` reports the local public key fingerprint
- `sealbox-server --version`
- Web UI navigation links to the secrets and master keys pages

### Changed
- Archive envelope and payload format v2 (base64 values, key fingerprint). Version 1 archives still import.
- Web UI login verifies the token against a v2 route instead of only the unauthenticated readiness probe

### Fixed
- Binary files could not be exported (archives required UTF-8 values)
- Truncated ciphertext made `DataKey::decrypt` panic instead of returning an error
- Web UI login errors rendered one word per line
- `vite dev` crashed when the shell set `NODE_ENV=production`, and the first visit to the keys page forced a reload that signed the user out

### Security
- `PrivateMasterKey` redacts key material in `Debug` output

## [0.1.5] - 2026-09-16

### Added
- **Encrypted file storage** - Store small files (up to 500 KB) alongside passwords and tokens
  - Files are encrypted client-side with the same RSA + AES-GCM envelope encryption used for secrets
  - Stored in the existing `secrets` table, so key rotation, TTL cleanup, backups, and tenant isolation work unchanged
  - File name and optional content type are stored as plaintext metadata (`{"type":"file","filename":"...","content_type":"..."}`) for listing and search; contents stay encrypted
  - New CLI commands: `file set`, `file get`, `file list`, `file delete`
  - `file get` writes mode-`0600` output and refuses to overwrite without `--force`
  - Server rejects ciphertext above the 500 KB plaintext limit with HTTP 413 on `PUT /v1/secrets/:key` and `/v2/secrets/:key`
  - File version history is capped at the newest 3 versions
- **Web UI (sealbox-web)** - Complete React-based web interface for secret management
  - Modern authentication system with Bearer Token support
  - Responsive secret list with real-time TTL status indicators
  - Secret deletion with confirmation dialogs
  - Mobile-friendly responsive design built with TailwindCSS and shadcn/ui
  - Integration with TanStack Query for efficient data fetching and caching
  - **English-first interface** - All UI elements use clear English text
- **Kubernetes Health Checks** - Production-ready monitoring endpoints
  - `GET /healthz/live` - Liveness probe for service availability
  - `GET /healthz/ready` - Readiness probe with database connection testing
  - No authentication required for health endpoints
  - Proper HTTP status codes and JSON responses
- **Complete English Internationalization** - Full language standardization
  - All UI components, error messages, and user-facing text in English
  - All code comments and documentation in English  
  - English locale (enUS) for date formatting throughout the application
  - Prepared foundation for future multi-language i18n support
- **New API Endpoint**: `GET /v1/secrets` - List all secrets with metadata
- **CORS Support** - Cross-origin request handling for web development
- Comprehensive test suite with 77 tests covering cryptographic operations, database layer, and API handlers
- Complete CI/CD pipeline with GitHub Actions
- Multi-platform builds (Linux, macOS, Windows)
- Docker support with optimized multi-stage builds
- Security scanning with cargo-audit, CodeQL, and Trivy
- Code coverage reporting with codecov
- Automatic dependency updates with Dependabot
- Performance benchmarks and code quality checks

### Changed
- Enhanced API architecture to support web interface requirements
- Improved error handling throughout the codebase
- Enhanced logging and observability
- Refactored crypto module with better error types
- Upgraded tower-http dependency with CORS feature support

### Security
- Resolved 14 of 15 RUSTSEC advisories reported by `cargo audit`, including
  `aws-lc-sys`, `rustls`, `rustls-webpki`, `h2`, `bytes`, and `slab`
- Dependency audit suppressions are centralized in `.cargo/audit.toml`
- Added a scheduled dependency audit workflow that re-checks the default branch weekly
- Added comprehensive cryptographic testing
- Implemented security scanning in CI pipeline
- Added vulnerability scanning for Docker images
- Secrets scanning with TruffleHog
- Secure token-based authentication for web interface

## [0.1.0] - 2024-XX-XX

### Added
- Initial release of Sealbox
- End-to-end encryption with RSA + AES-GCM
- SQLite-based storage with secret versioning
- REST API for secret management
- Master key management and rotation
- CLI tool for key generation and registration
- Static token authentication
- TTL support for secrets
- Docker deployment support

### Features
- Envelope encryption architecture
- Multiple secret versions
- Master key rotation
- Simple REST API
- Single binary deployment
- Embedded SQLite storage
- CLI tools for management

[Unreleased]: https://github.com/enzimo/sealbox/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/enzimo/sealbox/compare/v0.1.5...v0.2.0
[0.1.5]: https://github.com/enzimo/sealbox/compare/v0.1.0...v0.1.5
[0.1.0]: https://github.com/enzimo/sealbox/releases/tag/v0.1.0