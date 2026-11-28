# Server API and endpoint reference

This document maps Sealbox HTTP behavior at a task level.

## Base behavior

- Base URL: value in CLI config (`SEALBOX_URL`) or explicit server config.
- Authorization: `Authorization: Bearer <token>` for non-health routes.
- Content type for JSON requests: `application/json`.
- API versions:
  - `v1`: legacy/static-token workflows.
  - `v2`: tenant-scoped workflows; tenant token derives namespace by hashing bearer token.

## Health endpoints (no auth)

### `GET /healthz/live`
- Checks process availability only.

### `GET /healthz/ready`
- Includes DB connectivity check.
- Primary startup/provisioning readiness target for UIs and automation.

## v1 business endpoints (server token protected)

### Secrets

- `GET /v1/secrets`
  - List latest secret metadata for all active keys (omits keys whose newest version has expired).
- `PUT /v1/secrets/:key` (payload `encrypted_data` is capped at 500 KB of plaintext plus AES-GCM overhead; larger ciphertext is rejected with HTTP 413)
  - Create a new secret version (if the key's newest version has already expired, clears all expired versions in the same transaction first and restarts numbering at version `1`).
  - Body contains encrypted secret envelope and metadata.
  - Optional TTL handling by `ttl` in seconds.
- `GET /v1/secrets/:key`
  - Fetch a secret version (latest by default).
  - Supports `?version=<N>`.
  - If the key's newest version has expired, deletes all versions of the key in the same transaction and returns `404` (both for latest and for older `?version=<N>`). Expired older versions under an unexpired newest version are deleted on their own.
- `GET /v1/secrets/:key/history`
  - List active version metadata for a key (`404` if the key's newest version has expired; omits expired older versions under an unexpired newest version).
- `DELETE /v1/secrets/:key`
  - Delete all versions unless `?version=<N>` is set. Deleting a specific version of a key whose newest version has already expired deletes all versions of the key and returns `404`; deleting an existing expired older version under a live newest version removes it and returns `200`. Version numbers restart at `1` once a key is removed (expired or deleted) and are not stable identifiers across a key's removal.

### Credentials (username + password records)

- `GET /v1/credentials`
  - List credential metadata with server-side filters.
- `PUT /v1/credentials/:key`
  - Create/replace a credential version.
- `GET /v1/credentials/:key`
  - Fetch one credential metadata record and encrypted password blob.
- `GET /v1/credentials/:key/history`
  - List credential version metadata.
- `DELETE /v1/credentials/:key`
  - Delete latest or specific version with `?version=<N>`.

### Stored files

Stored files use the same secret endpoints and envelope encryption. There is no
separate file resource: a file is a secret whose plaintext metadata carries
`{"type":"file","filename":"app.yaml","content_type":"text/yaml"}`.

- `PUT /v1/secrets/:key`
  - Encrypts the file client-side; the server stores the ciphertext envelope.
  - Capped at 500 KB of plaintext plus AES-GCM overhead; larger ciphertext is rejected with HTTP 413.
- `GET /v1/secrets/:key`
  - Returns the ciphertext for client-side decryption.
- Version retention for `type: "file"` records is capped at the newest 3 versions.

### Master keys

- `GET /v1/master-key`
  - List registered keys and status.
- `POST /v1/master-key`
  - Register a public key.
- `GET /v1/master-key/by-id/:id/secrets`
  - Cleans up expired keys and expired older versions in the namespace, then returns encrypted records for client-side data-key rewrap.
- `PUT /v1/master-key`
  - Rotate active key using client-side rewrapped data keys. Cleans up expired keys first; every update requires `previous_encrypted_data_key_sha256` to bind it to the exact fetched row (upgrade `sealbox-cli` together with the server before running `key rotate`), and the server rejects the whole rotation on any mismatch or missing row (including rows that expired, were deleted, or were re-saved at a reused version number between fetch and rotate) so stale updates never land.

### Admin

- `DELETE /v1/admin/cleanup-expired`
  - Immediate cleanup of every version of expired keys plus expired older versions under unexpired newest versions (`deleted_count` counts every removed version row).

## v2 secret and key endpoints (tenant token protected)

- Same functional resources as v1 but scoped by tenant derived from token:
  - `GET /v2/secrets`
  - `PUT /v2/secrets/:key`
  - `GET /v2/secrets/:key`
  - `GET /v2/secrets/:key/history`
  - `DELETE /v2/secrets/:key`
  - `DELETE /v2/cleanup-expired` (removes every version of expired secrets, credentials, and files in the calling tenant plus expired older versions under active keys; `deleted_count` counts every removed row)
  - `GET /v2/credentials`
  - `PUT /v2/credentials/:key`
  - `GET /v2/credentials/:key`
  - `GET /v2/credentials/:key/history`
  - `DELETE /v2/credentials/:key`
  - `GET /v2/master-key`
  - `POST /v2/master-key`
  - `GET /v2/master-key/by-id/:id/secrets`
  - `PUT /v2/master-key`
- Static root token is intentionally not valid for v2 tenant data operations.

## v2 tenant admin endpoints (root token protected)

- `GET /v2/admin/tenants`
  - List tenants.
- `POST /v2/admin/tenants`
  - Create tenant.
- `GET /v2/admin/tenants/:tenant_id`
  - Get tenant details.
- `POST /v2/admin/tenants/:tenant_id/suspend`
  - Suspend tenant.
- `POST /v2/admin/tenants/:tenant_id/resume`
  - Resume tenant.
- `POST /v2/admin/tenants/:tenant_id/tokens`
  - Create a new tenant access token.
- `GET /v2/admin/tenants/:tenant_id/tokens`
  - List tenant tokens.
- `DELETE /v2/admin/tenants/:tenant_id/tokens/:token_id`
  - Revoke a token.
- `DELETE /v2/admin/cleanup-expired`
  - Immediate cleanup of every version of expired keys plus expired older versions across all tenants (`deleted_count` counts every removed row).

## API design notes

- All data mutating endpoints are versioned per key where applicable. Version numbers restart at `1` once a key is removed (expired or deleted), so version numbers are not stable identifiers across a key's removal.
- `output_format` conventions are client-side (CLI or UI), not server-specific.
- Expiry is decided by each key's newest version (highest version number): once the newest version passes `expires_at`, the whole key is gone (no fallback to older versions) across reads, listings, history, version delete, rotation, startup cleanup, and manual cleanup. An expired older version under an unexpired newest version is still removed on its own.
- v1 and v2 are intentionally aligned for most behaviors to simplify migration and tooling.
- Secret/certificate material remains encrypted in DB; API never needs private key material.

## Error semantics (high-level)

- Missing/invalid auth token: unauthorized response from middleware.
- Missing/invalid keys or token mismatch: authorization/lookup failures depending on endpoint.
- Expired entries: keys whose newest version has expired are omitted from listings/history and return `404` on reads (deleting all versions in the same transaction); expired older versions under active keys are omitted and cleaned up individually.
- Invalid payloads or path values: request validation errors with structured JSON error format.
