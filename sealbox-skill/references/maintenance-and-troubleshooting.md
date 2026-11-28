# Maintenance and troubleshooting guide

## Readiness and health

- `GET /healthz/live` should return quickly when process is alive.
- `GET /healthz/ready` validates DB readiness as well as process readiness.
- If readiness fails:
  - check `STORE_PATH` is writable/readable.
  - check `LISTEN_ADDR` binding permissions.
  - check server auth token expectations.

## Expiration cleanup

- **Whole-key expiry rule:** A key's expiry is decided by its newest version (highest version number). A value written with a TTL replaces the key's value until it expires; once that newest version passes `expires_at`, the whole key is treated as gone (reads by key or older version return `404` and delete all versions; listings and history omit the key; deleting a single version of an already-expired key deletes all versions and returns `404`). Silently reviving a superseded value is unsafe for credentials.
- **Expired older versions:** An expired older version under a newer, unexpired version is still removed on its own while the active key stays intact.
- Startup performs cleanup of expired keys (all versions) and expired older versions.
- Expired keys and expired older versions are also enforced and deleted on read.
- Tenant-scoped manual cleanup (CLI or API, tenant token only; root token returns `401`):
  - `sealbox-cli secret cleanup-expired [--output table|json|yaml]` (calls `DELETE /v2/cleanup-expired`; removes every version of expired secrets, credentials, and files for that tenant plus expired older versions under active keys, without requiring local key files; `deleted_count` counts every removed version row).
  - For scripts, prefer `SEALBOX_TOKEN_FILE` and `--output json`. The CLI uses a 10 s connect timeout (nothing sent) and 60 s total timeout; a request or response-body timeout exits `1` with unknown server outcome and is safe to retry. Older CLIs without this subcommand exit `2` with `unrecognized subcommand`.
- All-tenant manual cleanup (API-only, root token):
  - `DELETE /v2/admin/cleanup-expired` (removes every version of expired keys plus expired older versions across all tenants; `deleted_count` counts every removed version row).
- Master key rotation cleans up expired entries before listing secrets to rewrap and before committing rotation. Every rewrapped update requires `previous_encrypted_data_key_sha256` to bind it to the exact fetched row (upgrade `sealbox-cli` together with the server before running `key rotate`); if any row expired, was deleted, was added, or was re-saved between fetch and rotate, the server rejects the whole rotation cleanly so it can be retried.
- TTL checks are deterministic from creation timestamp + TTL seconds (`expires_at < now`).

## Migrations and compatibility

- Server exposes a command mode:
  - `sealbox-server migration-report --store-path <path>`
- Use this to inspect migration state before running bulk import/export or schema operations.
- `LEGACY_V1_ENABLED` helps control compatibility behavior during migration windows.

## Common failures and diagnosis

### Unauthorized (`401` family)

- Confirm `Authorization: Bearer <token>`.
- In v2 mode, confirm you are using a tenant token for tenant routes and not a root token.
- Confirm token has not expired or been revoked.

### Forbidden / tenant access failures

- Verify tenant is not suspended.
- Verify endpoint path version and route group (`v1` vs `v2`) matches token type.
- Verify tenant token was created under the same root namespace/instance.

### Key errors

- If reads fail after decryption errors:
  - confirm private key path.
  - confirm local private key matches server active key ID (`key status`).
- If writes fail:
  - verify public key exists and is registered.
  - verify key list shows an active key with no pending status mismatch.

### Command syntax / parse errors

- Use command help for current flags:
  - `sealbox-cli --help`
  - `sealbox-cli secret --help`
  - `sealbox-cli credential --help`
  - `sealbox-cli tenant --help`

### Import/export operational risks

- Use version-compatible archive format for target environment.
- Exported archives are encrypted but still sensitive; protect them like key-bearing artifacts.
- Do not import from untrusted sources because key IDs and metadata can disrupt local workflows.

## Safe operational runbook (minimal)

1. Check health.
2. Confirm token/URL/app-version.
3. Confirm key registration (`key list`, `key status`).
4. Perform requested operation with explicit version selection.
5. For failures, isolate with minimal repro command and endpoint log context.
