# CLI Reference

Complete reference for the Sealbox command-line interface.

## Server Maintenance Command

Inspect a pre-v2 database without modifying it:

```bash
sealbox-server migration-report --store-path /var/lib/sealbox/sealbox.db
```

The JSON report includes schema version, migration requirement, key and secret
counts, empty legacy namespace rows, and orphaned secret references. Normal
startup creates `<STORE_PATH>.pre-tenant-v2.bak` before migrating populated
legacy data.

### `sealbox-server backup`

Write a consistent, integrity-checked snapshot of the whole database. This is
safe while the server is running. The destination must not already exist and
is created with mode `0600`.

```bash
sealbox-server backup --out /backups/sealbox-$(date +%F).db [--store-path /var/lib/sealbox/sealbox.db]
```

### `sealbox-server restore`

Replace the database with a snapshot. **Stop the server first.** The snapshot
is verified before anything changes. An existing database is only replaced with
`--force`, and it is moved aside to `<STORE_PATH>.pre-restore-<unix-time>.bak`
(together with its `-wal`/`-shm` files) instead of being deleted.

```bash
sealbox-server restore --from /backups/sealbox-2026-09-26.db [--store-path /var/lib/sealbox/sealbox.db] [--force]
```

`--store-path` defaults to `STORE_PATH` for all three server commands. Secret
values in a snapshot stay envelope-encrypted, so restoring one needs the same
private keys as before. Snapshots also contain tenant metadata and token
hashes, so protect them like the root token.

## Global Options

All commands support these global options:

- `--output <format>` - Output format: `table`, `json`, `yaml` (default: `table`)
- `--help` - Show help information
- `--version` - Show version information

## Configuration Commands

### `config init`

Initialize CLI configuration interactively or with command-line parameters.

```bash
sealbox-cli config init [OPTIONS]
```

**Options:**
- `--url <url>` - Server URL
- `--token <token>` - Authentication token
- `--public-key <path>` - Public key file path
- `--private-key <path>` - Private key file path
- `--output <format>` - Output format: `table`, `json`, `yaml`
- `--force` - Overwrite existing configuration file

**Examples:**
```bash
# Initialize with all parameters
sealbox-cli config init \
    --url http://localhost:8080 \
    --token your-token \
    --public-key ~/.config/sealbox/public_key.pem \
    --private-key ~/.config/sealbox/private_key.pem \
    --output table

# Initialize interactively (prompts for missing values)
sealbox-cli config init

# Force overwrite existing configuration
sealbox-cli config init --force
```

Creates `~/.config/sealbox/config.toml` with your settings.

### `config show`

Display current configuration.

```bash
sealbox-cli config show
```

## Key Management Commands

### `key generate`

Generate a new RSA key pair for encryption.

```bash
sealbox-cli key generate [OPTIONS]
```

- `--public-key-path <path>` - Public key output path
- `--private-key-path <path>` - Private key output path
- `--force` - Overwrite existing keys

**Example:**
```bash
sealbox-cli key generate --force
```

### `key register`

Register your public key with the Sealbox server.

```bash
sealbox-cli key register [OPTIONS]
```

**Options:**
- `--new-key-id <uuid>` - New registered master key id
- `--old-key-id <uuid>` - Old active master key id

The CLI decrypts existing encrypted data keys locally with the old private key and sends only rewrapped encrypted data keys to the server.

**Example:**
```bash
sealbox-cli key register --url http://localhost:8080 --token my-token
```

### `key list`

List all registered public keys on the server.

```bash
sealbox-cli key list [OPTIONS]
```

**Options:**
- `--url <url>` - Server URL (overrides config)
- `--token <token>` - Authentication token (overrides config)

### `key status`

Show the status of your local keys and server registration.

```bash
sealbox-cli key status
```

### `key rotate`

Rotate to a new key pair (advanced operation).

```bash
sealbox-cli key rotate [OPTIONS]
```

**Options:**
- `--url <url>` - Server URL (overrides config)
- `--token <token>` - Authentication token (overrides config)

**Expiry handling during rotation:** Before listing secrets to rewrap and before committing the rotation, the server cleans up expired keys and expired older versions in the tenant. If a row expires and is removed between fetching secrets and submitting the rewrapped data keys, rotation accepts and drops that update (logging a warning on the server) instead of failing; unexpected updates for rows that still exist are rejected.

### `key export`

Back up the local key pair to a passphrase-encrypted bundle. The server only
stores public keys, so this bundle, or another copy of the private key, is
the only way to decrypt your secrets after losing this machine.

```bash
sealbox-cli key export --file <bundle> [--passphrase-file <path>] [--force]
```

- Reads the configured private key (`--private-key` overrides it). The public
  key is derived from the private key, and export fails if the configured
  public key file belongs to a different key.
- The passphrase is read from `--passphrase-file`, then
  `SEALBOX_BACKUP_PASSPHRASE`, then an interactive prompt (asked twice), then
  piped stdin. It must be at least 12 characters.
- Encryption: Argon2id (64 MiB, 3 passes) derives an AES-256-GCM key. The KDF
  parameters and file type are authenticated.
- The bundle records the key's `sha256:` fingerprint in the clear, so you can
  match it to `key status` or `key list` output without the passphrase.
- The file is created with mode `0600` and existing files are never overwritten
  without `--force`.

Store the bundle and the passphrase in different places.

### `key import`

Restore a key pair from a bundle created by `key export`.

```bash
sealbox-cli key import --file <bundle> [--passphrase-file <path>] \
  [--private-key-path <path>] [--public-key-path <path>] [--force]
```

- Writes to the configured key paths unless `--private-key-path` or
  `--public-key-path` is given.
- Refuses to overwrite either file without `--force`, and checks both paths
  before writing anything.
- Verifies that the decrypted private key, the stored public key, and the
  bundle's fingerprint all match.

`key status` also reports the local `public_key_fingerprint`.

## Secret Management Commands

### `secret set`

Store a secret with the given key.

```bash
sealbox-cli secret set <key> [value] [OPTIONS]
```

**Arguments:**
- `<key>` - Secret identifier
- `[value]` - Optional secret value. If omitted, the CLI reads from a hidden prompt when attached to a TTY, or from stdin when piped.

**Options:**
- `--ttl <seconds>` - Time-to-live in seconds (expires after creation time)
- `--url <url>` - Server URL (overrides config)
- `--token <token>` - Authentication token (overrides config)

**TTL Behavior:**
- A key's expiry is decided by its newest version (highest version number). A value written with a TTL replaces the key until it expires; once that newest version passes `expires_at`, the whole key is treated as gone rather than silently reviving an older, superseded version (which is unsafe for credentials).
- Saving a new value to an already-expired key clears its expired versions first in the same transaction and starts fresh at version `1`, so older versions are never revived.
- An expired older version under a newer, unexpired version is still removed on its own while keeping the active key intact.
- Expired keys (all versions) and expired older versions are deleted when accessed (lazy cleanup), on server startup, or via `sealbox-cli secret cleanup-expired` (per tenant) / `DELETE /v2/admin/cleanup-expired` (all tenants).

**Examples:**
```bash
# Store a simple secret (permanent)
sealbox-cli secret set db_password "my-secret-password"

# Store with TTL (expires in 1 hour = 3600 seconds)
sealbox-cli secret set temp_token "abc123" --ttl 3600

# Store session data (expires in 30 minutes)
sealbox-cli secret set session_data "user-session-123" --ttl 1800

# Store short-lived API key (expires in 5 minutes)
sealbox-cli secret set quick_key "temp-key-456" --ttl 300

# Read secret from piped stdin
printf '%s\n' "my-secret" | sealbox-cli secret set api_key
```

### `secret get`

Retrieve and decrypt a secret.

```bash
sealbox-cli secret get <key> [OPTIONS]
```

**Arguments:**
- `<key>` - Secret identifier

**Options:**
- `--version <version>` - Specific version to retrieve (default: latest)
- `--url <url>` - Server URL (overrides config)
- `--token <token>` - Authentication token (overrides config)

**TTL Behavior:**
- If the key's newest version has expired, all versions of the key are deleted and you get a "Secret not found" (`404`) error—both when reading the latest version and when requesting an older `--version`
- If only an older version has expired while a newer version is still valid, the expired older version is deleted on its own and the active key remains readable
- This is the lazy cleanup mechanism in action

**Examples:**
```bash
# Get latest version
sealbox-cli secret get db_password

# Get specific version
sealbox-cli secret get db_password --version 2

# Expired secret will return "Secret not found"
sealbox-cli secret get expired_token
```

### `secret list`

List all active secrets (metadata only, no values). Keys whose newest version has expired are omitted.

```bash
sealbox-cli secret list [OPTIONS]
```

**Options:**
- `--url <url>` - Server URL (overrides config)
- `--token <token>` - Authentication token (overrides config)

### `secret history`

List retained version metadata for one active secret. Secret values and encrypted payload bytes are not returned. Returns not found (`404`) if the key's newest version has expired; expired older versions under an unexpired newest version are omitted.

```bash
sealbox-cli secret history <key> [OPTIONS]
```

**Arguments:**
- `<key>` - Secret identifier

**Options:**
- `--url <url>` - Server URL (overrides config)
- `--token <token>` - Authentication token (overrides config)

### `secret delete`

Delete a secret and all stored versions by default, or delete one specific version. Deleting a specific version of a key whose newest version has already expired removes all versions of the key and returns not found (`404`).

```bash
sealbox-cli secret delete <key> [OPTIONS]
```

**Arguments:**
- `<key>` - Secret identifier

**Options:**
- `--version <version>` - Delete only this specific version
- `--url <url>` - Server URL (overrides config)
- `--token <token>` - Authentication token (overrides config)

**Examples:**
```bash
# Delete all versions
sealbox-cli secret delete old_password

# Delete specific version
sealbox-cli secret delete old_password --version 1
```

### `secret cleanup-expired`

Remove all expired records for the calling tenant by calling `DELETE /v2/cleanup-expired`.

```bash
sealbox-cli secret cleanup-expired [OPTIONS]
```

**Options (global):**
- `--output <format>` - Output format: `table` (default), `json`, `yaml`
- `--url <url>` - Server URL (overrides config)
- `--token <token>` - Tenant authentication token (overrides config; prefer `SEALBOX_TOKEN_FILE` in scripts so the token does not appear on the process command line)

**Behavior:**
- **Scope:** Although nested under `secret`, this removes all expired **secrets, credentials, and files** belonging to the calling tenant (all three are stored in the tenant's secrets table). A key's expiry is decided by its newest version: when the newest version has expired, cleanup removes **every version** of that key (including older permanent versions) so superseded values are never revived. Under an unexpired newest version, expired older versions are still removed on their own while the active key stays intact. Unexpired keys with no expired older versions, permanent keys, and other tenants' records are untouched.
- **Count semantics:** `deleted_count` counts every deleted **stored version (row)**, not distinct keys. For example, an expired key with a permanent v1 and an expired v2 contributes `2` to `deleted_count`, and an active key with one expired older version contributes `1`.
- **Auth and keys:** Requires only the server URL and a **tenant token**; local RSA public/private key files are not read or required. The server root token (`AUTH_TOKEN`) is rejected with HTTP `401`.
- **Output:** Prints only the formatted cleanup summary to stdout (no extra banner or info lines). With `--output json`, stdout is the pretty-printed server JSON object with `deleted_count` and `cleaned_at` (Unix seconds).
- **Timeouts and retries:** Uses a 10-second connect timeout and a 60-second total request timeout. A connect timeout exits `1` (`Failed to request server`) before any request is sent. A request timeout or a stalled response body also exits `1` (`Failed to request server` or `Failed to parse server response`) with empty stdout, leaving the server outcome unknown because the server may have already committed or may still finish deleting under its database lock. The operation is idempotent, so re-running is safe; `deleted_count` reports only what that single call removed, not everything removed since the last successful call.
- **Exit codes:** Exits `0` on success. Runtime failures (missing token, invalid `--api-version`, HTTP/auth error such as `401`, network/timeout error, or malformed/stalled response body) exit `1` with empty stdout and the error message (including the HTTP status code on server errors) on stderr. Usage errors (unknown flag, extra positional argument, or an invalid `--output` value) exit `2` with empty stdout and usage text on stderr before any request is made. An older `sealbox-cli` binary that predates this subcommand also exits `2` with `unrecognized subcommand` on stderr, which callers can check to detect an older CLI.

**Examples:**
```bash
# Interactive cleanup using configured tenant settings (table output)
sealbox-cli secret cleanup-expired

# Scripted / periodic janitor run using a token file and JSON output
SEALBOX_URL=http://localhost:8080 \
SEALBOX_TOKEN_FILE=/secure/tenant/token \
sealbox-cli secret cleanup-expired --output json
# {
#   "deleted_count": 3,
#   "cleaned_at": 1700000000
# }

# YAML output
sealbox-cli secret cleanup-expired --output yaml
```

### `secret export`

Export secrets to a Sealbox encrypted archive. The CLI decrypts each selected
secret locally, writes a tar payload in memory, and encrypts it with
AES-256-GCM. The archive key is protected in one of two ways:

- **Public key (default):** wrapped with the configured public key. The archive
  records that key's fingerprint, and importing it needs the matching private key.
- **Passphrase (`--passphrase` / `--passphrase-file`):** derived from a
  passphrase with Argon2id. You can import it without any RSA key, so it
  survives losing your key pair.

```bash
sealbox-cli secret export <file> [OPTIONS]
```

**Options:**
- `--keys <text>` - Export only keys containing this substring
- `--all-versions` - Export every retained version of each key, not just the latest
- `--passphrase` - Protect the archive with a passphrase instead of the public key
- `--passphrase-file <path>` - Read the passphrase from a file (implies `--passphrase`); `SEALBOX_BACKUP_PASSPHRASE` also works
- `--force` - Overwrite an existing archive file
- `--format <format>` - Archive format: `encrypted-tar` or `sealbox-v1` (default: `encrypted-tar`)
- `--public-key <path>` - Public key used to protect the archive (default mode)
- `--private-key <path>` - Private key used to decrypt the secrets being exported

**Archive format:**
- Outer file: JSON envelope (`envelope_version` 2) with a `protection` block of method `rsa-oaep-sha256` (includes `public_key_fingerprint`) or `passphrase`
- Encrypted payload: tar archive containing `manifest.json` and `secrets.json`
- `manifest.json`: `format_version` 2, `key_count`, `secret_count` (versions), `all_versions`
- `secrets.json`: one record per version, with base64 values so binary files round-trip
- Output file permissions: `0600` on Unix
- Version 1 archives from earlier releases can still be imported

**Examples:**
```bash
# Latest versions, protected by your public key
sealbox-cli secret export backups/sealbox-export.json

# Full history, readable with only a passphrase
sealbox-cli secret export backups/full-history.json --all-versions --passphrase

# Only matching keys
sealbox-cli secret export backups/db-secrets.json --keys db/
```

### `secret import`

Import secrets from a Sealbox encrypted archive. The CLI decrypts the archive
locally, then stores each record through the normal client-side encrypted write
path. Records are **re-encrypted to the target server's active master key**,
which does not have to be the key the archive was made with.

```bash
sealbox-cli secret import <file> [OPTIONS]
```

**Options:**
- `--private-key <path>` - For public-key archives: the private key the archive was exported with. Use this when it differs from the configured key, for example on a new server set up with a fresh key pair.
- `--passphrase-file <path>` - For passphrase archives: read the passphrase from a file (otherwise `SEALBOX_BACKUP_PASSPHRASE` or a prompt)
- `--format <format>` - Archive format: `encrypted-tar` or `sealbox-v1` (default: `encrypted-tar`)
- `--url <url>` - Server URL (overrides config)
- `--token <token>` - Authentication token (overrides config)

**Import behavior:**
- Detects the protection method from the archive; you do not need to specify it
- For public-key archives, compares the private key's fingerprint with the archive before decrypting and reports both fingerprints on a mismatch
- Fails before writing anything if the target server has no active master key (`key register` first)
- Imports versions oldest first per key, so the newest exported version becomes current; version numbers restart on the target server and retention limits apply (files keep 3, credentials 10)
- Imported records are added as new versions on top of any existing key with the same name
- Plaintext metadata is preserved
- Future `expires_at` values are converted back into TTL seconds; if a key's newest archived version has already expired, `secret import` skips **every archived version** of that key so older superseded versions are never revived. Under an unexpired newest archived version, individual expired older versions are still skipped.

**Example: restore onto a new server that already has its own key pair**
```bash
# The new server's config points at its own fresh key pair (already registered).
sealbox-cli secret import backups/sealbox-export.json \
  --private-key ~/old-machine/private_key.pem

# Secrets are now encrypted to the new key and readable with the configured key.
sealbox-cli secret get db/password
```

## Password Generation Commands

Password generation happens locally in the CLI. The standalone command prints generated passwords to stdout. Credential generation stores the password directly through the encrypted credential flow.

### `password generate`

Generate strong passwords or alphanumeric random-ID-style values.

```bash
sealbox-cli password generate [OPTIONS]
```

**Options:**
- `--length <number>` - Password length (default: 24)
- `--count <number>` - Number of passwords to generate (default: 1)
- `--alphanumeric` - Use ASCII letters and digits only
- `--no-symbols` - Exclude symbols
- `--no-numbers` - Exclude numbers
- `--no-uppercase` - Exclude uppercase letters
- `--no-lowercase` - Exclude lowercase letters
- `--exclude-ambiguous` - Exclude ambiguous characters such as `O`, `0`, `I`, `l`, and `1`

**Examples:**
```bash
# Generate one broad-character password
sealbox-cli password generate --length 32

# Generate an alphanumeric random-id-style value
sealbox-cli password generate --alphanumeric --length 40

# Generate several values
sealbox-cli password generate --count 5 --exclude-ambiguous
```

## Credential Commands

Credential commands store username/password pairs as encrypted JSON secret values. The username is also stored as plaintext metadata so credentials can be listed and filtered without decrypting every record.

Sealbox retains only the latest 10 versions for each credential key. Older credential versions are pruned automatically when a new credential version is saved.

### `credential set`

Store a username/password credential. The password is read from a hidden prompt when attached to a TTY, from stdin when piped, or generated locally with `--generate-password`.

```bash
sealbox-cli credential set <key> --username <username> [OPTIONS]
```

**Options:**
- `--username <username>` - Username to store in encrypted data and plaintext metadata
- `--ttl <seconds>` - Time-to-live in seconds
- `--generate-password` - Generate a strong password locally instead of prompting or reading stdin
- `--show-password` - Print the generated password after it is saved
- `--length <number>` - Generated password length (default: 24)
- `--alphanumeric` - Generate only ASCII letters and digits
- `--no-symbols` - Exclude symbols from generated passwords
- `--no-numbers` - Exclude numbers from generated passwords
- `--no-uppercase` - Exclude uppercase letters from generated passwords
- `--no-lowercase` - Exclude lowercase letters from generated passwords
- `--exclude-ambiguous` - Exclude ambiguous generated characters such as `O`, `0`, `I`, `l`, and `1`

**Example:**
```bash
sealbox-cli credential set db/postgres --username app_user

# Generate and store a password without printing it
sealbox-cli credential set db/postgres --username app_user --generate-password

# Generate an alphanumeric password for systems that reject symbols
sealbox-cli credential set api/service \
  --username service_user \
  --generate-password \
  --alphanumeric \
  --length 40

# Non-interactive stdin
printf '%s\n' "db-password" | sealbox-cli credential set db/postgres --username app_user
```

### `credential get`

Retrieve and decrypt a credential.

```bash
sealbox-cli credential get <key> [OPTIONS]
```

**Options:**
- `--version <version>` - Specific version to retrieve

### `credential list`

List credentials using plaintext metadata. Passwords are not included.

```bash
sealbox-cli credential list [OPTIONS]
```

**Options:**
- `--name <text>` - Filter by credential name/key substring
- `--key <text>` - Alias for `--name`
- `--username <text>` - Filter by username substring
- `--query <text>` - Filter by credential name/key or username substring

Search filters are case-insensitive substring matches. If multiple specific filters are provided, all of them must match. `--query` matches either credential name/key or username.

### `credential history`

List retained version metadata for one credential, including version numbers and plaintext username metadata. Passwords are not included.

```bash
sealbox-cli credential history <key>
```

**Example:**
```bash
sealbox-cli credential history db/postgres --output json
```

### `credential delete`

Delete a credential and all stored versions.

```bash
sealbox-cli credential delete <key>
```

**Example:**
```bash
sealbox-cli credential delete db/postgres
```

## TTL and Administration

### TTL (Time-To-Live) Overview

TTL allows secrets, credentials, and files to automatically expire and be deleted:

**How it works:**
- Set TTL in seconds when storing values with `--ttl <seconds>`
- **Whole-key expiry rule:** A key's expiry is decided by its newest version (highest version number). A value written with a TTL replaces the key's value until it expires; afterwards the key does not exist—reads by key or by older version delete all versions and return `404`, and listings and version history omit it. Silently reviving a superseded value when a temporary value expires is unsafe for credentials.
- **Expired older versions:** An expired older version under a newer, unexpired version is still removed on its own while the active key remains readable.
- Expired keys (all versions) and expired older versions are deleted when accessed (lazy cleanup) and on server startup
- Manual cleanup is available per tenant via `sealbox-cli secret cleanup-expired` (or `DELETE /v2/cleanup-expired`) and across all tenants via the root admin API (`DELETE /v2/admin/cleanup-expired`); `deleted_count` counts every removed version row

**Use cases:**
- **Temporary tokens**: API keys that should expire quickly
- **Session data**: User sessions with automatic timeout
- **One-time secrets**: Passwords that should be short-lived
- **Development**: Temporary configurations for testing

### Manual Cleanup

For a single tenant, run `sealbox-cli secret cleanup-expired` with a tenant token (no local key files required). It removes every version of expired secrets, credentials, and files in that tenant plus expired older versions under active keys, counts every deleted stored version (row) in `deleted_count`, and rejects the root token with HTTP `401`. For scripts, pass the token through `SEALBOX_TOKEN_FILE` instead of `--token`:

```bash
# Expired records in your tenant (tenant token, table output)
sealbox-cli secret cleanup-expired

# Scripted run with a token file and exact JSON output
SEALBOX_URL=http://localhost:8080 \
SEALBOX_TOKEN_FILE=/secure/tenant/token \
sealbox-cli secret cleanup-expired --output json
```

All-tenant cleanup has no CLI command; call the root admin API directly:

```bash
# Expired records in every tenant (root token, API-only)
curl -X DELETE -H "Authorization: Bearer $AUTH_TOKEN" \
  http://localhost:8080/v2/admin/cleanup-expired

# JSON response shape (for both the CLI --output json and the API)
{
  "deleted_count": 15,
  "cleaned_at": 1640995200
}
```

## Migrating from v1

The v1 API is **deprecated, disabled by default, and will be removed after
2026-11-25**. It used the server root token for data access and stored
everything in a built-in tenant named `legacy`. v2 is the default for the
server, the CLI, and the web UI.

Data written through v1 is still in the `legacy` tenant. To keep using it,
issue a tenant token for that tenant with the root token and switch the client
to v2:

```bash
# Root token: issue a token for the pre-tenant data
sealbox-cli --token "$AUTH_TOKEN" tenant token create legacy \
  --label "v1 migration" --token-file ~/.config/sealbox/tenant_token

# Point the CLI at v2 and the new token (existing key files stay the same)
sealbox-cli config set server.api_version v2
sealbox-cli config set server.token "$(cat ~/.config/sealbox/tenant_token)"
sealbox-cli secret list
```

Config files written by older CLIs may contain `api_version = "v1"`. The CLI
then prints a deprecation warning, and requests fail with `404` because servers
now disable v1. Run the `config set` command above to fix this.

Commands that use the root token (`tenant ...` and `admin backup`) are not
affected by `api_version`. Pass the root token with `--token` when your
configured token is a tenant token.

If a client cannot move yet, set `LEGACY_V1_ENABLED=true` on the server. v1
responses carry `Deprecation` and `Sunset` headers, and the server logs a
warning at startup.

## Output Formats

### Table Format (Default)

Human-readable table output:
```
┌─────────────┬─────────┬─────────────────────┐
│ Key         │ Version │ Created             │
├─────────────┼─────────┼─────────────────────┤
│ db_password │ 1       │ 2024-01-15 10:30:45 │
│ api_key     │ 2       │ 2024-01-15 11:15:20 │
└─────────────┴─────────┴─────────────────────┘
```

### JSON Format

Machine-readable JSON output:
```json
{
  "secrets": [
    {
      "key": "db_password",
      "version": 1,
      "created": "2024-01-15T10:30:45Z"
    }
  ]
}
```

### YAML Format

YAML output:
```yaml
secrets:
  - key: db_password
    version: 1
    created: 2024-01-15T10:30:45Z
```

## Environment Variables

CLI commands can be configured using environment variables:

- `SEALBOX_URL` - Server URL
- `SEALBOX_TOKEN` - Authentication token
- `SEALBOX_TOKEN_FILE` - File containing authentication token
- `SEALBOX_PUBLIC_KEY` - Public key path
- `SEALBOX_PRIVATE_KEY` - Private key path
- `SEALBOX_PUBLIC_KEY_FILE` - Mounted public key file path
- `SEALBOX_PRIVATE_KEY_FILE` - Mounted private key file path
- `SEALBOX_OUTPUT_FORMAT` - Default output format
- `SEALBOX_API_VERSION` - `v2` (default) or the deprecated `v1`
- `SEALBOX_BACKUP_PASSPHRASE` - Passphrase for `key export`/`key import` and passphrase-protected archives, when `--passphrase-file` is not given

## Exit Codes

- `0` - Success
- `1` - Error (authentication, HTTP/server, network/timeout, or file/configuration error — including an invalid `--api-version` value; details are written to stderr)
- `2` - Usage error (unknown subcommand such as `unrecognized subcommand` on an older CLI, unknown flag, missing required argument, or an invalid parser-validated option such as `--output`; reported before any request is made)

## Server Backup Commands

### `admin backup`

Download a consistent snapshot of the whole server database through
`GET /v2/admin/backup`. Requires the root token (`AUTH_TOKEN`). Tenant tokens
are rejected.

```bash
sealbox-cli admin backup --file backups/sealbox.db [--force]
```

The response is checked to be a SQLite database and written with mode `0600`.
Restore it with `sealbox-server restore`.

## Tenant Administration Commands

Tenant commands require the server root token. New token values are never
printed; `--token-file` must name a file that does not already exist.

```bash
sealbox-cli tenant create --display-name app-a --token-file /secure/app-a/token
sealbox-cli tenant list
sealbox-cli tenant get <tenant-id>
sealbox-cli tenant suspend <tenant-id>
sealbox-cli tenant resume <tenant-id>
sealbox-cli tenant token create <tenant-id> --label rotated --token-file /secure/app-a/token-2
sealbox-cli tenant token list <tenant-id>
sealbox-cli tenant token revoke <tenant-id> <token-id>
```

For tenant key and secret commands, set `SEALBOX_API_VERSION=v2`, select the
tenant token file, and select that tenant's public/private key files.
