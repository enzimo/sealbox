# Archive and bulk operations

Sealbox supports encrypted bulk operations for backup and migration through CLI import/export.

## `secret export`

- Creates archive files from current local-secret records.
- Exported artifacts are encrypted in structure and can be versioned back.
- Useful for:
  - off-host backup
  - migration to a fresh DB
  - cross-environment transfer workflows

## `secret import`

- Loads a compatible archive into current server context.
- Can restore encrypted versions and metadata according to import format.
- Requires appropriate target key material and endpoint compatibility.
- Applies the whole-key expiry rule: if a key's newest archived version has expired (`expires_at < now`), every archived version of that key is skipped so superseded older versions are never revived. Under an unexpired newest archived version, individual expired older versions are still skipped.

## Supported archive formats

- `sealbox-v1`: format for v1-era payload compatibility.
- `encrypted-tar`: encrypted tar-based portable bundle.
- Archive contains manifest and encrypted secret payloads; it is not plaintext JSON export.

## Safety notes

- Treat exported files as sensitive secrets-bearing artifacts.
- If importing into tenant mode, validate tenant mapping and API version.
- Rehearse import/export in a staging environment before production rotations.
- Verify key state (`key status`) and active key IDs after import.
