//! Consistent database snapshots for operator backup and restore.
//!
//! Every secret in the database is already envelope-encrypted, so a snapshot
//! is safe to store without further encryption. It does contain tenant token
//! hashes and plaintext metadata, so it is still written owner-only.

use std::{
    fs,
    path::{Path, PathBuf},
};

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;

use crate::error::{Result, SealboxError};

/// Tables every Sealbox database has after migrations have run.
const REQUIRED_TABLES: [&str; 3] = ["master_keys", "secrets", "tenants"];

#[derive(Debug, Clone, Serialize)]
pub struct BackupReport {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub master_key_count: i64,
    pub secret_version_count: i64,
    pub tenant_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestoreReport {
    pub store_path: PathBuf,
    /// Where the database that was replaced was moved, if one existed.
    pub previous_store_moved_to: Option<PathBuf>,
    pub backup: BackupReport,
}

fn io_error(context: &str, path: &Path, error: std::io::Error) -> SealboxError {
    SealboxError::DatabaseError(format!("{context} {}: {error}", path.display()))
}

fn restrict_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| io_error("failed to set permissions on", path, error))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Write a consistent, compacted snapshot of `conn` to `dest`.
///
/// `VACUUM INTO` reads inside a single transaction, so it is safe while the
/// server is running and captures committed WAL content. The snapshot is
/// integrity-checked before this returns. `dest` must not exist.
pub fn backup_database(conn: &Connection, dest: &Path) -> Result<BackupReport> {
    if dest.exists() {
        return Err(SealboxError::InvalidRequest(format!(
            "backup destination already exists: {}",
            dest.display()
        )));
    }
    if let Some(parent) = dest.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|error| io_error("failed to create directory", parent, error))?;
    }

    let dest_str = dest.to_str().ok_or_else(|| {
        SealboxError::InvalidRequest("backup destination must be valid UTF-8".to_string())
    })?;
    if let Err(error) = conn.execute("VACUUM main INTO ?1", [dest_str]) {
        let _ = fs::remove_file(dest);
        return Err(error.into());
    }
    restrict_permissions(dest)?;

    match verify_backup(dest) {
        Ok(report) => Ok(report),
        Err(error) => {
            let _ = fs::remove_file(dest);
            Err(error)
        }
    }
}

/// Check that `path` is an intact Sealbox database and summarize its contents.
pub fn verify_backup(path: &Path) -> Result<BackupReport> {
    if !path.is_file() {
        return Err(SealboxError::InvalidRequest(format!(
            "backup file does not exist: {}",
            path.display()
        )));
    }
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(SealboxError::DatabaseError(format!(
            "backup failed integrity check: {integrity}"
        )));
    }
    for table in REQUIRED_TABLES {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(SealboxError::InvalidRequest(format!(
                "{} is not a Sealbox database (missing table '{table}')",
                path.display()
            )));
        }
    }

    let count = |table: &str| -> Result<i64> {
        Ok(
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?,
        )
    };
    let size_bytes = fs::metadata(path)
        .map_err(|error| io_error("failed to read", path, error))?
        .len();

    Ok(BackupReport {
        path: path.to_path_buf(),
        size_bytes,
        master_key_count: count("master_keys")?,
        secret_version_count: count("secrets")?,
        tenant_count: count("tenants")?,
    })
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Replace the database at `store_path` with the snapshot at `backup`.
///
/// The server must be stopped first. The backup is verified before anything is
/// touched. An existing store is only replaced with `force`, and is moved aside
/// (with its `-wal`/`-shm` files, which would otherwise be replayed onto the
/// restored database) rather than deleted.
pub fn restore_database(backup: &Path, store_path: &Path, force: bool) -> Result<RestoreReport> {
    let backup_report = verify_backup(backup)?;

    let store_exists = store_path.exists();
    if store_exists && !force {
        return Err(SealboxError::InvalidRequest(format!(
            "store already exists: {} (pass --force to replace it; the current database is kept as a .pre-restore backup)",
            store_path.display()
        )));
    }
    if let Some(parent) = store_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|error| io_error("failed to create directory", parent, error))?;
    }

    // Stage the copy next to the store so the final rename stays on one
    // filesystem and is atomic.
    let staging = sidecar(store_path, ".restoring");
    if staging.exists() {
        fs::remove_file(&staging)
            .map_err(|error| io_error("failed to remove stale", &staging, error))?;
    }
    {
        let source = Connection::open_with_flags(backup, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let staging_str = staging.to_str().ok_or_else(|| {
            SealboxError::InvalidRequest("store path must be valid UTF-8".to_string())
        })?;
        source.execute("VACUUM main INTO ?1", [staging_str])?;
    }
    restrict_permissions(&staging)?;

    let previous_store_moved_to = if store_exists {
        let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
        let moved = sidecar(store_path, &format!(".pre-restore-{timestamp}.bak"));
        fs::rename(store_path, &moved)
            .map_err(|error| io_error("failed to move aside", store_path, error))?;
        for suffix in ["-wal", "-shm"] {
            let from = sidecar(store_path, suffix);
            if from.exists() {
                let to = sidecar(&moved, suffix);
                fs::rename(&from, &to)
                    .map_err(|error| io_error("failed to move aside", &from, error))?;
            }
        }
        Some(moved)
    } else {
        None
    };

    fs::rename(&staging, store_path)
        .map_err(|error| io_error("failed to install restored database at", store_path, error))?;

    Ok(RestoreReport {
        store_path: store_path.to_path_buf(),
        previous_store_moved_to,
        backup: backup_report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::{create_db_connection, run_migrations};

    fn seeded_store(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        let conn = create_db_connection(path.to_str().unwrap()).unwrap();
        run_migrations(&conn).unwrap();
        conn.execute(
            "INSERT INTO tenants (id, display_name, status, created_at, updated_at)
             VALUES ('marker', ?1, 'Active', 0, 0)",
            [name],
        )
        .unwrap();
        path
    }

    fn marker(path: &Path) -> String {
        Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT display_name FROM tenants WHERE id = 'marker'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn test_backup_database_writes_verified_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let store = seeded_store(dir.path(), "store.db");
        let conn = Connection::open(&store).unwrap();
        let dest = dir.path().join("backups/snapshot.db");

        let report = backup_database(&conn, &dest).unwrap();

        assert_eq!(report.path, dest);
        assert!(report.tenant_count >= 1);
        assert_eq!(marker(&dest), "store.db");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn test_backup_database_refuses_existing_destination() {
        let dir = tempfile::tempdir().unwrap();
        let store = seeded_store(dir.path(), "store.db");
        let conn = Connection::open(&store).unwrap();
        let dest = dir.path().join("snapshot.db");
        fs::write(&dest, "keep me").unwrap();

        assert!(backup_database(&conn, &dest).is_err());
        assert_eq!(fs::read_to_string(&dest).unwrap(), "keep me");
    }

    #[test]
    fn test_verify_backup_rejects_non_sealbox_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("other.db");
        Connection::open(&path)
            .unwrap()
            .execute("CREATE TABLE unrelated (id INTEGER)", [])
            .unwrap();

        let error = verify_backup(&path).unwrap_err().to_string();

        assert!(error.contains("not a Sealbox database"));
    }

    #[test]
    fn test_restore_database_into_empty_location() {
        let dir = tempfile::tempdir().unwrap();
        let backup = seeded_store(dir.path(), "backup.db");
        let store = dir.path().join("restored/store.db");

        let report = restore_database(&backup, &store, false).unwrap();

        assert!(report.previous_store_moved_to.is_none());
        assert_eq!(marker(&store), "backup.db");
    }

    #[test]
    fn test_restore_database_requires_force_and_keeps_previous_store() {
        let dir = tempfile::tempdir().unwrap();
        let backup = seeded_store(dir.path(), "backup.db");
        let store = seeded_store(dir.path(), "store.db");

        assert!(restore_database(&backup, &store, false).is_err());
        assert_eq!(marker(&store), "store.db");

        // Written after the last open: SQLite removes a WAL when it closes a connection.
        let stale_wal = sidecar(&store, "-wal");
        fs::write(&stale_wal, "stale").unwrap();
        let report = restore_database(&backup, &store, true).unwrap();

        let moved = report.previous_store_moved_to.unwrap();
        assert_eq!(marker(&store), "backup.db");
        assert!(!stale_wal.exists());
        assert_eq!(
            fs::read_to_string(sidecar(&moved, "-wal")).unwrap(),
            "stale"
        );
    }
}
