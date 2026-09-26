use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use anyhow::{Context, Result};

/// Write `bytes` to `path` with owner-only (0600) permissions on Unix.
///
/// Without `overwrite` the call fails if the file already exists, so a backup
/// or restored key can never silently replace an existing one.
pub fn write_private_file(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    let mut options = OpenOptions::new();
    options.write(true);
    if overwrite {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).with_context(|| {
        if !overwrite && path.exists() {
            format!(
                "Refusing to overwrite existing file: {} (use --force to replace it)",
                path.display()
            )
        } else {
            format!("Failed to create file: {}", path.display())
        }
    })?;

    // `mode` only applies when the file is created; tighten a replaced file too.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to set permissions on {}", path.display()))?;
    }

    file.write_all(bytes)
        .with_context(|| format!("Failed to write file: {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("Failed to sync file: {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_write_private_file_refuses_overwrite_without_flag() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("nested/backup.json");

        write_private_file(&path, b"first", false).unwrap();
        let second = write_private_file(&path, b"second", false);

        assert!(second.unwrap_err().to_string().contains("--force"));
        assert_eq!(fs::read(&path).unwrap(), b"first");
    }

    #[test]
    fn test_write_private_file_overwrites_with_flag_and_restricts_mode() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("backup.json");
        fs::write(&path, "old-content-that-is-longer").unwrap();

        write_private_file(&path, b"new", true).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
