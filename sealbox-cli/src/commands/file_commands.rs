use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use reqwest::Client;
use sealbox_server::repo::{FileMetadata, MAX_SECRET_PLAINTEXT_BYTES, SecretInfo};
use serde::Deserialize;
use serde_json::json;

use crate::{FileCommands, config::Config, output::OutputManager};

use super::secret_commands::{
    delete_secret, fetch_decrypted_secret_bytes, save_secret_bytes_summary,
};

#[derive(Debug, Deserialize)]
struct ListSecretsResponse {
    secrets: Vec<SecretInfo>,
}

pub async fn handle_command(command: FileCommands, config: &Config) -> Result<()> {
    let output = OutputManager::new(config.output.format.clone());

    match command {
        FileCommands::Set {
            key,
            file,
            ttl,
            content_type,
        } => set_file(config, &output, key, file, ttl, content_type).await,
        FileCommands::Get {
            key,
            file,
            version,
            force,
        } => get_file(config, &output, key, file, version, force).await,
        FileCommands::List { name, query } => list_files(config, &output, name, query).await,
        FileCommands::Delete { key } => delete_secret(config, &output, key, None).await,
    }
}

/// Parse the plaintext metadata column, returning `None` for non-file records.
///
/// Uses the shared [`FileMetadata`] type so the CLI and server cannot drift on
/// the metadata shape.
fn parse_file_metadata(metadata: Option<&str>) -> Option<FileMetadata> {
    FileMetadata::parse(metadata)
}

fn read_file_bytes(path: &str) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("Failed to read file: {path}"))?;
    if bytes.len() > MAX_SECRET_PLAINTEXT_BYTES {
        anyhow::bail!(
            "File '{}' is {} bytes, which exceeds the {} byte (500 KB) limit",
            path,
            bytes.len(),
            MAX_SECRET_PLAINTEXT_BYTES
        );
    }
    Ok(bytes)
}

fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

fn write_private_file(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "Refusing to overwrite existing file: {} (pass --force to replace it)",
            path.display()
        );
    }

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut handle = options
        .open(path)
        .with_context(|| format!("Failed to create file: {}", path.display()))?;
    handle
        .write_all(bytes)
        .with_context(|| format!("Failed to write file: {}", path.display()))?;
    handle
        .sync_all()
        .with_context(|| format!("Failed to sync file: {}", path.display()))?;
    Ok(())
}

async fn set_file(
    config: &Config,
    output: &OutputManager,
    key: String,
    file: String,
    ttl: Option<i64>,
    content_type: Option<String>,
) -> Result<()> {
    config
        .validate()
        .context("Configuration validation failed")?;

    let bytes = read_file_bytes(&file)?;
    let metadata = FileMetadata::new(file_name(&file), content_type)
        .to_json()
        .context("Failed to serialize file metadata")?;

    output.print_info(&format!(
        "Encrypting {} bytes from {} locally...",
        bytes.len(),
        file
    ));

    save_secret_bytes_summary(config, output, key, &bytes, ttl, Some(metadata)).await
}

async fn get_file(
    config: &Config,
    output: &OutputManager,
    key: String,
    file: Option<String>,
    version: Option<i32>,
    force: bool,
) -> Result<()> {
    config
        .validate()
        .context("Configuration validation failed")?;

    output.print_info("Fetching and decrypting file...");
    let decrypted = fetch_decrypted_secret_bytes(config, &key, version).await?;

    let metadata = parse_file_metadata(decrypted.metadata.as_deref());
    let target: PathBuf = match file {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(
            metadata
                .as_ref()
                .map(|metadata| metadata.filename.clone())
                .unwrap_or_else(|| key.clone()),
        ),
    };

    write_private_file(&target, &decrypted.bytes, force)?;

    output.print_success(&format!(
        "Wrote {} bytes to {}",
        decrypted.bytes.len(),
        target.display()
    ));
    output.print_value(&json!({
        "key": decrypted.key,
        "version": decrypted.version,
        "expires_at": decrypted.expires_at,
        "filename": metadata.as_ref().map(|metadata| metadata.filename.clone()),
        "content_type": metadata.as_ref().and_then(|metadata| metadata.content_type.clone()),
        "bytes": decrypted.bytes.len(),
        "path": target.display().to_string(),
    }))
}

async fn list_files(
    config: &Config,
    output: &OutputManager,
    name: Option<String>,
    query: Option<String>,
) -> Result<()> {
    config
        .validate()
        .context("Configuration validation failed")?;

    let client = Client::new();
    let response = client
        .get(config.api_url("secrets"))
        .bearer_auth(&config.server.token)
        .send()
        .await
        .context("Failed to request server")?;

    let status = response.status();
    if !status.is_success() {
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unable to get error information".to_string());
        anyhow::bail!(
            "Server returned error (status code: {}):\n{}",
            status,
            error_body
        );
    }

    let result: ListSecretsResponse = response
        .json()
        .await
        .context("Failed to parse server response")?;

    let name_filter = name.map(|filter| filter.to_lowercase());
    let query_filter = query.map(|filter| filter.to_lowercase());

    let files = result
        .secrets
        .into_iter()
        .filter_map(|secret| {
            let metadata = parse_file_metadata(secret.metadata.as_deref())?;
            if let Some(filter) = &name_filter
                && !secret.key.to_lowercase().contains(filter)
            {
                return None;
            }
            if let Some(filter) = &query_filter
                && !secret.key.to_lowercase().contains(filter)
                && !metadata.filename.to_lowercase().contains(filter)
            {
                return None;
            }
            Some(json!({
                "key": secret.key,
                "version": secret.version,
                "filename": metadata.filename,
                "content_type": metadata.content_type,
                "expires_at": secret.expires_at,
            }))
        })
        .collect::<Vec<_>>();

    if files.is_empty() {
        output.print_info("No files found");
    } else {
        output.print_value(&json!(files))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_file_metadata_accepts_file_records() {
        let metadata = r#"{"type":"file","filename":"app.yaml","content_type":"text/yaml"}"#;
        let parsed = parse_file_metadata(Some(metadata)).expect("Should parse file metadata");

        assert_eq!(parsed.filename, "app.yaml");
        assert_eq!(parsed.content_type.as_deref(), Some("text/yaml"));
    }

    #[test]
    fn test_parse_file_metadata_ignores_other_types() {
        let metadata = r#"{"type":"credential","username":"app"}"#;
        assert!(parse_file_metadata(Some(metadata)).is_none());
        assert!(parse_file_metadata(None).is_none());
        assert!(parse_file_metadata(Some("not-json")).is_none());
    }

    #[test]
    fn test_file_name_extracts_base_name() {
        assert_eq!(file_name("/etc/app/config.yaml"), "config.yaml");
        assert_eq!(file_name("config.yaml"), "config.yaml");
    }

    #[test]
    fn test_read_file_bytes_rejects_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");
        fs::write(&path, vec![0u8; MAX_SECRET_PLAINTEXT_BYTES + 1]).unwrap();

        let error = read_file_bytes(path.to_str().unwrap()).unwrap_err();

        assert!(error.to_string().contains("exceeds"));
    }

    #[test]
    fn test_read_file_bytes_accepts_file_at_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exact.bin");
        fs::write(&path, vec![0u8; MAX_SECRET_PLAINTEXT_BYTES]).unwrap();

        let bytes = read_file_bytes(path.to_str().unwrap()).unwrap();

        assert_eq!(bytes.len(), MAX_SECRET_PLAINTEXT_BYTES);
    }

    #[test]
    fn test_write_private_file_creates_owner_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("secret.bin");

        write_private_file(&path, b"payload", false).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"payload");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn test_write_private_file_refuses_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.bin");
        fs::write(&path, b"original").unwrap();

        let error = write_private_file(&path, b"replacement", false).unwrap_err();

        assert!(error.to_string().contains("--force"));
        assert_eq!(fs::read(&path).unwrap(), b"original");
    }

    #[test]
    fn test_write_private_file_overwrites_with_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.bin");
        fs::write(&path, b"original").unwrap();

        write_private_file(&path, b"replacement", true).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"replacement");
    }
}
