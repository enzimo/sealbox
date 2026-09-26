use std::path::Path;

use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::json;

use crate::{AdminCommands, config::Config, output::OutputManager};

use super::private_file::write_private_file;

const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

pub async fn handle_command(command: AdminCommands, config: &Config) -> Result<()> {
    config
        .validate()
        .context("Configuration validation failed")?;
    let output = OutputManager::new(config.output.format.clone());
    match command {
        AdminCommands::Backup { file, force } => backup(config, &output, file, force).await,
    }
}

/// Download a full database snapshot through `GET /v2/admin/backup`.
async fn backup(config: &Config, output: &OutputManager, file: String, force: bool) -> Result<()> {
    if !force && Path::new(&file).exists() {
        anyhow::bail!("Backup file already exists: {file} (use --force to replace it)");
    }

    output.print_info("Requesting database snapshot from server (requires the root token)...");
    let url = config.admin_url("backup");
    let response = Client::new()
        .get(&url)
        .bearer_auth(&config.server.token)
        .send()
        .await
        .with_context(|| format!("Failed to request Sealbox admin API: {url}"))?;

    let status = response.status();
    if !status.is_success() {
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unable to get error information".to_string());
        anyhow::bail!("Sealbox admin API returned {status}: {error_body}");
    }
    let bytes = response
        .bytes()
        .await
        .context("Failed to download database snapshot")?;
    if !bytes.starts_with(SQLITE_MAGIC) {
        anyhow::bail!("Server response is not a SQLite database snapshot");
    }

    write_private_file(Path::new(&file), &bytes, force)?;

    output.print_success(&format!("Database snapshot saved to: {file}"));
    output.print_warning(
        "Secret values in the snapshot stay encrypted, but it contains all tenant metadata and token hashes. Store it like the root token.",
    );
    output.print_value(&json!({
        "file": file,
        "size_bytes": bytes.len(),
    }))?;
    Ok(())
}
