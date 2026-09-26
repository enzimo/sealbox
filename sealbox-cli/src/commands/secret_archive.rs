use std::{
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use reqwest::Client;
use sealbox_server::{
    crypto::{
        data_key::DataKey,
        master_key::{PrivateMasterKey, PublicMasterKey},
    },
    repo::SecretInfo,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{config::Config, output::OutputManager};

use super::{
    passphrase::{self, DEFAULT_KDF_COST, KdfCost, PassphraseSealed},
    private_file::write_private_file,
    secret_commands::{
        encrypt_and_store, fetch_active_master_key, fetch_decrypted_secret_bytes,
        fetch_secret_history,
    },
};

/// Envelope written by releases before key fingerprints and passphrases.
/// Still accepted on import.
const LEGACY_ENVELOPE_VERSION: u32 = 1;
const ENVELOPE_VERSION: u32 = 2;
const ARCHIVE_FORMAT_VERSION: u32 = 2;
const ARCHIVE_TYPE: &str = "sealbox.encrypted-tar";
const ARCHIVE_CIPHER: &str = "AES-256-GCM";
const KEY_CIPHER: &str = "RSA-OAEP-SHA256";
/// Authenticated context for passphrase-protected archives.
const ARCHIVE_PASSPHRASE_CONTEXT: &str = "sealbox.encrypted-tar.v2";
const MANIFEST_PATH: &str = "manifest.json";
const SECRETS_PATH: &str = "secrets.json";

#[derive(Debug, Deserialize)]
struct ListSecretsResponse {
    secrets: Vec<SecretInfo>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct EncryptedExportEnvelopeV1 {
    envelope_version: u32,
    archive_type: String,
    archive_cipher: String,
    key_cipher: String,
    encrypted_data_key_b64: String,
    encrypted_archive_b64: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct EncryptedExportEnvelopeV2 {
    envelope_version: u32,
    archive_type: String,
    protection: ArchiveProtection,
}

/// How the archive's AES key is protected.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "method", rename_all = "kebab-case")]
enum ArchiveProtection {
    /// A random AES key wrapped with an RSA public key. The fingerprint names
    /// the key pair so import can reject the wrong private key up front.
    RsaOaepSha256 {
        public_key_fingerprint: String,
        archive_cipher: String,
        encrypted_data_key_b64: String,
        encrypted_archive_b64: String,
    },
    /// An AES key derived from a passphrase; readable without any RSA key.
    Passphrase { sealed: PassphraseSealed },
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct ExportManifestV1 {
    format_version: u32,
    application: String,
    exported_at: i64,
    secret_count: usize,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct ExportManifestV2 {
    format_version: u32,
    application: String,
    exported_at: i64,
    /// Number of records (secret versions) in `secrets.json`.
    secret_count: usize,
    /// Number of distinct secret keys.
    key_count: usize,
    all_versions: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct ExportSecretRecordV1 {
    key: String,
    value: String,
    version: i32,
    expires_at: Option<i64>,
    metadata: Option<String>,
}

/// One secret version. Values are base64 so binary files survive the trip;
/// v1 stored UTF-8 strings and could not export binary files at all.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ExportSecretRecordV2 {
    key: String,
    version: i32,
    value_b64: String,
    created_at: Option<i64>,
    expires_at: Option<i64>,
    metadata: Option<String>,
}

impl From<ExportSecretRecordV1> for ExportSecretRecordV2 {
    fn from(record: ExportSecretRecordV1) -> Self {
        Self {
            key: record.key,
            version: record.version,
            value_b64: BASE64.encode(record.value.as_bytes()),
            created_at: None,
            expires_at: record.expires_at,
            metadata: record.metadata,
        }
    }
}

pub struct ExportOptions {
    pub file: String,
    pub keys_pattern: Option<String>,
    pub format: String,
    pub all_versions: bool,
    pub passphrase: bool,
    pub passphrase_file: Option<String>,
    pub force: bool,
}

/// How to protect a new archive, resolved before any secrets are fetched so a
/// bad key or passphrase fails fast.
enum ExportProtection {
    PublicKey(PublicMasterKey),
    Passphrase(String),
}

pub async fn export_secrets(
    config: &Config,
    output: &OutputManager,
    options: ExportOptions,
) -> Result<()> {
    validate_archive_format(&options.format)?;
    config
        .validate()
        .context("Configuration validation failed")?;
    if !options.force && Path::new(&options.file).exists() {
        anyhow::bail!(
            "Archive already exists: {} (use --force to replace it)",
            options.file
        );
    }

    let protection = if options.passphrase || options.passphrase_file.is_some() {
        ExportProtection::Passphrase(passphrase::read_passphrase(
            output,
            options.passphrase_file.as_deref(),
            true,
        )?)
    } else {
        ExportProtection::PublicKey(load_public_key(&config.keys.public_key_path)?)
    };

    output.print_info("Fetching secret list...");
    let mut secret_infos = fetch_secret_infos(config).await?;
    if let Some(pattern) = &options.keys_pattern {
        secret_infos.retain(|secret| secret.key.contains(pattern));
    }
    if secret_infos.is_empty() {
        anyhow::bail!("No secrets matched export criteria");
    }
    secret_infos.sort_by(|left, right| left.key.cmp(&right.key));
    let key_count = secret_infos.len();

    output.print_info("Decrypting secrets locally for encrypted archive export...");
    let mut records = Vec::new();
    for secret in secret_infos {
        let versions = if options.all_versions {
            let mut history = fetch_secret_history(config, &secret.key)
                .await
                .with_context(|| format!("Failed to list versions of '{}'", secret.key))?;
            history.sort_by_key(|info| info.version);
            history
        } else {
            vec![secret]
        };

        for info in versions {
            let decrypted = fetch_decrypted_secret_bytes(config, &info.key, Some(info.version))
                .await
                .with_context(|| {
                    format!(
                        "Failed to decrypt '{}' version {} for export",
                        info.key, info.version
                    )
                })?;
            records.push(ExportSecretRecordV2 {
                key: decrypted.key,
                version: decrypted.version,
                value_b64: BASE64.encode(&decrypted.bytes),
                created_at: Some(info.created_at),
                expires_at: decrypted.expires_at,
                metadata: decrypted.metadata,
            });
        }
    }

    let manifest = ExportManifestV2 {
        format_version: ARCHIVE_FORMAT_VERSION,
        application: "sealbox-cli".to_string(),
        exported_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        secret_count: records.len(),
        key_count,
        all_versions: options.all_versions,
    };
    let tar_bytes = build_archive_tar(&manifest, &records)?;
    let (envelope, protection_summary) = match protection {
        ExportProtection::PublicKey(public_key) => {
            let fingerprint = public_key.fingerprint()?;
            (
                encrypt_archive_for_key(&public_key, &tar_bytes)?,
                json!({ "method": "rsa-oaep-sha256", "public_key_fingerprint": fingerprint }),
            )
        }
        ExportProtection::Passphrase(passphrase) => (
            encrypt_archive_with_passphrase(&passphrase, &tar_bytes, DEFAULT_KDF_COST)?,
            json!({ "method": "passphrase" }),
        ),
    };

    write_private_file(
        &PathBuf::from(&options.file),
        &serde_json::to_vec_pretty(&envelope)?,
        options.force,
    )?;

    output.print_success(&format!(
        "Exported {} secret versions across {} keys to encrypted archive: {}",
        records.len(),
        key_count,
        options.file
    ));
    output.print_value(&json!({
        "file": options.file,
        "archive_type": ARCHIVE_TYPE,
        "envelope_version": ENVELOPE_VERSION,
        "format_version": ARCHIVE_FORMAT_VERSION,
        "protection": protection_summary,
        "key_count": key_count,
        "secret_count": records.len(),
        "all_versions": options.all_versions
    }))?;

    Ok(())
}

pub async fn import_secrets(
    config: &Config,
    output: &OutputManager,
    file_path: String,
    format: String,
    passphrase_file: Option<String>,
) -> Result<()> {
    validate_archive_format(&format)?;
    config
        .validate()
        .context("Configuration validation failed")?;

    output.print_info(&format!("Reading encrypted archive: {file_path}"));
    let envelope_bytes =
        fs::read(&file_path).with_context(|| format!("Failed to read archive: {file_path}"))?;
    let tar_bytes = decrypt_archive(
        &envelope_bytes,
        &config.keys.private_key_path,
        output,
        || passphrase::read_passphrase(output, passphrase_file.as_deref(), false),
    )?;
    let mut records = read_archive_tar(&tar_bytes)?;

    // New secrets are encrypted to this server's active key, not the key the
    // archive was exported with, so fail before writing anything if none.
    let active_key = fetch_active_master_key(config).await.context(
        "The target server has no usable active master key. Register one first with 'sealbox-cli key register'",
    )?;
    output.print_info(&format!(
        "Re-encrypting {} secret versions to the server's active master key {}...",
        records.len(),
        active_key.id
    ));

    // Oldest first per key, so the newest imported version becomes current.
    records.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then(left.version.cmp(&right.version))
    });

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut imported_count = 0usize;
    let mut skipped_count = 0usize;

    for record in records {
        let ttl = match record.expires_at {
            Some(expires_at) if expires_at <= now => {
                skipped_count += 1;
                output.print_warning(&format!(
                    "Skipping expired secret '{}' version {}",
                    record.key, record.version
                ));
                continue;
            }
            Some(expires_at) => Some(expires_at - now),
            None => None,
        };
        let value = BASE64.decode(&record.value_b64).with_context(|| {
            format!(
                "Invalid value encoding for '{}' version {}",
                record.key, record.version
            )
        })?;

        encrypt_and_store(
            config,
            output,
            record.key.clone(),
            &value,
            ttl,
            record.metadata,
        )
        .await
        .with_context(|| {
            format!(
                "Failed to import secret '{}' version {}",
                record.key, record.version
            )
        })?;
        imported_count += 1;
    }

    output.print_success(&format!(
        "Import completed! Imported: {imported_count}, skipped expired: {skipped_count}"
    ));
    output.print_value(&json!({
        "file": file_path,
        "imported": imported_count,
        "skipped_expired": skipped_count,
        "master_key_id": active_key.id,
    }))?;

    Ok(())
}

async fn fetch_secret_infos(config: &Config) -> Result<Vec<SecretInfo>> {
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
            "Server returned error while listing secrets (status code: {}):\n{}",
            status,
            error_body
        );
    }

    let result: ListSecretsResponse = response
        .json()
        .await
        .context("Failed to parse secret list response")?;
    Ok(result.secrets)
}

fn validate_archive_format(format: &str) -> Result<()> {
    match format {
        "encrypted-tar" | "sealbox-v1" => Ok(()),
        _ => anyhow::bail!(
            "Unsupported archive format: {}. Supported formats: encrypted-tar, sealbox-v1",
            format
        ),
    }
}

fn load_public_key(path: &Path) -> Result<PublicMasterKey> {
    let pem = fs::read_to_string(path)
        .with_context(|| format!("Failed to read public key file: {}", path.display()))?;
    PublicMasterKey::from_str(&pem).context("Failed to parse public key")
}

fn load_private_key(path: &Path) -> Result<PrivateMasterKey> {
    let pem = fs::read_to_string(path).with_context(|| {
        format!(
            "Failed to read private key file: {}. Pass the key that was used for the export with --private-key <path>",
            path.display()
        )
    })?;
    PrivateMasterKey::from_str(&pem).context("Failed to parse private key")
}

fn encrypt_archive_for_key(
    public_key: &PublicMasterKey,
    tar_bytes: &[u8],
) -> Result<EncryptedExportEnvelopeV2> {
    let data_key = DataKey::new();
    let encrypted_archive = data_key
        .encrypt(tar_bytes)
        .context("Failed to encrypt archive")?;
    let encrypted_data_key = public_key
        .encrypt(data_key.as_bytes())
        .context("Failed to encrypt archive data key")?;

    Ok(EncryptedExportEnvelopeV2 {
        envelope_version: ENVELOPE_VERSION,
        archive_type: ARCHIVE_TYPE.to_string(),
        protection: ArchiveProtection::RsaOaepSha256 {
            public_key_fingerprint: public_key.fingerprint()?,
            archive_cipher: ARCHIVE_CIPHER.to_string(),
            encrypted_data_key_b64: BASE64.encode(encrypted_data_key),
            encrypted_archive_b64: BASE64.encode(encrypted_archive),
        },
    })
}

fn encrypt_archive_with_passphrase(
    passphrase: &str,
    tar_bytes: &[u8],
    cost: KdfCost,
) -> Result<EncryptedExportEnvelopeV2> {
    Ok(EncryptedExportEnvelopeV2 {
        envelope_version: ENVELOPE_VERSION,
        archive_type: ARCHIVE_TYPE.to_string(),
        protection: ArchiveProtection::Passphrase {
            sealed: passphrase::seal(passphrase, tar_bytes, ARCHIVE_PASSPHRASE_CONTEXT, cost)?,
        },
    })
}

/// Decrypt any supported envelope version to the inner tar bytes.
///
/// RSA archives use the private key at `private_key_path` (the configured key,
/// or `--private-key`). Passphrase archives call `read_passphrase` only when
/// needed, so RSA imports never prompt.
fn decrypt_archive(
    envelope_bytes: &[u8],
    private_key_path: &Path,
    output: &OutputManager,
    read_passphrase: impl FnOnce() -> Result<String>,
) -> Result<Vec<u8>> {
    let value: Value =
        serde_json::from_slice(envelope_bytes).context("Failed to parse export envelope")?;
    let envelope_version = value
        .get("envelope_version")
        .and_then(Value::as_u64)
        .context("Export envelope is missing envelope_version")?;

    match envelope_version {
        v if v == u64::from(LEGACY_ENVELOPE_VERSION) => {
            let envelope: EncryptedExportEnvelopeV1 =
                serde_json::from_value(value).context("Failed to parse v1 export envelope")?;
            validate_envelope_v1(&envelope)?;
            output.print_info(&format!(
                "Decrypting archive with private key: {}",
                private_key_path.display()
            ));
            let private_key = load_private_key(private_key_path)?;
            decrypt_with_private_key(
                &private_key,
                &envelope.encrypted_data_key_b64,
                &envelope.encrypted_archive_b64,
            )
            .context(
                "Failed to decrypt archive. It was probably exported with a different key pair; pass that private key with --private-key <path>",
            )
        }
        v if v == u64::from(ENVELOPE_VERSION) => {
            let envelope: EncryptedExportEnvelopeV2 =
                serde_json::from_value(value).context("Failed to parse v2 export envelope")?;
            if envelope.archive_type != ARCHIVE_TYPE {
                anyhow::bail!("Unsupported archive type: {}", envelope.archive_type);
            }
            match envelope.protection {
                ArchiveProtection::RsaOaepSha256 {
                    public_key_fingerprint,
                    archive_cipher,
                    encrypted_data_key_b64,
                    encrypted_archive_b64,
                } => {
                    if archive_cipher != ARCHIVE_CIPHER {
                        anyhow::bail!("Unsupported archive cipher: {archive_cipher}");
                    }
                    let private_key = load_private_key(private_key_path)?;
                    let local_fingerprint = private_key.public_key().fingerprint()?;
                    if local_fingerprint != public_key_fingerprint {
                        anyhow::bail!(
                            "Wrong private key for this archive.\n  Archive was encrypted for: {public_key_fingerprint}\n  {} is: {local_fingerprint}\nPass the private key that was used for the export with --private-key <path>",
                            private_key_path.display()
                        );
                    }
                    output.print_info(&format!(
                        "Decrypting archive with private key: {} ({local_fingerprint})",
                        private_key_path.display()
                    ));
                    decrypt_with_private_key(
                        &private_key,
                        &encrypted_data_key_b64,
                        &encrypted_archive_b64,
                    )
                }
                ArchiveProtection::Passphrase { sealed } => {
                    output.print_info("Archive is passphrase-protected");
                    passphrase::open(&read_passphrase()?, &sealed, ARCHIVE_PASSPHRASE_CONTEXT)
                }
            }
        }
        other => anyhow::bail!("Unsupported export envelope version: {other}"),
    }
}

fn decrypt_with_private_key(
    private_key: &PrivateMasterKey,
    encrypted_data_key_b64: &str,
    encrypted_archive_b64: &str,
) -> Result<Vec<u8>> {
    let encrypted_data_key = BASE64
        .decode(encrypted_data_key_b64)
        .context("Invalid archive data key encoding")?;
    let encrypted_archive = BASE64
        .decode(encrypted_archive_b64)
        .context("Invalid encrypted archive encoding")?;

    let data_key_bytes = private_key
        .decrypt(&encrypted_data_key)
        .context("Failed to decrypt archive data key")?;
    let data_key =
        DataKey::from_bytes(&data_key_bytes).context("Invalid archive data key length")?;

    data_key
        .decrypt(&encrypted_archive)
        .context("Failed to decrypt archive")
}

fn validate_envelope_v1(envelope: &EncryptedExportEnvelopeV1) -> Result<()> {
    if envelope.envelope_version != LEGACY_ENVELOPE_VERSION {
        anyhow::bail!(
            "Unsupported export envelope version: {}",
            envelope.envelope_version
        );
    }
    if envelope.archive_type != ARCHIVE_TYPE {
        anyhow::bail!("Unsupported archive type: {}", envelope.archive_type);
    }
    if envelope.archive_cipher != ARCHIVE_CIPHER {
        anyhow::bail!("Unsupported archive cipher: {}", envelope.archive_cipher);
    }
    if envelope.key_cipher != KEY_CIPHER {
        anyhow::bail!("Unsupported archive key cipher: {}", envelope.key_cipher);
    }
    Ok(())
}

fn build_archive_tar<M: Serialize, R: Serialize>(manifest: &M, records: &[R]) -> Result<Vec<u8>> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        append_json_file(&mut builder, MANIFEST_PATH, manifest)?;
        append_json_file(&mut builder, SECRETS_PATH, records)?;
        builder.finish().context("Failed to finish tar archive")?;
    }
    Ok(tar_bytes)
}

fn append_json_file<T: Serialize + ?Sized>(
    builder: &mut tar::Builder<&mut Vec<u8>>,
    path: &str,
    value: &T,
) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    builder
        .append_data(&mut header, path, Cursor::new(bytes))
        .with_context(|| format!("Failed to append {path} to tar archive"))?;
    Ok(())
}

fn read_archive_tar(tar_bytes: &[u8]) -> Result<Vec<ExportSecretRecordV2>> {
    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    let mut manifest_bytes = None;
    let mut secrets_bytes = None;

    for entry in archive.entries().context("Failed to read tar archive")? {
        let mut entry = entry.context("Failed to read tar entry")?;
        let path = entry
            .path()
            .context("Failed to read tar entry path")?
            .to_string_lossy()
            .into_owned();

        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .with_context(|| format!("Failed to read tar entry {path}"))?;

        match path.as_str() {
            MANIFEST_PATH => {
                if manifest_bytes.replace(bytes).is_some() {
                    anyhow::bail!("Encrypted archive contains duplicate {MANIFEST_PATH}");
                }
            }
            SECRETS_PATH => {
                if secrets_bytes.replace(bytes).is_some() {
                    anyhow::bail!("Encrypted archive contains duplicate {SECRETS_PATH}");
                }
            }
            _ => anyhow::bail!("Unexpected file in encrypted archive: {path}"),
        }
    }

    parse_archive_files(
        &manifest_bytes.context("Encrypted archive is missing manifest.json")?,
        &secrets_bytes.context("Encrypted archive is missing secrets.json")?,
    )
}

/// Parse archive contents of any supported format version into v2 records.
fn parse_archive_files(
    manifest_bytes: &[u8],
    secrets_bytes: &[u8],
) -> Result<Vec<ExportSecretRecordV2>> {
    let manifest_value: Value =
        serde_json::from_slice(manifest_bytes).context("Failed to parse archive manifest")?;
    let format_version = manifest_value
        .get("format_version")
        .and_then(Value::as_u64)
        .context("Archive manifest is missing format_version")?;

    let (secret_count, records) = match format_version {
        1 => {
            let manifest: ExportManifestV1 = serde_json::from_value(manifest_value)
                .context("Failed to parse v1 archive manifest")?;
            let records: Vec<ExportSecretRecordV1> =
                serde_json::from_slice(secrets_bytes).context("Failed to parse v1 secrets")?;
            (
                manifest.secret_count,
                records.into_iter().map(Into::into).collect::<Vec<_>>(),
            )
        }
        2 => {
            let manifest: ExportManifestV2 = serde_json::from_value(manifest_value)
                .context("Failed to parse v2 archive manifest")?;
            let records: Vec<ExportSecretRecordV2> =
                serde_json::from_slice(secrets_bytes).context("Failed to parse v2 secrets")?;
            (manifest.secret_count, records)
        }
        other => anyhow::bail!("Unsupported export archive format version: {other}"),
    };

    if secret_count != records.len() {
        anyhow::bail!(
            "Archive manifest secret_count {} does not match secrets.json count {}",
            secret_count,
            records.len()
        );
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{commands::passphrase::TEST_KDF_COST, config::OutputFormat};
    use sealbox_server::crypto::master_key::generate_key_pair;
    use tempfile::TempDir;

    const PASSPHRASE: &str = "correct horse battery staple";

    struct TestKeys {
        _temp_dir: TempDir,
        public_key: PublicMasterKey,
        public_key_path: PathBuf,
        private_key_path: PathBuf,
    }

    fn test_keys() -> TestKeys {
        let temp_dir = TempDir::new().unwrap();
        let public_key_path = temp_dir.path().join("public.pem");
        let private_key_path = temp_dir.path().join("private.pem");
        let (private_pem, public_pem) = generate_key_pair().unwrap();
        fs::write(&public_key_path, &public_pem).unwrap();
        fs::write(&private_key_path, private_pem).unwrap();
        TestKeys {
            _temp_dir: temp_dir,
            public_key: PublicMasterKey::from_str(&public_pem).unwrap(),
            public_key_path,
            private_key_path,
        }
    }

    fn output() -> OutputManager {
        OutputManager::new(OutputFormat::Json)
    }

    fn no_passphrase() -> Result<String> {
        panic!("RSA archives must not prompt for a passphrase")
    }

    fn test_records() -> Vec<ExportSecretRecordV2> {
        vec![
            ExportSecretRecordV2 {
                key: "db/password".to_string(),
                version: 3,
                value_b64: BASE64.encode("secret-value"),
                created_at: Some(1_700_000_000),
                expires_at: Some(4_102_444_800),
                metadata: Some(r#"{"type":"credential","username":"app"}"#.to_string()),
            },
            ExportSecretRecordV2 {
                key: "files/logo".to_string(),
                version: 1,
                value_b64: BASE64.encode([0u8, 159, 146, 150, 255]),
                created_at: Some(1_700_000_100),
                expires_at: None,
                metadata: Some(r#"{"type":"file","filename":"logo.png"}"#.to_string()),
            },
        ]
    }

    fn test_manifest(records: &[ExportSecretRecordV2]) -> ExportManifestV2 {
        ExportManifestV2 {
            format_version: ARCHIVE_FORMAT_VERSION,
            application: "sealbox-cli".to_string(),
            exported_at: 1_700_000_000,
            secret_count: records.len(),
            key_count: records.len(),
            all_versions: true,
        }
    }

    fn envelope_bytes(envelope: &impl Serialize) -> Vec<u8> {
        serde_json::to_vec(envelope).unwrap()
    }

    #[test]
    fn test_rsa_archive_roundtrip_preserves_binary_values() {
        let keys = test_keys();
        let records = test_records();
        let tar_bytes = build_archive_tar(&test_manifest(&records), &records).unwrap();

        let envelope = encrypt_archive_for_key(&keys.public_key, &tar_bytes).unwrap();
        let decrypted = decrypt_archive(
            &envelope_bytes(&envelope),
            &keys.private_key_path,
            &output(),
            no_passphrase,
        )
        .unwrap();

        assert_eq!(read_archive_tar(&decrypted).unwrap(), records);
    }

    #[test]
    fn test_rsa_archive_rejects_other_private_key_with_fingerprints() {
        let export_keys = test_keys();
        let other_keys = test_keys();
        let records = test_records();
        let tar_bytes = build_archive_tar(&test_manifest(&records), &records).unwrap();
        let envelope = encrypt_archive_for_key(&export_keys.public_key, &tar_bytes).unwrap();

        let error = decrypt_archive(
            &envelope_bytes(&envelope),
            &other_keys.private_key_path,
            &output(),
            no_passphrase,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("Wrong private key"));
        assert!(error.contains(&export_keys.public_key.fingerprint().unwrap()));
        assert!(error.contains("--private-key"));
    }

    #[test]
    fn test_rsa_archive_missing_private_key_mentions_flag() {
        let keys = test_keys();
        let records = test_records();
        let tar_bytes = build_archive_tar(&test_manifest(&records), &records).unwrap();
        let envelope = encrypt_archive_for_key(&keys.public_key, &tar_bytes).unwrap();

        let error = decrypt_archive(
            &envelope_bytes(&envelope),
            Path::new("/nonexistent/private.pem"),
            &output(),
            no_passphrase,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("--private-key"));
    }

    #[test]
    fn test_passphrase_archive_roundtrip_needs_no_private_key() {
        let records = test_records();
        let tar_bytes = build_archive_tar(&test_manifest(&records), &records).unwrap();

        let envelope =
            encrypt_archive_with_passphrase(PASSPHRASE, &tar_bytes, TEST_KDF_COST).unwrap();
        let decrypted = decrypt_archive(
            &envelope_bytes(&envelope),
            Path::new("/nonexistent/private.pem"),
            &output(),
            || Ok(PASSPHRASE.to_string()),
        )
        .unwrap();

        assert_eq!(read_archive_tar(&decrypted).unwrap(), records);
    }

    #[test]
    fn test_passphrase_archive_rejects_wrong_passphrase() {
        let records = test_records();
        let tar_bytes = build_archive_tar(&test_manifest(&records), &records).unwrap();
        let envelope =
            encrypt_archive_with_passphrase(PASSPHRASE, &tar_bytes, TEST_KDF_COST).unwrap();

        let result = decrypt_archive(
            &envelope_bytes(&envelope),
            Path::new("/nonexistent/private.pem"),
            &output(),
            || Ok("wrong passphrase".to_string()),
        );

        assert!(result.is_err());
    }

    /// Archives written before this change must still import.
    #[test]
    fn test_legacy_v1_archive_still_decrypts_and_migrates() {
        let keys = test_keys();
        let legacy_records = vec![ExportSecretRecordV1 {
            key: "db/password".to_string(),
            value: "secret-value".to_string(),
            version: 3,
            expires_at: None,
            metadata: None,
        }];
        let manifest = ExportManifestV1 {
            format_version: 1,
            application: "sealbox-cli".to_string(),
            exported_at: 1_700_000_000,
            secret_count: 1,
        };
        let tar_bytes = build_archive_tar(&manifest, &legacy_records).unwrap();
        let data_key = DataKey::new();
        let envelope = EncryptedExportEnvelopeV1 {
            envelope_version: LEGACY_ENVELOPE_VERSION,
            archive_type: ARCHIVE_TYPE.to_string(),
            archive_cipher: ARCHIVE_CIPHER.to_string(),
            key_cipher: KEY_CIPHER.to_string(),
            encrypted_data_key_b64: BASE64
                .encode(keys.public_key.encrypt(data_key.as_bytes()).unwrap()),
            encrypted_archive_b64: BASE64.encode(data_key.encrypt(&tar_bytes).unwrap()),
        };

        let decrypted = decrypt_archive(
            &envelope_bytes(&envelope),
            &keys.private_key_path,
            &output(),
            no_passphrase,
        )
        .unwrap();
        let records = read_archive_tar(&decrypted).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].key, "db/password");
        assert_eq!(records[0].version, 3);
        assert_eq!(
            BASE64.decode(&records[0].value_b64).unwrap(),
            b"secret-value"
        );
    }

    #[test]
    fn test_validate_archive_format_rejects_plaintext_formats() {
        let result = validate_archive_format("json");

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported archive format")
        );
    }

    #[test]
    fn test_parse_archive_rejects_unsupported_version() {
        let manifest = json!({
            "format_version": 999,
            "application": "sealbox-cli",
            "exported_at": 1,
            "secret_count": 0
        });
        let records: Vec<ExportSecretRecordV2> = Vec::new();

        let result = parse_archive_files(
            &serde_json::to_vec(&manifest).unwrap(),
            &serde_json::to_vec(&records).unwrap(),
        );

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported export archive format version")
        );
    }

    #[test]
    fn test_decrypt_rejects_unsupported_envelope_version() {
        let envelope = json!({ "envelope_version": 999, "archive_type": ARCHIVE_TYPE });

        let result = decrypt_archive(
            &serde_json::to_vec(&envelope).unwrap(),
            Path::new("/nonexistent/private.pem"),
            &output(),
            no_passphrase,
        );

        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported export envelope version")
        );
    }

    #[test]
    fn test_parse_archive_validates_secret_count() {
        let records = test_records();
        let mut manifest = test_manifest(&records);
        manifest.secret_count = 5;

        let result = parse_archive_files(
            &serde_json::to_vec(&manifest).unwrap(),
            &serde_json::to_vec(&records).unwrap(),
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("secret_count"));
    }

    #[tokio::test]
    async fn test_export_refuses_existing_file_without_force() {
        let keys = test_keys();
        let temp_dir = TempDir::new().unwrap();
        let archive = temp_dir.path().join("backup.json");
        fs::write(&archive, "existing").unwrap();
        let mut config = Config::default();
        config.server.token = "test-token".to_string();
        config.keys.public_key_path = keys.public_key_path.clone();

        let result = export_secrets(
            &config,
            &output(),
            ExportOptions {
                file: archive.display().to_string(),
                keys_pattern: None,
                format: "encrypted-tar".to_string(),
                all_versions: false,
                passphrase: false,
                passphrase_file: None,
                force: false,
            },
        )
        .await;

        assert!(result.unwrap_err().to_string().contains("--force"));
        assert_eq!(fs::read_to_string(&archive).unwrap(), "existing");
    }
}
