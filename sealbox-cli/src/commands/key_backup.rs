//! Passphrase-protected backup of the local RSA key pair.
//!
//! The server only ever sees public keys, so the private key file is the one
//! thing that cannot be recovered from a server backup. A key bundle is
//! encrypted with a passphrase rather than with the key it contains, so it
//! stays usable after the original key files are gone.

use std::{fs, path::PathBuf, str::FromStr};

use anyhow::{Context, Result};
use sealbox_server::crypto::master_key::{PrivateMasterKey, PublicMasterKey};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{config::Config, output::OutputManager};

use super::{
    passphrase::{self, DEFAULT_KDF_COST, KdfCost, PassphraseSealed},
    private_file::write_private_file,
};

const BUNDLE_TYPE: &str = "sealbox.key-bundle";
const BUNDLE_VERSION: u32 = 1;
const BUNDLE_CONTEXT: &str = "sealbox.key-bundle.v1";

/// On-disk bundle. The fingerprint is public information kept in the clear so
/// a bundle can be matched to a server key without the passphrase; it is
/// re-checked against the decrypted key on import.
#[derive(Debug, Serialize, Deserialize)]
struct KeyBundleFileV1 {
    bundle_type: String,
    bundle_version: u32,
    public_key_fingerprint: String,
    exported_at: i64,
    sealed: PassphraseSealed,
}

#[derive(Serialize, Deserialize)]
struct KeyBundlePayloadV1 {
    private_key_pem: String,
    public_key_pem: String,
}

struct KeyPair {
    private_key_pem: String,
    public_key_pem: String,
    fingerprint: String,
}

/// Parse a private key PEM and derive its public key and fingerprint.
fn key_pair_from_private_pem(private_key_pem: String) -> Result<KeyPair> {
    let private_key =
        PrivateMasterKey::from_str(&private_key_pem).context("Failed to parse private key")?;
    let public_key = private_key.public_key();
    Ok(KeyPair {
        private_key_pem,
        public_key_pem: public_key.to_pem().context("Failed to encode public key")?,
        fingerprint: public_key
            .fingerprint()
            .context("Failed to fingerprint public key")?,
    })
}

pub async fn export_keys(
    config: &Config,
    output: &OutputManager,
    file: String,
    passphrase_file: Option<String>,
    force: bool,
) -> Result<()> {
    let private_key_path = &config.keys.private_key_path;
    let private_key_pem = fs::read_to_string(private_key_path).with_context(|| {
        format!(
            "Failed to read private key file: {}",
            private_key_path.display()
        )
    })?;
    let key_pair = key_pair_from_private_pem(private_key_pem)?;

    // The bundle always carries the public key derived from the private key.
    // A configured public key that disagrees means the local setup is broken,
    // and silently backing up a mismatched pair would hide that.
    if let Ok(public_key_pem) = fs::read_to_string(&config.keys.public_key_path) {
        let configured = PublicMasterKey::from_str(&public_key_pem)
            .context("Failed to parse configured public key")?
            .fingerprint()?;
        if configured != key_pair.fingerprint {
            anyhow::bail!(
                "Public key {} does not belong to private key {} ({} vs {})",
                config.keys.public_key_path.display(),
                private_key_path.display(),
                configured,
                key_pair.fingerprint
            );
        }
    }

    let passphrase = passphrase::read_passphrase(output, passphrase_file.as_deref(), true)?;
    output.print_info("Encrypting key pair with passphrase...");
    let bundle = seal_bundle(&key_pair, &passphrase, DEFAULT_KDF_COST)?;
    write_private_file(
        &PathBuf::from(&file),
        &serde_json::to_vec_pretty(&bundle)?,
        force,
    )?;

    output.print_success(&format!("Key pair exported to: {file}"));
    output.print_warning(
        "Store this file and its passphrase separately. Anyone holding both can decrypt every secret.",
    );
    output.print_value(&json!({
        "file": file,
        "bundle_type": BUNDLE_TYPE,
        "bundle_version": BUNDLE_VERSION,
        "public_key_fingerprint": key_pair.fingerprint,
    }))?;
    Ok(())
}

pub async fn import_keys(
    config: &Config,
    output: &OutputManager,
    file: String,
    passphrase_file: Option<String>,
    public_key_path: Option<String>,
    private_key_path: Option<String>,
    force: bool,
) -> Result<()> {
    let bundle_bytes =
        fs::read(&file).with_context(|| format!("Failed to read key bundle: {file}"))?;
    let bundle: KeyBundleFileV1 =
        serde_json::from_slice(&bundle_bytes).context("Failed to parse key bundle")?;
    validate_bundle_header(&bundle)?;

    let passphrase = passphrase::read_passphrase(output, passphrase_file.as_deref(), false)?;
    output.print_info("Decrypting key bundle...");
    let key_pair = open_bundle(&bundle, &passphrase)?;

    let private_path = private_key_path
        .map(PathBuf::from)
        .unwrap_or_else(|| config.keys.private_key_path.clone());
    let public_path = public_key_path
        .map(PathBuf::from)
        .unwrap_or_else(|| config.keys.public_key_path.clone());

    // Check both targets before writing either, so a refusal never leaves a
    // half-restored pair behind.
    if !force {
        for path in [&private_path, &public_path] {
            if path.exists() {
                anyhow::bail!(
                    "Key file already exists: {} (use --force to replace it, or --private-key-path/--public-key-path to restore elsewhere)",
                    path.display()
                );
            }
        }
    }
    write_private_file(&private_path, key_pair.private_key_pem.as_bytes(), force)?;
    write_private_file(&public_path, key_pair.public_key_pem.as_bytes(), force)?;

    output.print_success("Key pair restored from bundle!");
    output.print_info(&format!("Private key: {}", private_path.display()));
    output.print_info(&format!("Public key: {}", public_path.display()));
    if private_path != config.keys.private_key_path || public_path != config.keys.public_key_path {
        output.print_info(
            "Restored to non-configured paths; pass --private-key/--public-key or run 'sealbox-cli config set' to use them.",
        );
    }
    output.print_value(&json!({
        "private_key_path": private_path,
        "public_key_path": public_path,
        "public_key_fingerprint": key_pair.fingerprint,
    }))?;
    Ok(())
}

fn seal_bundle(key_pair: &KeyPair, passphrase: &str, cost: KdfCost) -> Result<KeyBundleFileV1> {
    let payload = serde_json::to_vec(&KeyBundlePayloadV1 {
        private_key_pem: key_pair.private_key_pem.clone(),
        public_key_pem: key_pair.public_key_pem.clone(),
    })?;
    Ok(KeyBundleFileV1 {
        bundle_type: BUNDLE_TYPE.to_string(),
        bundle_version: BUNDLE_VERSION,
        public_key_fingerprint: key_pair.fingerprint.clone(),
        exported_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        sealed: passphrase::seal(passphrase, &payload, BUNDLE_CONTEXT, cost)?,
    })
}

fn validate_bundle_header(bundle: &KeyBundleFileV1) -> Result<()> {
    if bundle.bundle_type != BUNDLE_TYPE {
        anyhow::bail!("Not a Sealbox key bundle (type: {})", bundle.bundle_type);
    }
    if bundle.bundle_version != BUNDLE_VERSION {
        anyhow::bail!("Unsupported key bundle version: {}", bundle.bundle_version);
    }
    Ok(())
}

fn open_bundle(bundle: &KeyBundleFileV1, passphrase: &str) -> Result<KeyPair> {
    let payload_bytes = passphrase::open(passphrase, &bundle.sealed, BUNDLE_CONTEXT)?;
    let payload: KeyBundlePayloadV1 =
        serde_json::from_slice(&payload_bytes).context("Failed to parse key bundle contents")?;

    // Re-derive rather than trusting the stored public key, and check it
    // against both the stored copy and the cleartext header.
    let key_pair = key_pair_from_private_pem(payload.private_key_pem)?;
    let stored_public = PublicMasterKey::from_str(&payload.public_key_pem)
        .context("Failed to parse public key in bundle")?
        .fingerprint()?;
    if stored_public != key_pair.fingerprint
        || bundle.public_key_fingerprint != key_pair.fingerprint
    {
        anyhow::bail!("Key bundle is inconsistent: public key does not match private key");
    }
    Ok(key_pair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::passphrase::TEST_KDF_COST;
    use sealbox_server::crypto::master_key::generate_key_pair;

    const PASSPHRASE: &str = "correct horse battery staple";

    fn test_key_pair() -> KeyPair {
        let (private_pem, _) = generate_key_pair().unwrap();
        key_pair_from_private_pem(private_pem).unwrap()
    }

    #[test]
    fn test_bundle_roundtrip_restores_both_keys() {
        let key_pair = test_key_pair();
        let bundle = seal_bundle(&key_pair, PASSPHRASE, TEST_KDF_COST).unwrap();
        let bytes = serde_json::to_vec(&bundle).unwrap();

        let parsed: KeyBundleFileV1 = serde_json::from_slice(&bytes).unwrap();
        validate_bundle_header(&parsed).unwrap();
        let restored = open_bundle(&parsed, PASSPHRASE).unwrap();

        assert_eq!(restored.private_key_pem, key_pair.private_key_pem);
        assert_eq!(restored.public_key_pem, key_pair.public_key_pem);
        assert_eq!(parsed.public_key_fingerprint, key_pair.fingerprint);
    }

    #[test]
    fn test_bundle_does_not_contain_plaintext_key() {
        let key_pair = test_key_pair();
        let bundle = seal_bundle(&key_pair, PASSPHRASE, TEST_KDF_COST).unwrap();

        let text = serde_json::to_string(&bundle).unwrap();

        assert!(!text.contains("PRIVATE KEY"));
    }

    #[test]
    fn test_bundle_rejects_wrong_passphrase() {
        let bundle = seal_bundle(&test_key_pair(), PASSPHRASE, TEST_KDF_COST).unwrap();

        assert!(open_bundle(&bundle, "not the passphrase").is_err());
    }

    #[test]
    fn test_bundle_rejects_swapped_fingerprint_header() {
        let mut bundle = seal_bundle(&test_key_pair(), PASSPHRASE, TEST_KDF_COST).unwrap();
        bundle.public_key_fingerprint = test_key_pair().fingerprint;

        let error = open_bundle(&bundle, PASSPHRASE).err().unwrap().to_string();

        assert!(error.contains("inconsistent"));
    }

    #[tokio::test]
    async fn test_import_refuses_to_overwrite_existing_keys() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let key_pair = test_key_pair();
        let bundle = seal_bundle(&key_pair, PASSPHRASE, TEST_KDF_COST).unwrap();
        let bundle_path = temp_dir.path().join("keys.json");
        let passphrase_path = temp_dir.path().join("passphrase");
        fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
        fs::write(&passphrase_path, PASSPHRASE).unwrap();

        let mut config = Config::default();
        config.keys.private_key_path = temp_dir.path().join("private.pem");
        config.keys.public_key_path = temp_dir.path().join("public.pem");
        fs::write(&config.keys.private_key_path, "existing").unwrap();
        let output = OutputManager::new(crate::config::OutputFormat::Json);

        let refused = import_keys(
            &config,
            &output,
            bundle_path.display().to_string(),
            Some(passphrase_path.display().to_string()),
            None,
            None,
            false,
        )
        .await;
        assert!(refused.unwrap_err().to_string().contains("--force"));
        assert!(!config.keys.public_key_path.exists());

        import_keys(
            &config,
            &output,
            bundle_path.display().to_string(),
            Some(passphrase_path.display().to_string()),
            None,
            None,
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            fs::read_to_string(&config.keys.private_key_path).unwrap(),
            key_pair.private_key_pem
        );
        assert_eq!(
            fs::read_to_string(&config.keys.public_key_path).unwrap(),
            key_pair.public_key_pem
        );
    }
}
