//! Passphrase-based encryption for offline backups.
//!
//! Key bundles and passphrase-protected secret archives must stay readable
//! after the RSA private key is lost, so they derive an AES-256-GCM key from a
//! passphrase with Argon2id instead of wrapping a data key with RSA.

use std::{
    fs,
    io::{self, IsTerminal, Read},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, KeyInit, Payload},
};
use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::RngExt;
use serde::{Deserialize, Serialize};

use crate::output::OutputManager;

/// Environment variable read when no passphrase file is given, for automation.
pub const PASSPHRASE_ENV: &str = "SEALBOX_BACKUP_PASSPHRASE";

pub const MIN_PASSPHRASE_CHARS: usize = 12;

const KDF_ALGORITHM: &str = "argon2id";
const KDF_VERSION: u32 = 0x13;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Default cost for new backups: 64 MiB, 3 passes, 1 lane.
///
/// Backups are attackable offline, so this is deliberately heavier than
/// interactive login defaults.
pub const DEFAULT_KDF_COST: KdfCost = KdfCost {
    m_cost_kib: 64 * 1024,
    t_cost: 3,
    p_cost: 1,
};

// Upper bounds accepted when opening a file, so a crafted header cannot make
// the CLI allocate unbounded memory or spin for hours.
const MAX_M_COST_KIB: u32 = 1024 * 1024;
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfCost {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub algorithm: String,
    pub version: u32,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt_b64: String,
}

/// Passphrase-encrypted payload. `ciphertext_b64` is `nonce | ciphertext | tag`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PassphraseSealed {
    pub cipher: String,
    pub kdf: KdfParams,
    pub ciphertext_b64: String,
}

const CIPHER: &str = "AES-256-GCM";

impl KdfParams {
    fn new(cost: KdfCost) -> Self {
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill(&mut salt[..]);
        Self {
            algorithm: KDF_ALGORITHM.to_string(),
            version: KDF_VERSION,
            m_cost_kib: cost.m_cost_kib,
            t_cost: cost.t_cost,
            p_cost: cost.p_cost,
            salt_b64: BASE64.encode(salt),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.algorithm != KDF_ALGORITHM {
            anyhow::bail!("Unsupported key derivation function: {}", self.algorithm);
        }
        if self.version != KDF_VERSION {
            anyhow::bail!("Unsupported Argon2 version: {:#x}", self.version);
        }
        if self.m_cost_kib > MAX_M_COST_KIB || self.t_cost > MAX_T_COST || self.p_cost > MAX_P_COST
        {
            anyhow::bail!(
                "Refusing Argon2 parameters above the supported limits (m={} KiB, t={}, p={})",
                self.m_cost_kib,
                self.t_cost,
                self.p_cost
            );
        }
        Ok(())
    }

    fn derive_key(&self, passphrase: &str) -> Result<[u8; KEY_LEN]> {
        self.validate()?;
        let salt = BASE64
            .decode(&self.salt_b64)
            .context("Invalid key derivation salt encoding")?;
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|error| anyhow::anyhow!("Invalid Argon2 parameters: {error}"))?;
        let mut key = [0u8; KEY_LEN];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .map_err(|error| anyhow::anyhow!("Failed to derive key from passphrase: {error}"))?;
        Ok(key)
    }

    /// Bind the KDF parameters into the AEAD associated data so a tampered
    /// header fails authentication instead of silently deriving another key.
    fn associated_data(&self, context: &str) -> Vec<u8> {
        format!(
            "{context}|{}|{}|{}|{}|{}|{}",
            self.algorithm, self.version, self.m_cost_kib, self.t_cost, self.p_cost, self.salt_b64
        )
        .into_bytes()
    }
}

/// Encrypt `plaintext` under a key derived from `passphrase`.
///
/// `context` names the file type (for example `sealbox.key-bundle.v1`) and is
/// authenticated, so a payload cannot be replayed as a different file type.
pub fn seal(
    passphrase: &str,
    plaintext: &[u8],
    context: &str,
    cost: KdfCost,
) -> Result<PassphraseSealed> {
    let kdf = KdfParams::new(cost);
    let key = kdf.derive_key(passphrase)?;
    let cipher = Aes256Gcm::new_from_slice(&key).context("Invalid derived key length")?;
    let nonce = Nonce::generate();
    let aad = kdf.associated_data(context);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("Failed to encrypt with passphrase-derived key"))?;

    let mut sealed = nonce.to_vec();
    sealed.extend(ciphertext);
    Ok(PassphraseSealed {
        cipher: CIPHER.to_string(),
        kdf,
        ciphertext_b64: BASE64.encode(sealed),
    })
}

/// Decrypt a payload produced by [`seal`] with the same `context`.
pub fn open(passphrase: &str, sealed: &PassphraseSealed, context: &str) -> Result<Vec<u8>> {
    if sealed.cipher != CIPHER {
        anyhow::bail!("Unsupported passphrase cipher: {}", sealed.cipher);
    }
    let bytes = BASE64
        .decode(&sealed.ciphertext_b64)
        .context("Invalid passphrase ciphertext encoding")?;
    if bytes.len() < NONCE_LEN {
        anyhow::bail!("Passphrase ciphertext is truncated");
    }
    let (nonce_bytes, ciphertext) = bytes.split_at(NONCE_LEN);
    let nonce = Nonce::try_from(nonce_bytes).context("Invalid passphrase nonce")?;

    let key = sealed.kdf.derive_key(passphrase)?;
    let cipher = Aes256Gcm::new_from_slice(&key).context("Invalid derived key length")?;
    let aad = sealed.kdf.associated_data(context);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("Wrong passphrase, or the file has been modified"))
}

/// Resolve a backup passphrase from, in order: `passphrase_file`,
/// `SEALBOX_BACKUP_PASSPHRASE`, an interactive prompt, or piped stdin.
///
/// `confirm` asks twice on a terminal and enforces the minimum length; use it
/// when creating a backup, not when opening one.
pub fn read_passphrase(
    output: &OutputManager,
    passphrase_file: Option<&str>,
    confirm: bool,
) -> Result<String> {
    let passphrase = if let Some(path) = passphrase_file {
        let value = fs::read_to_string(path)
            .with_context(|| format!("Failed to read passphrase file: {path}"))?;
        trim_line_ending(value)
    } else if let Ok(value) = std::env::var(PASSPHRASE_ENV) {
        value
    } else if io::stdin().is_terminal() {
        output.print_info("Enter backup passphrase (input will be hidden):");
        let value = rpassword::read_password().context("Failed to read passphrase")?;
        if confirm {
            output.print_info("Confirm backup passphrase:");
            let repeated = rpassword::read_password().context("Failed to read passphrase")?;
            if repeated != value {
                anyhow::bail!("Passphrases do not match");
            }
        }
        value
    } else {
        let mut value = String::new();
        io::stdin()
            .read_to_string(&mut value)
            .context("Failed to read passphrase from stdin")?;
        trim_line_ending(value)
    };

    if passphrase.is_empty() {
        anyhow::bail!("Backup passphrase cannot be empty");
    }
    if confirm && passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        anyhow::bail!("Backup passphrase must be at least {MIN_PASSPHRASE_CHARS} characters");
    }
    Ok(passphrase)
}

fn trim_line_ending(value: String) -> String {
    value.trim_end_matches(['\r', '\n']).to_string()
}

#[cfg(test)]
pub(crate) const TEST_KDF_COST: KdfCost = KdfCost {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT: &str = "sealbox.test.v1";

    #[test]
    fn test_seal_open_roundtrip() {
        let sealed = seal("correct horse battery", b"payload", CONTEXT, TEST_KDF_COST).unwrap();

        let opened = open("correct horse battery", &sealed, CONTEXT).unwrap();

        assert_eq!(opened, b"payload");
    }

    #[test]
    fn test_open_rejects_wrong_passphrase() {
        let sealed = seal("correct horse battery", b"payload", CONTEXT, TEST_KDF_COST).unwrap();

        let result = open("wrong horse battery", &sealed, CONTEXT);

        assert!(result.unwrap_err().to_string().contains("Wrong passphrase"));
    }

    #[test]
    fn test_open_rejects_other_context() {
        let sealed = seal("correct horse battery", b"payload", CONTEXT, TEST_KDF_COST).unwrap();

        assert!(open("correct horse battery", &sealed, "sealbox.other.v1").is_err());
    }

    #[test]
    fn test_open_rejects_tampered_kdf_params() {
        let mut sealed = seal("correct horse battery", b"payload", CONTEXT, TEST_KDF_COST).unwrap();
        sealed.kdf.t_cost += 1;

        assert!(open("correct horse battery", &sealed, CONTEXT).is_err());
    }

    #[test]
    fn test_open_rejects_excessive_kdf_cost() {
        let mut sealed = seal("correct horse battery", b"payload", CONTEXT, TEST_KDF_COST).unwrap();
        sealed.kdf.m_cost_kib = MAX_M_COST_KIB + 1;

        let result = open("correct horse battery", &sealed, CONTEXT);

        assert!(result.unwrap_err().to_string().contains("supported limits"));
    }

    #[test]
    fn test_open_rejects_truncated_ciphertext() {
        let mut sealed = seal("correct horse battery", b"payload", CONTEXT, TEST_KDF_COST).unwrap();
        sealed.ciphertext_b64 = BASE64.encode([0u8; 4]);

        let result = open("correct horse battery", &sealed, CONTEXT);

        assert!(result.unwrap_err().to_string().contains("truncated"));
    }

    #[test]
    fn test_read_passphrase_from_file_trims_newline_and_enforces_length() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let output = OutputManager::new(crate::config::OutputFormat::Json);
        let good = temp_dir.path().join("good");
        let short = temp_dir.path().join("short");
        fs::write(&good, "a long enough passphrase\n").unwrap();
        fs::write(&short, "short\n").unwrap();

        let passphrase = read_passphrase(&output, good.to_str(), true).unwrap();
        let too_short = read_passphrase(&output, short.to_str(), true);
        let short_for_open = read_passphrase(&output, short.to_str(), false).unwrap();

        assert_eq!(passphrase, "a long enough passphrase");
        assert!(too_short.unwrap_err().to_string().contains("at least"));
        assert_eq!(short_for_open, "short");
    }
}
