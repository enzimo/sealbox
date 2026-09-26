mod commands;
mod config;
mod output;

use crate::commands::{
    admin_commands, config_commands, credential_commands, file_commands, key_commands,
    password_commands, secret_commands, tenant_commands,
};
use crate::config::{Config, LEGACY_V1_WARNING, OutputFormat, normalize_api_version};
use anyhow::Result;
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sealbox")]
#[command(author = "Sealbox Team")]
#[command(version)]
#[command(about = "Sealbox CLI - client-encrypted secret management tool")]
#[command(
    long_about = "Sealbox is a lightweight, single-node secret storage service where the CLI encrypts secrets locally using RSA key pairs."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Server URL
    #[arg(long, global = true)]
    url: Option<String>,

    /// Authentication token
    #[arg(long, global = true)]
    token: Option<String>,

    /// API version for secret/key operations: v2 (default) or the deprecated v1
    #[arg(long, global = true)]
    api_version: Option<String>,

    /// Public key file path
    #[arg(long, global = true)]
    public_key: Option<String>,

    /// Private key file path. For `secret import`, this is the key the archive
    /// was exported with, which may differ from the target server's key
    #[arg(long, global = true)]
    private_key: Option<String>,

    /// Output format
    #[arg(long, global = true, value_enum)]
    output: Option<OutputFormatArg>,
}

#[derive(clap::ValueEnum, Clone)]
enum OutputFormatArg {
    Json,
    Yaml,
    Table,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(arg: OutputFormatArg) -> Self {
        match arg {
            OutputFormatArg::Json => OutputFormat::Json,
            OutputFormatArg::Yaml => OutputFormat::Yaml,
            OutputFormatArg::Table => OutputFormat::Table,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Manage configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Manage keys
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },
    /// Manage secrets
    Secret {
        #[command(subcommand)]
        command: SecretCommands,
    },
    /// Manage username/password credentials
    Credential {
        #[command(subcommand)]
        command: CredentialCommands,
    },
    /// Store and retrieve small encrypted files (up to 500 KB)
    File {
        #[command(subcommand)]
        command: FileCommands,
    },
    /// Generate strong passwords
    Password {
        #[command(subcommand)]
        command: PasswordCommands,
    },
    /// Administer isolated tenants and tenant API tokens
    Tenant {
        #[command(subcommand)]
        command: TenantCommands,
    },
    /// Server-wide operator tasks (require the root token)
    Admin {
        #[command(subcommand)]
        command: AdminCommands,
    },
}

#[derive(Subcommand)]
enum AdminCommands {
    /// Download a consistent snapshot of the whole server database
    Backup {
        /// Destination file for the SQLite snapshot
        #[arg(long)]
        file: String,
        /// Overwrite the destination file if it already exists
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show,
    /// Set configuration value
    Set {
        /// Configuration key (e.g., server.url, server.token, keys.public_key_path)
        key: String,
        /// Configuration value
        value: String,
    },
    /// Initialize configuration
    Init {
        /// Server URL
        #[arg(long)]
        url: Option<String>,
        /// Authentication token
        #[arg(long)]
        token: Option<String>,
        /// Public key file path
        #[arg(long)]
        public_key: Option<String>,
        /// Private key file path
        #[arg(long)]
        private_key: Option<String>,
        /// Output format
        #[arg(long, value_enum)]
        output: Option<OutputFormatArg>,
        /// Force overwrite existing configuration
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Generate new key pair
    Generate {
        /// Public key file path
        #[arg(long)]
        public_key_path: Option<String>,
        /// Private key file path
        #[arg(long)]
        private_key_path: Option<String>,
        /// Overwrite existing key files
        #[arg(long)]
        force: bool,
    },
    /// Register public key to server
    Register,
    /// List master keys on server
    List,
    /// Rotate master key
    Rotate {
        /// New master key ID
        #[arg(long)]
        new_key_id: String,
        /// Old master key ID
        #[arg(long)]
        old_key_id: String,
    },
    /// Check key status
    Status,
    /// Back up the local key pair to a passphrase-encrypted bundle
    Export {
        /// Destination bundle file
        #[arg(long)]
        file: String,
        /// Read the passphrase from this file instead of prompting
        #[arg(long)]
        passphrase_file: Option<String>,
        /// Overwrite the destination file if it already exists
        #[arg(long)]
        force: bool,
    },
    /// Restore a key pair from a passphrase-encrypted bundle
    Import {
        /// Bundle file created by 'key export'
        #[arg(long)]
        file: String,
        /// Read the passphrase from this file instead of prompting
        #[arg(long)]
        passphrase_file: Option<String>,
        /// Where to write the public key (defaults to the configured path)
        #[arg(long)]
        public_key_path: Option<String>,
        /// Where to write the private key (defaults to the configured path)
        #[arg(long)]
        private_key_path: Option<String>,
        /// Overwrite existing key files
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum SecretCommands {
    /// Set secret
    Set {
        /// Secret key name
        key: String,
        /// Secret value (read from stdin if not provided)
        value: Option<String>,
        /// Time to live in seconds
        #[arg(long)]
        ttl: Option<i64>,
    },
    /// Get secret
    Get {
        /// Secret key name
        key: String,
        /// Specific version number
        #[arg(long)]
        version: Option<i32>,
    },
    /// Delete secret
    Delete {
        /// Secret key name
        key: String,
        /// Specific version number. If omitted, all versions are deleted.
        #[arg(long)]
        version: Option<i32>,
    },
    /// List all secret keys (requires server support)
    List,
    /// View secret version history
    History {
        /// Secret key name
        key: String,
    },
    /// Import secrets from an encrypted Sealbox archive
    ///
    /// Key-protected archives are decrypted with the private key they were
    /// exported for; pass it with --private-key if it is not the configured
    /// key. Imported secrets are re-encrypted to the server's active key.
    Import {
        /// Encrypted archive file path
        file: String,
        /// File format
        #[arg(long, default_value = "encrypted-tar")]
        format: String,
        /// For passphrase-protected archives: read the passphrase from this file
        #[arg(long)]
        passphrase_file: Option<String>,
    },
    /// Export secrets to an encrypted Sealbox archive
    Export {
        /// Encrypted archive file path
        file: String,
        /// Key substring filter
        #[arg(long)]
        keys: Option<String>,
        /// File format
        #[arg(long, default_value = "encrypted-tar")]
        format: String,
        /// Include every retained version, not just the latest
        #[arg(long)]
        all_versions: bool,
        /// Protect the archive with a passphrase instead of the public key,
        /// so it can be restored without the private key
        #[arg(long)]
        passphrase: bool,
        /// Read the passphrase from this file (implies --passphrase)
        #[arg(long)]
        passphrase_file: Option<String>,
        /// Overwrite the archive file if it already exists
        #[arg(long)]
        force: bool,
    },
}

#[derive(Args, Clone, Debug)]
struct PasswordPolicyArgs {
    /// Password length (default: 24)
    #[arg(long)]
    length: Option<usize>,
    /// Generate only ASCII letters and digits
    #[arg(long)]
    alphanumeric: bool,
    /// Exclude symbol characters
    #[arg(long)]
    no_symbols: bool,
    /// Exclude number characters
    #[arg(long)]
    no_numbers: bool,
    /// Exclude uppercase letters
    #[arg(long)]
    no_uppercase: bool,
    /// Exclude lowercase letters
    #[arg(long)]
    no_lowercase: bool,
    /// Exclude ambiguous characters such as O, 0, I, l, and 1
    #[arg(long)]
    exclude_ambiguous: bool,
}

#[derive(Subcommand)]
enum PasswordCommands {
    /// Generate a strong password locally
    Generate {
        /// Number of passwords to generate
        #[arg(long, default_value_t = 1)]
        count: usize,
        #[command(flatten)]
        policy: PasswordPolicyArgs,
    },
}

#[derive(Subcommand)]
enum CredentialCommands {
    /// Store a username/password credential
    Set {
        /// Credential key name
        key: String,
        /// Username stored as searchable plaintext metadata and encrypted value data
        #[arg(long)]
        username: String,
        /// Time to live in seconds
        #[arg(long)]
        ttl: Option<i64>,
        /// Generate a strong password locally instead of prompting or reading stdin
        #[arg(long)]
        generate_password: bool,
        /// Print the generated password after it is saved
        #[arg(long)]
        show_password: bool,
        #[command(flatten)]
        password_policy: PasswordPolicyArgs,
    },
    /// Retrieve and decrypt a credential
    Get {
        /// Credential key name
        key: String,
        /// Specific version number
        #[arg(long)]
        version: Option<i32>,
    },
    /// List credentials using plaintext metadata
    List {
        /// Filter by credential name/key substring
        #[arg(long, visible_alias = "key")]
        name: Option<String>,
        /// Filter by username substring
        #[arg(long)]
        username: Option<String>,
        /// Filter by credential name/key or username substring
        #[arg(long)]
        query: Option<String>,
    },
    /// View credential version history
    History {
        /// Credential key name
        key: String,
    },
    /// Delete a credential and all stored versions
    Delete {
        /// Credential key name
        key: String,
    },
}

#[derive(Subcommand)]
enum FileCommands {
    /// Store an encrypted file from disk
    Set {
        /// File key name used to address the stored file
        key: String,
        /// Path to the file to encrypt and upload
        #[arg(long)]
        file: String,
        /// Time to live in seconds
        #[arg(long)]
        ttl: Option<i64>,
        /// Optional content type recorded in plaintext metadata
        #[arg(long)]
        content_type: Option<String>,
    },
    /// Retrieve, decrypt, and write a stored file to disk
    Get {
        /// File key name
        key: String,
        /// Destination path (defaults to the stored file name)
        #[arg(long)]
        file: Option<String>,
        /// Specific version number
        #[arg(long)]
        version: Option<i32>,
        /// Overwrite the destination file if it already exists
        #[arg(long)]
        force: bool,
    },
    /// List stored files using plaintext metadata
    List {
        /// Filter by file key substring
        #[arg(long, visible_alias = "key")]
        name: Option<String>,
        /// Filter by file key or stored file name substring
        #[arg(long)]
        query: Option<String>,
    },
    /// Delete a stored file and all its versions
    Delete {
        /// File key name
        key: String,
    },
}

#[derive(Subcommand)]
enum TenantCommands {
    /// Create a tenant and write its initial API token to a private file
    Create {
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        token_label: Option<String>,
        #[arg(long)]
        token_expires_at: Option<i64>,
        #[arg(long)]
        token_file: String,
    },
    /// List tenant metadata
    List,
    /// Get one tenant
    Get { tenant_id: String },
    /// Suspend tenant data-token authentication
    Suspend { tenant_id: String },
    /// Resume tenant data-token authentication
    Resume { tenant_id: String },
    /// Manage tenant API tokens
    Token {
        #[command(subcommand)]
        command: TenantTokenCommands,
    },
}

#[derive(Subcommand)]
enum TenantTokenCommands {
    /// Create a tenant token and write it to a private file
    Create {
        tenant_id: String,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        expires_at: Option<i64>,
        #[arg(long)]
        token_file: String,
    },
    /// List non-secret token metadata for a tenant
    List { tenant_id: String },
    /// Revoke a tenant token
    Revoke { tenant_id: String, token_id: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load configuration
    let mut config = Config::load()?;

    // Command line arguments override configuration
    if let Some(url) = cli.url {
        config.server.url = url;
    }
    if let Some(token) = cli.token {
        config.server.token = token;
    }
    if let Some(api_version) = cli.api_version {
        config.server.api_version = normalize_api_version(&api_version)?;
    }
    if let Some(public_key) = cli.public_key {
        config.keys.public_key_path = public_key.into();
    }
    if let Some(private_key) = cli.private_key {
        config.keys.private_key_path = private_key.into();
    }
    if let Some(output) = cli.output {
        config.output.format = output.into();
    }

    // Only data commands go through `api_version`; admin/tenant always use v2.
    let uses_data_api = matches!(
        cli.command,
        Commands::Key { .. }
            | Commands::Secret { .. }
            | Commands::Credential { .. }
            | Commands::File { .. }
    );
    if uses_data_api && config.server.api_version == "v1" {
        eprintln!("⚠️  {LEGACY_V1_WARNING}");
    }

    // Execute command
    match cli.command {
        Commands::Config { command } => config_commands::handle_command(command, &mut config).await,
        Commands::Key { command } => key_commands::handle_command(command, &config).await,
        Commands::Secret { command } => secret_commands::handle_command(command, &config).await,
        Commands::Credential { command } => {
            credential_commands::handle_command(command, &config).await
        }
        Commands::File { command } => file_commands::handle_command(command, &config).await,
        Commands::Password { command } => password_commands::handle_command(command, &config).await,
        Commands::Tenant { command } => tenant_commands::handle_command(command, &config).await,
        Commands::Admin { command } => admin_commands::handle_command(command, &config).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_password_generate_alphanumeric() {
        let cli = Cli::try_parse_from([
            "sealbox",
            "password",
            "generate",
            "--alphanumeric",
            "--length",
            "40",
        ])
        .unwrap();

        match cli.command {
            Commands::Password {
                command:
                    PasswordCommands::Generate {
                        count,
                        policy:
                            PasswordPolicyArgs {
                                length,
                                alphanumeric,
                                ..
                            },
                    },
            } => {
                assert_eq!(count, 1);
                assert_eq!(length, Some(40));
                assert!(alphanumeric);
            }
            _ => panic!("Expected password generate command"),
        }
    }

    #[test]
    fn test_parse_credential_set_generate_password() {
        let cli = Cli::try_parse_from([
            "sealbox",
            "credential",
            "set",
            "db/postgres",
            "--username",
            "app_user",
            "--generate-password",
            "--alphanumeric",
            "--show-password",
        ])
        .unwrap();

        match cli.command {
            Commands::Credential {
                command:
                    CredentialCommands::Set {
                        key,
                        username,
                        generate_password,
                        show_password,
                        password_policy,
                        ..
                    },
            } => {
                assert_eq!(key, "db/postgres");
                assert_eq!(username, "app_user");
                assert!(generate_password);
                assert!(show_password);
                assert!(password_policy.alphanumeric);
            }
            _ => panic!("Expected credential set command"),
        }
    }

    #[test]
    fn test_parse_credential_list_search_filters() {
        let cli = Cli::try_parse_from([
            "sealbox",
            "credential",
            "list",
            "--name",
            "db/",
            "--username",
            "app",
            "--query",
            "prod",
        ])
        .unwrap();

        match cli.command {
            Commands::Credential {
                command:
                    CredentialCommands::List {
                        name,
                        username,
                        query,
                    },
            } => {
                assert_eq!(name.as_deref(), Some("db/"));
                assert_eq!(username.as_deref(), Some("app"));
                assert_eq!(query.as_deref(), Some("prod"));
            }
            _ => panic!("Expected credential list command"),
        }
    }

    #[test]
    fn test_parse_secret_delete_without_version() {
        let cli = Cli::try_parse_from(["sealbox", "secret", "delete", "db/postgres"]).unwrap();

        match cli.command {
            Commands::Secret {
                command: SecretCommands::Delete { key, version },
            } => {
                assert_eq!(key, "db/postgres");
                assert_eq!(version, None);
            }
            _ => panic!("Expected secret delete command"),
        }
    }

    #[test]
    fn test_parse_secret_delete_with_version() {
        let cli = Cli::try_parse_from([
            "sealbox",
            "secret",
            "delete",
            "db/postgres",
            "--version",
            "2",
        ])
        .unwrap();

        match cli.command {
            Commands::Secret {
                command: SecretCommands::Delete { key, version },
            } => {
                assert_eq!(key, "db/postgres");
                assert_eq!(version, Some(2));
            }
            _ => panic!("Expected secret delete command"),
        }
    }

    #[test]
    fn test_parse_credential_delete() {
        let cli = Cli::try_parse_from(["sealbox", "credential", "delete", "db/postgres"]).unwrap();

        match cli.command {
            Commands::Credential {
                command: CredentialCommands::Delete { key },
            } => {
                assert_eq!(key, "db/postgres");
            }
            _ => panic!("Expected credential delete command"),
        }
    }

    #[test]
    fn test_parse_credential_history() {
        let cli = Cli::try_parse_from(["sealbox", "credential", "history", "db/postgres"]).unwrap();

        match cli.command {
            Commands::Credential {
                command: CredentialCommands::History { key },
            } => {
                assert_eq!(key, "db/postgres");
            }
            _ => panic!("Expected credential history command"),
        }
    }

    #[test]
    fn test_parse_file_set() {
        let cli = Cli::try_parse_from([
            "sealbox",
            "file",
            "set",
            "config/app",
            "--file",
            "./app.yaml",
            "--ttl",
            "3600",
            "--content-type",
            "text/yaml",
        ])
        .unwrap();

        match cli.command {
            Commands::File {
                command:
                    FileCommands::Set {
                        key,
                        file,
                        ttl,
                        content_type,
                    },
            } => {
                assert_eq!(key, "config/app");
                assert_eq!(file, "./app.yaml");
                assert_eq!(ttl, Some(3600));
                assert_eq!(content_type.as_deref(), Some("text/yaml"));
            }
            _ => panic!("Expected file set command"),
        }
    }

    #[test]
    fn test_parse_file_get_defaults() {
        let cli = Cli::try_parse_from(["sealbox", "file", "get", "config/app"]).unwrap();

        match cli.command {
            Commands::File {
                command:
                    FileCommands::Get {
                        key,
                        file,
                        version,
                        force,
                    },
            } => {
                assert_eq!(key, "config/app");
                assert!(file.is_none());
                assert!(version.is_none());
                assert!(!force);
            }
            _ => panic!("Expected file get command"),
        }
    }

    #[test]
    fn test_parse_file_get_force_and_version() {
        let cli = Cli::try_parse_from([
            "sealbox",
            "file",
            "get",
            "config/app",
            "--file",
            "./restored.yaml",
            "--version",
            "2",
            "--force",
        ])
        .unwrap();

        match cli.command {
            Commands::File {
                command:
                    FileCommands::Get {
                        key,
                        file,
                        version,
                        force,
                    },
            } => {
                assert_eq!(key, "config/app");
                assert_eq!(file.as_deref(), Some("./restored.yaml"));
                assert_eq!(version, Some(2));
                assert!(force);
            }
            _ => panic!("Expected file get command"),
        }
    }

    #[test]
    fn test_parse_file_list_filters() {
        let cli = Cli::try_parse_from([
            "sealbox", "file", "list", "--name", "config/", "--query", "app",
        ])
        .unwrap();

        match cli.command {
            Commands::File {
                command: FileCommands::List { name, query },
            } => {
                assert_eq!(name.as_deref(), Some("config/"));
                assert_eq!(query.as_deref(), Some("app"));
            }
            _ => panic!("Expected file list command"),
        }
    }

    #[test]
    fn test_parse_file_delete() {
        let cli = Cli::try_parse_from(["sealbox", "file", "delete", "config/app"]).unwrap();

        match cli.command {
            Commands::File {
                command: FileCommands::Delete { key },
            } => {
                assert_eq!(key, "config/app");
            }
            _ => panic!("Expected file delete command"),
        }
    }

    #[test]
    fn test_parse_secret_import_accepts_private_key_after_subcommand() {
        let cli = Cli::try_parse_from([
            "sealbox",
            "secret",
            "import",
            "backup.sealbox",
            "--private-key",
            "/backup/original_private_key.pem",
        ])
        .unwrap();

        assert_eq!(
            cli.private_key.as_deref(),
            Some("/backup/original_private_key.pem")
        );
        match cli.command {
            Commands::Secret {
                command:
                    SecretCommands::Import {
                        file,
                        passphrase_file,
                        ..
                    },
            } => {
                assert_eq!(file, "backup.sealbox");
                assert!(passphrase_file.is_none());
            }
            _ => panic!("Expected secret import command"),
        }
    }

    #[test]
    fn test_parse_secret_export_backup_options() {
        let cli = Cli::try_parse_from([
            "sealbox",
            "secret",
            "export",
            "backup.sealbox",
            "--all-versions",
            "--passphrase-file",
            "/run/secrets/backup-passphrase",
            "--force",
        ])
        .unwrap();

        match cli.command {
            Commands::Secret {
                command:
                    SecretCommands::Export {
                        all_versions,
                        passphrase,
                        passphrase_file,
                        force,
                        ..
                    },
            } => {
                assert!(all_versions);
                assert!(!passphrase);
                assert_eq!(
                    passphrase_file.as_deref(),
                    Some("/run/secrets/backup-passphrase")
                );
                assert!(force);
            }
            _ => panic!("Expected secret export command"),
        }
    }

    #[test]
    fn test_parse_key_import_with_target_paths() {
        let cli = Cli::try_parse_from([
            "sealbox",
            "key",
            "import",
            "--file",
            "keys.bundle",
            "--private-key-path",
            "/keys/private.pem",
            "--public-key-path",
            "/keys/public.pem",
        ])
        .unwrap();

        match cli.command {
            Commands::Key {
                command:
                    KeyCommands::Import {
                        file,
                        private_key_path,
                        public_key_path,
                        force,
                        ..
                    },
            } => {
                assert_eq!(file, "keys.bundle");
                assert_eq!(private_key_path.as_deref(), Some("/keys/private.pem"));
                assert_eq!(public_key_path.as_deref(), Some("/keys/public.pem"));
                assert!(!force);
            }
            _ => panic!("Expected key import command"),
        }
    }

    #[test]
    fn test_parse_admin_backup() {
        let cli =
            Cli::try_parse_from(["sealbox", "admin", "backup", "--file", "sealbox.db"]).unwrap();

        match cli.command {
            Commands::Admin {
                command: AdminCommands::Backup { file, force },
            } => {
                assert_eq!(file, "sealbox.db");
                assert!(!force);
            }
            _ => panic!("Expected admin backup command"),
        }
    }

    #[test]
    fn test_cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
