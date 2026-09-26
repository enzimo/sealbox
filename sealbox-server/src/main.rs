use clap::{Parser, Subcommand};
use sealbox_server::{
    config::SealboxConfig,
    create_app,
    error::{Result, SealboxError},
    repo::{backup_database, inspect_migration_path, restore_database},
};
use std::path::Path;
use tracing::{error, info};
use tracing_subscriber::{self, EnvFilter};

#[derive(Debug, Parser)]
#[command(name = "sealbox-server")]
struct Cli {
    #[command(subcommand)]
    command: Option<ServerCommand>,
}

#[derive(Debug, Subcommand)]
enum ServerCommand {
    /// Inspect a database's tenant migration without modifying it
    MigrationReport {
        /// SQLite database path; defaults to STORE_PATH
        #[arg(long)]
        store_path: Option<String>,
    },
    /// Write a consistent, integrity-checked snapshot of the database.
    ///
    /// Safe to run while the server is running.
    Backup {
        /// Snapshot destination; must not already exist
        #[arg(long)]
        out: String,
        /// SQLite database path; defaults to STORE_PATH
        #[arg(long)]
        store_path: Option<String>,
    },
    /// Replace the database with a snapshot. Stop the server first.
    Restore {
        /// Snapshot to restore
        #[arg(long)]
        from: String,
        /// SQLite database path; defaults to STORE_PATH
        #[arg(long)]
        store_path: Option<String>,
        /// Replace an existing database (it is moved aside, not deleted)
        #[arg(long)]
        force: bool,
    },
}

fn resolve_store_path(store_path: Option<String>, command: &str) -> Result<String> {
    store_path
        .or_else(|| std::env::var("STORE_PATH").ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            SealboxError::InvalidRequest(format!(
                "--store-path or STORE_PATH is required for {command}"
            ))
        })
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(value)
            .map_err(|error| SealboxError::ResponseBuildFailed(error.to_string()))?
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file if present
    dotenvy::dotenv().ok();

    // Enhanced tracing_subscriber initialization with log level filtering and formatting
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            // axum logs rejections from built-in extractors with the `axum::rejection`
            // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
            format!(
                "{}=debug,tower_http=debug,axum::rejection=trace",
                env!("CARGO_CRATE_NAME")
            )
            .into()
        }))
        .with_target(true)
        .with_line_number(true)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Some(ServerCommand::MigrationReport { store_path }) => {
            let path = resolve_store_path(store_path, "migration-report")?;
            return print_json(&inspect_migration_path(&path)?);
        }
        Some(ServerCommand::Backup { out, store_path }) => {
            let path = resolve_store_path(store_path, "backup")?;
            if !Path::new(&path).is_file() {
                return Err(SealboxError::InvalidRequest(format!(
                    "database does not exist: {path}"
                )));
            }
            let conn = rusqlite::Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            return print_json(&backup_database(&conn, Path::new(&out))?);
        }
        Some(ServerCommand::Restore {
            from,
            store_path,
            force,
        }) => {
            let path = resolve_store_path(store_path, "restore")?;
            return print_json(&restore_database(
                Path::new(&from),
                Path::new(&path),
                force,
            )?);
        }
        None => {}
    }

    info!("Sealbox Server starting up...");

    // Load configuration from environment variables
    let config = match SealboxConfig::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    // Build application routes (all routes are managed in api.rs)
    let app = create_app(&config)?;

    // Listening address from configuration
    let addr = &config.listen_addr;
    info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            error!("Failed to bind address {}: {}", addr, e);
            std::process::exit(1);
        });
    if let Err(e) = axum::serve(listener, app).await {
        error!("Server crashed: {}", e);
    }

    Ok(())
}
