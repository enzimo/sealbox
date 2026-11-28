use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use axum::{Router, http::StatusCode, response::Html, routing::delete};
use reqwest::Client;
use rusqlite::Connection;
use sealbox_server::{config::SealboxConfig, create_app};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::process::Command;

const CLI_BIN: &str = env!("CARGO_BIN_EXE_sealbox-cli");
const CHILD_TIMEOUT: Duration = Duration::from_secs(20);
const EXPIRY_WAIT_TIMEOUT: Duration = Duration::from_secs(10);

struct CliOutput {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl CliOutput {
    fn assert_success(&self, context: &str) {
        assert_eq!(
            self.code,
            Some(0),
            "{context} failed (exit {:?})\nstdout:\n{}\nstderr:\n{}",
            self.code,
            self.stdout,
            self.stderr
        );
    }
}

/// Real `sealbox-server` running on its own OS thread and Tokio runtime so
/// child CLI invocations never compete with or block the server loop.
struct LiveServer {
    _dir: TempDir,
    db_path: PathBuf,
    base_url: String,
    root_token: String,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl LiveServer {
    fn start() -> Self {
        let dir = tempfile::tempdir().expect("create temp dir for server db");
        let db_path = dir.path().join("sealbox.db");
        let root_token = "root-integration-token".to_string();
        let config = SealboxConfig {
            auth_token: root_token.clone(),
            store_path: db_path.display().to_string(),
            listen_addr: "127.0.0.1:0".to_string(),
            legacy_v1_enabled: false,
        };
        let app = create_app(&config).expect("create sealbox-server app");

        let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let handle = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build server tokio runtime");
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind ephemeral port");
                let addr = listener.local_addr().expect("read bound local addr");
                addr_tx.send(addr).expect("send bound addr");

                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .expect("serve axum app");
            });
        });

        let addr = addr_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("receive server listen address");

        Self {
            _dir: dir,
            db_path,
            base_url: format!("http://{addr}"),
            root_token,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    async fn create_tenant(&self, display_name: &str) -> (String, String) {
        let client = Client::new();
        let response = client
            .post(format!("{}/v2/admin/tenants", self.base_url))
            .bearer_auth(&self.root_token)
            .json(&json!({
                "display_name": display_name,
                "token_label": "integration-test",
            }))
            .send()
            .await
            .expect("POST /v2/admin/tenants");
        assert!(
            response.status().is_success(),
            "create_tenant failed: {}",
            response.status()
        );
        let body: Value = response.json().await.expect("parse create_tenant response");
        let tenant_id = body["tenant"]["id"]
            .as_str()
            .expect("tenant.id string")
            .to_string();
        let token = body["token"].as_str().expect("token string").to_string();
        (tenant_id, token)
    }

    /// Count stored rows for `(namespace, key)` directly in SQLite.
    ///
    /// Reading an expired key through `secret get` lazily deletes it, so tests
    /// must inspect SQLite directly rather than calling `secret get` on keys
    /// expected to be removed by `cleanup-expired`.
    fn row_count(&self, namespace: &str, key: &str) -> i64 {
        let conn = Connection::open(&self.db_path).expect("open server sqlite db");
        conn.query_row(
            "SELECT COUNT(*) FROM secrets WHERE namespace = ?1 AND key = ?2",
            (namespace, key),
            |row| row.get(0),
        )
        .expect("count secret rows")
    }

    fn max_expires_at(&self, namespace: &str, key: &str) -> Option<i64> {
        let conn = Connection::open(&self.db_path).expect("open server sqlite db");
        conn.query_row(
            "SELECT MAX(expires_at) FROM secrets WHERE namespace = ?1 AND key = ?2",
            (namespace, key),
            |row| row.get(0),
        )
        .expect("query max expires_at")
    }

    /// Wait until the server's clock is strictly past every target key's
    /// `expires_at` (`expires_at < now`, matching `SqliteSecretRepo`).
    async fn wait_until_expired(&self, targets: &[(&str, &str)]) {
        let latest_expiry = targets
            .iter()
            .map(|(namespace, key)| {
                self.max_expires_at(namespace, key).unwrap_or_else(|| {
                    panic!("expected expires_at for namespace={namespace} key={key}")
                })
            })
            .max()
            .expect("at least one expiring target");

        let deadline = Instant::now() + EXPIRY_WAIT_TIMEOUT;
        while time::OffsetDateTime::now_utc().unix_timestamp() <= latest_expiry {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for now > {latest_expiry}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for LiveServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Run the compiled `sealbox-cli` binary with a cleared environment (`HOME` and
/// explicit `SEALBOX_*` overrides only) and a hard child timeout.
async fn run_cli(home: &Path, envs: &[(&str, &str)], args: &[&str]) -> CliOutput {
    let mut cmd = Command::new(CLI_BIN);
    cmd.env_clear()
        .env("HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .args(args);

    for (key, value) in envs {
        cmd.env(key, value);
    }

    let child = cmd.spawn().expect("spawn sealbox-cli");
    let output = tokio::time::timeout(CHILD_TIMEOUT, child.wait_with_output())
        .await
        .expect("sealbox-cli timed out")
        .expect("wait for sealbox-cli");

    CliOutput {
        code: output.status.code(),
        stdout: String::from_utf8(output.stdout).expect("stdout utf-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr utf-8"),
    }
}

async fn setup_tenant_keys(server: &LiveServer, home: &Path, token: &str) {
    let envs = [
        ("SEALBOX_URL", server.base_url.as_str()),
        ("SEALBOX_TOKEN", token),
    ];

    run_cli(home, &envs, &["key", "generate"])
        .await
        .assert_success("key generate");
    run_cli(home, &envs, &["key", "register"])
        .await
        .assert_success("key register");
}

/// Parse the JSON payload printed by `secret get --output json`, skipping the
/// leading `print_info` status lines that `secret get` emits on stdout.
fn parse_secret_get_json(stdout: &str) -> Value {
    let start = stdout
        .find('{')
        .unwrap_or_else(|| panic!("expected JSON object in secret get output: {stdout:?}"));
    serde_json::from_str(&stdout[start..])
        .unwrap_or_else(|err| panic!("failed to parse secret get JSON ({err}): {stdout:?}"))
}

fn parse_cleanup_json(stdout: &str) -> (u64, i64) {
    let value: Value = serde_json::from_str(stdout)
        .unwrap_or_else(|err| panic!("expected valid JSON on stdout, got error {err}: {stdout:?}"));
    let obj = value
        .as_object()
        .expect("cleanup-expired JSON output must be an object");
    assert_eq!(
        obj.len(),
        2,
        "cleanup-expired JSON output must have exactly two fields: {obj:?}"
    );
    let deleted_count = obj
        .get("deleted_count")
        .and_then(Value::as_u64)
        .expect("deleted_count u64");
    let cleaned_at = obj
        .get("cleaned_at")
        .and_then(Value::as_i64)
        .expect("cleaned_at i64");
    (deleted_count, cleaned_at)
}

#[tokio::test]
async fn cleanup_expired_deletes_expired_secret_keeps_surviving_and_works_with_token_file() {
    let server = LiveServer::start();
    let (tenant_id, token) = server.create_tenant("Tenant Alpha").await;
    let writer_home = tempfile::tempdir().expect("writer home");
    setup_tenant_keys(&server, writer_home.path(), &token).await;

    let writer_envs = [
        ("SEALBOX_URL", server.base_url.as_str()),
        ("SEALBOX_TOKEN", token.as_str()),
    ];

    run_cli(
        writer_home.path(),
        &writer_envs,
        &[
            "secret",
            "set",
            "temp-expired",
            "ephemeral-value",
            "--ttl",
            "1",
        ],
    )
    .await
    .assert_success("set temp-expired");
    run_cli(
        writer_home.path(),
        &writer_envs,
        &[
            "secret",
            "set",
            "temp-unexpired",
            "still-valid",
            "--ttl",
            "3600",
        ],
    )
    .await
    .assert_success("set temp-unexpired");
    run_cli(
        writer_home.path(),
        &writer_envs,
        &["secret", "set", "permanent-secret", "forever-value"],
    )
    .await
    .assert_success("set permanent-secret");

    assert_eq!(server.row_count(&tenant_id, "temp-expired"), 1);
    assert_eq!(server.row_count(&tenant_id, "temp-unexpired"), 1);
    assert_eq!(server.row_count(&tenant_id, "permanent-secret"), 1);

    // Never call `secret get temp-expired` before cleanup: reads lazily delete
    // expired rows and would mask whether cleanup-expired performed the delete.
    server
        .wait_until_expired(&[(&tenant_id, "temp-expired")])
        .await;

    // Run cleanup from a clean HOME with no config file and no RSA key files,
    // passing the token via SEALBOX_TOKEN_FILE as a periodic janitor does.
    let janitor_home = tempfile::tempdir().expect("janitor home");
    let token_dir = tempfile::tempdir().expect("token dir");
    let token_file = token_dir.path().join("tenant.token");
    fs::write(&token_file, format!("{token}\n")).expect("write token file");
    let token_file_str = token_file.to_str().expect("utf-8 token file path");

    let janitor_envs = [
        ("SEALBOX_URL", server.base_url.as_str()),
        ("SEALBOX_TOKEN_FILE", token_file_str),
    ];

    let before_ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let first = run_cli(
        janitor_home.path(),
        &janitor_envs,
        &["secret", "cleanup-expired", "--output", "json"],
    )
    .await;
    let after_ts = time::OffsetDateTime::now_utc().unix_timestamp();
    first.assert_success("first cleanup-expired");
    assert!(
        first.stderr.is_empty(),
        "unexpected stderr: {}",
        first.stderr
    );

    let (deleted_count, cleaned_at) = parse_cleanup_json(&first.stdout);
    assert_eq!(deleted_count, 1);
    assert!(
        (before_ts..=after_ts).contains(&cleaned_at),
        "cleaned_at {cleaned_at} outside [{before_ts}, {after_ts}]"
    );
    assert!(
        !janitor_home.path().join(".config").exists(),
        "cleanup-expired must not create config files in HOME"
    );

    assert_eq!(server.row_count(&tenant_id, "temp-expired"), 0);
    assert_eq!(server.row_count(&tenant_id, "temp-unexpired"), 1);
    assert_eq!(server.row_count(&tenant_id, "permanent-secret"), 1);

    // Surviving records still decrypt cleanly.
    let unexpired = run_cli(
        writer_home.path(),
        &writer_envs,
        &["secret", "get", "temp-unexpired", "--output", "json"],
    )
    .await;
    unexpired.assert_success("get temp-unexpired");
    let unexpired_json = parse_secret_get_json(&unexpired.stdout);
    assert_eq!(unexpired_json["value"], "still-valid");

    let permanent = run_cli(
        writer_home.path(),
        &writer_envs,
        &["secret", "get", "permanent-secret", "--output", "json"],
    )
    .await;
    permanent.assert_success("get permanent-secret");
    let permanent_json = parse_secret_get_json(&permanent.stdout);
    assert_eq!(permanent_json["value"], "forever-value");

    // Repeated cleanup is idempotent and reports 0 deletions.
    let second = run_cli(
        janitor_home.path(),
        &janitor_envs,
        &["secret", "cleanup-expired", "--output", "json"],
    )
    .await;
    second.assert_success("second cleanup-expired");
    let (second_deleted, _) = parse_cleanup_json(&second.stdout);
    assert_eq!(second_deleted, 0);
}

#[tokio::test]
async fn cleanup_expired_deletes_secrets_credentials_and_files() {
    let server = LiveServer::start();
    let (tenant_id, token) = server.create_tenant("Tenant Records").await;
    let home = tempfile::tempdir().expect("tenant home");
    setup_tenant_keys(&server, home.path(), &token).await;

    let envs = [
        ("SEALBOX_URL", server.base_url.as_str()),
        ("SEALBOX_TOKEN", token.as_str()),
    ];

    let sample_file = home.path().join("short-lived.txt");
    fs::write(&sample_file, b"temporary file payload").expect("write sample file");
    let sample_file_str = sample_file.to_str().expect("utf-8 sample file path");

    run_cli(
        home.path(),
        &envs,
        &["secret", "set", "exp-secret", "short-secret", "--ttl", "1"],
    )
    .await
    .assert_success("set exp-secret");
    run_cli(
        home.path(),
        &envs,
        &[
            "credential",
            "set",
            "exp-cred",
            "--username",
            "demo-user",
            "--ttl",
            "1",
            "--generate-password",
        ],
    )
    .await
    .assert_success("set exp-cred");
    run_cli(
        home.path(),
        &envs,
        &[
            "file",
            "set",
            "exp-file",
            "--file",
            sample_file_str,
            "--ttl",
            "1",
        ],
    )
    .await
    .assert_success("set exp-file");
    run_cli(
        home.path(),
        &envs,
        &["secret", "set", "keep-secret", "permanent-value"],
    )
    .await
    .assert_success("set keep-secret");

    assert_eq!(server.row_count(&tenant_id, "exp-secret"), 1);
    assert_eq!(server.row_count(&tenant_id, "exp-cred"), 1);
    assert_eq!(server.row_count(&tenant_id, "exp-file"), 1);
    assert_eq!(server.row_count(&tenant_id, "keep-secret"), 1);

    // Never read expired keys before cleanup-expired runs.
    server
        .wait_until_expired(&[
            (&tenant_id, "exp-secret"),
            (&tenant_id, "exp-cred"),
            (&tenant_id, "exp-file"),
        ])
        .await;

    let cleanup = run_cli(
        home.path(),
        &envs,
        &["secret", "cleanup-expired", "--output", "json"],
    )
    .await;
    cleanup.assert_success("cleanup-expired across record types");
    assert!(
        cleanup.stderr.is_empty(),
        "unexpected stderr: {}",
        cleanup.stderr
    );

    let (deleted_count, _) = parse_cleanup_json(&cleanup.stdout);
    assert_eq!(deleted_count, 3);

    assert_eq!(server.row_count(&tenant_id, "exp-secret"), 0);
    assert_eq!(server.row_count(&tenant_id, "exp-cred"), 0);
    assert_eq!(server.row_count(&tenant_id, "exp-file"), 0);
    assert_eq!(server.row_count(&tenant_id, "keep-secret"), 1);

    let surviving = run_cli(
        home.path(),
        &envs,
        &["secret", "get", "keep-secret", "--output", "json"],
    )
    .await;
    surviving.assert_success("get keep-secret");
    let surviving_json = parse_secret_get_json(&surviving.stdout);
    assert_eq!(surviving_json["value"], "permanent-value");
}

#[tokio::test]
async fn cleanup_expired_is_isolated_between_tenants() {
    let server = LiveServer::start();
    let (tenant_a, token_a) = server.create_tenant("Tenant A").await;
    let (tenant_b, token_b) = server.create_tenant("Tenant B").await;

    let home_a = tempfile::tempdir().expect("home a");
    let home_b = tempfile::tempdir().expect("home b");
    setup_tenant_keys(&server, home_a.path(), &token_a).await;
    setup_tenant_keys(&server, home_b.path(), &token_b).await;

    let envs_a = [
        ("SEALBOX_URL", server.base_url.as_str()),
        ("SEALBOX_TOKEN", token_a.as_str()),
    ];
    let envs_b = [
        ("SEALBOX_URL", server.base_url.as_str()),
        ("SEALBOX_TOKEN", token_b.as_str()),
    ];

    // Both tenants store an expired secret under the same key name plus a permanent secret.
    run_cli(
        home_a.path(),
        &envs_a,
        &["secret", "set", "shared-key", "a-temp", "--ttl", "1"],
    )
    .await
    .assert_success("tenant A set shared-key");
    run_cli(
        home_a.path(),
        &envs_a,
        &["secret", "set", "keep-a", "a-permanent"],
    )
    .await
    .assert_success("tenant A set keep-a");

    run_cli(
        home_b.path(),
        &envs_b,
        &["secret", "set", "shared-key", "b-temp", "--ttl", "1"],
    )
    .await
    .assert_success("tenant B set shared-key");
    run_cli(
        home_b.path(),
        &envs_b,
        &["secret", "set", "keep-b", "b-permanent"],
    )
    .await
    .assert_success("tenant B set keep-b");

    assert_eq!(server.row_count(&tenant_a, "shared-key"), 1);
    assert_eq!(server.row_count(&tenant_b, "shared-key"), 1);

    // Wait until both tenants' keys are expired without reading either key.
    server
        .wait_until_expired(&[(&tenant_a, "shared-key"), (&tenant_b, "shared-key")])
        .await;

    // Tenant A cleans up its own expired record using --url and --token CLI flags.
    let empty_home = tempfile::tempdir().expect("empty home");
    let cleanup_a = run_cli(
        empty_home.path(),
        &[],
        &[
            "--url",
            server.base_url.as_str(),
            "--token",
            token_a.as_str(),
            "secret",
            "cleanup-expired",
            "--output",
            "json",
        ],
    )
    .await;
    cleanup_a.assert_success("tenant A cleanup-expired");
    let (deleted_a, _) = parse_cleanup_json(&cleanup_a.stdout);
    assert_eq!(deleted_a, 1);

    // Tenant A's expired row is gone; Tenant B's expired row and both permanent rows remain.
    assert_eq!(server.row_count(&tenant_a, "shared-key"), 0);
    assert_eq!(server.row_count(&tenant_a, "keep-a"), 1);
    assert_eq!(server.row_count(&tenant_b, "shared-key"), 1);
    assert_eq!(server.row_count(&tenant_b, "keep-b"), 1);

    // Tenant B can now clean up its own expired record independently.
    let cleanup_b = run_cli(
        empty_home.path(),
        &[],
        &[
            "--url",
            server.base_url.as_str(),
            "--token",
            token_b.as_str(),
            "secret",
            "cleanup-expired",
            "--output",
            "json",
        ],
    )
    .await;
    cleanup_b.assert_success("tenant B cleanup-expired");
    let (deleted_b, _) = parse_cleanup_json(&cleanup_b.stdout);
    assert_eq!(deleted_b, 1);

    assert_eq!(server.row_count(&tenant_b, "shared-key"), 0);
    assert_eq!(server.row_count(&tenant_b, "keep-b"), 1);
}

#[tokio::test]
async fn cleanup_expired_supports_table_yaml_and_config_file() {
    let server = LiveServer::start();
    let (_tenant_id, token) = server.create_tenant("Tenant Formats").await;
    let home = tempfile::tempdir().expect("config home");

    run_cli(
        home.path(),
        &[],
        &[
            "config",
            "init",
            "--url",
            server.base_url.as_str(),
            "--token",
            token.as_str(),
            "--output",
            "table",
        ],
    )
    .await
    .assert_success("config init");

    let table_out = run_cli(home.path(), &[], &["secret", "cleanup-expired"]).await;
    table_out.assert_success("table cleanup-expired");
    assert!(
        table_out.stderr.is_empty(),
        "unexpected stderr: {}",
        table_out.stderr
    );
    let deleted_count_line = table_out
        .stdout
        .lines()
        .find(|line| line.contains("Deleted Count"))
        .expect("Deleted Count row in table output");
    let deleted_count_cells: Vec<&str> = deleted_count_line
        .split(['│', '┆'])
        .map(str::trim)
        .filter(|cell| !cell.is_empty())
        .collect();
    assert_eq!(
        deleted_count_cells,
        vec!["Deleted Count", "0"],
        "unexpected Deleted Count row: {deleted_count_line}"
    );
    assert!(table_out.stdout.contains("Cleaned At"));

    let yaml_out = run_cli(
        home.path(),
        &[],
        &["secret", "cleanup-expired", "--output", "yaml"],
    )
    .await;
    yaml_out.assert_success("yaml cleanup-expired");
    assert!(
        yaml_out.stderr.is_empty(),
        "unexpected stderr: {}",
        yaml_out.stderr
    );
    assert!(yaml_out.stdout.contains("deleted_count: 0"));
    assert!(yaml_out.stdout.contains("cleaned_at: "));
}

#[tokio::test]
async fn cleanup_expired_exits_1_with_empty_stdout_on_errors() {
    let server = LiveServer::start();
    let (_tenant_id, tenant_token) = server.create_tenant("Tenant Errors").await;
    let empty_home = tempfile::tempdir().expect("empty home");

    // 1. Root token is rejected by tenant-scoped /v2/cleanup-expired with 401.
    let root_err = run_cli(
        empty_home.path(),
        &[],
        &[
            "--url",
            server.base_url.as_str(),
            "--token",
            server.root_token.as_str(),
            "secret",
            "cleanup-expired",
            "--output",
            "json",
        ],
    )
    .await;
    assert_eq!(root_err.code, Some(1));
    assert!(root_err.stdout.is_empty(), "stdout: {:?}", root_err.stdout);
    assert!(
        root_err.stderr.contains("401"),
        "expected 401 on stderr, got: {:?}",
        root_err.stderr
    );

    // 2. Invalid token is rejected with 401.
    let invalid_err = run_cli(
        empty_home.path(),
        &[],
        &[
            "--url",
            server.base_url.as_str(),
            "--token",
            "not-a-valid-tenant-token",
            "secret",
            "cleanup-expired",
            "--output",
            "json",
        ],
    )
    .await;
    assert_eq!(invalid_err.code, Some(1));
    assert!(
        invalid_err.stdout.is_empty(),
        "stdout: {:?}",
        invalid_err.stdout
    );
    assert!(
        invalid_err.stderr.contains("401"),
        "expected 401 on stderr, got: {:?}",
        invalid_err.stderr
    );

    // 3. Missing token fails before network I/O.
    let missing_token_err = run_cli(
        empty_home.path(),
        &[],
        &[
            "--url",
            server.base_url.as_str(),
            "secret",
            "cleanup-expired",
            "--output",
            "json",
        ],
    )
    .await;
    assert_eq!(missing_token_err.code, Some(1));
    assert!(
        missing_token_err.stdout.is_empty(),
        "stdout: {:?}",
        missing_token_err.stdout
    );
    assert!(
        missing_token_err.stderr.to_lowercase().contains("token"),
        "expected token error on stderr, got: {:?}",
        missing_token_err.stderr
    );

    // 4. Closed port fails cleanly with exit 1 and empty stdout.
    let closed_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind temp port");
    let closed_addr = closed_listener.local_addr().expect("read temp port");
    drop(closed_listener);
    let closed_url = format!("http://{closed_addr}");

    let closed_err = run_cli(
        empty_home.path(),
        &[],
        &[
            "--url",
            closed_url.as_str(),
            "--token",
            tenant_token.as_str(),
            "secret",
            "cleanup-expired",
            "--output",
            "json",
        ],
    )
    .await;
    assert_eq!(closed_err.code, Some(1));
    assert!(
        closed_err.stdout.is_empty(),
        "stdout: {:?}",
        closed_err.stdout
    );
    assert!(
        closed_err.stderr.contains("Failed to request server"),
        "expected request error on stderr, got: {:?}",
        closed_err.stderr
    );
}

/// Minimal Axum stub server on its own OS thread for testing non-2xx and
/// malformed 200 HTTP responses independently of `sealbox-server`.
struct StubServer {
    base_url: String,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl StubServer {
    fn start(app: Router) -> Self {
        let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let handle = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build stub server tokio runtime");
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind ephemeral stub port");
                let addr = listener.local_addr().expect("read stub local addr");
                addr_tx.send(addr).expect("send stub addr");

                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .expect("serve stub axum app");
            });
        });

        let addr = addr_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("receive stub listen address");

        Self {
            base_url: format!("http://{addr}"),
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        }
    }
}

impl Drop for StubServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[tokio::test]
async fn cleanup_expired_exits_1_with_empty_stdout_on_500_and_non_json_200() {
    let empty_home = tempfile::tempdir().expect("empty home");

    // 1. 500 Internal Server Error exits 1 with empty stdout and status-code stderr prefix.
    let err_500_server = StubServer::start(Router::new().route(
        "/v2/cleanup-expired",
        delete(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "database unavailable") }),
    ));
    let err_500 = run_cli(
        empty_home.path(),
        &[],
        &[
            "--url",
            err_500_server.base_url.as_str(),
            "--token",
            "stub-tenant-token",
            "secret",
            "cleanup-expired",
            "--output",
            "json",
        ],
    )
    .await;
    assert_eq!(err_500.code, Some(1));
    assert!(err_500.stdout.is_empty(), "stdout: {:?}", err_500.stdout);
    assert!(
        err_500
            .stderr
            .starts_with("Error: Server returned error (status code: 500"),
        "expected 500 error prefix on stderr, got: {:?}",
        err_500.stderr
    );
    assert!(
        err_500.stderr.contains("database unavailable"),
        "expected response body on stderr, got: {:?}",
        err_500.stderr
    );

    // 2. 200 OK with an HTML body (e.g. proxy error page) exits 1 with empty stdout
    // and parse-failure stderr prefix.
    let html_200_server = StubServer::start(Router::new().route(
        "/v2/cleanup-expired",
        delete(|| async { Html("<html><body>proxy page</body></html>") }),
    ));
    let html_200 = run_cli(
        empty_home.path(),
        &[],
        &[
            "--url",
            html_200_server.base_url.as_str(),
            "--token",
            "stub-tenant-token",
            "secret",
            "cleanup-expired",
            "--output",
            "json",
        ],
    )
    .await;
    assert_eq!(html_200.code, Some(1));
    assert!(html_200.stdout.is_empty(), "stdout: {:?}", html_200.stdout);
    assert!(
        html_200
            .stderr
            .starts_with("Error: Failed to parse server response"),
        "expected parse error prefix on stderr, got: {:?}",
        html_200.stderr
    );
}

#[tokio::test]
async fn cleanup_expired_ends_whole_key_for_expired_newest_and_prunes_older_expired_versions() {
    let server = LiveServer::start();
    let (tenant_id, token) = server.create_tenant("Tenant MultiVersion").await;
    let home = tempfile::tempdir().expect("tenant home");
    setup_tenant_keys(&server, home.path(), &token).await;

    let envs = [
        ("SEALBOX_URL", server.base_url.as_str()),
        ("SEALBOX_TOKEN", token.as_str()),
    ];

    let perm_file = home.path().join("perm.txt");
    let temp_file = home.path().join("temp.txt");
    fs::write(&perm_file, b"permanent file v1").expect("write perm file");
    fs::write(&temp_file, b"ephemeral file v2").expect("write temp file");
    let perm_file_str = perm_file.to_str().expect("utf-8 perm file path");
    let temp_file_str = temp_file.to_str().expect("utf-8 temp file path");

    // 1. Plain secret, credential, and file each with permanent v1 + expiring v2.
    run_cli(
        home.path(),
        &envs,
        &["secret", "set", "ended-secret", "permanent-v1"],
    )
    .await
    .assert_success("set ended-secret v1");
    run_cli(
        home.path(),
        &envs,
        &[
            "secret",
            "set",
            "ended-secret",
            "ephemeral-v2",
            "--ttl",
            "1",
        ],
    )
    .await
    .assert_success("set ended-secret v2");

    run_cli(
        home.path(),
        &envs,
        &[
            "credential",
            "set",
            "ended-cred",
            "--username",
            "perm-user",
            "--generate-password",
        ],
    )
    .await
    .assert_success("set ended-cred v1");
    run_cli(
        home.path(),
        &envs,
        &[
            "credential",
            "set",
            "ended-cred",
            "--username",
            "temp-user",
            "--ttl",
            "1",
            "--generate-password",
        ],
    )
    .await
    .assert_success("set ended-cred v2");

    run_cli(
        home.path(),
        &envs,
        &["file", "set", "ended-file", "--file", perm_file_str],
    )
    .await
    .assert_success("set ended-file v1");
    run_cli(
        home.path(),
        &envs,
        &[
            "file",
            "set",
            "ended-file",
            "--file",
            temp_file_str,
            "--ttl",
            "1",
        ],
    )
    .await
    .assert_success("set ended-file v2");

    // 2. Active secret with expiring v1 under permanent v2: only v1 should be removed.
    run_cli(
        home.path(),
        &envs,
        &[
            "secret",
            "set",
            "active-with-expired-v1",
            "expired-v1",
            "--ttl",
            "1",
        ],
    )
    .await
    .assert_success("set active-with-expired-v1 v1");
    run_cli(
        home.path(),
        &envs,
        &["secret", "set", "active-with-expired-v1", "permanent-v2"],
    )
    .await
    .assert_success("set active-with-expired-v1 v2");

    assert_eq!(server.row_count(&tenant_id, "ended-secret"), 2);
    assert_eq!(server.row_count(&tenant_id, "ended-cred"), 2);
    assert_eq!(server.row_count(&tenant_id, "ended-file"), 2);
    assert_eq!(server.row_count(&tenant_id, "active-with-expired-v1"), 2);

    // Wait past expiry without calling `secret get` first so lazy cleanup cannot mask the result.
    server
        .wait_until_expired(&[
            (&tenant_id, "ended-secret"),
            (&tenant_id, "ended-cred"),
            (&tenant_id, "ended-file"),
            (&tenant_id, "active-with-expired-v1"),
        ])
        .await;

    // Even before cleanup runs, listings and version history already omit expired-newest keys.
    let list_before = run_cli(home.path(), &envs, &["secret", "list", "--output", "json"]).await;
    list_before.assert_success("list before cleanup");
    assert!(!list_before.stdout.contains("ended-secret"));
    assert!(!list_before.stdout.contains("ended-cred"));
    assert!(!list_before.stdout.contains("ended-file"));
    assert!(list_before.stdout.contains("active-with-expired-v1"));

    let history_before = run_cli(
        home.path(),
        &envs,
        &["secret", "history", "ended-secret", "--output", "json"],
    )
    .await;
    assert_eq!(
        history_before.code,
        Some(1),
        "stderr: {}",
        history_before.stderr
    );
    assert!(
        history_before.stderr.contains("404"),
        "expected 404 for ended-secret history, got: {}",
        history_before.stderr
    );

    // Tenant cleanup deletes all 2 versions of each ended key (6 rows) + expired v1 of active key (1 row) = 7.
    let janitor_home = tempfile::tempdir().expect("janitor home");
    let cleanup = run_cli(
        janitor_home.path(),
        &envs,
        &["secret", "cleanup-expired", "--output", "json"],
    )
    .await;
    cleanup.assert_success("multi-version cleanup-expired");
    assert!(
        cleanup.stderr.is_empty(),
        "unexpected stderr: {}",
        cleanup.stderr
    );

    let (deleted_count, _) = parse_cleanup_json(&cleanup.stdout);
    assert_eq!(deleted_count, 7);
    assert_eq!(server.row_count(&tenant_id, "ended-secret"), 0);
    assert_eq!(server.row_count(&tenant_id, "ended-cred"), 0);
    assert_eq!(server.row_count(&tenant_id, "ended-file"), 0);
    assert_eq!(server.row_count(&tenant_id, "active-with-expired-v1"), 1);

    // Reading ended keys by key or by older version fails with 404; active key still returns permanent v2.
    let get_ended_latest = run_cli(home.path(), &envs, &["secret", "get", "ended-secret"]).await;
    assert_eq!(
        get_ended_latest.code,
        Some(1),
        "stderr: {}",
        get_ended_latest.stderr
    );
    assert!(
        get_ended_latest.stderr.contains("404"),
        "stderr: {}",
        get_ended_latest.stderr
    );

    let get_ended_v1 = run_cli(
        home.path(),
        &envs,
        &["secret", "get", "ended-secret", "--version", "1"],
    )
    .await;
    assert_eq!(
        get_ended_v1.code,
        Some(1),
        "stderr: {}",
        get_ended_v1.stderr
    );
    assert!(
        get_ended_v1.stderr.contains("404"),
        "stderr: {}",
        get_ended_v1.stderr
    );

    let get_ended_cred = run_cli(home.path(), &envs, &["credential", "get", "ended-cred"]).await;
    assert_eq!(
        get_ended_cred.code,
        Some(1),
        "stderr: {}",
        get_ended_cred.stderr
    );
    assert!(
        get_ended_cred.stderr.contains("404"),
        "stderr: {}",
        get_ended_cred.stderr
    );

    let get_ended_file = run_cli(
        home.path(),
        &envs,
        &[
            "file",
            "get",
            "ended-file",
            "--file",
            home.path().join("restored.txt").to_str().unwrap(),
        ],
    )
    .await;
    assert_eq!(
        get_ended_file.code,
        Some(1),
        "stderr: {}",
        get_ended_file.stderr
    );
    assert!(
        get_ended_file.stderr.contains("404"),
        "stderr: {}",
        get_ended_file.stderr
    );

    let active = run_cli(
        home.path(),
        &envs,
        &[
            "secret",
            "get",
            "active-with-expired-v1",
            "--output",
            "json",
        ],
    )
    .await;
    active.assert_success("get active-with-expired-v1 after cleanup");
    let active_json = parse_secret_get_json(&active.stdout);
    assert_eq!(active_json["value"], "permanent-v2");
    assert_eq!(active_json["version"], 2);
}

#[tokio::test]
async fn read_and_import_do_not_revive_expired_newest_version() {
    let server = LiveServer::start();
    let (tenant_a, token_a) = server.create_tenant("Tenant Source").await;
    let (tenant_b, token_b) = server.create_tenant("Tenant Dest").await;

    let home_a = tempfile::tempdir().expect("home a");
    let home_b = tempfile::tempdir().expect("home b");
    setup_tenant_keys(&server, home_a.path(), &token_a).await;
    setup_tenant_keys(&server, home_b.path(), &token_b).await;

    let envs_a = [
        ("SEALBOX_URL", server.base_url.as_str()),
        ("SEALBOX_TOKEN", token_a.as_str()),
    ];
    let envs_b = [
        ("SEALBOX_URL", server.base_url.as_str()),
        ("SEALBOX_TOKEN", token_b.as_str()),
    ];

    // Permanent control key, plus permanent v1 + expiring v2 for ephemeral-override.
    // Create still-active first so only the single export command runs inside v2's TTL window.
    run_cli(
        home_a.path(),
        &envs_a,
        &["secret", "set", "still-active", "keep-me"],
    )
    .await
    .assert_success("set still-active");
    run_cli(
        home_a.path(),
        &envs_a,
        &["secret", "set", "ephemeral-override", "old-permanent-v1"],
    )
    .await
    .assert_success("set ephemeral-override v1");
    run_cli(
        home_a.path(),
        &envs_a,
        &[
            "secret",
            "set",
            "ephemeral-override",
            "temp-v2",
            "--ttl",
            "4",
        ],
    )
    .await
    .assert_success("set ephemeral-override v2");

    // Export --all-versions while v2 is still valid and verify all 3 versions were archived.
    let archive_path = home_a.path().join("backup.sealbox");
    let passphrase_file = home_a.path().join("passphrase.txt");
    fs::write(&passphrase_file, "test-archive-passphrase\n").expect("write passphrase");
    let export_out = run_cli(
        home_a.path(),
        &envs_a,
        &[
            "secret",
            "export",
            archive_path.to_str().unwrap(),
            "--all-versions",
            "--passphrase-file",
            passphrase_file.to_str().unwrap(),
        ],
    )
    .await;
    export_out.assert_success("export --all-versions before expiry");
    assert!(
        export_out
            .stdout
            .contains("Exported 3 secret versions across 2 keys"),
        "expected archive to contain both versions of ephemeral-override plus still-active, got:\n{}",
        export_out.stdout
    );

    // Wait until ephemeral-override v2 has expired.
    server
        .wait_until_expired(&[(&tenant_a, "ephemeral-override")])
        .await;

    // 1. Reading the older version through the CLI returns 404 and deletes all rows.
    let get_old_v1 = run_cli(
        home_a.path(),
        &envs_a,
        &["secret", "get", "ephemeral-override", "--version", "1"],
    )
    .await;
    assert_eq!(get_old_v1.code, Some(1), "stderr: {}", get_old_v1.stderr);
    assert!(
        get_old_v1.stderr.contains("404"),
        "stderr: {}",
        get_old_v1.stderr
    );
    assert_eq!(server.row_count(&tenant_a, "ephemeral-override"), 0);

    // 2. Importing the pre-expiry archive into Tenant B skips every version of
    //    ephemeral-override (never reviving old-permanent-v1) while importing still-active.
    let import_out = run_cli(
        home_b.path(),
        &envs_b,
        &[
            "secret",
            "import",
            archive_path.to_str().unwrap(),
            "--passphrase-file",
            passphrase_file.to_str().unwrap(),
        ],
    )
    .await;
    import_out.assert_success("import pre-expiry archive after expiry");
    assert!(
        import_out
            .stdout
            .contains("Skipping expired secret 'ephemeral-override'"),
        "expected import warning for ephemeral-override, got:\n{}",
        import_out.stdout
    );
    assert!(
        import_out.stdout.contains("2 version(s) skipped"),
        "expected import warning to report 2 skipped versions, got:\n{}",
        import_out.stdout
    );
    assert!(
        import_out
            .stdout
            .contains("Imported: 1, skipped expired: 2"),
        "expected import summary to report 1 imported and 2 skipped, got:\n{}",
        import_out.stdout
    );
    assert_eq!(server.row_count(&tenant_b, "ephemeral-override"), 0);
    assert_eq!(server.row_count(&tenant_b, "still-active"), 1);

    let imported_active = run_cli(
        home_b.path(),
        &envs_b,
        &["secret", "get", "still-active", "--output", "json"],
    )
    .await;
    imported_active.assert_success("get imported still-active");
    let active_json = parse_secret_get_json(&imported_active.stdout);
    assert_eq!(active_json["value"], "keep-me");
}

#[tokio::test]
async fn cleanup_expired_ignores_v1_api_version_without_warning() {
    let server = LiveServer::start();
    let (_tenant_id, token) = server.create_tenant("Tenant V1Env").await;
    let empty_home = tempfile::tempdir().expect("empty home");

    let envs = [
        ("SEALBOX_URL", server.base_url.as_str()),
        ("SEALBOX_TOKEN", token.as_str()),
        ("SEALBOX_API_VERSION", "v1"),
    ];

    let out = run_cli(
        empty_home.path(),
        &envs,
        &["secret", "cleanup-expired", "--output", "json"],
    )
    .await;
    out.assert_success("cleanup-expired with SEALBOX_API_VERSION=v1");
    assert!(
        out.stderr.is_empty(),
        "expected no v1 deprecation warning on stderr, got: {:?}",
        out.stderr
    );
    let (deleted_count, _) = parse_cleanup_json(&out.stdout);
    assert_eq!(deleted_count, 0);
}
