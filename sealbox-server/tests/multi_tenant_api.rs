use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

use sealbox_server::{config::SealboxConfig, create_app};

struct TestServer {
    dir: TempDir,
    app: Router,
    root_token: String,
}

impl TestServer {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root_token = "root-test-token".to_string();
        let config = SealboxConfig {
            auth_token: root_token.clone(),
            store_path: dir.path().join("sealbox.db").display().to_string(),
            listen_addr: "127.0.0.1:0".to_string(),
            legacy_v1_enabled: true,
        };
        let app = create_app(&config).unwrap();
        Self {
            dir,
            app,
            root_token,
        }
    }

    async fn json(
        &self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("Authorization", format!("Bearer {token}"));
        if body.is_some() {
            builder = builder.header("Content-Type", "application/json");
        }
        let request = builder
            .body(Body::from(
                body.map(|value| value.to_string()).unwrap_or_default(),
            ))
            .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes).to_string() }));
        (status, value)
    }

    /// Mark every stored version of `key` as already expired.
    fn expire(&self, key: &str) {
        let conn = rusqlite::Connection::open(self.dir.path().join("sealbox.db")).unwrap();
        let changed = conn
            .execute("UPDATE secrets SET expires_at = 1 WHERE key = ?1", [key])
            .unwrap();
        assert!(
            changed > 0,
            "expected expire({key}) to update at least one row, updated 0"
        );
    }

    /// Mark one specific version of `(namespace, key)` as already expired.
    fn expire_version(&self, namespace: &str, key: &str, version: i32) {
        let conn = rusqlite::Connection::open(self.dir.path().join("sealbox.db")).unwrap();
        let changed = conn
            .execute(
                "UPDATE secrets SET expires_at = 1 WHERE namespace = ?1 AND key = ?2 AND version = ?3",
                (namespace, key, version),
            )
            .unwrap();
        assert_eq!(
            changed, 1,
            "expected expire_version({namespace}, {key}, {version}) to update exactly 1 row"
        );
    }

    /// Count rows stored for `(namespace, key)` directly in SQLite.
    fn row_count(&self, namespace: &str, key: &str) -> i64 {
        let conn = rusqlite::Connection::open(self.dir.path().join("sealbox.db")).unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM secrets WHERE namespace = ?1 AND key = ?2",
            (namespace, key),
            |row| row.get(0),
        )
        .unwrap()
    }

    async fn save_secret_with_options(
        &self,
        token: &str,
        key: &str,
        master_key_id: &str,
        encrypted_data: Vec<u8>,
        ttl: Option<i64>,
        metadata: Option<&str>,
    ) -> (StatusCode, Value) {
        self.json(
            Method::PUT,
            &format!("/v2/secrets/{key}"),
            token,
            Some(json!({
                "encrypted_data": encrypted_data,
                "encrypted_data_key": [9, 8, 7],
                "master_key_id": master_key_id,
                "ttl": ttl,
                "metadata": metadata,
            })),
        )
        .await
    }

    async fn create_tenant(&self, name: &str) -> (String, String) {
        let (status, body) = self
            .json(
                Method::POST,
                "/v2/admin/tenants",
                &self.root_token,
                Some(json!({ "display_name": name, "token_label": "test" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        (
            body["tenant"]["id"].as_str().unwrap().to_string(),
            body["token"].as_str().unwrap().to_string(),
        )
    }

    async fn register_key(&self, token: &str, public_key: &str) -> String {
        let (status, body) = self
            .json(
                Method::POST,
                "/v2/master-key",
                token,
                Some(json!({ "public_key": public_key })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["id"].as_str().unwrap().to_string()
    }

    async fn save_secret(
        &self,
        token: &str,
        key: &str,
        master_key_id: &str,
        encrypted_data: Vec<u8>,
    ) -> (StatusCode, Value) {
        self.json(
            Method::PUT,
            &format!("/v2/secrets/{key}"),
            token,
            Some(json!({
                "encrypted_data": encrypted_data,
                "encrypted_data_key": [9, 8, 7],
                "master_key_id": master_key_id,
                "ttl": null,
                "metadata": "{\"type\":\"test\"}"
            })),
        )
        .await
    }
}

#[tokio::test]
async fn tenants_isolate_identical_keys_metadata_and_deletion() {
    let server = TestServer::new();
    let (tenant_a, token_a) = server.create_tenant("Tenant A").await;
    let (tenant_b, token_b) = server.create_tenant("Tenant B").await;
    let key_a = server.register_key(&token_a, "public-a").await;
    let key_b = server.register_key(&token_b, "public-b").await;

    let (status_a, _) = server
        .save_secret(&token_a, "same-key", &key_a, vec![1, 1, 1])
        .await;
    let (status_b, _) = server
        .save_secret(&token_b, "same-key", &key_b, vec![2, 2, 2])
        .await;
    assert_eq!(status_a, StatusCode::OK);
    assert_eq!(status_b, StatusCode::OK);

    let (_, value_a) = server
        .json(Method::GET, "/v2/secrets/same-key", &token_a, None)
        .await;
    let (_, value_b) = server
        .json(Method::GET, "/v2/secrets/same-key", &token_b, None)
        .await;
    assert_eq!(value_a["namespace"], tenant_a);
    assert_eq!(value_b["namespace"], tenant_b);
    assert_eq!(value_a["encrypted_data"], json!([1, 1, 1]));
    assert_eq!(value_b["encrypted_data"], json!([2, 2, 2]));

    let (status, _) = server
        .json(Method::DELETE, "/v2/secrets/same-key", &token_a, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = server
        .json(Method::GET, "/v2/secrets/same-key", &token_a, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = server
        .json(Method::GET, "/v2/secrets/same-key", &token_b, None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn oversized_encrypted_payload_is_rejected() {
    let server = TestServer::new();
    let (_, token) = server.create_tenant("Tenant").await;
    let key = server.register_key(&token, "public").await;

    // One byte past the largest payload a maximum-size secret can produce.
    let oversized = vec![0u8; sealbox_server::repo::MAX_ENCRYPTED_DATA_BYTES + 1];
    let (status, body) = server.save_secret(&token, "too-big", &key, oversized).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");

    // The boundary itself is accepted so a 500 KB file still round-trips.
    let at_limit = vec![0u8; sealbox_server::repo::MAX_ENCRYPTED_DATA_BYTES];
    let (status, body) = server.save_secret(&token, "at-limit", &key, at_limit).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn tenant_cannot_use_another_tenants_master_key() {
    let server = TestServer::new();
    let (_, token_a) = server.create_tenant("Tenant A").await;
    let (_, token_b) = server.create_tenant("Tenant B").await;
    let key_b = server.register_key(&token_b, "public-b").await;

    let (status, body) = server
        .save_secret(&token_a, "foreign-key", &key_b, vec![1])
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "{body}");
    let (status, _) = server
        .json(
            Method::GET,
            &format!("/v2/master-key/by-id/{key_b}"),
            &token_a,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn root_and_legacy_tokens_do_not_cross_authentication_surfaces() {
    let server = TestServer::new();
    let (tenant_id, tenant_token) = server.create_tenant("Tenant").await;

    let (status, _) = server
        .json(Method::GET, "/v2/secrets", &server.root_token, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = server
        .json(Method::GET, "/v1/secrets", &tenant_token, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = server
        .json(Method::GET, "/v2/admin/tenants", &tenant_token, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = server
        .json(
            Method::POST,
            &format!("/v2/admin/tenants/{tenant_id}/suspend"),
            &server.root_token,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = server
        .json(Method::GET, "/v2/secrets", &tenant_token, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn legacy_v1_routes_can_be_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let config = SealboxConfig {
        auth_token: "root-test-token".to_string(),
        store_path: dir.path().join("sealbox.db").display().to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        legacy_v1_enabled: false,
    };
    let app = create_app(&config).unwrap();
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/secrets")
        .header("Authorization", "Bearer root-test-token")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_backup_returns_restorable_snapshot_for_root_only() {
    let server = TestServer::new();
    let (tenant_id, tenant_token) = server.create_tenant("Tenant").await;
    let master_key_id = server.register_key(&tenant_token, "public-key").await;
    let (status, _) = server
        .save_secret(&tenant_token, "db-password", &master_key_id, vec![1, 2, 3])
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = server
        .json(Method::GET, "/v2/admin/backup", &tenant_token, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/v2/admin/backup")
        .header("Authorization", format!("Bearer {}", server.root_token))
        .body(Body::empty())
        .unwrap();
    let response = server.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "application/vnd.sqlite3"
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let backup_path = dir.path().join("backup.db");
    std::fs::write(&backup_path, &bytes).unwrap();
    let report = sealbox_server::repo::verify_backup(&backup_path).unwrap();
    assert_eq!(report.secret_version_count, 1);
    assert_eq!(report.master_key_count, 1);

    // The snapshot must serve the same data when a server starts from it.
    let restored_store = dir.path().join("restored.db");
    sealbox_server::repo::restore_database(&backup_path, &restored_store, false).unwrap();
    let restored = create_app(&SealboxConfig {
        auth_token: server.root_token.clone(),
        store_path: restored_store.display().to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        legacy_v1_enabled: true,
    })
    .unwrap();
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v2/secrets/db-password")
        .header("Authorization", format!("Bearer {tenant_token}"))
        .body(Body::empty())
        .unwrap();
    let response = restored.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "tenant {tenant_id}");
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["encrypted_data"], json!([1, 2, 3]));
}

#[tokio::test]
async fn legacy_v1_is_disabled_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let config = SealboxConfig {
        store_path: dir.path().join("sealbox.db").display().to_string(),
        ..SealboxConfig::default()
    };
    let app = create_app(&config).unwrap();
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/secrets")
        .header("Authorization", format!("Bearer {}", config.auth_token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn enabled_v1_responses_carry_deprecation_headers() {
    let server = TestServer::new();
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/secrets")
        .header("Authorization", format!("Bearer {}", server.root_token))
        .body(Body::empty())
        .unwrap();

    let response = server.app.clone().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["deprecation"], "true");
    assert_eq!(
        response.headers()["sunset"],
        sealbox_server::config::LEGACY_V1_SUNSET_HTTP_DATE
    );

    let request = Request::builder()
        .method(Method::GET)
        .uri("/v2/admin/tenants")
        .header("Authorization", format!("Bearer {}", server.root_token))
        .body(Body::empty())
        .unwrap();
    let response = server.app.clone().oneshot(request).await.unwrap();
    assert!(response.headers().get("deprecation").is_none());
}

/// Pre-tenant data lives in the `legacy` tenant. Issuing a token for it is the
/// migration path from v1 to v2.
#[tokio::test]
async fn legacy_tenant_token_reads_v1_data_over_v2() {
    let server = TestServer::new();
    let (status, key) = server
        .json(
            Method::POST,
            "/v1/master-key",
            &server.root_token,
            Some(json!({ "public_key": "legacy-public-key" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{key}");
    let (status, _) = server
        .json(
            Method::PUT,
            "/v1/secrets/old-secret",
            &server.root_token,
            Some(json!({
                "encrypted_data": [4, 5, 6],
                "encrypted_data_key": [9, 8, 7],
                "master_key_id": key["id"],
                "ttl": null,
                "metadata": null
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, issued) = server
        .json(
            Method::POST,
            "/v2/admin/tenants/legacy/tokens",
            &server.root_token,
            Some(json!({ "label": "v1 migration" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let legacy_token = issued["token"].as_str().unwrap();

    let (status, secret) = server
        .json(Method::GET, "/v2/secrets/old-secret", legacy_token, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{secret}");
    assert_eq!(secret["encrypted_data"], json!([4, 5, 6]));
    let (status, keys) = server
        .json(Method::GET, "/v2/master-key", legacy_token, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(keys["master_keys"][0]["id"], key["id"]);
}

#[tokio::test]
async fn cleanup_expired_is_tenant_scoped_for_tenants_and_global_for_root() {
    let server = TestServer::new();
    let (_, token_a) = server.create_tenant("Tenant A").await;
    let (_, token_b) = server.create_tenant("Tenant B").await;
    let key_a = server.register_key(&token_a, "public-a").await;
    let key_b = server.register_key(&token_b, "public-b").await;
    let (s, body) = server
        .save_secret(&token_a, "expired-a", &key_a, vec![1])
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let (s, body) = server
        .save_secret(&token_b, "expired-b", &key_b, vec![2])
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    server.expire("expired-a");
    server.expire("expired-b");

    let (status, _) = server
        .json(
            Method::DELETE,
            "/v2/cleanup-expired",
            &server.root_token,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = server
        .json(Method::DELETE, "/v2/admin/cleanup-expired", &token_a, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = server
        .json(Method::DELETE, "/v2/cleanup-expired", &token_a, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted_count"], 1);

    let (status, body) = server
        .json(
            Method::DELETE,
            "/v2/admin/cleanup-expired",
            &server.root_token,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["deleted_count"], 1,
        "tenant B's secret remained until root cleanup"
    );
}

#[tokio::test]
async fn expired_newest_version_ends_whole_key_across_reads_listings_writes_and_deletes() {
    let server = TestServer::new();
    let (tenant_id, token) = server.create_tenant("Tenant Expiry").await;
    let mk_id = server.register_key(&token, "public-expiry").await;

    let cases: [(&str, Option<&str>); 3] = [
        ("ended-secret", None),
        (
            "ended-cred",
            Some(r#"{"type":"credential","username":"demo"}"#),
        ),
        ("ended-file", Some(r#"{"type":"file","filename":"a.txt"}"#)),
    ];

    for (key, meta) in cases {
        let (s1, _) = server
            .save_secret_with_options(&token, key, &mk_id, vec![1], None, meta)
            .await;
        assert_eq!(s1, StatusCode::OK);
        let (s2, _) = server
            .save_secret_with_options(&token, key, &mk_id, vec![2], Some(3600), meta)
            .await;
        assert_eq!(s2, StatusCode::OK);
        server.expire_version(&tenant_id, key, 2);
    }

    // Active key with expired v1 and permanent v2.
    let (s1, body1) = server
        .save_secret_with_options(&token, "active-key", &mk_id, vec![10], Some(3600), None)
        .await;
    assert_eq!(s1, StatusCode::OK, "{body1}");
    let (s2, body2) = server
        .save_secret_with_options(&token, "active-key", &mk_id, vec![20], None, None)
        .await;
    assert_eq!(s2, StatusCode::OK, "{body2}");
    server.expire_version(&tenant_id, "active-key", 1);

    // Active key for verifying single-version delete of an expired older row returns 200 OK.
    let (s1, body1) = server
        .save_secret_with_options(
            &token,
            "delete-expired-older",
            &mk_id,
            vec![30],
            Some(3600),
            None,
        )
        .await;
    assert_eq!(s1, StatusCode::OK, "{body1}");
    let (s2, body2) = server
        .save_secret_with_options(&token, "delete-expired-older", &mk_id, vec![40], None, None)
        .await;
    assert_eq!(s2, StatusCode::OK, "{body2}");
    server.expire_version(&tenant_id, "delete-expired-older", 1);

    // Keys for testing write-before-cleanup and delete-by-version revival guards.
    for key in ["write-revival", "delete-ver-revival"] {
        let (s1, body1) = server
            .save_secret_with_options(&token, key, &mk_id, vec![1], None, None)
            .await;
        assert_eq!(s1, StatusCode::OK, "{key} v1: {body1}");
        let (s2, body2) = server
            .save_secret_with_options(&token, key, &mk_id, vec![2], Some(3600), None)
            .await;
        assert_eq!(s2, StatusCode::OK, "{key} v2: {body2}");
        server.expire_version(&tenant_id, key, 2);
    }

    // Listings omit every key whose newest version has expired while keeping active keys.
    let (status, list_body) = server.json(Method::GET, "/v2/secrets", &token, None).await;
    assert_eq!(status, StatusCode::OK);
    let mut listed_keys: Vec<&str> = list_body["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["key"].as_str().unwrap())
        .collect();
    listed_keys.sort_unstable();
    assert_eq!(listed_keys, vec!["active-key", "delete-expired-older"]);

    // History returns 404 for expired-newest keys and shows only v2 for active-key.
    for (key, _) in cases {
        let (status, _) = server
            .json(
                Method::GET,
                &format!("/v2/secrets/{key}/history"),
                &token,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "history for {key}");
    }
    let (status, active_history) = server
        .json(Method::GET, "/v2/secrets/active-key/history", &token, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(active_history["versions"].as_array().unwrap().len(), 1);
    assert_eq!(active_history["versions"][0]["version"], 2);

    // Reading an older version or latest version returns 404 and deletes all rows from SQLite.
    let (status, _) = server
        .json(
            Method::GET,
            "/v2/secrets/ended-secret?version=1",
            &token,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(server.row_count(&tenant_id, "ended-secret"), 0);

    let (status, _) = server
        .json(Method::GET, "/v2/secrets/ended-cred", &token, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(server.row_count(&tenant_id, "ended-cred"), 0);

    let (status, _) = server
        .json(
            Method::GET,
            "/v2/secrets/ended-file?version=1",
            &token,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(server.row_count(&tenant_id, "ended-file"), 0);

    // Active key still reads v2 cleanly and lazily removes its expired v1.
    let (status, active_body) = server
        .json(Method::GET, "/v2/secrets/active-key", &token, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(active_body["version"], 2);
    assert_eq!(active_body["encrypted_data"], json!([20]));
    assert_eq!(server.row_count(&tenant_id, "active-key"), 1);

    // Writing to an expired key before cleanup clears all expired rows and restarts at version 1.
    let (status, written) = server
        .save_secret_with_options(&token, "write-revival", &mk_id, vec![3], None, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(written["version"], 1);
    assert_eq!(server.row_count(&tenant_id, "write-revival"), 1);
    let (status, history) = server
        .json(
            Method::GET,
            "/v2/secrets/write-revival/history",
            &token,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(history["versions"].as_array().unwrap().len(), 1);
    assert_eq!(history["versions"][0]["version"], 1);

    // Deleting an existing expired older version under a live newest version returns 200 OK
    // and keeps the live newest version readable.
    let (status, _) = server
        .json(
            Method::DELETE,
            "/v2/secrets/delete-expired-older?version=1",
            &token,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(server.row_count(&tenant_id, "delete-expired-older"), 1);
    let (status, live_body) = server
        .json(
            Method::GET,
            "/v2/secrets/delete-expired-older",
            &token,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(live_body["version"], 2);
    assert_eq!(live_body["encrypted_data"], json!([40]));

    // Deleting the expired newest version before cleanup deletes the whole key and returns 404.
    let (status, _) = server
        .json(
            Method::DELETE,
            "/v2/secrets/delete-ver-revival?version=2",
            &token,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(server.row_count(&tenant_id, "delete-ver-revival"), 0);
}

#[tokio::test]
async fn cleanup_expired_and_startup_remove_all_versions_of_expired_keys_and_isolate_tenants() {
    let server = TestServer::new();
    let (tenant_a, token_a) = server.create_tenant("Tenant A").await;
    let (tenant_b, token_b) = server.create_tenant("Tenant B").await;
    let mk_a = server.register_key(&token_a, "public-a").await;
    let mk_b = server.register_key(&token_b, "public-b").await;

    // Tenant A: expired-newest (2 rows), active with expired v1 (2 rows), permanent (1 row).
    let (s, body) = server
        .save_secret_with_options(&token_a, "ended-a", &mk_a, vec![1], None, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let (s, body) = server
        .save_secret_with_options(&token_a, "ended-a", &mk_a, vec![2], Some(3600), None)
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    server.expire_version(&tenant_a, "ended-a", 2);

    let (s, body) = server
        .save_secret_with_options(&token_a, "active-a", &mk_a, vec![1], Some(3600), None)
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let (s, body) = server
        .save_secret_with_options(&token_a, "active-a", &mk_a, vec![2], None, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    server.expire_version(&tenant_a, "active-a", 1);

    let (s, body) = server
        .save_secret_with_options(&token_a, "perm-a", &mk_a, vec![9], None, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");

    // Tenant B: expired-newest (2 rows) and another expired-newest for startup test.
    let (s, body) = server
        .save_secret_with_options(&token_b, "ended-b", &mk_b, vec![1], None, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let (s, body) = server
        .save_secret_with_options(&token_b, "ended-b", &mk_b, vec![2], Some(3600), None)
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    server.expire_version(&tenant_b, "ended-b", 2);

    // Tenant A cleanup removes ended-a (2 rows) + expired v1 of active-a (1 row) = 3 rows.
    let (status, body) = server
        .json(Method::DELETE, "/v2/cleanup-expired", &token_a, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted_count"], 3);
    assert_eq!(server.row_count(&tenant_a, "ended-a"), 0);
    assert_eq!(server.row_count(&tenant_a, "active-a"), 1);
    assert_eq!(server.row_count(&tenant_a, "perm-a"), 1);
    // Tenant B is untouched.
    assert_eq!(server.row_count(&tenant_b, "ended-b"), 2);

    // Admin cleanup removes Tenant B's 2 rows across all versions.
    let (status, body) = server
        .json(
            Method::DELETE,
            "/v2/admin/cleanup-expired",
            &server.root_token,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted_count"], 2);
    assert_eq!(server.row_count(&tenant_b, "ended-b"), 0);

    // Create another expired-newest key for Tenant B and verify server startup cleanup removes all versions.
    let (s, body) = server
        .save_secret_with_options(&token_b, "startup-ended-b", &mk_b, vec![1], None, None)
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let (s, body) = server
        .save_secret_with_options(
            &token_b,
            "startup-ended-b",
            &mk_b,
            vec![2],
            Some(3600),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    server.expire_version(&tenant_b, "startup-ended-b", 2);
    assert_eq!(server.row_count(&tenant_b, "startup-ended-b"), 2);

    let restarted = create_app(&SealboxConfig {
        auth_token: server.root_token.clone(),
        store_path: server.dir.path().join("sealbox.db").display().to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        legacy_v1_enabled: false,
    })
    .unwrap();
    assert_eq!(server.row_count(&tenant_b, "startup-ended-b"), 0);
    assert_eq!(server.row_count(&tenant_a, "active-a"), 1);
    assert_eq!(server.row_count(&tenant_a, "perm-a"), 1);

    // Active key remains readable on the restarted server.
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v2/secrets/active-a")
        .header("Authorization", format!("Bearer {token_a}"))
        .body(Body::empty())
        .unwrap();
    let response = restarted.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn same_key_name_cross_tenant_isolation_on_expiry_reads_writes_deletes_and_cleanups() {
    let server = TestServer::new();
    let (tenant_a, token_a) = server.create_tenant("Tenant Iso A").await;
    let (tenant_b, token_b) = server.create_tenant("Tenant Iso B").await;
    let mk_a = server.register_key(&token_a, "public-iso-a").await;
    let mk_b = server.register_key(&token_b, "public-iso-b").await;

    // Seed identical key names with overlapping version numbers in both tenants:
    // Tenant A has expired newest version; Tenant B has active permanent versions.
    for key in [
        "shared-read",
        "shared-write",
        "shared-del",
        "shared-tenant-clean",
    ] {
        for (data, ttl) in [(vec![1u8], None), (vec![2u8], Some(3600))] {
            let (s, body) = server
                .save_secret_with_options(&token_a, key, &mk_a, data, ttl, None)
                .await;
            assert_eq!(s, StatusCode::OK, "tenant A {key}: {body}");
        }
        server.expire_version(&tenant_a, key, 2);

        for data in [vec![11u8], vec![12u8]] {
            let (s, body) = server
                .save_secret_with_options(&token_b, key, &mk_b, data, None, None)
                .await;
            assert_eq!(s, StatusCode::OK, "tenant B {key}: {body}");
        }
    }

    // All-tenant cleanup case: Tenant A has v1/v2 permanent + v3 expired; Tenant B has v1/v2 active.
    for (data, ttl) in [
        (vec![1u8], None),
        (vec![2u8], None),
        (vec![3u8], Some(3600)),
    ] {
        let (s, body) = server
            .save_secret_with_options(&token_a, "shared-all-clean", &mk_a, data, ttl, None)
            .await;
        assert_eq!(s, StatusCode::OK, "{body}");
    }
    server.expire_version(&tenant_a, "shared-all-clean", 3);
    for data in [vec![21u8], vec![22u8]] {
        let (s, body) = server
            .save_secret_with_options(&token_b, "shared-all-clean", &mk_b, data, None, None)
            .await;
        assert_eq!(s, StatusCode::OK, "{body}");
    }

    // 1. Read in tenant A lazily removes only tenant A's rows.
    let (status, _) = server
        .json(Method::GET, "/v2/secrets/shared-read", &token_a, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(server.row_count(&tenant_a, "shared-read"), 0);
    assert_eq!(server.row_count(&tenant_b, "shared-read"), 2);

    // 2. Write in tenant A clears only tenant A's expired key and restarts tenant A at v1.
    let (status, body) = server
        .save_secret_with_options(&token_a, "shared-write", &mk_a, vec![99], None, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["version"], 1);
    assert_eq!(server.row_count(&tenant_a, "shared-write"), 1);
    assert_eq!(server.row_count(&tenant_b, "shared-write"), 2);

    // 3. Single-version delete in tenant A clears only tenant A's expired key.
    let (status, _) = server
        .json(
            Method::DELETE,
            "/v2/secrets/shared-del?version=2",
            &token_a,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(server.row_count(&tenant_a, "shared-del"), 0);
    assert_eq!(server.row_count(&tenant_b, "shared-del"), 2);

    // 4. Per-tenant cleanup for tenant A removes tenant A's expired keys only.
    let (status, body) = server
        .json(Method::DELETE, "/v2/cleanup-expired", &token_a, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // 2 rows from shared-tenant-clean + 3 rows from shared-all-clean = 5.
    assert_eq!(body["deleted_count"], 5);
    assert_eq!(server.row_count(&tenant_a, "shared-tenant-clean"), 0);
    assert_eq!(server.row_count(&tenant_a, "shared-all-clean"), 0);
    assert_eq!(server.row_count(&tenant_b, "shared-tenant-clean"), 2);
    assert_eq!(server.row_count(&tenant_b, "shared-all-clean"), 2);

    // 5. Seed another expired same-named key in tenant A and run all-tenant cleanup:
    //    must delete tenant A's 3 rows while leaving tenant B's active 2 rows intact.
    for (data, ttl) in [
        (vec![4u8], None),
        (vec![5u8], None),
        (vec![6u8], Some(3600)),
    ] {
        let (s, body) = server
            .save_secret_with_options(&token_a, "shared-all-clean", &mk_a, data, ttl, None)
            .await;
        assert_eq!(s, StatusCode::OK, "{body}");
    }
    server.expire_version(&tenant_a, "shared-all-clean", 3);

    let (status, body) = server
        .json(
            Method::DELETE,
            "/v2/admin/cleanup-expired",
            &server.root_token,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted_count"], 3);
    assert_eq!(server.row_count(&tenant_a, "shared-all-clean"), 0);
    assert_eq!(server.row_count(&tenant_b, "shared-all-clean"), 2);
    let (status, b_body) = server
        .json(Method::GET, "/v2/secrets/shared-all-clean", &token_b, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(b_body["encrypted_data"], json!([22]));
}
