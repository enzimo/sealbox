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
        conn.execute("UPDATE secrets SET expires_at = 1 WHERE key = ?1", [key])
            .unwrap();
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
    server
        .save_secret(&token_a, "expired-a", &key_a, vec![1])
        .await;
    server
        .save_secret(&token_b, "expired-b", &key_b, vec![2])
        .await;
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
