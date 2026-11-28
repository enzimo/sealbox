use axum::{
    Extension,
    extract::{Json, State},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use tracing::error;
use uuid::Uuid;

use crate::{
    api::{SealboxResponse, Version, auth::TenantPrincipal, path::Path, state::AppState},
    error::{Result, SealboxError},
    repo::{LEGACY_TENANT_ID, MasterKey, MasterKeyStatus, encrypted_data_key_digest},
};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct MasterKeyPathParams {
    version: Version,
}

impl MasterKeyPathParams {
    fn version(&self) -> Version {
        self.version.clone()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct MasterKeyIdPathParams {
    version: Version,
    master_key_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct TenantMasterKeyIdPathParams {
    master_key_id: Uuid,
}

impl MasterKeyIdPathParams {
    fn version(&self) -> Version {
        self.version.clone()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct RotateMasterKeyPayload {
    new_master_key_id: Uuid,
    old_master_key_id: Uuid,
    updates: Vec<RewrappedSecretDataKey>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct RewrappedSecretDataKey {
    namespace: String,
    key: String,
    version: i32,
    /// `sha256:<hex>` digest of the `encrypted_data_key` fetched before rewrapping.
    /// Binds this update to the exact stored row so a stale update can never land
    /// on a re-saved row that reused the same version number.
    previous_encrypted_data_key_sha256: String,
    encrypted_data_key: Vec<u8>,
}

// GET /{version}/master-key
pub(crate) async fn list(
    State(state): State<AppState>,
    Path(params): Path<MasterKeyPathParams>,
) -> Result<SealboxResponse> {
    match params.version() {
        Version::V1 => {
            let conn = state.conn_pool.lock()?;
            let master_keys = state
                .master_key_repo
                .fetch_all_master_keys(&conn, LEGACY_TENANT_ID)?;
            Ok(SealboxResponse::Json(json!({ "master_keys": master_keys })))
        }
        _ => Err(SealboxError::InvalidApiVersion),
    }
}

// GET /{version}/master-key/active
pub(crate) async fn active(
    State(state): State<AppState>,
    Path(params): Path<MasterKeyPathParams>,
) -> Result<SealboxResponse> {
    match params.version() {
        Version::V1 => {
            let conn = state.conn_pool.lock()?;
            let master_key = state
                .master_key_repo
                .get_valid_master_key(&conn, LEGACY_TENANT_ID)?;
            Ok(SealboxResponse::Json(json!(master_key)))
        }
        _ => Err(SealboxError::InvalidApiVersion),
    }
}

// GET /{version}/master-key/by-id/{master_key_id}
pub(crate) async fn get(
    State(state): State<AppState>,
    Path(params): Path<MasterKeyIdPathParams>,
) -> Result<SealboxResponse> {
    match params.version() {
        Version::V1 => {
            let conn = state.conn_pool.lock()?;
            let master_key = state
                .master_key_repo
                .fetch_master_key(&conn, LEGACY_TENANT_ID, &params.master_key_id)?
                .ok_or(SealboxError::MasterKeyNotFound(params.master_key_id))?;
            Ok(SealboxResponse::Json(json!(master_key)))
        }
        _ => Err(SealboxError::InvalidApiVersion),
    }
}

// GET /{version}/master-key/by-id/{master_key_id}/secrets
pub(crate) async fn secrets(
    State(state): State<AppState>,
    Path(params): Path<MasterKeyIdPathParams>,
) -> Result<SealboxResponse> {
    match params.version() {
        Version::V1 => {
            let conn = state.conn_pool.lock()?;
            let _master_key = state
                .master_key_repo
                .fetch_master_key(&conn, LEGACY_TENANT_ID, &params.master_key_id)?
                .ok_or(SealboxError::MasterKeyNotFound(params.master_key_id))?;
            state
                .secret_repo
                .cleanup_expired_secrets_in_namespace(&conn, LEGACY_TENANT_ID)?;
            let secrets = state.secret_repo.fetch_secrets_by_master_key(
                &conn,
                LEGACY_TENANT_ID,
                &params.master_key_id,
            )?;
            Ok(SealboxResponse::Json(json!({ "secrets": secrets })))
        }
        _ => Err(SealboxError::InvalidApiVersion),
    }
}

// PUT /{version}/master-key
pub(crate) async fn rotate(
    State(state): State<AppState>,
    Path(params): Path<MasterKeyPathParams>,
    Json(payload): Json<RotateMasterKeyPayload>,
) -> Result<SealboxResponse> {
    match params.version() {
        Version::V1 => rotate_for_namespace(&state, LEGACY_TENANT_ID, payload),
        _ => Err(SealboxError::InvalidApiVersion),
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct CreateMasterKeyPayload {
    public_key: String,
}

// POST /{version}/master-key
pub(crate) async fn create(
    State(state): State<AppState>,
    Path(params): Path<MasterKeyPathParams>,
    Json(payload): Json<CreateMasterKeyPayload>,
) -> Result<SealboxResponse> {
    match params.version() {
        Version::V1 => {
            let conn = state.conn_pool.lock()?;
            let mut master_key = MasterKey::new(payload.public_key)?;
            if state
                .master_key_repo
                .get_valid_master_key(&conn, LEGACY_TENANT_ID)
                .is_ok()
            {
                master_key.status = MasterKeyStatus::Retired;
            }
            state
                .master_key_repo
                .create_master_key(&conn, &master_key)?;
            Ok(SealboxResponse::Json(json!(master_key)))
        }
        _ => Err(SealboxError::InvalidApiVersion),
    }
}

pub(crate) async fn list_v2(
    State(state): State<AppState>,
    Extension(principal): Extension<TenantPrincipal>,
) -> Result<SealboxResponse> {
    let conn = state.conn_pool.lock()?;
    let keys = state
        .master_key_repo
        .fetch_all_master_keys(&conn, &principal.tenant_id)?;
    Ok(SealboxResponse::Json(json!({ "master_keys": keys })))
}

pub(crate) async fn active_v2(
    State(state): State<AppState>,
    Extension(principal): Extension<TenantPrincipal>,
) -> Result<SealboxResponse> {
    let conn = state.conn_pool.lock()?;
    let key = state
        .master_key_repo
        .get_valid_master_key(&conn, &principal.tenant_id)?;
    Ok(SealboxResponse::Json(json!(key)))
}

pub(crate) async fn get_v2(
    State(state): State<AppState>,
    Extension(principal): Extension<TenantPrincipal>,
    Path(params): Path<TenantMasterKeyIdPathParams>,
) -> Result<SealboxResponse> {
    let conn = state.conn_pool.lock()?;
    let key = state
        .master_key_repo
        .fetch_master_key(&conn, &principal.tenant_id, &params.master_key_id)?
        .ok_or(SealboxError::MasterKeyNotFound(params.master_key_id))?;
    Ok(SealboxResponse::Json(json!(key)))
}

pub(crate) async fn secrets_v2(
    State(state): State<AppState>,
    Extension(principal): Extension<TenantPrincipal>,
    Path(params): Path<TenantMasterKeyIdPathParams>,
) -> Result<SealboxResponse> {
    let conn = state.conn_pool.lock()?;
    state
        .master_key_repo
        .fetch_master_key(&conn, &principal.tenant_id, &params.master_key_id)?
        .ok_or(SealboxError::MasterKeyNotFound(params.master_key_id))?;
    state
        .secret_repo
        .cleanup_expired_secrets_in_namespace(&conn, &principal.tenant_id)?;
    let secrets = state.secret_repo.fetch_secrets_by_master_key(
        &conn,
        &principal.tenant_id,
        &params.master_key_id,
    )?;
    Ok(SealboxResponse::Json(json!({ "secrets": secrets })))
}

pub(crate) async fn create_v2(
    State(state): State<AppState>,
    Extension(principal): Extension<TenantPrincipal>,
    Json(payload): Json<CreateMasterKeyPayload>,
) -> Result<SealboxResponse> {
    let conn = state.conn_pool.lock()?;
    let mut key = MasterKey::new_in_namespace(principal.tenant_id.clone(), payload.public_key)?;
    if state
        .master_key_repo
        .get_valid_master_key(&conn, &principal.tenant_id)
        .is_ok()
    {
        key.status = MasterKeyStatus::Retired;
    }
    state.master_key_repo.create_master_key(&conn, &key)?;
    Ok(SealboxResponse::Json(json!(key)))
}

pub(crate) async fn rotate_v2(
    State(state): State<AppState>,
    Extension(principal): Extension<TenantPrincipal>,
    Json(payload): Json<RotateMasterKeyPayload>,
) -> Result<SealboxResponse> {
    rotate_for_namespace(&state, &principal.tenant_id, payload)
}

fn rotate_for_namespace(
    state: &AppState,
    namespace: &str,
    payload: RotateMasterKeyPayload,
) -> Result<SealboxResponse> {
    let new_master_key_id = payload.new_master_key_id;
    let old_master_key_id = payload.old_master_key_id;
    if old_master_key_id == new_master_key_id {
        return Err(SealboxError::InvalidRequest(
            "old and new master key ids must be different".to_string(),
        ));
    }
    let mut conn = state.conn_pool.lock()?;
    state
        .master_key_repo
        .fetch_master_key(&conn, namespace, &old_master_key_id)?
        .ok_or(SealboxError::MasterKeyNotFound(old_master_key_id))?;
    state
        .master_key_repo
        .fetch_master_key(&conn, namespace, &new_master_key_id)?
        .ok_or(SealboxError::MasterKeyNotFound(new_master_key_id))?;

    let mut updates_by_secret = HashMap::new();
    for update in payload.updates {
        if update.namespace != namespace {
            return Err(SealboxError::InvalidRequest(
                "rewrapped secret namespace does not match authenticated tenant".to_string(),
            ));
        }
        let key = (update.namespace, update.key, update.version);
        if updates_by_secret
            .insert(
                key,
                (
                    update.previous_encrypted_data_key_sha256,
                    update.encrypted_data_key,
                ),
            )
            .is_some()
        {
            return Err(SealboxError::InvalidRequest(
                "duplicate rewrapped secret update".to_string(),
            ));
        }
    }

    let tx = conn.transaction()?;
    state
        .secret_repo
        .cleanup_expired_secrets_in_namespace(&tx, namespace)?;
    let secrets =
        state
            .secret_repo
            .fetch_secrets_by_master_key(&tx, namespace, &old_master_key_id)?;

    for secret in secrets {
        let update_key = (secret.namespace.clone(), secret.key.clone(), secret.version);
        let Some((expected_previous_digest, encrypted_data_key)) =
            updates_by_secret.remove(&update_key)
        else {
            return Err(SealboxError::InvalidRequest(format!(
                "missing rewrapped data key for {} version {}",
                secret.key, secret.version
            )));
        };
        let actual_digest = encrypted_data_key_digest(&secret.encrypted_data_key);
        if expected_previous_digest != actual_digest {
            return Err(SealboxError::InvalidRequest(format!(
                "stale rewrapped data key for {} version {}: row changed since fetch",
                secret.key, secret.version
            )));
        }
        let expected_encrypted_data_key = secret.encrypted_data_key.clone();
        let mut rotated = secret;
        rotated.encrypted_data_key = encrypted_data_key;
        rotated.master_key_id = new_master_key_id;
        rotated.updated_at = time::OffsetDateTime::now_utc().unix_timestamp();
        if let Err(err) = state.secret_repo.update_secret_master_key(
            &tx,
            &rotated,
            &old_master_key_id,
            &expected_encrypted_data_key,
        ) {
            error!(
                "Failed to update rewrapped data key for secret {}: {}",
                rotated.key, err
            );
            return Err(err);
        }
    }

    // Reject the whole rotation if any supplied update did not match a fetched
    // row under `old_master_key_id` (for example, a row expired, was deleted,
    // or belongs to another master key). Because all updates run inside `tx`,
    // nothing is mutated and the operator can safely retry rotation.
    if let Some((_, extra_key, extra_version)) = updates_by_secret.into_keys().next() {
        return Err(SealboxError::InvalidRequest(format!(
            "unexpected or stale rewrapped data key for {extra_key} version {extra_version}: row is missing or changed since fetch"
        )));
    }

    tx.execute(
        "UPDATE master_keys SET status = ?1 WHERE namespace = ?2 AND id = ?3",
        rusqlite::params![MasterKeyStatus::Retired, namespace, old_master_key_id],
    )?;
    tx.execute(
        "UPDATE master_keys SET status = ?1 WHERE namespace = ?2 AND id = ?3",
        rusqlite::params![MasterKeyStatus::Active, namespace, new_master_key_id],
    )?;
    tx.commit()?;
    Ok(SealboxResponse::Json(
        json!({ "master_key": new_master_key_id }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::{Version, path::Path as SealboxPath, state::AppState},
        config::SealboxConfig,
        crypto::master_key::generate_key_pair,
        repo::{SqliteHealthRepo, SqliteMasterKeyRepo, SqliteSecretRepo, SqliteTenantRepo},
    };
    use axum::extract::State;
    use std::sync::{Arc, Mutex};

    fn setup_test_state() -> AppState {
        let conn = rusqlite::Connection::open_in_memory().expect("Should create in-memory DB");
        crate::repo::SqliteMasterKeyRepo::init_table(&conn).expect("Should init master_keys table");
        crate::repo::SqliteSecretRepo::init_table(&conn).expect("Should init secrets table");
        crate::repo::SqliteTenantRepo::init_tables(&conn).expect("Should init tenants tables");

        AppState {
            conn_pool: Arc::new(Mutex::new(conn)),
            master_key_repo: Arc::new(SqliteMasterKeyRepo),
            secret_repo: Arc::new(SqliteSecretRepo),
            health_repo: Arc::new(SqliteHealthRepo),
            tenant_repo: Arc::new(SqliteTenantRepo),
            config: Arc::new(SealboxConfig::default()),
        }
    }

    #[tokio::test]
    async fn test_create_master_key() {
        let state = setup_test_state();
        let (_, public_pem) = generate_key_pair().expect("Should generate key pair");

        let path_params = MasterKeyPathParams {
            version: Version::V1,
        };
        let payload = CreateMasterKeyPayload {
            public_key: public_pem.clone(),
        };

        let result = create(
            State(state.clone()),
            SealboxPath(path_params),
            Json(payload),
        )
        .await;

        assert!(result.is_ok());
        match result.unwrap() {
            SealboxResponse::Json(json_value) => {
                let master_key: MasterKey =
                    serde_json::from_value(json_value).expect("Should deserialize MasterKey");
                assert_eq!(master_key.public_key, public_pem);
            }
            _ => panic!("Expected JSON response"),
        }
    }

    #[tokio::test]
    async fn test_create_master_key_invalid_version() {
        let state = setup_test_state();
        let (_, public_pem) = generate_key_pair().expect("Should generate key pair");

        let path_params = MasterKeyPathParams {
            version: Version::V2,
        }; // Invalid version
        let payload = CreateMasterKeyPayload {
            public_key: public_pem,
        };

        let result = create(State(state), SealboxPath(path_params), Json(payload)).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SealboxError::InvalidApiVersion => {} // Expected
            _ => panic!("Expected InvalidApiVersion error"),
        }
    }

    #[tokio::test]
    async fn test_list_master_keys_empty() {
        let state = setup_test_state();
        let path_params = MasterKeyPathParams {
            version: Version::V1,
        };

        let result = list(State(state), Path(path_params)).await;

        assert!(result.is_ok());
        match result.unwrap() {
            SealboxResponse::Json(json_value) => {
                let keys = json_value
                    .get("master_keys")
                    .and_then(|value| value.as_array())
                    .expect("Should include master_keys");
                assert_eq!(keys.len(), 0);
            }
            _ => panic!("Expected JSON response"),
        }
    }

    #[tokio::test]
    async fn test_list_master_keys_with_data() {
        let state = setup_test_state();
        let (_, public_pem) = generate_key_pair().expect("Should generate key pair");

        // First create a master key
        let path_params = MasterKeyPathParams {
            version: Version::V1,
        };
        let payload = CreateMasterKeyPayload {
            public_key: public_pem.clone(),
        };

        let _create_result = create(
            State(state.clone()),
            Path(path_params.clone()),
            Json(payload),
        )
        .await
        .expect("Should create master key");

        // Then list all master keys
        let result = list(State(state), Path(path_params)).await;

        assert!(result.is_ok());
        match result.unwrap() {
            SealboxResponse::Json(json_value) => {
                let keys: Vec<MasterKey> = serde_json::from_value(
                    json_value
                        .get("master_keys")
                        .expect("Should include master_keys")
                        .clone(),
                )
                .expect("Should deserialize Vec<MasterKey>");
                assert_eq!(keys.len(), 1);
                assert_eq!(keys[0].public_key, "[HIDDEN]"); // Public key is hidden in list API for security
            }
            _ => panic!("Expected JSON response"),
        }
    }

    #[tokio::test]
    async fn test_active_master_key_returns_public_key() {
        let state = setup_test_state();
        let (_, public_pem) = generate_key_pair().expect("Should generate key pair");
        let path_params = MasterKeyPathParams {
            version: Version::V1,
        };

        create(
            State(state.clone()),
            Path(path_params.clone()),
            Json(CreateMasterKeyPayload {
                public_key: public_pem.clone(),
            }),
        )
        .await
        .expect("Should create master key");

        let result = active(State(state), Path(path_params))
            .await
            .expect("Should fetch active master key");

        match result {
            SealboxResponse::Json(json_value) => {
                let master_key: MasterKey =
                    serde_json::from_value(json_value).expect("Should deserialize MasterKey");
                assert_eq!(master_key.public_key, public_pem);
                assert!(matches!(master_key.status, MasterKeyStatus::Active));
            }
            _ => panic!("Expected JSON response"),
        }
    }

    #[tokio::test]
    async fn test_create_second_master_key_is_retired() {
        let state = setup_test_state();
        let (_, first_public_pem) = generate_key_pair().expect("Should generate first key pair");
        let (_, second_public_pem) = generate_key_pair().expect("Should generate second key pair");
        let path_params = MasterKeyPathParams {
            version: Version::V1,
        };

        create(
            State(state.clone()),
            Path(path_params.clone()),
            Json(CreateMasterKeyPayload {
                public_key: first_public_pem,
            }),
        )
        .await
        .expect("Should create first master key");

        let result = create(
            State(state),
            Path(path_params),
            Json(CreateMasterKeyPayload {
                public_key: second_public_pem,
            }),
        )
        .await
        .expect("Should create second master key");

        match result {
            SealboxResponse::Json(json_value) => {
                let master_key: MasterKey =
                    serde_json::from_value(json_value).expect("Should deserialize MasterKey");
                assert!(matches!(master_key.status, MasterKeyStatus::Retired));
            }
            _ => panic!("Expected JSON response"),
        }
    }

    #[tokio::test]
    async fn test_list_master_keys_invalid_version() {
        let state = setup_test_state();
        let path_params = MasterKeyPathParams {
            version: Version::V2,
        }; // Invalid version

        let result = list(State(state), Path(path_params)).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SealboxError::InvalidApiVersion => {} // Expected
            _ => panic!("Expected InvalidApiVersion error"),
        }
    }

    #[tokio::test]
    async fn test_rotate_master_key_not_found() {
        let state = setup_test_state();
        let old_master_key_id = uuid::Uuid::new_v4();
        let new_master_key_id = uuid::Uuid::new_v4();

        let path_params = MasterKeyPathParams {
            version: Version::V1,
        };
        let payload = RotateMasterKeyPayload {
            old_master_key_id,
            new_master_key_id,
            updates: Vec::new(),
        };

        let result = rotate(State(state), SealboxPath(path_params), Json(payload)).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SealboxError::MasterKeyNotFound(_) => {} // Expected
            _ => panic!("Expected MasterKeyNotFound error"),
        }
    }

    #[tokio::test]
    async fn test_rotate_master_key_invalid_version() {
        let state = setup_test_state();
        let old_master_key_id = uuid::Uuid::new_v4();
        let new_master_key_id = uuid::Uuid::new_v4();

        let path_params = MasterKeyPathParams {
            version: Version::V2,
        }; // Invalid version
        let payload = RotateMasterKeyPayload {
            old_master_key_id,
            new_master_key_id,
            updates: Vec::new(),
        };

        let result = rotate(State(state), SealboxPath(path_params), Json(payload)).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SealboxError::InvalidApiVersion => {} // Expected
            _ => panic!("Expected InvalidApiVersion error"),
        }
    }

    #[tokio::test]
    async fn test_master_key_secrets_and_rotate_clean_up_expired_keys() {
        let state = setup_test_state();
        let (_, first_public_pem) = generate_key_pair().expect("Should generate first key pair");
        let (_, second_public_pem) = generate_key_pair().expect("Should generate second key pair");
        let principal = TenantPrincipal {
            tenant_id: "tenant-1".to_string(),
            token_id: Uuid::new_v4(),
        };

        let mk1: MasterKey = match create_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Json(CreateMasterKeyPayload {
                public_key: first_public_pem,
            }),
        )
        .await
        .expect("Should create first master key")
        {
            SealboxResponse::Json(v) => serde_json::from_value(v).expect("Should parse master key"),
            _ => panic!("Expected JSON"),
        };

        let mk2: MasterKey = match create_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Json(CreateMasterKeyPayload {
                public_key: second_public_pem,
            }),
        )
        .await
        .expect("Should create second master key")
        {
            SealboxResponse::Json(v) => serde_json::from_value(v).expect("Should parse master key"),
            _ => panic!("Expected JSON"),
        };

        let expired_at = time::OffsetDateTime::now_utc().unix_timestamp() - 10;
        {
            let mut conn = state.conn_pool.lock().expect("Should lock db");
            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    &principal.tenant_id,
                    "active",
                    "v1",
                    mk1.clone(),
                    None,
                )
                .expect("Should create active secret");
            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    &principal.tenant_id,
                    "expired-before-fetch",
                    "permanent-v1",
                    mk1.clone(),
                    None,
                )
                .expect("Should create permanent v1");
            let v2 = state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    &principal.tenant_id,
                    "expired-before-fetch",
                    "temp-v2",
                    mk1.clone(),
                    Some(3600),
                )
                .expect("Should create temp v2");
            conn.execute(
                "UPDATE secrets SET expires_at = ?1 WHERE namespace = ?2 AND key = ?3 AND version = ?4",
                (expired_at, &principal.tenant_id, "expired-before-fetch", v2.version),
            )
            .expect("Should expire v2");
        }

        // Fetching secrets for mk1 removes both versions of the expired key and returns only active.
        let fetched_secrets: Vec<crate::repo::Secret> = match secrets_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Path(TenantMasterKeyIdPathParams {
                master_key_id: mk1.id,
            }),
        )
        .await
        .expect("Should fetch secrets for master key")
        {
            SealboxResponse::Json(v) => {
                serde_json::from_value(v.get("secrets").expect("Should have secrets").clone())
                    .expect("Should parse secrets")
            }
            _ => panic!("Expected JSON"),
        };
        assert_eq!(fetched_secrets.len(), 1);
        assert_eq!(fetched_secrets[0].key, "active");

        // Add another expired key right before rotate and confirm rotate cleans it up instead of rewrapping it.
        {
            let mut conn = state.conn_pool.lock().expect("Should lock db");
            let remaining_fetch_expired: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM secrets WHERE namespace = ?1 AND key = ?2",
                    (&principal.tenant_id, "expired-before-fetch"),
                    |row| row.get(0),
                )
                .expect("Should count rows");
            assert_eq!(remaining_fetch_expired, 0);

            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    &principal.tenant_id,
                    "expired-before-rotate",
                    "permanent-v1",
                    mk1.clone(),
                    None,
                )
                .expect("Should create permanent v1");
            let v2 = state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    &principal.tenant_id,
                    "expired-before-rotate",
                    "temp-v2",
                    mk1.clone(),
                    Some(3600),
                )
                .expect("Should create temp v2");
            conn.execute(
                "UPDATE secrets SET expires_at = ?1 WHERE namespace = ?2 AND key = ?3 AND version = ?4",
                (expired_at, &principal.tenant_id, "expired-before-rotate", v2.version),
            )
            .expect("Should expire v2");
        }

        rotate_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Json(RotateMasterKeyPayload {
                old_master_key_id: mk1.id,
                new_master_key_id: mk2.id,
                updates: vec![RewrappedSecretDataKey {
                    namespace: principal.tenant_id.clone(),
                    key: "active".to_string(),
                    version: 1,
                    previous_encrypted_data_key_sha256: encrypted_data_key_digest(
                        &fetched_secrets[0].encrypted_data_key,
                    ),
                    encrypted_data_key: vec![9, 9, 9],
                }],
            }),
        )
        .await
        .expect("Rotation should succeed after cleaning expired keys");

        let conn = state.conn_pool.lock().expect("Should lock db");
        let remaining_rotate_expired: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM secrets WHERE namespace = ?1 AND key = ?2",
                (&principal.tenant_id, "expired-before-rotate"),
                |row| row.get(0),
            )
            .expect("Should count rows");
        assert_eq!(remaining_rotate_expired, 0);
    }

    #[tokio::test]
    async fn test_rotate_rejects_missing_or_unexpected_rows_and_succeeds_after_refetch() {
        let state = setup_test_state();
        let (_, first_public_pem) = generate_key_pair().expect("Should generate first key pair");
        let (_, second_public_pem) = generate_key_pair().expect("Should generate second key pair");
        let principal = TenantPrincipal {
            tenant_id: "tenant-race".to_string(),
            token_id: Uuid::new_v4(),
        };

        let mk1: MasterKey = match create_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Json(CreateMasterKeyPayload {
                public_key: first_public_pem,
            }),
        )
        .await
        .expect("Should create first master key")
        {
            SealboxResponse::Json(v) => serde_json::from_value(v).expect("Should parse master key"),
            _ => panic!("Expected JSON"),
        };

        let mk2: MasterKey = match create_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Json(CreateMasterKeyPayload {
                public_key: second_public_pem,
            }),
        )
        .await
        .expect("Should create second master key")
        {
            SealboxResponse::Json(v) => serde_json::from_value(v).expect("Should parse master key"),
            _ => panic!("Expected JSON"),
        };

        // Seed an active key, a key that will expire after fetch (permanent v1 + temp v2),
        // and an unrelated secret already encrypted with mk2.
        {
            let mut conn = state.conn_pool.lock().expect("Should lock db");
            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    &principal.tenant_id,
                    "active",
                    "v1",
                    mk1.clone(),
                    None,
                )
                .expect("Should create active secret");
            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    &principal.tenant_id,
                    "expiring-in-flight",
                    "permanent-v1",
                    mk1.clone(),
                    None,
                )
                .expect("Should create permanent v1");
            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    &principal.tenant_id,
                    "expiring-in-flight",
                    "temp-v2",
                    mk1.clone(),
                    Some(3600),
                )
                .expect("Should create temp v2");
            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    &principal.tenant_id,
                    "other-mk",
                    "v1",
                    mk2.clone(),
                    None,
                )
                .expect("Should create secret under mk2");
        }

        // Client fetches secrets under mk1 before expiring-in-flight expires: gets 3 rows.
        let fetched: Vec<crate::repo::Secret> = match secrets_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Path(TenantMasterKeyIdPathParams {
                master_key_id: mk1.id,
            }),
        )
        .await
        .expect("Should fetch secrets")
        {
            SealboxResponse::Json(v) => {
                serde_json::from_value(v.get("secrets").expect("Should have secrets").clone())
                    .expect("Should parse secrets")
            }
            _ => panic!("Expected JSON"),
        };
        assert_eq!(fetched.len(), 3);

        // Before the client submits PUT, expiring-in-flight v2 expires.
        let expired_at = time::OffsetDateTime::now_utc().unix_timestamp() - 10;
        {
            let conn = state.conn_pool.lock().expect("Should lock db");
            conn.execute(
                "UPDATE secrets SET expires_at = ?1 WHERE namespace = ?2 AND key = ?3 AND version = 2",
                (expired_at, &principal.tenant_id, "expiring-in-flight"),
            )
            .expect("Should expire v2");
        }

        let stale_updates: Vec<RewrappedSecretDataKey> = fetched
            .iter()
            .map(|secret| RewrappedSecretDataKey {
                namespace: secret.namespace.clone(),
                key: secret.key.clone(),
                version: secret.version,
                previous_encrypted_data_key_sha256: encrypted_data_key_digest(
                    &secret.encrypted_data_key,
                ),
                encrypted_data_key: vec![7, 7, 7],
            })
            .collect();

        // An extra update targeting a row that still exists (under mk2) must be rejected.
        let mut bad_updates = stale_updates.clone();
        bad_updates.push(RewrappedSecretDataKey {
            namespace: principal.tenant_id.clone(),
            key: "other-mk".to_string(),
            version: 1,
            previous_encrypted_data_key_sha256: encrypted_data_key_digest(&[1, 2, 3]),
            encrypted_data_key: vec![8, 8, 8],
        });
        let err = rotate_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Json(RotateMasterKeyPayload {
                old_master_key_id: mk1.id,
                new_master_key_id: mk2.id,
                updates: bad_updates,
            }),
        )
        .await
        .expect_err("Extra update for existing row must be rejected");
        assert!(
            matches!(err, SealboxError::InvalidRequest(ref msg) if msg.contains("unexpected or stale rewrapped data key")),
            "unexpected error: {err:?}"
        );

        // Submitting the client's stale updates (containing rows that expired and were
        // removed between fetch and rotate) must also reject the whole rotation cleanly.
        let stale_err = rotate_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Json(RotateMasterKeyPayload {
                old_master_key_id: mk1.id,
                new_master_key_id: mk2.id,
                updates: stale_updates,
            }),
        )
        .await
        .expect_err("Rotation must reject updates for rows missing after expiry cleanup");
        assert!(
            matches!(stale_err, SealboxError::InvalidRequest(ref msg) if msg.contains("unexpected or stale rewrapped data key")),
            "unexpected error: {stale_err:?}"
        );

        // Re-fetching cleans up the expired key and retrying rotation succeeds cleanly.
        let refreshed: Vec<crate::repo::Secret> = match secrets_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Path(TenantMasterKeyIdPathParams {
                master_key_id: mk1.id,
            }),
        )
        .await
        .expect("Should re-fetch secrets")
        {
            SealboxResponse::Json(v) => {
                serde_json::from_value(v.get("secrets").expect("Should have secrets").clone())
                    .expect("Should parse secrets")
            }
            _ => panic!("Expected JSON"),
        };
        assert_eq!(refreshed.len(), 1);
        assert_eq!(refreshed[0].key, "active");

        rotate_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Json(RotateMasterKeyPayload {
                old_master_key_id: mk1.id,
                new_master_key_id: mk2.id,
                updates: vec![RewrappedSecretDataKey {
                    namespace: refreshed[0].namespace.clone(),
                    key: refreshed[0].key.clone(),
                    version: refreshed[0].version,
                    previous_encrypted_data_key_sha256: encrypted_data_key_digest(
                        &refreshed[0].encrypted_data_key,
                    ),
                    encrypted_data_key: vec![7, 7, 7],
                }],
            }),
        )
        .await
        .expect("Rotation should succeed after re-fetching live secrets");

        let conn = state.conn_pool.lock().expect("Should lock db");
        let remaining_expired: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM secrets WHERE namespace = ?1 AND key = ?2",
                (&principal.tenant_id, "expiring-in-flight"),
                |row| row.get(0),
            )
            .expect("Should count expired rows");
        assert_eq!(remaining_expired, 0);

        let rotated_active = state
            .secret_repo
            .fetch_secrets_by_master_key(&conn, &principal.tenant_id, &mk2.id)
            .expect("Should fetch mk2 secrets");
        assert!(
            rotated_active.iter().any(|s| s.key == "active"),
            "active secret should now use mk2"
        );
    }

    #[tokio::test]
    async fn test_v1_master_key_secrets_and_rotate_clean_up_expired_keys() {
        let state = setup_test_state();
        let (_, first_public_pem) = generate_key_pair().expect("Should generate first key pair");
        let (_, second_public_pem) = generate_key_pair().expect("Should generate second key pair");
        let v1_path = MasterKeyPathParams {
            version: Version::V1,
        };

        let mk1: MasterKey = match create(
            State(state.clone()),
            Path(v1_path.clone()),
            Json(CreateMasterKeyPayload {
                public_key: first_public_pem,
            }),
        )
        .await
        .expect("Should create v1 mk1")
        {
            SealboxResponse::Json(v) => serde_json::from_value(v).expect("Should parse master key"),
            _ => panic!("Expected JSON"),
        };

        let mk2: MasterKey = match create(
            State(state.clone()),
            Path(v1_path.clone()),
            Json(CreateMasterKeyPayload {
                public_key: second_public_pem,
            }),
        )
        .await
        .expect("Should create v1 mk2")
        {
            SealboxResponse::Json(v) => serde_json::from_value(v).expect("Should parse master key"),
            _ => panic!("Expected JSON"),
        };

        let expired_at = time::OffsetDateTime::now_utc().unix_timestamp() - 10;
        {
            let mut conn = state.conn_pool.lock().expect("Should lock db");
            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    LEGACY_TENANT_ID,
                    "v1-active",
                    "keep",
                    mk1.clone(),
                    None,
                )
                .expect("Should create v1-active");
            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    LEGACY_TENANT_ID,
                    "v1-expired-before-fetch",
                    "perm-v1",
                    mk1.clone(),
                    None,
                )
                .expect("Should create perm v1");
            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    LEGACY_TENANT_ID,
                    "v1-expired-before-fetch",
                    "temp-v2",
                    mk1.clone(),
                    Some(3600),
                )
                .expect("Should create temp v2");
            conn.execute(
                "UPDATE secrets SET expires_at = ?1 WHERE namespace = ?2 AND key = ?3 AND version = 2",
                (expired_at, LEGACY_TENANT_ID, "v1-expired-before-fetch"),
            )
            .expect("Should expire v2");

            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    LEGACY_TENANT_ID,
                    "v1-expiring-in-flight",
                    "perm-v1",
                    mk1.clone(),
                    None,
                )
                .expect("Should create perm v1");
            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    LEGACY_TENANT_ID,
                    "v1-expiring-in-flight",
                    "temp-v2",
                    mk1.clone(),
                    Some(3600),
                )
                .expect("Should create temp v2");
        }

        // V1 secrets fetch removes v1-expired-before-fetch and returns v1-active + v1-expiring-in-flight (3 rows).
        let fetched: Vec<crate::repo::Secret> = match secrets(
            State(state.clone()),
            Path(MasterKeyIdPathParams {
                version: Version::V1,
                master_key_id: mk1.id,
            }),
        )
        .await
        .expect("Should fetch v1 secrets")
        {
            SealboxResponse::Json(v) => {
                serde_json::from_value(v.get("secrets").expect("Should have secrets").clone())
                    .expect("Should parse secrets")
            }
            _ => panic!("Expected JSON"),
        };
        assert_eq!(fetched.len(), 3);
        assert!(fetched.iter().all(|s| s.key != "v1-expired-before-fetch"));

        // Expire v1-expiring-in-flight between fetch and V1 rotate.
        {
            let conn = state.conn_pool.lock().expect("Should lock db");
            conn.execute(
                "UPDATE secrets SET expires_at = ?1 WHERE namespace = ?2 AND key = ?3 AND version = 2",
                (expired_at, LEGACY_TENANT_ID, "v1-expiring-in-flight"),
            )
            .expect("Should expire in-flight v2");
        }

        let stale_updates = fetched
            .iter()
            .map(|secret| RewrappedSecretDataKey {
                namespace: secret.namespace.clone(),
                key: secret.key.clone(),
                version: secret.version,
                previous_encrypted_data_key_sha256: encrypted_data_key_digest(
                    &secret.encrypted_data_key,
                ),
                encrypted_data_key: vec![5, 5, 5],
            })
            .collect();

        // Stale V1 updates containing rows that expired after fetch must be rejected.
        let err = rotate(
            State(state.clone()),
            Path(v1_path.clone()),
            Json(RotateMasterKeyPayload {
                old_master_key_id: mk1.id,
                new_master_key_id: mk2.id,
                updates: stale_updates,
            }),
        )
        .await
        .expect_err("V1 rotation must reject stale updates for missing expired rows");
        assert!(matches!(err, SealboxError::InvalidRequest(_)));

        // Re-fetching V1 secrets removes the expired key and retrying rotation succeeds.
        let refreshed: Vec<crate::repo::Secret> = match secrets(
            State(state.clone()),
            Path(MasterKeyIdPathParams {
                version: Version::V1,
                master_key_id: mk1.id,
            }),
        )
        .await
        .expect("Should re-fetch v1 secrets")
        {
            SealboxResponse::Json(v) => {
                serde_json::from_value(v.get("secrets").expect("Should have secrets").clone())
                    .expect("Should parse secrets")
            }
            _ => panic!("Expected JSON"),
        };
        assert_eq!(refreshed.len(), 1);
        assert_eq!(refreshed[0].key, "v1-active");

        rotate(
            State(state.clone()),
            Path(v1_path),
            Json(RotateMasterKeyPayload {
                old_master_key_id: mk1.id,
                new_master_key_id: mk2.id,
                updates: vec![RewrappedSecretDataKey {
                    namespace: refreshed[0].namespace.clone(),
                    key: refreshed[0].key.clone(),
                    version: refreshed[0].version,
                    previous_encrypted_data_key_sha256: encrypted_data_key_digest(
                        &refreshed[0].encrypted_data_key,
                    ),
                    encrypted_data_key: vec![5, 5, 5],
                }],
            }),
        )
        .await
        .expect("V1 rotation should succeed after re-fetching live secrets");

        let conn = state.conn_pool.lock().expect("Should lock db");
        let remaining_expired: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM secrets WHERE namespace = ?1 AND key IN (?2, ?3)",
                (
                    LEGACY_TENANT_ID,
                    "v1-expired-before-fetch",
                    "v1-expiring-in-flight",
                ),
                |row| row.get(0),
            )
            .expect("Should count expired rows");
        assert_eq!(remaining_expired, 0);
    }

    fn rewrap_for_rotation(
        secrets: &[crate::repo::Secret],
        old_private_pem: &str,
        new_public_pem: &str,
    ) -> Vec<RewrappedSecretDataKey> {
        use crate::crypto::master_key::{PrivateMasterKey, PublicMasterKey};
        use std::str::FromStr;

        let old_priv = PrivateMasterKey::from_str(old_private_pem).expect("parse old private key");
        let new_pub = PublicMasterKey::from_str(new_public_pem).expect("parse new public key");
        secrets
            .iter()
            .map(|secret| {
                let raw_data_key = old_priv
                    .decrypt(&secret.encrypted_data_key)
                    .expect("decrypt old data key");
                let rewrapped = new_pub
                    .encrypt(&raw_data_key)
                    .expect("encrypt new data key");
                RewrappedSecretDataKey {
                    namespace: secret.namespace.clone(),
                    key: secret.key.clone(),
                    version: secret.version,
                    previous_encrypted_data_key_sha256: encrypted_data_key_digest(
                        &secret.encrypted_data_key,
                    ),
                    encrypted_data_key: rewrapped,
                }
            })
            .collect()
    }

    fn decrypt_secret_plaintext(secret: &crate::repo::Secret, private_pem: &str) -> String {
        use crate::crypto::{data_key::DataKey, master_key::PrivateMasterKey};
        use std::str::FromStr;

        let priv_key = PrivateMasterKey::from_str(private_pem).expect("parse private key");
        let raw_data_key = priv_key
            .decrypt(&secret.encrypted_data_key)
            .expect("decrypt data key");
        let data_key = DataKey::from_bytes(&raw_data_key).expect("valid data key");
        let plaintext = data_key
            .decrypt(&secret.encrypted_data)
            .expect("decrypt secret payload");
        String::from_utf8(plaintext).expect("valid utf-8")
    }

    async fn setup_rotation_pair(
        state: &AppState,
        principal: &TenantPrincipal,
    ) -> (MasterKey, String, MasterKey, String) {
        let (priv1, pub1) = generate_key_pair().expect("generate key pair 1");
        let (priv2, pub2) = generate_key_pair().expect("generate key pair 2");

        let mk1: MasterKey = match create_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Json(CreateMasterKeyPayload { public_key: pub1 }),
        )
        .await
        .expect("create mk1")
        {
            SealboxResponse::Json(v) => serde_json::from_value(v).expect("parse mk1"),
            _ => panic!("expected JSON"),
        };
        let mk2: MasterKey = match create_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Json(CreateMasterKeyPayload { public_key: pub2 }),
        )
        .await
        .expect("create mk2")
        {
            SealboxResponse::Json(v) => serde_json::from_value(v).expect("parse mk2"),
            _ => panic!("expected JSON"),
        };
        (mk1, priv1, mk2, priv2)
    }

    async fn fetch_mk_secrets(
        state: &AppState,
        principal: &TenantPrincipal,
        mk_id: Uuid,
    ) -> Vec<crate::repo::Secret> {
        match secrets_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Path(TenantMasterKeyIdPathParams {
                master_key_id: mk_id,
            }),
        )
        .await
        .expect("fetch secrets for master key")
        {
            SealboxResponse::Json(v) => {
                serde_json::from_value(v.get("secrets").expect("secrets array").clone())
                    .expect("parse secrets")
            }
            _ => panic!("expected JSON"),
        }
    }

    #[tokio::test]
    async fn test_rotate_rejects_stale_update_after_expire_and_save() {
        let state = setup_test_state();
        let principal = TenantPrincipal {
            tenant_id: "tenant-rot-expire-save".to_string(),
            token_id: Uuid::new_v4(),
        };
        let (mk1, priv1, mk2, priv2) = setup_rotation_pair(&state, &principal).await;

        {
            let mut conn = state.conn_pool.lock().expect("lock db");
            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    &principal.tenant_id,
                    "cred",
                    "old-v1",
                    mk1.clone(),
                    None,
                )
                .expect("create v1");
            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    &principal.tenant_id,
                    "cred",
                    "old-v2-ttl",
                    mk1.clone(),
                    Some(3600),
                )
                .expect("create v2");
        }

        // Rotation client fetches and rewraps v1 and v2.
        let fetched = fetch_mk_secrets(&state, &principal, mk1.id).await;
        assert_eq!(fetched.len(), 2);
        let stale_updates = rewrap_for_rotation(&fetched, &priv1, &mk2.public_key);

        // Before PUT arrives: v2 expires, then a fresh value is saved (clears v1+v2, creates new v1).
        let expired_at = time::OffsetDateTime::now_utc().unix_timestamp() - 10;
        {
            let mut conn = state.conn_pool.lock().expect("lock db");
            conn.execute(
                "UPDATE secrets SET expires_at = ?1 WHERE namespace = ?2 AND key = ?3 AND version = 2",
                (expired_at, &principal.tenant_id, "cred"),
            )
            .expect("expire v2");
            let fresh = state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    &principal.tenant_id,
                    "cred",
                    "fresh-after-expire",
                    mk1.clone(),
                    None,
                )
                .expect("save fresh value");
            assert_eq!(fresh.version, 1);
        }

        // Stale rotation must be rejected so old v1's data key never overwrites fresh v1.
        let err = rotate_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Json(RotateMasterKeyPayload {
                old_master_key_id: mk1.id,
                new_master_key_id: mk2.id,
                updates: stale_updates,
            }),
        )
        .await
        .expect_err("expire+save during rotation must reject stale update");
        assert!(
            matches!(err, SealboxError::InvalidRequest(ref msg) if msg.contains("stale rewrapped data key")),
            "unexpected error: {err:?}"
        );

        // Fresh value remains intact under mk1 and decrypts cleanly.
        {
            let mut conn = state.conn_pool.lock().expect("lock db");
            let current = state
                .secret_repo
                .get_secret(&mut conn, &principal.tenant_id, "cred")
                .expect("read fresh secret");
            assert_eq!(current.version, 1);
            assert_eq!(current.master_key_id, mk1.id);
            assert_eq!(
                decrypt_secret_plaintext(&current, &priv1),
                "fresh-after-expire"
            );
            let active = state
                .master_key_repo
                .get_valid_master_key(&conn, &principal.tenant_id)
                .expect("active master key");
            assert_eq!(active.id, mk1.id);
        }

        // A retry that re-fetches and rewraps the fresh row succeeds and decrypts under mk2.
        let refreshed = fetch_mk_secrets(&state, &principal, mk1.id).await;
        assert_eq!(refreshed.len(), 1);
        let fresh_updates = rewrap_for_rotation(&refreshed, &priv1, &mk2.public_key);
        rotate_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Json(RotateMasterKeyPayload {
                old_master_key_id: mk1.id,
                new_master_key_id: mk2.id,
                updates: fresh_updates,
            }),
        )
        .await
        .expect("retried rotation must succeed");
        {
            let mut conn = state.conn_pool.lock().expect("lock db");
            let rotated = state
                .secret_repo
                .get_secret(&mut conn, &principal.tenant_id, "cred")
                .expect("read rotated secret");
            assert_eq!(rotated.master_key_id, mk2.id);
            assert_eq!(
                decrypt_secret_plaintext(&rotated, &priv2),
                "fresh-after-expire"
            );
        }
    }

    #[tokio::test]
    async fn test_rotate_rejects_stale_update_after_delete_and_save() {
        let state = setup_test_state();
        let principal = TenantPrincipal {
            tenant_id: "tenant-rot-delete-save".to_string(),
            token_id: Uuid::new_v4(),
        };
        let (mk1, priv1, mk2, _priv2) = setup_rotation_pair(&state, &principal).await;

        // Test both single-version (equal count) and multi-version delete+save.
        for (key, seed_second_version) in [("single-ver", false), ("multi-ver", true)] {
            {
                let mut conn = state.conn_pool.lock().expect("lock db");
                state
                    .secret_repo
                    .create_new_version(
                        &mut conn,
                        &principal.tenant_id,
                        key,
                        "original-v1",
                        mk1.clone(),
                        None,
                    )
                    .expect("create v1");
                if seed_second_version {
                    state
                        .secret_repo
                        .create_new_version(
                            &mut conn,
                            &principal.tenant_id,
                            key,
                            "original-v2",
                            mk1.clone(),
                            None,
                        )
                        .expect("create v2");
                }
            }

            let fetched = fetch_mk_secrets(&state, &principal, mk1.id).await;
            let stale_updates = rewrap_for_rotation(&fetched, &priv1, &mk2.public_key);

            {
                let mut conn = state.conn_pool.lock().expect("lock db");
                state
                    .secret_repo
                    .delete_secret(&conn, &principal.tenant_id, key)
                    .expect("delete key");
                let fresh = state
                    .secret_repo
                    .create_new_version(
                        &mut conn,
                        &principal.tenant_id,
                        key,
                        "fresh-after-delete",
                        mk1.clone(),
                        None,
                    )
                    .expect("re-save key");
                assert_eq!(fresh.version, 1);
            }

            let err = rotate_v2(
                State(state.clone()),
                Extension(principal.clone()),
                Json(RotateMasterKeyPayload {
                    old_master_key_id: mk1.id,
                    new_master_key_id: mk2.id,
                    updates: stale_updates,
                }),
            )
            .await
            .expect_err("delete+save during rotation must reject stale update");
            assert!(
                matches!(err, SealboxError::InvalidRequest(ref msg) if msg.contains("stale rewrapped data key")),
                "unexpected error for {key}: {err:?}"
            );

            let mut conn = state.conn_pool.lock().expect("lock db");
            let current = state
                .secret_repo
                .get_secret(&mut conn, &principal.tenant_id, key)
                .expect("read fresh secret");
            assert_eq!(current.master_key_id, mk1.id);
            assert_eq!(
                decrypt_secret_plaintext(&current, &priv1),
                "fresh-after-delete"
            );
            state
                .secret_repo
                .delete_secret(&conn, &principal.tenant_id, key)
                .expect("clean key for next case");
        }
    }

    #[tokio::test]
    async fn test_rotate_rejects_stale_update_after_expire_read_and_save() {
        let state = setup_test_state();
        let principal = TenantPrincipal {
            tenant_id: "tenant-rot-expire-read-save".to_string(),
            token_id: Uuid::new_v4(),
        };
        let (mk1, priv1, mk2, _priv2) = setup_rotation_pair(&state, &principal).await;

        {
            let mut conn = state.conn_pool.lock().expect("lock db");
            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    &principal.tenant_id,
                    "cred",
                    "old-permanent-v1",
                    mk1.clone(),
                    None,
                )
                .expect("create v1");
            state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    &principal.tenant_id,
                    "cred",
                    "old-temp-v2",
                    mk1.clone(),
                    Some(3600),
                )
                .expect("create v2");
        }

        let fetched = fetch_mk_secrets(&state, &principal, mk1.id).await;
        assert_eq!(fetched.len(), 2);
        let stale_updates = rewrap_for_rotation(&fetched, &priv1, &mk2.public_key);

        // Expire v2, perform a read (which lazily removes both rows), then save a fresh value.
        let expired_at = time::OffsetDateTime::now_utc().unix_timestamp() - 10;
        {
            let mut conn = state.conn_pool.lock().expect("lock db");
            conn.execute(
                "UPDATE secrets SET expires_at = ?1 WHERE namespace = ?2 AND key = ?3 AND version = 2",
                (expired_at, &principal.tenant_id, "cred"),
            )
            .expect("expire v2");
            let read_err = state
                .secret_repo
                .get_secret(&mut conn, &principal.tenant_id, "cred")
                .expect_err("read after expiry must return SecretNotFound");
            assert!(matches!(read_err, SealboxError::SecretNotFound(_)));
            let fresh = state
                .secret_repo
                .create_new_version(
                    &mut conn,
                    &principal.tenant_id,
                    "cred",
                    "fresh-after-expire-read",
                    mk1.clone(),
                    None,
                )
                .expect("save fresh value");
            assert_eq!(fresh.version, 1);
        }

        let err = rotate_v2(
            State(state.clone()),
            Extension(principal.clone()),
            Json(RotateMasterKeyPayload {
                old_master_key_id: mk1.id,
                new_master_key_id: mk2.id,
                updates: stale_updates,
            }),
        )
        .await
        .expect_err("expire+read+save during rotation must reject stale update");
        assert!(
            matches!(err, SealboxError::InvalidRequest(ref msg) if msg.contains("stale rewrapped data key")),
            "unexpected error: {err:?}"
        );

        let mut conn = state.conn_pool.lock().expect("lock db");
        let current = state
            .secret_repo
            .get_secret(&mut conn, &principal.tenant_id, "cred")
            .expect("read fresh secret");
        assert_eq!(current.version, 1);
        assert_eq!(current.master_key_id, mk1.id);
        assert_eq!(
            decrypt_secret_plaintext(&current, &priv1),
            "fresh-after-expire-read"
        );
    }
}
