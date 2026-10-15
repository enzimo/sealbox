use axum::{Extension, body::Body, extract::State, http::header, response::Response};
use serde_json::json;

use crate::{
    api::{SealboxResponse, auth::TenantPrincipal, state::AppState},
    error::{Result, SealboxError},
    repo::backup_database,
};

/// API handler for cleaning up expired secrets in every tenant
///
/// # Arguments
///
/// * `state` - Application state containing database connection pool and repository instances
///
/// # Returns
///
/// Returns JSON response with cleanup statistics
///
/// # HTTP Route
///
/// `DELETE /v2/admin/cleanup-expired` (root token), and the deprecated
/// `DELETE /v1/admin/cleanup-expired`
///
/// # Response Format
///
/// ```json
/// {
///   "deleted_count": 42,
///   "cleaned_at": 1703876543
/// }
/// ```
pub(crate) async fn cleanup_expired(State(state): State<AppState>) -> Result<SealboxResponse> {
    let conn = state.conn_pool.lock()?;
    let deleted_count = state.secret_repo.cleanup_expired_secrets(&conn)?;
    let cleaned_at = time::OffsetDateTime::now_utc().unix_timestamp();

    Ok(SealboxResponse::Json(json!({
        "deleted_count": deleted_count,
        "cleaned_at": cleaned_at
    })))
}

/// API handler for cleaning up expired secrets in the caller's tenant.
///
/// # HTTP Route
///
/// `DELETE /v2/cleanup-expired` (tenant token)
///
/// Same response format as [`cleanup_expired`].
pub(crate) async fn cleanup_expired_v2(
    State(state): State<AppState>,
    Extension(principal): Extension<TenantPrincipal>,
) -> Result<SealboxResponse> {
    let conn = state.conn_pool.lock()?;
    let deleted_count = state
        .secret_repo
        .cleanup_expired_secrets_in_namespace(&conn, &principal.tenant_id)?;
    let cleaned_at = time::OffsetDateTime::now_utc().unix_timestamp();

    Ok(SealboxResponse::Json(json!({
        "deleted_count": deleted_count,
        "cleaned_at": cleaned_at
    })))
}

/// Removes the temporary snapshot however the handler exits.
struct TempSnapshot(std::path::PathBuf);

impl Drop for TempSnapshot {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// API handler that returns a consistent SQLite snapshot of the whole store.
///
/// Root-token only. Secret values are envelope-encrypted, but the snapshot
/// also holds every tenant's metadata and token hashes, so it is as sensitive
/// as the root token itself.
///
/// # HTTP Route
///
/// `GET /v2/admin/backup`
pub(crate) async fn backup(State(state): State<AppState>) -> Result<Response> {
    let snapshot = TempSnapshot(
        std::env::temp_dir().join(format!("sealbox-backup-{}.db", uuid::Uuid::new_v4())),
    );
    {
        let conn = state.conn_pool.lock()?;
        backup_database(&conn, &snapshot.0)?;
    }
    let bytes = tokio::fs::read(&snapshot.0)
        .await
        .map_err(|error| SealboxError::DatabaseError(error.to_string()))?;

    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    Response::builder()
        .header(header::CONTENT_TYPE, "application/vnd.sqlite3")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"sealbox-backup-{timestamp}.db\""),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(bytes))
        .map_err(|error| SealboxError::ResponseBuildFailed(error.to_string()))
}
