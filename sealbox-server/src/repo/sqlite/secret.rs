use serde_rusqlite::*;
use tracing::info;
use uuid::Uuid;

use crate::{
    error::{Result, SealboxError},
    repo::{EncryptedSecretInput, Secret, SecretRepo},
};

const CREDENTIAL_VERSION_LIMIT: i32 = 10;
/// Files can be up to 500 KB each, so retained history is capped more tightly
/// than credentials to keep the database from growing without bound.
const FILE_VERSION_LIMIT: i32 = 3;

/// Shared CTE that annotates each row in the target scope with its key's
/// version rank (`1` = newest version) and the newest version's `expires_at`.
///
/// Only metadata columns are selected so encrypted BLOBs are never copied into
/// the CTE.
macro_rules! classified_secrets_cte {
    ($scope_where:literal) => {
        concat!(
            "WITH classified_secrets AS (
                SELECT
                    namespace,
                    key,
                    version,
                    created_at,
                    updated_at,
                    expires_at,
                    metadata,
                    ROW_NUMBER() OVER (
                        PARTITION BY namespace, key
                        ORDER BY version DESC
                    ) AS version_rank,
                    FIRST_VALUE(expires_at) OVER (
                        PARTITION BY namespace, key
                        ORDER BY version DESC
                    ) AS latest_expires_at
                FROM secrets
                ",
            $scope_where,
            ")"
        )
    };
}

/// Shared two-valued expiry predicate for rows in `classified_secrets`.
///
/// A row is expired when either its own `expires_at` is strictly before `:now`
/// or its key's newest version (`latest_expires_at`) is strictly before `:now`
/// (in which case the whole key has expired and every version must be removed).
///
/// Both branches guard with `IS NOT NULL` before `< :now`, and `:now` is a
/// non-null integer, so SQL three-valued logic always evaluates this predicate
/// to 0 or 1 (never NULL) and `NOT (...)` is exact for active rows.
macro_rules! classified_row_expired_sql {
    () => {
        "((expires_at IS NOT NULL AND expires_at < :now)
          OR (latest_expires_at IS NOT NULL AND latest_expires_at < :now))"
    };
}

const CLEANUP_EXPIRED_FOR_KEY_SQL: &str = concat!(
    classified_secrets_cte!("WHERE namespace = :namespace AND key = :key"),
    "
    DELETE FROM secrets
    WHERE namespace = :namespace
      AND key = :key
      AND version IN (
          SELECT version
          FROM classified_secrets
          WHERE ",
    classified_row_expired_sql!(),
    "
      )"
);

const CLEANUP_EXPIRED_NAMESPACE_SQL: &str = concat!(
    classified_secrets_cte!("WHERE namespace = :namespace"),
    "
    DELETE FROM secrets
    WHERE namespace = :namespace
      AND (key, version) IN (
          SELECT key, version
          FROM classified_secrets
          WHERE ",
    classified_row_expired_sql!(),
    "
      )"
);

const CLEANUP_EXPIRED_ALL_SQL: &str = concat!(
    classified_secrets_cte!(""),
    "
    DELETE FROM secrets
    WHERE (namespace, key, version) IN (
          SELECT namespace, key, version
          FROM classified_secrets
          WHERE ",
    classified_row_expired_sql!(),
    "
      )"
);

const LIST_SECRETS_SQL: &str = concat!(
    classified_secrets_cte!("WHERE namespace = :namespace"),
    "
    SELECT
        key,
        version,
        created_at,
        updated_at,
        expires_at,
        metadata
    FROM classified_secrets
    WHERE version_rank = 1
      AND NOT ",
    classified_row_expired_sql!(),
    "
    ORDER BY updated_at DESC"
);

const LIST_SECRET_VERSIONS_SQL: &str = concat!(
    classified_secrets_cte!("WHERE namespace = :namespace AND key = :key"),
    "
    SELECT
        key,
        version,
        created_at,
        updated_at,
        expires_at,
        metadata
    FROM classified_secrets
    WHERE NOT ",
    classified_row_expired_sql!(),
    "
    ORDER BY version DESC"
);

#[derive(Debug, Clone)]
pub(crate) struct SqliteSecretRepo;

impl SqliteSecretRepo {
    pub fn init_table(conn: &rusqlite::Connection) -> Result<()> {
        // Initialize database table structure
        conn.execute(
            "CREATE TABLE IF NOT EXISTS secrets (
                namespace TEXT NOT NULL DEFAULT 'legacy',
                key TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                encrypted_data BLOB NOT NULL,
                encrypted_data_key BLOB NOT NULL,
                master_key_id BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                expires_at INTEGER,
                metadata TEXT,
                PRIMARY KEY (namespace, key, version)
            )",
            (),
        )?;
        conn.execute(
            "UPDATE secrets SET namespace = 'legacy' WHERE namespace = ''",
            (),
        )?;

        Ok(())
    }
}

impl SqliteSecretRepo {
    /// Read the plaintext `type` discriminator from a secret's metadata.
    fn metadata_type(metadata: Option<&str>) -> Option<String> {
        let metadata = metadata?;
        let metadata: serde_json::Value = serde_json::from_str(metadata).ok()?;
        metadata
            .get("type")
            .and_then(|value| value.as_str())
            .map(str::to_string)
    }

    /// Version retention limit for a secret, based on its metadata type.
    ///
    /// Returns `None` for secret types that retain full history.
    fn version_limit_for(metadata: Option<&str>) -> Option<i32> {
        match Self::metadata_type(metadata).as_deref() {
            Some(crate::repo::SECRET_TYPE_CREDENTIAL) => Some(CREDENTIAL_VERSION_LIMIT),
            Some(crate::repo::SECRET_TYPE_FILE) => Some(FILE_VERSION_LIMIT),
            _ => None,
        }
    }

    fn prune_old_versions(
        tx: &rusqlite::Transaction,
        namespace: &str,
        key: &str,
        latest_version: i32,
        limit: i32,
        secret_type: &str,
    ) -> Result<()> {
        let oldest_version_to_delete = latest_version - limit;
        if oldest_version_to_delete <= 0 {
            return Ok(());
        }

        let deleted_count = tx.execute(
            "DELETE FROM secrets WHERE namespace = ?1 AND key = ?2 AND version <= ?3",
            (namespace, key, oldest_version_to_delete),
        )?;

        if deleted_count > 0 {
            info!(
                "Pruned {} old {} versions for '{}'",
                deleted_count, secret_type, key
            );
        }

        Ok(())
    }

    fn cleanup_expired_for_key(
        tx: &rusqlite::Transaction,
        namespace: &str,
        key: &str,
        now: i64,
    ) -> Result<usize> {
        let deleted_count = tx.execute(
            CLEANUP_EXPIRED_FOR_KEY_SQL,
            rusqlite::named_params! {
                ":namespace": namespace,
                ":key": key,
                ":now": now,
            },
        )?;
        if deleted_count > 0 {
            info!(
                "Deleted {} expired secret row(s) for '{}' in namespace '{}'",
                deleted_count, key, namespace
            );
        }
        Ok(deleted_count)
    }

    fn cleanup_expired_secrets_at(&self, conn: &rusqlite::Connection, now: i64) -> Result<usize> {
        let deleted_count = conn.execute(
            CLEANUP_EXPIRED_ALL_SQL,
            rusqlite::named_params! { ":now": now },
        )?;
        info!("Cleaned up {} expired secrets", deleted_count);
        Ok(deleted_count)
    }

    fn cleanup_expired_secrets_in_namespace_at(
        &self,
        conn: &rusqlite::Connection,
        namespace: &str,
        now: i64,
    ) -> Result<usize> {
        let deleted_count = conn.execute(
            CLEANUP_EXPIRED_NAMESPACE_SQL,
            rusqlite::named_params! {
                ":namespace": namespace,
                ":now": now,
            },
        )?;
        info!(
            "Cleaned up {} expired secrets in namespace {}",
            deleted_count, namespace
        );
        Ok(deleted_count)
    }

    fn list_secrets_at(
        &self,
        conn: &rusqlite::Connection,
        namespace: &str,
        now: i64,
    ) -> Result<Vec<crate::repo::SecretInfo>> {
        let mut stmt = conn.prepare_cached(LIST_SECRETS_SQL)?;
        let secret_infos = stmt
            .query_map(
                rusqlite::named_params! {
                    ":namespace": namespace,
                    ":now": now,
                },
                |row| {
                    Ok(crate::repo::SecretInfo {
                        key: row.get(0)?,
                        version: row.get(1)?,
                        created_at: row.get(2)?,
                        updated_at: row.get(3)?,
                        expires_at: row.get(4)?,
                        metadata: row.get(5)?,
                    })
                },
            )?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| SealboxError::DatabaseError(e.to_string()))?;

        Ok(secret_infos)
    }

    fn list_secret_versions_at(
        &self,
        conn: &rusqlite::Connection,
        namespace: &str,
        key: &str,
        now: i64,
    ) -> Result<Vec<crate::repo::SecretInfo>> {
        let mut stmt = conn.prepare_cached(LIST_SECRET_VERSIONS_SQL)?;
        let secret_infos = stmt
            .query_map(
                rusqlite::named_params! {
                    ":namespace": namespace,
                    ":key": key,
                    ":now": now,
                },
                |row| {
                    Ok(crate::repo::SecretInfo {
                        key: row.get(0)?,
                        version: row.get(1)?,
                        created_at: row.get(2)?,
                        updated_at: row.get(3)?,
                        expires_at: row.get(4)?,
                        metadata: row.get(5)?,
                    })
                },
            )?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| SealboxError::DatabaseError(e.to_string()))?;

        if secret_infos.is_empty() {
            return Err(SealboxError::SecretNotFound(key.to_string()));
        }

        Ok(secret_infos)
    }

    /// Common implementation for getting secrets with atomic cleanup
    fn get_secret_with_query(
        &self,
        conn: &mut rusqlite::Connection,
        query: &str,
        params: impl rusqlite::Params,
        namespace: &str,
        key: &str,
        now: i64,
    ) -> Result<Secret> {
        let tx = conn.transaction()?;

        Self::cleanup_expired_for_key(&tx, namespace, key, now)?;

        let row = {
            let mut stmt = tx.prepare_cached(query)?;
            // Using query_and_then() and from_row() as shown in the official example
            let mut rows = stmt.query_and_then(params, from_row::<Secret>)?;
            rows.next()
                .transpose()
                .map_err(|e| SealboxError::DatabaseError(e.to_string()))?
        };

        tx.commit()?;

        match row {
            Some(secret) => Ok(secret),
            None => Err(SealboxError::SecretNotFound(key.to_string())),
        }
    }
}

#[cfg(test)]
impl SqliteSecretRepo {
    fn get_secret(&self, conn: &mut rusqlite::Connection, key: &str) -> Result<Secret> {
        <Self as SecretRepo>::get_secret(self, conn, crate::repo::LEGACY_TENANT_ID, key)
    }

    fn get_secret_by_version(
        &self,
        conn: &mut rusqlite::Connection,
        key: &str,
        version: i32,
    ) -> Result<Secret> {
        <Self as SecretRepo>::get_secret_by_version(
            self,
            conn,
            crate::repo::LEGACY_TENANT_ID,
            key,
            version,
        )
    }

    fn create_new_version(
        &self,
        conn: &mut rusqlite::Connection,
        key: &str,
        data: &str,
        master_key: crate::repo::MasterKey,
        ttl: Option<i64>,
    ) -> Result<Secret> {
        <Self as SecretRepo>::create_new_version(
            self,
            conn,
            crate::repo::LEGACY_TENANT_ID,
            key,
            data,
            master_key,
            ttl,
        )
    }

    fn create_new_encrypted_version(
        &self,
        conn: &mut rusqlite::Connection,
        key: &str,
        input: EncryptedSecretInput,
    ) -> Result<Secret> {
        <Self as SecretRepo>::create_new_encrypted_version(
            self,
            conn,
            crate::repo::LEGACY_TENANT_ID,
            key,
            input,
        )
    }

    fn delete_secret(&self, conn: &rusqlite::Connection, key: &str) -> Result<()> {
        <Self as SecretRepo>::delete_secret(self, conn, crate::repo::LEGACY_TENANT_ID, key)
    }

    fn delete_secret_by_version(
        &self,
        conn: &mut rusqlite::Connection,
        key: &str,
        version: i32,
    ) -> Result<()> {
        <Self as SecretRepo>::delete_secret_by_version(
            self,
            conn,
            crate::repo::LEGACY_TENANT_ID,
            key,
            version,
        )
    }

    fn fetch_secrets_by_master_key(
        &self,
        conn: &rusqlite::Connection,
        master_key_id: &Uuid,
    ) -> Result<Vec<Secret>> {
        <Self as SecretRepo>::fetch_secrets_by_master_key(
            self,
            conn,
            crate::repo::LEGACY_TENANT_ID,
            master_key_id,
        )
    }

    fn list_secrets(&self, conn: &rusqlite::Connection) -> Result<Vec<crate::repo::SecretInfo>> {
        <Self as SecretRepo>::list_secrets(self, conn, crate::repo::LEGACY_TENANT_ID)
    }

    fn list_secret_versions(
        &self,
        conn: &rusqlite::Connection,
        key: &str,
    ) -> Result<Vec<crate::repo::SecretInfo>> {
        <Self as SecretRepo>::list_secret_versions(self, conn, crate::repo::LEGACY_TENANT_ID, key)
    }
}

impl SecretRepo for SqliteSecretRepo {
    fn get_secret(
        &self,
        conn: &mut rusqlite::Connection,
        namespace: &str,
        key: &str,
    ) -> Result<Secret> {
        info!("get_secret: namespace={}, key={}", namespace, key);
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        self.get_secret_with_query(
            conn,
            "SELECT
                namespace,
                key,
                version,
                encrypted_data,
                encrypted_data_key,
                master_key_id,
                created_at,
                updated_at,
                expires_at,
                metadata
            FROM secrets
            WHERE namespace = ?1 AND key = ?2
            ORDER BY version DESC
            LIMIT 1",
            (namespace, key),
            namespace,
            key,
            now,
        )
    }

    fn get_secret_by_version(
        &self,
        conn: &mut rusqlite::Connection,
        namespace: &str,
        key: &str,
        version: i32,
    ) -> Result<Secret> {
        info!(
            "get_secret_by_version: namespace={}, key={}, version={}",
            namespace, key, version
        );
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        self.get_secret_with_query(
            conn,
            "SELECT
                namespace,
                key,
                version,
                encrypted_data,
                encrypted_data_key,
                master_key_id,
                created_at,
                updated_at,
                expires_at,
                metadata
            FROM secrets
            WHERE namespace = ?1 AND key = ?2 AND version = ?3
            LIMIT 1",
            (namespace, key, version),
            namespace,
            key,
            now,
        )
    }

    #[cfg(test)]
    fn create_new_version(
        &self,
        conn: &mut rusqlite::Connection,
        namespace: &str,
        key: &str,
        data: &str,
        master_key: crate::repo::MasterKey,
        ttl: Option<i64>,
    ) -> Result<Secret> {
        info!("create_new_version");

        let tx = conn.transaction()?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        Self::cleanup_expired_for_key(&tx, namespace, key, now)?;

        let next_version = {
            let mut stmt = tx.prepare(
                "SELECT COALESCE(MAX(version), 0) FROM secrets WHERE namespace = ?1 AND key = ?2",
            )?;
            let latest_version: i32 = stmt.query_one((namespace, key), |row| row.get(0))?;
            latest_version + 1
        };

        let secret = Secret::new(namespace, key, data, master_key, next_version, ttl)?;

        tx.execute(
            "INSERT INTO secrets (
              namespace,
              key,
              version,
              encrypted_data,
              encrypted_data_key,
              master_key_id,
              created_at,
              updated_at,
              expires_at,
              metadata
          ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            (
                &secret.namespace,
                &secret.key,
                &secret.version,
                &secret.encrypted_data,
                &secret.encrypted_data_key,
                &secret.master_key_id,
                &secret.created_at,
                &secret.updated_at,
                &secret.expires_at,
                &secret.metadata,
            ),
        )?;

        tx.commit()?;

        Ok(secret)
    }

    fn create_new_encrypted_version(
        &self,
        conn: &mut rusqlite::Connection,
        namespace: &str,
        key: &str,
        input: EncryptedSecretInput,
    ) -> Result<Secret> {
        info!("create_new_encrypted_version");

        let tx = conn.transaction()?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        Self::cleanup_expired_for_key(&tx, namespace, key, now)?;

        let next_version = {
            let mut stmt = tx.prepare(
                "SELECT COALESCE(MAX(version), 0) FROM secrets WHERE namespace = ?1 AND key = ?2",
            )?;
            let latest_version: i32 = stmt.query_one((namespace, key), |row| row.get(0))?;
            latest_version + 1
        };

        let secret = Secret::from_encrypted(namespace, key, next_version, input)?;

        tx.execute(
            "INSERT INTO secrets (
              namespace,
              key,
              version,
              encrypted_data,
              encrypted_data_key,
              master_key_id,
              created_at,
              updated_at,
              expires_at,
              metadata
          ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            (
                &secret.namespace,
                &secret.key,
                &secret.version,
                &secret.encrypted_data,
                &secret.encrypted_data_key,
                &secret.master_key_id,
                &secret.created_at,
                &secret.updated_at,
                &secret.expires_at,
                &secret.metadata,
            ),
        )?;

        if let Some(limit) = Self::version_limit_for(secret.metadata.as_deref()) {
            let secret_type = Self::metadata_type(secret.metadata.as_deref())
                .unwrap_or_else(|| "secret".to_string());
            Self::prune_old_versions(
                &tx,
                &secret.namespace,
                &secret.key,
                secret.version,
                limit,
                &secret_type,
            )?;
        }

        tx.commit()?;

        Ok(secret)
    }

    fn delete_secret_by_version(
        &self,
        conn: &mut rusqlite::Connection,
        namespace: &str,
        key: &str,
        version: i32,
    ) -> Result<()> {
        info!("delete_secret_by_version");
        let tx = conn.transaction()?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        Self::cleanup_expired_for_key(&tx, namespace, key, now)?;

        let changed = tx.execute(
            "DELETE FROM secrets WHERE namespace = ?1 AND key = ?2 AND version = ?3",
            (namespace, key, version),
        )?;
        tx.commit()?;

        if changed == 0 {
            return Err(SealboxError::SecretNotFound(key.to_string()));
        }
        Ok(())
    }

    fn delete_secret(&self, conn: &rusqlite::Connection, namespace: &str, key: &str) -> Result<()> {
        info!("delete_secret");
        let changed = conn.execute(
            "DELETE FROM secrets WHERE namespace = ?1 AND key = ?2",
            (namespace, key),
        )?;
        if changed == 0 {
            return Err(SealboxError::SecretNotFound(key.to_string()));
        }
        Ok(())
    }

    fn fetch_secrets_by_master_key(
        &self,
        conn: &rusqlite::Connection,
        namespace: &str,
        master_key_id: &Uuid,
    ) -> Result<Vec<Secret>> {
        let mut stmt = conn.prepare(
            "SELECT
                namespace,
                key,
                version,
                encrypted_data,
                encrypted_data_key,
                master_key_id,
                created_at,
                updated_at,
                expires_at,
                metadata
            FROM secrets
            WHERE namespace = ?1 AND master_key_id = ?2",
        )?;
        // Using query() and from_rows(), the most efficient way as shown in the official example
        let rows = stmt.query(rusqlite::params![namespace, master_key_id])?;
        let secrets: Vec<Secret> = from_rows::<Secret>(rows)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| SealboxError::DatabaseError(e.to_string()))?;
        Ok(secrets)
    }

    fn update_secret_master_key(&self, conn: &rusqlite::Connection, secret: &Secret) -> Result<()> {
        conn.execute(
            "UPDATE secrets SET
                encrypted_data_key = ?1,
                master_key_id = ?2,
                updated_at = ?3
             WHERE namespace = ?4 AND key = ?5 AND version = ?6",
            rusqlite::params![
                &secret.encrypted_data_key,
                &secret.master_key_id,
                &secret.updated_at,
                &secret.namespace,
                &secret.key,
                &secret.version,
            ],
        )?;
        Ok(())
    }

    fn secret_version_exists(
        &self,
        conn: &rusqlite::Connection,
        namespace: &str,
        key: &str,
        version: i32,
    ) -> Result<bool> {
        let mut stmt = conn.prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM secrets WHERE namespace = ?1 AND key = ?2 AND version = ?3)",
        )?;
        let exists: bool = stmt.query_row((namespace, key, version), |row| row.get(0))?;
        Ok(exists)
    }

    fn cleanup_expired_secrets(&self, conn: &rusqlite::Connection) -> Result<usize> {
        info!("cleanup_expired_secrets");
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        self.cleanup_expired_secrets_at(conn, now)
    }

    fn cleanup_expired_secrets_in_namespace(
        &self,
        conn: &rusqlite::Connection,
        namespace: &str,
    ) -> Result<usize> {
        info!(
            "cleanup_expired_secrets_in_namespace: namespace={}",
            namespace
        );
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        self.cleanup_expired_secrets_in_namespace_at(conn, namespace, now)
    }

    fn list_secrets(
        &self,
        conn: &rusqlite::Connection,
        namespace: &str,
    ) -> Result<Vec<crate::repo::SecretInfo>> {
        info!("list_secrets: namespace={}", namespace);
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        self.list_secrets_at(conn, namespace, now)
    }

    fn list_secret_versions(
        &self,
        conn: &rusqlite::Connection,
        namespace: &str,
        key: &str,
    ) -> Result<Vec<crate::repo::SecretInfo>> {
        info!("list_secret_versions: namespace={}, key={}", namespace, key);
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        self.list_secret_versions_at(conn, namespace, key, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::master_key::generate_key_pair;
    use crate::repo::MasterKey;

    fn setup_test_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("Should create in-memory DB");
        SqliteSecretRepo::init_table(&conn).expect("Should initialize tables");
        conn
    }

    fn create_test_master_key() -> MasterKey {
        let (_, public_pem) = generate_key_pair().expect("Should generate key pair");
        MasterKey::new(public_pem).expect("Should create master key")
    }

    #[test]
    fn test_init_table() {
        let conn = setup_test_db();

        // Verify table exists and has correct structure
        let table_info: Vec<String> = conn
            .prepare("PRAGMA table_info(secrets)")
            .expect("Should prepare query")
            .query_map([], |row| {
                let column_name: String = row.get(1)?;
                Ok(column_name)
            })
            .expect("Should execute query")
            .collect::<Result<Vec<_>, _>>()
            .expect("Should collect results");

        let expected_columns = vec![
            "namespace",
            "key",
            "version",
            "encrypted_data",
            "encrypted_data_key",
            "master_key_id",
            "created_at",
            "updated_at",
            "expires_at",
            "metadata",
        ];

        for expected_col in expected_columns {
            assert!(
                table_info.contains(&expected_col.to_string()),
                "Missing column: {expected_col}"
            );
        }
    }

    #[test]
    fn test_create_and_get_secret() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();

        let secret_key = "test-secret";
        let secret_data = "This is secret data";

        // Create secret
        let mut conn_mut = conn;
        let created_secret = repo
            .create_new_version(&mut conn_mut, secret_key, secret_data, master_key, None)
            .expect("Should create secret");

        // Get secret back
        let retrieved_secret = repo
            .get_secret(&mut conn_mut, secret_key)
            .expect("Should retrieve secret");

        assert_eq!(created_secret.key, retrieved_secret.key);
        assert_eq!(created_secret.version, retrieved_secret.version);
        assert_eq!(
            created_secret.encrypted_data,
            retrieved_secret.encrypted_data
        );
        assert_eq!(
            created_secret.encrypted_data_key,
            retrieved_secret.encrypted_data_key
        );
        assert_eq!(created_secret.master_key_id, retrieved_secret.master_key_id);
    }

    #[test]
    fn test_get_secret_not_found() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;

        let mut conn = conn;
        let result = repo.get_secret(&mut conn, "nonexistent-key");
        assert!(result.is_err());

        match result.unwrap_err() {
            SealboxError::SecretNotFound(key) => assert_eq!(key, "nonexistent-key"),
            _ => panic!("Expected SecretNotFound error"),
        }
    }

    #[test]
    fn test_create_multiple_versions() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();

        let secret_key = "test-secret";

        // Create first version
        let mut conn_mut = conn;
        let secret_v1 = repo
            .create_new_version(
                &mut conn_mut,
                secret_key,
                "data version 1",
                master_key.clone(),
                None,
            )
            .expect("Should create version 1");

        // Create second version
        let secret_v2 = repo
            .create_new_version(
                &mut conn_mut,
                secret_key,
                "data version 2",
                master_key,
                None,
            )
            .expect("Should create version 2");

        assert_eq!(secret_v1.version, 1);
        assert_eq!(secret_v2.version, 2);
        assert_ne!(secret_v1.encrypted_data, secret_v2.encrypted_data);

        // Get latest version (should be v2)
        let latest = repo
            .get_secret(&mut conn_mut, secret_key)
            .expect("Should get latest version");
        assert_eq!(latest.version, 2);
        assert_eq!(latest.encrypted_data, secret_v2.encrypted_data);
    }

    #[test]
    fn test_get_secret_by_version() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();

        let secret_key = "test-secret";

        // Create multiple versions
        let mut conn_mut = conn;
        let secret_v1 = repo
            .create_new_version(
                &mut conn_mut,
                secret_key,
                "data version 1",
                master_key.clone(),
                None,
            )
            .expect("Should create version 1");

        let _secret_v2 = repo
            .create_new_version(
                &mut conn_mut,
                secret_key,
                "data version 2",
                master_key,
                None,
            )
            .expect("Should create version 2");

        // Get specific version
        let retrieved_v1 = repo
            .get_secret_by_version(&mut conn_mut, secret_key, 1)
            .expect("Should get version 1");

        assert_eq!(retrieved_v1.version, 1);
        assert_eq!(retrieved_v1.encrypted_data, secret_v1.encrypted_data);
    }

    #[test]
    fn test_get_secret_by_version_not_found() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;

        let mut conn = conn;
        let result = repo.get_secret_by_version(&mut conn, "nonexistent-key", 1);
        assert!(result.is_err());

        match result.unwrap_err() {
            SealboxError::SecretNotFound(key) => assert_eq!(key, "nonexistent-key"),
            _ => panic!("Expected SecretNotFound error"),
        }
    }

    #[test]
    fn test_delete_secret_by_version() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();

        let secret_key = "test-secret";

        // Create multiple versions
        let mut conn_mut = conn;
        let _secret_v1 = repo
            .create_new_version(
                &mut conn_mut,
                secret_key,
                "data version 1",
                master_key.clone(),
                None,
            )
            .expect("Should create version 1");

        let secret_v2 = repo
            .create_new_version(
                &mut conn_mut,
                secret_key,
                "data version 2",
                master_key,
                None,
            )
            .expect("Should create version 2");

        // Delete version 1
        repo.delete_secret_by_version(&mut conn_mut, secret_key, 1)
            .expect("Should delete version 1");

        // Version 1 should be gone
        let result = repo.get_secret_by_version(&mut conn_mut, secret_key, 1);
        assert!(result.is_err());

        // Version 2 should still exist and be the latest
        let latest = repo
            .get_secret(&mut conn_mut, secret_key)
            .expect("Should get latest version");
        assert_eq!(latest.version, 2);
        assert_eq!(latest.encrypted_data, secret_v2.encrypted_data);
    }

    #[test]
    fn test_delete_secret_by_version_not_found() {
        let mut conn = setup_test_db();
        let repo = SqliteSecretRepo;

        let result = repo.delete_secret_by_version(&mut conn, "nonexistent-key", 1);
        assert!(result.is_err());

        match result.unwrap_err() {
            SealboxError::SecretNotFound(key) => assert_eq!(key, "nonexistent-key"),
            _ => panic!("Expected SecretNotFound error"),
        }
    }

    #[test]
    fn test_delete_secret_deletes_all_versions() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();

        let secret_key = "test-secret";
        let mut conn_mut = conn;

        repo.create_new_version(
            &mut conn_mut,
            secret_key,
            "data version 1",
            master_key.clone(),
            None,
        )
        .expect("Should create version 1");

        repo.create_new_version(
            &mut conn_mut,
            secret_key,
            "data version 2",
            master_key,
            None,
        )
        .expect("Should create version 2");

        repo.delete_secret(&conn_mut, secret_key)
            .expect("Should delete all versions");

        let latest_result = repo.get_secret(&mut conn_mut, secret_key);
        assert!(latest_result.is_err());

        let version_1_result = repo.get_secret_by_version(&mut conn_mut, secret_key, 1);
        assert!(version_1_result.is_err());

        let version_2_result = repo.get_secret_by_version(&mut conn_mut, secret_key, 2);
        assert!(version_2_result.is_err());
    }

    #[test]
    fn test_delete_secret_not_found() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;

        let result = repo.delete_secret(&conn, "nonexistent-key");
        assert!(result.is_err());

        match result.unwrap_err() {
            SealboxError::SecretNotFound(key) => assert_eq!(key, "nonexistent-key"),
            _ => panic!("Expected SecretNotFound error"),
        }
    }

    #[test]
    fn test_credential_versions_are_capped_at_ten() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();
        let mut conn_mut = conn;

        let mut latest_version = 0;
        for index in 0..11 {
            let secret = repo
                .create_new_encrypted_version(
                    &mut conn_mut,
                    "db/postgres",
                    EncryptedSecretInput {
                        encrypted_data: vec![index],
                        encrypted_data_key: vec![index],
                        master_key_id: master_key.id,
                        ttl: None,
                        metadata: Some(
                            r#"{"type":"credential","username":"app_user"}"#.to_string(),
                        ),
                    },
                )
                .expect("Should create credential version");
            latest_version = secret.version;
        }

        assert_eq!(latest_version, 11);

        let version_1_result = repo.get_secret_by_version(&mut conn_mut, "db/postgres", 1);
        assert!(version_1_result.is_err());

        let version_2_result = repo
            .get_secret_by_version(&mut conn_mut, "db/postgres", 2)
            .expect("Version 2 should be retained");
        assert_eq!(version_2_result.version, 2);

        let latest = repo
            .get_secret(&mut conn_mut, "db/postgres")
            .expect("Latest credential version should be retained");
        assert_eq!(latest.version, 11);
    }

    #[test]
    fn test_non_credential_versions_are_not_capped() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();
        let mut conn_mut = conn;

        for index in 0..11 {
            repo.create_new_encrypted_version(
                &mut conn_mut,
                "plain-secret",
                EncryptedSecretInput {
                    encrypted_data: vec![index],
                    encrypted_data_key: vec![index],
                    master_key_id: master_key.id,
                    ttl: None,
                    metadata: None,
                },
            )
            .expect("Should create secret version");
        }

        let version_1 = repo
            .get_secret_by_version(&mut conn_mut, "plain-secret", 1)
            .expect("Non-credential version 1 should be retained");
        assert_eq!(version_1.version, 1);

        let latest = repo
            .get_secret(&mut conn_mut, "plain-secret")
            .expect("Latest secret version should be retained");
        assert_eq!(latest.version, 11);
    }

    #[test]
    fn test_file_versions_are_capped_at_three() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();
        let mut conn_mut = conn;

        let mut latest_version = 0;
        for index in 0..5 {
            let secret = repo
                .create_new_encrypted_version(
                    &mut conn_mut,
                    "config/app.yaml",
                    EncryptedSecretInput {
                        encrypted_data: vec![index],
                        encrypted_data_key: vec![index],
                        master_key_id: master_key.id,
                        ttl: None,
                        metadata: Some(r#"{"type":"file","filename":"app.yaml"}"#.to_string()),
                    },
                )
                .expect("Should create file version");
            latest_version = secret.version;
        }

        assert_eq!(latest_version, 5);

        // The cap keeps the newest three versions: 3, 4 and 5.
        assert!(
            repo.get_secret_by_version(&mut conn_mut, "config/app.yaml", 2)
                .is_err()
        );
        let retained = repo
            .get_secret_by_version(&mut conn_mut, "config/app.yaml", 3)
            .expect("Version 3 should be retained");
        assert_eq!(retained.version, 3);

        let latest = repo
            .get_secret(&mut conn_mut, "config/app.yaml")
            .expect("Latest file version should be retained");
        assert_eq!(latest.version, 5);
    }

    #[test]
    fn test_unknown_metadata_types_are_not_capped() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();
        let mut conn_mut = conn;

        for index in 0..6 {
            repo.create_new_encrypted_version(
                &mut conn_mut,
                "other-secret",
                EncryptedSecretInput {
                    encrypted_data: vec![index],
                    encrypted_data_key: vec![index],
                    master_key_id: master_key.id,
                    ttl: None,
                    metadata: Some(r#"{"type":"note"}"#.to_string()),
                },
            )
            .expect("Should create secret version");
        }

        let version_1 = repo
            .get_secret_by_version(&mut conn_mut, "other-secret", 1)
            .expect("Unknown types should retain full history");
        assert_eq!(version_1.version, 1);
    }

    #[test]
    fn test_list_secret_versions_returns_retained_versions_newest_first() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();
        let mut conn_mut = conn;

        for index in 0..3 {
            repo.create_new_encrypted_version(
                &mut conn_mut,
                "db/postgres",
                EncryptedSecretInput {
                    encrypted_data: vec![index],
                    encrypted_data_key: vec![index],
                    master_key_id: master_key.id,
                    ttl: None,
                    metadata: Some(r#"{"type":"credential","username":"app_user"}"#.to_string()),
                },
            )
            .expect("Should create credential version");
        }

        let versions = repo
            .list_secret_versions(&conn_mut, "db/postgres")
            .expect("Should list credential versions");

        let version_numbers = versions
            .iter()
            .map(|secret| secret.version)
            .collect::<Vec<_>>();
        assert_eq!(version_numbers, vec![3, 2, 1]);
        assert!(versions.iter().all(|secret| secret.key == "db/postgres"));
    }

    #[test]
    fn test_list_secret_versions_not_found() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;

        let result = repo.list_secret_versions(&conn, "missing-secret");
        assert!(result.is_err());

        match result.unwrap_err() {
            SealboxError::SecretNotFound(key) => assert_eq!(key, "missing-secret"),
            _ => panic!("Expected SecretNotFound error"),
        }
    }

    #[test]
    fn test_fetch_secrets_by_master_key() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key1 = create_test_master_key();
        let master_key2 = create_test_master_key();

        // Create secrets with different master keys
        let mut conn_mut = conn;
        let _secret1 = repo
            .create_new_version(&mut conn_mut, "secret1", "data1", master_key1.clone(), None)
            .expect("Should create secret1");

        let _secret2 = repo
            .create_new_version(&mut conn_mut, "secret2", "data2", master_key1.clone(), None)
            .expect("Should create secret2");

        let _secret3 = repo
            .create_new_version(&mut conn_mut, "secret3", "data3", master_key2.clone(), None)
            .expect("Should create secret3");

        // Fetch secrets by master key 1
        let secrets_mk1 = repo
            .fetch_secrets_by_master_key(&conn_mut, &master_key1.id)
            .expect("Should fetch secrets for master key 1");

        assert_eq!(secrets_mk1.len(), 2);
        assert!(
            secrets_mk1
                .iter()
                .all(|s| s.master_key_id == master_key1.id)
        );

        // Fetch secrets by master key 2
        let secrets_mk2 = repo
            .fetch_secrets_by_master_key(&conn_mut, &master_key2.id)
            .expect("Should fetch secrets for master key 2");

        assert_eq!(secrets_mk2.len(), 1);
        assert_eq!(secrets_mk2[0].master_key_id, master_key2.id);
    }

    #[test]
    fn test_update_secret_master_key() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();

        // Create a secret
        let mut conn_mut = conn;
        let mut secret = repo
            .create_new_version(&mut conn_mut, "test-secret", "test-data", master_key, None)
            .expect("Should create secret");

        // Modify the secret
        let new_master_key = create_test_master_key();
        secret.master_key_id = new_master_key.id;
        secret.encrypted_data_key = vec![1, 2, 3, 4]; // Dummy new encrypted key
        secret.updated_at = time::OffsetDateTime::now_utc().unix_timestamp();

        // Update in database
        repo.update_secret_master_key(&conn_mut, &secret)
            .expect("Should update secret");

        // Verify the update
        let updated_secret = repo
            .get_secret(&mut conn_mut, "test-secret")
            .expect("Should retrieve updated secret");

        assert_eq!(updated_secret.master_key_id, new_master_key.id);
        assert_eq!(updated_secret.encrypted_data_key, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_secret_with_ttl() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();

        let ttl = Some(3600i64); // 1 hour

        // Create secret with TTL
        let mut conn_mut = conn;
        let secret = repo
            .create_new_version(
                &mut conn_mut,
                "ttl-secret",
                "temporary-data",
                master_key,
                ttl,
            )
            .expect("Should create secret with TTL");

        assert!(secret.expires_at.is_some());
        let expected_expiry = secret.created_at + 3600;
        assert_eq!(secret.expires_at, Some(expected_expiry));

        // Retrieve and verify TTL is preserved
        let retrieved = repo
            .get_secret(&mut conn_mut, "ttl-secret")
            .expect("Should retrieve secret");
        assert_eq!(retrieved.expires_at, secret.expires_at);
    }

    #[test]
    fn test_expired_secret_not_retrievable() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();

        // Create a secret that expires immediately (TTL = 1 second)
        let mut conn_mut = conn;
        let _secret = repo
            .create_new_version(
                &mut conn_mut,
                "expired-secret",
                "temporary-data",
                master_key,
                Some(1i64), // 1 second
            )
            .expect("Should create secret with short TTL");

        // Wait for the secret to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Try to retrieve the expired secret
        let result = repo.get_secret(&mut conn_mut, "expired-secret");
        assert!(result.is_err());

        match result.unwrap_err() {
            SealboxError::SecretNotFound(key) => assert_eq!(key, "expired-secret"),
            _ => panic!("Expected SecretNotFound error"),
        }
    }

    #[test]
    fn test_expired_secret_by_version_not_retrievable() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();

        // Create a secret that expires immediately
        let mut conn_mut = conn;
        let secret = repo
            .create_new_version(
                &mut conn_mut,
                "expired-secret-v",
                "temporary-data",
                master_key,
                Some(1i64), // 1 second
            )
            .expect("Should create secret with short TTL");

        // Wait for the secret to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Try to retrieve the expired secret by version
        let result = repo.get_secret_by_version(&mut conn_mut, "expired-secret-v", secret.version);
        assert!(result.is_err());

        match result.unwrap_err() {
            SealboxError::SecretNotFound(key) => assert_eq!(key, "expired-secret-v"),
            _ => panic!("Expected SecretNotFound error"),
        }
    }

    fn count_secret_rows(conn: &rusqlite::Connection, namespace: &str, key: &str) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM secrets WHERE namespace = ?1 AND key = ?2",
            (namespace, key),
            |row| row.get(0),
        )
        .expect("Should count secret rows")
    }

    fn set_secret_expires_at(
        conn: &rusqlite::Connection,
        namespace: &str,
        key: &str,
        version: i32,
        expires_at: Option<i64>,
    ) {
        conn.execute(
            "UPDATE secrets SET expires_at = ?1 WHERE namespace = ?2 AND key = ?3 AND version = ?4",
            (expires_at, namespace, key, version),
        )
        .expect("Should update expires_at");
    }

    #[test]
    fn test_expired_newest_version_ends_key_for_secret_credential_and_file() {
        let mut conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();
        let expired_at = time::OffsetDateTime::now_utc().unix_timestamp() - 10;

        let cases: [(&str, Option<&str>); 3] = [
            ("plain-key", None),
            (
                "cred-key",
                Some(r#"{"type":"credential","username":"app_user"}"#),
            ),
            ("file-key", Some(r#"{"type":"file","filename":"cert.pem"}"#)),
        ];

        for (key, metadata) in cases {
            repo.create_new_encrypted_version(
                &mut conn,
                key,
                EncryptedSecretInput {
                    encrypted_data: vec![1],
                    encrypted_data_key: vec![1],
                    master_key_id: master_key.id,
                    ttl: None,
                    metadata: metadata.map(str::to_string),
                },
            )
            .expect("Should create permanent v1");

            let v2 = repo
                .create_new_encrypted_version(
                    &mut conn,
                    key,
                    EncryptedSecretInput {
                        encrypted_data: vec![2],
                        encrypted_data_key: vec![2],
                        master_key_id: master_key.id,
                        ttl: Some(3600),
                        metadata: metadata.map(str::to_string),
                    },
                )
                .expect("Should create TTL v2");

            set_secret_expires_at(
                &conn,
                crate::repo::LEGACY_TENANT_ID,
                key,
                v2.version,
                Some(expired_at),
            );
        }

        // Before any read or cleanup runs, listings must omit every expired key and its history.
        assert!(repo.list_secrets(&conn).expect("Should list").is_empty());
        for (key, _) in cases {
            assert!(matches!(
                repo.list_secret_versions(&conn, key),
                Err(SealboxError::SecretNotFound(ref k)) if k == key
            ));
            assert_eq!(
                count_secret_rows(&conn, crate::repo::LEGACY_TENANT_ID, key),
                2
            );
        }

        // Reading by key deletes all versions of plain-key.
        assert!(matches!(
            repo.get_secret(&mut conn, "plain-key"),
            Err(SealboxError::SecretNotFound(ref k)) if k == "plain-key"
        ));
        assert_eq!(
            count_secret_rows(&conn, crate::repo::LEGACY_TENANT_ID, "plain-key"),
            0
        );

        // Reading the older permanent version directly also ends cred-key and removes all rows.
        assert!(matches!(
            repo.get_secret_by_version(&mut conn, "cred-key", 1),
            Err(SealboxError::SecretNotFound(ref k)) if k == "cred-key"
        ));
        assert_eq!(
            count_secret_rows(&conn, crate::repo::LEGACY_TENANT_ID, "cred-key"),
            0
        );

        // Reading the expired latest version of file-key removes both rows too.
        assert!(matches!(
            repo.get_secret_by_version(&mut conn, "file-key", 2),
            Err(SealboxError::SecretNotFound(ref k)) if k == "file-key"
        ));
        assert_eq!(
            count_secret_rows(&conn, crate::repo::LEGACY_TENANT_ID, "file-key"),
            0
        );
    }

    #[test]
    fn test_expired_older_version_under_unexpired_newest_is_removed_alone() {
        let mut conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();
        let expired_at = time::OffsetDateTime::now_utc().unix_timestamp() - 10;

        let v1 = repo
            .create_new_version(
                &mut conn,
                "active-key",
                "old-temporary",
                master_key.clone(),
                Some(3600),
            )
            .expect("Should create v1");
        let v2 = repo
            .create_new_version(
                &mut conn,
                "active-key",
                "current-permanent",
                master_key,
                None,
            )
            .expect("Should create v2");

        set_secret_expires_at(
            &conn,
            crate::repo::LEGACY_TENANT_ID,
            "active-key",
            v1.version,
            Some(expired_at),
        );

        // Listings show only v2.
        let listed = repo.list_secrets(&conn).expect("Should list secrets");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key, "active-key");
        assert_eq!(listed[0].version, v2.version);

        let versions = repo
            .list_secret_versions(&conn, "active-key")
            .expect("Should list versions");
        assert_eq!(
            versions.iter().map(|v| v.version).collect::<Vec<_>>(),
            vec![v2.version]
        );

        // Reading v2 succeeds and cleans up expired v1.
        let latest = repo
            .get_secret(&mut conn, "active-key")
            .expect("Should return unexpired newest version");
        assert_eq!(latest.version, v2.version);
        assert_eq!(
            count_secret_rows(&conn, crate::repo::LEGACY_TENANT_ID, "active-key"),
            1
        );
        assert!(matches!(
            repo.get_secret_by_version(&mut conn, "active-key", v1.version),
            Err(SealboxError::SecretNotFound(ref k)) if k == "active-key"
        ));
    }

    #[test]
    fn test_expiry_boundary_at_exact_now_is_consistent_across_reads_listings_and_cleanup() {
        let mut conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();
        let fixed_now = 2_000_000_000i64;

        repo.create_new_version(
            &mut conn,
            "boundary-key",
            "v1-permanent",
            master_key.clone(),
            None,
        )
        .expect("Should create v1");
        let v2 = repo
            .create_new_version(
                &mut conn,
                "boundary-key",
                "v2-boundary",
                master_key,
                Some(3600),
            )
            .expect("Should create v2");

        set_secret_expires_at(
            &conn,
            crate::repo::LEGACY_TENANT_ID,
            "boundary-key",
            v2.version,
            Some(fixed_now),
        );

        // At expires_at == now, the key is not yet past expires_at.
        assert_eq!(
            repo.list_secrets_at(&conn, crate::repo::LEGACY_TENANT_ID, fixed_now)
                .expect("Should list at exact boundary")
                .len(),
            1
        );
        assert_eq!(
            repo.list_secret_versions_at(
                &conn,
                crate::repo::LEGACY_TENANT_ID,
                "boundary-key",
                fixed_now
            )
            .expect("Should list versions at exact boundary")
            .len(),
            2
        );
        assert_eq!(
            repo.cleanup_expired_secrets_in_namespace_at(
                &conn,
                crate::repo::LEGACY_TENANT_ID,
                fixed_now
            )
            .expect("Should cleanup at exact boundary"),
            0
        );
        let read_at_boundary = repo
            .get_secret_with_query(
                &mut conn,
                "SELECT namespace, key, version, encrypted_data, encrypted_data_key, master_key_id, created_at, updated_at, expires_at, metadata FROM secrets WHERE namespace = ?1 AND key = ?2 ORDER BY version DESC LIMIT 1",
                (crate::repo::LEGACY_TENANT_ID, "boundary-key"),
                crate::repo::LEGACY_TENANT_ID,
                "boundary-key",
                fixed_now,
            )
            .expect("Key should remain readable when expires_at == now");
        assert_eq!(read_at_boundary.version, v2.version);

        // One second later (expires_at < now), listings and cleanup both treat the whole key as expired.
        let past_now = fixed_now + 1;
        assert!(
            repo.list_secrets_at(&conn, crate::repo::LEGACY_TENANT_ID, past_now)
                .expect("Should list past boundary")
                .is_empty()
        );
        assert!(matches!(
            repo.list_secret_versions_at(
                &conn,
                crate::repo::LEGACY_TENANT_ID,
                "boundary-key",
                past_now
            ),
            Err(SealboxError::SecretNotFound(ref k)) if k == "boundary-key"
        ));
        assert_eq!(
            repo.cleanup_expired_secrets_in_namespace_at(
                &conn,
                crate::repo::LEGACY_TENANT_ID,
                past_now
            )
            .expect("Should cleanup past boundary"),
            2
        );
        assert_eq!(
            count_secret_rows(&conn, crate::repo::LEGACY_TENANT_ID, "boundary-key"),
            0
        );
    }

    #[test]
    fn test_cleanup_expired_counts_all_versions_and_isolates_tenants() {
        let mut conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();
        let expired_at = time::OffsetDateTime::now_utc().unix_timestamp() - 10;

        // Tenant A: expired-key has 3 versions (v1 permanent, v2 permanent, v3 expired).
        for data in ["v1", "v2"] {
            <SqliteSecretRepo as SecretRepo>::create_new_version(
                &repo,
                &mut conn,
                "tenant-a",
                "expired-key",
                data,
                master_key.clone(),
                None,
            )
            .expect("Should create permanent version");
        }
        let a_v3 = <SqliteSecretRepo as SecretRepo>::create_new_version(
            &repo,
            &mut conn,
            "tenant-a",
            "expired-key",
            "v3",
            master_key.clone(),
            Some(3600),
        )
        .expect("Should create v3");
        set_secret_expires_at(
            &conn,
            "tenant-a",
            "expired-key",
            a_v3.version,
            Some(expired_at),
        );

        // Tenant A: active-key has v1 expired and v2 permanent.
        let a_old = <SqliteSecretRepo as SecretRepo>::create_new_version(
            &repo,
            &mut conn,
            "tenant-a",
            "active-key",
            "old",
            master_key.clone(),
            Some(3600),
        )
        .expect("Should create v1");
        <SqliteSecretRepo as SecretRepo>::create_new_version(
            &repo,
            &mut conn,
            "tenant-a",
            "active-key",
            "current",
            master_key.clone(),
            None,
        )
        .expect("Should create v2");
        set_secret_expires_at(
            &conn,
            "tenant-a",
            "active-key",
            a_old.version,
            Some(expired_at),
        );

        // Tenant B: same key name with permanent v1 and expired v2.
        <SqliteSecretRepo as SecretRepo>::create_new_version(
            &repo,
            &mut conn,
            "tenant-b",
            "expired-key",
            "b-v1",
            master_key.clone(),
            None,
        )
        .expect("Should create tenant-b v1");
        let b_v2 = <SqliteSecretRepo as SecretRepo>::create_new_version(
            &repo,
            &mut conn,
            "tenant-b",
            "expired-key",
            "b-v2",
            master_key,
            Some(3600),
        )
        .expect("Should create tenant-b v2");
        set_secret_expires_at(
            &conn,
            "tenant-b",
            "expired-key",
            b_v2.version,
            Some(expired_at),
        );

        // Tenant A cleanup removes 3 rows from expired-key + 1 expired old row from active-key = 4.
        let tenant_a_deleted = repo
            .cleanup_expired_secrets_in_namespace(&conn, "tenant-a")
            .expect("Should clean tenant-a");
        assert_eq!(tenant_a_deleted, 4);
        assert_eq!(count_secret_rows(&conn, "tenant-a", "expired-key"), 0);
        assert_eq!(count_secret_rows(&conn, "tenant-a", "active-key"), 1);
        assert_eq!(
            <SqliteSecretRepo as SecretRepo>::get_secret(
                &repo,
                &mut conn,
                "tenant-a",
                "active-key"
            )
            .expect("Tenant A active-key should remain readable")
            .version,
            2
        );
        // Tenant B is completely untouched.
        assert_eq!(count_secret_rows(&conn, "tenant-b", "expired-key"), 2);

        // All-tenant cleanup removes both versions of tenant B's expired key.
        let all_deleted = repo
            .cleanup_expired_secrets(&conn)
            .expect("Should clean all tenants");
        assert_eq!(all_deleted, 2);
        assert_eq!(count_secret_rows(&conn, "tenant-b", "expired-key"), 0);
        assert_eq!(count_secret_rows(&conn, "tenant-a", "active-key"), 1);
    }

    #[test]
    fn test_write_before_cleanup_removes_expired_key_and_restarts_at_version_one() {
        let mut conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();
        let expired_at = time::OffsetDateTime::now_utc().unix_timestamp() - 10;

        // Scenario A via create_new_encrypted_version (production write path).
        repo.create_new_encrypted_version(
            &mut conn,
            "reused-encrypted",
            EncryptedSecretInput {
                encrypted_data: vec![1, 1],
                encrypted_data_key: vec![1],
                master_key_id: master_key.id,
                ttl: None,
                metadata: None,
            },
        )
        .expect("Should create permanent v1");
        let v2 = repo
            .create_new_encrypted_version(
                &mut conn,
                "reused-encrypted",
                EncryptedSecretInput {
                    encrypted_data: vec![2, 2],
                    encrypted_data_key: vec![2],
                    master_key_id: master_key.id,
                    ttl: Some(3600),
                    metadata: None,
                },
            )
            .expect("Should create TTL v2");
        set_secret_expires_at(
            &conn,
            crate::repo::LEGACY_TENANT_ID,
            "reused-encrypted",
            v2.version,
            Some(expired_at),
        );

        // Save a new value before any read or cleanup runs.
        let replacement = repo
            .create_new_encrypted_version(
                &mut conn,
                "reused-encrypted",
                EncryptedSecretInput {
                    encrypted_data: vec![3, 3],
                    encrypted_data_key: vec![3],
                    master_key_id: master_key.id,
                    ttl: None,
                    metadata: None,
                },
            )
            .expect("Should create replacement secret");

        assert_eq!(replacement.version, 1);
        assert_eq!(
            count_secret_rows(&conn, crate::repo::LEGACY_TENANT_ID, "reused-encrypted"),
            1
        );
        let history = repo
            .list_secret_versions(&conn, "reused-encrypted")
            .expect("Should list history");
        assert_eq!(
            history.iter().map(|v| v.version).collect::<Vec<_>>(),
            vec![1]
        );
        let fetched = repo
            .get_secret_by_version(&mut conn, "reused-encrypted", 1)
            .expect("Should read new v1");
        assert_eq!(fetched.encrypted_data, vec![3, 3]);

        // Scenario A via test-only create_new_version.
        repo.create_new_version(
            &mut conn,
            "reused-helper",
            "old-permanent",
            master_key.clone(),
            None,
        )
        .expect("Should create v1");
        let helper_v2 = repo
            .create_new_version(
                &mut conn,
                "reused-helper",
                "old-temp",
                master_key.clone(),
                Some(3600),
            )
            .expect("Should create v2");
        set_secret_expires_at(
            &conn,
            crate::repo::LEGACY_TENANT_ID,
            "reused-helper",
            helper_v2.version,
            Some(expired_at),
        );

        let helper_replacement = repo
            .create_new_version(&mut conn, "reused-helper", "fresh", master_key, None)
            .expect("Should create replacement");
        assert_eq!(helper_replacement.version, 1);
        assert_eq!(
            count_secret_rows(&conn, crate::repo::LEGACY_TENANT_ID, "reused-helper"),
            1
        );
    }

    #[test]
    fn test_delete_secret_by_version_on_expired_key_removes_all_versions_and_returns_not_found() {
        let mut conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();
        let expired_at = time::OffsetDateTime::now_utc().unix_timestamp() - 10;

        for (key, target_version) in [("del-latest", 2), ("del-older", 1)] {
            repo.create_new_version(&mut conn, key, "v1-permanent", master_key.clone(), None)
                .expect("Should create v1");
            let v2 = repo
                .create_new_version(&mut conn, key, "v2-temp", master_key.clone(), Some(3600))
                .expect("Should create v2");
            set_secret_expires_at(
                &conn,
                crate::repo::LEGACY_TENANT_ID,
                key,
                v2.version,
                Some(expired_at),
            );

            let err = repo
                .delete_secret_by_version(&mut conn, key, target_version)
                .expect_err("Deleting a version of an expired key must return SecretNotFound");
            assert!(matches!(err, SealboxError::SecretNotFound(ref k) if k == key));
            assert_eq!(
                count_secret_rows(&conn, crate::repo::LEGACY_TENANT_ID, key),
                0
            );
            assert!(matches!(
                repo.get_secret(&mut conn, key),
                Err(SealboxError::SecretNotFound(ref k)) if k == key
            ));
        }
    }

    #[test]
    fn test_cleanup_expired_secrets() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();

        let mut conn_mut = conn;

        // Create several secrets: some expired, some not
        let _expired1 = repo
            .create_new_version(
                &mut conn_mut,
                "expired1",
                "data1",
                master_key.clone(),
                Some(1i64), // 1 second
            )
            .expect("Should create expired secret 1");

        let _expired2 = repo
            .create_new_version(
                &mut conn_mut,
                "expired2",
                "data2",
                master_key.clone(),
                Some(1i64), // 1 second
            )
            .expect("Should create expired secret 2");

        let _permanent = repo
            .create_new_version(
                &mut conn_mut,
                "permanent",
                "permanent-data",
                master_key.clone(),
                None, // No TTL
            )
            .expect("Should create permanent secret");

        let _long_lived = repo
            .create_new_version(
                &mut conn_mut,
                "long-lived",
                "long-data",
                master_key,
                Some(3600i64), // 1 hour
            )
            .expect("Should create long-lived secret");

        // Wait for short-lived secrets to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Run cleanup
        let deleted_count = repo
            .cleanup_expired_secrets(&conn_mut)
            .expect("Should cleanup expired secrets");

        // Should have deleted 2 expired secrets
        assert_eq!(deleted_count, 2);

        // Verify that permanent and long-lived secrets are still retrievable
        let permanent = repo
            .get_secret(&mut conn_mut, "permanent")
            .expect("Permanent secret should still exist");
        assert_eq!(permanent.key, "permanent");

        let long_lived = repo
            .get_secret(&mut conn_mut, "long-lived")
            .expect("Long-lived secret should still exist");
        assert_eq!(long_lived.key, "long-lived");

        // Verify expired secrets are gone
        let expired1_result = repo.get_secret(&mut conn_mut, "expired1");
        assert!(expired1_result.is_err());

        let expired2_result = repo.get_secret(&mut conn_mut, "expired2");
        assert!(expired2_result.is_err());
    }

    #[test]
    fn test_cleanup_no_expired_secrets() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();

        let mut conn_mut = conn;

        // Create only non-expired secrets
        let _permanent = repo
            .create_new_version(&mut conn_mut, "permanent", "data", master_key.clone(), None)
            .expect("Should create permanent secret");

        let _long_lived = repo
            .create_new_version(
                &mut conn_mut,
                "long-lived",
                "data",
                master_key,
                Some(3600i64),
            )
            .expect("Should create long-lived secret");

        // Run cleanup
        let deleted_count = repo
            .cleanup_expired_secrets(&conn_mut)
            .expect("Should cleanup expired secrets");

        // Should have deleted 0 secrets
        assert_eq!(deleted_count, 0);

        // All secrets should still be retrievable
        repo.get_secret(&mut conn_mut, "permanent")
            .expect("Permanent secret should still exist");
        repo.get_secret(&mut conn_mut, "long-lived")
            .expect("Long-lived secret should still exist");
    }

    #[test]
    fn test_list_secrets() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();

        let mut conn_mut = conn;

        // Create several secrets
        let _secret1 = repo
            .create_new_version(&mut conn_mut, "secret1", "data1", master_key.clone(), None)
            .expect("Should create secret1");

        let _secret2 = repo
            .create_new_version(
                &mut conn_mut,
                "secret2",
                "data2",
                master_key.clone(),
                Some(3600),
            )
            .expect("Should create secret2 with TTL");

        let _secret3 = repo
            .create_new_version(&mut conn_mut, "secret3", "data3", master_key.clone(), None)
            .expect("Should create secret3");

        // Create multiple versions of secret1
        let _secret1_v2 = repo
            .create_new_version(&mut conn_mut, "secret1", "data1-v2", master_key, None)
            .expect("Should create secret1 version 2");

        // List all secrets
        let secret_list = repo.list_secrets(&conn_mut).expect("Should list secrets");

        // Should return 3 unique secrets (secret1, secret2, secret3)
        assert_eq!(secret_list.len(), 3);

        // Find secret1 - should have version 2 (latest)
        let secret1_info = secret_list
            .iter()
            .find(|s| s.key == "secret1")
            .expect("Should find secret1");
        assert_eq!(secret1_info.version, 2);

        // Find secret2 - should have TTL set
        let secret2_info = secret_list
            .iter()
            .find(|s| s.key == "secret2")
            .expect("Should find secret2");
        assert!(secret2_info.expires_at.is_some());

        // All secrets should have valid timestamps
        for secret_info in &secret_list {
            assert!(secret_info.created_at > 0);
            assert!(secret_info.updated_at > 0);
            assert!(secret_info.updated_at >= secret_info.created_at);
        }
    }

    #[test]
    fn test_list_secrets_metadata_comes_from_latest_row() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();
        let mut conn_mut = conn;

        let _secret_v1 = repo
            .create_new_version(
                &mut conn_mut,
                "metadata-secret",
                "data-v1",
                master_key.clone(),
                None,
            )
            .expect("Should create version 1");
        let secret_v2 = repo
            .create_new_version(
                &mut conn_mut,
                "metadata-secret",
                "data-v2",
                master_key,
                Some(3600),
            )
            .expect("Should create version 2");

        let secret_list = repo.list_secrets(&conn_mut).expect("Should list secrets");
        let secret_info = secret_list
            .iter()
            .find(|secret| secret.key == "metadata-secret")
            .expect("Should find metadata-secret");

        assert_eq!(secret_info.version, secret_v2.version);
        assert_eq!(secret_info.created_at, secret_v2.created_at);
        assert_eq!(secret_info.updated_at, secret_v2.updated_at);
        assert_eq!(secret_info.expires_at, secret_v2.expires_at);
    }

    #[test]
    fn test_list_secrets_excludes_expired() {
        let conn = setup_test_db();
        let repo = SqliteSecretRepo;
        let master_key = create_test_master_key();

        let mut conn_mut = conn;

        // Create a secret that expires immediately
        let _expired_secret = repo
            .create_new_version(
                &mut conn_mut,
                "expired-secret",
                "temporary-data",
                master_key.clone(),
                Some(1i64), // 1 second
            )
            .expect("Should create expired secret");

        // Create a permanent secret
        let _permanent_secret = repo
            .create_new_version(
                &mut conn_mut,
                "permanent-secret",
                "permanent-data",
                master_key,
                None,
            )
            .expect("Should create permanent secret");

        // Wait for the secret to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        // List secrets should only return the permanent one
        let secret_list = repo.list_secrets(&conn_mut).expect("Should list secrets");

        assert_eq!(secret_list.len(), 1);
        assert_eq!(secret_list[0].key, "permanent-secret");
    }
}
