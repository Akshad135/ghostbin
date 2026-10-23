use std::str::FromStr;
use std::time::Duration;

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

pub const SCHEMA_VERSION: i64 = 3;

/// How `RESET_DB` may wipe an existing database at startup.
pub enum ResetDb {
    /// Do not wipe anything; an incompatible schema is a startup error.
    No,
    /// `RESET_DB=1` — wipe only when the existing schema is incompatible.
    IfIncompatible,
    /// `RESET_DB=force` — wipe even a current schema. Recovery escape hatch
    /// (e.g. reclaiming an instance whose setup was squatted); destroys data.
    Force,
}

const REQUIRED_TABLES: &[&str] = &[
    "settings",
    "sessions",
    "pastes",
    "shares",
    "share_tokens",
    "share_challenges",
    "files",
];

/// Create a SQLite pool with the settings required by the E2EE backend.
pub async fn init_pool(db_path: &str) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(&format!("sqlite:{db_path}"))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(5))
        .foreign_keys(true)
        .synchronous(SqliteSynchronous::Normal);

    SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
}

async fn list_user_tables(pool: &SqlitePool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT name FROM sqlite_master
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )
    .fetch_all(pool)
    .await
}

async fn create_schema(pool: &SqlitePool) -> Result<(), String> {
    let schema = include_str!("../schema.sql");
    let schema_without_comments = schema
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");

    for statement in schema_without_comments.split(';') {
        let statement = statement.trim();
        if statement.is_empty() {
            continue;
        }
        sqlx::query(statement)
            .execute(pool)
            .await
            .map_err(|e| format!("Failed to create schema: {e}\nStatement: {statement}"))?;
    }

    sqlx::query(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))
        .execute(pool)
        .await
        .map_err(|e| format!("Failed to set schema version: {e}"))?;

    Ok(())
}

async fn drop_all_user_tables(pool: &SqlitePool) -> Result<(), String> {
    let tables = list_user_tables(pool)
        .await
        .map_err(|e| format!("Failed to list tables for reset: {e}"))?;

    let mut connection = pool
        .acquire()
        .await
        .map_err(|e| format!("Failed to acquire database connection for reset: {e}"))?;

    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *connection)
        .await
        .map_err(|e| format!("Failed to disable foreign keys for reset: {e}"))?;

    for table in tables {
        let quoted = table.replace('"', "\"\"");
        sqlx::query(&format!("DROP TABLE IF EXISTS \"{quoted}\""))
            .execute(&mut *connection)
            .await
            .map_err(|e| format!("Failed to drop table {table}: {e}"))?;
    }

    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&mut *connection)
        .await
        .map_err(|e| format!("Failed to re-enable foreign keys after reset: {e}"))?;

    Ok(())
}

fn has_required_tables(tables: &[String]) -> bool {
    REQUIRED_TABLES
        .iter()
        .all(|required| tables.iter().any(|table| table == required))
}

/// Create the current schema, or refuse to reuse an incompatible database.
///
/// `RESET_DB` is the only way to wipe an existing database. There is no
/// silent `CREATE TABLE IF NOT EXISTS` compatibility path for the old schema.
pub async fn init_schema(pool: &SqlitePool, reset: ResetDb) -> Result<(), String> {
    let tables = list_user_tables(pool)
        .await
        .map_err(|e| format!("Failed to inspect database schema: {e}"))?;

    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(pool)
        .await
        .map_err(|e| format!("Failed to read schema version: {e}"))?;

    if !tables.is_empty() {
        if version == SCHEMA_VERSION && has_required_tables(&tables) {
            if matches!(reset, ResetDb::Force) {
                tracing::warn!(
                    "RESET_DB=force: wiping the current schema v{SCHEMA_VERSION} as requested"
                );
                drop_all_user_tables(pool).await?;
            } else {
                if matches!(reset, ResetDb::IfIncompatible) {
                    tracing::warn!(
                        "RESET_DB=1 ignored: database schema v{SCHEMA_VERSION} is already \
                         current (use RESET_DB=force to wipe it anyway)"
                    );
                }
                tracing::info!("Database schema is current (version {SCHEMA_VERSION})");
                return Ok(());
            }
        } else if matches!(reset, ResetDb::IfIncompatible | ResetDb::Force) {
            tracing::warn!(
                "RESET_DB: dropping {} incompatible table(s) and creating schema v{}",
                tables.len(),
                SCHEMA_VERSION
            );
            drop_all_user_tables(pool).await?;
        } else {
            return Err(format!(
                "Existing database schema is not compatible with schema v{SCHEMA_VERSION}.\n\
                 Found tables: {}\n\
                 Back up the database, then set RESET_DB=1 once to wipe it.",
                tables.join(", ")
            ));
        }
    }

    create_schema(pool).await?;
    tracing::info!("Created database schema version {SCHEMA_VERSION}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn memory_pool() -> SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory SQLite")
    }

    #[tokio::test]
    async fn creates_schema_and_is_idempotent() {
        let pool = memory_pool().await;
        init_schema(&pool, ResetDb::No).await.expect("first init");
        init_schema(&pool, ResetDb::No).await.expect("second init");

        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        let tables = list_user_tables(&pool).await.unwrap();
        assert!(has_required_tables(&tables));
    }

    #[tokio::test]
    async fn refuses_existing_unknown_schema_without_reset() {
        let pool = memory_pool().await;
        sqlx::query("CREATE TABLE legacy (id INTEGER PRIMARY KEY)")
            .execute(&pool)
            .await
            .unwrap();

        let error = init_schema(&pool, ResetDb::No).await.unwrap_err();
        assert!(error.contains("RESET_DB=1"));
    }

    #[tokio::test]
    async fn reset_1_does_not_wipe_current_schema() {
        let pool = memory_pool().await;
        init_schema(&pool, ResetDb::No).await.expect("initial schema");

        sqlx::query(
            "INSERT INTO settings
                (id, kdf_salt, kdf_params, auth_hash, wrapped_vault_key, created_at, updated_at)
             VALUES (1, ?, ?, ?, ?, 0, 0)",
        )
        .bind(vec![1u8; 16])
        .bind("{}")
        .bind(vec![2u8; 32])
        .bind(vec![3u8; 60])
        .execute(&pool)
        .await
        .expect("insert settings");

        init_schema(&pool, ResetDb::IfIncompatible)
            .await
            .expect("current schema must survive reset flag");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM settings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn reset_force_wipes_current_schema() {
        let pool = memory_pool().await;
        init_schema(&pool, ResetDb::No).await.expect("initial schema");

        init_schema(&pool, ResetDb::Force)
            .await
            .expect("forced reset");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM settings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "forced reset must wipe existing data");

        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn reset_drops_old_schema_and_creates_current() {
        let pool = memory_pool().await;
        sqlx::query("CREATE TABLE legacy (id INTEGER PRIMARY KEY)")
            .execute(&pool)
            .await
            .unwrap();

        init_schema(&pool, ResetDb::IfIncompatible)
            .await
            .expect("reset init");

        let legacy: Option<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'legacy'",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert!(legacy.is_none());

        let tables = list_user_tables(&pool).await.unwrap();
        assert!(has_required_tables(&tables));
    }
}
